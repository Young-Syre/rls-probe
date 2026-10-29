-- rls-probe end-to-end fixture: a deliberately misconfigured schema.
--
-- Every finding rls-probe can report is reproduced here at least once, next to
-- a correctly configured object of the same kind so you can see the checks
-- staying quiet as well as firing.
--
-- RUN THIS ONLY AGAINST A THROWAWAY DATABASE.  It creates cluster-wide roles
-- (anon, authenticated), grants CREATE on the public schema to PUBLIC, and
-- creates tables, views and functions that are unsafe by construction.
--
--   createdb rls_probe_fixture
--   psql -d rls_probe_fixture -f tests/sql/fixture.sql
--   rls-probe audit --dsn postgresql:///rls_probe_fixture
--   dropdb rls_probe_fixture
--
-- Nothing in rls-probe itself writes to a database; this file is the only SQL
-- in the repository that does, and you run it yourself.

\set ON_ERROR_STOP on

-- ---------------------------------------------------------------------------
-- Roles.  These are the two roles a PostgREST or Supabase deployment maps
-- inbound requests onto: anon for an unauthenticated request, authenticated
-- for one carrying a valid JWT.
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        CREATE ROLE anon NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        CREATE ROLE authenticated NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO anon, authenticated;

-- Reproduces a cluster upgraded from PostgreSQL 14 or earlier, or one where
-- somebody granted this deliberately.  PostgreSQL 15 removed this from the
-- defaults.  It is what turns RLS008 from latent into reachable: it gives an
-- attacker somewhere to plant a shadowing object.
GRANT CREATE ON SCHEMA public TO PUBLIC;

-- A stand-in for auth.uid(). The fixture needs a caller identity that does not
-- depend on Supabase's auth schema being installed.
CREATE OR REPLACE FUNCTION public.current_user_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$ SELECT current_setting('rls_probe.user_id', true) $$;

-- ---------------------------------------------------------------------------
-- invoices: RLS on, not forced, a correct read policy and a careless write
-- policy.  Reads are scoped per user and writes are not, so the table looks
-- right from the application: every caller sees only their own rows, and every
-- caller can create a row attributed to anybody.
--
-- Expected: RLS003 (not forced), RLS005 x2 (WITH CHECK true; the RESTRICTIVE
-- USING true), RLS006 (UPDATE and DELETE uncovered, read/write divergence),
-- RLS009 (anon holds INSERT).
-- ---------------------------------------------------------------------------

CREATE TABLE public.invoices (
    invoice_id   bigserial PRIMARY KEY,
    owner_ref    text NOT NULL,
    amount_cents bigint NOT NULL,
    paid         boolean NOT NULL DEFAULT false
);

ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;

CREATE POLICY invoices_select_own
    ON public.invoices
    FOR SELECT
    TO anon, authenticated
    USING (owner_ref = public.current_user_id());

-- The bug. Reads are filtered; writes accept anything, including an invoice
-- attributed to somebody else.
CREATE POLICY invoices_insert_any
    ON public.invoices
    FOR INSERT
    TO anon, authenticated
    WITH CHECK (true);

-- A restrictive policy whose USING is the identity for AND, so it restricts
-- nothing. Reported, but only at LOW: it is dead weight rather than a hole.
CREATE POLICY invoices_restrict_nothing
    ON public.invoices
    AS RESTRICTIVE
    FOR SELECT
    TO anon, authenticated
    USING (true);

GRANT SELECT, INSERT ON public.invoices TO authenticated;
GRANT SELECT, INSERT ON public.invoices TO anon;
GRANT USAGE ON SEQUENCE public.invoices_invoice_id_seq TO anon, authenticated;

-- ---------------------------------------------------------------------------
-- The views.  invoice_overview is the single highest-impact object in this
-- fixture: it reads an RLS-protected table, it is owned by the role that owns
-- that table, and it has no security_invoker, so it returns every invoice to
-- every caller.
--
-- Expected: RLS001 x2 (invoice_overview CRITICAL, invoice_summary HIGH because
-- nothing is granted on it), RLS009 (grants on a bypassing view), and nothing
-- at all for invoice_overview_safe.
-- ---------------------------------------------------------------------------

CREATE VIEW public.invoice_overview AS
    SELECT invoice_id, owner_ref, amount_cents, paid
    FROM public.invoices;

GRANT SELECT ON public.invoice_overview TO anon, authenticated;

-- A view over a view: the dependency is two hops from the RLS table, which is
-- why rls-probe resolves pg_depend transitively instead of looking one level
-- down. No grants on it, so the same bypass is reported one severity lower.
CREATE VIEW public.invoice_summary AS
    SELECT owner_ref, sum(amount_cents) AS total_cents
    FROM public.invoice_overview
    GROUP BY owner_ref;

-- The fix, for comparison. Same query, same owner, no finding.
--
-- The reloption is set in a DO block rather than inline so this file also
-- loads on PostgreSQL 14 and earlier, where security_invoker does not exist.
-- On those servers the view stays unsafe and rls-probe reports it, together
-- with a collection note saying there is no ALTER VIEW that would fix it.
CREATE VIEW public.invoice_overview_safe AS
    SELECT invoice_id, owner_ref, amount_cents, paid
    FROM public.invoices;

DO $$
BEGIN
    IF current_setting('server_version_num')::int >= 150000 THEN
        ALTER VIEW public.invoice_overview_safe SET (security_invoker = on);
    ELSE
        RAISE NOTICE
            'server is older than PostgreSQL 15: leaving invoice_overview_safe '
            'without security_invoker, because there is no way to set it here';
    END IF;
END
$$;

GRANT SELECT ON public.invoice_overview_safe TO anon, authenticated;

-- ---------------------------------------------------------------------------
-- audit_log: no RLS at all, in the exposed schema, readable by anon.
-- Expected: RLS002 (HIGH), RLS009 (CRITICAL), RLS010 (sequence).
-- ---------------------------------------------------------------------------

CREATE TABLE public.audit_log (
    entry_id   bigserial PRIMARY KEY,
    actor      text,
    action     text,
    created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT ON public.audit_log TO anon, authenticated;
GRANT USAGE, SELECT ON SEQUENCE public.audit_log_entry_id_seq TO anon;

-- ---------------------------------------------------------------------------
-- feature_flags: RLS enabled and nobody ever wrote the policy. Fail-closed,
-- so nothing leaks -- and the next person to debug "the API returns []" has a
-- one-line fix available that turns this into audit_log.
-- Expected: RLS004.
-- ---------------------------------------------------------------------------

CREATE TABLE public.feature_flags (
    flag_key text PRIMARY KEY,
    enabled  boolean NOT NULL DEFAULT false
);

ALTER TABLE public.feature_flags ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON public.feature_flags TO authenticated;

-- ---------------------------------------------------------------------------
-- public_posts: USING (true) on the read path.
-- Expected: RLS005 (HIGH), RLS006 (uncovered INSERT/UPDATE/DELETE).
-- ---------------------------------------------------------------------------

CREATE TABLE public.public_posts (
    post_id bigserial PRIMARY KEY,
    title   text NOT NULL,
    author  text NOT NULL
);

ALTER TABLE public.public_posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.public_posts FORCE ROW LEVEL SECURITY;

CREATE POLICY public_posts_read_all
    ON public.public_posts
    FOR SELECT
    TO anon, authenticated
    USING (true);

GRANT SELECT ON public.public_posts TO anon, authenticated;

-- ---------------------------------------------------------------------------
-- documents + memberships: the WITH CHECK fallback that constrains nothing.
--
-- The FOR ALL policy has a USING clause and no WITH CHECK, so PostgreSQL
-- reuses USING to validate written rows. USING asks "is this caller a member
-- of anything" and says nothing about the row in front of it, so as a write
-- rule it accepts any post-image: a caller can update a document and set
-- org_ref to an organisation they have nothing to do with.
--
-- Expected: RLS003, RLS006 (WITH CHECK fallback, MEDIUM).
-- ---------------------------------------------------------------------------

CREATE TABLE public.memberships (
    membership_id bigserial PRIMARY KEY,
    member_ref    text NOT NULL,
    org_ref       text NOT NULL
);

ALTER TABLE public.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.memberships FORCE ROW LEVEL SECURITY;

CREATE POLICY memberships_all_own
    ON public.memberships
    FOR ALL
    TO authenticated
    USING (member_ref = public.current_user_id())
    WITH CHECK (member_ref = public.current_user_id());

CREATE TABLE public.documents (
    doc_id  bigserial PRIMARY KEY,
    org_ref text NOT NULL,
    title   text NOT NULL,
    body    text
);

ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY documents_all_for_members
    ON public.documents
    FOR ALL
    TO authenticated
    USING (
        EXISTS (
            SELECT 1
            FROM public.memberships m
            WHERE m.member_ref = public.current_user_id()
        )
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON public.documents TO authenticated;

-- ---------------------------------------------------------------------------
-- The functions.
--
-- is_org_member is a policy helper. It is SECURITY DEFINER so that it can read
-- memberships past that table's own policies, which is reasonable -- and it
-- lives in public, so PostgREST serves it as POST /rest/v1/rpc/is_org_member,
-- callable by anon with arguments of the caller's choosing. It also has no
-- pinned search_path, so the names in its body resolve against the caller's.
--
-- Expected: RLS007 (HIGH), RLS008 (unpinned, HIGH).
-- ---------------------------------------------------------------------------

CREATE FUNCTION public.is_org_member(org text)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM memberships
        WHERE org_ref = org AND member_ref = current_user_id()
    )
$$;

-- Volatile, SECURITY DEFINER, in the exposed schema, and EXECUTE reaches anon
-- through PostgreSQL's default grant to PUBLIC -- there is no GRANT statement
-- for it anywhere in this file. Its search_path is pinned, but pinned to a
-- schema PUBLIC can create in, which pins nothing.
--
-- Expected: RLS007, RLS008 (pinned-writable), RLS010 (MEDIUM).
CREATE FUNCTION public.record_audit(actor text, action text)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
VOLATILE
SET search_path = public
AS $$ INSERT INTO audit_log (actor, action) VALUES (actor, action) $$;

-- ---------------------------------------------------------------------------
-- The clean versions, as negative controls.
-- ---------------------------------------------------------------------------

-- A non-exposed schema for policy helpers. PostgREST will not route to it, and
-- policies can still call into it.
CREATE SCHEMA private;
REVOKE ALL ON SCHEMA private FROM PUBLIC;

CREATE FUNCTION private.is_org_member(org text)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.memberships
        WHERE org_ref = org AND member_ref = public.current_user_id()
    )
$$;

REVOKE EXECUTE ON FUNCTION private.is_org_member(text) FROM PUBLIC;

-- profiles: RLS enabled and forced, a policy for every command, the same
-- predicate on the read and the write side, and grants only to the role the
-- policies name. rls-probe should have nothing to say about this table.
CREATE TABLE public.profiles (
    profile_id bigserial PRIMARY KEY,
    owner_ref  text NOT NULL,
    nickname   text
);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles FORCE ROW LEVEL SECURITY;

CREATE POLICY profiles_select_own ON public.profiles
    FOR SELECT TO authenticated
    USING (owner_ref = public.current_user_id());

CREATE POLICY profiles_insert_own ON public.profiles
    FOR INSERT TO authenticated
    WITH CHECK (owner_ref = public.current_user_id());

CREATE POLICY profiles_update_own ON public.profiles
    FOR UPDATE TO authenticated
    USING (owner_ref = public.current_user_id())
    WITH CHECK (owner_ref = public.current_user_id());

CREATE POLICY profiles_delete_own ON public.profiles
    FOR DELETE TO authenticated
    USING (owner_ref = public.current_user_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON public.profiles TO authenticated;
GRANT USAGE ON SEQUENCE public.profiles_profile_id_seq TO authenticated;
