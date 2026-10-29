"""Per-check reference material: what it catches, why RLS still fails, how to fix it.

Kept apart from the check logic so that ``rls-probe explain`` has something to
print without importing a database driver, and so the long-form text can be
reviewed as prose.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Severity


@dataclass(frozen=True)
class CheckDoc:
    check_id: str
    title: str
    #: The severity this check reports when nothing modifies it.
    default_severity: Severity
    #: One line for the checks table and ``list-checks``.
    summary: str
    #: Why row-level security does not save you here.
    mechanism: str
    #: How to fix it, as prose plus SQL.
    fix: str
    references: tuple[str, ...] = ()
    #: Conditions under which this check deliberately reports something other
    #: than :attr:`default_severity`.
    severity_notes: tuple[str, ...] = ()
    catalogs: tuple[str, ...] = field(default_factory=tuple)


CHECK_DOCS: dict[str, CheckDoc] = {}


def _register(doc: CheckDoc) -> None:
    CHECK_DOCS[doc.check_id] = doc


_register(
    CheckDoc(
        check_id="RLS001",
        title="View over an RLS table without security_invoker",
        default_severity=Severity.CRITICAL,
        summary="A view reads an RLS-protected table but runs as its own owner.",
        mechanism="""\
A view is not a window onto a table, it is a stored query that someone else
runs for you.  By default PostgreSQL executes that stored query with the
privileges of the *view's owner*, not the caller's.  Row-level security is
evaluated against the role actually executing the scan -- so for a default
view, the policies that get checked are the view owner's, and the view owner
is usually the same role that created the table.

Table owners are exempt from their own policies unless the table is
FORCE-enabled, which means the view returns every row in the table to every
caller.  The policies on the base table are still there.  They are still
correct.  They are simply not the ones being evaluated.

This is the highest-impact finding rls-probe looks for, for three reasons:

  1. The failure is total.  It is not a narrow bypass of one predicate, it
     is the entire table, to anyone who can select from the view.
  2. It is invisible from the application.  Nothing errors, nothing warns,
     the query plan looks ordinary; you just get more rows than you should.
  3. Views are exactly what people reach for to "simplify" a schema that
     has RLS on it -- a reporting view, a joined view for a dashboard, a
     flattened view for an API -- so the pattern shows up precisely where
     the data is most interesting.

`security_invoker = on` (PostgreSQL 15 and later) switches the view to
execute its underlying scans as the *caller*, so the base table's policies
apply to the person actually asking.

rls-probe resolves what a view reads through pg_depend and pg_rewrite rather
than by reading the view's SQL text, and follows nested views: a plain view
on top of a security_invoker view still collapses the whole subtree back to
the outer view's owner.""",
        fix="""\
Recreate or alter the view with security_invoker enabled:

    ALTER VIEW public.my_view SET (security_invoker = on);

Then confirm the caller also holds SELECT on the *base* table -- with
security_invoker on, the view no longer lends them the owner's privileges, so
a view that used to work for `anon` may start returning permission errors
until the underlying grant exists.  That error is the check working.

On PostgreSQL 14 and earlier there is no security_invoker.  The options there
are to make the view's own query enforce the tenant predicate explicitly
(and accept that it is now duplicated logic you have to keep in step with the
policy), or to replace the view with a SECURITY INVOKER set-returning
function, or to upgrade.""",
        references=(
            "https://www.postgresql.org/docs/current/sql-createview.html#SQL-CREATEVIEW-SECURITY-INVOKER",
            "https://www.postgresql.org/docs/current/ddl-rowsecurity.html",
        ),
        severity_notes=(
            "CRITICAL when an exposed role or PUBLIC can read the view.",
            "HIGH when only the owner and other privileged roles can read it -- "
            "the bypass is real but not reachable from the front door yet.",
        ),
        catalogs=("pg_class.reloptions", "pg_rewrite", "pg_depend", "pg_class.relrowsecurity"),
    )
)

_register(
    CheckDoc(
        check_id="RLS002",
        title="Table in an exposed schema without row-level security",
        default_severity=Severity.HIGH,
        summary="A table a REST layer serves has no RLS at all.",
        mechanism="""\
Row-level security is off by default on every table.  Granting SELECT to a
role therefore grants the whole table, and in a PostgREST or Supabase
deployment every table in an exposed schema is already an HTTP endpoint --
`GET /rest/v1/<table>` -- for whichever role the request authenticates as.

So the gate on the data is the privilege grant alone.  That is a coarse gate:
it answers "may this role touch this table", never "which rows".  A single
`GRANT SELECT ... TO authenticated` on a table without RLS hands every row to
every signed-in user of the application, which in a multi-tenant product
means every tenant's rows.""",
        fix="""\
    ALTER TABLE public.my_table ENABLE ROW LEVEL SECURITY;

Enabling RLS with no policies denies all access to non-owners, so add the
policies in the same migration -- see RLS004.  Write the policy before you
ship the ENABLE, or you will ship an outage.""",
        references=(
            "https://www.postgresql.org/docs/current/ddl-rowsecurity.html",
            "https://docs.postgrest.org/en/stable/references/api/schemas.html",
        ),
        severity_notes=(
            "HIGH when an exposed role or PUBLIC holds any privilege on the table.",
            "MEDIUM when no exposed role can reach it -- still wrong, but it is not "
            "currently an open endpoint.",
        ),
        catalogs=("pg_class.relrowsecurity", "pg_class.relacl"),
    )
)

_register(
    CheckDoc(
        check_id="RLS003",
        title="Row-level security enabled but not forced",
        default_severity=Severity.MEDIUM,
        summary="Policies exist but the table owner is exempt from them.",
        mechanism="""\
`ALTER TABLE ... ENABLE ROW LEVEL SECURITY` does not apply to the table's
owner.  The owner is assumed to be the one administering the data, so their
queries skip policy evaluation entirely.  `FORCE ROW LEVEL SECURITY` removes
that exemption.

Without FORCE, anything that connects as the owning role sees the whole
table: migration jobs, cron tasks, a background worker that reuses the admin
connection string, an ORM configured with the superuser DSN in staging -- and
any view the owner owns that is not security_invoker (RLS001 is the same
exemption reached by a different route).

Two honest caveats.  FORCE never applies to superusers or to roles with
BYPASSRLS; those always see everything by design.  And in a Supabase project
the `service_role` key is deliberately a BYPASSRLS role, so FORCE will not
change what server-side code using that key can read -- which is the intent,
but it means FORCE buys you less there than the name suggests.""",
        fix="""\
    ALTER TABLE public.my_table FORCE ROW LEVEL SECURITY;

Before you ship it, find what connects as the owner.  If a migration or
maintenance job depends on reading past the policies, give it a BYPASSRLS
role explicitly instead of relying on the owner exemption, so the privilege
is written down somewhere.""",
        references=("https://www.postgresql.org/docs/current/sql-altertable.html",),
        catalogs=(
            "pg_class.relrowsecurity",
            "pg_class.relforcerowsecurity",
            "pg_roles.rolbypassrls",
        ),
    )
)

_register(
    CheckDoc(
        check_id="RLS004",
        title="Row-level security enabled with zero policies",
        default_severity=Severity.MEDIUM,
        summary="RLS is on and no policy exists, so every row is denied.",
        mechanism="""\
An RLS-enabled table with no policies is fail-closed: non-owner queries match
no policy, so they return nothing and writes are rejected.  Nothing leaks.

It is reported anyway because it is almost never what was intended, and
because of how it tends to get resolved.  The symptom reaches a developer as
"the API returns an empty array" or "insert fails with a permissions error",
with no indication that a policy is missing.  The quickest thing that makes
the symptom go away is `DISABLE ROW LEVEL SECURITY`, or a policy with
`USING (true)` to "unblock" -- which is how a fail-closed table becomes
RLS002 or RLS005.

Note that the owner still reads the table normally (see RLS003), so this can
be invisible in a console session and total in the application.""",
        fix="""\
Add the policy the table was enabled for.  The shape depends on your tenancy
model; this is the common Supabase per-user case:

    CREATE POLICY my_table_select_own
        ON public.my_table
        FOR SELECT
        TO authenticated
        USING (user_id = auth.uid());

If the table really is meant to be unreadable by application roles, say so
explicitly by revoking the grants instead, and leave a comment on the table --
then the intent survives the next person to look at it.""",
        references=("https://www.postgresql.org/docs/current/sql-createpolicy.html",),
        catalogs=("pg_class.relrowsecurity", "pg_policy"),
    )
)

_register(
    CheckDoc(
        check_id="RLS005",
        title="Policy expression is literally true",
        default_severity=Severity.HIGH,
        summary="A USING or WITH CHECK clause of `true` filters nothing.",
        mechanism="""\
`USING (true)` is a policy that passes every row.  `WITH CHECK (true)`
accepts every write.  The table reports RLS as enabled, the policy is listed,
dashboards show the table as protected -- and no row is ever filtered.

These get written for two reasons, and both leave the same artefact.  One is
a placeholder during development that nobody came back to.  The other is a
deliberate "this table is public", which is legitimate for reference data but
indistinguishable in the catalog from the first case, so it is worth saying out
loud in the schema rather than leaving a reader to guess.

The dangerous variant is asymmetric: a correctly scoped `USING` with a
`WITH CHECK (true)` on the same table.  Reads are filtered, so the table looks
right from the application, while any caller can insert or update rows into
any tenant.  On a table that carries money -- a balance, a credit, an
entitlement -- that asymmetry is a privilege escalation: the write check is the
only thing deciding which account a row is attributed to, and `true` decides
nothing.  Nothing in the read path looks wrong afterwards, because the reader
only ever sees their own rows.""",
        fix="""\
Replace the expression with the predicate you meant:

    ALTER POLICY my_policy ON public.my_table
        USING (tenant_id = current_setting('request.jwt.claims', true)::jsonb
                            ->> 'tenant_id');

If the data genuinely is public, keep `USING (true)` and record why, so the
next audit does not have to rediscover the decision:

    COMMENT ON POLICY my_policy ON public.my_table IS
        'Intentionally public: reference data, no tenant dimension.';

rls-probe does not read comments to suppress the finding -- a comment is for
the human reading the report.  Use a baseline file to accept it in CI.""",
        references=("https://www.postgresql.org/docs/current/sql-createpolicy.html",),
        severity_notes=(
            "HIGH when the policy applies to PUBLIC or to an exposed role.",
            "MEDIUM when it applies only to roles that are not reachable from the REST layer.",
        ),
        catalogs=("pg_policy.polqual", "pg_policy.polwithcheck", "pg_get_expr"),
    )
)

_register(
    CheckDoc(
        check_id="RLS006",
        title="Policy coverage gap",
        default_severity=Severity.LOW,
        summary="A command has no policy, or writes are checked by a different predicate than reads.",
        mechanism="""\
Policies are per-command.  A table with a single `FOR SELECT` policy has no
policy for INSERT, UPDATE or DELETE, and this check reports three distinct
situations that come out of that.

**Uncovered command.**  With RLS on and no policy for a command, that command
is denied for non-owners.  Fail-closed, so not a leak -- reported for the same
reason as RLS004: it reaches a developer as an unexplained failure, and the
fastest fix is usually the wrong one.

**UPDATE or ALL policy with no WITH CHECK.**  PostgreSQL falls back to the
USING expression and applies it to the *new* row.  For a row-scoped predicate
like `tenant_id = current_tenant()` that is exactly right and needs no action.
It stops being right when USING does not constrain the row at all -- for
instance `USING (EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = auth.uid()))`,
which asks "is this caller a member of anything" and says nothing about the
row in front of it.  Reused as WITH CHECK, that accepts any post-image: the
caller can update a row and set `tenant_id` to a tenant they have nothing to
do with.  rls-probe reports this case at a higher severity when the USING
expression does not mention any column of the table, which is a text-level
heuristic over the deparsed expression, so treat it as a prompt to read the
policy rather than a proof.

**Read/write predicate divergence.**  When the SELECT USING expression and the
INSERT/UPDATE WITH CHECK expression are different, the set of rows a caller
can write is not the set it can read.  Sometimes deliberate -- an append-only
audit table, a draft that becomes visible only once published -- and sometimes
a tenant predicate that was tightened on the read side and forgotten on the
write side.  Worth one look each time it changes.""",
        fix="""\
Add the missing policy, or state the write predicate explicitly rather than
leaning on the USING fallback:

    CREATE POLICY my_table_insert_own
        ON public.my_table
        FOR INSERT
        TO authenticated
        WITH CHECK (user_id = auth.uid());

    ALTER POLICY my_table_update_own ON public.my_table
        USING (user_id = auth.uid())
        WITH CHECK (user_id = auth.uid());

Writing WITH CHECK out even when it duplicates USING is worth the two lines:
it makes the write rule reviewable on its own, and it does not silently change
meaning when someone later edits USING.""",
        references=(
            "https://www.postgresql.org/docs/current/sql-createpolicy.html",
            "https://www.postgresql.org/docs/current/ddl-rowsecurity.html",
        ),
        severity_notes=(
            "MEDIUM for read/write predicate divergence, and for a WITH CHECK "
            "fallback whose USING expression references no column of the table.",
            "LOW for an uncovered command and for an ordinary WITH CHECK fallback.",
        ),
        catalogs=("pg_policy.polcmd", "pg_policy.polwithcheck", "pg_attribute"),
    )
)

_register(
    CheckDoc(
        check_id="RLS007",
        title="SECURITY DEFINER function in an exposed schema",
        default_severity=Severity.HIGH,
        summary="A privilege-escalating function in a schema PostgREST serves is a callable endpoint.",
        mechanism="""\
PostgREST exposes every function in an exposed schema as
`POST /rest/v1/rpc/<name>`.  There is no separate step that publishes a
function: being in the schema is what publishes it, and whether a given
caller may invoke it is decided solely by EXECUTE.

That matters for SECURITY DEFINER functions, which run as their owner instead
of the caller.  A helper written to be called *from inside a policy* --
`is_org_member(org uuid)`, `current_tenant()`, `has_role(text)` -- is a
perfectly reasonable SECURITY DEFINER function, and in the public schema it is
also a public API that anyone can call directly with arguments of their
choosing.  The useful ones are the ones that touch exactly the data the
policies are protecting.

PostgreSQL's default makes this worse than it looks: `EXECUTE` on a new
function is granted to `PUBLIC` automatically.  Unless somebody revoked it,
a SECURITY DEFINER function in `public` is callable by `anon` -- that is,
unauthenticated -- with no grant anywhere in the migration history to notice
during review.""",
        fix="""\
Move helpers out of the exposed schema.  The schema is the boundary:

    CREATE SCHEMA IF NOT EXISTS private;
    REVOKE ALL ON SCHEMA private FROM anon, authenticated;
    ALTER FUNCTION public.is_org_member(uuid) SET SCHEMA private;

Policies can still call `private.is_org_member(...)` -- policy evaluation is
not restricted to exposed schemas, and PostgREST will no longer route to it.
Make sure PostgREST's `db-schemas` / Supabase "Exposed schemas" setting does
not list `private`.

If the function must stay callable over REST, lock the privilege down
explicitly and do not rely on the default:

    REVOKE EXECUTE ON FUNCTION public.do_thing(uuid) FROM PUBLIC, anon;
    GRANT EXECUTE ON FUNCTION public.do_thing(uuid) TO authenticated;

and have the function authorise its own arguments, because a caller chooses
them.""",
        references=(
            "https://docs.postgrest.org/en/stable/references/api/functions.html",
            "https://docs.postgrest.org/en/stable/references/api/schemas.html",
            "https://www.postgresql.org/docs/current/sql-createfunction.html",
        ),
        severity_notes=(
            "HIGH when PUBLIC or an exposed role effectively holds EXECUTE.",
            "MEDIUM when EXECUTE has been revoked from the exposed roles -- the "
            "function is in the wrong schema but is not currently routable.",
        ),
        catalogs=("pg_proc.prosecdef", "pg_proc.proacl", "has_function_privilege"),
    )
)

_register(
    CheckDoc(
        check_id="RLS008",
        title="SECURITY DEFINER function with a mutable search_path",
        default_severity=Severity.HIGH,
        summary="A privilege-escalating function resolves object names using the caller's search_path.",
        mechanism="""\
A SECURITY DEFINER function without a pinned `search_path` resolves every
unqualified name in its body using the search_path of whoever called it.  The
caller controls that setting, so the caller controls which `users` table the
body means, or which `=` operator, or which `lower()` function -- and the body
runs with the owner's privileges.

Concretely: an attacker who can create objects in any schema creates
`evil.users`, sets `search_path = evil, public`, calls the function, and the
owner's privileges are used to read or write the attacker's object, or to run
the attacker's function body.  PostgreSQL 15 removed the default CREATE grant
on `public` for non-owners, which closed off the easiest route on new clusters
-- but clusters upgraded from 14 keep the old permissive grant, and plenty of
schemas hand out CREATE deliberately.

rls-probe reports the function at a higher severity when an exposed role or
PUBLIC actually holds CREATE on a schema that would be searched, because that
is the difference between a latent issue and a reachable one.  It also reports
a function whose *pinned* search_path names a schema those roles can create in,
since pinning to a writable schema pins nothing.""",
        fix="""\
Pin the path on the function.  The safest value is empty, which forces every
name in the body to be schema-qualified:

    ALTER FUNCTION public.do_thing(uuid) SET search_path = '';

If that is too invasive for an existing body, name the schemas explicitly and
put `pg_temp` last so a temporary object cannot shadow anything:

    ALTER FUNCTION public.do_thing(uuid) SET search_path = pg_catalog, public, pg_temp;

Then check that no role you do not trust holds CREATE on those schemas:

    REVOKE CREATE ON SCHEMA public FROM PUBLIC;""",
        references=(
            "https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY",
            "https://www.postgresql.org/docs/current/ddl-schemas.html#DDL-SCHEMAS-PATH",
        ),
        severity_notes=(
            "HIGH when PUBLIC or an exposed role holds CREATE on a schema that "
            "would be searched.",
            "MEDIUM when no such role can create objects anywhere on the path.",
        ),
        catalogs=("pg_proc.prosecdef", "pg_proc.proconfig", "pg_namespace.nspacl"),
    )
)

_register(
    CheckDoc(
        check_id="RLS009",
        title="Privilege granted to an exposed role on an unprotected relation",
        default_severity=Severity.HIGH,
        summary="anon or authenticated holds a privilege on a relation RLS does not cover.",
        mechanism="""\
In a Supabase or PostgREST deployment the access model is two-layered on
purpose: a grant decides whether a role may touch a relation at all, and RLS
decides which rows.  A grant on a relation where the second layer is missing
is therefore the whole story -- the role gets everything.

This check reports the combinations where that applies:

  * a privilege granted to an exposed role on a table with RLS switched off;
  * a privilege granted to an exposed role on a view that is not
    security_invoker, which is RLS001 reached from the grant side and the
    reason that finding is rated CRITICAL rather than theoretical;
  * INSERT, UPDATE, DELETE or TRUNCATE granted to the *anonymous* role, which
    is rarely intended even on a table whose RLS is in good order -- it means
    an unauthenticated HTTP request can write, and the only thing standing in
    its way is the WITH CHECK expression.

A grant to `authenticated` on a table whose RLS is correctly configured is the
normal, intended pattern and is not reported.""",
        fix="""\
Decide which layer you meant.  To keep the grant and add the missing layer:

    ALTER TABLE public.my_table ENABLE ROW LEVEL SECURITY;
    -- plus the policies, see RLS004

To remove the reach instead:

    REVOKE INSERT, UPDATE, DELETE ON public.my_table FROM anon;

Check your default privileges too, since they will re-grant on the next table
you create:

    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        REVOKE INSERT, UPDATE, DELETE ON TABLES FROM anon;""",
        references=(
            "https://www.postgresql.org/docs/current/sql-grant.html",
            "https://docs.postgrest.org/en/stable/explanations/db_authz.html",
        ),
        severity_notes=(
            "CRITICAL for a grant to an exposed role on a table with no RLS.",
            "HIGH for write privileges granted to the anonymous role.",
            "MEDIUM for a grant on a non-security_invoker view, where RLS001 "
            "carries the detail.",
        ),
        catalogs=("pg_class.relacl", "aclexplode", "information_schema.role_table_grants"),
    )
)

_register(
    CheckDoc(
        check_id="RLS010",
        title="EXECUTE or sequence privilege reachable by the anonymous role",
        default_severity=Severity.MEDIUM,
        summary="anon can invoke a state-changing function, or operate a sequence, over REST.",
        mechanism="""\
PostgREST routes `POST /rest/v1/rpc/<name>` to any function the request role
may execute, and PostgreSQL grants EXECUTE on new functions to PUBLIC by
default.  Every VOLATILE function in an exposed schema is therefore an
unauthenticated write endpoint until somebody revokes it -- and because the
privilege arrives by default rather than by a GRANT statement, there is
nothing in the migration history to review.

Volatility is the catalog's only signal here, and it is a one-way one: a
function that writes must be VOLATILE, but a VOLATILE function need not write.
So this check narrows the surface rather than proving a bug, and the finding
says which signal it is resting on.  A volatile SECURITY DEFINER function
reachable by `anon` is the combination worth looking at first, because the
write happens with the owner's privileges.

Sequences are included for the same reason.  `USAGE` or `UPDATE` on a sequence
lets a caller run `nextval()` and `setval()` directly, which leaks roughly how
many rows exist and how fast they are being created, and lets a caller push a
sequence forward or rewind it into a range that collides with existing keys.""",
        fix="""\
Revoke the default and grant deliberately:

    REVOKE EXECUTE ON FUNCTION public.do_thing(uuid) FROM PUBLIC, anon;
    GRANT EXECUTE ON FUNCTION public.do_thing(uuid) TO authenticated;

    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

For sequences, prefer `GENERATED ... AS IDENTITY` or a default of
`nextval(...)` on the column and no sequence privilege for the caller at all:

    REVOKE USAGE, UPDATE ON SEQUENCE public.my_table_id_seq FROM anon;""",
        references=(
            "https://www.postgresql.org/docs/current/sql-grant.html",
            "https://docs.postgrest.org/en/stable/references/api/functions.html",
        ),
        severity_notes=(
            "MEDIUM for a volatile SECURITY DEFINER function reachable by the anonymous role.",
            "LOW for a volatile SECURITY INVOKER function, and for sequence privileges.",
        ),
        catalogs=(
            "pg_proc.provolatile",
            "pg_proc.proacl",
            "pg_class.relacl",
            "has_function_privilege",
        ),
    )
)


def check_ids() -> list[str]:
    return sorted(CHECK_DOCS)


def get_doc(check_id: str) -> CheckDoc:
    key = check_id.strip().upper()
    try:
        return CHECK_DOCS[key]
    except KeyError:
        raise KeyError(
            f"unknown check {check_id!r}; known checks: " + ", ".join(check_ids())
        ) from None
