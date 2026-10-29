# rls-probe

[![CI](https://github.com/Young-Syre/rls-probe/actions/workflows/ci.yml/badge.svg)](https://github.com/Young-Syre/rls-probe/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![PostgreSQL](https://img.shields.io/badge/postgresql-14%20%E2%80%93%2018-336791.svg)](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
[![Dependencies](https://img.shields.io/badge/runtime%20deps-1-success.svg)](pyproject.toml)
[![Read only](https://img.shields.io/badge/access-read--only%20catalog%20SELECTs-success.svg)](#read-only-by-construction)

Audit the row-level-security posture of a PostgreSQL database and report the
misconfigurations that silently defeat RLS. Ten checks, each with the mechanism
spelled out and a remediation snippet for the specific object at fault.

Built for multi-tenant Postgres generally, with specific support for
Supabase and PostgREST deployments, where the schema *is* the API surface.

---

## The one most teams have wrong

**A view over an RLS-protected table bypasses RLS entirely unless it was created
`WITH (security_invoker = on)`.**

A view is not a window onto a table. It is a stored query that someone else
runs for you, and by default PostgreSQL executes it with the privileges of the
*view's owner*, not the caller's. Row-level security is evaluated against the
role actually executing the scan — so for a default view, the policies that get
checked belong to the view owner, and the view owner is usually the same role
that created the table. **Table owners are exempt from their own policies**
unless the table is `FORCE`-enabled.

The result: the view returns every row to every caller. The policies on the
base table are still there, still correct, and simply not the ones being
evaluated.

### Before

```sql
CREATE TABLE invoices (
    invoice_id   bigserial PRIMARY KEY,
    owner_ref    text NOT NULL,
    amount_cents bigint NOT NULL
);

ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;

CREATE POLICY invoices_select_own ON invoices
    FOR SELECT TO authenticated
    USING (owner_ref = auth.uid()::text);

-- Looks harmless. Leaks the entire table.
CREATE VIEW invoice_overview AS
    SELECT invoice_id, owner_ref, amount_cents FROM invoices;

GRANT SELECT ON invoice_overview TO anon, authenticated;
```

Three invoices exist, belonging to three different users. Here is the same
caller, in the same session, querying the table and then the view — run against
the fixture in this repository:

```
rls_probe_fixture=> SET ROLE anon;
rls_probe_fixture=> SELECT set_config('rls_probe.user_id', 'user-a', false);

-- the base table, policies applied
rls_probe_fixture=> SELECT count(*) FROM public.invoices;
 count
-------
     1

-- the view, same caller, same session
rls_probe_fixture=> SELECT count(*) FROM public.invoice_overview;
 count
-------
     3
```

No error, no warning, an ordinary query plan. Just more rows than there should
be. That is the whole failure mode, and it is why this is the one finding
rls-probe rates `CRITICAL`.

### After

```sql
ALTER VIEW invoice_overview SET (security_invoker = on);
```

```
-- the same view, with security_invoker on
rls_probe_fixture=> SELECT count(*) FROM public.invoice_overview_safe;
 count
-------
     1
```

One caveat worth knowing before you ship that `ALTER`: with `security_invoker`
on, the view no longer lends the caller the owner's privileges, so a view that
used to work for `anon` may start returning permission errors until `anon` also
holds `SELECT` on the base table. That error is the fix working.

`security_invoker` requires PostgreSQL 15 or later. On 14 and earlier rls-probe
says so in the report, because there is no `ALTER VIEW` that fixes it:

```
Collection notes
  - Server is PostgreSQL 14.24, which has no security_invoker option (added in
    15). Every view over an RLS table on this server bypasses RLS and cannot be
    fixed with ALTER VIEW; RLS001 findings here need the view's query to enforce
    the predicate itself, a SECURITY INVOKER set-returning function, or an
    upgrade.
```

---

## Checks

| ID | Severity | What it catches | Why RLS still fails |
| --- | --- | --- | --- |
| **RLS001** | CRITICAL | A view whose dependencies include an RLS-enabled table, without `security_invoker = on`. | The view's scans run as the view owner, who as table owner is exempt from the table's own policies. Every row, every caller. |
| **RLS002** | HIGH | A table in a REST-exposed schema with RLS not enabled. | Nothing is filtering rows. The privilege grant is the only gate, and a grant cannot express *which* rows. |
| **RLS003** | MEDIUM | RLS enabled but not `FORCE`d. | `ENABLE` does not apply to the table owner. Migrations, cron jobs and anything sharing the admin DSN read everything. |
| **RLS004** | MEDIUM | RLS enabled with zero policies. | Fail-closed, so nothing leaks — but it surfaces as an unexplained empty response, and the fastest fix is usually `DISABLE` or `USING (true)`. |
| **RLS005** | HIGH | A policy whose `USING` or `WITH CHECK` is literally `true`. | The table reports RLS as enabled and the policy is listed. No row is ever filtered. A scoped `USING` with `WITH CHECK (true)` reads correctly and writes unconstrained. |
| **RLS006** | LOW–MEDIUM | A command with no policy; an `UPDATE`/`ALL` policy relying on the `WITH CHECK` fallback; a write predicate that differs from the read predicate. | A `USING` reused as `WITH CHECK` constrains nothing if it never references the row — a membership test accepts any post-image, so a caller can move a row to another tenant. |
| **RLS007** | HIGH | `SECURITY DEFINER` functions in a PostgREST-exposed schema. | Being in the schema is what publishes a function. A policy helper is also `POST /rest/v1/rpc/<name>`, callable with arguments of the caller's choosing, running as its owner. |
| **RLS008** | HIGH | `SECURITY DEFINER` without a pinned `search_path`, or pinned to a schema the caller can create in. | Unqualified names in the body resolve against the *caller's* `search_path` while the body runs with the owner's privileges. |
| **RLS009** | CRITICAL–MEDIUM | Privileges granted to `anon`/`authenticated` on a relation RLS does not cover; write privileges granted to `anon`. | The Supabase model is grant *plus* RLS. Where the second layer is missing the grant is the whole story, and the role gets every row. |
| **RLS010** | LOW–MEDIUM | `EXECUTE` reachable by `anon` on a `VOLATILE` function in an exposed schema; sequence `USAGE`/`UPDATE` granted to `anon`. | PostgreSQL grants `EXECUTE` on new functions to `PUBLIC` *by default*, so the privilege arrives with no `GRANT` statement in the migration history to review. |

Severities shown are the defaults. Several checks move up or down depending on
whether an exposed role can actually reach the object — a bypassing view nobody
has been granted access to is `HIGH`, not `CRITICAL`; a `SECURITY DEFINER`
function whose `EXECUTE` has been revoked is `MEDIUM`, not `HIGH`. The point is
a report you can triage top-down rather than one that cries wolf.

Run `rls-probe explain <check-id>` for the full mechanism, the severity rules
and the fix. `rls-probe list-checks` lists them all.

---

## Install

```bash
pip install rls-probe
```

Or from a clone:

```bash
git clone https://github.com/Young-Syre/rls-probe
cd rls-probe
pip install -e .
```

Python 3.11+. One runtime dependency, `psycopg[binary]`, bounded to psycopg 3;
everything else is standard library. That is deliberate — the dependency
footprint of a tool you point at a production database is part of its threat
model.

---

## Usage

```bash
# Audit, reading the connection from $DATABASE_URL
rls-probe audit

# Or pass it explicitly
rls-probe audit --dsn postgresql://postgres@localhost:5432/mydb

# Supabase: the pooler DSN from Project Settings -> Database works fine
rls-probe audit --dsn "postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres"

# Narrow it down
rls-probe audit --schema public --schema billing
rls-probe audit --severity-threshold high
rls-probe audit --check RLS001 --check RLS007

# Other formats
rls-probe audit --format json | jq '.findings[] | select(.severity == "CRITICAL")'
rls-probe audit --format markdown > rls-report.md

# Reference
rls-probe list-checks
rls-probe explain RLS001
```

### Matching your deployment

The defaults describe a Supabase project: `public` is the exposed schema,
`anon` and `authenticated` are the request roles, `anon` is the unauthenticated
one. For a hand-rolled PostgREST deployment, or any other naming:

```bash
rls-probe audit \
    --exposed-schema api \
    --exposed-role web_anon --exposed-role web_user \
    --anon-role web_anon
```

Roles that do not exist in the database are reported as a collection note
rather than silently ignored, so a clean run cannot be mistaken for a complete
one.

Two sets of objects are skipped by default, both because findings on them are
not yours to fix: schemas owned by a managed platform (`auth`, `storage`,
`realtime`, `vault`, `extensions`, …) and functions that belong to an
extension. `--include-managed-schemas` and `--include-extension-objects` turn
them back on.

---

## Read-only by construction

rls-probe issues **only `SELECT` statements against `pg_catalog`**. It never
reads application data and never writes anything.

Three things enforce that, rather than one:

1. Every statement in the tool lives in [`src/rls_probe/catalog.py`](src/rls_probe/catalog.py)
   as a named constant. There are eleven of them, and they are all `SELECT` or
   `WITH ... SELECT` over `pg_catalog`.
2. The connection is put into **read-only mode before the first query**
   (`connection.read_only = True`), so the server would reject a write even if
   a future bug in this code attempted one.
3. The test suite asserts both properties — that every SQL constant starts with
   `SELECT`/`WITH` and that none contains a write keyword — so the claim in this
   README fails CI if it stops being true. See
   [`tests/test_catalog_sql.py`](tests/test_catalog_sql.py).

A `statement_timeout` (30s by default, `--statement-timeout`) keeps a run on a
large catalog from sitting on a connection.

The one piece of SQL in this repository that writes anything is
[`tests/sql/fixture.sql`](tests/sql/fixture.sql), which builds a deliberately
vulnerable schema for you to point the tool at. You run that one yourself.

### What it reads

| Catalog | For |
| --- | --- |
| `pg_class.relrowsecurity`, `.relforcerowsecurity` | RLS enabled / forced (RLS002, RLS003) |
| `pg_class.reloptions` | `security_invoker` on views (RLS001) |
| `pg_depend` + `pg_rewrite` | View dependency resolution (RLS001) |
| `pg_policy` + `pg_get_expr` | Policy commands, roles, `USING` and `WITH CHECK` (RLS004–006) |
| `pg_proc.prosecdef`, `.proconfig`, `.provolatile` | `SECURITY DEFINER`, pinned `search_path`, volatility (RLS007, RLS008, RLS010) |
| `aclexplode(pg_class.relacl)` | Direct table, view and sequence grants (RLS009, RLS010) |
| `has_table_privilege`, `has_function_privilege` | Effective privileges, inheritance and default grants included |
| `pg_namespace.nspacl` | Who can create objects on a `search_path` (RLS008) |

View dependencies come from `pg_depend` joined to `pg_rewrite`, **not** from
parsing `pg_views.definition`. The rewrite rule is what the server actually
executes, so aliases, `*` expansion and nested views resolve for free, and a
table name inside a comment or a string literal cannot produce a phantom
dependency. Nested views are followed transitively, because a plain view on top
of a `security_invoker` view still collapses the whole subtree back to the
outer view's owner.

Function `EXECUTE` comes from `has_function_privilege` rather than the ACL,
because the case that matters most has no ACL entry at all: PostgreSQL grants
`EXECUTE` on a new function to `PUBLIC` by default, so `proacl` is `NULL` and
every role can already call it.

---

## CI

Exit `1` on findings, and keep a reviewed baseline so the build only breaks on
*new* ones:

```bash
# Once, after reading every line of what you are accepting
rls-probe audit --write-baseline .rls-probe-baseline.json
git add .rls-probe-baseline.json

# In CI
rls-probe audit --baseline .rls-probe-baseline.json --exit-code
```

```yaml
name: rls

on: [push, pull_request]

jobs:
  rls-probe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"

      - run: pip install rls-probe

      - name: Audit row-level security
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
        run: |
          rls-probe audit \
            --severity-threshold medium \
            --baseline .rls-probe-baseline.json \
            --exit-code \
            --format markdown >> "$GITHUB_STEP_SUMMARY"
```

Point it at a database built from your migrations — a branch database, a
`supabase db reset` in a service container, or a restored dump — rather than at
production. It is read-only, but CI does not need production credentials to
answer this question.

A finding's **fingerprint** is derived from the check id, the object type, the
object name and a discriminator. It deliberately does **not** include the
severity or any prose, so re-rating a check or rewording a message cannot
invalidate a baseline somebody reviewed. Changing the schema can, which is the
point. Baseline entries that stop being reported are counted as resolved, so a
baseline that has drifted out of date tells you so.

---

## Reproducing the findings end to end

[`tests/sql/fixture.sql`](tests/sql/fixture.sql) builds a schema that is unsafe
by construction: an RLS table with a careless write policy, a view over it
without `security_invoker`, a nested view two hops away, a `SECURITY DEFINER`
helper in `public` with an unpinned `search_path`, a `USING (true)` policy, a
coverage gap, a table with no RLS at all granted to `anon`, and a sequence
`anon` can operate. Alongside each one it builds the correctly configured
equivalent, so you can watch the checks stay quiet as well as fire.

```bash
# Against a throwaway container
docker run -d --name rls-probe-demo -e POSTGRES_PASSWORD=probe -p 55432:5432 postgres:18-alpine
export PGPASSWORD=probe

psql -h 127.0.0.1 -p 55432 -U postgres -d postgres -c 'CREATE DATABASE rls_probe_fixture'
psql -h 127.0.0.1 -p 55432 -U postgres -d rls_probe_fixture \
     -v ON_ERROR_STOP=1 -f tests/sql/fixture.sql

rls-probe audit --dsn "postgresql://postgres:probe@127.0.0.1:55432/rls_probe_fixture"

docker rm -f rls-probe-demo
```

Read the header of the fixture before you run it: it creates cluster-wide
roles (`anon`, `authenticated`) and grants `CREATE` on `public` to `PUBLIC` to
reproduce a cluster upgraded from PostgreSQL 14. **Throwaway databases only.**

Verified end to end on three servers: `postgres:14-alpine` (14.24),
`postgres:18-alpine` (18.6), and the Supabase image
`public.ecr.aws/supabase/postgres:17.6.1.111` (17.6). 17 and 18 report the same
29 findings. 14 reports 32 — three more, because on a server without
`security_invoker` the "safe" view cannot be made safe and is correctly flagged
alongside the others.

Here is the real output, from the Supabase 17.6 image:

```
rls-probe row-level-security posture audit

         database : rls_probe_fixture
           server : 17.6
  schemas audited : private, public
  exposed schemas : public
    exposed roles : anon, authenticated
       checks run : 10 (RLS001, RLS002, RLS003, RLS004, RLS005, RLS006, RLS007, RLS008, RLS009, RLS010)

  Read-only: every statement issued was a SELECT against pg_catalog.

Findings

 CRITICAL  RLS001  view public.invoice_overview
    View over an RLS table without security_invoker

    View public.invoice_overview is owned by postgres and reads public.invoices, which
    has row-level security enabled. Without security_invoker the view's scans run as
    postgres, so the base table's policies are evaluated against postgres -- who, as the
    owner, is exempt from them. Every row is returned to every caller. anon,
    authenticated can select from the view, so the bypass is reachable through the API.

    Fix:
      ALTER VIEW public.invoice_overview SET (security_invoker = on);

    Evidence: view_owner=postgres; security_invoker=off;
    rls_tables_read=public.invoices; readable_by=anon, authenticated

    [RLS001 84a2460b064fe9e5]
```

...and the 29 findings it reports in full:

```
CRITICAL RLS001 public.invoice_overview                      View over an RLS table without security_invoker
CRITICAL RLS009 public.audit_log                             anon granted privileges on a table without RLS
CRITICAL RLS009 public.audit_log                             authenticated granted privileges on a table without RLS
HIGH     RLS001 public.invoice_summary                       View over an RLS table without security_invoker
HIGH     RLS002 public.audit_log                             Table in an exposed schema without row-level security
HIGH     RLS005 public.invoices.invoices_insert_any          Policy WITH CHECK expression is literally true
HIGH     RLS005 public.public_posts.public_posts_read_all    Policy USING expression is literally true
HIGH     RLS007 public.is_org_member(org text)               SECURITY DEFINER function in an exposed schema
HIGH     RLS007 public.record_audit(actor text, action text) SECURITY DEFINER function in an exposed schema
HIGH     RLS008 public.is_org_member(org text)               SECURITY DEFINER function with a mutable search_path
HIGH     RLS008 public.record_audit(actor text, action text) SECURITY DEFINER function pinned to a writable schema
HIGH     RLS009 public.invoices                              anon granted write privileges
MEDIUM   RLS004 public.feature_flags                         Row-level security enabled with zero policies
MEDIUM   RLS006 public.documents.documents_all_for_members   Policy relies on the WITH CHECK fallback to USING
MEDIUM   RLS006 public.invoices                              Rows a caller may write are not the rows it may read
MEDIUM   RLS009 public.invoice_overview                      anon granted privileges on a view that bypasses RLS
MEDIUM   RLS009 public.invoice_overview                      authenticated granted privileges on a view that bypasses RLS
MEDIUM   RLS010 public.record_audit(actor text, action text) PUBLIC can execute a state-changing function
LOW      RLS003 public.documents                             Row-level security enabled but not forced
LOW      RLS003 public.feature_flags                         Row-level security enabled but not forced
LOW      RLS003 public.invoices                              Row-level security enabled but not forced
LOW      RLS005 public.invoices.invoices_restrict_nothing    Policy USING expression is literally true
LOW      RLS006 public.invoices                              No policy covers DELETE
LOW      RLS006 public.invoices                              No policy covers UPDATE
LOW      RLS006 public.public_posts                          No policy covers DELETE
LOW      RLS006 public.public_posts                          No policy covers INSERT
LOW      RLS006 public.public_posts                          No policy covers UPDATE
LOW      RLS010 public.audit_log_entry_id_seq                anon can operate a sequence
LOW      RLS010 public.invoices_invoice_id_seq               anon can operate a sequence
```

Two details in that output are worth pointing out, because they are the checks
reasoning rather than pattern-matching:

* `public.invoice_summary` is a view over `invoice_overview`, which is a view
  over `invoices`. The RLS table is two hops away and the dependency is still
  resolved. It is rated `HIGH` rather than `CRITICAL` only because nothing has
  been granted on it.
* The `RLS003` findings are `LOW`, not `MEDIUM`, because this fixture's tables
  are owned by `postgres`, which holds `BYPASSRLS`. `FORCE ROW LEVEL SECURITY`
  would not change what that role sees, and the finding says so instead of
  overstating itself.

The correctly configured objects — `invoice_overview_safe`, `profiles`,
`private.is_org_member` — produce nothing.

---

## Limitations

Worth being straight about, because the gap between what this tool checks and
what you actually need is where the real work is.

**It audits configuration, not policy logic.** Every check here answers a
question about the shape of your setup: is the switch on, is the expression a
placeholder, is the function in the wrong schema. None of them can tell you
whether `USING (org_id = current_org())` is comparing the right column. A policy
can be structurally perfect — enabled, forced, covering every command, with a
`WITH CHECK` written out in full — and still join through the wrong table, or
compare `user_id` where it meant `owner_id`, or trust a JWT claim the client
controls. No tool will tell you your tenant predicate is wrong. Read the
policies.

**`USING (true)` is matched literally.** `1 = 1`, `current_user IS NOT NULL`
and `(SELECT true)` are all equally unfiltered and all equally not detected.
Deciding that an arbitrary expression is always true is a judgement about SQL
semantics that this tool deliberately does not make, because being wrong in
either direction is worse than being silent.

**Column references are detected by text.** The RLS006 rating that separates a
row-scoped `USING` from a membership test searches the deparsed expression for
column names. A column named like a function, or an unusual quoting style, can
fool it either way. That finding is a prompt to read the policy, and says so.

**Volatility is a proxy for "this writes".** A function that modifies the
database must be `VOLATILE`, so RLS010 uses it to narrow the surface — but
plenty of `VOLATILE` functions are read-only. The finding states which signal
it rests on.

**Materialized views are not covered by RLS001.** They do not support
`security_invoker`, and they are populated by their owner at refresh time, so
the base table's policies never apply to the stored contents. That is a
different problem with a different fix (do not put tenant-scoped data in a
matview), and rls-probe does not currently report it.

**Static only.** It reads the catalogs. It does not issue a request as `anon`
to see what actually comes back, and it cannot see anything your application
layer adds on top.

---

## Development

```bash
git clone https://github.com/Young-Syre/rls-probe
cd rls-probe
pip install -e '.[dev]'

pytest          # 206 tests, 245 assertions, all offline
ruff check .
ruff format --check .
```

Every check is a pure function from a `Snapshot` of catalog rows to a list of
`Finding`s — no connection, no I/O, no global state. That is what lets the
whole suite run with no database: the tests build the handful of rows a check
looks at and assert on what it says. Each check is tested against both the
vulnerable and the safe case, including the ones that are easy to get wrong:
the nested view dependency, the cycle guard, a `security_invoker` view that
should stay quiet, a restrictive `USING (true)` that is dead weight rather than
a hole, the `WITH CHECK` fallback that is fine and the one that is not.

Layout:

```
src/rls_probe/
    model.py      catalog row types, Snapshot, Finding, Severity
    catalog.py    every SQL statement the tool issues, and the collector
    checks.py     the ten checks, as pure functions
    knowledge.py  per-check reference text for `explain`
    audit.py      collect -> check -> threshold -> baseline
    baseline.py   fingerprints, load/write/diff
    report.py     text, JSON and Markdown renderers
    cli.py        argparse
```

Adding a check means a function in `checks.py`, an entry in its registry, a
`CheckDoc` in `knowledge.py`, and tests for both the vulnerable and the safe
case. If it needs catalog data that is not collected yet, the query goes in
`catalog.py` with a comment on why it is written that way.

---

## References

Row-level security and policies:

- [PostgreSQL: Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL: `CREATE POLICY`](https://www.postgresql.org/docs/current/sql-createpolicy.html)
- [PostgreSQL: `ALTER TABLE` — `ENABLE`/`FORCE ROW LEVEL SECURITY`](https://www.postgresql.org/docs/current/sql-altertable.html)

Views and `security_invoker`:

- [PostgreSQL: `CREATE VIEW` — `security_invoker`](https://www.postgresql.org/docs/current/sql-createview.html#SQL-CREATEVIEW-SECURITY-INVOKER)

Functions, `SECURITY DEFINER` and `search_path`:

- [PostgreSQL: `CREATE FUNCTION` — writing `SECURITY DEFINER` functions safely](https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY)
- [PostgreSQL: Schemas and the search path](https://www.postgresql.org/docs/current/ddl-schemas.html#DDL-SCHEMAS-PATH)

Schema exposure over REST:

- [PostgREST: Schemas](https://docs.postgrest.org/en/stable/references/api/schemas.html)
- [PostgREST: Stored procedures as endpoints](https://docs.postgrest.org/en/stable/references/api/functions.html)
- [PostgREST: Database authorization](https://docs.postgrest.org/en/stable/explanations/db_authz.html)
- [Supabase: Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)

---

## License

MIT. Copyright (c) 2026 David Nichols.
