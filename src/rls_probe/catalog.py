"""Reading the PostgreSQL system catalogs into a :class:`~rls_probe.model.Snapshot`.

This module holds every SQL statement rls-probe issues.  All of them are
SELECTs against ``pg_catalog``; none of them touch user data, and the session
is put into read-only mode before the first one runs.

The queries are the substance of the tool, so a few notes on why they look the
way they do:

* View dependencies come from ``pg_depend`` joined to ``pg_rewrite``, not from
  parsing ``pg_views.definition``.  The rewrite rule is what the server
  actually executes, so it resolves aliases, nested views and ``*`` expansion
  for free, and cannot be fooled by SQL that merely mentions a table name in a
  comment or a string literal.
* Relation grants come from ``aclexplode(pg_class.relacl)`` rather than
  ``information_schema.role_table_grants``.  The two agree on direct grants --
  the information_schema view is defined over the same ACL -- but aclexplode
  gives the grantee as an oid, so PUBLIC (oid 0) is distinguishable from a role
  that happens to be called "public", and it is one join instead of six.
* Function grants come from ``has_function_privilege`` instead of the ACL,
  because the case that matters most has no ACL entry: PostgreSQL grants
  EXECUTE on a new function to PUBLIC by default, so ``proacl`` is NULL and
  every role can already call it.
"""

from __future__ import annotations

import re
from typing import Any

from .model import (
    Policy,
    Relation,
    RelationColumn,
    RelationGrant,
    Routine,
    RoutineGrant,
    SchemaInfo,
    Snapshot,
)

#: Relation kinds rls-probe knows how to reason about.
AUDITED_RELKINDS = ("r", "p", "v", "m", "f", "S")

#: Schemas that are never the application's to fix.
SYSTEM_SCHEMAS = ("pg_catalog", "information_schema")

#: Schemas created and owned by a managed platform.  Auditing these produces
#: findings the operator of the database cannot act on -- you do not get to
#: ALTER Supabase's auth schema -- so they are skipped unless asked for.
MANAGED_SCHEMAS = (
    "auth",
    "cron",
    "extensions",
    "graphql",
    "graphql_public",
    "net",
    "pgbouncer",
    "pgsodium",
    "pgsodium_masks",
    "realtime",
    "storage",
    "supabase_functions",
    "supabase_migrations",
    "vault",
    "_analytics",
    "_realtime",
    "_supavisor",
)

#: PostgREST's own default, and Supabase's.
DEFAULT_EXPOSED_SCHEMAS = ("public",)

#: Supabase's request roles.  Harmless on a database that has neither.
DEFAULT_EXPOSED_ROLES = ("anon", "authenticated")
DEFAULT_ANONYMOUS_ROLES = ("anon",)

TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE")

#: ``security_invoker = on`` arrived in PostgreSQL 15.
SECURITY_INVOKER_MIN_VERSION = 150000


# ---------------------------------------------------------------------------
# reloptions parsing
# ---------------------------------------------------------------------------


def parse_reloptions(options: list[str] | None) -> dict[str, str]:
    """``{"security_invoker=true"}`` -> ``{"security_invoker": "true"}``."""
    parsed: dict[str, str] = {}
    for entry in options or ():
        key, _, value = entry.partition("=")
        parsed[key.strip().lower()] = value.strip()
    return parsed


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

SQL_SERVER_INFO = """
SELECT current_database()                       AS database,
       current_setting('server_version')        AS server_version,
       current_setting('server_version_num')::int AS server_version_num,
       current_user                             AS current_user
"""

SQL_SCHEMAS = """
SELECT n.oid,
       n.nspname AS name,
       pg_catalog.pg_get_userbyid(n.nspowner) AS owner,
       ARRAY(
           SELECT CASE
                      WHEN a.grantee = 0 THEN 'PUBLIC'
                      ELSE pg_catalog.pg_get_userbyid(a.grantee)
                  END
           FROM pg_catalog.aclexplode(
                    COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))
                ) AS a
           WHERE a.privilege_type = 'CREATE'
       ) AS create_grantees
FROM pg_catalog.pg_namespace n
WHERE n.nspname !~ '^pg_'
  AND n.nspname <> 'information_schema'
ORDER BY n.nspname
"""

# Relations in the audited schemas.  reloptions carries security_invoker for
# views; relrowsecurity / relforcerowsecurity carry the two RLS switches, which
# are genuinely independent and are the reason RLS003 exists.
SQL_RELATIONS = """
SELECT c.oid,
       n.nspname AS schema,
       c.relname AS name,
       c.relkind AS kind,
       pg_catalog.pg_get_userbyid(c.relowner) AS owner,
       c.relrowsecurity      AS rls_enabled,
       c.relforcerowsecurity AS rls_forced,
       c.reloptions,
       COALESCE(o.rolsuper OR o.rolbypassrls, false) AS owner_bypasses_rls
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_catalog.pg_roles o ON o.oid = c.relowner
WHERE c.relkind = ANY(%(relkinds)s)
  AND n.nspname = ANY(%(schemas)s)
ORDER BY n.nspname, c.relname
"""

# Same shape, by oid, for relations an audited view depends on that fall
# outside the schema filter.  They are needed to answer "does this view read an
# RLS table" correctly, and are marked out of scope so they are not themselves
# audited.
SQL_RELATIONS_BY_OID = """
SELECT c.oid,
       n.nspname AS schema,
       c.relname AS name,
       c.relkind AS kind,
       pg_catalog.pg_get_userbyid(c.relowner) AS owner,
       c.relrowsecurity      AS rls_enabled,
       c.relforcerowsecurity AS rls_forced,
       c.reloptions,
       COALESCE(o.rolsuper OR o.rolbypassrls, false) AS owner_bypasses_rls
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_catalog.pg_roles o ON o.oid = c.relowner
WHERE c.oid = ANY(%(oids)s)
ORDER BY n.nspname, c.relname
"""

# polroles is an oid[]; oid 0 means PUBLIC, which is not a row in pg_roles.
# pg_get_expr deparses the stored node trees back into the SQL the policy was
# written with, which is what makes RLS005 and RLS006 possible at all.
SQL_POLICIES = """
SELECT pol.oid,
       pol.polname AS name,
       pol.polrelid AS table_oid,
       n.nspname AS table_schema,
       c.relname AS table_name,
       pol.polcmd AS command,
       pol.polpermissive AS permissive,
       ARRAY(
           SELECT CASE
                      WHEN role_oid = 0 THEN 'PUBLIC'
                      ELSE pg_catalog.pg_get_userbyid(role_oid)
                  END
           FROM pg_catalog.unnest(pol.polroles) AS t(role_oid)
           ORDER BY 1
       ) AS roles,
       pg_catalog.pg_get_expr(pol.polqual, pol.polrelid)      AS using_expr,
       pg_catalog.pg_get_expr(pol.polwithcheck, pol.polrelid) AS check_expr
FROM pg_catalog.pg_policy pol
JOIN pg_catalog.pg_class c ON c.oid = pol.polrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = ANY(%(schemas)s)
ORDER BY n.nspname, c.relname, pol.polname
"""

# prosecdef is SECURITY DEFINER; proconfig holds the per-function SET clauses,
# which is where a pinned search_path lives.  Extension-owned functions are
# excluded by default: pg_depend deptype 'e' means the function belongs to an
# extension, and nobody is going to ALTER pgcrypto to satisfy an audit.
SQL_ROUTINES = """
SELECT p.oid,
       n.nspname AS schema,
       p.proname AS name,
       pg_catalog.pg_get_function_identity_arguments(p.oid) AS identity_arguments,
       pg_catalog.pg_get_userbyid(p.proowner) AS owner,
       p.prosecdef AS security_definer,
       p.provolatile AS volatility,
       p.prokind AS kind,
       p.proconfig AS config
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = ANY(%(schemas)s)
  AND p.prokind = ANY(ARRAY['f', 'p'])
  AND (
        %(include_extension_objects)s
        OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_depend d
            WHERE d.classid = 'pg_catalog.pg_proc'::regclass
              AND d.objid = p.oid
              AND d.deptype = 'e'
        )
      )
ORDER BY n.nspname, p.proname
"""

SQL_COLUMNS = """
SELECT a.attrelid AS relation_oid,
       a.attname  AS name
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE a.attnum > 0
  AND NOT a.attisdropped
  AND c.relkind = ANY(ARRAY['r', 'p'])
  AND n.nspname = ANY(%(schemas)s)
ORDER BY a.attrelid, a.attnum
"""

# Direct grants only.  relacl is NULL when nobody has been granted anything, in
# which case aclexplode yields no rows and the LATERAL join drops the relation,
# which is the correct answer: there is no grant to report.
SQL_RELATION_GRANTS = """
SELECT c.oid AS relation_oid,
       CASE
           WHEN a.grantee = 0 THEN 'PUBLIC'
           ELSE pg_catalog.pg_get_userbyid(a.grantee)
       END AS grantee,
       a.privilege_type AS privilege
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) AS a
WHERE c.relkind = ANY(%(relkinds)s)
  AND n.nspname = ANY(%(schemas)s)
ORDER BY c.oid, grantee, privilege
"""

# Effective privileges, inheritance included, for the roles a request can
# arrive as.  has_table_privilege answers the question the HTTP layer asks.
SQL_EFFECTIVE_RELATION_PRIVILEGES = """
SELECT c.oid AS relation_oid,
       r.rolname AS grantee,
       p.privilege
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN pg_catalog.pg_roles r
CROSS JOIN pg_catalog.unnest(%(privileges)s::text[]) AS p(privilege)
WHERE c.relkind = ANY(%(relkinds)s)
  AND n.nspname = ANY(%(schemas)s)
  AND r.rolname = ANY(%(roles)s)
  AND pg_catalog.has_table_privilege(r.oid, c.oid, p.privilege)
ORDER BY c.oid, r.rolname, p.privilege
"""

# EXECUTE, effective. The UNION ALL arm adds PUBLIC, which has no pg_roles row;
# COALESCE to acldefault is what catches the default grant on a function whose
# proacl was never touched.
SQL_ROUTINE_GRANTS = """
WITH target AS (
    SELECT p.oid, p.proacl, p.proowner
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = ANY(%(schemas)s)
      AND p.prokind = ANY(ARRAY['f', 'p'])
)
SELECT t.oid AS routine_oid,
       r.rolname AS grantee,
       EXISTS (
           SELECT 1
           FROM pg_catalog.aclexplode(t.proacl) AS a
           WHERE a.grantee = r.oid
             AND a.privilege_type = 'EXECUTE'
       ) AS direct
FROM target t
CROSS JOIN pg_catalog.pg_roles r
WHERE r.rolname = ANY(%(roles)s)
  AND pg_catalog.has_function_privilege(r.oid, t.oid, 'EXECUTE')
UNION ALL
SELECT t.oid AS routine_oid,
       'PUBLIC' AS grantee,
       (t.proacl IS NOT NULL) AS direct
FROM target t
WHERE EXISTS (
    SELECT 1
    FROM pg_catalog.aclexplode(
             COALESCE(t.proacl, pg_catalog.acldefault('f', t.proowner))
         ) AS a
    WHERE a.grantee = 0
      AND a.privilege_type = 'EXECUTE'
)
ORDER BY routine_oid, grantee
"""

# The authoritative answer to "what does this view read".  pg_rewrite holds the
# view's _RETURN rule; pg_depend records that rule's normal ('n') dependencies
# on the relations it scans.  The rule's own internal ('i') dependency on the
# view it belongs to is excluded by both the deptype filter and the explicit
# inequality, so a view never appears to depend on itself.
SQL_VIEW_DEPENDENCIES = """
SELECT DISTINCT
       r.ev_class  AS view_oid,
       d.refobjid  AS referenced_oid
FROM pg_catalog.pg_depend d
JOIN pg_catalog.pg_rewrite r ON r.oid = d.objid
JOIN pg_catalog.pg_class v ON v.oid = r.ev_class
JOIN pg_catalog.pg_namespace vn ON vn.oid = v.relnamespace
WHERE d.classid = 'pg_catalog.pg_rewrite'::regclass
  AND d.refclassid = 'pg_catalog.pg_class'::regclass
  AND r.rulename = '_RETURN'
  AND d.deptype = 'n'
  AND d.refobjid <> r.ev_class
  AND v.relkind = ANY(ARRAY['v', 'm'])
ORDER BY view_oid, referenced_oid
"""


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


class CatalogError(RuntimeError):
    pass


def resolve_schemas(
    connection: Any,
    requested: tuple[str, ...] | None,
    include_managed: bool,
) -> tuple[str, ...]:
    """Which schemas to audit.

    An explicit ``--schema`` is taken literally, including a managed schema if
    that is what was asked for.  With no filter, every schema in the database is
    audited except the system ones and, unless asked for, the ones a managed
    platform owns.
    """
    if requested:
        return tuple(dict.fromkeys(requested))

    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT n.nspname
            FROM pg_catalog.pg_namespace n
            WHERE n.nspname !~ '^pg_'
              AND n.nspname <> 'information_schema'
            ORDER BY n.nspname
            """
        )
        names = [row[0] for row in cursor.fetchall()]

    skip = set(SYSTEM_SCHEMAS) | (set() if include_managed else set(MANAGED_SCHEMAS))
    return tuple(name for name in names if name not in skip)


def _rows(
    connection: Any, sql: str, params: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    with connection.cursor() as cursor:
        # Pass None rather than {} when there are no parameters: psycopg only
        # scans a statement for placeholders when parameters are supplied.
        cursor.execute(sql, params if params else None)
        columns = [description[0] for description in cursor.description]
        return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]


def _relation_from_row(row: dict[str, Any], in_scope: bool) -> Relation:
    return Relation(
        oid=row["oid"],
        schema=row["schema"],
        name=row["name"],
        kind=row["kind"],
        owner=row["owner"] or "",
        rls_enabled=bool(row["rls_enabled"]),
        rls_forced=bool(row["rls_forced"]),
        reloptions=parse_reloptions(row["reloptions"]),
        owner_bypasses_rls=bool(row["owner_bypasses_rls"]),
        in_scope=in_scope,
    )


def collect(
    connection: Any,
    *,
    schemas: tuple[str, ...] | None = None,
    exposed_schemas: tuple[str, ...] = DEFAULT_EXPOSED_SCHEMAS,
    exposed_roles: tuple[str, ...] = DEFAULT_EXPOSED_ROLES,
    anonymous_roles: tuple[str, ...] = DEFAULT_ANONYMOUS_ROLES,
    include_managed_schemas: bool = False,
    include_extension_objects: bool = False,
) -> tuple[Snapshot, list[str]]:
    """Read the catalogs into a snapshot.

    Returns the snapshot and a list of human-readable notes about the
    collection itself -- a server too old for ``security_invoker``, an exposed
    role that does not exist -- which the report prints so that a clean run
    cannot be mistaken for a complete one.
    """
    notes: list[str] = []

    info = _rows(connection, SQL_SERVER_INFO)[0]
    if info["server_version_num"] < SECURITY_INVOKER_MIN_VERSION:
        notes.append(
            f"Server is PostgreSQL {info['server_version']}, which has no "
            f"security_invoker option (added in 15). Every view over an RLS table on "
            f"this server bypasses RLS and cannot be fixed with ALTER VIEW; RLS001 "
            f"findings here need the view's query to enforce the predicate itself, a "
            f"SECURITY INVOKER set-returning function, or an upgrade."
        )

    audited = resolve_schemas(connection, schemas, include_managed_schemas)
    if not audited:
        raise CatalogError(
            "no schemas to audit: the --schema filter matched nothing, or the database "
            "has only system and managed schemas"
        )

    existing_roles = {
        row["rolname"] for row in _rows(connection, "SELECT rolname FROM pg_catalog.pg_roles")
    }
    missing = [role for role in exposed_roles if role not in existing_roles]
    if missing:
        notes.append(
            f"Exposed role(s) not present in this database: {', '.join(missing)}. "
            f"Checks that depend on them (RLS009, RLS010, and the severity of RLS001, "
            f"RLS002, RLS007 and RLS008) will report less than they would against the "
            f"deployment those roles belong to. Use --exposed-role to name the roles "
            f"your API actually connects as."
        )
    live_exposed = tuple(role for role in exposed_roles if role in existing_roles)

    unknown_exposed_schemas = [s for s in exposed_schemas if s not in audited]
    if unknown_exposed_schemas:
        notes.append(
            f"Exposed schema(s) not in the audited set: "
            f"{', '.join(unknown_exposed_schemas)}. They either do not exist or were "
            f"excluded by --schema, so nothing in them was examined."
        )

    relkinds = list(AUDITED_RELKINDS)
    schema_params = {"schemas": list(audited)}

    relations = [
        _relation_from_row(row, in_scope=True)
        for row in _rows(connection, SQL_RELATIONS, {"relkinds": relkinds, **schema_params})
    ]
    known_oids = {relation.oid for relation in relations}

    dependencies: dict[int, set[int]] = {}
    for row in _rows(connection, SQL_VIEW_DEPENDENCIES):
        dependencies.setdefault(row["view_oid"], set()).add(row["referenced_oid"])

    # Pull in anything an audited view reads that the schema filter excluded,
    # so "does this view read an RLS table" is answered from the whole graph.
    reachable: set[int] = set()
    frontier = [oid for oid in dependencies if oid in known_oids]
    seen_views: set[int] = set()
    while frontier:
        oid = frontier.pop()
        if oid in seen_views:
            continue
        seen_views.add(oid)
        for referenced in dependencies.get(oid, ()):
            reachable.add(referenced)
            if referenced in dependencies:
                frontier.append(referenced)

    extra_oids = sorted(reachable - known_oids)
    if extra_oids:
        relations.extend(
            _relation_from_row(row, in_scope=False)
            for row in _rows(connection, SQL_RELATIONS_BY_OID, {"oids": extra_oids})
        )

    policies = [
        Policy(
            oid=row["oid"],
            name=row["name"],
            table_oid=row["table_oid"],
            table_schema=row["table_schema"],
            table_name=row["table_name"],
            command=row["command"],
            permissive=bool(row["permissive"]),
            roles=tuple(row["roles"] or ()),
            using_expr=row["using_expr"],
            check_expr=row["check_expr"],
        )
        for row in _rows(connection, SQL_POLICIES, schema_params)
    ]

    routines = [
        Routine(
            oid=row["oid"],
            schema=row["schema"],
            name=row["name"],
            identity_arguments=row["identity_arguments"] or "",
            owner=row["owner"] or "",
            security_definer=bool(row["security_definer"]),
            volatility=row["volatility"],
            kind=row["kind"],
            config=tuple(row["config"] or ()),
        )
        for row in _rows(
            connection,
            SQL_ROUTINES,
            {"include_extension_objects": include_extension_objects, **schema_params},
        )
    ]

    schema_infos = [
        SchemaInfo(
            oid=row["oid"],
            name=row["name"],
            owner=row["owner"] or "",
            create_grantees=tuple(row["create_grantees"] or ()),
        )
        for row in _rows(connection, SQL_SCHEMAS)
    ]

    columns = [
        RelationColumn(relation_oid=row["relation_oid"], name=row["name"])
        for row in _rows(connection, SQL_COLUMNS, schema_params)
    ]

    relation_grants = [
        RelationGrant(
            relation_oid=row["relation_oid"],
            grantee=row["grantee"],
            privilege=row["privilege"],
        )
        for row in _rows(
            connection, SQL_RELATION_GRANTS, {"relkinds": relkinds, **schema_params}
        )
    ]

    routine_grants = [
        RoutineGrant(
            routine_oid=row["routine_oid"],
            grantee=row["grantee"],
            direct=bool(row["direct"]),
        )
        for row in _rows(
            connection, SQL_ROUTINE_GRANTS, {"roles": list(live_exposed), **schema_params}
        )
    ]

    effective: dict[tuple[int, str], set[str]] = {}
    if live_exposed:
        for row in _rows(
            connection,
            SQL_EFFECTIVE_RELATION_PRIVILEGES,
            {
                "relkinds": [k for k in relkinds if k != "S"],
                "privileges": list(TABLE_PRIVILEGES),
                "roles": list(live_exposed),
                **schema_params,
            },
        ):
            effective.setdefault((row["relation_oid"], row["grantee"]), set()).add(
                row["privilege"]
            )

    snapshot = Snapshot(
        relations=relations,
        policies=policies,
        routines=routines,
        schemas=schema_infos,
        columns=columns,
        relation_grants=relation_grants,
        routine_grants=routine_grants,
        view_dependencies=dependencies,
        exposed_roles=live_exposed,
        anonymous_roles=tuple(r for r in anonymous_roles if r in existing_roles),
        exposed_schemas=tuple(exposed_schemas),
        effective_relation_privileges={
            key: frozenset(value) for key, value in effective.items()
        },
        database=info["database"],
        server_version=info["server_version"],
    )
    return snapshot, notes


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

_DSN_PASSWORD = re.compile(r"(?i)(password=)[^\s&]*")


def redact_dsn(dsn: str) -> str:
    """Keep a DSN printable.

    This value goes in the report header, which is the part people paste into
    tickets, so every place libpq accepts a password has to be covered -- not
    only the userinfo field.  ``password=`` in a URI query string is a legal
    libpq form, and it used to survive both branches: a URL with no ``@`` was
    returned untouched, and a URL with one had only its userinfo redacted while
    ``?password=`` went out verbatim.

    Other query parameters are kept, because ``sslmode`` and friends are worth
    seeing in a report header and carry nothing secret.
    """
    if "://" in dsn:
        scheme, _, rest = dsn.partition("://")
        authority, question, query = rest.partition("?")
        if "@" in authority:
            credentials, _, host = authority.partition("@")
            user, sep, _ = credentials.partition(":")
            if sep:
                authority = f"{user}:***@{host}"
        if question:
            query = _DSN_PASSWORD.sub(r"\1***", query)
        return f"{scheme}://{authority}{question}{query}"
    return _DSN_PASSWORD.sub(r"\1***", dsn)


def connect(dsn: str | None, *, statement_timeout_ms: int = 30_000) -> Any:
    """Open a read-only connection.

    ``read_only`` is set on the connection before any statement runs, so the
    server rejects any write this process might attempt -- including one from a
    future bug in this code.  It is belt and braces on top of the fact that
    every statement here is a catalog SELECT.
    """
    try:
        import psycopg
    except ModuleNotFoundError as exc:  # pragma: no cover - import guard
        raise CatalogError(
            "psycopg is required to talk to a database: pip install 'psycopg[binary]'"
        ) from exc

    connection = psycopg.connect(dsn) if dsn else psycopg.connect()
    connection.read_only = True
    connection.autocommit = False
    with connection.cursor() as cursor:
        # SET does not take parameters, so go through set_config, which does.
        #
        # is_local is false deliberately, which makes the setting session-wide
        # rather than transaction-local.  autocommit is off, so a local setting
        # would be reverted at the first commit and every later transaction
        # would run with the server's default timeout -- which is the opposite
        # of the intent.  The connection is opened and owned here and is
        # read-only, so a session-wide setting affects nothing else.
        cursor.execute(
            "SELECT pg_catalog.set_config('statement_timeout', %s, false)",
            (str(int(statement_timeout_ms)),),
        )
    return connection
