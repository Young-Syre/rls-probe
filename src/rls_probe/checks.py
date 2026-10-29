"""The checks.

Every check is a pure function from a :class:`~rls_probe.model.Snapshot` to a
list of :class:`~rls_probe.model.Finding`.  No connections, no I/O, no global
state -- which is what lets the test suite exercise all ten of them against
hand-built catalog rows with no database in sight.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable

from .model import (
    DML_COMMANDS,
    Finding,
    Policy,
    Relation,
    Severity,
    Snapshot,
)

#: Privileges that let a caller change rows.
WRITE_PRIVILEGES = ("INSERT", "UPDATE", "DELETE", "TRUNCATE")

#: Relation privilege required for each DML command.
PRIVILEGE_FOR_COMMAND = {
    "SELECT": "SELECT",
    "INSERT": "INSERT",
    "UPDATE": "UPDATE",
    "DELETE": "DELETE",
}


# ---------------------------------------------------------------------------
# Expression helpers
# ---------------------------------------------------------------------------


def strip_outer_parens(expr: str) -> str:
    """Remove balanced parentheses wrapping the whole expression.

    ``pg_get_expr`` parenthesises generously, so ``USING (true)`` can come back
    as ``true`` or ``(true)`` depending on how the expression was written and
    which server version deparsed it.
    """
    text = expr.strip()
    while text.startswith("(") and text.endswith(")"):
        depth = 0
        for index, char in enumerate(text):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and index != len(text) - 1:
                    # The leading "(" closes before the end, so the outer
                    # parens are not a single wrapper: "(a) AND (b)".
                    return text
        text = text[1:-1].strip()
    return text


def is_literally_true(expr: str | None) -> bool:
    """Whether a deparsed policy expression is the constant true.

    Only the literal is matched.  An expression that is *provably* always true
    for other reasons -- ``1 = 1``, ``current_user IS NOT NULL`` -- is a
    judgement call about SQL semantics that this tool does not make, and
    claiming otherwise would be the sort of silent over-reach that makes a
    scanner untrustworthy.
    """
    if expr is None:
        return False
    return strip_outer_parens(expr).lower() == "true"


def normalize_expr(expr: str | None) -> str | None:
    """Whitespace-normalised form, for comparing two expressions for sameness."""
    if expr is None:
        return None
    return re.sub(r"\s+", " ", strip_outer_parens(expr)).strip()


def references_any_column(expr: str | None, columns: Iterable[str]) -> bool:
    """Whether a deparsed expression mentions any column of the relation.

    A text-level heuristic over ``pg_get_expr`` output, used to tell a
    row-scoped predicate from one that only asks a question about the caller.
    It can be fooled -- a column named the same as a function, a quoted
    identifier -- so the findings that use it say they are a prompt to read the
    policy, not a verdict on it.
    """
    if expr is None:
        return False
    for column in columns:
        if not column:
            continue
        if re.search(rf"\b{re.escape(column)}\b", expr):
            return True
    return False


def _effective_check(policy: Policy) -> str | None:
    """The expression a write is actually validated against.

    For UPDATE and ALL policies with no WITH CHECK clause, PostgreSQL reuses
    the USING expression and applies it to the new row.
    """
    if policy.check_expr is not None:
        return policy.check_expr
    if policy.command in ("*", "w"):
        return policy.using_expr
    return None


def _policy_reaches_exposed_role(snapshot: Snapshot, policy: Policy) -> bool:
    if "PUBLIC" in policy.roles:
        return True
    return any(role in snapshot.exposed_roles for role in policy.roles)


def _format_roles(roles: Iterable[str]) -> str:
    listed = list(roles)
    return ", ".join(listed) if listed else "(none)"


def _reachable_by_exposed_role(snapshot: Snapshot, relation: Relation) -> dict[str, set[str]]:
    """Exposed roles that can touch a relation, direct grants or inherited."""
    reach = snapshot.exposed_grantees_on(relation.oid)
    for role, privs in snapshot.exposed_effective_on(relation.oid).items():
        if role in snapshot.exposed_roles and privs:
            reach.setdefault(role, set()).update(privs)
    return reach


# ---------------------------------------------------------------------------
# RLS001 -- view over an RLS table without security_invoker
# ---------------------------------------------------------------------------


def check_rls001(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    for view in snapshot.views():
        if view.security_invoker:
            continue

        direct = snapshot.view_dependencies.get(view.oid, set())
        protected: list[tuple[Relation, bool]] = []
        for oid in snapshot.resolve_view_dependencies(view.oid):
            dep = snapshot.relation(oid)
            if dep is not None and dep.is_table and dep.rls_enabled:
                protected.append((dep, oid in direct))
        if not protected:
            continue

        protected.sort(key=lambda item: item[0].qualified)
        names = ", ".join(
            dep.qualified if is_direct else f"{dep.qualified} (via a nested view)"
            for dep, is_direct in protected
        )
        reach = _reachable_by_exposed_role(snapshot, view)
        severity = Severity.CRITICAL if reach else Severity.HIGH

        if reach:
            reachability = (
                f"{_format_roles(sorted(reach))} can select from the view, so the bypass "
                f"is reachable through the API."
            )
        else:
            reachability = (
                "No exposed role currently holds a privilege on the view, so the bypass "
                "is not reachable from the REST layer yet -- but it is one GRANT away."
            )

        findings.append(
            Finding(
                check_id="RLS001",
                title="View over an RLS table without security_invoker",
                severity=severity,
                obj=view.qualified,
                obj_type="view",
                detail=(
                    f"View {view.qualified} is owned by {view.owner} and reads "
                    f"{names}, which has row-level security enabled. Without "
                    f"security_invoker the view's scans run as {view.owner}, so the base "
                    f"table's policies are evaluated against {view.owner} -- who, as the "
                    f"owner, is exempt from them. Every row is returned to every caller. "
                    f"{reachability}"
                ),
                remediation=f"ALTER VIEW {view.qualified} SET (security_invoker = on);",
                evidence={
                    "view_owner": view.owner,
                    "security_invoker": "off",
                    "rls_tables_read": names,
                    "readable_by": _format_roles(sorted(reach)),
                },
            )
        )
    return findings


# ---------------------------------------------------------------------------
# RLS002 -- table in an exposed schema with RLS disabled
# ---------------------------------------------------------------------------


def check_rls002(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    for table in snapshot.tables():
        if table.rls_enabled or not snapshot.is_exposed_schema(table.schema):
            continue

        reach = _reachable_by_exposed_role(snapshot, table)
        public_grants = snapshot.exposed_grantees_on(table.oid).get("PUBLIC", set())
        if public_grants:
            reach.setdefault("PUBLIC", set()).update(public_grants)

        if reach:
            severity = Severity.HIGH
            detail_tail = (
                f"{_format_roles(sorted(reach))} hold privileges on it, and "
                f"{table.schema} is served over REST, so GET /rest/v1/{table.name} "
                f"returns the whole table."
            )
        else:
            severity = Severity.MEDIUM
            detail_tail = (
                "No exposed role holds a privilege on it today, so there is no open "
                "endpoint yet; the table is one GRANT away from being one, and the "
                "grant is the easy part to add without noticing."
            )

        findings.append(
            Finding(
                check_id="RLS002",
                title="Table in an exposed schema without row-level security",
                severity=severity,
                obj=table.qualified,
                obj_type="table",
                detail=(
                    f"Table {table.qualified} has row-level security disabled, so the "
                    f"only access control on it is the privilege grant, which cannot "
                    f"express which rows. {detail_tail}"
                ),
                remediation=(
                    f"ALTER TABLE {table.qualified} ENABLE ROW LEVEL SECURITY;\n"
                    f"-- then add the policies this table needs; enabling RLS with no\n"
                    f"-- policy denies all access to non-owners (see RLS004)."
                ),
                evidence={
                    "rls_enabled": "false",
                    "owner": table.owner,
                    "exposed_schema": table.schema,
                    "reachable_by": _format_roles(sorted(reach)),
                },
            )
        )
    return findings


# ---------------------------------------------------------------------------
# RLS003 -- RLS enabled but not forced
# ---------------------------------------------------------------------------


def check_rls003(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    for table in snapshot.tables():
        if not table.rls_enabled or table.rls_forced:
            continue

        if table.owner_bypasses_rls:
            severity = Severity.LOW
            detail_tail = (
                f"Note that {table.owner} also holds BYPASSRLS (or is a superuser), so "
                f"FORCE would not change what that role sees -- the exemption has two "
                f"independent sources and this fixes one of them. Worth doing anyway so "
                f"the remaining exposure is attributable to an explicit role attribute "
                f"rather than to ownership."
            )
        else:
            severity = Severity.MEDIUM
            detail_tail = (
                f"Anything that connects as {table.owner} -- migrations, cron jobs, a "
                f"worker sharing the admin DSN -- reads and writes the whole table. "
                f"Views owned by {table.owner} are the same exemption reached another "
                f"way (see RLS001)."
            )

        findings.append(
            Finding(
                check_id="RLS003",
                title="Row-level security enabled but not forced",
                severity=severity,
                obj=table.qualified,
                obj_type="table",
                detail=(
                    f"Table {table.qualified} has row-level security enabled but not "
                    f"forced, so its owner {table.owner} is exempt from its own "
                    f"policies. {detail_tail}"
                ),
                remediation=f"ALTER TABLE {table.qualified} FORCE ROW LEVEL SECURITY;",
                evidence={
                    "rls_enabled": "true",
                    "rls_forced": "false",
                    "owner": table.owner,
                    "owner_bypasses_rls": str(table.owner_bypasses_rls).lower(),
                },
            )
        )
    return findings


# ---------------------------------------------------------------------------
# RLS004 -- RLS enabled with no policies
# ---------------------------------------------------------------------------


def check_rls004(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    for table in snapshot.tables():
        if not table.rls_enabled or snapshot.policies_for(table.oid):
            continue

        findings.append(
            Finding(
                check_id="RLS004",
                title="Row-level security enabled with zero policies",
                severity=Severity.MEDIUM,
                obj=table.qualified,
                obj_type="table",
                detail=(
                    f"Table {table.qualified} has row-level security enabled and no "
                    f"policies, so every non-owner query matches no policy: reads return "
                    f"nothing and writes are rejected. Nothing leaks, which is why this "
                    f"is not rated higher -- but the owner still reads the table normally, "
                    f"so this can look fine in a console session and be total in the "
                    f"application, and the quickest way to make the symptom stop is to "
                    f"disable RLS or add USING (true)."
                ),
                remediation=(
                    f"-- Add the policy this table was enabled for, e.g.:\n"
                    f"CREATE POLICY {table.name}_select_own\n"
                    f"    ON {table.qualified}\n"
                    f"    FOR SELECT\n"
                    f"    TO authenticated\n"
                    f"    USING (user_id = auth.uid());"
                ),
                evidence={
                    "rls_enabled": "true",
                    "policy_count": "0",
                    "owner": table.owner,
                },
            )
        )
    return findings


# ---------------------------------------------------------------------------
# RLS005 -- policy expression is literally true
# ---------------------------------------------------------------------------


def check_rls005(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    for policy in snapshot.policies:
        for clause, expr in (("USING", policy.using_expr), ("WITH CHECK", policy.check_expr)):
            if not is_literally_true(expr):
                continue

            if not policy.permissive:
                severity = Severity.LOW
                mechanism = (
                    f"This is a RESTRICTIVE policy, and restrictive policies are ANDed "
                    f"together, so a {clause} of true is the identity: it adds no "
                    f"restriction at all. Harmless in itself, and usually a sign that a "
                    f"restriction was intended here and never written."
                )
            elif clause == "USING":
                severity = (
                    Severity.HIGH
                    if _policy_reaches_exposed_role(snapshot, policy)
                    else Severity.MEDIUM
                )
                mechanism = (
                    f"USING (true) passes every row, so the {policy.command_label} path "
                    f"on this table is unfiltered for {_format_roles(policy.roles)}. The "
                    f"table reports RLS as enabled and the policy is listed, so this reads "
                    f"as protected everywhere except in the rows that come back."
                )
            else:
                severity = (
                    Severity.HIGH
                    if _policy_reaches_exposed_role(snapshot, policy)
                    else Severity.MEDIUM
                )
                mechanism = (
                    f"WITH CHECK (true) accepts every write, so any caller holding "
                    f"{policy.command_label} can write rows with any column values -- "
                    f"including rows belonging to another tenant. If this table's read "
                    f"policy is correctly scoped, reads will look right while writes are "
                    f"unconstrained, which is the asymmetry that hides this one."
                )

            findings.append(
                Finding(
                    check_id="RLS005",
                    title=f"Policy {clause} expression is literally true",
                    severity=severity,
                    obj=f"{policy.qualified_table}.{policy.name}",
                    obj_type="policy",
                    detail=(
                        f"Policy {policy.name} on {policy.qualified_table} "
                        f"({'PERMISSIVE' if policy.permissive else 'RESTRICTIVE'} "
                        f"FOR {policy.command_label} TO {_format_roles(policy.roles)}) has "
                        f"{clause} (true). {mechanism}"
                    ),
                    remediation=(
                        f"-- Replace the placeholder with the predicate you meant:\n"
                        f"ALTER POLICY {policy.name} ON {policy.qualified_table}\n"
                        f"    {clause} (tenant_id = ...);\n"
                        f"-- Or, if this table is intentionally public, record why:\n"
                        f"COMMENT ON POLICY {policy.name} ON {policy.qualified_table} IS\n"
                        f"    'Intentionally public: ...';"
                    ),
                    discriminator=clause.replace(" ", "_").lower(),
                    evidence={
                        "command": policy.command_label,
                        "permissive": str(policy.permissive).lower(),
                        "roles": _format_roles(policy.roles),
                        "expression": expr or "",
                    },
                )
            )
    return findings


# ---------------------------------------------------------------------------
# RLS006 -- policy coverage gaps
# ---------------------------------------------------------------------------


def check_rls006(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    for table in snapshot.tables():
        if not table.rls_enabled:
            continue
        policies = snapshot.policies_for(table.oid)
        if not policies:
            # RLS004 already says everything there is to say about this table.
            continue

        permissive = [p for p in policies if p.permissive]
        columns = snapshot.column_names(table.oid)
        reach = _reachable_by_exposed_role(snapshot, table)

        findings.extend(_rls006_uncovered(snapshot, table, permissive, reach))
        findings.extend(_rls006_with_check_fallback(table, permissive, columns))
        findings.extend(_rls006_divergence(table, permissive))
    return findings


def _rls006_uncovered(
    snapshot: Snapshot,
    table: Relation,
    permissive: list[Policy],
    reach: dict[str, set[str]],
) -> list[Finding]:
    findings: list[Finding] = []
    for command in DML_COMMANDS:
        covering = [p for p in permissive if p.covers(command)]
        if not covering:
            findings.append(
                Finding(
                    check_id="RLS006",
                    title=f"No policy covers {command}",
                    severity=Severity.LOW,
                    obj=table.qualified,
                    obj_type="table",
                    detail=(
                        f"Table {table.qualified} has row-level security enabled and "
                        f"policies for other commands, but none covering {command}. "
                        f"{command} is therefore denied for every non-owner. That is "
                        f"fail-closed and nothing leaks, but it reaches a developer as an "
                        f"unexplained failure rather than as a missing policy, and the "
                        f"fastest fix for an unexplained failure is rarely the right one."
                    ),
                    remediation=(
                        f"-- Add the missing policy, or confirm the denial is deliberate:\n"
                        f"CREATE POLICY {table.name}_{command.lower()}_own\n"
                        f"    ON {table.qualified}\n"
                        f"    FOR {command}\n"
                        f"    TO authenticated\n"
                        f"    {'WITH CHECK' if command == 'INSERT' else 'USING'} "
                        f"(user_id = auth.uid());"
                    ),
                    discriminator=f"uncovered:{command}",
                    evidence={
                        "command": command,
                        "policies_on_table": str(len(permissive)),
                        "covering_policies": "0",
                    },
                )
            )
            continue

        # Covered -- but is it covered for the roles that actually call in?
        privilege = PRIVILEGE_FOR_COMMAND[command]
        holders = sorted(role for role, privs in reach.items() if privilege in privs)
        if not holders:
            continue
        applicable = [p for p in covering if _policy_reaches_exposed_role(snapshot, p)]
        if applicable:
            continue

        findings.append(
            Finding(
                check_id="RLS006",
                title=f"{command} policy does not apply to the roles holding {command}",
                severity=Severity.LOW,
                obj=table.qualified,
                obj_type="table",
                detail=(
                    f"{_format_roles(holders)} hold {privilege} on {table.qualified}, but "
                    f"every policy covering {command} is restricted to other roles "
                    f"({'; '.join(f'{p.name} TO {_format_roles(p.roles)}' for p in covering)}). "
                    f"The grant suggests this path is meant to work; the policies mean it "
                    f"never will. Fail-closed, but the mismatch between the two layers is "
                    f"worth resolving in whichever direction was intended."
                ),
                remediation=(
                    f"-- Either widen the policy:\n"
                    f"ALTER POLICY {covering[0].name} ON {table.qualified} TO {holders[0]};\n"
                    f"-- or drop the privilege that is never usable:\n"
                    f"REVOKE {privilege} ON {table.qualified} FROM {', '.join(holders)};"
                ),
                discriminator=f"uncovered-for-role:{command}",
                evidence={
                    "command": command,
                    "privilege_holders": _format_roles(holders),
                    "covering_policy_roles": "; ".join(
                        _format_roles(p.roles) for p in covering
                    ),
                },
            )
        )
    return findings


def _rls006_with_check_fallback(
    table: Relation, permissive: list[Policy], columns: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for policy in permissive:
        if policy.command not in ("*", "w") or policy.check_expr is not None:
            continue
        if policy.using_expr is None:
            continue

        row_scoped = references_any_column(policy.using_expr, columns)
        if row_scoped:
            severity = Severity.LOW
            mechanism = (
                "The USING expression does reference columns of this table, so the "
                "fallback is most likely doing what you want. It is reported so the "
                "write rule is on the record: it is not written down anywhere, and it "
                "will change meaning silently the next time USING is edited."
            )
        else:
            severity = Severity.MEDIUM
            mechanism = (
                "The USING expression does not appear to reference any column of this "
                "table, so as a WITH CHECK it constrains the new row not at all: it asks "
                "a question about the caller and accepts any post-image. A caller who can "
                "update a row can set its tenant or owner column to any value. (Column "
                "detection is a text heuristic over the deparsed expression, so read the "
                "policy before acting on this one.)"
            )

        findings.append(
            Finding(
                check_id="RLS006",
                title="Policy relies on the WITH CHECK fallback to USING",
                severity=severity,
                obj=f"{policy.qualified_table}.{policy.name}",
                obj_type="policy",
                detail=(
                    f"Policy {policy.name} on {policy.qualified_table} is "
                    f"FOR {policy.command_label} with a USING clause and no WITH CHECK, "
                    f"so PostgreSQL validates written rows against the USING expression. "
                    f"{mechanism}"
                ),
                remediation=(
                    f"ALTER POLICY {policy.name} ON {policy.qualified_table}\n"
                    f"    USING ({policy.using_expr})\n"
                    f"    WITH CHECK (/* the predicate the NEW row must satisfy */);"
                ),
                discriminator=f"with-check-fallback:{policy.name}",
                evidence={
                    "command": policy.command_label,
                    "using": policy.using_expr,
                    "with_check": "(absent, falls back to USING)",
                    "using_references_table_columns": str(row_scoped).lower(),
                },
            )
        )
    return findings


def _rls006_divergence(table: Relation, permissive: list[Policy]) -> list[Finding]:
    read_exprs = {
        normalize_expr(p.using_expr)
        for p in permissive
        if p.covers("SELECT") and p.using_expr is not None
    }
    write_policies = [p for p in permissive if p.covers("INSERT") or p.covers("UPDATE")]
    write_exprs = {
        normalize_expr(_effective_check(p))
        for p in write_policies
        if _effective_check(p) is not None
    }
    if not read_exprs or not write_exprs or read_exprs == write_exprs:
        return []

    return [
        Finding(
            check_id="RLS006",
            title="Rows a caller may write are not the rows it may read",
            severity=Severity.MEDIUM,
            obj=table.qualified,
            obj_type="table",
            detail=(
                f"On {table.qualified} the SELECT predicate and the write predicate are "
                f"different expressions, so the set of rows a caller can insert or update "
                f"is not the set it can read back. Read: {' | '.join(sorted(e for e in read_exprs if e))}. "
                f"Write: {' | '.join(sorted(e for e in write_exprs if e))}. This is "
                f"deliberate often enough -- append-only tables, drafts that become "
                f"visible on publish -- that it is not rated higher, but it is also what a "
                f"tenant predicate tightened on the read side and forgotten on the write "
                f"side looks like, and a write you cannot read back is a write you will "
                f"not notice."
            ),
            remediation=(
                f"-- Confirm the asymmetry is intended. If it is not, align the two:\n"
                f"ALTER POLICY <write_policy> ON {table.qualified}\n"
                f"    WITH CHECK (<the same predicate the SELECT policy uses>);"
            ),
            discriminator="read-write-divergence",
            evidence={
                "select_using": " | ".join(sorted(e for e in read_exprs if e)),
                "write_with_check": " | ".join(sorted(e for e in write_exprs if e)),
            },
        )
    ]


# ---------------------------------------------------------------------------
# RLS007 -- SECURITY DEFINER function in an exposed schema
# ---------------------------------------------------------------------------


def _execute_grantees(snapshot: Snapshot, routine_oid: int) -> dict[str, bool]:
    """Grantee name -> whether the EXECUTE privilege is an explicit ACL entry."""
    return {
        grant.grantee: grant.direct
        for grant in snapshot.routine_grants
        if grant.routine_oid == routine_oid
    }


def check_rls007(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    for routine in snapshot.routines:
        if not routine.security_definer or routine.kind not in ("f", "p"):
            continue
        if not snapshot.is_exposed_schema(routine.schema):
            continue

        grantees = _execute_grantees(snapshot, routine.oid)
        callable_by = sorted(
            name for name in grantees if name == "PUBLIC" or name in snapshot.exposed_roles
        )
        if callable_by:
            severity = Severity.HIGH
            via_default = [name for name in callable_by if not grantees[name]]
            source = (
                f" {_format_roles(via_default)} reach it through PostgreSQL's default "
                f"grant of EXECUTE to PUBLIC, so there is no GRANT statement in the "
                f"migration history to notice during review."
                if via_default
                else ""
            )
            reachability = (
                f"{_format_roles(callable_by)} may execute it, so "
                f"POST /rest/v1/rpc/{routine.name} is live for them.{source}"
            )
        else:
            severity = Severity.MEDIUM
            reachability = (
                "EXECUTE has been revoked from the exposed roles, so it is not routable "
                "today. The schema is still the wrong place for it -- the next "
                "ALTER DEFAULT PRIVILEGES or a broad GRANT re-publishes it."
            )

        findings.append(
            Finding(
                check_id="RLS007",
                title="SECURITY DEFINER function in an exposed schema",
                severity=severity,
                obj=routine.signature,
                obj_type="function",
                detail=(
                    f"{routine.signature} is SECURITY DEFINER, so it runs as its owner "
                    f"{routine.owner} rather than as the caller, and it lives in "
                    f"{routine.schema}, which a PostgREST layer serves. Being in the "
                    f"schema is what publishes a function -- there is no separate step -- "
                    f"so a helper written to be called from inside a policy is also an "
                    f"endpoint a caller invokes directly with arguments of their choosing. "
                    f"{reachability}"
                ),
                remediation=(
                    f"CREATE SCHEMA IF NOT EXISTS private;\n"
                    f"REVOKE ALL ON SCHEMA private FROM "
                    f"{', '.join(snapshot.exposed_roles) or 'PUBLIC'};\n"
                    f"ALTER FUNCTION {routine.signature} SET SCHEMA private;\n"
                    f"-- Policies can still call private.{routine.name}(...); PostgREST cannot."
                ),
                evidence={
                    "security_definer": "true",
                    "owner": routine.owner,
                    "schema": routine.schema,
                    "execute_granted_to": _format_roles(callable_by),
                    "volatility": routine.volatility,
                },
            )
        )
    return findings


# ---------------------------------------------------------------------------
# RLS008 -- SECURITY DEFINER function with a mutable search_path
# ---------------------------------------------------------------------------


def _schemas_writable_by_exposed_roles(snapshot: Snapshot) -> dict[str, list[str]]:
    interesting = set(snapshot.exposed_roles) | {"PUBLIC"}
    out: dict[str, list[str]] = {}
    for schema in snapshot.schemas:
        grantees = sorted(set(schema.create_grantees) & interesting)
        if grantees:
            out[schema.name] = grantees
    return out


def _parse_search_path(value: str) -> list[str]:
    parts = []
    for raw in value.split(","):
        item = raw.strip().strip('"').strip("'")
        if item:
            parts.append(item)
    return parts


def check_rls008(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    writable = _schemas_writable_by_exposed_roles(snapshot)

    for routine in snapshot.routines:
        if not routine.security_definer or routine.kind not in ("f", "p"):
            continue

        pinned = routine.search_path
        if pinned is None:
            severity = Severity.HIGH if writable else Severity.MEDIUM
            if writable:
                where = ", ".join(
                    f"{name} (CREATE held by {_format_roles(roles)})"
                    for name, roles in sorted(writable.items())
                )
                reachability = (
                    f"Roles reachable from the API can create objects in: {where}. That is "
                    f"everything the attack needs -- create a shadowing object there, set "
                    f"search_path to put it first, call the function."
                )
            else:
                reachability = (
                    "No exposed role currently holds CREATE on any schema in this "
                    "database, so the hijack has nowhere to plant its object today. "
                    "PostgreSQL 15 dropped the default CREATE grant on public, but "
                    "clusters upgraded from 14 keep the old permissive grant, so confirm "
                    "this rather than assuming it."
                )
            detail = (
                f"{routine.signature} is SECURITY DEFINER with no pinned search_path, so "
                f"every unqualified name in its body -- tables, operators, functions -- is "
                f"resolved using the caller's search_path, while the body runs with "
                f"{routine.owner}'s privileges. The caller chooses which objects the "
                f"function means. {reachability}"
            )
            discriminator = "unpinned"
            remediation = (
                f"ALTER FUNCTION {routine.signature} SET search_path = '';\n"
                f"-- An empty path forces every name in the body to be schema-qualified.\n"
                f"-- If that is too invasive, name the schemas and put pg_temp last:\n"
                f"-- ALTER FUNCTION {routine.signature}\n"
                f"--     SET search_path = pg_catalog, public, pg_temp;"
            )
            findings.append(
                Finding(
                    check_id="RLS008",
                    title="SECURITY DEFINER function with a mutable search_path",
                    severity=severity,
                    obj=routine.signature,
                    obj_type="function",
                    detail=detail,
                    remediation=remediation,
                    discriminator=discriminator,
                    evidence={
                        "security_definer": "true",
                        "search_path": "(not set -- inherited from the caller)",
                        "owner": routine.owner,
                        "schemas_writable_by_exposed_roles": _format_roles(sorted(writable)),
                    },
                )
            )
            continue

        # Pinned -- but pinned to what?
        hijackable = [name for name in _parse_search_path(pinned) if name in writable]
        if not hijackable:
            continue

        findings.append(
            Finding(
                check_id="RLS008",
                title="SECURITY DEFINER function pinned to a writable schema",
                severity=Severity.HIGH,
                obj=routine.signature,
                obj_type="function",
                detail=(
                    f"{routine.signature} is SECURITY DEFINER and pins "
                    f"search_path = {pinned}, which is the right shape -- but "
                    f"{_format_roles(hijackable)} on that path can be created in by "
                    f"{_format_roles(sorted({r for name in hijackable for r in writable[name]}))}. "
                    f"Pinning a path to a schema an attacker can write to pins nothing: "
                    f"they plant the shadowing object in the schema the function already "
                    f"trusts."
                ),
                remediation=(
                    f"REVOKE CREATE ON SCHEMA {hijackable[0]} FROM PUBLIC;\n"
                    f"-- or pin tighter:\n"
                    f"ALTER FUNCTION {routine.signature} SET search_path = '';"
                ),
                discriminator=f"pinned-writable:{','.join(hijackable)}",
                evidence={
                    "security_definer": "true",
                    "search_path": pinned,
                    "writable_schemas_on_path": _format_roles(hijackable),
                },
            )
        )
    return findings


# ---------------------------------------------------------------------------
# RLS009 -- privileges granted to exposed roles on unprotected relations
# ---------------------------------------------------------------------------


def check_rls009(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    for relation in snapshot.audited():
        grants = snapshot.exposed_grantees_on(relation.oid)
        if not grants:
            continue

        for grantee in sorted(grants):
            privileges = sorted(grants[grantee])

            if relation.is_table and not relation.rls_enabled:
                findings.append(
                    Finding(
                        check_id="RLS009",
                        title=f"{grantee} granted privileges on a table without RLS",
                        severity=Severity.CRITICAL,
                        obj=relation.qualified,
                        obj_type="table",
                        detail=(
                            f"{grantee} holds {', '.join(privileges)} on "
                            f"{relation.qualified}, which has row-level security disabled. "
                            f"The access model here is two-layered on purpose -- the grant "
                            f"decides whether a role may touch the relation, RLS decides "
                            f"which rows -- and the second layer is missing, so the grant "
                            f"is the whole story. {grantee} gets every row."
                        ),
                        remediation=(
                            f"ALTER TABLE {relation.qualified} ENABLE ROW LEVEL SECURITY;\n"
                            f"-- plus the policies (RLS004), or drop the reach instead:\n"
                            f"-- REVOKE {', '.join(privileges)} ON {relation.qualified} "
                            f"FROM {grantee};"
                        ),
                        discriminator=f"no-rls:{grantee}",
                        evidence={
                            "grantee": grantee,
                            "privileges": ", ".join(privileges),
                            "rls_enabled": "false",
                        },
                    )
                )
                continue

            if relation.is_view and not relation.security_invoker:
                reads_rls = any(
                    (dep := snapshot.relation(oid)) is not None
                    and dep.is_table
                    and dep.rls_enabled
                    for oid in snapshot.resolve_view_dependencies(relation.oid)
                )
                if reads_rls:
                    findings.append(
                        Finding(
                            check_id="RLS009",
                            title=f"{grantee} granted privileges on a view that bypasses RLS",
                            severity=Severity.MEDIUM,
                            obj=relation.qualified,
                            obj_type="view",
                            detail=(
                                f"{grantee} holds {', '.join(privileges)} on view "
                                f"{relation.qualified}, which reads an RLS-protected table "
                                f"and is not security_invoker. This is the grant that makes "
                                f"RLS001 on this view reachable rather than theoretical; the "
                                f"RLS001 finding carries the mechanism and the fix."
                            ),
                            remediation=(
                                f"ALTER VIEW {relation.qualified} SET (security_invoker = on);"
                            ),
                            discriminator=f"bypassing-view:{grantee}",
                            evidence={
                                "grantee": grantee,
                                "privileges": ", ".join(privileges),
                                "security_invoker": "off",
                            },
                        )
                    )
                continue

            if snapshot.is_anonymous(grantee):
                writes = [p for p in privileges if p in WRITE_PRIVILEGES]
                if not writes:
                    continue
                findings.append(
                    Finding(
                        check_id="RLS009",
                        title=f"{grantee} granted write privileges",
                        severity=Severity.HIGH,
                        obj=relation.qualified,
                        obj_type="table" if relation.is_table else "relation",
                        detail=(
                            f"{grantee} holds {', '.join(writes)} on {relation.qualified}. "
                            f"{grantee} is what an unauthenticated HTTP request "
                            f"authenticates as, so this is an anonymous write endpoint. "
                            f"Row-level security is enabled here, so the only thing "
                            f"standing in the way is the WITH CHECK expression on the "
                            f"relevant policy -- one correct expression away from "
                            f"unauthenticated data injection, with nothing else in reserve."
                        ),
                        remediation=(
                            f"REVOKE {', '.join(writes)} ON {relation.qualified} FROM {grantee};\n"
                            f"ALTER DEFAULT PRIVILEGES IN SCHEMA {relation.schema}\n"
                            f"    REVOKE {', '.join(writes)} ON TABLES FROM {grantee};"
                        ),
                        discriminator=f"anon-write:{grantee}",
                        evidence={
                            "grantee": grantee,
                            "write_privileges": ", ".join(writes),
                            "rls_enabled": str(relation.rls_enabled).lower(),
                        },
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# RLS010 -- EXECUTE and sequence privileges reachable anonymously
# ---------------------------------------------------------------------------


def check_rls010(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []

    routines_by_oid = {r.oid: r for r in snapshot.routines}
    public_execute = {
        grant.routine_oid for grant in snapshot.routine_grants if grant.grantee == "PUBLIC"
    }
    for grant in snapshot.routine_grants:
        routine = routines_by_oid.get(grant.routine_oid)
        if routine is None or routine.kind not in ("f", "p"):
            continue
        if not snapshot.is_anonymous(grant.grantee):
            continue
        if (
            grant.grantee != "PUBLIC"
            and not grant.direct
            and grant.routine_oid in public_execute
        ):
            # This role reaches EXECUTE only by inheriting the PUBLIC grant,
            # which is reported on its own. Saying it twice is noise.
            continue
        if not snapshot.is_exposed_schema(routine.schema) or not routine.mutating:
            continue

        severity = Severity.MEDIUM if routine.security_definer else Severity.LOW
        definer_note = (
            f" It is also SECURITY DEFINER, so the write happens with {routine.owner}'s "
            f"privileges rather than the caller's."
            if routine.security_definer
            else ""
        )
        source = (
            "an explicit GRANT"
            if grant.direct
            else "PostgreSQL's default grant of EXECUTE to PUBLIC, so no GRANT statement "
            "for it exists in the migration history"
        )

        findings.append(
            Finding(
                check_id="RLS010",
                title=f"{grant.grantee} can execute a state-changing function",
                severity=severity,
                obj=routine.signature,
                obj_type="function",
                detail=(
                    f"{grant.grantee} may EXECUTE {routine.signature}, via {source}. The "
                    f"function is VOLATILE and lives in the exposed schema "
                    f"{routine.schema}, so POST /rest/v1/rpc/{routine.name} is an "
                    f"unauthenticated endpoint.{definer_note} Volatility is the only signal "
                    f"the catalog offers here -- a function that writes must be VOLATILE, "
                    f"but a VOLATILE function need not write -- so this narrows the surface "
                    f"rather than proving a bug."
                ),
                remediation=(
                    f"REVOKE EXECUTE ON FUNCTION {routine.signature} FROM PUBLIC, "
                    f"{grant.grantee};\n"
                    f"GRANT EXECUTE ON FUNCTION {routine.signature} TO authenticated;\n"
                    f"ALTER DEFAULT PRIVILEGES IN SCHEMA {routine.schema}\n"
                    f"    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;"
                ),
                discriminator=f"execute:{grant.grantee}",
                evidence={
                    "grantee": grant.grantee,
                    "grant_source": "direct" if grant.direct else "default PUBLIC grant",
                    "volatility": "volatile",
                    "security_definer": str(routine.security_definer).lower(),
                },
            )
        )

    for relation in snapshot.audited():
        if relation.kind != "S":
            continue
        for grantee, privileges in sorted(snapshot.grantees_on(relation.oid).items()):
            if not snapshot.is_anonymous(grantee):
                continue
            operable = sorted(privileges & {"USAGE", "UPDATE", "SELECT"})
            if not {"USAGE", "UPDATE"} & privileges:
                continue
            findings.append(
                Finding(
                    check_id="RLS010",
                    title=f"{grantee} can operate a sequence",
                    severity=Severity.LOW,
                    obj=relation.qualified,
                    obj_type="sequence",
                    detail=(
                        f"{grantee} holds {', '.join(operable)} on sequence "
                        f"{relation.qualified}, which means it can call nextval() and "
                        f"setval() directly. Reading the sequence leaks roughly how many "
                        f"rows exist and how fast they are being created; writing it lets a "
                        f"caller push the sequence forward, or rewind it into a range that "
                        f"collides with existing keys."
                    ),
                    remediation=(
                        f"REVOKE USAGE, UPDATE ON SEQUENCE {relation.qualified} FROM {grantee};\n"
                        f"-- A column default of nextval(...) or GENERATED AS IDENTITY does\n"
                        f"-- not need the caller to hold any sequence privilege."
                    ),
                    discriminator=f"sequence:{grantee}",
                    evidence={
                        "grantee": grantee,
                        "privileges": ", ".join(operable),
                    },
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

CHECKS: dict[str, Callable[[Snapshot], list[Finding]]] = {
    "RLS001": check_rls001,
    "RLS002": check_rls002,
    "RLS003": check_rls003,
    "RLS004": check_rls004,
    "RLS005": check_rls005,
    "RLS006": check_rls006,
    "RLS007": check_rls007,
    "RLS008": check_rls008,
    "RLS009": check_rls009,
    "RLS010": check_rls010,
}


def run_checks(snapshot: Snapshot, enabled: Iterable[str] | None = None) -> list[Finding]:
    """Run every check (or a named subset) and return the findings unsorted."""
    selected = CHECKS if enabled is None else {k: CHECKS[k] for k in enabled}
    findings: list[Finding] = []
    for check in selected.values():
        findings.extend(check(snapshot))
    return findings
