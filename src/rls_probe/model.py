"""Catalog row types, findings, and the snapshot that checks run against.

Every row type here mirrors one shape of data read out of the PostgreSQL system
catalogs.  Checks never touch a database connection: they are pure functions of
a :class:`Snapshot`, which is what makes them testable against hand-built rows.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Severity(IntEnum):
    """Ordered so that thresholds are a simple comparison."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(
                f"unknown severity {value!r}; expected one of "
                + ", ".join(s.name.lower() for s in cls)
            ) from None


# ---------------------------------------------------------------------------
# Catalog rows
# ---------------------------------------------------------------------------

#: pg_policy.polcmd codes mapped to the SQL command they cover.
POLICY_COMMANDS: dict[str, str] = {
    "r": "SELECT",
    "a": "INSERT",
    "w": "UPDATE",
    "d": "DELETE",
    "*": "ALL",
}

#: The commands a policy set has to cover for a table to be fully usable.
DML_COMMANDS: tuple[str, ...] = ("SELECT", "INSERT", "UPDATE", "DELETE")


@dataclass(frozen=True)
class Relation:
    """A row out of ``pg_class`` joined to ``pg_namespace``.

    Covers tables (``r``), partitioned tables (``p``), views (``v``),
    materialized views (``m``), foreign tables (``f``) and sequences (``S``).
    """

    oid: int
    schema: str
    name: str
    kind: str
    owner: str
    rls_enabled: bool = False
    rls_forced: bool = False
    #: Parsed ``pg_class.reloptions``, e.g. ``{"security_invoker": "true"}``.
    reloptions: dict[str, str] = field(default_factory=dict)
    #: True when the relation is owned by a role that can bypass RLS anyway.
    owner_bypasses_rls: bool = False
    #: False for relations pulled in only because an audited view depends on
    #: them.  They take part in dependency resolution but are not themselves
    #: audited, so a --schema filter means what it says.
    in_scope: bool = True

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.name}"

    @property
    def is_table(self) -> bool:
        return self.kind in ("r", "p")

    @property
    def is_view(self) -> bool:
        return self.kind == "v"

    @property
    def security_invoker(self) -> bool:
        """Whether ``security_invoker`` is switched on for this view.

        ``reloptions`` stores booleans as text and accepts every spelling libpq
        accepts, so normalise rather than comparing to ``"true"``.
        """
        raw = self.reloptions.get("security_invoker")
        if raw is None:
            return False
        return raw.strip().lower() in ("on", "true", "yes", "1")


@dataclass(frozen=True)
class Policy:
    """A row out of ``pg_policy`` with the expressions already deparsed."""

    oid: int
    name: str
    table_oid: int
    table_schema: str
    table_name: str
    #: pg_policy.polcmd, one of ``* r a w d``.
    command: str
    permissive: bool
    #: Role names the policy applies to; ``["PUBLIC"]`` for ``pg_policy.polroles = {0}``.
    roles: tuple[str, ...]
    #: ``pg_get_expr(polqual, polrelid)``; None when the policy has no USING clause.
    using_expr: str | None
    #: ``pg_get_expr(polwithcheck, polrelid)``; None when there is no WITH CHECK clause.
    check_expr: str | None

    @property
    def qualified_table(self) -> str:
        return f"{self.table_schema}.{self.table_name}"

    @property
    def command_label(self) -> str:
        return POLICY_COMMANDS.get(self.command, self.command)

    def covers(self, command: str) -> bool:
        return self.command == "*" or POLICY_COMMANDS.get(self.command) == command


@dataclass(frozen=True)
class Routine:
    """A row out of ``pg_proc`` joined to ``pg_namespace``."""

    oid: int
    schema: str
    name: str
    #: ``pg_get_function_identity_arguments``, for an unambiguous ALTER target.
    identity_arguments: str
    owner: str
    security_definer: bool
    #: ``pg_proc.provolatile``: ``i`` immutable, ``s`` stable, ``v`` volatile.
    volatility: str
    #: ``pg_proc.prokind``: ``f`` function, ``p`` procedure, ``a`` aggregate, ``w`` window.
    kind: str
    #: ``pg_proc.proconfig`` entries, e.g. ``["search_path=public, pg_temp"]``.
    config: tuple[str, ...] = ()

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.name}"

    @property
    def signature(self) -> str:
        return f"{self.schema}.{self.name}({self.identity_arguments})"

    @property
    def search_path(self) -> str | None:
        """The pinned ``search_path``, or None when the function inherits the caller's."""
        for entry in self.config:
            key, _, value = entry.partition("=")
            if key.strip().lower() == "search_path":
                return value
        return None

    @property
    def mutating(self) -> bool:
        """Volatile functions are the only ones permitted to write.

        ``provolatile = 'v'`` is a necessary condition for a function that
        modifies the database, so it is the right catalog-level filter for
        "this call can change state".  It is not sufficient -- plenty of
        volatile functions are read-only -- which is why findings that rest on
        it say so.
        """
        return self.volatility == "v"


@dataclass(frozen=True)
class RelationGrant:
    """One privilege from ``aclexplode(pg_class.relacl)``.

    Direct grants only.  That is deliberate: a direct grant is a line of SQL
    somebody wrote, which is the thing an audit should point at.  Privileges
    reached by role inheritance are reported separately via
    :attr:`Snapshot.effective_relation_privileges`.
    """

    relation_oid: int
    grantee: str
    privilege: str


@dataclass(frozen=True)
class RoutineGrant:
    """One EXECUTE privilege, as resolved by ``has_function_privilege``.

    Effective rather than direct, because PostgreSQL grants ``EXECUTE`` on new
    functions to ``PUBLIC`` by default -- so the dangerous case usually has no
    ACL entry at all.
    """

    routine_oid: int
    grantee: str
    #: True when the privilege comes from an explicit entry in ``pg_proc.proacl``.
    direct: bool


@dataclass(frozen=True)
class SchemaInfo:
    """A row out of ``pg_namespace`` plus who may create objects in it."""

    oid: int
    name: str
    owner: str
    #: Role names (or ``PUBLIC``) that hold CREATE on this schema.
    create_grantees: tuple[str, ...] = ()


@dataclass(frozen=True)
class RelationColumn:
    relation_oid: int
    name: str


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------


@dataclass
class Snapshot:
    """Everything a check is allowed to look at.

    Built once per run, either from a live connection (:mod:`rls_probe.catalog`)
    or by hand in the tests.
    """

    relations: list[Relation] = field(default_factory=list)
    policies: list[Policy] = field(default_factory=list)
    routines: list[Routine] = field(default_factory=list)
    schemas: list[SchemaInfo] = field(default_factory=list)
    columns: list[RelationColumn] = field(default_factory=list)
    relation_grants: list[RelationGrant] = field(default_factory=list)
    routine_grants: list[RoutineGrant] = field(default_factory=list)
    #: view oid -> relation oids its ``_RETURN`` rule depends on, from pg_depend/pg_rewrite.
    view_dependencies: dict[int, set[int]] = field(default_factory=dict)
    #: Roles reachable from the internet in this deployment, e.g. anon/authenticated.
    exposed_roles: tuple[str, ...] = ()
    #: Of those, the ones an *unauthenticated* request authenticates as.
    anonymous_roles: tuple[str, ...] = ()
    #: Schemas a REST layer such as PostgREST serves, e.g. ``("public",)``.
    exposed_schemas: tuple[str, ...] = ("public",)
    #: Effective SELECT/INSERT/UPDATE/DELETE per (relation oid, role), inheritance included.
    effective_relation_privileges: dict[tuple[int, str], frozenset[str]] = field(
        default_factory=dict
    )
    database: str = ""
    server_version: str = ""

    # -- lookups ----------------------------------------------------------

    def __post_init__(self) -> None:
        self._rebuild_indexes()

    def _rebuild_indexes(self) -> None:
        self._by_oid = {r.oid: r for r in self.relations}

    def relation(self, oid: int) -> Relation | None:
        if getattr(self, "_by_oid", None) is None or len(self._by_oid) != len(self.relations):
            self._rebuild_indexes()
        return self._by_oid.get(oid)

    def tables(self) -> list[Relation]:
        """In-scope tables only; see :attr:`Relation.in_scope`."""
        return [r for r in self.relations if r.is_table and r.in_scope]

    def views(self) -> list[Relation]:
        """In-scope views only; see :attr:`Relation.in_scope`."""
        return [r for r in self.relations if r.is_view and r.in_scope]

    def audited(self) -> list[Relation]:
        return [r for r in self.relations if r.in_scope]

    def policies_for(self, table_oid: int) -> list[Policy]:
        return [p for p in self.policies if p.table_oid == table_oid]

    def column_names(self, relation_oid: int) -> list[str]:
        return [c.name for c in self.columns if c.relation_oid == relation_oid]

    def is_exposed_schema(self, schema: str) -> bool:
        return schema in self.exposed_schemas

    def grantees_on(self, relation_oid: int) -> dict[str, set[str]]:
        """Direct grants on a relation as ``{grantee: {privilege, ...}}``."""
        out: dict[str, set[str]] = {}
        for grant in self.relation_grants:
            if grant.relation_oid == relation_oid:
                out.setdefault(grant.grantee, set()).add(grant.privilege)
        return out

    def is_anonymous(self, grantee: str) -> bool:
        """PUBLIC is reachable by every role, so it counts as anonymous too."""
        return grantee == "PUBLIC" or grantee in self.anonymous_roles

    def exposed_effective_on(self, relation_oid: int) -> dict[str, set[str]]:
        """Effective privileges held by exposed roles, inheritance included."""
        out: dict[str, set[str]] = {}
        for (oid, role), privs in self.effective_relation_privileges.items():
            if oid == relation_oid and privs:
                out[role] = set(privs)
        return out

    def exposed_grantees_on(self, relation_oid: int) -> dict[str, set[str]]:
        """Direct grants held by an exposed role or by PUBLIC."""
        interesting = set(self.exposed_roles) | {"PUBLIC"}
        return {
            grantee: privs
            for grantee, privs in self.grantees_on(relation_oid).items()
            if grantee in interesting
        }

    def resolve_view_dependencies(self, view_oid: int) -> set[int]:
        """Relation oids a view reads, following nested views transitively.

        A non-``security_invoker`` view runs its whole subtree as its owner, so
        an RLS table two views down is just as exposed as one directly
        referenced.  Guards against cycles, which should not exist but are
        cheap to rule out.
        """
        seen: set[int] = set()
        stack = list(self.view_dependencies.get(view_oid, ()))
        while stack:
            oid = stack.pop()
            if oid in seen or oid == view_oid:
                continue
            seen.add(oid)
            stack.extend(self.view_dependencies.get(oid, ()))
        return seen


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: Severity
    #: Fully qualified name of the object at fault, e.g. ``public.invoices``.
    obj: str
    #: What kind of object that is: table, view, policy, function, schema, sequence.
    obj_type: str
    #: One or two sentences on why this specific object is a problem.
    detail: str
    #: SQL that fixes this specific object.
    remediation: str
    #: Stable extra key, so two findings on one object do not collide.
    discriminator: str = ""
    #: Facts the finding rests on, rendered in verbose output and JSON.
    evidence: dict[str, str] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable identity for baselining.

        Deliberately excludes severity and prose: re-wording a message or
        re-rating a check must not invalidate a reviewed baseline.
        """
        material = "\x1f".join((self.check_id, self.obj_type, self.obj, self.discriminator))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    def as_dict(self) -> dict[str, object]:
        return {
            "check": self.check_id,
            "title": self.title,
            "severity": self.severity.label,
            "object": self.obj,
            "object_type": self.obj_type,
            "detail": self.detail,
            "remediation": self.remediation,
            "fingerprint": self.fingerprint,
            "evidence": dict(self.evidence),
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Highest severity first, then by check id and object, for stable output."""
    return sorted(
        findings, key=lambda f: (-int(f.severity), f.check_id, f.obj, f.discriminator)
    )
