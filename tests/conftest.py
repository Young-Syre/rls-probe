"""Builders for catalog rows, so every check can be tested with no database.

Each check is a pure function of a Snapshot, which means a test only has to
construct the handful of rows the check looks at.  The oids here are arbitrary
but have to be internally consistent, so the helpers assign them.
"""

from __future__ import annotations

import itertools

import pytest

from rls_probe.model import (
    Policy,
    Relation,
    RelationColumn,
    RelationGrant,
    Routine,
    RoutineGrant,
    SchemaInfo,
    Snapshot,
)

_oids = itertools.count(16_384)


def next_oid() -> int:
    return next(_oids)


def table(
    name: str,
    *,
    schema: str = "public",
    rls_enabled: bool = False,
    rls_forced: bool = False,
    owner: str = "app_owner",
    owner_bypasses_rls: bool = False,
    oid: int | None = None,
    in_scope: bool = True,
) -> Relation:
    return Relation(
        oid=oid if oid is not None else next_oid(),
        schema=schema,
        name=name,
        kind="r",
        owner=owner,
        rls_enabled=rls_enabled,
        rls_forced=rls_forced,
        owner_bypasses_rls=owner_bypasses_rls,
        in_scope=in_scope,
    )


def view(
    name: str,
    *,
    schema: str = "public",
    security_invoker: bool = False,
    owner: str = "app_owner",
    oid: int | None = None,
    in_scope: bool = True,
) -> Relation:
    options = {"security_invoker": "true"} if security_invoker else {}
    return Relation(
        oid=oid if oid is not None else next_oid(),
        schema=schema,
        name=name,
        kind="v",
        owner=owner,
        reloptions=options,
        in_scope=in_scope,
    )


def sequence(name: str, *, schema: str = "public", oid: int | None = None) -> Relation:
    return Relation(
        oid=oid if oid is not None else next_oid(),
        schema=schema,
        name=name,
        kind="S",
        owner="app_owner",
    )


def policy(
    name: str,
    on: Relation,
    *,
    command: str = "r",
    permissive: bool = True,
    roles: tuple[str, ...] = ("authenticated",),
    using: str | None = None,
    check: str | None = None,
) -> Policy:
    return Policy(
        oid=next_oid(),
        name=name,
        table_oid=on.oid,
        table_schema=on.schema,
        table_name=on.name,
        command=command,
        permissive=permissive,
        roles=roles,
        using_expr=using,
        check_expr=check,
    )


def routine(
    name: str,
    *,
    schema: str = "public",
    security_definer: bool = True,
    volatility: str = "s",
    config: tuple[str, ...] = (),
    owner: str = "app_owner",
    args: str = "",
    kind: str = "f",
    oid: int | None = None,
) -> Routine:
    return Routine(
        oid=oid if oid is not None else next_oid(),
        schema=schema,
        name=name,
        identity_arguments=args,
        owner=owner,
        security_definer=security_definer,
        volatility=volatility,
        kind=kind,
        config=config,
    )


def grant(relation: Relation, grantee: str, *privileges: str) -> list[RelationGrant]:
    return [
        RelationGrant(relation_oid=relation.oid, grantee=grantee, privilege=privilege)
        for privilege in privileges
    ]


def execute_grant(target: Routine, grantee: str, *, direct: bool = True) -> RoutineGrant:
    return RoutineGrant(routine_oid=target.oid, grantee=grantee, direct=direct)


def columns(relation: Relation, *names: str) -> list[RelationColumn]:
    return [RelationColumn(relation_oid=relation.oid, name=name) for name in names]


def schema(name: str, *, create_grantees: tuple[str, ...] = ()) -> SchemaInfo:
    return SchemaInfo(
        oid=next_oid(), name=name, owner="app_owner", create_grantees=create_grantees
    )


def snapshot(**kwargs) -> Snapshot:
    """A Snapshot with the Supabase-shaped defaults the checks expect."""
    kwargs.setdefault("exposed_roles", ("anon", "authenticated"))
    kwargs.setdefault("anonymous_roles", ("anon",))
    kwargs.setdefault("exposed_schemas", ("public",))
    kwargs.setdefault("database", "testdb")
    kwargs.setdefault("server_version", "17.0")
    return Snapshot(**kwargs)


def ids(findings) -> list[str]:
    return [f.check_id for f in findings]


def objects(findings) -> list[str]:
    return [f.obj for f in findings]


@pytest.fixture
def make():
    """Namespace of the builders, for tests that prefer attribute access."""

    class Make:
        table = staticmethod(table)
        view = staticmethod(view)
        sequence = staticmethod(sequence)
        policy = staticmethod(policy)
        routine = staticmethod(routine)
        grant = staticmethod(grant)
        execute_grant = staticmethod(execute_grant)
        columns = staticmethod(columns)
        schema = staticmethod(schema)
        snapshot = staticmethod(snapshot)

    return Make()
