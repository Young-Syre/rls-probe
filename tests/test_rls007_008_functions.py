"""RLS007 and RLS008: SECURITY DEFINER functions."""

from __future__ import annotations

from conftest import execute_grant, routine, schema, snapshot
from rls_probe.checks import check_rls007, check_rls008
from rls_probe.model import Severity

# -- RLS007 -----------------------------------------------------------------


def test_security_definer_function_in_public_is_reported():
    helper = routine("is_org_member", args="org uuid")
    snap = snapshot(routines=[helper])

    findings = check_rls007(snap)

    assert len(findings) == 1
    assert findings[0].obj == "public.is_org_member(org uuid)"
    assert "SET SCHEMA private" in findings[0].remediation


def test_security_invoker_function_is_not_an_rls007():
    snap = snapshot(routines=[routine("plain_helper", security_definer=False)])

    assert check_rls007(snap) == []


def test_security_definer_function_in_a_private_schema_is_not_an_rls007():
    snap = snapshot(routines=[routine("is_org_member", schema="private")])

    assert check_rls007(snap) == []


def test_rls007_is_high_when_execute_reaches_an_exposed_role():
    helper = routine("is_org_member")
    snap = snapshot(
        routines=[helper], routine_grants=[execute_grant(helper, "anon", direct=False)]
    )

    finding = check_rls007(snap)[0]

    assert finding.severity is Severity.HIGH
    assert "rpc/is_org_member" in finding.detail
    assert "default" in finding.detail


def test_rls007_names_an_explicit_grant_as_such():
    helper = routine("is_org_member")
    snap = snapshot(
        routines=[helper],
        routine_grants=[execute_grant(helper, "authenticated", direct=True)],
    )

    finding = check_rls007(snap)[0]

    assert finding.severity is Severity.HIGH
    assert "migration history" not in finding.detail


def test_rls007_is_medium_when_execute_has_been_revoked():
    snap = snapshot(routines=[routine("is_org_member")])

    finding = check_rls007(snap)[0]

    assert finding.severity is Severity.MEDIUM
    assert "not routable today" in finding.detail


def test_an_exposed_schema_other_than_public_is_honoured():
    snap = snapshot(
        routines=[routine("rpc_helper", schema="api")],
        exposed_schemas=("api",),
    )

    assert len(check_rls007(snap)) == 1


# -- RLS008 -----------------------------------------------------------------


def test_unpinned_search_path_is_reported():
    snap = snapshot(routines=[routine("is_org_member")], schemas=[schema("public")])

    findings = check_rls008(snap)

    assert len(findings) == 1
    assert findings[0].discriminator == "unpinned"
    assert "search_path = ''" in findings[0].remediation


def test_pinned_empty_search_path_is_safe():
    snap = snapshot(
        routines=[routine("is_org_member", config=("search_path=",))],
        schemas=[schema("public")],
    )

    assert check_rls008(snap) == []


def test_pinned_search_path_to_a_locked_schema_is_safe():
    snap = snapshot(
        routines=[routine("helper", config=("search_path=pg_catalog, public, pg_temp",))],
        schemas=[schema("public")],
    )

    assert check_rls008(snap) == []


def test_pinned_search_path_to_a_writable_schema_is_still_hijackable():
    snap = snapshot(
        routines=[routine("record_audit", config=("search_path=public",))],
        schemas=[schema("public", create_grantees=("PUBLIC",))],
    )

    findings = check_rls008(snap)

    assert len(findings) == 1
    assert findings[0].discriminator == "pinned-writable:public"
    assert findings[0].severity is Severity.HIGH
    assert "pins nothing" in findings[0].detail


def test_unpinned_is_high_when_an_exposed_role_can_create_objects():
    snap = snapshot(
        routines=[routine("is_org_member")],
        schemas=[schema("public", create_grantees=("anon",))],
    )

    finding = check_rls008(snap)[0]

    assert finding.severity is Severity.HIGH
    assert finding.evidence["schemas_writable_by_exposed_roles"] == "public"
    assert "CREATE held by anon" in finding.detail


def test_unpinned_is_medium_when_nobody_can_create_objects():
    snap = snapshot(
        routines=[routine("is_org_member")],
        schemas=[schema("public"), schema("private")],
    )

    finding = check_rls008(snap)[0]

    assert finding.severity is Severity.MEDIUM
    assert "nowhere to plant" in finding.detail


def test_create_granted_to_a_role_the_api_cannot_become_is_not_counted():
    snap = snapshot(
        routines=[routine("is_org_member")],
        schemas=[schema("public", create_grantees=("some_admin",))],
    )

    assert check_rls008(snap)[0].severity is Severity.MEDIUM


def test_rls008_covers_functions_outside_the_exposed_schema():
    # Hijacking a definer function does not require it to be routable.
    snap = snapshot(
        routines=[routine("internal_helper", schema="private")],
        schemas=[schema("public", create_grantees=("PUBLIC",))],
    )

    assert len(check_rls008(snap)) == 1


def test_security_invoker_function_is_not_an_rls008():
    snap = snapshot(
        routines=[routine("plain", security_definer=False)],
        schemas=[schema("public", create_grantees=("PUBLIC",))],
    )

    assert check_rls008(snap) == []


# -- search_path parsing ----------------------------------------------------


def test_parse_search_path_splits_and_unquotes():
    from rls_probe.checks import _parse_search_path

    assert _parse_search_path('pg_catalog, "my schema", public') == [
        "pg_catalog",
        "my schema",
        "public",
    ]


def test_parse_search_path_of_an_empty_pin_is_empty():
    from rls_probe.checks import _parse_search_path

    assert _parse_search_path("") == []


def test_search_path_property_reads_the_proconfig_entry():
    target = routine("f", config=("log_min_duration=0", "search_path=public, pg_temp"))

    assert target.search_path == "public, pg_temp"


def test_search_path_property_is_none_without_a_pin():
    assert routine("f", config=("log_min_duration=0",)).search_path is None
