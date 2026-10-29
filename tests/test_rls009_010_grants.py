"""RLS009 and RLS010: what the exposed roles can actually reach."""

from __future__ import annotations

from conftest import execute_grant, grant, routine, sequence, snapshot, table, view
from rls_probe.checks import check_rls009, check_rls010
from rls_probe.model import RoutineGrant, Severity

# -- RLS009 -----------------------------------------------------------------


def test_grant_to_anon_on_a_table_without_rls_is_critical():
    unprotected = table("audit_log")
    snap = snapshot(
        relations=[unprotected], relation_grants=grant(unprotected, "anon", "SELECT")
    )

    findings = check_rls009(snap)

    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].title.startswith("anon granted")


def test_grant_to_authenticated_on_a_well_configured_table_is_not_reported():
    # The two-layer model is the intended pattern; reporting it would be noise.
    protected = table("profiles", rls_enabled=True, rls_forced=True)
    snap = snapshot(
        relations=[protected],
        relation_grants=grant(protected, "authenticated", "SELECT", "UPDATE"),
    )

    assert check_rls009(snap) == []


def test_write_grant_to_anon_on_an_rls_table_is_high():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        relation_grants=grant(protected, "anon", "SELECT", "INSERT"),
    )

    findings = check_rls009(snap)

    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].evidence["write_privileges"] == "INSERT"


def test_read_only_grant_to_anon_on_an_rls_table_is_not_reported():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(relations=[protected], relation_grants=grant(protected, "anon", "SELECT"))

    assert check_rls009(snap) == []


def test_grant_on_a_bypassing_view_is_reported():
    protected = table("invoices", rls_enabled=True)
    leaky = view("invoice_overview")
    snap = snapshot(
        relations=[protected, leaky],
        view_dependencies={leaky.oid: {protected.oid}},
        relation_grants=grant(leaky, "anon", "SELECT"),
    )

    findings = check_rls009(snap)

    assert len(findings) == 1
    assert findings[0].obj_type == "view"
    assert findings[0].severity is Severity.MEDIUM


def test_grant_on_a_security_invoker_view_is_not_reported():
    protected = table("invoices", rls_enabled=True)
    safe = view("invoice_overview_safe", security_invoker=True)
    snap = snapshot(
        relations=[protected, safe],
        view_dependencies={safe.oid: {protected.oid}},
        relation_grants=grant(safe, "anon", "SELECT"),
    )

    assert check_rls009(snap) == []


def test_grant_on_a_view_over_an_unprotected_table_is_not_reported():
    plain = table("reference_data")
    plain_view = view("reference_view")
    snap = snapshot(
        relations=[plain, plain_view],
        view_dependencies={plain_view.oid: {plain.oid}},
        relation_grants=grant(plain_view, "anon", "SELECT"),
    )

    assert [f for f in check_rls009(snap) if f.obj == "public.reference_view"] == []


def test_grant_to_a_role_that_is_not_exposed_is_not_reported():
    unprotected = table("audit_log")
    snap = snapshot(
        relations=[unprotected], relation_grants=grant(unprotected, "reporting", "SELECT")
    )

    assert check_rls009(snap) == []


def test_grant_to_public_counts_as_exposed():
    unprotected = table("audit_log")
    snap = snapshot(
        relations=[unprotected], relation_grants=grant(unprotected, "PUBLIC", "SELECT")
    )

    assert check_rls009(snap)[0].severity is Severity.CRITICAL


def test_each_grantee_gets_its_own_finding():
    unprotected = table("audit_log")
    snap = snapshot(
        relations=[unprotected],
        relation_grants=grant(unprotected, "anon", "SELECT")
        + grant(unprotected, "authenticated", "SELECT"),
    )

    findings = check_rls009(snap)

    assert len(findings) == 2
    assert len({f.fingerprint for f in findings}) == 2


# -- RLS010 -----------------------------------------------------------------


def test_anon_execute_on_a_volatile_definer_function_is_medium():
    mutating = routine("record_audit", volatility="v")
    snap = snapshot(routines=[mutating], routine_grants=[execute_grant(mutating, "anon")])

    findings = check_rls010(snap)

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "rpc/record_audit" in findings[0].detail


def test_anon_execute_on_a_volatile_invoker_function_is_low():
    mutating = routine("do_thing", security_definer=False, volatility="v")
    snap = snapshot(routines=[mutating], routine_grants=[execute_grant(mutating, "anon")])

    assert check_rls010(snap)[0].severity is Severity.LOW


def test_a_stable_function_is_not_an_rls010():
    readonly = routine("is_org_member", volatility="s")
    snap = snapshot(routines=[readonly], routine_grants=[execute_grant(readonly, "anon")])

    assert check_rls010(snap) == []


def test_execute_by_authenticated_only_is_not_an_rls010():
    mutating = routine("record_audit", volatility="v")
    snap = snapshot(
        routines=[mutating], routine_grants=[execute_grant(mutating, "authenticated")]
    )

    assert check_rls010(snap) == []


def test_a_role_inheriting_the_public_grant_is_not_reported_twice():
    mutating = routine("record_audit", volatility="v")
    snap = snapshot(
        routines=[mutating],
        routine_grants=[
            RoutineGrant(routine_oid=mutating.oid, grantee="anon", direct=False),
            RoutineGrant(routine_oid=mutating.oid, grantee="PUBLIC", direct=False),
        ],
    )

    findings = check_rls010(snap)

    assert len(findings) == 1
    assert findings[0].evidence["grantee"] == "PUBLIC"


def test_a_direct_grant_to_anon_is_reported_alongside_the_public_grant():
    mutating = routine("record_audit", volatility="v")
    snap = snapshot(
        routines=[mutating],
        routine_grants=[
            RoutineGrant(routine_oid=mutating.oid, grantee="anon", direct=True),
            RoutineGrant(routine_oid=mutating.oid, grantee="PUBLIC", direct=False),
        ],
    )

    assert len(check_rls010(snap)) == 2


def test_function_outside_an_exposed_schema_is_not_an_rls010():
    mutating = routine("record_audit", schema="private", volatility="v")
    snap = snapshot(routines=[mutating], routine_grants=[execute_grant(mutating, "anon")])

    assert check_rls010(snap) == []


def test_sequence_usage_granted_to_anon_is_reported():
    seq = sequence("invoices_id_seq")
    snap = snapshot(relations=[seq], relation_grants=grant(seq, "anon", "USAGE"))

    findings = check_rls010(snap)

    assert len(findings) == 1
    assert findings[0].obj_type == "sequence"
    assert findings[0].severity is Severity.LOW
    assert "nextval" in findings[0].detail


def test_sequence_select_alone_is_not_reported():
    seq = sequence("invoices_id_seq")
    snap = snapshot(relations=[seq], relation_grants=grant(seq, "anon", "SELECT"))

    assert check_rls010(snap) == []


def test_sequence_granted_to_authenticated_only_is_not_reported():
    seq = sequence("invoices_id_seq")
    snap = snapshot(relations=[seq], relation_grants=grant(seq, "authenticated", "USAGE"))

    assert check_rls010(snap) == []
