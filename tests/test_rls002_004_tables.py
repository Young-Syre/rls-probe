"""RLS002, RLS003, RLS004: the three table-level switches."""

from __future__ import annotations

from conftest import grant, policy, snapshot, table
from rls_probe.checks import check_rls002, check_rls003, check_rls004
from rls_probe.model import Severity

# -- RLS002 -----------------------------------------------------------------


def test_table_in_exposed_schema_without_rls_is_reported():
    snap = snapshot(relations=[table("audit_log")])

    findings = check_rls002(snap)

    assert len(findings) == 1
    assert findings[0].check_id == "RLS002"
    assert "ENABLE ROW LEVEL SECURITY" in findings[0].remediation


def test_table_with_rls_enabled_is_not_an_rls002():
    snap = snapshot(relations=[table("invoices", rls_enabled=True)])

    assert check_rls002(snap) == []


def test_table_outside_an_exposed_schema_is_not_an_rls002():
    snap = snapshot(relations=[table("internal_log", schema="private")])

    assert check_rls002(snap) == []


def test_rls002_is_high_when_an_exposed_role_holds_a_privilege():
    unprotected = table("audit_log")
    snap = snapshot(
        relations=[unprotected], relation_grants=grant(unprotected, "anon", "SELECT")
    )

    finding = check_rls002(snap)[0]

    assert finding.severity is Severity.HIGH
    assert "GET /rest/v1/audit_log" in finding.detail


def test_rls002_is_medium_when_no_exposed_role_can_reach_it():
    snap = snapshot(relations=[table("audit_log")])

    assert check_rls002(snap)[0].severity is Severity.MEDIUM


def test_rls002_counts_effective_privileges_not_just_direct_grants():
    # A privilege reached by role inheritance is still reach.
    unprotected = table("audit_log")
    snap = snapshot(
        relations=[unprotected],
        effective_relation_privileges={
            (unprotected.oid, "authenticated"): frozenset({"SELECT"})
        },
    )

    assert check_rls002(snap)[0].severity is Severity.HIGH


# -- RLS003 -----------------------------------------------------------------


def test_rls_enabled_but_not_forced_is_reported():
    snap = snapshot(relations=[table("invoices", rls_enabled=True)])

    findings = check_rls003(snap)

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "FORCE ROW LEVEL SECURITY" in findings[0].remediation


def test_forced_table_is_not_an_rls003():
    snap = snapshot(relations=[table("invoices", rls_enabled=True, rls_forced=True)])

    assert check_rls003(snap) == []


def test_table_without_rls_is_not_an_rls003():
    snap = snapshot(relations=[table("audit_log")])

    assert check_rls003(snap) == []


def test_rls003_drops_to_low_when_the_owner_bypasses_rls_anyway():
    snap = snapshot(
        relations=[
            table("invoices", rls_enabled=True, owner="postgres", owner_bypasses_rls=True)
        ]
    )

    finding = check_rls003(snap)[0]

    assert finding.severity is Severity.LOW
    assert "BYPASSRLS" in finding.detail


# -- RLS004 -----------------------------------------------------------------


def test_rls_enabled_with_no_policies_is_reported():
    snap = snapshot(relations=[table("feature_flags", rls_enabled=True)])

    findings = check_rls004(snap)

    assert len(findings) == 1
    assert findings[0].check_id == "RLS004"
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].evidence["policy_count"] == "0"


def test_rls_enabled_with_a_policy_is_not_an_rls004():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[policy("p", protected, using="owner = f()")],
    )

    assert check_rls004(snap) == []


def test_rls004_ignores_tables_without_rls():
    snap = snapshot(relations=[table("audit_log")])

    assert check_rls004(snap) == []


def test_out_of_scope_tables_are_not_audited():
    # Pulled in only to resolve a view dependency; a --schema filter means what
    # it says.
    snap = snapshot(
        relations=[table("secrets", schema="other", in_scope=False)],
        exposed_schemas=("public", "other"),
    )

    assert check_rls002(snap) == []
    assert check_rls003(snap) == []
    assert check_rls004(snap) == []
