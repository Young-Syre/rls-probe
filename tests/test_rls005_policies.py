"""RLS005: a policy expression that is the constant true."""

from __future__ import annotations

from conftest import policy, snapshot, table
from rls_probe.checks import check_rls005
from rls_probe.model import Severity


def test_using_true_is_reported():
    protected = table("public_posts", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[policy("read_all", protected, command="r", using="true")],
    )

    findings = check_rls005(snap)

    assert len(findings) == 1
    assert findings[0].title.endswith("USING expression is literally true")
    assert findings[0].severity is Severity.HIGH


def test_with_check_true_is_reported_separately():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[policy("insert_any", protected, command="a", check="true")],
    )

    findings = check_rls005(snap)

    assert len(findings) == 1
    assert "WITH CHECK" in findings[0].title
    assert "another tenant" in findings[0].detail


def test_both_clauses_true_produces_two_distinct_findings():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[policy("all_true", protected, command="*", using="true", check="true")],
    )

    findings = check_rls005(snap)

    assert len(findings) == 2
    assert len({f.fingerprint for f in findings}) == 2


def test_a_real_predicate_is_not_reported():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[policy("own", protected, using="(owner_ref = current_user_id())")],
    )

    assert check_rls005(snap) == []


def test_restrictive_policy_with_using_true_is_only_low():
    # Restrictive policies are ANDed, so true is the identity: dead weight, not
    # a hole.
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[policy("restrict_nothing", protected, permissive=False, using="true")],
    )

    finding = check_rls005(snap)[0]

    assert finding.severity is Severity.LOW
    assert "is the identity" in finding.detail


def test_policy_for_a_non_exposed_role_is_only_medium():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[policy("admin_all", protected, roles=("admin_role",), using="true")],
    )

    assert check_rls005(snap)[0].severity is Severity.MEDIUM


def test_policy_for_public_is_high():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[policy("everyone", protected, roles=("PUBLIC",), using="true")],
    )

    assert check_rls005(snap)[0].severity is Severity.HIGH
