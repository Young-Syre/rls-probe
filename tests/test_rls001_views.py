"""RLS001: a view over an RLS table that runs as its owner."""

from __future__ import annotations

from conftest import grant, snapshot, table, view
from rls_probe.checks import check_rls001
from rls_probe.model import Severity


def test_plain_view_over_rls_table_is_reported():
    protected = table("invoices", rls_enabled=True)
    leaky = view("invoice_overview")
    snap = snapshot(
        relations=[protected, leaky],
        view_dependencies={leaky.oid: {protected.oid}},
    )

    findings = check_rls001(snap)

    assert len(findings) == 1
    assert findings[0].check_id == "RLS001"
    assert findings[0].obj == "public.invoice_overview"
    assert "public.invoices" in findings[0].detail
    assert "security_invoker = on" in findings[0].remediation


def test_security_invoker_view_is_safe():
    protected = table("invoices", rls_enabled=True)
    safe = view("invoice_overview_safe", security_invoker=True)
    snap = snapshot(
        relations=[protected, safe],
        view_dependencies={safe.oid: {protected.oid}},
    )

    assert check_rls001(snap) == []


def test_view_over_a_table_without_rls_is_not_an_rls001():
    unprotected = table("reference_data", rls_enabled=False)
    plain = view("reference_view")
    snap = snapshot(
        relations=[unprotected, plain],
        view_dependencies={plain.oid: {unprotected.oid}},
    )

    assert check_rls001(snap) == []


def test_nested_view_dependency_is_resolved_transitively():
    protected = table("invoices", rls_enabled=True)
    inner = view("invoice_overview")
    outer = view("invoice_summary")
    snap = snapshot(
        relations=[protected, inner, outer],
        view_dependencies={inner.oid: {protected.oid}, outer.oid: {inner.oid}},
    )

    findings = {f.obj: f for f in check_rls001(snap)}

    assert set(findings) == {"public.invoice_overview", "public.invoice_summary"}
    assert "via a nested view" in findings["public.invoice_summary"].detail


def test_outer_view_over_a_security_invoker_view_is_still_reported():
    # security_invoker on the inner view does not help: the outer view collapses
    # the whole subtree back to the outer view's owner.
    protected = table("invoices", rls_enabled=True)
    inner = view("invoice_overview_safe", security_invoker=True)
    outer = view("invoice_rollup")
    snap = snapshot(
        relations=[protected, inner, outer],
        view_dependencies={inner.oid: {protected.oid}, outer.oid: {inner.oid}},
    )

    assert [f.obj for f in check_rls001(snap)] == ["public.invoice_rollup"]


def test_severity_is_critical_when_an_exposed_role_can_read_the_view():
    protected = table("invoices", rls_enabled=True)
    leaky = view("invoice_overview")
    snap = snapshot(
        relations=[protected, leaky],
        view_dependencies={leaky.oid: {protected.oid}},
        relation_grants=grant(leaky, "anon", "SELECT"),
    )

    finding = check_rls001(snap)[0]

    assert finding.severity is Severity.CRITICAL
    assert "reachable through the API" in finding.detail


def test_severity_is_high_when_nothing_is_granted_on_the_view():
    protected = table("invoices", rls_enabled=True)
    leaky = view("invoice_overview")
    snap = snapshot(
        relations=[protected, leaky],
        view_dependencies={leaky.oid: {protected.oid}},
    )

    finding = check_rls001(snap)[0]

    assert finding.severity is Severity.HIGH
    assert "one GRANT away" in finding.detail


def test_dependency_cycle_does_not_hang():
    # Views cannot really be cyclic, but the resolver must not depend on that.
    protected = table("invoices", rls_enabled=True)
    a = view("a")
    b = view("b")
    snap = snapshot(
        relations=[protected, a, b],
        view_dependencies={a.oid: {b.oid}, b.oid: {a.oid, protected.oid}},
    )

    assert len(check_rls001(snap)) == 2


def test_out_of_scope_table_still_counts_as_a_dependency():
    # A --schema filter must not hide the fact that the view reads an RLS table
    # in a schema that was filtered out.
    protected = table("secrets", schema="other", rls_enabled=True, in_scope=False)
    leaky = view("secret_view")
    snap = snapshot(
        relations=[protected, leaky],
        view_dependencies={leaky.oid: {protected.oid}},
    )

    assert "other.secrets" in check_rls001(snap)[0].detail
