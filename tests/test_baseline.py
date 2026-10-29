"""Baseline round-trips and what a fingerprint is allowed to depend on."""

from __future__ import annotations

import json

import pytest

from conftest import grant, snapshot, table, view
from rls_probe import baseline
from rls_probe.checks import check_rls001, run_checks
from rls_probe.model import Finding, Severity


def _finding(**overrides) -> Finding:
    defaults = {
        "check_id": "RLS001",
        "title": "t",
        "severity": Severity.CRITICAL,
        "obj": "public.v",
        "obj_type": "view",
        "detail": "d",
        "remediation": "r",
    }
    return Finding(**{**defaults, "evidence": {}, **overrides})


def test_fingerprint_is_stable_across_runs():
    assert _finding().fingerprint == _finding().fingerprint


def test_fingerprint_ignores_severity_and_prose():
    # Re-rating a check or editing its wording must not invalidate a reviewed
    # baseline.
    original = _finding()
    rephrased = _finding(severity=Severity.LOW, title="different", detail="rewritten")

    assert original.fingerprint == rephrased.fingerprint


def test_fingerprint_changes_with_the_object():
    assert _finding().fingerprint != _finding(obj="public.other").fingerprint


def test_fingerprint_changes_with_the_discriminator():
    assert _finding().fingerprint != _finding(discriminator="using").fingerprint


def test_fingerprint_changes_with_the_check():
    assert _finding().fingerprint != _finding(check_id="RLS009").fingerprint


def test_round_trip_through_a_file(tmp_path):
    protected = table("invoices", rls_enabled=True)
    leaky = view("invoice_overview")
    snap = snapshot(
        relations=[protected, leaky],
        view_dependencies={leaky.oid: {protected.oid}},
        relation_grants=grant(leaky, "anon", "SELECT"),
    )
    findings = check_rls001(snap)
    path = tmp_path / "baseline.json"

    assert baseline.write(path, findings, database="testdb") == 1

    loaded = baseline.load(path)

    assert loaded.contains(findings[0])
    partition = baseline.apply(loaded, findings)
    assert partition.new == []
    assert partition.known == findings
    assert partition.resolved == []


def test_a_new_finding_is_not_suppressed(tmp_path):
    protected = table("invoices", rls_enabled=True)
    first = view("invoice_overview")
    snap = snapshot(
        relations=[protected, first],
        view_dependencies={first.oid: {protected.oid}},
    )
    path = tmp_path / "baseline.json"
    baseline.write(path, check_rls001(snap))

    second = view("invoice_summary")
    snap.relations.append(second)
    snap.view_dependencies[second.oid] = {protected.oid}

    partition = baseline.apply(baseline.load(path), check_rls001(snap))

    assert [f.obj for f in partition.new] == ["public.invoice_summary"]
    assert len(partition.known) == 1


def test_a_fixed_finding_is_reported_as_resolved(tmp_path):
    protected = table("invoices", rls_enabled=True)
    leaky = view("invoice_overview")
    snap = snapshot(
        relations=[protected, leaky],
        view_dependencies={leaky.oid: {protected.oid}},
    )
    path = tmp_path / "baseline.json"
    baseline.write(path, check_rls001(snap))

    fixed = snapshot(
        relations=[protected, view("invoice_overview", security_invoker=True, oid=leaky.oid)],
        view_dependencies={leaky.oid: {protected.oid}},
    )

    partition = baseline.apply(baseline.load(path), check_rls001(fixed))

    assert partition.new == []
    assert len(partition.resolved) == 1


def test_serialized_baseline_is_sorted_and_readable():
    protected = table("invoices", rls_enabled=True)
    leaky = view("invoice_overview")
    snap = snapshot(
        relations=[protected, leaky],
        view_dependencies={leaky.oid: {protected.oid}},
        relation_grants=grant(leaky, "anon", "SELECT"),
    )
    payload = json.loads(baseline.serialize(run_checks(snap), database="testdb"))

    assert payload["version"] == baseline.BASELINE_VERSION
    assert payload["database"] == "testdb"
    checks = [entry["check"] for entry in payload["findings"]]
    assert checks == sorted(checks)
    assert all("fingerprint" in entry and "object" in entry for entry in payload["findings"])


def test_missing_file_is_an_error(tmp_path):
    with pytest.raises(baseline.BaselineError, match="not found"):
        baseline.load(tmp_path / "nope.json")


def test_malformed_json_is_an_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{oops", encoding="utf-8")

    with pytest.raises(baseline.BaselineError, match="not valid JSON"):
        baseline.load(path)


def test_wrong_shape_is_an_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"version": 1, "stuff": []}), encoding="utf-8")

    with pytest.raises(baseline.BaselineError, match="does not look like"):
        baseline.load(path)


def test_a_future_version_is_refused_rather_than_misread(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"version": 99, "findings": []}), encoding="utf-8")

    with pytest.raises(baseline.BaselineError, match="version 99"):
        baseline.load(path)
