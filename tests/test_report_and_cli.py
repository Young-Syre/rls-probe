"""Rendering, the check registry, and the CLI -- all offline."""

from __future__ import annotations

import json

import pytest

from conftest import execute_grant, grant, policy, routine, schema, snapshot, table, view
from rls_probe import audit, report
from rls_probe.checks import CHECKS, run_checks
from rls_probe.cli import main
from rls_probe.knowledge import CHECK_DOCS, get_doc
from rls_probe.model import Severity, sort_findings


@pytest.fixture
def vulnerable():
    """A small snapshot that trips most of the checks at once."""
    invoices = table("invoices", rls_enabled=True)
    audit_log = table("audit_log")
    overview = view("invoice_overview")
    helper = routine("is_org_member", volatility="v")
    return snapshot(
        relations=[invoices, audit_log, overview],
        policies=[
            policy("select_own", invoices, command="r", using="(owner_ref = f())"),
            policy("insert_any", invoices, command="a", check="true"),
        ],
        routines=[helper],
        schemas=[schema("public", create_grantees=("PUBLIC",))],
        columns=[],
        relation_grants=(
            grant(invoices, "anon", "SELECT", "INSERT")
            + grant(audit_log, "anon", "SELECT")
            + grant(overview, "anon", "SELECT")
        ),
        routine_grants=[execute_grant(helper, "anon", direct=False)],
        view_dependencies={overview.oid: {invoices.oid}},
    )


# -- registry ---------------------------------------------------------------


def test_every_check_has_reference_documentation():
    assert set(CHECKS) == set(CHECK_DOCS)


@pytest.mark.parametrize("check_id", sorted(CHECK_DOCS))
def test_documentation_is_substantive(check_id):
    doc = get_doc(check_id)

    assert doc.title
    assert doc.summary.endswith(".")
    assert len(doc.mechanism) > 400
    assert doc.references
    assert doc.catalogs


def test_get_doc_is_case_insensitive():
    assert get_doc("rls001").check_id == "RLS001"


def test_get_doc_rejects_an_unknown_id():
    with pytest.raises(KeyError, match="unknown check"):
        get_doc("RLS999")


@pytest.mark.parametrize("check_id", sorted(CHECKS))
def test_every_check_is_quiet_on_an_empty_database(check_id):
    assert CHECKS[check_id](snapshot()) == []


def test_findings_carry_everything_a_reader_needs(vulnerable):
    findings = run_checks(vulnerable)

    assert findings
    for finding in findings:
        assert finding.check_id in CHECKS
        assert finding.obj
        assert finding.obj_type
        assert len(finding.detail) > 80
        assert finding.remediation.strip()
        assert len(finding.fingerprint) == 16


def test_fingerprints_are_unique_within_a_run(vulnerable):
    findings = run_checks(vulnerable)
    fingerprints = [f.fingerprint for f in findings]

    assert len(fingerprints) == len(set(fingerprints))


def test_findings_sort_by_descending_severity(vulnerable):
    severities = [f.severity for f in sort_findings(run_checks(vulnerable))]

    assert severities == sorted(severities, reverse=True)


# -- severity threshold -----------------------------------------------------


def test_threshold_filters_the_report(vulnerable):
    result = audit.run(vulnerable, threshold=Severity.HIGH)

    assert result.reported
    assert all(f.severity >= Severity.HIGH for f in result.reported)
    assert all(f.severity < Severity.HIGH for f in result.below_threshold)
    assert len(result.reported) + len(result.below_threshold) == len(result.all_findings)


def test_severity_parsing_accepts_any_case():
    assert Severity.parse("Critical") is Severity.CRITICAL
    assert Severity.parse(" high ") is Severity.HIGH


def test_severity_parsing_rejects_nonsense():
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("catastrophic")


# -- renderers --------------------------------------------------------------


def test_text_report_names_the_objects(vulnerable):
    rendered = report.render_text(audit.run(vulnerable, schemas=("public",)))

    assert "public.invoice_overview" in rendered
    assert "security_invoker = on" in rendered
    assert "SELECT against pg_catalog" in rendered
    assert "audits configuration, not policy logic" in rendered


def test_text_report_says_so_when_there_is_nothing_to_say():
    rendered = report.render_text(audit.run(snapshot()))

    assert "No findings at or above INFO" in rendered


def test_text_report_has_no_escape_codes_without_color(vulnerable):
    assert "\x1b[" not in report.render_text(audit.run(vulnerable), color=False)


def test_text_report_colours_when_asked(vulnerable):
    assert "\x1b[" in report.render_text(audit.run(vulnerable), color=True)


def test_json_report_is_valid_and_complete(vulnerable):
    payload = json.loads(report.render_json(audit.run(vulnerable, schemas=("public",))))

    assert payload["tool"] == "rls-probe"
    assert payload["read_only"] is True
    assert payload["schemas_audited"] == ["public"]
    assert payload["summary"]["reported"] == len(payload["findings"])
    assert payload["summary"]["highest_severity"] == "CRITICAL"
    assert payload["limitations"]
    first = payload["findings"][0]
    assert set(first) >= {
        "check",
        "severity",
        "object",
        "detail",
        "remediation",
        "fingerprint",
    }


def test_markdown_report_is_structured(vulnerable):
    rendered = report.render_markdown(audit.run(vulnerable, schemas=("public",)))

    assert rendered.startswith("# rls-probe report")
    assert "| Severity | Count |" in rendered
    assert "```sql" in rendered
    assert "## Limitations" in rendered


def test_check_list_mentions_every_check():
    rendered = report.render_check_list()

    for check_id in CHECK_DOCS:
        assert check_id in rendered


def test_explanation_contains_the_mechanism_and_the_fix():
    rendered = report.render_explanation("RLS001")

    assert "WHY RLS STILL FAILS" in rendered
    assert "FIX" in rendered
    assert "REFERENCES" in rendered
    assert "ALTER VIEW" in rendered


def test_explanation_preserves_a_numbered_list():
    # The mechanism text for RLS001 is a numbered list; re-wrapping it as prose
    # would run the items together.
    rendered = report.render_explanation("RLS001")

    assert "\n  1. The failure is total." in rendered


# -- CLI --------------------------------------------------------------------


def test_cli_list_checks(capsys):
    assert main(["list-checks", "--no-color"]) == 0
    assert "RLS001" in capsys.readouterr().out


def test_cli_list_checks_json(capsys):
    assert main(["list-checks", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert len(payload) == len(CHECK_DOCS)
    assert payload[0]["id"] == "RLS001"


def test_cli_explain(capsys):
    assert main(["explain", "RLS001", "--no-color"]) == 0
    assert "security_invoker" in capsys.readouterr().out


def test_cli_explain_is_case_insensitive(capsys):
    assert main(["explain", "rls007"]) == 0
    assert "RLS007" in capsys.readouterr().out


def test_cli_explain_rejects_an_unknown_check():
    with pytest.raises(SystemExit) as exc:
        main(["explain", "RLS999"])

    assert exc.value.code == 2


def test_cli_rejects_an_unknown_severity():
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--severity-threshold", "catastrophic"])

    assert exc.value.code == 2


def test_cli_refuses_to_read_and_write_a_baseline_at_once(capsys):
    code = main(["audit", "--baseline", "a.json", "--write-baseline", "b.json"])

    assert code == 2
    assert "do not make sense together" in capsys.readouterr().err


def test_cli_reports_a_missing_baseline_file(capsys, tmp_path):
    code = main(["audit", "--baseline", str(tmp_path / "nope.json")])

    assert code == 2
    assert "baseline file not found" in capsys.readouterr().err


def test_cli_requires_a_subcommand():
    with pytest.raises(SystemExit) as exc:
        main([])

    assert exc.value.code == 2
