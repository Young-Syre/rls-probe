"""Rendering an :class:`~rls_probe.audit.AuditResult` as text, JSON or Markdown."""

from __future__ import annotations

import json
import re
import textwrap

from .audit import AuditResult
from .knowledge import CHECK_DOCS, CheckDoc, get_doc
from .model import Finding, Severity

_ANSI = {
    Severity.CRITICAL: "\x1b[1;37;41m",
    Severity.HIGH: "\x1b[1;31m",
    Severity.MEDIUM: "\x1b[1;33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[2m",
}
_RESET = "\x1b[0m"
_DIM = "\x1b[2m"
_BOLD = "\x1b[1m"

WIDTH = 88


def _paint(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{_RESET}" if color else text


def _wrap(text: str, indent: str = "    ") -> str:
    paragraphs = [p.strip() for p in text.split("\n\n")]
    out = []
    for paragraph in paragraphs:
        out.append(
            textwrap.fill(
                paragraph,
                width=WIDTH,
                initial_indent=indent,
                subsequent_indent=indent,
                break_long_words=False,
                break_on_hyphens=False,
            )
        )
    return "\n\n".join(out)


def _indent_sql(sql: str, indent: str = "      ") -> str:
    return "\n".join(indent + line for line in sql.splitlines())


_LIST_MARKER = re.compile(r"^\s*(?:[-*\u2022]|\d+\.)\s")


def _is_preformatted(paragraph: str) -> bool:
    """Whether a paragraph has structure that re-wrapping would destroy.

    Numbered lists, bullets and SQL snippets are written the way they should be
    read; only flowing prose gets re-flowed.
    """
    lines = paragraph.splitlines()
    return any(
        _LIST_MARKER.match(line) or (line.startswith("    ") and line.strip()) for line in lines
    )


def _emit_block(paragraph: str, indent: str = "  ") -> str:
    """Wrap prose, pass structured text through with the same indent."""
    if _is_preformatted(paragraph):
        return textwrap.indent(textwrap.dedent(paragraph).rstrip("\n"), indent)
    return _wrap(paragraph, indent=indent)


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------


def render_text(result: AuditResult, *, color: bool = False, show_evidence: bool = True) -> str:
    lines: list[str] = []
    lines.append(_paint("rls-probe", _BOLD, color) + " row-level-security posture audit")
    lines.append("")
    meta = [
        ("database", result.database or "(unknown)"),
        ("server", result.server_version or "(unknown)"),
        ("schemas audited", ", ".join(result.schemas) or "(none)"),
        ("exposed schemas", ", ".join(result.exposed_schemas) or "(none)"),
        ("exposed roles", ", ".join(result.exposed_roles) or "(none found)"),
        ("checks run", f"{len(result.checks_run)} ({', '.join(result.checks_run)})"),
    ]
    if result.baseline_path:
        meta.append(("baseline", result.baseline_path))
    pad = max(len(key) for key, _ in meta)
    for key, value in meta:
        lines.append(f"  {key.rjust(pad)} : {value}")
    lines.append("")
    lines.append(
        _paint(
            "  Read-only: every statement issued was a SELECT against pg_catalog.",
            _DIM,
            color,
        )
    )
    lines.append("")

    if result.notes:
        lines.append(_paint("Collection notes", _BOLD, color))
        for note in result.notes:
            lines.append(
                textwrap.fill(
                    " ".join(note.split()),
                    width=WIDTH,
                    initial_indent="  - ",
                    subsequent_indent="    ",
                    break_long_words=False,
                    break_on_hyphens=False,
                )
            )
            lines.append("")

    if not result.reported:
        lines.append(
            _paint("No findings at or above ", "", color)
            + _paint(result.threshold.label, _BOLD, color)
            + "."
        )
    else:
        lines.append(_paint("Findings", _BOLD, color))
        lines.append("")
        for finding in result.reported:
            lines.extend(
                _render_finding_text(finding, color=color, show_evidence=show_evidence)
            )

    lines.append("")
    lines.append(_paint("Summary", _BOLD, color))
    counts = result.counts
    summary = "  " + "  ".join(
        _paint(f"{counts[s.label]} {s.label.lower()}", _ANSI[s], color and counts[s.label] > 0)
        for s in reversed(Severity)
    )
    lines.append(summary)
    if result.below_threshold:
        lines.append(
            f"  {len(result.below_threshold)} finding(s) below the "
            f"{result.threshold.label} threshold were not shown."
        )
    if result.baselined:
        lines.append(f"  {len(result.baselined)} finding(s) accepted by the baseline.")
    if result.resolved:
        lines.append(
            f"  {len(result.resolved)} baseline entr(y/ies) no longer reported -- "
            f"fixed, or the object was renamed."
        )
    lines.append("")
    lines.append(
        _paint(
            "  rls-probe audits configuration, not policy logic. A policy can be\n"
            "  correctly structured and still compare the wrong column.",
            _DIM,
            color,
        )
    )
    return "\n".join(lines) + "\n"


def _render_finding_text(finding: Finding, *, color: bool, show_evidence: bool) -> list[str]:
    lines: list[str] = []
    badge = _paint(f" {finding.severity.label:<8} ", _ANSI[finding.severity], color)
    lines.append(
        f"{badge} {_paint(finding.check_id, _BOLD, color)}  "
        f"{finding.obj_type} {_paint(finding.obj, _BOLD, color)}"
    )
    lines.append(_wrap(finding.title, indent="    "))
    lines.append("")
    lines.append(_wrap(finding.detail, indent="    "))
    lines.append("")
    lines.append("    Fix:")
    lines.append(_paint(_indent_sql(finding.remediation), _DIM, color))
    if show_evidence and finding.evidence:
        evidence = "; ".join(f"{k}={v}" for k, v in finding.evidence.items())
        lines.append("")
        lines.append(_paint(_wrap(f"Evidence: {evidence}", indent="    "), _DIM, color))
    lines.append("")
    lines.append(_paint(f"    [{finding.check_id} {finding.fingerprint}]", _DIM, color))
    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def render_json(result: AuditResult) -> str:
    payload = {
        "tool": "rls-probe",
        "database": result.database,
        "server_version": result.server_version,
        "schemas_audited": list(result.schemas),
        "exposed_schemas": list(result.exposed_schemas),
        "exposed_roles": list(result.exposed_roles),
        "checks_run": list(result.checks_run),
        "severity_threshold": result.threshold.label,
        "baseline": result.baseline_path,
        "read_only": True,
        "notes": list(result.notes),
        "summary": {
            "reported": len(result.reported),
            "baselined": len(result.baselined),
            "below_threshold": len(result.below_threshold),
            "resolved_baseline_entries": len(result.resolved),
            "by_severity": result.counts,
            "highest_severity": result.highest.label if result.highest else None,
        },
        "findings": [finding.as_dict() for finding in result.reported],
        "baselined_findings": [finding.as_dict() for finding in result.baselined],
        "resolved_baseline_fingerprints": list(result.resolved),
        "limitations": [
            "Audits configuration, not policy logic: a policy can be correctly "
            "structured and still reference the wrong column.",
            "Expression checks match the literal constant true, not expressions "
            "that are merely always true.",
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def render_markdown(result: AuditResult) -> str:
    out: list[str] = []
    out.append("# rls-probe report")
    out.append("")
    out.append(f"- **Database:** `{result.database or 'unknown'}`")
    out.append(f"- **Server:** {result.server_version or 'unknown'}")
    out.append(
        f"- **Schemas audited:** {', '.join(f'`{s}`' for s in result.schemas) or 'none'}"
    )
    out.append(
        f"- **Exposed schemas:** {', '.join(f'`{s}`' for s in result.exposed_schemas) or 'none'}"
    )
    out.append(
        f"- **Exposed roles:** {', '.join(f'`{r}`' for r in result.exposed_roles) or 'none found'}"
    )
    out.append(f"- **Checks run:** {', '.join(result.checks_run)}")
    out.append(f"- **Severity threshold:** {result.threshold.label}")
    if result.baseline_path:
        out.append(f"- **Baseline:** `{result.baseline_path}`")
    out.append("")
    out.append("> Read-only: every statement issued was a `SELECT` against `pg_catalog`.")
    out.append("")

    counts = result.counts
    out.append("| Severity | Count |")
    out.append("| --- | --- |")
    for severity in reversed(Severity):
        out.append(f"| {severity.label} | {counts[severity.label]} |")
    out.append("")

    if result.notes:
        out.append("## Collection notes")
        out.append("")
        for note in result.notes:
            out.append(f"- {' '.join(note.split())}")
        out.append("")

    if not result.reported:
        out.append(f"No findings at or above **{result.threshold.label}**.")
        out.append("")
    else:
        out.append("## Findings")
        out.append("")
        for finding in result.reported:
            out.append(
                f"### {finding.severity.label} &mdash; {finding.check_id} "
                f"&mdash; `{finding.obj}`"
            )
            out.append("")
            out.append(f"**{finding.title}** ({finding.obj_type})")
            out.append("")
            out.append(" ".join(finding.detail.split()))
            out.append("")
            out.append("```sql")
            out.append(finding.remediation)
            out.append("```")
            out.append("")
            if finding.evidence:
                out.append("<details><summary>Evidence</summary>")
                out.append("")
                for key, value in finding.evidence.items():
                    out.append(f"- `{key}`: {value}")
                out.append("")
                out.append("</details>")
                out.append("")
            out.append(f"<sub>fingerprint `{finding.fingerprint}`</sub>")
            out.append("")

    if result.baselined:
        out.append("## Accepted by the baseline")
        out.append("")
        for finding in result.baselined:
            out.append(
                f"- {finding.severity.label} {finding.check_id} `{finding.obj}` "
                f"(`{finding.fingerprint}`)"
            )
        out.append("")

    out.append("## Limitations")
    out.append("")
    out.append(
        "rls-probe audits configuration, not policy logic. A policy can be correctly "
        "structured, cover every command, and still compare the wrong column -- no "
        "tool will tell you your tenant predicate is wrong."
    )
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# list-checks / explain
# ---------------------------------------------------------------------------


def render_check_list(*, color: bool = False) -> str:
    lines = [_paint("rls-probe checks", _BOLD, color), ""]
    for check_id in sorted(CHECK_DOCS):
        doc = CHECK_DOCS[check_id]
        badge = _paint(f"{doc.default_severity.label:<8}", _ANSI[doc.default_severity], color)
        lines.append(f"  {_paint(check_id, _BOLD, color)}  {badge}  {doc.title}")
        lines.append(f"            {_paint(doc.summary, _DIM, color)}")
        lines.append("")
    lines.append(
        _paint(
            "  The severity shown is the default; several checks raise or lower it\n"
            "  based on whether an exposed role can actually reach the object.\n"
            "  Run `rls-probe explain <check-id>` for the mechanism and the fix.",
            _DIM,
            color,
        )
    )
    return "\n".join(lines) + "\n"


def render_explanation(check_id: str, *, color: bool = False) -> str:
    doc: CheckDoc = get_doc(check_id)
    lines = []
    lines.append(f"{_paint(doc.check_id, _BOLD, color)}  {doc.title}")
    lines.append("")
    lines.append(
        "  Default severity : "
        + _paint(doc.default_severity.label, _ANSI[doc.default_severity], color)
    )
    lines.append(f"  Catches          : {doc.summary}")
    if doc.catalogs:
        lines.append(f"  Reads            : {', '.join(doc.catalogs)}")
    lines.append("")
    lines.append(_paint("WHY RLS STILL FAILS", _BOLD, color))
    lines.append("")
    for paragraph in doc.mechanism.split("\n\n"):
        lines.append(_emit_block(paragraph))
        lines.append("")
    if doc.severity_notes:
        lines.append(_paint("SEVERITY", _BOLD, color))
        lines.append("")
        for note in doc.severity_notes:
            lines.append(
                textwrap.fill(
                    note,
                    width=WIDTH,
                    initial_indent="  - ",
                    subsequent_indent="    ",
                    break_long_words=False,
                    break_on_hyphens=False,
                )
            )
        lines.append("")
    lines.append(_paint("FIX", _BOLD, color))
    lines.append("")
    for paragraph in doc.fix.split("\n\n"):
        if paragraph.startswith("    "):
            lines.append(
                _paint(
                    textwrap.indent(textwrap.dedent(paragraph).rstrip("\n"), "    "),
                    _DIM,
                    color,
                )
            )
        else:
            lines.append(_emit_block(paragraph))
        lines.append("")
    if doc.references:
        lines.append(_paint("REFERENCES", _BOLD, color))
        lines.append("")
        for reference in doc.references:
            lines.append(f"  {reference}")
        lines.append("")
    return "\n".join(lines)
