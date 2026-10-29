"""Putting a run together: collect, check, threshold, baseline."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import baseline as baseline_module
from .checks import run_checks
from .model import Finding, Severity, Snapshot, sort_findings


@dataclass
class AuditResult:
    #: Every finding every selected check produced, highest severity first.
    all_findings: list[Finding] = field(default_factory=list)
    #: What this run reports: above the threshold, and not in the baseline.
    reported: list[Finding] = field(default_factory=list)
    #: Above the threshold but accepted by a baseline.
    baselined: list[Finding] = field(default_factory=list)
    #: Baseline fingerprints that produced no finding this run.
    resolved: list[str] = field(default_factory=list)
    #: Below the severity threshold.
    below_threshold: list[Finding] = field(default_factory=list)
    threshold: Severity = Severity.INFO
    notes: list[str] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    database: str = ""
    server_version: str = ""
    schemas: tuple[str, ...] = ()
    exposed_schemas: tuple[str, ...] = ()
    exposed_roles: tuple[str, ...] = ()
    baseline_path: str | None = None

    @property
    def counts(self) -> dict[str, int]:
        counts = {severity.label: 0 for severity in reversed(Severity)}
        for finding in self.reported:
            counts[finding.severity.label] += 1
        return counts

    @property
    def highest(self) -> Severity | None:
        return max((f.severity for f in self.reported), default=None)


def run(
    snapshot: Snapshot,
    *,
    checks: list[str] | None = None,
    threshold: Severity = Severity.INFO,
    notes: list[str] | None = None,
    baseline: baseline_module.Baseline | None = None,
    baseline_path: str | None = None,
    schemas: tuple[str, ...] = (),
) -> AuditResult:
    from .checks import CHECKS

    selected = sorted(CHECKS) if checks is None else sorted(checks)
    findings = sort_findings(run_checks(snapshot, selected))

    above = [f for f in findings if f.severity >= threshold]
    below = [f for f in findings if f.severity < threshold]

    if baseline is not None:
        partition = baseline_module.apply(baseline, above)
        reported, baselined, resolved = partition.new, partition.known, partition.resolved
    else:
        reported, baselined, resolved = above, [], []

    return AuditResult(
        all_findings=findings,
        reported=reported,
        baselined=baselined,
        resolved=resolved,
        below_threshold=below,
        threshold=threshold,
        notes=list(notes or []),
        checks_run=selected,
        database=snapshot.database,
        server_version=snapshot.server_version,
        schemas=schemas,
        exposed_schemas=snapshot.exposed_schemas,
        exposed_roles=snapshot.exposed_roles,
        baseline_path=baseline_path,
    )
