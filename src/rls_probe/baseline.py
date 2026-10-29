"""Baselines: accept the findings you have already looked at, fail on new ones.

A baseline is a JSON file of finding fingerprints.  A fingerprint is derived
from the check id, the object type, the object name and a discriminator -- not
from the severity or the wording -- so re-rating a check or editing its prose
does not invalidate a baseline somebody reviewed.  Changing the schema does,
which is the point.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .model import Finding

BASELINE_VERSION = 1


class BaselineError(RuntimeError):
    pass


@dataclass
class Baseline:
    fingerprints: set[str] = field(default_factory=set)
    #: fingerprint -> what it was, for a readable diff when something drops out.
    entries: dict[str, dict[str, str]] = field(default_factory=dict)
    generated_at: str | None = None

    def contains(self, finding: Finding) -> bool:
        return finding.fingerprint in self.fingerprints

    def describe(self, fingerprint: str) -> str:
        entry = self.entries.get(fingerprint, {})
        check = entry.get("check", "?")
        obj = entry.get("object", "?")
        return f"{check} {obj}"


def load(path: str | Path) -> Baseline:
    file = Path(path)
    try:
        raw = json.loads(file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise BaselineError(f"baseline file not found: {file}") from None
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline file {file} is not valid JSON: {exc}") from None

    if not isinstance(raw, dict) or "findings" not in raw:
        raise BaselineError(
            f"baseline file {file} does not look like an rls-probe baseline "
            f"(expected an object with a 'findings' array)"
        )

    version = raw.get("version")
    if version != BASELINE_VERSION:
        raise BaselineError(
            f"baseline file {file} has version {version!r}, this rls-probe writes "
            f"version {BASELINE_VERSION}; regenerate it with --write-baseline"
        )

    entries: dict[str, dict[str, str]] = {}
    for item in raw["findings"]:
        if not isinstance(item, dict) or "fingerprint" not in item:
            raise BaselineError(f"baseline file {file} has an entry without a fingerprint")
        entries[str(item["fingerprint"])] = {
            key: str(value) for key, value in item.items() if key != "fingerprint"
        }

    return Baseline(
        fingerprints=set(entries),
        entries=entries,
        generated_at=raw.get("generated_at"),
    )


def serialize(findings: list[Finding], *, database: str = "") -> str:
    """Render a baseline file.

    Each entry carries the human-readable check and object alongside the
    fingerprint.  The fingerprint is what matters; the rest is so that a
    reviewer can tell what they are accepting without running the tool.
    """
    payload = {
        "version": BASELINE_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "generated_by": "rls-probe",
        "database": database,
        "findings": [
            {
                "fingerprint": finding.fingerprint,
                "check": finding.check_id,
                "severity": finding.severity.label,
                "object_type": finding.obj_type,
                "object": finding.obj,
                "discriminator": finding.discriminator,
            }
            for finding in sorted(findings, key=lambda f: (f.check_id, f.obj, f.discriminator))
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def write(path: str | Path, findings: list[Finding], *, database: str = "") -> int:
    file = Path(path)
    file.write_text(serialize(findings, database=database), encoding="utf-8")
    return len(findings)


@dataclass
class Partition:
    """Findings split by whether the baseline already knows about them."""

    new: list[Finding] = field(default_factory=list)
    known: list[Finding] = field(default_factory=list)
    #: Fingerprints in the baseline that no longer appear -- fixed, or renamed.
    resolved: list[str] = field(default_factory=list)


def apply(baseline: Baseline, findings: list[Finding]) -> Partition:
    partition = Partition()
    seen: set[str] = set()
    for finding in findings:
        seen.add(finding.fingerprint)
        if baseline.contains(finding):
            partition.known.append(finding)
        else:
            partition.new.append(finding)
    partition.resolved = sorted(baseline.fingerprints - seen)
    return partition
