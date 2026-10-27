"""Data model shared by every detector, the CLI and the MCP server."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from devguard_mcp.iocs import load_iocs

EVIDENCE_LIMIT = 96
_CONTROL = re.compile(r"[^\x20-\x7e]")


class Severity(IntEnum):
    """Ordered so that ``Severity.HIGH > Severity.LOW``."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {valid}") from exc


def sanitize(text: str, limit: int = EVIDENCE_LIMIT) -> str:
    """Make attacker-controlled text safe to show: printable ASCII only, truncated.

    Findings must never echo a whole payload back to the user or to an LLM.
    """
    flat = _CONTROL.sub("?", " ".join(text.split()))
    if len(flat) > limit:
        return f"{flat[:limit]}... (+{len(flat) - limit} chars)"
    return flat


def redact_secret(value: str) -> str:
    """Keep only a short prefix and the length of a credential."""
    return f"{value[:4]}...<{len(value)} chars redacted>"


@dataclass(frozen=True)
class Finding:
    """One piece of evidence. ``evidence`` is already sanitised."""

    rule_id: str
    severity: Severity
    message: str
    path: str | None = None
    line: int | None = None
    evidence: str | None = None
    campaign: str = "generic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.name.lower(),
            "campaign": self.campaign,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
        }


@dataclass
class Report:
    """The result of one scan. A clean report is *not* a proof of safety."""

    target: str
    kind: str
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def add(self, *findings: Finding) -> None:
        self.findings.extend(findings)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity, f.path or "", f.line or 0))

    @property
    def worst(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def exceeds(self, threshold: Severity) -> bool:
        worst = self.worst
        return worst is not None and worst >= threshold

    def to_dict(self) -> dict[str, Any]:
        worst = self.worst
        return {
            "target": self.target,
            "kind": self.kind,
            "verdict": _verdict(worst),
            "worst_severity": worst.name.lower() if worst is not None else None,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "stats": self.stats,
            "notes": self.notes,
            "rules_version": load_iocs().version,
            "disclaimer": (
                "No findings means none of the KNOWN patterns matched. It is not proof that "
                "the target is safe. Indicators change; keep this tool updated."
            ),
        }


def _verdict(worst: Severity | None) -> str:
    if worst is None:
        return "no-known-indicators-found"
    if worst >= Severity.HIGH:
        return "likely-malicious-indicators-found"
    return "suspicious-review-needed"
