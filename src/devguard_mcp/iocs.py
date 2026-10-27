"""Loads the indicator data shipped in ``data/iocs.json`` and exposes compiled patterns."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from re import Pattern


@dataclass(frozen=True)
class Marker:
    id: str
    pattern: Pattern[str]
    campaign: str
    literal: str | None = None


@dataclass(frozen=True)
class Indicator:
    value: str
    campaign: str
    note: str = ""


@dataclass(frozen=True)
class IOCs:
    version: str
    sources: tuple[str, ...]
    strong_markers: tuple[Marker, ...]
    weak_markers: tuple[Marker, ...]
    ips: tuple[Indicator, ...]
    domains: tuple[Indicator, ...]
    helper_files: dict[str, tuple[str, str]]  # name -> (severity, campaign)
    workflow_filenames: dict[str, str]  # name -> campaign
    workflow_markers: tuple[str, ...]
    suspicious_commit_messages: tuple[str, ...]
    persistence_files: tuple[str, ...]
    persistence_dirs: tuple[str, ...]

    @property
    def c2_hosts(self) -> tuple[Indicator, ...]:
        return self.ips + self.domains

    def to_dict(self) -> dict[str, object]:
        """Public, payload-free view used by the ``list_iocs`` tool."""
        return {
            "version": self.version,
            "sources": list(self.sources),
            "strong_markers": [m.literal or m.pattern.pattern for m in self.strong_markers],
            "ips": [{"value": i.value, "campaign": i.campaign, "note": i.note} for i in self.ips],
            "domains": [
                {"value": d.value, "campaign": d.campaign, "note": d.note} for d in self.domains
            ],
            "helper_files": sorted(self.helper_files),
            "workflow_filenames": sorted(self.workflow_filenames),
            "suspicious_commit_messages": list(self.suspicious_commit_messages),
        }


def _markers(raw: list[dict[str, str]]) -> tuple[Marker, ...]:
    return tuple(
        Marker(m["id"], re.compile(m["regex"]), m["campaign"], m.get("literal")) for m in raw
    )


def _indicators(raw: list[dict[str, str]]) -> tuple[Indicator, ...]:
    return tuple(Indicator(i["value"], i["campaign"], i.get("note", "")) for i in raw)


@lru_cache(maxsize=1)
def load_iocs() -> IOCs:
    """Parse and cache the bundled indicator file."""
    text = resources.files("devguard_mcp").joinpath("data/iocs.json").read_text(encoding="utf-8")
    data = json.loads(text)
    persistence = data["persistence_paths"]
    return IOCs(
        version=data["version"],
        sources=tuple(data["sources"]),
        strong_markers=_markers(data["strong_markers"]),
        weak_markers=_markers(data["weak_markers"]),
        ips=_indicators(data["ips"]),
        domains=_indicators(data["domains"]),
        helper_files={h["name"]: (h["severity"], h["campaign"]) for h in data["helper_files"]},
        workflow_filenames={w["name"]: w["campaign"] for w in data["workflow_filenames"]},
        workflow_markers=tuple(data["workflow_markers"]),
        suspicious_commit_messages=tuple(data["suspicious_commit_messages"]),
        persistence_files=tuple(persistence["home_files"]),
        persistence_dirs=tuple(persistence["home_dirs"]),
    )
