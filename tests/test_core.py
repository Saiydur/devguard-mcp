"""Models, indicator data, rule catalogue and checklist."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from devguard_mcp.checklist import build_checklist
from devguard_mcp.iocs import load_iocs
from devguard_mcp.models import Finding, Report, Severity, redact_secret, sanitize
from devguard_mcp.rules import RULES, get_rule, rules_markdown


def test_severity_ordering_and_parse() -> None:
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert Severity.parse(" High ") is Severity.HIGH
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("severe")


def test_sanitize_strips_control_characters_and_truncates() -> None:
    assert sanitize("a\x1b[31mb\nc") == "a?[31mb c"
    long = sanitize("x" * 500, limit=20)
    assert long.startswith("x" * 20) and "+480 chars" in long


def test_redact_secret_keeps_prefix_and_length_only() -> None:
    secret = "ghp_" + "z" * 36
    redacted = redact_secret(secret)
    assert "zzzz" not in redacted and "40 chars" in redacted


def test_empty_report_is_clean_and_sorted_findings_are_stable() -> None:
    report = Report("t", "test")
    assert report.worst is None and not report.exceeds(Severity.INFO)
    report.add(
        Finding("DG-X-1", Severity.LOW, "low", path="b"),
        Finding("DG-X-2", Severity.CRITICAL, "crit", path="a"),
        Finding("DG-X-3", Severity.LOW, "low", path="a"),
    )
    assert [f.rule_id for f in report.sorted_findings()] == ["DG-X-2", "DG-X-3", "DG-X-1"]
    assert report.to_dict()["verdict"] == "likely-malicious-indicators-found"


def test_medium_only_report_is_review_not_malicious() -> None:
    report = Report("t", "test", [Finding("DG-X", Severity.MEDIUM, "m")])
    assert report.to_dict()["verdict"] == "suspicious-review-needed"


def test_iocs_load_and_every_regex_compiles() -> None:
    iocs = load_iocs()
    assert iocs.version and iocs.sources
    assert len(iocs.strong_markers) >= 5 and len(iocs.weak_markers) >= 2
    assert {i.value for i in iocs.ips} >= {"95.135.181.151", "193.32.204.199"}
    for marker in iocs.strong_markers:
        if marker.literal:
            assert marker.pattern.search(marker.literal), marker.id  # regex matches its literal


def test_iocs_public_view_contains_no_regex_payloads() -> None:
    public = load_iocs().to_dict()
    assert "temp_auto_push.bat" in public["helper_files"]  # type: ignore[operator]
    assert "weak_markers" not in public


def test_every_rule_is_complete_and_ids_are_unique() -> None:
    assert len(RULES) == len({r.id for r in RULES.values()})
    for rule in RULES.values():
        assert rule.id.startswith("DG-") and rule.title and rule.description and rule.remediation


def test_rules_used_in_code_exist() -> None:
    source = "".join(p.read_text() for p in Path("src/devguard_mcp").glob("*.py"))
    used = set(re.findall(r'"(DG-[A-Z]{2}-\d{3})"', source)) - {"DG-X"}
    assert used <= set(RULES), used - set(RULES)


def test_get_rule_is_case_insensitive() -> None:
    assert get_rule("dg-pr-001") is RULES["DG-PR-001"]
    assert get_rule("DG-NOPE") is None


def test_checklist_puts_clean_device_first_and_guide_pointer_last() -> None:
    steps = [s["title"] for s in build_checklist(machine_compromised=True, repos_infected=True)]
    assert steps[0].startswith("Stop using")
    assert steps.index("Revoke and rotate GitHub credentials (from a clean device)") < steps.index(
        "Rebuild the machine"
    )
    assert steps[-1] == "Read the full recovery guide"


def test_checklist_minimal_has_prevention_and_report_only() -> None:
    assert [s["title"] for s in build_checklist()] == [
        "Reduce the chance of it happening again",
        "Report it",
        "Read the full recovery guide",
    ]


def test_rules_doc_is_in_sync_with_the_catalogue() -> None:
    """Regenerate with: devguard-mcp rules --markdown > docs/RULES.md"""
    committed = Path("docs/RULES.md").read_text(encoding="utf-8")
    assert committed == rules_markdown()
