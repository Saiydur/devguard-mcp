"""Detection of GhostAction-style malicious GitHub Actions workflows.

GhostAction pushes a workflow (using stolen credentials) that reads the repository's secrets and
sends them to an attacker over HTTP. Detection is regex-based on purpose: it needs no YAML
dependency and works on text fetched from GitHub as well as from disk.
"""

from __future__ import annotations

import posixpath
import re

from devguard_mcp.iocs import load_iocs
from devguard_mcp.models import Finding, Severity, sanitize

WORKFLOW_DIR = ".github/workflows"
_CONTINUATION = re.compile(r"\\\r?\n")
_CURL_SECRET = re.compile(r"\bcurl\b[^\n]*?\$\{\{\s*secrets\.", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s'\"\\)]+", re.IGNORECASE)
_RAW_IP = re.compile(r"^https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/|$)", re.IGNORECASE)
_HISTORY_SWEEP = re.compile(r"git\s+log\s+(?:-p\s+--all|--all\s+-p|-p\b[^\n]*--all)", re.IGNORECASE)
_DUMP_SECRETS = re.compile(r"toJSON\(\s*secrets\s*\)", re.IGNORECASE)
_PR_TARGET = re.compile(r"^\s*pull_request_target\s*:|\bpull_request_target\b", re.MULTILINE)
_PR_HEAD_CHECKOUT = re.compile(r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref")


def is_workflow_path(path: str) -> bool:
    norm = path.replace("\\", "/")
    return (
        f"/{WORKFLOW_DIR}/" in f"/{norm}"
        and norm.rsplit("/", 1)[-1].lower().endswith((".yml", ".yaml"))
        and posixpath.dirname(norm).endswith(WORKFLOW_DIR)
    )


def scan_workflow(path: str, text: str) -> list[Finding]:
    """Return findings for one workflow file."""
    iocs = load_iocs()
    findings: list[Finding] = []
    base = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    collapsed = _CONTINUATION.sub(" ", text)

    if base in iocs.workflow_filenames:
        findings.append(
            Finding(
                "DG-GA-001",
                Severity.MEDIUM,
                f"Workflow file name '{base}' is used by the GhostAction campaign.",
                path=path,
                campaign="ghostaction",
            )
        )

    lowered = text.lower()
    for host in iocs.c2_hosts:
        if host.campaign == "ghostaction" and host.value.lower() in lowered:
            findings.append(
                Finding(
                    "DG-GA-002",
                    Severity.CRITICAL,
                    "Workflow references a known exfiltration host.",
                    path=path,
                    line=_line_of(text, host.value),
                    evidence=sanitize(host.value),
                    campaign="ghostaction",
                )
            )

    for marker in iocs.workflow_markers:
        if marker in text:
            findings.append(
                Finding(
                    "DG-GA-003",
                    Severity.HIGH,
                    "Workflow contains a GhostAction exfiltration job/step signature.",
                    path=path,
                    line=_line_of(text, marker),
                    evidence=sanitize(marker),
                    campaign="ghostaction",
                )
            )

    findings.extend(_curl_secret_findings(path, collapsed, text))

    if _HISTORY_SWEEP.search(collapsed):
        match = _HISTORY_SWEEP.search(collapsed)
        findings.append(
            Finding(
                "DG-GA-005",
                Severity.MEDIUM,
                "Workflow scans the full git history (`git log -p --all`).",
                path=path,
                evidence=sanitize(match.group(0)) if match else None,
                campaign="ghostaction",
            )
        )
    if _DUMP_SECRETS.search(text):
        findings.append(
            Finding(
                "DG-GA-006",
                Severity.MEDIUM,
                "Workflow serialises every secret with toJSON(secrets).",
                path=path,
                line=_line_of(text, "toJSON"),
                campaign="ghostaction",
            )
        )
    if _PR_TARGET.search(text) and _PR_HEAD_CHECKOUT.search(text):
        findings.append(
            Finding(
                "DG-GA-007",
                Severity.MEDIUM,
                "pull_request_target workflow checks out the pull request head.",
                path=path,
                campaign="ghostaction",
            )
        )
    return findings


def _curl_secret_findings(path: str, collapsed: str, original: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _CURL_SECRET.finditer(collapsed):
        command = collapsed[match.start() : collapsed.find("\n", match.start())]
        urls = _URL.findall(command)
        plain_or_ip = any(u.lower().startswith("http://") or _RAW_IP.match(u) for u in urls)
        severity = Severity.HIGH if plain_or_ip or not urls else Severity.MEDIUM
        findings.append(
            Finding(
                "DG-GA-004",
                severity,
                "Workflow sends secrets with curl"
                + (" over plain HTTP or to a raw IP." if plain_or_ip else "."),
                path=path,
                line=_line_of(original, "curl"),
                evidence=sanitize(urls[0]) if urls else None,
                campaign="ghostaction",
            )
        )
    return findings


def _line_of(text: str, needle: str) -> int | None:
    index = text.lower().find(needle.lower())
    return None if index < 0 else text.count("\n", 0, index) + 1
