"""Checks of the local machine for signs the PolinRider runner is installed or active.

The probes are read-only: they list processes and connections, and read startup and shell files.
All OS interaction goes through :class:`Probe`, so the logic is unit-testable on any platform.
"""

from __future__ import annotations

import platform
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from devguard_mcp.iocs import load_iocs
from devguard_mcp.models import Finding, Report, Severity, redact_secret, sanitize
from devguard_mcp.scanner import find_tokens

Command = Callable[[Sequence[str]], str]

# The *executable* (first token after the pid) must be node, otherwise a shell command line that
# merely mentions "node -e" (including this tool's own invocation) would match.
_NODE_EVAL = re.compile(
    r"^\s*(?:\d+\s+)?[\"']?[^\s\"']*node(?:\.exe)?[\"']?\s+(?:--?[\w-]+(?:=\S+)?\s+)*-e\b",
    re.IGNORECASE,
)
_EVAL_HINT = re.compile(r"eval\s*\(|http\.request|\.npm-ws|_0x[0-9a-f]{4,}|global\.i\s*=")
_STARTUP_HINT = re.compile(r"\.node_modules|npm-ws|\bnode(?:\.exe)?\s+-e\b")
_PIPE_TO_SHELL = re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z)?sh\b")
_MAX_READ = 2 * 1024 * 1024

SHELL_FILES = (
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".config/fish/config.fish",
)
HISTORY_FILES = (".zsh_history", ".bash_history", ".local/share/fish/fish_history")


def default_command(args: Sequence[str]) -> str:
    """Run a fixed argument list (no shell) and return stdout; '' on any failure."""
    try:
        result = subprocess.run(
            list(args), capture_output=True, text=True, timeout=30, check=False, errors="replace"
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout


@dataclass
class Probe:
    """Everything the machine checks need from the outside world."""

    home: Path = field(default_factory=Path.home)
    system: str = field(default_factory=platform.system)
    run: Command = default_command
    extra_startup_dirs: tuple[Path, ...] = ()


def check_machine(probe: Probe | None = None) -> Report:
    probe = probe or Probe()
    report = Report(target=f"{probe.system} ({probe.home})", kind="machine")
    for check in (
        _persistence,
        _processes,
        _connections,
        _startup_items,
        _shell_files,
        _history_tokens,
    ):
        report.add(*check(probe))
    report.notes.append(
        "A clean machine check cannot prove the machine is uncompromised; the second stage is "
        "downloaded at runtime and may use other persistence."
    )
    return report


def _read(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            return handle.read(_MAX_READ).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _persistence(probe: Probe) -> list[Finding]:
    iocs = load_iocs()
    findings: list[Finding] = []
    for rel in iocs.persistence_files:
        target = probe.home / rel
        if target.exists():
            findings.append(
                Finding(
                    "DG-MC-001",
                    Severity.CRITICAL,
                    f"PolinRider runner file present: ~/{rel}",
                    path=str(target),
                    campaign="polinrider",
                )
            )
    for rel in iocs.persistence_dirs:
        target = probe.home / rel
        if target.is_dir() and not any(f.path == str(target) for f in findings):
            findings.append(
                Finding(
                    "DG-MC-001",
                    Severity.MEDIUM,
                    f"Unusual directory ~/{rel} exists. npm does not normally create it in the "
                    "home directory; review its contents.",
                    path=str(target),
                    campaign="polinrider",
                )
            )
    return findings


def _process_listing(probe: Probe) -> str:
    if probe.system == "Windows":
        return probe.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Process | "
                'ForEach-Object { "$($_.ProcessId) $($_.CommandLine)" }',
            ]
        )
    return probe.run(["ps", "-axo", "pid=,command="])


def _processes(probe: Probe) -> list[Finding]:
    findings: list[Finding] = []
    markers = load_iocs().strong_markers
    for line in _process_listing(probe).splitlines():
        if not _NODE_EVAL.search(line):
            continue
        if _EVAL_HINT.search(line) or any(m.pattern.search(line) for m in markers):
            pid = line.strip().split(" ", 1)[0]
            findings.append(
                Finding(
                    "DG-MC-002",
                    Severity.CRITICAL,
                    f"Process {pid} runs `node -e` with eval/download behaviour matching "
                    "the PolinRider runner.",
                    evidence=sanitize(line, 120),
                    campaign="polinrider",
                )
            )
    return findings


def _connections(probe: Probe) -> list[Finding]:
    if probe.system == "Windows":
        listing = probe.run(["netstat", "-ano"])
    else:
        listing = probe.run(["lsof", "-nP", "-i"]) or probe.run(["netstat", "-an"])
    findings: list[Finding] = []
    for host in load_iocs().ips:
        if re.search(rf"(?<![\d.]){re.escape(host.value)}(?![\d.])", listing):
            findings.append(
                Finding(
                    "DG-MC-003",
                    Severity.CRITICAL,
                    f"Connection involving known attacker address {host.value} ({host.campaign}).",
                    evidence=host.note or None,
                    campaign=host.campaign,
                )
            )
    return findings


def _startup_files(probe: Probe) -> list[Path]:
    home = probe.home
    candidates: list[Path] = []
    if probe.system == "Darwin":
        roots = [
            home / "Library/LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]
        pattern = "*.plist"
    elif probe.system == "Windows":
        roots = [home / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"]
        pattern = "*"
    else:
        roots = [home / ".config/autostart", home / ".config/systemd/user"]
        pattern = "*"
    for root in (*roots, *probe.extra_startup_dirs):
        try:
            candidates.extend(p for p in root.glob(pattern) if p.is_file())
        except OSError:
            continue
    return candidates


def _startup_items(probe: Probe) -> list[Finding]:
    markers = load_iocs().strong_markers
    findings: list[Finding] = []

    def flag(where: str, text: str) -> None:
        match = _STARTUP_HINT.search(text) or next(
            (m.pattern.search(text) for m in markers if m.pattern.search(text)), None
        )
        if match:
            findings.append(
                Finding(
                    "DG-MC-004",
                    Severity.HIGH,
                    f"Startup item references a PolinRider indicator: {where}",
                    path=where,
                    evidence=sanitize(match.group(0)),
                    campaign="polinrider",
                )
            )

    for path in _startup_files(probe):
        flag(str(path), _read(path))
    if probe.system == "Windows":
        flag("scheduled tasks", probe.run(["schtasks", "/query", "/fo", "csv", "/v"]))
        flag(
            "HKCU Run key",
            probe.run(["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"]),
        )
    else:
        flag("crontab", probe.run(["crontab", "-l"]))
    return findings


def _shell_files(probe: Probe) -> list[Finding]:
    findings: list[Finding] = []
    for rel in SHELL_FILES:
        path = probe.home / rel
        text = _read(path)
        match = _STARTUP_HINT.search(text) or _PIPE_TO_SHELL.search(text)
        if match:
            findings.append(
                Finding(
                    "DG-MC-005",
                    Severity.HIGH,
                    f"{rel} contains a line that looks like persistence or a remote "
                    "script piped to a shell.",
                    path=str(path),
                    evidence=sanitize(match.group(0)),
                    campaign="polinrider",
                )
            )
    return findings


def _history_tokens(probe: Probe) -> list[Finding]:
    findings: list[Finding] = []
    for rel in HISTORY_FILES:
        path = probe.home / rel
        tokens = find_tokens(_read(path))
        if tokens:
            findings.append(
                Finding(
                    "DG-CR-001",
                    Severity.MEDIUM,
                    f"{len(set(tokens))} GitHub token(s) found in ~/{rel}.",
                    path=str(path),
                    evidence=redact_secret(tokens[0]),
                )
            )
    return findings
