"""Filesystem scanner.

``analyze_file`` is a pure function over ``(path, bytes)`` so the same logic serves local
directories and files fetched from GitHub. ``scan_directory`` is the walker around it.
The scanner reads files; it never executes, imports or modifies anything.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from devguard_mcp.iocs import load_iocs
from devguard_mcp.models import Finding, Report, Severity, redact_secret, sanitize
from devguard_mcp.workflows import is_workflow_path, scan_workflow

JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx")
FONT_EXTENSIONS = (".ttf", ".otf", ".woff", ".woff2", ".eot")
PRUNE_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".next",
        ".nuxt",
        ".svelte-kit",
        "dist",
        "build",
        "coverage",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        "Pods",
        ".gradle",
        "target",
        ".turbo",
    }
)
MAX_FILE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_FILES = 250_000

PAD_LINE_MIN = 3000
PAD_RUN_MIN = 100
PAD_TAIL_MIN = 500
OBF_HEX_MIN = 40
OBF_UNICODE_MIN = 80
LARGE_SCRIPT_BYTES = 5000

PAD_PATTERN = re.compile(rf"[ \t]{{{PAD_RUN_MIN},}}(?=\S)")
_OBF_HEX = re.compile(r"_0x[0-9a-fA-F]{4,}")
_OBF_UNICODE = re.compile(r"\\u00[0-9a-fA-F]{2}")
_NODE_RUN = re.compile(
    r"\bnode\s+(?:--?[\w-]+(?:=\S+)?\s+)*([\w./\\-]+\.(?:c|m)?js)\b(?=\s*(?:&&|;))"
)
_DOWNLOADER = re.compile(
    r"\b(?:curl|wget|Invoke-WebRequest|iwr|iex)\b|bash\s+-c|\|\s*(?:ba)?sh\b|powershell",
    re.IGNORECASE,
)
_NODE_WORD = re.compile(r'(?:^|["\s])node(?:["\s]|$)')
_NON_SCRIPT_TARGET = re.compile(
    r"\.(?:ttf|otf|woff2?|eot|png|jpe?g|gif|svg|ico|txt|bin|dat|map)[\"\s\]]", re.IGNORECASE
)
_TOKEN = re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})")
_FONT_MAGIC = (b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1", b"wOFF", b"wOF2", b"ttcf")

SiblingReader = Callable[[str], "bytes | None"]


def find_tokens(text: str) -> list[str]:
    return _TOKEN.findall(text)


def analyze_file(
    path: str, data: bytes, read_sibling: SiblingReader | None = None
) -> list[Finding]:
    """Analyse one file given its repo-relative POSIX ``path`` and raw ``data``."""
    norm = path.replace("\\", "/")
    base = norm.rsplit("/", 1)[-1]
    lower = base.lower()
    findings: list[Finding] = []
    iocs = load_iocs()

    if lower in iocs.helper_files:
        severity_name, campaign = iocs.helper_files[lower]
        findings.append(
            Finding(
                "DG-PR-008",
                Severity.parse(severity_name),
                f"Known attacker helper file '{base}' present.",
                path=norm,
                campaign=campaign,
            )
        )
    if is_workflow_path(norm):
        findings.extend(scan_workflow(norm, _decode(data)))
    if norm.endswith(".vscode/tasks.json") or norm == ".vscode/tasks.json":
        findings.extend(_scan_tasks(norm, _decode(data)))
    if lower == "package.json":
        findings.extend(_scan_package_json(norm, _decode(data), read_sibling))
    if lower.endswith(FONT_EXTENSIONS):
        findings.extend(_scan_font(norm, data))
    if lower.endswith(JS_EXTENSIONS):
        findings.extend(_scan_code(norm, _decode(data)))
    return findings


def _decode(data: bytes) -> str:
    return data.decode("utf-8-sig", errors="replace")


# ---------------------------------------------------------------------------------------------
# JavaScript / TypeScript content
# ---------------------------------------------------------------------------------------------


def _scan_code(path: str, text: str) -> list[Finding]:
    iocs = load_iocs()
    findings: list[Finding] = []
    seen_strong: set[str] = set()

    for marker in iocs.strong_markers:
        match = marker.pattern.search(text)
        if match and marker.id not in seen_strong:
            seen_strong.add(marker.id)
            findings.append(
                Finding(
                    "DG-PR-001",
                    Severity.HIGH,
                    f"Known payload marker '{marker.id}' found.",
                    path=path,
                    line=text.count("\n", 0, match.start()) + 1,
                    evidence=sanitize(match.group(0)),
                    campaign=marker.campaign,
                )
            )

    if not seen_strong:
        for marker in iocs.weak_markers:
            match = marker.pattern.search(text)
            if match:
                findings.append(
                    Finding(
                        "DG-PR-002",
                        Severity.MEDIUM,
                        f"Weak payload marker '{marker.id}' found.",
                        path=path,
                        line=text.count("\n", 0, match.start()) + 1,
                        evidence=sanitize(match.group(0)),
                        campaign=marker.campaign,
                    )
                )
                break

    padded = list(padded_lines(text))
    for number, run, tail in padded[:3]:
        findings.append(
            Finding(
                "DG-PR-003",
                Severity.HIGH,
                "Code hidden after a long whitespace run on a very long line.",
                path=path,
                line=number,
                evidence=f"whitespace run of {run} chars, then {tail} more chars of code",
                campaign="polinrider",
            )
        )

    if not seen_strong and not padded and looks_obfuscated(text):
        findings.append(
            Finding(
                "DG-PR-009",
                Severity.MEDIUM,
                "Heavily obfuscated JavaScript.",
                path=path,
                campaign="generic",
            )
        )
    return findings


def padded_lines(text: str) -> Iterator[tuple[int, int, int]]:
    """Yield ``(line_number, whitespace_run, chars_after_run)`` for padded long lines."""
    for number, line in enumerate(text.split("\n"), start=1):
        if len(line) <= PAD_LINE_MIN:
            continue
        match = PAD_PATTERN.search(line)
        if match and len(line) - match.end() >= PAD_TAIL_MIN:
            yield number, match.end() - match.start(), len(line) - match.end()


def looks_obfuscated(text: str) -> bool:
    return (
        len(_OBF_HEX.findall(text)) >= OBF_HEX_MIN
        or len(_OBF_UNICODE.findall(text)) >= OBF_UNICODE_MIN
    )


# ---------------------------------------------------------------------------------------------
# package.json, VS Code tasks, fonts
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ScriptRun:
    """A package.json script that runs a suspicious local JavaScript file first."""

    script: str
    command: str
    written_target: str  # exactly as typed in the script
    target: str  # normalised path relative to the scan root
    size: int


def suspicious_script_runs(
    path: str, text: str, read_sibling: SiblingReader | None
) -> list[ScriptRun]:
    """Find ``node <file>.js &&`` prefixes whose file is large, obfuscated or marked."""
    try:
        scripts = json.loads(text).get("scripts", {})
    except (ValueError, AttributeError):
        return []
    if not isinstance(scripts, dict) or read_sibling is None:
        return []
    directory = posixpath.dirname(path)
    runs: list[ScriptRun] = []
    for name, command in scripts.items():
        if not isinstance(command, str):
            continue
        for match in _NODE_RUN.finditer(command):
            target = posixpath.normpath(posixpath.join(directory, match.group(1)))
            content = read_sibling(target)
            if content is None:
                continue
            body = _decode(content)
            if (
                len(content) > LARGE_SCRIPT_BYTES
                or looks_obfuscated(body)
                or any(m.pattern.search(body) for m in load_iocs().strong_markers)
            ):
                runs.append(ScriptRun(name, command, match.group(1), target, len(content)))
    return runs


def _scan_package_json(path: str, text: str, read_sibling: SiblingReader | None) -> list[Finding]:
    return [
        Finding(
            "DG-PR-004",
            Severity.HIGH,
            f"Script '{run.script}' runs '{run.target}' ({run.size} bytes) before the real "
            "command.",
            path=path,
            evidence=sanitize(run.command),
            campaign="polinrider",
        )
        for run in suspicious_script_runs(path, text, read_sibling)
    ]


def _scan_tasks(path: str, text: str) -> list[Finding]:
    if "folderOpen" not in text:
        return []
    suspicious = bool(_DOWNLOADER.search(text)) or (
        bool(_NODE_WORD.search(text)) and bool(_NON_SCRIPT_TARGET.search(text))
    )
    if suspicious:
        return [
            Finding(
                "DG-PR-005",
                Severity.HIGH,
                "VS Code task runs on folder open and downloads code or runs node on a "
                "non-script file.",
                path=path,
                evidence=sanitize(text, 120),
                campaign="polinrider",
            )
        ]
    return [
        Finding(
            "DG-PR-006",
            Severity.LOW,
            "VS Code task runs automatically when the folder is opened.",
            path=path,
            campaign="polinrider",
        )
    ]


def _head_summary(head: bytes) -> str:
    """Describe the first bytes without echoing attacker-controlled text."""
    kind = "text-like" if all(b in b"\t\n\r" or 32 <= b < 127 for b in head) else "binary"
    return f"first bytes (hex): {head[:8].hex()}, {kind} content"


def _scan_font(path: str, data: bytes) -> list[Finding]:
    if not data:
        return []
    head = data[:64]
    valid = head[:4] in _FONT_MAGIC
    if not valid and path.lower().endswith(".eot"):
        valid = head[34:36] == b"LP"  # EOT magic number at offset 34
    if valid:
        return []
    return [
        Finding(
            "DG-PR-007",
            Severity.HIGH,
            f"'{path.rsplit('/', 1)[-1]}' is {len(data)} bytes but does not start with a font "
            "header.",
            path=path,
            evidence=_head_summary(head),
            campaign="polinrider",
        )
    ]


# ---------------------------------------------------------------------------------------------
# Directory walker
# ---------------------------------------------------------------------------------------------


def is_relevant(rel: str) -> bool:
    lower = rel.lower()
    base = lower.rsplit("/", 1)[-1]
    return (
        lower.endswith(JS_EXTENSIONS + FONT_EXTENSIONS)
        or base in ("package.json", *load_iocs().helper_files)
        or lower.endswith(".vscode/tasks.json")
        or is_workflow_path(lower)
    )


def scan_directory(root: str, max_files: int = DEFAULT_MAX_FILES) -> Report:
    """Scan ``root`` recursively. Symlinks are not followed."""
    root_abs = os.path.realpath(os.path.expanduser(root))
    if not os.path.isdir(root_abs):
        raise NotADirectoryError(f"not a directory: {root}")

    report = Report(target=root_abs, kind="directory")
    scanned = skipped = 0

    def read_sibling(rel: str) -> bytes | None:
        full = os.path.realpath(os.path.join(root_abs, *rel.split("/")))
        if not (full == root_abs or full.startswith(root_abs + os.sep)) or not os.path.isfile(full):
            return None
        try:
            with open(full, "rb") as handle:
                return handle.read(MAX_FILE_BYTES)
        except OSError:
            return None

    for current, dirs, files in os.walk(root_abs, followlinks=False):
        if ".git" in dirs:
            report.add(*_scan_git_config(root_abs, os.path.join(current, ".git", "config")))
        dirs[:] = [d for d in dirs if d not in PRUNE_DIRS]
        for name in files:
            full = os.path.join(current, name)
            rel = os.path.relpath(full, root_abs).replace(os.sep, "/")
            if not is_relevant(rel) or os.path.islink(full):
                continue
            if scanned >= max_files:
                report.notes.append(f"Stopped after {max_files} files (max_files reached).")
                report.stats.update(files_scanned=scanned, files_skipped=skipped)
                return report
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    skipped += 1
                    continue
                with open(full, "rb") as handle:
                    data = handle.read()
            except OSError:
                skipped += 1
                continue
            scanned += 1
            report.add(*analyze_file(rel, data, read_sibling))

    report.stats.update(files_scanned=scanned, files_skipped=skipped)
    return report


def _scan_git_config(root_abs: str, config_path: str) -> list[Finding]:
    try:
        with open(config_path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return []
    tokens = find_tokens(text)
    if not tokens:
        return []
    rel = os.path.relpath(config_path, root_abs).replace(os.sep, "/")
    return [
        Finding(
            "DG-CR-002",
            Severity.MEDIUM,
            "A GitHub token is stored in plaintext in this repository's git config.",
            path=rel,
            evidence=redact_secret(tokens[0]),
        )
    ]
