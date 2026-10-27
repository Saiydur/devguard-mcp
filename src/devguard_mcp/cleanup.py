"""Cleanup planning and (explicit, opt-in) application.

``plan_cleanup`` never writes anything. It scans a directory and produces a list of
:class:`CleanupAction` objects with *redacted* diffs. ``apply_plan`` is only reachable from the
CLI (``devguard-mcp fix --apply``); the MCP server does not expose it. Originals are copied to a
quarantine directory (mode 0600) before any file is changed, and nothing is executed.

Workflows and anything ambiguous are always left as ``manual`` actions.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from devguard_mcp.iocs import load_iocs
from devguard_mcp.models import Finding
from devguard_mcp.rules import get_rule
from devguard_mcp.scanner import (
    JS_EXTENSIONS,
    PAD_LINE_MIN,
    PAD_PATTERN,
    PAD_TAIL_MIN,
    padded_lines,
    scan_directory,
    suspicious_script_runs,
)

_SHIM = re.compile(
    r"import \{ createRequire \} from 'module';\n\s*\nconst require = "
    r"createRequire\(import\.meta\.url\);\n\s*\n?"
)
_PREVIEW_LINE = 160


@dataclass(frozen=True)
class CleanupAction:
    kind: str  # "delete" | "rewrite" | "manual"
    path: str  # relative to the plan root, POSIX separators
    reason: str
    preview: str = ""
    new_text: str | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "reason": self.reason,
            "preview": self.preview,
        }


@dataclass
class CleanupPlan:
    root: str
    actions: list[CleanupAction] = field(default_factory=list)

    @property
    def automatic(self) -> list[CleanupAction]:
        return [a for a in self.actions if a.kind != "manual"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "applied": False,
            "automatic_actions": [a.to_dict() for a in self.automatic],
            "manual_actions": [a.to_dict() for a in self.actions if a.kind == "manual"],
            "note": (
                "This is a dry run. Review the diffs, then run `devguard-mcp fix <path> --apply` "
                "in a terminal. After cleanup, run `recovery_checklist`: removing files does "
                "not undo credential theft."
            ),
        }


# ---------------------------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------------------------


def strip_payload(text: str) -> str | None:
    """Return ``text`` without the hidden payload, or ``None`` if nothing was removed."""
    markers = load_iocs().strong_markers
    kept: list[str] = []
    changed = False
    for line in text.split("\n"):
        if len(line) > PAD_LINE_MIN:
            match = PAD_PATTERN.search(line)
            if match and len(line) - match.end() >= PAD_TAIL_MIN:
                changed = True
                prefix = line[: match.start()].rstrip()
                if prefix:
                    kept.append(prefix)
                continue
            if any(m.pattern.search(line) for m in markers):
                changed = True
                continue
        kept.append(line)
    if not changed:
        return None
    result = "\n".join(kept)
    if _SHIM.search(result) and not re.search(r"(?<![A-Za-z])require\(", _SHIM.sub("", result)):
        result = _SHIM.sub("", result)
    return result.rstrip("\n") + "\n"


def _still_dirty(text: str) -> bool:
    return bool(list(padded_lines(text))) or any(
        m.pattern.search(text) for m in load_iocs().strong_markers
    )


def _syntax_ok(path: str, text: str) -> bool:
    """Best-effort ``node --check``; skipped (treated as OK) when node is unavailable."""
    suffix = Path(path).suffix
    node = shutil.which("node")
    if node is None or suffix not in (".js", ".mjs", ".cjs"):
        return True
    candidates = (".cjs", ".mjs") if suffix == ".js" else (suffix,)
    with tempfile.TemporaryDirectory() as tmp:
        for ext in candidates:
            target = Path(tmp) / f"check{ext}"
            target.write_text(text, encoding="utf-8")
            result = subprocess.run(
                [node, "--check", str(target)], capture_output=True, timeout=30, check=False
            )
            if result.returncode == 0:
                return True
    return False


def _shorten(line: str) -> str:
    if len(line) <= _PREVIEW_LINE:
        return line
    return f"{line[:60]}<... {len(line) - 60} chars redacted ...>"


def _diff(path: str, old: str, new: str) -> str:
    diff = difflib.unified_diff(
        old.splitlines(), new.splitlines(), f"a/{path}", f"b/{path}", lineterm="", n=1
    )
    return "\n".join(_shorten(line) for line in diff)


def plan_cleanup(root: str) -> CleanupPlan:
    """Scan ``root`` and plan how to remove what was found. Writes nothing."""
    report = scan_directory(root)
    base = Path(report.target)
    plan = CleanupPlan(root=str(base))

    by_path: dict[str, list[Finding]] = {}
    for finding in report.findings:
        if finding.path:
            by_path.setdefault(finding.path, []).append(finding)

    deleted: set[str] = set()
    for path, findings in sorted(by_path.items()):
        action = _plan_one(base, path, {f.rule_id for f in findings}, findings)
        if action is not None:
            plan.actions.append(action)
            if action.kind == "delete":
                deleted.add(path)

    # package.json rewrites depend on which files are being removed
    for path, findings in sorted(by_path.items()):
        if any(f.rule_id == "DG-PR-004" for f in findings):
            plan.actions = [a for a in plan.actions if a.path != path]
            plan.actions.append(_plan_package_json(base, path))
    return plan


def _plan_one(
    base: Path, path: str, ids: set[str], findings: list[Finding]
) -> CleanupAction | None:
    full = base / path
    if "DG-PR-007" in ids:
        return _delete(full, path, "File is not a font; it contains hidden JavaScript.")
    if "DG-PR-008" in ids and any(f.severity.name == "HIGH" for f in findings):
        return _delete(full, path, "Known attacker helper script.")
    if "DG-PR-005" in ids:
        return _plan_tasks(full, path)
    if ids & {"DG-PR-001", "DG-PR-003"} and path.lower().endswith(JS_EXTENSIONS):
        return _plan_code(full, path)
    if "DG-PR-004" in ids:
        return None  # handled in the second pass
    top = max(findings, key=lambda f: f.severity)
    rule = get_rule(top.rule_id)
    return CleanupAction(
        "manual", path, f"{top.rule_id}: {rule.remediation if rule else top.message}"
    )


def _delete(full: Path, path: str, reason: str) -> CleanupAction:
    size = full.stat().st_size if full.exists() else 0
    return CleanupAction(
        "delete", path, reason, preview=f"--- a/{path}\n+++ /dev/null\n(file deleted, {size} bytes)"
    )


def _plan_code(full: Path, path: str) -> CleanupAction:
    try:
        text = full.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        return CleanupAction("manual", path, f"Could not read file: {exc}")
    new = strip_payload(text)
    if new is None:
        if full.name == "api.js":
            return _delete(full, path, "Standalone dropper file (api.js with payload marker).")
        return CleanupAction(
            "manual",
            path,
            "Payload marker found but no padded payload line to remove; review by hand.",
        )
    if not new.strip() or full.name == "api.js":
        return _delete(full, path, "Entire file is payload.")
    if _still_dirty(new) or not _syntax_ok(path, new):
        return CleanupAction(
            "manual", path, "Automatic strip did not produce a clean, valid file; review by hand."
        )
    return CleanupAction(
        "rewrite",
        path,
        "Removed hidden payload appended after whitespace padding.",
        preview=_diff(path, text, new),
        new_text=new,
    )


def _plan_tasks(full: Path, path: str) -> CleanupAction:
    try:
        data = json.loads(full.read_text(encoding="utf-8-sig"))
        tasks = data.get("tasks", [])
    except (OSError, ValueError, AttributeError):
        return CleanupAction("manual", path, "Could not parse tasks.json; remove the task by hand.")
    if isinstance(tasks, list) and len(tasks) == 1:
        return _delete(full, path, "tasks.json contains only the malicious auto-run task.")
    return CleanupAction(
        "manual", path, "tasks.json has several tasks; remove only the malicious one."
    )


def _plan_package_json(base: Path, path: str) -> CleanupAction:
    full = base / path
    text = full.read_text(encoding="utf-8-sig")

    def read_sibling(rel: str) -> bytes | None:
        target = base / rel
        return target.read_bytes() if target.is_file() else None

    new = text
    for run in suspicious_script_runs(path, text, read_sibling):
        new = re.sub(r"node\s+" + re.escape(run.written_target) + r"\s*&&\s*", "", new)
    try:
        json.loads(new)
    except ValueError:
        return CleanupAction(
            "manual",
            path,
            "Could not safely edit package.json; remove the `node <file> &&` prefix by hand.",
        )
    if new == text:
        return CleanupAction(
            "manual", path, "Suspicious script prefix found but not removable automatically."
        )
    return CleanupAction(
        "rewrite",
        path,
        "Removed the `node <file>.js &&` prefix that runs the payload.",
        preview=_diff(path, text, new),
        new_text=new,
    )


# ---------------------------------------------------------------------------------------------
# Applying (CLI only)
# ---------------------------------------------------------------------------------------------


def default_quarantine() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path.home() / ".devguard-mcp" / "quarantine" / stamp


def apply_plan(plan: CleanupPlan, quarantine: Path | None = None) -> list[str]:
    """Quarantine originals, then delete or rewrite. Returns human-readable log lines."""
    root = Path(plan.root).resolve()
    quarantine = quarantine or default_quarantine()
    log: list[str] = []
    for action in plan.automatic:
        target = (root / action.path).resolve()
        if root not in target.parents:
            log.append(f"SKIPPED (outside root): {action.path}")
            continue
        if not target.is_file():
            log.append(f"SKIPPED (missing): {action.path}")
            continue
        saved = quarantine / action.path
        saved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, saved)
        os.chmod(saved, 0o600)
        if action.kind == "delete":
            target.unlink()
            log.append(f"DELETED   {action.path}  (original in {saved})")
        elif action.new_text is not None:
            target.write_text(action.new_text, encoding="utf-8")
            log.append(f"REWROTE   {action.path}  (original in {saved})")
    return log
