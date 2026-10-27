from __future__ import annotations

import json
import sys
from pathlib import Path

from devguard_mcp.cleanup import CleanupAction, CleanupPlan, apply_plan, plan_cleanup, strip_payload
from devguard_mcp.scanner import scan_directory
from tests.conftest import CLEAN_POSTCSS, FILLER, MARKER, padded

SHIM = (
    "import { createRequire } from 'module';\n\nconst require = createRequire(import.meta.url);\n\n"
)


def by_path(plan):  # type: ignore[no-untyped-def]
    return {a.path: a for a in plan.actions}


def test_strip_payload_keeps_legitimate_code_and_drops_the_tail() -> None:
    text = CLEAN_POSTCSS.rsplit("\n", 1)[0] + "\n" + padded("export default config;", marker=True)
    cleaned = strip_payload(text)
    assert cleaned is not None
    assert cleaned.endswith("export default config;\n")
    assert MARKER not in cleaned
    assert len(cleaned) < 200


def test_strip_payload_returns_none_when_nothing_to_remove() -> None:
    assert strip_payload(CLEAN_POSTCSS) is None


def test_strip_payload_drops_injected_require_shim_when_unused() -> None:
    shim = SHIM
    cleaned = strip_payload(shim + padded())
    assert cleaned == "export default config;\n"


def test_strip_payload_keeps_shim_when_require_is_used() -> None:
    shim = SHIM
    text = shim + "const x = require('y');\n" + padded()
    cleaned = strip_payload(text)
    assert cleaned is not None and "createRequire" in cleaned


def test_plan_is_a_dry_run_and_redacts_payload_in_previews(infected_project: Path) -> None:
    before = {p: p.read_bytes() for p in infected_project.rglob("*") if p.is_file()}
    plan = plan_cleanup(str(infected_project))
    after = {p: p.read_bytes() for p in infected_project.rglob("*") if p.is_file()}
    assert before == after  # nothing written

    actions = by_path(plan)
    assert actions["api.js"].kind == "delete"
    assert actions["public/fonts/fake.ttf"].kind == "delete"
    assert actions["postcss.config.mjs"].kind == "rewrite"
    assert actions["package.json"].kind == "rewrite"
    for action in plan.actions:
        assert FILLER not in action.preview
        assert MARKER not in action.preview
    assert "redacted" in actions["postcss.config.mjs"].preview
    assert plan.to_dict()["applied"] is False


def test_apply_quarantines_originals_and_leaves_a_clean_project(
    infected_project: Path, tmp_path_factory
) -> None:  # type: ignore[no-untyped-def]
    quarantine = tmp_path_factory.mktemp("quarantine")
    log = apply_plan(plan_cleanup(str(infected_project)), quarantine)
    assert len(log) == 4

    assert not (infected_project / "api.js").exists()
    assert not (infected_project / "public/fonts/fake.ttf").exists()
    pkg = json.loads((infected_project / "package.json").read_text())
    assert pkg["scripts"]["dev"] == "next dev"

    assert scan_directory(str(infected_project)).findings == []
    assert (quarantine / "api.js").read_text().startswith(f"var {MARKER}")
    if sys.platform != "win32":  # POSIX permission bits
        assert oct((quarantine / "api.js").stat().st_mode & 0o777) == "0o600"


def test_apply_is_idempotent(infected_project: Path, tmp_path_factory) -> None:  # type: ignore[no-untyped-def]
    apply_plan(plan_cleanup(str(infected_project)), tmp_path_factory.mktemp("q"))
    assert plan_cleanup(str(infected_project)).actions == []


def test_workflows_are_never_auto_edited(tmp_path: Path, write) -> None:  # type: ignore[no-untyped-def]
    write(
        ".github/workflows/github_actions_security.yml",
        "jobs:\n  send-secrets:\n    runs-on: x\n",
    )
    plan = plan_cleanup(str(tmp_path))
    assert plan.automatic == []
    (action,) = plan.actions
    assert action.kind == "manual"
    assert "DG-GA" in action.reason


def test_tasks_json_with_one_malicious_task_is_deleted_but_several_are_manual(
    tmp_path: Path, write
) -> None:  # type: ignore[no-untyped-def]
    task = {"command": "node", "args": ["a.ttf"], "runOptions": {"runOn": "folderOpen"}}
    write(".vscode/tasks.json", json.dumps({"tasks": [task]}))
    assert by_path(plan_cleanup(str(tmp_path)))[".vscode/tasks.json"].kind == "delete"
    write(".vscode/tasks.json", json.dumps({"tasks": [task, {"command": "ls"}]}))
    assert by_path(plan_cleanup(str(tmp_path)))[".vscode/tasks.json"].kind == "manual"


def test_apply_never_touches_paths_outside_the_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    plan = CleanupPlan(str(root), [CleanupAction("delete", "../victim.txt", "evil")])
    log = apply_plan(plan, tmp_path / "q")
    assert victim.read_text() == "keep me"
    assert "outside root" in log[0]
