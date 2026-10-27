from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from devguard_mcp.server import ALLOWED_ROOTS_ENV, build_server, resolve_path

EXPECTED_TOOLS = {
    "scan_directory",
    "scan_git_history",
    "scan_workflows",
    "check_machine",
    "scan_github",
    "audit_github_token",
    "audit_actions_exposure",
    "plan_cleanup",
    "recovery_checklist",
    "explain_rule",
    "list_iocs",
}


def call(name: str, args: dict[str, Any]) -> Any:
    result = asyncio.run(build_server().call_tool(name, args))
    assert not result.is_error, result
    return json.loads(result.content[0].text)  # type: ignore[union-attr]


def test_exactly_the_documented_tools_are_exposed() -> None:
    tools = asyncio.run(build_server().list_tools())
    assert {t.name for t in tools} == EXPECTED_TOOLS


def test_every_tool_is_marked_read_only_and_non_destructive() -> None:
    for tool in asyncio.run(build_server().list_tools()):
        assert tool.annotations is not None, tool.name
        assert tool.annotations.read_only_hint is True, tool.name
        assert tool.annotations.destructive_hint is False, tool.name


def test_no_tool_can_write_or_apply_changes() -> None:
    names = {t.name for t in asyncio.run(build_server().list_tools())}
    assert not {n for n in names if n.startswith(("apply", "fix", "delete", "write", "remove"))}


def test_only_github_tools_declare_open_world_access() -> None:
    open_world = {
        t.name
        for t in asyncio.run(build_server().list_tools())
        if t.annotations and t.annotations.open_world_hint
    }
    assert open_world == {"scan_github", "audit_github_token", "audit_actions_exposure"}


def test_scan_directory_tool_returns_structured_report(infected_project: Path) -> None:
    data = call("scan_directory", {"path": str(infected_project)})
    assert data["verdict"] == "likely-malicious-indicators-found"
    assert data["finding_count"] >= 4
    assert "disclaimer" in data


def test_plan_cleanup_tool_is_a_dry_run(infected_project: Path) -> None:
    data = call("plan_cleanup", {"path": str(infected_project)})
    assert data["applied"] is False
    assert (infected_project / "api.js").exists()


def test_explain_rule_and_unknown_rule() -> None:
    assert call("explain_rule", {"rule_id": "DG-GA-004"})["campaign"] == "ghostaction"
    with pytest.raises(ToolError, match="unknown rule"):
        asyncio.run(build_server().call_tool("explain_rule", {"rule_id": "nope"}))


def test_bad_path_is_a_clean_tool_error_not_a_crash(tmp_path: Path) -> None:
    with pytest.raises(ToolError, match="not a directory"):
        asyncio.run(build_server().call_tool("scan_directory", {"path": str(tmp_path / "nope")}))
    with pytest.raises(ToolError, match="not a git repository"):
        asyncio.run(build_server().call_tool("scan_git_history", {"path": str(tmp_path)}))


def test_list_iocs_and_checklist_tools() -> None:
    assert call("list_iocs", {})["version"]
    steps = call("recovery_checklist", {"machine_compromised": True})["steps"]
    assert [s["order"] for s in steps] == list(range(1, len(steps) + 1))


def test_resolve_path_enforces_allowed_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inside = tmp_path / "work"
    inside.mkdir()
    monkeypatch.setenv(ALLOWED_ROOTS_ENV, str(inside))
    assert resolve_path(str(inside)) == str(inside.resolve())
    with pytest.raises(ValueError, match="outside"):
        resolve_path(str(tmp_path))
    with pytest.raises(ValueError, match="outside"):
        resolve_path(str(inside / ".." / "etc"))


def test_resolve_path_unrestricted_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ALLOWED_ROOTS_ENV, raising=False)
    assert resolve_path(str(tmp_path)) == str(tmp_path.resolve())
