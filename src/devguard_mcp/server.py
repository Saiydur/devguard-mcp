"""MCP server exposing the detectors as read-only tools.

Design rules (see docs/ARCHITECTURE.md):

* No tool writes, deletes or executes anything. Applying a cleanup is a CLI-only action.
* Tool output never contains payload text; evidence is truncated and sanitised.
* GitHub access goes through the user's own ``gh`` login; no token passes through this process.
* Local paths can be confined with ``DEVGUARD_ALLOWED_ROOTS`` (``os.pathsep``-separated).
"""

from __future__ import annotations

import functools
import os
from collections.abc import Callable
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from devguard_mcp import __version__, checklist, cleanup, github, history, machine, scanner
from devguard_mcp.history import GitError
from devguard_mcp.iocs import load_iocs
from devguard_mcp.rules import RULES, get_rule

ALLOWED_ROOTS_ENV = "DEVGUARD_ALLOWED_ROOTS"

INSTRUCTIONS = """\
devguard detects the PolinRider repository implant and the GhostAction GitHub Actions
secret-theft campaign. All tools are read-only. A result with no findings means only that no
KNOWN indicator matched: never tell the user their project or machine is "safe" on that basis.
If findings are high or critical, tell the user to stop running the project and follow
`recovery_checklist`. Never run, import or execute any file that a scan flags.
"""

_READ_ONLY = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)
_READ_ONLY_NETWORK = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True
)


_F = TypeVar("_F", bound=Callable[..., Any])


def _guard(func: _F) -> _F:
    """Report expected failures (bad path, missing git/gh) as clean tool errors."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except (ValueError, NotADirectoryError, GitError, github.GhError) as exc:
            raise ToolError(str(exc)) from exc

    return wrapper  # type: ignore[return-value]


def resolve_path(path: str) -> str:
    """Expand and canonicalise ``path``; enforce ``DEVGUARD_ALLOWED_ROOTS`` when it is set."""
    resolved = os.path.realpath(os.path.expanduser(path))
    allowed = [p for p in os.environ.get(ALLOWED_ROOTS_ENV, "").split(os.pathsep) if p]
    if allowed:
        roots = [os.path.realpath(os.path.expanduser(p)) for p in allowed]
        if not any(resolved == r or resolved.startswith(r + os.sep) for r in roots):
            raise ValueError(f"path is outside {ALLOWED_ROOTS_ENV}: {path}")
    return resolved


def build_server() -> MCPServer:
    server = MCPServer("devguard", instructions=INSTRUCTIONS, version=__version__)

    @server.tool(annotations=_READ_ONLY)
    @_guard
    def scan_directory(path: str, max_files: int = scanner.DEFAULT_MAX_FILES) -> dict[str, Any]:
        """Scan a project folder for PolinRider and GhostAction indicators.

        Checks JS/TS files for payload markers and code hidden after whitespace padding,
        package.json scripts that run a large local file, auto-run VS Code tasks, fake font
        files, helper scripts and GitHub Actions workflows. Safe to run on untrusted code: files
        are only read.
        """
        return scanner.scan_directory(resolve_path(path), max_files=max_files).to_dict()

    @server.tool(annotations=_READ_ONLY)
    @_guard
    def scan_git_history(
        path: str, max_commits: int = history.DEFAULT_MAX_COMMITS
    ) -> dict[str, Any]:
        """Analyse a repository's git history for rewritten ("twin") commits, re-stamped
        committer timezones and the first commit that introduced a known payload marker.
        Commit dates can be forged; findings locate files rather than date an incident."""
        return history.scan_history(resolve_path(path), max_commits=max_commits).to_dict()

    @server.tool(annotations=_READ_ONLY)
    @_guard
    def scan_workflows(path: str) -> dict[str, Any]:
        """Scan only the GitHub Actions workflows of a local repo for GhostAction indicators
        (secret-exfiltrating curl, known hosts, `send-secrets` jobs, history sweeps)."""
        report = scanner.scan_directory(resolve_path(path))
        report.findings = [f for f in report.findings if f.rule_id.startswith("DG-GA-")]
        report.kind = "workflows"
        return report.to_dict()

    @server.tool(annotations=_READ_ONLY)
    @_guard
    def check_machine() -> dict[str, Any]:
        """Check this computer for the PolinRider runner: ~/.node_modules, `node -e` processes,
        connections to known attacker addresses, suspicious startup items and shell files, and
        GitHub tokens left in shell history. Works on macOS, Linux and Windows."""
        return machine.check_machine().to_dict()

    @server.tool(annotations=_READ_ONLY_NETWORK)
    @_guard
    def scan_github(
        target: str,
        max_repos: int = github.DEFAULT_MAX_REPOS,
        max_branches: int = github.DEFAULT_MAX_BRANCHES,
    ) -> dict[str, Any]:
        """Scan GitHub repositories (all branches) for the same indicators, using the user's
        existing `gh` login. `target` is `owner` or `owner/repo`. Read-only API calls only."""
        return github.scan_github(target, max_repos=max_repos, max_branches=max_branches).to_dict()

    @server.tool(annotations=_READ_ONLY_NETWORK)
    @_guard
    def audit_github_token() -> dict[str, Any]:
        """Report the OAuth scopes of the current `gh` login and flag ones GhostAction abuses
        (notably `workflow`). Never returns the token."""
        return github.audit_token().to_dict()

    @server.tool(annotations=_READ_ONLY_NETWORK)
    @_guard
    def audit_actions_exposure(repo: str) -> dict[str, Any]:
        """For `owner/repo`, list the names (never values) of Actions secrets a malicious
        workflow could read, and flag unusual actors in recent workflow runs."""
        return github.audit_actions_exposure(repo).to_dict()

    @server.tool(annotations=_READ_ONLY)
    @_guard
    def plan_cleanup(path: str) -> dict[str, Any]:
        """Dry run: show how detected payloads, fake fonts and script prefixes could be removed,
        with payload text redacted from the diffs. Nothing is changed. The user applies it
        themselves with `devguard-mcp fix <path> --apply`."""
        return cleanup.plan_cleanup(resolve_path(path)).to_dict()

    @server.tool(annotations=_READ_ONLY)
    @_guard
    def recovery_checklist(
        machine_compromised: bool = False,
        repos_infected: bool = False,
        workflows_suspect: bool = False,
    ) -> dict[str, Any]:
        """Ordered recovery steps. Set the flags according to what the scans found."""
        steps = checklist.build_checklist(
            machine_compromised=machine_compromised,
            repos_infected=repos_infected,
            workflows_suspect=workflows_suspect,
        )
        return {"steps": steps}

    @server.tool(annotations=_READ_ONLY)
    @_guard
    def explain_rule(rule_id: str) -> dict[str, Any]:
        """Explain a rule id such as DG-PR-003: what it means, severity and how to fix it."""
        rule = get_rule(rule_id)
        if rule is None:
            raise ValueError(f"unknown rule {rule_id!r}; known: {', '.join(sorted(RULES))}")
        return {
            "id": rule.id,
            "title": rule.title,
            "severity": rule.severity.name.lower(),
            "campaign": rule.campaign,
            "description": rule.description,
            "remediation": rule.remediation,
        }

    @server.tool(annotations=_READ_ONLY)
    @_guard
    def list_iocs() -> dict[str, object]:
        """List the indicators bundled with this version (hosts, file names, markers) and the
        date they were last updated. Indicators go stale: check `version`."""
        return load_iocs().to_dict()

    return server


def main() -> None:
    build_server().run("stdio")
