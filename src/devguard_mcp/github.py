"""Read-only scanning of GitHub repositories through the user's own ``gh`` login.

No token is read, stored or transmitted by this package: every request is made by invoking the
GitHub CLI, which uses the credentials the user already configured. Only GET-style ``gh api``
calls and ``gh repo list`` / ``gh secret list`` are issued.
"""

from __future__ import annotations

import dataclasses
import json
import shutil
import subprocess
from collections.abc import Callable, Sequence
from typing import Any

from devguard_mcp.models import Finding, Report, Severity, sanitize
from devguard_mcp.scanner import analyze_file, is_relevant

GhRunner = Callable[[Sequence[str]], bytes]

DEFAULT_MAX_REPOS = 25
DEFAULT_MAX_BRANCHES = 15
MAX_BLOB_BYTES = 400_000
BROAD_SCOPES = {
    "workflow": "can create or change GitHub Actions workflows (GhostAction's entry point)",
    "delete_repo": "can delete repositories",
    "admin:org": "can administer organisations",
    "admin:repo_hook": "can manage repository webhooks",
    "admin:public_key": "can manage SSH keys on the account",
    "write:packages": "can publish packages",
}


class GhError(RuntimeError):
    """The GitHub CLI is missing, not logged in, or a call failed."""


def default_gh(args: Sequence[str]) -> bytes:
    if shutil.which("gh") is None:
        raise GhError("GitHub CLI (`gh`) not found. Install it and run `gh auth login`.")
    try:
        result = subprocess.run(["gh", *args], capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GhError(f"gh failed: {exc}") from exc
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise GhError(sanitize(message or f"gh exited with {result.returncode}", 200))
    return result.stdout


class GhClient:
    """Thin wrapper that only ever issues read requests."""

    def __init__(self, runner: GhRunner = default_gh) -> None:
        self._run = runner

    def api(self, path: str) -> Any:
        return json.loads(self._run(["api", path]).decode("utf-8", errors="replace") or "null")

    def blob(self, repo: str, sha: str) -> bytes:
        return self._run(
            ["api", f"repos/{repo}/git/blobs/{sha}", "-H", "Accept: application/vnd.github.raw"]
        )

    def list_repos(self, owner: str, limit: int) -> list[str]:
        out = self._run(["repo", "list", owner, "--limit", str(limit), "--json", "nameWithOwner"])
        return [r["nameWithOwner"] for r in json.loads(out or b"[]")]

    def text(self, args: Sequence[str]) -> str:
        return self._run(args).decode("utf-8", errors="replace")


def scan_github(
    target: str,
    client: GhClient | None = None,
    max_repos: int = DEFAULT_MAX_REPOS,
    max_branches: int = DEFAULT_MAX_BRANCHES,
) -> Report:
    """Scan ``owner`` (all repos, capped) or ``owner/repo`` across its branches."""
    client = client or GhClient()
    report = Report(target=target, kind="github")
    repos = [target] if "/" in target else client.list_repos(target, max_repos)
    if "/" not in target and len(repos) >= max_repos:
        report.notes.append(f"Only the first {max_repos} repositories were scanned.")
    report.stats["repos_scanned"] = 0
    report.stats["files_scanned"] = 0

    for repo in repos:
        try:
            _scan_repo(repo, client, max_branches, report)
            report.stats["repos_scanned"] += 1
        except GhError as exc:
            report.notes.append(f"{repo}: skipped ({exc})")
    return report


def _scan_repo(repo: str, client: GhClient, max_branches: int, report: Report) -> None:
    branches = client.api(f"repos/{repo}/branches?per_page=100") or []
    if len(branches) > max_branches:
        report.notes.append(f"{repo}: only {max_branches} of {len(branches)} branches scanned.")
    branches = branches[:max_branches]

    seen: dict[tuple[str, str], list[str]] = {}
    trees: dict[str, dict[str, str]] = {}
    for branch in branches:
        tree = client.api(f"repos/{repo}/git/trees/{branch['commit']['sha']}?recursive=1") or {}
        if tree.get("truncated"):
            report.notes.append(f"{repo}@{branch['name']}: file tree truncated by GitHub.")
        paths: dict[str, str] = {}
        for entry in tree.get("tree", []):
            if entry.get("type") != "blob":
                continue
            paths[entry["path"]] = entry["sha"]
            if is_relevant(entry["path"]) and entry.get("size", 0) <= MAX_BLOB_BYTES:
                seen.setdefault((entry["path"], entry["sha"]), []).append(branch["name"])
        trees[branch["name"]] = paths

    cache: dict[str, bytes] = {}

    def fetch(sha: str) -> bytes:
        if sha not in cache:
            cache[sha] = client.blob(repo, sha)
        return cache[sha]

    for (path, sha), on_branches in seen.items():
        first = trees[on_branches[0]]

        def sibling(rel: str, paths: dict[str, str] = first) -> bytes | None:
            blob_sha = paths.get(rel)
            return fetch(blob_sha) if blob_sha else None

        report.stats["files_scanned"] += 1
        for finding in analyze_file(path, fetch(sha), sibling):
            report.add(_with_location(finding, repo, on_branches))


def _with_location(finding: Finding, repo: str, branches: list[str]) -> Finding:
    shown = ", ".join(branches[:4]) + (" ..." if len(branches) > 4 else "")
    return dataclasses.replace(
        finding,
        path=f"{repo}:{finding.path}",
        message=f"{finding.message} [branches: {shown}]",
    )


def audit_token(client: GhClient | None = None) -> Report:
    """Report the OAuth scopes of the current ``gh`` login (never the token itself)."""
    client = client or GhClient()
    report = Report(target="gh auth token", kind="github-token")
    headers = client.text(["api", "-i", "user"]).split("\n\n", 1)[0]
    scopes_line = next(
        (ln for ln in headers.splitlines() if ln.lower().startswith("x-oauth-scopes:")), None
    )
    if scopes_line is None:
        report.notes.append(
            "No X-OAuth-Scopes header: this looks like a fine-grained token or GitHub App "
            "token, which is the safer choice."
        )
        return report
    scopes = [s.strip() for s in scopes_line.split(":", 1)[1].split(",") if s.strip()]
    report.stats["scope_count"] = len(scopes)
    report.notes.append(f"Scopes: {', '.join(scopes) or '(none)'}")
    for scope in scopes:
        if scope in BROAD_SCOPES:
            report.add(
                Finding(
                    "DG-CR-003",
                    Severity.MEDIUM if scope == "workflow" else Severity.LOW,
                    f"Token scope '{scope}' {BROAD_SCOPES[scope]}.",
                    campaign="ghostaction",
                )
            )
    if "repo" in scopes:
        report.notes.append(
            "The `repo` scope grants full read/write to every private repo. Prefer a "
            "fine-grained token limited to the repositories you need."
        )
    return report


def audit_actions_exposure(repo: str, client: GhClient | None = None) -> Report:
    """List which secret *names* a malicious workflow could read, and unusual run actors."""
    client = client or GhClient()
    report = Report(target=repo, kind="github-actions")
    owner = repo.split("/", 1)[0].lower()

    try:
        listing = client.text(["secret", "list", "-R", repo])
    except GhError as exc:
        report.notes.append(f"Could not list secrets ({exc}). Admin access is required.")
        listing = ""
    names = [ln.split()[0] for ln in listing.splitlines() if ln.strip()]
    report.stats["secret_count"] = len(names)
    if names:
        report.add(
            Finding(
                "DG-GH-001",
                Severity.INFO,
                f"{len(names)} Actions secret(s) readable by workflows: {', '.join(names[:20])}"
                + (" ..." if len(names) > 20 else ""),
                path=repo,
                campaign="ghostaction",
            )
        )

    runs = (client.api(f"repos/{repo}/actions/runs?per_page=30") or {}).get("workflow_runs", [])
    report.stats["recent_runs"] = len(runs)
    trusted = {owner, "dependabot[bot]", "github-actions[bot]", "renovate[bot]"}
    unusual = sorted(
        {r["actor"]["login"] for r in runs if r["actor"]["login"].lower() not in trusted}
    )
    if unusual:
        report.notes.append(
            "Recent workflow runs were triggered by: " + ", ".join(unusual[:10]) + ". "
            "Confirm these are collaborators you expect."
        )
    return report
