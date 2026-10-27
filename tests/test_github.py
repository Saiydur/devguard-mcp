from __future__ import annotations

import json
from collections.abc import Sequence

import pytest

from devguard_mcp.github import (
    GhClient,
    GhError,
    audit_actions_exposure,
    audit_token,
    default_gh,
    scan_github,
)
from devguard_mcp.models import Severity
from tests.conftest import FILLER, MARKER, padded

DROPPER = f"var {MARKER}=1;{FILLER}".encode()
PKG = b'{"scripts":{"dev":"node api.js && next dev"}}'
POSTCSS = ("export default {};\n" + padded()).encode()


class FakeGitHub:
    """Serves a tiny repo: two branches sharing the infected files, one clean extra branch."""

    def __init__(self) -> None:
        self.blobs = {"b-api": DROPPER, "b-pkg": PKG, "b-css": POSTCSS, "b-ok": b"x=1;"}
        self.calls: list[Sequence[str]] = []

    def __call__(self, args: Sequence[str]) -> bytes:
        self.calls.append(args)
        head = args[0]
        if head == "repo" and args[1] == "list":
            return json.dumps([{"nameWithOwner": "me/app"}]).encode()
        if head == "api":
            path = args[1]
            if path.endswith("/branches?per_page=100"):
                return json.dumps(
                    [
                        {"name": "main", "commit": {"sha": "c-main"}},
                        {"name": "dev", "commit": {"sha": "c-dev"}},
                    ]
                ).encode()
            if "/git/trees/" in path:
                tree = [
                    {"type": "blob", "path": "api.js", "sha": "b-api", "size": len(DROPPER)},
                    {"type": "blob", "path": "package.json", "sha": "b-pkg", "size": len(PKG)},
                    {"type": "blob", "path": "postcss.config.mjs", "sha": "b-css", "size": 9000},
                    {"type": "blob", "path": "README.md", "sha": "b-readme", "size": 10},
                    {"type": "tree", "path": "src", "sha": "t"},
                ]
                if "c-dev" in path:
                    tree.append({"type": "blob", "path": "ok.js", "sha": "b-ok", "size": 4})
                return json.dumps({"tree": tree, "truncated": False}).encode()
            if "/git/blobs/" in path:
                return self.blobs[path.rsplit("/", 1)[-1]]
        raise AssertionError(f"unexpected gh call: {args}")


def test_scan_github_finds_dropper_across_branches_once() -> None:
    gh = FakeGitHub()
    report = scan_github("me", GhClient(gh))
    found = {f.rule_id for f in report.findings}
    assert {"DG-PR-001", "DG-PR-003", "DG-PR-004"} <= found
    dropper = next(f for f in report.findings if f.rule_id == "DG-PR-001")
    assert dropper.path == "me/app:api.js"
    assert "main, dev" in dropper.message
    # identical blobs on two branches are analysed once, not twice
    assert sum(1 for f in report.findings if f.rule_id == "DG-PR-001") == 1
    assert report.stats["repos_scanned"] == 1


def test_scan_github_only_issues_read_requests() -> None:
    gh = FakeGitHub()
    scan_github("me/app", GhClient(gh))
    for call in gh.calls:
        assert call[0] in {"api", "repo"}
        assert "-X" not in call and "--method" not in call


def test_scan_github_records_failed_repos_and_continues() -> None:
    def failing(args: Sequence[str]) -> bytes:
        if args[0] == "repo":
            return json.dumps([{"nameWithOwner": "a/b"}, {"nameWithOwner": "c/d"}]).encode()
        raise GhError("rate limited")

    report = scan_github("a", GhClient(failing))
    assert report.stats["repos_scanned"] == 0
    assert len([n for n in report.notes if "skipped" in n]) == 2


def test_scan_github_respects_repo_cap_note() -> None:
    gh = FakeGitHub()
    report = scan_github("me", GhClient(gh), max_repos=1)
    assert any("first 1 repositories" in n for n in report.notes)


def test_audit_token_flags_workflow_scope() -> None:
    headers = "HTTP/2.0 200 OK\nX-Oauth-Scopes: gist, read:org, repo, workflow\n\n{}"
    report = audit_token(GhClient(lambda _a: headers.encode()))
    (finding,) = report.findings
    assert finding.rule_id == "DG-CR-003"
    assert finding.severity is Severity.MEDIUM
    assert any("`repo` scope" in n for n in report.notes)


def test_audit_token_fine_grained_token_has_no_findings() -> None:
    report = audit_token(GhClient(lambda _a: b"HTTP/2.0 200 OK\nContent-Type: json\n\n{}"))
    assert report.findings == []
    assert any("fine-grained" in n for n in report.notes)


def test_audit_actions_lists_secret_names_never_values_and_unusual_actors() -> None:
    def gh(args: Sequence[str]) -> bytes:
        if args[0] == "secret":
            return b"VPS_SSH_KEY\tUpdated 2026-01-01\nDB_URL\tUpdated 2026-01-02\n"
        return json.dumps(
            {
                "workflow_runs": [
                    {"actor": {"login": "Me"}},
                    {"actor": {"login": "stranger"}},
                    {"actor": {"login": "dependabot[bot]"}},
                ]
            }
        ).encode()

    report = audit_actions_exposure("me/app", GhClient(gh))
    (finding,) = report.findings
    assert finding.rule_id == "DG-GH-001"
    assert "VPS_SSH_KEY" in finding.message and "DB_URL" in finding.message
    assert any("stranger" in n and "Me" not in n.split("triggered by:")[1] for n in report.notes)


def test_audit_actions_survives_missing_admin_rights() -> None:
    def gh(args: Sequence[str]) -> bytes:
        if args[0] == "secret":
            raise GhError("HTTP 403")
        return b'{"workflow_runs": []}'

    report = audit_actions_exposure("me/app", GhClient(gh))
    assert report.findings == []
    assert any("Admin access" in n for n in report.notes)


def test_default_gh_reports_missing_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("devguard_mcp.github.shutil.which", lambda _name: None)
    with pytest.raises(GhError, match="not found"):
        default_gh(["api", "user"])
