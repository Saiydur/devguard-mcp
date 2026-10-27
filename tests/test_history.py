from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from devguard_mcp.history import GitError, scan_history
from devguard_mcp.models import Severity
from tests.conftest import FILLER, MARKER, commit, git, requires_git

pytestmark = requires_git


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "base.txt").write_text("base\n")
    commit(tmp_path, "base", author_date="2026-01-01T10:00:00+0600")
    return tmp_path


def ids(report) -> set[str]:  # type: ignore[no-untyped-def]
    return {f.rule_id for f in report.findings}


def test_clean_history_has_no_findings(repo: Path) -> None:
    (repo / "a.txt").write_text("a\n")
    commit(repo, "feat: a", author_date="2026-01-02T10:00:00+0600")
    report = scan_history(str(repo))
    assert report.findings == []
    assert report.stats["commits_scanned"] == 2


def test_twin_commit_that_adds_a_dropper_is_high(repo: Path) -> None:
    date = "2026-01-05T12:00:00+0600"
    git(repo, "checkout", "-q", "-b", "original")
    (repo / "feature.txt").write_text("feature\n")
    commit(repo, "feat: add feature", author_date=date)

    git(repo, "checkout", "-q", "main")
    git(repo, "checkout", "-q", "-b", "twin")
    (repo / "feature.txt").write_text("feature\n")
    (repo / "api.js").write_text(FILLER)
    commit(repo, "feat: add feature", author_date=date)

    report = scan_history(str(repo))
    twins = [f for f in report.findings if f.rule_id == "DG-HS-001"]
    assert len(twins) == 1
    assert twins[0].severity is Severity.HIGH
    assert "api.js" in (twins[0].evidence or "")


def test_cherry_picks_with_identical_changes_are_not_flagged(repo: Path) -> None:
    date = "2026-01-05T12:00:00+0600"
    git(repo, "checkout", "-q", "-b", "one")
    (repo / "x.txt").write_text("x\n")
    commit(repo, "feat: x", author_date=date)
    git(repo, "checkout", "-q", "main")
    (repo / "unrelated.txt").write_text("u\n")  # different base, so a different tree
    commit(repo, "chore: unrelated", author_date="2026-01-04T12:00:00+0600")
    git(repo, "checkout", "-q", "-b", "two")
    (repo / "x.txt").write_text("x\n")
    commit(repo, "feat: x", author_date=date)

    assert "DG-HS-001" not in ids(scan_history(str(repo)))


def test_restamped_committer_timezone_is_reported(repo: Path) -> None:
    # 10:00+0600 == 05:00+0100: same instant, different timezone, same person.
    for i in range(3):
        (repo / f"f{i}.txt").write_text(str(i))
        commit(
            repo,
            f"change {i}",
            author_date=f"2026-02-0{i + 1}T10:00:00+0600",
            committer_date=f"2026-02-0{i + 1}T05:00:00+0100",
        )
    findings = [f for f in scan_history(str(repo)).findings if f.rule_id == "DG-HS-002"]
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "3 of" in findings[0].message


def test_single_restamped_commit_is_low(repo: Path) -> None:
    (repo / "f.txt").write_text("f")
    commit(
        repo,
        "one",
        author_date="2026-02-01T10:00:00+0600",
        committer_date="2026-02-01T05:00:00+0100",
    )
    (finding,) = [f for f in scan_history(str(repo)).findings if f.rule_id == "DG-HS-002"]
    assert finding.severity is Severity.LOW


def test_normal_timezone_difference_between_instants_is_ignored(repo: Path) -> None:
    (repo / "f.txt").write_text("f")
    commit(
        repo,
        "one",
        author_date="2026-02-01T10:00:00+0600",
        committer_date="2026-02-03T10:00:00+0100",  # different instant: e.g. a rebase
    )
    assert "DG-HS-002" not in ids(scan_history(str(repo)))


def test_first_introduction_of_marker_is_reported_as_info(repo: Path) -> None:
    (repo / "postcss.config.js").write_text(f"var {MARKER};\n")
    sha = commit(repo, "add config", author_date="2026-03-01T10:00:00+0600")
    (finding,) = [f for f in scan_history(str(repo)).findings if f.rule_id == "DG-HS-003"]
    assert finding.severity is Severity.INFO
    assert sha[:7] in finding.message
    assert "may be forged" in finding.message


def test_ghostaction_commit_message_is_flagged(repo: Path) -> None:
    (repo / "w.yml").write_text("x")
    commit(repo, "Add Github Actions Security workflow", author_date="2026-03-01T10:00:00+0600")
    assert "DG-GA-008" in ids(scan_history(str(repo)))


def test_not_a_repository_raises(tmp_path: Path) -> None:
    with pytest.raises(GitError):
        scan_history(str(tmp_path / "nope"))


def test_max_commits_truncates_and_notes_it(repo: Path) -> None:
    for i in range(3):
        (repo / f"f{i}").write_text("x")
        commit(repo, f"c{i}", author_date=f"2026-04-0{i + 1}T10:00:00+0600")
    report = scan_history(str(repo), max_commits=2)
    assert report.stats["commits_scanned"] == 2
    assert any("truncated" in n for n in report.notes)


def test_git_is_invoked_with_hardening_overrides(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hostile repo's config must not be able to make git run helpers."""
    captured: list[list[str]] = []
    real_run = subprocess.run

    def spy(cmd, *args, **kwargs):  # type: ignore[no-untyped-def]
        captured.append(list(cmd))
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr("devguard_mcp.history.subprocess.run", spy)
    scan_history(str(repo))
    assert captured
    for cmd in captured:
        assert "core.fsmonitor=false" in cmd
        assert any(part.startswith("core.hooksPath=") for part in cmd)
    pickaxe = [c for c in captured if any(p.startswith("-S") for p in c)]
    assert pickaxe and all("--no-textconv" in c and "--no-ext-diff" in c for c in pickaxe)


@pytest.mark.skipif(sys.platform == "win32", reason="uses a POSIX shell helper")
def test_malicious_textconv_driver_in_repo_config_is_not_executed(
    repo: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Regression: `git log -S` honours diff.<driver>.textconv unless told not to."""
    proof = tmp_path_factory.mktemp("proof") / "executed"
    git(repo, "config", "diff.evil.textconv", f"sh -c 'touch {proof}; cat' #")
    (repo / ".gitattributes").write_text("*.js diff=evil\n")
    (repo / "a.js").write_text(f"var {MARKER};\n")
    commit(repo, "add", author_date="2026-05-01T10:00:00+0600")
    scan_history(str(repo))
    assert not proof.exists()
