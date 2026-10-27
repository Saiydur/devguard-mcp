"""Git history analysis: detect rewritten ("twin") commits and re-stamped committer data.

PolinRider amends the most recent commit to add its payload and force-pushes, keeping the
original author and timestamp. That leaves two traces this module looks for:

* *twin commits*: same author, author time and subject, but a different set of changed files;
* *re-stamped committer data*: committer time equal to author time but in another timezone.

Everything here is read-only ``git`` plumbing. Commit dates can be forged, so findings describe
*what* changed, never *when* an attack happened.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from devguard_mcp.iocs import load_iocs
from devguard_mcp.models import Finding, Report, Severity, sanitize

GitRunner = Callable[[str, Sequence[str]], str]

DEFAULT_MAX_COMMITS = 20_000
MAX_TWIN_GROUPS = 25
MAX_TWIN_SHAS = 6
TZ_SUMMARY_THRESHOLD = 3
_FIELD, _RECORD = "\x1f", "\x1e"
_SUSPICIOUS_PATH = re.compile(
    r"(?:^|/)(?:api\.js|package\.json|tasks\.json|temp_auto_push\.bat|"
    r"[^/]*\.config\.(?:js|mjs|cjs|ts)|\.eslintrc\.(?:js|cjs)|"
    r"[^/]*\.(?:ttf|otf|woff2?|eot))$"
)


# A scanned repository is untrusted: its config could name helpers that git would execute.
# These overrides take precedence over the repository's own configuration.
_HARDENING = (
    "-c", "core.fsmonitor=false",
    "-c", f"core.hooksPath={os.devnull}",
    "-c", "core.pager=cat",
    "-c", "protocol.ext.allow=never",
)  # fmt: skip


class GitError(RuntimeError):
    """``git`` is missing, the path is not a repository, or a command failed."""


def run_git(repo: str, args: Sequence[str], timeout: int = 120) -> str:
    """Run a read-only git command. Never uses a shell."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
    try:
        result = subprocess.run(
            ["git", *_HARDENING, "-C", repo, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError(f"git failed: {exc}") from exc
    if result.returncode != 0:
        raise GitError(result.stderr.strip() or f"git exited with {result.returncode}")
    return result.stdout


@dataclass(frozen=True)
class Commit:
    sha: str
    author: str
    author_ts: int
    author_date: str
    committer: str
    committer_ts: int
    committer_date: str
    tree: str
    subject: str

    @property
    def author_tz(self) -> str:
        return self.author_date.rsplit(" ", 1)[-1]

    @property
    def committer_tz(self) -> str:
        return self.committer_date.rsplit(" ", 1)[-1]


def scan_history(
    repo: str, max_commits: int = DEFAULT_MAX_COMMITS, git: GitRunner = run_git
) -> Report:
    """Analyse the history of every ref in ``repo``."""
    path = os.path.realpath(os.path.expanduser(repo))
    try:
        git(path, ["rev-parse", "--git-dir"])
    except GitError as exc:
        raise GitError(f"not a git repository: {repo} ({exc})") from exc

    report = Report(target=path, kind="git-history")
    commits = _load_commits(path, max_commits, git)
    report.stats["commits_scanned"] = len(commits)
    if len(commits) >= max_commits:
        report.notes.append(f"History truncated at {max_commits} commits.")

    report.add(*_twin_findings(path, commits, git))
    report.add(*_timezone_findings(commits))
    report.add(*_introduction_findings(path, git))
    report.add(*_message_findings(path, git))
    report.notes.append(
        "Commit timestamps are attacker-controlled; use these findings to locate files, "
        "not to date an incident."
    )
    return report


def _load_commits(path: str, limit: int, git: GitRunner) -> list[Commit]:
    fmt = _FIELD.join(["%H", "%an", "%at", "%ai", "%cn", "%ct", "%ci", "%T", "%s"]) + _RECORD
    out = git(path, ["log", "--all", f"--max-count={limit}", f"--format={fmt}"])
    commits: list[Commit] = []
    for record in out.split(_RECORD):
        parts = record.strip("\n").split(_FIELD)
        if len(parts) != 9 or not parts[0]:
            continue
        try:
            commits.append(
                Commit(
                    parts[0],
                    parts[1],
                    int(parts[2]),
                    parts[3],
                    parts[4],
                    int(parts[5]),
                    parts[6],
                    parts[7],
                    parts[8],
                )
            )
        except ValueError:
            continue
    return commits


def _changed_files(path: str, sha: str, git: GitRunner) -> set[str]:
    out = git(
        path,
        ["diff-tree", "--no-commit-id", "--name-only", "-r", "-m", "--first-parent", sha],
    )
    return {line for line in out.splitlines() if line}


def _twin_findings(path: str, commits: list[Commit], git: GitRunner) -> list[Finding]:
    groups: dict[tuple[str, int, str], list[Commit]] = defaultdict(list)
    for commit in commits:
        groups[(commit.author, commit.author_ts, commit.subject)].append(commit)

    findings: list[Finding] = []
    examined = 0
    for (_, _, subject), members in groups.items():
        if len({c.tree for c in members}) < 2:
            continue
        if examined >= MAX_TWIN_GROUPS:
            break
        examined += 1
        shas = [c.sha for c in members[:MAX_TWIN_SHAS]]
        try:
            sets = {sha: _changed_files(path, sha, git) for sha in shas}
        except GitError:
            continue
        union = set().union(*sets.values())
        common = set.intersection(*sets.values())
        extra = union - common
        if not extra:
            continue  # plain cherry-picks change the same files
        suspicious = sorted(p for p in extra if _SUSPICIOUS_PATH.search(p))
        severity = Severity.HIGH if suspicious else Severity.MEDIUM
        findings.append(
            Finding(
                "DG-HS-001",
                severity,
                f"{len(members)} commits share author, time and subject "
                f"'{sanitize(subject, 50)}' but touch different files "
                f"({', '.join(s[:8] for s in shas)}).",
                evidence=sanitize(", ".join((suspicious or sorted(extra))[:5])),
                campaign="polinrider",
            )
        )
    return findings


def _timezone_findings(commits: list[Commit]) -> list[Finding]:
    restamped = [
        c
        for c in commits
        if c.author == c.committer
        and c.author_ts == c.committer_ts
        and c.author_tz != c.committer_tz
    ]
    if not restamped:
        return []
    severity = Severity.MEDIUM if len(restamped) >= TZ_SUMMARY_THRESHOLD else Severity.LOW
    example = restamped[0]
    return [
        Finding(
            "DG-HS-002",
            severity,
            f"{len(restamped)} of {len(commits)} commits have a committer time equal to the "
            f"author time but in a different timezone (e.g. {example.sha[:8]}: "
            f"author {example.author_tz}, committer {example.committer_tz}).",
            evidence=", ".join(c.sha[:8] for c in restamped[:5]),
            campaign="polinrider",
        )
    ]


def _introduction_findings(path: str, git: GitRunner) -> list[Finding]:
    findings: list[Finding] = []
    for marker in load_iocs().strong_markers:
        if not marker.literal:
            continue
        try:
            out = git(
                path,
                [
                    "log",
                    "--all",
                    "--reverse",
                    "--no-textconv",  # never run a repository-defined diff helper
                    "--no-ext-diff",
                    "-S" + marker.literal,
                    f"--format=%h{_FIELD}%an{_FIELD}%ai{_FIELD}%s",
                ],
            )
        except GitError:
            continue
        first = next((ln for ln in out.splitlines() if ln.strip()), "")
        parts = first.split(_FIELD)
        if len(parts) == 4:
            findings.append(
                Finding(
                    "DG-HS-003",
                    Severity.INFO,
                    f"Marker '{marker.id}' first appears in commit {parts[0]} by "
                    f"'{sanitize(parts[1], 30)}' dated {parts[2]} ('{sanitize(parts[3], 50)}'). "
                    "The date may be forged.",
                    campaign=marker.campaign,
                )
            )
    return findings


def _message_findings(path: str, git: GitRunner) -> list[Finding]:
    wanted = {m.lower() for m in load_iocs().suspicious_commit_messages}
    try:
        out = git(path, ["log", "--all", f"--format=%h{_FIELD}%an{_FIELD}%s"])
    except GitError:
        return []
    findings: list[Finding] = []
    for line in out.splitlines():
        parts = line.split(_FIELD)
        if len(parts) == 3 and parts[2].strip().lower() in wanted:
            findings.append(
                Finding(
                    "DG-GA-008",
                    Severity.MEDIUM,
                    f"Commit {parts[0]} by '{sanitize(parts[1], 30)}' uses a message "
                    f"associated with GhostAction: '{sanitize(parts[2], 60)}'.",
                    campaign="ghostaction",
                )
            )
    return findings[:10]
