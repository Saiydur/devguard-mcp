"""Command-line interface: ``devguard-mcp <command>``.

Exit codes: 0 = nothing at or above ``--fail-on``; 1 = findings at or above it; 2 = error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from devguard_mcp import __version__, checklist, cleanup, github, history, machine, scanner
from devguard_mcp.history import GitError
from devguard_mcp.iocs import load_iocs
from devguard_mcp.models import Report, Severity
from devguard_mcp.rules import RULES, get_rule, rules_markdown

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
_COLORS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}


def _use_color() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def format_report(report: Report) -> str:
    """Human-readable rendering of a report."""
    color = _use_color()
    data = report.to_dict()
    lines = [f"devguard {report.kind} scan: {report.target}"]
    lines.append(f"verdict: {data['verdict']}  (rules {data['rules_version']})")
    if report.stats:
        lines.append("stats: " + ", ".join(f"{k}={v}" for k, v in report.stats.items()))
    lines.append("")
    for finding in report.sorted_findings():
        tag = finding.severity.name
        if color:
            tag = f"{_COLORS[finding.severity]}{tag}\033[0m"
        where = finding.path or ""
        if finding.line:
            where += f":{finding.line}"
        lines.append(f"[{tag}] {finding.rule_id} {where}".rstrip())
        lines.append(f"    {finding.message}")
        if finding.evidence:
            lines.append(f"    evidence: {finding.evidence}")
    if not report.findings:
        lines.append("No known indicators found.")
    for note in report.notes:
        lines.append(f"note: {note}")
    lines.append("")
    lines.append(data["disclaimer"])
    return "\n".join(lines)


def _emit(report: Report, args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_report(report))
    return EXIT_FINDINGS if report.exceeds(Severity.parse(args.fail_on)) else EXIT_OK


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument(
        "--fail-on",
        default="medium",
        choices=[s.name.lower() for s in Severity],
        help="exit with status 1 if any finding is at or above this severity (default: medium)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devguard-mcp",
        description="Detect PolinRider and GhostAction supply-chain malware. Read-only by "
        "default; the only command that changes files is `fix --apply`.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="scan a directory for indicators")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--max-files", type=int, default=scanner.DEFAULT_MAX_FILES)
    _add_common(p)

    p = sub.add_parser("history", help="analyse git history for rewritten commits")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--max-commits", type=int, default=history.DEFAULT_MAX_COMMITS)
    _add_common(p)

    p = sub.add_parser("workflows", help="scan GitHub Actions workflows (GhostAction)")
    p.add_argument("path", nargs="?", default=".")
    _add_common(p)

    p = sub.add_parser("machine", help="check this machine for the PolinRider runner")
    _add_common(p)

    p = sub.add_parser("github", help="scan GitHub repos via the `gh` CLI (owner or owner/repo)")
    p.add_argument("target")
    p.add_argument("--max-repos", type=int, default=github.DEFAULT_MAX_REPOS)
    p.add_argument("--max-branches", type=int, default=github.DEFAULT_MAX_BRANCHES)
    _add_common(p)

    p = sub.add_parser("token", help="report the scopes of the current gh login")
    _add_common(p)

    p = sub.add_parser("actions", help="list Actions secret names and run actors for owner/repo")
    p.add_argument("repo")
    _add_common(p)

    p = sub.add_parser("fix", help="plan (default) or apply (--apply) a cleanup")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--apply", action="store_true", help="write changes (originals are quarantined)")
    p.add_argument("--quarantine", type=Path, help="where to copy originals before changing them")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("rules", help="list rules, or explain one rule id")
    p.add_argument("rule_id", nargs="?")
    p.add_argument("--markdown", action="store_true", help="print the full rule reference")

    sub.add_parser("iocs", help="print the bundled indicators and their version")

    p = sub.add_parser("checklist", help="print ordered recovery steps")
    p.add_argument("--machine", action="store_true", help="the machine ran infected code")
    p.add_argument("--repos", action="store_true", help="repositories were infected")
    p.add_argument("--workflows", action="store_true", help="malicious workflows were found")

    sub.add_parser("serve", help="run the MCP server over stdio")
    return parser


def _cmd_fix(args: argparse.Namespace) -> int:
    plan = cleanup.plan_cleanup(args.path)
    if args.json:
        print(json.dumps(plan.to_dict(), indent=2))
    else:
        for action in plan.actions:
            print(f"[{action.kind.upper()}] {action.path}: {action.reason}")
            if action.preview:
                print(action.preview)
            print()
        if not plan.actions:
            print("Nothing to clean up.")
    if not args.apply:
        if plan.automatic:
            print("Dry run only. Re-run with --apply to make these changes.")
        return EXIT_OK
    if not plan.automatic:
        return EXIT_OK
    if not args.yes:
        answer = input(
            f"Apply {len(plan.automatic)} change(s)? Originals will be quarantined. [y/N] "
        )
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return EXIT_OK
    for line in cleanup.apply_plan(plan, args.quarantine):
        print(line)
    print(
        "Done. Now run `devguard-mcp checklist` and rotate credentials: "
        "cleanup does not undo theft."
    )
    return EXIT_OK


def _cmd_rules(args: argparse.Namespace) -> int:
    if args.markdown:
        print(rules_markdown(), end="")
        return EXIT_OK
    if args.rule_id:
        rule = get_rule(args.rule_id)
        if rule is None:
            print(f"unknown rule: {args.rule_id}", file=sys.stderr)
            return EXIT_ERROR
        print(f"{rule.id}  {rule.title}  [{rule.severity.name.lower()}, {rule.campaign}]")
        print(f"\n{rule.description}\n\nFix: {rule.remediation}")
        return EXIT_OK
    for rule in RULES.values():
        print(f"{rule.id}  {rule.severity.name.lower():8} {rule.title}")
    return EXIT_OK


def _cmd_checklist(args: argparse.Namespace) -> int:
    steps = checklist.build_checklist(
        machine_compromised=args.machine,
        repos_infected=args.repos,
        workflows_suspect=args.workflows,
    )
    for step in steps:
        print(f"{step['order']}. {step['title']}\n   {step['detail']}\n")
    return EXIT_OK


def _cmd_serve(_args: argparse.Namespace) -> int:
    try:
        # Imported lazily so every other command works without the MCP SDK installed.
        from devguard_mcp.server import main as serve  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - depends on the environment
        print(f"The MCP SDK is not installed ({exc}). Run: pip install mcp", file=sys.stderr)
        return EXIT_ERROR
    serve()
    return EXIT_OK


def _cmd_workflows(args: argparse.Namespace) -> int:
    report = scanner.scan_directory(args.path)
    report.findings = [f for f in report.findings if f.rule_id.startswith("DG-GA-")]
    report.kind = "workflows"
    return _emit(report, args)


def _cmd_iocs(_args: argparse.Namespace) -> int:
    print(json.dumps(load_iocs().to_dict(), indent=2))
    return EXIT_OK


_HANDLERS: dict[str, Callable[[argparse.Namespace], int]] = {
    "scan": lambda a: _emit(scanner.scan_directory(a.path, a.max_files), a),
    "history": lambda a: _emit(history.scan_history(a.path, a.max_commits), a),
    "workflows": _cmd_workflows,
    "machine": lambda a: _emit(machine.check_machine(), a),
    "github": lambda a: _emit(github.scan_github(a.target, None, a.max_repos, a.max_branches), a),
    "token": lambda a: _emit(github.audit_token(), a),
    "actions": lambda a: _emit(github.audit_actions_exposure(a.repo), a),
    "fix": _cmd_fix,
    "rules": _cmd_rules,
    "iocs": _cmd_iocs,
    "checklist": _cmd_checklist,
    "serve": _cmd_serve,
}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _HANDLERS[args.command](args)
    except (NotADirectoryError, GitError, github.GhError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
