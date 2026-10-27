# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (0.x: the API and rule ids may change).

## [Unreleased]

### Added
- `docs/RECOVERY.md`: recovery guide for affected devices (reset vs cleanup decision table,
  macOS/Windows/Linux reset steps, what to back up, full credential-rotation list, repository and
  GitHub recovery, best-effort containment, verification, hardening, FAQ).
- Test that every relative documentation link and anchor resolves.

## [0.1.0] - 2026-10-26

Initial alpha release.

### Added
- `devguard-mcp` CLI: `scan`, `history`, `workflows`, `machine`, `github`, `token`, `actions`,
  `fix`, `rules`, `iocs`, `checklist`, `serve`; `--json` and `--fail-on`; documented exit codes.
- MCP server (stdio) with 11 read-only tools, all annotated read-only; optional path allow-list
  via `DEVGUARD_ALLOWED_ROOTS`.
- PolinRider detection: known markers (strong and weak tiers), code hidden after whitespace
  padding, `package.json` scripts running large local files, auto-run VS Code tasks, fake font
  files, helper scripts, obfuscation heuristic.
- Git-history analysis: twin (rewritten) commits, committer-timezone re-stamping, first
  appearance of a marker, GhostAction commit messages. Git is invoked with hardening overrides and
  `--no-textconv`/`--no-ext-diff` so a hostile repository cannot make it run helpers.
- GhostAction detection in workflows: exfiltration hosts and job signatures, `curl` posting
  secrets (HTTP/raw-IP rated higher), `toJSON(secrets)`, history sweeps, `pull_request_target`
  head checkout.
- Machine checks for macOS, Linux and Windows: runner files, `node -e` processes, known
  attacker connections, startup items, shell files, tokens in shell history.
- GitHub scanning through the user's `gh` login: all branches, token-scope audit, Actions secret
  names and run actors.
- Cleanup planner with redacted diffs; `fix --apply` (CLI only) quarantines originals first.
- Recovery checklist, rule reference generated from code (`docs/RULES.md`), threat-intel notes.
- Test suite including an end-to-end stdio MCP test (coverage gate 85%); ruff, strict mypy and
  CI on Linux, macOS and Windows.
