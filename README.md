# devguard-mcp

[![CI](https://github.com/OWNER/devguard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/devguard-mcp/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

A **read-only** command-line tool and [MCP](https://modelcontextprotocol.io) server that detects two
developer-targeting supply-chain campaigns:

- **PolinRider**: a DPRK-linked implant that hides obfuscated JavaScript in the config files of
  GitHub repositories (`postcss.config.*`, `tailwind.config.js`, `eslint.config.*`, ...), in
  `api.js` droppers wired into `package.json` scripts, in fake font files run by auto-run VS Code
  tasks, and that rewrites commits to hide itself. The payload installs a runner that steals
  credentials.
- **GhostAction**: malicious GitHub Actions workflows, planted with stolen tokens, that read your
  repository secrets and send them to an attacker.

It works on **macOS, Linux and Windows**, scans without executing anything, and lets an AI
assistant (Claude Code, Claude Desktop, Cursor, VS Code, ...) answer *"is this repo safe to run?"*
before you type `npm run dev`.

> **Read this first.** A scan with no findings means *none of the known patterns matched*. It is
> **not** proof that a project or machine is safe. Indicators change quickly, the second-stage
> payload is downloaded at runtime, and this tool cannot see what it does. See
> [Limitations](#limitations).

> **Think you are already infected?** Go straight to the
> **[recovery guide](docs/RECOVERY.md)**: how to decide between a reset and a cleanup, how to
> reset macOS, Windows or Linux, which credentials to rotate and in what order, and what to do if
> you cannot reset yet. Do the account steps from a *different* device.

## Contents

- [What it checks](#what-it-checks)
- [Install](#install)
- [Quick start (CLI)](#quick-start-cli)
- [Use with an AI assistant (MCP)](#use-with-an-ai-assistant-mcp)
- [MCP tools](#mcp-tools)
- [Cleaning up an infected project](#cleaning-up-an-infected-project) · [recovery guide](docs/RECOVERY.md)
- [Safety model](#safety-model)
- [Configuration](#configuration)
- [Limitations](#limitations)
- [Documentation](#documentation) · [Development](#development) · [Contributing](#contributing) · [License](#license)

## What it checks

| Area | Examples | Rules |
|------|----------|-------|
| **Source files** | known loader markers; code hidden after a long whitespace run on a very long line; heavily obfuscated JS | `DG-PR-001`..`003`, `009` |
| **`package.json`** | `"dev": "node api.js && next dev"` where `api.js` is large or obfuscated | `DG-PR-004` |
| **VS Code** | `.vscode/tasks.json` tasks with `runOn: folderOpen` that download code or run `node` on a font | `DG-PR-005`, `006` |
| **Fake fonts** | `.ttf/.otf/.woff/.woff2/.eot` files that are really JavaScript | `DG-PR-007` |
| **Helper files** | `temp_auto_push.bat` | `DG-PR-008` |
| **Git history** | rewritten "twin" commits; committer time re-stamped into another timezone; first commit containing a marker | `DG-HS-001`..`003` |
| **GitHub Actions** | `send-secrets` jobs, `curl` posting `${{ secrets.* }}`, known exfiltration hosts, `toJSON(secrets)`, history sweeps | `DG-GA-001`..`008` |
| **This machine** | `~/.node_modules` runner, `node -e` processes, connections to known attacker IPs, startup items, shell rc files, tokens in shell history | `DG-MC-001`..`005`, `DG-CR-001` |
| **GitHub account** (via `gh`) | every branch of your repos; token scopes like `workflow`; which Actions secrets a malicious workflow could read | `DG-CR-003`, `DG-GH-001` |

The full list, with severities and remediation, is in [docs/RULES.md](docs/RULES.md).

## Install

`devguard-mcp` is not on PyPI yet. Install from source (Python 3.10 or newer):

```bash
git clone https://github.com/OWNER/devguard-mcp.git
cd devguard-mcp

# Option A: isolated command with pipx
pipx install .

# Option B: a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install .

devguard-mcp --version
```

The scanning code uses only the Python standard library. The `mcp` package is needed only for
`devguard-mcp serve`.

Optional: the [GitHub CLI](https://cli.github.com) (`gh`), logged in with `gh auth login`, for the
`github`, `token` and `actions` commands. `devguard-mcp` never reads or stores your token; it only
runs read-only `gh` commands.

## Quick start (CLI)

```bash
# Scan a project before running it (safe on untrusted code: files are only read)
devguard-mcp scan path/to/project

# Look for rewritten commits and the first commit that contained a marker
devguard-mcp history path/to/project

# Only the GitHub Actions workflows
devguard-mcp workflows path/to/project

# Check this computer for the runner, suspicious processes, startup items, tokens in history
devguard-mcp machine

# Scan every branch of your GitHub repos (needs `gh`)
devguard-mcp github YOUR_USERNAME
devguard-mcp github owner/repo

# Which scopes does my gh token have? Which secrets could a malicious workflow read?
devguard-mcp token
devguard-mcp actions owner/repo

# Explain a rule, list indicators, print recovery steps
devguard-mcp rules DG-PR-003
devguard-mcp iocs
devguard-mcp checklist --machine --repos
```

Add `--json` for machine-readable output and `--fail-on high` to control the exit status.

| Exit code | Meaning |
|-----------|---------|
| `0` | nothing at or above `--fail-on` (default `medium`) |
| `1` | at least one finding at or above `--fail-on` |
| `2` | usage or runtime error (bad path, `git`/`gh` missing, ...) |

Example output:

```text
devguard directory scan: /work/shop
verdict: likely-malicious-indicators-found  (rules 2026-10-26)
stats: files_scanned=129, files_skipped=0

[HIGH] DG-PR-003 postcss.config.mjs:11
    Code hidden after a long whitespace run on a very long line.
    evidence: whitespace run of 336 chars, then 12319 more chars of code
[HIGH] DG-PR-004 package.json
    Script 'dev' runs 'api.js' (12564 bytes) before the real command.
    evidence: node api.js && next dev
```

More recipes (CI, pre-commit, scanning a fresh clone) are in [docs/USAGE.md](docs/USAGE.md).

## Use with an AI assistant (MCP)

`devguard-mcp serve` starts an MCP server on stdio. Find the absolute path of the command first:

```bash
which devguard-mcp        # Windows: where devguard-mcp
```

**Claude Code**

```bash
claude mcp add devguard -- /absolute/path/to/devguard-mcp serve
```

**Claude Desktop** (`claude_desktop_config.json`), **Cursor** (`~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "devguard": {
      "command": "/absolute/path/to/devguard-mcp",
      "args": ["serve"]
    }
  }
}
```

**VS Code** (`.vscode/mcp.json`)

```json
{
  "servers": {
    "devguard": {
      "type": "stdio",
      "command": "/absolute/path/to/devguard-mcp",
      "args": ["serve"]
    }
  }
}
```

Config locations and formats change between client versions; check your client's MCP documentation
if the above does not match.

Then ask, for example:

- *"Scan `~/Downloads/interview-task` with devguard before I run it."*
- *"Check this machine for PolinRider."*
- *"Scan my GitHub account `octocat` for GhostAction workflows and tell me which secrets are exposed."*
- *"Plan a cleanup for this repo and explain every change."*

To confine the server to certain folders, set `DEVGUARD_ALLOWED_ROOTS` in the client's `env`
(see [Configuration](#configuration)).

## MCP tools

Every tool is **read-only** and annotated `readOnlyHint: true, destructiveHint: false`. There is
deliberately no tool that writes, deletes or executes anything.

| Tool | Purpose | Network |
|------|---------|---------|
| `scan_directory` | PolinRider and GhostAction indicators in a folder | no |
| `scan_git_history` | twin commits, re-stamped timezones, first appearance of a marker | no |
| `scan_workflows` | GitHub Actions workflows only | no |
| `check_machine` | runner, processes, connections, startup items, shell files, tokens in history | no |
| `scan_github` | the same checks on GitHub repos and branches, via `gh` | yes (GitHub) |
| `audit_github_token` | scopes of the current `gh` login (never the token) | yes (GitHub) |
| `audit_actions_exposure` | Actions secret *names* and unusual run actors for a repo | yes (GitHub) |
| `plan_cleanup` | dry-run diffs with payload text redacted | no |
| `recovery_checklist` | ordered recovery steps | no |
| `explain_rule` | what a rule means and how to fix it | no |
| `list_iocs` | bundled indicators and their version date | no |

## Cleaning up an infected project

Removing the files is the easy part; the hard part is assuming the machine that ran the project
may be compromised. Use `plan_cleanup` (or `fix` without `--apply`) to see what would change:

```bash
devguard-mcp fix path/to/project            # dry run: diffs only, payload text redacted
devguard-mcp fix path/to/project --apply    # asks for confirmation
```

`--apply` is **CLI-only** (the MCP server cannot do it). Before changing anything it copies each
original into `~/.devguard-mcp/quarantine/<timestamp>/` with mode `0600` (override with
`--quarantine DIR`). It deletes dropper files and fake fonts, strips padded payloads from config
files (and re-checks that the result is clean and, when `node` is available, syntactically
valid), and removes the `node file.js &&` prefix from `package.json` scripts. Workflows and
anything ambiguous are reported as **manual** and never edited.

After cleaning, run `devguard-mcp checklist` and **rotate credentials from a clean device**:
cleanup does not undo theft. If the machine itself ran the code, cleaning files is not enough:
follow the [recovery guide](docs/RECOVERY.md) (a reset is the reliable fix).

## Safety model

This tool reads untrusted code and its output may be shown to an LLM, so it is built defensively:

- **Never executes** scanned files; no `eval`, no `import`, no shell. Subprocesses (`git`, `gh`,
  `ps`, `lsof`, ...) use fixed argument lists.
- **Read-only by default.** The only command that writes is `fix --apply`, and it is not exposed
  over MCP.
- **Output is data, not payload.** Evidence is printable ASCII, whitespace-collapsed and truncated
  to 96 characters; tokens are shown as a 4-character prefix plus length; diffs redact long lines.
  This limits what a malicious repository can smuggle into an assistant's context.
- **No credentials handled.** GitHub access goes through your own `gh` login.
- **No telemetry** and no network access except the `gh` calls you ask for.
- Symlinks are not followed; large files are skipped; scans have file/commit/repo caps.

More in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).

## Configuration

| Variable | Effect |
|----------|--------|
| `DEVGUARD_ALLOWED_ROOTS` | `os.pathsep`-separated folders (`:` on macOS/Linux, `;` on Windows). When set, MCP tools refuse paths outside them. |
| `NO_COLOR` | Disable colored CLI output. |

Indicator data lives in [`src/devguard_mcp/data/iocs.json`](src/devguard_mcp/data/iocs.json) with a
`version` date; `devguard-mcp iocs` and the `list_iocs` tool print it.

## Limitations

- **Known patterns only.** New variants will evade string markers. Structural checks (padding,
  auto-run scripts, fake fonts, rewritten commits) generalise better but are not complete.
- **Cannot see the second stage.** It is downloaded at runtime; a machine finding means "rebuild",
  and a clean machine check does not prove the machine is clean.
- **History dates can be forged.** `DG-HS-003` shows *where* a marker is in history, not *when* an
  attack happened.
- **False positives exist.** Rare legitimate files can match (for example generated code with a
  long whitespace-padded line). Low and medium findings need a human look.
- **GitHub scans are capped** (25 repos, 15 branches, 400 KB per file by default) and need a
  working `gh` login. Org-level secrets need admin access to list.
- Not a replacement for EDR, dependency scanners (`npm audit`, OSV) or secret scanners.

## Documentation

- [docs/RECOVERY.md](docs/RECOVERY.md): **what to do if you ran infected code**: reset vs cleanup, step-by-step, credential rotation
- [docs/USAGE.md](docs/USAGE.md): CLI recipes, CI and pre-commit integration
- [docs/RULES.md](docs/RULES.md): every rule, generated from the code
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): design, modules, threat model of the tool itself
- [docs/THREAT_INTEL.md](docs/THREAT_INTEL.md): what is known about the campaigns, with sources
- [CHANGELOG.md](CHANGELOG.md) · [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md)

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

ruff check src tests && ruff format --check src tests
mypy
pytest                      # includes an end-to-end stdio MCP test; coverage must stay >= 85%
```

Tests use only harmless synthetic samples (filler text plus public indicator strings). Real
malware must never be added to this repository.

## Contributing

New indicators and false-positive reports are the most valuable contributions. See
[CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE). Provided as-is, without warranty; see the disclaimer above.
