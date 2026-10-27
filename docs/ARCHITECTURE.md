# Architecture

## Goals

1. **Safe to point at hostile input.** Scanning must never run, import or modify the target.
2. **Safe to put in front of an LLM.** Output may be read by an assistant, so it must not carry
   payload text or secrets, and the server must not offer destructive tools.
3. **Portable.** macOS, Linux and Windows; Python 3.10+; scanning core is standard-library only.
4. **Testable without real malware or a real machine.** All OS and network access is injectable.
5. **Honest.** Every report says that "no findings" is not "safe".

## Module map

```text
                 +-----------------------------+
   CLI  -------> |  cli.py   (argparse)        |
   MCP client -> |  server.py (MCPServer tools)|
                 +--------------+--------------+
                                |
     +---------+----------+-----+-----+-----------+-----------+
     |         |          |           |           |           |
 scanner.py  history.py  machine.py  github.py  cleanup.py  checklist.py
     |  \         |          |           |           |
     |   workflows.py       |        (uses analyze_file)
     |                      |
     +------ iocs.py <------+----> data/iocs.json
     +------ rules.py          models.py (Finding, Report, Severity, sanitize)
```

| Module | Responsibility |
|--------|----------------|
| `models.py` | `Severity`, `Finding`, `Report`; `sanitize()` and `redact_secret()` guarantee safe evidence |
| `iocs.py` + `data/iocs.json` | indicator data, loaded once and compiled; versioned by date |
| `rules.py` | the rule catalogue (id, severity, description, remediation); generates `docs/RULES.md` |
| `scanner.py` | `analyze_file(path, bytes)` (pure) and `scan_directory()` (the walker) |
| `workflows.py` | GhostAction detection on workflow text |
| `history.py` | read-only `git` plumbing: twin commits, timezone re-stamping, marker introduction |
| `machine.py` | processes, connections, startup items, shell files, history tokens via an injectable `Probe` |
| `github.py` | the scanner over the GitHub API using `gh`; token-scope and Actions-exposure audits |
| `cleanup.py` | plan (pure) and apply (CLI-only) of removals |
| `checklist.py` | static, ordered recovery guidance |
| `server.py` | MCP tools, all read-only; path allow-list |
| `cli.py` | command-line front end and exit codes |

## Key design decisions

### One pure analyzer, many sources

`scanner.analyze_file(path, data, read_sibling)` takes a repo-relative path and raw bytes and
returns findings. The directory walker feeds it from disk; the GitHub scanner feeds it blobs from
the API. Detection logic therefore cannot drift between "local" and "remote" scans, and it is
trivial to unit-test. `read_sibling` lets a `package.json` rule look at the file a script runs
without knowing where files come from.

### Structural heuristics before string markers

Strings (`_0xdf6eg`, XOR keys) are easy for an attacker to change. The padding rule (a line over
3,000 characters containing 100+ spaces or tabs followed by 500+ more characters) targets *how*
the implant hides rather than *what* it says, and catches variants that share no marker. Markers
remain useful for confidence and for history lookups.

### Evidence is sanitised at the source

Findings are built with `sanitize()` (printable ASCII, whitespace-collapsed, truncated to 96
characters) or with summaries (`"whitespace run of 336 chars, then 12319 more chars of code"`).
Tokens go through `redact_secret()`. Because the text comes from files an attacker controls, this
also limits **prompt-injection** surface: a malicious repo cannot place a paragraph of
instructions into a finding. The server's `instructions` additionally tell the model to treat tool
output as data and never to execute flagged files.

### Read-only server, write-capable CLI

The MCP server exposes only read tools (`readOnlyHint=True`, `destructiveHint=False`; a test
asserts this for every tool and that no tool name suggests writing). `cleanup.apply_plan` exists
only behind `devguard-mcp fix --apply`, requires confirmation (or `--yes`), quarantines originals
with mode `0600` first, refuses paths outside the plan root, and never edits workflows.

### Injectable I/O

- `history.scan_history(..., git=run_git)`: tests can supply a fake `git`.
- `machine.Probe(home, system, run)`: tests simulate macOS/Linux/Windows by passing fixture
  output; production uses `subprocess` with fixed argument lists, no shell, a 30 s timeout.
- `github.GhClient(runner)`: tests serve a fake repository; production shells out to `gh`.

### No credentials in process

GitHub access uses the user's `gh` login. The package never reads `GH_TOKEN`, keychains or
`hosts.yml`. `audit_token` reads only the `X-OAuth-Scopes` response header.

### Data-driven indicators

`data/iocs.json` holds markers, hosts, file names and commit messages with a `version` date, so
indicator updates are small, reviewable data changes. A test asserts every strong marker's regex
matches its own literal.

## Threat model of the tool itself

| Threat | Mitigation |
|--------|-----------|
| Scanned repo tries to execute code in the scanner | Files are read as bytes and matched with regexes; nothing is imported, evaluated or executed |
| Catastrophic regex backtracking on attacker-sized input | Patterns are linear; files over 16 MiB are skipped; per-scan file/commit/repo caps |
| Path traversal / symlink escape | Symlinks not followed; sibling reads are confined to the scan root; cleanup refuses paths outside the plan root; optional `DEVGUARD_ALLOWED_ROOTS` |
| Prompt injection through findings | Sanitised, truncated evidence; no raw lines; instructions mark output as data |
| Secret leakage in output | Tokens redacted to prefix + length; Actions secret *names* only |
| Malicious `git` config in a scanned repo (textconv/external-diff helpers, `core.fsmonitor`, hooks) | Every call overrides `core.fsmonitor`, `core.hooksPath`, `core.pager` and `protocol.ext.allow`; pickaxe searches pass `--no-textconv --no-ext-diff`; only `log`, `diff-tree` and `rev-parse` are used. A regression test proves a hostile `diff.<driver>.textconv` is never executed |
| Supply-chain compromise of this project | One runtime dependency (`mcp`), pinned to a major range; CI actions pinned by commit SHA; Dependabot; no install scripts |
| A destructive tool added by mistake | Test enumerates tools and asserts the exact set and read-only annotations |

Residual risks: a hostile repository can still make `git log` slow (mitigated by timeouts), and the
process runs with the invoking user's privileges. Run it as an unprivileged user.

## Adding a detector

1. Add a `Rule` in `rules.py` (id `DG-<AREA>-NNN`, severity, description, remediation).
2. Implement the check; build `Finding`s with sanitised evidence.
3. Add tests with a synthetic sample *and* a benign near-miss (false-positive guard).
4. Regenerate the reference: `devguard-mcp rules --markdown > docs/RULES.md`
   (a test fails if it is stale).
5. Note the change in `CHANGELOG.md`; add indicators to `data/iocs.json` and bump its `version`.
