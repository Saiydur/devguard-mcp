# Usage recipes

All commands accept `--json` and `--fail-on {info,low,medium,high,critical}` (default `medium`).
Exit status: `0` clean at that threshold, `1` findings, `2` error.

## Before running an unfamiliar repository

The two infections this tool targets are triggered by *running* a project (`npm run dev`) or by
*opening it in an editor* (extensions that load config files). Scan first:

```bash
git clone --no-checkout https://github.com/someone/task.git /tmp/task   # no hooks run on clone
git -C /tmp/task checkout -q main
devguard-mcp scan /tmp/task --fail-on low
devguard-mcp history /tmp/task
```

Do not open the folder in VS Code or run any package manager until both are clean. If findings
are high or critical, do not run the project at all.

## Scanning everything you own

```bash
gh auth login
devguard-mcp github YOUR_USERNAME --max-repos 100 --max-branches 30
devguard-mcp github some-org
```

Each finding's path looks like `owner/repo:path/in/repo [branches: main, develop]`; identical files
on several branches are reported once.

```bash
devguard-mcp token               # does your gh token have `workflow`?
devguard-mcp actions owner/repo  # which secret names could a malicious workflow read?
```

## Checking a machine

```bash
devguard-mcp machine
```

Any `critical` finding means the runner is installed or active: disconnect from the network, stop
using the machine for sensitive work, and follow `devguard-mcp checklist --machine`.

## Continuous integration

Fail a pull request that introduces known indicators:

```yaml
# .github/workflows/devguard.yml
name: devguard
on: [pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pin to a commit SHA>
        with:
          fetch-depth: 0
      - uses: actions/setup-python@<pin to a commit SHA>
        with:
          python-version: "3.12"
      - run: pip install "git+https://github.com/OWNER/devguard-mcp.git@<tag or commit>"
      - run: devguard-mcp scan . --fail-on high
      - run: devguard-mcp history .
```

Pin actions and the tool itself to commit SHAs; an unpinned security scanner is itself a
supply-chain risk.

## pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: devguard
        name: devguard scan
        entry: devguard-mcp scan . --fail-on high
        language: system
        pass_filenames: false
        always_run: true
```

## Reading the output

- **verdict** `likely-malicious-indicators-found` means at least one *high* or *critical* finding;
  `suspicious-review-needed` means only medium or lower; `no-known-indicators-found` is not "safe".
- **evidence** is deliberately terse. To investigate, open the file at the reported line with word
  wrap on, or run `awk 'length > 3000 {print FILENAME": "FNR": "length}' file`.
- Use `devguard-mcp rules <ID>` for what a rule means and what to do.

## JSON schema (stable fields)

```json
{
  "target": "/path",
  "kind": "directory | git-history | machine | github | github-token | github-actions | workflows",
  "verdict": "no-known-indicators-found | suspicious-review-needed | likely-malicious-indicators-found",
  "worst_severity": "high",
  "finding_count": 2,
  "findings": [
    {"rule_id": "DG-PR-003", "severity": "high", "campaign": "polinrider",
     "message": "...", "path": "postcss.config.mjs", "line": 11, "evidence": "..."}
  ],
  "stats": {"files_scanned": 129},
  "notes": [],
  "rules_version": "2026-10-26",
  "disclaimer": "..."
}
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `error: not a git repository` | run `history` inside a repository (it reads `.git`) |
| `GitHub CLI (gh) not found` | install `gh` and run `gh auth login` |
| `path is outside DEVGUARD_ALLOWED_ROOTS` | add the folder to the variable or unset it |
| `scan` is slow on a huge monorepo | lower `--max-files`; `node_modules`, `.git`, `dist`, `build`, `.next` are already skipped |
| `The MCP SDK is not installed` | `pip install mcp` (only `serve` needs it) |
