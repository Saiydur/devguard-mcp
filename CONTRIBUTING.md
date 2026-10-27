# Contributing

Thank you for helping. The most valuable contributions are **new indicators**, **false-positive
reports** and **tests for real-world variants** (described, not attached; see
[SECURITY.md](SECURITY.md#handling-malware-samples)).

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ground rules

1. **No live malware, ever.** Fixtures are synthetic. A pull request containing a real payload will
   be closed and the content removed from history.
2. **Read-only by default.** Do not add an MCP tool that writes, deletes or executes. Cleanup writes
   belong behind the CLI's `fix --apply` and must quarantine first.
3. **Evidence stays small.** Findings must use `sanitize()`/summaries, never raw lines or secrets.
4. **Prefer structural detection** over new string markers; markers are easy to evade.
5. **Every detector needs a false-positive test**: a benign near-miss that must *not* fire.
6. Keep runtime dependencies at the minimum (currently only `mcp`).

## Development setup

```bash
git clone https://github.com/OWNER/devguard-mcp.git && cd devguard-mcp
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Run everything CI runs:

```bash
ruff check src tests          # lint (includes security rules)
ruff format --check src tests # formatting (use `ruff format` to fix)
mypy                          # strict typing
pytest                        # tests + coverage (fails under 85%)
```

Supported Python: 3.10 to 3.14. Avoid syntax newer than 3.10 and POSIX-only APIs in shared code;
OS-specific logic belongs in `machine.py` behind `Probe`.

## Code standards

- Type-annotate everything; `mypy --strict` must pass.
- Match the surrounding style; formatting is enforced by `ruff format` (line length 100).
- Public functions and modules get docstrings that say *why*, not just *what*.
- No `eval`, `exec`, `pickle`, `shell=True`, or importing scanned content. Subprocess calls use
  fixed argument lists (see the `S603/S607` per-file ignores and why they are justified).
- Errors a user can cause (bad path, no `gh`) raise `ValueError`/`NotADirectoryError`/`GitError`/
  `GhError`; the CLI and server turn these into clean messages.

## Adding or changing a rule

1. Add or edit a `Rule` in `src/devguard_mcp/rules.py` (`DG-<AREA>-NNN`).
2. Implement the check; build findings with sanitised evidence.
3. Add tests: a positive sample, a benign near-miss, and the edge of any threshold.
4. Regenerate the reference and commit it:
   ```bash
   devguard-mcp rules --markdown > docs/RULES.md
   ```
   (`tests/test_core.py::test_rules_doc_is_in_sync_with_the_catalogue` fails if stale).
5. Update `CHANGELOG.md` under "Unreleased".

## Adding or updating indicators

Edit `src/devguard_mcp/data/iocs.json` and bump its `version` to today's date. In the pull request,
give for each indicator: the **source** (link or first-hand analysis), **which campaign**, and your
**confidence**. Avoid indicators that also appear in benign software (public APIs, common file
names) or put them in `weak_markers`/low severity. Add them to `docs/THREAT_INTEL.md` if they
change our understanding of a campaign.

## Reporting a false positive

Open an issue using the *False positive* template with: the rule id, the file type and project
type, and a **minimal synthetic reproduction** (the structure that triggered it, not the file).

## Pull requests

- Small and focused; one logical change each.
- Describe the behaviour change and link the issue.
- CI must be green. Commit messages: imperative mood, e.g. `Detect padded payloads in .cts files`.
- A maintainer will review for safety first (does it execute, write or leak anything?), then
  correctness and false-positive risk.

## Maintainer checklist before the first release

- [ ] Replace every `OWNER` placeholder (README badges and clone URLs, `CONTRIBUTING.md`, the
      CI example in `docs/USAGE.md`) and add `[project.urls]` to `pyproject.toml`.
- [ ] Enable GitHub private vulnerability reporting, branch protection (required reviews and
      status checks, no force-push) and secret scanning with push protection.
- [ ] Set Actions default permissions to read-only; restrict workflow runs from forks.
- [ ] Review `data/iocs.json` and `docs/THREAT_INTEL.md` for freshness.
- [ ] Publish through PyPI trusted publishing (OIDC), not a long-lived token; sign tags.
