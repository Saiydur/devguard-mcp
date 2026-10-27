## What and why

<!-- Link the issue. Describe the behaviour change, not just the diff. -->

## Checklist

- [ ] No live malware or working loaders in the diff (fixtures are synthetic)
- [ ] Nothing here writes, deletes or executes from an MCP tool (writes stay behind `fix --apply`)
- [ ] Findings use sanitised evidence (no raw lines, no secrets)
- [ ] New/changed detector has a positive test **and** a benign near-miss test
- [ ] `docs/RULES.md` regenerated if rules changed (`devguard-mcp rules --markdown > docs/RULES.md`)
- [ ] `CHANGELOG.md` updated; `data/iocs.json` `version` bumped if indicators changed
- [ ] `ruff check`, `ruff format --check`, `mypy`, `pytest` pass locally
