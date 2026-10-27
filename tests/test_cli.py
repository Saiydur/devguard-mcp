from __future__ import annotations

import json
from pathlib import Path

import pytest

from devguard_mcp import __version__
from devguard_mcp.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_scan_clean_directory_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "a.js").write_text("x=1;")
    assert main(["scan", str(tmp_path)]) == EXIT_OK
    assert "No known indicators found" in capsys.readouterr().out


def test_scan_infected_directory_exits_one_and_prints_no_payload(
    infected_project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["scan", str(infected_project)]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "DG-PR-003" in out and "likely-malicious" in out
    assert "void 0;void 0;void 0;" not in out  # payload filler is never echoed


def test_json_output_is_valid_and_has_disclaimer(
    infected_project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["scan", str(infected_project), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["kind"] == "directory"
    assert data["finding_count"] >= 4
    assert "not proof" in data["disclaimer"]
    assert data["findings"][0]["severity"] in {"critical", "high"}


def test_fail_on_threshold(tmp_path: Path) -> None:
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode/tasks.json").write_text(
        '{"tasks":[{"command":"npm run dev","runOptions":{"runOn":"folderOpen"}}]}'
    )
    assert main(["scan", str(tmp_path), "--fail-on", "medium"]) == EXIT_OK  # only LOW
    assert main(["scan", str(tmp_path), "--fail-on", "low"]) == EXIT_FINDINGS


def test_missing_directory_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(tmp_path / "nope")]) == EXIT_ERROR
    assert "error:" in capsys.readouterr().err


def test_workflows_command_only_reports_workflow_rules(
    infected_project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wf = infected_project / ".github/workflows"
    wf.mkdir(parents=True)
    (wf / "security-check.yml").write_text("on: push\n")
    assert main(["workflows", str(infected_project), "--json"]) == EXIT_FINDINGS
    rules = {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert rules == {"DG-GA-001"}


def test_fix_is_a_dry_run_by_default(
    infected_project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["fix", str(infected_project)]) == EXIT_OK
    assert (infected_project / "api.js").exists()
    assert "Dry run only" in capsys.readouterr().out


def test_fix_apply_with_yes_cleans_and_quarantines(
    infected_project: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    quarantine = tmp_path_factory.mktemp("q")
    code = main(["fix", str(infected_project), "--apply", "--yes", "--quarantine", str(quarantine)])
    assert code == EXIT_OK
    assert not (infected_project / "api.js").exists()
    assert (quarantine / "api.js").exists()
    assert main(["scan", str(infected_project)]) == EXIT_OK


def test_fix_apply_aborts_without_confirmation(
    infected_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    main(["fix", str(infected_project), "--apply"])
    assert (infected_project / "api.js").exists()


def test_rules_listing_and_explanation(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules"]) == EXIT_OK
    assert "DG-PR-003" in capsys.readouterr().out
    assert main(["rules", "dg-pr-003"]) == EXIT_OK
    assert "whitespace" in capsys.readouterr().out.lower()
    assert main(["rules", "DG-XX-999"]) == EXIT_ERROR


def test_iocs_output_has_version_and_no_payload(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["iocs"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["version"] and "95.135.181.151" in json.dumps(data)


def test_checklist_orders_steps(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["checklist", "--machine", "--repos"]) == EXIT_OK
    out = capsys.readouterr().out
    assert out.index("Stop using") < out.index("Rotate every secret") < out.index("Rebuild")
