"""Documentation hygiene: every relative link and heading anchor must resolve."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCS = [*ROOT.glob("*.md"), *(ROOT / "docs").glob("*.md"), *(ROOT / ".github").glob("*.md")]
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$", re.MULTILINE)


def slug(heading: str) -> str:
    """GitHub-style heading anchor."""
    text = re.sub(r"[`*_]", "", heading.strip().lower())
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


def anchors(path: Path) -> set[str]:
    return {slug(h) for h in HEADING.findall(path.read_text(encoding="utf-8"))}


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_and_anchors_resolve(doc: Path) -> None:
    text = re.sub(r"```.*?```", "", doc.read_text(encoding="utf-8"), flags=re.DOTALL)
    problems: list[str] = []
    for target in LINK.findall(text):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        path_part, _, fragment = target.partition("#")
        resolved = doc if not path_part else (doc.parent / path_part).resolve()
        if not resolved.exists():
            problems.append(f"missing file: {target}")
        elif fragment and resolved.suffix == ".md" and fragment not in anchors(resolved):
            problems.append(f"missing anchor: {target}")
    assert not problems, problems


def test_recovery_guide_is_linked_from_readme_and_covers_every_platform() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "RECOVERY.md").read_text(encoding="utf-8")
    assert "docs/RECOVERY.md" in readme
    for heading in ("### macOS", "### Windows", "### Linux", "## 6. Rotate credentials"):
        assert heading in guide
