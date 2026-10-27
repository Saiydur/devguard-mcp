"""Shared fixtures. All samples are synthetic: filler text plus public indicator strings."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

MARKER = "_0xdf6eg"  # a public PolinRider loader identifier
CLEAN_POSTCSS = (
    'const config = {\n  plugins: { "@tailwindcss/postcss": {} },\n};\n\nexport default config;'
)
FILLER = "void 0;" * 600  # ~4200 harmless characters standing in for a payload


def padded(prefix: str = "export default config;", *, marker: bool = False, run: int = 200) -> str:
    """A config-file line followed by a whitespace run and a long tail, like the real implant."""
    tail = (f"var {MARKER}=1;" if marker else "") + FILLER
    return prefix + " " * run + tail


@pytest.fixture
def write(tmp_path: Path) -> Callable[[str, str | bytes], Path]:
    """Create ``tmp_path/<rel>`` with the given content and return its path."""

    def _write(rel: str, content: str | bytes) -> Path:
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
        return target

    return _write


@pytest.fixture
def infected_project(tmp_path: Path, write: Callable[[str, str | bytes], Path]) -> Path:
    """A project with a dropper, a padded config, a scripted prefix and a fake font."""
    write("api.js", f"var {MARKER}=1;" + FILLER)
    write(
        "postcss.config.mjs", CLEAN_POSTCSS + "\n" + padded().replace("export default config;", "")
    )
    write(
        "package.json",
        '{"name":"demo","scripts":{"dev":"node api.js && next dev","lint":"eslint"}}',
    )
    write("public/fonts/fake.ttf", "function y7(){}" + FILLER)
    write("src/index.js", "console.log('hello');\n")
    return tmp_path


requires_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    """Run git in ``repo`` with a fixed identity; used to build history fixtures."""
    full_env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Dev",
        "GIT_AUTHOR_EMAIL": "dev@example.com",
        "GIT_COMMITTER_NAME": "Dev",
        "GIT_COMMITTER_EMAIL": "dev@example.com",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        **(env or {}),
    }
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
        env=full_env,
    )
    return result.stdout.strip()


def commit(
    repo: Path,
    message: str,
    *,
    author_date: str,
    committer_date: str | None = None,
) -> str:
    """Create a commit with explicit dates and return its sha."""
    env = {
        "GIT_AUTHOR_DATE": author_date,
        "GIT_COMMITTER_DATE": committer_date or author_date,
    }
    git(repo, "add", "-A", env=env)
    git(repo, "commit", "-q", "--allow-empty", "-m", message, env=env)
    return git(repo, "rev-parse", "HEAD")
