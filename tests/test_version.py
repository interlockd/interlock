"""One version everywhere: the package, pyproject, and every shim that reports it to the daemon."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from interlockd import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_versions_agree():
    assert tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"] == __version__
    for shim in (ROOT / "interlockd" / "shims").rglob("*"):
        if shim.is_file():
            for v in re.findall(r'VERSION\s*=\s*"([^"]+)"', shim.read_text()):
                assert v in (__version__, "__VERSION__"), shim     # OpenCode's plugin is filled in at install
