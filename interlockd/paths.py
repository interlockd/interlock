"""Path normalization and classification against workspace roots, protected paths, and sensitive paths.

Every rule sees one path form: forward slashes, normalized, with a Windows drive kept (`C:/Users/me/...`), so the same
patterns (`~/.ssh/**`, `.github/workflows/**`) and markers (`/.claude/`) apply on every platform. Matching ignores case
on macOS and Windows, whose default file systems do (`~/.CLAUDE/settings.json` there *is* `~/.claude/settings.json`);
the path itself keeps its case for display.
"""

from __future__ import annotations

import fnmatch
import os
import posixpath
import re
import sys
from pathlib import Path

WINDOWS = os.name == "nt"
CASE_INSENSITIVE = WINDOWS or sys.platform == "darwin"
_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def canon(p: str) -> str:
    """The rule-facing form of an absolute (or pattern) path; see the module docstring."""
    if WINDOWS:
        return posixpath.normpath(p.replace("\\", "/"))
    return os.path.normpath(p)


def fold(p: str) -> str:
    """The form to compare: case-folded where the file system ignores case."""
    return p.lower() if CASE_INSENSITIVE else p


def home() -> str:
    return canon(os.path.expanduser("~"))


def _is_abs(p: str) -> bool:
    return p.startswith("/") or (WINDOWS and (p.startswith("\\") or bool(_DRIVE.match(p))))


def normalize_path(raw: str, cwd: str | None) -> str:
    p = os.path.expanduser(raw)
    if not _is_abs(p):
        p = (cwd or os.getcwd()).rstrip("/\\") + "/" + p
    return canon(p)


def _match(path: str, pattern: str) -> bool:
    path, pat = fold(path), fold(canon(os.path.expanduser(pattern)))
    if pat.startswith("**/"):
        # match the tail against any depth
        tail = pat[3:]
        return fnmatch.fnmatchcase(posixpath.basename(path), tail) or any(
            fnmatch.fnmatchcase(part, tail) for part in path.split("/")
        )
    if pat.endswith("/**"):
        root = pat[:-3]
        return path == root or path.startswith(root + "/")
    return fnmatch.fnmatchcase(path, pat)


def is_under(path: str, roots: list[str]) -> bool:
    path = fold(path)
    for r in roots:
        root = fold(canon(os.path.expanduser(r)))
        if path == root or path.startswith(root + "/"):
            return True
    return False


def is_protected(path: str, roots: list[str], protected: list[str]) -> bool:
    """Protected patterns are relative to each workspace root (".kiro/**") or absolute/home ("~/x/**")."""
    for pat in protected:
        if pat.startswith("~") or _is_abs(pat):
            if _match(path, pat):
                return True
            continue
        for r in roots:
            root = canon(os.path.expanduser(r))
            if _match(path, root.rstrip("/") + "/" + pat):
                return True
    return False


def is_sensitive(path: str, sensitive: list[str]) -> bool:
    return any(_match(path, pat) for pat in sensitive)


def find_git_root(start: str | None) -> str | None:
    cur = Path(start or os.getcwd()).resolve()
    for p in [cur, *cur.parents]:
        if (p / ".git").exists():
            return str(p)
    return None
