"""Path normalization and classification against workspace roots, protected paths, and sensitive paths."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path


def normalize_path(raw: str, cwd: str | None) -> str:
    p = os.path.expanduser(raw)
    if not os.path.isabs(p):
        p = os.path.join(cwd or os.getcwd(), p)
    return os.path.normpath(p)


def _match(path: str, pattern: str) -> bool:
    pat = os.path.expanduser(pattern)
    if pat.startswith("**/"):
        # match the tail against any depth
        tail = pat[3:]
        return fnmatch.fnmatch(os.path.basename(path), tail) or any(
            fnmatch.fnmatch(part, tail) for part in path.split(os.sep)
        )
    if pat.endswith("/**"):
        root = pat[:-3]
        root = os.path.normpath(root)
        return path == root or path.startswith(root + os.sep)
    return fnmatch.fnmatch(path, pat)


def is_under(path: str, roots: list[str]) -> bool:
    for r in roots:
        root = os.path.normpath(os.path.expanduser(r))
        if path == root or path.startswith(root + os.sep):
            return True
    return False


def is_protected(path: str, roots: list[str], protected: list[str]) -> bool:
    """Protected patterns are relative to each workspace root (".kiro/**") or absolute/home ("~/x/**")."""
    for pat in protected:
        if pat.startswith(("/", "~")):
            if _match(path, pat):
                return True
            continue
        for r in roots:
            root = os.path.normpath(os.path.expanduser(r))
            if _match(path, os.path.join(root, pat)):
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
