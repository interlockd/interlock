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


# Claude Code checks agent worktrees out under <repo>/.claude/worktrees/<name>/. Each one is a checkout of its own:
# its source files are workspace files, while its own .claude/, .kiro/, ... are agent configuration like anywhere else.
_AGENT_WORKTREE = re.compile(r"^(.*/\.claude/worktrees/[^/]+)/(.+)$", re.IGNORECASE)


def _worktree_split(path: str) -> tuple[str, str] | None:
    if any(part in (".", "..") for part in path.split("/")):
        return None                                  # only normalized paths qualify
    m = _AGENT_WORKTREE.match(path)                  # greedy: the innermost worktree wins
    if not m or m.group(1).lower().startswith(home().lower() + "/.claude/"):
        return None                                  # the user's own ~/.claude/ is never a repository
    return m.group(1), m.group(2)


def agent_worktree(path: str) -> tuple[str, str, str] | None:
    """(path, worktree root, path inside the worktree) when `path` is inside a Claude Code agent worktree
    (`<repo>/.claude/worktrees/<name>/...`), else None. The worktree directory itself, anything directly under
    `.claude/worktrees/`, and the user's own `~/.claude/worktrees/` do not count. Symlinks are followed: the result
    describes where the write really lands (the returned path is the resolved one), and a path that resolves out of
    every worktree is None, so it gets the strict checks."""
    split = _worktree_split(path)
    if split is None:
        return None
    try:
        real = canon(os.path.realpath(path))
    except (OSError, ValueError):
        return None
    if real.lower() == path.lower():
        return path, *split
    real_split = _worktree_split(real)
    return (real, *real_split) if real_split is not None else None


def _covers_all_of_claude(pattern: str) -> bool:
    return pattern.replace("\\", "/").strip("/").lower() in (".claude/**", "./.claude/**")


def is_protected_scoped(path: str, roots: list[str], protected: list[str]) -> bool:
    """is_protected, with a Claude Code agent worktree treated as a workspace root of its own: `.claude/**` (the
    default) protects `<worktree>/.claude/...` but no longer every file of a checkout that lives under
    `<repo>/.claude/worktrees/`. Every other pattern applies as before, relative to the original roots too."""
    wt = agent_worktree(path)
    if wt is None:
        return is_protected(path, roots, protected)
    real, root, _ = wt
    narrow = [p for p in protected if not _covers_all_of_claude(p)]
    return is_protected(real, [root], protected) or is_protected(path, roots, narrow) or is_protected(real, roots, narrow)


def is_sensitive(path: str, sensitive: list[str]) -> bool:
    return any(_match(path, pat) for pat in sensitive)


def find_git_root(start: str | None) -> str | None:
    cur = Path(start or os.getcwd()).resolve()
    for p in [cur, *cur.parents]:
        if (p / ".git").exists():
            return str(p)
    return None
