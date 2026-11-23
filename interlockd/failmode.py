"""`<Home>/fail-mode.json`: the fail-mode table the shims read when the daemon cannot judge a call.

One writer for every command that refreshes the file (`init`, `install`, `serve`, `shadow`, `enforce`), so the
shape is stable: the per-category table and `default` from the daemon settings (unchanged semantics), plus `tamper`,
the effective `fail_mode.tamper` from the policy (Requirement 4.1, 4.2). Every written file carries both `default`
and `tamper`.

The format stays `json.dumps(indent=2)`: the shims find `"default": "` and `"tamper": "` by substring, and the
category keys (`security.secret_leak.*`) are not state-file identifiers, so this is not a `statefile` document. The
write is atomic (temp file created 0600, renamed over the target).
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

FILE = "fail-mode.json"
MODES = ("open", "closed")


def effective_tamper(policy: Any) -> str:
    """`fail_mode.tamper` of `policy` (a Policy, a fail_mode mapping, or None): its value when open or closed, else
    closed. Absent, None or anything unexpected is `closed` (4.1, 4.7)."""
    fm = getattr(policy, "fail_mode", policy)
    value = fm.get("tamper") if isinstance(fm, Mapping) else getattr(fm, "tamper", None)
    return value if value in MODES else "closed"


def document(table: Mapping[str, str], policy: Any = None) -> dict[str, str]:
    """The file's content: `table` (categories and `default`) with `default` defaulting to open, and `tamper` set
    from the policy. A `tamper` entry in `table` is replaced: the policy is the only source for it."""
    doc = {k: v for k, v in table.items() if k != "tamper"}
    doc.setdefault("default", "open")
    doc["tamper"] = effective_tamper(policy)
    return doc


def dumps(doc: Mapping[str, str]) -> str:
    return json.dumps(dict(doc), indent=2) + "\n"


def write(home: Path, table: Mapping[str, str], policy: Any = None) -> dict[str, str]:
    """Atomically write `<home>/fail-mode.json` (mode 0600) and return the document. Raises OSError on failure; the
    previous file is left in place."""
    home = Path(home)
    doc = document(table, policy)
    path = home / FILE
    tmp = path.with_name(FILE + ".tmp")
    home.mkdir(parents=True, exist_ok=True)
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(dumps(doc))
        os.replace(tmp, path)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise
    return doc
