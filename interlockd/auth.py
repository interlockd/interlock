"""Per-install bearer token (design D6). Created on first serve, mode 0600, compared in constant time."""

from __future__ import annotations

import hmac
import os
import secrets
import sys
from pathlib import Path


def _owner_only(path: Path) -> None:
    """Windows: `os.open(..., 0o600)` sets no ACL, so a new token would inherit whatever its folder grants. Reset it
    to the owner, SYSTEM and Administrators (`integrity.restore_token_mode`). Best effort: the daemon's token check
    reports and retries an ACL this could not fix (`token_permissions`)."""
    if sys.platform == "win32":
        from .integrity import restore_token_mode

        restore_token_mode(path)


def load_or_create_token(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    _owner_only(path)
    return token


def check_bearer(header_value: str | None, token: str) -> bool:
    if not header_value or not header_value.startswith("Bearer "):
        return False
    return hmac.compare_digest(header_value[7:].strip(), token)


def rotate_token(path: Path) -> str:
    """Replace the token atomically (mode 0600 from creation). Hooks read it per call; the daemon needs a restart."""
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    tmp = path.with_name(path.name + ".new")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    _owner_only(tmp)                    # before the rename: the token is never readable more widely
    os.replace(tmp, path)
    return token
