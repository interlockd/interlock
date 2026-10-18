"""Per-install bearer token (design D6). Created on first serve, mode 0600, compared in constant time."""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path


def load_or_create_token(path: Path) -> str:
    if path.exists():
        return path.read_text().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
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
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    os.replace(tmp, path)
    return token
