"""Daemon_Identity: proves to a shim that a reply came from this Home's daemon (hook-tamper-detection, Req 1).

At start the daemon derives a 128-bit value from the Home's token and a fresh nonce, writes it to `<Home>/identity`
(mode 0600, the same protection class as the token) and sends it in an `X-Interlock-Identity` header on every reply.
A shim compares the header to the file with string equality: no hashing in the shim, no extra round trip. A process
answering on the same address without this Home's token cannot produce the value (HMAC-SHA256 is a PRF keyed by the
token), and the value reveals neither the token nor the Home path.

The HMAC key is sha256(token), not the raw token. HMAC zero-pads a key shorter than the 64-byte block and replaces a
longer key with its hash, so raw tokens such as "abc" and "abc\\x00", or a long token and the text of its digest, would
be the same key. A fixed 32-byte key avoids both: distinct tokens give distinct keys unless sha256 collides.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path

FILE = "identity"
HEADER = "X-Interlock-Identity"
PREFIX = b"interlock-identity:v1:"
_VALUE_RE = re.compile(r"^[0-9a-f]{32}\Z")


def derive(token: str, start_nonce: bytes) -> str:
    """128 bits of HMAC-SHA256(key=sha256(token), msg=PREFIX + nonce), as 32 lowercase hex characters.
    The fixed-length key keeps HMAC's key padding and long-key hashing from mapping distinct tokens to one key."""
    key = hashlib.sha256(token.encode("utf-8")).digest()
    return hmac.new(key, PREFIX + start_nonce, hashlib.sha256).hexdigest()[:32]


def new_nonce() -> bytes:
    return secrets.token_bytes(16)


def write(home: Path, value: str) -> None:
    """Write `<home>/identity` as one line, mode 0600 from creation (O_EXCL temp file, then os.replace).
    Raises ValueError for a malformed value and OSError when the file cannot be written; the temp file is removed."""
    if not _VALUE_RE.match(value):
        raise ValueError("identity must be 32 lowercase hex characters")
    home.mkdir(parents=True, exist_ok=True)
    path = home / FILE
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(value + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise


def read(home: Path) -> str | None:
    """The stored identity, or None when the file is absent, unreadable or not exactly 32 lowercase hex chars."""
    try:
        text = (home / FILE).read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError):
        return None
    value = text.strip()
    return value if _VALUE_RE.match(value) else None


def verify(header_values: list[str], expected: str) -> bool:
    """True iff exactly one header value was received and it equals `expected`. The shims implement the same check
    in their own language; this is the reference used by tests and `selftest --shim`."""
    if len(header_values) != 1:
        return False
    # bytes, so a non-ASCII header value compares unequal instead of raising TypeError
    return hmac.compare_digest(header_values[0].encode("utf-8", "surrogateescape"), expected.encode("utf-8"))
