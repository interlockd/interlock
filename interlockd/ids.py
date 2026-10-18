"""ULID generation (Crockford base32, time-ordered) for event ids."""

from __future__ import annotations

import secrets
import time

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid(ts_ms: int | None = None) -> str:
    ts = int(time.time() * 1000) if ts_ms is None else ts_ms
    value = (ts << 80) | secrets.randbits(80)
    out = []
    for _ in range(26):
        out.append(_ALPHABET[value & 31])
        value >>= 5
    return "".join(reversed(out))


def ulid_ts_ms(value: str) -> int:
    n = 0
    for ch in value[:10]:
        n = n * 32 + _ALPHABET.index(ch)
    return n
