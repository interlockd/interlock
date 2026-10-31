"""The one way to write and read a small JSON state file in the Interlock home (Requirement 12).

State files (integrity baseline, stop marker, protection state, clean-exit mark) are flat JSON objects with at most
one level of nesting, identifier keys, and str/int/bool values that need no JSON escape, so the shims can read them
with plain string matching. Writes are atomic (0600 temp file, fsync, rename); reads treat anything that does not
conform, or that has the wrong owner or permissions, as absent and report it once through `on_error`. Neither
function raises.
"""

from __future__ import annotations

import errno
import json
import os
import re
import stat
from collections.abc import Callable
from pathlib import Path

MAX_BYTES = 64 * 1024
KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")
ErrorCallback = Callable[[str, str], None]
_POSIX = os.name == "posix" and hasattr(os, "geteuid")


def _scalar_problem(value: object) -> str | None:
    if isinstance(value, int):  # bool is an int
        return None
    if isinstance(value, str):
        return None if json.dumps(value) == '"' + value + '"' else "needs_escape"
    return "too_deep" if isinstance(value, (dict, list, tuple)) else "bad_value"


def _doc_problem(doc: object) -> str | None:
    """The first schema violation in `doc` as a fixed reason code, or None when it conforms."""
    if not isinstance(doc, dict):
        return "not_object"
    for k, v in doc.items():
        if not isinstance(k, str) or not KEY_RE.match(k):
            return "bad_key"
        if isinstance(v, dict):
            for k2, v2 in v.items():
                if not isinstance(k2, str) or not KEY_RE.match(k2):
                    return "bad_key"
                if (p := _scalar_problem(v2)) is not None:
                    return p
        elif (p := _scalar_problem(v)) is not None:
            return p
    return None


def _type_ok(value: object, want: type) -> bool:
    if want is int:
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, want)


def dumps(doc: dict) -> str:
    """Deterministic serialization: sorted keys, ", " and ": " separators, ASCII only, one trailing newline.
    Raises ValueError when the document is not a conforming state document or serializes above MAX_BYTES."""
    if (p := _doc_problem(doc)) is not None:
        raise ValueError(f"state document rejected: {p}")
    text = json.dumps(doc, sort_keys=True, separators=(", ", ": "), ensure_ascii=True) + "\n"
    if len(text.encode("ascii")) > MAX_BYTES:
        raise ValueError("state document rejected: too_large")
    return text


def single_line(doc: dict) -> str:
    """dumps() without the trailing newline (daemon.json: the sh shim reads its first line)."""
    return dumps(doc)[:-1]


def write_state(path: Path, doc: dict, *, on_error: ErrorCallback | None = None) -> bool:
    """Atomically replace `path` with `doc`: `<name>.tmp` created O_EXCL with mode 0600, written, fsynced, renamed.
    On failure the previous file is untouched, the temp file is removed, on_error(file, "state_write_failed:<why>")
    is called, and False is returned. Never raises."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    try:
        data = dumps(doc).encode("ascii")
    except ValueError:
        if on_error is not None:
            on_error(str(path), "state_write_failed:invalid_document")
        return False
    created = False
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp.unlink(missing_ok=True)  # a temp left by an interrupted write is replaced, never read (12.5)
        flags = (
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(tmp, flags, 0o600)
        created = True
        try:
            if _POSIX:
                os.fchmod(fd, 0o600)  # umask can only clear bits; make owner rw explicit
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        return True
    except OSError as e:
        if created:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        if on_error is not None:
            on_error(str(path), f"state_write_failed:{_errno_name(e)}")
        return False


def _errno_name(e: OSError) -> str:
    return errno.errorcode.get(e.errno or 0, "os_error").lower()


class _Duplicate(ValueError):
    pass


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise _Duplicate
        out[k] = v
    return out


def _reject_constant(_: str) -> object:
    raise ValueError("non-finite number")


def read_state(
    path: Path, required: dict[str, type], *, on_error: ErrorCallback | None = None
) -> dict | None:
    """The parsed document, or None when the file is absent or does not conform. Checks, in order: regular file
    (not a symlink), owned by the effective user and no group/other bits (POSIX only) -> else
    on_error(file, "state_permissions:<check>"); then size, encoding, JSON, schema and every required key with the
    required type -> else on_error(file, "state_unreadable:<reason>"). Never modifies the file; never raises."""
    path = Path(path)

    def fail(kind: str, reason: str) -> None:
        if on_error is not None:
            on_error(str(path), f"{kind}:{reason}")

    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        fail("state_unreadable", "io_error")
        return None
    if not stat.S_ISREG(st.st_mode):
        fail("state_permissions", "not_regular")
        return None
    if _POSIX:
        if st.st_uid != os.geteuid():
            fail("state_permissions", "owner")
            return None
        if st.st_mode & 0o077:
            fail("state_permissions", "mode")
            return None
    if st.st_size > MAX_BYTES:
        fail("state_unreadable", "too_large")
        return None
    try:
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except FileNotFoundError:
        return None
    except OSError:
        fail("state_unreadable", "io_error")
        return None
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (fst.st_ino, fst.st_dev) != (st.st_ino, st.st_dev):
            fail("state_permissions", "not_regular")  # swapped between lstat and open
            return None
        chunks, total = [], 0
        while total <= MAX_BYTES:
            chunk = os.read(fd, MAX_BYTES + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        fail("state_unreadable", "io_error")
        return None
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if len(raw) > MAX_BYTES:
        fail("state_unreadable", "too_large")
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("state_unreadable", "encoding")
        return None
    try:
        doc = json.loads(text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
    except _Duplicate:
        fail("state_unreadable", "duplicate_key")
        return None
    except (ValueError, RecursionError):
        fail("state_unreadable", "invalid_json")
        return None
    if (p := _doc_problem(doc)) is not None:
        fail("state_unreadable", p)
        return None
    for key, want in required.items():
        if key not in doc:
            fail("state_unreadable", "missing_key")
            return None
        if not _type_ok(doc[key], want):
            fail("state_unreadable", "wrong_type")
            return None
    return doc
