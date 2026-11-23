"""Property 22: state-file reader tolerance (Requirements 9.12, 12.3, 12.6).

A conforming Stop_Marker document is mutated into something `read_state` must refuse: content mutations
(invalid JSON or UTF-8, non-object top level, nesting deeper than one level, a missing or wrongly typed required
key, a duplicate key, more than 64 KiB) and, on POSIX, file mutations (group/other permission bits, a symlink).
For every mutation the reader returns None, calls `on_error` exactly once naming the file and the failing check,
and leaves the file's bytes (and mode) unchanged.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from interlockd.statefile import MAX_BYTES, dumps, read_state

from .strategies import PROPS, escape_free_text, identifiers, posix_modes, stop_marker_docs

REQUIRED = {"action": str, "written_at": str}
POSIX = os.name == "posix" and hasattr(os, "geteuid")


# --- content mutations: (doc, data) -> file bytes that must be refused as state_unreadable -----------------------

def _truncated(doc: dict, data: st.DataObject) -> bytes:
    text = dumps(doc)
    k = data.draw(st.integers(0, len(text) - 2), label="truncate_at")   # drops at least the closing brace
    return text[:k].encode()


def _bad_utf8(doc: dict, data: st.DataObject) -> bytes:
    text = dumps(doc).encode()
    k = data.draw(st.integers(0, len(text)), label="insert_at")
    return text[:k] + data.draw(st.sampled_from((b"\xff", b"\xc3", b"\xed\xa0\x80")), label="bad") + text[k:]


def _non_object(doc: dict, data: st.DataObject) -> bytes:
    top = data.draw(st.one_of(st.just([doc]), st.just(list(doc)), st.none(), st.integers(), st.booleans(),
                              escape_free_text()), label="top_level")
    return (json.dumps(top) + "\n").encode()


def _too_deep(doc: dict, data: st.DataObject) -> bytes:
    key = data.draw(identifiers(), label="key")
    deep = data.draw(st.one_of(
        st.builds(lambda k, v: {k: {"x": v}}, identifiers(), st.integers()),      # dict inside dict
        st.lists(st.integers(), max_size=3),                                       # list value
        st.builds(lambda k: {k: [1]}, identifiers()),                              # list inside dict
    ), label="deep")
    return (json.dumps({**doc, key: deep}) + "\n").encode()


def _missing_required(doc: dict, data: st.DataObject) -> bytes:
    key = data.draw(st.sampled_from(sorted(REQUIRED)), label="drop")
    return dumps({k: v for k, v in doc.items() if k != key}).encode()


def _wrong_type(doc: dict, data: st.DataObject) -> bytes:
    key = data.draw(st.sampled_from(sorted(REQUIRED)), label="retype")
    value = data.draw(st.one_of(st.integers(), st.booleans(), st.none(), st.lists(st.integers(), max_size=2),
                                st.dictionaries(identifiers(), st.integers(), max_size=2)), label="value")
    return (json.dumps({**doc, key: value}) + "\n").encode()


def _duplicate_key(doc: dict, data: st.DataObject) -> bytes:
    key = data.draw(st.sampled_from(sorted(doc)), label="dup")
    body = dumps(doc).rstrip("\n")
    return (body[:-1] + f", {json.dumps(key)}: {json.dumps(doc[key])}" + "}\n").encode()


def _oversize(doc: dict, data: st.DataObject) -> bytes:
    extra = data.draw(st.integers(1, 2048), label="extra_bytes")
    text = json.dumps({**doc, "pad": ""}, sort_keys=True)
    pad = MAX_BYTES - len(text) + extra
    return json.dumps({**doc, "pad": "a" * pad}, sort_keys=True).encode()   # otherwise a valid document


CONTENT_MUTATIONS = {
    "truncated": _truncated,
    "bad_utf8": _bad_utf8,
    "non_object": _non_object,
    "too_deep": _too_deep,
    "missing_required": _missing_required,
    "wrong_type": _wrong_type,
    "duplicate_key": _duplicate_key,
    "oversize": _oversize,
}


def _write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.write_bytes(data)
    os.chmod(path, mode)


def _read(path: Path) -> tuple[dict | None, list[tuple[str, str]]]:
    calls: list[tuple[str, str]] = []
    return read_state(path, REQUIRED, on_error=lambda f, r: calls.append((f, r))), calls


# Feature: hook-tamper-detection, Property 22: State-file reader tolerance
@PROPS
@given(doc=stop_marker_docs(), mutation=st.sampled_from(sorted(CONTENT_MUTATIONS)), data=st.data())
def test_nonconforming_content_is_absent(doc: dict, mutation: str, data: st.DataObject) -> None:
    """**Validates: Requirements 9.12, 12.3**"""
    raw = CONTENT_MUTATIONS[mutation](doc, data)
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "stop-marker.json"

        _write(path, dumps(doc).encode())                     # control: the unmutated document is accepted
        assert _read(path) == (doc, [])

        _write(path, raw)
        got, calls = _read(path)
        assert got is None
        assert len(calls) == 1, calls
        assert calls[0][0] == str(path)
        assert calls[0][1].startswith("state_unreadable:"), calls
        assert path.read_bytes() == raw


# Feature: hook-tamper-detection, Property 22: State-file reader tolerance
@pytest.mark.skipif(not POSIX, reason="POSIX permission bits only")
@PROPS
@given(doc=stop_marker_docs(), mode=posix_modes().filter(lambda m: m & 0o077))
def test_group_or_other_bits_make_file_absent(doc: dict, mode: int) -> None:
    """**Validates: Requirements 12.6**"""
    raw = dumps(doc).encode()
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "stop-marker.json"
        _write(path, raw, mode)
        got, calls = _read(path)
        assert got is None
        assert calls == [(str(path), "state_permissions:mode")]
        assert os.lstat(path).st_mode & 0o777 == mode           # reader does not touch the mode
        os.chmod(path, 0o600)                                   # mode may deny the owner read; restore to compare
        assert path.read_bytes() == raw


# Feature: hook-tamper-detection, Property 22: State-file reader tolerance
@pytest.mark.skipif(not POSIX, reason="POSIX symlinks and permission bits only")
@PROPS
@given(doc=stop_marker_docs())
def test_symlink_is_absent(doc: dict) -> None:
    """**Validates: Requirements 12.6**"""
    raw = dumps(doc).encode()
    with tempfile.TemporaryDirectory() as d:
        target, path = Path(d) / "elsewhere.json", Path(d) / "stop-marker.json"
        _write(target, raw)
        path.symlink_to(target)
        got, calls = _read(path)
        assert got is None
        assert calls == [(str(path), "state_permissions:not_regular")]
        assert path.is_symlink() and target.read_bytes() == raw
