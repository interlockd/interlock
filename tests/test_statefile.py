"""statefile: deterministic serializer, atomic 0600 writes, tolerant reads (Requirement 12)."""

from __future__ import annotations

import json
import os
import sys

import pytest

from interlockd import statefile
from interlockd.statefile import MAX_BYTES, dumps, read_state, single_line, write_state

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")

MARKER = {"action": "restart", "expires_at": "2026-10-17T10:02:00Z", "expires_epoch": 1792231320, "pid": 5150,
          "version": "0.2.0", "written_at": "2026-10-17T10:00:00Z"}
PROTECTION = {"aggregate": "compromised", "observing": False,
              "reasons": {"claude_code__shim_modified": "2026-10-17T10:00:00Z"},
              "events": {"claude_code__shim_modified": "01JD0000000000000000000000"}, "state_kiro": "protected"}


class Errors(list):
    def __call__(self, file: str, reason: str) -> None:
        self.append((file, reason))


def _write_raw(path, data: bytes, mode: int = 0o600) -> None:
    path.write_bytes(data)
    os.chmod(path, mode)


# --- dumps / single_line ---------------------------------------------------------------------------------------

def test_dumps_is_deterministic_and_round_trips():
    text = dumps(MARKER)
    assert text.endswith("}\n") and not text.endswith("\n\n")
    assert text == dumps(dict(reversed(list(MARKER.items()))))           # key order of the input does not matter
    assert text.index('"action"') < text.index('"expires_at"') < text.index('"written_at"')
    assert '"action": "restart", ' in text
    assert json.loads(text) == MARKER
    assert dumps(json.loads(text)) == text
    assert dumps(json.loads(dumps(PROTECTION))) == dumps(PROTECTION)


def test_single_line_has_no_newline_and_keeps_listen_match():
    line = single_line({"listen": "127.0.0.1:7391", "pid": 42, "version": "0.2.0"})
    assert "\n" not in line
    assert '"listen": "127.0.0.1:7391"' in line                          # what the sh shim matches


@pytest.mark.parametrize("doc", [
    {"": "x"}, {"1abc": "x"}, {"a-b": "x"}, {"k" * 33: "x"}, {"a": {"b-c": "x"}},   # bad keys
    {"a": {"b": {"c": "d"}}}, {"a": ["x"]}, {"a": {"b": ["x"]}},                     # nesting
    {"a": 1.5}, {"a": None}, {"a": {"b": None}},                                     # value types
    {"a": 'say "hi"'}, {"a": "line\nbreak"}, {"a": "back\\slash"}, {"a": "caf\u00e9"},   # need escapes
])
def test_dumps_rejects_nonconforming_documents(doc):
    with pytest.raises(ValueError):
        dumps(doc)


def test_dumps_rejects_oversize_and_accepts_limits():
    assert dumps({"k" * 32: True, "_": 0, "n": -7})
    with pytest.raises(ValueError):
        dumps({"a": "x" * MAX_BYTES})


# --- write_state -----------------------------------------------------------------------------------------------

def test_write_then_read_round_trip(tmp_path):
    p = tmp_path / "stop-marker.json"
    assert write_state(p, MARKER) is True
    assert p.read_text() == dumps(MARKER)
    assert read_state(p, {"action": str, "written_at": str, "expires_epoch": int}) == MARKER
    assert not (tmp_path / "stop-marker.json.tmp").exists()


@posix_only
def test_written_file_is_owner_only_even_with_open_umask(tmp_path):
    old = os.umask(0)
    try:
        p = tmp_path / "protection-state.json"
        assert write_state(p, PROTECTION)
    finally:
        os.umask(old)
    assert p.stat().st_mode & 0o777 == 0o600


def test_stale_temp_file_is_replaced(tmp_path):
    p = tmp_path / "integrity-baseline.json"
    (tmp_path / "integrity-baseline.json.tmp").write_text("{half a docu")
    assert write_state(p, {"version": "0.2.0"})
    assert not (tmp_path / "integrity-baseline.json.tmp").exists()
    assert read_state(p, {"version": str}) == {"version": "0.2.0"}


def test_failed_rename_keeps_previous_and_removes_temp(tmp_path):
    p = tmp_path / "state.json"
    p.mkdir()                                                            # rename onto a directory fails
    (p / "keep").write_text("x")
    errors = Errors()
    assert write_state(p, MARKER, on_error=errors) is False
    assert not (tmp_path / "state.json.tmp").exists()
    assert (p / "keep").read_text() == "x"
    assert len(errors) == 1 and errors[0][0] == str(p) and errors[0][1].startswith("state_write_failed:")


@posix_only
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores directory permissions")
def test_unwritable_directory_reports_and_keeps_previous(tmp_path):
    d = tmp_path / "home"
    d.mkdir()
    p = d / "stop-marker.json"
    assert write_state(p, MARKER)
    before = p.read_bytes()
    os.chmod(d, 0o500)
    try:
        errors = Errors()
        assert write_state(p, {"action": "stop", "written_at": "x"}, on_error=errors) is False
        assert p.read_bytes() == before
        assert [r for _, r in errors] == ["state_write_failed:eacces"]
    finally:
        os.chmod(d, 0o700)
    assert not (d / "stop-marker.json.tmp").exists()


def test_invalid_document_is_reported_not_raised(tmp_path):
    p = tmp_path / "s.json"
    errors = Errors()
    assert write_state(p, {"a": None}, on_error=errors) is False
    assert errors == [(str(p), "state_write_failed:invalid_document")]
    assert not p.exists()


# --- read_state ------------------------------------------------------------------------------------------------

def test_absent_file_is_none_without_error(tmp_path):
    errors = Errors()
    assert read_state(tmp_path / "nope.json", {}, on_error=errors) is None
    assert errors == []


@pytest.mark.parametrize("data,required,reason", [
    (b"not json", {}, "invalid_json"),
    (b"", {}, "invalid_json"),
    (b'["a"]', {}, "not_object"),
    (b'{"a": {"b": {"c": "d"}}}', {}, "too_deep"),
    (b'{"a": [1]}', {}, "too_deep"),
    (b'{"a": 1.5}', {}, "bad_value"),
    (b'{"a": NaN}', {}, "invalid_json"),
    (b'{"a": "x", "a": "y"}', {}, "duplicate_key"),
    (b'{"a-b": "x"}', {}, "bad_key"),
    (b'{"a": "x\\ny"}', {}, "needs_escape"),
    (b'{"a": "\xff"}', {}, "encoding"),
    (b'{"written_at": "x"}', {"action": str, "written_at": str}, "missing_key"),
    (b'{"action": 1, "written_at": "x"}', {"action": str, "written_at": str}, "wrong_type"),
    (b'{"pid": true}', {"pid": int}, "wrong_type"),
    (b'{"a": "' + b"x" * MAX_BYTES + b'"}', {}, "too_large"),
])
def test_nonconforming_content_is_absent_reported_once_and_untouched(tmp_path, data, required, reason):
    p = tmp_path / "s.json"
    _write_raw(p, data)
    errors = Errors()
    assert read_state(p, required, on_error=errors) is None
    assert errors == [(str(p), f"state_unreadable:{reason}")]
    assert p.read_bytes() == data


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlink_is_rejected(tmp_path):
    real = tmp_path / "real.json"
    _write_raw(real, dumps(MARKER).encode())
    link = tmp_path / "stop-marker.json"
    link.symlink_to(real)
    errors = Errors()
    assert read_state(link, {"action": str}, on_error=errors) is None
    assert errors == [(str(link), "state_permissions:not_regular")]


def test_directory_is_rejected(tmp_path):
    d = tmp_path / "s.json"
    d.mkdir()
    errors = Errors()
    assert read_state(d, {}, on_error=errors) is None
    assert errors == [(str(d), "state_permissions:not_regular")]


@posix_only
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o666, 0o610])
def test_group_or_other_bits_are_rejected(tmp_path, mode):
    p = tmp_path / "s.json"
    data = dumps(MARKER).encode()
    _write_raw(p, data, mode)
    errors = Errors()
    assert read_state(p, {"action": str}, on_error=errors) is None
    assert errors == [(str(p), "state_permissions:mode")]
    assert p.read_bytes() == data and p.stat().st_mode & 0o777 == mode


@posix_only
def test_foreign_owner_is_rejected(tmp_path, monkeypatch):
    p = tmp_path / "s.json"
    _write_raw(p, dumps(MARKER).encode())
    monkeypatch.setattr(os, "geteuid", lambda: p.stat().st_uid + 1)
    errors = Errors()
    assert read_state(p, {"action": str}, on_error=errors) is None
    assert errors == [(str(p), "state_permissions:owner")]


def test_owner_and_mode_checks_skipped_without_posix_bits(tmp_path, monkeypatch):
    p = tmp_path / "s.json"
    _write_raw(p, dumps(MARKER).encode(), 0o644)
    monkeypatch.setattr(statefile, "_POSIX", False)
    assert read_state(p, {"action": str}) == MARKER


def test_conforming_file_is_left_unchanged_by_read(tmp_path):
    p = tmp_path / "s.json"
    assert write_state(p, PROTECTION)
    before, mtime = p.read_bytes(), p.stat().st_mtime_ns
    assert read_state(p, {"aggregate": str, "reasons": dict, "observing": bool}) == PROTECTION
    assert p.read_bytes() == before and p.stat().st_mtime_ns == mtime
