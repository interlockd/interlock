"""Daemon_Identity (hook-tamper-detection Req 1): derivation, the 0600 file, verification, and the reply header."""

from __future__ import annotations

import http.client
import json
import os
import re
import shutil
import socket
import stat
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import PRE_BASH

from interlockd import identity
from interlockd.api import ApiServer
from interlockd.auth import rotate_token

TOKEN = "test-token-123"
HEX32 = re.compile(r"^[0-9a-f]{32}$")
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")


# ------------------------------------------------------------------------------------------------ derive / verify


def test_derive_is_32_lowercase_hex_and_deterministic():
    n = bytes(range(16))
    v = identity.derive(TOKEN, n)
    assert HEX32.match(v) and v == identity.derive(TOKEN, n)
    assert identity.derive(TOKEN, identity.new_nonce()) != identity.derive(TOKEN, identity.new_nonce())
    assert len(identity.new_nonce()) == 16


def test_derive_is_token_bound_and_leaks_nothing(tmp_path):
    n = identity.new_nonce()
    assert identity.derive("token-a", n) != identity.derive("token-b", n)
    v = identity.derive(TOKEN, n)
    assert TOKEN not in v and all(part not in v for part in tmp_path.parts if len(part) > 3)


def test_token_rotation_changes_the_value(tmp_path):
    path = tmp_path / "token"
    old = rotate_token(path)
    new = rotate_token(path)
    n = identity.new_nonce()
    assert old != new and identity.derive(old, n) != identity.derive(new, n)


def test_verify_requires_exactly_one_matching_value():
    want = identity.derive(TOKEN, identity.new_nonce())
    assert identity.verify([want], want)
    assert not identity.verify([], want)
    assert not identity.verify([want, want], want)
    assert not identity.verify(["0" * 32], want)
    assert not identity.verify([want.upper()], want)
    assert not identity.verify(["é" * 32], want)              # non-ASCII compares unequal instead of raising


# ------------------------------------------------------------------------------------------------ file


def test_write_read_roundtrip_leaves_no_temp(tmp_path):
    v = identity.derive(TOKEN, identity.new_nonce())
    identity.write(tmp_path, v)
    assert identity.read(tmp_path) == v
    assert (tmp_path / identity.FILE).read_text(encoding="ascii") == v + "\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == [identity.FILE]
    v2 = identity.derive(TOKEN, identity.new_nonce())
    identity.write(tmp_path, v2)                               # rewritten on every start
    assert identity.read(tmp_path) == v2


@posix_only
def test_written_file_is_owner_only(tmp_path):
    (tmp_path / identity.FILE).write_text("stale\n", encoding="ascii")
    os.chmod(tmp_path / identity.FILE, 0o644)                  # a widened leftover is replaced, not reused
    identity.write(tmp_path, identity.derive(TOKEN, identity.new_nonce()))
    assert stat.S_IMODE((tmp_path / identity.FILE).stat().st_mode) == 0o600


def test_read_rejects_absent_and_malformed(tmp_path):
    assert identity.read(tmp_path) is None
    for text in ("", "xyz\n", "0" * 31, "0" * 33, "A" * 32, "\xff\xfe"):
        (tmp_path / identity.FILE).write_bytes(text.encode("latin-1"))
        assert identity.read(tmp_path) is None, text


def test_write_rejects_malformed_value(tmp_path):
    with pytest.raises(ValueError):
        identity.write(tmp_path, "not-hex")
    assert not (tmp_path / identity.FILE).exists()


def test_write_failure_raises_and_cleans_up(tmp_path):
    (tmp_path / identity.FILE).mkdir()                         # os.replace onto a directory fails
    with pytest.raises(OSError):
        identity.write(tmp_path, identity.derive(TOKEN, identity.new_nonce()))
    assert not (tmp_path / (identity.FILE + ".tmp")).exists()


# ------------------------------------------------------------------------------------------------ reply header


@pytest.fixture
def server(daemon):
    s = ApiServer(daemon, TOKEN, "127.0.0.1", 0, identity=identity.derive(TOKEN, identity.new_nonce()))
    s.start_background()
    yield s
    s.shutdown()


def _identity_headers(server, method, path, body: bytes | None = None, token: str | None = TOKEN) -> tuple[int, list]:
    host, port = server.address
    c = http.client.HTTPConnection(host, port, timeout=5)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    r.read()
    c.close()
    return r.status, r.msg.get_all(identity.HEADER) or []


def test_every_reply_carries_exactly_one_identity_header(server):
    hook = json.dumps({"adapter": {"name": "kiro", "version": "t"}, "payload": PRE_BASH}).encode()
    cases = [
        ("GET", "/interlock/v1/health", None, None, 200),
        ("GET", "/v1/health", None, None, 200),
        ("GET", "/interlock/v1/limits", None, None, 401),
        ("POST", "/interlock/v1/hooks/kiro", hook, "wrong", 401),
        ("POST", "/interlock/v1/hooks/kiro", hook, TOKEN, 200),
        ("POST", "/interlock/v1/hooks/kiro?format=text", hook, TOKEN, 200),
        ("POST", "/interlock/v1/hooks/claude-code?format=claude-code",
         json.dumps({"adapter": {"name": "claude-code"}, "payload": {}}).encode(), TOKEN, 200),
        ("POST", "/interlock/v1/hooks/kiro", b"{not json", TOKEN, 400),
        ("GET", "/nope", None, TOKEN, 404),
        ("POST", "/nope", b"{}", TOKEN, 404),
        ("DELETE", "/nope", None, TOKEN, 404),
    ]
    for method, path, body, token, want in cases:
        status, values = _identity_headers(server, method, path, body, token)
        assert status == want, (method, path, status)
        assert values == [server.identity], (method, path, values)


def test_oversize_request_reply_carries_identity(server):
    from interlockd.config import MAX_REQUEST_BYTES

    host, port = server.address
    c = http.client.HTTPConnection(host, port, timeout=5)
    c.putrequest("POST", "/interlock/v1/hooks/kiro")
    c.putheader("Authorization", f"Bearer {TOKEN}")
    c.putheader("Content-Length", str(MAX_REQUEST_BYTES + 1))
    c.putheader("Connection", "close")                        # the body is never sent; no keep-alive read after
    c.endheaders()                                             # the daemon answers 413 before reading the body
    r = c.getresponse()
    assert r.status == 413 and r.msg.get_all(identity.HEADER) == [server.identity]
    c.close()


def test_embedded_server_gets_a_token_bound_identity(daemon):
    s = ApiServer(daemon, TOKEN, "127.0.0.1", 0)
    try:
        assert HEX32.match(s.identity)
    finally:
        s.httpd.server_close()


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="no Unix sockets")
def test_unix_socket_reply_carries_identity(daemon):
    d = Path(tempfile.mkdtemp(prefix="ilid", dir="/tmp"))      # socket paths are length-limited
    try:
        s = ApiServer(daemon, TOKEN, "127.0.0.1", 0, unix_socket=str(d / "s.sock"),
                      identity=identity.derive(TOKEN, identity.new_nonce()))
        s.start_background()
        try:
            for path in ("/interlock/v1/health", "/interlock/v1/limits"):        # 200 and 401
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
                    c.settimeout(5)
                    c.connect(str(d / "s.sock"))
                    c.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
                    raw = b""
                    while chunk := c.recv(65536):
                        raw += chunk
                head = raw.split(b"\r\n\r\n", 1)[0].decode()
                values = [ln.split(":", 1)[1].strip() for ln in head.split("\r\n")[1:]
                          if ln.lower().startswith(identity.HEADER.lower() + ":")]
                assert values == [s.identity], (path, head)
        finally:
            s.shutdown()
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ cmd_serve


class _Stop(Exception):
    pass


def test_serve_writes_identity_before_the_server_and_passes_it(tmp_path, monkeypatch):
    from interlockd import cli

    seen = {}

    def fake_server(daemon, token, host, port, *, unix_socket=None, identity=None):
        seen["file"] = cli_identity_file.read_text(encoding="ascii").strip()
        seen["arg"] = identity
        raise _Stop

    cli_identity_file = tmp_path / identity.FILE
    monkeypatch.setattr(cli, "ApiServer", fake_server)
    with pytest.raises(_Stop):
        cli.cmd_serve(SimpleNamespace(home=str(tmp_path), mode=None, listen="127.0.0.1:0"))
    assert HEX32.match(seen["arg"]) and seen["file"] == seen["arg"]


def test_serve_refuses_to_start_without_identity_file(tmp_path, monkeypatch, capsys):
    from interlockd import cli

    def boom(home, value):
        raise PermissionError("denied")

    monkeypatch.setattr(identity, "write", boom)
    monkeypatch.setattr(cli, "ApiServer", lambda *a, **k: pytest.fail("server constructed without identity"))
    assert cli.cmd_serve(SimpleNamespace(home=str(tmp_path), mode=None, listen="127.0.0.1:0")) == 1
    assert "identity" in capsys.readouterr().err
