"""Unix-socket transport: created 0600, serves the same API, and the shim prefers it over TCP."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

from interlockd.api import ApiServer

SHIM = Path(__file__).resolve().parents[1] / "interlockd" / "shims" / "claude-code" / "interlock-hook.sh"
PRE = {"session_id": "u1", "cwd": "/ws", "hook_event_name": "PreToolUse", "tool_name": "Bash",
       "tool_input": {"command": "git push --force origin main"}, "tool_use_id": "t"}


@pytest.fixture
def short_home():
    d = Path(tempfile.mkdtemp(prefix="ilsock", dir="/tmp"))     # socket paths are length-limited (~104 bytes)
    (d / "token").write_text("tok\n")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def server(settings, short_home):
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool

    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = ["/ws"]
    d = Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol)
    s = ApiServer(d, "tok", "127.0.0.1", 0, unix_socket=str(short_home / "interlockd.sock")); s.start_background()
    yield s
    s.shutdown()


def test_socket_is_private(server, short_home):
    sock = short_home / "interlockd.sock"
    assert sock.is_socket() and stat.S_IMODE(sock.stat().st_mode) == 0o600


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl not available")
def test_shim_uses_the_socket(server, short_home):
    shim = short_home / "shim.sh"; shim.write_text(SHIM.read_text().replace("__HARNESS__", "claude-code"))
    env = {k: v for k, v in os.environ.items() if k != "INTERLOCK_URL"}
    env["INTERLOCK_HOME"] = str(short_home)
    (short_home / "daemon.json").write_text(json.dumps({"listen": "127.0.0.1:9"}))   # TCP would fail: only the socket works
    r = subprocess.run(["sh", str(shim)], input=json.dumps(PRE), text=True, capture_output=True, env=env, timeout=10, check=False)
    assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    host, port = server.address                                  # an explicit URL still wins over the socket
    env["INTERLOCK_URL"] = f"http://{host}:{port}"
    r = subprocess.run(["sh", str(shim)], input=json.dumps(PRE), text=True, capture_output=True, env=env, timeout=10, check=False)
    assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_socket_removed_on_shutdown(settings, short_home):
    from interlockd.pipeline import Daemon
    from interlockd.store.spool import Spool

    s = ApiServer(Daemon(settings, spool=Spool(settings.spool_dir)), "tok", "127.0.0.1", 0, unix_socket=str(short_home / "x.sock"))
    s.start_background(); s.shutdown()
    assert not (short_home / "x.sock").exists()

