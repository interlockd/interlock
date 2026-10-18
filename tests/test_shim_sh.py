"""Integration tests for interlockd/shims/kiro/interlock-hook.sh against a stub daemon (text verdicts)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SHIM = Path(__file__).resolve().parents[1] / "interlockd" / "shims" / "kiro" / "interlock-hook.sh"
PRE = json.dumps({"session_id": "s", "hook_event_name": "PreToolUse", "cwd": "/ws", "tool_name": "execute_bash",
                  "tool_input": {"command": "git push --force origin main"}}, separators=(",", ":"))
POST = json.dumps({"session_id": "s", "hook_event_name": "PostToolUse", "cwd": "/ws", "tool_name": "execute_bash",
                   "tool_input": {"command": "x"}, "tool_response": "Output:\nok\n\nExit Code: 0"}, separators=(",", ":"))

pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="curl not available")


class Stub:
    """Returns a configurable text verdict and records what it received."""

    def __init__(self):
        self.text = "allow shadow 0\n"
        self.seen: list[dict] = []
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): ...

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n))
                stub.seen.append({"auth": self.headers.get("Authorization"), "path": self.path, "body": body})
                if stub.text is None:
                    self.send_response(500); self.end_headers(); return
                data = stub.text.encode()
                self.send_response(200); self.send_header("Content-Type", "text/plain"); self.send_header("Content-Length", str(len(data)))
                self.end_headers(); self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()


@pytest.fixture
def stub():
    s = Stub()
    yield s
    s.close()


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "ih"; h.mkdir()
    (h / "token").write_text("tok-123\n")
    (h / "fail-mode.json").write_text(json.dumps({"default": "open"}))
    return h


def run(home, url, payload, **env):
    e = {**os.environ, "INTERLOCK_HOME": str(home), "INTERLOCK_URL": url, **env}
    return subprocess.run(["sh", str(SHIM)], input=payload, text=True, capture_output=True, env=e, timeout=10, check=False)


def test_allow_shadow_exits_0_and_sends_token(stub, home):
    r = run(home, stub.url, PRE)
    assert r.returncode == 0 and r.stderr == ""
    assert stub.seen[0]["auth"] == "Bearer tok-123"
    assert stub.seen[0]["path"].endswith("/interlock/v1/hooks/kiro?format=text")
    assert stub.seen[0]["body"]["payload"]["tool_name"] == "execute_bash"
    assert stub.seen[0]["body"]["adapter"]["name"] == "kiro"


def test_block_in_enforce_exits_2_with_notice(stub, home):
    stub.text = "block enforce 2\n[interlock] refused: force-push to main was NOT executed.\nSecond line.\n"
    r = run(home, stub.url, PRE)
    assert r.returncode == 2
    assert r.stderr.startswith("[interlock] refused") and "Second line." in r.stderr


def test_ask_in_enforce_exits_2(stub, home):
    stub.text = "ask enforce 2\nPlease confirm with the user.\n"
    r = run(home, stub.url, PRE)
    assert r.returncode == 2 and "confirm" in r.stderr


def test_block_in_shadow_is_not_enforced(stub, home):
    stub.text = "block shadow 2\nwould have blocked\n"
    assert run(home, stub.url, PRE).returncode == 0


def test_post_action_is_record_only(stub, home):
    stub.text = "block enforce 2\nnope\n"
    r = run(home, stub.url, POST)
    assert r.returncode == 0 and stub.seen[0]["body"]["payload"]["hook_event_name"] == "PostToolUse"


def test_daemon_down_fail_open_and_closed(home):
    r = run(home, "http://127.0.0.1:1", PRE)
    assert r.returncode == 0
    r = run(home, "http://127.0.0.1:1", PRE, INTERLOCK_FAIL_MODE="closed")
    assert r.returncode == 2 and "unreachable" in r.stderr
    log = (home / "hook.log").read_text()
    assert "unjudged tool=execute_bash kind=pre" in log and "fail_mode=closed" in log


def test_server_error_falls_back_to_fail_mode(stub, home):
    stub.text = None
    assert run(home, stub.url, PRE).returncode == 0
    assert "unjudged" in (home / "hook.log").read_text()


def test_missing_token_is_inert(stub, home):
    (home / "token").unlink()
    r = run(home, stub.url, PRE)
    assert r.returncode == 0 and stub.seen == []
