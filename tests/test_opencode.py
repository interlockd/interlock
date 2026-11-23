"""OpenCode plugin (JS) against a real daemon via Node: blocks by throwing, passes benign calls, records results,
fails open or closed when the daemon is down; installer and uninstall. Then the stub-based tamper matrix
(hook-tamper-detection Req 1-5, 12.4): identity verification, token rejection, unexpected loss versus operator stop,
fail-mode selection and the hook.log lines."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
from shim_stub import FIXTURE_IDENTITY, FIXTURE_TOKEN, Reply, ShimHome, StubDaemon, install_shim, run_opencode

from interlockd.api import ApiServer
from interlockd.cli import main
from interlockd.lifecycle import summarize_hook_log

PLUGIN = Path(__file__).resolve().parents[1] / "interlockd" / "shims" / "opencode" / "interlock.js"
DRIVER = """
const { Interlock } = await import(process.argv[2]);
const hooks = await Interlock({ directory: "/ws" });
const out = [];
for (const [tool, args] of [["bash", {command: "git push --force origin main"}], ["bash", {command: "ls"}]]) {
  try { await hooks["tool.execute.before"]({tool, sessionID: "oc1"}, {args}); out.push("allowed"); }
  catch (e) { out.push("blocked: " + e.message.slice(0, 40)); }
}
await hooks["tool.execute.after"]({tool: "read", sessionID: "oc1"}, {args: {filePath: "README.md"}, output: "hello"});
console.log(JSON.stringify(out));
"""

def _node_works() -> bool:
    if shutil.which("node") is None:
        return False
    try:
        return subprocess.run(["node", "--version"], capture_output=True, timeout=10, check=False).returncode == 0
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _node_works(), reason="node not available or not runnable")


@pytest.fixture
def server(settings):
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool

    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = ["/ws"]
    d = Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol)
    s = ApiServer(d, "tok", "127.0.0.1", 0); s.start_background()
    yield s
    s.shutdown()


def _run(tmp_path, url, identity=None, files=None, **env):
    home = tmp_path / "ih"; home.mkdir(exist_ok=True); (home / "token").write_text("tok\n", encoding="utf-8")
    if identity is not None:
        (home / "identity").write_text(identity + "\n", encoding="utf-8")
    for name, text in (files or {}).items():
        (home / name).write_text(text, encoding="utf-8")
    plugin = tmp_path / "interlock.mjs"; plugin.write_text(PLUGIN.read_text(encoding="utf-8").replace("__VERSION__", "t"), encoding="utf-8")
    driver = tmp_path / "driver.mjs"; driver.write_text(DRIVER, encoding="utf-8")
    e = {**{k: v for k, v in os.environ.items() if not k.startswith("INTERLOCK_")},
         "INTERLOCK_HOME": str(home), "INTERLOCK_URL": url, **env}
    r = subprocess.run(["node", str(driver), plugin.as_uri()], text=True, capture_output=True, env=e, timeout=30, check=False)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_plugin_against_daemon(server, tmp_path):
    host, port = server.address
    out = _run(tmp_path, f"http://{host}:{port}", identity=server.identity)
    assert out[0].startswith("blocked: [interlock]") and out[1] == "allowed"
    recs = list(server.daemon.spool.iter_records())
    assert {r["kind"] for r in recs} == {"pre_action", "post_action"} and {r["agent_type"] for r in recs} == {"opencode"}


def test_plugin_refuses_a_daemon_with_another_identity(server, tmp_path):
    host, port = server.address
    out = _run(tmp_path, f"http://{host}:{port}", identity="f" * 32)
    assert out == ["blocked: [interlock] This action was NOT executed"] * 2
    log = (tmp_path / "ih" / "hook.log").read_text(encoding="utf-8").splitlines()
    assert [line.split()[1:3] for line in log] == [["tamper", "daemon_identity"]] * 3 and server.identity not in str(log)


def test_plugin_daemon_down(tmp_path):
    # no stop marker: an unexpected loss, refused under fail_mode.tamper (closed when fail-mode.json is absent)
    assert _run(tmp_path, "http://127.0.0.1:1") == ["blocked: [interlock] This action was NOT executed"] * 2
    stopped = {"stop-marker.json": json.dumps({"action": "stop", "written_at": "2026-10-17T10:00:00Z"})}
    assert _run(tmp_path, "http://127.0.0.1:1", files=stopped) == ["allowed", "allowed"]   # operator stop: default open
    out = _run(tmp_path, "http://127.0.0.1:1", files=stopped, INTERLOCK_FAIL_MODE="closed")
    assert out[0].startswith("blocked: [interlock] This action was NOT") and out[1].startswith("blocked")


def test_install_uninstall(tmp_path, monkeypatch):
    home = tmp_path / "home"; (home / ".config" / "opencode").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home)); monkeypatch.setenv("INTERLOCK_HOME", str(home / ".interlock"))
    monkeypatch.setenv("USERPROFILE", str(home)); monkeypatch.setenv("INTERLOCK_HOME", str(home / ".interlock"))   # Windows: Path.home()
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False); monkeypatch.setenv("PATH", "/usr/bin:/bin"); monkeypatch.chdir(tmp_path)
    assert main(["init", "--yes", "--no-service", "--harness", "opencode"]) == 0
    plugin = home / ".config" / "opencode" / "plugins" / "interlock.js"
    assert plugin.exists() and "__VERSION__" not in plugin.read_text(encoding="utf-8")
    assert main(["uninstall", "--yes"]) == 0 and not plugin.exists()


# ------------------------------------------------------------------------------------- stub-based tamper matrix

KEYWORDS = ("token_rejected", "daemon_identity", "daemon_lost", "enforcement_point")
UNREACHABLE = "blocked: [interlock] This action was NOT executed: the Interlock daemon is unreachable"
PRE = json.dumps({"hook": "before", "tool": "bash", "args": {"command": "echo SECRET-ARG-MARKER"}})
POST = json.dumps({"hook": "after", "tool": "bash", "args": {"command": "echo SECRET-ARG-MARKER"},
                   "output": "SECRET-OUTPUT-MARKER"})


def _verdict(disposition: str, mode: str = "enforce", notice: str | None = None, reason: str = "") -> str:
    return json.dumps({"disposition": disposition, "mode": mode, "tier": 2, "reason": reason, "notice": notice},
                      separators=(",", ":"))


def _closed_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    return port


class OC:
    """One home, one stub and the plugin installed for it; `call` runs one hook and returns the result."""

    def __init__(self, **home_kw):
        self.home = ShimHome.create(**home_kw)
        self.stub = StubDaemon(Reply(body=_verdict("allow"), identity=[self.home.identity]))
        self.home.write_daemon_json(self.stub.listen)
        self.plugin = install_shim(PLUGIN, "opencode", self.home)

    def call(self, spec: str = PRE, **kw):
        return run_opencode(self.plugin, spec, self.home, **kw)

    def down(self) -> None:
        """No daemon: daemon.json points at a closed port."""
        self.stub.close()
        self.home.write_daemon_json(f"127.0.0.1:{_closed_port()}")

    def marker(self, doc: dict | str) -> None:
        self.home.write("stop-marker.json", doc if isinstance(doc, str) else json.dumps(doc, sort_keys=True))

    def lines(self) -> list[str]:
        return self.home.hook_log().splitlines()

    def close(self) -> None:
        with contextlib.suppress(OSError):     # down() already closed it
            self.stub.close()
        self.home.cleanup()


@pytest.fixture
def oc():
    made: list[OC] = []

    def make(**kw) -> OC:
        o = OC(**kw); made.append(o)
        return o

    yield make
    for o in made:
        o.close()


def _assert_tamper(o: OC, out, cause: str, *, kind: str = "pre", status: str, fail_mode: str = "closed",
                   blocked: bool = True) -> None:
    if blocked:
        msg = out.stdout.strip()
        assert msg.startswith("blocked: [interlock] This action was NOT executed"), out
        assert sum(msg.count(k) for k in KEYWORDS) == 1 and msg.count(cause) == 1
        assert "`interlock doctor`" in msg
    else:
        assert out.stdout.strip() == "allowed", out
    lines = o.lines()
    assert len(lines) == 1, lines
    line = lines[0]
    assert f" tamper {cause} harness=opencode tool=bash kind={kind} " in line
    assert line.endswith(f" status={status} fail_mode={fail_mode}")
    assert sum(line.count(k) for k in KEYWORDS) == 1
    for secret in filter(None, (FIXTURE_TOKEN, o.home.identity, FIXTURE_IDENTITY, "SECRET-ARG-MARKER",
                                "SECRET-OUTPUT-MARKER")):
        assert secret not in line and secret not in out.stdout and secret not in out.stderr


@pytest.mark.parametrize("disposition,expect", [
    ("allow", "allowed"),
    ("ask", "blocked: [interlock] refused: needs confirmation"),
    ("block", "blocked: [interlock] fixture block notice"),
])
def test_verified_reply_applied_unchanged(oc, disposition, expect):
    o = oc()
    o.stub.set(body=_verdict(disposition, notice="[interlock] fixture block notice" if disposition == "block" else None,
                             reason="needs confirmation"), identity=[o.home.identity])
    out = o.call()
    assert (out.returncode, out.stdout.strip(), out.stderr) == (0, expect, "")
    assert o.home.hook_log() == ""
    req = o.stub.requests[0]
    assert (req.method, req.path, req.header("Authorization")) == (
        "POST", "/interlock/v1/decide", [f"Bearer {FIXTURE_TOKEN}"])
    assert req.json()["adapter"] == {"name": "opencode", "version": "0.1.8", "shim": str(o.plugin)}   # Req 5.10


def test_shadow_and_post_replies_are_not_refusals(oc):
    o = oc()
    o.stub.set(body=_verdict("block", mode="shadow", notice="n"), identity=[o.home.identity])
    assert o.call().stdout.strip() == "allowed"
    o.stub.set(body=_verdict("warn"), identity=[o.home.identity])
    assert o.call(POST).stdout.strip() == "allowed" and o.home.hook_log() == ""
    assert o.stub.requests[-1].json()["result"]["content"] == "SECRET-OUTPUT-MARKER"


@pytest.mark.parametrize("status", [401, 403])
def test_token_rejected_pre_refuses(oc, status):
    o = oc()
    o.stub.set(status=status, body='{"error":"unauthorized"}', identity=[o.home.identity])
    out = o.call()
    _assert_tamper(o, out, "token_rejected", status=str(status))
    assert f"the process at {o.stub.url} rejected" in out.stdout


@pytest.mark.parametrize("status", [401, 403])
def test_token_rejected_post_logs_only(oc, status):
    o = oc()
    o.stub.set(status=status, body='{"error":"unauthorized"}')
    _assert_tamper(o, o.call(POST), "token_rejected", kind="post", status=str(status), blocked=False)


@pytest.mark.parametrize("identity", [[], ["dup"], ["0" * 32]], ids=["missing", "duplicated", "wrong"])
def test_daemon_identity_refused(oc, identity):
    o = oc()
    ids = [o.home.identity, o.home.identity] if identity == ["dup"] else identity
    o.stub.set(body=_verdict("allow"), identity=ids)
    out = o.call()
    _assert_tamper(o, out, "daemon_identity", status="200")
    assert f"answering at {o.stub.url} is not this home's" in out.stdout


def test_daemon_identity_post_logs_only(oc):
    o = oc()
    o.stub.set(body=_verdict("allow"), identity=[])
    _assert_tamper(o, o.call(POST), "daemon_identity", kind="post", status="200", blocked=False)


def test_identity_file_missing_is_daemon_identity(oc):
    o = oc(identity=None)
    o.stub.set(body=_verdict("allow"), identity=[FIXTURE_IDENTITY])
    _assert_tamper(o, o.call(), "daemon_identity", status="200")


def test_interlock_url_is_verified_too(oc):
    o = oc()
    (o.home.path / "daemon.json").unlink()        # INTERLOCK_URL alone is enough to connect
    assert o.call(url=o.stub.url + "/").stdout.strip() == "allowed" and len(o.stub.requests) == 1
    o.stub.set(body=_verdict("allow"), identity=["f" * 32])
    _assert_tamper(o, o.call(url=o.stub.url), "daemon_identity", status="200")
    assert f" addr={o.stub.url} " in o.lines()[0]


def test_missing_token_is_inert(oc):
    o = oc(token=None)
    out = o.call()
    assert out.stdout.strip() == "allowed" and o.stub.requests == []
    assert [line.split(" ", 1)[1] for line in o.lines()] == [f"inert: no token at {o.home.path / 'token'}"]


@pytest.mark.parametrize("fail_mode,expect", [("open", "allowed"), ("closed", UNREACHABLE)])
def test_other_http_errors_use_the_default_fail_mode(oc, fail_mode, expect):
    o = oc(fail_mode={"default": fail_mode, "tamper": "closed"})
    o.stub.set(status=500, body='{"error":"x"}', identity=[o.home.identity])
    assert o.call().stdout.strip().startswith(expect)
    assert o.lines()[0].split(" ", 1)[1] == (
        f"unjudged why=http_500 harness=opencode tool=bash kind=pre addr={o.stub.url} fail_mode={fail_mode}")


def test_daemon_json_absent_is_daemon_lost_without_a_request(oc):
    o = oc()
    (o.home.path / "daemon.json").unlink()
    out = o.call()
    _assert_tamper(o, out, "daemon_lost", status="-")
    assert o.stub.requests == []
    msg = out.stdout
    assert "Interlock daemon stopped unexpectedly" in msg and f"Home: {o.home.path}." in msg
    assert "`interlock doctor`" in msg and "`interlock start`" in msg


def _now() -> int:
    return int(time.time())


MARKERS = {
    "none": (None, "tamper daemon_lost"),
    "stop": ({"action": "stop", "written_at": "2026-10-17T10:00:00Z", "pid": 1, "version": "0.2.0"},
             "unjudged why=operator_stopped"),
    "uninstall": ({"action": "uninstall", "written_at": "2026-10-17T10:00:00Z"}, "unjudged why=operator_stopped"),
    "restarting": ("future", "unjudged why=restarting"),
    "restart-expired": ("past", "tamper daemon_lost"),
    "restart-now": ("now", "tamper daemon_lost"),
    "garbage": ("{not json", "tamper daemon_lost"),
    "array": ("[1, 2]", "tamper daemon_lost"),
    "no-written-at": ({"action": "stop"}, "tamper daemon_lost"),
    "action-not-string": ({"action": 1, "written_at": "2026-10-17T10:00:00Z"}, "tamper daemon_lost"),
    "expiry-not-int": ({"action": "restart", "written_at": "x", "expires_epoch": "9999999999"}, "tamper daemon_lost"),
}


@pytest.mark.parametrize("name", list(MARKERS))
def test_daemon_down_marker_variants(oc, name):
    doc, expect = MARKERS[name]
    o = oc(fail_mode={"default": "open", "tamper": "closed"})
    o.down()
    if doc in ("future", "past", "now"):
        exp = _now() + {"future": 120, "past": -1, "now": 0}[doc]
        doc = {"action": "restart", "written_at": "2026-10-17T10:00:00Z", "expires_at": "2026-10-17T10:02:00Z",
               "expires_epoch": exp}
    if doc is not None:
        o.marker(doc)
    out = o.call()
    if expect.startswith("tamper"):
        _assert_tamper(o, out, "daemon_lost", status="-")
    else:
        assert out.stdout.strip() == "allowed"
        assert len(o.lines()) == 1 and f" {expect} harness=opencode tool=bash kind=pre " in o.lines()[0]
        assert o.lines()[0].endswith(" fail_mode=open")


def test_operator_stop_with_default_closed_refuses_as_unreachable(oc):
    o = oc(fail_mode={"default": "closed", "tamper": "open"})
    o.down()
    o.marker({"action": "stop", "written_at": "2026-10-17T10:00:00Z"})
    out = o.call()
    assert out.stdout.strip().startswith(UNREACHABLE)
    assert not any(k in out.stdout for k in KEYWORDS)
    assert o.lines()[0].endswith("fail_mode=closed") and " unjudged why=operator_stopped " in o.lines()[0]


def test_reachable_daemon_ignores_the_stop_marker(oc):
    o = oc()
    o.marker({"action": "stop", "written_at": "2026-10-17T10:00:00Z"})
    assert o.call().stdout.strip() == "allowed" and len(o.stub.requests) == 1 and o.home.hook_log() == ""


def test_daemon_lost_post_logs_only(oc):
    o = oc()
    o.down()
    _assert_tamper(o, o.call(POST), "daemon_lost", kind="post", status="-", blocked=False)


def test_timeout_is_an_unexpected_loss(oc):
    o = oc()
    o.stub.set(body=_verdict("allow"), identity=[o.home.identity], delay_s=3.0)
    t0 = time.monotonic()
    _assert_tamper(o, o.call(), "daemon_lost", status="-")
    assert time.monotonic() - t0 < 3.0


def test_connection_closed_without_reply_is_an_unexpected_loss(oc):
    o = oc()
    o.stub.set(close_without_reply=True)
    _assert_tamper(o, o.call(), "daemon_lost", status="-")


FAIL_MODE_FILES = {
    "missing": (None, "closed"),
    "no-tamper-key": ('{"default": "open"}', "closed"),
    "invalid-tamper": ('{"default": "open", "tamper": "bogus"}', "closed"),
    "unparseable": ('{"default": "open", "tamper": "open"', "closed"),
    "oversize": (json.dumps({"default": "open", "tamper": "open", "pad": "x" * (64 * 1024)}), "closed"),
    "tamper-open": ('{\n  "default": "closed",\n  "tamper": "open"\n}\n', "open"),
}


@pytest.mark.parametrize("name", list(FAIL_MODE_FILES))
def test_tamper_fail_mode_from_the_file(oc, name):
    text, mode = FAIL_MODE_FILES[name]
    o = oc()
    if text is None:
        (o.home.path / "fail-mode.json").unlink()
    else:
        o.home.write("fail-mode.json", text)
    o.stub.set(status=401, body="")
    _assert_tamper(o, o.call(), "token_rejected", status="401", fail_mode=mode, blocked=mode == "closed")


@pytest.mark.parametrize("value", ["open", "", "CLOSED", "no"])
def test_env_values_other_than_closed_are_ignored(oc, value):
    o = oc(fail_mode={"default": "closed"})               # tamper missing -> closed
    o.stub.set(status=401, body="")
    _assert_tamper(o, o.call(env={"INTERLOCK_FAIL_MODE": value}), "token_rejected", status="401")
    o.down()
    o.marker({"action": "stop", "written_at": "2026-10-17T10:00:00Z"})
    assert o.call(env={"INTERLOCK_FAIL_MODE": value}).stdout.strip().startswith(UNREACHABLE)


def test_env_closed_tightens_both_modes(oc):
    o = oc(fail_mode={"default": "open", "tamper": "open"})
    o.stub.set(status=403, body="")
    _assert_tamper(o, o.call(env={"INTERLOCK_FAIL_MODE": "closed"}), "token_rejected", status="403")
    o.down()
    o.marker({"action": "stop", "written_at": "2026-10-17T10:00:00Z"})
    assert o.call(env={"INTERLOCK_FAIL_MODE": "closed"}).stdout.strip().startswith(UNREACHABLE)


def test_unwritable_hook_log_still_refuses(oc):
    o = oc()
    (o.home.path / "hook.log").mkdir()                    # appending to a directory fails
    o.stub.set(status=401, body="")
    out = o.call()
    assert out.stdout.strip().startswith("blocked: [interlock] This action was NOT executed") and "token_rejected" in out.stdout
    assert out.stderr.strip() == f"[interlock] could not write {o.home.path / 'hook.log'}"
    assert FIXTURE_TOKEN not in out.stderr and "SECRET-ARG-MARKER" not in out.stderr


def test_hook_log_lines_feed_the_startup_summary(oc):
    o = oc(fail_mode={"default": "open"})
    o.stub.set(status=401, body="")
    o.call()
    o.stub.set(body=_verdict("allow"), identity=[])
    o.call()
    o.down()
    o.call()
    o.marker({"action": "stop", "written_at": "2026-10-17T10:00:00Z"})
    o.call()
    s = summarize_hook_log(o.lines(), "2000-01-01T00:00:00Z")
    assert s is not None
    assert (s["unjudged"], s["tamper_token_rejected"], s["tamper_daemon_identity"], s["tamper_daemon_lost"]) == (1, 1, 1, 1)
