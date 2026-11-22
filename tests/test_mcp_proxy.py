"""`interlock mcp-proxy` against a fake stdio MCP server and a real daemon: tool pinning and rug pulls, poisoned
descriptions, gated tools/call, withheld results, shadow mode, and fail modes."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from interlockd.api import ApiServer
from interlockd.config import Settings
from interlockd.mcp_proxy import Pins, Proxy, tool_fingerprint

FAKE = [sys.executable, str(Path(__file__).parent / "fake_mcp_server.py")]


def _daemon_server(settings, mode):
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool

    pol = Policy(); pol.mode = mode; pol.trust.workspace_roots = [str(Path.cwd())]
    d = Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol)
    s = ApiServer(d, "tok", "127.0.0.1", 0)
    s.start_background()
    return s


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    home = tmp_path / "il"; home.mkdir(); (home / "token").write_text("tok\n", encoding="utf-8")
    s = Settings(home=home)
    servers = []

    def make(mode="enforce", up=True):
        if up:
            srv = _daemon_server(s, mode); servers.append(srv)
            s.listen = "{}:{}".format(*srv.address)
        else:
            s.listen = "127.0.0.1:9"
        return s

    yield make
    for srv in servers:
        srv.shutdown()


REQS = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": "hi"}}},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "shell", "arguments": {"command": "git push --force origin main"}}},
    {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "readme", "arguments": {}}},
]


def _run(settings, reqs=REQS, extra_env=None, monkeypatch=None):
    out = io.StringIO()
    p = Proxy("fake", FAKE, settings, client_in=io.StringIO("".join(json.dumps(r) + "\n" for r in reqs)), client_out=out)
    rc = p.run()
    replies = {m["id"]: m for m in map(json.loads, out.getvalue().splitlines()) if "id" in m}
    return rc, replies


def test_enforce(env):
    s = env("enforce")
    rc, r = _run(s)
    assert rc == 0 and r[1]["result"]["serverInfo"]["name"] == "fake"
    names = [t["name"] for t in r[2]["result"]["tools"]]
    assert "add" not in names and {"echo", "readme", "shell"} <= set(names)       # poisoned description hidden
    assert r[3]["result"]["content"][0]["text"].startswith("ran echo")             # benign call forwarded
    assert r[4]["result"]["isError"] is True and "[interlock]" in r[4]["result"]["content"][0]["text"]   # blocked
    assert "evil.example" not in json.dumps(r[5]) and "[interlock]" in r[5]["result"]["content"][0]["text"]  # withheld
    pins = Pins(s.home / "mcp-pins.json").load()
    assert set(pins["fake"]) == {"echo", "add", "readme", "shell"}
    assert "hid tool add" in (s.home / "mcp-proxy.log").read_text(encoding="utf-8")


def test_rug_pull_is_hidden_until_accepted(env, monkeypatch):
    s = env("enforce")
    _run(s)                                                                          # pins the original definitions
    monkeypatch.setenv("RUG", "1")
    _, r = _run(s, REQS[:3])
    assert "shell" not in [t["name"] for t in r[2]["result"]["tools"]]
    assert "possible rug pull" in (s.home / "mcp-proxy.log").read_text(encoding="utf-8")
    assert Pins(s.home / "mcp-pins.json").accept("fake", "shell") == 1
    _, r = _run(s, REQS[:3])
    assert "shell" in [t["name"] for t in r[2]["result"]["tools"]]                   # re-pinned after review


def test_shadow_records_but_changes_nothing(env):
    s = env("shadow")
    _, r = _run(s)
    assert "add" in [t["name"] for t in r[2]["result"]["tools"]]
    assert r[4]["result"]["content"][0]["text"].startswith("ran shell")             # forwarded
    assert "evil.example" in json.dumps(r[5])                                         # not withheld
    assert "would hide (shadow)" in (s.home / "mcp-proxy.log").read_text(encoding="utf-8")


def test_daemon_down_fail_open_and_closed(env):
    s = env(up=False)
    _, r = _run(s)
    assert r[4]["result"]["content"][0]["text"].startswith("ran shell")             # fail open by default
    s.fail_mode = {**s.fail_mode, "default": "closed"}
    _, r = _run(s)
    assert r[3]["result"]["isError"] is True and "unreachable" in r[3]["result"]["content"][0]["text"]


def _in_process(tmp_path, mode):
    """A proxy whose decisions come from an in-process daemon (as the HTTP gateway runs it) with one compromised
    harness."""
    from interlockd import records
    from interlockd.models import InterlockEvent
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.protection import ProtectionState
    from interlockd.store.spool import Spool

    s = Settings(home=tmp_path / "il")
    s.home.mkdir(exist_ok=True)
    pol = Policy(); pol.mode = mode; pol.trust.workspace_roots = [str(tmp_path)]
    d = Daemon(s, spool=Spool(s.spool_dir), policy=pol)
    d.protection = ProtectionState(s.home, d.spool, None, lambda: d.mode, harnesses=lambda: ["claude-code"])
    d.protection.add_reason("claude-code", "shim_modified", "", records.now_iso())
    out = io.StringIO()
    p = Proxy("fake", FAKE, s, client_out=out, quiet=True, mode_fn=lambda: d.mode,
              decider=lambda ev: d.decide(InterlockEvent.model_validate(ev)).model_dump())
    return d, p, out


def test_compromised_harness_blocks_gateway_calls_in_enforce(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    d, p, out = _in_process(tmp_path, "enforce")
    call = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": "hi"}}}
    assert p.on_client_message(call) is None                                 # answered here, never forwarded
    reply = json.loads(out.getvalue())
    assert reply["result"]["isError"] is True
    assert "enforcement_point" in reply["result"]["content"][0]["text"] and "claude-code" in reply["result"]["content"][0]["text"]
    rec = next(d.spool.iter_records())
    assert rec["disposition"] == "block" and rec["findings"][-1]["category"] == "control.hook_tamper"


def test_compromised_harness_annotates_gateway_results_in_shadow(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    d, p, _ = _in_process(tmp_path, "shadow")
    call = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": "hi"}}}
    assert p.on_client_message(call) == call                                 # shadow: forwarded unchanged
    result = {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "ran echo"}]}}
    texts = [c["text"] for c in p.on_server_message(result)["result"]["content"]]
    assert texts[0] == "ran echo" and len(texts) == 2 and "enforcement_point" in texts[1]   # notice appended once
    p.on_client_message({**call, "id": 4})
    again = p.on_server_message({**result, "id": 4})
    assert [c["text"] for c in again["result"]["content"]] == ["ran echo"]   # windowed: once per 60 s
    flagged = [r for r in d.spool.iter_records() if r.get("adapter") == "mcp-proxy"]
    assert flagged and all(r["findings"][-1]["category"] == "control.hook_tamper" for r in flagged)


def test_annotate_result_does_not_repeat_a_carried_notice():
    from interlockd.mcp_proxy import annotate_result

    msg = {"id": 1, "result": {"content": [{"type": "text", "text": "withheld\n\nNOTICE"}]}}
    assert annotate_result(msg, ["NOTICE"]) is msg and annotate_result(msg, []) is msg
    assert annotate_result({"id": 1, "result": {}}, ["N"])["result"]["content"] == [{"type": "text", "text": "N"}]


def test_fingerprint_covers_description_and_schema():
    a = {"name": "t", "description": "d", "inputSchema": {"type": "object"}}
    assert tool_fingerprint(a) == tool_fingerprint(dict(a))
    assert tool_fingerprint(a) != tool_fingerprint({**a, "description": "d2"})
    assert tool_fingerprint(a) != tool_fingerprint({**a, "inputSchema": {"type": "object", "properties": {"x": {}}}})


def test_cli_requires_a_command(capsys):
    from interlockd.cli import main

    assert main(["mcp-proxy", "--name", "x"]) == 2
