"""`interlock mcp`: the JSON-RPC lifecycle over stdio and each advisory tool. Read-only by construction."""

from __future__ import annotations

import io
import json
import subprocess
import sys

import pytest

from interlockd.config import Settings
from interlockd.mcp_server import TOOLS, InterlockMCP


@pytest.fixture
def mcp(tmp_path, monkeypatch):
    home = tmp_path / "home"; home.mkdir()
    monkeypatch.setenv("HOME", str(home)); monkeypatch.setenv("PATH", "/usr/bin:/bin"); monkeypatch.chdir(tmp_path)
    s = Settings(home=home / ".interlock"); s.listen = "127.0.0.1:9"
    return InterlockMCP(s)


def _session(mcp, *msgs):
    out = io.StringIO()
    mcp.serve(io.StringIO("".join(json.dumps(m) + "\n" for m in msgs)), out)
    return [json.loads(line) for line in out.getvalue().splitlines()]


def test_lifecycle(mcp):
    r = _session(mcp, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                 {"jsonrpc": "2.0", "method": "notifications/initialized"},
                 {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                 {"jsonrpc": "2.0", "id": 3, "method": "nope"},
                 {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "missing", "arguments": {}}})
    assert [m["id"] for m in r] == [1, 2, 3, 4]                         # the notification gets no reply
    assert r[0]["result"]["serverInfo"]["name"] == "interlock" and "tools" in r[0]["result"]["capabilities"]
    assert {t["name"] for t in r[1]["result"]["tools"]} == {t["name"] for t in TOOLS}
    assert r[2]["error"]["code"] == -32601 and r[3]["error"]["code"] == -32602


def test_check_action(mcp, tmp_path):
    v = mcp.call("check_action", {"command": "git push --force origin main", "cwd": str(tmp_path)})
    assert v["decision"] == "block" and v["rules"][0]["rule"] == "git.force_push_protected_branch" and "do not rephrase" in v["note"]
    assert mcp.call("check_action", {"command": "pytest -q", "cwd": str(tmp_path)})["decision"] == "allow"
    assert not (mcp.settings.home / "spool").exists()                   # a what-if never lands in the audit log
    assert "error" in mcp.call("check_action", {})


def test_decisions_and_explain(mcp):
    from interlockd.store.spool import Spool

    sp = Spool(mcp.settings.spool_dir)
    sp.append({"event_id": "e1", "received_at": "2026-10-17T00:00:00Z", "disposition": "allow", "tool_name": "Bash", "arguments": {"command": "ls"}})
    sp.append({"event_id": "e2", "received_at": "2026-10-17T00:00:01Z", "disposition": "block", "mode": "enforce", "tool_name": "Bash",
               "arguments": {"command": "git push -f origin main"}, "reason": "git: force push",
               "findings": [{"rule": "git.force_push_protected_branch", "category": "security.malicious_command"}]})
    d = mcp.call("recent_decisions", {})["decisions"]
    assert [x["event_id"] for x in d] == ["e2"]
    assert len(mcp.call("recent_decisions", {"only_stops": False})["decisions"]) == 2
    e = mcp.call("explain_decision", {})
    assert e["event_id"] == "e2" and e["rules"][0]["rule"] == "git.force_push_protected_branch"
    assert "error" in mcp.call("explain_decision", {"event_id": "nope"})


def test_override_is_a_suggestion_only(mcp):
    out = mcp.call("suggest_rule_override", {"rule_id": "git.push_unknown_remote", "action": "allow"})
    assert "git.push_unknown_remote: { action: allow }" in out["yaml"] and "does not apply" in out["note"]
    assert not (mcp.settings.home / "policy.yaml").exists()
    assert "error" in mcp.call("suggest_rule_override", {"rule_id": "made.up", "action": "allow"})


def test_status_and_scan(mcp):
    st = mcp.call("interlock_status", {})
    assert st["ok"] is False and any(c["check"] == "daemon" and not c["ok"] for c in st["checks"])
    assert set(mcp.call("scan_mcp_servers", {})) == {"servers", "findings"}


def test_cli_stdio():
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    r = subprocess.run([sys.executable, "-m", "interlockd", "mcp"], input="".join(json.dumps(m) + "\n" for m in msgs),
                       text=True, capture_output=True, timeout=30, check=False)
    lines = [json.loads(x) for x in r.stdout.splitlines()]
    assert r.returncode == 0 and len(lines) == 2 and lines[1]["result"]["tools"]


def test_init_mcp_registers_and_uninstall_removes(tmp_path, monkeypatch):
    from interlockd.cli import main

    home = tmp_path / "home"
    for d in (".cursor", ".codex", ".gemini", ".kiro/settings"):
        (home / d).mkdir(parents=True)
    toml = 'model = "x"\n\n[mcp_servers.other]\ncommand = "other"\n'
    (home / ".codex" / "config.toml").write_text(toml)
    (home / ".gemini" / "settings.json").write_text(json.dumps({"theme": "dark", "mcpServers": {"mine": {"command": "m"}}}))
    proj = tmp_path / "ws"; (proj / ".kiro").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home)); monkeypatch.setenv("INTERLOCK_HOME", str(home / ".interlock"))
    monkeypatch.setenv("PATH", "/usr/bin:/bin"); monkeypatch.chdir(proj)

    assert main(["init", "--yes", "--no-service", "--mcp", "--harness", "codex,cursor,gemini-cli,kiro"]) == 0
    t = (home / ".codex" / "config.toml").read_text()
    assert "[mcp_servers.interlock]" in t and "[mcp_servers.other]" in t and '"-m", "interlockd", "mcp"' in t
    import tomllib
    assert tomllib.loads(t)["mcp_servers"]["interlock"]["args"] == ["-m", "interlockd", "mcp"]
    assert json.loads((home / ".cursor" / "mcp.json").read_text())["mcpServers"]["interlock"]["args"][-1] == "mcp"
    g = json.loads((home / ".gemini" / "settings.json").read_text())
    assert set(g["mcpServers"]) == {"mine", "interlock"} and g["theme"] == "dark"
    assert "interlock" in json.loads((home / ".kiro" / "settings" / "mcp.json").read_text())["mcpServers"]
    assert main(["init", "--yes", "--no-service", "--mcp", "--harness", "codex"]) == 0       # idempotent
    assert (home / ".codex" / "config.toml").read_text().count("[mcp_servers.interlock]") == 1

    assert main(["uninstall", "--yes"]) == 0
    assert (home / ".codex" / "config.toml").read_text() == toml
    assert not (home / ".cursor" / "mcp.json").exists()                 # init created it
    assert json.loads((home / ".gemini" / "settings.json").read_text())["mcpServers"] == {"mine": {"command": "m"}}


def test_claude_registration_uses_its_cli(monkeypatch):
    from interlockd import onboard

    calls = []
    monkeypatch.setattr(onboard.shutil, "which", lambda n: "/x/claude" if n == "claude" else None)
    run = lambda cmd: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", "")
    entry = onboard.register_mcp("claude-code", run=run)
    assert entry == {"harness": "claude-code", "via": "claude-cli"}
    assert calls[-1][:6] == ["/x/claude", "mcp", "add", "--scope", "user", "interlock"] and calls[-1][-3:] == ["-m", "interlockd", "mcp"]
    assert onboard.unregister_mcp(entry, run=run) and calls[-1] == ["/x/claude", "mcp", "remove", "--scope", "user", "interlock"]
