"""`interlock gateway wrap | unwrap | status`: exact round trips on every JSON config format, Claude via its CLI."""

from __future__ import annotations

import json
import subprocess

import pytest

from interlockd import gateway
from interlockd.gateway import is_wrapped, unwrap_entry, wrap_entry


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    home = tmp_path / "home"; proj = tmp_path / "proj"
    (home / ".cursor").mkdir(parents=True); (home / ".kiro" / "settings").mkdir(parents=True); (proj / ".vscode").mkdir(parents=True)
    files = {
        home / ".cursor" / "mcp.json": {"mcpServers": {
            "gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@1.2.0"], "env": {"X": "${X}"}},
            "remote": {"url": "https://mcp.example.com/mcp"}}},
        home / ".kiro" / "settings" / "mcp.json": {"mcpServers": {
            "fetch": {"command": "uvx", "args": ["mcp-server-fetch==1.0"], "disabled": True, "autoApprove": []},
            "interlock": {"command": "/py", "args": ["-m", "interlockd", "mcp"]}}},
        proj / ".vscode" / "mcp.json": {"servers": {"fs": {"command": "npx", "args": ["-y", "fs@1", "/proj"]}}, "inputs": []},
        proj / ".mcp.json": {"mcpServers": {"pg": {"command": "postgres-mcp"}}},
    }
    for f, d in files.items():
        f.write_text(json.dumps(d, indent=2) + "\n")
    monkeypatch.setenv("HOME", str(home)); monkeypatch.setenv("PATH", "/usr/bin:/bin")
    return home, proj, {f: f.read_text() for f in files}


def test_entry_round_trip():
    cfg = {"command": "npx", "args": ["-y", "pkg@1"], "env": {"A": "1"}}
    w = wrap_entry("gh", cfg, python="/py")
    assert w["command"] == "/py" and w["args"][:6] == ["-m", "interlockd", "mcp-proxy", "--name", "gh", "--"] and w["env"] == {"A": "1"}
    assert is_wrapped(w) and not is_wrapped(cfg) and unwrap_entry(w) == cfg


def test_wrap_unwrap_is_exact(sandbox):
    home, proj, original = sandbox
    ch = gateway.apply(True, home=home, project=proj, python="/py")
    got = {(c.agent, c.server): c.action for c in ch}
    assert got[("cursor", "gh")] == "wrapped" and got[("vscode", "fs")] == "wrapped" and got[("claude-code", "pg")] == "wrapped"
    assert got[("cursor", "remote")] == "skipped" and got[("kiro", "fetch")] == "skipped" and got[("kiro", "interlock")] == "skipped"
    cur = json.loads((home / ".cursor" / "mcp.json").read_text())["mcpServers"]
    assert cur["gh"]["args"][-3:] == ["npx", "-y", "@modelcontextprotocol/server-github@1.2.0"] and cur["gh"]["env"] == {"X": "${X}"}
    assert (home / ".cursor" / "mcp.json.interlock-backup").read_text() == original[home / ".cursor" / "mcp.json"]
    assert all(c.action != "wrapped" for c in gateway.apply(True, home=home, project=proj, python="/py"))   # idempotent
    st = {(c.agent, c.server): c.action for c in gateway.status(home, proj)}
    assert st[("cursor", "gh")] == "wrapped"

    gateway.apply(False, home=home, project=proj)
    for f, text in original.items():
        assert json.loads(f.read_text()) == json.loads(text), f


def test_dry_run_changes_nothing(sandbox):
    home, proj, original = sandbox
    assert any(c.action == "wrapped" for c in gateway.apply(True, home=home, project=proj, dry_run=True))
    assert all(f.read_text() == t for f, t in original.items())


def test_claude_user_scope_goes_through_its_cli(tmp_path, monkeypatch):
    home = tmp_path / "home"; home.mkdir()
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {"gh": {"type": "stdio", "command": "npx", "args": ["-y", "g@1"]}}}))
    monkeypatch.setattr(gateway.shutil, "which", lambda n: "/x/claude" if n == "claude" else None)
    calls = []
    run = lambda cmd: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", "")
    ch = gateway.apply(True, home=home, project=tmp_path, python="/py", run=run)
    assert [(c.agent, c.server, c.action) for c in ch] == [("claude-code", "gh", "wrapped")]
    add = next(c for c in calls if c[2] == "add-json")
    entry = json.loads(add[-1])
    assert add[:6] == ["/x/claude", "mcp", "add-json", "--scope", "user", "gh"] and entry["args"][2] == "mcp-proxy"
    assert (home / ".claude.json").read_text().count("mcp-proxy") == 0            # Interlock never edits the file itself


def test_init_gateway_and_uninstall(sandbox, monkeypatch):
    from interlockd.cli import main

    home, proj, original = sandbox
    monkeypatch.setenv("INTERLOCK_HOME", str(home / ".interlock")); monkeypatch.chdir(proj)
    assert main(["init", "--yes", "--no-service", "--gateway", "--harness", "cursor"]) == 0
    assert is_wrapped(json.loads((home / ".cursor" / "mcp.json").read_text())["mcpServers"]["gh"])
    assert main(["uninstall", "--yes"]) == 0
    for f, text in original.items():
        assert json.loads(f.read_text()) == json.loads(text), f
