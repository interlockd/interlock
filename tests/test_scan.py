"""`interlock scan`: discovery across agent config formats, each static check, secret redaction, exit codes."""

from __future__ import annotations

import json

import pytest

from interlockd.cli import main
from interlockd.scan import Server, check_server, discover, run_scan

GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"   # synthetic, matches the pack pattern


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    home = tmp_path / "home"; proj = tmp_path / "proj"
    (home / ".cursor").mkdir(parents=True); (home / ".codex").mkdir(); (home / ".kiro" / "settings").mkdir(parents=True)
    (home / ".claude").mkdir(); (proj / ".vscode").mkdir(parents=True)
    (home / ".claude.json").write_text(json.dumps({
        "mcpServers": {"gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                              "env": {"GITHUB_TOKEN": GH_TOKEN}}},
        "projects": {"/x": {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.0", str(home)]}}}}}))
    (home / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {
        "remote": {"url": "http://mcp.example.com/sse"},
        "safe": {"url": "https://mcp.example.com/mcp", "headers": {"Authorization": "Bearer ${MCP_TOKEN}"}}}}))
    (home / ".codex" / "config.toml").write_text(
        'sandbox_mode = "danger-full-access"\napproval_policy = "never"\n\n[mcp_servers.py]\ncommand = "uvx"\nargs = ["mcp-server-fetch==2025.1.1"]\n')
    (home / ".kiro" / "settings" / "mcp.json").write_text(json.dumps({"mcpServers": {
        "box": {"command": "docker", "args": ["run", "--rm", "-i", "--privileged", "ghcr.io/acme/mcp:latest"], "autoApprove": ["*"]},
        "off": {"command": "uvx", "args": ["thing"], "disabled": True}}}))
    (home / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]}}))
    (proj / ".vscode" / "mcp.json").write_text(json.dumps({"servers": {"sh": {"command": "bash", "args": ["-c", "node srv.js"]}}}))
    monkeypatch.setenv("HOME", str(home)); monkeypatch.setenv("INTERLOCK_HOME", str(home / ".interlock"))
    monkeypatch.setenv("PATH", "/usr/bin:/bin"); monkeypatch.chdir(proj)
    return home, proj


def test_discovers_every_format(sandbox):
    home, proj = sandbox
    servers, _ = discover(home, proj)
    got = {(s.agent, s.name) for s in servers}
    assert got == {("claude-code", "gh"), ("claude-code", "fs"), ("cursor", "remote"), ("cursor", "safe"),
                   ("codex", "py"), ("kiro", "box"), ("kiro", "off"), ("vscode", "sh")}


def test_findings_and_redaction(sandbox):
    home, proj = sandbox
    r = run_scan(home, home / ".interlock", proj)
    rules = {(f.rule, f.subject) for f in r.findings}
    assert ("mcp.unpinned_package", "gh") in rules                    # npx without a version
    assert ("mcp.inline_secret", "gh") in rules                       # literal token in env
    assert ("mcp.broad_filesystem", "fs") in rules                    # whole home directory
    assert ("mcp.unpinned_package", "fs") not in rules                # pinned @1.2.0
    assert ("mcp.plaintext_remote", "remote") in rules
    assert not any(f.subject == "safe" and f.severity != "info" for f in r.findings)   # ${VAR} reference is fine
    assert ("mcp.unpinned_package", "py") not in rules                # ==version
    assert {("mcp.privileged_container", "box"), ("mcp.unpinned_image", "box"), ("mcp.auto_approve", "box")} <= rules
    assert ("mcp.inline_shell", "sh") in rules
    assert any(f.rule == "agent.bypass_permissions" for f in r.findings) and any(f.rule == "agent.broad_allow" for f in r.findings)
    assert any(f.rule == "agent.codex_full_access" and f.severity == "high" for f in r.findings)
    assert next(f for f in r.findings if f.subject == "off").severity == "info"
    assert GH_TOKEN not in json.dumps(r.to_json())                    # secrets never leave the scan


def test_cli_exit_codes_and_json(sandbox, capsys):
    assert main(["scan"]) == 1                                         # high findings present
    assert "HIGH" in capsys.readouterr().out
    assert main(["scan", "--fail-on", "never"]) == 0
    capsys.readouterr()
    assert main(["scan", "--json", "--fail-on", "never"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["servers"] and data["findings"] and GH_TOKEN not in json.dumps(data)


@pytest.mark.parametrize("cmd,args,pinned", [
    ("npx", ["-y", "pkg"], False), ("npx", ["-y", "pkg@1.0.0"], True), ("npx", ["@scope/pkg"], False),
    ("npx", ["@scope/pkg@2.1.0"], True), ("npx", ["pkg@latest"], False), ("uvx", ["tool"], False),
    ("uvx", ["tool==1.2"], True), ("uvx", ["--from", "pkg==1.0", "tool"], True), ("pipx", ["run", "tool"], False),
])
def test_pinning(cmd, args, pinned, tmp_path):
    f = check_server(Server(name="s", agent="a", source="x", transport="stdio", command=cmd, args=args), tmp_path)
    assert any(x.rule == "mcp.unpinned_package" for x in f) is not pinned
