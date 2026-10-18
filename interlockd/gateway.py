"""`interlock gateway wrap | unwrap | status`: route every stdio MCP server through `interlock mcp-proxy`.

Wrapping rewrites a server entry's launch command, keeping the original after `--` so unwrapping is exact:

    {"command": "npx", "args": ["-y", "pkg@1"]}
      -> {"command": "<python>", "args": ["-m", "interlockd", "mcp-proxy", "--name", "<server>", "--", "npx", "-y", "pkg@1"]}

Edited in place: the JSON configs of Cursor, Kiro, Gemini CLI, Claude Desktop, Windsurf, VS Code, and a project's
`.mcp.json`. Claude Code's user-scope servers go through its own CLI (`claude mcp remove` + `add-json`) because Claude
rewrites ~/.claude.json itself. Not wrapped (reported instead): Codex's TOML config, remote HTTP servers (they need the
HTTP gateway), disabled servers, and Interlock's own MCP server.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

PROXY_MARK = "mcp-proxy"


@dataclass
class Change:
    agent: str
    server: str
    source: str
    action: str           # wrapped | unwrapped | skipped
    detail: str = ""


def json_targets(home: Path, project: Path) -> list[tuple[str, Path, str]]:
    return [
        ("claude-code", project / ".mcp.json", "mcpServers"),
        ("claude-desktop", home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json", "mcpServers"),
        ("claude-desktop", home / ".config" / "Claude" / "claude_desktop_config.json", "mcpServers"),
        ("cursor", home / ".cursor" / "mcp.json", "mcpServers"),
        ("cursor", project / ".cursor" / "mcp.json", "mcpServers"),
        ("vscode", project / ".vscode" / "mcp.json", "servers"),
        ("kiro", home / ".kiro" / "settings" / "mcp.json", "mcpServers"),
        ("kiro", project / ".kiro" / "settings" / "mcp.json", "mcpServers"),
        ("gemini-cli", home / ".gemini" / "settings.json", "mcpServers"),
        ("gemini-cli", project / ".gemini" / "settings.json", "mcpServers"),
        ("windsurf", home / ".codeium" / "windsurf" / "mcp_config.json", "mcpServers"),
    ]


def is_wrapped(cfg: dict) -> bool:
    args = cfg.get("args") or []
    return PROXY_MARK in args and "--" in args


def wrap_entry(name: str, cfg: dict, python: str | None = None) -> dict:
    bare = ["--bare"] if "args" not in cfg else []          # remember the original had no args key: exact unwrap
    return {**cfg, "command": python or sys.executable,
            "args": ["-m", "interlockd", PROXY_MARK, "--name", name, *bare, "--", str(cfg["command"]),
                     *[str(a) for a in cfg.get("args") or []]]}


def unwrap_entry(cfg: dict) -> dict:
    args = list(cfg.get("args") or [])
    rest = args[args.index("--") + 1:]
    if not rest:
        return cfg
    out = {**cfg, "command": rest[0], "args": rest[1:]}
    if "--bare" in args[:args.index("--")]:
        out.pop("args")
    return out


def _skip_reason(name: str, cfg: dict) -> str | None:
    if not isinstance(cfg, dict):
        return "not a server entry"
    if name == "interlock" or (cfg.get("args") or [])[-1:] == ["mcp"] and "interlockd" in (cfg.get("args") or []):
        return "Interlock's own MCP server"
    if cfg.get("disabled") or cfg.get("enabled") is False:
        return "disabled"
    if not cfg.get("command"):
        return "remote (HTTP) server: needs the HTTP gateway (coming)"
    return None


def _edit_json(agent: str, path: Path, key: str, wrap: bool, dry_run: bool, python: str | None) -> list[Change]:
    try:
        data = json.loads(path.read_text()) if path.read_text().strip() else {}
    except (OSError, ValueError):
        return []
    servers = data.get(key)
    if not isinstance(servers, dict):
        return []
    out, changed = [], False
    for name, cfg in servers.items():
        if wrap:
            why = _skip_reason(name, cfg) or ("already wrapped" if is_wrapped(cfg) else None)
            if why:
                out.append(Change(agent, name, str(path), "skipped", why))
                continue
            servers[name] = wrap_entry(name, cfg, python)
            out.append(Change(agent, name, str(path), "wrapped"))
        elif isinstance(cfg, dict) and is_wrapped(cfg):
            servers[name] = unwrap_entry(cfg)
            out.append(Change(agent, name, str(path), "unwrapped"))
        else:
            continue
        changed = True
    if changed and not dry_run:
        backup = path.with_name(path.name + ".interlock-backup")
        if not backup.exists():
            shutil.copy2(path, backup)
        path.write_text(json.dumps(data, indent=2) + "\n")
    return out


def _claude_user(wrap: bool, dry_run: bool, python: str | None, home: Path, run) -> list[Change]:
    """Claude Code user scope lives in ~/.claude.json, which Claude rewrites; change it only through `claude mcp`."""
    f = home / ".claude.json"
    try:
        servers = (json.loads(f.read_text()).get("mcpServers") or {}) if f.exists() else {}
    except ValueError:
        return []
    claude = shutil.which("claude")
    out = []
    for name, cfg in servers.items():
        if wrap:
            why = _skip_reason(name, cfg) or ("already wrapped" if is_wrapped(cfg) else None)
            new = None if why else wrap_entry(name, cfg, python)
        else:
            why, new = (None, unwrap_entry(cfg)) if isinstance(cfg, dict) and is_wrapped(cfg) else ("not wrapped", None)
            if why:
                continue
        if why:
            out.append(Change("claude-code", name, str(f), "skipped", why))
            continue
        if not claude:
            out.append(Change("claude-code", name, str(f), "skipped", "claude CLI not on PATH"))
            continue
        if not dry_run:
            run([claude, "mcp", "remove", "--scope", "user", name])
            entry = {k: v for k, v in new.items() if k in ("command", "args", "env", "type")}
            entry.setdefault("type", "stdio")
            r = run([claude, "mcp", "add-json", "--scope", "user", name, json.dumps(entry)])
            if r.returncode != 0:
                run([claude, "mcp", "add-json", "--scope", "user", name, json.dumps(cfg)])     # put the original back
                out.append(Change("claude-code", name, str(f), "skipped", f"claude mcp add-json failed: {r.stderr.strip()[:120]}"))
                continue
        out.append(Change("claude-code", name, str(f), "wrapped" if wrap else "unwrapped"))
    return out


def _codex_note(home: Path) -> list[Change]:
    f = home / ".codex" / "config.toml"
    if not f.exists():
        return []
    import tomllib

    try:
        servers = tomllib.loads(f.read_text()).get("mcp_servers") or {}
    except tomllib.TOMLDecodeError:
        return []
    return [Change("codex", n, str(f), "skipped",
                   "Codex TOML is not rewritten automatically; set command to the proxy by hand (see docs)")
            for n, c in servers.items() if n != "interlock" and not is_wrapped(c)]


def apply(wrap: bool, *, home: Path | None = None, project: Path | None = None, dry_run: bool = False,
          python: str | None = None, run=None) -> list[Change]:
    home = home or Path.home()
    project = (project or Path.cwd()).resolve()
    run = run or (lambda cmd: subprocess.run(cmd, capture_output=True, text=True, check=False))
    out: list[Change] = []
    seen: set[Path] = set()
    for agent, path, key in json_targets(home, project):
        rp = path.resolve() if path.exists() else path
        if path.is_file() and rp not in seen:
            seen.add(rp)
            out += _edit_json(agent, path, key, wrap, dry_run, python)
    out += _claude_user(wrap, dry_run, python, home, run)
    if wrap:
        out += _codex_note(home)
    return out


def status(home: Path | None = None, project: Path | None = None) -> list[Change]:
    """Which stdio servers go through the gateway, without changing anything."""
    from .scan import discover

    servers, _ = discover(home or Path.home(), (project or Path.cwd()).resolve())
    out = []
    for s in servers:
        cfg = {"command": s.command, "args": s.args, "disabled": s.disabled}
        why = _skip_reason(s.name, cfg)
        out.append(Change(s.agent, s.name, s.source, "wrapped" if is_wrapped(cfg) else ("skipped" if why else "unwrapped"),
                          why or ""))
    return out
