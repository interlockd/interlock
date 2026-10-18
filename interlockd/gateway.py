"""`interlock gateway wrap | unwrap | status`: route every stdio MCP server through `interlock mcp-proxy`.

Wrapping rewrites a server entry's launch command, keeping the original after `--` so unwrapping is exact:

    {"command": "npx", "args": ["-y", "pkg@1"]}
      -> {"command": "<python>", "args": ["-m", "interlockd", "mcp-proxy", "--name", "<server>", "--", "npx", "-y", "pkg@1"]}

Edited in place: the JSON configs of Cursor, Kiro, Gemini CLI, Claude Desktop, Windsurf, VS Code, and a project's
`.mcp.json`; Codex's config.toml by rewriting only the command/args of each [mcp_servers.<name>] table, verified by
re-parsing before anything is written. Claude Code's user-scope servers go through its own CLI (`claude mcp remove` +
`add-json`) because Claude rewrites ~/.claude.json itself. Not wrapped (reported instead): remote HTTP servers (they
need the HTTP gateway), disabled servers, inline-table TOML entries, and Interlock's own MCP server.
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


def _local_route(cfg: dict) -> bool:
    return isinstance(cfg.get("url"), str) and "/mcp/" in cfg["url"] and cfg["url"].startswith(("http://127.0.0.1", "http://localhost"))


def wrap_http(name: str, cfg: dict, routes, listen: str, dry_run: bool) -> dict:
    if not dry_run:
        routes.add(name, cfg["url"])
    return {**cfg, "url": routes.local_url(listen, name) if not dry_run else f"http://{listen}/mcp/{name}/<secret>"}


def unwrap_http(name: str, cfg: dict, routes, dry_run: bool) -> dict | None:
    upstream = (routes.load().get("routes") or {}).get(name, {}).get("url")
    if not upstream:
        return None
    if not dry_run:
        routes.remove(name)
    return {**cfg, "url": upstream}


def _skip_reason(name: str, cfg: dict) -> str | None:
    if not isinstance(cfg, dict):
        return "not a server entry"
    if name == "interlock" or (cfg.get("args") or [])[-1:] == ["mcp"] and "interlockd" in (cfg.get("args") or []):
        return "Interlock's own MCP server"
    if cfg.get("disabled") or cfg.get("enabled") is False:
        return "disabled"
    if not cfg.get("command") and not cfg.get("url"):
        return "no command or url"
    if cfg.get("url") and not str(cfg["url"]).startswith(("http://", "https://")):
        return "unsupported url scheme"
    return None


def _ctx():
    from .config import Settings
    from .mcp_http import Routes

    s = Settings.load()
    return Routes(s.home), s.listen


def _wrap_one(name: str, cfg: dict, python: str | None, dry_run: bool) -> tuple[dict | None, str | None]:
    why = _skip_reason(name, cfg) or ("already wrapped" if is_wrapped(cfg) or _local_route(cfg) else None)
    if why:
        return None, why
    if cfg.get("url") and not cfg.get("command"):
        routes, listen = _ctx()
        return wrap_http(name, cfg, routes, listen, dry_run), None
    return wrap_entry(name, cfg, python), None


def _unwrap_one(name: str, cfg: dict, dry_run: bool) -> dict | None:
    if not isinstance(cfg, dict):
        return None
    if is_wrapped(cfg):
        return unwrap_entry(cfg)
    if _local_route(cfg):
        routes, _ = _ctx()
        return unwrap_http(name, cfg, routes, dry_run)
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
            new, why = _wrap_one(name, cfg, python, dry_run)
            if why:
                out.append(Change(agent, name, str(path), "skipped", why))
                continue
            servers[name] = new
            out.append(Change(agent, name, str(path), "wrapped", "via HTTP gateway" if cfg.get("url") and not cfg.get("command") else ""))
        else:
            new = _unwrap_one(name, cfg, dry_run)
            if new is None:
                continue
            servers[name] = new
            out.append(Change(agent, name, str(path), "unwrapped"))
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
            new, why = _wrap_one(name, cfg, python, dry_run)
        else:
            new = _unwrap_one(name, cfg, dry_run)
            why = None
            if new is None:
                continue
        if why:
            out.append(Change("claude-code", name, str(f), "skipped", why))
            continue
        if not claude:
            out.append(Change("claude-code", name, str(f), "skipped", "claude CLI not on PATH"))
            continue
        if not dry_run:
            run([claude, "mcp", "remove", "--scope", "user", name])
            entry = {k: v for k, v in new.items() if k in ("command", "args", "env", "type", "url", "headers")}
            entry.setdefault("type", "http" if entry.get("url") else "stdio")
            r = run([claude, "mcp", "add-json", "--scope", "user", name, json.dumps(entry)])
            if r.returncode != 0:
                run([claude, "mcp", "add-json", "--scope", "user", name, json.dumps(cfg)])     # put the original back
                out.append(Change("claude-code", name, str(f), "skipped", f"claude mcp add-json failed: {r.stderr.strip()[:120]}"))
                continue
        out.append(Change("claude-code", name, str(f), "wrapped" if wrap else "unwrapped"))
    return out


def _toml_value_end(lines: list[str], i: int) -> int:
    """Index after the last line of the `key = value` starting at line i (multi-line arrays balanced outside strings)."""
    depth, j = 0, i
    while j < len(lines):
        in_str, q = False, ""
        for ch in lines[j]:
            if in_str:
                if ch == q:
                    in_str = False
            elif ch in "\"'":
                in_str, q = True, ch
            elif ch == "#":
                break
            elif ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
        j += 1
        if depth <= 0:
            return j
    return j


def rewrite_codex_toml(text: str, update) -> tuple[str, list[str]]:
    """Rewrite command/args of each [mcp_servers.<name>] table via update(name, cfg) -> new cfg | None.
    Returns (new text, names changed). The caller verifies the result by re-parsing."""
    import re

    lines = text.splitlines(keepends=True)
    out, changed, i = [], [], 0
    header = re.compile(r"^\s*\[mcp_servers\.(\"[^\"]+\"|[A-Za-z0-9_-]+)\]\s*(#.*)?$")
    import tomllib

    data = tomllib.loads(text).get("mcp_servers") or {}
    while i < len(lines):
        m = header.match(lines[i].rstrip("\n"))
        if not m:
            out.append(lines[i]); i += 1
            continue
        name = m.group(1).strip('"')
        out.append(lines[i]); i += 1
        start = i
        while i < len(lines) and not re.match(r"^\s*\[", lines[i]):
            i += 1
        block = lines[start:i]
        new = update(name, data.get(name) or {})
        if new is None:
            out += block
            continue
        kept, k = [], 0
        while k < len(block):
            if re.match(r"^\s*(command|args)\s*=", block[k]):
                k = _toml_value_end(block, k)
                continue
            kept.append(block[k]); k += 1
        assign = f"command = {json.dumps(new['command'])}\n"
        if "args" in new:
            assign += "args = [" + ", ".join(json.dumps(a) for a in new["args"]) + "]\n"
        out += [assign, *kept]
        changed.append(name)
    return "".join(out), changed


def _codex(wrap: bool, dry_run: bool, python: str | None, home: Path) -> list[Change]:
    import tomllib

    f = home / ".codex" / "config.toml"
    if not f.exists():
        return []
    text = f.read_text()
    try:
        before = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        return [Change("codex", "*", str(f), "skipped", f"config.toml does not parse: {e}")]
    servers = before.get("mcp_servers") or {}
    out: list[Change] = []
    expected: dict[str, dict] = {}

    def update(name, cfg):
        if wrap:
            why = _skip_reason(name, cfg) or ("already wrapped" if is_wrapped(cfg) else None)
            if not why and cfg.get("url") and not cfg.get("command"):
                why = "remote server in config.toml: point its url at the HTTP gateway by hand (see docs)"
            if why:
                out.append(Change("codex", name, str(f), "skipped", why))
                return None
            new = wrap_entry(name, cfg, python)
        else:
            if not is_wrapped(cfg):
                return None
            new = unwrap_entry(cfg)
        expected[name] = new
        return new

    new_text, changed = rewrite_codex_toml(text, update)
    for name in servers:
        if name not in changed and name not in {c.server for c in out} and wrap and servers[name] is not None \
                and not is_wrapped(servers[name]):
            out.append(Change("codex", name, str(f), "skipped", "not a [mcp_servers.<name>] table (inline form); wrap by hand"))
    if not changed:
        return out
    # safety net: only command/args of the changed servers may differ
    after = tomllib.loads(new_text)
    want = {**before, "mcp_servers": {**servers, **{n: {**{k: v for k, v in servers[n].items() if k not in ("command", "args")},
                                                       **{k: v for k, v in expected[n].items() if k in ("command", "args")}}
                                                    for n in changed}}}
    if after != want:
        return out + [Change("codex", n, str(f), "skipped", "rewrite did not verify; left untouched") for n in changed]
    if not dry_run:
        backup = f.with_name(f.name + ".interlock-backup")
        if not backup.exists():
            shutil.copy2(f, backup)
        f.write_text(new_text)
    return out + [Change("codex", n, str(f), "wrapped" if wrap else "unwrapped") for n in changed]


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
    out += _codex(wrap, dry_run, python, home)
    return out


def status(home: Path | None = None, project: Path | None = None) -> list[Change]:
    """Which stdio servers go through the gateway, without changing anything."""
    from .scan import discover

    servers, _ = discover(home or Path.home(), (project or Path.cwd()).resolve())
    out = []
    for s in servers:
        cfg = {"command": s.command, "args": s.args, "disabled": s.disabled, **({"url": s.url} if s.url else {})}
        why = _skip_reason(s.name, cfg)
        wrapped = is_wrapped(cfg) or _local_route(cfg)
        out.append(Change(s.agent, s.name, s.source, "wrapped" if wrapped else ("skipped" if why else "unwrapped"),
                          why or ("via HTTP gateway" if wrapped and s.url else "")))
    return out
