"""`interlock scan`: a static audit of the MCP servers and agent settings on this machine. No daemon, no network.

Reads every MCP config the supported agents use (user level and the current project), normalizes each server, and
reports risky shapes: unpinned packages fetched at launch, plain-HTTP remotes, secrets written inline, filesystem roots
at / or ~, inline shell commands, auto-approved tools, privileged containers. It also flags agent settings that turn
off the agent's own guard rails, and agents that Interlock is not protecting. Nothing is executed and no server is
contacted; secret values are never printed. Tool-description checks need the live tool list (MCP gateway, M5).
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .det.packs import SECRET_PATTERNS

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class Server:
    name: str
    agent: str
    source: str
    transport: str                     # stdio | http
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    disabled: bool = False
    auto_approve: list[str] = field(default_factory=list)


@dataclass
class Finding:
    severity: str
    rule: str
    agent: str
    subject: str                       # server name or settings file
    message: str
    fix: str = ""
    source: str = ""


# ------------------------------------------------------------------------------------------------ discovery


def _load(path: Path) -> Any:
    try:
        if path.suffix == ".toml":
            return tomllib.loads(path.read_text())
        text = path.read_text()
        return json.loads(text) if text.strip() else {}
    except (OSError, ValueError, tomllib.TOMLDecodeError):
        return None


def _servers_from(mapping: Any, agent: str, source: Path) -> list[Server]:
    out = []
    if not isinstance(mapping, dict):
        return out
    for name, cfg in mapping.items():
        if not isinstance(cfg, dict):
            continue
        url = cfg.get("url") or cfg.get("serverUrl") or cfg.get("httpUrl") or ""
        args = [str(a) for a in (cfg.get("args") or [])]
        out.append(Server(
            name=str(name), agent=agent, source=str(source), transport="http" if url and not cfg.get("command") else "stdio",
            command=str(cfg.get("command") or ""), args=args,
            env={str(k): str(v) for k, v in (cfg.get("env") or {}).items()},
            url=str(url), headers={str(k): str(v) for k, v in (cfg.get("headers") or cfg.get("http_headers") or {}).items()},
            disabled=bool(cfg.get("disabled") or cfg.get("enabled") is False),
            auto_approve=[str(t) for t in (cfg.get("autoApprove") or cfg.get("alwaysAllow") or [])],
        ))
    return out


def config_sources(home: Path, project: Path) -> list[tuple[str, Path, str]]:
    """(agent, path, key) for every MCP config location; `key` is where the server map lives."""
    return [
        ("claude-code", home / ".claude.json", "mcpServers"),
        ("claude-code", home / ".claude.json", "projects"),                # per-project maps inside the same file
        ("claude-code", project / ".mcp.json", "mcpServers"),
        ("claude-desktop", home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json", "mcpServers"),
        ("claude-desktop", home / ".config" / "Claude" / "claude_desktop_config.json", "mcpServers"),
        ("codex", home / ".codex" / "config.toml", "mcp_servers"),
        ("cursor", home / ".cursor" / "mcp.json", "mcpServers"),
        ("cursor", project / ".cursor" / "mcp.json", "mcpServers"),
        ("vscode", project / ".vscode" / "mcp.json", "servers"),
        ("kiro", home / ".kiro" / "settings" / "mcp.json", "mcpServers"),
        ("kiro", project / ".kiro" / "settings" / "mcp.json", "mcpServers"),
        ("gemini-cli", home / ".gemini" / "settings.json", "mcpServers"),
        ("gemini-cli", project / ".gemini" / "settings.json", "mcpServers"),
        ("windsurf", home / ".codeium" / "windsurf" / "mcp_config.json", "mcpServers"),
    ]


def discover(home: Path, project: Path) -> tuple[list[Server], list[str]]:
    servers, sources = [], []
    seen: set[tuple[str, str]] = set()
    for agent, path, key in config_sources(home, project):
        if not path.is_file():
            continue
        data = _load(path)
        if not isinstance(data, dict):
            continue
        if key == "projects":
            for proj, pcfg in (data.get("projects") or {}).items():
                if isinstance(pcfg, dict) and pcfg.get("mcpServers"):
                    servers += _servers_from(pcfg["mcpServers"], agent, Path(f"{path} [project {proj}]"))
            continue
        found = _servers_from(data.get(key), agent, path)
        if found and (agent, str(path)) not in seen:
            seen.add((agent, str(path)))
            sources.append(str(path))
        servers += found
    return servers, sorted(set(sources) | {s.source for s in servers})


# ------------------------------------------------------------------------------------------------ server checks

LAUNCHERS = {"npx": "npm", "bunx": "npm", "pnpx": "npm", "uvx": "pypi", "pipx": "pypi"}
SECRET_KEY = re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|credential|auth|private[_-]?key)")
REFERENCE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$|^\$\{(env|input):[^}]+\}$|^<[^>]+>$|^your[-_ ]|^\*+$|^x{4,}$", re.IGNORECASE)


def _package_arg(cmd: str, args: list[str]) -> str | None:
    """The package a launcher fetches: `npx -y pkg`, `uvx pkg`, `uvx --from pkg tool`, `pipx run pkg`, `pnpm dlx pkg`."""
    a = list(args)
    if cmd == "pipx":
        if not a or a[0] != "run":
            return None
        a = a[1:]
    i = 0
    while i < len(a):
        x = a[i]
        if x in ("--from", "-p", "--package"):
            return a[i + 1] if i + 1 < len(a) else None
        if x.startswith("-"):
            i += 1
            continue
        return x
    return None


def _npm_pinned(spec: str) -> bool:
    body = spec.removeprefix("@")
    if "@" not in body:
        return False
    ver = body.rsplit("@", 1)[1]
    return bool(ver) and ver not in ("latest", "next", "*") and not ver.startswith(("^", "~", ">"))


def _pypi_pinned(spec: str) -> bool:
    return bool(re.search(r"(==|@)\s*[0-9]", spec))


def _is_secret_value(key: str, value: str) -> str | None:
    if not value or REFERENCE.search(value.strip()):
        return None
    # "Bearer ${TOKEN}" is a reference with a prefix, not a secret: judge only what is left after the references
    rest = re.sub(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*", "", value)
    if rest != value and len(rest.strip()) < 12:
        return None
    for name, pat in SECRET_PATTERNS:
        if pat.search(value) or pat.search(f"{key}={value}"):
            return name
    if SECRET_KEY.search(key) and len(value) >= 8 and not value.startswith(("$", "op://", "keychain:")):
        return "secret-named value"
    return None


def check_server(s: Server, home: Path) -> list[Finding]:
    f: list[Finding] = []

    def add(sev, rule, msg, fix=""):
        f.append(Finding(sev, rule, s.agent, s.name, msg, fix, s.source))

    if s.disabled:
        add("info", "mcp.disabled", "disabled; not checked further")
        return f
    cmd = Path(s.command).name if s.command else ""
    # 1. packages fetched at launch without a pinned version: whatever is published next runs with your permissions
    sub_launcher = cmd in ("pnpm", "yarn", "bun") and s.args[:1] in (["dlx"], ["x"])
    if cmd in LAUNCHERS or sub_launcher:
        eco = LAUNCHERS.get(cmd, "npm")
        spec = _package_arg(cmd, s.args[1:] if sub_launcher else s.args)
        if spec and not (_npm_pinned(spec) if eco == "npm" else _pypi_pinned(spec)):
            add("medium", "mcp.unpinned_package", f"`{cmd} {spec}` fetches whatever version is latest at every launch",
                f"pin it, e.g. {spec}@<version>" if eco == "npm" else f"pin it, e.g. {spec}==<version>")
    # 2. containers
    if cmd in ("docker", "podman") and "run" in s.args:
        joined = " ".join(s.args)
        image = next((a for a in s.args[s.args.index("run") + 1:] if not a.startswith("-") and "=" not in a
                      and not re.match(r"^[\w.-]+:/", a)), "")
        if "--privileged" in s.args or re.search(r"(-v|--volume)[ =]/:/", joined) or "--network=host" in joined or \
                ("--network" in s.args and "host" in s.args):
            add("high", "mcp.privileged_container", "container runs privileged, with the host network, or mounts / ",
                "drop --privileged / host networking; mount only the directories it needs")
        if image and "@sha256:" not in image:
            add("low" if ":" in image and not image.endswith(":latest") else "medium", "mcp.unpinned_image",
                f"image `{image}` is not pinned by digest", f"use {image.split(':')[0]}@sha256:<digest>")
    # 3. inline shell
    if cmd in ("sh", "bash", "zsh") and "-c" in s.args:
        add("medium", "mcp.inline_shell", "server is an inline shell command", "point at a script or package you can review and pin")
    # 4. remote transport
    if s.url:
        m = re.match(r"^(https?)://([^/:]+)", s.url)
        if m and m.group(1) == "http" and m.group(2) not in ("localhost", "127.0.0.1", "::1"):
            add("high", "mcp.plaintext_remote", f"remote server over plain HTTP ({m.group(2)})", "use https")
        elif m:
            add("info", "mcp.remote", f"remote server at {m.group(2)}: its tools and results come from a third party")
    # 5. secrets written into the config
    for where, items in (("env", s.env), ("headers", s.headers)):
        for k, v in items.items():
            kind = _is_secret_value(k, v)
            if kind:
                add("high", "mcp.inline_secret", f"{where}.{k} holds a literal secret ({kind}); value not shown",
                    f"reference it from the environment instead, e.g. \"{k}\": \"${{{k}}}\"")
    for i, a in enumerate(s.args):
        kind = next((n for n, p in SECRET_PATTERNS if p.search(a)), None)
        if kind:
            add("high", "mcp.inline_secret", f"argument {i} holds a literal secret ({kind}); value not shown",
                "pass it through an environment variable")
    # 6. filesystem scope
    roots = {"/", "~", "$HOME", "${HOME}", str(home), str(home) + "/", "C:\\", "C:/"}
    broad = [a for a in s.args if a in roots]
    if broad:
        add("high" if any("filesystem" in x for x in [s.command, *s.args]) else "medium", "mcp.broad_filesystem",
            f"gets access to {broad[0]} (your whole {'disk' if broad[0] in ('/', 'C:\\\\', 'C:/') else 'home directory'})",
            "pass only the project directories it needs")
    # 7. tools approved without asking
    if s.auto_approve:
        sev = "high" if "*" in s.auto_approve else "medium"
        add(sev, "mcp.auto_approve", f"tools run without asking: {', '.join(s.auto_approve[:6])}"
            + (" …" if len(s.auto_approve) > 6 else ""), "remove autoApprove/alwaysAllow for tools that write or send data")
    return f


# ------------------------------------------------------------------------------------------------ agent settings


def check_agent_settings(home: Path, project: Path) -> list[Finding]:
    f: list[Finding] = []
    for path in (home / ".claude" / "settings.json", project / ".claude" / "settings.json",
                 project / ".claude" / "settings.local.json"):
        d = _load(path) if path.is_file() else None
        if not isinstance(d, dict):
            continue
        perms = d.get("permissions") or {}
        if perms.get("defaultMode") == "bypassPermissions":
            f.append(Finding("high", "agent.bypass_permissions", "claude-code", str(path),
                             "defaultMode is bypassPermissions: every tool runs without asking",
                             "use the default mode, or keep Interlock in enforce mode", str(path)))
        broad = [a for a in perms.get("allow") or [] if a in ("Bash", "Bash(*)", "Bash(*:*)", "*")]
        if broad:
            f.append(Finding("high", "agent.broad_allow", "claude-code", str(path),
                             f"permissions.allow contains {broad[0]}: any shell command runs without asking",
                             "allow specific commands, e.g. Bash(npm test:*)", str(path)))
        if d.get("enableAllProjectMcpServers") is True:
            f.append(Finding("medium", "agent.all_project_mcp", "claude-code", str(path),
                             "enableAllProjectMcpServers: any repo you open can start its own MCP servers",
                             "approve project servers individually", str(path)))
    cx = home / ".codex" / "config.toml"
    d = _load(cx) if cx.is_file() else None
    if isinstance(d, dict) and d.get("sandbox_mode") == "danger-full-access":
            f.append(Finding("high" if d.get("approval_policy") == "never" else "medium", "agent.codex_full_access", "codex",
                             str(cx), "sandbox_mode is danger-full-access" + (" with approval_policy never" if
                             d.get("approval_policy") == "never" else ""), "use workspace-write", str(cx)))
    for gp in (home / ".gemini" / "settings.json", project / ".gemini" / "settings.json"):
        d = _load(gp) if gp.is_file() else None
        if isinstance(d, dict) and (d.get("autoAccept") is True or d.get("yolo") is True):
            f.append(Finding("medium", "agent.auto_accept", "gemini-cli", str(gp), "tool calls are auto-accepted",
                             "turn off autoAccept/yolo", str(gp)))
    return f


def check_protection(home: Path, interlock_home: Path, project: Path) -> list[Finding]:
    from .insights import _has_interlock_hook
    from .onboard import detect

    out = []
    for d in detect(project):
        if d.present and d.target and not _has_interlock_hook(d.target, interlock_home):
            out.append(Finding("medium", "agent.unprotected", d.name, str(d.target),
                               f"{d.name} is installed but its tool calls are not checked by Interlock",
                               f"interlock init --yes --harness {d.name}", str(d.target)))
    return out


# ------------------------------------------------------------------------------------------------ run + format


@dataclass
class ScanResult:
    servers: list[Server]
    sources: list[str]
    findings: list[Finding]

    def to_json(self) -> dict:
        return {"servers": [asdict(s) | {"env": sorted(s.env), "headers": sorted(s.headers)} for s in self.servers],
                "sources": self.sources, "findings": [asdict(f) for f in self.findings]}


def run_scan(home: Path, interlock_home: Path, project: Path) -> ScanResult:
    servers, sources = discover(home, project)
    findings = [x for s in servers for x in check_server(s, home)]
    findings += check_agent_settings(home, project)
    findings += check_protection(home, interlock_home, project)
    findings.sort(key=lambda x: (SEVERITY_ORDER[x.severity], x.agent, x.subject))
    return ScanResult(servers, sources, findings)


def format_scan(r: ScanResult, *, show_info: bool = False) -> str:
    marks = {"high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "info"}
    head = (f"Interlock scan: {len(r.servers)} MCP server{'s' if len(r.servers) != 1 else ''} in "
            f"{len(r.sources)} config file{'s' if len(r.sources) != 1 else ''}")
    lines = [head, ""]
    if r.servers:
        lines.append("MCP servers")
        for s in r.servers:
            what = s.url or " ".join([Path(s.command).name, *s.args])[:70]
            lines.append(f"  {s.agent:<14} {s.name:<22} {s.transport:<5} {'(disabled) ' if s.disabled else ''}{what}")
        lines.append("")
    shown = [f for f in r.findings if show_info or f.severity != "info"]
    if not shown:
        lines.append("No findings.")
    else:
        lines.append("Findings")
        for f in shown:
            lines.append(f"  {marks[f.severity]}  {f.agent:<14} {Path(f.subject).name if '/' in f.subject else f.subject:<22} {f.message}")
            if f.fix:
                lines.append(f"  {'':<4}  {'':<14} {'':<22} → {f.fix}")
    counts = {k: sum(1 for f in r.findings if f.severity == k) for k in ("high", "medium", "low")}
    tail = (f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low. "
            "Static checks only; tool descriptions are checked live by the MCP gateway (coming).")
    lines += ["", tail]
    return "\n".join(lines)
