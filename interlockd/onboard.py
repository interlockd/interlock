"""One-command onboarding: `interlock init`, `interlock uninstall`, and the shadow/enforce switch.

`init` detects the harnesses on this machine, installs Interlock's hooks at the user level (Claude Code, Codex) or in
the Kiro workspace it is run from, writes a commented starter policy, installs and starts the background service,
and checks the daemon answers. Every file it touches is recorded in `<home>/install-manifest.json`, which is exactly
what `uninstall` reverses. Nothing here needs AWS, a model, or network access.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .config import Settings

MANIFEST = "install-manifest.json"
HARNESSES = ("claude-code", "codex", "cursor", "gemini-cli", "kiro")

STARTER_POLICY = """\
# Interlock user policy, written by `interlock init`. Layered: built-in defaults <- this file <- <workspace>/.interlock/policy.yaml
# Full reference: https://github.com/interlockd/interlock/blob/main/docs/USER-GUIDE.md#3-policy
version: 1

# shadow: decide and record every tool call, never block (start here; see `interlock report`)
# enforce: block the closed categories (exfiltration, malicious commands, persistence, secret leaks, privilege
#          escalation) and ask on the rest. Switch with `interlock enforce` / `interlock shadow`.
mode: shadow

trust:
  # Pushes to remotes outside this list ask first. Example: ["github.com/my-org/*"]
  allowed_git_remotes: []
  # protected_branches, protected_paths, sensitive_paths, and allowed_hosts have sensible defaults.

packs:
  enabled: [shell, git, egress, persistence, secrets, packages]
  overrides: {}
  #  git.force_push_own_branch: { action: allow }     # per rule: block | ask | flag | allow | model, or enabled: false

judge:
  probe:
    local: { enabled: true }   # post-action injection detector, runs locally, no network
"""


@dataclass
class Detected:
    name: str
    present: bool
    why: str = ""
    target: Path | None = None       # file the hooks go in
    note: str = ""


@dataclass
class Manifest:
    version: str = ""
    created_at: str = ""
    hooks: list[dict] = field(default_factory=list)      # {harness, file, marker, created}
    files: list[str] = field(default_factory=list)       # files init created outright (policy, shims)
    mcp: list[dict] = field(default_factory=list)        # MCP server registrations (init --mcp)
    gateway: bool = False                                # init --gateway wrapped MCP servers through mcp-proxy
    service: dict = field(default_factory=dict)          # {backend, label, unit_path}

    @classmethod
    def load(cls, home: Path) -> Manifest | None:
        p = home / MANIFEST
        if not p.exists():
            return None
        d = json.loads(p.read_text())
        return cls(**{k: d.get(k, v) for k, v in cls().__dict__.items()})

    def save(self, home: Path) -> None:
        (home / MANIFEST).write_text(json.dumps(self.__dict__, indent=2, default=str) + "\n")


# ------------------------------------------------------------------------------------------------ detection


def find_kiro_root(start: Path) -> Path | None:
    for p in [start, *start.parents]:
        if (p / ".kiro").is_dir() and p != Path.home():
            return p
    return None


def detect(cwd: Path | None = None) -> list[Detected]:
    home = Path.home()
    cwd = (cwd or Path.cwd()).resolve()
    out = []
    claude = shutil.which("claude")
    out.append(Detected("claude-code", bool(claude or (home / ".claude").is_dir()),
                        why=claude or str(home / ".claude"), target=home / ".claude" / "settings.json"))
    codex = shutil.which("codex")
    out.append(Detected("codex", bool(codex or (home / ".codex").is_dir()), why=codex or str(home / ".codex"),
                        target=home / ".codex" / "hooks.json",
                        note="open Codex and run /hooks once to review and trust the Interlock hook"))
    cursor = shutil.which("cursor") or shutil.which("cursor-agent")
    out.append(Detected("cursor", bool(cursor or (home / ".cursor").is_dir()), why=cursor or str(home / ".cursor"),
                        target=home / ".cursor" / "hooks.json",
                        note="Cursor 1.7+ runs hooks; this adapter is built from Cursor's docs, not yet verified live"))
    gemini = shutil.which("gemini")
    out.append(Detected("gemini-cli", bool(gemini or (home / ".gemini").is_dir()), why=gemini or str(home / ".gemini"),
                        target=home / ".gemini" / "settings.json",
                        note="built from Gemini CLI's docs, not yet verified live; hooksConfig.enabled must not be false"))
    kiro = shutil.which("kiro") or shutil.which("kiro-cli")
    root = find_kiro_root(cwd)
    out.append(Detected("kiro", bool(root), why=str(root) if root else (kiro or ""),
                        target=(root / ".kiro" / "hooks" / "interlock.json") if root else None,
                        note="" if root else ("Kiro hooks are per workspace: run `interlock install --kiro "
                                              "--workspace-root <folder Kiro has open>`" if kiro else "")))
    return out


# ------------------------------------------------------------------------------------------------ hook removal


def remove_hook_groups(path: Path, marker: str) -> bool:
    """Drop every hook group whose JSON mentions `marker` (the installed shim path). Returns True if changed."""
    if not path.exists() or not path.read_text().strip():
        return False
    data = json.loads(path.read_text())
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return False
    changed = False
    for event in list(hooks):
        groups = hooks[event] or []
        kept = [g for g in groups if marker not in json.dumps(g)]
        if len(kept) != len(groups):
            changed = True
            if kept:
                hooks[event] = kept
            else:
                del hooks[event]
    if changed:
        if not hooks:
            data.pop("hooks")
        if data.get("description") == "Interlock pre/post-action gate":
            data.pop("description")
        path.write_text(json.dumps(data, indent=2) + "\n")
    return changed


# ------------------------------------------------------------------------------------------------ mode switch


def set_mode(policy_path: Path, mode: str) -> str:
    """Set `mode:` in a policy file in place, preserving comments. Creates the starter policy if absent.
    Returns the previous mode."""
    if mode not in ("shadow", "enforce"):
        raise ValueError(mode)
    if not policy_path.exists():
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(STARTER_POLICY)
    text = policy_path.read_text()
    m = re.search(r"^mode:\s*(\w+)", text, flags=re.MULTILINE)
    if m:
        prev = m.group(1)
        text = text[: m.start(1)] + mode + text[m.end(1):]
    else:
        prev = "shadow"
        text = text.rstrip("\n") + f"\nmode: {mode}\n"
    policy_path.write_text(text)
    return prev


def workspace_mode_override(user_policy: Path, cwd: Path | None = None) -> Path | None:
    """A workspace policy that sets `mode:` wins over the user policy; report it so the switch isn't silently ignored."""
    cwd = (cwd or Path.cwd()).resolve()
    mine = user_policy.expanduser().resolve()
    for p in [cwd, *cwd.parents]:
        f = p / ".interlock" / "policy.yaml"
        if f.exists() and f.resolve() != mine and re.search(r"^mode:", f.read_text(), flags=re.MULTILINE):
            return f
    return None


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print(f"{prompt} [not a terminal; pass --yes to proceed]")
        return False
    return input(f"{prompt} [Y/n] ").strip().lower() in ("", "y", "yes")


def settings_for(home: Path | None) -> Settings:
    return Settings.load(home)


# ------------------------------------------------------------------------------------------------ MCP registration

MCP_NAME = "interlock"
CODEX_BEGIN, CODEX_END = "# >>> interlock mcp (managed by `interlock init --mcp`)", "# <<< interlock mcp"


def mcp_command() -> list[str]:
    """How an agent launches the Interlock MCP server: this interpreter, so it works from a pipx/uv tool venv."""
    return [sys.executable, "-m", "interlockd", "mcp"]


def _json_mcp_file(harness: str) -> Path | None:
    home = Path.home()
    return {"cursor": home / ".cursor" / "mcp.json", "gemini-cli": home / ".gemini" / "settings.json",
            "kiro": home / ".kiro" / "settings" / "mcp.json"}.get(harness)


def register_mcp(harness: str, run=None) -> dict | None:
    """Add the Interlock MCP server to one agent's config. Returns a manifest entry, or None if not supported/failed."""
    import subprocess

    run = run or (lambda cmd: subprocess.run(cmd, capture_output=True, text=True, check=False))
    cmd = mcp_command()
    if harness == "claude-code":
        claude = shutil.which("claude")
        if not claude:
            return None
        run([claude, "mcp", "remove", "--scope", "user", MCP_NAME])           # idempotent re-add
        r = run([claude, "mcp", "add", "--scope", "user", MCP_NAME, "--", *cmd])
        return {"harness": harness, "via": "claude-cli"} if r.returncode == 0 else None
    if harness == "codex":
        f = Path.home() / ".codex" / "config.toml"
        text = f.read_text() if f.exists() else ""
        text = _strip_codex_block(text)
        args = ", ".join(json.dumps(a) for a in cmd[1:])
        block = f'\n{CODEX_BEGIN}\n[mcp_servers.{MCP_NAME}]\ncommand = {json.dumps(cmd[0])}\nargs = [{args}]\n{CODEX_END}\n'
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text.rstrip("\n") + "\n" + block if text.strip() else block.lstrip("\n"))
        return {"harness": harness, "file": str(f), "via": "toml-block"}
    f = _json_mcp_file(harness)
    if f is None:
        return None
    data = json.loads(f.read_text()) if f.exists() and f.read_text().strip() else {}
    created = not f.exists()
    data.setdefault("mcpServers", {})[MCP_NAME] = {"command": cmd[0], "args": cmd[1:]}
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data, indent=2) + "\n")
    return {"harness": harness, "file": str(f), "via": "json", "created": created}


def _strip_codex_block(text: str) -> str:
    i = text.find(CODEX_BEGIN)
    if i < 0:
        return text
    j = text.find(CODEX_END, i)
    return text[:i].rstrip("\n") + ("\n" if text[:i].strip() else "") + (text[j + len(CODEX_END):].lstrip("\n") if j >= 0 else "")


def unregister_mcp(entry: dict, run=None) -> bool:
    import subprocess

    run = run or (lambda cmd: subprocess.run(cmd, capture_output=True, text=True, check=False))
    via = entry.get("via")
    if via == "claude-cli":
        claude = shutil.which("claude")
        return bool(claude) and run([claude, "mcp", "remove", "--scope", "user", MCP_NAME]).returncode == 0
    f = Path(entry.get("file", ""))
    if not f.exists():
        return False
    if via == "toml-block":
        f.write_text(_strip_codex_block(f.read_text()))
        return True
    data = json.loads(f.read_text() or "{}")
    if MCP_NAME not in (data.get("mcpServers") or {}):
        return False
    del data["mcpServers"][MCP_NAME]
    if not data["mcpServers"]:
        del data["mcpServers"]
    if entry.get("created") and not data:
        f.unlink()
    else:
        f.write_text(json.dumps(data, indent=2) + "\n")
    return True
