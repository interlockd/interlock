"""`interlock sandbox -- <command>`: run an agent (or anything) inside an OS sandbox derived from the policy.

Hooks see what the agent reports; the sandbox holds even for what it doesn't. Writes are refused, at the OS level,
to the places persistence and guard-rail tampering go: shell startup files, ~/.ssh, LaunchAgents and autostart, and
Interlock's own home (its hook log stays writable); agents' own config files with --protect-agent-configs. Optional: refuse reads of private keys
and cloud credentials (`--deny-secret-reads`; this breaks git over SSH), and limit outbound network to localhost
(`--local-network-only`; the daemon stays reachable).

macOS: sandbox-exec with a generated SBPL profile (later rules override earlier ones; paths are fully resolved).
Linux: bubblewrap, binding protected paths read-only and masking secret files.
"""

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path

WRITE_PROTECTED = [".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile", ".bash_login", ".kshrc",
                   ".config/fish/config.fish", ".gitconfig", ".netrc", ".npmrc", ".pypirc", ".ssh", "Library/LaunchAgents",
                   ".config/autostart", ".config/systemd/user", ".interlock"]
# Agents rewrite their own config at startup (measured: Claude Code renames ~/.claude/settings.json into place), so
# these are opt-in (--protect-agent-configs); hook removal through them is caught by `interlock doctor`.
AGENT_CONFIGS = [".claude/settings.json", ".codex/hooks.json", ".codex/config.toml", ".cursor/hooks.json",
                 ".gemini/settings.json", ".gemini/config/hooks.json", ".copilot/hooks", ".kiro/settings",
                 ".config/opencode/plugins", ".codeium/windsurf/hooks.json"]
SECRET_READS = [".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/id_dsa", ".aws/credentials", ".aws/sso/cache",
                ".config/gh/hosts.yml", ".docker/config.json", ".kube/config", ".netrc", ".npmrc", ".pypirc"]
WRITABLE_EXCEPTIONS = [".interlock/hook.log"]         # the hook shim logs fail-open events here


def _real(p: Path) -> str:
    return os.path.realpath(str(p))


def _q(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def macos_profile(home: Path, *, deny_secret_reads: bool = False, local_network_only: bool = False,
                  extra_write_protected: list[str] = (), protect_agent_configs: bool = False) -> str:
    lines = ["(version 1)", "(allow default)"]
    targets = [_real(home / p) for p in WRITE_PROTECTED + (AGENT_CONFIGS if protect_agent_configs else [])] + [_real(Path(p).expanduser()) for p in extra_write_protected]
    lines.append("(deny file-write* " + " ".join(f'(subpath "{_q(t)}")' for t in targets) + ")")
    lines.append("(allow file-write* " + " ".join(f'(literal "{_q(_real(home / p))}")' for p in WRITABLE_EXCEPTIONS) + ")")
    if deny_secret_reads:
        lines.append("(deny file-read* " + " ".join(f'(subpath "{_q(_real(home / p))}")' for p in SECRET_READS) + ")")
    if local_network_only:
        lines += ["(deny network-outbound)", '(allow network-outbound (remote ip "localhost:*"))',
                  '(allow network-outbound (remote unix-socket))']
    return "\n".join(lines) + "\n"


def bwrap_args(home: Path, *, deny_secret_reads: bool = False, local_network_only: bool = False,
               extra_write_protected: list[str] = (), protect_agent_configs: bool = False) -> list[str]:
    args = ["bwrap", "--dev-bind", "/", "/", "--proc", "/proc", "--die-with-parent"]
    for p in [*(home / x for x in WRITE_PROTECTED + (AGENT_CONFIGS if protect_agent_configs else [])), *(Path(x).expanduser() for x in extra_write_protected)]:
        if p.exists():
            args += ["--ro-bind", str(p), str(p)]
    for p in (home / x for x in WRITABLE_EXCEPTIONS):
        if p.exists():
            args += ["--bind", str(p), str(p)]
    if deny_secret_reads:
        for p in (home / x for x in SECRET_READS):
            if p.is_file():
                args += ["--ro-bind", "/dev/null", str(p)]
            elif p.is_dir():
                args += ["--tmpfs", str(p)]
    if local_network_only:
        args += ["--unshare-net"]           # loopback only; note: this also hides the host's loopback daemon
    return args + ["--"]


def command(cmd: list[str], home: Path | None = None, **opts) -> list[str]:
    """The full argv that runs `cmd` sandboxed on this OS."""
    home = home or Path.home()
    system = platform.system()
    if system == "Darwin":
        if not shutil.which("sandbox-exec"):
            raise RuntimeError("sandbox-exec not found")
        return ["sandbox-exec", "-p", macos_profile(home, **opts), *cmd]
    if system == "Linux":
        if not shutil.which("bwrap"):
            raise RuntimeError("bubblewrap (bwrap) not found: install it (apt install bubblewrap / dnf install bubblewrap)")
        return [*bwrap_args(home, **opts), *cmd]
    raise RuntimeError(f"no sandbox backend for {system}")
