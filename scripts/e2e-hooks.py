"""End to end: `interlock init` into a throwaway home, then every installed agent hook run exactly as the agent runs it
(its configured command, through the agent's shell), with payloads captured from the real agents.

    python scripts/e2e-hooks.py [--service]     # run from the repository root, with HOME / USERPROFILE set to a
                                                # throwaway directory; --service lets init install the background
                                                # service (Windows: the per-user Run key), otherwise --no-service

Checks: a force push to main is refused by every agent's hook, a benign command is not, `doctor` passes, and
`uninstall` removes every hook (and the Run-key entry). Exits non-zero on the first failure.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"
WIN = sys.platform == "win32"
HOME = Path.home()
WORKSPACE = HOME / "work"                 # a Kiro workspace (Kiro hooks are per workspace)
AGENT_DIRS = [".claude", ".codex", ".cursor", ".gemini", ".copilot", ".codeium/windsurf"]
INTERLOCK = [sys.executable, "-m", "interlockd"]
PORT = int(os.environ.get("E2E_PORT") or 7499)     # never the default 7391: a real daemon may be running there


def sh(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", cwd=WORKSPACE, check=False, **kw)
    print(f"$ {' '.join(cmd[2:]) if cmd[:2] == INTERLOCK[:2] else ' '.join(cmd)}  -> {r.returncode}")
    return r


def check(ok: bool, what: str) -> None:
    print(("  ok   " if ok else "  FAIL ") + what)
    if not ok:
        sys.exit(1)


def hook_commands() -> dict[str, tuple[str, str]]:
    """{harness: (pre-tool command, shell)} read back from each agent's config, as init wrote them."""
    def load(p: Path) -> dict:
        return json.loads(p.read_text(encoding="utf-8"))

    cmds = {}
    c = load(HOME / ".claude" / "settings.json")["hooks"]["PreToolUse"][-1]["hooks"][0]["command"]
    cmds["claude-code"] = (c, "shell")
    cmds["codex"] = (load(HOME / ".codex" / "hooks.json")["hooks"]["PreToolUse"][-1]["hooks"][0]["command"], "shell")
    cmds["cursor"] = (load(HOME / ".cursor" / "hooks.json")["hooks"]["preToolUse"][-1]["command"], "shell")
    cmds["gemini-cli"] = (load(HOME / ".gemini" / "settings.json")["hooks"]["BeforeTool"][-1]["hooks"][0]["command"], "shell")
    cp = load(HOME / ".copilot" / "hooks" / "interlock.json")["hooks"]["preToolUse"][-1]
    cmds["copilot-cli"] = (cp["powershell"], "powershell") if WIN else (cp["bash"], "shell")
    cmds["windsurf"] = (load(HOME / ".codeium" / "windsurf" / "hooks.json")["hooks"]["pre_run_command"][-1]["command"], "shell")
    cmds["kiro"] = (load(WORKSPACE / ".kiro" / "hooks" / "interlock.json")["hooks"][0]["action"]["command"], "shell")
    return cmds


def run_hook(cmd: str, shell: str, payload: str) -> subprocess.CompletedProcess:
    argv = ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd] if shell == "powershell" else cmd
    return subprocess.run(argv, shell=shell != "powershell", input=payload, capture_output=True, text=True,
                          encoding="utf-8", cwd=WORKSPACE, timeout=30, check=False)


def payloads(harness: str) -> tuple[str, str]:
    """(force push to main, the same call running `ls -la`) in the harness's own captured payload shape."""
    if harness == "kiro":
        block = json.dumps({"session_id": "e2e", "hook_event_name": "PreToolUse", "cwd": str(WORKSPACE),
                            "tool_name": "execute_bash", "tool_input": {"command": "git push --force origin main"}})
    else:
        block = next((FIX / harness).glob("pre-*-block.json")).read_text(encoding="utf-8")
    return block, block.replace("git push --force origin main", "ls -la")


def refused(harness: str, r: subprocess.CompletedProcess) -> bool:
    if harness in ("windsurf", "kiro"):
        return r.returncode == 2 and "[interlock]" in r.stderr
    return r.returncode == 0 and "deny" in r.stdout and "[interlock]" in r.stdout


def main() -> int:
    service = "--service" in sys.argv
    for d in AGENT_DIRS:
        (HOME / d).mkdir(parents=True, exist_ok=True)
    (WORKSPACE / ".kiro").mkdir(parents=True, exist_ok=True)
    il_home = Path(os.environ.get("INTERLOCK_HOME") or HOME / ".interlock")
    il_home.mkdir(parents=True, exist_ok=True)
    (il_home / "config.json").write_text(json.dumps({"listen": f"127.0.0.1:{PORT}"}), encoding="utf-8")

    r = sh([*INTERLOCK, "init", "--yes", "--enforce", *([] if service else ["--no-service"])])
    print(r.stdout[-3000:], r.stderr[-2000:])
    check(r.returncode == 0, "interlock init")
    daemon = None if service else subprocess.Popen([*INTERLOCK, "serve"], stdout=subprocess.DEVNULL,
                                                   stderr=subprocess.DEVNULL, cwd=WORKSPACE)
    listen = f"127.0.0.1:{PORT}"
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"http://{listen}/interlock/v1/health", timeout=1) as h:
                if h.status == 200:
                    break
        except OSError:
            time.sleep(0.5)
    else:
        check(False, "daemon answers on " + listen)
    check(True, "daemon answers on " + listen)

    for harness, (cmd, shell) in hook_commands().items():
        block, benign = payloads(harness)
        t0 = time.perf_counter()
        r = run_hook(cmd, shell, block)
        ms = (time.perf_counter() - t0) * 1000
        check(refused(harness, r), f"{harness}: force push refused via `{cmd}` ({ms:.0f} ms) {r.stdout[:120]!r}{r.stderr[:120]!r}")
        r = run_hook(cmd, shell, benign)
        check(not refused(harness, r), f"{harness}: `ls -la` not refused (exit {r.returncode})")

    r = sh([*INTERLOCK, "doctor"])
    print(r.stdout[-3000:])
    check(r.returncode == 0, "interlock doctor")
    r = sh([*INTERLOCK, "uninstall", "--yes"])
    if daemon is not None:                       # only the daemon this script started
        daemon.terminate(); daemon.wait(timeout=10)
    check(r.returncode == 0, "interlock uninstall")
    for f in (HOME / ".claude" / "settings.json", HOME / ".codex" / "hooks.json", HOME / ".cursor" / "hooks.json",
              HOME / ".gemini" / "settings.json", HOME / ".codeium" / "windsurf" / "hooks.json"):
        check(not f.exists() or "interlock-hook" not in f.read_text(encoding="utf-8"), f"no Interlock hook left in {f.name} ({f.parent.name})")
    if WIN and service:
        from interlockd.service import ServiceManager

        svc = ServiceManager(il_home)
        check(svc.run_key.get(svc.label) is None, "Run-key entry removed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
