"""`interlock bench`: measure decision latency on this machine (in-process, HTTP, and the real hook shim).

Runs against a private daemon in a temporary home, so nothing touches your real audit log. Reports p50 / p95 / p99
in milliseconds for:

  decide        the pipeline alone, over the rule corpus (every pack, attack and benign cases)
  http          one hook call over loopback HTTP, as the daemon receives it
  shim (tcp)    the full path an agent pays: POSIX sh shim + curl + daemon, over TCP
  shim (unix)   the same over the 0600 Unix socket
  floor         sh + cat + curl to the health endpoint, no decision: what process spawn alone costs here
  probe 4 KB    the post-action injection probe on a 4 KB tool result
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path


def _pct(xs: list[float]) -> dict[str, float]:
    xs = sorted(xs)
    at = lambda q: round(xs[min(len(xs) - 1, int(q * len(xs)))], 2)
    return {"n": len(xs), "p50": round(statistics.median(xs), 2), "p95": at(0.95), "p99": at(0.99)}


def run(rounds: int = 3, http_calls: int = 300, shim_calls: int = 100) -> dict[str, dict]:
    from .api import ApiServer
    from .cli import CLAUDE_SHIM_SRC
    from .config import Settings
    from .models import AdapterInfo, Capabilities, Context, InterlockEvent, ToolCall, ToolResult
    from .pipeline import Daemon
    from .policy import Policy
    from .store.memory import MemoryRepository
    from .store.spool import Spool
    from .testkit import default_corpus_dir, load_cases

    out: dict[str, dict] = {}
    home = Path(tempfile.mkdtemp(prefix="ilb", dir="/tmp"))      # short path: the Unix socket has a length limit
    try:
        (home / "token").write_text("tok\n")
        s = Settings(home=home)
        pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = [str(home)]
        d = Daemon(s, spool=Spool(s.spool_dir, fsync=False), repo=MemoryRepository(), policy=pol)
        cases = [c for c in load_cases(default_corpus_dir()) if "cmd" in c or "tool" in c]
        t = []
        for _ in range(rounds):
            for c in cases:
                name, args = ("Bash", {"command": c["cmd"]}) if "cmd" in c else (c["tool"], c.get("args", {}))
                ev = InterlockEvent(kind="pre_action", adapter=AdapterInfo(name="bench"), session_hint=f"b{len(t)}",
                                    tool_call=ToolCall(name=name, arguments=args), context=Context(cwd=str(home)))
                t0 = time.perf_counter(); d.decide(ev); t.append((time.perf_counter() - t0) * 1000)
        out["decide"] = _pct(t)

        text = ("Build steps: run make, then make test. " * 120)[:4096]
        t = []
        for i in range(200):
            ev = InterlockEvent(kind="post_action", adapter=AdapterInfo(name="bench"), session_hint=f"p{i}",
                                tool_call=ToolCall(name="Read", arguments={"file_path": "README.md"}), context=Context(cwd=str(home)),
                                result=ToolResult(content=text), capabilities=Capabilities(withhold=True))
            t0 = time.perf_counter(); d.decide(ev); t.append((time.perf_counter() - t0) * 1000)
        out["probe 4 KB"] = _pct(t)

        sock = str(home / "interlockd.sock")
        api = ApiServer(d, "tok", "127.0.0.1", 0, unix_socket=sock); api.start_background()
        host, port = api.address
        (home / "daemon.json").write_text(json.dumps({"listen": f"{host}:{port}"}))
        payload = {"session_id": "b", "cwd": str(home), "hook_event_name": "PreToolUse", "tool_name": "Bash",
                   "tool_input": {"command": "ls -la"}, "tool_use_id": "t"}
        body = json.dumps({"adapter": {"name": "claude-code", "version": "bench"}, "payload": payload}).encode()
        t = []
        for _ in range(http_calls):
            req = urllib.request.Request(f"http://{host}:{port}/interlock/v1/hooks/claude-code?format=claude-code", data=body, method="POST")
            req.add_header("authorization", "Bearer tok"); req.add_header("content-type", "application/json")
            t0 = time.perf_counter(); urllib.request.urlopen(req, timeout=5).read(); t.append((time.perf_counter() - t0) * 1000)
        out["http"] = _pct(t)

        if shutil.which("curl"):
            shim = home / "shim.sh"; shim.write_text(CLAUDE_SHIM_SRC.read_text().replace("__HARNESS__", "claude-code"))
            for label, extra in (("shim (tcp)", {"INTERLOCK_URL": f"http://{host}:{port}"}), ("shim (unix)", {})):
                env = {**{k: v for k, v in os.environ.items() if k != "INTERLOCK_URL"}, "INTERLOCK_HOME": str(home), **extra}
                t = []
                for _ in range(shim_calls):
                    t0 = time.perf_counter()
                    subprocess.run(["sh", str(shim)], input=json.dumps(payload), text=True, capture_output=True, env=env, timeout=10, check=False)
                    t.append((time.perf_counter() - t0) * 1000)
                out[label] = _pct(t)
            floor = f'payload=$(cat); curl -sf -m 5 http://{host}:{port}/interlock/v1/health >/dev/null'
            t = []
            for _ in range(shim_calls):
                t0 = time.perf_counter()
                subprocess.run(["sh", "-c", floor], input="{}", text=True, capture_output=True, timeout=10, check=False)
                t.append((time.perf_counter() - t0) * 1000)
            out["floor"] = _pct(t)
        api.shutdown()
    finally:
        shutil.rmtree(home, ignore_errors=True)
    return out


def format_results(r: dict[str, dict]) -> str:
    lines = [f"  {'path':<14} {'n':>6} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8}"]
    for k, v in r.items():
        lines.append(f"  {k:<14} {v['n']:>6} {v['p50']:>8} {v['p95']:>8} {v['p99']:>8}")
    return "\n".join(lines)
