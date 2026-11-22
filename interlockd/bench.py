"""`interlock bench`: measure decision latency on this machine (in-process, HTTP, and the real hook shim).

Runs against a private daemon in a temporary home, so nothing touches your real audit log. Reports p50 / p95 / p99
in milliseconds for:

  decide            the pipeline alone, over the rule corpus (every pack, attack and benign cases)
  http              one hook call over loopback HTTP, as the daemon receives it, with hot-path enforcement-point
                    verification (the daemon's `Verifier`) on, as `interlock serve` runs it
  http (no verify)  the same call with `daemon.verifier = None`; the two rows are interleaved call by call so drift
                    on the machine lands on both, and `verify_delta` is their p95 difference (Requirement 5.2)
  shim (tcp)        the full path an agent pays: POSIX sh shim + curl + daemon, over TCP
  shim (unix)       the same over the 0600 Unix socket
  floor             sh + cat + curl to the health endpoint, no decision: what process spawn alone costs here
  probe 4 KB        the post-action injection probe on a 4 KB tool result

The private home gets a real enforcement point for claude-code (the shim the shim rows run, a hook config that
registers it, an install manifest and an integrity baseline seeded from disk), so the verified row measures the
intact-and-cached path every request takes in practice, not the `no_baseline` shortcut.
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

MIN_HTTP_CALLS = 300            # Requirement 14.5: the verified and unverified http rows each get at least this many
HTTP = "http"
HTTP_NO_VERIFY = "http (no verify)"


def _pct(xs: list[float]) -> dict[str, float]:
    xs = sorted(xs)
    at = lambda q: round(xs[min(len(xs) - 1, int(q * len(xs)))], 2)
    return {"n": len(xs), "p50": round(statistics.median(xs), 2), "p95": at(0.95), "p99": at(0.99)}


def verify_delta(r: dict[str, dict]) -> float | None:
    """p95 of the verified http row minus p95 of the unverified one, in ms (None when either row is missing)."""
    if HTTP not in r or HTTP_NO_VERIFY not in r:
        return None
    return round(r[HTTP]["p95"] - r[HTTP_NO_VERIFY]["p95"], 2)


def over_budget(r: dict[str, dict], budget_ms: float | None) -> bool:
    """True when a budget is given and the verification Δp95 exceeds it (or cannot be measured)."""
    if budget_ms is None:
        return False
    delta = verify_delta(r)
    return delta is None or delta > budget_ms


def _install_enforcement_point(home: Path, shim: Path) -> None:
    """A claude-code enforcement point in the private home: hook config registering `shim`, and the manifest."""
    from .onboard import Manifest

    settings = home / "settings.json"
    hook = {"type": "command", "command": str(shim)}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [hook]}]}}), encoding="utf-8")
    Manifest(version="bench", hooks=[{"harness": "claude-code", "file": str(settings), "marker": str(shim),
                                      "created": True}]).save(home)


def run(rounds: int = 3, http_calls: int = MIN_HTTP_CALLS, shim_calls: int = 100) -> dict[str, dict]:
    from . import identity
    from .api import ApiServer
    from .cli import CLAUDE_SHIM_SRC, PY_SHIM_SRC, _hook_python, attach_integrity, hook_runtime
    from .config import Settings
    from .models import AdapterInfo, Capabilities, Context, InterlockEvent, ToolCall, ToolResult
    from .pipeline import Daemon
    from .policy import Policy
    from .store.memory import MemoryRepository
    from .store.spool import Spool
    from .testkit import default_corpus_dir, load_cases

    out: dict[str, dict] = {}
    home = Path(tempfile.mkdtemp(prefix="ilb", dir="/tmp" if os.name != "nt" else None))   # short: socket path limit
    try:
        (home / "token").write_text("tok\n", encoding="utf-8")
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

        # The enforcement point the verified row checks is the shim the shim rows run.
        py_shim = hook_runtime() == "py"                    # the Python shim (native Windows)
        shim = home / ("shim.py" if py_shim else "shim.sh")
        src = PY_SHIM_SRC if py_shim else CLAUDE_SHIM_SRC
        shim.write_text(src.read_text(encoding="utf-8").replace("__HARNESS__", "claude-code"), encoding="utf-8")
        _install_enforcement_point(home, shim)
        attach_integrity(d, home, None)                     # protection, baseline (seeded from disk), verifier
        verifier = d.verifier

        sock = str(home / "interlockd.sock") if s.unix_socket else None    # no Unix sockets on Windows
        ident = identity.derive("tok", identity.new_nonce())
        identity.write(home, ident)                         # the shims verify every reply against it
        api = ApiServer(d, "tok", "127.0.0.1", 0, unix_socket=sock, identity=ident); api.start_background()
        host, port = api.address
        (home / "daemon.json").write_text(json.dumps({"listen": f"{host}:{port}"}), encoding="utf-8")
        payload = {"session_id": "b", "cwd": str(home), "hook_event_name": "PreToolUse", "tool_name": "Bash",
                   "tool_input": {"command": "ls -la"}, "tool_use_id": "t"}
        adapter = {"name": "claude-code", "version": "bench", "shim": str(shim)}
        body = json.dumps({"adapter": adapter, "payload": payload}).encode()
        url = f"http://{host}:{port}/interlock/v1/hooks/claude-code?format=claude-code"
        # `interlock serve` runs HookWatch's first pass (a verify per manifest harness) before serving, so requests
        # meet a warm cache; do the same, plus one untimed request in each configuration.
        verifier.verify("claude-code", str(shim))
        timed: dict[str, list[float]] = {HTTP: [], HTTP_NO_VERIFY: []}
        for i in range(-1, http_calls):
            # interleaved, alternating which goes first, so neither row gets the warmer half of the run
            for label in ((HTTP, HTTP_NO_VERIFY) if i % 2 == 0 else (HTTP_NO_VERIFY, HTTP)):
                d.verifier = verifier if label == HTTP else None
                req = urllib.request.Request(url, data=body, method="POST")
                req.add_header("authorization", "Bearer tok"); req.add_header("content-type", "application/json")
                t0 = time.perf_counter(); urllib.request.urlopen(req, timeout=5).read()
                if i >= 0:
                    timed[label].append((time.perf_counter() - t0) * 1000)
        d.verifier = verifier                               # the shim rows take the real (verified) path
        out[HTTP] = _pct(timed[HTTP])
        out[HTTP_NO_VERIFY] = _pct(timed[HTTP_NO_VERIFY])

        if py_shim:                                         # over TCP
            env = {**os.environ, "INTERLOCK_HOME": str(home), "INTERLOCK_URL": f"http://{host}:{port}"}
            t = []
            for _ in range(shim_calls):
                t0 = time.perf_counter()
                subprocess.run([_hook_python(), "-I", "-S", str(shim)], input=json.dumps(payload), text=True, capture_output=True,
                               env=env, timeout=10, check=False)
                t.append((time.perf_counter() - t0) * 1000)
            if t:
                out["shim (python)"] = _pct(t)
        elif shutil.which("curl"):
            for label, extra in (("shim (tcp)", {"INTERLOCK_URL": f"http://{host}:{port}"}), ("shim (unix)", {})):
                env = {**{k: v for k, v in os.environ.items() if k != "INTERLOCK_URL"}, "INTERLOCK_HOME": str(home), **extra}
                t = []
                for _ in range(shim_calls):
                    t0 = time.perf_counter()
                    subprocess.run(["sh", str(shim)], input=json.dumps(payload), text=True, capture_output=True, env=env, timeout=10, check=False)
                    t.append((time.perf_counter() - t0) * 1000)
                if t:
                    out[label] = _pct(t)
            floor = f'payload=$(cat); curl -sf -m 5 http://{host}:{port}/interlock/v1/health >/dev/null'
            t = []
            for _ in range(shim_calls):
                t0 = time.perf_counter()
                subprocess.run(["sh", "-c", floor], input="{}", text=True, capture_output=True, timeout=10, check=False)
                t.append((time.perf_counter() - t0) * 1000)
            if t:
                out["floor"] = _pct(t)
        api.shutdown()
    finally:
        shutil.rmtree(home, ignore_errors=True)
    return out


def format_results(r: dict[str, dict]) -> str:
    lines = [f"  {'path':<17} {'n':>6} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8}"]
    for k, v in r.items():
        lines.append(f"  {k:<17} {v['n']:>6} {v['p50']:>8} {v['p95']:>8} {v['p99']:>8}")
    delta = verify_delta(r)
    if delta is not None:
        lines.append(f"\n  verify Δp95 ms {delta:+.2f}   (hot-path enforcement-point check: {HTTP!r} minus {HTTP_NO_VERIFY!r})")
    return "\n".join(lines)
