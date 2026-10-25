"""The Python hook shim (interlockd/shims/py/interlock-hook.py, used where there is no sh + curl, e.g. native Windows),
against a real enforcing daemon, with the payloads captured from each agent. Where sh and curl exist, its output must
equal the sh shim's byte for byte."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from interlockd.api import ApiServer

SHIMS = Path(__file__).resolve().parents[1] / "interlockd" / "shims"
PY_SHIM, SH_SHIM, KIRO_SH = SHIMS / "py" / "interlock-hook.py", SHIMS / "claude-code" / "interlock-hook.sh", SHIMS / "kiro" / "interlock-hook.sh"
FIXTURES = Path(__file__).parent / "fixtures"
HAVE_SH = shutil.which("sh") is not None and shutil.which("curl") is not None and sys.platform != "win32"
NEEDS_ARG = {"copilot-cli", "windsurf"}            # installers pass pre/post where the payload doesn't name the event


@pytest.fixture
def daemon_home(tmp_path):
    h = tmp_path / "ih"; h.mkdir()
    (h / "token").write_text("tok\n", encoding="utf-8")
    return h


@pytest.fixture
def server(settings):
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool

    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = ["/ws/proj"]
    s = ApiServer(Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol), "tok", "127.0.0.1", 0)
    s.start_background()
    yield s
    s.shutdown()


def _install(tmp_path, src: Path, harness: str) -> Path:
    dst = tmp_path / harness / src.name
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(src.read_text(encoding="utf-8").replace("__HARNESS__", harness), encoding="utf-8")
    return dst


def _run(cmd, payload, home, url, cwd, **env):
    e = {**os.environ, "INTERLOCK_HOME": str(home), "INTERLOCK_URL": url, **env}
    r = subprocess.run(cmd, input=payload.encode("utf-8"), capture_output=True, env=e, cwd=cwd, timeout=20, check=False)
    return r.returncode, r.stdout.decode("utf-8").strip(), r.stderr.decode("utf-8").strip()


def _py(tmp_path, harness, payload, home, url, arg="", **env):
    shim = _install(tmp_path, PY_SHIM, harness)
    return _run([sys.executable, "-I", "-S", str(shim), *([arg] if arg else [])], payload, home, url, tmp_path, **env)


def _sh(tmp_path, harness, payload, home, url, arg="", **env):
    shim = KIRO_SH if harness == "kiro" else _install(tmp_path, SH_SHIM, harness)
    return _run(["sh", str(shim), *([arg] if arg else [])], payload, home, url, tmp_path, **env)


def _url(server):
    host, port = server.address
    return f"http://{host}:{port}"


CASES = sorted(FIXTURES.glob("*/*.json"))


@pytest.mark.parametrize("path", CASES, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_captured_payloads(server, daemon_home, tmp_path, path):
    harness = path.parent.name
    payload = path.read_text(encoding="utf-8")
    arg = ("post" if path.stem.startswith("post-") else "pre") if harness in NEEDS_ARG else ""
    rc, out, err = _py(tmp_path, harness, payload, daemon_home, _url(server), arg)
    block = path.stem.startswith("pre-") and path.stem.endswith("-block")
    if harness == "windsurf":
        assert (rc == 2 and "[interlock]" in err) if block else rc == 0
    elif block:
        assert rc == 0 and "deny" in out and "[interlock]" in out
    elif path.stem.startswith("pre-") and harness == "cursor":
        assert rc == 1 and out == ""                       # Cursor: "no opinion" is a non-zero exit
    elif path.stem.startswith("post-") and path.stem.endswith("-inject"):   # the daemon's replacement or refusal
        assert rc == 0 and "[interlock]" in out and "evil.example" not in out
    else:
        assert rc == 0 and out == ""
    if HAVE_SH:
        assert (rc, out, err) == _sh(tmp_path, harness, payload, daemon_home, _url(server), arg)


KIRO_PRE = json.dumps({"session_id": "s", "hook_event_name": "PreToolUse", "cwd": "/ws/proj", "tool_name": "execute_bash",
                       "tool_input": {"command": "git push --force origin main"}}, separators=(",", ":"))
KIRO_OK = KIRO_PRE.replace("git push --force origin main", "ls -la")
KIRO_POST = json.dumps({"session_id": "s", "hook_event_name": "PostToolUse", "cwd": "/ws/proj", "tool_name": "execute_bash",
                        "tool_input": {"command": "ls"}, "tool_response": "Output:\nok\n\nExit Code: 0"}, separators=(",", ":"))


@pytest.mark.parametrize("payload,want_rc", [(KIRO_PRE, 2), (KIRO_OK, 0), (KIRO_POST, 0)], ids=["block", "allow", "post"])
def test_kiro(server, daemon_home, tmp_path, payload, want_rc):
    rc, out, err = _py(tmp_path, "kiro", payload, daemon_home, _url(server))
    assert rc == want_rc and out == "" and (("[interlock]" in err) == (want_rc == 2))
    if HAVE_SH:
        assert (rc, out, err) == _sh(tmp_path, "kiro", payload, daemon_home, _url(server))


DOWN = "http://127.0.0.1:9"                                 # nothing listens: the daemon is "down"
PRE_CLAUDE = (FIXTURES / "claude-code" / "pre-bash-block.json").read_text(encoding="utf-8")


@pytest.mark.parametrize("harness,arg", [("claude-code", ""), ("codex", ""), ("cursor", ""), ("gemini-cli", ""),
                                         ("copilot-cli", "pre"), ("windsurf", "pre"), ("antigravity", "pre"), ("kiro", "")])
def test_daemon_down(daemon_home, tmp_path, harness, arg):
    for mode in ("open", "closed"):
        rc, out, err = _py(tmp_path, harness, PRE_CLAUDE, daemon_home, DOWN, arg, INTERLOCK_FAIL_MODE=mode)
        if HAVE_SH:
            sh = _sh(tmp_path, harness, PRE_CLAUDE, daemon_home, DOWN, arg, INTERLOCK_FAIL_MODE=mode)
            assert rc == sh[0] and out == sh[1], (mode, sh)
        if mode == "closed":
            assert ("[interlock]" in err and rc == 2) if harness in ("windsurf", "kiro") else ("deny" in out and rc == 0)
        else:
            assert "deny" not in out and "[interlock]" not in err
    log = (daemon_home / "hook.log").read_text(encoding="utf-8")
    assert "unjudged" in log and "fail_mode=closed" in log


def test_no_token_is_inert(tmp_path):
    home = tmp_path / "empty"; home.mkdir()
    rc, out, _ = _py(tmp_path, "claude-code", PRE_CLAUDE, home, DOWN)
    assert rc == 0 and out == "" and "inert: no token" in (home / "hook.log").read_text(encoding="utf-8")


def test_version_line_matches_the_package():
    from interlockd import __version__

    assert f'VERSION = "{__version__}"' in PY_SHIM.read_text(encoding="utf-8")
