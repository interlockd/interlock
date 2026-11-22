"""The Python hook shim (interlockd/shims/py/interlock-hook.py, used where there is no sh + curl, e.g. native Windows),
against a real enforcing daemon, with the payloads captured from each agent. Where sh and curl exist, its output must
equal the sh shim's byte for byte."""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from kiro_shim_matrix import STOP, marker_text, one_keyword, restart_marker
from shim_stub import (
    HAVE_UNIX,
    SHIMS_018,
    ShimHome,
    StubDaemon,
    _payload,
    install_shim,
    load_recording,
    play,
    reply_from,
    run_shim,
)

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
def server(settings, daemon_home):
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool

    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = ["/ws/proj"]
    s = ApiServer(Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol), "tok", "127.0.0.1", 0)
    s.start_background()
    # what `interlock serve` leaves in its home: the identity the shims verify and daemon.json with the address
    (daemon_home / "identity").write_text(s.identity + "\n", encoding="utf-8")
    (daemon_home / "daemon.json").write_text('{{"listen": "{}:{}", "pid": 1}}\n'.format(*s.address), encoding="utf-8")
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


HARNESS_ARGS = [("claude-code", ""), ("codex", ""), ("cursor", ""), ("gemini-cli", ""), ("copilot-cli", "pre"),
                ("windsurf", "pre"), ("antigravity", "pre"), ("kiro", "")]


def _refused(harness, rc, out, err) -> str:
    """The refusal text when the shim refused the call through the harness's fail-closed channel, else ""."""
    if harness in ("windsurf", "kiro"):
        return err if rc == 2 and "[interlock]" in err else ""
    return out if rc == 0 and "deny" in out else ""


def _fail_mode(home, default, tamper=None):
    doc = {"default": default, **({"tamper": tamper} if tamper else {})}
    (home / "fail-mode.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


@pytest.mark.parametrize("harness,arg", HARNESS_ARGS)
def test_operator_stop_applies_the_default_fail_mode(daemon_home, tmp_path, harness, arg):
    (daemon_home / "stop-marker.json").write_text(
        '{"action": "stop", "pid": 1, "version": "0.1.8", "written_at": "2026-10-17T10:00:00Z"}\n', encoding="utf-8")
    for mode in ("open", "closed"):
        _fail_mode(daemon_home, mode, "closed")
        rc, out, err = _py(tmp_path, harness, PRE_CLAUDE, daemon_home, DOWN, arg)
        if mode == "closed":
            assert "daemon is unreachable" in _refused(harness, rc, out, err)
        else:
            assert "deny" not in out and "[interlock]" not in err
    log = (daemon_home / "hook.log").read_text(encoding="utf-8")
    assert "unjudged why=operator_stopped" in log and "fail_mode=closed" in log and "tamper" not in log


@pytest.mark.parametrize("harness,arg", HARNESS_ARGS)
def test_daemon_lost_fails_closed(daemon_home, tmp_path, harness, arg):
    _fail_mode(daemon_home, "open")                               # default open; tamper absent means closed
    rc, out, err = _py(tmp_path, harness, PRE_CLAUDE, daemon_home, DOWN, arg, INTERLOCK_FAIL_MODE="open")
    msg = _refused(harness, rc, out, err)
    assert "Interlock daemon stopped unexpectedly (daemon_lost)" in msg and "`interlock start`" in msg
    assert "interlock doctor" in msg and json.dumps(str(daemon_home))[1:-1] in msg
    _fail_mode(daemon_home, "closed", "open")                     # tamper open: logged, no opinion
    rc, out, err = _py(tmp_path, harness, PRE_CLAUDE, daemon_home, DOWN, arg)
    assert not _refused(harness, rc, out, err) and "[interlock]" not in err
    log = (daemon_home / "hook.log").read_text(encoding="utf-8").splitlines()
    assert [ln.split()[1:3] for ln in log] == [["tamper", "daemon_lost"]] * 2
    assert "status=-" in log[0] and log[0].endswith("fail_mode=closed") and log[1].endswith("fail_mode=open")
    assert "git push" not in "\n".join(log) and "tool=Bash kind=pre" in log[0]


def test_no_token_is_inert(tmp_path):
    home = tmp_path / "empty"; home.mkdir()
    rc, out, _ = _py(tmp_path, "claude-code", PRE_CLAUDE, home, DOWN)
    assert rc == 0 and out == "" and "inert: no token" in (home / "hook.log").read_text(encoding="utf-8")


def _load_shim():
    import importlib.util

    spec = importlib.util.spec_from_file_location("interlock_py_shim", PY_SHIM)
    mod = importlib.util.module_from_spec(spec)
    before, sys.dont_write_bytecode = sys.dont_write_bytecode, True   # no __pycache__ in the packaged shims
    try:
        spec.loader.exec_module(mod)       # main() runs only as __main__
    finally:
        sys.dont_write_bytecode = before
    return mod


def test_classify_and_select_fail_mode_are_importable():
    shim = _load_shim()
    ident = "0123456789abcdef0123456789abcdef"
    assert shim.classify(True, 200, [ident], ident) == ("apply", "")
    assert shim.classify(True, 200, [], ident) == ("tamper", "daemon_identity")
    assert shim.classify(True, 200, [ident, ident], ident) == ("tamper", "daemon_identity")
    assert shim.classify(True, 200, [ident], "") == ("tamper", "daemon_identity")      # no identity file
    assert shim.classify(True, 401) == shim.classify(True, 403, [ident], ident) == ("tamper", "token_rejected")
    assert shim.classify(True, 500, [ident], ident) == ("unjudged", "http_500")
    stop = '{"action": "stop", "pid": 1, "version": "0.2.0", "written_at": "2026-10-17T10:00:00Z"}\n'
    restart = ('{"action": "restart", "expires_at": "2026-10-17T10:02:00Z", "expires_epoch": 1000, "pid": 1, '
               '"version": "0.2.0", "written_at": "2026-10-17T10:00:00Z"}\n')
    assert shim.classify(False, marker_text=stop, now=5) == ("unjudged", "operator_stopped")
    assert shim.classify(False, marker_text=restart, now=999) == ("unjudged", "restarting")
    for marker, now in ((restart, 1000), ("", 0), ("{not json", 0), ('{"action": "stop"}', 0)):
        assert shim.classify(False, marker_text=marker, now=now) == ("tamper", "daemon_lost")
    fm = '{\n  "default": "open",\n  "tamper": "closed"\n}\n'
    assert shim.select_fail_mode("daemon_lost", None, fm) == "closed"
    assert shim.select_fail_mode("http_500", None, fm) == "open"
    assert shim.select_fail_mode("daemon_lost", "open", fm.replace('"closed"', '"open"')) == "open"
    assert shim.select_fail_mode("token_rejected", None, '{"default": "open"}') == "closed"
    assert shim.select_fail_mode("token_rejected", None, '{"tamper": "maybe"}') == "closed"
    assert shim.select_fail_mode("operator_stopped", "closed", fm) == "closed"
    assert shim.select_fail_mode("operator_stopped", "open", '{"default": "closed"}') == "closed"


@pytest.fixture
def stub_home():
    from shim_stub import ShimHome, StubDaemon

    home = ShimHome.create()
    with StubDaemon() as stub:
        home.write_daemon_json(stub.listen)
        yield home, stub
    home.cleanup()


def _stub_run(stub_home, harness="claude-code", payload=PRE_CLAUDE, arg="", **env):
    from shim_stub import install_shim, run_shim

    home, _ = stub_home
    return run_shim(install_shim(PY_SHIM, harness, home), payload, home, arg=arg, env=env or None)


POST_CLAUDE = json.dumps({"session_id": "s", "hook_event_name": "PostToolUse", "cwd": "/ws", "tool_name": "Bash",
                          "tool_input": {"command": "git push --force"}, "tool_response": {"stdout": "x"}})


def test_verified_reply_applies_and_sends_the_shim_path(stub_home):
    home, stub = stub_home
    deny = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}'
    stub.set(status=200, body=deny, identity=[home.identity])
    r = _stub_run(stub_home)
    assert (r.returncode, r.stdout, r.stderr) == (0, deny + "\n", "") and home.hook_log() == ""
    adapter = stub.requests[0].json()["adapter"]
    assert adapter["shim"] == str(home.root / "shims" / "claude-code" / "py" / "interlock-hook.py")


@pytest.mark.parametrize("status", [401, 403])
def test_token_rejected_refuses_pre_and_only_logs_post(stub_home, status):
    home, stub = stub_home
    stub.set(status=status, body='{"error":"unauthorized"}', identity=[home.identity])
    r = _stub_run(stub_home, INTERLOCK_FAIL_MODE="open")              # the environment cannot loosen the gate
    reason = json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
    assert r.returncode == 0 and "(token_rejected)" in reason and "interlock doctor" in reason
    r = _stub_run(stub_home, payload=POST_CLAUDE)
    assert (r.returncode, r.stdout) == (0, "")
    log = home.hook_log().splitlines()
    assert len(log) == 2 and all("tamper token_rejected harness=claude-code tool=Bash" in ln for ln in log)
    assert f"addr={stub.url} status={status} fail_mode=closed" in log[0] and "kind=post" in log[1]
    assert home.token not in home.hook_log() and "git push" not in home.hook_log()


@pytest.mark.parametrize("identity", [[], ["f" * 32], ["$ID", "$ID"]], ids=["missing", "wrong", "duplicated"])
@pytest.mark.parametrize("harness,arg", [("claude-code", ""), ("cursor", ""), ("kiro", ""), ("windsurf", "pre")])
def test_unverified_reply_is_never_applied(stub_home, identity, harness, arg):
    home, stub = stub_home
    body = "allow enforce 0\n\n" if harness in ("kiro", "windsurf") else '{"permission":"allow"}'
    stub.set(status=200, body=body, identity=[home.identity if v == "$ID" else v for v in identity])
    r = _stub_run(stub_home, harness, arg=arg)
    msg = _refused(harness, r.returncode, r.stdout, r.stderr)
    assert msg.count("daemon_identity") == 1 and "allow" not in r.stdout
    log = home.hook_log()
    assert "tamper daemon_identity" in log and "status=200" in log and home.identity not in log + r.stdout + r.stderr


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX") or os.name == "nt", reason="needs Unix sockets")
def test_unix_socket_is_verified_like_tcp():
    from shim_stub import ShimHome, StubDaemon, install_shim, run_shim

    home = ShimHome.create(listen="127.0.0.1:9")                 # TCP address dead: only the socket answers
    deny = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}'
    try:
        with StubDaemon(unix_socket=home.socket_path) as stub:
            shim = install_shim(PY_SHIM, "claude-code", home)
            stub.set(status=200, body=deny, identity=[home.identity])
            r = run_shim(shim, PRE_CLAUDE, home)
            assert (r.returncode, r.stdout) == (0, deny + "\n") and len(stub.requests) == 1
            stub.set(status=200, body=deny, identity=["f" * 32])
            r = run_shim(shim, PRE_CLAUDE, home)
            reason = json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
            assert reason.count("daemon_identity") == 1 and f"addr=unix:{home.socket_path}" in home.hook_log()
    finally:
        home.cleanup()


def test_other_http_errors_keep_the_default_fail_mode(stub_home):
    home, stub = stub_home
    stub.set(status=500, body="boom", identity=[home.identity])
    r = _stub_run(stub_home)
    assert (r.returncode, r.stdout) == (0, "") and "unjudged why=http_500" in home.hook_log()


def test_unwritable_hook_log_still_refuses(stub_home):
    home, stub = stub_home
    (home.path / "hook.log").mkdir()
    stub.set(status=401, identity=[home.identity])
    r = _stub_run(stub_home)
    assert "token_rejected" in r.stdout and "could not write" in r.stderr and home.token not in r.stderr


def test_version_line_matches_the_package():
    from interlockd import __version__

    assert f'VERSION = "{__version__}"' in PY_SHIM.read_text(encoding="utf-8")


# ---- the rest of the stub case matrix (Req 1.5-1.9, 2.2-2.9, 3.6-3.14, 4.5-4.9, 5.10, 12.4, 14.6) ----------------

TS = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
DEAD = "127.0.0.1:9"
OLD_PY = SHIMS_018 / "py" / "interlock-hook.py"
DENY = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}'
TOOL = {"claude-code": "Bash", "codex": "Bash", "antigravity": "Bash", "cursor": "Shell",
        "gemini-cli": "run_shell_command", "kiro": "execute_bash", "copilot-cli": "?", "windsurf": "?"}


def _post_arg(arg: str) -> str:
    return "post" if arg else ""


def _no_opinion(harness: str, post: bool) -> tuple[int, str]:
    """(exit status, stdout) of the harness's "no opinion" response (adapters/<harness>/PAYLOADS.md)."""
    if harness == "cursor" and not post:
        return 1, ""
    if harness == "antigravity":
        return 0, ("{}\n" if post else '{"decision":"allow"}\n')
    return 0, ""


def _go(stub_home, harness="claude-code", post=False, arg="", payload=None, url=None, **env):
    home, _ = stub_home
    shim = install_shim(PY_SHIM, harness, home)
    return run_shim(shim, payload or _payload(harness, post), home, arg=arg, url=url,
                    env={k: str(v) for k, v in env.items()} or None)


def _down(home: ShimHome) -> None:
    home.write_daemon_json(DEAD)


PY_018 = [c for c in load_recording("py")["cases"] if c["case"] in ("pre-allow", "pre-ask", "pre-block")]


@pytest.mark.parametrize("transport", ["tcp", "unix"])
@pytest.mark.parametrize("case", PY_018, ids=[f"{c['harness']}/{c['case']}" for c in PY_018])
def test_verified_allow_ask_block_match_the_018_recording(case, transport):
    """Req 1.5 and 1.7: a verified reply gives the 0.1.8 shim's exact output, over TCP and over the Unix socket."""
    if transport == "tcp":
        outcome, request = play("py", case, PY_SHIM)
    else:
        if not HAVE_UNIX or os.name == "nt":
            pytest.skip("needs Unix sockets")
        home = ShimHome.create(listen=DEAD)                       # only the socket answers
        try:
            with StubDaemon(unix_socket=home.socket_path) as stub:
                stub.reply = reply_from(case["reply"], home)
                r = run_shim(install_shim(PY_SHIM, case["harness"], home), case["payload"], home, arg=case["arg"])
                outcome = {"returncode": r.returncode, "stdout": home.normalize(r.stdout),
                           "stderr": home.normalize(r.stderr), "hook_log": home.normalize(home.hook_log())}
                request = {"path": stub.requests[0].path} if len(stub.requests) == 1 else None
        finally:
            home.cleanup()
    assert outcome == case["expect"]
    assert request is not None and request["path"] == case["request"]["path"]


def _run_named(tmp_path, src: Path, sub: str, harness: str, payload: str, home, url, arg=""):
    dst = tmp_path / sub / harness / src.name
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(src.read_text(encoding="utf-8").replace("__HARNESS__", harness), encoding="utf-8")
    return _run([sys.executable, "-I", "-S", str(dst), *([arg] if arg else [])], payload, home, url, tmp_path,
                INTERLOCK_FAIL_MODE="")


@pytest.mark.parametrize("path", CASES, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_018_fixture_shim_against_the_new_api_server(server, daemon_home, tmp_path, path):
    """Req 1.9: the 0.1.8 shim ignores the identity header, so it applies the new daemon's replies exactly as the
    current shim (which verifies the header) does."""
    harness = path.parent.name
    payload = path.read_text(encoding="utf-8")
    arg = ("post" if path.stem.startswith("post-") else "pre") if harness in NEEDS_ARG else ""
    old = _run_named(tmp_path, OLD_PY, "old", harness, payload, daemon_home, _url(server), arg)
    new = _run_named(tmp_path, PY_SHIM, "new", harness, payload, daemon_home, _url(server), arg)
    assert old == new
    assert not (daemon_home / "hook.log").exists()


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("harness,arg", HARNESS_ARGS)
def test_token_rejected_per_harness(stub_home, harness, arg, status):
    """Req 2.2, 2.3, 2.8: refused through each harness's channel on pre, logged with no opinion on post."""
    home, stub = stub_home
    stub.set(status=status, body='{"error":"unauthorized"}')        # 401/403 is classified before the identity
    r = _go(stub_home, harness, arg=arg)
    msg = _refused(harness, r.returncode, r.stdout, r.stderr)
    assert one_keyword(msg) == "token_rejected" and f"at {stub.url} " in msg and "interlock doctor" in msg
    r = _go(stub_home, harness, post=True, arg=_post_arg(arg))
    assert (r.returncode, r.stdout) == _no_opinion(harness, True) and r.stderr == ""
    lines = home.hook_log().splitlines()
    for line, kind in zip(lines, ("pre", "post"), strict=True):
        assert re.fullmatch(rf"{TS} tamper token_rejected harness={harness} tool={re.escape(TOOL[harness])} "
                            rf"kind={kind} addr={re.escape(stub.url)} status={status} fail_mode=closed", line), line
    assert home.token not in home.hook_log() + msg


@pytest.mark.parametrize("ids", [["$ID", "f" * 32], ["$ID-x"], [" $ID x"]], ids=["two-different", "suffixed", "padded"])
def test_identity_header_must_be_exactly_the_home_identity(stub_home, ids):
    home, stub = stub_home
    stub.set(status=200, body=DENY, identity=[v.replace("$ID", home.identity) for v in ids])
    r = _go(stub_home)
    reason = json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
    assert one_keyword(reason) == "daemon_identity" and " tamper daemon_identity " in home.hook_log()


@pytest.mark.parametrize("harness,arg", [h for h in HARNESS_ARGS if h[0] in ("codex", "gemini-cli", "copilot-cli",
                                                                              "antigravity")])
def test_missing_identity_file_refuses_every_harness(stub_home, harness, arg):
    """Req 1.6: deleting <Home>/identity cannot switch verification off."""
    home, stub = stub_home
    (home.path / "identity").unlink()
    stub.set(status=200, body="", identity=[home.identity])
    r = _go(stub_home, harness, arg=arg)
    assert one_keyword(_refused(harness, r.returncode, r.stdout, r.stderr)) == "daemon_identity"
    assert re.fullmatch(rf"{TS} tamper daemon_identity harness={harness} tool={re.escape(TOOL[harness])} kind=pre "
                        rf"addr={re.escape(stub.url)} status=200 fail_mode=closed", home.hook_log().strip())


def test_unverified_post_reply_is_logged_not_applied(stub_home):
    home, stub = stub_home
    stub.set(status=200, body='{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"X"}}')
    r = _go(stub_home, post=True)
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "") and " tamper daemon_identity " in home.hook_log()


def test_interlock_url_is_verified_too(stub_home):
    """Req 1.7: an explicit INTERLOCK_URL is not exempt; it wins over daemon.json and its address is logged."""
    home, stub = stub_home
    _down(home)
    stub.set(status=200, body=DENY, identity=["f" * 32])
    r = _go(stub_home, url=stub.url + "/")
    assert one_keyword(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"]) == "daemon_identity"
    assert f"addr={stub.url} status=200" in home.hook_log() and len(stub.requests) == 1
    (home.path / "daemon.json").unlink()                             # INTERLOCK_URL works without daemon.json
    stub.set(status=200, body=DENY, identity=[home.identity])
    r = _go(stub_home, url=stub.url)
    assert (r.returncode, r.stdout) == (0, DENY + "\n") and len(stub.requests) == 2


@pytest.mark.parametrize("marker,outcome", [
    (marker_text(restart_marker(4_000_000_000)), "restarting"),
    (marker_text(restart_marker(1_000)), "daemon_lost"),                # expired
    ("{not json", "daemon_lost"),
    ("", "daemon_lost"),
    (marker_text({"action": "stop", "pid": 1}), "daemon_lost"),         # no written_at
    (marker_text({**STOP, "action": ""}), "daemon_lost"),
    (marker_text(restart_marker("soon")), "daemon_lost"),               # expiry not an integer
    ('{"action": "stop", "written_at": "x"' + " " * 70_000 + "}\n", "daemon_lost"),   # above 64 KiB
], ids=["restart-future", "restart-expired", "garbage", "empty", "no-written-at", "empty-action", "bad-expiry",
        "oversize"])
@pytest.mark.parametrize("default", ["open", "closed"])
def test_unreachable_daemon_is_classified_by_the_stop_marker(stub_home, marker, outcome, default):
    """Req 3.6-3.9, 3.11 (absent and `stop` markers: test_daemon_lost_fails_closed, test_operator_stop_...)."""
    home, _ = stub_home
    _down(home)
    home.write_fail_mode({"default": default, "tamper": "closed"})
    home.write("stop-marker.json", marker)
    r = _go(stub_home, payload=PRE_CLAUDE)
    reason = json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"] if r.stdout else ""
    (line,) = home.hook_log().splitlines()
    if outcome == "daemon_lost":
        assert reason == (f"[interlock] This action was NOT executed: Interlock daemon stopped unexpectedly "
                          f"(daemon_lost). Home: {home.path}. Run `interlock doctor`, then `interlock start`.")
        assert re.fullmatch(rf"{TS} tamper daemon_lost harness=claude-code tool=Bash kind=pre "
                            rf"addr=http://{re.escape(DEAD)} status=- fail_mode=closed", line), line
    else:
        assert ("daemon is unreachable" in reason) == (default == "closed") and "daemon_lost" not in reason
        assert re.fullmatch(rf"{TS} unjudged why=restarting harness=claude-code tool=Bash kind=pre "
                            rf"addr=http://{re.escape(DEAD)} fail_mode={default}", line), line
    assert "git push" not in line and r.stderr == ""


@pytest.mark.parametrize("how", ["timeout", "dropped", "no-daemon-json"])
def test_timeout_dropped_connection_and_no_daemon_json_are_a_loss(stub_home, how):
    """Req 3.13: each counts as unreachable; with no daemon.json the shim sends nothing at all."""
    home, stub = stub_home
    if how == "timeout":
        stub.set(status=200, body=DENY, identity=[home.identity], delay_s=3)
    elif how == "dropped":
        stub.set(close_without_reply=True)
    else:
        (home.path / "daemon.json").unlink()
        stub.set(status=200, body=DENY, identity=[home.identity])
    r = _go(stub_home, INTERLOCK_PRE_TIMEOUT_MS=400)
    assert one_keyword(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"]) == "daemon_lost"
    assert " tamper daemon_lost " in home.hook_log() and "status=-" in home.hook_log()
    assert (stub.requests == []) == (how == "no-daemon-json")


def test_stop_marker_is_ignored_while_the_daemon_answers(stub_home):
    """Req 3.14."""
    home, stub = stub_home
    home.write("stop-marker.json", marker_text(STOP))
    stub.set(status=200, body=DENY, identity=[home.identity])
    r = _go(stub_home)
    assert (r.returncode, r.stdout, home.hook_log()) == (0, DENY + "\n", "")


def test_post_tool_loss_only_logs(stub_home):
    home, _ = stub_home
    _down(home)
    r = _go(stub_home, post=True)
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
    assert " tamper daemon_lost harness=claude-code tool=Bash kind=post " in home.hook_log()


@pytest.mark.parametrize("content,mode", [
    (None, "closed"),
    ("{garbage", "closed"),
    ('{\n  "default": "open"\n}\n', "closed"),
    ('{\n  "default": "open",\n  "tamper": "maybe"\n}\n', "closed"),
    ('{\n  "default": "open",\n  "tamper": "open"\n}\n', "open"),
    ('{"default": "open", "tamper": "open"}', "open"),
    ('{\n  "tamper": "open",\n' + '  "x": "' + "y" * 70_000 + '"\n}\n', "closed"),   # above 64 KiB
    ("<dir>", "closed"),
], ids=["absent", "garbage", "no-tamper", "invalid", "open", "one-line-open", "oversize", "directory"])
def test_tamper_fail_mode_from_the_file(stub_home, content, mode):
    """Req 4.5, 4.7, 12.4."""
    home, stub = stub_home
    (home.path / "fail-mode.json").unlink()
    if content == "<dir>":
        (home.path / "fail-mode.json").mkdir()
    elif content is not None:
        home.write("fail-mode.json", content)
    stub.set(status=200, body=DENY, identity=["f" * 32])
    r = _go(stub_home)
    if mode == "closed":
        assert r.returncode == 0 and one_keyword(r.stdout) == "daemon_identity"
    else:
        assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
    assert home.hook_log().splitlines()[0].endswith(f"fail_mode={mode}")


def test_tamper_open_post_and_pre_give_no_opinion_and_log(stub_home):
    """Req 4.5, 4.6: no opinion on pre (tamper open) and on post (either value), the cause logged each time."""
    home, stub = stub_home
    home.write_fail_mode({"default": "closed", "tamper": "open"})
    stub.set(status=403, body="")
    for harness, arg in HARNESS_ARGS:
        r = _go(stub_home, harness, arg=arg)
        assert (r.returncode, r.stdout) == _no_opinion(harness, False) and r.stderr == "", harness
    home.write_fail_mode({"default": "closed", "tamper": "closed"})
    r = _go(stub_home, post=True)
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
    lines = home.hook_log().splitlines()
    assert len(lines) == len(HARNESS_ARGS) + 1 and all(" tamper token_rejected " in ln for ln in lines)
    assert all(ln.endswith("fail_mode=open") for ln in lines[:-1]) and lines[-1].endswith("fail_mode=closed")


@pytest.mark.parametrize("value", ["open", "", "OPEN", "closed "])
def test_env_other_than_closed_is_ignored(stub_home, value):
    """Req 4.9: no INTERLOCK_FAIL_MODE value loosens either mode; `closed` tightens both (Req 4.8)."""
    home, stub = stub_home
    stub.set(status=200, body=DENY, identity=[])
    assert one_keyword(_go(stub_home, INTERLOCK_FAIL_MODE=value).stdout) == "daemon_identity"
    home.write_fail_mode({"default": "closed", "tamper": "open"})
    assert _go(stub_home, INTERLOCK_FAIL_MODE=value).stdout == ""
    assert one_keyword(_go(stub_home, INTERLOCK_FAIL_MODE="closed").stdout) == "daemon_identity"
    stub.set(status=500, body="boom", identity=[home.identity])          # a non-tamper cause: fail_mode.default
    assert "daemon is unreachable" in _go(stub_home, INTERLOCK_FAIL_MODE=value).stdout
    home.write_fail_mode({"default": "open", "tamper": "open"})
    assert _go(stub_home, INTERLOCK_FAIL_MODE=value).stdout == ""
    assert "daemon is unreachable" in _go(stub_home, INTERLOCK_FAIL_MODE="closed").stdout


@pytest.mark.parametrize("name,content,want", [
    ("daemon.json", "", "daemon_lost"),
    ("daemon.json", '{"listen": "$LISTEN", "pid": 1, "x": "' + "y" * 70_000 + '"}\n', "daemon_lost"),
    ("daemon.json", "<dir>", "daemon_lost"),
    ("identity", "", "daemon_identity"),
    ("identity", "not-an-identity\n", "daemon_identity"),
    ("identity", "$ID" + "\n" * 70_000, "daemon_identity"),
    ("identity", "<dir>", "daemon_identity"),
    ("stop-marker.json", "<dir>", "daemon_lost"),
], ids=["daemon-empty", "daemon-oversize", "daemon-dir", "identity-empty", "identity-garbage", "identity-oversize",
        "identity-dir", "marker-dir"])
def test_garbage_state_files_count_as_absent(stub_home, name, content, want):
    """Req 12.4: an empty, oversize, unreadable or garbage state file behaves like an absent one, quietly."""
    home, stub = stub_home
    stub.set(status=200, body=DENY, identity=[home.identity])
    if name == "stop-marker.json":
        _down(home)
    (home.path / name).unlink(missing_ok=True)
    if content == "<dir>":
        (home.path / name).mkdir()
    else:
        home.write(name, content.replace("$LISTEN", stub.listen).replace("$ID", home.identity))
    r = _go(stub_home)
    assert r.returncode == 0 and r.stderr == "" and one_keyword(r.stdout) == want
    assert (stub.requests == []) == (name != "identity")               # daemon.json bad or daemon down: no request
    (line,) = home.hook_log().splitlines()
    assert f" tamper {want} " in line and home.identity not in line


def test_garbage_token_file_is_inert(stub_home):
    """Req 1.11, 12.4: an unreadable token behaves like a missing one: inert, no request, no tamper line."""
    home, stub = stub_home
    (home.path / "token").unlink()
    (home.path / "token").mkdir()
    stub.set(status=401)
    r = _go(stub_home)
    assert (r.returncode, r.stdout, r.stderr, stub.requests) == (0, "", "", [])
    (line,) = home.hook_log().splitlines()
    assert line.endswith(f"inert: no token at {home.path / 'token'}") and "tamper" not in line


@pytest.mark.parametrize("harness,arg", [("kiro", ""), ("windsurf", "pre"), ("cursor", "")])
def test_shim_path_in_the_request_body(stub_home, harness, arg):
    """Req 5.10: every harness's adapter block carries the absolute path of the file that ran."""
    home, stub = stub_home
    stub.set(status=200, body="allow enforce 0\n\n" if harness in ("kiro", "windsurf") else "",
             identity=[home.identity])
    shim = install_shim(PY_SHIM, harness, home)
    run_shim(shim, _payload(harness, False), home, arg=arg)
    (req,) = stub.requests
    adapter = req.json()["adapter"]
    assert adapter["name"] == harness and Path(adapter["shim"]).is_absolute()
    assert Path(adapter["shim"]).resolve() == shim.resolve()
    assert req.json()["payload"] == json.loads(_payload(harness, False))


@pytest.mark.parametrize("cause", ["token_rejected", "daemon_lost"])
def test_unwritable_hook_log_still_refuses_on_stderr_channels(stub_home, cause):
    """Req 2.9: the refusal still reaches Kiro (stderr, exit 2) and the stderr note names the log, nothing else."""
    home, stub = stub_home
    (home.path / "hook.log").mkdir()
    if cause == "daemon_lost":
        _down(home)
    else:
        stub.set(status=401)
    r = _go(stub_home, "kiro")
    assert r.returncode == 2 and r.stdout == "" and one_keyword(r.stderr) == cause
    assert r.stderr.startswith(f"[interlock] could not write {home.path / 'hook.log'}\n")
    assert home.token not in r.stderr and "execute_bash" not in r.stderr
    r = _go(stub_home, "kiro", post=True)                                # post: the note only, no refusal
    assert (r.returncode, r.stdout, r.stderr) == (0, "", f"[interlock] could not write {home.path / 'hook.log'}\n")
