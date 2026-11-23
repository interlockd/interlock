"""Property 5: Tamper messages and log lines carry exactly one keyword and no payload.

For any cause, harness, address, Home path, HTTP status and hook payload whose tool arguments contain a marker string,
the refusal message built by the shim contains exactly one occurrence of exactly one keyword from
{token_rejected, daemon_identity, daemon_lost, enforcement_point}, and the hook.log line contains the literal
`tamper <cause>`, the harness name, the tool name (or `?`), the kind, the address and the status, and contains
neither the marker, nor the token, nor the identity value.

The shim-side causes are checked on the Python shim's `tamper_message()` and `tamper()` (in-process, 100 examples)
and end to end by running the shim as a subprocess against tests/shim_stub.py (few examples). `enforcement_point`
is the daemon-side cause: its refusal text is `render.tamper_notice()`.

**Validates: Requirements 1.6, 1.10, 2.3, 3.9, 4.4, 4.10**
"""
from __future__ import annotations

import importlib.util
import io
import json
import shutil
import socket
import string
import sys
import tempfile
from pathlib import Path

from hypothesis import assume, given, settings
from hypothesis import strategies as st
from shim_stub import CURRENT_SHIMS, Reply, ShimHome, StubDaemon, install_shim, run_shim

from interlockd import render

from .strategies import (
    HARNESS_REASONS,
    PROPS,
    TAMPER_CAUSES,
    addresses,
    harnesses,
    home_paths,
    identities,
    status_codes,
)

PY_SHIM = Path(__file__).resolve().parents[2] / "interlockd" / "shims" / "py" / "interlock-hook.py"
SHIM_CAUSES = ("token_rejected", "daemon_identity", "daemon_lost")      # the causes the shim itself detects
PY_HARNESSES = ("claude-code", "codex", "cursor", "gemini-cli", "copilot-cli", "windsurf", "antigravity", "kiro")


def _load_shim():
    spec = importlib.util.spec_from_file_location("interlock_py_shim_p5", PY_SHIM)
    mod = importlib.util.module_from_spec(spec)
    before, sys.dont_write_bytecode = sys.dont_write_bytecode, True   # no __pycache__ in the packaged shims
    try:
        spec.loader.exec_module(mod)       # main() runs only as __main__
    finally:
        sys.dont_write_bytecode = before
    return mod


SHIM = _load_shim()


def keyword_hits(text: str) -> list[str]:
    """Every occurrence of every cause keyword in `text` (a keyword occurring twice appears twice)."""
    return [k for k in TAMPER_CAUSES for _ in range(text.count(k))]


def no_keyword(*texts: str) -> bool:
    return not any(keyword_hits(t) for t in texts)


# ---- strategies ---------------------------------------------------------------------------------------------------

def markers() -> st.SearchStrategy[str]:
    return st.text(alphabet="0123456789abcdef", min_size=16, max_size=16).map(lambda h: "MARK" + h)


def bearer_tokens() -> st.SearchStrategy[str]:
    """Tokens of the real shape (token_urlsafe(32)): long enough that an accidental substring match is impossible."""
    return st.text(alphabet=string.ascii_letters + string.digits + "-_", min_size=43, max_size=43)


def tool_names() -> st.SearchStrategy[str | None]:
    return st.one_of(st.none(), st.sampled_from(("Bash", "Write", "execute_bash", "Shell", "run_shell_command")),
                     st.text(alphabet=string.ascii_letters + string.digits + "_", min_size=1, max_size=20))


@st.composite
def payloads(draw, marker: str, *, post: bool) -> tuple[str, str]:
    """(payload text, the tool name the log line must show). The marker sits in tool argument values, in nested
    argument keys, in the transcript path and (post) in the tool result; `tool_name` precedes `tool_input`, the
    order the harnesses send."""
    tool = draw(tool_names())
    arg_keys = draw(st.lists(st.sampled_from(("command", "file_path", "content", "url", "query")), min_size=1,
                             max_size=3, unique=True))
    args = {k: f"{draw(st.text(max_size=8))}{marker}{draw(st.text(max_size=8))}" for k in arg_keys}
    args[f"k_{marker}"] = {"nested": marker}
    doc: dict = {"session_id": "s1", "transcript_path": f"/tmp/{marker}.jsonl",
                 "hook_event_name": "PostToolUse" if post else "PreToolUse", "cwd": "/ws/proj"}
    if tool is not None:
        doc["tool_name"] = tool
    doc["tool_input"] = args
    if post:
        doc["tool_response"] = {"stdout": marker}
    compact = draw(st.booleans())
    text = json.dumps(doc, separators=(",", ":") if compact else (", ", ": "))
    assume(tool is None or marker not in tool)
    return text, tool or "?"


# ---- refusal messages ---------------------------------------------------------------------------------------------

# Feature: hook-tamper-detection, Property 5: Tamper messages and log lines carry exactly one keyword and no payload
@PROPS
@given(st.sampled_from(SHIM_CAUSES), addresses(), home_paths())
def test_shim_refusal_message_has_exactly_one_keyword(cause, addr, home):
    assume(no_keyword(addr, home))         # a path that itself spells a keyword is outside the property
    msg = SHIM.tamper_message(cause, addr, home)
    assert keyword_hits(msg) == [cause]
    assert "`interlock doctor`" in msg
    if cause == "daemon_lost":             # Req 3.9: cause, Home path and both repair commands
        assert "Interlock daemon stopped unexpectedly" in msg
        assert home in msg and "`interlock start`" in msg
    else:
        assert addr in msg


# Feature: hook-tamper-detection, Property 5: Tamper messages and log lines carry exactly one keyword and no payload
@PROPS
@given(harnesses(), st.sampled_from(sorted(HARNESS_REASONS)), st.sampled_from(("blocked", "observed", "result")))
def test_enforcement_point_notice_has_exactly_one_keyword(harness, reason, outcome):
    notice = render.tamper_notice(harness, reason, outcome=outcome)
    assert keyword_hits(notice) == ["enforcement_point"]
    assert harness in notice and reason in notice
    assert "`interlock doctor`" in notice


# ---- the shim's tamper() path, in-process -------------------------------------------------------------------------

def _run_tamper(home_dir: Path, harness: str, payload: str, is_post: bool, cause: str, addr: str,
                status) -> tuple[int, str, str]:
    """Call the shim's tamper() with stdout/stderr captured; returns (exit code, stdout, stderr)."""
    saved_globals = SHIM.HARNESS, SHIM.HOME_DIR
    SHIM.HARNESS, SHIM.HOME_DIR = harness, str(home_dir)
    out, err = io.TextIOWrapper(io.BytesIO(), encoding="utf-8"), io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    saved = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    code = None
    try:
        SHIM.tamper(payload, is_post, cause, addr, status)
    except SystemExit as e:
        code = e.code
    finally:
        sys.stdout, sys.stderr = saved
        SHIM.HARNESS, SHIM.HOME_DIR = saved_globals
    out.flush()
    err.flush()
    assert code is not None, "tamper() must end the hook"
    return code, out.buffer.getvalue().decode("utf-8"), err.buffer.getvalue().decode("utf-8")


@st.composite
def tamper_cases(draw):
    cause = draw(st.sampled_from(SHIM_CAUSES))
    is_post = draw(st.booleans())
    marker = draw(markers())
    payload, tool = draw(payloads(marker, post=is_post))
    status = "-" if cause == "daemon_lost" else draw(
        st.sampled_from((401, 403)) if cause == "token_rejected" else status_codes().filter(lambda s: s < 400))
    return {"cause": cause, "is_post": is_post, "marker": marker, "payload": payload, "tool": tool,
            "status": status, "harness": draw(st.sampled_from(PY_HARNESSES)), "addr": draw(addresses()),
            "token": draw(bearer_tokens()), "identity": draw(identities()),
            "fail_mode": draw(st.sampled_from(("open", "closed")))}


# Feature: hook-tamper-detection, Property 5: Tamper messages and log lines carry exactly one keyword and no payload
@PROPS
@given(tamper_cases())
def test_shim_tamper_log_line_and_output(monkeypatch, case):
    monkeypatch.delenv("INTERLOCK_FAIL_MODE", raising=False)
    c = case
    assume(no_keyword(c["addr"], c["tool"]))
    home = Path(tempfile.mkdtemp(prefix="ilk-p5-"))
    try:
        (home / "token").write_text(c["token"] + "\n")
        (home / "identity").write_text(c["identity"] + "\n")
        (home / "fail-mode.json").write_text(json.dumps({"default": "open", "tamper": c["fail_mode"]}, indent=2))
        code, out, err = _run_tamper(home, c["harness"], c["payload"], c["is_post"], c["cause"], c["addr"],
                                     c["status"])
        log = (home / "hook.log").read_text(encoding="utf-8")
    finally:
        shutil.rmtree(home, ignore_errors=True)

    lines = log.splitlines()
    assert len(lines) == 1
    line = lines[0]
    fields = line.split(" ")
    assert fields[1:3] == ["tamper", c["cause"]]                     # `<ts> tamper <cause> ...`
    assert f" harness={c['harness']} " in line
    assert f" tool={c['tool']} " in line
    assert f" kind={'post' if c['is_post'] else 'pre'} " in line
    assert f" addr={c['addr']} " in line
    assert f" status={c['status']} " in line
    assert keyword_hits(line) == [c["cause"]]
    for secret in (c["marker"], c["token"], c["identity"]):
        assert secret not in line
        assert secret not in out and secret not in err

    refused = not c["is_post"] and c["fail_mode"] == "closed"
    shown = out + err
    if refused:                            # Req 4.4: the harness's refusal channel carries exactly one keyword
        assert keyword_hits(shown) == [c["cause"]]
        assert "interlock doctor" in shown
        assert code == (2 if c["harness"] in ("kiro", "windsurf") else 0)
    else:                                  # Req 4.5, 4.6: no-opinion response, nothing that names a cause
        assert keyword_hits(shown) == []


# ---- end to end: the shim as a subprocess against the stub --------------------------------------------------------

def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# Feature: hook-tamper-detection, Property 5: Tamper messages and log lines carry exactly one keyword and no payload
@settings(PROPS, max_examples=12)
@given(st.sampled_from(SHIM_CAUSES), st.sampled_from(PY_HARNESSES), st.booleans(), markers(), bearer_tokens(),
       identities(), identities(), st.data())
def test_shim_subprocess_tamper_is_content_free(cause, harness, is_post, marker, token, identity, wrong, data):
    assume(wrong != identity)
    payload, tool = data.draw(payloads(marker, post=is_post))
    assume(no_keyword(tool))
    home = ShimHome.create(token=token, identity=identity, fail_mode={"default": "open", "tamper": "closed"})
    shim = install_shim(CURRENT_SHIMS / "py" / "interlock-hook.py", harness, home)
    try:
        if cause == "daemon_lost":
            home.write_daemon_json(f"127.0.0.1:{_closed_port()}")
            r = run_shim(shim, payload, home, arg="post" if is_post else "pre")
        else:
            status = data.draw(st.sampled_from((401, 403))) if cause == "token_rejected" else 200
            ids = [wrong] if cause == "daemon_identity" else [identity]
            body = json.dumps({"hookSpecificOutput": {"permissionDecision": "allow", "reason": marker}})
            with StubDaemon(Reply(status=status, identity=ids, body=body)) as stub:
                r = run_shim(shim, payload, home, arg="post" if is_post else "pre", url=stub.url)
        log = home.hook_log()
    finally:
        home.cleanup()

    tamper_lines = [ln for ln in log.splitlines() if ln.split(" ")[1:2] == ["tamper"]]
    assert len(tamper_lines) == 1, log
    line = tamper_lines[0]
    assert line.split(" ")[2] == cause
    assert f" tool={tool} " in line and f" harness={harness} " in line
    shown = r.stdout + r.stderr
    for secret in (marker, token, identity, wrong):       # Req 1.6, 1.10, 2.3: no payload, token or identity value
        assert secret not in log
        assert secret not in shown
    if is_post:
        assert keyword_hits(shown) == []
    else:
        assert keyword_hits(shown) == [cause]
