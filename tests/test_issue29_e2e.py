"""End-to-end reproduction of issue #29: a foreign daemon answering on this home's configured port.

Home A installs a shim and starts its daemon on a free loopback port. That daemon goes away and Home B's daemon
binds the same port, so Home A's `daemon.json` now points at a process that serves another home. Before
hook-tamper-detection the shim read B's 401 as "daemon down" and `fail_mode.default: open` let the call through.
Now (Requirements 1.6, 2.1-2.4, 4.4, 4.5) the shim refuses the call through the harness's refusal channel with
exactly one cause keyword and logs one `tamper` line, and Home B records `control.token_rejected` without the
presented token. The daemon-loss cases (3.6, 3.8, 3.9) stop Home A's daemon with and without an `interlock stop`
marker.

Every daemon here is a real `ApiServer` wired like `interlock serve`: its token, identity and `daemon.json` in its
own temporary home, `daemon.tamper = TokenRejections(daemon)`, operator actions. It binds 127.0.0.1 on an
OS-assigned port; neither the real home nor port 7391 is used.
"""

from __future__ import annotations

import json
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from shim_stub import CURRENT_SHIMS, HAVE_SH, ShimHome, ShimResult, install_shim, run_shim

from interlockd import failmode, lifecycle
from interlockd import identity as identity_mod
from interlockd.api import ApiServer
from interlockd.config import Settings

TOKEN_A = "home-a-fixture-token-not-a-secret-0001"
TOKEN_B = "home-b-fixture-token-not-a-secret-0002"
COMMAND = "ls -la issue29-marker-dir"            # tool arguments: must never reach a log line or a refusal message
WS = "/ws/proj"
KEYWORDS = ("token_rejected", "daemon_identity", "daemon_lost", "enforcement_point")
TS = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
REAL_PORT = 7391
UNREACHABLE = ("[interlock] This action was NOT executed: the Interlock daemon is unreachable and this workspace "
               "fails closed. Start it with `interlock start`, then retry.")

# (runtime, shim template, harness). Claude Code refuses with a deny decision on stdout and exit 0
# (adapters/claude-code/PAYLOADS.md, "Tamper refusals"); Kiro with the message on stderr and exit 2
# (adapters/kiro/PAYLOADS.md §9).
SHIMS = {
    "py-claude-code": ("py", CURRENT_SHIMS / "py" / "interlock-hook.py", "claude-code"),
    "sh-claude-code": ("sh", CURRENT_SHIMS / "claude-code" / "interlock-hook.sh", "claude-code"),
    "py-kiro": ("py", CURRENT_SHIMS / "py" / "interlock-hook.py", "kiro"),
    "sh-kiro": ("sh", CURRENT_SHIMS / "kiro" / "interlock-hook.sh", "kiro"),
}
TOOL = {"claude-code": "Bash", "kiro": "execute_bash"}


def pre_payload(harness: str) -> str:
    return json.dumps({"session_id": "s29", "hook_event_name": "PreToolUse", "cwd": WS, "tool_name": TOOL[harness],
                       "tool_input": {"command": COMMAND}}, separators=(",", ":"))


def one_keyword(text: str) -> str:
    """The single tamper keyword in `text`, asserting exactly one keyword occurs exactly once."""
    found = {k: text.count(k) for k in KEYWORDS if k in text}
    assert len(found) == 1 and list(found.values()) == [1], (found, text)
    return next(iter(found))


def refusal_message(harness: str, r: ShimResult) -> str:
    """The refusal text from the harness's documented refusal channel; asserts the channel and exit status."""
    if harness == "kiro":
        assert (r.returncode, r.stdout) == (2, ""), r
        assert r.stderr.endswith("\n") and r.stderr.count("\n") == 1, r.stderr
        return r.stderr.rstrip("\n")
    assert (r.returncode, r.stderr) == (0, ""), r
    doc = json.loads(r.stdout)
    out = doc["hookSpecificOutput"]
    assert set(out) == {"hookEventName", "permissionDecision", "permissionDecisionReason"}, doc
    assert (out["hookEventName"], out["permissionDecision"]) == ("PreToolUse", "deny"), doc
    return out["permissionDecisionReason"]


def assert_no_opinion(harness: str, r: ShimResult) -> None:
    """Claude Code and Kiro: no output, exit 0 (PAYLOADS.md: `fail_mode.tamper: open`)."""
    assert (r.returncode, r.stdout, r.stderr) == (0, "", ""), r


def token_fragments(token: str, n: int = 8) -> set[str]:
    return {token[i:i + n] for i in range(len(token) - n + 1)}


# ---- daemons ------------------------------------------------------------------------------------------------------

@dataclass
class HomeDaemon:
    settings: Settings
    daemon: object
    api: ApiServer
    stopped: bool = False

    @property
    def port(self) -> int:
        return self.api.address[1]

    @property
    def listen(self) -> str:
        return "{}:{}".format(*self.api.address)

    def records(self, record: str) -> list[dict]:
        return [r for r in self.daemon.spool.iter_records(reverse=False)
                if r.get("kind") == "control" and r.get("arguments", {}).get("record") == record]

    def stop(self) -> None:
        if not self.stopped:
            self.stopped = True
            self.api.shutdown()


def _bind(daemon, token: str, port: int) -> ApiServer:
    """An ApiServer on 127.0.0.1:`port` (0: any free port). Rebinding a port just released by another ApiServer
    can briefly fail with EADDRINUSE; retry for up to 5 s, then skip (something else took the port)."""
    deadline = time.monotonic() + 5.0
    while True:
        try:
            return ApiServer(daemon, token, "127.0.0.1", port)
        except OSError as e:
            if port == 0 or time.monotonic() > deadline:
                if port:
                    pytest.skip(f"could not rebind 127.0.0.1:{port} for the foreign daemon: {e}")
                raise
            time.sleep(0.05)


def start_daemon(home: Path, token: str, *, port: int = 0) -> HomeDaemon:
    """A daemon serving `home`, wired as `interlock serve` does for this feature: token file, identity file written
    before serving, daemon.json, token-rejection recorder and operator actions."""
    from interlockd.operator import OperatorActions
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool
    from interlockd.tamper import TokenRejections

    home.mkdir(mode=0o700, exist_ok=True)
    s = Settings(home=home)
    s.workspace_roots = [WS]
    s.token_path.write_text(token + "\n", encoding="utf-8")
    s.token_path.chmod(0o600)
    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = [WS]
    d = Daemon(s, spool=Spool(s.spool_dir), repo=MemoryRepository(), policy=pol)
    d.operator_actions = OperatorActions(d.spool)
    d.tamper = TokenRejections(d)
    api = _bind(d, token, port)
    assert api.address[0] == "127.0.0.1" and api.address[1] != REAL_PORT
    identity_mod.write(home, api.identity)
    s.listen = "{}:{}".format(*api.address)
    assert lifecycle.write_daemon_json(home, lifecycle.daemon_json_doc(s.listen))
    api.start_background()
    return HomeDaemon(s, d, api)


def wait_closed(port: int, timeout: float = 5.0) -> None:
    """Until nothing accepts on 127.0.0.1:`port` (shutdown has fully released the listener)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                pass
        except OSError:
            return
        time.sleep(0.05)
    raise AssertionError(f"127.0.0.1:{port} still accepts connections")


@pytest.fixture(params=list(SHIMS))
def shim_case(request):
    runtime, template, harness = SHIMS[request.param]
    if runtime == "sh" and not HAVE_SH:
        pytest.skip("sh and curl are required for the POSIX sh shim")
    return template, harness


@pytest.fixture
def scenario(tmp_path):
    """Home A (a ShimHome, so shims run with INTERLOCK_HOME=A) and a list collecting every daemon to stop."""
    home_a = ShimHome.create(token=TOKEN_A, identity=None, fail_mode=None)
    daemons: list[HomeDaemon] = []
    try:
        yield home_a, daemons, tmp_path
    finally:
        for d in daemons:
            d.stop()
        home_a.cleanup()


def setup_home_a(home_a: ShimHome, daemons: list[HomeDaemon], template: Path, harness: str, *,
                 default: str = "open", tamper: str = "closed") -> tuple[HomeDaemon, Path]:
    """Home A's fail modes as `interlock init` writes them, its daemon running and its shim installed; one verified
    call proves the setup before anything is broken."""
    failmode.write(home_a.path, {"default": default}, {"tamper": tamper})
    a = start_daemon(home_a.path, TOKEN_A)
    daemons.append(a)
    home_a.identity = (home_a.path / "identity").read_text(encoding="utf-8").strip()
    shim = install_shim(template, harness, home_a)
    r = run_shim(shim, pre_payload(harness), home_a)
    assert home_a.hook_log() == "", home_a.hook_log()                 # a verified reply from this home's daemon
    assert "NOT executed" not in r.stdout + r.stderr, r
    return a, shim


def tamper_line(home: ShimHome, cause: str, harness: str, addr: str, status: str, fail_mode: str) -> str:
    (line,) = home.hook_log().splitlines()
    assert re.fullmatch(rf"{TS} tamper {cause} harness={harness} tool={TOOL[harness]} kind=pre "
                        rf"addr={re.escape(addr)} status={status} fail_mode={fail_mode}", line), line
    return line


def assert_no_leak(home: ShimHome, *texts: str) -> None:
    blob = "\n".join((home.hook_log(), *texts))
    assert COMMAND not in blob and TOKEN_A not in blob and TOKEN_B not in blob
    assert home.identity not in blob


# ---- the #29 scenario: another home's daemon on this home's port --------------------------------------------------

def test_foreign_daemon_with_another_token_is_refused_as_token_rejected(scenario, shim_case):
    """The #29 failure: B answers A's token with 401. A's shim refuses (2.1, 2.2, 4.4) and logs one line (2.3);
    B records control.token_rejected with A's adapter name and no fragment of A's token (2.4)."""
    template, harness = shim_case
    home_a, daemons, tmp = scenario
    a, shim = setup_home_a(home_a, daemons, template, harness)
    port = a.port
    a.stop()                                                          # killed: no marker, no clean exit
    wait_closed(port)
    b = start_daemon(tmp / "home-b", TOKEN_B, port=port)
    daemons.append(b)
    assert b.port == port and b.settings.home != home_a.path

    r = run_shim(shim, pre_payload(harness), home_a)
    addr = f"http://127.0.0.1:{port}"
    msg = refusal_message(harness, r)
    assert one_keyword(msg) == "token_rejected"
    assert msg == (f"[interlock] This action was NOT executed: the process at {addr} rejected this hook's token "
                   "(token_rejected). Run `interlock doctor`.")
    tamper_line(home_a, "token_rejected", harness, addr, "401", "closed")
    assert_no_leak(home_a, r.stdout, r.stderr)

    (rec,) = b.records("token_rejected")
    assert rec["arguments"]["adapter"] == harness
    assert rec["arguments"]["addr"] == f"127.0.0.1:{port}"
    assert rec["disposition"] == "flag" and rec["arguments"].get("tamper_kind", "token_rejected") == "token_rejected"
    spool_text = json.dumps(list(b.daemon.spool.iter_records(reverse=False)))
    assert not any(f in spool_text for f in token_fragments(TOKEN_A))
    assert not any(f in spool_text for f in token_fragments(TOKEN_B))


def test_foreign_daemon_with_tamper_fail_mode_open_gives_no_opinion(scenario, shim_case):
    """`fail_mode.tamper: open`: the shim logs the cause and returns the harness's no-opinion response (4.5); the
    foreign daemon still records the rejection."""
    template, harness = shim_case
    home_a, daemons, tmp = scenario
    a, shim = setup_home_a(home_a, daemons, template, harness, default="closed", tamper="open")
    port = a.port
    a.stop()
    wait_closed(port)
    b = start_daemon(tmp / "home-b", TOKEN_B, port=port)
    daemons.append(b)

    r = run_shim(shim, pre_payload(harness), home_a)
    assert_no_opinion(harness, r)
    tamper_line(home_a, "token_rejected", harness, f"http://127.0.0.1:{port}", "401", "open")
    assert_no_leak(home_a, r.stdout, r.stderr)
    (rec,) = b.records("token_rejected")
    assert rec["arguments"]["adapter"] == harness


def test_foreign_daemon_holding_the_same_token_is_refused_as_daemon_identity(scenario, shim_case):
    """A copied home: B holds A's token, so it accepts the request and judges it, but its identity is not A's. No
    part of B's reply reaches the harness (1.6)."""
    template, harness = shim_case
    home_a, daemons, tmp = scenario
    a, shim = setup_home_a(home_a, daemons, template, harness)
    port = a.port
    a.stop()
    wait_closed(port)
    b = start_daemon(tmp / "home-b", TOKEN_A, port=port)
    daemons.append(b)
    assert b.api.identity != home_a.identity

    r = run_shim(shim, pre_payload(harness), home_a)
    addr = f"http://127.0.0.1:{port}"
    msg = refusal_message(harness, r)
    assert one_keyword(msg) == "daemon_identity"
    assert msg == (f"[interlock] This action was NOT executed: the process answering at {addr} is not this home's "
                   "Interlock daemon (daemon_identity). Run `interlock doctor`.")
    tamper_line(home_a, "daemon_identity", harness, addr, "200", "closed")
    assert_no_leak(home_a, r.stdout, r.stderr)
    assert b.api.identity not in home_a.hook_log() + r.stdout + r.stderr
    assert b.records("token_rejected") == []                          # B accepted the token
    assert any(rec.get("kind") != "control" for rec in b.daemon.spool.iter_records(reverse=False))   # and judged it


# ---- daemon loss versus an operator stop ---------------------------------------------------------------------------

def test_killed_daemon_without_a_marker_is_daemon_lost(scenario, shim_case):
    """No Stop_Marker: an Unexpected_Loss (3.8), refused with the cause, the Home and both repair commands (3.9),
    even though `fail_mode.default` is open."""
    template, harness = shim_case
    home_a, daemons, _ = scenario
    a, shim = setup_home_a(home_a, daemons, template, harness, default="open")
    port = a.port
    a.stop()
    wait_closed(port)
    assert not (home_a.path / lifecycle.STOP_MARKER).exists()

    r = run_shim(shim, pre_payload(harness), home_a)
    msg = refusal_message(harness, r)
    assert one_keyword(msg) == "daemon_lost"
    assert "Interlock daemon stopped unexpectedly" in msg and f"Home: {home_a.path}." in msg
    assert "`interlock doctor`" in msg and "`interlock start`" in msg
    tamper_line(home_a, "daemon_lost", harness, f"http://127.0.0.1:{port}", "-", "closed")
    assert_no_leak(home_a, r.stdout, r.stderr)


@pytest.mark.parametrize("default", ["open", "closed"])
def test_operator_stop_marker_applies_the_default_fail_mode(scenario, shim_case, default):
    """`interlock stop` writes the marker before stopping the daemon: the outcome is `unjudged operator_stopped`
    and `fail_mode.default` applies as before (3.6), with no tamper line."""
    template, harness = shim_case
    home_a, daemons, _ = scenario
    a, shim = setup_home_a(home_a, daemons, template, harness, default=default)
    port = a.port
    lifecycle.write_stop_marker(home_a.path, "stop")
    a.stop()
    assert lifecycle.mark_clean_exit(home_a.path, "stop")
    wait_closed(port)

    r = run_shim(shim, pre_payload(harness), home_a)
    if default == "open":
        assert_no_opinion(harness, r)
    else:
        msg = refusal_message(harness, r)
        assert msg == UNREACHABLE and not any(k in msg for k in KEYWORDS)
    (line,) = home_a.hook_log().splitlines()
    assert re.match(rf"{TS} unjudged why=operator_stopped harness={harness} tool={TOOL[harness]} kind=pre "
                    rf"addr={re.escape(f'http://127.0.0.1:{port}')} ", line), line
    assert line.endswith(f"fail_mode={default}") and "tamper" not in line
    assert_no_leak(home_a, r.stdout, r.stderr)
