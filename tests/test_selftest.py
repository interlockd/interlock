"""`interlock selftest` against a real daemon in every harness format; repeated runs never trip the denial budget.

The tamper-path cases (hook-tamper-detection Requirement 14.3, 14.4, 14.7-14.9) run against a private daemon in a
temporary Home and a private `ApiServer`; the `--shim` cases run shims installed into that temporary Home only.
"""

from __future__ import annotations

import json
import shutil
import socket
import sys
from pathlib import Path

import pytest

from interlockd import identity as identity_mod
from interlockd.api import ApiServer
from interlockd.selftest import (
    CASES,
    REFUSALS,
    ShimStub,
    installed_shims,
    is_selftest,
    main,
    refusal_matches,
    run,
    shim_cases,
    token_cases,
)

HARNESSES = ["claude-code", "codex", "cursor", "gemini-cli", "kiro"]
TOKEN = "selftest-fixture-token-not-a-secret"
SHIMS = Path(__file__).resolve().parents[1] / "interlockd" / "shims"
ADAPTERS = Path(__file__).resolve().parents[1] / "adapters"
FIXTURE_018_PY = Path(__file__).resolve().parent / "fixtures" / "shims-0.1.8" / "py" / "interlock-hook.py"
HAVE_SH = sys.platform != "win32" and shutil.which("sh") is not None and shutil.which("curl") is not None


@pytest.fixture
def daemon_api(settings, tmp_path):
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool

    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = [str(tmp_path)]
    d = Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol)
    api = ApiServer(d, "tok", "127.0.0.1", 0); api.start_background()
    yield "{}:{}".format(*api.address), d
    api.shutdown()


def test_selftest_all_harnesses_twice(daemon_api, tmp_path):
    listen, d = daemon_api
    for _ in range(2):                                              # the second run must not inherit denials
        rows, mode = run(listen, "tok", HARNESSES, cwd=str(tmp_path))
        assert mode == "enforce" and len(rows) == len(HARNESSES) * len(CASES)
        assert all(r.ok for r in rows), [(r.harness, r.label, r.decision) for r in rows if not r.ok]
    recs = list(d.spool.iter_records())
    assert recs and all(is_selftest(r) for r in recs)               # every event is tagged, so views can skip it


def test_shadow_reports_what_enforce_would_do(daemon_api, tmp_path):
    listen, d = daemon_api
    d.mode = "shadow"
    rows, mode = run(listen, "tok", ["claude-code"], cwd=str(tmp_path))
    assert mode == "shadow" and all(r.ok for r in rows) and rows[0].decision == "block"


def test_unreachable_daemon():
    rows, msg = run("127.0.0.1:9", "tok", ["claude-code"])
    assert rows == [] and "not reachable" in msg


# ---- the tamper path: a private daemon serving a temporary Home ---------------------------------------------------

@pytest.fixture
def private(settings, tmp_path):
    """(settings, daemon, api) for a private daemon serving the temporary Home `settings.home`, wired like
    `interlock serve` for this feature: token file, identity file, token-rejection recorder, operator actions."""
    from interlockd.operator import OperatorActions
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool
    from interlockd.tamper import TokenRejections

    settings.token_path.write_text(TOKEN + "\n", encoding="utf-8")
    settings.token_path.chmod(0o600)
    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = [str(tmp_path)]
    d = Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol)
    d.operator_actions = OperatorActions(d.spool)
    d.tamper = TokenRejections(d)
    api = ApiServer(d, TOKEN, "127.0.0.1", 0); api.start_background()
    identity_mod.write(settings.home, api.identity)
    settings.listen = "{}:{}".format(*api.address)
    (settings.home / "fail-mode.json").write_text(json.dumps({"default": "open", "tamper": "closed"}, indent=2) + "\n",
                                                  encoding="utf-8")
    yield settings, d, api
    api.shutdown()


def _records(d) -> list[dict]:
    return list(d.spool.iter_records(reverse=False))


def _control(recs, record: str) -> list[int]:
    return [i for i, r in enumerate(recs) if r.get("kind") == "control" and r["arguments"].get("record") == record]


def test_selftest_records_the_operator_action_before_any_case(private, tmp_path):
    """14.7 and 14.3: `selftest` is on the record first; then one wrong-token case per harness, each rejected and
    recorded as control.token_rejected naming the adapter. The real token never appears in the spool."""
    settings, d, _ = private
    lines: list[str] = []
    assert main(settings, "claude-code,cursor,kiro", cwd=str(tmp_path), out=lines.append) == 0, lines
    recs = _records(d)
    (action,) = _control(recs, "operator_action")
    assert recs[action]["arguments"]["action"] == "selftest"
    assert action == 0                                              # before every case's record
    rejected = _control(recs, "token_rejected")
    assert {recs[i]["arguments"]["adapter"] for i in rejected} == {"claude-code", "cursor", "kiro"}
    assert all(i > action for i in rejected)
    assert TOKEN not in json.dumps(recs)
    text = "\n".join(lines)
    assert text.count("wrong token") == 3 and "All checks passed." in text
    assert d.operator_actions.explains("token_rejected")["action"] == "selftest"     # attributed to the selftest


def test_wrong_token_case_fails_without_a_record(private, tmp_path):
    settings, d, _ = private
    d.tamper = None                                                 # a daemon that rejects but records nothing
    (case,) = token_cases(settings.listen, TOKEN, ["claude-code"], settings.spool_dir, cwd=str(tmp_path), wait_s=0.3)
    assert (case.result, case.reason) == ("fail", "no record")


def test_wrong_token_case_fails_without_a_rejection(tmp_path):
    with ShimStub() as stub:                                        # accepts any token
        (case,) = token_cases(f"127.0.0.1:{stub.port}", TOKEN, ["codex"], tmp_path / "spool", wait_s=0.3)
    assert case.result == "fail" and case.reason.startswith("no rejection")


def test_unreachable_daemon_runs_no_cases(settings):
    settings.token_path.write_text(TOKEN + "\n", encoding="utf-8")
    settings.listen = "127.0.0.1:9"
    lines: list[str] = []
    assert main(settings, "claude-code", out=lines.append) == 1
    assert len(lines) == 1 and "127.0.0.1:9" in lines[0] and "interlock start" in lines[0]
    assert not settings.spool_dir.exists() or not any(settings.spool_dir.glob("*.jsonl"))   # nothing recorded


def test_a_daemon_of_another_home_is_never_sent_the_token(private):
    """Issue #29: a process answering on the port without this Home's identity gets no case and no token."""
    settings, d, _ = private
    identity_mod.write(settings.home, "f" * 32)
    lines: list[str] = []
    assert main(settings, "claude-code", out=lines.append) == 1
    assert "daemon_identity" in lines[0] and _records(d) == []


# ---- --shim -------------------------------------------------------------------------------------------------------

def _install(home: Path, src: Path, harness: str) -> Path:
    """As `interlock init` writes a shim: <Home>/adapters/<harness>/<name>, HARNESS (and VERSION) baked in."""
    dst = home / "adapters" / harness / src.name
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(src.read_text(encoding="utf-8").replace("__HARNESS__", harness).replace("__VERSION__", "0.2.0"),
                   encoding="utf-8")
    dst.chmod(0o755)
    return dst


def _node_works() -> bool:
    import subprocess

    try:
        return shutil.which("node") is not None and subprocess.run(
            ["node", "--version"], capture_output=True, timeout=10, check=False).returncode == 0
    except OSError:
        return False


SHIM_MATRIX = [("py", "claude-code"), ("py", "cursor"), ("py", "windsurf"), ("py", "copilot-cli"),
               ("py", "antigravity"), ("py", "kiro"), ("sh", "claude-code"), ("sh", "gemini-cli"), ("kiro-sh", "kiro"),
               ("kiro-mjs", "kiro"), ("opencode", "opencode")]
SHIM_SRC = {"py": SHIMS / "py" / "interlock-hook.py", "sh": SHIMS / "claude-code" / "interlock-hook.sh",
            "kiro-sh": SHIMS / "kiro" / "interlock-hook.sh", "kiro-mjs": SHIMS / "kiro" / "interlock-hook.mjs",
            "opencode": SHIMS / "opencode" / "interlock.js"}


@pytest.mark.parametrize("runtime,harness", SHIM_MATRIX, ids=[f"{r}/{h}" for r, h in SHIM_MATRIX])
def test_shim_refuses_a_stub_without_identity(private, runtime, harness):
    """14.4: the documented refusal with `daemon_identity` and a `tamper daemon_identity` hook.log line."""
    if runtime in ("sh", "kiro-sh") and not HAVE_SH:
        pytest.skip("needs sh and curl")
    if runtime in ("kiro-mjs", "opencode") and not _node_works():
        pytest.skip("needs node")
    settings, d, _ = private
    shim = _install(settings.home, SHIM_SRC[runtime], harness)
    (case,) = shim_cases(settings.home, [(harness, shim)])
    assert (case.result, case.reason) == ("pass", "refused with daemon_identity"), case
    log = (settings.home / "hook.log").read_text(encoding="utf-8")
    assert f"tamper daemon_identity harness={harness}" in log and TOKEN not in log
    assert _records(d) == []                                        # the shim talked to the stub, not the daemon


def test_shim_that_applies_an_unverified_reply_fails(private):
    """A 0.1.8 shim ignores the identity header and applies the stub's allow: that is not a refusal."""
    settings, _, _ = private
    shim = _install(settings.home, FIXTURE_018_PY, "claude-code")
    (case,) = shim_cases(settings.home, [("claude-code", shim)])
    assert case.result == "fail" and case.reason == "not the documented refusal"


def test_shim_cases_are_skipped_when_tamper_fails_open(private):
    settings, _, _ = private
    (settings.home / "fail-mode.json").write_text('{"default": "open", "tamper": "open"}\n', encoding="utf-8")
    shim = _install(settings.home, SHIM_SRC["py"], "claude-code")
    (case,) = shim_cases(settings.home, [("claude-code", shim)])
    assert (case.result, case.reason) == ("skipped", "fail_mode.tamper is open")
    assert not (settings.home / "hook.log").exists()                # nothing was run


@pytest.mark.skipif(not HAVE_SH, reason="needs sh")
def test_a_hanging_shim_is_a_timeout(private):
    settings, _, _ = private
    shim = settings.home / "adapters" / "claude-code" / "interlock-hook.sh"
    shim.parent.mkdir(parents=True)
    shim.write_text("sleep 5\n", encoding="utf-8")
    (case,) = shim_cases(settings.home, [("claude-code", shim)], timeout_s=0.5)
    assert (case.result, case.reason) == ("fail", "timeout")


def test_missing_shim_and_empty_manifest_fail(private):
    settings, _, _ = private
    (case,) = shim_cases(settings.home, [("codex", settings.home / "adapters" / "codex" / "interlock-hook.sh")])
    assert case.result == "fail" and case.reason.startswith("shim missing")
    (case,) = shim_cases(settings.home, [])
    assert case.result == "fail" and "interlock init" in case.reason


def test_stub_is_loopback_only_sends_no_identity_and_closes_on_error():
    with pytest.raises(RuntimeError), ShimStub() as stub:
        port = stub.port
        assert stub.httpd.server_address[0] == "127.0.0.1"
        import urllib.request

        with urllib.request.urlopen(f"{stub.url}/interlock/v1/hooks/kiro?format=text", data=b"{}", timeout=5) as r:
            assert r.status == 200 and r.headers.get_all(identity_mod.HEADER) is None
            assert r.read() == b"allow enforce 0\n\n"
        raise RuntimeError("boom")
    assert stub.closed
    with pytest.raises(OSError), socket.create_connection(("127.0.0.1", port), timeout=1):
        pass


def test_main_with_shim_end_to_end(private, tmp_path):
    """`interlock selftest --shim`: the manifest's shim is run against the stub; exit 0 when every case passes."""
    from interlockd.onboard import Manifest

    settings, _, _ = private
    shim = _install(settings.home, SHIM_SRC["py"], "claude-code")
    man = Manifest(hooks=[{"harness": "claude-code", "file": str(tmp_path / "settings.json"), "marker": str(shim),
                           "created": True}])
    man.save(settings.home)
    assert installed_shims(Manifest.load(settings.home)) == [("claude-code", shim)]
    lines: list[str] = []
    assert main(settings, None, shim=True, cwd=str(tmp_path), out=lines.append) == 0, lines
    assert any("shim identity" in ln and "pass" in ln for ln in lines)


def test_main_exits_non_zero_when_a_shim_case_fails(private, tmp_path):
    from interlockd.onboard import Manifest

    settings, _, _ = private
    shim = _install(settings.home, FIXTURE_018_PY, "claude-code")
    Manifest(hooks=[{"harness": "claude-code", "file": str(tmp_path / "s.json"), "marker": str(shim),
                     "created": True}]).save(settings.home)
    lines: list[str] = []
    assert main(settings, None, shim=True, cwd=str(tmp_path), out=lines.append) == 1
    assert "1 tamper check(s) failed" in "\n".join(lines)


# ---- the refusal table matches the documentation ---------------------------------------------------------------

@pytest.mark.parametrize("harness", ["claude-code", "codex", "cursor", "gemini-cli", "copilot-cli", "windsurf",
                                     "antigravity"])
def test_refusal_table_matches_payloads_md(harness):
    from test_shim_sh import documented_refusal

    rc, channel, template = documented_refusal(harness)
    want_rc, want_channel, want_template = REFUSALS[harness]
    assert (rc, channel) == (want_rc, want_channel)
    assert template == want_template


def test_refusal_table_matches_kiro_and_opencode_docs():
    kiro = (ADAPTERS / "kiro" / "PAYLOADS.md").read_text(encoding="utf-8")
    assert "`fail_mode.tamper: closed` | exit 2, `<tamper message>` on stderr" in kiro
    assert REFUSALS["kiro"] == (2, "stderr", None)
    opencode = (ADAPTERS / "opencode" / "PAYLOADS.md").read_text(encoding="utf-8")
    assert '`throw new Error("<tamper message>")`' in opencode and REFUSALS["opencode"][1] == "throw"


@pytest.mark.parametrize("out,why", [
    ('{"decision":"deny","reason":"x (daemon_identity) y"}\n', ""),
    ('{"decision":"deny","reason":"x (daemon_lost)"}\n', "no daemon_identity keyword"),
    ('{"decision":"deny","reason":"daemon_identity daemon_identity"}\n', "no daemon_identity keyword"),
    ('{"decision":"allow"}\n', "not the documented refusal"),
    ("", "not the documented refusal"),
])
def test_refusal_matching(out, why):
    assert refusal_matches("gemini-cli", 0, out, "") == why
