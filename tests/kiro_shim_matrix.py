"""The Kiro shim case matrix (hook-tamper-detection Req 1-4, 5.10, 12.4, 14.6), shared by the sh shim
(tests/test_shim_sh.py) and the Node shim (tests/test_shim_kiro_mjs.py).

`KiroShimMatrix` is not collected itself; each test module subclasses it with `RUNTIME = "kiro-sh"` or
`"kiro-mjs"`. Every case runs the shim this tree ships as a subprocess against `shim_stub.StubDaemon` (no live
daemon), except the `real_daemon` cases, which run it, and the 0.1.8 fixture shim, against a real `ApiServer`.

Kiro's refusal channel (adapters/kiro/PAYLOADS.md §5) is stderr plus exit 2; "no opinion" is exit 0 with no output.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
from shim_stub import (
    CURRENT_SHIMS,
    SHIMS_018,
    ShimHome,
    ShimResult,
    StubDaemon,
    install_shim,
    run_shim,
    shim_command,
    shim_env,
)

COMMAND = "git push --force origin main"          # a marker: tool arguments must never reach a log or message
PRE = json.dumps({"session_id": "s1", "hook_event_name": "PreToolUse", "cwd": "/ws/proj", "tool_name": "execute_bash",
                  "tool_input": {"command": COMMAND}}, separators=(",", ":"))
OK = PRE.replace(COMMAND, "ls -la")
POST = json.dumps({"session_id": "s1", "hook_event_name": "PostToolUse", "cwd": "/ws/proj",
                   "tool_name": "execute_bash", "tool_input": {"command": COMMAND},
                   "tool_response": "Output:\nok\n\nExit Code: 0"}, separators=(",", ":"))
DOWN = "127.0.0.1:9"                               # nothing listens there: the daemon is "down"
KEYWORDS = ("token_rejected", "daemon_identity", "daemon_lost", "enforcement_point")
NOTICE = "[interlock] fixture notice: BODY-MARKER was refused."
UNREACHABLE = ("[interlock] This action was NOT executed: the Interlock daemon is unreachable and this workspace "
               "fails closed. Start it with `interlock start`, then retry.")
TS = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{3})?Z"

STOP = {"action": "stop", "pid": 1, "version": "0.2.0", "written_at": "2026-10-17T10:00:00Z"}


def restart_marker(expires_epoch) -> dict:
    return {"action": "restart", "expires_at": "2026-10-17T10:02:00Z", "expires_epoch": expires_epoch, "pid": 1,
            "version": "0.2.0", "written_at": "2026-10-17T10:00:00Z"}


def marker_text(doc: dict) -> str:
    """As statefile.dumps writes it: sorted keys, ", " and ": " separators, one trailing newline."""
    return json.dumps(doc, sort_keys=True, separators=(", ", ": ")) + "\n"


def one_keyword(text: str) -> str:
    """The single tamper keyword in `text`, asserting exactly one keyword occurs exactly once."""
    found = {k: text.count(k) for k in KEYWORDS if k in text}
    assert len(found) == 1 and list(found.values()) == [1], found
    return next(iter(found))


class KiroShimMatrix:
    RUNTIME = ""                                   # "kiro-sh" | "kiro-mjs"

    # ------------------------------------------------------------------------------------------- helpers

    @property
    def template(self) -> Path:
        return CURRENT_SHIMS / "kiro" / ("interlock-hook.sh" if self.RUNTIME == "kiro-sh" else "interlock-hook.mjs")

    @property
    def path(self) -> str:
        return "/interlock/v1/hooks/kiro" + ("?format=text" if self.RUNTIME == "kiro-sh" else "")

    def body(self, disposition: str, mode: str = "enforce", notice: str | None = NOTICE) -> str:
        """A verdict as the daemon renders it for this shim: text for sh, the verdict JSON for Node."""
        if self.RUNTIME == "kiro-sh":
            return f"{disposition} {mode} 2\n{notice or ''}\n"
        return json.dumps({"disposition": disposition, "mode": mode, "tier": 2, "reason": "fixture",
                           "notice": notice}, separators=(",", ":"))

    @pytest.fixture
    def env(self):
        """(home, stub, shim): a home whose daemon.json points at a running stub; tamper fail mode closed."""
        home = ShimHome.create(fail_mode={"default": "open", "tamper": "closed"})
        try:
            with StubDaemon() as stub:
                home.write_daemon_json(stub.listen)
                yield home, stub, install_shim(self.template, "kiro", home)
        finally:
            home.cleanup()

    def run(self, env, payload: str = PRE, **extra) -> ShimResult:
        home, _, shim = env
        url = extra.pop("url", None)
        return run_shim(shim, payload, home, url=url, env={k: str(v) for k, v in extra.items()} or None)

    def log_lines(self, home: ShimHome) -> list[str]:
        return home.hook_log().splitlines()

    def assert_no_leak(self, home: ShimHome, *texts: str) -> None:
        blob = "\n".join((home.hook_log(), *texts))
        assert COMMAND not in blob and home.token not in blob and home.identity not in blob

    def assert_tamper_refusal(self, env, r: ShimResult, cause: str, status: str, addr: str | None = None) -> None:
        home, stub, _ = env
        addr = addr or stub.url
        assert (r.returncode, r.stdout) == (2, "")
        assert one_keyword(r.stderr) == cause and r.stderr.endswith("\n") and r.stderr.count("\n") == 1
        if cause == "daemon_lost":
            assert r.stderr == (f"[interlock] This action was NOT executed: Interlock daemon stopped unexpectedly "
                                f"(daemon_lost). Home: {home.path}. Run `interlock doctor`, then `interlock start`.\n")
        else:
            assert f"at {addr} " in r.stderr and "Run `interlock doctor`." in r.stderr
        (line,) = self.log_lines(home)
        assert re.fullmatch(rf"{TS} tamper {cause} harness=kiro tool=execute_bash kind=pre addr={re.escape(addr)} "
                            rf"status={status} fail_mode=closed", line), line
        self.assert_no_leak(home, r.stderr)
        assert "BODY-MARKER" not in r.stderr                       # no part of an unverified reply reaches Kiro

    # ------------------------------------------------------------------------------------------- verified replies

    def test_verified_allow_applies_and_reports_the_shim_path(self, env):
        home, stub, shim = env
        stub.set(status=200, body=self.body("allow", notice=None), identity=[home.identity])
        r = self.run(env, OK)
        assert (r.returncode, r.stdout, r.stderr, home.hook_log()) == (0, "", "", "")
        (req,) = stub.requests
        assert req.path == self.path and req.header("authorization") == [f"Bearer {home.token}"]
        adapter = req.json()["adapter"]
        assert adapter["name"] == "kiro" and Path(adapter["shim"]).resolve() == shim.resolve()
        assert Path(adapter["shim"]).is_absolute() and req.json()["payload"] == json.loads(OK)

    @pytest.mark.parametrize("disposition", ["block", "ask"])
    def test_verified_block_and_ask_refuse_with_the_daemon_notice(self, env, disposition):
        home, stub, _ = env
        stub.set(status=200, body=self.body(disposition), identity=[home.identity])
        r = self.run(env)
        assert (r.returncode, r.stdout, r.stderr, home.hook_log()) == (2, "", NOTICE + "\n", "")

    def test_verified_shadow_and_post_are_not_enforced(self, env):
        home, stub, _ = env
        stub.set(status=200, body=self.body("block", "shadow"), identity=[home.identity])
        assert (self.run(env).returncode, home.hook_log()) == (0, "")
        stub.set(status=200, body=self.body("block"), identity=[home.identity])
        r = self.run(env, POST)
        assert (r.returncode, r.stdout, r.stderr, home.hook_log()) == (0, "", "", "")

    def test_stop_marker_is_ignored_while_the_daemon_answers(self, env):
        home, stub, _ = env
        home.write("stop-marker.json", marker_text(STOP))
        stub.set(status=200, body=self.body("block"), identity=[home.identity])
        r = self.run(env)
        assert (r.returncode, r.stderr, home.hook_log()) == (2, NOTICE + "\n", "")

    # ------------------------------------------------------------------------------------------- token rejection

    @pytest.mark.parametrize("status", [401, 403])
    def test_token_rejected_refuses_pre_even_with_env_open(self, env, status):
        home, stub, _ = env
        stub.set(status=status, body='{"error":"unauthorized"}', identity=[home.identity])
        r = self.run(env, INTERLOCK_FAIL_MODE="open")              # the environment cannot loosen the gate
        self.assert_tamper_refusal(env, r, "token_rejected", str(status))

    def test_token_rejected_on_post_only_logs(self, env):
        home, stub, _ = env
        stub.set(status=401, body='{"error":"unauthorized"}')      # no identity either: 401 is classified first
        r = self.run(env, POST)
        assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
        (line,) = self.log_lines(home)
        assert re.fullmatch(rf"{TS} tamper token_rejected harness=kiro tool=execute_bash kind=post "
                            rf"addr={re.escape(stub.url)} status=401 fail_mode=closed", line), line
        self.assert_no_leak(home)

    # ------------------------------------------------------------------------------------------- daemon identity

    @pytest.mark.parametrize("ids", [[], ["f" * 32], ["$ID", "$ID"], ["$ID", "f" * 32], ["$ID-x"]],
                             ids=["missing", "wrong", "duplicated", "two-different", "suffixed"])
    @pytest.mark.parametrize("disposition", ["allow", "block"])
    def test_unverified_reply_is_never_applied(self, env, ids, disposition):
        home, stub, _ = env
        stub.set(status=200, body=self.body(disposition),
                 identity=[v.replace("$ID", home.identity) for v in ids])
        self.assert_tamper_refusal(env, self.run(env), "daemon_identity", "200")

    def test_missing_identity_file_fails_verification(self, env):
        home, stub, _ = env
        (home.path / "identity").unlink()
        stub.set(status=200, body=self.body("allow", notice=None), identity=[home.identity])
        self.assert_tamper_refusal(env, self.run(env, OK), "daemon_identity", "200")

    def test_interlock_url_is_verified_too(self, env):
        home, stub, _ = env
        home.write_daemon_json(DOWN)                               # only the explicit URL answers
        stub.set(status=200, body=self.body("allow", notice=None), identity=["f" * 32])
        self.assert_tamper_refusal(env, self.run(env, OK, url=stub.url + "/"), "daemon_identity", "200")
        (home.path / "hook.log").unlink()
        stub.set(status=200, body=self.body("block"), identity=[home.identity])
        r = self.run(env, url=stub.url)
        assert (r.returncode, r.stderr, home.hook_log()) == (2, NOTICE + "\n", "")

    def test_tamper_open_logs_and_gives_no_opinion(self, env):
        home, stub, _ = env
        home.write_fail_mode({"default": "closed", "tamper": "open"})
        stub.set(status=200, body=self.body("block"), identity=[])
        r = self.run(env)
        assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
        (line,) = self.log_lines(home)
        assert " tamper daemon_identity " in line and line.endswith("status=200 fail_mode=open")

    # ------------------------------------------------------------------------------------------- other HTTP errors

    def test_other_http_errors_use_the_default_fail_mode(self, env):
        home, stub, _ = env
        stub.set(status=500, body="boom", identity=[home.identity])
        r = self.run(env)
        assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
        home.write_fail_mode({"default": "closed", "tamper": "open"})
        r = self.run(env)
        assert (r.returncode, r.stderr) == (2, UNREACHABLE + "\n")
        lines = self.log_lines(home)
        assert [ln.split(" ", 1)[1] for ln in lines] == [
            f"unjudged why=http_500 harness=kiro tool=execute_bash kind=pre addr={stub.url} fail_mode={m}"
            for m in ("open", "closed")]

    def test_env_closed_tightens_the_default_fail_mode(self, env):
        home, stub, _ = env
        stub.set(status=500, body="boom", identity=[home.identity])
        r = self.run(env, INTERLOCK_FAIL_MODE="closed")
        assert (r.returncode, r.stderr) == (2, UNREACHABLE + "\n")

    # ------------------------------------------------------------------------------------------- unreachable daemon

    @pytest.mark.parametrize("marker,outcome", [
        (None, "daemon_lost"),
        (marker_text(STOP), "operator_stopped"),
        (marker_text(restart_marker(4_000_000_000)), "restarting"),
        (marker_text(restart_marker(1_000)), "daemon_lost"),          # expired
        ("{not json", "daemon_lost"),
        ("", "daemon_lost"),
        (marker_text({"action": "stop", "pid": 1}), "daemon_lost"),   # no written_at
        (marker_text({**STOP, "action": ""}), "daemon_lost"),
        (marker_text(restart_marker("soon")), "daemon_lost"),         # expiry not an integer
        ('{"action": "stop", "written_at": "x"' + ' ' * 70_000 + "}\n", "daemon_lost"),   # above 64 KiB
    ], ids=["absent", "stop", "restart-future", "restart-expired", "garbage", "empty", "no-written-at",
            "empty-action", "bad-expiry", "oversize"])
    @pytest.mark.parametrize("default", ["open", "closed"])
    def test_unreachable_daemon_is_classified_by_the_stop_marker(self, env, marker, outcome, default):
        home, _, _ = env
        home.write_daemon_json(DOWN)
        home.write_fail_mode({"default": default, "tamper": "closed"})
        if marker is not None:
            home.write("stop-marker.json", marker)
        r = self.run(env)
        if outcome == "daemon_lost":
            self.assert_tamper_refusal(env, r, "daemon_lost", "-", addr=f"http://{DOWN}")
            return
        assert r.stdout == "" and (r.returncode, r.stderr) == ((2, UNREACHABLE + "\n") if default == "closed"
                                                               else (0, ""))
        (line,) = self.log_lines(home)
        assert re.fullmatch(rf"{TS} unjudged why={outcome} harness=kiro tool=execute_bash kind=pre "
                            rf"addr=http://{re.escape(DOWN)} fail_mode={default}", line), line

    def test_no_daemon_json_means_unreachable_without_a_request(self, env):
        home, stub, _ = env
        (home.path / "daemon.json").unlink()
        stub.set(status=200, body=self.body("allow", notice=None), identity=[home.identity])
        r = self.run(env)
        assert stub.requests == [] and (r.returncode, r.stdout) == (2, "") and one_keyword(r.stderr) == "daemon_lost"
        (home.path / "hook.log").unlink()
        home.write("stop-marker.json", marker_text(STOP))
        r = self.run(env)
        assert r.returncode == 0 and "unjudged why=operator_stopped" in home.hook_log()

    @pytest.mark.parametrize("how", ["timeout", "dropped"])
    def test_timeout_and_dropped_connection_are_a_loss(self, env, how):
        home, stub, _ = env
        if how == "timeout":
            stub.set(status=200, body=self.body("allow", notice=None), identity=[home.identity], delay_s=3)
        else:
            stub.set(close_without_reply=True)
        r = self.run(env, INTERLOCK_PRE_TIMEOUT_MS=400)
        assert (r.returncode, r.stdout) == (2, "") and one_keyword(r.stderr) == "daemon_lost"
        assert " tamper daemon_lost " in home.hook_log() and "status=-" in home.hook_log()

    def test_post_tool_loss_only_logs(self, env):
        home, _, _ = env
        home.write_daemon_json(DOWN)
        r = self.run(env, POST)
        assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
        assert " tamper daemon_lost harness=kiro tool=execute_bash kind=post " in home.hook_log()

    # ------------------------------------------------------------------------------------------- fail-mode file

    @pytest.mark.parametrize("content,mode", [
        (None, "closed"),
        ("{garbage", "closed"),
        ('{\n  "default": "open"\n}\n', "closed"),
        ('{\n  "default": "open",\n  "tamper": "maybe"\n}\n', "closed"),
        ('{\n  "default": "open",\n  "tamper": "open"\n}\n', "open"),
        ('{"default": "open", "tamper": "open"}', "open"),
        ('{\n  "tamper": "open",\n' + '  "x": "' + "y" * 70_000 + '"\n}\n', "closed"),   # above 64 KiB
    ], ids=["absent", "garbage", "no-tamper", "invalid", "open", "one-line-open", "oversize"])
    def test_tamper_fail_mode_from_the_file(self, env, content, mode):
        home, stub, _ = env
        if content is None:
            (home.path / "fail-mode.json").unlink()
        else:
            home.write("fail-mode.json", content)
        stub.set(status=200, body=self.body("allow", notice=None), identity=["f" * 32])
        r = self.run(env)
        assert r.returncode == (2 if mode == "closed" else 0)
        assert self.log_lines(home)[0].endswith(f"fail_mode={mode}")

    @pytest.mark.parametrize("value", ["open", "", "OPEN", "closed "])
    def test_env_other_than_closed_is_ignored(self, env, value):
        home, stub, _ = env
        stub.set(status=200, body=self.body("allow", notice=None), identity=[])
        assert self.run(env, INTERLOCK_FAIL_MODE=value).returncode == 2
        home.write_fail_mode({"default": "open", "tamper": "open"})
        assert self.run(env, INTERLOCK_FAIL_MODE=value).returncode == 0
        assert self.run(env, INTERLOCK_FAIL_MODE="closed").returncode == 2

    # ------------------------------------------------------------------------------------------- local failures

    def test_unwritable_hook_log_still_refuses(self, env):
        home, stub, _ = env
        (home.path / "hook.log").mkdir()
        stub.set(status=401, identity=[home.identity])
        r = self.run(env)
        assert r.returncode == 2 and one_keyword(r.stderr) == "token_rejected"
        assert f"[interlock] could not write {home.path / 'hook.log'}\n" in r.stderr
        assert home.token not in r.stderr and COMMAND not in r.stderr

    def test_missing_token_is_inert(self, env):
        home, stub, _ = env
        (home.path / "token").unlink()
        stub.set(status=401)
        r = self.run(env)
        assert (r.returncode, r.stdout, r.stderr, stub.requests) == (0, "", "", [])
        (line,) = self.log_lines(home)
        assert line.endswith(f"inert: no token at {home.path / 'token'}") and "tamper" not in line

    # ------------------------------------------------------------------------------------------- real daemon

    @pytest.fixture
    def real_daemon(self, settings):
        """A real enforcing ApiServer and a home holding its token, identity and address (as `interlock serve`)."""
        from interlockd.api import ApiServer
        from interlockd.pipeline import Daemon
        from interlockd.policy import Policy
        from interlockd.store.memory import MemoryRepository
        from interlockd.store.spool import Spool

        pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = ["/ws/proj"]
        home = ShimHome.create(token="tok-kiro", identity=None)
        s = ApiServer(Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol),
                      "tok-kiro", "127.0.0.1", 0)
        s.start_background()
        try:
            home.write("identity", s.identity + "\n")
            home.write_daemon_json("{}:{}".format(*s.address))
            yield home, s
        finally:
            s.shutdown()
            home.cleanup()

    def _run_real(self, template: Path, home: ShimHome, payload: str) -> ShimResult:
        shim = install_shim(template, "kiro", home)
        r = subprocess.run(shim_command(shim), input=payload.encode(), capture_output=True, env=shim_env(home),
                           cwd=home.cwd, timeout=20, check=False)
        return ShimResult(r.returncode, r.stdout.decode(), r.stderr.decode())

    @pytest.mark.parametrize("payload,rc", [(PRE, 2), (OK, 0), (POST, 0)], ids=["block", "allow", "post"])
    def test_real_daemon_current_and_018_shims_agree(self, real_daemon, payload, rc):
        home, _ = real_daemon
        rel = self.template.relative_to(CURRENT_SHIMS)
        current = self._run_real(self.template, home, payload)
        old = self._run_real(SHIMS_018 / rel, home, payload)
        assert current == old and current.returncode == rc and current.stdout == ""
        assert ("[interlock]" in current.stderr) == (rc == 2) and home.hook_log() == ""

    def test_real_daemon_of_another_home_is_refused(self, real_daemon):
        home, s = real_daemon
        home.write("identity", "f" * 32 + "\n")                    # the reply comes from some other home's daemon
        r = self._run_real(self.template, home, OK)
        assert (r.returncode, r.stdout) == (2, "") and one_keyword(r.stderr) == "daemon_identity"
        home.write("token", "not-this-daemons-token\n")
        (home.path / "hook.log").unlink()
        r = self._run_real(self.template, home, OK)
        assert r.returncode == 2 and one_keyword(r.stderr) == "token_rejected"
        assert "status=401" in home.hook_log() and s.identity not in home.hook_log() + r.stderr
