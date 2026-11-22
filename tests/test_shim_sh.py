"""Subprocess tests for the POSIX sh shims against a stub daemon (no live daemon).

Kiro sh shim (interlockd/shims/kiro/interlock-hook.sh): the shared Kiro case matrix in tests/kiro_shim_matrix.py
(identity verification, token rejection, stop marker versus loss, fail modes, hook.log lines), run with sh + curl.

Claude-code family sh shim (interlockd/shims/claude-code/interlock-hook.sh): the same case matrix for every
harness that shim serves, with refusals checked against adapters/<harness>/PAYLOADS.md (second section below).
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
from kiro_shim_matrix import KiroShimMatrix
from shim_stub import (
    ARG_HARNESSES,
    CURRENT_SHIMS,
    FORMATS,
    HAVE_SH,
    HAVE_UNIX,
    IDENTITY_HEADER,
    SHARED_HARNESSES,
    SHIMS_018,
    ShimHome,
    ShimResult,
    StubDaemon,
    _payload,
    install_shim,
    load_recording,
    run_shim,
    shim_command,
    shim_env,
)

# ----------------------------------------------------------------------------------------------- Kiro sh shim


@pytest.mark.skipif(not HAVE_SH, reason="needs sh and curl")
class TestKiroShShim(KiroShimMatrix):
    RUNTIME = "kiro-sh"

    def test_dependencies_stay_sh_curl_and_date(self):
        """The shim forks only cat, curl, date and mkdir (log path) and reads files with builtins."""
        text = self.template.read_text(encoding="utf-8")
        code = "\n".join(ln.split(" # ")[0] for ln in text.splitlines() if not ln.lstrip().startswith("#"))
        for prog in ("grep", "sed", "awk", "openssl", "shasum", "sha256sum", "python", "node", "jq", "cut", "tr"):
            assert not re.search(rf"(^|[\s;|&(]){prog}\s", code, re.MULTILINE), prog
        assert "curl -s " in text and "-sf" not in text and "-D - -w '\\n%{http_code}' -H 'Expect:'" in text


# ------------------------------------------------------------------------------- claude-code family sh shim
#
# interlockd/shims/claude-code/interlock-hook.sh, installed with __HARNESS__ replaced for claude-code, codex, cursor,
# gemini-cli, copilot-cli, windsurf and antigravity (the last three get "pre"/"post" as $1). Every case runs the shim
# this tree ships as a subprocess against shim_stub.StubDaemon (no live daemon), except the real-daemon cases at the
# end, which run it and the 0.1.8 fixture shim against a real ApiServer. Format-dependent cases (refusal and
# no-opinion output) run for every harness; transport and state-file cases run for one harness, since the shim's
# classification code is the same for all of them.
#
# Refusal output is taken from the "Tamper refusals" table in adapters/<harness>/PAYLOADS.md, so the tests fail when
# the shim and its documentation disagree.

CC_TEMPLATE = CURRENT_SHIMS / "claude-code" / "interlock-hook.sh"
ADAPTERS = Path(__file__).resolve().parent.parent / "adapters"
CC_COMMAND = "git push --force origin main"     # a marker: tool arguments must never reach a log or message
CC_DOWN = "127.0.0.1:9"                         # nothing listens there: the daemon is "down"
CC_KEYWORDS = ("token_rejected", "daemon_identity", "daemon_lost", "enforcement_point")
CC_TS = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
CC_TOOLS = {"claude-code": "Bash", "codex": "Bash", "antigravity": "Bash", "cursor": "Shell",
            "gemini-cli": "run_shell_command", "copilot-cli": "bash", "windsurf": "?"}
CC_UNREACHABLE = ("[interlock] This action was NOT executed: the Interlock daemon is unreachable and this workspace "
                  "fails closed. Start it with `interlock start`, then retry.")
CC_STOP = {"action": "stop", "pid": 1, "version": "0.2.0", "written_at": "2026-10-17T10:00:00Z"}
UNAUTHORIZED = '{"error":"unauthorized"}'


def cc_payload(harness: str, post: bool = False, command: str = CC_COMMAND) -> str:
    """The recorded 0.1.8 payload for `harness` with the command replaced by `command`."""
    p = _payload(harness, post)
    return p.replace('"ls"', json.dumps(command)).replace('\\"ls\\"', json.dumps(json.dumps(command))[1:-1])


def cc_restart_marker(expires_epoch) -> dict:
    return {"action": "restart", "expires_at": "2026-10-17T10:02:00Z", "expires_epoch": expires_epoch, "pid": 1,
            "version": "0.2.0", "written_at": "2026-10-17T10:00:00Z"}


def cc_marker_text(doc: dict) -> str:
    """As statefile.dumps writes it: sorted keys, ", " and ": " separators, one trailing newline."""
    return json.dumps(doc, sort_keys=True, separators=(", ", ": ")) + "\n"


def cc_one_keyword(text: str) -> str:
    """The single tamper keyword in `text`, asserting exactly one keyword occurs exactly once."""
    found = {k: text.count(k) for k in CC_KEYWORDS if k in text}
    assert len(found) == 1 and list(found.values()) == [1], found
    return next(iter(found))


def cc_message(cause: str, addr: str, home: ShimHome) -> str:
    """The refusal message for `cause` (adapters/README.md, "Refusal messages")."""
    return {
        "token_rejected": f"[interlock] This action was NOT executed: the process at {addr} rejected this hook's "
                          "token (token_rejected). Run `interlock doctor`.",
        "daemon_identity": f"[interlock] This action was NOT executed: the process answering at {addr} is not this "
                           "home's Interlock daemon (daemon_identity). Run `interlock doctor`.",
        "daemon_lost": "[interlock] This action was NOT executed: Interlock daemon stopped unexpectedly "
                       f"(daemon_lost). Home: {home.path}. Run `interlock doctor`, then `interlock start`.",
    }[cause]


def documented_refusal(harness: str) -> tuple[int, str, dict | None]:
    """(exit code, channel, JSON template) for a closed tamper refusal, from the first row of the "Tamper refusals"
    table in adapters/<harness>/PAYLOADS.md. Channel is "stdout" (JSON template) or "stderr" (template None)."""
    text = (ADAPTERS / harness / "PAYLOADS.md").read_text(encoding="utf-8")
    section = text.split("## Tamper refusals", 1)[1].split("\n## ", 1)[0]
    row = next(ln for ln in section.splitlines()
               if ln.startswith("| `token_rejected`, `daemon_identity`, `daemon_lost`"))
    cell = row.split("|")[2].strip()
    rc = int(re.search(r"exit (\d)", cell).group(1))
    if "on stderr" in cell:
        assert "`<tamper message>`" in cell, cell
        return rc, "stderr", None
    return rc, "stdout", json.loads(re.match(r"`(\{.*\})`", cell).group(1))


# no-opinion output per harness: (exit code, stdout) for pre and post (adapters/<harness>/PAYLOADS.md)
CC_NO_OPINION = {h: {"pre": (0, ""), "post": (0, "")} for h in SHARED_HARNESSES}
CC_NO_OPINION["cursor"]["pre"] = (1, "")
CC_NO_OPINION["antigravity"] = {"pre": (0, '{"decision":"allow"}\n'), "post": (0, "{}\n")}


@pytest.mark.skipif(not HAVE_SH, reason="needs sh and curl")
class TestClaudeCodeFamilyShShim:
    # ------------------------------------------------------------------------------------------- helpers

    @pytest.fixture
    def make(self):
        """make(harness) -> (home, stub, shim): a home whose daemon.json points at a running stub; tamper closed."""
        made = []

        def _make(harness: str = "claude-code", *, unix: bool = False):
            home = ShimHome.create(fail_mode={"default": "open", "tamper": "closed"})
            stub = StubDaemon(unix_socket=home.socket_path if unix else None)
            made.append((home, stub))
            home.write_daemon_json(stub.listen or CC_DOWN)
            return home, stub, install_shim(CC_TEMPLATE, harness, home)

        yield _make
        for home, stub in made:
            stub.close()
            home.cleanup()

    @staticmethod
    def run(harness: str, env, *, post: bool = False, payload: str | None = None, url: str | None = None,
            **extra) -> ShimResult:
        home, _, shim = env
        arg = ("post" if post else "pre") if harness in ARG_HARNESSES else ""
        return run_shim(shim, payload if payload is not None else cc_payload(harness, post), home, arg=arg, url=url,
                        env={k: str(v) for k, v in extra.items()} or None)

    @staticmethod
    def assert_no_leak(home: ShimHome, *texts: str) -> None:
        blob = "\n".join((home.hook_log(), *texts))
        assert CC_COMMAND not in blob and home.token not in blob and home.identity not in blob
        assert "BODY-MARKER" not in blob                            # no part of an unverified reply

    @staticmethod
    def assert_refused(harness: str, r: ShimResult, message: str, *, cursor_summary: str) -> None:
        """`r` is the harness's documented refusal carrying exactly `message`."""
        rc, channel, template = documented_refusal(harness)
        assert r.returncode == rc
        if channel == "stderr":
            assert (r.stdout, r.stderr) == ("", message + "\n")
            return
        assert r.stdout.endswith("\n") and r.stdout.count("\n") == 1 and r.stderr == ""
        got = json.loads(r.stdout)
        want = {k: (message if v == "<tamper message>" else v) for k, v in template.items()}
        if harness == "cursor":
            assert want.pop("user_message") == "<short summary>"
            assert got.pop("user_message") == cursor_summary
            assert not any(k in cursor_summary for k in CC_KEYWORDS)
        if "hookSpecificOutput" in want:
            want["hookSpecificOutput"] = {k: (message if v == "<tamper message>" else v)
                                          for k, v in want["hookSpecificOutput"].items()}
        assert got == want

    def assert_tamper_refusal(self, harness: str, env, r: ShimResult, cause: str, status: str,
                              addr: str | None = None) -> None:
        home, stub, _ = env
        addr = addr or stub.url
        self.assert_refused(harness, r, cc_message(cause, addr, home),
                            cursor_summary="Interlock protection is not intact (fail closed)")
        assert cc_one_keyword(r.stdout + r.stderr) == cause
        (line,) = home.hook_log().splitlines()
        assert re.fullmatch(rf"{CC_TS} tamper {cause} harness={harness} tool={re.escape(CC_TOOLS[harness])} "
                            rf"kind=pre addr={re.escape(addr)} status={status} fail_mode=closed", line), line
        self.assert_no_leak(home, r.stdout, r.stderr)

    @staticmethod
    def assert_no_opinion(harness: str, r: ShimResult, kind: str) -> None:
        assert (r.returncode, r.stdout, r.stderr) == (*CC_NO_OPINION[harness][kind], "")

    # ------------------------------------------------------------------------------------------- documentation

    @pytest.mark.parametrize("harness", SHARED_HARNESSES)
    def test_payloads_md_documents_the_tamper_outputs(self, harness):
        rc, channel, _ = documented_refusal(harness)
        assert (channel == "stderr") == (harness == "windsurf") and rc == (2 if harness == "windsurf" else 0)
        section = (ADAPTERS / harness / "PAYLOADS.md").read_text(encoding="utf-8").split("## Tamper refusals")[1]
        if harness == "cursor":
            assert "**exit 1**" in section
        elif harness == "antigravity":
            assert '`{"decision": "allow"}`' in section and "`{}`" in section
        else:
            assert "no output, exit 0" in section

    def test_dependencies_stay_sh_curl_and_date(self):
        """The shim forks only cat, curl, date and mkdir (log path) and reads files with builtins."""
        text = CC_TEMPLATE.read_text(encoding="utf-8")
        code = "\n".join(ln.split(" # ")[0] for ln in text.splitlines() if not ln.lstrip().startswith("#"))
        for prog in ("grep", "sed", "awk", "openssl", "shasum", "sha256sum", "python", "node", "jq", "cut", "tr"):
            assert not re.search(rf"(^|[\s;|&(]){prog}\s", code, re.MULTILINE), prog
        assert "curl -s " in text and "-sf" not in text and "-D - -w '\\n%{http_code}' -H 'Expect:'" in text

    # ------------------------------------------------------------------------------------------- verified replies

    @pytest.mark.skipif(not HAVE_UNIX, reason="needs Unix sockets")
    @pytest.mark.parametrize("case", load_recording("claude-code-sh")["cases"],
                             ids=lambda c: f"{c['harness']}/{c['case']}")
    def test_018_recordings_byte_identical_over_the_unix_socket(self, make, case):
        """Req 1.5, 1.7: a verified reply over the socket gives the recorded 0.1.8 output (TCP: test_shim_fixtures)."""
        home, stub, shim = make(case["harness"], unix=True)
        ids = [home.identity if v == "$IDENTITY" else v for v in case["reply"]["identity"]]
        stub.set(status=case["reply"]["status"], body=case["reply"]["body"], identity=ids,
                 content_type=case["reply"]["content_type"])
        r = run_shim(shim, case["payload"], home, arg=case["arg"])
        got = {"returncode": r.returncode, "stdout": home.normalize(r.stdout), "stderr": home.normalize(r.stderr),
               "hook_log": home.normalize(home.hook_log())}
        assert got == case["expect"]
        (req,) = stub.requests
        assert req.path == case["request"]["path"]

    @pytest.mark.parametrize("harness", SHARED_HARNESSES)
    def test_request_carries_the_shim_path_and_token(self, make, harness):
        """Req 5.10: the adapter block names the installed shim by absolute path."""
        env = make(harness)
        home, stub, shim = env
        stub.set(status=200, body="", identity=[home.identity])
        payload = cc_payload(harness, command="ls -la")
        r = self.run(harness, env, payload=payload)
        self.assert_no_opinion(harness, r, "pre")
        (req,) = stub.requests
        assert req.method == "POST" and req.path == f"/interlock/v1/hooks/{harness}?format={FORMATS[harness]}"
        assert req.header("authorization") == [f"Bearer {home.token}"]
        body = req.json()
        adapter = body["adapter"]
        assert {k: adapter[k] for k in ("name", "event", "cwd")} == {"name": harness, "event": "pre",
                                                                     "cwd": str(home.cwd)}
        assert Path(adapter["shim"]).is_absolute() and Path(adapter["shim"]).resolve() == shim.resolve()
        assert body["payload"] == json.loads(payload) and home.hook_log() == ""

    def test_relative_shim_path_is_made_absolute(self, make):
        home, stub, shim = make()
        stub.set(status=200, body="", identity=[home.identity])
        rel = Path("..") / shim.relative_to(home.root)                 # run from home.cwd, a sibling of shims/
        r = subprocess.run(["sh", str(rel)], input=cc_payload("claude-code").encode(), capture_output=True,
                           env=shim_env(home), cwd=home.cwd, timeout=20, check=False)
        assert r.returncode == 0
        reported = stub.requests[0].json()["adapter"]["shim"]
        assert Path(reported).is_absolute() and Path(reported).resolve() == shim.resolve()

    def test_lowercase_identity_header_name_verifies(self, make):
        """Header names are case-insensitive (adapters/README.md)."""
        env = make()
        home, stub, _ = env
        stub.set(status=200, body='{"ok":1}', identity=[], headers=[("x-interlock-identity", home.identity)])
        r = self.run("claude-code", env)
        assert (r.returncode, r.stdout, r.stderr, home.hook_log()) == (0, '{"ok":1}\n', "", "")

    def test_stop_marker_is_ignored_while_the_daemon_answers(self, make):
        """Req 3.14."""
        env = make()
        home, stub, _ = env
        home.write("stop-marker.json", cc_marker_text(CC_STOP))
        block = json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                   "permissionDecisionReason": "[interlock] fixture"}})
        stub.set(status=200, body=block, identity=[home.identity])
        r = self.run("claude-code", env)
        assert (r.returncode, r.stdout, r.stderr, home.hook_log()) == (0, block + "\n", "", "")

    # ------------------------------------------------------------------------------------------- token rejection

    @pytest.mark.parametrize("harness", SHARED_HARNESSES)
    def test_token_rejected_refuses_pre_in_the_harness_format(self, make, harness):
        """Req 2.1-2.3: 401 is a tamper cause, refused in the documented channel even with the env set to open."""
        env = make(harness)
        home, stub, _ = env
        stub.set(status=401, body=UNAUTHORIZED, identity=[home.identity])
        r = self.run(harness, env, INTERLOCK_FAIL_MODE="open")
        self.assert_tamper_refusal(harness, env, r, "token_rejected", "401")

    def test_403_is_a_token_rejection_too(self, make):
        env = make()
        env[1].set(status=403, body=UNAUTHORIZED)                     # no identity either: 403 is classified first
        self.assert_tamper_refusal("claude-code", env, self.run("claude-code", env), "token_rejected", "403")

    @pytest.mark.parametrize("status", [401, 403])
    @pytest.mark.parametrize("harness", SHARED_HARNESSES)
    def test_token_rejected_on_post_only_logs(self, make, harness, status):
        """Req 2.8: post-tool is logged and answered with the harness's no-opinion response."""
        env = make(harness)
        home, stub, _ = env
        stub.set(status=status, body=UNAUTHORIZED)
        r = self.run(harness, env, post=True)
        self.assert_no_opinion(harness, r, "post")
        (line,) = home.hook_log().splitlines()
        assert re.fullmatch(rf"{CC_TS} tamper token_rejected harness={harness} tool={re.escape(CC_TOOLS[harness])} "
                            rf"kind=post addr={re.escape(stub.url)} status={status} fail_mode=closed", line), line
        self.assert_no_leak(home, r.stdout, r.stderr)

    # ------------------------------------------------------------------------------------------- daemon identity

    @pytest.mark.parametrize("harness", SHARED_HARNESSES)
    def test_missing_identity_header_refuses_in_the_harness_format(self, make, harness):
        """Req 1.6: an unverified allow is never applied, whatever the harness."""
        env = make(harness)
        stub = env[1]
        body = "allow enforce 0\nBODY-MARKER\n" if harness == "windsurf" else '{"BODY-MARKER":1}'
        stub.set(status=200, body=body, identity=[])
        self.assert_tamper_refusal(harness, env, self.run(harness, env), "daemon_identity", "200")

    @pytest.mark.parametrize("ids", [["f" * 32], ["$ID", "$ID"], ["$ID", "f" * 32], ["$ID-x"], ["x$ID"],
                                     ["$UP"], [""]],
                             ids=["wrong", "duplicated", "two-different", "suffixed", "prefixed", "upper", "empty"])
    @pytest.mark.parametrize("harness", ["claude-code", "windsurf"])
    def test_unverified_reply_is_never_applied(self, make, harness, ids):
        env = make(harness)
        home, stub, _ = env
        body = ("block enforce 2\nBODY-MARKER\n" if harness == "windsurf" else
                json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                                   "permissionDecisionReason": "BODY-MARKER"}}))
        stub.set(status=200, body=body,
                 identity=[v.replace("$ID", home.identity).replace("$UP", home.identity.upper()) for v in ids])
        self.assert_tamper_refusal(harness, env, self.run(harness, env), "daemon_identity", "200")

    def test_duplicate_identity_with_mixed_header_case_is_refused(self, make):
        env = make()
        home, stub, _ = env
        stub.set(status=200, body="", identity=[home.identity], headers=[("x-interlock-identity", home.identity)])
        self.assert_tamper_refusal("claude-code", env, self.run("claude-code", env), "daemon_identity", "200")

    def test_identity_in_the_body_does_not_count(self, make):
        env = make()
        home, stub, _ = env
        stub.set(status=200, body=f"{IDENTITY_HEADER}: {home.identity}\n", identity=[])
        r = self.run("claude-code", env)
        assert cc_one_keyword(r.stdout) == "daemon_identity" and home.identity not in r.stdout

    @pytest.mark.parametrize("harness", ["claude-code", "antigravity", "cursor"])
    def test_tamper_open_logs_and_gives_no_opinion(self, make, harness):
        """Req 4.5: fail_mode.tamper open gives the harness's no-opinion response (Cursor exit 1, Antigravity
        allow)."""
        env = make(harness)
        home, stub, _ = env
        home.write_fail_mode({"default": "closed", "tamper": "open"})
        stub.set(status=200, body='{"BODY-MARKER":1}', identity=[])
        r = self.run(harness, env)
        self.assert_no_opinion(harness, r, "pre")
        (line,) = home.hook_log().splitlines()
        assert f" tamper daemon_identity harness={harness} " in line and line.endswith("status=200 fail_mode=open")

    @pytest.mark.parametrize("harness", ["claude-code", "antigravity", "windsurf"])
    def test_unverified_post_reply_only_logs(self, make, harness):
        """Req 4.6: post-tool tamper is no opinion even when closed."""
        env = make(harness)
        home, stub, _ = env
        stub.set(status=200, body='{"BODY-MARKER":1}', identity=["f" * 32])
        r = self.run(harness, env, post=True)
        self.assert_no_opinion(harness, r, "post")
        assert f" tamper daemon_identity harness={harness} tool=" in home.hook_log()
        assert " kind=post " in home.hook_log()
        self.assert_no_leak(home, r.stdout, r.stderr)

    # ------------------------------------------------------------------------------------------- transports

    def test_interlock_url_is_verified_too(self, make):
        """Req 1.7: an explicit INTERLOCK_URL gets no exemption; the trailing slash is dropped from the address."""
        env = make()
        home, stub, _ = env
        home.write_daemon_json(CC_DOWN)                                # only the explicit URL answers
        stub.set(status=200, body="", identity=["f" * 32])
        r = self.run("claude-code", env, url=stub.url + "/")
        self.assert_tamper_refusal("claude-code", env, r, "daemon_identity", "200")
        (home.path / "hook.log").unlink()
        stub.set(status=200, body='{"ok":1}', identity=[home.identity])
        r = self.run("claude-code", env, url=stub.url)
        assert (r.returncode, r.stdout, home.hook_log()) == (0, '{"ok":1}\n', "")

    @pytest.mark.skipif(not HAVE_UNIX, reason="needs Unix sockets")
    def test_interlock_url_wins_over_the_unix_socket(self, make):
        home, sock_stub, shim = make(unix=True)
        sock_stub.set(status=200, body='{"from":"socket"}', identity=[home.identity])
        with StubDaemon() as tcp:
            tcp.set(status=200, body='{"from":"url"}', identity=[home.identity])
            r = run_shim(shim, cc_payload("claude-code"), home, url=tcp.url)
        assert (r.returncode, r.stdout) == (0, '{"from":"url"}\n') and sock_stub.requests == []

    @pytest.mark.skipif(not HAVE_UNIX, reason="needs Unix sockets")
    @pytest.mark.parametrize("case", ["verified", "wrong-identity", "token-rejected"])
    def test_unix_socket_is_verified(self, make, case):
        """Req 1.7: the socket is preferred over daemon.json's address and verified the same way."""
        env = make(unix=True)
        home, stub, _ = env
        addr = f"unix:{home.socket_path}"
        if case == "verified":
            stub.set(status=200, body='{"ok":1}', identity=[home.identity])
            r = self.run("claude-code", env)
            assert (r.returncode, r.stdout, home.hook_log()) == (0, '{"ok":1}\n', "")
            assert stub.requests[0].path == "/interlock/v1/hooks/claude-code?format=claude-code"
        elif case == "wrong-identity":
            stub.set(status=200, body='{"BODY-MARKER":1}', identity=["f" * 32])
            self.assert_tamper_refusal("claude-code", env, self.run("claude-code", env), "daemon_identity", "200",
                                       addr=addr)
        else:
            stub.set(status=401, body=UNAUTHORIZED, identity=[home.identity])
            self.assert_tamper_refusal("claude-code", env, self.run("claude-code", env), "token_rejected", "401",
                                       addr=addr)

    # ------------------------------------------------------------------------------------------- other HTTP errors

    @pytest.mark.parametrize("harness", ["claude-code", "cursor", "windsurf"])
    def test_other_http_errors_use_the_default_fail_mode(self, make, harness):
        env = make(harness)
        home, stub, _ = env
        stub.set(status=500, body="boom", identity=[home.identity])
        self.assert_no_opinion(harness, self.run(harness, env), "pre")
        home.write_fail_mode({"default": "closed", "tamper": "open"})
        self.assert_refused(harness, self.run(harness, env), CC_UNREACHABLE,
                            cursor_summary="Interlock daemon unreachable (fail closed)")
        assert [ln.split(" ", 1)[1] for ln in home.hook_log().splitlines()] == [
            f"unjudged why=http_500 harness={harness} tool={CC_TOOLS[harness]} kind=pre addr={stub.url} "
            f"status=500 fail_mode={m}" for m in ("open", "closed")]

    # ------------------------------------------------------------------------------------------- unreachable daemon

    @pytest.mark.parametrize("harness", SHARED_HARNESSES)
    def test_unexpected_loss_refuses_in_the_harness_format(self, make, harness):
        """Req 3.8, 3.9: no marker and nothing listening is daemon_lost, naming the home and both repairs."""
        env = make(harness)
        home, _, _ = env
        home.write_daemon_json(CC_DOWN)
        self.assert_tamper_refusal(harness, env, self.run(harness, env), "daemon_lost", "-", addr=f"http://{CC_DOWN}")

    @pytest.mark.parametrize("harness", SHARED_HARNESSES)
    def test_operator_stop_uses_the_default_fail_mode(self, make, harness):
        """Req 3.6, 14.6: an operator stop applies fail_mode.default, asserted for open and closed."""
        env = make(harness)
        home, _, _ = env
        home.write_daemon_json(CC_DOWN)
        home.write("stop-marker.json", cc_marker_text(CC_STOP))
        self.assert_no_opinion(harness, self.run(harness, env), "pre")
        home.write_fail_mode({"default": "closed", "tamper": "open"})
        self.assert_refused(harness, self.run(harness, env), CC_UNREACHABLE,
                            cursor_summary="Interlock daemon unreachable (fail closed)")
        assert [ln.split(" ", 1)[1] for ln in home.hook_log().splitlines()] == [
            f"unjudged why=operator_stopped harness={harness} tool={CC_TOOLS[harness]} kind=pre "
            f"addr=http://{CC_DOWN} status=- fail_mode={m}" for m in ("open", "closed")]

    @pytest.mark.parametrize("marker,outcome", [
        (None, "daemon_lost"),
        (cc_marker_text(CC_STOP), "operator_stopped"),
        (cc_marker_text({**CC_STOP, "action": "uninstall"}), "operator_stopped"),
        (cc_marker_text(cc_restart_marker(4_000_000_000)), "restarting"),
        (cc_marker_text(cc_restart_marker(1_000)), "daemon_lost"),              # expired
        ("{not json", "daemon_lost"),
        ("", "daemon_lost"),
        (cc_marker_text({"action": "stop", "pid": 1}), "daemon_lost"),          # no written_at
        (cc_marker_text({"pid": 1, "written_at": "2026-10-17T10:00:00Z"}), "daemon_lost"),   # no action
        (cc_marker_text({**CC_STOP, "action": ""}), "daemon_lost"),
        (cc_marker_text(cc_restart_marker("soon")), "daemon_lost"),             # expiry not an integer
        (cc_marker_text(cc_restart_marker(10 ** 13)), "daemon_lost"),           # more than 12 digits
        ('{"action": "stop", "written_at": "x"' + " " * 70_000 + "}\n", "daemon_lost"),   # above 64 KiB
    ], ids=["absent", "stop", "uninstall", "restart-future", "restart-expired", "garbage", "empty", "no-written-at",
            "no-action", "empty-action", "bad-expiry", "huge-expiry", "oversize"])
    @pytest.mark.parametrize("default", ["open", "closed"])
    def test_unreachable_daemon_is_classified_by_the_stop_marker(self, make, marker, outcome, default):
        """Req 3.6-3.8, 3.11, 12.4."""
        env = make()
        home, _, _ = env
        home.write_daemon_json(CC_DOWN)
        home.write_fail_mode({"default": default, "tamper": "closed"})
        if marker is not None:
            home.write("stop-marker.json", marker)
        r = self.run("claude-code", env)
        if outcome == "daemon_lost":
            self.assert_tamper_refusal("claude-code", env, r, "daemon_lost", "-", addr=f"http://{CC_DOWN}")
            return
        if default == "closed":
            self.assert_refused("claude-code", r, CC_UNREACHABLE, cursor_summary="")
        else:
            self.assert_no_opinion("claude-code", r, "pre")
        (line,) = home.hook_log().splitlines()
        assert re.fullmatch(rf"{CC_TS} unjudged why={outcome} harness=claude-code tool=Bash kind=pre "
                            rf"addr=http://{re.escape(CC_DOWN)} status=- fail_mode={default}", line), line

    def test_no_daemon_json_means_unreachable_without_a_request(self, make):
        """Req 3.13."""
        env = make()
        home, stub, _ = env
        (home.path / "daemon.json").unlink()
        stub.set(status=200, body="", identity=[home.identity])
        r = self.run("claude-code", env)
        assert stub.requests == [] and cc_one_keyword(r.stdout) == "daemon_lost"
        (home.path / "hook.log").unlink()
        home.write("stop-marker.json", cc_marker_text(CC_STOP))
        r = self.run("claude-code", env)
        assert (r.returncode, r.stdout) == (0, "") and "unjudged why=operator_stopped" in home.hook_log()

    @pytest.mark.parametrize("how", ["timeout", "dropped"])
    def test_timeout_and_dropped_connection_are_a_loss(self, make, how):
        """Req 3.13: no response within the timeout (or no response at all) is unreachable."""
        env = make()
        home, stub, _ = env
        if how == "timeout":
            stub.set(status=200, body="", identity=[home.identity], delay_s=3)
        else:
            stub.set(close_without_reply=True)
        r = self.run("claude-code", env, INTERLOCK_PRE_TIMEOUT_MS=400)
        assert r.returncode == 0 and cc_one_keyword(r.stdout) == "daemon_lost"
        assert " tamper daemon_lost " in home.hook_log() and "status=-" in home.hook_log()

    @pytest.mark.parametrize("harness", ["claude-code", "cursor", "antigravity"])
    def test_post_tool_loss_only_logs(self, make, harness):
        env = make(harness)
        home, _, _ = env
        home.write_daemon_json(CC_DOWN)
        self.assert_no_opinion(harness, self.run(harness, env, post=True), "post")
        assert f" tamper daemon_lost harness={harness} tool={CC_TOOLS[harness]} kind=post " in home.hook_log()

    # ------------------------------------------------------------------------------------------- fail-mode file

    @pytest.mark.parametrize("content,mode", [
        (None, "closed"),
        ("{garbage", "closed"),
        ('{\n  "default": "open"\n}\n', "closed"),
        ('{\n  "default": "open",\n  "tamper": "maybe"\n}\n', "closed"),
        ('{\n  "default": "open",\n  "tamper": "OPEN"\n}\n', "closed"),
        ('{\n  "default": "open",\n  "tamper": "open"\n}\n', "open"),
        ('{"default": "open", "tamper": "open"}', "open"),
        ('{\n  "tamper": "open",\n' + '  "x": "' + "y" * 70_000 + '"\n}\n', "closed"),   # above 64 KiB
    ], ids=["absent", "garbage", "no-tamper", "invalid", "uppercase", "open", "one-line-open", "oversize"])
    def test_tamper_fail_mode_from_the_file(self, make, content, mode):
        """Req 4.7, 12.4."""
        env = make()
        home, stub, _ = env
        if content is None:
            (home.path / "fail-mode.json").unlink()
        else:
            home.write("fail-mode.json", content)
        stub.set(status=200, body="", identity=["f" * 32])
        r = self.run("claude-code", env)
        assert (cc_one_keyword(r.stdout) == "daemon_identity") if mode == "closed" else (r.stdout == "")
        assert home.hook_log().splitlines()[0].endswith(f"fail_mode={mode}")

    @pytest.mark.parametrize("content,mode", [
        (None, "open"), ("{garbage", "open"), ('{\n  "default": "closed"\n}\n', "closed"),
        ('{\n  "default": "maybe",\n  "tamper": "closed"\n}\n', "open"),
    ], ids=["absent", "garbage", "closed", "invalid"])
    def test_default_fail_mode_from_the_file(self, make, content, mode):
        env = make()
        home, stub, _ = env
        if content is None:
            (home.path / "fail-mode.json").unlink()
        else:
            home.write("fail-mode.json", content)
        stub.set(status=502, body="", identity=[home.identity])
        r = self.run("claude-code", env)
        assert (r.stdout == "") == (mode == "open")
        assert home.hook_log().splitlines()[0].endswith(f"fail_mode={mode}")

    # ------------------------------------------------------------------------------------------- environment

    @pytest.mark.parametrize("value", ["open", "", "OPEN", "closed ", "0"])
    def test_env_other_than_closed_is_ignored(self, make, value):
        """Req 4.9: the environment cannot loosen either fail mode."""
        env = make()
        home, stub, _ = env
        stub.set(status=200, body="", identity=[])
        assert cc_one_keyword(self.run("claude-code", env, INTERLOCK_FAIL_MODE=value).stdout) == "daemon_identity"
        home.write_fail_mode({"default": "closed", "tamper": "open"})
        assert self.run("claude-code", env, INTERLOCK_FAIL_MODE=value).stdout == ""
        stub.set(status=500, body="", identity=[home.identity])
        assert CC_UNREACHABLE in self.run("claude-code", env, INTERLOCK_FAIL_MODE=value).stdout

    @pytest.mark.parametrize("harness", ["claude-code", "cursor"])
    def test_env_closed_tightens_both_fail_modes(self, make, harness):
        """Req 4.8."""
        env = make(harness)
        home, stub, _ = env
        home.write_fail_mode({"default": "open", "tamper": "open"})
        stub.set(status=200, body="", identity=[])
        r = self.run(harness, env, INTERLOCK_FAIL_MODE="closed")
        self.assert_refused(harness, r, cc_message("daemon_identity", stub.url, home),
                            cursor_summary="Interlock protection is not intact (fail closed)")
        stub.set(status=500, body="", identity=[home.identity])
        r = self.run(harness, env, INTERLOCK_FAIL_MODE="closed")
        self.assert_refused(harness, r, CC_UNREACHABLE, cursor_summary="Interlock daemon unreachable (fail closed)")
        assert [ln.rsplit(" ", 1)[1] for ln in home.hook_log().splitlines()] == ["fail_mode=closed"] * 2

    # ------------------------------------------------------------------------------------------- garbage state files

    @pytest.mark.parametrize("content", ["", "\n", "not-hex\n", "f" * 32 + "\n", "$ID-x\n"],
                             ids=["empty", "blank-line", "garbage", "other-value", "suffixed"])
    def test_garbage_identity_file_fails_verification(self, make, content):
        """Req 1.6, 12.4: an unusable identity file never verifies, even against an empty or equal header."""
        env = make()
        home, stub, _ = env
        home.write("identity", content.replace("$ID", home.identity))
        stub.set(status=200, body="", identity=[home.identity if content.strip() else ""])
        self.assert_tamper_refusal("claude-code", env, self.run("claude-code", env), "daemon_identity", "200")

    def test_missing_identity_file_fails_verification(self, make):
        env = make()
        home, stub, _ = env
        (home.path / "identity").unlink()
        stub.set(status=200, body="", identity=[home.identity])
        self.assert_tamper_refusal("claude-code", env, self.run("claude-code", env), "daemon_identity", "200")

    def test_identity_file_is_read_by_its_first_line(self, make):
        env = make()
        home, stub, _ = env
        home.write("identity", home.identity + "\ntrailing garbage\n")
        stub.set(status=200, body='{"ok":1}', identity=[home.identity])
        r = self.run("claude-code", env)
        assert (r.returncode, r.stdout, home.hook_log()) == (0, '{"ok":1}\n', "")

    @pytest.mark.skipif(not HAVE_UNIX, reason="needs Unix sockets")
    @pytest.mark.parametrize("content", ["", "{garbage\n", '{"pid": 1}\n'], ids=["empty", "garbage", "no-listen"])
    def test_garbage_daemon_json_still_uses_the_socket(self, make, content):
        """Req 12.4: a daemon.json without a usable address is read as no address; the socket still answers.
        (Only tested with a socket present, so the shim's 127.0.0.1:7391 default never reaches a real daemon.)"""
        env = make(unix=True)
        home, stub, _ = env
        home.write("daemon.json", content, 0o644)
        stub.set(status=200, body='{"ok":1}', identity=[home.identity])
        r = self.run("claude-code", env)
        assert (r.returncode, r.stdout, home.hook_log()) == (0, '{"ok":1}\n', "") and len(stub.requests) == 1

    @pytest.mark.parametrize("harness", ["claude-code", "cursor", "antigravity"])
    def test_missing_or_empty_token_is_inert(self, make, harness):
        """Req 1.11: no token is not a tamper case: no request, no tamper line, the harness's no-opinion reply."""
        env = make(harness)
        home, stub, _ = env
        home.write("token", "")
        stub.set(status=401)
        r = self.run(harness, env)
        self.assert_no_opinion(harness, r, "pre")
        assert stub.requests == []
        (line,) = home.hook_log().splitlines()
        assert line.endswith(f"inert: no token at {home.path / 'token'}") and "tamper" not in line
        (home.path / "token").unlink()
        self.assert_no_opinion(harness, self.run(harness, env), "pre")
        assert stub.requests == [] and "tamper" not in home.hook_log()

    # ------------------------------------------------------------------------------------------- local failures

    @pytest.mark.parametrize("harness", ["claude-code", "windsurf"])
    def test_unwritable_hook_log_still_refuses(self, make, harness):
        """Req 2.9: the refusal is still emitted, plus one stderr line naming the log."""
        env = make(harness)
        home, stub, _ = env
        (home.path / "hook.log").mkdir()
        stub.set(status=401, body=UNAUTHORIZED, identity=[home.identity])
        r = self.run(harness, env)
        warn = f"[interlock] could not write {home.path}/hook.log\n"
        msg = cc_message("token_rejected", stub.url, home)
        if harness == "windsurf":
            assert (r.returncode, r.stdout, r.stderr) == (2, "", warn + msg + "\n")
        else:
            assert r.stderr == warn
            self.assert_refused(harness, ShimResult(r.returncode, r.stdout, ""), msg, cursor_summary="")
        assert home.token not in r.stdout + r.stderr and CC_COMMAND not in r.stdout + r.stderr

    def test_unwritable_hook_log_on_post_still_answers(self, make):
        env = make()
        home, stub, _ = env
        (home.path / "hook.log").mkdir()
        stub.set(status=403, body=UNAUTHORIZED)
        r = self.run("claude-code", env, post=True)
        assert (r.returncode, r.stdout, r.stderr) == (0, "", f"[interlock] could not write {home.path}/hook.log\n")

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
        home = ShimHome.create(token="tok-cc-family", identity=None)
        s = ApiServer(Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol),
                      "tok-cc-family", "127.0.0.1", 0)
        s.start_background()
        try:
            home.write("identity", s.identity + "\n")
            home.write_daemon_json("{}:{}".format(*s.address))
            yield home, s
        finally:
            s.shutdown()
            home.cleanup()

    @staticmethod
    def _run_real(template: Path, harness: str, home: ShimHome, payload: str, post: bool = False) -> ShimResult:
        shim = install_shim(template, harness, home)
        arg = ("post" if post else "pre") if harness in ARG_HARNESSES else ""
        r = subprocess.run(shim_command(shim, arg), input=payload.encode(), capture_output=True, env=shim_env(home),
                           cwd=home.cwd, timeout=20, check=False)
        return ShimResult(r.returncode, r.stdout.decode(), r.stderr.decode())

    @pytest.mark.parametrize("which", ["block", "allow", "post"])
    @pytest.mark.parametrize("harness", SHARED_HARNESSES)
    def test_real_daemon_current_and_018_shims_agree(self, real_daemon, harness, which):
        """Req 1.5, 1.9: against the new ApiServer (identity header on every reply) the 0.1.8 fixture shim and the
        current shim give the same output, and neither logs anything."""
        if harness == "windsurf" and which == "post":
            pytest.skip("Windsurf hooks are installed on pre_* events only")
        home, _ = real_daemon
        post = which == "post"
        command = "ls -la" if which == "allow" else CC_COMMAND
        payload = cc_payload(harness, post, command=command)
        if harness == "antigravity":    # the daemon's Antigravity normalizer reads toolCall (PAYLOADS.md "Input")
            payload = json.dumps({"conversationId": "c1", "workspacePaths": ["/ws/proj"],
                                  "toolCall": {"name": "run_command", "args": {"CommandLine": command,
                                                                               "Cwd": "/ws/proj"}}})
        old = self._run_real(SHIMS_018 / "claude-code" / "interlock-hook.sh", harness, home, payload, post)
        current = self._run_real(CC_TEMPLATE, harness, home, payload, post)
        assert current == old and home.hook_log() == ""
        if which == "block":
            assert "[interlock]" in current.stdout + current.stderr
            assert current.returncode == (2 if harness == "windsurf" else 0)

    def test_real_daemon_of_another_home_is_refused(self, real_daemon):
        home, s = real_daemon
        home.write("identity", "f" * 32 + "\n")                    # the reply comes from some other home's daemon
        payload = cc_payload("claude-code", command="ls -la")
        r = self._run_real(CC_TEMPLATE, "claude-code", home, payload)
        assert r.returncode == 0 and cc_one_keyword(r.stdout) == "daemon_identity"
        home.write("token", "not-this-daemons-token\n")
        (home.path / "hook.log").unlink()
        r = self._run_real(CC_TEMPLATE, "claude-code", home, payload)
        assert cc_one_keyword(r.stdout) == "token_rejected"
        assert "status=401" in home.hook_log() and s.identity not in home.hook_log() + r.stdout + r.stderr
