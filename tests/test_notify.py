"""Desktop notifications (Requirements 6.6, 6.7): once per transition into `compromised`, argv-only commands,
fixed message text, failures recorded as `control.notify_failed`, never on the verdict path.

`subprocess.run` and `shutil.which` are replaced for every test: no real notification is ever posted."""

from __future__ import annotations

import base64
import subprocess
import threading
import time

import pytest

from interlockd import notify
from interlockd.notify import DesktopNotifier
from interlockd.protection import HOME, ProtectionState
from interlockd.store.spool import Spool

AT = "2026-10-17T10:00:00Z"
LATER = "2026-10-17T10:05:00Z"
EID = "01JD0000000000000000000000"


class Run:
    def __init__(self):
        self.calls: list[dict] = []
        self.returncode = 0
        self.raises: BaseException | None = None
        self.gate: threading.Event | None = None

    def __call__(self, argv, **kw):
        self.calls.append({"argv": list(argv), **kw})
        if self.gate is not None:
            self.gate.wait(5)
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(argv, self.returncode)


@pytest.fixture
def run(monkeypatch):
    r = Run()
    monkeypatch.setattr(notify.subprocess, "run", r)
    monkeypatch.setattr(notify.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    return r


def make(tmp_path, platform="darwin", **kw):
    spool = Spool(tmp_path / "spool", fsync=False)
    ps = ProtectionState(tmp_path, spool, None, lambda: "enforce", harnesses=lambda: ["claude-code", "kiro"])
    n = DesktopNotifier(spool.append, platform=platform, **kw)
    n.seed(ps.snapshot())
    ps.subscribe(n)
    return ps, n, spool


def failures(spool):
    return [r["arguments"]["reason"] for r in spool.iter_records(reverse=False)
            if (r.get("arguments") or {}).get("record") == "notify_failed"]


def test_once_per_transition_into_compromised(tmp_path, run):
    ps, n, spool = make(tmp_path)
    assert ps.add_reason("claude-code", "shim_modified", EID, AT)
    assert ps.add_reason("claude-code", "hook_removed", EID, LATER)      # already compromised: no second post
    assert ps.add_reason("kiro", "hook_removed", EID, AT)                 # another subject: its own post
    assert n.join(5)
    texts = [c["argv"][-2] for c in run.calls]
    assert texts == [notify.message("claude-code", "shim_modified"), notify.message("kiro", "hook_removed")]

    ps.clear(lambda r: r.subject == "claude-code", caused_by=EID)        # leaves compromised ...
    ps.add_reason("claude-code", "shim_relocated", EID, LATER)            # ... and re-enters: posts again
    assert n.join(5)
    assert len(run.calls) == 3 and "shim_relocated" in run.calls[-1]["argv"][-2]
    assert failures(spool) == []


def test_home_reason_notifies_as_home(tmp_path, run):
    ps, n, _ = make(tmp_path)
    ps.add_reason(HOME, "policy_modified", EID, AT)
    ps.add_reason(HOME, "token_modified", EID, LATER)
    assert n.join(5)
    assert [c["argv"][-2] for c in run.calls] == [notify.message(HOME, "policy_modified")]


def test_restored_state_is_not_reposted(tmp_path, run):
    spool = Spool(tmp_path / "spool", fsync=False)
    ps = ProtectionState(tmp_path, spool, None, lambda: "enforce", harnesses=lambda: ["claude-code"])
    ps.add_reason("claude-code", "shim_modified", EID, AT)
    n = DesktopNotifier(spool.append, platform="darwin")
    n.seed(ps.snapshot())
    ps.subscribe(n)
    ps.add_reason(HOME, "token_permissions", EID, AT)                     # unrelated change re-sends the snapshot
    assert n.join(5)
    assert [c["argv"][-2] for c in run.calls] == [notify.message(HOME, "token_permissions")]


def test_macos_text_passed_as_argv_not_script(tmp_path, run):
    ps, n, _ = make(tmp_path)
    ps.add_reason("claude-code", "shim_modified", EID, AT)
    assert n.join(5)
    (call,) = run.calls
    argv = call["argv"]
    scripts = [argv[i + 1] for i, a in enumerate(argv) if a == "-e"]
    assert scripts == list(notify._APPLESCRIPT)
    assert all("claude-code" not in s for s in scripts)
    assert argv[-2:] == [notify.message("claude-code", "shim_modified"), notify.TITLE]
    assert call.get("shell") is not True and call["timeout"] == notify.TIMEOUT_S


def test_linux_and_windows_commands():
    tool, argv, env = notify.command("linux", "Interlock", "Protection for kiro is compromised (hook_removed).")
    assert tool == "notify-send" and env is None and argv[-2:] == ["Interlock", argv[-1]] and argv[-3] == "--"

    text = "Protection for kiro is compromised (hook_removed). Run interlock doctor."
    tool, argv, env = notify.command("win32", "Interlock", text)
    assert tool == "powershell" and argv[argv.index("-EncodedCommand") - 1] == "Bypass"
    script = base64.b64decode(argv[argv.index("-EncodedCommand") + 1]).decode("utf-16-le")
    assert script == notify._PS_SCRIPT and "kiro" not in script and "CreateTextNode" in script
    assert env == {notify._ENV_TITLE: "Interlock", notify._ENV_TEXT: text}


def test_windows_post_passes_text_through_environment(tmp_path, run):
    ps, n, _ = make(tmp_path, platform="win32")
    ps.add_reason("kiro", "hook_removed", EID, AT)
    assert n.join(5)
    (call,) = run.calls
    assert call["env"][notify._ENV_TEXT] == notify.message("kiro", "hook_removed")
    assert all("kiro" not in a for a in call["argv"])


def test_message_carries_only_harness_and_reason_code():
    snap = {"harnesses": {"claude-code": {"state": "compromised",
                                          "reasons": [{"reason": "/etc/passwd; rm -rf ~", "detected_at": AT}]},
                          "Bad Name'\"": {"state": "compromised", "reasons": [{"reason": "hook_removed"}]},
                          "kiro": {"state": "protected", "reasons": []}},
            "home_reasons": []}
    assert notify.compromised_subjects(snap) == {"claude-code": "unknown", "unknown": "hook_removed"}


def test_missing_tool_recorded_once(tmp_path, run, monkeypatch):
    monkeypatch.setattr(notify.shutil, "which", lambda tool: None)
    ps, n, spool = make(tmp_path, platform="linux")
    ps.add_reason("claude-code", "shim_modified", EID, AT)
    ps.add_reason("kiro", "hook_removed", EID, AT)
    assert n.join(5)
    assert run.calls == [] and failures(spool) == ["notify_send_missing"]


@pytest.mark.parametrize(("setup", "reason"), [
    (lambda r: setattr(r, "returncode", 1), "osascript_failed"),
    (lambda r: setattr(r, "raises", subprocess.TimeoutExpired("osascript", 5)), "timeout"),
    (lambda r: setattr(r, "raises", OSError("exec format error")), "osascript_failed"),
])
def test_post_failure_records_notify_failed(tmp_path, run, setup, reason):
    setup(run)
    ps, n, spool = make(tmp_path)
    ps.add_reason("claude-code", "shim_modified", EID, AT)
    assert n.join(5)
    assert failures(spool) == [reason]
    assert ps.harness_state("claude-code") == "compromised"


def test_slow_notifier_never_delays_the_change(tmp_path, run):
    run.gate = threading.Event()
    ps, n, _ = make(tmp_path)
    t0 = time.monotonic()
    ps.add_reason("claude-code", "shim_modified", EID, AT)
    assert time.monotonic() - t0 < 1.0                                    # returned while the post is blocked
    run.gate.set()
    assert n.join(5) and len(run.calls) == 1


def test_disabled_by_policy_posts_nothing(tmp_path, run):
    ps, n, _ = make(tmp_path, enabled=lambda: False)
    ps.add_reason("claude-code", "shim_modified", EID, AT)
    assert n.join(5) and run.calls == []


def test_attach_integrity_subscribes_only_when_enabled(daemon, settings, run):
    from interlockd.cli import attach_integrity

    attach_integrity(daemon, settings.home, None)
    assert daemon.notifier is None

    daemon.policy.notify.desktop = True
    attach_integrity(daemon, settings.home, None)
    assert isinstance(daemon.notifier, DesktopNotifier)
    daemon.notifier.platform = "darwin"
    daemon.protection.add_reason(HOME, "token_modified", EID, AT)
    assert daemon.notifier.join(5)
    assert [c["argv"][-2] for c in run.calls] == [notify.message(HOME, "token_modified")]
