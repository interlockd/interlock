"""Hook watch: removed hooks and edited shims become control records in the audit chain; repairs are recorded too.

The first tests run against a bare daemon (no integrity wiring): the watch keeps its pre-tamper-detection behaviour.
The rest wire the daemon as `interlock serve` does (`cli.attach_integrity`) and cover the 10 s pass, shim repair and
repair failure, the token checks, one event per distinct condition, the version-guarded refresh and the identity file.
"""

from __future__ import annotations

import hashlib
import os
import sys
import threading
import time

import pytest

from interlockd import identity, integrity, records, watch
from interlockd.auth import load_or_create_token
from interlockd.cli import CLAUDE_SHIM_SRC, attach_integrity
from interlockd.insights import build_report, expected_shim, format_report
from interlockd.onboard import Manifest
from interlockd.watch import INTERVAL_S, HookWatch, PollingNotifier

POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
NOT_ROOT = pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores permission bits")


def _packaged():
    return CLAUDE_SHIM_SRC.read_text(encoding="utf-8").replace("__HARNESS__", "claude-code")


def _install(settings, tmp_path):
    shim = settings.home / "adapters" / "claude-code" / "interlock-hook.sh"
    shim.parent.mkdir(parents=True)
    shim.write_text(_packaged(), encoding="utf-8")
    hooks = tmp_path / "settings.json"
    hooks.write_text(f'{{"hooks": {{"PreToolUse": [{{"hooks": [{{"command": "sh {shim}"}}]}}]}}}}', encoding="utf-8")
    Manifest(created_at="2026-10-18T00:00:00Z", hooks=[{"harness": "claude-code", "file": str(hooks), "marker": str(shim),
                                                         "created": False}]).save(settings.home)
    return hooks, shim


def test_changes_are_recorded(daemon, settings, tmp_path):
    hooks, shim = _install(settings, tmp_path)
    w = HookWatch(daemon, settings.home)
    assert w.check() == []                                         # intact at start: nothing to record
    shim.write_text(shim.read_text(encoding="utf-8") + "\nexit 0\n", encoding="utf-8")
    [rec] = w.check()
    args = rec["arguments"]
    assert rec["kind"] == "control" and args["tamper_kind"] == "shim_modified" and rec["disposition"] == "flag"
    assert rec["findings"][0]["rule"] == "control.shim_modified"
    assert args["path"] == str(shim)
    assert args["observed_sha256"] == hashlib.sha256(shim.read_bytes()).hexdigest()
    assert args["expected_sha256"] and args["expected_sha256"] != args["observed_sha256"]
    assert w.check() == []                                         # unchanged: recorded once
    hooks.write_text("{}", encoding="utf-8")
    [rec] = w.check()
    assert rec["arguments"]["tamper_kind"] == "hook_removed" and rec["arguments"]["path"] == str(hooks)
    shim.write_text(_packaged(), encoding="utf-8")
    hooks.write_text(f'{{"command": "sh {shim}"}}', encoding="utf-8")
    [rec] = w.check()
    assert rec["arguments"]["record"] == "hook_restored" and rec["arguments"]["previous"] == "hook_removed"
    assert rec["disposition"] == "allow" and rec["findings"] == []
    v = daemon.spool.verify()
    assert v["ok"] and v["records"] == 3                           # in the hash chain
    text = format_report(build_report(daemon.spool.iter_records(), days=7))
    assert "Hook changes" in text and "restored" in text


def test_first_check_records_existing_problems(daemon, settings, tmp_path):
    hooks, _ = _install(settings, tmp_path)
    hooks.write_text("{}", encoding="utf-8")
    [rec] = HookWatch(daemon, settings.home).check()
    assert rec["arguments"]["tamper_kind"] == "hook_removed"


def test_upgrade_leftovers_are_refreshed_not_flagged(daemon, settings, tmp_path):
    _, shim = _install(settings, tmp_path)
    current = shim.read_text(encoding="utf-8")
    shim.write_text(current.replace('VERSION="', 'VERSION="0.0.9-', 1), encoding="utf-8")
    assert HookWatch(daemon, settings.home).check() == []
    assert shim.read_text(encoding="utf-8") == current


def test_refresh_waits_for_a_restart_when_the_package_is_newer(daemon, settings, tmp_path, monkeypatch):
    _, shim = _install(settings, tmp_path)
    leftover = shim.read_text(encoding="utf-8").replace('VERSION="', 'VERSION="0.0.9-', 1)
    shim.write_text(leftover, encoding="utf-8")
    monkeypatch.setattr(watch, "__version__", "9.9.9")             # the running daemon is not the installed package
    assert not watch.packaged_shims_current()
    assert HookWatch(daemon, settings.home).check() == []
    assert shim.read_text(encoding="utf-8") == leftover            # left alone: a newer shim refuses an older daemon


# ---- wired as `interlock serve` wires it -------------------------------------------------------------------------


def _wired(daemon, settings, tmp_path):
    hooks, shim = _install(settings, tmp_path)
    load_or_create_token(settings.token_path)
    attach_integrity(daemon, settings.home, None)
    daemon.identity = identity.derive("t", b"\x00" * 16)
    identity.write(settings.home, daemon.identity)
    return hooks, shim


def _kinds(recs):
    return [r["arguments"].get("tamper_kind") or r["arguments"]["record"] for r in recs]


def _reasons(daemon):
    return {r.code for r in daemon.protection.reasons()}


def test_interval_and_first_pass_at_start(daemon, settings, tmp_path, monkeypatch):
    assert INTERVAL_S == 10.0 and HookWatch(daemon, settings.home).interval == 10.0
    w = HookWatch(daemon, settings.home, interval=0.02)
    passes = []
    monkeypatch.setattr(w, "check", lambda: passes.append(time.monotonic()) or [])
    w.start()
    try:
        assert len(passes) >= 1                                    # synchronous first pass, before serving
        deadline = time.monotonic() + 5
        while len(passes) < 3 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(passes) >= 3
    finally:
        w.stop()


def test_loop_survives_a_failing_pass(daemon, settings):
    w = HookWatch(daemon, settings.home, interval=0.01)
    calls, done = [], threading.Event()

    def boom():
        calls.append(1)
        if len(calls) >= 3:
            done.set()
        raise RuntimeError("boom")

    w.check = boom
    w.start()
    try:
        assert done.wait(5)
    finally:
        w.stop()


def test_notifier_wakes_the_loop_early(daemon, settings, monkeypatch):
    class Early(PollingNotifier):
        def start(self, wake):
            self.wake = wake

    n = Early()
    w = HookWatch(daemon, settings.home, interval=60.0, notifier=n)
    ran = threading.Event()
    monkeypatch.setattr(w, "check", lambda: ran.set() or [])
    w.start()
    try:
        ran.clear()
        n.wake()
        assert ran.wait(5)                                         # well before the 60 s interval
    finally:
        w.stop()


def test_modified_shim_is_repaired_and_stays_compromised(daemon, settings, tmp_path):
    _, shim = _wired(daemon, settings, tmp_path)
    w = HookWatch(daemon, settings.home)
    assert w.check() == []
    shim.write_text(_packaged() + "\nexit 0\n", encoding="utf-8")
    tampered = hashlib.sha256(shim.read_bytes()).hexdigest()
    recs = w.check()
    assert _kinds(recs) == ["shim_modified", "shim_repaired"]
    assert recs[0]["arguments"]["observed_sha256"] == tampered
    assert shim.read_text(encoding="utf-8") == expected_shim("claude-code", shim)     # rewritten from the package
    assert recs[1]["arguments"]["sha256"] == hashlib.sha256(shim.read_bytes()).hexdigest()
    assert daemon.protection.harness_state("claude-code") == "compromised"            # until ack / init
    assert w.check() == []                                         # intact again, reason kept, nothing new
    assert _reasons(daemon) == {"claude-code:shim_modified"}
    shim.write_text(_packaged() + "\nexit 0\n", encoding="utf-8")  # the same edit again: a new condition
    assert _kinds(w.check()) == ["shim_modified", "shim_repaired"]
    assert daemon.spool.verify()["ok"]


@POSIX
@NOT_ROOT
def test_repair_failure_is_recorded_once_and_retried(daemon, settings, tmp_path):
    _, shim = _wired(daemon, settings, tmp_path)
    w = HookWatch(daemon, settings.home)
    w.check()
    shim.write_text(_packaged() + "\nexit 0\n", encoding="utf-8")
    os.chmod(shim.parent, 0o500)                                   # no temp file can be created next to the shim
    try:
        recs = w.check()
        assert _kinds(recs) == ["shim_modified", "shim_repair_failed"]
        assert recs[1]["arguments"]["cause"] == "eacces"           # an errno code, no exception text
        assert w.check() == []                                     # same condition, same cause: nothing new
        assert shim.read_text(encoding="utf-8") != _packaged()
    finally:
        os.chmod(shim.parent, 0o755)
    assert _kinds(w.check()) == ["shim_repaired"]                  # retried: no second event, no hook_restored
    assert shim.read_text(encoding="utf-8") == _packaged()
    assert daemon.protection.harness_state("claude-code") == "compromised"


def test_removed_hook_is_one_event_and_left_untouched(daemon, settings, tmp_path):
    hooks, _ = _wired(daemon, settings, tmp_path)
    w = HookWatch(daemon, settings.home)
    w.check()
    hooks.write_bytes(b'{"hooks": {}}  \n')
    before = hooks.read_bytes()
    [rec] = w.check()
    assert rec["arguments"]["tamper_kind"] == "hook_removed" and rec["arguments"]["path"] == str(hooks)
    assert w.check() == [] and w.check() == []
    assert hooks.read_bytes() == before                            # never edited
    assert _reasons(daemon) == {"claude-code:hook_removed"}


def test_reason_already_open_is_not_recorded_twice(daemon, settings, tmp_path):
    """Restored from protection-state.json (or raised on the hot path): the event exists; the shim is still repaired."""
    _, shim = _wired(daemon, settings, tmp_path)
    shim.write_text(_packaged() + "\nexit 0\n", encoding="utf-8")
    daemon.protection.add_reason("claude-code", "shim_modified", "", records.now_iso())
    assert _kinds(HookWatch(daemon, settings.home).check()) == ["shim_repaired"]


@POSIX
def test_widened_token_mode_is_restored_once_per_condition(daemon, settings, tmp_path):
    _wired(daemon, settings, tmp_path)
    w = HookWatch(daemon, settings.home)
    assert w.check() == []
    os.chmod(settings.token_path, 0o644)
    [rec] = w.check()
    args = rec["arguments"]
    assert args["tamper_kind"] == "token_permissions" and args["path"] == str(settings.token_path)
    assert (args["observed_mode"], args["restored_mode"], args["restore_error"]) == (0o644, 0o600, "")
    assert os.stat(settings.token_path).st_mode & 0o777 == 0o600
    assert rec["findings"][0]["subject"] == "home"
    assert w.check() == []
    assert _reasons(daemon) == {"home:token_permissions"}
    os.chmod(settings.token_path, 0o604)
    assert _kinds(w.check()) == ["token_permissions"]              # widened again after the restore: a new event
    os.chmod(settings.token_path, 0o604)
    assert _kinds(w.check()) == ["token_permissions"]              # the same mode again is still a new condition
    token = settings.token_path.read_text(encoding="utf-8").strip()
    assert all(token not in str(r) for r in daemon.spool.iter_records())


@POSIX
def test_failed_token_restore_is_noted_and_retried(daemon, settings, tmp_path, monkeypatch):
    _wired(daemon, settings, tmp_path)
    w = HookWatch(daemon, settings.home)
    w.check()
    tries = []
    monkeypatch.setattr(integrity, "restore_token_mode", lambda p: tries.append(p) or "chmod_failed:eperm")
    os.chmod(settings.token_path, 0o640)
    [rec] = w.check()
    assert rec["arguments"]["restore_error"] == "chmod_failed:eperm" and rec["arguments"]["restored_mode"] == 0o640
    assert w.check() == [] and len(tries) == 2                     # retried each pass, recorded once
    assert daemon.protection.aggregate() == "compromised"


@POSIX
def test_widened_mode_on_a_modified_token_does_not_repeat_the_digest_event(daemon, settings, tmp_path):
    """Property 16 counterexample: token_check stops at the mode, so that pass did not observe the digest; the next
    pass must not read the unchanged modified digest as new."""
    _wired(daemon, settings, tmp_path)
    w = HookWatch(daemon, settings.home)
    assert w.check() == []
    settings.token_path.write_text("tok-A\n", encoding="utf-8")
    os.chmod(settings.token_path, 0o600)
    assert _kinds(w.check()) == ["token_modified"]
    os.chmod(settings.token_path, 0o001)
    assert _kinds(w.check()) == ["token_permissions"]
    assert w.check() == []                                         # same digest, mode restored: nothing new
    assert _reasons(daemon) == {"home:token_modified", "home:token_permissions"}


@POSIX
def test_failed_restore_keeps_the_digest_fingerprint(daemon, settings, tmp_path, monkeypatch):
    _wired(daemon, settings, tmp_path)
    w = HookWatch(daemon, settings.home)
    w.check()
    settings.token_path.write_text("tok-A\n", encoding="utf-8")
    os.chmod(settings.token_path, 0o600)
    assert _kinds(w.check()) == ["token_modified"]
    with monkeypatch.context() as mp:
        mp.setattr(integrity, "restore_token_mode", lambda p: "chmod_failed:eperm")
        os.chmod(settings.token_path, 0o640)
        assert _kinds(w.check()) == ["token_permissions"]
        assert w.check() == []                                     # digest not observable: carried forward
    assert w.check() == []                                         # restored; the digest is the one already recorded


def test_token_digest_and_presence(daemon, settings, tmp_path):
    _wired(daemon, settings, tmp_path)
    w = HookWatch(daemon, settings.home)
    w.check()
    pinned = daemon.baseline.token_sha256
    settings.token_path.write_text("other\n", encoding="utf-8")
    os.chmod(settings.token_path, 0o600)
    [rec] = w.check()
    assert rec["arguments"]["tamper_kind"] == "token_modified"
    assert rec["arguments"]["expected_sha256"] == pinned
    assert rec["arguments"]["observed_sha256"] == hashlib.sha256(b"other\n").hexdigest()
    assert w.check() == []
    settings.token_path.write_text("third\n", encoding="utf-8")
    assert _kinds(w.check()) == ["token_modified"]                 # a second, different digest
    settings.token_path.unlink()
    assert _kinds(w.check()) == ["token_missing"]
    assert w.check() == [] and not settings.token_path.exists()    # no replacement token created
    assert _reasons(daemon) == {"home:token_modified", "home:token_missing"}
    assert "other" not in str(list(daemon.spool.iter_records()))


def test_operator_explained_token_change_moves_the_baseline(daemon, settings, tmp_path):
    _wired(daemon, settings, tmp_path)
    w = HookWatch(daemon, settings.home)
    w.check()
    daemon.operator_actions.add(records.operator_action("token_rotate"))
    settings.token_path.write_text("rotated\n", encoding="utf-8")
    os.chmod(settings.token_path, 0o600)
    assert w.check() == []
    want = hashlib.sha256(b"rotated\n").hexdigest()
    assert daemon.baseline.token_sha256 == want and integrity.Baseline.load(settings.home).token_sha256 == want
    assert daemon.protection.reasons() == []                       # explained: no Tamper_Event, no reason


def test_operator_explained_shim_change_is_rebaselined_not_repaired(daemon, settings, tmp_path):
    _, shim = _wired(daemon, settings, tmp_path)
    w = HookWatch(daemon, settings.home)
    w.check()
    daemon.operator_actions.add(records.operator_action("init"))
    shim.write_text(_packaged() + "\n# local\n", encoding="utf-8")
    assert w.check() == [] and w.check() == []
    assert shim.read_text(encoding="utf-8").endswith("# local\n")  # the Operator's change stays
    assert daemon.baseline.shims["claude_code"] == hashlib.sha256(shim.read_bytes()).hexdigest()
    assert daemon.verifier.verify("claude-code").problem == ""
    assert daemon.protection.reasons() == []


def test_missing_identity_is_rewritten_from_memory(daemon, settings, tmp_path):
    _wired(daemon, settings, tmp_path)
    w = HookWatch(daemon, settings.home)
    assert w.check() == []
    (settings.home / identity.FILE).unlink()
    [rec] = w.check()
    assert rec["arguments"]["record"] == "identity_restored" and rec["arguments"]["tamper_kind"] == "identity_missing"
    assert identity.read(settings.home) == daemon.identity
    assert daemon.identity not in str(rec)
    assert w.check() == []
    (settings.home / identity.FILE).write_text("0" * 32 + "\n", encoding="utf-8")      # altered: rewritten too
    assert _kinds(w.check()) == ["identity_missing"]
    assert identity.read(settings.home) == daemon.identity
    assert _reasons(daemon) == {"home:identity_missing"}


def test_pass_runs_policy_guard_and_summaries(daemon, settings, tmp_path, monkeypatch):
    _wired(daemon, settings, tmp_path)
    calls = []
    monkeypatch.setattr(daemon.policy_guard, "check", lambda *a, **k: calls.append("policy"))
    monkeypatch.setattr(daemon.tamper, "pending_summaries", lambda *a, **k: calls.append("summaries") or [])
    monkeypatch.setattr(integrity, "token_check", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    HookWatch(daemon, settings.home).check()                       # a failing step does not stop the others
    assert calls == ["policy", "summaries"]
