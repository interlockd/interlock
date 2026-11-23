"""State-changing CLI commands record the Operator_Action first and write the Stop_Marker before any stop or restart
(Requirements 2.6, 3.1, 3.2, 3.15, 7.1, 8.2, 11.1, 11.4, 11.6, 11.10).

Every test runs against a sandboxed HOME / INTERLOCK_HOME with a fake service: nothing here talks to launchd,
systemd or the daemon of the machine running the suite.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from interlockd import cli, integrity, lifecycle, operator
from interlockd.cli import main
from interlockd.config import Settings
from interlockd.onboard import Manifest
from interlockd.protection import FILE as STATE_FILE
from interlockd.protection import ProtectionState
from interlockd.service import ServiceManager
from interlockd.store.spool import Spool


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text(json.dumps({"model": "x"}), encoding="utf-8")
    (home / ".codex").mkdir()
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("INTERLOCK_HOME", str(home / ".interlock"))
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.chdir(proj)
    return home


def _settings() -> Settings:
    return Settings.load(None)


def _actions(s: Settings) -> list[dict]:
    if not s.spool_dir.exists():
        return []
    return [r["arguments"] | {"event_id": r["event_id"]} for r in Spool(s.spool_dir).iter_records(reverse=False)
            if r.get("kind") == "control" and r["arguments"].get("record") == "operator_action"]


class FakeService:
    """Stands in for ServiceManager. Each stop / restart / uninstall snapshots what was on disk at that moment:
    the Stop_Marker and the operator actions already recorded."""

    backend = "process"
    label = "dev.interlock.daemon.test"

    def __init__(self, home: Path, running: bool = True):
        self.home = home
        self.running = running
        self.calls: list[dict] = []
        self.unit_path = home / "unit"
        self.log_path = home / "interlockd.log"

    stop_for = ServiceManager.stop_for          # the real marker-first wrappers, over the fake stop / restart
    restart_for = ServiceManager.restart_for

    def _snap(self, what: str) -> None:
        marker = lifecycle.read_stop_marker(self.home)
        s = _settings()
        self.calls.append({"what": what, "marker": (marker or {}).get("action"),
                           "expires": marker is not None and "expires_epoch" in marker,
                           "recorded": [a["action"] for a in _actions(s)],
                           "claude_hooked": "PreToolUse" in json.loads(
                               (Path(os.environ["HOME"]) / ".claude" / "settings.json").read_text("utf-8")
                           ).get("hooks", {})})

    def runs_here(self) -> bool:
        return self.running

    def stop(self) -> None:
        self._snap("stop")

    def restart(self) -> None:
        self._snap("restart")

    def uninstall(self) -> None:
        self._snap("uninstall")

    def wait_healthy(self, seconds: float = 8.0) -> bool:
        return True

    def install(self):
        raise AssertionError("tests use --no-service")

    start = install


@pytest.fixture
def svc(sandbox, monkeypatch):
    fake = FakeService(sandbox / ".interlock", running=False)
    monkeypatch.setattr(cli, "_service", lambda s, backend=None: fake)
    return fake


@pytest.fixture
def installed(svc):
    assert main(["init", "--yes", "--no-service"]) == 0
    svc.calls.clear()
    return svc


def _block_marker(home: Path) -> None:
    (home / lifecycle.STOP_MARKER).mkdir()          # the atomic rename over a directory fails: OSError


# ---- stop / restart ---------------------------------------------------------------------------------------------

def test_stop_records_then_writes_a_marker_without_expiry_then_stops(installed):
    assert main(["stop"]) == 0
    [call] = installed.calls
    assert call["what"] == "stop" and call["marker"] == "stop" and not call["expires"]
    assert call["recorded"][-1] == "stop"


def test_restart_writes_a_marker_with_expiry(installed):
    assert main(["restart"]) == 0
    [call] = installed.calls
    assert call["what"] == "restart" and call["marker"] == "restart" and call["expires"]
    assert call["recorded"][-1] == "restart"


@pytest.mark.parametrize("cmd", ["stop", "restart", "shadow", "enforce"])
def test_marker_failure_exits_1_and_leaves_the_daemon_alone(installed, capsys, cmd):
    installed.running = True
    _block_marker(installed.home)
    assert main([cmd]) == 1
    assert installed.calls == []
    assert f"cannot write {installed.home / 'stop-marker.json'} for {cmd}" in capsys.readouterr().err


# ---- shadow / enforce -------------------------------------------------------------------------------------------

def test_shadow_records_pins_and_restarts(installed):
    home = installed.home
    installed.running = True
    assert main(["shadow"]) == 0
    [call] = installed.calls
    assert call["what"] == "restart" and call["marker"] == "shadow" and call["expires"]
    assert call["recorded"][-1] == "shadow"
    data = (home / "policy.yaml").read_bytes()
    assert integrity.Baseline.load(home).policy_file_sha256 == hashlib.sha256(data).hexdigest()
    assert (home / "pinned" / "policy.yaml").read_bytes() == data


def test_mode_switch_while_down_updates_the_persisted_observing_reason(installed):
    home = installed.home
    ProtectionState(home, Spool(_settings().spool_dir), None, lambda: "enforce").save()
    assert main(["shadow"]) == 0
    assert json.loads((home / STATE_FILE).read_text("utf-8"))["observing"] is True
    assert main(["enforce"]) == 0
    assert json.loads((home / STATE_FILE).read_text("utf-8"))["observing"] is False
    assert installed.calls == []                      # nothing was running: nothing restarted


# ---- token --rotate ---------------------------------------------------------------------------------------------

def test_token_rotate_records_marks_rotates_rebaselines_and_restarts(installed):
    home = installed.home
    installed.running = True
    old = integrity.file_sha256(home / "token")
    assert main(["token", "--rotate"]) == 0
    [call] = installed.calls
    assert call["what"] == "restart" and call["marker"] == "token_rotate" and call["expires"]
    assert call["recorded"][-1] == "token_rotate"
    rec = _actions(_settings())[-1]
    assert rec["grace_s"] == 120 and rec["failed"] is False                   # 2.6: grace length on the record
    base = integrity.Baseline.load(home)
    assert base.token_sha256 == integrity.file_sha256(home / "token") != old
    assert base.token_sha256_previous == old
    assert os.name == "nt" or base.token_mode == 0o600


def test_token_rotation_failure_keeps_the_token_and_cancels_the_grace(installed, monkeypatch, capsys):
    home = installed.home
    installed.running = True
    before = (home / "token").read_bytes()

    def boom(path):
        raise OSError("disk full")

    monkeypatch.setattr("interlockd.auth.rotate_token", boom)
    assert main(["token", "--rotate"]) == 1
    assert "token rotation failed" in capsys.readouterr().err
    assert (home / "token").read_bytes() == before
    assert installed.calls == [] and lifecycle.read_stop_marker(home) is None
    first, second = _actions(_settings())[-2:]
    assert first["action"] == second["action"] == "token_rotate"
    assert second["failed"] is True and second["caused_by"] == first["event_id"]
    ops = operator.OperatorActions(Spool(_settings().spool_dir))
    ops.seed()
    assert [e["action"] for e in ops.recent()] == ["init"]                     # the rotation opened no grace period


def test_token_rotate_clears_token_reasons_when_the_daemon_is_down(installed):
    home = installed.home
    ps = ProtectionState(home, Spool(_settings().spool_dir), None, lambda: "enforce", harnesses=list)
    ps.add_reason("home", "token_permissions", "", "2026-10-17T10:00:00Z")
    ps.add_reason("home", "policy_modified", "", "2026-10-17T10:00:00Z")
    assert main(["token", "--rotate"]) == 0
    left = json.loads((home / STATE_FILE).read_text("utf-8"))["reasons"]
    assert set(left) == {"home__policy_modified"}


# ---- init -------------------------------------------------------------------------------------------------------

def test_init_records_first_and_rebuilds_the_baseline(svc):
    assert main(["init", "--yes", "--no-service"]) == 0
    s = _settings()
    assert _actions(s)[0]["action"] == "init"
    base = integrity.Baseline.load(s.home)
    shim = Path(next(h["marker"] for h in Manifest.load(s.home).hooks if h["harness"] == "claude-code"))
    assert base.shims["claude_code"] == hashlib.sha256(shim.read_bytes()).hexdigest()
    assert base.policy_file_sha256 == hashlib.sha256((s.home / "policy.yaml").read_bytes()).hexdigest()


def test_init_clears_only_enforcement_point_reasons(installed):
    home = installed.home
    s = _settings()
    ps = ProtectionState(home, Spool(s.spool_dir), None, lambda: "shadow", harnesses=list)
    for subject, reason in (("claude-code", "shim_modified"), ("codex", "hook_removed"), ("home", "policy_modified"),
                            ("home", "token_modified"), ("home", "state_unreadable")):
        ps.add_reason(subject, reason, "", "2026-10-17T10:00:00Z")
    assert main(["init", "--yes", "--no-service"]) == 0
    left = json.loads((home / STATE_FILE).read_text("utf-8"))["reasons"]
    assert set(left) == {"home__policy_modified", "home__token_modified", "home__state_unreadable"}
    [ack] = [r for r in Spool(s.spool_dir).iter_records(reverse=False)
             if r.get("kind") == "control" and r["arguments"].get("record") == "operator_ack"]
    assert set(ack["arguments"]["reasons"]) == {"claude-code:shim_modified", "codex:hook_removed"}


def test_rerunning_init_does_not_pin_a_modified_policy_or_token(installed):
    home = installed.home
    pinned_policy = integrity.Baseline.load(home).policy_file_sha256
    pinned_token = integrity.Baseline.load(home).token_sha256
    (home / "policy.yaml").write_text("mode: enforce\n", encoding="utf-8")
    (home / "token").write_text("swapped\n", encoding="utf-8")
    assert main(["init", "--yes", "--no-service"]) == 0
    base = integrity.Baseline.load(home)
    assert base.policy_file_sha256 == pinned_policy and base.token_sha256 == pinned_token


@pytest.mark.parametrize("version,restarted", [("0.0.1", True), (cli.__version__, False)])
def test_init_restarts_a_daemon_of_another_version_before_refreshing_shims(svc, version, restarted):
    home = svc.home
    home.mkdir(parents=True)
    (home / "daemon.json").write_text(json.dumps({"listen": "127.0.0.1:1", "pid": 1, "version": version}),
                                      encoding="utf-8")
    svc.running = True
    assert main(["init", "--yes", "--no-service"]) == 0
    if restarted:
        [call] = svc.calls
        assert call["what"] == "restart" and call["marker"] == "init" and call["recorded"] == ["init"]
        assert call["claude_hooked"] is False            # the shims and hooks came after the restart
    else:
        assert svc.calls == []


# ---- uninstall --------------------------------------------------------------------------------------------------

def _with_service(home: Path) -> None:
    man = Manifest.load(home)
    man.service = {"backend": "process", "label": "x", "unit_path": "x"}
    man.save(home)


def test_uninstall_records_removes_marks_then_stops(installed):
    _with_service(installed.home)
    assert main(["uninstall", "--yes"]) == 0
    [call] = installed.calls
    assert call["what"] == "uninstall" and call["marker"] == "uninstall" and not call["expires"]
    assert call["recorded"][-1] == "uninstall" and call["claude_hooked"] is False


def test_uninstall_continues_past_a_failed_step_and_exits_1(installed, sandbox, capsys):
    _with_service(installed.home)
    codex = sandbox / ".codex" / "hooks.json"
    codex.unlink()
    codex.mkdir()                                       # cannot be read as a hook config
    assert main(["uninstall", "--yes"]) == 1
    err = capsys.readouterr().err
    assert "could not remove the codex hooks" in err and str(codex) in err
    [call] = installed.calls                            # the daemon was still stopped, after the marker
    assert call["what"] == "uninstall" and call["marker"] == "uninstall" and call["claude_hooked"] is False


def test_uninstall_reports_a_marker_failure_and_still_stops(installed, capsys):
    _with_service(installed.home)
    _block_marker(installed.home)
    assert main(["uninstall", "--yes"]) == 1
    assert "could not write the stop marker" in capsys.readouterr().err
    assert [c["what"] for c in installed.calls] == ["uninstall"]
