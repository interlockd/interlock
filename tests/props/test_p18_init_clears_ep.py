"""Property 18: `interlock init` clears exactly the enforcement-point reasons (Requirement 11.6).

Every example runs the real `cmd_init` against a sandboxed HOME / INTERLOCK_HOME with a fake ServiceManager and
`--no-service`; nothing here talks to launchd, systemd or the daemon of the machine running the suite. The daemon
of the sandboxed Home is down, so `init` clears the reasons in the persisted `protection-state.json` (the path a
running daemon takes, the ack route, is covered by tests/test_operator.py).

The token already exists before each example (the `installed` fixture ran `init` once). When `init` creates the
token itself it also clears the token reasons (Requirement 8.2); keeping the token in place makes this property
about the enforcement-point reasons only.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given

from interlockd import cli, operator, protection
from interlockd.cli import main
from interlockd.config import Settings
from interlockd.protection import ProtectionState
from interlockd.service import ServiceManager
from interlockd.store.spool import Spool

from .strategies import HARNESS_REASONS, HOME_REASONS, PROPS, reason_sets


class FakeService:
    """Stands in for ServiceManager (as in tests/test_cli_operator.py): never running, records any stop/restart."""

    backend = "process"
    label = "dev.interlock.daemon.test"

    def __init__(self, home):
        self.home = home
        self.calls: list[str] = []
        self.unit_path = home / "unit"
        self.log_path = home / "interlockd.log"

    stop_for = ServiceManager.stop_for
    restart_for = ServiceManager.restart_for

    def runs_here(self) -> bool:
        return False

    def stop(self) -> None:
        self.calls.append("stop")

    def restart(self) -> None:
        self.calls.append("restart")

    def uninstall(self) -> None:
        self.calls.append("uninstall")

    def wait_healthy(self, seconds: float = 8.0) -> bool:
        return True

    def install(self):
        raise AssertionError("tests use --no-service")

    start = install


@pytest.fixture
def installed(tmp_path, monkeypatch):
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
    fake = FakeService(home / ".interlock")
    monkeypatch.setattr(cli, "_service", lambda s, backend=None: fake)
    # The sandboxed Home has no daemon (and no identity file, so the real _deliver would return None before
    # connecting). Pin that down so no example can ever send anything to the live daemon on this machine.
    monkeypatch.setattr(operator, "_deliver", lambda *a, **k: None)
    assert main(["init", "--yes", "--no-service"]) == 0
    return fake


def test_strategy_code_sets_match_the_module():
    assert HARNESS_REASONS == protection.HARNESS_REASONS == protection.EP_REASONS
    assert HOME_REASONS == protection.HOME_REASONS


# Feature: hook-tamper-detection, Property 18: `init` clears exactly the enforcement-point reasons
# Each example runs a full `interlock init` (hook configs, shims, baseline, policy pin), about 30 ms, so the
# profile's 100 examples take a few seconds.
@PROPS
@given(reason_sets())
def test_init_clears_exactly_the_enforcement_point_reasons(installed, before):
    """**Validates: Requirements 11.6**"""
    home = installed.home
    s = Settings.load(None)
    assert s.token_path.exists()                     # precondition: init will not create (and clear) the token

    ps = ProtectionState(home, Spool(s.spool_dir), None, lambda: "enforce", harnesses=list)
    ps.save()                                        # replace the previous example's document
    for subject, reason in sorted(before):
        ps.add_reason(subject, reason, "", "2026-10-17T10:00:00Z")

    assert main(["init", "--yes", "--no-service"]) == 0
    assert installed.calls == []                     # nothing was running: nothing stopped or restarted

    after = ProtectionState.load(home, Spool(s.spool_dir), None, lambda: "enforce", harnesses=list)
    left = {(r.subject, r.reason) for r in after.reasons()}
    expected = {(subj, r) for subj, r in before if r not in protection.EP_REASONS}
    assert left == expected
