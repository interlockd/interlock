"""Onboarding: `interlock init` / `uninstall` / mode switch against a sandboxed HOME, and the service manager's unit
files and command sequences with a fake runner (no launchctl/systemctl is touched)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from interlockd.cli import main
from interlockd.onboard import (
    STARTER_POLICY,
    Manifest,
    detect,
    remove_hook_groups,
    set_mode,
    workspace_mode_override,
)
from interlockd.service import ServiceManager


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text(json.dumps({"model": "x", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo hi"}]}]}}), encoding="utf-8")
    (home / ".codex").mkdir()
    proj = tmp_path / "proj"; proj.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))   # Windows: Path.home()
    monkeypatch.setenv("INTERLOCK_HOME", str(home / ".interlock"))
    monkeypatch.setenv("PATH", "/usr/bin:/bin")       # no claude/codex/kiro binaries: detection falls back to dirs
    monkeypatch.chdir(proj)
    return home


def test_detect_uses_config_dirs_and_kiro_workspace(sandbox, tmp_path):
    found = {d.name: d for d in detect()}
    assert found["claude-code"].present and found["codex"].present and not found["kiro"].present
    ws = tmp_path / "proj"; (ws / ".kiro").mkdir()
    k = {d.name: d for d in detect(ws)}["kiro"]
    assert k.present and k.target == ws / ".kiro" / "hooks" / "interlock.json"


def test_init_and_uninstall_round_trip(sandbox, capsys):
    il = sandbox / ".interlock"
    assert main(["init", "--yes", "--no-service"]) == 0
    out = capsys.readouterr().out
    assert "block  git push --force origin main" in out and "allow  pytest -q" in out
    settings = json.loads((sandbox / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert settings["model"] == "x" and "Stop" in settings["hooks"] and "PreToolUse" in settings["hooks"]
    assert "PreToolUse" in json.loads((sandbox / ".codex" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    assert (il / "policy.yaml").read_text(encoding="utf-8") == STARTER_POLICY
    assert os.name == "nt" or (il / "token").stat().st_mode & 0o777 == 0o600     # Windows: no POSIX modes
    man = Manifest.load(il)
    assert {h["harness"] for h in man.hooks} == {"claude-code", "codex"}
    # idempotent: a second init replaces our groups rather than duplicating them
    assert main(["init", "--yes", "--no-service"]) == 0
    assert len(json.loads((sandbox / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]["PreToolUse"]) == 1

    assert main(["uninstall", "--yes"]) == 0
    settings = json.loads((sandbox / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert settings == {"model": "x", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo hi"}]}]}}
    assert not (sandbox / ".codex" / "hooks.json").exists()          # init created it, uninstall removes it
    assert (il / "policy.yaml").exists() and not (il / "install-manifest.json").exists()
    assert main(["uninstall", "--yes", "--purge"]) == 0
    assert not il.exists()


def test_init_and_uninstall_are_recorded_operator_actions(sandbox):
    """11.1, 11.4: each command records its Operator_Action in the audit chain; uninstall leaves a Stop_Marker
    without expiry, so a shim that still runs reads the outage as operator_stopped."""
    from interlockd.lifecycle import read_stop_marker
    from interlockd.store.spool import Spool

    il = sandbox / ".interlock"
    assert main(["init", "--yes", "--no-service"]) == 0
    assert main(["uninstall", "--yes"]) == 0
    spool = Spool(il / "spool")
    actions = [r["arguments"]["action"] for r in spool.iter_records(reverse=False)
               if r.get("kind") == "control" and r["arguments"].get("record") == "operator_action"]
    assert actions == ["init", "uninstall"] and spool.verify()["ok"]
    marker = read_stop_marker(il)
    assert marker["action"] == "uninstall" and "expires_epoch" not in marker


def test_init_respects_harness_subset_and_enforce(sandbox):
    assert main(["init", "--yes", "--no-service", "--harness", "codex", "--enforce"]) == 0
    assert "PreToolUse" not in json.loads((sandbox / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]
    assert "mode: enforce" in (sandbox / ".interlock" / "policy.yaml").read_text(encoding="utf-8")


def test_init_without_tty_needs_yes(sandbox, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["init", "--no-service"]) == 1
    assert not (sandbox / ".interlock" / "policy.yaml").exists()


def test_set_mode_preserves_comments_and_detects_workspace_override(tmp_path):
    p = tmp_path / "policy.yaml"
    assert set_mode(p, "enforce") == "shadow"          # created from the starter policy
    text = p.read_text(encoding="utf-8")
    assert "mode: enforce" in text and "# shadow: decide and record" in text
    assert set_mode(p, "shadow") == "enforce"
    ws = tmp_path / "repo"; (ws / ".interlock").mkdir(parents=True)
    (ws / ".interlock" / "policy.yaml").write_text("mode: enforce\n", encoding="utf-8")
    assert workspace_mode_override(p, ws) == ws / ".interlock" / "policy.yaml"
    assert workspace_mode_override(p, tmp_path) is None
    with pytest.raises(ValueError):
        set_mode(p, "off")


def test_remove_hook_groups_keeps_foreign_hooks(tmp_path):
    f = tmp_path / "settings.json"
    f.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"command": "sh /x/interlock-hook.sh"}]},
                                                       {"matcher": "Bash", "hooks": [{"command": "other"}]}],
                                       "PostToolUse": [{"hooks": [{"command": "sh /x/interlock-hook.sh"}]}]}}), encoding="utf-8")
    assert remove_hook_groups(f, "/x/interlock-hook.sh")
    assert json.loads(f.read_text(encoding="utf-8")) == {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"command": "other"}]}]}}
    assert not remove_hook_groups(f, "/x/interlock-hook.sh")
    assert not remove_hook_groups(tmp_path / "missing.json", "x")


class FakeRunner:
    def __init__(self, fail_first: int = 0):
        self.calls: list[list[str]] = []
        self.fail_first = fail_first

    def __call__(self, cmd):
        self.calls.append(cmd)
        rc = 0
        if cmd[:2] == ["launchctl", "bootstrap"] and self.fail_first > 0:
            self.fail_first -= 1
            rc = 5
        if cmd[:2] in (["launchctl", "print"], ["launchctl", "kickstart"]):
            rc = 113   # not loaded
        return subprocess.CompletedProcess(cmd, rc, "", "")


def test_launchd_unit_and_sequence(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))   # Windows: Path.home()
    run = FakeRunner(fail_first=2)
    svc = ServiceManager(tmp_path / "ih", backend="launchd", python="/py", runner=run)
    assert svc.label.startswith("dev.interlock.daemon.")          # non-default home gets its own label
    unit = svc.install()
    xml = unit.read_text(encoding="utf-8")
    assert unit.parent == tmp_path / "Library" / "LaunchAgents"
    assert "<string>/py</string>" in xml and "<string>interlockd</string>" in xml and str(tmp_path / "ih") in xml
    svc.start()
    assert [c[:2] for c in run.calls].count(["launchctl", "bootstrap"]) == 3   # retried past the EIO window
    svc.uninstall()
    assert ["launchctl", "bootout", f"gui/{__import__('os').getuid()}/{svc.label}"] in run.calls and not unit.exists()


def test_systemd_unit(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    run = FakeRunner()
    svc = ServiceManager(tmp_path / "ih", backend="systemd", python="/py", runner=run)
    unit = svc.install()
    text = unit.read_text(encoding="utf-8")
    assert unit == tmp_path / "cfg" / "systemd" / "user" / svc.unit
    assert "ExecStart=/py -m interlockd --home" in text and "Restart=on-failure" in text
    assert ["systemctl", "--user", "enable", svc.unit] in run.calls
    svc.restart()
    assert ["systemctl", "--user", "restart", svc.unit] in run.calls


def test_process_backend_runs_the_daemon(tmp_path):
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
    svc = ServiceManager(tmp_path / "ih", listen=f"127.0.0.1:{port}", backend="process")
    try:
        svc.start()
        up = svc.wait_healthy(30)
        log = svc.log_path.read_text(encoding="utf-8") if svc.log_path.exists() else "<no log>"
        assert up and svc.status().running, f"daemon did not come up; log:\n{log[-3000:]}"
    finally:
        svc.stop()
    assert not svc.healthy() and not svc.pid_path.exists()
    assert Path(svc.log_path).exists()


def test_token_rotate(sandbox):
    il = sandbox / ".interlock"
    assert main(["init", "--yes", "--no-service"]) == 0
    before = (il / "token").read_text(encoding="utf-8")
    assert main(["token", "--rotate"]) == 0
    after = (il / "token").read_text(encoding="utf-8")
    assert after != before and len(after.strip()) > 30
    assert os.name == "nt" or (il / "token").stat().st_mode & 0o777 == 0o600
    assert not (il / "token.new").exists()


def test_remove_hook_groups_finds_windows_paths(tmp_path):
    """On Windows the shim path is JSON-escaped in agent configs (each backslash doubled)."""
    marker = r"C:\Users\me\.interlock\adapters\cursor\interlock-hook.py"
    f = tmp_path / "hooks.json"
    cmd = f'"C:\\Python312\\python.exe" -I -S "{marker}"'
    f.write_text(json.dumps({"version": 1, "hooks": {"preToolUse": [{"command": cmd}, {"command": "mine"}]}}), encoding="utf-8")
    assert remove_hook_groups(f, marker)
    assert json.loads(f.read_text(encoding="utf-8"))["hooks"] == {"preToolUse": [{"command": "mine"}]}


def test_token_rotate_and_mode_switch_restart_only_this_homes_daemon(sandbox, monkeypatch):
    """A daemon answering on the port that isn't this home's (another INTERLOCK_HOME, or the developer's own daemon
    while tests run) is never restarted: that leaked launchd jobs running sandbox daemons on the real port."""
    from interlockd.service import ServiceManager

    restarts = []
    monkeypatch.setattr(ServiceManager, "healthy", lambda self, timeout=1.0: True)        # someone answers on 7391
    monkeypatch.setattr(ServiceManager, "restart", lambda self: restarts.append(self.home))
    monkeypatch.setattr(ServiceManager, "wait_healthy", lambda self, seconds=8.0: True)
    assert main(["init", "--yes", "--no-service"]) == 0
    assert main(["token", "--rotate"]) == 0 and main(["enforce"]) == 0 and main(["shadow"]) == 0
    assert restarts == []                                             # no daemon.json here: not ours
    (sandbox / ".interlock" / "daemon.json").write_text(json.dumps({"pid": os.getpid()}), encoding="utf-8")
    assert main(["token", "--rotate"]) == 0 and main(["enforce"]) == 0
    assert len(restarts) == 2                                          # this home's daemon is running: restart it
