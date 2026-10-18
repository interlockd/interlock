"""Onboarding: `interlock init` / `uninstall` / mode switch against a sandboxed HOME, and the service manager's unit
files and command sequences with a fake runner (no launchctl/systemctl is touched)."""

from __future__ import annotations

import json
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
    (home / ".claude" / "settings.json").write_text(json.dumps({"model": "x", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo hi"}]}]}}))
    (home / ".codex").mkdir()
    proj = tmp_path / "proj"; proj.mkdir()
    monkeypatch.setenv("HOME", str(home))
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
    settings = json.loads((sandbox / ".claude" / "settings.json").read_text())
    assert settings["model"] == "x" and "Stop" in settings["hooks"] and "PreToolUse" in settings["hooks"]
    assert "PreToolUse" in json.loads((sandbox / ".codex" / "hooks.json").read_text())["hooks"]
    assert (il / "policy.yaml").read_text() == STARTER_POLICY and (il / "token").stat().st_mode & 0o777 == 0o600
    man = Manifest.load(il)
    assert {h["harness"] for h in man.hooks} == {"claude-code", "codex"}
    # idempotent: a second init replaces our groups rather than duplicating them
    assert main(["init", "--yes", "--no-service"]) == 0
    assert len(json.loads((sandbox / ".claude" / "settings.json").read_text())["hooks"]["PreToolUse"]) == 1

    assert main(["uninstall", "--yes"]) == 0
    settings = json.loads((sandbox / ".claude" / "settings.json").read_text())
    assert settings == {"model": "x", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo hi"}]}]}}
    assert not (sandbox / ".codex" / "hooks.json").exists()          # init created it, uninstall removes it
    assert (il / "policy.yaml").exists() and not (il / "install-manifest.json").exists()
    assert main(["uninstall", "--yes", "--purge"]) == 0
    assert not il.exists()


def test_init_respects_harness_subset_and_enforce(sandbox):
    assert main(["init", "--yes", "--no-service", "--harness", "codex", "--enforce"]) == 0
    assert "PreToolUse" not in json.loads((sandbox / ".claude" / "settings.json").read_text())["hooks"]
    assert "mode: enforce" in (sandbox / ".interlock" / "policy.yaml").read_text()


def test_init_without_tty_needs_yes(sandbox, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["init", "--no-service"]) == 1
    assert not (sandbox / ".interlock" / "policy.yaml").exists()


def test_set_mode_preserves_comments_and_detects_workspace_override(tmp_path):
    p = tmp_path / "policy.yaml"
    assert set_mode(p, "enforce") == "shadow"          # created from the starter policy
    text = p.read_text()
    assert "mode: enforce" in text and "# shadow: decide and record" in text
    assert set_mode(p, "shadow") == "enforce"
    ws = tmp_path / "repo"; (ws / ".interlock").mkdir(parents=True)
    (ws / ".interlock" / "policy.yaml").write_text("mode: enforce\n")
    assert workspace_mode_override(p, ws) == ws / ".interlock" / "policy.yaml"
    assert workspace_mode_override(p, tmp_path) is None
    with pytest.raises(ValueError):
        set_mode(p, "off")


def test_remove_hook_groups_keeps_foreign_hooks(tmp_path):
    f = tmp_path / "settings.json"
    f.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"command": "sh /x/interlock-hook.sh"}]},
                                                       {"matcher": "Bash", "hooks": [{"command": "other"}]}],
                                       "PostToolUse": [{"hooks": [{"command": "sh /x/interlock-hook.sh"}]}]}}))
    assert remove_hook_groups(f, "/x/interlock-hook.sh")
    assert json.loads(f.read_text()) == {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"command": "other"}]}]}}
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
    run = FakeRunner(fail_first=2)
    svc = ServiceManager(tmp_path / "ih", backend="launchd", python="/py", runner=run)
    assert svc.label.startswith("dev.interlock.daemon.")          # non-default home gets its own label
    unit = svc.install()
    xml = unit.read_text()
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
    text = unit.read_text()
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
        log = svc.log_path.read_text() if svc.log_path.exists() else "<no log>"
        assert up and svc.status().running, f"daemon did not come up; log:\n{log[-3000:]}"
    finally:
        svc.stop()
    assert not svc.healthy() and not svc.pid_path.exists()
    assert Path(svc.log_path).exists()


def test_token_rotate(sandbox):
    il = sandbox / ".interlock"
    assert main(["init", "--yes", "--no-service"]) == 0
    before = (il / "token").read_text()
    assert main(["token", "--rotate"]) == 0
    after = (il / "token").read_text()
    assert after != before and len(after.strip()) > 30 and (il / "token").stat().st_mode & 0o777 == 0o600
    assert not (il / "token.new").exists()
