"""Hook watch: removed hooks and edited shims become control records in the audit chain; repairs are recorded too."""

from __future__ import annotations

from interlockd.cli import CLAUDE_SHIM_SRC
from interlockd.insights import build_report, format_report
from interlockd.onboard import Manifest
from interlockd.watch import HookWatch


def _install(settings, tmp_path):
    shim = settings.home / "adapters" / "claude-code" / "interlock-hook.sh"
    shim.parent.mkdir(parents=True)
    shim.write_text(CLAUDE_SHIM_SRC.read_text().replace("__HARNESS__", "claude-code"))
    hooks = tmp_path / "settings.json"
    hooks.write_text(f'{{"hooks": {{"PreToolUse": [{{"hooks": [{{"command": "sh {shim}"}}]}}]}}}}')
    Manifest(created_at="2026-10-18T00:00:00Z", hooks=[{"harness": "claude-code", "file": str(hooks), "marker": str(shim),
                                                         "created": False}]).save(settings.home)
    return hooks, shim


def test_changes_are_recorded(daemon, settings, tmp_path):
    hooks, shim = _install(settings, tmp_path)
    w = HookWatch(daemon, settings.home)
    assert w.check() == []                                         # intact at start: nothing to record
    shim.write_text(shim.read_text() + "\nexit 0\n")
    [rec] = w.check()
    assert rec["kind"] == "control" and rec["arguments"]["problem"] == "shim_modified"
    assert rec["findings"][0]["rule"] == "control.shim_modified"
    assert w.check() == []                                         # unchanged: recorded once
    hooks.write_text("{}")
    [rec] = w.check()
    assert rec["arguments"]["problem"] == "hook_removed"
    shim.write_text(CLAUDE_SHIM_SRC.read_text().replace("__HARNESS__", "claude-code"))
    hooks.write_text(f'{{"command": "sh {shim}"}}')
    [rec] = w.check()
    assert rec["arguments"]["problem"] == "restored" and rec["disposition"] == "allow"
    v = daemon.spool.verify()
    assert v["ok"] and v["records"] == 3                           # in the hash chain
    text = format_report(build_report(daemon.spool.iter_records(), days=7))
    assert "Hook changes" in text and "restored" in text


def test_first_check_records_existing_problems(daemon, settings, tmp_path):
    hooks, _ = _install(settings, tmp_path)
    hooks.write_text("{}")
    [rec] = HookWatch(daemon, settings.home).check()
    assert rec["arguments"]["problem"] == "hook_removed"


def test_upgrade_leftovers_are_refreshed_not_flagged(daemon, settings, tmp_path):
    _, shim = _install(settings, tmp_path)
    current = shim.read_text()
    shim.write_text(current.replace('VERSION="', 'VERSION="0.0.9-', 1))
    assert HookWatch(daemon, settings.home).check() == []
    assert shim.read_text() == current
