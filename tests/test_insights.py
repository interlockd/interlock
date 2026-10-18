"""`interlock report` aggregation and `interlock doctor` checks (token, daemon, policy, hooks, shim tamper)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from interlockd.cli import main
from interlockd.insights import build_report, format_doctor, format_report, run_doctor

NOW = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)


def _rec(disp, mode="shadow", kind="pre_action", rule=None, cmd="ls", age_h=1, agent="claude-code", ms=1.0):
    return {"received_at": (NOW - timedelta(hours=age_h)).isoformat().replace("+00:00", "Z"), "kind": kind,
            "disposition": disp, "mode": mode, "agent_type": agent, "tool_name": "Bash", "arguments": {"command": cmd},
            "findings": [{"rule": rule, "category": "security.malicious_command"}] if rule else [],
            "timing_ms": {"total": ms}, "reason": rule or ""}


def test_report_counts_shadow_would_and_enforced():
    recs = [_rec("allow"), _rec("block", rule="git.force_push_protected_branch", cmd="git push -f origin main"),
            _rec("ask", rule="packages.install_undeclared"), _rec("block", mode="enforce", rule="egress.secret_upload"),
            _rec("withhold", kind="post_action", mode="enforce", rule="local.injection_heuristic", agent="codex"),
            _rec("block", rule="old", age_h=24 * 9)]                                  # outside the window
    r = build_report(recs, days=7, now=NOW)
    assert r.total == 5 and r.pre == 4 and r.post == 1
    assert r.shadow_would == {"block": 1, "ask": 1} and r.enforced == {"block": 1, "withhold": 1}
    assert r.rules["git.force_push_protected_branch"] == 1 and "old" not in r.rules
    text = format_report(r)
    assert "enforce would have: blocked 1, asked on 1" in text and "git push -f origin main" in text
    assert "interlock enforce" in text


def test_report_empty_points_to_doctor():
    assert "interlock doctor" in format_report(build_report([], days=7, now=NOW))


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    home = tmp_path / "home"; (home / ".claude").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home)); monkeypatch.setenv("INTERLOCK_HOME", str(home / ".interlock"))
    monkeypatch.setenv("PATH", "/usr/bin:/bin"); monkeypatch.chdir(tmp_path)
    il = home / ".interlock"; il.mkdir()
    (il / "config.json").write_text(json.dumps({"listen": "127.0.0.1:9"}))   # nothing listens on port 9
    return home


def _checks(home):
    return {c.name: c for c in run_doctor(home / ".interlock", "127.0.0.1:9")}


def test_doctor_after_init_then_tamper(sandbox):
    assert main(["init", "--yes", "--no-service"]) == 0
    c = _checks(sandbox)
    assert c["token"].ok and c["policy"].ok and c["hooks claude-code"].ok
    assert not c["daemon"].ok                                            # no service was started
    _, rc = format_doctor(list(c.values()))
    assert rc == 1

    shim = sandbox / ".interlock" / "adapters" / "claude-code" / "interlock-hook.sh"
    shim.write_text(shim.read_text() + "\nexit 0\n")                     # an agent neutering its own gate
    c = _checks(sandbox)
    assert not c["hooks claude-code"].ok and "tampered" in c["hooks claude-code"].detail

    settings = sandbox / ".claude" / "settings.json"
    settings.write_text(json.dumps({"hooks": {}}))                       # hook removed
    c = _checks(sandbox)
    assert not c["hooks claude-code"].ok and "missing" in c["hooks claude-code"].detail


def test_doctor_flags_loose_token_and_bad_policy(sandbox):
    assert main(["init", "--yes", "--no-service"]) == 0
    il = sandbox / ".interlock"
    (il / "token").chmod(0o644)
    (il / "policy.yaml").write_text("mode: sideways\n")
    c = _checks(sandbox)
    assert not c["token"].ok and not c["policy"].ok
