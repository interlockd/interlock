"""`interlock report` aggregation and `interlock doctor` checks (token, daemon, policy, hooks, shim tamper)."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

import pytest
from conftest import installed_shim_name

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
    monkeypatch.setenv("USERPROFILE", str(home)); monkeypatch.setenv("INTERLOCK_HOME", str(home / ".interlock"))   # Windows: Path.home()
    monkeypatch.setenv("PATH", "/usr/bin:/bin"); monkeypatch.chdir(tmp_path)
    il = home / ".interlock"; il.mkdir()
    (il / "config.json").write_text(json.dumps({"listen": "127.0.0.1:9"}), encoding="utf-8")   # nothing listens on port 9
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

    shim = sandbox / ".interlock" / "adapters" / "claude-code" / installed_shim_name()
    shim.write_text(shim.read_text(encoding="utf-8") + "\nexit 0\n", encoding="utf-8")                     # an agent neutering its own gate
    c = _checks(sandbox)
    assert not c["hooks claude-code"].ok and "tampered" in c["hooks claude-code"].detail

    settings = sandbox / ".claude" / "settings.json"
    settings.write_text(json.dumps({"hooks": {}}), encoding="utf-8")                       # hook removed
    c = _checks(sandbox)
    assert not c["hooks claude-code"].ok and "missing" in c["hooks claude-code"].detail


def test_doctor_flags_loose_token_and_bad_policy(sandbox):
    assert main(["init", "--yes", "--no-service"]) == 0
    il = sandbox / ".interlock"
    (il / "token").chmod(0o644)
    (il / "policy.yaml").write_text("mode: sideways\n", encoding="utf-8")
    c = _checks(sandbox)
    assert not c["policy"].ok
    assert not c["token"].ok if os.name != "nt" else c["token"].warn      # Windows: modes aren't checked, said so


def test_report_includes_gateway_interventions(tmp_path):
    from interlockd.insights import add_gateway_log

    log = tmp_path / "mcp-proxy.log"
    log.write_text("2026-10-17T11:00:00Z [fake] pinned 4 tool definition(s): a, b, c, d\n"
                   "2026-10-17T11:00:00Z [fake] hid tool add: description reads as instructions to the model (0.84: ...)\n"
                   "2026-10-17T11:01:00Z [gh] would hide (shadow) tool shell: definition changed since it was pinned\n"
                   "2026-10-01T11:00:00Z [old] hid tool x: too old\n", encoding="utf-8")
    r = build_report([], days=7, now=NOW)
    add_gateway_log(r, log, now=NOW)
    assert r.gateway_pinned == 4 and len(r.gateway_hidden) == 2 and r.gateway_hidden[1].endswith("(shadow)")
    text = format_report(r)
    assert "MCP gateway: 4 tool definitions pinned" in text and "fake/add" in text


def test_every_rule_has_a_description():
    from interlockd.det import RULES, flow, mcp, packs  # noqa: F401  register every rule
    from interlockd.det.describe import WHY

    assert set(RULES) <= set(WHY), sorted(set(RULES) - set(WHY))


def test_explain(tmp_path, monkeypatch, capsys):
    from interlockd.cli import main
    from interlockd.store.spool import Spool

    monkeypatch.setenv("INTERLOCK_HOME", str(tmp_path))
    Spool(tmp_path / "spool").append({"event_id": "01ABC", "received_at": "2026-10-17T10:00:00Z", "tool_name": "Bash",
        "agent_type": "codex", "disposition": "block", "mode": "enforce", "arguments": {"command": "git push --force origin main"},
        "notice": "[interlock] refused", "findings": [{"rule": "git.force_push_protected_branch", "severity": "critical"}]})
    assert main(["explain"]) == 0
    out = capsys.readouterr().out
    assert "refused a Bash call from codex" in out and "rewrites shared history" in out and "overrides:" in out
    assert main(["explain", "01A"]) == 0 and main(["explain", "zzz"]) == 1


def test_replay_shows_policy_changes(tmp_path, monkeypatch, capsys):
    from interlockd.cli import main
    from interlockd.store.spool import Spool

    monkeypatch.setenv("INTERLOCK_HOME", str(tmp_path)); monkeypatch.setenv("HOME", str(tmp_path))
    now = datetime.now(UTC).isoformat()
    sp = Spool(tmp_path / "spool")
    sp.append({"event_id": "a", "received_at": now, "kind": "pre_action", "tool_name": "Bash", "disposition": "allow",
               "arguments": {"command": "git push --force origin main"}, "cwd": str(tmp_path)})
    sp.append({"event_id": "b", "received_at": now, "kind": "pre_action", "tool_name": "Bash", "disposition": "allow",
               "arguments": {"command": "ls"}, "cwd": str(tmp_path)})
    assert main(["replay"]) == 0
    out = capsys.readouterr().out
    assert "replayed 2" in out and "1 decision(s) would change: 1 newly stopped" in out and "allow -> block" in out
    (tmp_path / "policy.yaml").write_text("packs:\n  overrides:\n    git.force_push_protected_branch: { action: allow }\n", encoding="utf-8")
    assert main(["replay"]) == 0 and "no decision would change" in capsys.readouterr().out


def test_version_compare_and_opt_out(monkeypatch):
    from interlockd.insights import _newer, latest_release

    assert _newer("0.1.1", "0.1.0") and _newer("0.2.0", "0.1.9") and _newer("0.1.0", "0.1.0a0")
    assert not _newer("0.1.0", "0.1.0") and not _newer("0.1.0a0", "0.1.0")
    monkeypatch.setenv("INTERLOCK_NO_UPDATE_CHECK", "1")
    assert latest_release() is None


# ------------------------------------------------------------------ protection in status / doctor (hook-tamper-detection 10.4)

IDENT = "0123456789abcdef0123456789abcdef"
PINNED, ON_DISK = "a" * 64, "b" * 64


def _snapshot(*, harness_reasons=(), home_reasons=(), aggregate=None):
    hs = {"claude-code": {"state": "compromised" if harness_reasons else "protected",
                          "reasons": [{"reason": r, "detected_at": "2026-10-17T10:00:00Z"} for r in harness_reasons]}}
    hr = [{"reason": r, "detected_at": "2026-10-17T10:01:00Z"} for r in home_reasons]
    agg = aggregate or ("compromised" if harness_reasons or home_reasons else "protected")
    return {"status": "ok", "version": "x", "mode": "enforce",
            "protection": {"aggregate": agg, "harnesses": hs, "home_reasons": hr, "last_tamper_at": None,
                           "observing": False},
            "policy_pin": {"pinned_sha256": PINNED, "on_disk_sha256": ON_DISK if "policy_modified" in home_reasons
                           else PINNED, "modified": "policy_modified" in home_reasons},
            "fail_mode_tamper": "closed"}


@pytest.fixture
def phome(tmp_path):
    from interlockd import identity

    home = tmp_path / "il"
    home.mkdir()
    identity.write(home, IDENT)
    return home


def _stub(body, ident=(IDENT,)):
    from shim_stub import Reply, StubDaemon

    return StubDaemon(Reply(body=json.dumps(body), identity=list(ident)))


def test_status_prints_protection_first_with_reasons_and_policy_digests(phome):
    from interlockd import records
    from interlockd.insights import format_protection_status
    from interlockd.store.spool import Spool

    Spool(phome / "spool").append(records.policy_modified("policy", str(phome / "policy.yaml"), PINNED, ON_DISK,
                                                          changed=["mode"], added=["fail_mode"]))
    with _stub(_snapshot(harness_reasons=["shim_modified"], home_reasons=["policy_modified"])) as stub:
        text, rc = format_protection_status(phome, stub.listen)
        assert all(r.header("authorization") == [] for r in stub.requests)      # the token is never sent
    lines = text.splitlines()
    assert lines[0] == "protection  compromised" and rc == 1
    shim = next(ln for ln in lines if "shim_modified" in ln)
    assert "claude-code" in shim and "2026-10-17T10:00:00Z" in shim and "interlock init" in shim and "interlock ack" in shim
    assert any("policy_modified" in ln and "interlock policy accept" in ln for ln in lines)
    assert any(PINNED in ln for ln in lines) and any(ON_DISK in ln for ln in lines)
    assert any("added: fail_mode" in ln and "changed: mode" in ln for ln in lines)


def test_status_protected_and_observing(phome):
    from interlockd.insights import format_protection_status

    with _stub(_snapshot()) as stub:
        assert format_protection_status(phome, stub.listen) == ("protection  protected", 0)
    with _stub(_snapshot(aggregate="observing")) as stub:
        assert format_protection_status(phome, stub.listen) == ("protection  observing", 0)


@pytest.mark.parametrize("ident", [(), ("f" * 32,), (IDENT, IDENT)])
def test_status_refuses_an_unverified_listener(phome, ident):
    from interlockd.insights import format_protection_status

    with _stub(_snapshot(), ident=ident) as stub:       # claims "protected", but cannot prove it is this home's daemon
        text, rc = format_protection_status(phome, stub.listen)
    assert text.splitlines()[0] == "protection  compromised daemon_identity" and rc == 1


def test_status_unreachable_stopped_versus_lost(phome):
    from interlockd import lifecycle
    from interlockd.insights import format_protection_status

    text, rc = format_protection_status(phome, "127.0.0.1:9")
    assert text.splitlines()[0] == "protection  compromised daemon_unreachable" and rc == 1
    assert "interlock start" in text
    lifecycle.write_stop_marker(phome, "stop")
    text, rc = format_protection_status(phome, "127.0.0.1:9")
    assert text.splitlines()[0] == "protection  stopped" and rc == 0 and "interlock stop" in text


def test_status_command_first_line_and_exit(sandbox, capsys):
    assert main(["init", "--yes", "--no-service"]) == 0
    capsys.readouterr()
    assert main(["status", "--backend", "process"]) == 1                     # nothing listens on port 9, no marker
    assert capsys.readouterr().out.splitlines()[0] == "protection  compromised daemon_unreachable"


def test_status_against_private_daemon(daemon):
    """A private ApiServer in a temporary Home: the identity header verifies and the snapshot is what status prints."""
    from interlockd import identity
    from interlockd.api import ApiServer
    from interlockd.insights import format_protection_status
    from interlockd.protection import ProtectionState

    home = daemon.settings.home
    home.mkdir(parents=True, exist_ok=True)
    identity.write(home, IDENT)
    daemon.protection = ProtectionState(home, daemon.spool, None, lambda: "enforce", harnesses=lambda: ["codex"])
    daemon.protection.add_reason("codex", "hook_removed", "01ABC", "2026-10-17T10:00:00Z")
    s = ApiServer(daemon, "tok", "127.0.0.1", 0, identity=IDENT)
    s.start_background()
    try:
        host, port = s.address
        text, rc = format_protection_status(home, f"{host}:{port}")
    finally:
        s.shutdown()
    assert text.splitlines()[0] == "protection  compromised" and rc == 1
    assert any("codex" in ln and "hook_removed" in ln for ln in text.splitlines())


def _spool_tamper(home):
    from interlockd import records
    from interlockd.store.spool import Spool

    sp = Spool(home / "spool")
    sp.append(records.tamper_event("shim_modified", "codex", "/x", at="2026-10-17T08:00:00.000Z"))     # before the ack
    sp.append(records.operator_ack(["codex:shim_modified"], at="2026-10-17T09:00:00.000Z"))
    for i in range(55):
        sp.append(records.tamper_event("hook_removed", "claude-code", "/y", at=f"2026-10-17T10:{i:02d}:00.000Z"))
    sp.append(records.operator_action("selftest", at="2026-10-17T11:00:00.000Z"))
    sp.append(records.token_rejected("claude-code", "127.0.0.1:7391", at="2026-10-17T11:00:30.000Z"))   # selftest's
    sp.append(records.token_rejected("cursor", "127.0.0.1:7391", at="2026-10-17T11:05:00.000Z"))        # after grace


def test_tamper_events_since_last_ack_without_selftest_rejections(phome):
    from interlockd.insights import tamper_events

    _spool_tamper(phome)
    events, since = tamper_events(phome)
    assert since.startswith("2026-10-17T09:00:00") and len(events) == 56
    assert events[0]["kind"] == "token_rejected" and events[0]["subject"] == "cursor"
    assert not any(e["subject"] == "codex" for e in events)


def _doctor(home, listen="127.0.0.1:9"):
    from interlockd.insights import Check, fetch_health, protection_checks

    checks: list[Check] = protection_checks(home, fetch_health(home, listen), "closed")
    return {c.name: c for c in checks}, checks


def test_doctor_protection_block(phome):
    _spool_tamper(phome)
    (phome / "hook.log").write_text(
        f"{datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')} tamper daemon_lost harness=codex tool=Bash kind=pre "
        "addr=127.0.0.1:7391 status=- fail_mode=closed\n2020-01-01T00:00:00Z tamper token_rejected harness=x\n",
        encoding="utf-8")
    with _stub(_snapshot(harness_reasons=["shim_modified"], home_reasons=["policy_modified"])) as stub:
        c, checks = _doctor(phome, stub.listen)
    assert not c["protection"].ok and not c["tamper claude-code"].ok and not c["tamper home"].ok
    assert "interlock policy diff" in c["tamper home"].fix and any(ON_DISK in ln for ln in c["tamper home"].lines)
    ev = c["tamper events"]
    assert ev.warn and "56 since" in ev.detail and "latest 50" in ev.detail and len(ev.lines) == 50
    assert not c["baseline"].ok and "interlock init" in c["baseline"].fix
    assert c["identity"].ok and "matches" in c["identity"].detail
    hl = c["hook.log tamper"]
    assert hl.warn and "daemon_lost 1" in hl.detail and len(hl.lines) == 1
    text, rc = format_doctor(checks)
    assert rc == 1 and "56 since" in text and "hook_removed" in text


def test_doctor_fail_mode_tamper_open_is_a_warning_only(phome):
    from interlockd.insights import fetch_health, protection_checks

    body = _snapshot() | {"fail_mode_tamper": "open"}
    with _stub(body) as stub:
        checks = [c for c in protection_checks(phome, fetch_health(phome, stub.listen), "closed")
                  if c.name != "baseline"]                                  # no baseline in this bare home
    fm = next(c for c in checks if c.name == "fail_mode.tamper")
    assert fm.warn and "open" in fm.detail and "tamper: closed" in fm.fix
    assert format_doctor(checks)[1] == 0                                    # the warning alone does not fail


def test_doctor_identity_checks(phome):
    from interlockd import integrity

    integrity.Baseline.from_disk(phome, None).save(phome)
    c, _ = _doctor(phome)
    assert c["identity"].ok and "not compared" in c["identity"].detail and c["baseline"].ok
    assert not c["protection"].ok and "daemon_unreachable" in c["protection"].detail
    with _stub(_snapshot(), ident=["f" * 32]) as stub:
        c, _ = _doctor(phome, stub.listen)
    assert not c["identity"].ok and "different identity" in c["identity"].detail
    if os.name != "nt":
        (phome / "identity").chmod(0o644)
        c, _ = _doctor(phome)
        assert not c["identity"].ok and "0o644" in c["identity"].detail
    (phome / "identity").unlink()
    c, _ = _doctor(phome)
    assert not c["identity"].ok and "interlock restart" in c["identity"].fix


def test_doctor_lists_persisted_reasons_when_the_daemon_is_down(phome):
    from interlockd.protection import ProtectionState
    from interlockd.store.spool import Spool

    ps = ProtectionState(phome, Spool(phome / "spool"), None, lambda: "enforce", harnesses=list)
    ps.add_reason("home", "token_permissions", "01ABC", "2026-10-17T10:00:00Z")
    c, _ = _doctor(phome)
    assert "token_permissions" in c["tamper home"].detail and "last recorded" in c["tamper home"].detail


def test_status_names_a_daemon_from_before_identities(tmp_path):
    from interlockd.insights import format_protection_status

    home = tmp_path / "old"
    home.mkdir()                                   # no identity file, and the listener sends no header: a 0.1.x daemon
    with _stub(_snapshot(), ident=()) as stub:
        text, rc = format_protection_status(home, stub.listen)
    assert text.splitlines()[0] == "protection  compromised daemon_identity" and rc == 1
    assert "before identities" in text and "interlock restart" in text
