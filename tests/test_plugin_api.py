"""Contract for interlockd.plugin_api (plugin API version 1): every public name, as plugins use it.

Changing what a test here expects is a breaking change for plugins: bump API_VERSION (see the module docstring).
"""

from __future__ import annotations

import argparse
import inspect
import json
import threading
from datetime import UTC, datetime, timedelta

import pytest

from interlockd import __version__, plugin_api, plugins
from interlockd.config import Settings
from interlockd.models import AdapterInfo, Context, InterlockEvent, ToolCall
from interlockd.pipeline import Daemon
from interlockd.policy import Policy
from interlockd.store.memory import MemoryRepository
from interlockd.store.spool import Spool


def test_version_one_surface_is_complete():
    assert plugin_api.API_VERSION == 1 and plugin_api.INTERLOCKD_VERSION == __version__
    for name in plugin_api.__all__:
        assert hasattr(plugin_api, name), name
    sigs = {n: list(inspect.signature(getattr(plugin_api, n)).parameters) for n in
            ("settings_from_args", "spool_dir", "load_policy", "validate_policy", "managed_policy_path",
             "check_managed_policy", "effective_policy", "daemon_status", "hook_status", "decisions",
             "tighten_policy", "compose_policies", "lint_policy", "protection_status", "subscribe_protection",
             "pin_managed_policy", "record_operator_action", "startup_report")}
    assert sigs == {"settings_from_args": ["args"], "spool_dir": ["home"], "load_policy": ["home"],
                    "validate_policy": ["data"], "managed_policy_path": ["home"],
                    "check_managed_policy": ["data", "base", "home"], "effective_policy": ["policy", "home"],
                    "daemon_status": ["daemon"], "hook_status": ["home"], "decisions": ["spool", "since", "until"],
                    "tighten_policy": ["base", "data"], "compose_policies": ["docs"], "lint_policy": ["policy"],
                    "protection_status": ["daemon", "since"], "subscribe_protection": ["daemon", "callback"],
                    "pin_managed_policy": ["home", "daemon"],
                    "record_operator_action": ["home", "action", "harness", "daemon"],
                    "startup_report": ["daemon"]}
    assert set(plugin_api.StartupReport.__dataclass_fields__) == {"unexpected_exit", "calls_unjudged", "started_at"}
    assert set(plugin_api.ProtectionStatus.__dataclass_fields__) == {
        "aggregate", "harnesses", "home_reasons", "last_tamper_at", "tamper_count_since", "pinned_policy_sha256",
        "on_disk_policy_sha256", "operator_action"}
    assert set(plugin_api.HarnessProtection.__dataclass_fields__) == {"name", "state", "reasons", "detected_at"}


def test_settings_and_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("INTERLOCK_HOME", str(tmp_path / "ih"))
    s = plugin_api.settings_from_args(argparse.Namespace(home=None))
    assert s.home == tmp_path / "ih"
    assert plugin_api.spool_dir(tmp_path / "ih") == s.spool_dir
    assert plugin_api.managed_policy_path(tmp_path / "ih") == tmp_path / "ih" / "managed-policy.yaml"


def test_policy_load_validate_and_managed(tmp_path):
    home = tmp_path / "ih"; home.mkdir()
    (home / "policy.yaml").write_text("version: 1\nmode: shadow\n", encoding="utf-8")
    pol = plugin_api.load_policy(home)
    assert isinstance(pol, Policy) and pol.mode == "shadow"

    assert plugin_api.validate_policy({"mode": "enforce"}).mode == "enforce"
    for bad in ({"mode": "sometimes"}, ["not", "a", "mapping"]):
        with pytest.raises(ValueError):
            plugin_api.validate_policy(bad)

    # tighten-only: switching enforce on is kept, turning a pack off is reported as ignored
    ignored = plugin_api.check_managed_policy({"mode": "enforce", "packs": {"enabled": ["git"]}}, base=pol)
    assert any("packs" in k for k in ignored)
    assert plugin_api.check_managed_policy({"mode": "enforce"}, home=home) == []
    with pytest.raises(ValueError):
        plugin_api.check_managed_policy({"mode": 3})

    assert plugin_api.effective_policy(pol, home).mode == "shadow"                       # no managed file
    plugin_api.managed_policy_path(home).write_text("mode: enforce\n", encoding="utf-8")
    eff = plugin_api.effective_policy(pol, home)
    assert eff.mode == "enforce" and eff.sha256 != pol.sha256


def test_daemon_status_and_decisions(tmp_path):
    s = Settings(home=tmp_path / "ih")
    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = [str(tmp_path)]
    d = Daemon(s, spool=Spool(s.spool_dir), repo=MemoryRepository(), policy=pol)

    st = plugin_api.daemon_status(d)
    assert (st.mode, st.judge, st.probe, st.ledger, st.spool_dir) == ("enforce", "off", "ok", "ok", s.spool_dir)
    assert st.policy is pol
    assert plugin_api.daemon_status(None).mode == "shadow"

    before = datetime.now(UTC) - timedelta(seconds=1)
    for cmd in ("git push --force origin main", "ls"):
        d.decide(InterlockEvent(kind="pre_action", adapter=AdapterInfo(name="claude-code"), session_hint="s1",
                                tool_call=ToolCall(name="Bash", arguments={"command": cmd}),
                                context=Context(cwd=str(tmp_path))))
    got = list(plugin_api.decisions(s.spool_dir, before, datetime.now(UTC) + timedelta(seconds=1)))
    assert [g.disposition for g in got] == ["block", "allow"]
    assert got[0].kind == "pre_action" and not got[0].selftest and isinstance(got[0].received_at, datetime)
    assert "git.force_push_protected_branch" in {r for r, _ in got[0].findings}
    assert all(c.startswith("security.") for _, c in got[0].findings)
    b = got[0]
    assert b.event_id and (b.agent, b.tool_name, b.mode) == ("claude-code", "Bash", "enforce")
    assert b.action_class and b.tier == 2 and b.policy_sha256      # "default" for a policy built in code
    assert len(b.finding_severities) == len(b.findings) and set(b.finding_severities) <= {"low", "medium", "high", "critical"}
    assert b.keyed_session(b"k1") == got[1].keyed_session(b"k1") != b.keyed_session(b"k2")
    assert b.keyed_session(b"k1").startswith("s_") and "s1" not in b.keyed_session(b"k1")
    assert list(plugin_api.decisions(s.spool_dir, before - timedelta(days=2), before)) == []
    assert list(plugin_api.decisions(tmp_path / "missing", before, datetime.now(UTC))) == []


def test_decisions_expose_no_tool_content(tmp_path):
    fields = set(plugin_api.Decision.__dataclass_fields__)
    assert fields == {"received_at", "kind", "disposition", "findings", "judged", "session_id", "selftest",
                      "event_id", "agent", "action_class", "tier", "mode", "tool_name", "finding_severities",
                      "policy_sha256", "tamper_kind", "protection_state"}
    # a record full of content: none of it reaches a Decision
    secret = "SECRET-7f3a"
    spool = tmp_path / "spool"
    spool.mkdir()
    rec = {"event_id": "evt_1", "received_at": datetime.now(UTC).isoformat(), "kind": "post_action",
           "adapter": "codex", "tool_name": "Bash", "disposition": "withhold", "mode": "enforce", "tier": 2,
           "normalized": {"action_class": "shell", "command": f"cat {secret}"}, "session_id": "s9",
           "arguments": {"command": f"echo {secret}"}, "cwd": f"/home/{secret}", "reason": f"saw {secret}",
           "notice": f"{secret}", "result_head": secret, "result_tail": secret, "evidence": [secret],
           "state": {"user_messages": [secret]}, "agent_user": secret, "agent_workspace": secret,
           "findings": [{"rule": "local.injection_heuristic", "category": "security.prompt_injection",
                         "severity": "high", "detector": "local", "path": f"/x/{secret}", "subject": secret}]}
    (spool / f"{datetime.now(UTC).date().isoformat()}.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
    got = list(plugin_api.decisions(spool, datetime.now(UTC) - timedelta(days=1), datetime.now(UTC) + timedelta(days=1)))
    assert len(got) == 1 and secret not in repr(got[0])
    assert (got[0].action_class, got[0].finding_severities, got[0].agent) == ("shell", ("high",), "codex")
    assert (got[0].tamper_kind, got[0].protection_state) == ("", "")

    # one control record per Tamper_Event kind (13.8): markers in path, digests, reason and every optional field
    from interlockd import records

    lines, marks = [], {}
    for kind in sorted(records.TAMPER_KINDS):
        mark = f"MARK-{kind}-9c1e"
        marks[kind] = mark
        rec = records.tamper_event(kind, "claude-code", "/tmp/shim.sh", "a" * 64, "b" * 64)
        rec["arguments"].update({"path": f"/home/{mark}/shim.sh", "expected_sha256": mark, "observed_sha256": mark,
                                 "reason": mark, "observed_mode": mark, "restored_mode": mark,
                                 "restore_error": mark, "adapter": mark, "addr": mark, "file": mark,
                                 "pinned_sha256": mark, "on_disk_sha256": mark, "added": [mark],
                                 "changed": [mark], "harness": mark})
        rec.update({"reason": mark, "cwd": mark, "notice": mark, "agent_type": mark, "state": {"x": mark},
                    "result_head": mark, "evidence": [mark], "guardrails": [mark]})
        rec["findings"][0].update({"path": mark, "subject": mark})
        lines.append(rec)
    ps = records.protection_state("claude-code", "protected", "compromised", ["claude-code:shim_modified"], "x")
    ps["arguments"].update({"reasons": ["MARK-ps-9c1e"], "caused_by": "MARK-ps-9c1e"})
    ps["reason"] = "MARK-ps-9c1e"
    oa = records.operator_action("ack", "", "protected")
    oa["arguments"]["caused_by"] = "MARK-oa-9c1e"
    bogus = records.operator_action("ack", "", "protected")
    bogus["arguments"].update({"protection_state": "MARK-bogus-9c1e", "tamper_kind": "MARK-bogus-9c1e"})
    lines += [ps, oa, bogus]
    (spool / f"{datetime.now(UTC).date().isoformat()}.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in lines), encoding="utf-8")
    ctl = [d for d in plugin_api.decisions(spool, datetime.now(UTC) - timedelta(days=1),
                                           datetime.now(UTC) + timedelta(days=1)) if d.kind == "control"]
    assert len(ctl) == len(records.TAMPER_KINDS) + 3
    assert "9c1e" not in repr(ctl)
    assert sorted(d.tamper_kind for d in ctl[:len(marks)]) == sorted(records.TAMPER_KINDS)
    assert all(d.disposition == "flag" and d.findings for d in ctl[:len(marks)])
    assert [(d.tamper_kind, d.protection_state) for d in ctl[len(marks):]] == [
        ("", "compromised"), ("", "protected"), ("", "")]


# ---- protection state ------------------------------------------------------------------------------------------

def _protected_daemon(tmp_path, mode="enforce", managed: str | None = None):
    from interlockd.cli import attach_integrity

    s = Settings(home=tmp_path / "ih")
    s.home.mkdir(parents=True, exist_ok=True)
    if managed is not None:
        plugin_api.managed_policy_path(s.home).write_text(managed, encoding="utf-8")
    pol = Policy(); pol.mode = mode; pol.trust.workspace_roots = [str(tmp_path)]
    d = Daemon(s, spool=Spool(s.spool_dir, fsync=False), repo=MemoryRepository(), policy=pol)
    attach_integrity(d, s.home, None)
    return d


def test_protection_status_and_tamper_count(tmp_path):
    from interlockd import records

    assert plugin_api.protection_status(None) == plugin_api.ProtectionStatus("unknown", (), (), None, 0,
                                                                             None, None, None)
    d = _protected_daemon(tmp_path)
    st = plugin_api.protection_status(d)
    assert (st.aggregate, st.home_reasons, st.last_tamper_at, st.tamper_count_since) == ("protected", (), None, 0)

    t0 = datetime.now(UTC) - timedelta(seconds=1)
    rec = records.tamper_event("shim_modified", "claude-code", "/x", "a" * 64, "b" * 64)
    d.spool.append(rec)
    d.protection.add_reason("claude-code", "shim_modified", rec["event_id"], rec["received_at"])
    d.protection.add_reason("home", "token_permissions", "", records.now_iso())
    d.spool.append(records.operator_action("selftest"))
    d.spool.append(records.token_rejected("claude-code", "127.0.0.1:7391"))     # a selftest's own rejection
    st = plugin_api.protection_status(d, since=t0)
    assert st.aggregate == "compromised" and st.home_reasons == ("token_permissions",)
    assert [(h.name, h.state, h.reasons) for h in st.harnesses] == [("claude-code", "compromised", ("shim_modified",))]
    assert st.last_tamper_at and st.harnesses[0].detected_at == (rec["received_at"],)
    assert st.tamper_count_since == 1
    assert plugin_api.protection_status(d, since=datetime.now(UTC) + timedelta(seconds=5)).tamper_count_since == 0
    assert st.operator_action is None

    d.protection.clear(lambda r: True, caused_by="")
    d.protection.set_observing(True, caused_by="")
    st = plugin_api.protection_status(d)
    assert (st.aggregate, st.operator_action) == ("observing", "shadow")


def test_subscribe_protection_runs_off_the_verdict_thread(tmp_path):
    d = _protected_daemon(tmp_path)
    got, seen = [], threading.Event()
    main = threading.get_ident()

    def cb(st):
        got.append((st.aggregate, threading.get_ident()))
        seen.set()

    unsubscribe = plugin_api.subscribe_protection(d, cb)
    d.protection.add_reason("home", "token_modified", "", "2026-10-17T10:00:00Z")
    assert seen.wait(5)
    assert got[-1][0] == "compromised" and got[-1][1] != main
    unsubscribe()
    seen.clear()
    d.protection.clear(lambda r: True, caused_by="")
    assert not seen.wait(0.3)
    assert plugin_api.subscribe_protection(None, cb)() is None


def test_startup_report_reads_this_starts_audit(tmp_path):
    from interlockd import lifecycle, records

    assert plugin_api.startup_report(None) == plugin_api.StartupReport(False, {}, None)
    d = _protected_daemon(tmp_path)
    home = d.settings.home
    assert plugin_api.startup_report(d) == plugin_api.StartupReport(False, {}, None)       # no daemon.json yet
    old = (datetime.now(UTC) - timedelta(hours=1)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    d.spool.append(records.daemon_unexpected_exit(41, "0.1.8", at=old))                   # a previous start's
    lifecycle.write_daemon_json(home, lifecycle.daemon_json_doc("127.0.0.1:7391"))
    rep = plugin_api.startup_report(d)
    assert (rep.unexpected_exit, rep.calls_unjudged) == (False, {}) and rep.started_at
    d.spool.append(records.daemon_started(False))
    d.spool.append(records.daemon_unexpected_exit(42, "0.1.8"))
    d.spool.append(records.calls_unjudged(unjudged=2, tamper_daemon_lost=3, span_from="2026-10-17T10:00:00Z",
                                          span_to="2026-10-17T10:05:00Z"))
    rep = plugin_api.startup_report(d)
    assert rep.unexpected_exit and rep.calls_unjudged == {
        "unjudged": 2, "tamper_token_rejected": 0, "tamper_daemon_identity": 0, "tamper_daemon_lost": 3}
    assert "/" not in repr(rep) and "0.1.8" not in repr(rep)


def _ops(spool_dir, action):
    sp = Spool(spool_dir, fsync=False)
    return [r for r in sp.iter_records() if r.get("kind") == "control"
            and r["arguments"].get("record") == "operator_action" and r["arguments"].get("action") == action]


def test_pin_managed_policy_without_a_daemon(tmp_path):
    import hashlib

    from interlockd import integrity
    from interlockd.policy import pin as policy_pin

    home = tmp_path / "ih"; home.mkdir()
    body = b"mode: enforce\n"
    plugin_api.managed_policy_path(home).write_bytes(body)
    digest = plugin_api.pin_managed_policy(home)
    assert digest == hashlib.sha256(body).hexdigest()
    assert integrity.Baseline.load(home).managed_policy_file_sha256 == digest
    assert policy_pin.pinned_copy(home, "managed", digest) == body
    [op] = _ops(home / "spool", "console_sync")
    assert op["arguments"]["via"] == "console"

    plugin_api.record_operator_action(home, "console_sync")
    assert len(_ops(home / "spool", "console_sync")) == 2
    with pytest.raises(ValueError):
        plugin_api.record_operator_action(home, "rm -rf")
    (home / integrity.BASELINE).write_text("{not json", encoding="utf-8")
    with pytest.raises(OSError):
        plugin_api.pin_managed_policy(home)


def test_pin_managed_policy_inside_the_daemon(tmp_path):
    d = _protected_daemon(tmp_path, managed="mode: enforce\n")
    home = d.settings.home
    assert d.baseline.managed_policy_file_sha256                # pinned at first start
    plugin_api.managed_policy_path(home).write_text("mode: enforce\nfail_mode: {default: closed}\n", encoding="utf-8")
    d.policy_guard.check()                                     # an unexplained managed edit: compromised
    assert "managed_policy_modified" in plugin_api.protection_status(d).home_reasons
    plugin_api.managed_policy_path(home).write_text("mode: enforce\npacks: {}\n", encoding="utf-8")
    digest = plugin_api.pin_managed_policy(home, daemon=d)
    assert d.baseline.managed_policy_file_sha256 == digest
    st = plugin_api.protection_status(d)
    assert st.aggregate == "protected" and st.home_reasons == ()
    assert len(_ops(d.spool.dir, "console_sync")) == 1


def test_hook_status_without_init(tmp_path):
    assert plugin_api.hook_status(tmp_path / "ih") == []


def test_plugin_needing_a_newer_api_is_skipped(monkeypatch):
    import types

    newer = types.ModuleType("needs_v2"); newer.PLUGIN_API = 2
    ok = types.ModuleType("needs_v1"); ok.PLUGIN_API = 1

    class EP:
        def __init__(self, name, mod):
            self.name, self.value, self.dist, self._m = name, f"{name}.plugin", None, mod

        def load(self):
            return self._m

    monkeypatch.setattr(plugins, "_entry_points", lambda: [EP("a_new", newer), EP("b_ok", ok)])
    plugins.reset()
    try:
        loaded = {p.name: p for p in plugins.load()}
        assert loaded["a_new"].module is None and "needs plugin API 2" in loaded["a_new"].error
        assert loaded["b_ok"].module is ok and not loaded["b_ok"].error
    finally:
        plugins.reset()


def test_tighten_compose_and_lint():
    base = plugin_api.validate_policy({})
    pol, ignored = plugin_api.tighten_policy(base, {"mode": "enforce", "trust": {"allowed_hosts": ["evil.example"]},
                                                    "sha256": "x"})
    assert pol.mode == "enforce" and ignored == ["trust.allowed_hosts (hosts you have not allowed)"]
    doc = plugin_api.compose_policies([{"mode": "enforce"}, {"trust": {"protected_branches": ["prod"]}}, "junk"])
    assert doc == {"mode": "enforce", "trust": {"protected_branches": ["prod"]}}
    one, _ = plugin_api.tighten_policy(base, doc)
    assert one.mode == "enforce" and "prod" in one.trust.protected_branches
    issues = plugin_api.lint_policy(plugin_api.validate_policy({"packs": {"overrides": {"shell.pipe_to_shel": {"action": "block"}}}}))
    assert issues and issues[0].level == "error" and "pipe_to_shell" in issues[0].message
