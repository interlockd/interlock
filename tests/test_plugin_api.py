"""Contract for interlockd.plugin_api (plugin API version 1): every public name, as plugins use it.

Changing what a test here expects is a breaking change for plugins: bump API_VERSION (see the module docstring).
"""

from __future__ import annotations

import argparse
import inspect
import json
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
             "tighten_policy", "compose_policies", "lint_policy")}
    assert sigs == {"settings_from_args": ["args"], "spool_dir": ["home"], "load_policy": ["home"],
                    "validate_policy": ["data"], "managed_policy_path": ["home"],
                    "check_managed_policy": ["data", "base", "home"], "effective_policy": ["policy", "home"],
                    "daemon_status": ["daemon"], "hook_status": ["home"], "decisions": ["spool", "since", "until"],
                    "tighten_policy": ["base", "data"], "compose_policies": ["docs"], "lint_policy": ["policy"]}


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
                      "policy_sha256"}
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
