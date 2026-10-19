"""Cedar mandate bindings: shell egress (curl, wget) is the same capability as a fetch tool, so the mandate sees
`net.egress` with the destination hosts. Skipped when cedarpy is not installed."""

from __future__ import annotations

import pytest

pytest.importorskip("cedarpy")

from interlockd.models import AdapterInfo, Context, InterlockEvent, ToolCall
from interlockd.pipeline import Daemon
from interlockd.policy import Policy
from interlockd.store.memory import MemoryRepository
from interlockd.store.spool import Spool

ALLOW_GITHUB_API = ('permit (principal, action == Interlock::Action::"net.egress", resource) '
                    'when { ["api.github.com"].containsAll(context.input.hosts) };')


def test_shell_egress_binds_to_net_egress(settings, tmp_path):
    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = [str(tmp_path)]
    pol.mandate.mode, pol.mandate.inline = "enforce", ALLOW_GITHUB_API
    d = Daemon(settings, spool=Spool(settings.spool_dir, fsync=False), repo=MemoryRepository(), policy=pol)

    def run(cmd, sid):
        return d.decide(InterlockEvent(kind="pre_action", adapter=AdapterInfo(name="claude-code"), session_hint=sid,
                                       tool_call=ToolCall(name="Bash", arguments={"command": cmd}), context=Context(cwd=str(tmp_path))))

    ok = run("curl -s https://api.github.com/repos/x/y", "a")
    assert ok.disposition == "allow" and "mandate" not in ok.unjudged
    bad = run("curl -s https://example.com", "b")
    assert bad.disposition == "block" and "mandate:net.egress" in {f.rule for f in bad.findings}
