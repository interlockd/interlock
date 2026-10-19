"""`interlock capture`: hook calls are recorded with the reply sent, the report tells whether a block held, and the
export redacts the home path, user name and email addresses."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from interlockd import capture
from interlockd.api import ApiServer

FIX = Path(__file__).parent / "fixtures"


def _post(addr, harness, payload, event=None):
    body = {"adapter": {"name": harness, "version": "t", **({"event": event} if event else {})}, "payload": payload}
    req = urllib.request.Request(f"http://{addr[0]}:{addr[1]}/interlock/v1/hooks/{harness}?format={harness}",
                                 data=json.dumps(body).encode(), method="POST")
    req.add_header("authorization", "Bearer tok"); req.add_header("content-type", "application/json")
    return urllib.request.urlopen(req, timeout=10).read()


def test_capture_report_and_export(settings, tmp_path):
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool

    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = [str(tmp_path)]
    d = Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol)
    api = ApiServer(d, "tok", "127.0.0.1", 0); api.start_background()
    try:
        pre = json.loads((FIX / "claude-code" / "pre-bash-block.json").read_text())
        _post(api.address, "claude-code", pre)                                   # capture off: nothing recorded
        assert capture.load(settings.home) == {}
        capture.start(settings.home, ["claude-code"], 5)
        pre["user_email"] = "someone@corp.example"; pre["cwd"] = str(Path.home() / "proj")
        _post(api.address, "claude-code", pre)
        _post(api.address, "claude-code", json.loads((FIX / "claude-code" / "post-read-inject.json").read_text()))
        _post(api.address, "cursor", json.loads((FIX / "cursor" / min(p.name for p in (FIX / "cursor").glob("*.json"))).read_text()))
    finally:
        api.shutdown()
    caps = capture.load(settings.home)
    assert list(caps) == ["claude-code"] and len(caps["claude-code"]) == 2         # only the chosen agent
    rec = caps["claude-code"][0]
    assert rec["verdict"]["disposition"] == "block" and "permissionDecision" in rec["reply"]
    text = capture.report(caps)
    assert "block held: yes" in text and "PreToolUse" in text and "withhold" in text
    files = capture.export(caps, tmp_path / "out")
    exported = files[0].read_text()
    assert "someone@corp.example" not in exported and str(Path.home()) not in exported and "/Users/dev/proj" in exported
    assert capture.stop(settings.home) and not capture.active(settings.home, "claude-code")


def test_scratch_project(tmp_path):
    d = capture.scratch(tmp_path / "s")
    assert "assistant:" in (d / "README.md").read_text() and "mode: enforce" in (d / ".interlock" / "policy.yaml").read_text()
    assert (d / ".git").exists()
