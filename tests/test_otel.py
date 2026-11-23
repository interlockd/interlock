"""OpenTelemetry export: spans per decision over OTLP/HTTP JSON; a session is one trace; no arguments exported;
a dead collector never affects decisions; control records add only the tamper kind and protection state.
The only collector used is a local stub bound to 127.0.0.1."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from interlockd import records
from interlockd.models import AdapterInfo, Context, InterlockEvent, ToolCall
from interlockd.otel import span_from_record
from interlockd.pipeline import Daemon
from interlockd.policy import Policy
from interlockd.store.memory import MemoryRepository
from interlockd.store.spool import Spool


@pytest.fixture
def collector():
    got: list[dict] = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): ...

        def do_POST(self):
            got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            got[-1]["_auth"] = self.headers.get("x-api-key")
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"{}")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1/traces", got
    srv.shutdown()


def _ev(cmd, session="s1"):
    return InterlockEvent(kind="pre_action", adapter=AdapterInfo(name="claude-code"), session_hint=session,
                          tool_call=ToolCall(id="t1", name="Bash", arguments={"command": cmd}), context=Context(cwd="/ws"))


def _attrs(span):
    out = {}
    for a in span["attributes"]:
        v = a["value"]
        out[a["key"]] = v.get("stringValue", v.get("intValue", v.get("arrayValue")))
    return out


def test_spans_per_decision(settings, collector):
    url, got = collector
    settings.otlp_endpoint, settings.otlp_headers = url, {"x-api-key": "k"}
    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = ["/ws"]
    d = Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol)
    d.decide(_ev("git push --force origin main"))
    d.decide(_ev("ls -la"))
    d.decide(_ev("ls", session="s2"))
    d.otel.stop()
    spans = [sp for p in got for rs in p["resourceSpans"] for ss in rs["scopeSpans"] for sp in ss["spans"]]
    assert len(spans) == 3 and got[0]["_auth"] == "k"
    block = next(s for s in spans if _attrs(s).get("interlock.disposition") == "block")
    a = _attrs(block)
    assert a["gen_ai.tool.name"] == "Bash" and a["gen_ai.agent.name"] == "claude-code" and block["status"]["code"] == 2
    assert {"stringValue": "git.force_push_protected_branch"} in a["interlock.rules"]["values"]
    assert spans[0]["traceId"] == spans[1]["traceId"] != spans[2]["traceId"]           # one trace per session
    assert "git push" not in json.dumps(got)                                          # arguments never exported
    res = {x["key"]: x["value"]["stringValue"] for x in got[0]["resourceSpans"][0]["resource"]["attributes"]}
    assert res["service.name"] == "interlock"


def test_dead_collector_never_breaks_decisions(settings):
    settings.otlp_endpoint = "http://127.0.0.1:9/v1/traces"
    d = Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=Policy())
    assert d.decide(_ev("ls")).disposition == "allow"
    d.otel.stop()
    assert d.otel.dropped == 1 and d.otel.sent == 0


def test_cli_backfill(settings, collector, monkeypatch):
    from interlockd.cli import main

    url, got = collector
    Spool(settings.spool_dir).append({"event_id": "e1", "received_at": "2026-10-17T00:00:00Z", "kind": "pre_action",
                                      "tool_name": "Bash", "disposition": "allow", "session_id": "s"})
    monkeypatch.setenv("INTERLOCK_HOME", str(settings.home))
    assert main(["otel", "export", "--endpoint", url]) == 0 and len(got) == 1


# ---- control records (hook-tamper-detection, Requirement 13.5) -------------------------------------------------
DECISION_KEYS = {"gen_ai.operation.name", "gen_ai.tool.name", "gen_ai.tool.call.id", "gen_ai.agent.name",
                 "gen_ai.conversation.id", "interlock.event_id", "interlock.kind", "interlock.disposition",
                 "interlock.mode", "interlock.tier", "interlock.action_class", "interlock.rules",
                 "interlock.workspace", "interlock.policy_sha256", "interlock.unjudged"}
CONTROL_KEYS = {"interlock.tamper_kind", "interlock.protection_state"}
MARK = "PLANTEDMARK7f3a"


def _planted(kind: str) -> dict:
    """A tamper-kind control record with the marker in its path, digests, reason and every optional field."""
    rec = records.tamper_event(kind, "claude-code", f"/home/{MARK}/adapters/interlock-hook.sh",
                               reason=f"{MARK}_reason", observed_mode=0o644, restored_mode=0o600,
                               restore_error=f"{MARK}_err", mode="enforce", policy_sha256="a" * 64)
    a = rec["arguments"]
    a["expected_sha256"], a["observed_sha256"] = f"{MARK}-expected", f"{MARK}-observed"   # planted, not hex
    a["restore_error"], a["file"], a["cause"] = f"{MARK} err", f"/{MARK}/file", f"{MARK} cause"
    rec.update(reason=f"{MARK} reason text", cwd=f"/work/{MARK}", agent_workspace=f"/work/{MARK}",
               tool_call_id=f"{MARK}-call", state={"x": MARK}, answers=[MARK], guardrails=[MARK],
               result_summary=MARK, unjudged=[MARK])
    return rec


@pytest.mark.parametrize("kind", sorted(records.TAMPER_KINDS))
def test_control_span_is_content_free(kind):
    span = span_from_record(_planted(kind))
    a = _attrs(span)
    assert MARK not in json.dumps(span)
    assert a["interlock.tamper_kind"] == kind and a["interlock.kind"] == "control"
    assert set(a) <= DECISION_KEYS | CONTROL_KEYS
    assert {"stringValue": f"control.{kind}"} in a["interlock.rules"]["values"]


def test_control_span_protection_state():
    ps = span_from_record(records.protection_state("claude-code", "protected", "compromised", ["shim_modified"]))
    op = span_from_record(records.operator_action("shadow", protection_state="observing"))
    assert _attrs(ps)["interlock.protection_state"] == "compromised" and "interlock.tamper_kind" not in _attrs(ps)
    assert _attrs(op)["interlock.protection_state"] == "observing"


def test_control_span_drops_values_outside_the_fixed_sets():
    rec = records.protection_state("home", "protected", "compromised", [])
    rec["arguments"]["new"] = MARK
    rec["arguments"]["tamper_kind"] = MARK
    rec["findings"] = [{"rule": f"control.{MARK}"}, {"rule": MARK}]
    span = span_from_record(rec)
    assert MARK not in json.dumps(span)
    assert not CONTROL_KEYS & set(_attrs(span)) and "interlock.rules" not in _attrs(span)


def test_decision_span_has_no_control_attributes():
    rec = {"event_id": "e1", "received_at": "2026-10-17T00:00:00Z", "kind": "pre_action", "tool_name": "Bash",
           "disposition": "allow", "session_id": "s", "arguments": {"tamper_kind": "shim_modified", "new": "compromised"}}
    assert not CONTROL_KEYS & set(_attrs(span_from_record(rec)))
