"""OpenTelemetry export: one span per decision over OTLP/HTTP JSON (no SDK dependency).

Enable with `"otlp_endpoint": "http://localhost:4318/v1/traces"` (and optional `"otlp_headers"`) in
~/.interlock/config.json. Spans are queued and sent in batches by a background thread; when the collector is slow
or down, spans are dropped, never the decision. A session's calls share a trace id (derived from the session id).
Attributes follow the OTel GenAI conventions where they fit (`gen_ai.tool.name`, `gen_ai.agent.name`,
`gen_ai.tool.call.id`) plus `interlock.*` for the verdict. Arguments and results are never exported.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import threading
import time
import urllib.request
from datetime import datetime
from typing import Any

from . import __version__

log = logging.getLogger("interlockd.otel")


def _ns(iso: str | None) -> int:
    try:
        return int(datetime.fromisoformat(iso or "").timestamp() * 1e9)
    except ValueError:
        return time.time_ns()


def _attr(k: str, v: Any) -> dict:
    if isinstance(v, bool):
        return {"key": k, "value": {"boolValue": v}}
    if isinstance(v, int):
        return {"key": k, "value": {"intValue": str(v)}}
    if isinstance(v, float):
        return {"key": k, "value": {"doubleValue": v}}
    if isinstance(v, list):
        return {"key": k, "value": {"arrayValue": {"values": [{"stringValue": str(x)} for x in v]}}}
    return {"key": k, "value": {"stringValue": str(v)}}


def span_from_record(rec: dict) -> dict:
    """An OTLP span for one audit record (the same record the spool holds)."""
    sid = rec.get("session_id") or "unknown"
    trace_id = hashlib.sha256(f"interlock-session:{sid}".encode()).hexdigest()[:32]
    span_id = hashlib.sha256(f"interlock-event:{rec.get('event_id')}".encode()).hexdigest()[:16]
    start = _ns(rec.get("received_at"))
    dur_ms = float((rec.get("timing_ms") or {}).get("total") or 0.0)
    disp = rec.get("disposition", "")
    rules = sorted({f.get("rule") for f in rec.get("findings") or [] if f.get("rule")})
    attrs = {
        "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": rec.get("tool_name", ""),
        "gen_ai.tool.call.id": rec.get("tool_call_id") or "", "gen_ai.agent.name": rec.get("agent_type") or rec.get("adapter") or "",
        "gen_ai.conversation.id": sid, "interlock.event_id": rec.get("event_id", ""),
        "interlock.kind": rec.get("kind", ""), "interlock.disposition": disp, "interlock.mode": rec.get("mode", ""),
        "interlock.tier": int(rec.get("tier") or 0), "interlock.action_class": (rec.get("normalized") or {}).get("action_class", ""),
        "interlock.rules": rules, "interlock.workspace": rec.get("agent_workspace", ""),
        "interlock.policy_sha256": rec.get("policy_sha256", ""),
    }
    if rec.get("unjudged"):
        attrs["interlock.unjudged"] = list(rec["unjudged"])
    stopped = disp in ("block", "ask", "withhold")
    return {"traceId": trace_id, "spanId": span_id, "name": f"interlock {rec.get('kind', 'decide')} {rec.get('tool_name', '')}".strip(),
            "kind": 1, "startTimeUnixNano": str(start), "endTimeUnixNano": str(start + int(dur_ms * 1e6)),
            "attributes": [_attr(k, v) for k, v in attrs.items() if v not in ("", [], None)],
            # the reason text quotes the command, so the status carries only the disposition and rule ids
            "status": {"code": 2, "message": f"{disp}: {', '.join(rules) or 'policy'}"} if stopped else {"code": 1}}


def payload(spans: list[dict]) -> dict:
    return {"resourceSpans": [{
        "resource": {"attributes": [_attr("service.name", "interlock"), _attr("service.version", __version__),
                                    _attr("host.name", os.uname().nodename)]},
        "scopeSpans": [{"scope": {"name": "interlockd", "version": __version__}, "spans": spans}]}]}


def send(endpoint: str, spans: list[dict], headers: dict[str, str] | None = None, timeout: float = 3.0) -> int:
    req = urllib.request.Request(endpoint, data=json.dumps(payload(spans)).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


class Exporter:
    """Background batch exporter. `submit(record)` never blocks the decision path."""

    def __init__(self, endpoint: str, headers: dict[str, str] | None = None, *, batch: int = 64, interval: float = 2.0,
                 max_queue: int = 5000):
        self.endpoint, self.headers, self.batch, self.interval = endpoint, headers or {}, batch, interval
        self.q: queue.Queue = queue.Queue(maxsize=max_queue)
        self.dropped = 0
        self.sent = 0
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, name="interlock-otel", daemon=True)
        self._t.start()

    def submit(self, rec: dict) -> None:
        try:
            self.q.put_nowait(span_from_record(rec))
        except queue.Full:
            self.dropped += 1

    def _drain(self) -> list[dict]:
        out = []
        while len(out) < self.batch:
            try:
                out.append(self.q.get_nowait())
            except queue.Empty:
                break
        return out

    def _run(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(self.interval)
            self.flush()

    def flush(self) -> None:
        while True:
            spans = self._drain()
            if not spans:
                return
            try:
                send(self.endpoint, spans, self.headers)
                self.sent += len(spans)
            except Exception as e:  # noqa: BLE001  the collector being down must never affect decisions
                self.dropped += len(spans)
                log.warning("otel export failed (%s); dropped %d span(s)", type(e).__name__, len(spans))
                return

    def stop(self) -> None:
        self._stop.set()
        self.flush()
