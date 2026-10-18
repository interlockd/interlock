"""Session ledger (design §4.9): per-session counters the mandate and denial budget read."""

from __future__ import annotations

import threading
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from .models import InterlockEvent


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Ledger:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.sessions: dict[str, dict[str, Any]] = {}

    def touch(self, event: InterlockEvent, *, turn_no: int, action_class: str) -> dict[str, Any]:
        sid = event.session_hint or "unknown"
        with self._lock:
            s = self.sessions.get(sid)
            if s is None:
                s = self.sessions[sid] = {
                    "session_id": sid, "agent_id": event.identity.agent_id, "agent_workspace": event.identity.agent_workspace,
                    "started_at": _now(), "last_seen_at": _now(), "calls": 0, "denials_total": 0,
                    "denials_consecutive": 0, "turn_no": 0, "counters": defaultdict(int), "recent_calls": [],
                }
            s["last_seen_at"] = _now()
            s["turn_no"] = max(s["turn_no"], turn_no)
            if event.kind == "pre_action":
                s["calls"] += 1
                args = event.tool_call.arguments
                detail = next((str(args[k])[:160] for k in ("command", "path", "file_path", "url", "query") if isinstance(args.get(k), str)), "")
                s["recent_calls"] = (s["recent_calls"] + [f"{event.tool_call.name}: {detail}".rstrip(": ")])[-8:]
                s["counters"][f"class:{action_class}"] += 1
                s["counters"][f"tool:{event.tool_call.name}"] += 1
            return s

    def record_disposition(self, session_id: str | None, disposition: str) -> None:
        sid = session_id or "unknown"
        with self._lock:
            s = self.sessions.get(sid)
            if not s:
                return
            if disposition in ("block", "ask"):
                s["denials_total"] += 1
                s["denials_consecutive"] += 1
            elif disposition == "allow":
                s["denials_consecutive"] = 0

    def summary(self, session_id: str | None) -> dict[str, Any] | None:
        s = self.sessions.get(session_id or "unknown")
        if not s:
            return None
        out = dict(s)
        out["counters"] = dict(s["counters"])
        out["recent_calls"] = list(s.get("recent_calls", []))
        return out
