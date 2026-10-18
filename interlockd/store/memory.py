"""In-memory repository for tests and the spool-only mode."""

from __future__ import annotations

from typing import Any


class MemoryRepository:
    def __init__(self) -> None:
        self.events: dict[str, dict[str, Any]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}

    def put_event(self, record: dict[str, Any]) -> None:
        self.events[record["event_id"]] = record

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        return self.events.get(event_id)

    def tail(self, workspace: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        rows = [r for r in self.events.values() if workspace is None or r.get("agent_workspace") == workspace]
        rows.sort(key=lambda r: r["event_id"], reverse=True)
        return rows[:limit]

    def put_session(self, summary: dict[str, Any]) -> None:
        self.sessions[summary["session_id"]] = summary

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        return self.sessions.get(session_id)
