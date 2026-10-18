"""Audit store: a local write-ahead spool in front of a repository (memory for tests, DynamoDB for real).

Design §7: one record per event, findings and answers embedded; separate items for explanations,
feedback, and session summaries. The decision path writes only to the spool (fsync) and returns.
"""

from __future__ import annotations

from typing import Any, Protocol


class Repository(Protocol):
    def put_event(self, record: dict[str, Any]) -> None: ...
    def get_event(self, event_id: str) -> dict[str, Any] | None: ...
    def tail(self, workspace: str | None = None, limit: int = 50) -> list[dict[str, Any]]: ...
    def put_session(self, summary: dict[str, Any]) -> None: ...
    def get_session(self, session_id: str) -> dict[str, Any] | None: ...


def hour_bucket(received_at: str) -> str:
    # "2026-10-08T01:08:33.123Z" -> "2026-10-08-01"
    return received_at[:13].replace("T", "-")
