"""Read user messages from a Kiro session transcript (adapters/kiro/PAYLOADS.md §6).

Layout: <sessions_dir>/<workspace-hash>/<session_id>/messages.jsonl, one JSON object per line with
payload.type in {user, assistant, tool_call, tool_result, turn_start, ...}; session.json alongside.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from ..models import UserMessage


class KiroTranscript:
    def __init__(self, sessions_dir: Path):
        self.sessions_dir = Path(sessions_dir).expanduser()
        self._paths: dict[str, Path] = {}
        self._cache: dict[str, tuple[int, list[str]]] = {}  # session -> (bytes consumed, user texts)
        self._lock = threading.Lock()

    def find(self, session_id: str) -> Path | None:
        if session_id in self._paths and self._paths[session_id].exists():
            return self._paths[session_id]
        if not self.sessions_dir.exists():
            return None
        for ws in self.sessions_dir.iterdir():
            cand = ws / session_id / "messages.jsonl"
            if cand.exists():
                self._paths[session_id] = cand
                return cand
        return None

    def session_meta(self, session_id: str) -> dict[str, Any]:
        p = self.find(session_id)
        if not p:
            return {}
        meta = p.with_name("session.json")
        try:
            return json.loads(meta.read_text()) if meta.exists() else {}
        except json.JSONDecodeError:
            return {}

    def _user_texts(self, session_id: str) -> list[str]:
        """Incremental: the transcript is append-only, so only bytes past the last offset are parsed."""
        p = self.find(session_id)
        if not p:
            return []
        try:
            size = p.stat().st_size
        except FileNotFoundError:
            return []
        with self._lock:
            offset, texts = self._cache.get(session_id, (0, []))
            if size < offset:  # rotated or truncated: start over
                offset, texts = 0, []
            if size == offset:
                return texts
            texts = list(texts)
            with open(p, "rb") as f:
                f.seek(offset)
                chunk = f.read(size - offset)
            # keep a partial trailing line for the next read
            last_nl = chunk.rfind(b"\n")
            if last_nl < 0:
                return texts
            consumed = offset + last_nl + 1
            for raw in chunk[: last_nl + 1].splitlines():
                if b'"user"' not in raw and b'"interaction_resolved"' not in raw:
                    continue
                try:
                    o = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                payload = o.get("payload") or {}
                if payload.get("type") == "interaction_resolved" and payload.get("outcome") == "answered":
                    # the user's answer to a question the agent asked (user_input tool); these are the user's words too
                    answer = payload.get("selectedOption") or payload.get("response") or payload.get("answer")
                    if isinstance(answer, str) and answer.strip():
                        texts.append(f"[answer] {answer.strip()}")
                    continue
                if payload.get("type") != "user":
                    continue
                content = payload.get("content")
                if isinstance(content, list):
                    content = " ".join(c.get("text", "") if isinstance(c, dict) else str(c) for c in content)
                if isinstance(content, str) and content.strip():
                    texts.append(content.strip())
            self._cache[session_id] = (consumed, texts)
            return texts

    def user_messages(self, session_id: str, n: int = 3) -> list[UserMessage] | None:
        texts = self._user_texts(session_id)
        if not texts:
            return None
        last = texts[-n:]
        return [UserMessage(n=i - len(last), text=t) for i, t in enumerate(last)]

    def turn_count(self, session_id: str) -> int:
        return len(self._user_texts(session_id))
