"""Read user messages from a Claude Code transcript (the JSONL at the payload's transcript_path).

Each line is one JSON object; user turns have type == "user" with message.content either a string or a list of
blocks. Blocks of type tool_result are the harness feeding tool output back and are NOT user instructions, so only
text blocks count. Incremental like the Kiro reader: the file is append-only.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from ..models import UserMessage


class ClaudeTranscript:
    def __init__(self) -> None:
        self._cache: dict[str, tuple[int, list[str]]] = {}
        self._lock = threading.Lock()

    def _user_texts(self, path: str) -> list[str]:
        p = Path(path).expanduser()
        try:
            size = p.stat().st_size
        except OSError:
            return []
        with self._lock:
            offset, texts = self._cache.get(path, (0, []))
            if size < offset:
                offset, texts = 0, []
            if size == offset:
                return texts
            texts = list(texts)
            with open(p, "rb") as f:
                f.seek(offset)
                chunk = f.read(size - offset)
            last_nl = chunk.rfind(b"\n")
            if last_nl < 0:
                return texts
            for raw in chunk[: last_nl + 1].splitlines():
                if b'"user"' not in raw:
                    continue
                try:
                    o = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if o.get("type") != "user":
                    continue
                msg = o.get("message") or {}
                content = msg.get("content")
                if isinstance(content, str):
                    text = content
                elif isinstance(content, list):
                    text = " ".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
                else:
                    continue
                if text.strip() and not (o.get("isMeta") or o.get("isCompactSummary")):
                    texts.append(text.strip())
            self._cache[path] = (offset + last_nl + 1, texts)
            return texts

    def user_messages(self, path: str | None, n: int = 3) -> list[UserMessage] | None:
        if not path:
            return None
        texts = self._user_texts(path)
        if not texts:
            return None
        last = texts[-n:]
        return [UserMessage(n=i - len(last), text=t) for i, t in enumerate(last)]

    def turn_count(self, path: str | None) -> int:
        return len(self._user_texts(path)) if path else 0
