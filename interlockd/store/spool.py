"""Append-only JSONL spool with per-segment drain offsets.

Segments are one file per UTC day. `append` writes one line and fsyncs so the record is durable on the
host before the verdict is returned. A drainer reads undrained bytes and advances the offset file after
the remote write is confirmed.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class Spool:
    def __init__(self, directory: Path, *, fsync: bool = True):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.fsync = fsync
        self._lock = threading.Lock()

    def _segment(self, received_at: str | None = None) -> Path:
        day = (received_at or datetime.now(UTC).isoformat())[:10]
        return self.dir / f"{day}.jsonl"

    def append(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n"
        seg = self._segment(record.get("received_at"))
        with self._lock:
            fd = os.open(seg, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
                if self.fsync:
                    os.fsync(fd)
            finally:
                os.close(fd)

    def segments(self) -> list[Path]:
        return sorted(self.dir.glob("*.jsonl"))

    def iter_records(self, *, limit: int | None = None, reverse: bool = True) -> Iterator[dict[str, Any]]:
        n = 0
        segs = self.segments()
        if reverse:
            segs = list(reversed(segs))
        for seg in segs:
            lines = seg.read_text(encoding="utf-8").splitlines()
            if reverse:
                lines = list(reversed(lines))
            for line in lines:
                if not line.strip():
                    continue
                yield json.loads(line)
                n += 1
                if limit is not None and n >= limit:
                    return

    def _offset_path(self, seg: Path) -> Path:
        return seg.with_suffix(".drained")

    def drained_offset(self, seg: Path) -> int:
        p = self._offset_path(seg)
        return int(p.read_text().strip() or 0) if p.exists() else 0

    def undrained(self) -> Iterator[tuple[Path, int, dict[str, Any]]]:
        """Yield (segment, end_offset_after_record, record) for every record not yet drained."""
        for seg in self.segments():
            start = self.drained_offset(seg)
            with open(seg, "rb") as f:
                f.seek(start)
                pos = start
                for raw in f:
                    pos += len(raw)
                    if raw.strip():
                        yield seg, pos, json.loads(raw.decode("utf-8"))

    def mark_drained(self, seg: Path, offset: int) -> None:
        tmp = self._offset_path(seg).with_suffix(".drained.tmp")
        tmp.write_text(str(offset))
        os.replace(tmp, self._offset_path(seg))
