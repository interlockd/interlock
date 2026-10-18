"""Append-only JSONL spool with per-segment drain offsets, hash-chained for tamper evidence.

Segments are one file per UTC day. `append` writes one line and fsyncs so the record is durable on the
host before the verdict is returned. A drainer reads undrained bytes and advances the offset file after
the remote write is confirmed.

Every record carries `prev_hash` and `hash = sha256(prev_hash + canonical JSON of the record without `hash`)`,
chained across segments, so editing, deleting, reordering, or inserting a record breaks `verify()`. Truncating
the newest records is only detectable against an anchored head (`interlock audit head`). Records written before
chaining existed are reported as legacy, not as breaks.
"""

from __future__ import annotations

import fcntl
import hashlib
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
        seg = self._segment()      # by write time, not received_at: the chain must follow file order
        with self._lock:
            lock_fd = os.open(self.dir / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)         # one chain even with several writers on this spool
                rec = {k: v for k, v in record.items() if k not in ("hash", "prev_hash")}
                rec["prev_hash"] = self.head()
                rec["hash"] = record_hash(rec)
                line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n"
                fd = os.open(seg, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try:
                    os.write(fd, line.encode("utf-8"))
                    if self.fsync:
                        os.fsync(fd)
                finally:
                    os.close(fd)
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)

    def head(self) -> str:
        """Hash of the newest chained record ("genesis" for an empty or legacy-only spool)."""
        for seg in reversed(self.segments()):
            last = _last_line(seg)
            if last:
                try:
                    return json.loads(last).get("hash") or GENESIS
                except ValueError:
                    return GENESIS
        return GENESIS

    def verify(self) -> dict[str, Any]:
        """Walk every segment in order. Returns {ok, records, legacy, head, break: {segment, line, reason} | None}."""
        expected, n, legacy = None, 0, 0
        for seg in self.segments():
            for i, raw in enumerate(seg.read_text(encoding="utf-8").splitlines(), 1):
                if not raw.strip():
                    continue
                try:
                    rec = json.loads(raw)
                except ValueError:
                    return _broken(seg, i, "not valid JSON", n, legacy)
                if "hash" not in rec:
                    if expected is not None:
                        return _broken(seg, i, "unchained record after the chain started (inserted?)", n, legacy)
                    legacy += 1
                    continue
                prev = rec.get("prev_hash")
                if expected is None and prev != GENESIS and legacy == 0:
                    return _broken(seg, i, "first chained record does not start the chain (records removed before it?)", n, legacy)
                if expected is not None and prev != expected:
                    return _broken(seg, i, "prev_hash does not match the previous record (removed or reordered?)", n, legacy)
                if record_hash({k: v for k, v in rec.items() if k != "hash"}) != rec["hash"]:
                    return _broken(seg, i, "content does not match its hash (edited)", n, legacy)
                expected, n = rec["hash"], n + 1
        return {"ok": True, "records": n, "legacy": legacy, "head": expected or GENESIS, "break": None}

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


GENESIS = "genesis"


def record_hash(rec_without_hash: dict[str, Any]) -> str:
    body = json.dumps(rec_without_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(f"{rec_without_hash.get('prev_hash', GENESIS)}\n{body}".encode()).hexdigest()


def _last_line(path: Path) -> str | None:
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        block = min(size, 1 << 20)
        f.seek(size - block)
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
        return lines[-1].decode("utf-8") if lines else None


def _broken(seg: Path, line: int, reason: str, n: int, legacy: int) -> dict[str, Any]:
    return {"ok": False, "records": n, "legacy": legacy, "head": None, "break": {"segment": seg.name, "line": line, "reason": reason}}
