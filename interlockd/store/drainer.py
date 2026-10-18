"""Background drainer: moves undrained spool records to the repository in batches, off the decision path."""

from __future__ import annotations

import logging
import threading
from typing import Any

from . import Repository
from .spool import Spool

log = logging.getLogger("interlockd.drainer")


class Drainer:
    def __init__(self, spool: Spool, repo: Repository, *, interval_s: float = 2.0, batch: int = 25):
        self.spool, self.repo, self.interval, self.batch = spool, repo, interval_s, batch
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.drained_total = 0
        self.last_error: str | None = None

    def drain_once(self) -> int:
        n = 0
        pending: list[tuple[Any, int, dict[str, Any]]] = []

        def flush() -> None:
            nonlocal n
            if not pending:
                return
            records = [r for _, _, r in pending]
            if hasattr(self.repo, "put_events"):
                self.repo.put_events(records)  # type: ignore[attr-defined]
            else:
                for r in records:
                    self.repo.put_event(r)
            seg, off, _ = pending[-1]
            self.spool.mark_drained(seg, off)
            n += len(pending)
            pending.clear()

        current_seg = None
        for seg, off, rec in self.spool.undrained():
            if current_seg is not None and seg != current_seg:
                flush()
            current_seg = seg
            pending.append((seg, off, rec))
            if len(pending) >= self.batch:
                flush()
        flush()
        self.drained_total += n
        return n

    def _run(self) -> None:
        backoff = self.interval
        while not self._stop.is_set():
            try:
                self.drain_once()
                self.last_error = None
                backoff = self.interval
            except Exception as e:  # noqa: BLE001  boundary: network, credentials, throttling; keep the spool, retry
                self.last_error = f"{type(e).__name__}: {e}"
                log.warning("drain failed, will retry: %s", self.last_error)
                backoff = min(backoff * 2, 60.0)
            self._stop.wait(backoff)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="interlock-drainer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
