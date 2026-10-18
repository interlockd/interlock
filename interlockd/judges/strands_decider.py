"""Strands Decider 2B backend over POST /v1/systemone (the Jev-compatible shape), with two transports:

- http:  an already-running server (the daemon can also start and supervise one: `LocalDeciderProcess`)
- sagemaker: a SageMaker AI real-time endpoint serving the same JSON (team profile)

Requests are single-flight because the reference server's behavior under concurrency is unverified.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from typing import Any

from . import Answer, BackendError, BackendResult, Question

log = logging.getLogger("interlockd.judge.decider")


class StrandsDeciderBackend:
    name = "strands_decider"

    def __init__(self, *, base_url: str = "http://127.0.0.1:8000", checkpoint: str = "", sagemaker_endpoint: str | None = None,
                 region: str | None = None, profile: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.checkpoint = checkpoint
        self.sagemaker_endpoint = sagemaker_endpoint
        self.region, self.profile = region, profile
        self._lock = threading.Lock()
        self._snapshot: str | None = None
        self._sm = None

    # ---- transport
    def _post_http(self, body: dict[str, Any], timeout_ms: int) -> dict[str, Any]:
        req = urllib.request.Request(f"{self.base_url}/v1/systemone", data=json.dumps(body).encode(),
                                     headers={"content-type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=max(timeout_ms, 50) / 1000) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            raise BackendError(f"decider http {e.code}: {e.read()[:200]!r}") from e
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
            raise BackendError(f"decider unreachable: {type(e).__name__}: {e}") from e

    def _post_sagemaker(self, body: dict[str, Any], timeout_ms: int) -> dict[str, Any]:
        if self._sm is None:
            import boto3  # lazy
            from botocore.config import Config

            self._sm = boto3.Session(profile_name=self.profile, region_name=self.region).client(
                "sagemaker-runtime", config=Config(read_timeout=max(timeout_ms, 100) / 1000, retries={"max_attempts": 0}))
        try:
            r = self._sm.invoke_endpoint(EndpointName=self.sagemaker_endpoint, ContentType="application/json",
                                         Accept="application/json", Body=json.dumps(body).encode())
            return json.loads(r["Body"].read())
        except Exception as e:
            raise BackendError(f"sagemaker invoke failed: {type(e).__name__}: {e}") from e

    # ---- interface
    def healthy(self) -> bool:
        if self.sagemaker_endpoint:
            return True  # checked by the first call
        try:
            with urllib.request.urlopen(f"{self.base_url}/health", timeout=2) as r:
                h = json.load(r)
                self._snapshot = h.get("model") or self._snapshot
                return h.get("status") == "ok"
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            return False

    def ask(self, state: dict[str, Any], questions: dict[str, Question], *, timeout_ms: int) -> BackendResult:
        body = {"state": state, "questions": questions}
        t0 = time.perf_counter()
        with self._lock:
            raw = self._post_sagemaker(body, timeout_ms) if self.sagemaker_endpoint else self._post_http(body, timeout_ms)
        latency = (time.perf_counter() - t0) * 1000
        answers_raw = raw.get("answers")
        if not isinstance(answers_raw, dict):
            raise BackendError("decider reply has no answers")
        answers: dict[str, Answer] = {}
        for qid, a in answers_raw.items():
            if not isinstance(a, dict):
                continue
            ans: Answer = {"id": qid, "type": a.get("type", questions.get(qid, {}).get("type", ""))}
            for k in ("noul", "choice", "score", "probabilities", "confidence"):
                if k in a:
                    ans[k] = a[k]  # type: ignore[literal-required]
            if ans["type"] == "noul" and not isinstance(ans.get("noul"), (int, float)):
                raise BackendError(f"decider noul answer malformed for {qid}")
            answers[qid] = ans
        model = raw.get("model") or self._snapshot or self.checkpoint or "strands-decider"
        snapshot = f"{model}" + (f"@{self.checkpoint}" if self.checkpoint and self.checkpoint not in model else "")
        return BackendResult(answers=answers, model_snapshot=snapshot, latency_ms=round(latency, 1), cost_usd=0.0, raw=raw)


class LocalDeciderProcess:
    """Start and supervise `strands-decider serve` as a child of the daemon (laptop profile)."""

    def __init__(self, *, command: list[str], health_url: str, startup_timeout_s: float = 240.0):
        self.command, self.health_url, self.startup_timeout_s = command, health_url, startup_timeout_s
        self.proc: subprocess.Popen | None = None

    def start(self) -> bool:
        exe = self.command[0]
        if not (os.path.exists(exe) or shutil.which(exe)):
            log.warning("decider command not found: %s", exe)
            return False
        self.proc = subprocess.Popen(self.command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        deadline = time.monotonic() + self.startup_timeout_s
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                log.warning("decider exited during startup with code %s", self.proc.returncode)
                return False
            try:
                with urllib.request.urlopen(self.health_url, timeout=2) as r:
                    if json.load(r).get("status") == "ok":
                        return True
            except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
                pass
            time.sleep(1.0)
        return False

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class ReplayBackend:
    """Answers from a recorded map keyed by the sha256 of (state, questions); tests and `interlock replay`."""

    name = "replay"

    def __init__(self, recorded: dict[str, dict[str, Answer]] | None = None, model_snapshot: str = "replay"):
        self.recorded = recorded or {}
        self.model_snapshot = model_snapshot

    @staticmethod
    def key(state: dict[str, Any], questions: dict[str, Question]) -> str:
        return hashlib.sha256(json.dumps({"s": state, "q": questions}, sort_keys=True).encode()).hexdigest()

    def healthy(self) -> bool:
        return True

    def ask(self, state, questions, *, timeout_ms: int) -> BackendResult:
        k = self.key(state, questions)
        if k not in self.recorded:
            raise BackendError("no recorded answer for this state")
        return BackendResult(answers=self.recorded[k], model_snapshot=self.model_snapshot, latency_ms=0.0, cost_usd=0.0)
