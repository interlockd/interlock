"""Amazon Bedrock Guardrails `InvokeGuardrailChecks` as an OGR-style detector on untrusted content.

Detect-only, resourceless: we name the checks per call. promptAttack returns a severityScore in [0, 1] per category;
sensitiveInformation returns entity hits with character offsets. Both map onto findings with OGR categories.
Verified live on 2026-10-08 in us-east-1 (509 ms, one text unit per check for a short result).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from ..models import Finding

log = logging.getLogger("interlockd.judge.guardrails")

DEFAULT_ATTACKS = ["PROMPT_INJECTION", "JAILBREAK"]
DEFAULT_ENTITIES = ["AWS_ACCESS_KEY", "AWS_SECRET_KEY", "PASSWORD"]
MAX_CHARS = 20_000  # about 20 text units per check; the projector caps untrusted content well below this


@dataclass
class GuardrailsResult:
    scores: dict[str, float] = field(default_factory=dict)      # category -> severity
    findings: list[Finding] = field(default_factory=list)
    text_units: int = 0
    latency_ms: float = 0.0
    error: str | None = None


class BedrockGuardrailsProbe:
    name = "bedrock_guardrails"

    def __init__(self, *, region: str | None = None, profile: str | None = None, attacks: list[str] | None = None,
                 entities: list[str] | None = None, injection_threshold: float = 0.6, client=None):
        self.region, self.profile = region, profile
        self.attacks = attacks or DEFAULT_ATTACKS
        self.entities = entities or DEFAULT_ENTITIES
        self.injection_threshold = injection_threshold
        self._client = client

    def _c(self, timeout_ms: int):
        if self._client is None:
            import boto3  # lazy
            from botocore.config import Config

            # the first call pays TLS and credential resolution; later calls reuse the connection
            self._client = boto3.Session(profile_name=self.profile, region_name=self.region).client(
                "bedrock-runtime", config=Config(read_timeout=max(timeout_ms, 200) / 1000 + 1.0, connect_timeout=3,
                                                 retries={"max_attempts": 0}, tcp_keepalive=True))
        return self._client

    def check(self, *, untrusted: str, user_context: str | None = None, path: str = "result.content", timeout_ms: int = 1500) -> GuardrailsResult:
        out = GuardrailsResult()
        content = untrusted[:MAX_CHARS]
        if not content.strip():
            return out
        messages: list[dict[str, Any]] = []
        if user_context:
            messages.append({"role": "system", "content": [{"text": user_context[:2000]}]})
        messages.append({"role": "assistant", "content": [{"text": content}]})   # the content under test is not the user's words
        checks: dict[str, Any] = {}
        if self.attacks:
            checks["promptAttack"] = {"categories": [{"category": a} for a in self.attacks]}
        if self.entities:
            checks["sensitiveInformation"] = {"entities": [{"type": e} for e in self.entities]}
        t0 = time.perf_counter()
        try:
            r = self._c(timeout_ms).invoke_guardrail_checks(messages=messages, checks=checks)
        except Exception as e:  # noqa: BLE001  the probe going dark is reported as unjudged by the caller
            out.error = f"{type(e).__name__}: {str(e)[:160]}"
            out.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
            return out
        out.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        res = r.get("results", {})
        for item in (res.get("promptAttack") or {}).get("results", []):
            cat, score = item.get("category"), float(item.get("severityScore", 0.0))
            out.scores[cat] = score
            if score >= self.injection_threshold:
                out.findings.append(Finding(category="security.prompt_injection" if cat == "PROMPT_INJECTION" else "security.jailbreak",
                                            severity="critical" if score >= 0.8 else "high", rule=f"guardrails.{cat.lower()}",
                                            detector="bedrock.guardrails", path=path, score=score, subject=f"{cat} severity {score:.1f}"))
        for item in (res.get("sensitiveInformation") or {}).get("results", []):
            etype, conf = item.get("type"), float(item.get("confidenceScore", 0.0))
            out.scores[f"PII:{etype}"] = max(out.scores.get(f"PII:{etype}", 0.0), conf)
            if conf >= 0.5 and item.get("messageIndex") == len(messages) - 1:
                out.findings.append(Finding(category="security.secret_leak", severity="high", rule=f"guardrails.pii.{etype.lower()}",
                                            detector="bedrock.guardrails", path=path, start=item.get("beginOffset"),
                                            end=item.get("endOffset"), score=conf, subject=f"{etype} at {item.get('beginOffset')}-{item.get('endOffset')}"))
        usage = r.get("usage", {})
        out.text_units = sum(int((u or {}).get("textUnits", 0)) for u in usage.values()) if isinstance(usage, dict) else 0
        return out
