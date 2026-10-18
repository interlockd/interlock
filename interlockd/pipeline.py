"""The decide() pipeline (design §4.2). M0 scope: authenticate at the API, normalize, ledger, tier route,
record, return. The deterministic engine (M1) and the judge (M2) plug in between steps 4 and 10.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

from . import __version__
from .compose import compose
from .config import Settings
from .det.engine import evaluate as det_evaluate
from .det.flow import check as flow_check
from .det.flow import observe as flow_observe
from .det.mandate import evaluate_mandate
from .ids import ulid
from .judges import QUESTIONS_V1, QUESTIONS_VERSION, BackendError
from .judges.projector import project_confirmation, project_intent, project_probe, user_context_text
from .ledger import Ledger
from .models import InterlockEvent, Verdict
from .policy import Policy
from .store import Repository
from .store.spool import Spool
from .tiers import route
from .transcript.claude_code import ClaudeTranscript
from .transcript.kiro import KiroTranscript

log = logging.getLogger("interlockd.pipeline")

RESULT_HEAD_TAIL = 2000


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Daemon:
    def __init__(self, settings: Settings, *, spool: Spool, repo: Repository | None = None, policy: Policy | None = None):
        self.settings = settings
        self.spool = spool
        self.repo = repo
        self.ledger = Ledger()
        self.transcript = KiroTranscript(settings.kiro_sessions_dir)
        self.claude_transcript = ClaudeTranscript()
        self.policy = policy or Policy()
        if not self.policy.trust.workspace_roots and settings.workspace_roots:
            self.policy.trust.workspace_roots = list(settings.workspace_roots)
        self.mode = self.policy.mode if policy is not None else settings.mode
        self.backend = None      # DecisionBackend, set by the CLI from policy.judge.primary
        self.probe = None        # BedrockGuardrailsProbe, set by the CLI when policy.judge.probe.enabled
        self.local_probe = None  # LocalInjectionProbe: no AWS, no network; on unless policy.judge.probe.local.enabled is false
        lp = self.policy.judge.probe.local
        if lp.enabled:
            from .judges.local_probe import LocalInjectionProbe

            self.local_probe = LocalInjectionProbe(threshold=lp.threshold, classifier_model=lp.classifier_model,
                                                   classifier_threshold=lp.classifier_threshold)

    # ---- judge stage ----------------------------------------------------------------------------------
    def _judge_pre(self, event, det, session, composed):
        """Ask the judge about a gated pre-action call. Returns (disposition, findings_added, answers_rows, unjudged_add)."""
        from .models import Finding

        b = self.policy.judge.bands
        qids = list(det.questions) or ["intent_authorized"]
        if any(f.rule and f.rule.startswith("egress.") for f in det.findings) and "exfil_risk" not in qids:
            qids.append("exfil_risk")
        if not event.context.user_messages:
            return composed.disposition, [], [], ["judge:no_user_messages"]
        questions = {q: QUESTIONS_V1[q] for q in qids if q in QUESTIONS_V1}
        state = project_intent(event, normalized=det.normalized, prior_calls=session.get("recent_calls", [])[:-1],
                               max_tokens=b.max_intent_state_tokens)
        try:
            res = self.backend.ask(state, questions, timeout_ms=self.policy.judge.primary.timeout_ms)
        except BackendError as e:
            log.warning("judge unavailable: %s", e)
            return composed.disposition, [], [], ["judge"]
        rows = [{"backend": self.backend.name, "model_snapshot": res.model_snapshot, "question_id": q, "questions_version": QUESTIONS_VERSION,
                 "answer": a, "latency_ms": res.latency_ms, "pass": 1} for q, a in res.answers.items()]
        intent = res.answers.get("intent_authorized", {}).get("noul")
        exfil = res.answers.get("exfil_risk", {}).get("noul")
        disp = composed.disposition
        findings = []
        if intent is not None:
            findings.append(Finding(category="x.interlock.intent", severity="medium" if intent < b.intent_ask_below else "low",
                                    detector=f"interlock.judge/{res.model_snapshot}", path="tool_call", score=round(1 - intent, 3),
                                    subject=f"P(user authorized)={intent:.2f}"))
            if disp == "allow":
                if intent < b.intent_block_below and det.harm >= b.harm_block_min:
                    disp = "block"
                elif intent < b.intent_ask_below:
                    disp = "ask"
        if exfil is not None and exfil >= b.exfil_ask_at and disp == "allow":
            findings.append(Finding(category="security.data_exfiltration", severity="high", detector=f"interlock.judge/{res.model_snapshot}",
                                    path="tool_call", score=round(exfil, 3), subject=f"P(exfiltration)={exfil:.2f}"))
            disp = "ask"
        return disp, findings, rows, []

    def _confirm_via_transcript(self, event, det, session, findings):
        """Harnesses without a native ask (Kiro) cannot carry the user's confirmation back to the hook. The notice tells
        the agent to ask the user; the user's answer lands in the session transcript, which the daemon reads. If the judge
        finds the latest user messages authorize this exact action, the ask resolves to allow, with the evidence recorded.
        The agent cannot forge this channel without writing into the harness's own transcript, which the persistence pack
        treats as agent-config tampering."""
        from .models import Finding

        b = self.policy.judge.bands
        if self.backend is None or not event.context.user_messages:
            return "ask", [], [], ["confirmation:no_judge" if self.backend is None else "confirmation:no_user_messages"]
        reason = "; ".join(f.subject or f.category for f in findings[:3]) or None
        state = project_confirmation(event, normalized=det.normalized, reason=reason)
        try:
            res = self.backend.ask(state, {"confirmation_given": QUESTIONS_V1["confirmation_given"]},
                                   timeout_ms=self.policy.judge.primary.timeout_ms)
        except BackendError as e:
            log.warning("confirmation judge unavailable: %s", e)
            return "ask", [], [], ["confirmation:judge"]
        intent = res.answers.get("confirmation_given", {}).get("noul")
        rows = [{"backend": self.backend.name, "model_snapshot": res.model_snapshot, "question_id": "confirmation_given",
                 "questions_version": QUESTIONS_VERSION, "answer": res.answers.get("confirmation_given"), "latency_ms": res.latency_ms, "pass": 1,
                 "purpose": "confirmation"}]
        if intent is not None and intent >= b.confirm_allow_at:
            f = Finding(category="x.interlock.confirmed_via_transcript", severity="low", detector=f"interlock.judge/{res.model_snapshot}",
                        path="tool_call", score=round(intent, 3),
                        subject=f"ask resolved: the user confirmed this action, P={intent:.2f} (last: {event.context.user_messages[-1].text[:80]!r})")
            return "allow", [f], rows, []
        return "ask", [], rows, []

    def _probe_post(self, event, composed):
        """Post-action: Guardrails and the judge on the tool result. Returns (disposition, findings_added, answers_rows, unjudged, guard_scores)."""
        from .models import Finding

        b = self.policy.judge.bands
        findings, rows, unjudged, scores = [], [], [], {}
        disp = composed.disposition
        content = event.result.content if event.result else ""
        if not content.strip():
            return disp, findings, rows, unjudged, scores
        max_sev = 0.0
        if self.local_probe is not None:
            lr = self.local_probe.check(untrusted=content[: b.max_untrusted_tokens * 4])
            if lr.error:   # the classifier went dark; the heuristic result still stands
                unjudged.append("probe:local_classifier")
            scores.update(lr.scores)
            findings.extend(lr.findings)
            # a local score below its own threshold is not a signal: the bands are tuned for calibrated detectors
            max_sev = max([f.score or 0.0 for f in lr.findings] or [0.0])
            rows.append({"backend": "local_probe", "model_snapshot": self.local_probe.classifier_model or "heuristics-v1",
                         "question_id": "prompt_attack", "answer": {"scores": lr.scores}, "latency_ms": lr.latency_ms, "pass": 1})
        if self.probe is not None:
            g = self.probe.check(untrusted=content[: b.max_untrusted_tokens * 4], user_context=user_context_text(event),
                                 timeout_ms=self.policy.judge.probe.timeout_ms)
            if g.error:
                unjudged.append("probe:guardrails")
                log.warning("guardrails probe failed: %s", g.error)
            else:
                scores.update(g.scores)
                findings.extend(g.findings)
                max_sev = max([max_sev] + [v for k, v in g.scores.items() if not k.startswith("PII:")])
                rows.append({"backend": "bedrock_guardrails", "model_snapshot": "bedrock-guardrails", "question_id": "prompt_attack",
                             "answer": {"scores": g.scores, "text_units": g.text_units}, "latency_ms": g.latency_ms, "pass": 1})
        p_inj = None
        if self.backend is not None:
            state, truncated = project_probe(event, max_untrusted_tokens=b.max_untrusted_tokens)
            try:
                res = self.backend.ask(state, {"injection_present": QUESTIONS_V1["injection_present"]},
                                       timeout_ms=self.policy.judge.primary.timeout_ms)
                p_inj = res.answers.get("injection_present", {}).get("noul")
                rows.append({"backend": self.backend.name, "model_snapshot": res.model_snapshot, "question_id": "injection_present",
                             "questions_version": QUESTIONS_VERSION, "answer": res.answers.get("injection_present"), "latency_ms": res.latency_ms, "pass": 1})
                if truncated:
                    findings.append(Finding(category="x.interlock.truncated_untrusted", severity="low", detector="interlock.projector",
                                            path="result.content", score=1.0, subject="content judged on head and tail only"))
            except BackendError as e:
                unjudged.append("probe:judge")
                log.warning("judge probe unavailable: %s", e)
        signal = max(max_sev, p_inj or 0.0)
        if p_inj is not None and p_inj >= b.injection_warn_at:
            findings.append(Finding(category="security.prompt_injection", severity="high" if p_inj < b.injection_withhold_at else "critical",
                                    detector="interlock.judge", path="result.content", score=round(p_inj, 3), subject=f"P(injection)={p_inj:.2f}"))
        if signal >= b.injection_withhold_at and event.capabilities.withhold:
            disp = "withhold"
        elif signal >= b.injection_warn_at:
            disp = "warn"
        return disp, findings, rows, unjudged, scores

    @property
    def policy_sha256(self) -> str:
        return self.policy.sha256 or "default"

    # ---- helpers -------------------------------------------------------------------------------------
    def _fill_user_messages(self, event: InterlockEvent) -> int:
        """Hooks carry no user messages; read them from the harness transcript. Returns the turn number."""
        if event.adapter.name in ("claude-code", "codex"):
            path = event.context.transcript_path
            if event.context.user_messages is None and path:
                event.context.user_messages = self.claude_transcript.user_messages(path, self.settings.user_messages_n)
            return self.claude_transcript.turn_count(path) if path else 0
        if event.adapter.name != "kiro" or not event.session_hint:
            return len(event.context.user_messages or []) and 1 or 0
        if event.context.user_messages is None:
            event.context.user_messages = self.transcript.user_messages(event.session_hint, self.settings.user_messages_n)
        if event.context.permission_mode is None:
            meta = self.transcript.session_meta(event.session_hint)
            if meta:
                event.context.permission_mode = "autopilot" if meta.get("autopilot") else "supervised"
        return self.transcript.turn_count(event.session_hint)

    def _record(self, event: InterlockEvent, verdict: Verdict, *, received_at: str, session: dict[str, Any], turn_no: int,
                normalized: dict[str, Any] | None = None, answers: list | None = None, guardrails: dict | None = None) -> dict[str, Any]:
        state = {
            "user_messages": [m.model_dump() for m in (event.context.user_messages or [])],
            "proposed_action": {"tool": event.tool_call.name, "arguments": event.tool_call.arguments},
        }
        state_json = json.dumps(state, sort_keys=True, separators=(",", ":"))
        rec: dict[str, Any] = {
            "event_id": verdict.event_id,
            "received_at": received_at,
            "kind": event.kind,
            "adapter": event.adapter.name, "adapter_version": event.adapter.version,
            "agent_id": event.identity.agent_id, "agent_type": event.identity.agent_type,
            "agent_workspace": event.identity.agent_workspace, "agent_user": event.identity.agent_user,
            "session_id": event.session_hint or "unknown", "turn_no": turn_no,
            "tool_call_id": event.tool_call.id, "tool_name": event.tool_call.name,
            "arguments": event.tool_call.arguments,
            "normalized": {"action_class": verdict.action_class, **(normalized or {})},
            "tier": verdict.tier,
            "state": state, "state_sha256": hashlib.sha256(state_json.encode()).hexdigest(),
            "disposition": verdict.disposition, "mode": verdict.mode,
            "reason": verdict.reason, "notice": verdict.notice,
            "unjudged": verdict.unjudged,
            "findings": [f.model_dump() for f in verdict.findings],
            "answers": list(answers or []),
            "guardrails": dict(guardrails or {}),
            "timing_ms": verdict.timing_ms,
            "cost_usd": 0.0,
            "policy_sha256": self.policy_sha256,
            "daemon_version": __version__,
            "capabilities": event.capabilities.model_dump(),
            "permission_mode": event.context.permission_mode,
        }
        if event.result is not None:
            content = event.result.content
            rec["result_sha256"] = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
            rec["result_bytes"] = len(content)
            rec["result_head"] = content[:RESULT_HEAD_TAIL]
            rec["result_tail"] = content[-RESULT_HEAD_TAIL:] if len(content) > RESULT_HEAD_TAIL else ""
            rec["evidence"] = event.result.evidence
        return rec

    # ---- the pipeline ----------------------------------------------------------------------------------
    def decide(self, event: InterlockEvent) -> Verdict:
        t0 = time.perf_counter()
        received_at = _now_iso()
        event_id = ulid()

        turn_no = self._fill_user_messages(event)
        t_ctx = time.perf_counter()

        pol = self.policy
        tier = route(
            event,
            workspace_roots=pol.trust.workspace_roots,
            protected=pol.trust.protected_paths,
            sensitive=pol.trust.sensitive_paths,
        )
        session = self.ledger.touch(event, turn_no=turn_no, action_class=tier.action_class)
        t_tier = time.perf_counter()

        findings: list = []
        unjudged: list[str] = []
        det = None
        answers_rows: list = []
        guard_scores: dict = {}
        if event.kind == "post_action":
            det = det_evaluate(event, pol, tier)
            composed = compose(det, evaluate_mandate(pol, det, agent_id="", workspace="", session_counters={}), pol,
                               session=session, kind="post_action")
            disposition, reason, notice, findings, unjudged = composed.disposition, composed.reason, None, composed.findings, []
            action_class = det.action_class
            if self.backend is not None or self.probe is not None or self.local_probe is not None:
                disposition, extra, rows, more_unjudged, scores = self._probe_post(event, composed)
                findings = findings + extra
                unjudged = unjudged + more_unjudged
                answers_rows, guard_scores = rows, scores
                if extra:
                    reason = "; ".join(f.subject or f.category for f in extra)
                if disposition == "withhold":
                    notice = ("[interlock] This tool result was withheld by a security policy because it appears to contain "
                              "instructions addressed to the agent that the user did not give. Its contents are recorded in the audit store.")
        elif tier.tier == 0:
            disposition, reason, notice, action_class = "allow", tier.reason, None, tier.action_class
        else:
            # tier 1 runs the secrets and persistence packs on the content; tier 2 runs everything the policy enables
            det = det_evaluate(event, pol, tier)
            flow_check(event, det, session, pol)
            mandate = evaluate_mandate(pol, det, agent_id=event.identity.agent_id, workspace=event.identity.agent_workspace,
                                       session_counters=session.get("counters", {}))
            composed = compose(det, mandate, pol, session=session, kind="pre_action")
            disposition, reason, notice, findings, unjudged = (composed.disposition, composed.reason, composed.notice,
                                                              composed.findings, composed.unjudged)
            action_class = det.action_class
            if composed.needs_judge and self.backend is not None and self.policy.judge.ask_intent_for_model_rules:
                disposition, extra, rows, more_unjudged = self._judge_pre(event, det, session, composed)
                findings = findings + extra
                unjudged = unjudged + more_unjudged
                answers_rows = rows
                if disposition in ("ask", "block") and not notice:
                    from .compose import render_notice
                    reason = "; ".join(f.subject or f.category for f in extra) or reason
                    notice = render_notice(disposition, findings, reason=reason)
            elif composed.needs_judge:
                unjudged = unjudged + ["judge"]   # no backend configured: a model-routed rule is recorded, not enforced
            if disposition == "ask" and not event.capabilities.ask and self.mode == "enforce":
                disposition, extra, rows, more_unjudged = self._confirm_via_transcript(event, det, session, findings)
                findings = findings + extra
                unjudged = unjudged + more_unjudged
                answers_rows = answers_rows + rows
                if disposition == "allow":
                    notice = None

        verdict = Verdict(
            event_id=event_id,
            disposition=disposition,  # type: ignore[arg-type]
            reason=reason,
            notice=notice,
            findings=findings,
            mode=self.mode,  # type: ignore[arg-type]
            tier=tier.tier,
            action_class=action_class,
            unjudged=unjudged,
            timing_ms={},
        )
        self.ledger.record_disposition(event.session_hint, disposition if self.mode == "enforce" else "allow")
        flow_observe(event, session, pol, findings)

        t_dec = time.perf_counter()
        verdict.timing_ms = {
            "context": round((t_ctx - t0) * 1000, 2),
            "tier": round((t_tier - t_ctx) * 1000, 2),
            "decide": round((t_dec - t_tier) * 1000, 2),
            "total": round((t_dec - t0) * 1000, 2),  # pipeline time up to the store write
        }
        rec = self._record(event, verdict, received_at=received_at, session=session, turn_no=turn_no,
                           normalized=({**det.normalized, "harm": det.harm} if det is not None else None),
                           answers=answers_rows, guardrails=guard_scores)
        rec["timing_ms"] = dict(verdict.timing_ms)  # the stored copy must not alias the live verdict
        self.spool.append(rec)
        if self.repo is not None and not hasattr(self.repo, "put_events"):
            # a local repository (memory) is written inline; remote repositories are fed by the drainer
            self.repo.put_event(rec)
            summary = self.ledger.summary(event.session_hint)
            if summary:
                self.repo.put_session(summary)
        t_store = time.perf_counter()
        verdict.timing_ms["store"] = round((t_store - t_dec) * 1000, 2)
        verdict.timing_ms["total_with_store"] = round((t_store - t0) * 1000, 2)
        return verdict
