"""Composer (design §4.7): findings and rule actions -> one disposition, a reason, and a notice for the model."""

from __future__ import annotations

from dataclasses import dataclass

from .det import DetResult
from .det.mandate import MandateResult
from .models import Finding
from .policy import Policy

ORDER = {"block": 4, "ask": 3, "model": 2, "flag": 1, "allow": 0}


@dataclass
class Composed:
    disposition: str
    reason: str | None
    notice: str | None
    findings: list[Finding]
    unjudged: list[str]
    needs_judge: bool = False


def _describe(f: Finding) -> str:
    rule = (f.rule or f.category).replace("_", " ").replace(".", ": ", 1)
    return f"{rule}" + (f" ({f.subject})" if f.subject else "")


def render_notice(disposition: str, findings: list[Finding], *, reason: str | None) -> str:
    """OGR `continuation` wording: what was refused, that it did not run, what the agent may do, no disguised retry."""
    what = "; ".join(_describe(f) for f in findings[:3]) or (reason or "a security policy")
    if disposition == "block":
        return (f"[interlock] This action was refused by a security policy and was NOT executed. Reason: {what}. "
                "You may pursue the user's goal by other legitimate means, but you MUST NOT retry this action in a disguised form "
                "(different encoding, split across commands, via another tool). If the action is genuinely required, stop and ask the user.")
    if disposition == "ask":
        return (f"[interlock] This action was NOT executed because it needs the user's explicit confirmation. Reason: {what}. "
                "Ask the user whether to proceed, quoting the exact command, and only retry after they confirm. Do not retry in a disguised form.")
    return ""


def compose(det: DetResult, mandate: MandateResult, policy: Policy, *, session: dict | None, kind: str) -> Composed:
    findings = list(det.findings)
    unjudged = list(mandate.unjudged) if mandate.unjudged and policy.mandate.mode != "off" else []
    if mandate.finding is not None:
        findings.append(mandate.finding)

    if kind == "post_action":
        disp = "warn" if any(f.rule == "secrets.literal_in_result" for f in findings) else "pass"
        reason = "; ".join(_describe(f) for f in findings[:3]) or None
        return Composed(disp, reason, None, findings, unjudged)

    # strongest rule action wins (deny-wins)
    action = det.decision  # block | ask | model | flag | allow | None
    if mandate.finding is not None and policy.mandate.mode == "enforce":
        action = "block" if ORDER.get(action or "allow", 0) < ORDER["block"] else action
    elif mandate.finding is not None:  # log_only: a finding, no enforcement
        pass

    # denial budget (Anthropic backstop): after N consecutive or M total denials, escalate to the human
    budget_hit = False
    if session:
        b = policy.denial_budget
        if session.get("denials_consecutive", 0) >= b.consecutive or session.get("denials_total", 0) >= b.total:
            budget_hit = True

    if action == "block":
        disp = "block"
    elif action == "ask":
        disp = "ask"
    elif action in ("model", None, "flag", "allow"):
        disp = "allow"
    else:
        disp = "allow"
    needs_judge = action == "model" or bool(det.questions)
    if budget_hit and disp == "allow" and det.action_class not in ("read", "harness", "edit_in_workspace", "build_or_test"):
        disp = policy.denial_budget.then
        findings.append(Finding(category="x.interlock.denial_budget_exhausted", severity="high", rule="budget.denials",
                                detector="interlock.ledger", path="tool_call", score=1.0,
                                subject=f"{session.get('denials_consecutive', 0)} consecutive / {session.get('denials_total', 0)} total denials"))
    reason = "; ".join(_describe(f) for f in findings[:3]) or None
    notice = render_notice(disp, findings, reason=reason) if disp in ("block", "ask") else None
    return Composed(disp, reason, notice, findings, unjudged, needs_judge=needs_judge)
