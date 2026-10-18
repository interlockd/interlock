"""Deterministic engine (design §4.3): pure functions from an event and a policy to findings.

Every finding carries an OGR category, a payload path, a rule id, and score 1.0 (a deterministic
comparison is never presented as a model's confidence). Packs are table-driven and each ships a
cases file under daemon/interlockd/data/packs/.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import Finding
from ..policy import Policy, RuleAction

# Rule id -> (OGR category, severity, default action)
RULES: dict[str, tuple[str, str, RuleAction]] = {}


def rule(rule_id: str, category: str, severity: str, default: RuleAction):
    RULES[rule_id] = (category, severity, default)
    return rule_id


@dataclass
class DetResult:
    findings: list[Finding] = field(default_factory=list)
    actions: dict[str, RuleAction] = field(default_factory=dict)      # rule id -> resolved action
    normalized: dict[str, Any] = field(default_factory=dict)          # parsed structure for the record and the judge
    action_class: str = "other"
    harm: int = 0                                                      # 0..3, see harm()
    questions: list[str] = field(default_factory=list)                 # judge questions requested by rules

    @property
    def decision(self) -> RuleAction | None:
        order = {"block": 4, "ask": 3, "model": 2, "flag": 1, "allow": 0}
        if not self.actions:
            return None
        return max(self.actions.values(), key=lambda a: order[a])

    def add(self, policy: Policy, rule_id: str, *, path: str, subject: str | None = None,
            start: int | None = None, end: int | None = None, detector: str = "interlock.det") -> bool:
        category, severity, default = RULES[rule_id]
        action = policy.rule_action(rule_id, default)
        if action is None:
            return False
        self.findings.append(Finding(category=category, severity=severity, rule=rule_id, detector=detector,
                                     path=path, start=start, end=end, score=1.0, subject=subject))
        self.actions[rule_id] = action
        ov = policy.packs.overrides.get(rule_id)
        if ov and ov.questions:
            self.questions.extend(q for q in ov.questions if q not in self.questions)
        return True
