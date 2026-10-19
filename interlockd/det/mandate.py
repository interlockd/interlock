"""Cedar mandate (design D8): the operator's authorization envelope, evaluated locally with cedarpy.

Bindings map the deterministic engine's normalized structure onto Interlock::Action names and a context.
Unbound actions are reported in `unjudged`, never silently permitted (OGR mandate semantics). Cedar's own
default-deny applies only to bound actions when at least one policy exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import Finding
from ..policy import Policy
from . import DetResult


@dataclass
class MandateResult:
    evaluated: bool = False
    decision: str | None = None          # "Allow" | "Deny" | None
    action: str | None = None
    reasons: list[str] = field(default_factory=list)
    unjudged: list[str] = field(default_factory=list)
    finding: Finding | None = None


def bind_action(res: DetResult, tool_name: str) -> tuple[str | None, dict[str, Any]]:
    """Return (Interlock::Action id, context.input) for the normalized structure, or (None, {}) if unbound."""
    n = res.normalized
    if "git_push" in n:
        gp = n["git_push"]
        return "git.push", {"remote": gp["remote"], "branch": gp["branch"], "force": bool(gp["force"]), "delete": bool(gp["delete"])}
    if "git_remote_add" in n:
        return "git.remote_add", {"url": n["git_remote_add"]["url"]}
    if any(f.rule in ("git.history_rewrite", "git.reset_hard", "git.clean_force") for f in res.findings):
        return "git.history_rewrite", {}
    if n.get("egress_hosts"):                          # network tools and shell egress (curl, wget, ...) alike
        return "net.egress", {"hosts": n["egress_hosts"]}
    if res.action_class == "destructive":
        return "destructive", {}
    if res.action_class == "install_or_configure":
        return "install", {"undeclared": n.get("undeclared_packages", [])}
    if res.action_class == "credential_access":
        return "fs.read_sensitive", {}
    if res.action_class in ("edit_in_workspace",):
        return "fs.write", {}
    if res.action_class in ("edit_outside_workspace", "edit_protected"):
        return "fs.write_outside", {}
    if any(f.rule == "shell.sudo" for f in res.findings):
        return "sys.privilege", {}
    if res.action_class in ("build_or_test",):
        return "shell.build_or_test", {}
    return None, {}


def evaluate_mandate(policy: Policy, res: DetResult, *, agent_id: str, workspace: str, session_counters: dict[str, Any]) -> MandateResult:
    out = MandateResult()
    m = policy.mandate
    if m.mode == "off" or (not m.cedar and not m.inline):
        return out
    try:
        import cedarpy  # lazy, optional dependency
    except ImportError:
        out.unjudged = ["mandate"]
        return out
    text = m.inline or ""
    if m.cedar:
        p = Path(m.cedar)
        if not p.exists():
            out.unjudged = ["mandate"]
            return out
        text = p.read_text() + "\n" + text
    action, ctx_input = bind_action(res, "")
    if action is None:
        out.unjudged = ["mandate"]
        return out
    request = {
        "principal": f'Interlock::Agent::"{agent_id or "agent"}"',
        "action": f'Interlock::Action::"{action}"',
        "resource": f'Interlock::Workspace::"{workspace or "workspace"}"',
        "context": {"input": ctx_input, "session": {k.replace(":", "_"): v for k, v in session_counters.items() if isinstance(v, int)}},
    }
    try:
        r = cedarpy.is_authorized(request, text, [])
    except Exception as e:  # noqa: BLE001  a policy that fails to parse or evaluate is reported, not swallowed
        out.unjudged = ["mandate"]
        out.reasons = [f"cedar error: {type(e).__name__}: {e}"[:200]]
        return out
    out.evaluated, out.action = True, action
    out.decision = "Allow" if str(r.decision).endswith("Allow") else "Deny"
    try:
        out.reasons = list(r.diagnostics.reasons)
    except Exception:  # noqa: BLE001  diagnostics shape differs across cedarpy versions
        out.reasons = []
    if out.decision == "Deny":
        dim = "capability"
        if action == "git.push" and ctx_input.get("force"):
            dim = "irreversible"
        elif action in ("net.egress", "git.push", "git.remote_add"):
            dim = "scope"
        elif any(k.endswith("_count") or k.startswith("class_") for k in request["context"]["session"]) and "destructive" in action:
            dim = "limit"
        out.finding = Finding(category=f"security.mandate_violation.{dim}", severity="high", rule=f"mandate:{action}",
                              detector="interlock.mandate", path="tool_call", score=1.0,
                              subject=f"{action} denied by mandate" + (f" ({', '.join(out.reasons)})" if out.reasons else ""))
    return out
