"""`interlock policy lint`: catch policy mistakes that would otherwise fail silently.

A typo in `packs.overrides` (an unknown rule id) does nothing at all, so the rule you meant to tune keeps its default;
an override that turns a critical rule into `allow` is legal but worth a second look. Errors make the command exit 1.
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import get_close_matches

from .policy import Policy

KNOWN_PACKS = {"shell", "git", "egress", "persistence", "secrets", "packages"}
COMPOSER_RULES = {"budget.denials"}


@dataclass
class Issue:
    level: str          # error | warning
    where: str
    message: str


def lint(policy: Policy) -> list[Issue]:
    from .det import RULES, flow, mcp, oauth, packs  # noqa: F401  register every rule

    out: list[Issue] = []
    known = set(RULES) | COMPOSER_RULES
    for rid, ov in policy.packs.overrides.items():
        if rid not in known:
            near = get_close_matches(rid, known, n=1)
            out.append(Issue("error", f"packs.overrides.{rid}", "unknown rule id: this override does nothing"
                             + (f" (did you mean {near[0]}?)" if near else "")))
            continue
        _, severity, default = RULES.get(rid, ("", "high", "ask"))
        weaker = {"block": 4, "ask": 3, "model": 2, "flag": 1, "allow": 0}
        if ov.action and severity == "critical" and weaker[ov.action] < weaker.get(default, 0):
            out.append(Issue("warning", f"packs.overrides.{rid}", f"weakens a critical rule ({default} -> {ov.action})"))
        if ov.enabled is False and severity == "critical":
            out.append(Issue("warning", f"packs.overrides.{rid}", "disables a critical rule"))
    for p in policy.packs.enabled:
        if p not in KNOWN_PACKS:
            near = get_close_matches(p, KNOWN_PACKS, n=1)
            out.append(Issue("error", "packs.enabled", f"unknown pack {p!r}" + (f" (did you mean {near[0]}?)" if near else "")))
    missing = KNOWN_PACKS - set(policy.packs.enabled)
    if missing:
        out.append(Issue("warning", "packs.enabled", f"packs turned off: {', '.join(sorted(missing))}"))
    for r in policy.trust.allowed_git_remotes:
        if r.strip() in ("*", "**", "*/*"):
            out.append(Issue("warning", "trust.allowed_git_remotes", f"{r!r} allows pushing anywhere"))
    for h in policy.trust.allowed_hosts:
        if h.strip() in ("*", "**"):
            out.append(Issue("warning", "trust.allowed_hosts", f"{h!r} allows egress to any host"))
    for pat in policy.mcp.tools:
        server = pat.split("/", 1)[0]
        if "/" in pat and not pat.split("/", 1)[1]:
            out.append(Issue("error", f"mcp.tools[{pat!r}]", "empty tool part; use the server name alone for a whole server"))
        if server == "":
            out.append(Issue("error", f"mcp.tools[{pat!r}]", "empty server part"))
    if policy.mcp.tools.get("*") == "allow" or policy.mcp.tools.get("*/*") == "allow":
        out.append(Issue("warning", "mcp.tools", "a catch-all allow; more specific patterns still win, but nothing new is ever asked"))
    if not policy.flow.enabled:
        out.append(Issue("warning", "flow.enabled", "toxic-flow detection is off"))
    if policy.mode == "enforce" and policy.judge.probe.local.enabled is False and not policy.judge.probe.enabled:
        out.append(Issue("warning", "judge.probe", "no injection detector is enabled: tool results are not checked"))
    return out


def format_issues(issues: list[Issue]) -> tuple[str, int]:
    if not issues:
        return "policy: no issues", 0
    lines = [f"  {'✗' if i.level == 'error' else '!'} {i.where}: {i.message}" for i in issues]
    errors = sum(i.level == "error" for i in issues)
    lines.append(f"\n{errors} error(s), {len(issues) - errors} warning(s)")
    return "\n".join(lines), 1 if errors else 0
