"""Policy lint: silent mistakes become visible."""

from __future__ import annotations

from interlockd.policy import Policy, RuleOverride
from interlockd.policy_lint import format_issues, lint


def _w(pol):
    return {(i.level, i.where): i.message for i in lint(pol)}


def test_clean_default_policy():
    assert lint(Policy()) == [] and format_issues([])[1] == 0


def test_typo_in_override_is_an_error_with_a_suggestion():
    p = Policy(); p.packs.overrides["git.force_push_protectd_branch"] = RuleOverride(action="allow")
    msg = _w(p)[("error", "packs.overrides.git.force_push_protectd_branch")]
    assert "does nothing" in msg and "git.force_push_protected_branch" in msg
    assert format_issues(lint(p))[1] == 1


def test_weakening_and_disabling_critical_rules_warn():
    p = Policy()
    p.packs.overrides["shell.pipe_to_shell"] = RuleOverride(action="allow")
    p.packs.overrides["shell.fork_bomb"] = RuleOverride(enabled=False)
    p.packs.overrides["git.reset_hard"] = RuleOverride(action="allow")          # high, not critical: fine
    w = _w(p)
    assert "weakens a critical rule" in w[("warning", "packs.overrides.shell.pipe_to_shell")]
    assert "disables" in w[("warning", "packs.overrides.shell.fork_bomb")]
    assert ("warning", "packs.overrides.git.reset_hard") not in w


def test_other_checks():
    p = Policy()
    p.packs.enabled = ["shell", "gti"]
    p.trust.allowed_git_remotes = ["*"]
    p.mcp.tools = {"github/": "block", "*": "allow"}
    p.flow.enabled = False
    w = _w(p)
    assert "did you mean git" in w[("error", "packs.enabled")] and ("warning", "trust.allowed_git_remotes") in w
    assert ("error", "mcp.tools['github/']") in w and ("warning", "mcp.tools") in w and ("warning", "flow.enabled") in w
