"""compose(): one document that tightens like applying several, in order (central baseline + group policies)."""

from __future__ import annotations

import random

import pytest

from interlockd.policy import Policy
from interlockd.policy.workspace import compose, tighten

RULES = ["git.force_push_own_branch", "git.force_push_protected_branch", "shell.pipe_to_shell", "egress.unknown_host",
         "no.such_rule"]
ACTIONS = ["allow", "flag", "model", "ask", "block"]
HOSTS = ["github.com", "pypi.org", "registry.npmjs.org", "example.com"]
REMOTES = ["github.com/acme/*", "github.com/acme/api", "gitlab.com/acme/*"]
PATHS = ["~/.ssh/**", "deploy/**", "infra/**"]
BRANCHES = ["main", "release/*", "prod"]
MCP_PATTERNS = ["github/*", "fs/write_file", "*/delete_*", "slack/post"]
PACKS = ["shell", "git", "egress", "persistence", "secrets", "packages"]


def sub(rng: random.Random, xs: list[str]) -> list[str]:
    return [x for x in xs if rng.random() < 0.5]


def random_doc(rng: random.Random) -> dict:
    d: dict = {}
    if rng.random() < 0.4:
        d["mode"] = rng.choice(["enforce", "shadow"])
    if rng.random() < 0.5:
        d["packs"] = {}
        if rng.random() < 0.4:
            d["packs"]["enabled"] = sub(rng, PACKS)
        if rng.random() < 0.8:
            d["packs"]["overrides"] = {r: rng.choice([{"action": rng.choice(ACTIONS)}, {"enabled": False}, {"action": "nope"}])
                                       for r in sub(rng, RULES)}
    if rng.random() < 0.6:
        t: dict = {}
        for k, universe in (("protected_paths", PATHS), ("sensitive_paths", PATHS), ("protected_branches", BRANCHES),
                            ("allowed_hosts", HOSTS), ("allowed_package_indexes", HOSTS),
                            ("allowed_git_remotes", REMOTES)):
            if rng.random() < 0.35:
                t[k] = sub(rng, universe)
        if rng.random() < 0.2:
            t["declared_packages_only"] = rng.choice([True, False])
        if rng.random() < 0.1:
            t["trusted_workspaces"] = ["~/code/*"]                 # ignored by tighten
        d["trust"] = t
    if rng.random() < 0.5:
        m: dict = {}
        if rng.random() < 0.5:
            m["default"] = rng.choice(["allow", "ask", "block"])
        if rng.random() < 0.7:
            m["tools"] = {p: rng.choice(["allow", "ask", "block"]) for p in sub(rng, MCP_PATTERNS)}
        if rng.random() < 0.3:
            m["oauth"] = {"deny_scopes": sub(rng, ["admin:*", "delete_repo"]),
                          **({"pin_authorization_servers": rng.choice([True, False])} if rng.random() < 0.5 else {})}
        if rng.random() < 0.05:
            m["default"] = "maybe"                                  # invalid: the whole mcp section is ignored
        d["mcp"] = m
    if rng.random() < 0.4:
        d["flow"] = {k: v for k, v in {"enabled": rng.choice([True, False]), "action": rng.choice(["block", "ask", "flag", "x"]),
                                       "sinks": sub(rng, ["egress", "git.push", "mcp:slack/*"])}.items() if rng.random() < 0.6}
    if rng.random() < 0.3:
        d["denial_budget"] = {k: v for k, v in {"consecutive": rng.choice([1, 2, 5, 0, -1]), "total": rng.choice([5, 10, 50]),
                                                "then": rng.choice(["ask", "block"])}.items() if rng.random() < 0.6}
    if rng.random() < 0.15:
        d["judge"] = {"backend": "none"}                            # never applied by tighten
    if rng.random() < 0.05:
        d["packs"] = "not a mapping"
    return d


def random_base(rng: random.Random) -> Policy:
    p, _ = Policy(), None
    data = random_doc(rng)
    data.pop("judge", None)
    if isinstance(data.get("packs"), str):
        data.pop("packs")
    for k in ("mode",):
        if k in data:
            p.mode = data[k]
    try:                                                            # a base with its own lists, overrides, MCP rules
        merged = Policy.model_validate({**p.model_dump(exclude={"source_paths", "sha256"}),
                                        **{k: {**p.model_dump()[k], **v} for k, v in data.items()
                                           if isinstance(v, dict) and k in ("trust", "mcp", "flow", "denial_budget")}})
        if isinstance(data.get("packs"), dict) and "overrides" in data["packs"]:
            for rid, ov in data["packs"]["overrides"].items():
                if ov.get("action") in ACTIONS or ov.get("enabled") is False:
                    merged.packs.overrides[rid] = merged.packs.overrides.get(rid, None) or type(next(iter(
                        Policy.model_validate({"packs": {"overrides": {rid: ov}}}).packs.overrides.values())))(**ov)
        return merged
    except ValueError:
        return p


def view(p: Policy) -> dict:
    d = p.model_dump(exclude={"source_paths", "sha256"})
    d["trust"].pop("allowed_git_remotes")
    return d


@pytest.mark.parametrize("seed", range(25))
def test_compose_matches_applying_the_layers_in_order(seed):
    rng = random.Random(seed)
    for _ in range(120):
        base = random_base(rng)
        docs = [random_doc(rng) for _ in range(rng.randint(0, 4))]
        seq = base
        for d in docs:
            seq, _ = tighten(seq, d)
        one, _ = tighten(base, compose(docs))
        assert view(one) == view(seq), (docs, compose(docs))
        # remotes: exact for a machine without its own list, never looser than the machine's list
        if not base.trust.allowed_git_remotes:
            assert one.trust.allowed_git_remotes == seq.trust.allowed_git_remotes
        else:
            assert set(one.trust.allowed_git_remotes) <= set(base.trust.allowed_git_remotes)


def test_compose_is_never_looser_than_any_layer():
    rng = random.Random(7)
    for _ in range(300):
        base = random_base(rng)
        docs = [random_doc(rng) for _ in range(rng.randint(1, 4))]
        one, _ = tighten(base, compose(docs))
        for d in docs:
            alone, _ = tighten(base, d)
            again, _ = tighten(one, d)                              # applying a layer once more changes nothing
            assert view(again) == view(one)
            assert (alone.mode == "enforce") <= (one.mode == "enforce")


def test_compose_examples():
    baseline = {"mode": "enforce", "trust": {"allowed_hosts": ["github.com", "pypi.org"]},
                "mcp": {"tools": {"fs/write_file": "ask"}}}
    oncall = {"packs": {"overrides": {"git.force_push_own_branch": {"action": "block"}}},
              "trust": {"allowed_hosts": ["github.com"], "protected_branches": ["prod"]},
              "mcp": {"tools": {"*/delete_*": "block", "github/*": "ask"}}}         # same layer: the ask applies
    contractors = {"mcp": {"tools": {"slack/post": "ask"}}}                   # after a block: a machine ignores it
    out = compose([baseline, oncall, contractors])
    assert out == {"mode": "enforce",
                   "packs": {"overrides": {"git.force_push_own_branch": {"action": "block"}}},
                   "trust": {"protected_branches": ["prod"], "allowed_hosts": ["github.com"]},
                   "mcp": {"tools": {"fs/write_file": "ask", "*/delete_*": "block", "github/*": "ask"}}}
    assert compose([]) == {} and compose([{"judge": {"backend": "none"}, "mode": "shadow"}, "junk"]) == {}
    assert compose([{"trust": {"allowed_git_remotes": ["a"]}}, {"trust": {"allowed_git_remotes": ["b"]}}]) == \
        {"trust": {"allowed_git_remotes": ["a"]}}                   # a layer sharing no remote is skipped
