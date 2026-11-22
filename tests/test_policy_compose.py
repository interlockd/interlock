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


# --- fail_mode.tamper and notify.desktop (hook-tamper-detection, Requirements 4.1, 4.2, 6.6) ------------------------

def test_fail_mode_tamper_defaults_to_closed_and_accepts_open_or_closed():
    assert Policy().fail_mode["tamper"] == "closed"
    assert Policy.model_validate({"fail_mode": {"default": "open"}}).fail_mode == {"default": "open", "tamper": "closed"}
    for v in ("open", "closed"):
        assert Policy.model_validate({"fail_mode": {"default": "closed", "tamper": v}}).fail_mode["tamper"] == v
    assert Policy().notify.desktop is False
    assert Policy.model_validate({"notify": {"desktop": True}}).notify.desktop is True


@pytest.mark.parametrize("bad", ["Closed", "", "off", "deny", True, 0, None])
def test_fail_mode_tamper_rejects_other_values(bad):
    with pytest.raises(ValueError, match=f"fail_mode.tamper: {bad} is not one of open, closed"):
        Policy.model_validate({"fail_mode": {"tamper": bad}})


def test_notify_rejects_unknown_keys():
    with pytest.raises(ValueError):
        Policy.model_validate({"notify": {"sound": True}})


def test_load_policy_validates_fail_mode_tamper(tmp_path):
    from interlockd.policy import load_policy

    (tmp_path / "policy.yaml").write_text("fail_mode:\n  default: open\n  tamper: maybe\n", encoding="utf-8")
    with pytest.raises(ValueError, match="fail_mode.tamper: maybe"):
        load_policy(None, home=tmp_path)
    (tmp_path / "policy.yaml").write_text("fail_mode:\n  default: closed\n", encoding="utf-8")
    assert load_policy(None, home=tmp_path).fail_mode["tamper"] == "closed"


def test_repository_and_managed_layers_cannot_change_fail_mode_tamper():
    # fail modes follow `fail_mode.default`: only your own policy sets them; tighten-only layers ignore them
    for base_value in ("open", "closed"):
        base = Policy.model_validate({"fail_mode": {"default": "open", "tamper": base_value}})
        other = "closed" if base_value == "open" else "open"
        pol, ignored = tighten(base, {"fail_mode": {"tamper": other}})
        assert pol.fail_mode["tamper"] == base_value and "fail_mode" in ignored
        pol, ignored = tighten(base, {"fail_mode": {"tamper": base_value}})   # restating it is not reported
        assert pol.fail_mode["tamper"] == base_value and "fail_mode" not in ignored
    assert "fail_mode" not in compose([{"fail_mode": {"tamper": "open"}}])


def test_fail_mode_file_always_carries_default_and_tamper(tmp_path):
    import json
    import os
    import stat

    from interlockd import failmode
    from interlockd.config import DEFAULT_FAIL_MODE

    doc = failmode.write(tmp_path, DEFAULT_FAIL_MODE, Policy())
    text = (tmp_path / "fail-mode.json").read_text(encoding="utf-8")
    assert json.loads(text) == doc == {**DEFAULT_FAIL_MODE, "tamper": "closed"}
    assert '"default": "open"' in text and '"tamper": "closed"' in text     # what the shims match on
    if os.name == "posix":
        assert stat.S_IMODE((tmp_path / "fail-mode.json").stat().st_mode) == 0o600
    assert not (tmp_path / "fail-mode.json.tmp").exists()

    open_pol = Policy.model_validate({"fail_mode": {"default": "closed", "tamper": "open"}})
    # `default` keeps coming from the settings table; `tamper` only from the policy (a stray table entry is replaced)
    doc = failmode.write(tmp_path, {"default": "closed", "tamper": "open"}, None)
    assert doc == {"default": "closed", "tamper": "closed"}
    doc = failmode.write(tmp_path, {"security.persistence": "closed"}, open_pol)
    assert doc == {"security.persistence": "closed", "default": "open", "tamper": "open"}
    assert json.loads((tmp_path / "fail-mode.json").read_text(encoding="utf-8")) == doc
    assert failmode.effective_tamper({"tamper": "nope"}) == "closed"


def test_cli_writers_include_tamper(tmp_path):
    import json

    from interlockd.cli import _write_fail_mode
    from interlockd.config import Settings

    s = Settings(home=tmp_path)
    assert _write_fail_mode(s)["tamper"] == "closed"                       # no policy file: closed
    (tmp_path / "policy.yaml").write_text("fail_mode:\n  default: open\n  tamper: open\n", encoding="utf-8")
    assert _write_fail_mode(s)["tamper"] == "open"
    (tmp_path / "policy.yaml").write_text("fail_mode:\n  tamper: bogus\n", encoding="utf-8")
    assert _write_fail_mode(s)["tamper"] == "closed"                       # a policy that does not load: closed
    on_disk = json.loads((tmp_path / "fail-mode.json").read_text(encoding="utf-8"))
    assert on_disk["default"] == s.fail_mode["default"] and on_disk["tamper"] == "closed"
