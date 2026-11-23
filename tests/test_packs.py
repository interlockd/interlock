"""Table-driven pack corpus (interlockd/data/packs/*.jsonl). Each case is one tool call and the rules it must (and must not) fire.

Case fields: id, cmd (shell) or tool+args, expect (block|ask|model|allow), rules (must fire), not_rules (must not fire;
"*" = no finding at all), optional manifest {filename: content} written to the workspace root, optional tier.

The case runner lives in interlockd.testkit so that `interlock test` (the CLI) and this pytest module share one
implementation and never drift. This file keeps the per-case assertions; the CLI adds FPR/FNR aggregation on top.
"""

from __future__ import annotations

from collections import Counter

import pytest

from interlockd.testkit import default_corpus_dir, load_cases, load_corpus_trust, run_case

CASES = load_cases(default_corpus_dir())
CORPUS_TRUST = load_corpus_trust(default_corpus_dir())


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_pack_case(case, tmp_path):
    ws = tmp_path / "proj"
    ws.mkdir()
    res = run_case(case, ws, corpus_trust=CORPUS_TRUST)
    # testkit collects every mismatch (rules, not_rules, disposition, tier) into res.errors.
    assert not res.errors, f"[{res.pack}] {res.case_id}: " + "; ".join(res.errors)


def test_corpus_size_and_balance():
    assert len(CASES) >= 200
    negatives = sum(1 for c in CASES if c["expect"] == "allow")
    assert negatives >= 0.3 * len(CASES), "corpus needs hard negatives, not only attacks"


def test_report(tmp_path, capsys):
    """Per-rule and per-pack summary, printed with -s. Not an assertion; the parametrized cases are."""
    by_pack = Counter(c["pack"] for c in CASES)
    by_expect = Counter(c["expect"] for c in CASES)
    rules = Counter(r for c in CASES for r in c.get("rules", []))
    print(f"\npacks: {dict(by_pack)}\nexpect: {dict(by_expect)}\nrules covered: {len(rules)}")


@pytest.mark.parametrize("cmd, spelled, code", [
    ("interlock ack -y", "ack", "ack"),
    ("sudo interlock stop", "stop", "stop"),
    ("cd ~ && interlock policy accept", "policy accept", "policy_accept"),
    ("interlock policy --workspace . revert", "policy revert", "policy_revert"),
    ("python3 -m interlockd token --rotate", "token --rotate", "token_rotate"),
    ("interlock token --rot", "token --rotate", "token_rotate"),          # argparse prefix of --rotate
    ("uv run --with x interlock --home /tmp/h uninstall --yes", "uninstall", "uninstall"),
    ("timeout 5 interlock restart", "restart", "restart"),
])
def test_interlock_control_normalized_subcommand(cmd, spelled, code):
    """normalized["interlock_control"] is the command-line spelling; operator.action_name maps it to the record code
    that correlate_hook_session compares against."""
    from interlockd.det import DetResult
    from interlockd.det.packs import CONTROL_SUBCOMMANDS, check_persistence_shell
    from interlockd.det.shellparse import parse
    from interlockd.operator import action_name
    from interlockd.policy import Policy

    res = DetResult()
    check_persistence_shell(parse(cmd), res, Policy(), None)
    assert [f.rule for f in res.findings if f.rule == "persistence.interlock_control"]
    assert res.actions["persistence.interlock_control"] == "ask"
    assert res.normalized["interlock_control"] == spelled and spelled in CONTROL_SUBCOMMANDS
    assert action_name(res.normalized["interlock_control"]) == code


@pytest.mark.parametrize("cmd", ["interlock status", "interlock enforce", "interlock token", "interlock stop --help",
                                 "interlock capture stop", "echo interlock stop", "python -c 'print(1)' -m interlockd stop"])
def test_interlock_control_read_only_or_data(cmd):
    from interlockd.det import DetResult
    from interlockd.det.packs import check_persistence_shell
    from interlockd.det.shellparse import parse
    from interlockd.policy import Policy

    res = DetResult()
    check_persistence_shell(parse(cmd), res, Policy(), None)
    assert "persistence.interlock_control" not in res.actions and "interlock_control" not in res.normalized
