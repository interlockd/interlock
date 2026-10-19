"""`interlock judge`: the policy edit keeps comments and is reversible; status reports a missing judge."""

from __future__ import annotations

from interlockd import judge_setup as js
from interlockd.onboard import STARTER_POLICY
from interlockd.policy import load_policy


def test_configure_into_starter_policy_and_back(tmp_path):
    home = tmp_path / "il"; home.mkdir()
    pol = home / "policy.yaml"; pol.write_text(STARTER_POLICY)
    assert "added" in js.configure(pol, home, 8017)
    p = load_policy(None, home=home)
    assert p.judge.primary.type == "strands_decider" and p.judge.primary.base_url == "http://127.0.0.1:8017"
    assert p.judge.primary.local_command[:2] == [str(home / "judge" / "bin" / "strands-decider"), "serve"]
    assert p.judge.probe.local.enabled                                       # the existing judge.probe block is kept
    assert "unchanged" in js.configure(pol, home, 8017)                     # idempotent
    assert js.unconfigure(pol) and pol.read_text() == STARTER_POLICY


def test_configure_without_a_judge_section(tmp_path):
    home = tmp_path / "il"; home.mkdir()
    pol = home / "policy.yaml"; pol.write_text("mode: shadow\n")
    js.configure(pol, home, 9000)
    assert load_policy(None, home=home).judge.primary.base_url == "http://127.0.0.1:9000"


def test_status_without_judge(settings, capsys):
    from interlockd.cli import main

    assert main(["--home", str(settings.home), "judge", "status"]) == 0
    assert "not configured" in capsys.readouterr().out
