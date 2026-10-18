"""Every example policy loads and lints clean; every example agent script at least parses."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from interlockd.policy import load_policy
from interlockd.policy_lint import lint

ROOT = next((p for p in (Path(__file__).resolve().parents[2] / "oss" / "examples", Path(__file__).resolve().parents[1] / "examples")
             if p.exists()), None)
pytestmark = pytest.mark.skipif(ROOT is None, reason="examples not in this layout")


@pytest.mark.parametrize("path", sorted((ROOT / "policies").glob("*.yaml")) if ROOT else [], ids=lambda p: p.name)
def test_policy_examples(path, tmp_path):
    (tmp_path / "policy.yaml").write_text(path.read_text())
    pol = load_policy(None, home=tmp_path)
    assert [i for i in lint(pol) if i.level == "error"] == []


@pytest.mark.parametrize("path", sorted((ROOT / "agents").glob("*.py")) if ROOT else [], ids=lambda p: p.name)
def test_agent_examples_parse(path):
    ast.parse(path.read_text())
