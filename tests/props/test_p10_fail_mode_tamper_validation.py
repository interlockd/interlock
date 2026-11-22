"""Property 10: `fail_mode.tamper` validation (Policy._fail_mode_tamper, load_policy, failmode.write).

A policy with `fail_mode.tamper: v` validates iff v is "open" or "closed"; the error otherwise names
`fail_mode.tamper` and v; a policy without the key has effective value "closed". The fail-mode.json written from
any valid policy carries both `default` and `tamper`.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from interlockd import failmode
from interlockd.policy import Policy, load_policy

from .strategies import _CATEGORY_KEYS, FAIL_MODES, PROPS

_text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=16)

# Any value a YAML document or a caller could put under `fail_mode.tamper`, biased towards near misses.
tamper_values = st.one_of(
    st.sampled_from(FAIL_MODES),
    st.sampled_from(("Open", "CLOSED", " closed", "open ", "", "deny", "allow", "true", "null")),
    _text,
    st.integers(),
    st.booleans(),
    st.none(),
    st.floats(allow_nan=False),
    st.lists(st.sampled_from(FAIL_MODES), max_size=2),
    st.dictionaries(st.sampled_from(FAIL_MODES), st.sampled_from(FAIL_MODES), max_size=1),
)

# Other, valid fail_mode entries (category keys and `default`) so the tamper key is judged alongside them.
other_keys = st.dictionaries(st.sampled_from((*_CATEGORY_KEYS, "default")), st.sampled_from(FAIL_MODES),
                             max_size=len(_CATEGORY_KEYS) + 1)

# Values that survive a YAML dump/load round trip as themselves (no floats: YAML may re-type them).
yaml_tamper_values = st.one_of(
    st.sampled_from(FAIL_MODES),
    st.sampled_from(("Open", "CLOSED", " closed", "open ", "", "deny", "yes", "on", "null", "~")),
    st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7e), max_size=16),
    st.integers(-10**6, 10**6),
    st.booleans(),
    st.none(),
)


def _validates(fail_mode: dict) -> tuple[Policy | None, Exception | None]:
    try:
        return Policy.model_validate({"fail_mode": fail_mode}), None
    except ValueError as e:                              # pydantic.ValidationError subclasses ValueError
        return None, e


def _assert_property(value, accepted: Policy | None, err: Exception | None) -> None:
    if value in FAIL_MODES and isinstance(value, str):
        assert err is None, f"{value!r} rejected: {err}"
        assert accepted.fail_mode["tamper"] == value
        assert failmode.effective_tamper(accepted) == value
    else:
        assert accepted is None, f"{value!r} accepted as fail_mode.tamper"
        msg = str(err)
        assert "fail_mode.tamper" in msg
        assert f"fail_mode.tamper: {value} is not one of open, closed" in msg


# Feature: hook-tamper-detection, Property 10: `fail_mode.tamper` validation
@PROPS
@given(value=tamper_values, others=other_keys)
def test_tamper_accepted_iff_open_or_closed(value, others):
    """**Validates: Requirements 4.1**"""
    accepted, err = _validates({**others, "tamper": value})
    _assert_property(value, accepted, err)


# Feature: hook-tamper-detection, Property 10: `fail_mode.tamper` validation
@PROPS
@given(others=other_keys)
def test_absent_tamper_is_closed(others):
    """**Validates: Requirements 4.1**"""
    accepted, err = _validates(dict(others))
    assert err is None
    assert accepted.fail_mode["tamper"] == "closed"
    assert failmode.effective_tamper(accepted) == "closed"
    for k, v in others.items():                          # the other keys are kept as given
        assert accepted.fail_mode[k] == v


def test_default_policy_tamper_is_closed():
    """**Validates: Requirements 4.1**"""
    assert Policy().fail_mode["tamper"] == "closed"
    assert failmode.effective_tamper(Policy()) == "closed"


# Feature: hook-tamper-detection, Property 10: `fail_mode.tamper` validation
@PROPS
@given(value=st.one_of(st.just(None), yaml_tamper_values), others=other_keys,
       table=st.dictionaries(st.sampled_from((*_CATEGORY_KEYS, "default")), st.sampled_from(FAIL_MODES)),
       absent=st.booleans())
def test_policy_file_round_trip_and_fail_mode_json(value, others, table, absent):
    """Through a YAML policy file and load_policy: same accept/reject rule; every fail-mode.json written from an
    accepted policy carries both `default` and `tamper`, with `tamper` equal to the effective policy value.

    **Validates: Requirements 4.1**"""
    fail_mode = dict(others) if absent else {**others, "tamper": value}
    with tempfile.TemporaryDirectory() as d:
        home = Path(d)
        (home / "policy.yaml").write_text(yaml.safe_dump({"fail_mode": fail_mode}), encoding="utf-8")
        try:
            pol, err = load_policy(None, home=home), None
        except ValueError as e:
            pol, err = None, e
        if absent:
            assert err is None
            want = "closed"
        else:
            assert yaml.safe_load((home / "policy.yaml").read_text())["fail_mode"]["tamper"] == value
            _assert_property(value, pol, err)
            if pol is None:
                return
            want = value
        assert pol.fail_mode["tamper"] == want
        doc = failmode.write(home, table, pol)
        on_disk = json.loads((home / failmode.FILE).read_text(encoding="utf-8"))
        assert on_disk == doc
        assert on_disk["tamper"] == want
        assert on_disk["default"] == table.get("default", "open")
        assert set(on_disk) == set(table) | {"default", "tamper"}


@pytest.mark.parametrize("value", ["opened", "Closed", 0, None])
def test_rejection_message_examples(value):
    """**Validates: Requirements 4.1**"""
    _, err = _validates({"default": "open", "tamper": value})
    assert f"fail_mode.tamper: {value} is not one of open, closed" in str(err)
