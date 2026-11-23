"""Property 4: Fail-mode selection (the Python shim's select_fail_mode).
For any cause (tamper or not), INTERLOCK_FAIL_MODE value (unset or any string) and fail-mode.json content (valid with
both keys, valid without `tamper`, invalid `tamper` value, unparseable, absent): `closed` for every cause when the
environment value is exactly `closed`; otherwise a tamper cause gets the file's `tamper` value when it is `open` or
`closed` and `closed` in every other case, and a non-tamper cause gets the file's `default` value when valid and
`open` otherwise.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from .strategies import FAIL_MODES, NON_TAMPER_CAUSES, PROPS, TAMPER_CAUSES, env_fail_modes, fail_mode_docs

PY_SHIM = Path(__file__).resolve().parents[2] / "interlockd" / "shims" / "py" / "interlock-hook.py"


def _load_shim():
    spec = importlib.util.spec_from_file_location("interlock_py_shim_p4", PY_SHIM)
    mod = importlib.util.module_from_spec(spec)
    before, sys.dont_write_bytecode = sys.dont_write_bytecode, True   # no __pycache__ in the packaged shims
    try:
        spec.loader.exec_module(mod)       # main() runs only as __main__
    finally:
        sys.dont_write_bytecode = before
    return mod


SHIM = _load_shim()


def _expected(cause: str, env: str | None, variant: str, text: str | None) -> str:
    """The oracle, from the parsed document rather than the shim's string matching."""
    if env == "closed":
        return "closed"
    doc = json.loads(text) if variant in ("valid", "missing_tamper", "invalid_tamper") else {}
    key, fallback = ("tamper", "closed") if cause in TAMPER_CAUSES else ("default", "open")
    value = doc.get(key)
    return value if value in FAIL_MODES else fallback


# Feature: hook-tamper-detection, Property 4: Fail-mode selection
@PROPS
@given(st.sampled_from(TAMPER_CAUSES + NON_TAMPER_CAUSES), env_fail_modes(), fail_mode_docs())
def test_fail_mode_selection(cause, env, doc):
    """**Validates: Requirements 4.3, 4.7, 4.8, 4.9**"""
    variant, text = doc
    got = SHIM.select_fail_mode(cause, env, text or "")
    assert got == _expected(cause, env, variant, text), (cause, env, variant, text)


# Feature: hook-tamper-detection, Property 4: Fail-mode selection (an environment value cannot loosen the gate)
@PROPS
@given(st.sampled_from(TAMPER_CAUSES + NON_TAMPER_CAUSES), env_fail_modes(), fail_mode_docs())
def test_environment_never_loosens(cause, env, doc):
    """**Validates: Requirements 4.8, 4.9**"""
    _, text = doc
    with_env = SHIM.select_fail_mode(cause, env, text or "")
    without_env = SHIM.select_fail_mode(cause, None, text or "")
    assert with_env == ("closed" if env == "closed" else without_env)


def test_shim_tamper_causes_cover_the_design_set():
    """The shim treats exactly the design's four keywords as tamper causes (three shim-side plus enforcement_point)."""
    assert set(SHIM.TAMPER_CAUSES) | {"enforcement_point"} == set(TAMPER_CAUSES)
