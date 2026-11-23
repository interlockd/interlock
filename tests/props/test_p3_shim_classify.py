"""Property 3: Shim outcome classification (the Python shim's pure `classify()`).

For any (transport result, HTTP status, identity header values, Stop_Marker) tuple the shim returns:
token_rejected iff connected and status in {401, 403}; unjudged http_<n> iff connected and status >= 400 otherwise;
daemon_identity iff connected, status < 400 and the identity values are not exactly [expected]; operator_stopped iff
not connected and the marker is valid without expiry; restarting iff not connected and expires_epoch > now;
daemon_lost in every remaining not-connected case (absent, expired or malformed marker).

**Validates: Requirements 2.1, 3.6, 3.7, 3.8, 3.11, 3.13**
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from .strategies import GRACE_S, PROPS, epochs, header_lists, identities, marker_variants, status_codes

PY_SHIM = Path(__file__).resolve().parents[2] / "interlockd" / "shims" / "py" / "interlock-hook.py"

# Transport results the shim can observe (Req 3.13): only "connected" reaches the status and identity checks.
TRANSPORTS = ("connected", "refused", "timeout", "daemon_json_absent")


def _load_shim():
    spec = importlib.util.spec_from_file_location("interlock_py_shim_p3", PY_SHIM)
    mod = importlib.util.module_from_spec(spec)
    before, sys.dont_write_bytecode = sys.dont_write_bytecode, True   # no __pycache__ in the packaged shims
    try:
        spec.loader.exec_module(mod)       # main() runs only as __main__
    finally:
        sys.dont_write_bytecode = before
    return mod


SHIM = _load_shim()


@st.composite
def outcomes(draw):
    """(transport, status, identity values, expected identity, marker variant, marker text, now)."""
    now = draw(epochs()) + GRACE_S         # marker_variants needs room for a past-expiry marker before `now`
    expected = draw(identities())
    variant, marker_text = draw(marker_variants(now))
    return (draw(st.sampled_from(TRANSPORTS)), draw(status_codes()), draw(header_lists(expected)), expected,
            variant, marker_text, now)


def _oracle(transport, status, values, expected, variant):
    if transport != "connected":
        return {"no_expiry": ("unjudged", "operator_stopped"),
                "future_expiry": ("unjudged", "restarting")}.get(variant, ("tamper", "daemon_lost"))
    if status in (401, 403):
        return "tamper", "token_rejected"
    if status >= 400:
        return "unjudged", f"http_{status}"
    if values != [expected]:
        return "tamper", "daemon_identity"
    return "apply", ""


# Feature: hook-tamper-detection, Property 3: Shim outcome classification
@PROPS
@given(outcomes())
def test_shim_outcome_classification(case):
    transport, status, values, expected, variant, marker_text, now = case
    got = SHIM.classify(transport == "connected", status, values, expected, marker_text, now)
    assert got == _oracle(transport, status, values, expected, variant), case
    if transport != "connected":
        # the marker alone decides; status and identity are never consulted (Req 3.13, 3.14)
        assert SHIM.marker_state(marker_text, now) == {"no_expiry": "operator_stopped",
                                                       "future_expiry": "restarting"}.get(variant)
