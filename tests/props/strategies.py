"""Shared Hypothesis strategies and settings for the hook-tamper-detection property tests.

Shapes follow design.md (Data Models). The fixed code sets below mirror the design's constants for modules that are
built in later tasks (``protection.py``, ``lifecycle.py``); once those exist, tests should assert that these sets
equal the module constants so the two cannot drift.

Usage in a property module::

    from hypothesis import given
    from .strategies import PROPS, tokens, nonces

    # Feature: hook-tamper-detection, Property 1: Identity derivation is token-bound, fixed-width and leak-free
    @PROPS
    @given(tokens(), nonces())
    def test_...(token, nonce): ...
"""

from __future__ import annotations

import json
import string
from datetime import UTC, datetime

from hypothesis import HealthCheck, settings
from hypothesis import strategies as st

from interlockd.onboard import HARNESSES

# --- settings profile ---------------------------------------------------------------------------------------------

PROFILE = "interlock-props"
settings.register_profile(
    PROFILE,
    max_examples=100,
    deadline=None,                                   # file-system and subprocess-free tests; no per-example deadline
    suppress_health_check=[HealthCheck.function_scoped_fixture],   # tmp_path is reset by the test body itself
)
PROPS = settings.get_profile(PROFILE)
"""Decorator for every property test: ``@PROPS`` above ``@given(...)``."""

# --- fixed code sets (design.md) ----------------------------------------------------------------------------------

HARNESS_REASONS = frozenset({"shim_modified", "shim_missing", "shim_relocated", "hook_removed"})
HOME_REASONS = frozenset({"token_modified", "token_missing", "token_permissions", "policy_modified",
                          "managed_policy_modified", "identity_missing", "state_unreadable"})
TAMPER_CAUSES = ("token_rejected", "daemon_identity", "daemon_lost", "enforcement_point")
NON_TAMPER_CAUSES = ("operator_stopped", "restarting", "timeout", "curl_rc_7", "curl_rc_28", "http_500", "http_404")
RESTARTING = ("restart", "shadow", "enforce", "token_rotate", "init")
STOPPING = ("stop", "uninstall")
STATES = ("protected", "observing", "stopped", "compromised", "unknown")
FAIL_MODES = ("open", "closed")
GRACE_S = 120

# --- primitives ---------------------------------------------------------------------------------------------------

_HEX = "0123456789abcdef"
# characters JSON serializes without an escape sequence (Req 12.1): printable ASCII minus '"' and '\\'
_ESCAPE_FREE = "".join(c for c in string.printable if c not in '"\\' and c.isprintable())
_PATH_PART = string.ascii_letters + string.digits + "._-"
_IDENT_HEAD = string.ascii_letters + "_"
_IDENT_TAIL = string.ascii_letters + string.digits + "_"


def harnesses() -> st.SearchStrategy[str]:
    return st.sampled_from(HARNESSES)


def tokens() -> st.SearchStrategy[str]:
    """Bearer tokens: the real shape (token_urlsafe(32), 43 chars) and arbitrary non-empty text."""
    urlsafe = st.text(alphabet=string.ascii_letters + string.digits + "-_", min_size=43, max_size=43)
    arbitrary = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=64)
    return st.one_of(urlsafe, arbitrary)


def nonces() -> st.SearchStrategy[bytes]:
    """Daemon start nonces (secrets.token_bytes(16))."""
    return st.binary(min_size=16, max_size=16)


def identities() -> st.SearchStrategy[str]:
    """Daemon_Identity values: 32 lowercase hex characters."""
    return st.text(alphabet=_HEX, min_size=32, max_size=32)


def sha256_hex() -> st.SearchStrategy[str]:
    return st.text(alphabet=_HEX, min_size=64, max_size=64)


def escape_free_text(min_size: int = 0, max_size: int = 64) -> st.SearchStrategy[str]:
    return st.text(alphabet=_ESCAPE_FREE, min_size=min_size, max_size=max_size)


def identifiers() -> st.SearchStrategy[str]:
    """State-file keys: ASCII identifiers of 1-32 characters (Req 12.1)."""
    return st.builds(lambda h, t: h + t, st.sampled_from(_IDENT_HEAD),
                     st.text(alphabet=_IDENT_TAIL, min_size=0, max_size=31))


def path_components() -> st.SearchStrategy[str]:
    return st.text(alphabet=_PATH_PART, min_size=1, max_size=16).filter(lambda s: s not in (".", ".."))


def home_paths() -> st.SearchStrategy[str]:
    """Absolute Home paths: ``~/.interlock``-style and arbitrary ``$INTERLOCK_HOME`` locations."""
    default = st.builds(lambda root, user: f"/{root}/{user}/.interlock",
                        st.sampled_from(("Users", "home")), path_components())
    custom = st.builds(lambda parts: "/" + "/".join(parts), st.lists(path_components(), min_size=1, max_size=5))
    return st.one_of(default, custom)


def addresses() -> st.SearchStrategy[str]:
    """Daemon base addresses as the shims log them."""
    tcp = st.builds(lambda p: f"http://127.0.0.1:{p}", st.integers(min_value=1, max_value=65535))
    sock = st.builds(lambda h: f"unix:{h}/interlockd.sock", home_paths())
    return st.one_of(tcp, sock)


def status_codes() -> st.SearchStrategy[int]:
    return st.integers(min_value=100, max_value=599)


def posix_modes() -> st.SearchStrategy[int]:
    return st.integers(min_value=0, max_value=0o777)


def adapter_names() -> st.SearchStrategy[str | None]:
    """Self-reported adapter names of any length; None stands for an absent or unparseable body."""
    return st.one_of(st.none(), harnesses(), st.text(max_size=200))


_EPOCH_MIN = int(datetime(2020, 1, 1, tzinfo=UTC).timestamp())
_EPOCH_MAX = int(datetime(2100, 1, 1, tzinfo=UTC).timestamp())


def epochs() -> st.SearchStrategy[int]:
    return st.integers(min_value=_EPOCH_MIN, max_value=_EPOCH_MAX)


def iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_timestamps() -> st.SearchStrategy[str]:
    return epochs().map(iso)


# --- identity header lists ----------------------------------------------------------------------------------------

def header_lists(expected: str) -> st.SearchStrategy[list[str]]:
    """``X-Interlock-Identity`` values as received: 0-2 entries mixing the expected value and others.
    Exactly ``[expected]`` is the only verifying list."""
    other = st.one_of(identities(), st.text(max_size=40)).filter(lambda v: v != expected)
    value = st.one_of(st.just(expected), other)
    return st.lists(value, min_size=0, max_size=2)


# --- Stop_Marker documents ----------------------------------------------------------------------------------------

def stop_marker_docs(actions=RESTARTING + STOPPING, written: st.SearchStrategy[int] | None = None):
    """Valid Stop_Marker documents per design.md; expiry keys only for restarting actions."""
    written = written if written is not None else epochs()

    def build(action: str, at: int, pid: int, version: str) -> dict:
        doc: dict = {"action": action, "written_at": iso(at), "pid": pid, "version": version}
        if action in RESTARTING:
            doc["expires_epoch"] = at + GRACE_S
            doc["expires_at"] = iso(at + GRACE_S)
        return doc

    versions = st.builds(lambda a, b, c: f"{a}.{b}.{c}", *(st.integers(0, 20) for _ in range(3)))
    return st.builds(build, st.sampled_from(actions), written, st.integers(1, 2**22), versions)


MARKER_VARIANTS = ("absent", "no_expiry", "future_expiry", "past_expiry", "malformed")


def _malformed_marker_texts() -> st.SearchStrategy[str]:
    """Texts a shim must treat as an absent marker (Req 3.11, 12.4)."""
    garbage = st.text(max_size=80).filter(lambda s: '"action": "' not in s)
    missing_action = epochs().map(lambda t: json.dumps({"written_at": iso(t), "pid": 1}))
    missing_written = st.sampled_from(RESTARTING + STOPPING).map(lambda a: json.dumps({"action": a, "pid": 1}))
    wrong_type = st.just(json.dumps({"action": 7, "written_at": 0}))
    return st.one_of(st.just(""), garbage, missing_action, missing_written, wrong_type, st.just("[]"))


def marker_variants(now_epoch: int) -> st.SearchStrategy[tuple[str, str | None]]:
    """(variant, file text or None for absent) relative to ``now_epoch``, as the shim classifier sees them."""
    stop = stop_marker_docs(STOPPING).map(lambda d: ("no_expiry", json.dumps(d)))
    future = stop_marker_docs(RESTARTING, st.integers(now_epoch - GRACE_S + 1, now_epoch)).map(
        lambda d: ("future_expiry", json.dumps(d)))
    past = stop_marker_docs(RESTARTING, st.integers(_EPOCH_MIN, now_epoch - GRACE_S)).map(
        lambda d: ("past_expiry", json.dumps(d)))
    return st.one_of(st.just(("absent", None)), stop, future, past,
                     _malformed_marker_texts().map(lambda t: ("malformed", t)))


# --- fail-mode.json documents -------------------------------------------------------------------------------------

FAIL_MODE_VARIANTS = ("valid", "missing_tamper", "invalid_tamper", "unparseable", "absent")
_CATEGORY_KEYS = ("security.data_exfiltration", "security.malicious_command", "security.persistence",
                  "security.secret_leak.*", "security.privilege_escalation")


def fail_mode_docs() -> st.SearchStrategy[tuple[str, str | None]]:
    """(variant, ``fail-mode.json`` text or None for absent). Text uses ``indent=2`` like the CLI writer."""
    modes = st.sampled_from(FAIL_MODES)
    categories = st.dictionaries(st.sampled_from(_CATEGORY_KEYS), modes, max_size=len(_CATEGORY_KEYS))
    bad_value = st.text(max_size=12).filter(lambda v: v not in FAIL_MODES)

    def render(doc: dict) -> str:
        return json.dumps(doc, indent=2)

    valid = st.builds(lambda c, d, t: {**c, "default": d, "tamper": t}, categories, modes, modes)
    missing = st.builds(lambda c, d: {**c, "default": d}, categories, modes)
    invalid = st.builds(lambda c, d, t: {**c, "default": d, "tamper": t}, categories, modes, bad_value)
    unparseable = st.text(max_size=60).filter(lambda s: '"tamper": "' not in s and '"default": "' not in s)
    return st.one_of(
        valid.map(lambda d: ("valid", render(d))),
        missing.map(lambda d: ("missing_tamper", render(d))),
        invalid.map(lambda d: ("invalid_tamper", render(d))),
        unparseable.map(lambda t: ("unparseable", t)),
        st.just(("absent", None)),
    )


def env_fail_modes() -> st.SearchStrategy[str | None]:
    """``INTERLOCK_FAIL_MODE`` values: unset, the two modes, empty and unrecognised strings."""
    return st.one_of(st.none(), st.sampled_from(("closed", "open", "", "CLOSED", "closed ")), st.text(max_size=10))


# --- YAML mappings (policy diff) ----------------------------------------------------------------------------------

def yaml_scalars() -> st.SearchStrategy:
    return st.one_of(st.none(), st.booleans(), st.integers(-1000, 1000), st.text(alphabet=_PATH_PART, max_size=12))


def yaml_mappings(max_depth: int = 3) -> st.SearchStrategy[dict]:
    """Policy-like YAML mappings: identifier keys, scalar/list/mapping values, nesting up to ``max_depth``."""
    keys = st.text(alphabet=string.ascii_lowercase + "_", min_size=1, max_size=12)

    def extend(children: st.SearchStrategy) -> st.SearchStrategy:
        return st.one_of(st.lists(children, max_size=3), st.dictionaries(keys, children, max_size=3))

    values = st.recursive(yaml_scalars(), extend, max_leaves=max(1, 4 * max_depth))
    return st.dictionaries(keys, values, max_size=6)


# --- protection reasons -------------------------------------------------------------------------------------------

def reasons() -> st.SearchStrategy[tuple[str, str]]:
    """(subject, reason): a harness with a harness reason, or ``home`` with a Home reason."""
    harness_reason = st.tuples(harnesses(), st.sampled_from(sorted(HARNESS_REASONS)))
    home_reason = st.tuples(st.just("home"), st.sampled_from(sorted(HOME_REASONS)))
    return st.one_of(harness_reason, home_reason)


def reason_sets(max_size: int = 12) -> st.SearchStrategy[frozenset[tuple[str, str]]]:
    return st.frozensets(reasons(), max_size=max_size)


def reason_ops(max_size: int = 30) -> st.SearchStrategy[list[tuple[str, tuple[str, str]]]]:
    """Operation sequences for ProtectionState: ("add" | "clear", (subject, reason))."""
    return st.lists(st.tuples(st.sampled_from(("add", "clear")), reasons()), max_size=max_size)


def modes() -> st.SearchStrategy[str]:
    return st.sampled_from(("shadow", "enforce"))


def elapsed() -> st.SearchStrategy[float]:
    """Seconds since an Operator_Action, around the 120 s grace boundary (including negative clock skew)."""
    return st.one_of(st.floats(-5, 300, allow_nan=False), st.sampled_from((0.0, GRACE_S - 1e-6, float(GRACE_S))))

