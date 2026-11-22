"""Property 1: Identity derivation is token-bound, fixed-width and leak-free.

For any two distinct tokens and any nonce the derived identities differ; every identity is exactly 32 lowercase hex
characters; and neither the token nor any path component of the Home appears in the identity or in the reply headers
the daemon sends.

**Validates: Requirements 1.3, 1.4, 1.12**
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import string
import sys
import threading
from pathlib import Path

from conftest import PRE_READ
from hypothesis import example, given
from hypothesis import strategies as st

from interlockd import __version__, identity
from interlockd.api import ApiServer

from .strategies import PROPS, home_paths, nonces, tokens

_IDENTITY_RE = re.compile(r"^[0-9a-f]{32}$")
_URLSAFE = string.ascii_letters + string.digits + "-_"
# A secret or path component shorter than this can coincide with fixed reply text without leaking anything ("T", a
# macOS temp-dir component, is inside "Content-Type"; a 4-hex-digit string is inside most identities). From 8
# characters on, a chance match against a 32-hex identity has odds below 1e-8 per check.
_MIN_LEAK_LEN = 8
# Header names the daemon sends: fixed for every Home and token, so they are compared as a set rather than searched
# (a token such as "Interloc" is inside "X-Interlock-Identity" without leaking anything).
_HEADER_NAMES = {"server", "date", identity.HEADER.lower(), "content-type", "content-length", "connection"}
# Header-value text that is the same for every Home and token. A needle inside it (a Home component such as
# `interlock`, the test fixture's Home directory, inside `interlockd/<version>`) cannot be told apart from it.
_FIXED_REPLY_TEXT = (f"interlockd/{__version__} Python/{sys.version.split()[0]} "
                     "application/json text/plain; charset=utf-8 close")
# An 82-byte token whose sha256 digest happens to be valid UTF-8 (found by a one-off search), and that digest as text.
# Under a raw-token HMAC key the two tokens are the same key, because HMAC hashes keys longer than 64 bytes.
_LONG_TOKEN = "interlock-long-token-" + "x" * 50 + "-11-6029603"
_LONG_TOKEN_DIGEST_TEXT = hashlib.sha256(_LONG_TOKEN.encode("utf-8")).digest().decode("utf-8")


def _near_miss(token: str) -> st.SearchStrategy[str]:
    """Tokens that differ from `token` only slightly: a suffix, a dropped last character, a case change."""
    suffix = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=4).map(
        lambda s: token + s)
    variants = [suffix]
    if len(token) > 1:
        variants.append(st.just(token[:-1]))
    if token.swapcase() != token:
        variants.append(st.just(token.swapcase()))
    return st.one_of(*variants)


def _token_pairs() -> st.SearchStrategy[tuple[str, str]]:
    independent = st.tuples(tokens(), tokens())
    related = tokens().flatmap(lambda t: st.tuples(st.just(t), _near_miss(t)))
    return st.one_of(independent, related).filter(lambda p: p[0] != p[1])


def _long_components(path: str | Path) -> list[str]:
    return [p for p in Path(path).parts if p != "/" and len(p) >= _MIN_LEAK_LEN]


# Feature: hook-tamper-detection, Property 1: Identity derivation is token-bound, fixed-width and leak-free
@PROPS
@given(_token_pairs(), nonces(), nonces())
# Regression pins for the raw-token HMAC key that `derive` used to have. HMAC zero-pads a key shorter than the
# 64-byte block (so "abc" and "abc\x00" were one key) and replaces a longer key with its sha256 (so a long token and
# the text of its digest were one key). `derive` now keys HMAC with sha256(token), a fixed 32-byte key, so neither
# pair collides. Random generation rarely produces these pairs; pin both so every run checks them.
@example(("abc", "abc\x00"), bytes(16), bytes(16))
@example((_LONG_TOKEN, _LONG_TOKEN_DIGEST_TEXT), bytes(16), bytes(16))
def test_identity_is_token_bound(pair, nonce, other_nonce):
    t1, t2 = pair
    # Same nonce, different token: a Home's identity never verifies for another Home's token (Req 1.3).
    assert identity.derive(t1, nonce) != identity.derive(t2, nonce)
    # Token replaced and daemon restarted (fresh nonce): the new identity does not verify for the old one (Req 1.12).
    old, new = identity.derive(t1, nonce), identity.derive(t2, other_nonce)
    assert not identity.verify([new], old)
    assert identity.verify([new], identity.derive(t2, other_nonce))


# Feature: hook-tamper-detection, Property 1: Identity derivation is token-bound, fixed-width and leak-free
@PROPS
@given(tokens(), nonces(), home_paths())
def test_identity_is_fixed_width_and_leak_free(token, nonce, home):
    value = identity.derive(token, nonce)
    assert _IDENTITY_RE.match(value)
    assert len(value) == 32                              # 128 bits
    if len(token) >= _MIN_LEAK_LEN:
        assert token not in value
    for part in _long_components(home):
        assert part not in value


def _exchange(srv: ApiServer, method: str, path: str, *, token: str | None, body: dict | None = None):
    """One request against a server that is not running serve_forever: handle exactly one request on a thread, so no
    shutdown poll interval is paid per example. Returns (status, header names lower-cased, header values joined,
    identity header values)."""
    worker = threading.Thread(target=srv.httpd.handle_request, daemon=True)
    worker.start()
    host, port = srv.address
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        headers = {"Connection": "close", "Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode() if body is not None else None
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        resp.read()
        pairs = resp.getheaders()
        names = {k.lower() for k, _ in pairs}
        values = "\r\n".join(v for _, v in pairs)
        return resp.status, names, values, resp.headers.get_all(identity.HEADER) or []
    finally:
        conn.close()
        worker.join(timeout=5)


# Feature: hook-tamper-detection, Property 1: Identity derivation is token-bound, fixed-width and leak-free
@PROPS
@given(st.text(alphabet=_URLSAFE, min_size=_MIN_LEAK_LEN, max_size=64), nonces(), home_paths())
# Regression pin: "Interloc" is inside the header name X-Interlock-Identity, which once read as a leak.
@example("Interloc", bytes(16), Path("/Users/dev/.interlock"))
def test_reply_headers_leak_neither_token_nor_home(daemon, token, nonce, home):
    value = identity.derive(token, nonce)
    srv = ApiServer(daemon, token, "127.0.0.1", 0, identity=value)
    hook = {"adapter": {"name": "kiro", "version": "t"}, "payload": PRE_READ}
    try:
        replies = [
            _exchange(srv, "GET", "/interlock/v1/health", token=None),
            _exchange(srv, "POST", "/interlock/v1/hooks/kiro", token=token, body=hook),
            _exchange(srv, "POST", "/interlock/v1/hooks/kiro", token=token + "x", body=hook),
            _exchange(srv, "GET", "/interlock/v1/no-such-route", token=token),
        ]
    finally:
        srv.httpd.server_close()
    assert [r[0] for r in replies] == [200, 200, 401, 404]
    # the served Home (tmp dir) and an arbitrary generated Home path
    components = [*_long_components(daemon.settings.home), *_long_components(home)]
    needles = [n for n in (token, *components) if n not in _FIXED_REPLY_TEXT]
    for _status, names, values, ident in replies:
        assert ident == [value]
        assert names <= _HEADER_NAMES                    # no header name carries anything Home- or token-specific
        for needle in needles:
            assert needle not in values
