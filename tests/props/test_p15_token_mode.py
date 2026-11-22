"""Property 15: Token mode check (integrity.token_check, the Hook_Watch token pass).

For any POSIX mode 0o000-0o777 applied to the token file, the check reports `token_permissions` with the observed
and restored modes iff any group or other bit is set, and afterwards the file has no group or other bits (0600);
for owner-only modes no `token_permissions` is reported and the mode is left as it was.

Owner-only modes split in two. With the owner read bit (0o400, 0o600, 0o700, ...) the digest matches the baseline,
so the check is intact. Without it (0o000, 0o200, 0o100, 0o300) the digest cannot be computed, and the code reports
`token_missing {"unreadable": True}` (documented in token_check). Requirement 8.4 only governs `token_permissions`;
Requirement 8.3 needs the digest checked, so an unreadable token is not reported as intact.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path

import pytest
from hypothesis import given

from interlockd.integrity import TOKEN_FILE, Baseline, token_check

from .strategies import PROPS, posix_modes

pytestmark = [
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes; Windows uses the ACL check (Req 8.8)"),
    pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads files regardless of mode"),
]

_TOKEN = "t" * 43


def _check_mode(mode: int) -> None:
    with tempfile.TemporaryDirectory() as d:
        home = Path(d)
        path = home / TOKEN_FILE
        path.write_text(_TOKEN + "\n")
        os.chmod(path, 0o600)
        baseline = Baseline.from_disk(home, None)
        assert baseline.token_mode == 0o600 and baseline.token_sha256

        os.chmod(path, mode)
        try:
            kind, info = token_check(home, baseline)
            after = stat.S_IMODE(os.stat(path).st_mode)
        finally:
            os.chmod(path, 0o600)       # let the temp dir clean up whatever the example left

        widened = bool(mode & 0o077)
        assert (kind == "token_permissions") == widened, (oct(mode), kind, info)
        if widened:
            assert info == {"observed_mode": mode, "restored_mode": 0o600, "restore_error": ""}, oct(mode)
            assert after == 0o600, (oct(mode), oct(after))
            return
        assert after == mode, (oct(mode), oct(after))
        if mode & stat.S_IRUSR:
            assert (kind, info) == ("", {}), oct(mode)
        else:
            assert (kind, info) == ("token_missing", {"unreadable": True}), oct(mode)


# Feature: hook-tamper-detection, Property 15: Token mode check
@PROPS
@given(posix_modes())
def test_token_mode_check(mode: int) -> None:
    """**Validates: Requirements 8.4**"""
    _check_mode(mode)


def test_token_mode_check_every_mode() -> None:
    """The mode space is 512 values: cover all of it, not only the sampled ones. **Validates: Requirements 8.4**"""
    for mode in range(0o1000):
        _check_mode(mode)
