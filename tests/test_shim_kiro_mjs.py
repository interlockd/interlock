"""Subprocess tests for the Kiro Node shim (interlockd/shims/kiro/interlock-hook.mjs) against a stub daemon.

Runs the shared Kiro case matrix in tests/kiro_shim_matrix.py with node; skipped where node is not installed.
"""

from __future__ import annotations

import pytest
from kiro_shim_matrix import KiroShimMatrix
from shim_stub import node_works

pytestmark = pytest.mark.skipif(not node_works(), reason="node not available")


class TestKiroMjsShim(KiroShimMatrix):
    RUNTIME = "kiro-mjs"

    def test_no_dependencies_beyond_node_builtins(self):
        imports = [ln for ln in self.template.read_text(encoding="utf-8").splitlines() if ln.startswith("import ")]
        assert imports and all('from "node:' in ln for ln in imports)
