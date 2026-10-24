"""Every text read/write names its encoding: Windows defaults to cp1252, which garbles or crashes on non-ASCII."""

from __future__ import annotations

import ast
from pathlib import Path

PKG = Path(__file__).resolve().parents[1] / "interlockd"


def _text_mode_open(node: ast.Call) -> bool:
    mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"), None)
    return not (isinstance(mode, ast.Constant) and "b" in str(mode.value))


def test_text_io_names_its_encoding():
    missing = []
    for f in PKG.rglob("*.py"):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call) or any(k.arg == "encoding" for k in node.keywords):
                continue
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else ""
            text_file = name in ("read_text", "write_text") and isinstance(fn, ast.Attribute) and not (name == "read_text" and node.args)
            text_open = name == "open" and _text_mode_open(node) and getattr(getattr(fn, "value", None), "id", "") not in ("os", "webbrowser")
            if text_file or text_open:
                missing.append(f"{f.relative_to(PKG)}:{node.lineno}")
    assert not missing, "text I/O without encoding=: " + ", ".join(missing)
