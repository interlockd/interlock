"""The Homebrew formula generator, against offline PyPI metadata (the oss/ overlay ships it as packaging/homebrew)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

GEN = next((p for p in (Path(__file__).resolve().parents[2] / "oss" / "packaging" / "homebrew" / "make_formula.py",
                        Path(__file__).resolve().parents[1] / "packaging" / "homebrew" / "make_formula.py") if p.exists()), None)
pytestmark = pytest.mark.skipif(GEN is None, reason="formula generator not in this layout")


def _meta(name, version, requires=()):
    return {"info": {"name": name, "version": version, "requires_dist": list(requires)},
            "urls": [{"packagetype": "bdist_wheel", "url": "x.whl", "digests": {"sha256": "w"}},
                     {"packagetype": "sdist", "url": f"https://files/{name}-{version}.tar.gz", "digests": {"sha256": f"sha-{name}-{version}"}}]}


DB = {
    ("interlockd", "0.1.0"): _meta("interlockd", "0.1.0", ["pydantic<3,>=2.9", "pyyaml<7,>=6.0", 'boto3<2,>=1.35; extra == "aws"']),
    ("pydantic", None): _meta("pydantic", "2.13.5"),
    ("pydantic", "2.13.5"): _meta("pydantic", "2.13.5", ["annotated-types>=0.6.0", "pydantic-core==2.46.5", "typing-extensions>=4.14.1"]),
    ("pydantic-core", "2.46.5"): _meta("pydantic-core", "2.46.5", ["typing-extensions>=4.14.1"]),
    ("pydantic-core", None): _meta("pydantic-core", "9.9.9"),                       # latest is NOT what pydantic pins
    ("pyyaml", None): _meta("pyyaml", "6.0.3"), ("pyyaml", "6.0.3"): _meta("pyyaml", "6.0.3"),
    ("annotated-types", None): _meta("annotated-types", "0.8.0"), ("annotated-types", "0.8.0"): _meta("annotated-types", "0.8.0"),
    ("typing-extensions", None): _meta("typing-extensions", "4.16.0"), ("typing-extensions", "4.16.0"): _meta("typing-extensions", "4.16.0"),
}


def test_formula():
    spec = importlib.util.spec_from_file_location("make_formula", GEN)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    rb = mod.main("0.1.0", fetch=lambda n, v=None: DB[(n, v)])
    assert 'url "https://files/interlockd-0.1.0.tar.gz"' in rb and 'sha256 "sha-interlockd-0.1.0"' in rb
    assert 'resource "pydantic-core" do' in rb and "pydantic-core-2.46.5" in rb and "9.9.9" not in rb   # exact pin wins
    assert "boto3" not in rb                                                                   # extras are not runtime deps
    assert 'depends_on "rust" => :build' in rb and "virtualenv_install_with_resources" in rb and "service do" in rb
