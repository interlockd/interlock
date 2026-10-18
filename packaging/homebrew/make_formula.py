#!/usr/bin/env python3
"""Generate the Homebrew formula for Interlock from PyPI metadata (run after a release is on PyPI).

    python3 packaging/homebrew/make_formula.py 0.1.0 > Formula/interlock.rb    # in the interlockd/homebrew-tap repo

Homebrew formulas pin every dependency's sdist and sha256, so this reads them from PyPI's JSON API for the released
version of `interlock` and the exact versions of its runtime dependencies. pydantic-core is built from source by
Homebrew, which needs Rust at build time.
"""

from __future__ import annotations

import json
import sys
import urllib.request


def pypi(name: str, version: str | None = None) -> dict:
    url = f"https://pypi.org/pypi/{name}/{version}/json" if version else f"https://pypi.org/pypi/{name}/json"
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read())


def sdist(meta: dict) -> tuple[str, str]:
    for f in meta["urls"]:
        if f["packagetype"] == "sdist":
            return f["url"], f["digests"]["sha256"]
    raise SystemExit(f"no sdist for {meta['info']['name']} {meta['info']['version']}")


def render(version: str, main: tuple[str, str], resources: list[tuple[str, str, str]]) -> str:
    res = "\n".join(f'  resource "{n}" do\n    url "{u}"\n    sha256 "{h}"\n  end\n' for n, u, h in resources)
    return f'''class Interlock < Formula
  include Language::Python::Virtualenv

  desc "Pre/post-action gate for AI coding agents"
  homepage "https://github.com/interlockd/interlock"
  url "{main[0]}"
  sha256 "{main[1]}"
  license "Apache-2.0"

  depends_on "rust" => :build
  depends_on "python@3.12"

{res}
  def install
    virtualenv_install_with_resources
  end

  service do
    run [opt_bin/"interlock", "serve"]
    keep_alive true
    log_path var/"log/interlockd.log"
    error_log_path var/"log/interlockd.log"
  end

  test do
    assert_match "PASS", shell_output("#{{bin}}/interlock test")
  end
end
'''


def _requirements(meta: dict) -> list[tuple[str, str | None]]:
    """(name, exact version or None) for each unconditional requirement."""
    import re

    out = []
    for req in meta["info"].get("requires_dist") or []:
        if ";" in req:                                   # extras and environment markers are not runtime deps
            continue
        m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(.*)$", req)
        if not m:
            continue
        exact = re.search(r"==\s*([0-9][^,\s]*)", m.group(2))
        out.append((m.group(1).lower().replace("_", "-"), exact.group(1) if exact else None))
    return out


def main(version: str, fetch=pypi) -> str:
    """Resolve runtime deps transitively; an exact pin (pydantic -> pydantic-core==X) wins over the latest release."""
    meta = fetch("interlock", version)
    pins: dict[str, str] = {}
    queue = _requirements(meta)
    while queue:
        name, exact = queue.pop(0)
        if name in pins and not exact:
            continue
        ver = exact or fetch(name)["info"]["version"]
        if pins.get(name) == ver:
            continue
        pins[name] = ver
        queue += _requirements(fetch(name, ver))
    resources = [(name, *sdist(fetch(name, pins[name]))) for name in sorted(pins)]
    return render(version, sdist(meta), resources)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: make_formula.py VERSION")
    sys.stdout.write(main(sys.argv[1]))
