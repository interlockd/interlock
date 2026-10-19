"""How often Interlock's pre-action rules stop everyday shell commands: NL2Bash (Lin et al., 2018), ~12k one-liners
collected from real usage. https://github.com/TellinaTool/nl2bash (GPL-3.0; downloaded, not redistributed)

    curl -sLO https://raw.githubusercontent.com/TellinaTool/nl2bash/master/data/bash/all.cm
    python benchmarks/nl2bash.py all.cm

NL2Bash is not labelled benign: it contains `rm -rf`, `sudo` and `chmod 777` because people run them. So this
reports what the default rules do with each command (allow, recorded for a model, ask, block) and which rules fire
most, rather than a false-positive rate.
"""

from __future__ import annotations

import sys
import tempfile
from collections import Counter
from pathlib import Path


def main(path: str) -> int:
    from interlockd.policy import Policy
    from interlockd.testkit import run_case

    cmds = [c.strip() for c in Path(path).read_text(errors="replace").splitlines() if c.strip()]
    pol = Policy(); pol.mode = "enforce"
    decisions, rules, examples = Counter(), Counter(), {}
    with tempfile.TemporaryDirectory() as td:
        for i, cmd in enumerate(cmds):
            r = run_case({"id": f"n{i}", "cmd": cmd}, Path(td), policy=pol)
            decisions[r.decision] += 1
            for rule in r.fired:
                rules[rule] += 1
                examples.setdefault(rule, cmd)
    n = len(cmds)
    print(f"{n} commands")
    for d in ("allow", "flag", "model", "ask", "block"):
        print(f"  {d:<6} {decisions[d]:>6}  {decisions[d] / n:6.1%}")
    print("\nrules that fired most (with an example):")
    for rule, k in rules.most_common(15):
        print(f"  {k:>5}  {rule:<36} {examples[rule][:70]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
