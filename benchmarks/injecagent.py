"""Interlock's post-action injection check on InjecAgent (Zhan et al., 2024; MIT): https://github.com/uiuc-kang-lab/InjecAgent

    curl -sLO https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/test_cases_dh_base.json   # and _ds_, _enhanced
    python benchmarks/injecagent.py test_cases_*.json
    python benchmarks/injecagent.py --judge http://127.0.0.1:8017 test_cases_*.json    # also ask the judge model

Each case is a realistic tool response with an attacker instruction placed in it (positives). Negatives are the same
response templates with the instruction slot filled by ordinary text. Every response goes through the real decision
pipeline as a post-action event (default policy, local detector only, no model), the way a hook would send it.
Reports detection rate per file and attack type, and the false-positive rate on the negatives.
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

BENIGN = "Arrived quickly and works as described; I would buy it again."


def main(argv: list[str]) -> int:
    from interlockd.config import Settings
    from interlockd.models import (
        AdapterInfo,
        Capabilities,
        Context,
        InterlockEvent,
        ToolCall,
        ToolResult,
        UserMessage,
    )
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool

    home = Path(tempfile.mkdtemp(prefix="ilbench"))
    s = Settings(home=home)
    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = [str(home)]
    d = Daemon(s, spool=Spool(s.spool_dir, fsync=False), repo=MemoryRepository(), policy=pol)
    judge = None
    if argv[:1] == ["--judge"]:
        from interlockd.judges.strands_decider import StrandsDeciderBackend

        judge, argv = argv[1], argv[2:]
        d.backend = StrandsDeciderBackend(base_url=judge)
        pol.judge.primary.timeout_ms = 30_000
    paths = argv

    def caught(tool: str, text: str, i: int, ask: str = "") -> bool:
        ctx = Context(cwd=str(home), user_messages=[UserMessage(n=1, text=ask)] if ask else None)
        ev = InterlockEvent(kind="post_action", adapter=AdapterInfo(name="bench"), session_hint=f"b{i}",
                            tool_call=ToolCall(name=tool, arguments={}), context=ctx,
                            result=ToolResult(content=text), capabilities=Capabilities(withhold=True))
        return d.decide(ev).disposition in ("withhold", "warn", "block")

    rows, by_type, templates, n = [], Counter(), {}, 0
    for path in paths:
        cases = json.loads(Path(path).read_text())
        hit = 0
        for c in cases:
            n += 1
            ok = caught(c["User Tool"], c["Tool Response"], n, c["User Instruction"])
            hit += ok
            by_type[(c["Attack Type"], ok)] += 1
            templates.setdefault(c["Tool Response Template"], (c["User Tool"], c["User Instruction"]))
        rows.append((Path(path).name, len(cases), hit))
    fp = sum(caught(tool, t.replace("<Attacker Instruction>", BENIGN), 10**6 + i, ask)
             for i, (t, (tool, ask)) in enumerate(templates.items()))
    print(f"detectors: local heuristics{' + judge at ' + judge if judge else ''}\n")

    print(f"{'file':<32} {'cases':>6} {'detected':>9} {'rate':>7}")
    for name, total, hit in rows:
        print(f"{name:<32} {total:>6} {hit:>9} {hit / total:>7.1%}")
    tot, hits = sum(r[1] for r in rows), sum(r[2] for r in rows)
    print(f"{'all':<32} {tot:>6} {hits:>9} {hits / tot:>7.1%}")
    print("\nby attack type:")
    for t in sorted({k[0] for k in by_type}):
        h, m = by_type[(t, True)], by_type[(t, False)]
        print(f"  {t:<28} {h:>5}/{h + m:<5} {h / (h + m):.1%}")
    print(f"\nfalse positives on {len(templates)} benign responses: {fp} ({fp / max(1, len(templates)):.1%})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
