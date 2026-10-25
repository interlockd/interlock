# Working on Interlock (for AI coding agents and their humans)

Interlock is a pre- and post-action gate for AI agents: a local daemon, a deterministic rule engine, hook adapters
for each agent, an MCP gateway, and Python/JS SDKs. Read `CONTRIBUTING.md` first; `docs/USER-GUIDE.md` is the full
reference and `docs/ADAPTERS.md` covers agent adapters.

## Setup and checks (run all before you commit)

```sh
uv venv --python 3.12 && uv pip install -e ".[dev]" --python .venv/bin/python
.venv/bin/ruff check .
.venv/bin/pytest -q
.venv/bin/interlock test                              # rule corpus gates
.venv/bin/interlock test --corpus corpus/archetypes   # evaluation corpus
scripts/check-hygiene.sh                              # no real home paths, account ids or keys
```

## Rules

- **Sign off every commit** (`git commit -s`); work on a branch and open a PR to `main`. If several agents or sessions
  work on this repo at once, give each its own `git worktree`; never switch branches in a checkout someone else uses.
- **Never touch the real environment while testing:** use a throwaway `HOME` and `INTERLOCK_HOME`, and a port other
  than 7391. Don't edit your own agent configs (`~/.claude`, `~/.codex`, ...) or the running daemon.
- **A rule change needs positive and hard-negative cases** in `interlockd/data/packs/<pack>.jsonl`.
- **Adapters are verified live, never assumed:** record real payloads with `interlock capture`, export them redacted,
  and replay them as fixtures. Don't write "verified" anywhere without a live run; say what is untested.
- **Cross-platform:** paths go through `interlockd/paths.py` (forward slashes, case-insensitive on macOS and Windows);
  text files are read and written with `encoding="utf-8"` (a test enforces it).
- **Commit nothing that identifies a real machine, account or person:** redact home paths, user names, emails, tokens
  and account ids in fixtures and docs. Security fixes go through a private advisory (`SECURITY.md`), not a public PR.
