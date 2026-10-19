# Contributing to Interlock

Thanks for helping make AI agents safer.

## Development setup

```sh
uv venv --python 3.12 && uv pip install -e ".[dev]" --python .venv/bin/python
.venv/bin/ruff check .
.venv/bin/pytest -q
.venv/bin/interlock test                              # rule corpus: per-rule and per-category FPR/FNR gates
.venv/bin/interlock test --corpus corpus/archetypes   # evaluation corpus
```

CI runs all four on every pull request.

## What to contribute

- **A rule.** Register it in `interlockd/det/packs.py`, implement the check, and add positive *and* negative cases to `interlockd/data/packs/<pack>.jsonl`. A rule without hard negatives will not be merged: false positives are what make people uninstall a security tool.
- **An adapter for a new agent.** Read [docs/ADAPTERS.md](docs/ADAPTERS.md) first. A normalizer (`interlockd/normalize/`), a shim (`interlockd/shims/`), detection in `interlockd/onboard.py`, and **payloads captured from the real tool** (`interlock capture`, see docs/ADAPTERS.md §4) as fixtures in `tests/fixtures/<agent>/`, plus a `adapters/<agent>/PAYLOADS.md` describing what you measured. Documented-but-unmeasured contracts have been wrong before.
- **Corpus cases.** Real attack shapes and real benign commands that a rule gets wrong.

## Pull requests

Open pull requests against `main` here as usual. This repository is published from the maintainers' development
repository, so a merged change reaches `main` through the next published commit, with you credited as author (and
`Co-authored-by` on the published commit); your PR is closed with a link to it rather than merged with the button.

- Keep changes focused; include tests.
- Describe what you verified and how (live against the tool, or tests only).
- By contributing you agree your contribution is licensed under Apache-2.0.

By taking part you agree to the [code of conduct](CODE_OF_CONDUCT.md).
