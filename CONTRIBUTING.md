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

CI runs all four on every pull request, on Linux, macOS and Windows, plus `scripts/check-hygiene.sh` (no real home
paths, account ids or keys in committed files; run it before you push).

## What to contribute

- **A rule.** Register it in `interlockd/det/packs.py`, implement the check, and add positive *and* negative cases to `interlockd/data/packs/<pack>.jsonl`. A rule without hard negatives will not be merged: false positives are what make people uninstall a security tool.
- **An adapter for a new agent.** Read [docs/ADAPTERS.md](docs/ADAPTERS.md) first. A normalizer (`interlockd/normalize/`), a shim (`interlockd/shims/`), detection in `interlockd/onboard.py`, and **payloads captured from the real tool** (`interlock capture`, see docs/ADAPTERS.md §4) as fixtures in `tests/fixtures/<agent>/`, plus a `adapters/<agent>/PAYLOADS.md` describing what you measured. Documented-but-unmeasured contracts have been wrong before.
- **Corpus cases.** Real attack shapes and real benign commands that a rule gets wrong.

## Pull requests

Fork, branch, and open a pull request against `main`. A maintainer reviews it; when CI is green and the review is
done, it is merged here.

- **Sign off every commit** (`git commit -s`). This adds `Signed-off-by: Your Name <you@example.com>` and certifies the
  [Developer Certificate of Origin](https://developercertificate.org/): that you wrote the change or otherwise have the
  right to submit it under this project's license. CI checks it; to fix a branch, `git rebase --signoff main` and
  force-push. There is no separate contributor agreement.
- Contributions are licensed under Apache-2.0, the same license as the project (inbound = outbound). The project
  stays Apache-2.0.
- Keep changes focused; include tests.
- Describe what you verified and how (live against the tool, or tests only).
- **Security issues**: don't open a pull request or issue; report privately (see [SECURITY.md](SECURITY.md)). Fixes
  are prepared in a private security advisory and released before details are public.

By taking part you agree to the [code of conduct](CODE_OF_CONDUCT.md).
