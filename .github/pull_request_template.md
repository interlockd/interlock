## What and why

## How it was verified

- [ ] Every commit is signed off (`git commit -s`, see CONTRIBUTING.md)
- [ ] Tests (`pytest -q`, `interlock test`)
- [ ] Live against the real agent (which one, which version)

## For a rule change

- [ ] Positive **and** hard-negative cases in `interlockd/data/packs/<pack>.jsonl`
