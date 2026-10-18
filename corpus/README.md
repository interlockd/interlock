# Interlock corpus v1

The evaluation corpus, separate from `daemon/interlockd/data/packs/` (which is the **unit** corpus that gates per-rule
behavior in CI). This corpus is for **measurement** — FPR/FNR and, later, judge calibration — built from three
sources, all in the case schema `interlockd.testkit` consumes.

```
corpus/
├── _corpus.yaml        trust context these cases are authored against (see interlock test §3.1)
├── shadow/             real pre_action events, redacted + deduped, labelled by a human
├── archetypes/         hand-authored cases (Phase 2): the attacks we must catch, by name
└── imported/           re-shaped AgentDojo / InjecAgent / AgentDrift cases
```

## Building it

```sh
# 1. Export real traffic from the local spool + the DynamoDB audit table, redacted and deduped
interlock corpus export --source both --out corpus/shadow/export.jsonl

# 2. Label it (sets expect / label / category interactively)
interlock corpus label corpus/shadow/export.jsonl

# 3. Re-shape external datasets
interlock corpus import --from agentdojo  path/to/agentdojo.json   --out corpus/imported/agentdojo.jsonl
interlock corpus import --from injecagent path/to/injecagent.jsonl --out corpus/imported/injecagent.jsonl
interlock corpus import --from agentdrift path/to/agentdrift.jsonl --out corpus/imported/agentdrift.jsonl

# 4. Stamp a stable dev/heldout split on any file (export/import already do this; use for hand-authored)
interlock corpus assign-split corpus/archetypes/*.jsonl

# 5. Run the whole corpus (or one split) through the deterministic layer
interlock test --corpus corpus/shadow --corpus corpus/archetypes --corpus corpus/imported
interlock test --corpus corpus/archetypes --split heldout
```

## Schema additions in v1

Beyond the base case fields (see `docs/USER-GUIDE.md` §3.1), v1 adds:

| Field | Meaning |
|---|---|
| `transcript` | `[{role, text}]` user-intent turns a judge case needs (role in `user`/`assistant`); never read by the deterministic layer |
| `judge` | `{question_id: expected_noul}` expected judge answers, e.g. `{"intent_authorized": 0.1}` |
| `split` | `dev` \| `heldout` — stable 70/30 by `sha256(id)`; stamped into the file so it never drifts |
| `_meta` | provenance for shadow/imported cases (source, source_event_id, captured_disposition, redacted kinds) |

Every **benign** case should carry a `category` — the attack category it is a hard negative *for* — so
per-category FPR is meaningful (an uncategorized benign case lands in `(uncategorized)` and contributes to
no category's FPR). The importers and labeller set this; the hand-authored archetypes set it explicitly.

## Redaction

`corpus export` never writes a live secret. Every command, argument, manifest, and transcript turn is run
through the deterministic engine's own `SECRET_PATTERNS` (the same matcher the secrets pack uses on real
traffic), and each hit is replaced with `<REDACTED:kind>`. The kinds found are recorded under `_meta.redacted`.
