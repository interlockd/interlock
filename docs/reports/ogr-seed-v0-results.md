# Interlock — OGR seed-v0 Conformance Run

**Date:** 2026-10-17
**Suite:** `daemon/corpus/ogr-seed-v0/` — 40 GuardEvent cases (26 labelled, 14 unlabelled)
**Driver:** in-process pipeline, clean `Policy()`, no judge, `ask_maps_to=block`
**Schema:** `interlockd/schema/verdict.schema.json`
**Reproduce:** `interlock ogr run corpus/ogr-seed-v0 --out docs/reports/ogr-seed-v0-results.jsonl`
**Raw verdicts:** [`ogr-seed-v0-results.jsonl`](./ogr-seed-v0-results.jsonl)

The OGR conformance seat (`POST /v1/evaluate`, design §5.2) maps an OGR `GuardEvent` onto one or more
`InterlockEvent`s, runs each through the same `Daemon.decide()` pipeline as the native path, and
composes the per-event dispositions into one OGR `Verdict` (deny-wins). This run drives the built
suite through that seat and validates every verdict against the OGR schema.

## Result

```
suite                           n  allow  block  labelled    acc
------------------------------------------------------------------
data_exfiltration               8      3      5         6   100%
malicious_command              14      6      8        10   100%
memory_poisoning                1      0      1         0      -
persistence                     4      0      4         4   100%
privilege_escalation            2      0      2         1   100%
prompt_injection                4      4      0         1   100%
secret_leak                     3      1      2         1   100%
ssrf                            2      0      2         2   100%
supply_chain                    2      1      1         1   100%
------------------------------------------------------------------
labelled accuracy: 26/26 = 100.0%

SCHEMA: all 40 verdict(s) valid against verdict.schema.json
```

- **Labelled accuracy 26/26 (100%).** Every labelled case — 14 `block` (deterministic hard-block
  rules) and 12 `allow` (benign) — produced the expected OGR decision. Because these are decided by
  the deterministic engine alone and the run attaches no judge, this number is **reproducible and
  judge-independent**: re-running yields the same 26/26.
- **Schema conformance 40/40.** Every verdict — labelled and unlabelled — validates against
  `verdict.schema.json`, confirming the endpoint emits OGR-conformant output across all four protocols
  and both step kinds.

## Coverage

- **Protocols (all four):** `openai.chat` (12), `canonical` (10), `anthropic.messages` (10),
  `openai.responses` (8).
- **Kinds:** 37 `step/response` (pre-action), 3 `step/request` (post-action).
- **Categories:** all 9 Interlock security categories (table above).

## The 14 unlabelled cases

Cases whose OGR decision is **not** fixed by the deterministic layer alone are intentionally left
unlabelled, so the accuracy number stays judge- and configuration-independent:

- **ask-routed (7):** `git clean -fd`, `git reset --hard`, `sudo systemctl restart`, pastebin upload,
  alternate package index, credential-helper config, transcript write. Their OGR decision depends on
  `ask_maps_to` (here `block`, so they appear in the `block` column but are not scored).
- **model-routed (4):** own-branch force-push, `rm -rf build`, reading `~/.ssh/id_rsa`, unknown-host
  fetch. These need the judge's `intent_authorized` vote; without a judge the engine records them but
  the decision is not a conformance label.
- **post-action injection (3):** two injected tool-results and one benign. These need the live judge's
  `injection_present` and/or the Bedrock Guardrails probe; see the calibration report for the judge's
  characterized injection behavior.

Running with `--judge <decider-url>` makes the model-routed and post-action cases meaningful; this
published number deliberately isolates the deterministic conformance guarantee.

## Relationship to the calibration report

This run certifies the **mapping and schema** of the OGR seat — that a GuardEvent in any of the four
protocols becomes a schema-valid OGR verdict with the right deterministic decision. The judge's
behavior on the model-routed and injection cases is characterized separately in
[M3-judge-calibration.md](./M3-judge-calibration.md). Together they cover both halves of the evaluation
story: deterministic conformance here, judge calibration there.
