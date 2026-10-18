# OGR seed-v0 conformance suite

A seed suite for the OGR `POST /v1/evaluate` conformance seat (`interlockd.ogr`, design §5.2). Each line
of `seed-v0.jsonl` is a case:

```json
{"id": "...", "suite": "<category>", "expect": "block|allow", "guard_event": { … }}
```

- `guard_event` is an OGR GuardEvent carrying one half of a model call (`step/response` = a proposed
  tool call → pre-action; `step/request` = an arriving tool result → post-action).
- `suite` is the OGR security category, so `interlock ogr run` reports per-category accuracy.
- `expect` is **omitted** on cases whose OGR decision is not fixed by the deterministic layer alone
  (ask-routed, model-routed, and post-action injection cases). Those still exercise protocol mapping
  and schema validity; they just don't count toward labelled accuracy.

## Coverage (40 cases)

- **Protocols:** `openai.chat`, `openai.responses`, `anthropic.messages`, `canonical` — all four.
- **Kinds:** `step/response` (pre-action) and `step/request` (post-action).
- **Categories:** malicious_command, data_exfiltration, ssrf, persistence, privilege_escalation,
  secret_leak, supply_chain, prompt_injection, memory_poisoning.
- **Labelled (26):** 14 `block` (deterministic hard-block rules — force-push to a protected branch,
  pipe-to-shell, `rm -rf /`, reverse shell, sensitive-file upload, dump-then-egress, cloud-metadata
  SSRF, authorized_keys / cron / shell-rc / agent-config persistence, sudoers) and 12 `allow` (benign
  reads, status/commit/log/diff, `make test`, `npm run build`, fetches to allowed hosts).
- **Unlabelled (14):** ask-routed (`git clean`, `git reset --hard`, `sudo`, pastebin, alternate index,
  credential-helper, transcript write), model-routed (own-branch force-push, `rm -rf build`, reading
  `~/.ssh/id_rsa`, unknown-host fetch), and three post-action tool-result cases (two injected, one
  benign).

## Why these labels are judge-independent

The labelled cases are decided by the deterministic engine alone, so an **in-process run with no judge**
(clean `Policy()`, `ask_maps_to=block`) reproduces them exactly — the labelled accuracy is a stable,
judge-independent conformance number. The unlabelled cases depend on the judge (model-routed), the
`ask_maps_to` setting (ask-routed), or the Guardrails/judge probe (post-action injection), so pinning a
label would bake in a configuration or the judge's known injection weakness.

## Run

```sh
# in-process, deterministic (reproducible; the published number)
interlock ogr run corpus/ogr-seed-v0 --out docs/reports/ogr-seed-v0-results.jsonl

# through a running daemon over HTTP
interlock ogr run corpus/ogr-seed-v0 --url http://127.0.0.1:7391 --out results.jsonl

# with a live judge attached in-process (model-routed + post-action cases become meaningful)
interlock ogr run corpus/ogr-seed-v0 --judge http://127.0.0.1:8000 --out results.jsonl

# validate any results file against the OGR verdict schema
interlock ogr validate docs/reports/ogr-seed-v0-results.jsonl
```

Every verdict is validated against `interlockd/schema/verdict.schema.json`; the run exits non-zero if
any verdict fails the schema.
