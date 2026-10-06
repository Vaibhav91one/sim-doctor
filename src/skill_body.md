# sim-doctor

`sim-doctor` examines a SIM/UICC card over PC/SC and reports what it found. It is a
CLI-first tool: every command has a headless mode with a stable JSON envelope and a
meaningful exit code. Run it; do not guess what a card holds.

## Run a scan

```sh
sim-doctor scan --json              # one JSON envelope on stdout, nothing else
sim-doctor scan --json --score      # adds data.score (integer 0-100)
sim-doctor scan --json --severity high   # drop findings below a level
sim-doctor scan --json --tar focused     # probe TARs for MSL 0 (gsma/msl-zero-allowed)
sim-doctor scan --help              # the full contract, including what it cannot do
```

stdout carries the envelope and nothing else; diagnostics go to stderr.

## Read the envelope

```json
{ "type": "scan", "payload": { "code": 0, "message": "...", "data": { } } }
```

- `payload.code` is **0 whenever the walk finished**, including a truncated walk and a
  walk that produced findings. It is not a verdict on the card.
- **Gate on `payload.data.complete`, not on `payload.code`.** `complete: false` means a
  bound was hit (`truncated_by`, `limits_hit`) and you read only part of the card.
- `payload.data.findings.findings[]` holds the findings. Each has `rule`
  (`namespace/name`), `severity`, `message`, `location`, bounded `evidence`, and a
  `coverage` of `complete` or `partial`. A `partial` finding came from a scan that did not
  finish: the list may be short.
- `payload.data.score` (with `--score`) is `100 - sum of penalties`, floored at 0. Read
  `rules_run` beside it: **a score of 100 with `rules_run` 0 means nothing was checked,
  not that the card is clean.**
- On failure `payload.data.error.kind` names why (`no-reader`, ...) and `scanned` is false.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the walk finished (findings do not change this) |
| 1 | the scan could not run: no reader, no card, or a flag not implemented yet |
| 129 | bad command line |
| 130 | interrupted |

## What it does not tell you

- Only one rule runs today, `gsma/msl-zero-allowed`, behind `--tar`. A clean scan is not a
  clean bill of health for the card.
- The default FCP dialect and candidate set are assumptions the output names; they can miss
  a file. `--dialect` and `--max-children` say how.
- Never commit card secrets (keys, KI/OPc, ADM codes) found while testing.

Docs: AGENTS.md (contract, domain facts), docs/swsim-fixture.md (software card for testing
without hardware).
