<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img src="docs/assets/logo-light.svg" alt="sim-doctor" width="360">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/Vaibhav91one/sim-doctor/actions/workflows/ci.yml"><img src="https://github.com/Vaibhav91one/sim-doctor/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.npmjs.com/package/sim-doctor"><img src="https://img.shields.io/npm/v/sim-doctor?style=flat&color=000000&labelColor=000000&label=npm" alt="npm"></a>
  <a href="https://crates.io/crates/sim-doctor"><img src="https://img.shields.io/crates/v/sim-doctor?style=flat&color=000000&labelColor=000000&label=crates.io" alt="crates.io"></a>
  <img src="https://img.shields.io/badge/Rust-1.82%2B-000000?style=flat&color=000000&labelColor=000000" alt="Rust 1.82+">
  <img src="https://img.shields.io/badge/license-MIT-000000?style=flat&color=000000&labelColor=000000" alt="license MIT">
  <img src="https://img.shields.io/badge/telemetry-none-000000?style=flat&color=000000&labelColor=000000" alt="telemetry none">
</p>

CLI-first SIM/UICC/eUICC security testing tool.

`sim-doctor` examines a card over PC/SC and reports what it found through both a
terminal table and one stable JSON envelope with a meaningful exit code, so the same
binary serves an operator and an automated agent. **It is structure-only today: see
[Status](#status) before you trust a clean result.**

```sh
npx sim-doctor scan --json
sim-doctor scan --json --score --tar focused
sim-doctor install
```

## Contents

- [Get started](#get-started)
- [Install](#install)
- [CLI reference](#cli-reference)
- [Exit codes](#exit-codes)
- [Agent integration](#agent-integration)
- [What it will not tell you](#what-it-will-not-tell-you)
- [Status](#status)
- [Documentation](#documentation)
- [Privacy and telemetry](#privacy-and-telemetry)
- [Design principles](#design-principles)
- [License](#license)

## Get started

### 1. Install

```sh
cargo install sim-doctor
```

More ways in [Install](#install). You also need a PC/SC reader and a card, or the
software card in [docs/swsim-fixture.md](docs/swsim-fixture.md).

### 2. First scan

```sh
sim-doctor scan --json
```

With no reader attached, this is the real output, and it exits `1`:

```json
{"type":"scan","payload":{"code":1,"message":"no PC/SC reader is attached. Start pcscd and attach a card, or see docs/swsim-fixture.md for the software SIM this project tests against","data":{"card_touched":false,"error":{"kind":"no-reader","message":"no PC/SC reader is attached. Start pcscd and attach a card, or see docs/swsim-fixture.md for the software SIM this project tests against"},"scanned":false}}}
```

With a card, `payload.code` is `0` once the walk finishes and `payload.data` carries the
file tree, the dialect it was read under, `complete` / `truncated` / `limits_hit`, and
`findings`. **Gate on `payload.data.complete`, not on `payload.code`.**

### 3. Score and probe TARs

```sh
sim-doctor scan --json --score --tar focused
```

`--tar focused` probes 592 TARs for MSL 0 (`gsma/msl-zero-allowed`, the one rule that
runs). `--score` adds an integer 0-100 beside `rules_run`. A 100 with `rules_run` 0 means
nothing was checked, and the report says so in words.

### 4. Hand it to an agent

```sh
sim-doctor install
```

```
wrote ./.claude/skills/sim-doctor/SKILL.md
wrote ./.cursor/rules/sim-doctor.mdc
wrote ./AGENTS.md
```

## Install

| Way | Command |
| --- | --- |
| npx | `npx sim-doctor <args>` downloads the matching release binary once into `~/.cache/sim-doctor` and checks its SHA-256 |
| cargo | `cargo install sim-doctor` |
| Prebuilt binary | download `sim-doctor-<target>.tar.gz` (and its `.sha256`) from [Releases](https://github.com/Vaibhav91one/sim-doctor/releases): `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu` |

The npm package, the crate and the binaries are all published by the tagged-release workflow.
From a checkout, `cargo build --release` builds the same binary.

Linux needs `libpcsclite` (build: `libpcsclite-dev`, run: `pcscd`). macOS uses the
built-in PCSC framework.

## CLI reference

| Command | What it does |
| --- | --- |
| `scan` | select the master file, walk the card, report |
| `install [--agent claude\|cursor\|codex\|opencode] [--print-only] [--dir DIR]` | write agent guidance into a project |
| `modules [--json]` | describe the crate's module roots and layering |
| `completions <shell>` | shell completion script for the whole flag surface |
| `rules list\|explain <id>`, `why <rule-id\|FILE>` | what a rule means and how to fix it, from the catalog or a saved `scan --json` envelope; no card needed |

`scan` flags (`sim-doctor scan --help` is the full contract):

| Flag | What it does |
| --- | --- |
| `--json` | one JSON envelope on stdout and nothing else; diagnostics go to stderr |
| `--reader <NAME>` | which PC/SC reader (default: the first) |
| `--dialect <TABLE>` | FCP tag table: `swicc` (default) or `iec-7816-4-table-42` |
| `--max-depth`, `--max-children`, `--max-nodes`, `--max-directories` | walk bounds; hitting one is reported as truncation |
| `--tar <SELECTION>` | TARs to probe for MSL 0: `off` (default), `focused`, `full`, `range:A-B`, `regex:P`; capped at 4096 probes |
| `--severity <LEVEL>` | drop findings below `info\|low\|medium\|high\|critical` |
| `--score` | add `data.score`, integer 0-100 |
| `--baseline <FILE>`, `--diff` | regression gating against a saved run (in review, see the baseline PR) |

## Exit codes

| | |
| --- | --- |
| `0` | the walk finished (findings do not change this; AGENTS.md section 3 says why) |
| `1` | the scan could not run: no reader, no card, or a flag not implemented yet |
| `129` | the command line could not be parsed |
| `130` | interrupted |

## Agent integration

`sim-doctor install` writes `.claude/skills/sim-doctor/SKILL.md`,
`.cursor/rules/sim-doctor.mdc` and a marked block in `AGENTS.md` (replaced in place on
re-run, the rest of your file untouched), telling an agent to run `scan --json` and how
to read the envelope. `--agent codex` and `--agent opencode` both write the `AGENTS.md`
block. `--print-only` shows what would be written.

## What it will not tell you

- **A clean scan is not a clean card.** One rule runs (`gsma/msl-zero-allowed`), and only
  with `--tar`. Most of the rule space does not exist yet.
- **A truncated walk saw part of the card.** The report says so in three places; check `data.complete`.
- **The default dialect and candidate set are assumptions.** The output names the ones used;
  a file outside the default identifier families is never probed and cannot be reported missing.
- **`--tar` is bounded.** The full TAR space is 16 777 216 values; the tool sends at most 4096.
- Verified only against the swSIM software card, not yet against a real card.

## Status

**M1, structure-only.** `sim-doctor scan` opens a real PC/SC session, selects the master
file, walks the file system, and reports it as a table or, under `--json`, as one
envelope with a meaningful exit code. It is card-verified against the swSIM fixture in CI.

What it is **not** yet: a security rule engine. The rule model exists (findings,
locations, bounded evidence, a registry that refuses a duplicate ID) and a single rule,
`gsma/msl-zero-allowed`, runs behind `--tar`. Everything else is deferred:
real SIM/UICC/eUICC rules that make `--score` meaningful ([#40](https://github.com/Vaibhav91one/sim-doctor/issues/40)),
an MCP server ([#41](https://github.com/Vaibhav91one/sim-doctor/issues/41)),
a CI action ([#43](https://github.com/Vaibhav91one/sim-doctor/issues/43)),
`fix` ([#44](https://github.com/Vaibhav91one/sim-doctor/issues/44)),
`ci install` ([#45](https://github.com/Vaibhav91one/sim-doctor/issues/45)),
`why` / `rules explain` ([#46](https://github.com/Vaibhav91one/sim-doctor/issues/46)) and
a corpus/precision gate ([#47](https://github.com/Vaibhav91one/sim-doctor/issues/47)).
See [CONTEXT.md](CONTEXT.md) for the plan.

`sim-doctor scan --sarif FILE` also writes the findings as SARIF 2.1.0, using logical locations
because a card has no files on disk and stating partial coverage in `runs[0].properties`;
it is written only after a completed scan (a refused or interrupted scan leaves any existing file untouched);
GitHub code-scanning upload of that file is not yet verified.

## Documentation

| File | Purpose |
|---|---|
| [AGENTS.md](AGENTS.md) | Canonical agent instructions: architecture, contracts, domain facts, gotchas |
| [CLAUDE.md](CLAUDE.md) | Pointer to AGENTS.md |
| [CONTEXT.md](CONTEXT.md) | Project decisions, open questions, milestone plan |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |
| [docs/research-report.md](docs/research-report.md) | Full source-verified research findings |
| [docs/swsim-fixture.md](docs/swsim-fixture.md) | Software-card fixture: how to run swSIM behind pcscd locally |

## Privacy and telemetry

`sim-doctor` sends nothing anywhere. It talks to the PC/SC reader you point it at. The
only network access is the npm launcher's one-time release download. Never commit card
secrets (keys, KI/OPc, ADM codes).

## Design principles

1. **Agent-first, not agent-optional.** Every command has a headless mode with a stable
   JSON contract and a meaningful exit code. The TUI is a view, not the product.
2. **Verified facts only.** Claims carry a [V] verified or [U] unverified tag so nobody
   builds on a guess. See AGENTS.md.
3. **Testable without hardware.** The primary dev loop runs against a software SIM behind
   a software PC/SC reader. `cargo test` needs no reader at all; the card-backed tests are
   behind the `card-fixture` feature and run in a separate CI job. See
   [docs/swsim-fixture.md](docs/swsim-fixture.md).

## License

[MIT](LICENSE)
