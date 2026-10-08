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
- [GitHub Action](#github-action)
- [Agent integration](#agent-integration)
- [What it will not tell you](#what-it-will-not-tell-you)
- [Status](#status)
- [Documentation](#documentation)
- [Privacy and telemetry](#privacy-and-telemetry)
- [Design principles](#design-principles)
- [License](#license)

## MCP server

`sim-doctor mcp` serves three tools over stdio (JSON-RPC 2.0, MCP protocol 2024-11-05) so a coding agent can call sim-doctor without shelling out:

- `scan`: a card scan; needs a card and a reader. Its arguments are generated from `scan --help`.
- `rules_list`: the rule catalogue. No card.
- `rules_explain`: one rule by `id`. No card.

`baseline`, `diff` and `sarif` are deliberately not exposed: they read or write files, and an agent could overwrite one. `json` is always on. Each call runs `sim-doctor` itself as a subprocess and returns its JSON envelope unchanged as the tool text. Exit 0 and 1 are normal results (isError false): exit 1 from `scan` is findings, regressed, or a refusal that carries `data.error`, and the envelope is returned as is. 129, 130 or any other exit is a tool error (isError true) carrying the child's stderr. Arguments are validated first: an unknown property, a wrong type or a string value starting with `-` is refused without running anything.

Calls are handled serially, one at a time. Each child is killed after 300 seconds (override with `SIM_DOCTOR_MCP_TIMEOUT_SECONDS`; 0 or a non-number means the default) and the call returns an error saying it timed out. Captured stdout and stderr are each capped at 16 MiB; a truncated result is an error and says so. A scan holds the PC/SC reader only while its child runs, so the reader is released when the scan finishes or is killed. Ctrl-C ends the server.

Tested through the real process: the initialize, tools/list and tools/call handshake, `rules_list`, refusal of file-flag arguments, and Ctrl-C. `scan` itself is not exercised through the server (it needs a card). Acceptance by specific agent clients is unverified.

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

`--tar focused` probes 592 TARs for MSL 0 (`gsma/msl-zero-allowed`). Without it the scan
still checks PIN1 status (`auth/pin1-disabled`) and sensitive EFs under ALWays
(`filesystem/sensitive-ef-always`) from the FCPs and EF.ARR, read-only. `--score` adds an integer 0-100 beside `rules_run`. A 100 with `rules_run` 0 means
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

## Terminal view

`sim-doctor scan --tui` shows the findings in an interactive terminal view: the count per severity, the score
when `--score` is on, a list (severity, rule id, message; critical and high red, medium yellow, low blue, info
grey) and a detail pane for the selected finding (location, coverage reason when partial, evidence), plus the
coverage and TAR-stop notes. The status area at the top always shows the score warning, walk-stop and truncation notes, candidate warning and diff counts when the JSON has them. Keys: up/down or j/k, PgUp/PgDn, Home/End, Tab to scroll the detail pane, q, Esc or Ctrl-C to quit. SIGINT and SIGTERM also exit cleanly and restore the terminal (`sim-doctor mcp` and a launched `fix` agent keep the default disposition for both and just end).

It is a view over the data `--json` carries and never shows anything the envelope lacks. It cannot be combined
with `--json` (usage error, exit 129). When stdin or stdout is not a terminal it prints the normal report and
writes `sim-doctor: --tui needs a terminal; showing the plain report` to stderr. The rendering is unit-tested
against an in-memory backend; the interactive loop is **not** tested against a real terminal in CI.

## Install

| Way | Command |
| --- | --- |
| npx | `npx sim-doctor <args>` downloads the matching release binary once into `~/.cache/sim-doctor` and checks its SHA-256 |
| cargo | `cargo install sim-doctor` |
| Prebuilt binary | download `sim-doctor-<target>.tar.gz` (and its `.sha256`) from [Releases](https://github.com/Vaibhav91one/sim-doctor/releases): `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` |

The npm package, the crate and the binaries are all published by the tagged-release workflow.
From a checkout, `cargo build --release` builds the same binary.

Linux needs `libpcsclite` (build: `libpcsclite-dev`, run: `pcscd`). macOS uses the
built-in PCSC framework.

Raspberry Pi 4/5 (Debian 13 trixie, aarch64): `sudo apt install pcscd libccid`, then download the
`aarch64-unknown-linux-gnu` binary or run `npx sim-doctor`. The Linux binaries are built on Ubuntu 24.04,
so they need glibc 2.39 or newer (Debian 13 has 2.41; Debian 12 is too old, build from source there).

## CLI reference

| Command | What it does |
| --- | --- |
| `scan` | select the master file, walk the card, report |
| `ts48 compare [--json] [--reader NAME] [--dialect TABLE]` | walk the card (read-only, no TAR probes) and diff its file system against the public GSMA TS.48 test profile; see below |
| `install [--agent claude\|cursor\|codex\|opencode] [--print-only] [--dir DIR]` | write agent guidance into a project |
| `modules [--json]` | describe the crate's module roots and layering |
| `completions <shell>` | shell completion script for the whole flag surface |
| `rules list\|explain <id>`, `why <rule-id\|FILE>` | what a rule means and how to fix it, from the catalog or a saved `scan --json` envelope; no card needed |
| `fix <rule-id> --from FILE [--agent claude\|codex\|cursor] [--skip-approvals]` | print a prompt for one finding of a saved `scan --json` envelope; `fix` strips zero-width joiners (U+200C/U+200D), the combining grapheme joiner and variation selectors from agent-bound text, so emoji ZWJ sequences and Persian/Indic shaping marks are removed; unassigned code points and some other Cf characters (e.g. U+0600-0605, U+06DD) are NOT stripped. card text is fenced as untrusted data; with `--agent` it starts that coding agent, which keeps its own approval prompts unless `--skip-approvals`; nothing is launched when already inside an agent; `SIM_DOCTOR_HANDOFF_SKIP_APPROVALS=1` is the same as `--skip-approvals`; an agent that is not installed exits 1, and one killed by a signal exits 128+signal. The skip flags (`--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `--force`) are copied from the sibling tool android-doctor and are not verified against every CLI version |

`scan` flags (`sim-doctor scan --help` is the full contract):

| Flag | What it does |
| --- | --- |
| `--json` | one JSON envelope on stdout and nothing else; diagnostics go to stderr |
| `--reader <NAME>` | which PC/SC reader (default: the first) |
| `--dialect <TABLE>` | FCP tag table: `ts-102-221` (default, ETSI TS 102 221; real cards and swSIM) or `swicc` (same tags, own name). `iec-7816-4-table-42` is a deprecated alias for `ts-102-221` |
| `--max-depth`, `--max-children`, `--max-nodes`, `--max-directories` | walk bounds; hitting one is reported as truncation |
| `--tar <SELECTION>` | TARs to probe for MSL 0: `off` (default), `focused`, `full`, `range:A-B`, `regex:P`; capped at 4096 probes |
| `--severity <LEVEL>` | drop findings below `info\|low\|medium\|high\|critical` |
| `--score` | add `data.score`, integer 0-100 |
| `--baseline <FILE>`, `--diff` | regression gating against a saved run (in review, see the baseline PR) |

### `ts48 compare`

Walks the card exactly as `scan` does (SELECT and GET RESPONSE only; no ENVELOPE, no TAR
probes) and diffs the files it found against the file list of the GSMA Generic eUICC Test
Profile (TS.48 v7.0, SAIP 2.3). GSMA publishes that profile under Apache-2.0 at
[GSMATerminals/Generic-eUICC-Test-Profile-for-Device-Testing-Public](https://github.com/GSMATerminals/Generic-eUICC-Test-Profile-for-Device-Testing-Public);
the list compiled into the binary is `tests/corpus/ts48/ts48-v7.0-files.json`, derived from the
pinned commit named in it. The profile package itself, which carries public test keys, is never
committed; `cargo test regenerates_the_fixture -- --ignored` re-derives the list from a download.

Findings go through the usual contract, rules `ts48/file-missing` and `ts48/file-different`
(low) and `ts48/file-extra` (info), and `data.summary` carries the counts
(`expected`, `matched`, `missing`, `extra`, `different`, `unverified`). A file under a directory
the card refused to select is `unverified`, not missing. Compared: file type, EF layout, size and
record length, each only when both sides state it. An operator SIM is not a TS.48 card, so
differences are the expected result and the exit code is 0 whenever the walk finished.

**Matching the TS.48 file structure is not GCF or PTCRB conformance.** This compares a file
system with a public test profile and certifies nothing. The walk's limits apply (the default
candidate set can miss a file). Applications are found the way a UICC exposes them: the walk
reads EF.DIR (`2F00`, READ RECORD only), SELECTs each AID, and lists its files as
`3F00/ADF:<AID>/6F07`; for the comparison the 3GPP USIM (`A0000000871002`) maps to the
profile's `7FD0` and ISIM (`A0000000871004`) to `7FC0`.

## Exit codes

| | |
| --- | --- |
| `0` | the walk finished (findings do not change this; AGENTS.md section 3 says why) |
| `1` | the scan could not run: no reader, no card, or a flag not implemented yet |
| `129` | the command line could not be parsed |
| `130` | interrupted by SIGINT or SIGTERM (SIGTERM exits 130 too, not 143) |

## Agent integration

`sim-doctor install` writes `.claude/skills/sim-doctor/SKILL.md`,
`.cursor/rules/sim-doctor.mdc` and a marked block in `AGENTS.md` (replaced in place on
re-run, the rest of your file untouched), telling an agent to run `scan --json` and how
to read the envelope. `--agent codex` and `--agent opencode` both write the `AGENTS.md`
block. `--print-only` shows what would be written.

## What it will not tell you

- **A clean scan is not a clean card.** Four rules are registered: MSL 0 (only with
  `--tar`), PIN1 disabled, sensitive EFs under ALWays, and SCP03 (no CLI path). Crypto
  (COMP128, Milenage use) and eUICC rules do not exist yet.
- **A truncated walk saw part of the card.** The report says so in three places; check `data.complete`.
- **The default dialect and candidate set are assumptions.** The output names the ones used;
  a file outside the default identifier families is never probed and cannot be reported missing.
- **`--tar` is bounded.** The full TAR space is 16 777 216 values; the tool sends at most 4096.
- Verified against the swSIM software card in CI and read-only against one live operator USIM.
- **SCP03 never runs against a card.** `src/scp03.rs` is a library (key derivation,
  cryptograms, C-MAC, INITIALIZE UPDATE / EXTERNAL AUTHENTICATE builders) verified by
  known-answer vectors. The `auth/scp03-missing-mac` rule is registered, but a scan has no
  recorded SCP03 exchange to hand it, so it reports no evidence. There is no CLI path; a
  future one must refuse to run without an explicit opt-in flag. Milenage (`src/aka.rs`) is
  likewise vector-tested only. SCP02 and SCP11 are not implemented.

## Status

**Structure plus a first rule set.** `sim-doctor scan` opens a real PC/SC session, selects the
master file, walks the file system, and reports it as a table or, under `--json`, as one envelope
with a meaningful exit code. It is card-verified against the swSIM fixture in CI and, read-only
(`--tar off`), against a live operator USIM: the walk completes under the default
`ts-102-221` FCP dialect.

What it is **not** yet: a full security rule engine. Registered rules: `gsma/msl-zero-allowed`
(behind `--tar`) and `auth/scp03-missing-mac` (registered; no scan path records SCP03 yet, so
it has no evidence on a real card). Access-condition and PIN-status rules are in progress
([#40](https://github.com/Vaibhav91one/sim-doctor/issues/40)); every rule is gated by the corpus
precision/recall test (`tests/corpus.rs`). Library modules without a card path yet: SCP03
(`src/scp03.rs`), Milenage (`src/aka.rs`), RFC 6979 signing (`src/sign.rs`).
See [CONTEXT.md](CONTEXT.md) for the plan.

`sim-doctor scan --sarif FILE` also writes the findings as SARIF 2.1.0, using logical locations
because a card has no files on disk and stating partial coverage in `runs[0].properties`;
it is written only after a completed scan (a refused or interrupted scan leaves any existing file untouched);
GitHub code-scanning upload of that file is not yet verified.

## GitHub Action

A composite action (`action.yml` at the repo root) runs `sim-doctor scan`, fails the job only on findings that are
new since a committed baseline, comments once on the pull request and uploads SARIF to code scanning.

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write
steps:
  - uses: actions/checkout@v5
  - uses: Vaibhav91one/sim-doctor@<tag> # a release tag, e.g. v0.2.0
    with:
      swsim: "true"   # build the pinned software card; omit when the runner has a real reader
```

| Input | Default | Meaning |
|---|---|---|
| `swsim` | `false` | `true` builds the pinned swSIM + swicc-pcsc and starts pcscd (same pins as `card-fixture.yml`, see [docs/swsim-fixture.md](docs/swsim-fixture.md)). `false` needs a reader already on the runner. |
| `baseline` | `.sim-doctor/baseline.json` | Committed file written by `sim-doctor scan --baseline FILE`. With `require-baseline: "false"` and no file there is no gate. (This repo's `.gitignore` ignores `baseline.json`; use another path or `git add -f`.) |
| `require-baseline` | `true` | A missing baseline file (typo, directory, not committed) fails the job with an error naming the path: the baseline is part of the contract of a gating action. `false` scans and reports without gating, with a warning and a NOT GATED row in the summary. |
| `reader` | none | Passed to `--reader` (must not start with a dash). |
| `severity` | none | Passed to `--severity`. |
| `comment` | `true` | One PR comment, updated in place (found by a hidden marker); a missing permission does not fail the job. |
| `upload-sarif` | `true` | Upload `sim-doctor.sarif` (category `sim-doctor`); non-fatal, private repositories need code scanning enabled. |

Output: `summary`, the path of the markdown summary.

The card is the subject, so there is no per-capture file: the baseline is a committed file. Gate contract: a regressed
`--diff` exits 1 (the job fails, "GATE FAILED"); a refusal, exit 129/130, an unreadable envelope, or a gated run whose envelope carries no `diff` is a tool failure
(script exit 2) and shows the sanitised error text; exit 0 passes.

What is verified: the script logic (gate mapping, argv, summary, sanitising of card/tool text) locally against a fake
`sim-doctor` in `tests/action_script.rs`. The software-card build, install, scan and SARIF upload are exercised only by the
`action-selftest` workflow on a hosted runner, with no baseline (so it reports, it does not gate). A gating run against a
real baseline, and acceptance of the SARIF by code scanning, are not verified. Use a released tag (v0.2.0 or later) for `@<tag>`.

### `sim-doctor ci install`

Writes `.github/workflows/sim-doctor.yml`: on every `pull_request` it checks out with full history and runs the action
above, pinned to the version that wrote it.

```sh
sim-doctor ci install [--dir DIR] [--force] [--print-only] [--swsim true|false] [--baseline PATH]
                      [--require-baseline true|false] [--severity LEVEL] [--ref REF]
```

Defaults: `--swsim true` (a CI runner has no card otherwise), `--baseline .sim-doctor/baseline.json`,
`--require-baseline true`, no `--severity`, `--ref v<this version>`, `--dir .`. There is no `paths:` filter, because a card
has no files in the repository.

Safety: every value is validated before anything is written, because it lands inside YAML. `--baseline` allows only
`A-Za-z0-9._/-`, no leading `-` or `/`, no `..`; `--ref` must match `^[A-Za-z0-9][A-Za-z0-9._/-]*$`; an empty value is
refused, not defaulted; a bad value exits 129 with a message on stderr and writes nothing. It refuses to write through a
symlink anywhere from `--dir` down to the file (exit 1). A differing existing file is kept unless `--force` (exit 1); an
identical one is not a conflict. `--print-only` prints the workflow and writes nothing. Output is plain text
(`wrote <path>`), not an envelope.

The file is written atomically (a temp file renamed over the target); a directory at the path is always refused. After a write, two hints go to stderr: commit a baseline first with `sim-doctor scan --baseline <path>` (with the default `--require-baseline true` the first run fails without one), and the pinned ref `v<version>` exists only once that release is tagged; until then pass `--ref main` or another existing ref. `--baseline` and `--ref` also refuse `__`, and `--baseline` refuses `.` and a trailing `/`; `--ref` refuses `..`, a trailing `/` and `.lock`.

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
