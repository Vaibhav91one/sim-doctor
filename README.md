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
binary serves an operator and an automated agent. **Its rules cover access conditions, PIN state, risky services and 5G
SUCI privacy, and not yet crypto or eUICC weaknesses: see [Status](#status) before you trust a
clean result.**

```sh
npx sim-doctor scan --json
sim-doctor scan --json --score --tar focused
sim-doctor install
```

## Contents

- [Get started](#get-started)
- [Install](#install)
- [CLI reference](#cli-reference)
- [Machine output and exit codes](#machine-output-doctor1)
- [GitHub Action](#github-action)
- [Agent integration](#agent-integration)
- [What it will not tell you](#what-it-will-not-tell-you)
- [Status](#status)
- [Documentation](#documentation)
- [Privacy and telemetry](#privacy-and-telemetry)
- [Design principles](#design-principles)
- [License](#license)

## MCP server

`sim-doctor mcp` serves six tools over stdio (JSON-RPC 2.0, MCP protocol 2024-11-05) so a coding agent can call sim-doctor without shelling out:

- `scan`: a card scan; needs a card and a reader. Its arguments are generated from `scan --help`.
- `rules_list`: the rule catalogue. No card.
- `rules_explain`: one rule by `id`. No card.
- `euicc_info`, `euicc_profiles`, `euicc_notifications`: the read-only `euicc` commands below, one optional `reader` argument each; they return the lpac envelope of `euicc <sub> --json` byte for byte. Need an eUICC and a reader. `euicc nickname` (the only eUICC write) is deliberately not an MCP tool.
- `gp_info`, `gp_ara`, `gp_status`: the read-only `gp` commands below, one optional `reader` argument each; they return the envelope of `gp <sub> --json` byte for byte. Need a card and a reader.

Every `scan` flag is an argument (`baseline`, `fail-on` and `sarif` included) except `tui`, `json` (always on), `help` and `version`; `baseline` and `sarif` take a file path, as on the command line. Each call runs `sim-doctor` itself as a subprocess and returns its doctor/1 envelope byte for byte as the tool text. Exit 0, 1 and 3 are normal results (isError false): findings at or above `--fail-on`, or a new finding against a baseline. 2 (the scan could not run: its envelope has `data.error`), 130 or any other exit is a tool error (isError true) carrying the child's stderr. Arguments are validated first: an unknown property, a wrong type or a string value starting with `-` is refused without running anything.

Calls are handled serially, one at a time. Each child is killed after 300 seconds (override with `SIM_DOCTOR_MCP_TIMEOUT_SECONDS`; 0 or a non-number means the default) and the call returns an error saying it timed out. Captured stdout and stderr are each capped at 16 MiB; a truncated result is an error and says so. A scan holds the PC/SC reader only while its child runs, so the reader is released when the scan finishes or is killed. Ctrl-C ends the server.

Tested through the real process: the initialize, tools/list and tools/call handshake, `rules_list`, refusal of arguments the server does not expose, and Ctrl-C. `scan` itself is not exercised through the server (it needs a card). Acceptance by specific agent clients is unverified.

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

With no reader attached, this is the real output, and it exits `2`:

```json
{"data":{"card_touched":false,"error":{"kind":"no-reader","message":"no PC/SC reader is attached. Start pcscd and attach a card, or see docs/swsim-fixture.md for the software SIM this project tests against"},"scanned":false},"exit_code":2,"findings":[],"schema":"doctor/1","score":{"coverage_gaps":1,"label":"critical","model":"sim/1","value":0},"tool":"sim-doctor","version":"0.3.0"}
```

With a card, `findings` and `score` are the result and `data` carries the file tree, the dialect
it was read under, `complete` / `truncated` / `limits_hit`, and the rest of the report. The
exit code is `0` or `1` by `--fail-on` (see [Machine output](#machine-output-doctor1)), **not** by whether
the walk finished: read `data.complete` (or require `score.coverage_gaps` to be 0) before trusting a clean result.

### 3. Score and probe TARs

```sh
sim-doctor scan --json --score --tar focused
```

`--tar focused` probes 592 TARs for MSL 0 (`gsma/msl-zero-allowed`). Without it the scan
still checks PIN1 status, EF access conditions and the 5G SUCI configuration from the FCPs, EF.ARR and
EF contents, read-only (`sim-doctor rules list`; each rule is documented in
[docs/rule_docs](docs/rule_docs)). The JSON always carries `score` (an integer 0-100, `data.score_detail.rules_run` beside it); `--score` adds it to the human report. A 100 with `rules_run` 0 means
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
with `--json` (usage error, exit 2). When stdin or stdout is not a terminal it prints the normal report and
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
| `ts48 compare [--json] [--reader NAME] [--dialect TABLE] [walk bounds]` | walk the card (read-only, no TAR probes) and diff its file system against the public GSMA TS.48 test profile; see below |
| `install [--agent claude\|cursor\|codex\|opencode] [--print-only] [--dir DIR]` | write agent guidance into a project |
| `modules [--json]` | describe the crate's module roots and layering |
| `completions <shell>` | shell completion script for the whole flag surface |
| `rules list\|explain <id>`, `why <rule-id\|FILE>` | what a rule means and how to fix it, from the catalog or a saved `scan --json` envelope; no card needed |
| `fix <rule-id> --from FILE [--agent claude\|codex\|cursor] [--skip-approvals]` | print a prompt for one finding of a saved `scan --json` envelope; `fix` strips zero-width joiners (U+200C/U+200D), the combining grapheme joiner and variation selectors from agent-bound text, so emoji ZWJ sequences and Persian/Indic shaping marks are removed; unassigned code points and some other Cf characters (e.g. U+0600-0605, U+06DD) are NOT stripped. card text is fenced as untrusted data; with `--agent` it starts that coding agent, which keeps its own approval prompts unless `--skip-approvals`; nothing is launched when already inside an agent; `SIM_DOCTOR_HANDOFF_SKIP_APPROVALS=1` is the same as `--skip-approvals`; an agent that is not installed exits 1, and one killed by a signal exits 128+signal. The skip flags (`--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `--force`) are copied from the sibling tool android-doctor and are not verified against every CLI version |
| `gp info\|ara\|status [--json] [--reader NAME] [--trace]` | read-only GlobalPlatform reads, see below |
| `euicc info\|profiles\|notifications [--json] [--reader NAME] [--aid HEX] [--max-segment BYTES]` | read-only eUICC queries over ES10, see below |
| `euicc nickname ICCID NAME [--yes] [...]` | set a profile nickname; a dry run unless `--yes`, see below |

`scan` flags (`sim-doctor scan --help` is the full contract):

| Flag | What it does |
| --- | --- |
| `--json` | one JSON envelope on stdout and nothing else; diagnostics go to stderr |
| `--reader <NAME>` | which PC/SC reader (default: the first) |
| `--dialect <TABLE>` | FCP tag table: `ts-102-221` (default, ETSI TS 102 221; real cards and swSIM) or `swicc` (same tags, own name). `iec-7816-4-table-42` is a deprecated alias for `ts-102-221` |
| `--max-depth`, `--max-children`, `--max-nodes`, `--max-directories` | walk bounds; hitting one is reported as truncation. `--max-nodes` (default 16384) counts files the card selected, not absent probes; walk time is bounded by `--max-directories` (64) x `--max-children` (1280). `ts48 compare` takes the same four flags |
| `--tar <SELECTION>` | TARs to probe for MSL 0: `off` (default), `focused`, `full`, `range:A-B`, `regex:P`; capped at 4096 probes |
| `--terminal-profile` | with `--tar` other than `off` only (else exit 2): send TERMINAL PROFILE `80 10 00 00 01 13` (SMS-PP data download declared, nothing else) before the TAR audit. **Changes the card's CAT session state** (no file is written); a pending proactive command is fetched and declined, never executed. Off by default |
| `--severity <LEVEL>` | drop findings below `info\|low\|medium\|high\|critical` |
| `--score` | show the score in the human report (the JSON always has `score`, integer 0-100) |
| `--fail-on <LEVEL>` | exit 1 (3 under `--baseline`) on a finding at or above `info\|low\|medium\|high\|critical`; default `critical` |
| `--baseline <FILE>` | compare with a previous `scan --json` envelope; only new findings gate (exit 3). Replaces the old `--baseline` writer and `--diff` |
| `--sarif <FILE>` | also write SARIF 2.1.0 |

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

### `euicc`

Queries to an eUICC's ISD-R (SGP.22 ES10), named after lpac's, and one write (`nickname`):

| sim-doctor | lpac | Asks the card for |
| --- | --- | --- |
| `euicc info` | `chip info` | EID (GetEID), the configured default SM-DP+ and root SM-DS addresses (ES10a GetEuiccConfiguredAddresses), EUICCInfo1 and EUICCInfo2 (GetEuiccInfo1/2): SVN, profile version, firmware, RSP capability, CI key ids, category |
| `euicc profiles` | `profile list` | GetProfilesInfo: ICCID, state, class, nickname, service provider, name, ISD-P AID |
| `euicc notifications` | `notification list` | ListNotification metadata only (sequence number, operation, address, ICCID); nothing is retrieved or removed |

Each command opens a logical channel, selects the ISD-R by AID (`A0000005591010FFFFFFFF8900000100`,
`--aid HEX` overrides), sends one STORE DATA request and closes the channel again, also when it
fails. `--max-segment BYTES` (1 to 255, default 120 as in lpac; 255 is the short-APDU Lc limit) caps the data bytes in one STORE DATA block, because some eUICCs reject full 255-byte blocks. `info`, `profiles` and `notifications` change nothing. `--json` prints the lpac envelope
(`{"type":"lpa","payload":{"code","message","data"}}`); without it you get a table with
card-supplied text sanitized. Exit codes: `0` answered; `1` the card is not an eUICC (the ISD-R
SELECT was refused: `data.error.kind` is `not-an-euicc`), the card refused a logical channel or an
ES10 request, the response was malformed, or no reader or card; `129` bad command line; `130`
interrupted. The swSIM fixture is not an eUICC, so these are tested against synthetic responses
through the replay transport and still need a live-card check (tracked on #92). The online side
(download, discovery, notification handling) needs the HTTPS transport (#20) and is not here.

`euicc nickname ICCID NAME` (lpac `profile nickname`, ES10c SetNickname) is the only command here that
changes the card, and it is cautious by default. The ICCID (18 to 20 digits) and the name (at most 64
bytes of UTF-8, no control characters; `""` clears it) are checked before a reader is opened.
Without `--yes` it is a **dry run**: it reads the EID and the profile list, prints the target EID
and ICCID and the current and the new nickname, and exits 0 without sending SetNickname. With `--yes`
it sends SetNickname, re-reads the profile list and exits 1 (`verify-failed`) unless the nickname
changed. An ICCID the eUICC does not hold is `iccid-not-found`, and nothing is written. The nickname
write is **not exposed over MCP**: the MCP server offers the three read-only `euicc_*` tools only.

### `gp`

Read-only GlobalPlatform: SELECT, GET DATA and GET STATUS only, no keys, no authentication, no writes.
`gp info` reads the ISD, CPLC, card data, key information and counters. `gp ara` selects the ARA-M
(`A00000015141434C00`) and reads every access rule (GET DATA `FF40`), decoding applet AID, device
app hash, APDU filters, NFC rule and permissions; a rule that lets every device app send any APDU to
every applet is marked `grants_all_apps_all_access`. `gp status` lists the ISD, applications and load
files (GET STATUS) with lifecycle and privilege names, and decodes Card Recognition Data, listing any
SCP01/SCP02 offered as `weak_scp`. A card that wants a secure channel (`6982`/`6985`) is reported as
`requires_authentication`, exit 0. Exit 1 when the ISD (or ARA-M) does not answer SELECT. Human
output is sanitized; `--json` is the lpac envelope of kind `gp`. Tested against synthetic replay
responses only; not yet checked on a live card with an ARA-M. Not done: authenticated GET STATUS, and
a `scan` rule for the all-access ARA-M rule (scan does not select the ARA-M).

### `trace`

Decodes a captured APDU trace offline: no card, no reader. Input is hex lines (command, then
response, alternating; `#` comments), sim-doctor's own `gp info --json --trace` output, or a pcap/pcapng capture of GSMTAP SIM APDUs
(UDP port 4729 over Ethernet, loopback, raw IP or Linux cooked capture, IPv4; the format is detected
from the file's magic number), from a file or stdin. A capture is read like pySim-trace does: only the
GSMTAP SIM sub-type `APDU` (one packet holds the whole `CLA INS P1 P2 P3 DATA SW` exchange) is used;
ATR, PPS and the TPDU sub-types are skipped. Each exchange is named (ISO 7816-4, TS 102 221, TS 31.102 and GlobalPlatform
commands), the status word is explained, and the selected file is tracked. Nothing is masked or
redacted: PIN, PUT KEY, EXTERNAL AUTHENTICATE and challenge/cryptogram values are shown in full, in
the text and in `--json`, so treat a decoded trace like the capture itself. `--json` adds
`data.exchanges[]`.

    printf 'A0A40000023F00\n9F16\n' | sim-doctor trace

## Machine output (doctor/1)

`scan --json` prints the shared **doctor/1** envelope, the same one luasec, pcap-doctor,
android-doctor and ble-doctor print, so one parser reads all five. The contract is
[docs/doctor-contract.md](docs/doctor-contract.md); the sim-doctor specifics are in AGENTS.md section 3.

```json
{"schema":"doctor/1","tool":"sim-doctor","version":"0.3.0","exit_code":1,
 "score":{"value":61,"label":"needs work","model":"sim/1","coverage_gaps":0},
 "findings":[{"id":"...","fingerprint":"<16 hex>","severity":"critical","category":"gsma",
              "message":"...","location":{"kind":"card-path","ref":"3F00/2F00/6F07"},
              "evidence":[{"ref":"octets","value":"a4000a"}],"remedy":"..."}],
 "data":{}}
```

`findings` is the failed checks only (critical first); everything else the report carries (the
walk, `complete`/`truncated`, the TAR audit, EF contents, `findings_detail`, `score_detail`) is
under `data`.

**Score, model `sim/1`.** `max(0, 100 - sum(penalty[severity] for every finding in this report))`
with a penalty of info 1, low 3, medium 10, high 25, critical 50 (`--severity` removes findings
before the score is taken). Label: `good` from 90, `needs work` from 60, else `critical`;
`incomplete` replaces `good` while `coverage_gaps > 0`. `coverage_gaps` counts each walk bound that
fired, an unfinished TAR scan, no rule having run, and each rule that ran with nothing to look at
(MSL 0 without `--tar`), so a default scan reads `incomplete` rather than `good`.

**Exit codes.**

| | |
| --- | --- |
| `0` | ran; no finding at or above `--fail-on` |
| `1` | ran; at least one finding at or above `--fail-on` (default `critical`) |
| `2` | usage error, bad input (including a bad `--baseline`), or the scan could not run: no reader, no card |
| `3` | `--baseline` given; at least one new finding at or above `--fail-on` (instead of 1) |
| `130` | interrupted by SIGINT or SIGTERM (SIGTERM exits 130 too, not 143) |

`--fail-on` defaults to `critical` because before doctor/1 a scan with findings exited 0; this is the
closest default that keeps a scan with only lower findings (swSIM can produce none above high)
passing. The other commands (`rules`, `why`, `fix`, `gp`, `ts48`, `fuzz`, `modules`, ...) keep their lpac-style envelope
`{type, payload:{code, message, data}}` and the codes 0 / 1 (could not run) / 129 (bad usage) / 130.

**Baseline.** Save one (see below), compare with
`sim-doctor scan --baseline baseline.json`: findings match by `fingerprint`, each gets
`baseline_state` (`new` or `unchanged`), the envelope gets `baseline: {new, unchanged, fixed}`, and
exit 3 means a new finding at or above `--fail-on`. A baseline from a truncated walk, a different
`--severity`, `--dialect` or `--tar`, or one where a rule had no evidence is refused (exit 2),
as before. A baseline needs only `schema`, `data.run` and each finding's `id`, `fingerprint` and `severity`, so the loader reads nothing else and a reduced file works as well as a full one. **A full envelope carries the ATR and EF contents**: the Action writes the reduced form, and for a manual baseline use `sim-doctor scan --json | jq -f scripts/reduce-baseline.jq > baseline.json`. Do not commit a full envelope.

**SARIF.** Each result carries `partialFingerprints["doctorFinding/v1"]` (the finding's JSON
`fingerprint`) and the run carries `properties.score`. Locations stay logical (the card path).

**Terminal output** passes every card-derived string through one sanitiser that strips control
characters (so ESC), bidi controls, zero-width characters and line/paragraph separators.

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
- **A card that answers every ENVELOPE `6F 00` (or `6D 00`, `6E 00`, `69 85`, `6A 81`) was not audited.** `data.tar.blind_spot` says so, no baseline is claimed and no sweep is sent. Many UICCs ignore CAT traffic until a TERMINAL PROFILE arrives; `--terminal-profile` sends one and is the only thing here that changes CAT state.
- **`--tar` is bounded.** The full TAR space is 16 777 216 values; the tool sends at most 4096.
- Verified against the swSIM software card in CI and against one live operator USIM (read-only, plus a consented `--tar focused` run).
- **SCP03 never runs against a card.** `src/scp03.rs` is a library (key derivation,
  cryptograms, C-MAC, INITIALIZE UPDATE / EXTERNAL AUTHENTICATE builders) verified by
  known-answer vectors. The `auth/scp03-missing-mac` rule is registered, but a scan has no
  recorded SCP03 exchange to hand it, so it reports no evidence. There is no CLI path; a
  future one must refuse to run without an explicit opt-in flag. Milenage (`src/aka.rs`) is
  likewise vector-tested only. SCP02 and SCP11 are not implemented.

## Status

**Structure plus a first rule set, verified on a live card.** `sim-doctor scan` opens a real PC/SC
session, walks the master file and the USIM/ISIM applications (selected by AID from EF.DIR), and
reports a table or one `--json` envelope with a meaningful exit code. It is card-verified against
the swSIM fixture in CI and against a live operator USIM. On that card the default walk completes in
about 2 minutes with nothing truncated.

**Full visibility.** As an authorized on-card security tool, sim-doctor shows card values in full
(IMSI, ICCID, file and key-file contents) with no runtime masking. It never commits real card data to
a repo; test fixtures are synthetic.

Rules that evaluate today: `auth/pin1-disabled`, `filesystem/sensitive-ef-always` (now including the
5GS key and context files), `filesystem/config-ef-updatable-always` (EF.UST, EST, AD, ACC, SPN,
OPLMNwAcT, SUCI_Calc_Info, Routing_Indicator with UPDATE ALWays), `filesystem/ef-updatable-always`
(any other EF with UPDATE ALWays, one finding per scan), `identity/readable-without-pin` (MSISDN,
ADN, FDN), `exposure/risky-service-available` (EF.UST services 28, SMS-PP data download, and 32,
RUN AT COMMAND; low), `privacy/suci-null-scheme` (high: the card's EF.SUCI_Calc_Info leaves the IMSI
in the clear on 5G), `privacy/suci-not-provisioned` (medium: 5GS services without service 124) and
`gsma/msl-zero-allowed` (behind `--tar`). Ten ordinary violations score below 30 (the formula is
unchanged, `sim/1`); `low` advisories alone do not. `scan` also decodes the
security-relevant EFs and reads key files where the card allows: ICCID, IMSI, MSISDN, EF.DIR, AD, SPN,
UST/EST, FPLMN, OPLMNwAcT, HPLMNwAcT, ACC, LOCI, PSLOCI, EPSLOCI, ADN, FDN, the ISIM IMPI/IMPU/P-CSCF,
and EF.MANUAREA (`3F00/0002`, shown as hex: not a 3GPP/ETSI file, so it is probed directly and
simply absent on most cards). Every rule is gated by the corpus precision/recall test
(`tests/corpus.rs`). `auth/scp03-missing-mac` is registered, but no scan path records SCP03, so it
has no evidence on a real card. Not validated on a real card yet: the new
rules are gated on generated cards and cross-checked against swSIM in CI, which does not reproduce a
real card's access conditions ([#40](https://github.com/Vaibhav91one/sim-doctor/issues/40)). Not
possible from a read-only scan: COMP128 v1/v2 and Milenage configuration (the algorithm and the
key material are not in any readable EF; telling them apart needs AUTHENTICATE, issue #105), and
anything that needs PIN, ADM or SCP keys. eUICC/SGP.22 rules need the eUICC read path, which is
separate work. The MSL 0 check runs on a real
card, but a card that answers every ENVELOPE with `6F00` gives an inconclusive result
([#98](https://github.com/Vaibhav91one/sim-doctor/issues/98)). The eUICC stack (SCP03t, BPP, ES10x,
ES9+) is library code with no card or network path yet.
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
  - uses: Vaibhav91one/sim-doctor@<tag> # a release tag, e.g. v0.3.0
    with:
      swsim: "true"   # build the pinned software card; omit when the runner has a real reader
```

| Input | Default | Meaning |
|---|---|---|
| `swsim` | `false` | `true` builds the pinned swSIM + swicc-pcsc and starts pcscd (same pins as `card-fixture.yml`, see [docs/swsim-fixture.md](docs/swsim-fixture.md)). `false` needs a reader already on the runner. |
| `baseline` | `.sim-doctor/baseline.json` | Committed baseline: a doctor/1 envelope, ideally the reduced one (the Action writes the reduced form to its `baseline` output; see Machine output). With `require-baseline: "false"` and no file there is no gate. (This repo's `.gitignore` ignores `baseline.json`; use another path or `git add -f`.) |
| `require-baseline` | `true` | A missing baseline file (typo, directory, not committed) fails the job with an error naming the path: the baseline is part of the contract of a gating action. `false` scans and reports without gating, with a warning and a NOT GATED row in the summary. |
| `reader` | none | Passed to `--reader` (must not start with a dash). |
| `severity` | none | Passed to `--severity`. |
| `fail-on` | none | Passed to `--fail-on` (default `critical`). Under a baseline only new findings at or above it fail the job. |
| `comment` | `true` | One PR comment, updated in place (found by a hidden marker); a missing permission does not fail the job. |
| `upload-sarif` | `true` | Upload `sim-doctor.sarif` (category `sim-doctor`); non-fatal, private repositories need code scanning enabled. |

Outputs: `summary`, the path of the markdown summary; `baseline`, the path of this run's **reduced** baseline (rule ids, fingerprints, severities and the run record, no card data; needs `jq`, present on GitHub-hosted runners), ready to commit.

The card is the subject, so there is no per-capture file: the baseline is a committed file. Gate contract: CLI exit 3 (a new finding
against the baseline) fails the job ("GATE FAILED"); a CLI exit 2 or 130, an error envelope, an unreadable envelope, an `exit_code` that disagrees with the status, or a gated run whose envelope carries no `baseline` block is a tool failure
(script exit 2) and shows the sanitised error text; exit 0 passes. Without a baseline file the run only reports (a CLI exit 1 shows as NOT GATED).

What is verified: the script logic (gate mapping, argv, summary, sanitising of card/tool text) locally against a fake
`sim-doctor` in `tests/action_script.rs`. The software-card build, install, scan and SARIF upload are exercised only by the
`action-selftest` workflow on a hosted runner, with no baseline (so it reports, it does not gate). A gating run against a
real baseline, and acceptance of the SARIF by code scanning, are not verified. Use a released tag (v0.3.0 or later) for `@<tag>`.

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

The file is written atomically (a temp file renamed over the target); a directory at the path is always refused. After a write, two hints go to stderr: commit a baseline first with `sim-doctor scan --json | jq -f scripts/reduce-baseline.jq > <path>` (with the default `--require-baseline true` the first run fails without one), and the pinned ref `v<version>` exists only once that release is tagged; until then pass `--ref main` or another existing ref. `--baseline` and `--ref` also refuse `__`, and `--baseline` refuses `.` and a trailing `/`; `--ref` refuses `..`, a trailing `/` and `.lock`.

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
