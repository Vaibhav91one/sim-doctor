# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `sim-doctor trace` reads pcap and pcapng captures of GSMTAP SIM APDUs (UDP 4729, as produced by SIMtrace2 and pySim-trace), detected by magic number. A small hand-written reader (classic pcap, pcapng EPB/SPB, Ethernet/loopback/raw/cooked, IPv4, UDP) instead of a pcap crate; the APDU sub-type is split into command and response as pySim does and fed to the existing decoder. Truncated or malformed files give an error, never a panic; TPDU sub-types are skipped (#109).
- `sim-doctor gp ara`: selects the ARA-M (AID `A00000015141434C00`) and reads every access rule with GET DATA [all] (`80 CA FF 40`), decoding each REF-AR-DO: applet AID (or all / default selected), device app hash (or any), APDU rule (always / never / header+mask filters), NFC rule and permission mask. A rule naming all applets and any device app with APDU access always sets `grants_all_apps_all_access`. A card that wants a secure channel (`6982`/`6985`) is reported as `requires_authentication`, not an error. No scan rule yet: `scan` does not select the ARA-M (#111).
- `sim-doctor gp status`: GET STATUS (`80 F2`, TLV format) for the ISD, applications, executable load files and load files with modules, with lifecycle and privilege names, following `63 10` up to 16 pages per scope; a scope that needs authentication says so. Also decodes Card Recognition Data (GET DATA tag 66) and lists any SCP01/SCP02 it offers as `weak_scp`. Authenticated GET STATUS and lifecycle/privilege findings remain open (#112).
- MCP: `gp_info`, `gp_ara` and `gp_status` tools (nine tools in total).
- Security rules for issue #40 and #110, all decided from data a read-only scan collects:
  `filesystem/config-ef-updatable-always` (high/medium: EF.UST, EST, AD, ACC, SPN, OPLMNwAcT, SUCI_Calc_Info or Routing_Indicator with UPDATE ALWays), `filesystem/ef-updatable-always` (medium, one finding per scan: any other EF with UPDATE ALWays), `privacy/suci-null-scheme` (high: EF.SUCI_Calc_Info puts the null scheme first or has no scheme with a provisioned home network public key, so the IMSI is sent in the clear on 5G) and `privacy/suci-not-provisioned` (medium: EF.UST marks 5GS service 122 or 123 but not 124). `filesystem/sensitive-ef-always` now also covers EF.5GS3GPPLOCI, 5GSN3GPPLOCI, 5GS3GPPNSC, 5GSN3GPPNSC and 5GAUTHKEYS under DF.5GS, and `identity/readable-without-pin` also covers EF.ADN and EF.FDN.
- `scan` decodes EF.SUCI_Calc_Info (`4F07`) and EF.Routing_Indicator (`4F0A`) under DF.5GS `5FC0` into `ef_contents`; the transparent-EF read cap rose from 64 to 255 octets so a key list fits.
- `rules explain` (text and `--json`) now carries each rule's `cwe` and specification `reference`. `docs/rule_docs/<namespace>/<name>.json` holds `{id, severity, description, remediation, cwe, reference}` for every rule; it is generated from the rule declarations and `tests/rule_docs.rs` fails when a file is missing, stale or orphaned (`UPDATE_RULE_DOCS=1 cargo test --test rule_docs` regenerates).
- A test pins the `--score` acceptance: ten medium-or-worse violations score under 30 with the unchanged `sim/1` formula, and the whole pipeline scores a badly misconfigured generated card under 30. Not done, and why: COMP128 v1/v2 detection and a Milenage configuration check need AUTHENTICATE probing or key material, neither of which a read-only scan has (#105).

- `sim-doctor euicc info|profiles|notifications`: read-only ES10 queries to the ISD-R on a logical channel (lpac `chip info`, `profile list`, `notification list`): EID, EUICCInfo1/2, profile list, notification metadata. lpac envelope under `--json`, sanitized table otherwise; a non-eUICC card is a clean `not-an-euicc` error, exit 1. Never changes a profile or notification. New ES10 codecs `get_eid_request`/`decode_get_eid` and `list_notification_request`/`decode_list_notification` (#116, #132).
- MCP: `euicc_info`, `euicc_profiles` and `euicc_notifications` tools (six tools in total).
- `scan` decodes more EFs, read-only (SELECT, READ BINARY, READ RECORD) and shown in full in `ef_contents`: EF.FPLMN, EF.OPLMNwAcT, EF.HPLMNwAcT, EF.ACC, EF.LOCI, EF.PSLOCI, EF.EPSLOCI, EF.ADN (`6F3A`, and `4F3A` in a phonebook), EF.FDN, and the ISIM EF.IMPI, EF.IMPU and EF.P-CSCF (told apart from the USIM's EF.KeysPS by the ISIM AID) (#108).
- EF.MANUAREA (`3F00/0002`, a vendor-specific file with no standard identifier, as SIMTester reads it) is probed with one SELECT and READ BINARY and shown as hex when the card has it; a card without it is not an error (#102).
- Rule `exposure/risky-service-available` (low): EF.UST marks service 28 (SMS-PP data download) or 32 (RUN AT COMMAND) available, one finding per service (#108). EF.EST is decoded but not judged.

## [0.3.0] - 2026-10-09

### Changed (BREAKING)

`sim-doctor scan` adopts the cross-tool **doctor/1** output contract (docs/doctor-contract.md), shared with luasec, pcap-doctor, android-doctor and ble-doctor so one parser reads all five (Refs Vaibhav91one/android-doctor#161). No legacy flag; the old scan JSON is gone.

- `scan --json` prints `{schema:"doctor/1", tool, version, exit_code, score, findings, data}` instead of the lpac envelope `{type, payload:{code,message,data}}`. Findings are top-level with `id`, `fingerprint`, `severity`, `category`, `message`, `location:{kind,ref}`, `evidence[]`, `remedy`. `data.findings` became top-level `findings` (old shape kept as `data.findings_detail.findings`); `data.score` became top-level `score` `{value, label, model:"sim/1", coverage_gaps}` (old block: `data.score_detail`, now always present). The rest of `data` is unchanged. A scan that cannot run is also a doctor/1 envelope (exit 2, `findings: []`, `data.error`).
- Exit codes for `scan`: `0` no finding at or above `--fail-on`, `1` at least one, `2` usage error or the scan could not run (was 129 and 1), `3` a new finding against `--baseline`, `130` interrupted. A scan with findings used to exit 0.
- New `--fail-on <level>`, default `critical` (the closest value to the old "findings never fail the scan").
- `--baseline <FILE>` now READS a previous `scan --json` envelope and gates on new findings (exit 3), matching by fingerprint. It no longer writes a file: save a baseline with `sim-doctor scan --json | jq -f scripts/reduce-baseline.jq > baseline.json`. `--diff` is removed. A baseline loader reads only `schema`, `data.run` and each finding's `id`, `fingerprint` and `severity`, so it holds no card data; a full envelope and the reduced one the Action writes (output `baseline`, `scripts/reduce-baseline.jq`) load identically. Do not commit a full `scan --json` envelope: it carries the ATR and EF contents.
- SARIF: the fingerprint key is `doctorFinding/v1` (was `simDoctorFinding/v1`) and the run carries `properties.score`.
- MCP: the `scan` tool now exposes `baseline`, `fail-on` and `sarif`; exit 3 is a normal result.
- GitHub Action: reads the doctor/1 envelope, fails on CLI exit 3, new input `fail-on`; the baseline file is a saved envelope.
- Card-derived text in the scan table, the TUI, `why` and the `fix` prompt goes through one sanitiser that strips control characters (ESC), bidi controls, zero-width characters and line/paragraph separators.
- `why` and `fix` read doctor/1 envelopes saved from `scan --json`.

### Fixed

- A baseline taken with `--severity` is read back with that threshold (it was written under `severity_threshold` and read under `severity`).
- `scan` works on real cards: a GET RESPONSE rejected at the GSM class (`6E 00`/`6D 00`) re-sends a read-only command once and collects at the command's own class; swSIM is unaffected (#64).
- The FCP tag table for real cards was wrong. The new default `--dialect ts-102-221` (ETSI TS 102 221: 80 size, 82 descriptor, 83 FID, 84 DF name) replaces it; `iec-7816-4-table-42` is a deprecated alias. A baseline taken under another dialect is refused by `--diff` (#69).
- An empty reader is reported as `no card in reader` (error kind `no-card`) instead of an unusable reader (#64).
- Tests no longer open an attached reader (#72).
- `scan` walks the USIM/ISIM applications by AID from EF.DIR (path form `3F00/ADF:<AID>/…`). Before this, real cards only showed the legacy DF.GSM/DF.TELECOM paths (#83).
- A real card no longer truncates the walk. `--max-nodes` now counts only files the card selected, as its help already said; absent probes still cost an exchange and are bounded by `--max-directories` × `--max-children`. Inside an application, the reserved identifiers 7FF0–7FFF are not walked again (#90).
- A card command stuck in a PC/SC exchange can be interrupted: after SIGINT/SIGTERM a watchdog ends the run about 3 s later with exit 130 and releases the reader (#88).
- The TAR probe and the fuzz OTA sweep send ENVELOPE as one APDU, so `--tar` works through real readers. Before, the header/data split was rejected by PC/SC and nothing was probed. The split is kept for the swicc-pcsc software reader only (#96).
- The no-TAR-evidence score warning no longer claims a value of 100 (#84).
- A tied or unusable TAR calibration is reported as a blind spot with no MSL-0 verdict, instead of classing every TAR as accepted and raising a false critical finding (#101).

### Added

- SCP03 core (key derivation, cryptograms, C-MAC, INITIALIZE UPDATE / EXTERNAL AUTHENTICATE builders), Milenage wrapper and the `auth/scp03-missing-mac` rule; vector-tested, never sent to a card. `rules_run` is now 2, so older baselines are refused by `--diff` (#22).
- RFC 6979 deterministic ECDSA P-256/SHA-256 signing, 64-byte r||s (#21).
- A generated-card corpus with a per-rule precision/recall gate (#47).
- Rules `auth/pin1-disabled`, `filesystem/sensitive-ef-always` and `identity/readable-without-pin`, decoded from compact/expanded/EF.ARR-referenced access rules (#40, partial).
- `sim-doctor gp info [--trace]`: read-only GlobalPlatform pass — ISD select, GET DATA for CPLC / card data / key information / sequence+confirmation counters / extended card resources, Card Recognition Data decode, AES+3DES key check values. Sends only SELECT, GET RESPONSE and GET DATA. Plus offline builders (CAP→load file, INSTALL/LOAD, MANAGE CHANNEL) for later use (#19, partial).
- `sim-doctor ts48 compare`: diffs a card's file system against the public GSMA TS.48 v7.0 test profile, using a derived file list with no keys. It takes the same walk-limit flags as `scan`. Matching TS.48 is not GCF/PTCRB conformance (#25).
- `sim-doctor fuzz apdu|ota`: CLA/INS discovery and a TAR × keyset × SPI sweep, bounded. It refuses to run without `--i-understand-this-can-brick-the-card`, and on any reader other than the swicc-pcsc software card it also needs `--allow-real-hardware` (#16).
- `sim-doctor scan` decodes the security-relevant EFs (ICCID, IMSI, MSISDN, EF.DIR, EF.AD, EF.SPN, service tables UST/EST) into `ef_contents`, and reads key files (EF.Keys/KeysPS) where the card allows; read-only (SELECT/READ only) (#108, #102).
- `sim-doctor trace`: an offline APDU-trace decoder (hex or `gp info --json --trace` input) that names ISO/UICC/GlobalPlatform commands and tracks the selected file; pcap input deferred (#109).
- A record/replay transport for hardware-free regression tests: `SIM_DOCTOR_RECORD` captures a session (0600, raw), and a recorded log replays through the walk in CI (#120).
- An SGP.26 test-PKI check: a committed manifest (URL + pinned SHA-256) and an ignored test that fetches the GSMA certs at run time and validates signing against the chain; no certs are committed (#73).
- Library modules, vector-tested and sending nothing on their own: SCP03t (#23), the SGP.22 Bound Profile Package builder (#17), ES10x STORE DATA and ES10b/ES10c codecs (#18), and the ES9+ message layer behind a transport trait (#20, partial; no HTTPS backend yet).
- Prebuilt `aarch64-unknown-linux-gnu` binary (Raspberry Pi, glibc 2.39 or later); CI uploads it as an artifact on every run (#91).

### Changed

- SGP.22 and TS.48 are public; the recorded GSMA member-access blockers were wrong and are resolved; TS.48 work is re-scoped to comparing a card with the public test profile (#26, #25).
- Full-visibility output: as an authorized on-card security tool, sim-doctor shows card values in full (IMSI, ICCID, MSISDN, file and key-file contents) with no runtime redaction. Real card data is still never committed to the repo; test fixtures are synthetic (#128).

## [0.2.0] - 2026-10-07

### Fixed

- `fix` hardening: the prompt sanitiser strips a wider invisible-character table (soft hyphen, variation selectors, tag characters, private use, fillers; unassigned code points outside the table are not covered), at most 20 findings are collected from a saved scan, the agent is spawned directly (not-installed is detected from the spawn error), and a signal-killed agent exits 128+signal; it strips zero-width joiners (U+200C/U+200D), the combining grapheme joiner and variation selectors from agent-bound text, so emoji ZWJ sequences and Persian/Indic shaping marks are removed; unassigned code points and some other Cf characters (e.g. U+0600-0605, U+06DD) are NOT stripped. `SIM_DOCTOR_HANDOFF_SKIP_APPROVALS=1` is documented and tested (#55).
- SIGTERM now sets the same interrupt flag as SIGINT, so a killed `scan --tui` restores the terminal and a killed scan exits 130; `sim-doctor mcp` ends on SIGTERM (#59).

### Added

- `sim-doctor ci install [--dir DIR] [--force] [--print-only]` writes `.github/workflows/sim-doctor.yml` running the action on pull requests, pinned to this version's tag; values are validated before writing, symlinks are never written through, and a differing file is kept without `--force`; the generated workflow has not been run on a hosted runner (#45).
- A composite GitHub Action (`action.yml`, `scripts/sim-doctor-action.sh`) gating CI on new findings against a committed baseline, with a PR comment and SARIF upload; script logic is tested locally, the hosted run is exercised only by the `action-selftest` workflow (#43).
- `sim-doctor scan --tui` shows the findings in a ratatui view (severity colours, a detail pane, the coverage and TAR-stop notes); it shows only what `--json` carries, conflicts with `--json` (exit 129), and falls back to the plain report with a stderr line when stdin or stdout is not a terminal; not tested against a real terminal in CI (#15).
- `sim-doctor mcp` serves `scan`, `rules_list` and `rules_explain` as MCP tools over stdio by running itself as a subprocess; `baseline`, `diff` and `sarif` are not exposed; agent-client acceptance beyond the handshake is unverified (#41).
- `sim-doctor fix <rule-id> --from FILE [--agent claude|codex|cursor] [--skip-approvals]` prints a prompt for one finding of a saved scan (card text fenced as untrusted) and can start a coding agent with its approvals kept; nothing is launched inside an agent (#44).
- `sim-doctor scan --sarif FILE` writes the findings as SARIF 2.1.0 (logical locations, partial coverage in run properties), written only after a completed scan; GitHub code-scanning acceptance is unverified (#42).
- `sim-doctor rules list [--json]`, `rules explain <id>` and `why <rule-id|FILE>` explain what a rule means and how to fix it without a card; the rule registry now refuses a rule with no summary or remediation (#46).
- `sim-doctor install [--agent claude|cursor|codex|opencode] [--print-only] [--dir DIR]` writes agent guidance:
  `.claude/skills/sim-doctor/SKILL.md`, `.cursor/rules/sim-doctor.mdc`, and a marked block in `AGENTS.md`
  that is replaced in place on re-run.
- Prebuilt binaries on tagged releases (macOS aarch64 and x86_64, Linux x86_64) and an `npx sim-doctor` launcher.
- Tagged-release publishing: the release workflow checks that the tag, `Cargo.toml` and `npm/package.json` agree,
  attaches binaries plus `.sha256` files to the GitHub release, then publishes to crates.io and npm (with provenance),
  skipping with a notice when a token is unset or the version already exists. crates.io package metadata added.
- The `npx` launcher verifies the downloaded binary's SHA-256 and has no-network tests (`npm test`).
- Illustrated logo (SIM card with a pulse line) as `docs/assets/logo-{light,dark}.svg` and `mark.svg`.
- README install section, CLI reference and logo; this changelog.

## [0.1.0] - 2026-10-06

First tagged state of the M1 path: `sim-doctor scan` opens a PC/SC session, walks the card's file
system and reports it as a table or one JSON envelope. Structure-only: one rule runs (`gsma/msl-zero-allowed`,
behind `--tar`), so a score of 100 does not mean a clean card.

### Added

- Crate skeleton with documented module boundaries (#29).
- APDU codec, status-word handling and the session composition layer (#31).
- TLV stream decoder, caller-supplied FCP tag table and EF metadata (#32).
- The DF-tree filesystem walker (#33).
- SIGINT handling and process-level exit-status tests (#34).
- The clap CLI surface for `scan`: `--json`, `--dialect`, `--reader`, the walk bounds (#35).
- Finding and rule model with namespaced rule IDs (#36).
- `--severity` filtering, `--score`, and JSON purity guarantees (#37).
- TAR scanner and the MSL=0 rule `gsma/msl-zero-allowed` (#38).
- CI: fmt, clippy `-D warnings`, test (#27), and the swSIM + swicc-pcsc software-card fixture (#30).

### Changed

- Switched the license to MIT.
- Closed resolved dependency blockers in AGENTS.md (#28).
