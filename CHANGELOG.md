# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
