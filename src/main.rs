//! `sim-doctor` as a binary.
//!
//! Every line here is a view: parse arguments, ask the library for a value,
//! put it on stdout, exit. Nothing in this file decides what a module owns,
//! what the JSON looks like, or which exit code means what - those live in
//! the library, where they can be tested without a terminal.
//!
//! This is also the only place in the crate that writes to stdout, and AGENTS.md
//! section 3 makes that a hard rule: under `--json`, stdout carries one JSON
//! envelope and not one byte else. Three things enforce it structurally here:
//!
//! - **Every diagnostic goes to stderr.** [`eprintln!`] for anything a human
//!   reads, [`init_diagnostics`] for anything a library module logs. There is
//!   no path from this file to `println!` any more: [`emit_stdout`] returns its
//!   error instead of panicking, which is what `tests/process_contract.rs` uses
//!   to reach exit code 1.
//! - **Output is assembled, then written once.** Nothing is printed while it is
//!   being built, so a half-formed envelope cannot reach stdout.
//! - **An interrupted run still emits exactly one envelope**, carrying code 130.
//!   See [`report_interrupted`] and `contract::INTERRUPTED_MESSAGE`.

use std::env;
use std::io::{self, IsTerminal, Write};
use std::process;
use std::thread;
use std::time::{Duration, Instant};

use clap::{error::ErrorKind, Args, CommandFactory, Parser, Subcommand};
use clap_complete::aot::generate;
use sim_doctor::{
    access, apdu_fuzz, apdu_scan, baseline, ci, contract, ef, euicc, fix, fuzz, gp, rules, sarif,
    scan, session, signals, skill, tar, trace,
    transport::{
        pcsc::{Pcsc, PcscSession},
        replay, CardSession, Error as TransportError, ReaderName, ReaderProvider,
    },
    ts48,
    walk::{self, Limits},
    MODULES,
};

/// The `type` every `modules` envelope carries.
///
/// Named once so the interrupted envelope cannot drift from the successful
/// one. `modules` is a self-description rather than a scan, but it is the
/// discriminator the crate has always emitted for it (see
/// `contract::DEFAULT_KIND`); changing it is a contract change and not this
/// issue's business.
const MODULES_KIND: &str = contract::DEFAULT_KIND;

/// Set by `tests/process_contract.rs` to park the process at its first
/// interrupt checkpoint, in milliseconds.
///
/// A SIGINT can only be tested by sending one, and a signal can only be sent to
/// a process that is still running. `modules` finishes in well under a
/// millisecond and `scan` spends most of its time on the wire, so without this
/// the test would be a race between the signal and the exit - and a race that
/// passes on a fast machine fails on a loaded CI runner. With it, the process is
/// provably parked when the signal arrives.
///
/// Unset in every normal invocation. When unset this costs one failed
/// environment lookup and nothing else, and the checkpoint behaves exactly as
/// it would without it.
const SIGNAL_HOLD_ENV: &str = "SIM_DOCTOR_TEST_SIGNAL_HOLD_MS";

/// The phrase [`SIGNAL_HOLD_ENV`] announces on stderr once the process is
/// parked with its handler installed.
///
/// The test waits for this line before sending SIGINT. That handshake is the
/// whole reason the SIGINT test is deterministic rather than merely usually
/// right: a signal delivered before `install()` returns hits the kernel's
/// default disposition and kills the process, which is indistinguishable in a
/// shell from the exit status we are trying to prove but is a different thing
/// entirely.
const PARKED_MARKER: &str = "parked at the interrupt checkpoint";

/// Whether this process has already parked at a checkpoint.
///
/// `scan` has more than one checkpoint, and a test that sets
/// [`SIGNAL_HOLD_ENV`] and does not get its signal through in time would
/// otherwise wait out the whole hold at every one of them - two checkpoints
/// multiplied by thirty seconds, on a run that was going to be interrupted at
/// the first. Parking once makes the hold mean "the first checkpoint", which is
/// what the tests that set it actually mean.
static PARKED_ONCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Test-only, and only honoured together with [`SIGNAL_HOLD_ENV`]: after parking,
/// block this thread forever instead of polling the interrupt flag, standing in
/// for a PC/SC transmit that never returns. Unset in every normal invocation.
const WEDGE_ENV: &str = "SIM_DOCTOR_TEST_WEDGE";

/// How long a card command gets to unwind on its own after SIGINT/SIGTERM
/// before [`guard_exchange`] ends the process (issue #88).
///
/// Long enough for a transmit in flight to return and reach a checkpoint
/// (the safe order, see `signals::install`), short enough to be "within seconds".
const INTERRUPT_GRACE: Duration = Duration::from_secs(3);

/// Set once an interrupted envelope has been written, so the watchdog and the
/// normal checkpoint path can never both write one.
static INTERRUPT_REPORTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[derive(Parser)]
#[command(
    name = "sim-doctor",
    version,
    about = "CLI-first SIM/UICC security testing tool",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Describe the crate module roots and the layering between them.
    Modules(ModulesArgs),

    /// Select a card's master file, walk everything under it, and report.
    ///
    /// Opens a real PC/SC session against one reader, selects the master file
    /// (3F00), probes every candidate file identifier underneath it, descends
    /// into the directories the card itself describes, and reports what it
    /// found - as a table for a person, or as one JSON envelope under --json.
    ///
    /// # What a clean result does and does not mean
    ///
    /// Truncation is always reported. A walk that hit one of its bounds did
    /// not see the whole card, and the output says so in three places: the
    /// "TRUNCATED" banner is the first line of the human report, and the JSON
    /// carries "complete", "truncated", "truncated_by" and the full "limits_hit"
    /// list. A file list without those is a file list an agent could read as the
    /// card's complete contents, which is a silent under-report of the attack
    /// surface.
    ///
    /// The default dialect and the default candidate set can both
    /// under-report. Both are reported in the output, and --dialect exists so
    /// the choice is yours rather than this tool's. See --dialect and the note
    /// under --max-children.
    ///
    /// Exit codes (doctor/1): 0 no finding at or above --fail-on, 1 at least
    /// one, 2 usage error or the scan could not run, 3 a new finding against
    /// --baseline, 130 if you interrupt it.
    #[command(long_about = SCAN_LONG_ABOUT)]
    Scan(ScanArgs),

    /// Compare a card against the public GSMA TS.48 test profile.
    Ts48(Ts48Args),

    /// Write agent guidance (Claude skill, Cursor rule, AGENTS.md block) into a project.
    ///
    /// Teaches a coding agent to run `sim-doctor scan --json` and read the
    /// envelope. Writes `.claude/skills/sim-doctor/SKILL.md`,
    /// `.cursor/rules/sim-doctor.mdc` and a marked block in `AGENTS.md`
    /// (replaced in place on re-run; the rest of the file is untouched).
    Install(InstallArgs),

    /// Write the GitHub Actions workflow that runs this repo's action on pull requests.
    Ci(CiArgs),

    /// Write a shell completion script to stdout.
    ///
    /// The script names every subcommand and flag this binary has, including
    /// the ones whose behaviour is not implemented yet: an agent completing
    /// "sim-doctor scan --" should be able to see the whole contract, not the
    /// half of it that works today.
    ///
    ///     sim-doctor completions zsh > ~/.local/share/zsh/completions/_sim-doctor
    ///     sim-doctor completions bash > /etc/bash_completion.d/sim-doctor
    ///
    /// The script IS the document here, so it is written to stdout and nothing
    /// else is. It is not JSON, so --json does not apply to this subcommand.
    Completions(CompletionsArgs),

    /// Serve the scan and the rules as MCP tools over stdio.
    ///
    /// Needs no card to start. stdout carries JSON-RPC lines and nothing else.
    Mcp,

    /// List the rules a scan runs, or explain one, without a card.
    ///
    /// With no subcommand this is `rules list`.
    Rules(RulesArgs),

    /// Explain a rule, or every rule in a saved `scan --json` envelope.
    ///
    /// The argument is a rule id (like `rules explain`) or the path of an
    /// existing file holding a saved `sim-doctor scan --json` envelope. There
    /// is no persisted "last scan": save one with `scan --json > scan.json`.
    Why(WhyArgs),

    /// Hand one finding from a saved scan to a coding agent.
    ///
    /// Prints a prompt as plain text on stdout (not JSON) and exits 0. With
    /// --agent it also starts that agent with the prompt; the agent keeps its own
    /// approval prompts unless --skip-approvals (or SIM_DOCTOR_HANDOFF_SKIP_APPROVALS=1).
    /// Nothing is launched when already inside a coding agent. FILE is a saved
    /// `sim-doctor scan --json` envelope, like `why` reads.
    Fix(FixArgs),

    /// Read-only GlobalPlatform queries.
    ///
    /// Sends SELECT, GET RESPONSE and GET DATA only. Never an authenticating
    /// or writing command.
    Gp(GpArgs),

    /// Decode a captured APDU trace offline (no card, no reader).
    ///
    /// Reads hex lines (alternating command, response), our own `--trace`
    /// JSON, or a pcap/pcapng capture of GSMTAP SIM APDUs (UDP 4729, as from
    /// SIMtrace2 or pySim-trace; detected automatically) from FILE or stdin,
    /// names each command, tracks the selected file and explains each status
    /// word.
    Trace(TraceArgs),

    /// APDU discovery and the OTA/SMS fuzz sweep.
    ///
    /// REFUSES to run unless BOTH --i-understand-this-can-brick-the-card is
    /// given AND the reader's name matches the software card (swicc-pcsc
    /// names its reader with "swICC"; see docs/swsim-fixture.md), or
    /// --allow-real-hardware is also given. A fuzz run sends ENVELOPE and
    /// undocumented CLA/INS combinations, either of which can brick a real
    /// SIM; this crate will not run one against hardware by accident.
    ///
    /// Exit codes: 0 when the run finished, 1 when it could not (including
    /// the opt-in refusal, error kind fuzz-needs-opt-in), 129 for a bad
    /// command line, 130 if interrupted.
    Fuzz(FuzzArgs),

    /// eUICC queries over ES10 (lpac: chip info, profile list, notification list), and the profile and notification writes.
    ///
    /// Opens a logical channel, selects the ISD-R by AID, sends STORE DATA
    /// requests, and closes the channel. info, profiles and notifications only
    /// read. `nickname`, `enable`, `disable`, `delete`, `reset` and
    /// `notifications remove` are the writes: dry runs unless --yes (`reset` also
    /// needs --confirm-eid). Never retrieves a notification. The output is the
    /// lpac envelope under --json. Exit codes: 0 answered, 1 the card is not an
    /// eUICC, refused, or answered something malformed (the envelope carries
    /// `data.error.kind`), 129 for a bad command line, 130 if interrupted.
    Euicc(EuiccArgs),
}

/// Everything `sim-doctor euicc` takes.
#[derive(Args)]
struct EuiccArgs {
    #[command(subcommand)]
    action: EuiccAction,
}

#[derive(Subcommand)]
enum EuiccAction {
    /// EID, EUICCInfo1 and EUICCInfo2 (lpac `chip info`).
    Info(EuiccFlags),
    /// Installed profiles: ICCID, state, class, nickname, provider, name (lpac `profile list`).
    Profiles(EuiccFlags),
    /// Pending notification metadata, nothing retrieved (lpac `notification list`);
    /// `notifications remove <seq>` removes one.
    Notifications(NotificationsArgs),
    /// Set a profile's nickname (lpac `profile nickname`). A write: a dry
    /// run unless `--yes`, never exposed over MCP.
    Nickname(NicknameArgs),
    /// Enable a profile (lpac `profile enable`, ES10c EnableProfile with REFRESH).
    /// A dry run unless `--yes`: switches the active profile and the device
    /// loses its connection until it re-attaches. Never exposed over MCP.
    Enable(StateArgs),
    /// Disable a profile (lpac `profile disable`, ES10c DisableProfile with
    /// REFRESH). A dry run unless `--yes`: disabling the only enabled profile
    /// leaves no active profile. Never exposed over MCP.
    Disable(StateArgs),
    /// Delete a profile (lpac `profile delete`, ES10c DeleteProfile). A dry run
    /// unless `--yes`: the profile is erased permanently and can only come back
    /// by downloading it again from the operator. An enabled profile is refused.
    /// Never exposed over MCP.
    Delete(DeleteArgs),
    /// Reset the eUICC memory (lpac `chip purge`, ES10c eUICCMemoryReset). Can
    /// erase every profile: nothing is selected by default, and sending needs
    /// both `--yes` and `--confirm-eid <EID>` matching the card. Never exposed over MCP.
    Reset(ResetArgs),
}

/// Everything `sim-doctor euicc notifications` takes: the list, or `remove`.
#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
struct NotificationsArgs {
    #[command(subcommand)]
    action: Option<NotificationAction>,
    #[command(flatten)]
    flags: EuiccFlags,
}

#[derive(Subcommand)]
enum NotificationAction {
    /// Remove a notification from the eUICC's list (lpac `notification remove`,
    /// ES10b RemoveNotificationFromList). A dry run unless `--yes`: a removed
    /// notification is never sent to the operator's server. Never exposed over MCP.
    Remove(RemoveArgs),
}

/// Everything `sim-doctor euicc notifications remove` takes.
#[derive(Args)]
struct RemoveArgs {
    /// Sequence number of the notification, as `euicc notifications` lists it.
    seq: u32,
    /// Send the request, then re-read the list and confirm. Without it
    /// nothing is changed.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    flags: EuiccFlags,
}

/// Everything `sim-doctor euicc delete` takes.
#[derive(Args)]
struct DeleteArgs {
    /// ICCID (18 to 20 digits) or ISD-P AID (hex) of the profile.
    id: String,
    /// Send DeleteProfile, then re-read the profile list and confirm. Without
    /// it nothing is changed: the profile and its consequence are printed.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    flags: EuiccFlags,
}

/// Everything `sim-doctor euicc reset` takes.
#[derive(Args)]
struct ResetArgs {
    /// Delete the operational profiles (resetOptions bit 0).
    #[arg(long)]
    operational: bool,
    /// Delete the field-loaded test profiles (resetOptions bit 1).
    #[arg(long)]
    test: bool,
    /// Reset the default SM-DP+ address (resetOptions bit 2).
    #[arg(long)]
    smdp_address: bool,
    /// The card's EID (32 hex digits); must match the EID read from the card.
    #[arg(long, value_name = "EID")]
    confirm_eid: Option<String>,
    /// Send the reset (needs `--confirm-eid`), then re-read and confirm.
    /// Without it nothing is changed: the profiles that would be erased are listed.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    flags: EuiccFlags,
}

/// Everything `sim-doctor euicc enable` and `disable` take.
#[derive(Args)]
struct StateArgs {
    /// ICCID (18 to 20 digits) or ISD-P AID (hex) of the profile.
    id: String,
    /// Send the request, then re-read the profile list and confirm. Without
    /// it nothing is changed: the plan and its consequence are printed.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    flags: EuiccFlags,
}

/// Everything `sim-doctor euicc nickname` takes.
#[derive(Args)]
struct NicknameArgs {
    /// ICCID of the profile (18 to 20 digits).
    iccid: String,
    /// The new nickname, at most 64 bytes of UTF-8; "" clears it.
    #[arg(allow_hyphen_values = true)]
    name: String,
    /// Send SetNickname, then re-read the profile list and confirm. Without
    /// it nothing is changed: the target EID and ICCID, the current and the
    /// new nickname are printed and the command exits.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    flags: EuiccFlags,
}

/// Flags every `euicc` subcommand shares.
#[derive(Args)]
struct EuiccFlags {
    /// The reader to use, matched against the driver's own name.
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,
    /// Emit one lpac envelope on stdout, and nothing else.
    #[arg(long)]
    json: bool,
    /// ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100).
    #[arg(long, value_name = "HEX")]
    aid: Option<String>,
    /// Most data bytes in one STORE DATA block, 1 to 255 (default 120, as
    /// lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks.
    #[arg(long, value_name = "BYTES", default_value_t = 120, value_parser = clap::value_parser!(u16).range(1..=255))]
    max_segment: u16,
}

/// Everything `sim-doctor fuzz` takes.
#[derive(Args)]
struct FuzzArgs {
    #[command(subcommand)]
    action: FuzzAction,
}

#[derive(Subcommand)]
enum FuzzAction {
    /// CLA discovery (level 1) or CLA+INS discovery (level 2) over a session.
    ///
    /// Every candidate is sent as a CASE 1 header (CLA INS 00 00, no data):
    /// discovery never carries a payload. Classified by status word: 6E00 is
    /// "class not supported", 6D00 is "instruction not supported", anything
    /// else reached a handler and is reported interesting.
    Apdu(FuzzApduArgs),

    /// The OTA/SMS fuzz sweep: TAR x keyset x mechanism, built on the TAR
    /// scanner's ENVELOPE builder.
    Ota(FuzzOtaArgs),

    /// Allowlist-only APDU mutation fuzzer, against a replay log or the
    /// built-in mock card only (no reader).
    ///
    /// Generates malformed variations of SELECT, READ BINARY, READ RECORD,
    /// STATUS, GET DATA, GET RESPONSE and unassigned INS values; nothing else
    /// can be generated. Every APDU and status word is in the report; a card
    /// answering success to a command the spec says to reject is a
    /// fuzz/malformed-command-accepted finding. --dry-run prints the plan and
    /// sends nothing. Running this against a real reader is not implemented.
    Mutate(FuzzMutateArgs),
}

/// Everything `sim-doctor fuzz mutate` takes.
#[derive(Args)]
struct FuzzMutateArgs {
    /// Answer from a recorded exchange log (one {"command","response"} JSON
    /// object per line, as SIM_DOCTOR_RECORD writes) instead of a card.
    #[arg(long, value_name = "FILE", conflicts_with = "mock")]
    replay: Option<std::path::PathBuf>,

    /// Answer from the built-in strict mock card.
    #[arg(long)]
    mock: bool,

    /// Cases to send (1 to 10000).
    #[arg(long, default_value_t = apdu_fuzz::DEFAULT_MAX_CASES, value_name = "N")]
    max_cases: usize,

    /// Stop sending after this many seconds.
    #[arg(long, value_name = "SECONDS")]
    timeout: Option<u64>,

    /// PRNG seed. The same seed gives the same APDUs.
    #[arg(long, default_value_t = 0)]
    seed: u64,

    /// Print the planned APDUs and the allowlist/denylist; send nothing.
    #[arg(long)]
    dry_run: bool,

    /// Stop after the first finding.
    #[arg(long)]
    stop_on_first_finding: bool,

    /// Emit one JSON envelope on stdout, and nothing else.
    #[arg(long)]
    json: bool,
}

/// Flags every `fuzz` subcommand shares: the safety interlock and the reader.
#[derive(Args, Clone)]
struct FuzzSafety {
    /// Required. Without it, `fuzz` refuses to run at all (exit 1, error
    /// kind fuzz-needs-opt-in).
    #[arg(long = "i-understand-this-can-brick-the-card")]
    i_understand: bool,

    /// Required in addition to the opt-in above when the reader's name does
    /// not match the software card (swicc-pcsc names its reader with
    /// "swICC"). Without it, `fuzz` refuses to run against anything that is
    /// not recognisably the software card.
    #[arg(long = "allow-real-hardware")]
    allow_real_hardware: bool,

    /// The reader to use, matched against the driver's own name.
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,

    /// Emit one JSON envelope on stdout, and nothing else.
    #[arg(long)]
    json: bool,

    /// Probe a small, documented subset instead of the full space.
    #[arg(long)]
    quick: bool,
}

/// Everything `sim-doctor fuzz apdu` takes.
#[derive(Args)]
struct FuzzApduArgs {
    #[command(flatten)]
    safety: FuzzSafety,

    /// 1 for CLA discovery, 2 for CLA+INS discovery.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=2))]
    level: u8,

    /// The CLA level 2 probes INS values at, as two hex digits (e.g. A0).
    /// Required for --level 2.
    #[arg(long, value_name = "HEX")]
    class: Option<String>,
}

/// Everything `sim-doctor fuzz ota` takes.
#[derive(Args)]
struct FuzzOtaArgs {
    #[command(flatten)]
    safety: FuzzSafety,
}

/// Everything `sim-doctor gp` takes.
#[derive(Args)]
struct GpArgs {
    #[command(subcommand)]
    action: GpAction,
}

#[derive(Subcommand)]
enum GpAction {
    /// Select the issuer security domain and read CPLC, card data, key
    /// information, IIN and CIN with GET DATA.
    ///
    /// Exit 0 when an ISD answered, 1 when none did (the envelope still carries
    /// the status words), 129 for a bad command line.
    Info {
        /// The reader to use, matched against the driver's own name.
        #[arg(long, value_name = "NAME")]
        reader: Option<String>,
        /// Emit one JSON envelope of kind "gp" on stdout.
        #[arg(long)]
        json: bool,
        /// Add every APDU exchange (command and response hex) as data.trace.
        #[arg(long)]
        trace: bool,
    },
    /// Select the ARA-M (Access Rule Application Master) and read every access
    /// rule with GET DATA [all], decoded (read-only, no keys).
    ///
    /// Exit 0 when the ARA-M answered, 1 when it did not.
    Ara {
        /// The reader to use, matched against the driver's own name.
        #[arg(long, value_name = "NAME")]
        reader: Option<String>,
        /// Emit one JSON envelope of kind "gp" on stdout.
        #[arg(long)]
        json: bool,
        /// Add every APDU exchange (command and response hex) as data.trace.
        #[arg(long)]
        trace: bool,
    },
    /// GlobalPlatform registry inventory: GET STATUS for the ISD, applications
    /// and load files, plus Card Recognition Data (read-only). A scope
    /// the card only gives over a secure channel is reported as requiring
    /// authentication.
    ///
    /// With --keys-file or --keys-env the registry is read over an SCP03 secure
    /// channel (C-MAC) opened with ONE authentication attempt.
    ///
    /// The key text is `ENC [MAC [DEK]]`, 32 hex digits each (AES-128), split by
    /// spaces, commas or newlines; one key means ENC = MAC. A key may be written
    /// KEY/KCV (6 hex digits); a wrong KCV stops the run before the card is
    /// touched. Keys are never taken from the command line and never printed.
    /// Failed attempts count toward locking the ISD, so there is no retry, and the
    /// card cryptogram is checked locally first: wrong keys stop with "keys do not
    /// match this card" and EXTERNAL AUTHENTICATE is not sent.
    ///
    /// Exit 0 when an ISD answered, 1 when none did or authentication stopped.
    Status {
        /// The reader to use, matched against the driver's own name.
        #[arg(long, value_name = "NAME")]
        reader: Option<String>,
        /// Emit one JSON envelope of kind "gp" on stdout.
        #[arg(long)]
        json: bool,
        /// Add every APDU exchange (command and response hex) as data.trace.
        #[arg(long)]
        trace: bool,
        #[command(flatten)]
        keys: GpKeyArgs,
    },
    /// SELECT a GlobalPlatform (or any) application by AID and report the status
    /// word and the FCI. Read-only, no keys; it only changes the card's current
    /// selection.
    ///
    /// Exit 0 when the application answered 90 00, 1 when it did not.
    Select {
        /// The application AID, 5 to 16 bytes of hex.
        #[arg(long, value_name = "HEX")]
        aid: String,
        /// The reader to use, matched against the driver's own name.
        #[arg(long, value_name = "NAME")]
        reader: Option<String>,
        /// Emit one JSON envelope of kind "gp" on stdout.
        #[arg(long)]
        json: bool,
        /// Add every APDU exchange (command and response hex) as data.trace.
        #[arg(long)]
        trace: bool,
    },
}

/// Where `gp status` gets ISD keys. Never a value on the command line: it would
/// land in shell history and the process list.
///
/// The text is `ENC [MAC [DEK]]`, each 32 hex digits (AES-128),
/// separated by spaces, commas or newlines; one key means ENC = MAC. A key may
/// be written `KEY/KCV` (6 hex digits); a wrong KCV stops the run before the
/// card is touched. The channel is C-MAC only. Exactly ONE authentication attempt
/// is made per run and it is never retried, because failed attempts count toward
/// locking the ISD. The card cryptogram is checked locally first: wrong keys stop
/// with "keys do not match this card" and EXTERNAL AUTHENTICATE is not sent.
/// Keys are never printed.
#[derive(Args)]
#[command(group(clap::ArgGroup::new("key_source").args(["keys_file", "keys_env"])))]
struct GpKeyArgs {
    /// File holding the keys (keep it chmod 600).
    #[arg(long, value_name = "PATH")]
    keys_file: Option<std::path::PathBuf>,
    /// Environment variable holding the keys.
    #[arg(long, value_name = "VAR")]
    keys_env: Option<String>,
    /// Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets
    /// the card choose its first key set.
    #[arg(long, value_name = "HEX", default_value = "00", requires = "key_source",
          value_parser = parse_hex_byte)]
    key_version: u8,
}

fn parse_hex_byte(text: &str) -> Result<u8, String> {
    u8::from_str_radix(text, 16).map_err(|_| "expected one byte as hex, like 30".into())
}

/// The long description of `sim-doctor scan`.
///
/// A constant rather than a literal in the derive so
/// [`tests/process_contract.rs`] can assert the exact sentence that warns about
/// under-reporting. A warning that lives only in prose is a warning that gets
/// reworded out of existence by the next person to tidy a doc comment; one that
/// a test quotes is a warning that has to keep meaning what it says.
const SCAN_LONG_ABOUT: &str = concat!(
    "Select a card's master file, walk everything under it, and report.\n\n",
    "Opens a real PC/SC session against one reader, selects the master file\n",
    "(3F00), probes every candidate file identifier underneath it, descends into\n",
    "the directories the card itself describes, and reports what it found.\n\n",
    "WHAT A CLEAN RESULT DOES AND DOES NOT MEAN\n",
    "  * Truncation is always reported. A walk that hit one of its bounds did\n",
    "    not see the whole card: the human report opens with a TRUNCATED banner,\n",
    "    and --json carries \"complete\", \"truncated\", \"truncated_by\" and the\n",
    "    full \"limits_hit\" list. A file list without those is a file list an\n",
    "    agent could read as the card's complete contents.\n",
    "  * The default dialect is an assumption, not a fact. Reading a card's\n",
    "    capabilities template with the wrong tag table produces a file size the\n",
    "    card never sent. Pass --dialect to declare which table is in use; the\n",
    "    one actually used is named in both output modes.\n",
    "  * The default candidate set can MISS a file. See --max-children.\n",
    "  * A default TAR scan does NOT prove MSL != 0. See TAR AND MSL 0.\n\n",
    "OUTPUT: doctor/1\n",
    "  --json prints the shared doctor/1 envelope (docs/doctor-contract.md):\n",
    "  schema, tool, version, exit_code, score, findings and data. Findings are\n",
    "  top-level (id, fingerprint, severity, category, message, location,\n",
    "  evidence, remedy); the walk, the TAR audit and everything else this report\n",
    "  carries are under data.\n\n",
    "READ data.complete BEFORE TRUSTING A CLEAN RESULT\n",
    "  The exit code is decided by findings, not by whether the walk finished: a\n",
    "  walk cut short at a bound exits 0 when its findings are below --fail-on.\n",
    "  An agent gating a build should also require data.complete to be true, or\n",
    "  score.coverage_gaps to be 0 (the score label is `incomplete`, not `good`,\n",
    "  while there is a gap).\n\n",
    "TAR AND MSL 0\n",
    "  A TAR is a three-octet value a network uses to route an SMS payload to one\n",
    "  application on a card. A card running at MSL 0 accepts ANY command under\n",
    "  ANY TAR with no cryptographic verification, so the security question is\n",
    "  which TARs the card will act on. --tar selects them: off (none), focused\n",
    "  (592 TARs, the default), full (from 000000), range:FIRST-LAST, or\n",
    "  regex:PATTERN over the six-hex-digit spelling.\n",
    "  THE PROBE COUNT IS CAPPED AT 4096 WHATEVER YOU ASK FOR. The full TAR\n",
    "  space is 16 777 216 values and this tool will not send them all to a\n",
    "  card. A selection larger than the cap stops at it; data.tar.stopped says\n",
    "  so, and any finding it carries is marked partial rather than read as an\n",
    "  exhaustive audit of the card's TAR accept-list.\n",
    "  A TAR is reported as ACCEPTED when the card answers it DIFFERENTLY from\n",
    "  the way it answers TARs it has no opinion about. That is a measurement,\n",
    "  not a status word this tool guesses at: no 3GPP TS 31.111 text has been\n",
    "  read here, and the one card this crate has talked to answers 94 04 for\n",
    "  something else entirely. data.tar.baseline carries the measurement, and\n",
    "  every probe's status word is in data.tar.probes.\n",
    "  A CARD THAT ANSWERS EVERY TAR IDENTICALLY REPORTS NOTHING ACCEPTED. On\n",
    "  a card with no TAR check that is the correct answer, not a miss. A scan\n",
    "  whose baseline could not be established says so in data.tar.blind_spot\n",
    "  and raises nothing. So does a baseline that is only a generic error\n",
    "  (6F00, 6D00, 6E00, 6985, 6A81): the card did not process the envelopes,\n",
    "  the sweep is not sent, and the blind spot names --terminal-profile.\n\n",
    "SEVERITY AND SCORE\n",
    "  --severity <level> REMOVES findings below that level from the report.\n",
    "  Not marked, not counted, absent from the JSON entirely, so a count or a\n",
    "  grep sees only what survived. The level in force is reported as\n",
    "  data.findings_detail.severity_threshold. It does not filter the walk:\n",
    "  complete, truncated and limits_hit are unaffected by it.\n",
    "  The top-level score is an INTEGER 0-100 (model sim/1), always present;\n",
    "  --score adds it to the human report. It is computed as\n",
    "    max(0, 100 - sum of one penalty per finding)\n",
    "  with a penalty of info 1, low 3, medium 10, high 25, critical 50. The\n",
    "  block carries the formula, that penalty table, the penalty total and\n",
    "  the number of findings scored, so the number can be recomputed from\n",
    "  the report (data.score_detail). It scores the findings this report\n",
    "  carries, so --severity\n",
    "  and --score compose rather than contradict each other.\n",
    "  A rules_run OF 0 means no rule was evaluated, and the block then carries\n",
    "  a warning beside the 100 saying so in words. A rules_run above 0 with a\n",
    "  score of 100 means a rule looked and found nothing, which is a verdict.\n",
    "  The two are different numbers wearing the same digits, and warning is\n",
    "  what tells them apart.\n\n",
    "EXIT CODES\n",
    "  0  ran; no finding at or above --fail-on (default critical)\n",
    "  1  ran; at least one finding at or above --fail-on\n",
    "  2  usage error, bad input (including an unusable --baseline), or the\n",
    "     scan could not run (no reader, no card, a failed walk)\n",
    "  3  --baseline given; at least one NEW finding at or above --fail-on.\n",
    "     Under --baseline only new findings count: 3 or 0, never 1\n",
    "  130  interrupted\n",
);
/// Everything `sim-doctor ts48` takes.
#[derive(Args)]
struct Ts48Args {
    #[command(subcommand)]
    action: Ts48Action,
}

#[derive(Subcommand)]
enum Ts48Action {
    /// Walk the card and diff its file system against the GSMA TS.48 test profile.
    ///
    /// Read-only: the same SELECT / GET RESPONSE walk as `scan`, and nothing
    /// else (no TAR probes, no ENVELOPE). The expected file list is derived from
    /// the public TS.48 v7.0 SAIP profile (Apache-2.0, pinned commit) and is
    /// compiled into this binary.
    ///
    /// Reports files the profile defines that the card lacks (ts48/file-missing),
    /// files the card has that the profile does not (ts48/file-extra) and files
    /// present in both that differ in type, layout, size or record length
    /// (ts48/file-different). An operator SIM is not a TS.48 card, so many
    /// differences are the expected answer: they are findings, exit code 0.
    ///
    /// MATCHING THE TS.48 FILE STRUCTURE IS NOT GCF OR PTCRB CONFORMANCE. This
    /// compares a file system with a public test profile and certifies nothing.
    ///
    /// Exit codes: 0 when the walk finished, 1 when it could not run (no reader,
    /// no card), 129 for a bad command line, 130 if interrupted.
    Compare(Ts48CompareArgs),
}

/// The walk bounds, shared by `scan` and `ts48 compare` so they cannot drift.
#[derive(Args)]
struct WalkLimitArgs {
    /// Deepest path below the master file the walk descends into.
    ///
    /// The default (16) leaves room for a real card. Lowering it is how you
    /// force a truncation on purpose, which is the supported way to see what a
    /// truncated report looks like.
    #[arg(long, value_name = "N")]
    max_depth: Option<usize>,

    /// Identifiers probed per directory.
    ///
    /// THE DEFAULT CANDIDATE SET CAN MISS A FILE. By default the walk probes
    /// the five GSM 11.11 identifier families 2Fxx/4Fxx/5Fxx/6Fxx/7Fxx, 1280 of
    /// them. Every file on the swSIM USIM profile falls inside one of those, so
    /// it cost no coverage there. On a card that puts a file anywhere else, that
    /// file is INVISIBLE to the scan - never probed, so it cannot even be
    /// reported missing - and a clean result is not proof the card holds nothing
    /// else. The output reports which candidate set ran and whether it covered
    /// the whole identifier space; an exhaustive --candidates range is not
    /// offered on this flag yet, which is itself an under-reporting default
    /// rather than a documented way out.
    #[arg(long, value_name = "N")]
    max_children: Option<usize>,

    /// Files the card selected across the whole walk (default 16384).
    ///
    /// Absent probes do not count, so this is a bound on files found, not on
    /// identifiers tried. How long a walk can run is bounded by
    /// --max-directories times --max-children.
    #[arg(long, value_name = "N")]
    max_nodes: Option<usize>,

    /// Directories whose children are enumerated.
    #[arg(long, value_name = "N")]
    max_directories: Option<usize>,
}

#[derive(Args)]
struct Ts48CompareArgs {
    /// Emit one JSON envelope (type "ts48") on stdout, and nothing else.
    #[arg(long)]
    json: bool,

    /// The reader to use, matched against the driver's own name.
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,

    /// Which FCP tag table this card answers SELECT with (see `scan --help`).
    #[arg(
        long,
        value_name = "TABLE",
        default_value_t = scan::Dialect::Ts102221,
        value_parser = parse_dialect
    )]
    dialect: scan::Dialect,

    #[command(flatten)]
    walk_limits: WalkLimitArgs,
}

/// Everything `sim-doctor scan` takes.
#[derive(Args)]
struct ScanArgs {
    /// Emit one JSON envelope on stdout, and nothing else.
    ///
    /// Implemented. stdout carries the envelope and not one byte else; every
    /// diagnostic goes to stderr in this mode and in every other.
    #[arg(long)]
    json: bool,

    /// Show the findings in an interactive terminal view instead of the report.
    ///
    /// A view over the same data `--json` carries: nothing is shown that the
    /// envelope does not contain. Needs a terminal on stdin and stdout; without
    /// one the plain report is printed and a line on stderr says so. Keys:
    /// up/down or j/k, PgUp/PgDn, Home/End, q or Esc to quit.
    #[arg(long, conflicts_with = "json")]
    tui: bool,

    /// Which FCP tag table this card answers SELECT with.
    ///
    /// Defaults to ts-102-221. This is an assumption and the output says which
    /// one was used; the chosen table's name appears in the human report and
    /// under "dialect" in the JSON, so the assumption is never invisible.
    ///
    /// ts-102-221 is the ETSI TS 102 221 clause 11.1.1.3 layout that real UICCs
    /// and swSIM both write: file size in 80, descriptor in 82, file id in 83,
    /// DF name in 84. swicc has the same tags and exists only so a baseline
    /// taken under that name stays comparable. iec-7816-4-table-42 is a
    /// deprecated alias for ts-102-221.
    ///
    /// A card nobody has characterised needs a hand-built TagSet, which this
    /// flag cannot express yet. That is a real gap rather than a missing third
    /// value: an "unknown" dialect would render an empty table as though it
    /// meant something.
    #[arg(
        long,
        value_name = "TABLE",
        default_value_t = scan::Dialect::Ts102221,
        value_parser = parse_dialect
    )]
    dialect: scan::Dialect,

    /// The reader to use, matched against the driver's own name.
    ///
    /// Defaults to the first reader PC/SC reports. Pass this when more than one
    /// is attached, or to get an explicit error naming what is available
    /// instead of scanning whichever reader happened to be first.
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,

    #[command(flatten)]
    walk_limits: WalkLimitArgs,

    /// Add one quality score for this card, for CI gating.
    ///
    /// Implemented. The score is an INTEGER from 0 to 100, and it is
    /// reproducible rather than merely present: 100 minus the penalty of every
    /// finding in this report, where a finding costs info 1, low 3, medium 10,
    /// high 25 or critical 50, floored at 0. AGENTS.md section 3 states the
    /// formula in full, and the JSON repeats it - the formula, the penalty
    /// table, the penalty total and how many findings were scored - so an
    /// agent can recompute the number from the document it is holding.
    ///
    /// It scores what this report carries, so --severity and --score compose:
    /// `--severity high --score` scores the high and critical findings and
    /// nothing else, and `data.score_detail.scored_findings` says how many that was.
    /// The top-level `score` of the JSON envelope is always present; this flag
    /// only adds the score to the human report.
    ///
    /// WHILE NO RULE IS IMPLEMENTED the score is 100 with `rules_run` 0 and a
    /// warning beside it. A 100 that means "nothing was checked" is not a
    /// clean card, and the report says so rather than leaving a CI gate to
    /// work that out from the absence of findings.
    #[arg(long)]
    score: bool,

    /// Drop findings below this severity.
    ///
    /// Implemented. Accepted and validated as one of info, low, medium, high,
    /// critical, so a typo is still a usage error (exit 2) rather than being
    /// silently ignored.
    ///
    /// A finding below the level is REMOVED, not marked: it is absent from
    /// the top-level `findings`, absent from `data.findings_detail.count`, and its
    /// rule ID appears nowhere in the document. An agent counting findings
    /// therefore gets the count that survived the filter, and an agent
    /// grepping for a dropped rule finds nothing rather than an empty shell
    /// carrying the ID.
    ///
    /// The level in force is reported as `data.findings_detail.severity_threshold`,
    /// because a short list is otherwise indistinguishable from a quiet card.
    ///
    /// It does not filter the WALK. `complete`, `truncated`, `truncated_by`
    /// and `limits_hit` are unchanged by it, so raising the level can never
    /// make a truncated scan look like a whole one.
    #[arg(long, value_name = "LEVEL")]
    severity: Option<rules::Severity>,

    /// Compare this run against a previous `scan --json` envelope (doctor/1).
    ///
    /// The file is a saved envelope: `sim-doctor scan --json > baseline.json`.
    /// Findings are matched by `fingerprint` only. Every finding in the report
    /// gets a `baseline_state` (`new` or `unchanged`), the envelope gets a
    /// top-level `baseline` block with `new`, `unchanged` and `fixed` counts,
    /// and `data.diff` carries the lists.
    ///
    /// UNDER A BASELINE ONLY NEW FINDINGS GATE. The exit code is 3 when at least
    /// one new finding is at or above --fail-on, else 0; the findings the
    /// baseline already had never fail the run.
    ///
    /// THE COMPARISON REFUSES RATHER THAN GUESSES (exit 2, `data.error`, no
    /// findings). A baseline written by a truncated scan, by a scan that ran
    /// fewer rules, at a different --severity, --dialect or --tar, or by a scan
    /// in which a rule had no evidence, cannot be honestly compared with this
    /// run. `--tar off` is the default, so the usual baseline never checked
    /// MSL 0 and the first `--tar focused` scan cannot be read as a regression
    /// against it. A file that is not a doctor/1 envelope of a finished scan is
    /// refused too, as is a hand-edited or hostile one (strings and arrays are
    /// bounded before parsing).
    ///
    /// A RENAMED RULE READS AS A RENAME. An ID in exactly one of the two runs is
    /// listed under `data.diff.rules` with a warning; the gate does not count
    /// it, though its findings carry `baseline_state: new`.
    ///
    /// THE BASELINE IS A FULL ENVELOPE. It carries the ATR and the decoded EF
    /// contents (`data.ef_contents`, key files included) that the report
    /// carries. Treat it as sensitive; do not commit one taken from a card with
    /// real keys.
    #[arg(long, value_name = "FILE")]
    baseline: Option<std::path::PathBuf>,

    /// Exit 1 (3 under --baseline) when a finding is at or above this severity.
    ///
    /// One of info, low, medium, high, critical. The default is `critical`:
    /// before doctor/1 a scan with findings exited 0, so the default fails only
    /// on the worst finding rather than on every report. Use `--fail-on info`
    /// to fail on any finding, `--fail-on high` for a stricter CI gate. This is
    /// the gate only; --severity is what REMOVES findings from the report.
    #[arg(long, value_name = "LEVEL", default_value = "critical")]
    fail_on: rules::Severity,

    /// Also write the findings to FILE as SARIF 2.1.0.
    ///
    /// A card has no files on disk, so each result carries a logical location
    /// (the card path) and never a physical one. Partial coverage is stated in
    /// the run's properties. Written after the normal output, so a failure to
    /// write it (exit 2, a message on stderr) never costs you the report. Each
    /// result carries `partialFingerprints["doctorFinding/v1"]`, the same value
    /// as the finding's JSON `fingerprint`, and the run carries `properties.score`. The
    /// file is written only after a completed scan: a refused or interrupted
    /// scan leaves any existing file untouched. It must not be the --baseline path.
    /// stdout is unchanged. Whether GitHub code scanning accepts the file is
    /// not verified.
    #[arg(long, value_name = "FILE")]
    sarif: Option<std::path::PathBuf>,

    /// Which TARs to probe for MSL 0, and how many.
    ///
    /// Implemented. Defaults to `focused`, which is 592 TARs chosen from
    /// SIMTester's own ranged-scan bands; `off` probes nothing, `full`
    /// starts at 000000, `range:FIRST-LAST` scans a band and
    /// `regex:PATTERN` scans everything matching a pattern over the
    /// six-hex-digit spelling (SIMTester's `-str` and `-stre`).
    ///
    /// THE PROBE COUNT IS BOUNDED AT 4096 WHATEVER YOU ASK FOR. The full TAR
    /// space is 16 777 216 values; sending them all to a card is not
    /// something this tool will do behind a flag. A selection larger than the
    /// bound stops at it and the report says so, under
    /// `data.tar.stopped`, and the finding it carries is marked partial
    /// rather than read as an exhaustive audit of the card's TAR accept-list.
    ///
    /// A TAR is accepted when the card's answer to it differs from the answer
    /// it gives to TARs it has no opinion about - the `-stbs` differential
    /// from SIMTester, reimplemented in src/tar.rs with the reasoning. A card
    /// that answers every TAR identically therefore reports nothing, which on
    /// a card with no TAR check is the correct answer rather than a miss.
    #[arg(long, value_name = "SELECTION", default_value_t = tar::Selection::default())]
    tar: tar::Selection,

    /// Send a TERMINAL PROFILE to the card before the TAR audit.
    ///
    /// Only meaningful with --tar other than `off`; without it the command
    /// line is refused (exit 2).
    ///
    /// WHAT IS SENT: `80 10 00 00 01 13` (TS 102 221 clause 11.2.1), a
    /// one-octet profile with three bits set, all in byte 1 (TS 102 223 /
    /// TS 31.111 clause 5.2): b1 profile download, b2 and b5 SMS-PP data
    /// download. No proactive command, menu, event or display capability is
    /// declared. A card that answers `91 xx` anyway has that command fetched
    /// and answered with TERMINAL RESPONSE `30` (command beyond terminal's
    /// capabilities); nothing it asks for is executed.
    ///
    /// WHY: a card that ignores CAT traffic until it has seen a profile
    /// answers every ENVELOPE `6F 00`, and the TAR audit then says nothing
    /// (data.tar.blind_spot). This is the handset's own first CAT step.
    ///
    /// WHAT IT CHANGES: the card's CAT session state for this power cycle.
    /// It writes no file. It is off by default for that reason. The exchange
    /// is reported as data.tar.terminal_profile.
    #[arg(long)]
    terminal_profile: bool,
}

/// Everything `sim-doctor rules` takes.
#[derive(Args)]
struct RulesArgs {
    #[command(subcommand)]
    action: Option<RulesAction>,
}

#[derive(Subcommand)]
enum RulesAction {
    /// One row per rule: id, severity, summary.
    List {
        /// Emit one JSON envelope of kind "rules" on stdout.
        #[arg(long)]
        json: bool,
    },
    /// What a rule means and how to fix it.
    Explain {
        /// The rule id, such as gsma/msl-zero-allowed.
        id: String,
        /// Emit one JSON envelope of kind "rules" on stdout.
        #[arg(long)]
        json: bool,
    },
}

/// Everything `sim-doctor trace` takes.
#[derive(Args)]
struct TraceArgs {
    /// A trace file; stdin when omitted or "-".
    file: Option<String>,
    /// Emit one JSON envelope of kind "trace" on stdout.
    #[arg(long)]
    json: bool,
}

/// Everything `sim-doctor why` takes.
#[derive(Args)]
struct WhyArgs {
    /// A rule id, or the path of a saved `sim-doctor scan --json` envelope.
    target: String,
    /// Emit one JSON envelope of kind "rules" on stdout.
    #[arg(long)]
    json: bool,
}

/// Everything `sim-doctor fix` takes.
#[derive(Args)]
struct FixArgs {
    /// The rule id to fix, such as gsma/msl-zero-allowed.
    rule_id: String,
    /// A saved `sim-doctor scan --json` envelope holding a finding for that rule.
    #[arg(long, value_name = "FILE")]
    from: String,
    /// Start this coding agent with the prompt instead of only printing it.
    #[arg(long, value_parser = ["claude", "codex", "cursor"])]
    agent: Option<String>,
    /// Pass the agent its flag that skips approval prompts (unverified for every CLI version).
    #[arg(long)]
    skip_approvals: bool,
}

#[derive(Args)]
struct ModulesArgs {
    /// Emit the JSON envelope on stdout instead of a human-readable table.
    #[arg(long)]
    json: bool,
}

/// Everything `sim-doctor install` takes.
#[derive(Args)]
struct InstallArgs {
    /// Install for one agent only; omit for all of them.
    #[arg(long, value_parser = skill::Agent::NAMES)]
    agent: Option<String>,

    /// Print what would be written instead of writing it.
    #[arg(long)]
    print_only: bool,

    /// Project root to write under (default: the current directory).
    #[arg(long, value_name = "DIR", default_value = ".")]
    dir: std::path::PathBuf,
}

/// Everything `sim-doctor ci` takes.
#[derive(Args)]
struct CiArgs {
    #[command(subcommand)]
    action: CiAction,
}

#[derive(Subcommand)]
enum CiAction {
    /// Write .github/workflows/sim-doctor.yml, pinned to this version's tag.
    ///
    /// Refuses to write through a symlink, keeps a differing existing file
    /// unless --force, and validates every value before writing anything.
    Install {
        /// Build the software card on the runner (CI has no card otherwise).
        #[arg(long, value_parser = ["true", "false"], default_value = "true")]
        swsim: String,
        /// Committed baseline path (letters, digits and . _ / - only).
        #[arg(long, value_name = "PATH", default_value = ".sim-doctor/baseline.json")]
        baseline: String,
        /// Fail the job when the baseline file is missing.
        #[arg(long, value_parser = ["true", "false"], default_value = "true")]
        require_baseline: String,
        /// Pass --severity to the scan.
        #[arg(long)]
        severity: Option<rules::Severity>,
        /// The action ref to pin (default: v<this version>; it exists once that release is cut).
        #[arg(long = "ref", value_name = "REF")]
        ref_: Option<String>,
        /// Project root to write under (default: the current directory).
        #[arg(long, value_name = "DIR", default_value = ".")]
        dir: std::path::PathBuf,
        /// Overwrite a differing existing workflow.
        #[arg(long)]
        force: bool,
        /// Print the workflow instead of writing it.
        #[arg(long)]
        print_only: bool,
    },
}

/// Everything `sim-doctor completions` takes.
#[derive(Args)]
struct CompletionsArgs {
    /// The shell to generate for.
    ///
    /// One of bash, elvish, fish, powershell or zsh.
    #[arg(value_name = "SHELL")]
    shell: clap_complete::Shell,
}

/// Parses `--dialect`, saying once on stderr when the deprecated spelling is used.
fn parse_dialect(text: &str) -> Result<scan::Dialect, scan::UnknownDialect> {
    if text.eq_ignore_ascii_case(scan::DEPRECATED_TABLE_42) {
        eprintln!(
            "sim-doctor: --dialect {} is deprecated: that mapping was wrong for real cards; using ts-102-221",
            scan::DEPRECATED_TABLE_42
        );
    }
    text.parse()
}

fn main() -> process::ExitCode {
    init_diagnostics();

    // Installed before clap runs, so even a command line this process has not
    // finished reading can be interrupted. A refusal is a diagnostic and not a
    // failed run: see signals::install.
    if let Err(err) = signals::install() {
        eprintln!("sim-doctor: {err}");
    }

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => return exit_with_clap_error(err),
    };

    exit(match cli.command {
        Command::Modules(args) => run_modules(args),
        Command::Scan(args) => run_scan(args),
        Command::Ts48(args) => match args.action {
            Ts48Action::Compare(args) => run_ts48_compare(args),
        },
        Command::Install(args) => run_install(args),
        Command::Completions(args) => run_completions(args),
        Command::Ci(args) => run_ci(args),
        Command::Rules(args) => match args.action {
            None => run_rules_list(false),
            Some(RulesAction::List { json }) => run_rules_list(json),
            Some(RulesAction::Explain { id, json }) => run_why_rule(&id, json),
        },
        Command::Why(args) => run_why(&args.target, args.json),
        Command::Fix(args) => run_fix(&args),
        Command::Gp(args) => match args.action {
            GpAction::Info {
                reader,
                json,
                trace,
            } => run_gp("gp info", reader.as_deref(), json, trace, gp::info),
            GpAction::Ara {
                reader,
                json,
                trace,
            } => run_gp("gp ara", reader.as_deref(), json, trace, gp::ara),
            GpAction::Status {
                reader,
                json,
                trace,
                keys,
            } => run_gp_status(reader.as_deref(), json, trace, &keys),
            GpAction::Select {
                aid,
                reader,
                json,
                trace,
            } => match hex::decode(&aid) {
                Ok(aid) if (5..=16).contains(&aid.len()) => {
                    run_gp("gp select", reader.as_deref(), json, trace, |s, t| {
                        gp::select(s, &aid, t)
                    })
                }
                _ => report_refusal(
                    "gp",
                    "--aid must be 5 to 16 bytes of hex",
                    serde_json::json!({ "error": { "kind": "bad-aid" } }),
                    json,
                ),
            },
        },
        Command::Euicc(args) => match args.action {
            EuiccAction::Info(f) => run_euicc(euicc::Query::Info, &f),
            EuiccAction::Profiles(f) => run_euicc(euicc::Query::Profiles, &f),
            EuiccAction::Notifications(n) => match n.action {
                None => run_euicc(euicc::Query::Notifications, &n.flags),
                Some(NotificationAction::Remove(a)) => run_euicc_remove(&a),
            },
            EuiccAction::Nickname(n) => run_euicc_nickname(&n),
            EuiccAction::Enable(a) => run_euicc_state(euicc::Action::Enable, &a),
            EuiccAction::Disable(a) => run_euicc_state(euicc::Action::Disable, &a),
            EuiccAction::Delete(a) => run_euicc_delete(&a),
            EuiccAction::Reset(a) => run_euicc_reset(&a),
        },
        Command::Trace(args) => run_trace(&args),
        Command::Mcp => run_mcp(),
        Command::Fuzz(args) => match args.action {
            FuzzAction::Apdu(args) => run_fuzz_apdu(args),
            FuzzAction::Ota(args) => run_fuzz_ota(args),
            FuzzAction::Mutate(args) => run_fuzz_mutate(args),
        },
    })
}

/// Routes every `tracing` event to stderr, at a level quiet enough to leave it
/// silent on a clean run.
///
/// `tracing-subscriber` is already a dependency and was, before this issue,
/// installed nowhere - which is the same thing as saying no library module had
/// a safe place to log from. Its default writer is **stdout**, the one stream
/// `--json` reserves for the envelope, so the wiring has to say `stderr`
/// explicitly or the first `tracing::warn!` in a future module silently breaks
/// every agent consuming this tool.
///
/// `with_max_level(WARN)` rather than `EnvFilter`: honouring `RUST_LOG` needs
/// tracing-subscriber's `env-filter` feature, and taking a dependency feature
/// for a log level nothing in the repo sets yet is the kind of speculative
/// change AGENTS.md section 4 warns about. The issue that first needs
/// per-module levels records that decision instead.
///
/// `with_ansi(false)` because stderr is read by CI logs and by `2>` files as
/// often as by a terminal, and escape codes are noise in both.
fn init_diagnostics() {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .init();
}

/// Runs `modules` and returns the exit code for it.
///
/// The interrupt checkpoint lives here rather than inside `emit_modules` so that
/// `emit_modules` stays a function that renders data and nothing else. [`run_scan`]
/// copies this shape and adds a second checkpoint after the walk; see its own
/// documentation for why there are exactly two.
fn run_modules(args: ModulesArgs) -> contract::ExitCode {
    if checkpoint() {
        return report_interrupted(MODULES_KIND, args.json);
    }

    match emit_modules(args.json) {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            // No rule produces findings yet (issue #13), so the only way a run
            // fails today is by being unable to deliver its result. AGENTS.md
            // section 3 shares code 1 between findings and a failed check, and
            // a run that could not write its answer is a failed run.
            contract::ExitCode::Findings
        }
    }
}

/// The interrupt checkpoint: have we been asked to stop, and is it safe to?
///
/// Checkpoints go *before* output is produced, never after. A run that has
/// already written its envelope has finished, and retroactively converting a
/// complete, correct answer into "interrupted" would either need a second
/// envelope on stdout or would break the documented promise that `payload.code`
/// is the value the process exits with. Both are worse than a Ctrl-C that
/// arrives microseconds too late.
fn checkpoint() -> bool {
    hold_for_the_signal_test();
    signals::interrupted()
}

/// Parks at the checkpoint so a test can deliver a real SIGINT to a process
/// that is known to still be alive. See [`SIGNAL_HOLD_ENV`].
///
/// The announcement on stderr is the handshake. The test reads it before
/// signalling, which is what makes the SIGINT test a test rather than a race:
/// by the time that line exists the handler is installed, so the signal cannot
/// land in the window between `execve` and the first instruction of `main` and
/// kill the process through the kernel's default disposition. Sleeping a fixed
/// interval instead is what made this flaky - four tests spawn children in
/// parallel and a cold exec on a loaded CI runner outlived any fixed delay.
///
/// **Once per process**, through [`PARKED_ONCE`]. `scan` takes two checkpoints
/// and a walk can take minutes; a test whose signal never landed would
/// otherwise sit out the full hold at each of them. Parking only at the first
/// keeps the hold meaning what the tests that set it mean.
fn hold_for_the_signal_test() {
    let Ok(milliseconds) = env::var(SIGNAL_HOLD_ENV) else {
        return;
    };
    let Ok(milliseconds) = milliseconds.parse::<u64>() else {
        return;
    };
    if PARKED_ONCE.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }

    eprintln!("sim-doctor: {PARKED_MARKER} for {milliseconds}ms");

    if env::var_os(WEDGE_ENV).is_some() {
        loop {
            thread::park();
        }
    }

    let deadline = Instant::now() + Duration::from_millis(milliseconds);
    while Instant::now() < deadline {
        if signals::interrupted() {
            return;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// Makes a card command interruptible even while it is stuck inside an exchange
/// (issue #88).
///
/// The signal handler only sets a flag, and the flag is read between steps, so a
/// PC/SC transmit that never returns would block the run forever. This starts a
/// watchdog thread: once the flag is set it waits [`INTERRUPT_GRACE`] for the
/// command to unwind through its own checkpoints, and if the process is still
/// alive it writes the interrupted envelope and exits 130 itself. Process exit
/// closes the PC/SC socket, which releases the reader.
///
/// Why not `SCardCancel` (`pcsc::Context::cancel`): pcsc-lite documents it as
/// cancelling pending `SCardGetStatusChange` calls only, and a transmit made
/// through a `Card` is not on that path, so it would not unblock this. The
/// watchdog is correct on both macOS and Linux without depending on either
/// daemon's behaviour.
fn guard_exchange(kind: &'static str, json: bool) {
    let _ = thread::Builder::new()
        .name("interrupt-watchdog".into())
        .spawn(move || {
            while !signals::interrupted() {
                thread::sleep(Duration::from_millis(50));
            }
            thread::sleep(INTERRUPT_GRACE);
            let code = report_interrupted(kind, json);
            process::exit(i32::from(code.process_code()));
        });
}

/// Reports an interrupted run and returns [`contract::ExitCode::Interrupted`].
///
/// Exactly one envelope under `--json`, carrying code 130 and an empty `data`,
/// and a note on stderr in either mode. Never a partial result: the reasoning is
/// on [`contract::INTERRUPTED_MESSAGE`], and `tests/process_contract.rs` pins
/// both halves of it.
fn report_interrupted(kind: &str, json: bool) -> contract::ExitCode {
    if INTERRUPT_REPORTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return contract::ExitCode::Interrupted;
    }
    if json {
        // `scan` speaks doctor/1; every other command keeps the lpa envelope.
        let line = if kind == scan::KIND {
            serde_json::to_string(&contract::doctor_failure(
                contract::ExitCode::Interrupted,
                contract::interrupted_data(),
            ))
            .map_err(|err| err.to_string())
        } else {
            contract::Envelope::new(
                kind,
                contract::ExitCode::Interrupted,
                contract::INTERRUPTED_MESSAGE,
                contract::interrupted_data(),
            )
            .to_json()
            .map_err(|err| err.to_string())
        };
        match line {
            Ok(line) => {
                // A failure here does not change the exit code. The operator
                // asked to stop and stopping is what happened; reporting 130
                // while also reporting that stdout was unwritable is the
                // truthful answer, where reporting 1 would claim the run got
                // far enough to have a result.
                if let Err(message) = emit_stdout(&line, "the interrupted envelope") {
                    eprintln!("sim-doctor: {message}");
                }
            }
            Err(err) => eprintln!("sim-doctor: {err}"),
        }
    }

    eprintln!("sim-doctor: interrupted");
    contract::ExitCode::Interrupted
}

/// Renders the module table, as a table or as the JSON envelope.
///
/// `--json` puts the envelope and nothing else on stdout, which is the
/// AGENTS.md section 3 rule. Without it the same data is printed as a table
/// for a person, and the distinction is why the flag is checked here rather
/// than inside the library: formatting for a terminal is the binary job.
///
/// Both branches render into a `String` first and hand it to [`emit_stdout`]
/// as a single write. That keeps a failure halfway through from putting half
/// an envelope on stdout, and it is the reason this function can return the
/// message that explains a write error instead of panicking like `println!`.
fn emit_modules(json: bool) -> Result<(), String> {
    let rendered = if json {
        let data = serde_json::json!({
            "modules": MODULES
                .iter()
                .map(|module| {
                    serde_json::json!({
                        "name": module.name,
                        "owns": module.owns,
                        "depends_on": module.depends_on,
                    })
                })
                .collect::<Vec<_>>(),
        });
        let envelope = contract::Envelope::success(data);
        envelope.to_json().map_err(|e| e.to_string())?
    } else {
        let mut table = String::new();
        table.push_str(&format!("{:<10}  {:<5}  DEPENDS ON\n", "MODULE", "LAYER"));
        for (layer, module) in MODULES.iter().enumerate() {
            let depends = if module.depends_on.is_empty() {
                "-".to_owned()
            } else {
                module.depends_on.join(", ")
            };
            table.push_str(&format!("{:<10}  {:<5}  {}\n", module.name, layer, depends));
        }
        for module in MODULES {
            table.push_str(&format!("\n{}: {}\n", module.name, module.owns));
        }
        table
    };

    emit_stdout(rendered.trim_end_matches('\n'), "the module report")
}

/// Writes one line to stdout, returning the error instead of panicking on it.
///
/// `println!` panics when stdout cannot be written - a closed pipe from
/// `sim-doctor modules --json | head -5` is enough - and a panic is exit code
/// 101, which is not one of the four numbers AGENTS.md section 3 promises. Going
/// through `write_all` is what makes that failure reach a caller as
/// [`contract::ExitCode::Findings`] instead.
///
/// **The `flush` is load-bearing, and its absence is a silent zero.** `stdout()`
/// is a line-buffered writer, so `write_all` returning `Ok` means "accepted into
/// the buffer", not "the bytes reached the stream". Anything still buffered when
/// the command returns is flushed by the standard library's exit-time cleanup,
/// which runs after `main` has already chosen the process exit code and
/// discards the error. A caller of a run whose envelope was never written would
/// therefore get exit 0 and nothing on stdout: the pipe closed, the answer was
/// never delivered, and the status said everything was fine. That is strictly
/// worse for an agent than the `println!` panic this function exists to replace,
/// and it is exactly what
/// `a_run_that_cannot_write_its_report_exits_1_and_explains_itself_on_stderr`
/// exists to catch.
///
/// Whether the buffer happens to be flushed inside `write_all` is not this
/// crate's to rely on. It depends on the payload's size against the buffer's
/// capacity and on how the standard library flushes a completed line, and that
/// has moved between releases and between platforms. Observed both ways: the
/// Ubuntu runner returned 0 where the same binary on macOS returned 1. Flushing
/// explicitly is what makes the property hold on every toolchain.
fn emit_stdout(text: &str, what: &str) -> Result<(), String> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let mut line = String::with_capacity(text.len() + 1);
    line.push_str(text);
    line.push('\n');
    handle
        .write_all(line.as_bytes())
        // Checked rather than chained blindly: a write that failed must not be
        // reported as a flush failure, and a write that succeeded must not be
        // allowed to hide a flush that did not.
        .and_then(|()| handle.flush())
        .map_err(|e| format!("cannot write {what} to stdout: {e}"))
}

/// Runs `sim-doctor install`: write the agent guidance, or with `--print-only` show it.
fn run_install(args: InstallArgs) -> contract::ExitCode {
    let agent = args.agent.as_deref().and_then(skill::Agent::parse);
    let mut printed = String::new();
    for target in skill::targets(agent) {
        if args.print_only {
            printed.push_str(&format!("==> {}\n{}\n", target.path(), target.content()));
        } else {
            match skill::install(&args.dir, target) {
                Ok(path) => println!("wrote {}", path.display()),
                Err(err) => {
                    eprintln!("sim-doctor: cannot write {}: {err}", target.path());
                    return contract::ExitCode::Findings;
                }
            }
        }
    }
    if args.print_only {
        if let Err(message) = emit_stdout(printed.trim_end_matches('\n'), "the skill") {
            eprintln!("sim-doctor: {message}");
            return contract::ExitCode::Findings;
        }
    }
    contract::ExitCode::Success
}

/// Runs `sim-doctor ci install`: plain text, no envelope.
fn run_ci(args: CiArgs) -> contract::ExitCode {
    let CiAction::Install {
        swsim,
        baseline,
        require_baseline,
        severity,
        ref_,
        dir,
        force,
        print_only,
    } = args.action;
    let options = ci::Options {
        swsim: swsim == "true",
        baseline,
        require_baseline: require_baseline == "true",
        severity,
    };
    let ref_ = ref_.unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));
    match ci::install(&dir, &options, &ref_, force, print_only) {
        Ok(ci::InstallOutcome::Printed(text)) => {
            match emit_stdout(text.trim_end_matches('\n'), "the workflow") {
                Ok(()) => contract::ExitCode::Success,
                Err(message) => {
                    eprintln!("sim-doctor: {message}");
                    contract::ExitCode::Findings
                }
            }
        }
        Ok(ci::InstallOutcome::Wrote(path)) => {
            println!("wrote {}", path.display());
            eprintln!(
                "next: commit a baseline first (`sim-doctor scan --json | jq -f scripts/reduce-baseline.jq > {}`), because require-baseline fails the first run without one.",
                options.baseline
            );
            eprintln!("next: the pinned ref {ref_} only exists once that release is tagged.");
            contract::ExitCode::Success
        }
        Ok(ci::InstallOutcome::Unchanged(path)) => {
            println!("unchanged {}", path.display());
            contract::ExitCode::Success
        }
        Err(err @ ci::CiError::Invalid(_)) => {
            eprintln!("sim-doctor: {err}");
            contract::ExitCode::InvalidUsage
        }
        Err(err) => {
            eprintln!("sim-doctor: {err}");
            contract::ExitCode::Findings
        }
    }
}

/// Runs `sim-doctor completions` and returns the exit code for it.
///
/// The script goes to stdout because a completion script *is* the output of
/// this command, exactly as the module table is the output of `modules`. The
/// stdout-purity rule is about `--json`, which this subcommand does not have:
/// a caller piping this into a file wants the script and nothing else.
///
/// Regenerated from [`Cli::command`] on every run rather than shipped as a
/// static file, so a flag that exists and refuses is completable. An agent that
/// types `sim-doctor scan --` and hits tab has to see `--score` - a flag that
/// exists and says "not yet" is the whole point - and a checked-in script would
/// go stale the moment a flag is added.
fn run_completions(args: CompletionsArgs) -> contract::ExitCode {
    let mut command = Cli::command();
    // Read before the mutable borrow: `generate` takes `&mut Command` and calls
    // `build()` on it, so asking it for its own name at the same time is two
    // borrows of one value.
    let bin_name = command.get_name().to_owned();
    let mut script: Vec<u8> = Vec::new();
    generate(args.shell, &mut command, bin_name, &mut script);
    let script = String::from_utf8(script).unwrap_or_else(|_| {
        eprintln!("sim-doctor: the generated completion script is not UTF-8");
        String::new()
    });

    match emit_stdout(script.trim_end_matches('\n'), "the completion script") {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            contract::ExitCode::Findings
        }
    }
}

/// Runs `sim-doctor scan` and returns the exit code for it.
///
/// **The shape of this function is the whole SIGINT/SIGTERM contract (both exit 130).** Two
/// checkpoints, both before anything is written to stdout:
///
/// 1. before a reader is opened, so an operator who hits Ctrl-C while the tool
///    is still finding hardware is not made to wait for a card,
/// 2. after the walk and before the report is rendered, so a walk that
///    finished is either reported in full or reported as interrupted, never as
///    half of a tree.
///
/// There is no third checkpoint, and that is deliberate: a run that has already
/// written its envelope has finished. Retroactively converting a complete,
/// correct answer into "interrupted" would need a second envelope on stdout or
/// would break the promise that `exit_code` is the value the process exits
/// with. See [`report_interrupted`] and CONTEXT.md section 3.
///
/// **A `--baseline` run reads its baseline before it opens a reader**, so a file
/// this build cannot read is refused in milliseconds rather than after a walk
/// it was never going to need. See the comment at the top of the body.
///
/// The JSON is the doctor/1 envelope, and its `exit_code` is decided here (see
/// [`scan::Verdict::exit_code`]) before it is rendered. `--score`, `--severity`,
/// `--baseline` and `--fail-on` are all implemented. There
/// is no flag left on the surface whose behaviour is deferred, and the
/// refusal that used to stand in for them is now reached only by real failures
/// - no card, an unreadable baseline, an incomparable pair.
fn run_scan(args: ScanArgs) -> contract::ExitCode {
    guard_exchange(scan::KIND, args.json);
    // A flag's own shape is refused before a reader is opened, as clap would.
    if args.terminal_profile && matches!(args.tar.mode, tar::Mode::Off) {
        eprintln!("sim-doctor: --terminal-profile is only meaningful with --tar other than off");
        return contract::ExitCode::Error;
    }
    // Read the baseline before a reader is opened, and refuse before one is.
    // A --baseline naming a file that is not there, is not a doctor/1 envelope,
    // or is over a bound has an answer before a card exists, and an agent
    // scripting against this tool deserves it in milliseconds rather than after
    // a walk it was never going to need. The rules that depend on BOTH runs
    // necessarily wait, because they cannot be known until there is something to
    // compare against.
    let saved = match &args.baseline {
        Some(path) => match baseline::Baseline::load(path) {
            Ok(saved) => Some(saved),
            Err(err) => {
                return report_scan_failure(
                    &scan::Failure::new(err.kind(), err.to_string()),
                    args.json,
                )
            }
        },
        None => None,
    };

    if let (Some(a), Some(b)) = (&args.sarif, &args.baseline) {
        if a == b {
            return report_scan_failure(
                &scan::Failure::new(
                    "sarif-baseline-same-path",
                    format!(
                        "--sarif and --baseline both name {}; the SARIF file would destroy the baseline",
                        a.display()
                    ),
                ),
                args.json,
            );
        }
    }

    if checkpoint() {
        return report_interrupted(scan::KIND, args.json);
    }

    let readers = match Pcsc::readers() {
        Ok(readers) => readers,
        Err(err) => {
            return report_scan_failure(
                &scan::Failure::new("context-unavailable", err.to_string()),
                args.json,
            )
        }
    };

    let reader = match pick_reader(&readers, args.reader.as_deref()) {
        Ok(reader) => reader,
        Err(failure) => return report_scan_failure(&failure, args.json),
    };

    let session = match PcscSession::open(reader) {
        Ok(session) => session,
        Err(err) => {
            let kind = match err {
                TransportError::NoCard { .. } => "no-card",
                _ => "reader-unavailable",
            };
            return report_scan_failure(&scan::Failure::new(kind, err.to_string()), args.json);
        }
    };

    // Best effort. An ATR this transport could not read is a fact about the
    // session, not a reason to refuse to scan a card that is otherwise
    // answering, so it is Option rather than an error. A reader that cannot
    // even be opened has already failed above.
    let atr = session.atr().ok();

    // Opt-in capture for issue #120: SIM_DOCTOR_RECORD=<path> logs every
    // exchange of this scan (JSON lines, see transport::replay). The log is
    // raw card output; it is never written unless the operator asks.
    let mut session: Box<dyn CardSession> = match std::env::var_os("SIM_DOCTOR_RECORD") {
        Some(path) => match record_log_file(&path) {
            Ok(file) => Box::new(replay::Record::new(session, file)),
            Err(err) => {
                return report_scan_failure(
                    &scan::Failure::new(
                        "record-log-unwritable",
                        format!("SIM_DOCTOR_RECORD {}: {err}", path.to_string_lossy()),
                    ),
                    args.json,
                )
            }
        },
        None => Box::new(session),
    };

    let options = walk::Options {
        addressing: walk::Addressing::PathFromMasterFile,
        // Spelled out rather than inherited: this is the set that can miss a
        // file, and the line that decides that belongs where the walk is built.
        candidates: walk::Candidates::SimFamilies,
        // Only 6A 82 is classified. Nothing else is, because this repository has
        // read no other table; see walk::StatusMeaning and CONTEXT.md section 3.
        meaning: walk::StatusMeaning::default(),
        limits: limits_from(&args.walk_limits),
        ..walk::Options::default()
    };

    let mut tree = match walk::walk(&mut *session, &args.dialect.tag_set(), &options) {
        Ok(tree) => tree,
        Err(err) => {
            return report_scan_failure(
                &scan::Failure::new("walk-failed", err.to_string()),
                args.json,
            )
        }
    };

    // EF.ARR, read-only (SELECT and READ RECORD), so that the access rules the
    // FCPs only reference can be decoded by the rules.
    if let Err(err) = access::resolve(&mut *session, &mut tree, &session::Policy::default()) {
        return report_scan_failure(
            &scan::Failure::new("access-rules-failed", err.to_string()),
            args.json,
        );
    }

    // The security-relevant EFs' contents, read-only (SELECT, READ BINARY, READ
    // RECORD), decoded later and shown in full (key files included).
    if let Err(err) = ef::read(&mut *session, &mut tree, &session::Policy::default()) {
        return report_scan_failure(
            &scan::Failure::new("ef-read-failed", err.to_string()),
            args.json,
        );
    }

    // The second of three checkpoints. Everything the tree knows is still only
    // in memory here, so stopping now costs the whole run rather than emitting
    // something a caller could mistake for a result.
    if checkpoint() {
        return report_interrupted(scan::KIND, args.json);
    }

    // The TAR audit, over the same live session. It is the longest part of a
    // scan after the walk, so `tar::audit` polls signals::interrupted()
    // before every probe: a Ctrl-C during a full sweep is acted on rather than
    // queued. A TAR probe is an ENVELOPE, and swSIM answers every one with
    // `61 Lc` before reading a byte of it, so the default selection is
    // 592 probes of two exchanges each - see src/tar.rs, which is where the
    // wire sequence, the bound and the differential are argued.
    let audit = match tar::audit_with(
        &mut *session,
        &args.tar,
        &session::Policy::default(),
        args.terminal_profile,
        &mut || signals::interrupted(),
    ) {
        Ok(audit) => audit,
        Err(err) => {
            return report_scan_failure(
                &scan::Failure::new("tar-audit-failed", err.to_string()),
                args.json,
            )
        }
    };

    // The third and last checkpoint, and it exists because of the line above:
    // an interrupted TAR scan must be reported as interrupted, never rendered
    // as a shorter audit. A report that says "8 of 4096 TARs probed" and exits
    // 0 is a card reported as having passed 4096 probes never made.
    if checkpoint() {
        return report_interrupted(scan::KIND, args.json);
    }

    // The rules, over both halves of the scan: the tree that is still in
    // memory, and the TAR evidence that was just measured.
    let found = match scan::findings(&scan::Subject {
        tree: &tree,
        tar: &audit,
        scp03: None,
    }) {
        Ok(found) => found,
        Err(err) => {
            return report_scan_failure(
                &scan::Failure::new("rule-misattribution", err.to_string()),
                args.json,
            )
        }
    };

    // Filtered before it is scored, and the score taken from what is left:
    // the number in the report is a function of the findings in the report.
    let mut verdict = scan::Verdict::new(found, scan::rules_run())
        .tar_audit(audit)
        .at_least(args.severity)
        .scored(args.score);

    let context = scan::Context::new(
        reader.as_str(),
        atr.as_deref(),
        args.dialect,
        options.candidates.clone(),
        options.limits,
    );

    // What this run actually did, which is what a baseline has to record and
    // what a comparison is allowed to assume. Built from the tree and the
    // verdict rather than from the flags, so it cannot describe a walk that
    // did not happen.
    let facts = scan::run_facts(&tree, &context, &verdict);

    // Compared last, and REFUSED rather than reported when the two runs cannot
    // honestly be compared. Every refusal here is the same shape as "no
    // reader": data.error, exit 2, no findings and no data.diff.
    if let Some(saved) = saved {
        match baseline::Diff::compare(&saved, &facts, verdict.findings().as_slice()) {
            Ok(diff) => {
                eprintln!(
                    "sim-doctor: compared against the baseline: {} new, {} fixed, {} persisting",
                    diff.new_findings().len(),
                    diff.fixed().len(),
                    diff.persisting().len(),
                );
                if let Some(warning) = diff.rules_warning() {
                    eprintln!("sim-doctor: warning: {warning}");
                }
                verdict = verdict.compared_against(diff);
            }
            Err(incomparable) => {
                return report_scan_failure(
                    &scan::Failure::new(incomparable.kind(), incomparable.explain(&saved, &facts)),
                    args.json,
                );
            }
        }
    }

    // SARIF first, because the envelope carries the exit code and a failed
    // SARIF write is a run error (exit 2). The report is still printed below:
    // a SARIF failure never costs the caller the report.
    let mut exit_code = verdict.exit_code(args.fail_on);
    if let Some(path) = &args.sarif {
        let score = scan::doctor_score(&tree, &context, &verdict, &facts);
        let doc = sarif::to_sarif(verdict.findings().as_slice(), &scan::specs(), &score);
        if let Err(error) = sarif::write(path, &doc) {
            // stderr only: stdout stays one envelope.
            eprintln!(
                "sim-doctor: sarif-unwritable: could not write SARIF to {}: {error}",
                path.display()
            );
            exit_code = contract::ExitCode::Error;
        }
    }

    // Assembled, then written once, so a failure halfway through cannot put
    // half an envelope on stdout. See emit_stdout.
    let mut shown_in_tui = false;
    let rendered = if args.json {
        let document = scan::doctor_json(&tree, &context, &verdict, &facts, exit_code);
        match serde_json::to_string(&document) {
            Ok(line) => line,
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Error;
            }
        }
    } else if args.tui && io::stdin().is_terminal() && io::stdout().is_terminal() {
        // The view is the output: nothing goes to stdout but the terminal UI.
        let data = scan::to_json(&tree, &context, &verdict);
        // A failed view must not skip the stderr warnings below, and must not
        // change the exit status: say so and carry on.
        if let Err(err) = sim_doctor::tui::run(&data) {
            eprintln!("sim-doctor: tui: {err}");
        }
        shown_in_tui = true;
        String::new()
    } else {
        if args.tui {
            eprintln!("sim-doctor: --tui needs a terminal; showing the plain report");
        }
        scan::to_human(&tree, &context, &verdict)
    };

    // One line on stderr for a truncated walk, in BOTH modes, on top of the
    // banner and the JSON fields. Under --json stdout is the envelope, so this
    // is where a human watching a CI log learns the answer is partial without
    // having to pipe the envelope through a formatter first.
    if !tree.is_complete() {
        let hit: Vec<String> = tree
            .limits_hit()
            .iter()
            .copied()
            .map(|limit| limit.to_string())
            .collect();
        eprintln!(
            "sim-doctor: warning: the walk stopped early, so this is not the whole card; \
             bounds hit: {}",
            if hit.is_empty() {
                "none recorded".to_owned()
            } else {
                hit.join(", ")
            }
        );
    }

    // One line on stderr for a TAR scan that did not finish, in BOTH modes,
    // for the same reason the walk has one: under --json stdout is the
    // envelope, and an agent reading it has to be able to see that the TAR
    // audit stopped early without piping it through a formatter first.
    if let Some(reason) = verdict.tar().stopped.as_deref() {
        eprintln!(
            "sim-doctor: warning: the TAR scan did not finish, so its findings are partial: {reason}"
        );
    }

    let what = if args.json {
        "the scan envelope"
    } else {
        "the scan report"
    };
    let emitted = if shown_in_tui {
        Ok(())
    } else {
        emit_stdout(rendered.trim_end_matches('\n'), what)
    };

    match emitted {
        Ok(()) => exit_code,
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            contract::ExitCode::Error
        }
    }
}

/// `sim-doctor gp <info|ara|status>`: one read-only GlobalPlatform pass over one card.
fn run_gp(
    what: &str,
    reader: Option<&str>,
    json: bool,
    trace: bool,
    pass: impl FnOnce(&mut PcscSession, bool) -> Result<gp::Report, session::Error>,
) -> contract::ExitCode {
    const KIND: &str = "gp";
    guard_exchange(KIND, json);
    let refuse =
        |failure: scan::Failure| report_refusal(KIND, &failure.message, failure.data(), json);
    let readers = match Pcsc::readers() {
        Ok(readers) => readers,
        Err(err) => return refuse(scan::Failure::new("context-unavailable", err.to_string())),
    };
    let reader = match pick_reader(&readers, reader) {
        Ok(reader) => reader,
        Err(failure) => return refuse(failure),
    };
    let mut session = match PcscSession::open(reader) {
        Ok(session) => session,
        Err(err) => {
            let kind = match err {
                TransportError::NoCard { .. } => "no-card",
                _ => "reader-unavailable",
            };
            return refuse(scan::Failure::new(kind, err.to_string()));
        }
    };
    let report = match pass(&mut session, trace) {
        Ok(report) => report,
        Err(err) => return refuse(scan::Failure::new("gp-exchange-failed", err.to_string())),
    };
    let mut data = report.data;
    data["reader"] = serde_json::json!(reader.as_str());
    // An error the pass itself recorded (an authentication that stopped) wins.
    if let Some(message) = data["error"]["message"].as_str().map(str::to_owned) {
        return report_refusal(KIND, &message, data, json);
    }
    if !report.isd_found {
        let (kind, message) = match what {
            "gp ara" => ("ara-m-not-found", "no ARA-M answered SELECT at its AID"),
            "gp select" => (
                "aid-not-found",
                "no application answered SELECT at that AID",
            ),
            _ => (
                "isd-not-found",
                "no issuer security domain answered SELECT at either AID",
            ),
        };
        data["error"] = serde_json::json!({ "kind": kind, "message": message });
        return report_refusal(KIND, message, data, json);
    }
    let rendered = if json {
        match contract::Envelope::new(
            KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        )
        .to_json()
        {
            Ok(line) => line,
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Findings;
            }
        }
    } else if what == "gp info" {
        serde_json::to_string_pretty(&data).unwrap_or_default()
    } else {
        gp::render_text(&data)
    };
    if let Err(err) = emit_stdout(&rendered, &format!("the {what} report")) {
        eprintln!("sim-doctor: {err}");
        return contract::ExitCode::Findings;
    }
    contract::ExitCode::Success
}

/// `sim-doctor gp status [--keys-file PATH | --keys-env VAR]`. The keys are read
/// and checked (format, stated KCVs) before a reader is opened, so a typo costs
/// the card nothing. The host challenge is fresh per run.
fn run_gp_status(
    reader: Option<&str>,
    json: bool,
    trace: bool,
    args: &GpKeyArgs,
) -> contract::ExitCode {
    let source = match (&args.keys_file, &args.keys_env) {
        (Some(path), _) => Some(gp::KeySource::File(path)),
        (None, Some(name)) => Some(gp::KeySource::Env(name)),
        (None, None) => None,
    };
    let Some(source) = source else {
        return run_gp("gp status", reader, json, trace, gp::status);
    };
    let keys = match gp::Keys::load(source) {
        Ok(keys) => keys,
        Err(err) => {
            let kind = match err {
                gp::KeyError::Kcv { .. } => "key-kcv-mismatch",
                _ => "keys-unusable",
            };
            let message = err.to_string();
            let data = serde_json::json!({ "error": { "kind": kind, "message": message } });
            return report_refusal("gp", &message, data, json);
        }
    };
    let mut host_challenge = [0u8; 8];
    rand::fill(&mut host_challenge);
    let auth = gp::Auth {
        keys: &keys,
        key_version: args.key_version,
        host_challenge,
    };
    run_gp("gp status", reader, json, trace, |s, t| {
        gp::status_authenticated(s, t, &auth)
    })
}

/// `sim-doctor euicc <info|profiles|notifications>`: one read-only ES10 query.
fn run_euicc(query: euicc::Query, flags: &EuiccFlags) -> contract::ExitCode {
    let max = usize::from(flags.max_segment);
    run_euicc_op(
        flags,
        |session, aid| euicc::run_with(session, aid, query, max),
        |data| euicc::to_human(query, data),
    )
}

/// `sim-doctor euicc nickname <iccid> <name> [--yes]`: SetNickname, a dry run
/// unless `--yes`. The ICCID and name are checked before a reader is opened.
fn run_euicc_nickname(args: &NicknameArgs) -> contract::ExitCode {
    let request = match euicc::Nickname::new(&args.iccid, &args.name, args.yes) {
        Ok(request) => request,
        Err(f) => {
            return report_refusal(contract::DEFAULT_KIND, &f.message, f.data, args.flags.json)
        }
    };
    let max = usize::from(args.flags.max_segment);
    run_euicc_op(
        &args.flags,
        |session, aid| euicc::nickname(session, aid, max, &request),
        euicc::nickname_to_human,
    )
}

/// `sim-doctor euicc <enable|disable> <iccid|aid> [--yes]`: a dry run unless
/// `--yes`. The identifier is checked before a reader is opened.
fn run_euicc_state(action: euicc::Action, args: &StateArgs) -> contract::ExitCode {
    let request = match euicc::StateChange::new(action, &args.id, args.yes) {
        Ok(request) => request,
        Err(f) => {
            return report_refusal(contract::DEFAULT_KIND, &f.message, f.data, args.flags.json)
        }
    };
    let max = usize::from(args.flags.max_segment);
    run_euicc_op(
        &args.flags,
        |session, aid| euicc::set_state(session, aid, max, &request),
        euicc::state_to_human,
    )
}

/// `sim-doctor euicc delete <iccid|aid> [--yes]`: a dry run unless `--yes`.
fn run_euicc_delete(args: &DeleteArgs) -> contract::ExitCode {
    let request = match euicc::ProfileDelete::new(&args.id, args.yes) {
        Ok(request) => request,
        Err(f) => {
            return report_refusal(contract::DEFAULT_KIND, &f.message, f.data, args.flags.json)
        }
    };
    let max = usize::from(args.flags.max_segment);
    run_euicc_op(
        &args.flags,
        |session, aid| euicc::delete_profile(session, aid, max, &request),
        euicc::erase_to_human,
    )
}

/// `sim-doctor euicc reset [--operational] [--test] [--smdp-address]
/// [--confirm-eid EID] [--yes]`. Options and confirmation are checked before a
/// reader is opened.
fn run_euicc_reset(args: &ResetArgs) -> contract::ExitCode {
    let options = sim_doctor::es10::ResetOptions {
        delete_operational_profiles: args.operational,
        delete_field_loaded_test_profiles: args.test,
        reset_default_smdp_address: args.smdp_address,
    };
    let request = match euicc::MemoryReset::new(options, args.confirm_eid.as_deref(), args.yes) {
        Ok(request) => request,
        Err(f) => {
            return report_refusal(contract::DEFAULT_KIND, &f.message, f.data, args.flags.json)
        }
    };
    let max = usize::from(args.flags.max_segment);
    run_euicc_op(
        &args.flags,
        |session, aid| euicc::memory_reset(session, aid, max, &request),
        euicc::erase_to_human,
    )
}

/// `sim-doctor euicc notifications remove <seq> [--yes]`: a dry run unless `--yes`.
fn run_euicc_remove(args: &RemoveArgs) -> contract::ExitCode {
    let request = euicc::NotificationRemoval {
        seq_number: args.seq,
        apply: args.yes,
    };
    let max = usize::from(args.flags.max_segment);
    run_euicc_op(
        &args.flags,
        |session, aid| euicc::remove_notification(session, aid, max, request),
        euicc::erase_to_human,
    )
}

/// Connects to the reader and card named by `flags`, runs `op` against the
/// ISD-R, and prints its data (lpac envelope under `--json`, else `human`).
fn run_euicc_op(
    flags: &EuiccFlags,
    op: impl FnOnce(&mut PcscSession, &[u8]) -> Result<serde_json::Value, euicc::Failure>,
    human: impl FnOnce(&serde_json::Value) -> String,
) -> contract::ExitCode {
    const KIND: &str = contract::DEFAULT_KIND;
    let json = flags.json;
    guard_exchange(KIND, json);
    let refuse =
        |failure: scan::Failure| report_refusal(KIND, &failure.message, failure.data(), json);
    let aid = match flags.aid.as_deref() {
        None => euicc::ISDR_AID.to_vec(),
        Some(text) => match hex::decode(text) {
            Ok(aid) if (5..=16).contains(&aid.len()) => aid,
            _ => {
                return refuse(scan::Failure::new(
                    "bad-aid",
                    format!("--aid must be 5 to 16 bytes of hex, got {text:?}"),
                ))
            }
        },
    };
    let readers = match Pcsc::readers() {
        Ok(readers) => readers,
        Err(err) => return refuse(scan::Failure::new("context-unavailable", err.to_string())),
    };
    let reader = match pick_reader(&readers, flags.reader.as_deref()) {
        Ok(reader) => reader,
        Err(failure) => return refuse(failure),
    };
    let mut session = match PcscSession::open(reader) {
        Ok(session) => session,
        Err(err) => {
            let kind = match err {
                TransportError::NoCard { .. } => "no-card",
                _ => "reader-unavailable",
            };
            return refuse(scan::Failure::new(kind, err.to_string()));
        }
    };
    let mut data = match op(&mut session, &aid) {
        Ok(data) => data,
        Err(failure) => {
            let mut data = failure.data;
            data["reader"] = serde_json::json!(reader.as_str());
            return report_refusal(KIND, &failure.message, data, json);
        }
    };
    data["reader"] = serde_json::json!(reader.as_str());
    let rendered = if json {
        match contract::Envelope::new(
            KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        )
        .to_json()
        {
            Ok(line) => line,
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Findings;
            }
        }
    } else {
        human(&data).trim_end().to_owned()
    };
    if let Err(err) = emit_stdout(&rendered, "the euicc report") {
        eprintln!("sim-doctor: {err}");
        return contract::ExitCode::Findings;
    }
    contract::ExitCode::Success
}

/// `sim-doctor trace`: decode a saved APDU trace. Touches no card.
fn run_trace(args: &TraceArgs) -> contract::ExitCode {
    use std::io::Read;
    const KIND: &str = "trace";
    let refuse = |m: String| report_refusal(KIND, &m, serde_json::json!({ "error": m }), args.json);
    let mut input = Vec::new();
    let read = match args.file.as_deref() {
        None | Some("-") => io::stdin().take(MAX_WHY_FILE_BYTES).read_to_end(&mut input),
        Some(path) => std::fs::File::open(path)
            .and_then(|f| f.take(MAX_WHY_FILE_BYTES).read_to_end(&mut input)),
    };
    if let Err(err) = read {
        return refuse(format!("cannot read the trace: {err}"));
    }
    let rows = match trace::parse_bytes(&input) {
        Ok(pairs) => trace::decode(&pairs),
        Err(message) => return refuse(message),
    };
    if rows.last().is_some_and(|r| r.response.is_empty()) {
        eprintln!("sim-doctor: warning: the trace ends on a command with no response (odd number of hex lines?)");
    }
    let rendered = if args.json {
        let exchanges: Vec<_> = rows
            .iter()
            .enumerate()
            .map(|(i, r)| r.to_json(i + 1))
            .collect();
        let data = serde_json::json!({
            "card_touched": false,
            "count": rows.len(),
            "selected": rows.last().map(|r| r.selected.clone()),
            "exchanges": exchanges,
        });
        match contract::Envelope::new(
            KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        )
        .to_json()
        {
            Ok(line) => line,
            Err(err) => return refuse(err.to_string()),
        }
    } else {
        trace::render(&rows).trim_end().to_owned()
    };
    match emit_stdout(&rendered, "the decoded trace") {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => refuse(message),
    }
}

/// Every rule `rules list`, `rules explain`, `why` and `fix` know: the scan's,
/// then the TS.48 comparison's. A scan still runs and scores only its own.
fn all_specs() -> Vec<rules::RuleSpec> {
    scan::all_specs()
}

/// Runs `sim-doctor ts48 compare`: the scan's walk, then the diff.
///
/// The walk is the one `run_scan` does (same candidates, same status meaning,
/// same default bounds, same walk-limit flags) and nothing after it touches the card: no TAR audit.
fn run_ts48_compare(args: Ts48CompareArgs) -> contract::ExitCode {
    guard_exchange(ts48::KIND, args.json);
    let fixture = match ts48::Fixture::bundled() {
        Ok(fixture) => fixture,
        Err(err) => {
            return report_refusal(
                ts48::KIND,
                &format!("the bundled TS.48 file list is unreadable: {err}"),
                serde_json::json!({ "error": { "kind": "fixture-unreadable" } }),
                args.json,
            )
        }
    };
    let refuse = |failure: scan::Failure| {
        report_refusal(ts48::KIND, &failure.message, failure.data(), args.json)
    };

    if checkpoint() {
        return report_interrupted(ts48::KIND, args.json);
    }
    let readers = match Pcsc::readers() {
        Ok(readers) => readers,
        Err(err) => return refuse(scan::Failure::new("context-unavailable", err.to_string())),
    };
    let reader = match pick_reader(&readers, args.reader.as_deref()) {
        Ok(reader) => reader,
        Err(failure) => return refuse(failure),
    };
    let mut session = match PcscSession::open(reader) {
        Ok(session) => session,
        Err(err) => {
            let kind = match err {
                TransportError::NoCard { .. } => "no-card",
                _ => "reader-unavailable",
            };
            return refuse(scan::Failure::new(kind, err.to_string()));
        }
    };

    let options = walk::Options {
        addressing: walk::Addressing::PathFromMasterFile,
        candidates: walk::Candidates::SimFamilies,
        meaning: walk::StatusMeaning::default(),
        limits: limits_from(&args.walk_limits),
        ..walk::Options::default()
    };
    let tree = match walk::walk(&mut session, &args.dialect.tag_set(), &options) {
        Ok(tree) => tree,
        Err(err) => return refuse(scan::Failure::new("walk-failed", err.to_string())),
    };
    if checkpoint() {
        return report_interrupted(ts48::KIND, args.json);
    }

    let comparison = ts48::compare(&fixture.files, &ts48::observe(&tree));
    let complete = tree.is_complete();
    let findings = ts48::findings(
        &comparison,
        (!complete).then_some("the walk stopped at a bound, so this list may be short"),
    );
    if !complete {
        eprintln!("sim-doctor: warning: the walk stopped early, so this is not the whole card");
    }

    let (rendered, what) = if args.json {
        let data = ts48::to_json(
            &fixture,
            &comparison,
            &findings,
            reader.as_str(),
            args.dialect.id(),
            complete,
        );
        let envelope = contract::Envelope::new(
            ts48::KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        );
        match envelope.to_json() {
            Ok(line) => (line, "the ts48 envelope"),
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Findings;
            }
        }
    } else {
        (
            ts48::to_human(&comparison, &findings, complete),
            "the ts48 report",
        )
    };
    match emit_stdout(rendered.trim_end_matches('\n'), what) {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            contract::ExitCode::Findings
        }
    }
}

/// The fragment swicc-pcsc names its reader with.
///
/// \[V] docs/swsim-fixture.md: "Expect a reader whose name contains swICC",
/// and every other place in this crate that matches the software card's
/// reader (`tests/card_fixture.rs`) does it the same way: a case-insensitive
/// substring match, because the exact spelling is not part of swicc-pcsc's
/// contract and this crate does not own it.
const SWICC_READER_FRAGMENT: &str = "swicc";

/// Error kind every `fuzz` opt-in refusal carries.
const FUZZ_OPT_IN_KIND: &str = "fuzz-needs-opt-in";

/// The mandatory safety interlock on every `fuzz` subcommand (issue #16).
///
/// Refuses, with [`FUZZ_OPT_IN_KIND`], unless BOTH
/// `--i-understand-this-can-brick-the-card` is given AND the reader's name
/// matches the software card, or `--allow-real-hardware` is also given.
///
/// **Deterministic, and never touches PC/SC.** `reader` is the raw
/// `--reader` string the command line carried, not a name read back from an
/// opened session - so this decision never depends on what hardware happens
/// to be attached to the machine running it, only on what was typed. An
/// omitted `--reader` is treated as "not recognisably the software card",
/// the same as a name that does not match: this is the side to be wrong on,
/// since the alternative is listing readers to find out what the default
/// would have been, which is exactly the PC/SC round trip this check exists
/// to run only once the interlock has already passed.
fn fuzz_opt_in(safety: &FuzzSafety, reader: Option<&str>) -> Result<(), String> {
    if !safety.i_understand {
        return Err(
            "fuzz refuses to run without --i-understand-this-can-brick-the-card: a fuzz run \
             sends undocumented CLA/INS values and OTA envelopes that can brick a SIM"
                .to_owned(),
        );
    }
    let is_software =
        reader.is_some_and(|name| name.to_ascii_lowercase().contains(SWICC_READER_FRAGMENT));
    if !is_software && !safety.allow_real_hardware {
        return Err(format!(
            "fuzz refuses to run against {:?}: it does not look like the software card \
             (swicc-pcsc names its reader with \"swICC\", see docs/swsim-fixture.md); pass \
             --allow-real-hardware to run against it anyway",
            reader.unwrap_or("(no --reader given)")
        ));
    }
    Ok(())
}

/// Opens the reader `safety` and `kind` agree to open, or returns the exit
/// code of a refusal.
///
/// Shared by `fuzz apdu` and `fuzz ota`: the opt-in check, then the same
/// reader-listing and reader-opening path `run_scan` and `run_ts48_compare`
/// use, so a fuzz refusal is the same shape as every other refusal in this
/// crate - `data.error`, exit 1, no `data.findings`.
///
/// **The interlock runs once, first, against the raw `--reader` string.**
/// [`fuzz_opt_in`] never needs PC/SC to answer, so it is checked - and can
/// refuse - before [`Pcsc::readers`] is even called, which is what makes the
/// refusal deterministic: it depends only on the command line, never on
/// which readers happen to be attached to the machine running it.
fn open_fuzz_session(
    kind: &str,
    safety: &FuzzSafety,
) -> Result<(ReaderName, PcscSession), contract::ExitCode> {
    if let Err(message) = fuzz_opt_in(safety, safety.reader.as_deref()) {
        return Err(report_refusal(
            kind,
            &message,
            serde_json::json!({ "error": { "kind": FUZZ_OPT_IN_KIND, "message": message } }),
            safety.json,
        ));
    }
    if checkpoint() {
        return Err(report_interrupted(kind, safety.json));
    }
    let readers = match Pcsc::readers() {
        Ok(readers) => readers,
        Err(err) => {
            return Err(report_failure(
                &scan::Failure::new("context-unavailable", err.to_string()),
                safety.json,
            ))
        }
    };
    let reader = match pick_reader(&readers, safety.reader.as_deref()) {
        Ok(reader) => reader.clone(),
        Err(failure) => return Err(report_failure(&failure, safety.json)),
    };
    let session = match PcscSession::open(&reader) {
        Ok(session) => session,
        Err(err) => {
            let failure_kind = match err {
                TransportError::NoCard { .. } => "no-card",
                _ => "reader-unavailable",
            };
            return Err(report_failure(
                &scan::Failure::new(failure_kind, err.to_string()),
                safety.json,
            ));
        }
    };
    Ok((reader, session))
}

/// Creates (truncating) the `SIM_DOCTOR_RECORD` log. Its content is sensitive
/// raw card data (ICCID, IMSI, file contents), so on unix it is owner-only 0600.
fn record_log_file(path: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Runs `sim-doctor fuzz apdu`: CLA discovery (level 1) or CLA+INS discovery
/// (level 2), behind the safety interlock.
fn run_fuzz_apdu(args: FuzzApduArgs) -> contract::ExitCode {
    // The opt-in flag is the very first gate: a run missing it is refused
    // before any other flag, including --class, is even looked at. The
    // reader-matches-the-software-card half of the interlock needs a reader
    // to check against, so it waits for `open_fuzz_session`.
    if !args.safety.i_understand {
        return report_refusal(
            apdu_scan::KIND,
            &fuzz_opt_in(&args.safety, None).unwrap_err(),
            serde_json::json!({ "error": { "kind": FUZZ_OPT_IN_KIND } }),
            args.safety.json,
        );
    }

    let mode = if args.safety.quick {
        apdu_scan::Mode::Quick
    } else {
        apdu_scan::Mode::Full
    };

    // A bad or missing --class is a command-line mistake, not a card fact, so
    // it is caught before a reader is even listed - the same reason
    // `pick_reader` is exit 1 rather than 129 but a flag's own shape is
    // caught before either runs.
    let class = if args.level == 2 {
        let Some(class_text) = &args.class else {
            return report_refusal(
                apdu_scan::KIND,
                "--level 2 needs --class HEX, the CLA to probe INS values at",
                serde_json::json!({ "error": { "kind": "missing-class" } }),
                args.safety.json,
            );
        };
        match u8::from_str_radix(class_text.trim_start_matches("0x"), 16) {
            Ok(class) => Some(class),
            Err(_) => {
                return report_refusal(
                    apdu_scan::KIND,
                    &format!("{class_text:?} is not a CLA byte; expected two hex digits, e.g. A0"),
                    serde_json::json!({ "error": { "kind": "bad-class" } }),
                    args.safety.json,
                )
            }
        }
    } else {
        None
    };

    let (reader, mut session) = match open_fuzz_session(apdu_scan::KIND, &args.safety) {
        Ok(opened) => opened,
        Err(code) => return code,
    };

    // A single candidate can leave the PC/SC transaction unusable without
    // the card itself having gone anywhere - observed against the real
    // swSIM fixture - so discovery survives that rather than aborting the
    // whole run: `reconnect` re-opens the session in place, bounded by
    // `apdu_scan::MAX_RECONNECTS`. See `apdu_scan::sweep`.
    let mut reconnect = |session: &mut PcscSession| -> Result<(), TransportError> {
        *session = PcscSession::open(&reader)?;
        Ok(())
    };

    if let Some(class) = class {
        let audit =
            apdu_scan::ins_discovery(&mut session, class, mode, &mut reconnect, &mut || {
                signals::interrupted()
            });
        let findings = apdu_scan::ins_findings(&audit);
        emit_fuzz_report(
            apdu_scan::KIND,
            reader.as_str(),
            audit.to_json(),
            &findings,
            args.safety.json,
        )
    } else {
        let audit = apdu_scan::cla_discovery(&mut session, mode, &mut reconnect, &mut || {
            signals::interrupted()
        });
        let findings = apdu_scan::cla_findings(&audit);
        emit_fuzz_report(
            apdu_scan::KIND,
            reader.as_str(),
            audit.to_json(),
            &findings,
            args.safety.json,
        )
    }
}

/// Runs `sim-doctor fuzz mutate`: replay log or mock card only.
fn run_fuzz_mutate(args: FuzzMutateArgs) -> contract::ExitCode {
    let config = match apdu_fuzz::Config::new(
        args.seed,
        args.max_cases,
        args.timeout.map(Duration::from_secs),
        args.stop_on_first_finding,
    ) {
        Ok(config) => config,
        Err(message) => {
            return report_refusal(
                apdu_fuzz::KIND,
                &message,
                serde_json::json!({ "error": { "kind": "bad-max-cases" } }),
                args.json,
            )
        }
    };
    if args.dry_run && !args.json {
        let plan = apdu_fuzz::plan_json(&config);
        let mut text = String::from("fuzz mutate dry run: nothing is sent\n");
        text.push_str(&format!("allowed INS: {}\n", plan["allowed_ins"]));
        for case in plan["planned"].as_array().into_iter().flatten() {
            text.push_str(&format!(
                "{} {} {}\n",
                case["index"], case["kind"], case["command"]
            ));
        }
        return match emit_stdout(text.trim_end_matches('\n'), "the fuzz plan") {
            Ok(()) => contract::ExitCode::Success,
            Err(message) => {
                eprintln!("sim-doctor: {message}");
                contract::ExitCode::Findings
            }
        };
    }
    if args.dry_run {
        return emit_fuzz_report(
            apdu_fuzz::KIND,
            "(dry run)",
            apdu_fuzz::plan_json(&config),
            &[],
            args.json,
        );
    }
    let run = if args.mock {
        apdu_fuzz::run(&mut apdu_fuzz::MockCard::strict(), &config, &mut || {
            signals::interrupted()
        })
    } else if let Some(path) = &args.replay {
        let log = match std::fs::read_to_string(path) {
            Ok(log) => log,
            Err(err) => {
                return report_refusal(
                    apdu_fuzz::KIND,
                    &format!("cannot read {}: {err}", path.display()),
                    serde_json::json!({ "error": { "kind": "bad-replay" } }),
                    args.json,
                )
            }
        };
        let mut replay = match replay::Replay::from_log(&log) {
            Ok(replay) => replay,
            Err(err) => {
                return report_refusal(
                    apdu_fuzz::KIND,
                    &err,
                    serde_json::json!({ "error": { "kind": "bad-replay" } }),
                    args.json,
                )
            }
        };
        apdu_fuzz::run(&mut replay, &config, &mut || signals::interrupted())
    } else {
        return report_refusal(
            apdu_fuzz::KIND,
            "fuzz mutate needs --replay FILE, --mock or --dry-run; it has no real-reader path",
            serde_json::json!({ "error": { "kind": "no-source" } }),
            args.json,
        );
    };
    let findings = apdu_fuzz::findings(&run);
    emit_fuzz_report(
        apdu_fuzz::KIND,
        if args.mock { "mock" } else { "replay" },
        run.to_json(),
        &findings,
        args.json,
    )
}

/// Runs `sim-doctor fuzz ota`: the TAR x keyset x mechanism sweep, behind the
/// safety interlock.
fn run_fuzz_ota(args: FuzzOtaArgs) -> contract::ExitCode {
    let (reader, mut session) = match open_fuzz_session(fuzz::KIND, &args.safety) {
        Ok(opened) => opened,
        Err(code) => return code,
    };

    let sweep = fuzz::Sweep {
        quick: args.safety.quick,
        class: tar::Class::Etsi,
    };
    let audit = match fuzz::audit(
        &mut session,
        sweep,
        &session::Policy::default(),
        &mut || signals::interrupted(),
    ) {
        Ok(audit) => audit,
        Err(err) => {
            return report_failure(
                &scan::Failure::new("fuzz-sweep-failed", err.to_string()),
                args.safety.json,
            )
        }
    };
    let findings = fuzz::findings(&audit);
    emit_fuzz_report(
        fuzz::KIND,
        reader.as_str(),
        audit.to_json(),
        &findings,
        args.safety.json,
    )
}

/// One `fuzz` report, in both modes: the reader name, the raw audit block
/// (named `data` under its own key per subcommand) and the findings, through
/// the same [`rules::Finding::to_json`] contract every other rule uses.
fn emit_fuzz_report(
    kind: &str,
    reader: &str,
    audit: serde_json::Value,
    findings: &[rules::Finding],
    json: bool,
) -> contract::ExitCode {
    let data = serde_json::json!({
        "reader": reader,
        "audit": audit,
        "findings": {
            "count": findings.len(),
            "findings": findings.iter().map(rules::Finding::to_json).collect::<Vec<_>>(),
        },
    });
    let rendered = if json {
        let envelope = contract::Envelope::new(
            kind,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        );
        match envelope.to_json() {
            Ok(line) => line,
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Findings;
            }
        }
    } else {
        let mut text = format!("{kind} on {reader}: {} finding(s)\n", findings.len());
        for finding in findings {
            text.push_str(&format!("{finding}\n"));
        }
        text
    };
    match emit_stdout(rendered.trim_end_matches('\n'), "the fuzz report") {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            contract::ExitCode::Findings
        }
    }
}

/// Picks the reader to scan, or says why there is not one.
///
/// Exit code 1 rather than 129 for both refusals. A reader name that matches
/// nothing and a machine with no reader are conditions of the environment, not
/// a malformed command line, and an operator who gets 129 for them will go
/// looking for a typo in a command line that is perfectly correct. The message
/// lists what *is* attached either way, because "no reader named X" on its own
/// sends the next person looking at the driver rather than the machine.
fn pick_reader<'a>(
    readers: &'a [ReaderName],
    requested: Option<&str>,
) -> Result<&'a ReaderName, scan::Failure> {
    if readers.is_empty() {
        return Err(scan::Failure::new(
            "no-reader",
            "no PC/SC reader is attached. Start pcscd and attach a card, or see \
             docs/swsim-fixture.md for the software SIM this project tests against",
        ));
    }

    let Some(requested) = requested else {
        return Ok(&readers[0]);
    };

    readers
        .iter()
        .find(|reader| reader.as_str() == requested)
        .ok_or_else(|| {
            let available: Vec<&str> = readers.iter().map(ReaderName::as_str).collect();
            scan::Failure::new(
                "unknown-reader",
                scan::unknown_reader(requested, &available).to_string(),
            )
        })
}

/// The bounds this run asked for, on top of [`Limits::default`].
///
/// Every one is an override rather than a positional, so a run that changes
/// one bound still reports the other three: a report that silently used a
/// different depth bound than the last run is not comparable to it.
fn limits_from(args: &WalkLimitArgs) -> Limits {
    let mut limits = Limits::default();
    if let Some(value) = args.max_depth {
        limits.max_depth = value;
    }
    if let Some(value) = args.max_children {
        limits.max_children = value;
    }
    if let Some(value) = args.max_nodes {
        limits.max_nodes = value;
    }
    if let Some(value) = args.max_directories {
        limits.max_directories = value;
    }
    limits
}

const RULES_KIND: &str = "rules";

/// The largest saved envelope `why` will read: 16 MiB.
const MAX_WHY_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Strips control and invisible characters so untrusted file text cannot drive
/// the terminal: the shared [`contract::sanitize`].
fn printable(text: &str) -> String {
    contract::sanitize(text)
}

/// One rule's page, as JSON.
fn rule_json(spec: &sim_doctor::rules::RuleSpec) -> serde_json::Value {
    serde_json::json!({
        "id": spec.id().as_str(),
        "severity": spec.severity().id(),
        "summary": spec.summary(),
        "remediation": spec.remediation(),
        "cwe": spec.cwe(),
        "reference": spec.reference(),
    })
}

/// One rule's page, as text.
fn rule_page(spec: &sim_doctor::rules::RuleSpec) -> String {
    format!(
        "{}  [{}]\n\nWhat it means\n  {}\n\nHow to fix\n  {}\n\nWeakness\n  {}\n\nSpecification\n  {}\n",
        spec.id().as_str(),
        spec.severity().id(),
        spec.summary(),
        spec.remediation().unwrap_or("(none declared)"),
        spec.cwe().unwrap_or("(not a weakness class)"),
        spec.reference().unwrap_or("(none cited)"),
    )
}

/// Prints one success document: the envelope under --json, else `text`.
fn emit_rules(json: bool, data: serde_json::Value, text: String) -> contract::ExitCode {
    let rendered = if json {
        match contract::Envelope::new(
            RULES_KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            data,
        )
        .to_json()
        {
            Ok(line) => line,
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Findings;
            }
        }
    } else {
        text.trim_end().to_owned()
    };
    match emit_stdout(&rendered, "the rules document") {
        Ok(()) => contract::ExitCode::Success,
        Err(message) => {
            eprintln!("sim-doctor: {message}");
            contract::ExitCode::Findings
        }
    }
}

/// `sim-doctor mcp`: the stdio server, handed the real clap `scan` command.
fn run_mcp() -> contract::ExitCode {
    // main() installed the SIGINT/SIGTERM flag handler, which this server never polls
    // and which would swallow Ctrl-C and `kill`; restore the default for both so either
    // ends the server (chosen deliberately for SIGTERM: no cleanup is owed). Each child
    // scan installs its own handler.
    // SAFETY: SIG_DFL is a valid disposition for these signals; no handler pointer is involved.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
    }
    let cli = <Cli as CommandFactory>::command();
    let scan = cli.find_subcommand("scan").expect("scan subcommand exists");
    match sim_doctor::mcp::serve(scan) {
        Ok(()) => contract::ExitCode::Success,
        Err(err) => {
            eprintln!("sim-doctor: mcp: {err}");
            contract::ExitCode::Findings
        }
    }
}

fn run_rules_list(json: bool) -> contract::ExitCode {
    let specs = all_specs();
    let mut text = format!("{:<28}  {:<8}  SUMMARY\n", "RULE", "SEVERITY");
    for spec in &specs {
        text.push_str(&format!(
            "{:<28}  {:<8}  {}\n",
            spec.id().as_str(),
            spec.severity().id(),
            spec.summary()
        ));
    }
    let data = serde_json::json!({ "rules": specs.iter().map(rule_json).collect::<Vec<_>>() });
    emit_rules(json, data, text)
}

/// Edit distance between two short ids, for did-you-mean.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cur = row[j + 1];
            row[j + 1] = (prev + usize::from(ca != *cb)).min(row[j] + 1).min(cur + 1);
            prev = cur;
        }
    }
    row[b.len()]
}

/// The nearest known id to `id`, if it is close enough to be a typo.
fn nearest_rule(specs: &[sim_doctor::rules::RuleSpec], id: &str) -> Option<String> {
    specs
        .iter()
        .map(|spec| (edit_distance(spec.id().as_str(), id), spec.id().as_str()))
        .min()
        .filter(|(distance, _)| *distance <= 3)
        .map(|(_, name)| name.to_owned())
}

fn unknown_rule(specs: &[sim_doctor::rules::RuleSpec], id: &str, json: bool) -> contract::ExitCode {
    let near = nearest_rule(specs, id);
    let mut message = format!("unknown rule `{id}`");
    if let Some(near) = &near {
        message.push_str(&format!("; did you mean `{near}`?"));
    }
    report_refusal(
        RULES_KIND,
        &message,
        serde_json::json!({ "error": message, "did_you_mean": near }),
        json,
    )
}

fn run_why_rule(id: &str, json: bool) -> contract::ExitCode {
    let specs = all_specs();
    match specs.iter().find(|spec| spec.id().as_str() == id) {
        Some(spec) => emit_rules(
            json,
            serde_json::json!({ "rule": rule_json(spec) }),
            rule_page(spec),
        ),
        None => unknown_rule(&specs, id, json),
    }
}

/// Reads a saved `scan --json` envelope: a file, within the size limit, UTF-8, an envelope.
/// Shared by `why` and `fix`; the error is the refusal sentence.
fn read_saved_envelope(target: &str) -> Result<serde_json::Value, String> {
    let path = std::path::Path::new(target);
    let meta = std::fs::metadata(path).map_err(|err| format!("cannot read {target}: {err}"))?;
    if !meta.is_file() {
        return Err(format!("{target} is not a file"));
    }
    if meta.len() > MAX_WHY_FILE_BYTES {
        return Err(format!(
            "{target} is {} bytes, over the {MAX_WHY_FILE_BYTES}-byte limit for a saved envelope",
            meta.len()
        ));
    }
    let raw =
        std::fs::read_to_string(path).map_err(|err| format!("cannot read {target}: {err}"))?;
    let envelope: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|err| format!("{target} is not a saved sim-doctor envelope: {err}"))?;
    if envelope["schema"] != contract::DOCTOR_SCHEMA {
        return Err(format!(
            "{target} is not a doctor/1 envelope; was it saved from `scan --json`?"
        ));
    }
    Ok(envelope)
}

/// Explains a rule id, or every rule in a saved scan envelope.
fn run_why(target: &str, json: bool) -> contract::ExitCode {
    let path = std::path::Path::new(target);
    let looks_like_path = target.contains(['/', '\\']) || target.ends_with(".json");
    let refuse = |message: String| {
        report_refusal(
            RULES_KIND,
            &message,
            serde_json::json!({ "error": message }),
            json,
        )
    };
    if !path.is_file() && !looks_like_path && !path.exists() {
        return run_why_rule(target, json);
    }
    let envelope = match read_saved_envelope(target) {
        Ok(envelope) => envelope,
        Err(message) => return refuse(message),
    };
    let Some(findings) = envelope["findings"].as_array() else {
        return refuse(format!(
            "{target} carries no findings array; was it saved from `scan --json`?"
        ));
    };

    // (rule id, severity, count), in first-seen order.
    let mut seen: Vec<(String, String, usize)> = Vec::new();
    for finding in findings {
        let rule = finding["id"].as_str().unwrap_or("(unnamed)");
        match seen.iter_mut().find(|(id, _, _)| id == rule) {
            Some(entry) => entry.2 += 1,
            None => seen.push((
                rule.to_owned(),
                finding["severity"].as_str().unwrap_or("?").to_owned(),
                1,
            )),
        }
    }

    let specs = all_specs();
    let mut text = String::new();
    let mut rules = Vec::new();
    for (id, severity, count) in &seen {
        text.push_str(&format!(
            "{}  [{}]  {count} finding(s)\n",
            printable(id),
            printable(severity)
        ));
        let spec = specs.iter().find(|spec| spec.id().as_str() == id);
        match spec {
            Some(spec) => text.push_str(&rule_page(spec)),
            None => text.push_str("  no catalog entry for this rule in this build\n"),
        }
        text.push('\n');
        rules.push(serde_json::json!({
            "id": id, "severity": severity, "count": count,
            "rule": spec.map(rule_json),
        }));
    }
    if seen.is_empty() {
        text.push_str("no findings in this envelope\n");
    }
    emit_rules(json, serde_json::json!({ "rules": rules }), text)
}

/// Runs `sim-doctor fix`: print the prompt, and with `--agent` launch that agent.
fn run_fix(args: &FixArgs) -> contract::ExitCode {
    let specs = all_specs();
    let Some(spec) = specs.iter().find(|s| s.id().as_str() == args.rule_id) else {
        return unknown_rule(&specs, &args.rule_id, false);
    };
    let refuse = |message: String| {
        report_refusal(
            RULES_KIND,
            &message,
            serde_json::json!({ "error": message }),
            false,
        )
    };
    let envelope = match read_saved_envelope(&args.from) {
        Ok(envelope) => envelope,
        Err(message) => return refuse(message),
    };
    let Some(all) = envelope["findings"].as_array() else {
        return refuse(format!(
            "{} carries no findings array; was it saved from `scan --json`?",
            args.from
        ));
    };
    let findings: Vec<(String, String)> = all
        .iter()
        .filter(|f| f["id"].as_str() == Some(spec.id().as_str()))
        // Cap before collecting: a 16 MiB file of matches must not allocate per finding.
        .take(fix::MAX_FINDINGS)
        .map(|f| {
            (
                f["severity"].as_str().unwrap_or("?").to_owned(),
                f["message"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    if findings.is_empty() {
        return refuse(format!(
            "rule `{}` has no finding in {}",
            args.rule_id, args.from
        ));
    }
    let prompt = fix::build_prompt(
        spec.id().as_str(),
        spec.summary(),
        spec.remediation().unwrap_or("(none declared)"),
        &findings,
        env!("CARGO_PKG_VERSION"),
    );
    if let Err(message) = emit_stdout(&prompt, "the prompt") {
        eprintln!("sim-doctor: {message}");
        return contract::ExitCode::Findings;
    }
    let Some(name) = &args.agent else {
        return contract::ExitCode::Success;
    };
    if fix::in_agent(|k| std::env::var(k).ok()) {
        eprintln!(
            "sim-doctor: already inside a coding agent: not launching another; use the prompt above"
        );
        return contract::ExitCode::Success;
    }
    let agent = fix::AGENTS
        .iter()
        .find(|a| a.name == name)
        .expect("clap restricts --agent to the table");
    let skip = args.skip_approvals
        || std::env::var("SIM_DOCTOR_HANDOFF_SKIP_APPROVALS").is_ok_and(|v| v == "1");
    let argv = fix::launch_argv(agent, &prompt, skip);
    eprintln!("$ {} <prompt>", argv[..argv.len() - 1].join(" "));
    // `.status()` blocks while the agent runs and the flag handler would swallow
    // Ctrl-C and `kill`; restore the default for both, as run_mcp does, so either
    // ends this process (the agent shares the terminal's process group for Ctrl-C).
    // SAFETY: SIG_DFL is a valid disposition for these signals; no handler pointer is involved.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
    }
    // Spawned directly: the OS resolves PATH, so the path run is the path checked.
    match std::process::Command::new(agent.bin)
        .args(&argv[1..])
        .status()
    {
        Ok(status) if status.success() => contract::ExitCode::Success,
        Ok(status) => {
            eprintln!("sim-doctor: {} exited with {status}", agent.bin);
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(signal) = status.signal() {
                    // The shell convention (130 for SIGINT); the child's own code is
                    // lost to the kernel here, so report the signal instead.
                    eprintln!("sim-doctor: {} was killed by signal {signal}", agent.bin);
                    process::exit(128 + signal);
                }
            }
            contract::ExitCode::Findings
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "sim-doctor: {} is not installed (not found on PATH)",
                agent.bin
            );
            contract::ExitCode::Findings
        }
        Err(err) => {
            eprintln!("sim-doctor: could not launch {}: {err}", agent.bin);
            contract::ExitCode::Findings
        }
    }
}

/// Reports a refusal of a lpa-style command that shares `scan`'s failure shape
/// (the fuzz commands), and returns exit code 1. `scan` itself uses
/// [`report_scan_failure`] and exits 2.
///
/// The same shape as every other refusal: AGENTS.md
/// section 3 shares code 1 between "findings present" and "a check failed", and
/// a run that could not reach a card is a check that failed. Under `--json` an
/// agent reads the envelope and learns why; without it the sentence is on
/// stderr and stdout stays empty, because there is no report to give.
fn report_failure(failure: &scan::Failure, json: bool) -> contract::ExitCode {
    report_refusal(scan::KIND, &failure.message, failure.data(), json)
}

/// One refusal in both modes: a sentence on stderr always, and one envelope on
/// stdout under `--json`.
///
/// The stderr line is printed first and unconditionally. It is a diagnostic,
/// and AGENTS.md section 3 puts every diagnostic on stderr in every mode; the
/// envelope is the machine-readable copy of the same sentence, not a
/// replacement for it.
fn report_refusal(
    kind: &str,
    message: &str,
    data: serde_json::Value,
    json: bool,
) -> contract::ExitCode {
    eprintln!("sim-doctor: {message}");

    if json {
        let line = contract::Envelope::new(kind, contract::ExitCode::Findings, message, data)
            .to_json()
            .map_err(|e| e.to_string());
        match line {
            Ok(line) => {
                // A write failure does not change the exit code, for the same
                // reason it does not in report_interrupted: the run genuinely
                // failed, and "could not report the failure" is not a different
                // answer.
                if let Err(err) = emit_stdout(&line, "the failure envelope") {
                    eprintln!("sim-doctor: {err}");
                }
            }
            Err(err) => eprintln!("sim-doctor: {err}"),
        }
    }

    contract::ExitCode::Findings
}

/// Reports a `scan` that could not run: a doctor/1 envelope with no findings and
/// the reason in `data`, exit 2. (Other commands keep the lpa refusal and exit 1.)
fn report_scan_failure(failure: &scan::Failure, json: bool) -> contract::ExitCode {
    eprintln!("sim-doctor: {}", failure.message);
    if json {
        let envelope = contract::doctor_failure(contract::ExitCode::Error, failure.data());
        // A write failure does not change the exit code: the run genuinely
        // failed, and "could not report the failure" is not a different answer.
        match serde_json::to_string(&envelope) {
            Ok(line) => {
                if let Err(err) = emit_stdout(&line, "the failure envelope") {
                    eprintln!("sim-doctor: {err}");
                }
            }
            Err(err) => eprintln!("sim-doctor: {err}"),
        }
    }
    contract::ExitCode::Error
}

/// Turns a clap failure into one of the four contract exit codes.
///
/// clap exits with 2 by default. That number is not in AGENTS.md section 3,
/// so passing it through would mean a caller could not tell a typo from a
/// crash. `--help` and `--version` are not failures and exit 0.
fn exit_with_clap_error(err: clap::Error) -> process::ExitCode {
    let code = match err.kind() {
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayVersion
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => contract::ExitCode::Success,
        // `scan` is a doctor/1 findings command: a usage error is 2 there.
        _ if std::env::args()
            .skip(1)
            .find(|a| !a.starts_with('-'))
            .as_deref()
            == Some("scan") =>
        {
            contract::ExitCode::Error
        }
        _ => contract::ExitCode::InvalidUsage,
    };
    // clap already routes help to stdout and errors to stderr; do not print
    // twice, and do not stack a second message on top of the one it built.
    let _ = err.print();
    exit(code)
}
/// Converts a contract exit code into the exit status of this process.
fn exit(code: contract::ExitCode) -> process::ExitCode {
    process::ExitCode::from(code.process_code())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--fail-on` defaults to `critical`: the choice that keeps a scan with
    /// only lower findings at exit 0, as it was before doctor/1. Documented in
    /// `scan --help`, the README and AGENTS.md section 3.
    #[test]
    fn fail_on_defaults_to_critical() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["sim-doctor", "scan"]).expect("parses");
        let Command::Scan(args) = cli.command else {
            panic!("not a scan")
        };
        assert_eq!(args.fail_on, rules::Severity::Critical);
    }

    /// `scan` no longer has `--diff`: `--baseline` alone gates (doctor/1).
    #[test]
    fn scan_has_no_diff_flag() {
        use clap::Parser;
        assert!(Cli::try_parse_from(["sim-doctor", "scan", "--diff"]).is_err());
    }
}
