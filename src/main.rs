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
use std::io::{self, Write};
use std::process;
use std::thread;
use std::time::{Duration, Instant};

use clap::{error::ErrorKind, Args, CommandFactory, Parser, Subcommand};
use clap_complete::aot::generate;
use sim_doctor::{
    contract, rules, scan, session, signals, tar,
    transport::{
        pcsc::{Pcsc, PcscSession},
        ReaderName, ReaderProvider,
    },
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
    /// Exit codes. 0 when the walk finished, 1 when it could not run (no
    /// reader, no card, a card that would not select its master file, or a flag
    /// whose behaviour is not built yet), 129 for a command line this tool
    /// cannot parse, 130 if you interrupt it.
    #[command(long_about = SCAN_LONG_ABOUT)]
    Scan(ScanArgs),

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
    "GATE ON data.complete, NOT ON payload.code\n",
    "  payload.code is 0 whenever the walk FINISHED, including a walk that was\n",
    "  cut short: a card that describes an unbounded tree is a card we read part\n",
    "  of, and that is not a failed check. An agent gating a build should\n",
    "  require payload.data.complete to be true.\n\n",
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
    "  and raises nothing.\n\n",
    "SEVERITY AND SCORE\n",
    "  --severity <level> REMOVES findings below that level from the report.\n",
    "  Not marked, not counted, absent from the JSON entirely, so a count or a\n",
    "  grep sees only what survived. The level in force is reported as\n",
    "  data.findings.severity_threshold. It does not filter the walk:\n",
    "  complete, truncated and limits_hit are unaffected by it.\n",
    "  --score adds data.score, an INTEGER 0-100 computed as\n",
    "    max(0, 100 - sum of one penalty per finding)\n",
    "  with a penalty of info 1, low 3, medium 10, high 25, critical 50. The\n",
    "  block carries the formula, that penalty table, the penalty total and\n",
    "  the number of findings scored, so the number can be recomputed from\n",
    "  the report. It scores the findings this report carries, so --severity\n",
    "  and --score compose rather than contradict each other.\n",
    "  A rules_run OF 0 means no rule was evaluated, and the block then carries\n",
    "  a warning beside the 100 saying so in words. A rules_run above 0 with a\n",
    "  score of 100 means a rule looked and found nothing, which is a verdict.\n",
    "  The two are different numbers wearing the same digits, and warning is\n",
    "  what tells them apart.\n\n",
    "EXIT CODES\n",
    "  0  the walk finished. A FINDING DOES NOT CHANGE THIS, deliberately: exit\n",
    "     1 already means a check could not run, and the document reporting that\n",
    "     carries data.error and no data.findings, so one code would carry two\n",
    "     document schemas. Gate on data.complete and data.score instead.\n",
    "  1  the walk could not run, or a requested flag is not implemented yet\n",
    "  129  the command line could not be parsed\n",
    "  130  interrupted\n",
);
/// Everything `sim-doctor scan` takes.
#[derive(Args)]
struct ScanArgs {
    /// Emit one JSON envelope on stdout, and nothing else.
    ///
    /// Implemented. stdout carries the envelope and not one byte else; every
    /// diagnostic goes to stderr in this mode and in every other.
    #[arg(long)]
    json: bool,

    /// Which FCP tag table this card answers SELECT with.
    ///
    /// Defaults to swicc. This is an assumption and the output says which one
    /// was used; the chosen table's name appears in the human report and under
    /// "dialect" in the JSON, so the assumption is never invisible.
    ///
    /// swicc is what swSIM writes: file size in 80, descriptor in 82, file id in
    /// 83. A card that follows ISO/IEC 7816-4 table 42 puts the file size in 82
    /// instead, and reading such a card with the swicc table reports a 10-octet
    /// file as 2337 octets. A real UICC is more likely to follow the ISO table
    /// than the software simulator, so prefer iec-7816-4-table-42 unless you
    /// have checked.
    ///
    /// A card nobody has characterised needs a hand-built TagSet, which this
    /// flag cannot express yet. That is a real gap rather than a missing third
    /// value: an "unknown" dialect would render an empty table as though it
    /// meant something.
    #[arg(long, value_name = "TABLE", default_value_t = scan::Dialect::Swicc)]
    dialect: scan::Dialect,

    /// The reader to use, matched against the driver's own name.
    ///
    /// Defaults to the first reader PC/SC reports. Pass this when more than one
    /// is attached, or to get an explicit error naming what is available
    /// instead of scanning whichever reader happened to be first.
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,

    /// Deepest path below the master file the walk descends into.
    ///
    /// The default (16) leaves room for a real card. Lowering it is how you
    /// force a truncation on purpose, which is the supported way to see what a
    /// truncated report looks like.
    #[arg(long, value_name = "N")]
    max_depth: Option<usize>,

    /// Identifiers probed per directory, and the whole walk's node budget.
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

    /// Files recorded across the whole walk.
    #[arg(long, value_name = "N")]
    max_nodes: Option<usize>,

    /// Directories whose children are enumerated.
    #[arg(long, value_name = "N")]
    max_directories: Option<usize>,

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
    /// nothing else, and `data.score.scored_findings` says how many that was.
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
    /// critical, so a typo is still exit 129 rather than being silently
    /// ignored.
    ///
    /// A finding below the level is REMOVED, not marked: it is absent from
    /// `data.findings.findings`, absent from `data.findings.count`, and its
    /// rule ID appears nowhere in the document. An agent counting findings
    /// therefore gets the count that survived the filter, and an agent
    /// grepping for a dropped rule finds nothing rather than an empty shell
    /// carrying the ID.
    ///
    /// The level in force is reported as `data.findings.severity_threshold`,
    /// because a short list is otherwise indistinguishable from a quiet card.
    ///
    /// It does not filter the WALK. `complete`, `truncated`, `truncated_by`
    /// and `limits_hit` are unchanged by it, so raising the level can never
    /// make a truncated scan look like a whole one.
    #[arg(long, value_name = "LEVEL")]
    severity: Option<rules::Severity>,

    /// NOT IMPLEMENTED YET. Exits 1 with "implemented": false before any reader
    /// is opened.
    ///
    /// Regression gating against a saved run is issue #9.
    #[arg(long, value_name = "FILE")]
    baseline: Option<String>,

    /// NOT IMPLEMENTED YET. Exits 1 with "implemented": false before any reader
    /// is opened.
    ///
    /// Requires --baseline, so --diff on its own is exit 129 rather than a
    /// silent no-op. Diffing against a baseline is issue #9.
    #[arg(long, requires = "baseline")]
    diff: bool,

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
}

/// Whether a scan that produced findings exits 1.
///
/// **No. It does not, and after issue #24 that is a decision rather than an
/// accident: a rule now runs, and the reason it deferred is gone.**
///
/// AGENTS.md section 3 lists exit 1 as "findings present (or checks failed)"
/// and issue #13 left this half-taken with three reasons. They are not all
/// still standing, and saying so is the point:
///
/// 1. ~~**No rule runs yet.**~~ **WITHDRAWN by issue #24.** The vocabulary
///    arrived with #13 and the first rule arrived with this one, so a scan can
///    produce a finding and this question is observable for the first time.
///    A reason that has stopped being true must stop being written down, or the
///    next reader inherits it as a live argument.
/// 2. **`payload.code` already means something else.** Still true and still
///    independent of the first: it is 0 whenever the walk *finished*, including
///    a walk that was cut short, and `scan --help` has said `GATE ON
///    data.complete, NOT ON payload.code` since issue #6. Spending code 1 on
///    "the card is dirty" makes that sentence wrong unless it is reworded in
///    the same commit, which is a contract edit, not a constant.
/// 3. **The two meanings have two different documents.** **This is the
///    decisive one and it was not written down before.** Exit 1 is reachable
///    today from six conditions - no reader, unknown reader, reader
///    unavailable, walk failed, rule misattribution, a deferred flag - plus an
///    unwritable stdout. Every one of them emits a *refusal* document:
///    `data.error` and `data.card_touched`, and **no `data.findings`
///    key at all**. A scan that found something would emit the opposite shape:
///    `data.findings` and `data.score`, and **no `data.error` key at
///    all**. So flipping this does not add a meaning to an exit code; it gives
///    one code two mutually exclusive document schemas, and an agent that
///    branches on the status has to read the body to pick one. For a tool whose
///    whole promise is that an agent can branch on the status, that is the
///    wrong trade to make in the same release that first produces a finding.
///
/// **What to gate on instead, which is already in the document:** a CI gate
/// reads `data.complete` (was the whole card read?) and
/// `data.score.value` (is it under the threshold?). Both are per-field,
/// neither collides with the exit code, and `data.score.warning` is null
/// now that a rule runs - which is exactly the three-way distinction the exit
/// code could never carry: *checked and clean*, *checked and dirty*, *not
/// checked*.
///
/// **When to revisit.** When #9 lands `--baseline` and `--diff`, both
/// of which are already designed to exit 1, a gate has a threshold to fail
/// against rather than a bare "something is wrong". That is the moment
/// findings-fail-a-scan can be attached to a number an operator chose, instead
/// of being smeared across every way a scan can go wrong. Recorded in
/// CONTEXT.md section 3.
const FINDINGS_FAIL_A_SCAN: bool = false;

impl ScanArgs {
    /// The first requested flag whose behaviour is not built, if there is one.
    ///
    /// Order is fixed and documented rather than "whatever clap saw first", so
    /// the message an operator gets does not depend on the order they typed the
    /// flags. Only one is reported: listing every unimplemented flag at once is
    /// noise, and the operator will find the next one on the next run.
    fn deferred(&self) -> Option<scan::Deferred> {
        if let Some(path) = &self.baseline {
            return Some(scan::Deferred::Baseline(path.clone()));
        }
        if self.diff {
            return Some(scan::Deferred::Diff);
        }
        None
    }
}

#[derive(Args)]
struct ModulesArgs {
    /// Emit the JSON envelope on stdout instead of a human-readable table.
    #[arg(long)]
    json: bool,
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
        Command::Completions(args) => run_completions(args),
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

    let deadline = Instant::now() + Duration::from_millis(milliseconds);
    while Instant::now() < deadline {
        if signals::interrupted() {
            return;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// Reports an interrupted run and returns [`contract::ExitCode::Interrupted`].
///
/// Exactly one envelope under `--json`, carrying code 130 and an empty `data`,
/// and a note on stderr in either mode. Never a partial result: the reasoning is
/// on [`contract::INTERRUPTED_MESSAGE`], and `tests/process_contract.rs` pins
/// both halves of it.
fn report_interrupted(kind: &str, json: bool) -> contract::ExitCode {
    if json {
        let envelope = contract::Envelope::new(
            kind,
            contract::ExitCode::Interrupted,
            contract::INTERRUPTED_MESSAGE,
            contract::interrupted_data(),
        );
        match envelope.to_json() {
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
/// **The shape of this function is the whole SIGINT contract.** Two
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
/// would break the promise that `payload.code` is the value the process exits
/// with. See [`report_interrupted`] and CONTEXT.md section 3.
///
/// The deferred flags are checked before the first checkpoint and before any
/// I/O, because `--baseline` has an answer whether or not a card exists and
/// an agent that scripts against it deserves that answer in milliseconds.
///
/// `--score` and `--severity` are NOT deferred any more. They need a card,
/// because what they say is about a card.
fn run_scan(args: ScanArgs) -> contract::ExitCode {
    if let Some(deferred) = args.deferred() {
        return report_deferred(&deferred, args.json);
    }

    if checkpoint() {
        return report_interrupted(scan::KIND, args.json);
    }

    let readers = match Pcsc::readers() {
        Ok(readers) => readers,
        Err(err) => {
            return report_failure(
                &scan::Failure::new("context-unavailable", err.to_string()),
                args.json,
            )
        }
    };

    let reader = match pick_reader(&readers, args.reader.as_deref()) {
        Ok(reader) => reader,
        Err(failure) => return report_failure(&failure, args.json),
    };

    let mut session = match PcscSession::open(reader) {
        Ok(session) => session,
        Err(err) => {
            return report_failure(
                &scan::Failure::new("reader-unavailable", err.to_string()),
                args.json,
            )
        }
    };

    // Best effort. An ATR this transport could not read is a fact about the
    // session, not a reason to refuse to scan a card that is otherwise
    // answering, so it is Option rather than an error. A reader that cannot
    // even be opened has already failed above.
    let atr = session.atr().ok();

    let options = walk::Options {
        addressing: walk::Addressing::PathFromMasterFile,
        // Spelled out rather than inherited: this is the set that can miss a
        // file, and the line that decides that belongs where the walk is built.
        candidates: walk::Candidates::SimFamilies,
        // Only 6A 82 is classified. Nothing else is, because this repository has
        // read no other table; see walk::StatusMeaning and CONTEXT.md section 3.
        meaning: walk::StatusMeaning::default(),
        limits: limits_from(&args),
        ..walk::Options::default()
    };

    let tree = match walk::walk(&mut session, &args.dialect.tag_set(), &options) {
        Ok(tree) => tree,
        Err(err) => {
            return report_failure(
                &scan::Failure::new("walk-failed", err.to_string()),
                args.json,
            )
        }
    };

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
    let audit = match tar::audit(
        &mut session,
        &args.tar,
        &session::Policy::default(),
        &mut || signals::interrupted(),
    ) {
        Ok(audit) => audit,
        Err(err) => {
            return report_failure(
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
    }) {
        Ok(found) => found,
        Err(err) => {
            return report_failure(
                &scan::Failure::new("rule-misattribution", err.to_string()),
                args.json,
            )
        }
    };

    // Filtered before it is scored, and the score taken from what is left:
    // the number in the report is a function of the findings in the report.
    let verdict = scan::Verdict::new(found, scan::rules_run())
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

    // Assembled, then written once, so a failure halfway through cannot put
    // half an envelope on stdout. See emit_stdout.
    let rendered = if args.json {
        let envelope = contract::Envelope::new(
            scan::KIND,
            contract::ExitCode::Success,
            contract::OK_MESSAGE,
            scan::to_json(&tree, &context, &verdict),
        );
        match envelope.to_json() {
            Ok(line) => line,
            Err(err) => {
                eprintln!("sim-doctor: {err}");
                return contract::ExitCode::Findings;
            }
        }
    } else {
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
    match emit_stdout(rendered.trim_end_matches('\n'), what) {
        // The one place FINDINGS_FAIL_A_SCAN would change the answer, and
        // deliberately unchanged for now. See the constant.
        Ok(()) if FINDINGS_FAIL_A_SCAN && verdict.findings().reaches(rules::Severity::MIN) => {
            contract::ExitCode::Findings
        }
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
fn limits_from(args: &ScanArgs) -> Limits {
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

/// Reports a flag whose behaviour is not built yet, and returns exit code 1.
///
/// Not 129: the command line *was* understood. Not 0 either, because 0 means
/// "no findings above threshold" and this is not a card that passed - nothing
/// was scanned at all. One envelope in `--json` carrying
/// `"implemented": false`, and the sentence on stderr in either mode.
fn report_deferred(deferred: &scan::Deferred, json: bool) -> contract::ExitCode {
    let message = scan::deferred_message(deferred);
    report_refusal(scan::KIND, &message, scan::deferred_json(deferred), json)
}

/// Reports a scan that could not run, and returns exit code 1.
///
/// The same shape as [`report_deferred`] and for the same reason: AGENTS.md
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
        let envelope = contract::Envelope::new(kind, contract::ExitCode::Findings, message, data);
        match envelope.to_json() {
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

    /// The decision `run_scan`'s success arm is built on, pinned.
    ///
    /// This test exists so that flipping [`FINDINGS_FAIL_A_SCAN`] to `true`
    /// cannot be an accident: the constant becomes the only place the
    /// behaviour is written, and this is the place somebody has to read
    /// before agreeing to it. The card fixture's
    /// `scans_a_real_card_end_to_end` asserts exit 0 against a live card and
    /// would go red on the day the first rule lands, which is the intended
    /// signal and not a surprise.
    #[test]
    fn findings_do_not_fail_a_scan_yet() {
        // Bound to a local first, on purpose. clippy is right that the
        // condition is a constant: that is the whole point of this test, and
        // the failure it produces is the message below rather than a line
        // number. A `const { assert! }` block would say the same thing at
        // compile time, but it would also stop the binary building at all, and
        // a contract decision is not worth taking the tool away over.
        let findings_fail_a_scan: bool = FINDINGS_FAIL_A_SCAN;
        assert!(
            !findings_fail_a_scan,
            concat!(
                "a scan that produced findings now exits 1. That IS a contract change:\n",
                "AGENTS.md section 3 allows it, but it needs the scan --help \n",
                "sentence GATE ON data.complete reworded, the exit-code table \n",
                "updated, and tests/card_fixture.rs moved deliberately rather than \n",
                "quietly. Do those three things in the same commit as this constant."
            )
        );
    }

    /// `--severity` and `--score` are no longer deferred flags.
    ///
    /// The refusal they used to raise is gone, so this pins the direction the
    /// change went: only `--baseline` and `--diff` still stand in the way.
    #[test]
    fn only_the_baseline_flags_still_defer() {
        let deferring = ScanArgs {
            json: false,
            dialect: scan::Dialect::Swicc,
            reader: None,
            max_depth: None,
            max_children: None,
            max_nodes: None,
            max_directories: None,
            score: true,
            severity: Some(rules::Severity::High),
            baseline: Some("saved.json".to_owned()),
            diff: true,
            tar: tar::Selection::default(),
        };

        // With a baseline in the list, that is what refuses - the two
        // implemented flags are not what stands in the way.
        assert_eq!(
            deferring.deferred(),
            Some(scan::Deferred::Baseline("saved.json".to_owned()))
        );

        // And on their own they defer to nothing at all.
        let alone = ScanArgs {
            baseline: None,
            diff: false,
            ..deferring
        };
        assert_eq!(alone.deferred(), None);
        assert!(alone.score, "the flag is still on the surface");
        assert_eq!(alone.severity, Some(rules::Severity::High));
    }
}
