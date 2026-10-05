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

use clap::{error::ErrorKind, Args, Parser, Subcommand};
use sim_doctor::{contract, signals, MODULES};

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
/// millisecond, so without this the test would be a race between the signal and
/// the exit - and a race that passes on a fast machine fails on a loaded CI
/// runner. With it, the process is provably parked when the signal arrives.
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
}

#[derive(Args)]
struct ModulesArgs {
    /// Emit the JSON envelope on stdout instead of a human-readable table.
    #[arg(long)]
    json: bool,
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
/// `emit_modules` stays a function that renders data and nothing else. Issue
/// #9's `scan` copies this shape: take the checkpoint at the point where it is
/// still safe to stop, and stop *before* producing any output.
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
fn hold_for_the_signal_test() {
    let Ok(milliseconds) = env::var(SIGNAL_HOLD_ENV) else {
        return;
    };
    let Ok(milliseconds) = milliseconds.parse::<u64>() else {
        return;
    };

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
fn emit_stdout(text: &str, what: &str) -> Result<(), String> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let mut line = String::with_capacity(text.len() + 1);
    line.push_str(text);
    line.push('\n');
    handle
        .write_all(line.as_bytes())
        .map_err(|e| format!("cannot write {what} to stdout: {e}"))
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
