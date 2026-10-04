//! `sim-doctor` as a binary.
//!
//! Every line here is a view: parse arguments, ask the library for a value,
//! put it on stdout, exit. Nothing in this file decides what a module owns,
//! what the JSON looks like, or which exit code means what - those live in
//! the library, where they can be tested without a terminal.
//!
//! This is also the only place in the crate that writes to stdout. AGENTS.md
//! section 2 requires the tool to work headless, and the way that stays
//! honest is structural: the library cannot print even if a future change
//! tried to, because nothing in it holds a handle on a stream.

use std::process;

use clap::{error::ErrorKind, Args, Parser, Subcommand};
use sim_doctor::{contract, MODULES};

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
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => return exit_with_clap_error(err),
    };

    match cli.command {
        Command::Modules(args) => match emit_modules(args.json) {
            Ok(()) => exit(contract::ExitCode::Success),
            Err(message) => {
                eprintln!("{message}");
                exit(contract::ExitCode::Findings)
            }
        },
    }
}

/// Writes the module table, as a table or as the JSON envelope.
///
/// `--json` puts the envelope and nothing else on stdout, which is the
/// AGENTS.md section 3 rule. Without it the same data is printed as a table
/// for a person, and the distinction is why the flag is checked here rather
/// than inside the library: formatting for a terminal is the binary job.
fn emit_modules(json: bool) -> Result<(), String> {
    if json {
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
        println!("{}", envelope.to_json().map_err(|e| e.to_string())?);
        return Ok(());
    }

    println!("{:<10}  {:<5}  DEPENDS ON", "MODULE", "LAYER");
    for (layer, module) in MODULES.iter().enumerate() {
        let depends = if module.depends_on.is_empty() {
            "-".to_owned()
        } else {
            module.depends_on.join(", ")
        };
        println!("{:<10}  {:<5}  {}", module.name, layer, depends);
    }
    for module in MODULES {
        println!("\n{}: {}", module.name, module.owns);
    }
    Ok(())
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
