//! sim-doctor on doctor-kit: the CLI skeleton comes from `doctor_kit::run_with`, the commands are ours.
//!
//! Every top-level command of the derive-built [`Cli`] is mounted as an `ExtCommand` of its own
//! name, so its flags, its `--help` text and its handler are exactly what they were; a command
//! named like one of the kit's (`scan`, `fix`, `install`, `ci`, `mcp`) replaces the kit's.
//! The doctor itself is a card, not a directory (`TargetKind::Detached`).

use std::process::ExitCode;

use clap::{ArgMatches, CommandFactory, FromArgMatches};
use doctor_kit::doctor_core::Severity;
use doctor_kit::{Check, Doctor, ExtCommand, Extensions, Meta, TargetKind};

use super::{contract, dispatch, Cli};

/// The doctor the kit's pipeline runs. It holds the parsed command line: the kit hands each
/// mounted command only its own matches, and the handlers want the whole `Cli`.
pub struct SimDoctor {
    root: ArgMatches,
}

impl Doctor for SimDoctor {
    fn name(&self) -> &str {
        "sim-doctor"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn about(&self) -> &str {
        "CLI-first SIM/UICC security testing tool"
    }
    fn categories(&self) -> Vec<&'static str> {
        vec![]
    }
    /// Unused: the rules share one card subject and run from `scan` itself.
    fn checks(&self) -> Vec<Box<dyn Check>> {
        vec![]
    }
    fn target(&self) -> TargetKind {
        TargetKind::Detached
    }
    /// `--fail-on` defaults to `critical`: a scan fails only on the worst finding.
    fn default_fail_on(&self) -> Severity {
        Severity::Critical
    }
}

/// Runs the mounted command: parse the whole command line again as the derive-built `Cli`.
fn run_cli(d: &SimDoctor, _own: &ArgMatches) -> Result<u8, String> {
    let cli = Cli::from_arg_matches(&d.root).map_err(|e| e.to_string())?;
    Ok(dispatch(cli.command).process_code())
}

/// Exit code of a command line clap refused. Help and version are not failures (0); `scan` is a
/// doctor/1 findings command, so a usage error is 2 there; everywhere else it is 129.
fn usage_exit(err: &clap::Error, argv: &[String]) -> u8 {
    use clap::error::ErrorKind;
    let code = match err.kind() {
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayVersion
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => contract::ExitCode::Success,
        _ if argv
            .iter()
            .skip(1)
            .find(|a| !a.starts_with('-'))
            .map(String::as_str)
            == Some("scan") =>
        {
            contract::ExitCode::Error
        }
        _ => contract::ExitCode::InvalidUsage,
    };
    code.process_code()
}

/// Run the CLI.
pub fn run() -> ExitCode {
    let cli = Cli::command();
    let meta = Meta {
        name: "sim-doctor".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        about: cli.get_about().map(ToString::to_string).unwrap_or_default(),
        fail_on: Severity::Critical,
        target: TargetKind::Detached,
    };
    let commands = cli
        .get_subcommands()
        .cloned()
        .enumerate()
        // Keeps `--help` listing the commands in the order they are declared in.
        .map(|(i, command)| ExtCommand {
            command: command.display_order(i),
            run: run_cli,
        })
        .collect();
    let ext = Extensions {
        commands,
        global_args: vec![],
        usage_exit,
    };
    doctor_kit::run_with(meta, ext, |root| Ok(SimDoctor { root: root.clone() }))
}
