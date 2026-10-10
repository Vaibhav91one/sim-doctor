//! `sim-doctor card`: the loop around [`sim_doctor::cardsh::Shell`] (PC/SC, stdin, stdout).

use std::io::{self, BufRead, IsTerminal, Write};

use clap::Args;
use sim_doctor::cardsh::{self, Opts, Profile, Shell};
use sim_doctor::{contract, scan};

/// Everything `sim-doctor card` takes.
#[derive(Args)]
pub struct CardShellArgs {
    /// The reader to use, matched against the driver's own name (default: the first reader).
    #[arg(long, value_name = "NAME")]
    reader: Option<String>,

    /// The command set the card speaks: uicc (class 00) or sim (class A0, GSM 11.11).
    #[arg(long, value_name = "PROFILE", default_value = "uicc", value_parser = ["uicc", "sim"])]
    profile: String,

    /// Which FCP tag table the card answers SELECT with (see `scan --help`).
    #[arg(
        long,
        value_name = "TABLE",
        default_value_t = scan::Dialect::Ts102221,
        value_parser = super::parse_dialect
    )]
    dialect: scan::Dialect,

    /// Run these `;`-separated commands and exit.
    #[arg(short = 'c', value_name = "COMMANDS", conflicts_with = "script")]
    command: Option<String>,

    /// Run the commands in this file, one per line (`#` starts a comment), and exit.
    #[arg(long, value_name = "PATH")]
    script: Option<std::path::PathBuf>,

    /// Print every reply as one JSON record (for agents).
    #[arg(long)]
    json: bool,

    /// Send the commands that change the card (APDUs outside the read-only set, PIN checks, ...).
    /// Without it they print what they would send and the card is not touched by them.
    #[arg(long)]
    yes: bool,
}

pub fn run(args: CardShellArgs) -> contract::ExitCode {
    let opener: cardsh::Opener = Box::new(|requested| {
        let (session, reader, atr) = super::open_scan_session(requested).map_err(|f| f.message)?;
        Ok((session, reader.as_str().to_owned(), atr))
    });
    let mut shell = Shell::new(
        opener,
        Opts {
            yes: args.yes,
            dialect: args.dialect.tag_set(),
        },
    );
    let profile = if args.profile == "sim" {
        Profile::Sim
    } else {
        Profile::Uicc
    };
    if let Err(message) = shell.equip(args.reader.as_deref(), profile) {
        eprintln!("sim-doctor: {message}");
        return contract::ExitCode::Error;
    }
    let lines: Vec<String> = if let Some(script) = &args.command {
        cardsh::split_commands(script)
    } else if let Some(path) = &args.script {
        match std::fs::read_to_string(path) {
            Ok(text) => text.lines().map(str::to_owned).collect(),
            Err(err) => {
                eprintln!("sim-doctor: {}: {err}", path.display());
                return contract::ExitCode::Error;
            }
        }
    } else {
        return interactive(&mut shell, args.json);
    };
    for line in lines {
        let reply = shell.exec(&line);
        if emit(&line, &reply, args.json).is_err() {
            return contract::ExitCode::Error;
        }
        if reply.quit {
            break;
        }
    }
    finish(&shell)
}

fn finish(shell: &Shell) -> contract::ExitCode {
    if shell.failed == 0 {
        contract::ExitCode::Success
    } else {
        contract::ExitCode::Findings
    }
}

/// Prints one reply: the text for a person, one record for `--json`. Errors go to stderr as text.
fn emit(line: &str, reply: &cardsh::Reply, json: bool) -> io::Result<()> {
    if line.trim().is_empty() || line.trim_start().starts_with('#') {
        return Ok(());
    }
    let mut out = io::stdout().lock();
    if json {
        writeln!(out, "{}", reply.record(line.trim()))?;
    } else if !reply.ok {
        eprintln!("error: {}", reply.text);
    } else if !reply.text.is_empty() {
        writeln!(out, "{}", reply.text)?;
    }
    out.flush()
}

fn interactive(shell: &mut Shell, json: bool) -> contract::ExitCode {
    let tty = io::stdin().is_terminal();
    if tty && !json {
        println!("sim-doctor card: type `help`; `quit` leaves.");
    }
    // The shell reads until EOF or `quit`: Ctrl-C ends the process like any command line tool.
    // SAFETY: SIG_DFL is a valid disposition; no handler pointer is involved.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
    let stdin = io::stdin();
    let mut line = String::new();
    loop {
        if tty && !json {
            print!("{}> ", shell.pwd());
            let _ = io::stdout().flush();
        }
        line.clear();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let reply = shell.exec(&line);
        if emit(&line, &reply, json).is_err() || reply.quit {
            break;
        }
    }
    finish(shell)
}
