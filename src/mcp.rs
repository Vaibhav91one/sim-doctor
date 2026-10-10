//! The tools of `sim-doctor mcp`: what an agent can call over the Model Context Protocol.
//!
//! The server loop (JSON-RPC 2.0 over stdio: `initialize`, `ping`, `tools/list`, `tools/call`,
//! the -32600 / -32601 / -32700 errors) is the kit's (`doctor_kit::mcp::serve`); this module is
//! the tool list. `scan`, `rules_list`, `rules_explain`, the three read-only eUICC queries
//! `euicc_info`, `euicc_profiles` and `euicc_notifications`, and the three read-only
//! GlobalPlatform queries `gp_info`, `gp_ara` and `gp_status`. The `euicc nickname` write is
//! deliberately not a tool.
//!
//! Each call runs this same binary as a subprocess (`scan --json ...`), so the envelope an agent
//! receives is byte for byte the one the CLI prints, and no card-handling code lives in this
//! module. The child's stdout is captured and never inherited: only JSON-RPC lines may reach this
//! process's stdout.
//!
//! [`tools`] is pure given a runner, so the argument checks and the exit-code mapping are tested
//! without spawning anything. The clap `scan` command is passed in by the binary, which keeps this
//! module a leaf with no dependency on `main.rs`.
//!
//! Acceptance by agent clients beyond the handshake is unverified.
use std::sync::Arc;
use std::time::Duration;

use clap::{ArgAction, Command};
use doctor_kit::mcp::{exec_self_with, ExecFailure, ExecFailureKind, ExecOpts};
use doctor_kit::McpTool;
use serde_json::{json, Map, Value};

/// This module's name in [`crate::MODULES`].
pub const NAME: &str = "mcp";

/// The server loop moved to the kit. These are the kit's own functions (they take the doctor
/// first, not a `scan` command and a runner): the names stay for one minor release.
#[deprecated(
    since = "0.4.0",
    note = "use `doctor_kit::mcp::{handle, process_line, serve}`"
)]
pub use doctor_kit::mcp::{handle, process_line, serve};

/// `scan` flags an agent cannot reach: `tui` is interactive, `json` is always
/// forced on, `help` and `version` make no sense over MCP, and `face`, `theme`, `color` and
/// `headless` only style a terminal report. `baseline`,
/// `fail-on` and `sarif` ARE exposed (doctor/1 section 7); `baseline` and
/// `sarif` take a path the agent chooses, as the CLI does.
const EXCLUDED: &[&str] = &[
    "tui", "json", "help", "version", "face", "theme", "color", "headless",
];

/// A call's default wall-clock limit; `SIM_DOCTOR_MCP_TIMEOUT_SECONDS` overrides it.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);
/// Most bytes kept from each of a child's stdout and stderr.
const OUTPUT_CAP: usize = 16 * 1024 * 1024;

/// The scan flags exposed to agents: (long name, help, kind).
fn scan_flags(scan: &Command) -> Vec<(String, String, &'static str)> {
    scan.get_arguments()
        .filter(|a| !a.is_positional())
        .filter_map(|a| {
            let long = a.get_long()?;
            if EXCLUDED.contains(&long) {
                return None;
            }
            let kind = if matches!(a.get_action(), ArgAction::SetTrue | ArgAction::SetFalse) {
                "boolean"
            } else if a.get_value_parser().type_id() == std::any::TypeId::of::<usize>() {
                "integer"
            } else {
                "string"
            };
            let help = a.get_help().map(|h| h.to_string()).unwrap_or_default();
            Some((long.to_string(), help, kind))
        })
        .collect()
}

/// The read-only reader tools: (tool name, command, subcommand, description).
const READER_TOOLS: [(&str, &str, &str, &str); 6] = [
    ("euicc_info", "euicc", "info", "Read the EID, EUICCInfo1 and EUICCInfo2 of the eUICC in a PC/SC reader (lpac chip info), as the sim-doctor lpac envelope. Read-only. Needs an eUICC and a reader."),
    ("euicc_profiles", "euicc", "profiles", "List the profiles on the eUICC in a PC/SC reader (lpac profile list), as the sim-doctor lpac envelope. Read-only. Needs an eUICC and a reader."),
    ("euicc_notifications", "euicc", "notifications", "List pending notification metadata on the eUICC in a PC/SC reader (lpac notification list), as the sim-doctor lpac envelope. Nothing is retrieved or removed. Needs an eUICC and a reader."),
    ("gp_info", "gp", "info", "Read the GlobalPlatform ISD, CPLC, card data, key information and counters of the card in a PC/SC reader, as the sim-doctor gp envelope. Read-only: SELECT and GET DATA only. Needs a card and a reader."),
    ("gp_ara", "gp", "ara", "Select the ARA-M and read every applet access rule (GET DATA all), decoded, as the sim-doctor gp envelope. Read-only, no keys. Needs a card and a reader."),
    ("gp_status", "gp", "status", "List the GlobalPlatform ISD, applications and load files (GET STATUS) and decode Card Recognition Data, as the sim-doctor gp envelope. Read-only, no keys; a scope that needs a secure channel is reported as requiring authentication. Needs a card and a reader."),
];

/// The tools this server exposes, in MCP `tools/list` shape.
pub fn tool_list(scan: &Command) -> Value {
    let props: Map<String, Value> = scan_flags(scan)
        .into_iter()
        .map(|(name, help, kind)| (name, json!({ "type": kind, "description": help })))
        .collect();
    let mut tools = vec![
        json!({
            "name": "scan",
            "description": "Scan the card in a PC/SC reader and return the sim-doctor JSON envelope. Needs a card and a reader.",
            "inputSchema": { "type": "object", "properties": props, "additionalProperties": false },
        }),
        json!({
            "name": "rules_list",
            "description": "List the rules a scan runs, as the sim-doctor JSON envelope. No card needed.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        }),
        json!({
            "name": "rules_explain",
            "description": "Explain one rule by id (for example gsma/msl-zero-allowed), as the sim-doctor JSON envelope. No card needed.",
            "inputSchema": {
                "type": "object",
                "properties": { "id": { "type": "string", "description": "The rule id." } },
                "required": ["id"],
                "additionalProperties": false,
            },
        }),
    ];
    for (name, _, _, description) in READER_TOOLS {
        tools.push(json!({
            "name": name,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": { "reader": { "type": "string", "description": "The reader to use, matched against the driver's own name." } },
                "additionalProperties": false,
            },
        }));
    }
    json!({ "tools": tools })
}

/// Validate a tool call and build the child argv, or say why it is refused.
fn build_argv(scan: &Command, name: &str, args: &Value) -> Result<Vec<String>, String> {
    let empty = Map::new();
    let obj = match args {
        Value::Null => &empty,
        Value::Object(m) => m,
        _ => return Err("arguments must be an object".into()),
    };
    match name {
        "rules_list" => {
            if let Some(k) = obj.keys().next() {
                return Err(format!("unknown argument \"{k}\""));
            }
            Ok(vec!["rules".into(), "list".into(), "--json".into()])
        }
        "rules_explain" => {
            if let Some(k) = obj.keys().find(|k| *k != "id") {
                return Err(format!("unknown argument \"{k}\""));
            }
            let id = obj
                .get("id")
                .ok_or_else(|| "missing required argument \"id\"".to_string())?
                .as_str()
                .ok_or_else(|| "\"id\" must be a string".to_string())?;
            if id.is_empty() || id.starts_with('-') {
                return Err("\"id\" must be a rule id, not a flag".into());
            }
            Ok(vec![
                "rules".into(),
                "explain".into(),
                id.into(),
                "--json".into(),
            ])
        }
        _ if READER_TOOLS.iter().any(|(n, ..)| *n == name) => {
            let (_, cmd, sub, _) = READER_TOOLS.iter().find(|(n, ..)| *n == name).unwrap();
            if let Some(k) = obj.keys().find(|k| *k != "reader") {
                return Err(format!("unknown argument \"{k}\""));
            }
            let mut argv = vec![cmd.to_string(), sub.to_string(), "--json".to_string()];
            if let Some(reader) = obj.get("reader") {
                let reader = reader
                    .as_str()
                    .ok_or_else(|| "\"reader\" must be a string".to_string())?;
                if reader.starts_with('-') {
                    return Err("\"reader\" must not start with '-'".into());
                }
                argv.extend(["--reader".to_string(), reader.to_string()]);
            }
            Ok(argv)
        }
        "scan" => {
            let flags = scan_flags(scan);
            let mut argv = vec!["scan".to_string(), "--json".to_string()];
            for (key, value) in obj {
                let (_, _, kind) = flags
                    .iter()
                    .find(|(n, _, _)| n == key)
                    .ok_or_else(|| format!("unknown argument \"{key}\""))?;
                let flag = format!("--{key}");
                match (*kind, value) {
                    ("boolean", Value::Bool(true)) => argv.push(flag),
                    ("boolean", Value::Bool(false)) => {}
                    ("integer", Value::Number(n)) if n.is_u64() => {
                        argv.push(flag);
                        argv.push(n.to_string());
                    }
                    ("string", Value::String(s)) => {
                        // So a value can never be parsed as another flag.
                        if s.starts_with('-') {
                            return Err(format!("\"{key}\" must not start with '-'"));
                        }
                        argv.push(flag);
                        argv.push(s.clone());
                    }
                    _ => return Err(format!("\"{key}\" must be of type {kind}")),
                }
            }
            Ok(argv)
        }
        other => Err(format!("unknown tool {other}")),
    }
}

fn error_text(what: &str, stderr: &str) -> String {
    if stderr.trim().is_empty() {
        what.to_string()
    } else {
        stderr.to_string()
    }
}

/// How a tool runs its argv: [`run_self`] in the server, a stand-in in tests.
pub type Runner = Arc<dyn Fn(&[String]) -> Result<String, String> + Send + Sync>;

/// The tools `mcp` offers, for the kit's server: [`tool_list`] as [`McpTool`]s whose call checks
/// the arguments ([`build_argv`]) and runs the argv.
pub fn tools(scan: &Command, run: Runner) -> Vec<McpTool> {
    let list = tool_list(scan);
    list["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|tool| {
            let name = tool["name"].as_str().unwrap_or_default().to_owned();
            let (scan, run, called) = (scan.clone(), run.clone(), name.clone());
            McpTool {
                description: tool["description"].as_str().unwrap_or_default().to_owned(),
                schema: tool["inputSchema"].clone(),
                call: Box::new(move |args| {
                    build_argv(&scan, &called, args).and_then(|argv| run(&argv))
                }),
                name,
            }
        })
        .collect()
}

/// `SIM_DOCTOR_MCP_TIMEOUT_SECONDS`, or the default when unset, 0 or not a number.
fn timeout_from(var: Option<&str>) -> Duration {
    match var.and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(n) if n > 0 => Duration::from_secs(n),
        _ => DEFAULT_TIMEOUT,
    }
}

/// The text of a failed child, the way this server has always worded it: 0, 1 (findings) and 3
/// (new findings against a baseline) are results; anything else is an error with the child's
/// stderr untrimmed, or a plain sentence when it said nothing.
fn failure_text(f: &ExecFailure) -> String {
    match f.kind {
        ExecFailureKind::Spawn => format!(
            "could not run sim-doctor: {}",
            f.detail.strip_prefix("cannot start: ").unwrap_or(&f.detail)
        ),
        ExecFailureKind::OutputLimit => {
            format!("{}\n[output truncated at {} bytes]", f.stdout, f.max_bytes)
        }
        ExecFailureKind::Timeout => format!(
            "timed out after {} s; the child was killed",
            f.timeout.map_or(0, |t| t.as_secs())
        ),
        ExecFailureKind::Signal => error_text("the process did not exit normally", &f.stderr),
        ExecFailureKind::Exit => error_text(
            &format!("exit code {}", f.code.map_or(-1, i64::from)),
            &f.stderr,
        ),
    }
}

/// Run this binary with `argv` under the timeout and output cap.
pub fn run_self(argv: &[String]) -> Result<String, String> {
    let var = std::env::var("SIM_DOCTOR_MCP_TIMEOUT_SECONDS").ok();
    let opts = ExecOpts {
        ok_codes: vec![0, 1, 3],
        timeout: Some(timeout_from(var.as_deref())),
        max_bytes: OUTPUT_CAP,
    };
    exec_self_with(argv, &opts, failure_text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{value_parser, Arg};
    use std::sync::Mutex;

    // A stand-in for main.rs's `scan` subcommand (the binary's Cli is not
    // reachable from the lib). The process test in tests/process_contract.rs
    // checks the real one end to end.
    fn fake_scan() -> Command {
        Command::new("scan")
            .arg(Arg::new("json").long("json").action(ArgAction::SetTrue))
            .arg(Arg::new("reader").long("reader").help("The reader."))
            .arg(
                Arg::new("max-depth")
                    .long("max-depth")
                    .value_parser(value_parser!(usize)),
            )
            .arg(
                Arg::new("score")
                    .long("score")
                    .action(ArgAction::SetTrue)
                    .help("A score."),
            )
            .arg(Arg::new("baseline").long("baseline"))
            .arg(Arg::new("fail-on").long("fail-on"))
            .arg(Arg::new("sarif").long("sarif"))
            .arg(Arg::new("tui").long("tui").action(ArgAction::SetTrue))
    }

    /// Calls a tool with a runner that records its argv and answers `code`.
    fn call(name: &str, args: Value, code: i32) -> (Result<String, String>, Option<Vec<String>>) {
        let seen = Arc::new(Mutex::new(None));
        let record = seen.clone();
        let run: Runner = Arc::new(move |argv| {
            *record.lock().unwrap() = Some(argv.to_vec());
            if [0, 1, 3].contains(&code) {
                Ok("ENVELOPE".into())
            } else {
                Err("BOOM".into())
            }
        });
        let all = tools(&fake_scan(), run);
        let tool = all.iter().find(|t| t.name == name).expect("a listed tool");
        let result = (tool.call)(&args);
        let argv = seen.lock().unwrap().take();
        (result, argv)
    }

    fn never() -> Runner {
        Arc::new(|_| panic!("runner must not be called"))
    }

    #[test]
    fn tools_are_exactly_the_nine_with_object_schemas() {
        let all = tools(&fake_scan(), never());
        let names: Vec<_> = all.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "scan",
                "rules_list",
                "rules_explain",
                "euicc_info",
                "euicc_profiles",
                "euicc_notifications",
                "gp_info",
                "gp_ara",
                "gp_status"
            ]
        );
        for t in &all {
            assert_eq!(t.schema["type"], "object");
            assert!(!t.description.is_empty());
        }
    }

    #[test]
    fn scan_schema_is_generated_and_exposes_the_contract_flags() {
        let scan = fake_scan();
        let list = tool_list(&scan);
        let props = list["tools"][0]["inputSchema"]["properties"]
            .as_object()
            .unwrap();
        for a in scan.get_arguments() {
            let id = a.get_id().as_str();
            if EXCLUDED.contains(&id) {
                assert!(!props.contains_key(id), "{id} must not be exposed");
            } else {
                assert!(props.contains_key(id), "{id} missing from the scan schema");
            }
        }
        for flag in ["baseline", "fail-on", "sarif"] {
            assert!(
                props.contains_key(flag),
                "{flag} must be exposed (doctor/1 section 7)"
            );
        }
        assert_eq!(props["max-depth"]["type"], "integer");
        assert_eq!(props["score"]["type"], "boolean");
        assert_eq!(props["reader"]["type"], "string");
        assert_eq!(props["reader"]["description"], "The reader.");
    }

    fn failed(kind: ExecFailureKind) -> ExecFailure {
        ExecFailure {
            kind,
            stdout: "x".into(),
            stderr: "BOOM\n".into(),
            code: Some(2),
            signal: None,
            timeout: Some(Duration::from_secs(5)),
            max_bytes: 1000,
            detail: "cannot start: no such file".into(),
        }
    }

    /// The error texts of a failed child, word for word.
    #[test]
    fn a_failed_child_is_worded_as_it_always_was() {
        let text = |k| failure_text(&failed(k));
        assert_eq!(
            text(ExecFailureKind::Timeout),
            "timed out after 5 s; the child was killed"
        );
        assert_eq!(
            text(ExecFailureKind::OutputLimit),
            "x\n[output truncated at 1000 bytes]"
        );
        assert_eq!(
            text(ExecFailureKind::Spawn),
            "could not run sim-doctor: no such file"
        );
        // stderr is returned as the child wrote it, trailing newline and all.
        assert_eq!(text(ExecFailureKind::Exit), "BOOM\n");
        assert_eq!(text(ExecFailureKind::Signal), "BOOM\n");
        let mut quiet = failed(ExecFailureKind::Exit);
        quiet.stderr = "  \n".into();
        assert_eq!(failure_text(&quiet), "exit code 2");
        quiet.kind = ExecFailureKind::Signal;
        assert_eq!(failure_text(&quiet), "the process did not exit normally");
    }

    #[test]
    fn the_timeout_env_falls_back_on_zero_and_junk() {
        assert_eq!(timeout_from(None), DEFAULT_TIMEOUT);
        assert_eq!(timeout_from(Some("0")), DEFAULT_TIMEOUT);
        assert_eq!(timeout_from(Some("abc")), DEFAULT_TIMEOUT);
        assert_eq!(timeout_from(Some("7")), Duration::from_secs(7));
    }

    #[test]
    fn bad_calls_are_errors_and_never_spawn() {
        let cases = [
            ("scan", json!({"tui": true})),
            ("scan", json!({"json": true})),
            ("scan", json!({"reader": "--sarif"})),
            ("scan", json!({"max-depth": "3"})),
            ("scan", json!({"max-depth": -1})),
            ("scan", json!({"score": "yes"})),
            ("rules_list", json!({"x": 1})),
            ("rules_explain", json!({})),
            ("rules_explain", json!({"id": "--json"})),
            ("rules_explain", json!({"id": 5})),
        ];
        let all = tools(&fake_scan(), never());
        for (name, args) in cases {
            let tool = all.iter().find(|t| t.name == name).unwrap();
            assert!((tool.call)(&args).is_err(), "{name} {args}");
        }
    }

    #[test]
    fn valid_calls_build_the_argv() {
        let (_, argv) = call(
            "scan",
            json!({"reader": "A B", "max-depth": 3, "score": true}),
            0,
        );
        let argv = argv.unwrap();
        assert_eq!(&argv[..2], ["scan", "--json"]);
        for pair in [["--reader", "A B"], ["--max-depth", "3"]] {
            assert!(argv.windows(2).any(|w| w == pair), "{argv:?}");
        }
        assert!(argv.contains(&"--score".to_string()));
        assert_eq!(
            call("rules_list", json!({}), 0).1.unwrap(),
            ["rules", "list", "--json"]
        );
        assert_eq!(
            call("rules_explain", json!({"id": "gsma/x"}), 0).1.unwrap(),
            ["rules", "explain", "gsma/x", "--json"]
        );
    }

    #[test]
    fn euicc_tools_run_the_read_only_subcommands() {
        for (tool, sub) in [
            ("euicc_info", "info"),
            ("euicc_profiles", "profiles"),
            ("euicc_notifications", "notifications"),
        ] {
            assert_eq!(
                call(tool, json!({}), 0).1.unwrap(),
                ["euicc", sub, "--json"]
            );
            assert_eq!(
                call(tool, json!({"reader": "R 1"}), 1).1.unwrap(),
                ["euicc", sub, "--json", "--reader", "R 1"]
            );
        }
        let all = tools(&fake_scan(), never());
        let tool = all.iter().find(|t| t.name == "euicc_info").unwrap();
        for args in [
            json!({"aid": "A0"}),
            json!({"reader": "--json"}),
            json!({"reader": 1}),
        ] {
            assert!((tool.call)(&args).is_err());
        }
    }

    #[test]
    fn gp_tools_run_the_read_only_subcommands() {
        let all = tools(&fake_scan(), never());
        for (tool, sub) in [
            ("gp_info", "info"),
            ("gp_ara", "ara"),
            ("gp_status", "status"),
        ] {
            assert_eq!(call(tool, json!({}), 0).1.unwrap(), ["gp", sub, "--json"]);
            assert_eq!(
                call(tool, json!({"reader": "R 1"}), 1).1.unwrap(),
                ["gp", sub, "--json", "--reader", "R 1"]
            );
            let t = all.iter().find(|t| t.name == tool).unwrap();
            assert!((t.call)(&json!({"trace": true})).is_err());
        }
    }

    #[test]
    fn exit_codes_map_to_is_error() {
        for code in [0, 1, 3] {
            assert_eq!(call("rules_list", json!({}), code).0, Ok("ENVELOPE".into()));
        }
        for code in [129, 130, 2, 101] {
            assert_eq!(
                call("rules_list", json!({}), code).0,
                Err("BOOM".into()),
                "code {code}"
            );
        }
    }
}
