//! A Model Context Protocol server: JSON-RPC 2.0 over stdio, no new crates.
//!
//! `sim-doctor mcp` lets a coding agent call the scan and the rule catalogue as
//! tools instead of shelling out. Three tools only: `scan`, `rules_list` and
//! `rules_explain`.
//!
//! Each call runs this same binary as a subprocess (`scan --json ...`), so the
//! envelope an agent receives is byte for byte the one the CLI prints, and no
//! card-handling code lives in this module. The child's stdout is captured and
//! never inherited: only JSON-RPC lines may reach this process's stdout.
//!
//! `handle` and [`process_line`] are pure given a runner, so the protocol is
//! tested without spawning anything. The clap `scan` command is passed in by
//! the binary, which keeps this module a leaf with no dependency on `main.rs`.
//!
//! GitHub / agent-client acceptance beyond the handshake is unverified.
use std::io::{self, BufRead, Write};
use std::process::{Command as Process, Stdio};

use clap::{ArgAction, Command};
use serde_json::{json, Map, Value};

/// This module's name in [`crate::MODULES`].
pub const NAME: &str = "mcp";

/// `scan` flags an agent must never reach: `baseline`, `diff` and `sarif` read
/// or write files (an agent could overwrite one), `tui` is interactive, and
/// `json` is always forced on.
const EXCLUDED: &[&str] = &[
    "baseline", "diff", "sarif", "tui", "json", "help", "version",
];

/// What running one tool as a child process produced.
pub struct ToolOutcome {
    /// Exit code, or `None` when the child could not be spawned or was killed.
    pub code: Option<i32>,
    /// Captured stdout of the child.
    pub stdout: String,
    /// Captured stderr of the child.
    pub stderr: String,
}

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

/// The tools this server exposes, in MCP `tools/list` shape.
pub fn tool_list(scan: &Command) -> Value {
    let props: Map<String, Value> = scan_flags(scan)
        .into_iter()
        .map(|(name, help, kind)| (name, json!({ "type": kind, "description": help })))
        .collect();
    json!({ "tools": [
        {
            "name": "scan",
            "description": "Scan the card in a PC/SC reader and return the sim-doctor JSON envelope. Needs a card and a reader.",
            "inputSchema": { "type": "object", "properties": props, "additionalProperties": false },
        },
        {
            "name": "rules_list",
            "description": "List the rules a scan runs, as the sim-doctor JSON envelope. No card needed.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        },
        {
            "name": "rules_explain",
            "description": "Explain one rule by id (for example gsma/msl-zero-allowed), as the sim-doctor JSON envelope. No card needed.",
            "inputSchema": {
                "type": "object",
                "properties": { "id": { "type": "string", "description": "The rule id." } },
                "required": ["id"],
                "additionalProperties": false,
            },
        },
    ] })
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

/// Map a child's outcome to an MCP tool result. 0 and 1 (findings, regressed)
/// carry the envelope; everything else is an error with the child's stderr.
fn tool_result(out: ToolOutcome) -> Value {
    let (text, is_error) = match out.code {
        Some(0) | Some(1) => (out.stdout, false),
        Some(c) => (error_text(&format!("exit code {c}"), &out.stderr), true),
        None => (
            error_text("the process did not exit normally", &out.stderr),
            true,
        ),
    };
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

fn error_text(what: &str, stderr: &str) -> String {
    if stderr.trim().is_empty() {
        what.to_string()
    } else {
        stderr.to_string()
    }
}

fn refused(message: String) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Handle one JSON-RPC request; `None` for a notification or a request with no method.
pub fn handle(
    req: &Value,
    scan: &Command,
    runner: &dyn Fn(&[String]) -> ToolOutcome,
) -> Option<Value> {
    let method = req.get("method").and_then(Value::as_str)?;
    // A request without an id is a notification and is never answered.
    let id = req.get("id").cloned()?;
    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "sim-doctor", "version": env!("CARGO_PKG_VERSION") },
        }),
        "tools/list" => tool_list(scan),
        "tools/call" => {
            let name = req
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let args = req.pointer("/params/arguments").unwrap_or(&Value::Null);
            match build_argv(scan, name, args) {
                Ok(argv) => tool_result(runner(&argv)),
                Err(message) => refused(message),
            }
        }
        other => return Some(error(id, -32601, &format!("unknown method {other}"))),
    };
    Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

/// One input line to at most one response line. Malformed JSON is a -32700
/// with a null id, never a crash, so the loop carries on.
pub fn process_line(
    line: &str,
    scan: &Command,
    runner: &dyn Fn(&[String]) -> ToolOutcome,
) -> Option<Value> {
    if line.trim().is_empty() {
        return None;
    }
    match serde_json::from_str::<Value>(line) {
        Ok(req) => handle(&req, scan, runner),
        Err(e) => Some(error(Value::Null, -32700, &format!("parse error: {e}"))),
    }
}

/// Run this binary with `argv`, capturing both streams. Stdin is closed so a
/// child can never read the JSON-RPC stream.
fn run_self(argv: &[String]) -> ToolOutcome {
    let spawned = std::env::current_exe().and_then(|exe| {
        Process::new(exe)
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
    });
    match spawned {
        Ok(o) => ToolOutcome {
            code: o.status.code(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        },
        Err(e) => ToolOutcome {
            code: None,
            stdout: String::new(),
            stderr: format!("could not run sim-doctor: {e}"),
        },
    }
}

/// Serve JSON-RPC over stdin/stdout until EOF.
pub fn serve(scan: &Command) -> io::Result<()> {
    let mut stdout = io::stdout();
    for line in io::stdin().lock().lines() {
        if let Some(resp) = process_line(&line?, scan, &run_self) {
            writeln!(stdout, "{resp}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{value_parser, Arg};
    use std::cell::Cell;

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
            .arg(Arg::new("sarif").long("sarif"))
            .arg(Arg::new("diff").long("diff").action(ArgAction::SetTrue))
    }

    fn call(name: &str, args: Value, code: i32) -> (Value, Option<Vec<String>>) {
        let seen = Cell::new(None);
        let runner = |argv: &[String]| {
            seen.set(Some(argv.to_vec()));
            ToolOutcome {
                code: Some(code),
                stdout: "ENVELOPE".into(),
                stderr: "BOOM".into(),
            }
        };
        let req = json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":name,"arguments":args}});
        let r = handle(&req, &fake_scan(), &runner).unwrap();
        (r["result"].clone(), seen.take())
    }

    fn never(_: &[String]) -> ToolOutcome {
        panic!("runner must not be called")
    }

    fn req(method: &str, id: Option<i64>) -> Value {
        match id {
            Some(i) => json!({"jsonrpc":"2.0","id":i,"method":method}),
            None => json!({"jsonrpc":"2.0","method":method}),
        }
    }

    #[test]
    fn initialize_shape() {
        let r = handle(&req("initialize", Some(1)), &fake_scan(), &never).unwrap();
        assert_eq!(r["id"], 1);
        assert_eq!(r["result"]["protocolVersion"], "2024-11-05");
        assert!(r["result"]["capabilities"]["tools"].is_object());
        assert_eq!(r["result"]["serverInfo"]["name"], "sim-doctor");
        assert_eq!(
            r["result"]["serverInfo"]["version"],
            env!("CARGO_PKG_VERSION")
        );
    }

    #[test]
    fn tools_list_has_exactly_the_three_tools_with_object_schemas() {
        let r = handle(&req("tools/list", Some(2)), &fake_scan(), &never).unwrap();
        let tools = r["result"]["tools"].as_array().unwrap();
        let names: Vec<_> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["scan", "rules_list", "rules_explain"]);
        for t in tools {
            assert_eq!(t["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn scan_schema_is_generated_and_hides_file_flags() {
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
        assert_eq!(props["max-depth"]["type"], "integer");
        assert_eq!(props["score"]["type"], "boolean");
        assert_eq!(props["reader"]["type"], "string");
        assert_eq!(props["reader"]["description"], "The reader.");
    }

    #[test]
    fn a_notification_gets_no_response_and_no_method_is_ignored() {
        assert!(handle(
            &req("notifications/initialized", None),
            &fake_scan(),
            &never
        )
        .is_none());
        assert!(handle(&json!({"jsonrpc":"2.0","id":1}), &fake_scan(), &never).is_none());
    }

    #[test]
    fn unknown_method_is_32601() {
        let r = handle(&req("nope", Some(3)), &fake_scan(), &never).unwrap();
        assert_eq!(r["error"]["code"], -32601);
        assert_eq!(r["id"], 3);
    }

    #[test]
    fn bad_calls_are_errors_and_never_spawn() {
        let cases = [
            ("nope", json!({})),
            ("scan", json!({"baseline": "x.json"})),
            ("scan", json!({"sarif": "out.sarif"})),
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
        for (name, args) in cases {
            let req = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}});
            let r = handle(&req, &fake_scan(), &never).unwrap();
            assert_eq!(r["result"]["isError"], true, "{name} {args}");
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
    fn exit_codes_map_to_is_error() {
        for code in [0, 1] {
            let (r, _) = call("rules_list", json!({}), code);
            assert_eq!(r["isError"], false);
            assert_eq!(r["content"][0]["text"], "ENVELOPE");
        }
        for code in [129, 130, 2, 101] {
            let (r, _) = call("rules_list", json!({}), code);
            assert_eq!(r["isError"], true, "code {code}");
            assert_eq!(r["content"][0]["text"], "BOOM");
        }
        let spawn_failed = tool_result(ToolOutcome {
            code: None,
            stdout: String::new(),
            stderr: String::new(),
        });
        assert_eq!(spawn_failed["isError"], true);
    }

    #[test]
    fn a_malformed_line_is_32700_and_the_next_line_still_works() {
        let scan = fake_scan();
        let bad = process_line("{not json", &scan, &never).unwrap();
        assert_eq!(bad["error"]["code"], -32700);
        assert!(bad["id"].is_null());
        let good = process_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            &scan,
            &never,
        );
        assert!(good.is_some());
        assert!(process_line("   ", &scan, &never).is_none());
    }
}
