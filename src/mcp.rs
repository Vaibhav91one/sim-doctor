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
//! Acceptance by agent clients beyond the handshake is unverified.
use std::io::{self, BufRead, Read, Write};
use std::process::{Command as Process, Stdio};
use std::time::{Duration, Instant};

use clap::{ArgAction, Command};
use serde_json::{json, Map, Value};

/// This module's name in [`crate::MODULES`].
pub const NAME: &str = "mcp";

/// `scan` flags an agent cannot reach: `tui` is interactive, `json` is always
/// forced on, and `help` and `version` make no sense over MCP. `baseline`,
/// `fail-on` and `sarif` ARE exposed (doctor/1 section 7); `baseline` and
/// `sarif` take a path the agent chooses, as the CLI does.
const EXCLUDED: &[&str] = &["tui", "json", "help", "version"];

/// A call's default wall-clock limit; `SIM_DOCTOR_MCP_TIMEOUT_SECONDS` overrides it.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);
/// Most bytes kept from each of a child's stdout and stderr.
const OUTPUT_CAP: usize = 16 * 1024 * 1024;

/// What running one tool as a child process produced.
pub struct ToolOutcome {
    /// Exit code, or `None` when the child could not be spawned or was killed.
    pub code: Option<i32>,
    /// Captured stdout of the child.
    pub stdout: String,
    /// Captured stderr of the child.
    pub stderr: String,
    /// Whether stdout or stderr was cut at the capture cap.
    pub truncated: bool,
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

/// Map a child's outcome to an MCP tool result. 0, 1 (findings) and 3 (new
/// findings against a baseline) carry the envelope unchanged; everything else
/// is an error with the child's stderr.
fn tool_result(out: ToolOutcome) -> Value {
    if out.truncated {
        let text = format!("{}\n[output truncated at {OUTPUT_CAP} bytes]", out.stdout);
        return json!({ "content": [{ "type": "text", "text": text }], "isError": true });
    }
    let (text, is_error) = match out.code {
        Some(0) | Some(1) | Some(3) => (out.stdout, false),
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
    let Some(obj) = req.as_object() else {
        return Some(error(Value::Null, -32600, "invalid request: not an object"));
    };
    // Only a string or integer id can be echoed; anything else (null included)
    // is an invalid request answered with a null id.
    let id = match obj.get("id") {
        None => None,
        Some(v) if v.is_string() || v.is_i64() || v.is_u64() => Some(v.clone()),
        Some(_) => return Some(error(Value::Null, -32600, "invalid request: bad id")),
    };
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        return Some(error(
            id.unwrap_or(Value::Null),
            -32600,
            "invalid request: no string method",
        ));
    };
    // A request without an id is a notification and is never answered.
    let id = id?;
    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "sim-doctor", "version": env!("CARGO_PKG_VERSION") },
        }),
        "ping" => json!({}),
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
    line: &[u8],
    scan: &Command,
    runner: &dyn Fn(&[String]) -> ToolOutcome,
) -> Option<Value> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return None;
    }
    // Invalid UTF-8 is a parse error like any other malformed line.
    match serde_json::from_slice::<Value>(line) {
        Ok(req) => handle(&req, scan, runner),
        Err(e) => Some(error(Value::Null, -32700, &format!("parse error: {e}"))),
    }
}

/// `SIM_DOCTOR_MCP_TIMEOUT_SECONDS`, or the default when unset, 0 or not a number.
fn timeout_from(var: Option<&str>) -> Duration {
    match var.and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(n) if n > 0 => Duration::from_secs(n),
        _ => DEFAULT_TIMEOUT,
    }
}

/// Read a pipe to its end, keeping at most `cap` bytes. The rest is read and
/// dropped so the child never blocks on a full pipe.
fn capture(mut pipe: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let (mut kept, mut cut, mut buf) = (Vec::new(), false, [0u8; 8192]);
    while let Ok(n) = pipe.read(&mut buf) {
        if n == 0 {
            break;
        }
        let room = cap - kept.len();
        kept.extend_from_slice(&buf[..n.min(room)]);
        cut |= n > room;
    }
    (kept, cut)
}

/// Run `cmd` with captured, capped output and a hard deadline; kill it when
/// the deadline passes. Stdin is closed so a child can never read the
/// JSON-RPC stream.
fn run_with_deadline(mut cmd: Process, timeout: Duration, cap: usize) -> ToolOutcome {
    let failed = |stderr: String| ToolOutcome {
        code: None,
        stdout: String::new(),
        stderr,
        truncated: false,
    };
    let mut child = match cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return failed(format!("could not run sim-doctor: {e}")),
    };
    let out = child.stdout.take().expect("piped");
    let err = child.stderr.take().expect("piped");
    let out_t = std::thread::spawn(move || capture(out, cap));
    let err_t = std::thread::spawn(move || capture(err, cap));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return failed(format!("could not wait for sim-doctor: {e}")),
        }
    };
    let (stdout, cut_out) = out_t.join().unwrap_or_default();
    let (stderr, cut_err) = err_t.join().unwrap_or_default();
    let text = |b: Vec<u8>| String::from_utf8_lossy(&b).into_owned();
    match status {
        Ok(status) => ToolOutcome {
            code: status.code(),
            stdout: text(stdout),
            stderr: text(stderr),
            truncated: cut_out || cut_err,
        },
        Err(()) => failed(format!(
            "timed out after {} s; the child was killed",
            timeout.as_secs()
        )),
    }
}

/// Run this binary with `argv` under the timeout and output cap.
fn run_self(argv: &[String]) -> ToolOutcome {
    match std::env::current_exe() {
        Ok(exe) => {
            let mut cmd = Process::new(exe);
            cmd.args(argv);
            let var = std::env::var("SIM_DOCTOR_MCP_TIMEOUT_SECONDS").ok();
            run_with_deadline(cmd, timeout_from(var.as_deref()), OUTPUT_CAP)
        }
        Err(e) => ToolOutcome {
            code: None,
            stdout: String::new(),
            stderr: format!("could not run sim-doctor: {e}"),
            truncated: false,
        },
    }
}

/// Serve JSON-RPC over stdin/stdout until EOF. Calls are handled one at a time.
pub fn serve(scan: &Command) -> io::Result<()> {
    let mut stdout = io::stdout();
    let mut stdin = io::stdin().lock();
    let mut line = Vec::new();
    loop {
        line.clear();
        // Bytes, not `lines()`: a non-UTF-8 line must be a parse error, not the end of the server.
        if stdin.read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        if let Some(resp) = process_line(&line, scan, &run_self) {
            writeln!(stdout, "{resp}")?;
            stdout.flush()?;
        }
    }
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
            .arg(Arg::new("fail-on").long("fail-on"))
            .arg(Arg::new("sarif").long("sarif"))
            .arg(Arg::new("tui").long("tui").action(ArgAction::SetTrue))
    }

    fn call(name: &str, args: Value, code: i32) -> (Value, Option<Vec<String>>) {
        let seen = Cell::new(None);
        let runner = |argv: &[String]| {
            seen.set(Some(argv.to_vec()));
            ToolOutcome {
                code: Some(code),
                stdout: "ENVELOPE".into(),
                stderr: "BOOM".into(),
                truncated: false,
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

    #[test]
    fn a_notification_gets_no_response_and_no_method_is_ignored() {
        assert!(handle(
            &req("notifications/initialized", None),
            &fake_scan(),
            &never
        )
        .is_none());
    }

    #[test]
    fn invalid_requests_are_32600_and_echo_a_usable_id() {
        let scan = fake_scan();
        let code = |v: Value| handle(&v, &scan, &never).unwrap();
        let r = code(json!([{"jsonrpc":"2.0","id":1,"method":"ping"}]));
        assert_eq!(
            (r["error"]["code"].clone(), r["id"].clone()),
            (json!(-32600), Value::Null)
        );
        assert_eq!(code(json!(5))["error"]["code"], -32600);
        let r = code(json!({"jsonrpc":"2.0","id":4,"method":7}));
        assert_eq!(
            (r["error"]["code"].clone(), r["id"].clone()),
            (json!(-32600), json!(4))
        );
        let r = code(json!({"jsonrpc":"2.0","id":"abc"}));
        assert_eq!(
            (r["error"]["code"].clone(), r["id"].clone()),
            (json!(-32600), json!("abc"))
        );
        let r = code(json!({"jsonrpc":"2.0","id":null,"method":"ping"}));
        assert_eq!(
            (r["error"]["code"].clone(), r["id"].clone()),
            (json!(-32600), Value::Null)
        );
        let r = code(json!({"jsonrpc":"2.0","id":{"a":1},"method":"ping"}));
        assert_eq!(
            (r["error"]["code"].clone(), r["id"].clone()),
            (json!(-32600), Value::Null)
        );
    }

    #[test]
    fn ping_answers_an_empty_result() {
        let r = handle(&req("ping", Some(9)), &fake_scan(), &never).unwrap();
        assert_eq!(r["result"], json!({}));
    }

    #[test]
    fn non_utf8_input_is_32700_and_the_loop_continues() {
        let scan = fake_scan();
        let bad = process_line(b"\xff\xfe", &scan, &never).unwrap();
        assert_eq!(bad["error"]["code"], -32700);
        assert!(bad["id"].is_null());
        let ok = process_line(
            br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            &scan,
            &never,
        );
        assert_eq!(ok.unwrap()["result"], json!({}));
    }

    #[test]
    fn a_timed_out_or_truncated_child_is_an_error() {
        let t = tool_result(ToolOutcome {
            code: None,
            stdout: String::new(),
            stderr: "timed out after 5 s; the child was killed".into(),
            truncated: false,
        });
        assert_eq!(t["isError"], true);
        assert!(t["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("timed out after 5 s"));
        let t = tool_result(ToolOutcome {
            code: Some(0),
            stdout: "x".into(),
            stderr: String::new(),
            truncated: true,
        });
        assert_eq!(t["isError"], true);
        assert!(t["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("truncated"));
    }

    #[test]
    fn the_timeout_env_falls_back_on_zero_and_junk() {
        assert_eq!(timeout_from(None), DEFAULT_TIMEOUT);
        assert_eq!(timeout_from(Some("0")), DEFAULT_TIMEOUT);
        assert_eq!(timeout_from(Some("abc")), DEFAULT_TIMEOUT);
        assert_eq!(timeout_from(Some("7")), Duration::from_secs(7));
    }

    #[cfg(unix)]
    #[test]
    fn a_stalled_child_is_killed_at_the_deadline() {
        let mut p = Process::new("sleep");
        p.arg("30");
        let start = std::time::Instant::now();
        let out = run_with_deadline(p, Duration::from_millis(300), 1024);
        assert!(start.elapsed() < Duration::from_secs(10));
        assert_eq!(out.code, None);
        assert!(
            out.stderr.contains("the child was killed"),
            "{}",
            out.stderr
        );
    }

    #[cfg(unix)]
    #[test]
    fn output_is_capped_and_flagged() {
        let mut p = Process::new("sh");
        p.args(["-c", "head -c 100000 /dev/zero | tr '\\0' a"]);
        let out = run_with_deadline(p, Duration::from_secs(20), 1000);
        assert_eq!(out.stdout.len(), 1000);
        assert!(out.truncated);
        assert_eq!(out.code, Some(0));
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
        for code in [0, 1, 3] {
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
            truncated: false,
        });
        assert_eq!(spawn_failed["isError"], true);
    }

    #[test]
    fn a_malformed_line_is_32700_and_the_next_line_still_works() {
        let scan = fake_scan();
        let bad = process_line(b"{not json", &scan, &never).unwrap();
        assert_eq!(bad["error"]["code"], -32700);
        assert!(bad["id"].is_null());
        let good = process_line(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            &scan,
            &never,
        );
        assert!(good.is_some());
        assert!(process_line(b"   ", &scan, &never).is_none());
    }
}
