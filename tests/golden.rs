//! Golden snapshots of every MACHINE-readable output (migration step S0).
//!
//! The doctor-kit migration must not change a single byte of what an agent or a
//! CI job parses: the `--json` envelopes, the SARIF file, the command names in
//! `--help`, the MCP wire text, the files `install` writes, and the exit codes.
//! This file pins today's bytes under `tests/golden/`; every later migration PR
//! must keep it green without regenerating anything.
//!
//! Human terminal text (`scan` without `--json`, `rules list`, ...) is
//! deliberately NOT snapshotted: it is allowed to change.
//!
//! Compare: every test builds the output, normalises it (below) and compares
//! BYTES with the committed file. Regenerate with
//!
//! ```text
//! UPDATE_GOLDENS=1 cargo test --test golden
//! ```
//!
//! then read `git diff tests/golden` before committing: a diff is a behaviour
//! change by definition.
//!
//! Normalisation (the only edits made to output before comparing; each is
//! applied by `norm`):
//! * the crate version, `CARGO_PKG_VERSION`, becomes `<VERSION>`, so a release
//!   bump does not churn every file;
//! * `HOST_ERROR`: where the failure depends on the machine (no PC/SC
//!   service, readers attached) the `"error":{"kind":..,"message":..}` object
//!   becomes `"error":<HOST_ERROR>`. The envelope around it stays exact;
//! * the per-run temp directory path becomes `<TMP>`.
//!
//! The scan pipeline cannot read a card on a test machine, so the success
//! envelopes come from the library entry points the binary itself calls
//! (`walk` -> `access` -> `ef` -> `tar` -> `scan::findings` -> `Verdict` ->
//! `scan::doctor_json` -> `sarif`) over an in-process card. The failure and
//! no-card paths, `rules`, `why`, `fix`, `trace`, `modules`, `install`, `ci`,
//! `completions`, `--help` and `mcp` run the real binary.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sim_doctor::access;
use sim_doctor::baseline::{Baseline, Diff};
use sim_doctor::contract;
use sim_doctor::ef;
use sim_doctor::rules::Severity;
use sim_doctor::sarif;
use sim_doctor::scan::{self, Context, Dialect, Subject, Verdict};
use sim_doctor::session::Policy;
use sim_doctor::tar::{self, Selection};
use sim_doctor::transport::{CardSession, Error, ReaderName};
use sim_doctor::ts48;
use sim_doctor::walk::{self, Candidates, Limits};

// ---------------------------------------------------------------------------
// Compare / regenerate
// ---------------------------------------------------------------------------

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// Replaces what legitimately differs between runs and machines. See the
/// module documentation; nothing else is touched.
fn norm(text: &str, tmp: Option<&Path>) -> String {
    let mut out = text.replace(env!("CARGO_PKG_VERSION"), "<VERSION>");
    if let Some(tmp) = tmp {
        out = out.replace(&tmp.to_string_lossy().into_owned(), "<TMP>");
    }
    out
}

/// `"error":{"kind":"..","message":".."}` -> `"error":<HOST_ERROR>`, and the
/// payload-level `message` beside it likewise.
fn host_error(text: &str) -> String {
    let re = regex::Regex::new(r#""error":\{"kind":"[^"]*","message":"[^"]*"\}"#).unwrap();
    let text = re.replace_all(text, r#""error":<HOST_ERROR>"#);
    // The legacy `{type,payload}` envelope repeats the message beside the data.
    let re = regex::Regex::new(r#""payload":\{"code":(\d+),"message":"[^"]*""#).unwrap();
    re.replace_all(&text, r#""payload":{"code":$1,"message":<HOST_ERROR>"#)
        .into_owned()
}

/// Compares `actual` with `tests/golden/<name>` byte for byte, or rewrites the
/// file when `UPDATE_GOLDENS` is set.
fn check(name: &str, actual: &str) {
    let path = golden_dir().join(name);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let want = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "missing golden {}: {e}\nrun: UPDATE_GOLDENS=1 cargo test --test golden",
            path.display()
        )
    });
    if want != actual.as_bytes() {
        let want = String::from_utf8_lossy(&want).into_owned();
        let line = want
            .lines()
            .zip(actual.lines())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| want.lines().count().min(actual.lines().count()));
        panic!(
            "golden {name} differs (first differing line {}):\n  golden: {}\n  actual: {}\n\
             machine output must stay byte-identical; if the change is intended: \
             UPDATE_GOLDENS=1 cargo test --test golden",
            line + 1,
            want.lines().nth(line).unwrap_or("<end>"),
            actual.lines().nth(line).unwrap_or("<end>"),
        );
    }
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("golden-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// An in-process card (a reduced tests/corpus.rs Card)
// ---------------------------------------------------------------------------

/// Answers SELECT by path, GET RESPONSE and the whole-APDU ENVELOPE of a TAR
/// probe. With `msl0`, TAR 000000 answers `6D 00` and every other TAR `94 04`
/// (the card runs at MSL 0); without it every TAR gets `94 04`.
struct Card {
    files: HashMap<Vec<u8>, Vec<u8>>,
    queued: Vec<Vec<u8>>,
    msl0: bool,
    reader: ReaderName,
}

fn atom(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, u8::try_from(body.len()).unwrap()];
    out.extend_from_slice(body);
    out
}

impl Card {
    fn new(msl0: bool) -> Self {
        let mut card = Self {
            files: HashMap::new(),
            queued: Vec::new(),
            msl0,
            reader: ReaderName::new("golden card").unwrap(),
        };
        for (path, size) in [
            ("3F00", None),
            ("3F00/2FE2", Some(10u16)),
            ("3F00/7F20", None),
            ("3F00/7F20/6F07", Some(4)),
        ] {
            let ids: Vec<u8> = path
                .split('/')
                .flat_map(|s| u16::from_str_radix(s, 16).unwrap().to_be_bytes())
                .collect();
            let mut body = Vec::new();
            if let Some(size) = size {
                body.extend(atom(0x80, &size.to_be_bytes()));
            }
            body.extend(atom(
                0x82,
                if size.is_some() {
                    &[0x09, 0x21]
                } else {
                    &[0x38, 0x21]
                },
            ));
            body.extend(atom(0x83, &ids[ids.len() - 2..]));
            card.files.insert(ids, atom(0x62, &body));
        }
        card
    }
}

impl CardSession for Card {
    fn reader(&self) -> &ReaderName {
        &self.reader
    }

    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
        match command.get(1) {
            Some(0xC0) => Ok(if self.queued.is_empty() {
                vec![0x6F, 0x00]
            } else {
                let mut body = self.queued.remove(0);
                body.extend_from_slice(&[0x90, 0x00]);
                body
            }),
            Some(0xA4) => {
                let body = command.get(5..).unwrap_or_default();
                let mut path = if command.get(2) == Some(&0x08) {
                    vec![0x3F, 0x00]
                } else {
                    Vec::new()
                };
                path.extend_from_slice(body);
                Ok(match self.files.get(&path) {
                    Some(fcp) => {
                        self.queued.push(fcp.clone());
                        vec![0x61, u8::try_from(fcp.len()).unwrap()]
                    }
                    None => vec![0x6A, 0x82],
                })
            }
            Some(0xC2) => {
                let zero = tar::envelope_data(tar::TAR_MIN, tar::Class::Etsi).unwrap();
                Ok(if self.msl0 && command.get(5..) == Some(zero.as_slice()) {
                    vec![0x6D, 0x00]
                } else {
                    vec![0x94, 0x04]
                })
            }
            _ => Ok(vec![0x6D, 0x00]),
        }
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// What one scan of the card produced, via the same calls `run_scan` makes.
struct Scanned {
    envelope: String,
    sarif: String,
}

/// Candidate identifiers probed per directory: the binary's full SIM families
/// (1280, which makes a big `data.absent` list) or a short list for the variants.
fn candidates(full: bool) -> Candidates {
    if full {
        Candidates::SimFamilies
    } else {
        Candidates::List(
            ["2F06", "2FE2", "6F07", "7F20"]
                .iter()
                .map(|s| s.parse().unwrap())
                .collect(),
        )
    }
}

fn scan_card(
    full: bool,
    msl0: bool,
    limits: Limits,
    severity: Option<Severity>,
    baseline: Option<&str>,
    tmp: &Path,
) -> Scanned {
    let mut card = Card::new(msl0);
    let options = walk::Options {
        addressing: walk::Addressing::PathFromMasterFile,
        candidates: candidates(full),
        limits,
        ..walk::Options::default()
    };
    let dialect = Dialect::default();
    let mut tree = walk::walk(&mut card, &dialect.tag_set(), &options).expect("walk");
    access::resolve(&mut card, &mut tree, &Policy::default()).expect("access");
    ef::read(&mut card, &mut tree, &Policy::default()).expect("ef");
    let audit = tar::audit_with(
        &mut card,
        &Selection::focused(),
        &Policy::default(),
        false,
        &mut || false,
    )
    .expect("tar");
    let found = scan::findings(&Subject {
        tree: &tree,
        tar: &audit,
        scp03: None,
    })
    .expect("rules");
    let mut verdict = Verdict::new(found, scan::rules_run())
        .tar_audit(audit)
        .at_least(severity)
        .scored(true);
    let context = Context::new(
        "golden card",
        Some(&[0x3B, 0x9F, 0x95]),
        dialect,
        options.candidates.clone(),
        options.limits,
    );
    let facts = scan::run_facts(&tree, &context, &verdict);
    if let Some(text) = baseline {
        let saved = Baseline::from_envelope(text).expect("baseline");
        let diff = Diff::compare(&saved, &facts, verdict.findings().as_slice())
            .unwrap_or_else(|_| panic!("the baseline is comparable"));
        verdict = verdict.compared_against(diff);
    }
    let exit = verdict.exit_code(Severity::Critical);
    let score = scan::doctor_score(&tree, &context, &verdict, &facts);
    let doc = sarif::to_sarif(verdict.findings().as_slice(), &scan::specs(), &score);
    let path = tmp.join("out.sarif");
    sarif::write(&path, &doc).unwrap();
    let envelope = scan::doctor_json(&tree, &context, &verdict, &facts, exit);
    Scanned {
        envelope: norm(&serde_json::to_string(&envelope).unwrap(), None) + "\n",
        sarif: norm(&std::fs::read_to_string(path).unwrap(), None),
    }
}

#[test]
fn scan_envelopes_and_sarif() {
    let tmp = tmp_dir("scan");
    let none = Limits::default;

    // The binary's own candidate set (all of 2Fxx/4Fxx/5Fxx/6Fxx/7Fxx), with SARIF.
    let full = scan_card(true, true, none(), None, None, &tmp);
    check("scan_msl0_full.json", &full.envelope);
    check("scan_msl0_full.sarif", &full.sarif);

    // The variants use a short candidate list, which keeps the files small.
    let msl0 = scan_card(false, true, none(), None, None, &tmp);
    check("scan_msl0.json", &msl0.envelope);
    check("scan_msl0.sarif", &msl0.sarif);
    let clean = scan_card(false, false, none(), None, None, &tmp);
    check("scan_clean.json", &clean.envelope);
    check("scan_clean.sarif", &clean.sarif);

    // --severity: the level in force is reported as data.findings_detail.severity_threshold.
    let high = scan_card(false, true, none(), Some(Severity::High), None, &tmp);
    check("scan_msl0_severity_high.json", &high.envelope);

    // A truncated walk (the walk stops at --max-nodes).
    let limits = Limits {
        max_nodes: 2,
        ..none()
    };
    let truncated = scan_card(false, true, limits, None, None, &tmp);
    check("scan_msl0_truncated.json", &truncated.envelope);

    // --baseline: same findings (unchanged, exit 0) and a regression (new, exit 3).
    // The baseline text is the golden envelope itself, as a user saves it.
    let same = scan_card(false, true, none(), None, Some(&msl0.envelope), &tmp);
    check("scan_msl0_vs_msl0.json", &same.envelope);
    let regressed = scan_card(false, true, none(), None, Some(&clean.envelope), &tmp);
    check("scan_msl0_vs_clean.json", &regressed.envelope);
}

#[test]
fn ts48_compare_envelope() {
    let mut card = Card::new(false);
    let options = walk::Options {
        addressing: walk::Addressing::PathFromMasterFile,
        candidates: candidates(false),
        ..walk::Options::default()
    };
    let tree = walk::walk(&mut card, &Dialect::default().tag_set(), &options).unwrap();
    let fixture = ts48::Fixture::bundled().unwrap();
    let comparison = ts48::compare(&fixture.files, &ts48::observe(&tree));
    let complete = tree.is_complete();
    let findings = ts48::findings(&comparison, None);
    let data = ts48::to_json(
        &fixture,
        &comparison,
        &findings,
        "golden card",
        Dialect::default().id(),
        complete,
    );
    let envelope = contract::Envelope::new(
        ts48::KIND,
        contract::ExitCode::Success,
        contract::OK_MESSAGE,
        data,
    );
    check(
        "ts48_compare.json",
        &(norm(&envelope.to_json().unwrap(), None) + "\n"),
    );
}

// ---------------------------------------------------------------------------
// The real binary
// ---------------------------------------------------------------------------

struct Out {
    code: i32,
    stdout: String,
}

/// Runs `sim-doctor args` with a clean environment (no agent variables, no
/// record log), in `cwd` when given.
fn bin(args: &[&str], cwd: Option<&Path>, stdin: Option<&str>) -> Out {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sim-doctor"));
    cmd.args(args)
        .env_remove("SIM_DOCTOR_RECORD")
        .env_remove("CLAUDECODE")
        .env_remove("SIM_DOCTOR_AGENT")
        .env_remove("CURSOR_AGENT")
        .env_remove("CODEX_SANDBOX")
        .env_remove("OPENCODE")
        .env("NO_COLOR", "1")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    let mut child = cmd.spawn().expect("spawn sim-doctor");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    Out {
        code: out.status.code().expect("exited, not killed"),
        stdout: String::from_utf8(out.stdout).unwrap(),
    }
}

/// Every command path, found by walking the `Commands:` section of `-h`.
fn command_paths() -> Vec<Vec<String>> {
    fn walk_help(prefix: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
        out.push(prefix.clone());
        let args: Vec<&str> = prefix.iter().map(String::as_str).chain(["-h"]).collect();
        let help = bin(&args, None, None).stdout;
        let mut in_commands = false;
        for line in help.lines() {
            if line == "Commands:" {
                in_commands = true;
            } else if in_commands {
                if !line.starts_with("  ") {
                    break;
                }
                let name = line.split_whitespace().next().unwrap().to_owned();
                if name != "help" {
                    prefix.push(name);
                    walk_help(prefix, out);
                    prefix.pop();
                }
            }
        }
    }
    let mut out = Vec::new();
    walk_help(&mut Vec::new(), &mut out);
    out
}

#[test]
fn help_and_version() {
    let mut text = String::new();
    let version = bin(&["--version"], None, None);
    writeln!(
        text,
        "$ sim-doctor --version [exit {}]\n{}",
        version.code, version.stdout
    )
    .unwrap();
    for path in command_paths() {
        let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
        args.push("-h");
        let out = bin(&args, None, None);
        writeln!(
            text,
            "$ sim-doctor {} [exit {}]\n{}",
            args.join(" "),
            out.code,
            out.stdout
        )
        .unwrap();
    }
    check("help.txt", &norm(&text, None));
}

#[test]
fn completions() {
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let out = bin(&["completions", shell], None, None);
        assert_eq!(out.code, 0, "{shell}");
        check(&format!("completions.{shell}"), &norm(&out.stdout, None));
    }
}

#[test]
fn rules_modules_trace_and_fuzz_dry_run() {
    let list = bin(&["rules", "list", "--json"], None, None);
    check("rules_list.json", &list.stdout);

    // `rules explain` and `why` for every rule id the list carries.
    let doc: serde_json::Value = serde_json::from_str(&list.stdout).unwrap();
    let ids: Vec<&str> = doc["payload"]["data"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    let mut explain = String::new();
    for id in &ids {
        let out = bin(&["rules", "explain", id, "--json"], None, None);
        writeln!(
            explain,
            "$ rules explain {id} --json [exit {}]\n{}",
            out.code, out.stdout
        )
        .unwrap();
        let out = bin(&["why", id, "--json"], None, None);
        writeln!(
            explain,
            "$ why {id} --json [exit {}]\n{}",
            out.code, out.stdout
        )
        .unwrap();
    }
    check("rules_explain_why.txt", &explain);

    check(
        "modules.json",
        &bin(&["modules", "--json"], None, None).stdout,
    );

    let trace = golden_dir().join("inputs/trace.hex");
    let trace = trace.to_str().unwrap();
    check(
        "trace.json",
        &bin(&["trace", trace, "--json"], None, None).stdout,
    );

    // The mock-card mutation fuzzer needs no reader: plan only, fixed seed.
    let fuzz = bin(
        &[
            "fuzz",
            "mutate",
            "--mock",
            "--dry-run",
            "--json",
            "--max-cases",
            "5",
        ],
        None,
        None,
    );
    check("fuzz_mutate_dry_run.json", &norm(&fuzz.stdout, None));
}

#[test]
fn why_and_fix_read_a_saved_envelope() {
    let tmp = tmp_dir("saved");
    // The envelope is made here, not read from a golden, so this test does not
    // depend on another one having written its file first.
    let file = tmp.join("scan.json");
    let saved = scan_card(false, true, Limits::default(), None, None, &tmp);
    std::fs::write(&file, saved.envelope).unwrap();
    let file = file.to_str().unwrap();
    let why = bin(&["why", file, "--json"], None, None);
    let fix = bin(
        &["fix", "gsma/msl-zero-allowed", "--from", file],
        None,
        None,
    );
    let mut text = String::new();
    writeln!(
        text,
        "$ why <envelope> --json [exit {}]\n{}",
        why.code, why.stdout
    )
    .unwrap();
    writeln!(
        text,
        "$ fix gsma/msl-zero-allowed --from <envelope> [exit {}]\n{}",
        fix.code, fix.stdout
    )
    .unwrap();
    check("why_fix_saved.txt", &norm(&text, Some(&tmp)));
}

#[test]
fn install_and_ci_bodies() {
    let mut text = String::new();
    for args in [
        vec!["install", "--print-only"],
        vec!["install", "--print-only", "--agent", "claude"],
        vec!["install", "--print-only", "--agent", "cursor"],
        vec!["install", "--print-only", "--agent", "codex"],
        vec!["install", "--print-only", "--agent", "opencode"],
        vec!["ci", "install", "--print-only"],
        vec![
            "ci",
            "install",
            "--print-only",
            "--swsim",
            "false",
            "--severity",
            "high",
        ],
    ] {
        let out = bin(&args, None, None);
        writeln!(
            text,
            "$ sim-doctor {} [exit {}]\n{}",
            args.join(" "),
            out.code,
            out.stdout
        )
        .unwrap();
    }
    check("install_print_only.txt", &norm(&text, None));

    // A real install into a project that already has an AGENTS.md, twice: the
    // marked block is replaced in place and the rest of the file is untouched.
    let dir = tmp_dir("install");
    std::fs::write(dir.join("AGENTS.md"), "# Project\n\nkeep me\n").unwrap();
    let mut files = String::new();
    for run in 1..=2 {
        let out = bin(&["install"], Some(&dir), None);
        assert_eq!(out.code, 0);
        writeln!(files, "##### after install #{run}").unwrap();
        for rel in [
            ".claude/skills/sim-doctor/SKILL.md",
            ".cursor/rules/sim-doctor.mdc",
            "AGENTS.md",
        ] {
            writeln!(
                files,
                "===== {rel}\n{}",
                std::fs::read_to_string(dir.join(rel)).unwrap()
            )
            .unwrap();
        }
    }
    check("install_files.txt", &norm(&files, None));

    let ci = bin(&["ci", "install"], Some(&dir), None);
    assert_eq!(ci.code, 0);
    check(
        "ci_workflow.yml",
        &norm(
            &std::fs::read_to_string(dir.join(".github/workflows/sim-doctor.yml")).unwrap(),
            None,
        ),
    );
}

/// Exit codes and stdout of every path that needs no card. The no-reader runs
/// depend on the machine (is a PC/SC service running, which readers exist), so
/// only their `data.error` object is normalised (`host_error`); the exit code
/// and every other byte are compared.
#[test]
fn no_card_paths_exit_codes_and_stdout() {
    let tmp = tmp_dir("nocard");
    let garbage = tmp.join("garbage.json");
    std::fs::write(&garbage, "not json").unwrap();
    let not_envelope = tmp.join("other.json");
    std::fs::write(&not_envelope, r#"{"hello":"world"}"#).unwrap();
    let (garbage, not_envelope) = (garbage.to_str().unwrap(), not_envelope.to_str().unwrap());

    let cases: Vec<(&str, Vec<&str>, bool)> = vec![
        (
            "scan: unknown reader",
            vec!["scan", "--json", "--reader", "golden-no-such-reader"],
            true,
        ),
        (
            "scan: baseline missing",
            vec!["scan", "--json", "--baseline", "/nonexistent/golden.json"],
            false,
        ),
        (
            "scan: baseline not json",
            vec!["scan", "--json", "--baseline", garbage],
            false,
        ),
        (
            "scan: baseline not an envelope",
            vec!["scan", "--json", "--baseline", not_envelope],
            false,
        ),
        (
            "scan: bad --tar",
            vec!["scan", "--json", "--tar", "bogus"],
            false,
        ),
        (
            "scan: bad --severity",
            vec!["scan", "--json", "--severity", "bogus"],
            false,
        ),
        (
            "scan: bad --fail-on",
            vec!["scan", "--json", "--fail-on", "bogus"],
            false,
        ),
        (
            "scan: --terminal-profile needs --tar",
            vec!["scan", "--json", "--terminal-profile"],
            false,
        ),
        (
            "ts48 compare: unknown reader",
            vec![
                "ts48",
                "compare",
                "--json",
                "--reader",
                "golden-no-such-reader",
            ],
            true,
        ),
        ("unknown subcommand", vec!["bogus"], false),
        ("no subcommand", vec![], false),
        (
            "rules explain: unknown id",
            vec!["rules", "explain", "no/such-rule", "--json"],
            false,
        ),
        (
            "why: unknown id",
            vec!["why", "no/such-rule", "--json"],
            false,
        ),
        (
            "trace: missing file",
            vec!["trace", "/nonexistent/golden.hex", "--json"],
            false,
        ),
        (
            "trace: not a trace",
            vec!["trace", garbage, "--json"],
            false,
        ),
        (
            "fix: unknown rule",
            vec!["fix", "no/such-rule", "--from", not_envelope],
            false,
        ),
        (
            "fuzz apdu: refuses without opt-in",
            vec!["fuzz", "apdu", "--json"],
            false,
        ),
        (
            "fuzz mutate: bad replay file",
            vec!["fuzz", "mutate", "--json", "--replay", garbage],
            false,
        ),
        ("mcp: not a TTY, immediate EOF", vec!["mcp"], false),
    ];
    let mut text = String::new();
    for (name, args, host) in cases {
        let out = bin(&args, None, None);
        let stdout = if host {
            host_error(&out.stdout)
        } else {
            out.stdout
        };
        writeln!(
            text,
            "# {name}: sim-doctor {}\nexit {}\n{}",
            args.join(" "),
            out.code,
            stdout
        )
        .unwrap();
    }
    check("no_card_exit_codes.txt", &norm(&text, Some(&tmp)));
}

// ---------------------------------------------------------------------------
// MCP over stdio
// ---------------------------------------------------------------------------

#[test]
fn mcp_transcript() {
    let requests = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"golden","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rules_list","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"rules_explain","arguments":{"id":"gsma/msl-zero-allowed"}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"scan","arguments":{"tui":true}}}"#,
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":7,"method":"no/such/method"}"#,
        "not json",
    ];
    let mut input = requests.join("\n");
    input.push('\n');
    let out = bin(&["mcp"], None, Some(&input));
    assert_eq!(out.code, 0);
    let mut text = String::new();
    for (request, response) in requests
        .iter()
        .filter(|r| r.contains("\"id\"") || !r.starts_with('{'))
        .zip(out.stdout.lines())
    {
        writeln!(text, "-> {request}\n<- {response}").unwrap();
    }
    assert_eq!(
        out.stdout.lines().count(),
        8,
        "one response per request that has an id"
    );
    check("mcp_transcript.txt", &norm(&text, None));
}
