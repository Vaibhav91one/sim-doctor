//! Process-level goldens of `scan` (migration step S0b).
//!
//! `tests/golden.rs` pins the library's envelopes; it cannot pin what only the
//! binary decides: which flag does what, the exit code, the bytes on stdout,
//! the SARIF file, what a refused `--baseline` prints. This file runs the real
//! binary over a recorded card session, with no reader and no PC/SC service:
//! `SIM_DOCTOR_TEST_REPLAY=<log>` makes `scan` answer from a log in the format
//! `SIM_DOCTOR_RECORD` writes (see `transport::replay`), and the log is made
//! here by running the same library calls `scan` makes over an in-process card.
//!
//! The doctor-kit migration must keep every byte of this output. Regenerate
//! (only for an intended change) with `UPDATE_GOLDENS=1 cargo test --test
//! golden_scan` and read `git diff tests/golden` first.
//!
//! A full `scan --json` envelope is 150 KB (the whole `data.absent` list), so
//! the bulk cases are stored as `sha256` + length and the readable ones in full;
//! `tests/golden/proc_scan_msl0.json` is one complete envelope for people to read.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};
use sim_doctor::access;
use sim_doctor::ef;
use sim_doctor::session::Policy;
use sim_doctor::tar::{self, Selection};
use sim_doctor::transport::replay::Record;
use sim_doctor::transport::{CardSession, Error, ReaderName};
use sim_doctor::walk::{self, Candidates, Limits};

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn check(name: &str, actual: &str) {
    let path = golden_dir().join(name);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing golden {}: {e}\nrun: UPDATE_GOLDENS=1 cargo test --test golden_scan",
            path.display()
        )
    });
    if want != actual {
        let line = want
            .lines()
            .zip(actual.lines())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| want.lines().count().min(actual.lines().count()));
        panic!(
            "golden {name} differs (first differing line {}):\n  golden: {}\n  actual: {}\n\
             machine output must stay byte-identical",
            line + 1,
            want.lines().nth(line).unwrap_or("<end>"),
            actual.lines().nth(line).unwrap_or("<end>"),
        );
    }
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("golden-scan-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// An in-process card (the one tests/golden.rs uses) and the session log of a scan
// ---------------------------------------------------------------------------

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

/// The exchanges `scan` makes on this card with these bounds and this TAR
/// selection: the same library calls, in the same order, as `run_scan`.
fn log(msl0: bool, limits: Limits, selection: &Selection) -> String {
    let mut session = Record::new(Card::new(msl0), Vec::new());
    let options = walk::Options {
        addressing: walk::Addressing::PathFromMasterFile,
        candidates: Candidates::SimFamilies,
        limits,
        ..walk::Options::default()
    };
    let dialect = sim_doctor::scan::Dialect::default();
    let mut tree = walk::walk(&mut session, &dialect.tag_set(), &options).expect("walk");
    access::resolve(&mut session, &mut tree, &Policy::default()).expect("access");
    ef::read(&mut session, &mut tree, &Policy::default()).expect("ef");
    tar::audit_with(
        &mut session,
        selection,
        &Policy::default(),
        false,
        &mut || false,
    )
    .expect("tar");
    String::from_utf8(session.into_log()).unwrap()
}

// ---------------------------------------------------------------------------
// Running the binary
// ---------------------------------------------------------------------------

struct Ran {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], replay: Option<&Path>) -> Ran {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sim-doctor"));
    cmd.args(args)
        .env_remove("SIM_DOCTOR_RECORD")
        .env_remove("SIM_DOCTOR_TEST_REPLAY")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(log) = replay {
        cmd.env("SIM_DOCTOR_TEST_REPLAY", log);
    }
    let out = cmd.output().expect("spawn sim-doctor");
    Ran {
        code: out.status.code().expect("exited, not killed"),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn norm(text: &str, tmp: &Path) -> String {
    text.replace(env!("CARGO_PKG_VERSION"), "<VERSION>")
        .replace(&tmp.to_string_lossy().into_owned(), "<TMP>")
}

/// One case as text: the command, the exit code, stderr in full, stdout in full
/// when short or as a digest when long, and the SARIF file when one was asked for.
fn show(label: &str, args: &[&str], r: &Ran, tmp: &Path, files: &[&Path], full: bool) -> String {
    let mut out = String::new();
    writeln!(out, "# {label}: sim-doctor {}", norm(&args.join(" "), tmp)).unwrap();
    writeln!(out, "exit {}", r.code).unwrap();
    writeln!(out, "--- stderr\n{}", norm(&r.stderr, tmp)).unwrap();
    let stdout = norm(&r.stdout, tmp);
    if full || stdout.len() < 6000 {
        writeln!(out, "--- stdout\n{stdout}").unwrap();
    } else {
        let digest = Sha256::digest(stdout.as_bytes());
        writeln!(
            out,
            "--- stdout: {} bytes, sha256 {}",
            stdout.len(),
            hex::encode(digest)
        )
        .unwrap();
    }
    for file in files {
        match std::fs::read(file) {
            Ok(bytes) => {
                let text = norm(&String::from_utf8_lossy(&bytes), tmp);
                let digest = Sha256::digest(text.as_bytes());
                writeln!(
                    out,
                    "--- file {}: {} bytes, sha256 {}",
                    file.file_name().unwrap().to_string_lossy(),
                    text.len(),
                    hex::encode(digest)
                )
                .unwrap();
            }
            Err(_) => writeln!(
                out,
                "--- file {}: absent",
                file.file_name().unwrap().to_string_lossy()
            )
            .unwrap(),
        }
    }
    out
}

#[test]
fn scan_through_the_binary() {
    let tmp = tmp_dir("main");
    let focused = Selection::focused();
    let write = |name: &str, text: String| -> PathBuf {
        let path = tmp.join(name);
        std::fs::write(&path, text).unwrap();
        path
    };
    let msl0 = write("msl0.log", log(true, Limits::default(), &focused));
    let clean = write("clean.log", log(false, Limits::default(), &focused));
    let off = write(
        "off.log",
        log(true, Limits::default(), &Selection::default()),
    );
    let small = write(
        "small.log",
        log(
            true,
            Limits {
                max_nodes: 2,
                ..Limits::default()
            },
            &focused,
        ),
    );

    let mut text = String::new();
    let mut case = |label: &str, args: &[&str], replay: Option<&Path>, files: &[&Path]| -> Ran {
        let r = run(args, replay);
        text.push_str(&show(label, args, &r, &tmp, files, false));
        r
    };

    // The reference envelope, stored whole.
    let first = run(&["scan", "--json", "--tar", "focused"], Some(&msl0));
    assert_eq!(first.code, 1, "{}", first.stderr);
    check("proc_scan_msl0.json", &norm(&first.stdout, &tmp));

    case(
        "msl0, default --fail-on (critical)",
        &["scan", "--json", "--tar", "focused"],
        Some(&msl0),
        &[],
    );
    case(
        "clean card",
        &["scan", "--json", "--tar", "focused"],
        Some(&clean),
        &[],
    );
    case(
        "TAR audit off (the default)",
        &["scan", "--json"],
        Some(&off),
        &[],
    );
    case(
        "--fail-on info",
        &["scan", "--json", "--tar", "focused", "--fail-on", "info"],
        Some(&msl0),
        &[],
    );
    case(
        "--fail-on high",
        &["scan", "--json", "--tar", "focused", "--fail-on", "high"],
        Some(&msl0),
        &[],
    );
    case(
        "--severity high",
        &["scan", "--json", "--tar", "focused", "--severity", "high"],
        Some(&msl0),
        &[],
    );
    case(
        "--severity critical --fail-on info",
        &[
            "scan",
            "--json",
            "--tar",
            "focused",
            "--severity",
            "critical",
            "--fail-on",
            "info",
        ],
        Some(&msl0),
        &[],
    );
    case(
        "--score with --json",
        &["scan", "--json", "--tar", "focused", "--score"],
        Some(&msl0),
        &[],
    );
    case(
        "truncated walk (--max-nodes 2)",
        &["scan", "--json", "--tar", "focused", "--max-nodes", "2"],
        Some(&small),
        &[],
    );
    case(
        "--terminal-profile needs --tar",
        &["scan", "--json", "--terminal-profile"],
        Some(&msl0),
        &[],
    );
    case(
        "bad --fail-on is a usage error (2 on scan)",
        &["scan", "--json", "--fail-on", "bogus"],
        Some(&msl0),
        &[],
    );
    case(
        "--tui conflicts with --json (2 on scan)",
        &["scan", "--json", "--tui"],
        Some(&msl0),
        &[],
    );
    // The human report: the exit code and stderr are pinned, its text is not.
    let human = run(&["scan", "--tar", "focused"], Some(&msl0));
    writeln!(
        text,
        "# human report: exit {}\n--- stderr\n{}",
        human.code,
        norm(&human.stderr, &tmp)
    )
    .unwrap();
    assert!(human.stdout.contains("gsma/msl-zero-allowed"));
    let human_tui = run(&["scan", "--tar", "focused", "--tui"], Some(&msl0));
    writeln!(
        text,
        "# --tui without a terminal: exit {}\n--- stderr\n{}",
        human_tui.code,
        norm(&human_tui.stderr, &tmp)
    )
    .unwrap();
    assert_eq!(
        human_tui.stdout, human.stdout,
        "plain report when not a TTY"
    );

    // SARIF: written, and the report still printed.
    let sarif = tmp.join("out.sarif");
    let r = run(
        &[
            "scan",
            "--json",
            "--tar",
            "focused",
            "--sarif",
            sarif.to_str().unwrap(),
        ],
        Some(&msl0),
    );
    text.push_str(&show(
        "--sarif",
        &[
            "scan",
            "--json",
            "--tar",
            "focused",
            "--sarif",
            sarif.to_str().unwrap(),
        ],
        &r,
        &tmp,
        &[&sarif],
        false,
    ));
    let sarif_text = norm(&std::fs::read_to_string(&sarif).unwrap(), &tmp);
    check("proc_scan_msl0.sarif", &sarif_text);

    // A SARIF path that cannot be written: exit 2, the report is still printed
    // and its exit_code says 2.
    let unwritable = tmp.join("no-such-dir").join("out.sarif");
    let args = [
        "scan",
        "--json",
        "--tar",
        "focused",
        "--sarif",
        unwritable.to_str().unwrap(),
    ];
    let r = run(&args, Some(&msl0));
    text.push_str(&show(
        "--sarif to an unwritable path",
        &args,
        &r,
        &tmp,
        &[&unwritable],
        false,
    ));
    let v: serde_json::Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(
        v["exit_code"], 2,
        "the printed exit_code is the process exit"
    );

    // --baseline: saved the way a user saves one.
    let saved_clean = write(
        "clean.json",
        run(&["scan", "--json", "--tar", "focused"], Some(&clean)).stdout,
    );
    let saved_msl0 = write("msl0.json", first.stdout.clone());
    let saved_small = write(
        "small.json",
        run(
            &["scan", "--json", "--tar", "focused", "--max-nodes", "2"],
            Some(&small),
        )
        .stdout,
    );
    for (label, base, log) in [
        ("baseline: same findings", &saved_msl0, &msl0),
        (
            "baseline: a new finding gates (exit 3)",
            &saved_clean,
            &msl0,
        ),
        ("baseline: the finding is fixed", &saved_msl0, &clean),
        (
            "baseline from a truncated walk is refused",
            &saved_small,
            &msl0,
        ),
    ] {
        let args = [
            "scan",
            "--json",
            "--tar",
            "focused",
            "--baseline",
            base.to_str().unwrap(),
        ];
        let r = run(&args, Some(log));
        text.push_str(&show(label, &args, &r, &tmp, &[], false));
    }
    let base = saved_clean.to_str().unwrap();
    for (label, extra) in [
        ("baseline with --fail-on info", ["--fail-on", "info"]),
        ("baseline with --severity high", ["--severity", "high"]),
    ] {
        let args = [
            "scan",
            "--json",
            "--tar",
            "focused",
            "--baseline",
            base,
            extra[0],
            extra[1],
        ];
        let r = run(&args, Some(&msl0));
        text.push_str(&show(label, &args, &r, &tmp, &[], false));
    }
    // A baseline under a different TAR selection is refused rather than compared.
    let args = ["scan", "--json", "--baseline", saved_msl0.to_str().unwrap()];
    let r = run(&args, Some(&off));
    text.push_str(&show(
        "baseline taken under another --tar",
        &args,
        &r,
        &tmp,
        &[],
        false,
    ));

    // --sarif and --baseline naming one file: refused before any card is read, nothing written.
    let same = tmp.join("same.json");
    std::fs::copy(&saved_clean, &same).unwrap();
    let args = [
        "scan",
        "--json",
        "--tar",
        "focused",
        "--baseline",
        same.to_str().unwrap(),
        "--sarif",
        same.to_str().unwrap(),
    ];
    let r = run(&args, Some(&msl0));
    text.push_str(&show(
        "--sarif is the --baseline file",
        &args,
        &r,
        &tmp,
        &[],
        false,
    ));
    assert_eq!(
        std::fs::read(&same).unwrap(),
        std::fs::read(&saved_clean).unwrap(),
        "the baseline was not overwritten"
    );
    // ...in the human mode too: no envelope, just the sentence and exit 2.
    let args = [
        "scan",
        "--baseline",
        same.to_str().unwrap(),
        "--sarif",
        same.to_str().unwrap(),
    ];
    let r = run(&args, Some(&msl0));
    text.push_str(&show(
        "--sarif is the --baseline file (no --json)",
        &args,
        &r,
        &tmp,
        &[],
        false,
    ));

    check("proc_scan.txt", &text);
}

/// Baseline files the loader has always refused or accepted, byte for byte what
/// `scan` says about each. Runs before any card is read, so no replay log.
#[test]
fn baseline_files_through_the_binary() {
    let tmp = tmp_dir("baseline");
    let mut text = String::new();
    let envelope = r#"{"schema":"doctor/1","tool":"sim-doctor","version":"0","exit_code":0,"score":{"value":100,"label":"good","model":"sim/1","coverage_gaps":0},"findings":[],"data":{}}"#;
    let long = "x".repeat(2000);
    let cases: Vec<(&str, String)> = vec![
        (
            "a bare array of findings",
            r#"[{"id":"a/b","fingerprint":"0123456789abcdef"}]"#.into(),
        ),
        ("an envelope of a failed run (no data.run)", envelope.into()),
        (
            "not the doctor/1 schema",
            r#"{"schema":"other/1","findings":[]}"#.into(),
        ),
        (
            "a string over the bound",
            format!(r#"{{"schema":"doctor/1","findings":[],"data":{{"run":{{"x":"{long}"}}}}}}"#),
        ),
        ("an empty file", String::new()),
        ("a directory instead of a file", "<DIR>".into()),
    ];
    for (n, (label, body)) in cases.iter().enumerate() {
        let path = tmp.join(format!("b{n}.json"));
        if body == "<DIR>" {
            std::fs::create_dir_all(&path).unwrap();
        } else {
            std::fs::write(&path, body).unwrap();
        }
        let args = ["scan", "--json", "--baseline", path.to_str().unwrap()];
        let r = run(&args, None);
        text.push_str(&show(label, &args, &r, &tmp, &[], true));
    }
    check("proc_scan_baseline_files.txt", &text);
}

/// stdout that cannot be written is an error of the run (exit 2 for `scan`, a sentence on
/// stderr naming what it could not write), never a panic (101) and never a silent 0. The kit
/// prints with `print!`, which panics on a closed pipe, so this is pinned for `scan`.
#[cfg(unix)]
#[test]
fn a_scan_that_cannot_write_its_report_exits_2_and_says_so() {
    use std::os::unix::io::FromRawFd;
    let tmp = tmp_dir("closed");
    let msl0 = tmp.join("msl0.log");
    std::fs::write(&msl0, log(true, Limits::default(), &Selection::focused())).unwrap();
    let mut text = String::new();
    for (label, extra) in [("--json", Some("--json")), ("human report", None)] {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` has room for the two descriptors `pipe` writes.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // Not inherited by the child: only the write end is handed over, as its stdout.
        for fd in fds {
            // SAFETY: a descriptor this test just opened.
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        // SAFETY: the read end is ours alone; closing it makes every write fail with EPIPE.
        unsafe { libc::close(fds[0]) };
        // SAFETY: the write end is ours alone, so the `Stdio` is its only owner.
        let stdout = unsafe { Stdio::from_raw_fd(fds[1]) };
        let mut args = vec!["scan", "--tar", "focused"];
        args.extend(extra);
        let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
            .args(&args)
            .env("SIM_DOCTOR_TEST_REPLAY", &msl0)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        writeln!(
            text,
            "# {label}: exit {}\n--- stderr\n{}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr)
        )
        .unwrap();
    }
    check("proc_scan_closed_stdout.txt", &text);
}

/// The kept contract fix: `--sarif` and `--baseline` naming one file are refused however the
/// two paths are spelled (before, only identical spellings were), and nothing is written.
#[test]
fn sarif_and_baseline_are_one_file_however_spelled() {
    let tmp = tmp_dir("samefile");
    let msl0 = tmp.join("msl0.log");
    std::fs::write(&msl0, log(true, Limits::default(), &Selection::focused())).unwrap();
    let base = tmp.join("base.json");
    let saved = run(&["scan", "--json", "--tar", "focused"], Some(&msl0)).stdout;
    std::fs::write(&base, &saved).unwrap();
    std::fs::create_dir_all(tmp.join("sub")).unwrap();
    let respelled = tmp.join("sub").join("..").join("base.json");
    let args = [
        "scan",
        "--json",
        "--tar",
        "focused",
        "--baseline",
        base.to_str().unwrap(),
        "--sarif",
        respelled.to_str().unwrap(),
    ];
    let r = run(&args, Some(&msl0));
    assert_eq!(std::fs::read_to_string(&base).unwrap(), saved);
    check(
        "proc_scan_fixed_contract.txt",
        &show("same file, spelled two ways", &args, &r, &tmp, &[], true),
    );
}
