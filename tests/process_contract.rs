//! The output contract, asserted against the process rather than the enum.
//!
//! Every other test of the contract lives in `src/contract.rs` and asserts the
//! *value*: that `ExitCode::Interrupted` is 130, that an envelope serialises to
//! a particular string. That is necessary and it is not sufficient. An enum is
//! a thing the crate believes; an exit status is a thing the operating system
//! observed, and a build can satisfy every unit test in the crate while the
//! binary still exits 2 on a typo, because clap is what actually parses the
//! command line.
//!
//! So each test here spawns the built binary. `binary()` is
//! `env!("CARGO_BIN_EXE_sim-doctor")`, resolved by cargo at compile time, not
//! `cargo run` and not a path guessed at at runtime, and the assertions are
//! on the `ExitStatus` the kernel reported rather than on a value the crate
//! produced for itself.
//!
//! The SIGINT test is the one that cannot be faked. It does not call the exit
//! function; it sends a genuine SIGINT to a genuine child and asserts what the
//! operating system says happened. It also asserts the status is
//! `code() == Some(130)` rather than `signal() == Some(SIGINT)`, because those
//! are two different outcomes: the first is a process that handled the signal
//! and exited with the contract's number, the second is a process the kernel
//! killed because no handler was installed. They look identical in a shell and
//! they are not identical to an agent.

#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use sim_doctor::contract;

/// The binary under test, as built by cargo for this integration test.
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sim-doctor")
}

/// What one run of the binary produced.
struct Run {
    /// The real exit status, as the operating system reported it.
    status: ExitStatus,
    /// Everything the process wrote to stdout, byte for byte.
    stdout: String,
    /// Everything the process wrote to stderr, byte for byte.
    stderr: String,
}

impl Run {
    /// The exit status as a number, or a panic explaining the difference.
    ///
    /// A `None` here means the kernel killed the process rather than the
    /// process choosing an exit code, which on Unix is `signal() == Some(n)`.
    /// For this tool that is always a bug, so the message says what it was.
    fn code(&self) -> i32 {
        let status = self.status;
        self.status.code().unwrap_or_else(|| {
            panic!("the process was killed by a signal instead of exiting: {status:?}")
        })
    }
}

/// Runs the binary with stderr captured, and stdout replaced if asked.
fn run(args: &[&str], stdout: Stdio) -> Run {
    let output = Command::new(binary())
        .args(args)
        // Never inherit the harness's stdin. A child that can read a human's
        // terminal is a child whose behaviour depends on who ran the tests.
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("could not run the binary with {args:?}: {e}"));

    Run {
        status: output.status,
        stdout: String::from_utf8(output.stdout).expect("stdout is UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr is UTF-8"),
    }
}

/// Runs the binary with both streams captured from a pipe.
fn run_piped(args: &[&str]) -> Run {
    run(args, Stdio::piped())
}

/// Asserts that `raw` is exactly one JSON envelope and not one byte else.
///
/// This is the assertion that would fail if somebody added a `println!`. The
/// line count catches a stray line, the single `from_str` catches anything
/// trailing the object *and* anything before it, and the byte comparison catches
/// a reordering or a reformatting that still happens to parse.
///
/// Returns the parsed envelope so the caller can assert on its code.
fn assert_exactly_one_envelope(raw: &str, expected: contract::ExitCode) -> contract::Envelope {
    assert!(
        raw.ends_with('\n'),
        "stdout must end with the one newline that terminates the envelope: {raw:?}"
    );
    assert_eq!(
        raw.matches('\n').count(),
        1,
        "stdout is not a single line, so it is not a single envelope: {raw:?}"
    );

    let body = raw.strip_suffix('\n').expect("checked above");
    let envelope: contract::Envelope = serde_json::from_str(body)
        .unwrap_or_else(|e| panic!("stdout is not one JSON envelope: {e}\n{body:?}"));

    assert_eq!(
        envelope.to_json().unwrap(),
        body,
        "the envelope does not re-serialise to the bytes that are on stdout"
    );
    assert_eq!(envelope.payload().code(), expected);
    envelope
}
/// The phrase `main.rs` prints on stderr once the child has installed its
/// handler and reached its first interrupt checkpoint.
///
/// Waiting for that sentence before signalling is what makes the SIGINT test
/// deterministic rather than merely usually right. Sleeping a fixed interval
/// instead is what made it flaky: these tests run on parallel threads, several
/// children are exec'd at once, and a cold exec on a loaded runner outlived any
/// fixed delay - so the signal landed before `install()` had returned, hit the
/// kernel's default disposition, and the process died of SIGINT instead of
/// exiting 130.
#[cfg(unix)]
const PARKED: &str = "parked at the interrupt checkpoint";

/// How long the binary parks when the tests ask it to.
///
/// Generous, because a failure here should be slow rather than flaky, and the
/// parked child is the only thing being waited on.
#[cfg(unix)]
const HOLD_MS: u64 = 30_000;

/// Backstop for a child that exits without ever announcing itself.
#[cfg(unix)]
const ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(30);

/// Sends a real SIGINT to a running child and waits for it.
///
/// The child parks at its first interrupt checkpoint for [`HOLD_MS` and says
/// so on stderr; this waits for that sentence before signalling. Nothing inside
/// the child is called into from here - this is `kill(2)` from outside, exactly
/// as an operator's Ctrl-C would be, and the only thing the test knows about
/// the binary is its pid.
#[cfg(unix)]
fn interrupt(args: &[&str]) -> Run {
    let mut child = Command::new(binary())
        .args(args)
        .env("SIM_DOCTOR_TEST_SIGNAL_HOLD_MS", HOLD_MS.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary should start");

    let mut stderr = child.stderr.take().expect("stderr was piped");
    let mut stdout = child.stdout.take().expect("stdout was piped");

    let announced = wait_for_park(&mut stderr);
    assert!(
        announced.contains(PARKED),
        "the binary never reached its interrupt checkpoint (stderr so far: {announced:?}), so there was nothing to interrupt"
    );

    // SAFETY: `child.id()` is the pid of a process this test spawned and has
    // not yet reaped. A non-zero return would mean the signal was not
    // delivered at all, which the status assertions below report far more
    // usefully than an ignored errno would.
    let delivered = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) };
    assert_eq!(delivered, 0, "SIGINT could not be delivered");

    // Safe to drain stderr to EOF before stdout: this process writes at most
    // one envelope, far below a pipe buffer, so the child cannot block writing
    // there while this blocks reading here.
    let mut rest = String::new();
    stderr.read_to_string(&mut rest).expect("stderr is UTF-8");
    let mut captured = String::new();
    stdout
        .read_to_string(&mut captured)
        .expect("stdout is UTF-8");

    Run {
        status: child.wait().expect("the child should exit"),
        stdout: captured,
        stderr: announced + &rest,
    }
}

/// Reads stderr until the pipe closes or [`PARKED`] shows up, and returns what
/// it saw.
///
/// [`Read::read`] blocks, so this is not a polling loop: it wakes when the child
/// writes. The deadline is only the backstop for a child that exits without
/// parking, so it never fires on a healthy run.
#[cfg(unix)]
fn wait_for_park(stderr: &mut impl Read) -> String {
    let mut seen = String::new();
    let mut chunk = [0_u8; 256];
    let deadline = Instant::now() + ANNOUNCE_TIMEOUT;

    while !seen.contains(PARKED) && Instant::now() < deadline {
        match stderr.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => seen.push_str(&String::from_utf8_lossy(&chunk[..read])),
            Err(err) => panic!("could not read the child's stderr: {err}"),
        }
    }
    seen
}

/// A run that finishes with nothing to report.
fn success() -> Run {
    run_piped(&["modules", "--json"])
}

/// A run that cannot deliver its report.
///
/// Exit code 1 means "findings present, or a check failed". No rule produces
/// findings yet, so today the only way to reach it is a run that fails, and the
/// failure that needs no hardware, no card and no race is being unable to write
/// its answer. It is also the shape of a real operator mistake:
/// `sim-doctor modules --json | head -5` closes the pipe out from under the tool.
///
/// The write end of a pipe whose read end has **already been closed**, so every
/// write fails with EPIPE from the very first byte. Two other candidates were
/// tried first and are wrong on macOS: pointing stdout at a read-only directory
/// or at a read-only regular file makes the writes *succeed*, because Rust's
/// runtime polls fds 0, 1 and 2 at startup and quietly replaces anything that
/// reports POLLNVAL - which poll does for regular files and for directories -
/// with `/dev/null`. Closing the read end before the child is spawned also
/// removes the race that closing it afterwards would leave.
fn undeliverable() -> Run {
    let mut ends = [0 as libc::c_int; 2];
    // SAFETY: `ends` is a two-element array of the type `pipe` writes into, and
    // `pipe` either fills both slots or fails without touching either.
    let piped = unsafe { libc::pipe(ends.as_mut_ptr()) };
    assert_eq!(
        piped,
        0,
        "could not create a pipe: {}",
        std::io::Error::last_os_error()
    );
    let (read_end, write_end) = (ends[0], ends[1]);

    // SAFETY: `read_end` is a descriptor this process opened moments ago and
    // nobody else holds, so closing it cannot affect any other descriptor.
    unsafe { libc::close(read_end) };

    // `Stdio::from_raw_fd` takes ownership of the write end, hands it to the
    // child as fd 1, and closes the parent's copy once the child is spawned.
    // SAFETY: `write_end` is a fresh descriptor owned by nobody else, so the
    // resulting `Stdio` is its only owner and no double close is possible.
    let stdout = unsafe { Stdio::from_raw_fd(write_end) };
    run(&["modules", "--json"], stdout)
}

/// A run whose command line could not be understood.
fn invalid_usage() -> Run {
    run_piped(&["modules", "--no-such-flag"])
}

/// The headline test: AGENTS.md section 3's four numbers, each one observed as a
/// real process exit status.
#[test]
fn all_four_exit_codes_are_reachable_from_a_real_process() {
    let mut observed = vec![
        success().code(),
        undeliverable().code(),
        invalid_usage().code(),
    ];

    if cfg!(unix) {
        observed.push(interrupt(&["modules", "--json"]).code());
    }

    observed.sort_unstable();
    observed.dedup();
    assert_eq!(
        observed,
        contract::ExitCode::ALL.map(|code| i32::from(code.process_code())),
        "the exit codes a caller can actually observe are not the four AGENTS.md section 3 promises"
    );
}

#[test]
fn a_clean_run_exits_0_and_says_nothing_on_stderr() {
    let run = success();

    assert_eq!(run.code(), 0);
    assert_exactly_one_envelope(&run.stdout, contract::ExitCode::Success);
    assert_eq!(
        run.stderr,
        "",
        "a successful run has no diagnostic to report, and every one it did report would have gone to stdout"
    );
}

#[test]
fn a_run_that_cannot_write_its_report_exits_1_and_explains_itself_on_stderr() {
    let run = undeliverable();

    assert_eq!(run.code(), 1);
    assert_eq!(
        run.stdout, "",
        "nothing could be written, so nothing must have been"
    );
    assert!(
        run.stderr.contains("stdout"),
        "the diagnostic does not say what failed: {:?}",
        run.stderr
    );
}

#[test]
fn an_unparsable_command_line_exits_129_with_nothing_on_stdout() {
    let run = invalid_usage();

    assert_eq!(run.code(), 129);
    assert_eq!(
        run.stdout, "",
        "clap's usage error must not land on stdout under --json semantics"
    );
    assert!(
        !run.stderr.is_empty(),
        "a bad flag that reports nothing is a bad flag nobody can debug"
    );
}
#[test]
#[cfg(unix)]
fn a_real_sigint_exits_130_rather_than_killing_the_process() {
    let run = interrupt(&["modules", "--json"]);

    // The distinction this test exists for. `code() == Some(130)` means the
    // handler ran and the process chose to exit; `signal() == Some(SIGINT)`
    // would mean no handler was installed and the kernel did it.
    assert_eq!(
        run.status.signal(),
        None,
        "the process died of the signal instead of handling it, so exit code 130 is not being produced by this crate at all"
    );
    assert_eq!(run.code(), 130);

    // Exactly one envelope, and it is the interrupted one - not a partial
    // report, and not the successful envelope the run would otherwise have
    // produced.
    let envelope = assert_exactly_one_envelope(&run.stdout, contract::ExitCode::Interrupted);
    assert_eq!(envelope.payload().message(), contract::INTERRUPTED_MESSAGE);
    assert_eq!(envelope.payload().data(), &contract::interrupted_data());

    assert!(
        run.stderr.contains("interrupted"),
        "the human-facing side of an interruption goes to stderr: {:?}",
        run.stderr
    );
}

#[test]
#[cfg(unix)]
fn an_interrupted_human_run_prints_no_report_and_exits_130() {
    // Without --json stdout is a report, and an interrupted run has no report.
    // The exit code and the stderr note are what the operator gets instead.
    let run = interrupt(&["modules"]);

    assert_eq!(run.code(), 130);
    assert_eq!(run.stdout, "");
    assert!(
        run.stderr.contains("interrupted"),
        "no note about the interruption on stderr: {:?}",
        run.stderr
    );
}

#[test]
fn json_stdout_is_byte_for_byte_one_envelope() {
    // Named after the acceptance criterion rather than after the code: with
    // --json, stdout parses as exactly one JSON envelope and nothing else, and
    // every diagnostic is on stderr.
    let run = success();

    let envelope = assert_exactly_one_envelope(&run.stdout, contract::ExitCode::Success);
    assert_eq!(envelope.kind(), contract::DEFAULT_KIND);
    assert_eq!(envelope.payload().message(), contract::OK_MESSAGE);
    assert!(
        envelope.payload().data()["modules"].is_array(),
        "the envelope does not describe the crate: {}",
        run.stdout
    );
}

#[test]
fn json_stdout_is_stable_across_runs() {
    // "Stable" for an agent means two runs of the same command produce the
    // same bytes, so a diff between two runs means the *card* changed and not
    // the tool.
    let first = success();
    let second = success();

    assert_eq!(first.status.code(), second.status.code());
    assert_eq!(
        first.stdout, second.stdout,
        "the same command produced two different documents"
    );
}

#[test]
fn the_human_mode_report_stays_on_stdout_and_diagnostics_never_do() {
    // Both halves of "diagnostics go to stderr in every mode": the report is
    // on stdout because that is what it is, and the failure diagnostics are
    // on stderr because that is what they are.
    let clean = run_piped(&["modules"]);
    assert_eq!(clean.code(), 0);
    assert!(
        clean.stdout.contains("MODULE"),
        "no module table on stdout: {:?}",
        clean.stdout
    );
    assert_eq!(clean.stderr, "");

    let broken = run_piped(&["modules", "--no-such-flag"]);
    assert_eq!(broken.code(), 129);
    assert_eq!(broken.stdout, "");
    assert!(!broken.stderr.is_empty());
}

#[test]
fn asking_for_help_is_not_a_failure() {
    // clap exits 0 for --help and prints to stdout; if that ever became 2, or
    // 129, an agent probing the tool would read it as a crash.
    let run = run_piped(&["--help"]);

    assert_eq!(run.code(), 0);
    assert!(
        run.stdout.contains("sim-doctor"),
        "no usage banner on stdout: {:?}",
        run.stdout
    );
    assert_eq!(run.stderr, "");
}

/// The shells `clap_complete` can generate for.
///
/// Written out rather than derived from the enum so a shell the crate adds
/// later fails this test loudly instead of silently going untested.
const SHELLS: [&str; 5] = ["bash", "elvish", "fish", "powershell", "zsh"];

/// Issue #6's first acceptance criterion, on the command surface itself: a
/// flag this tool does not understand is exit 129, and `scan` is no exception
/// to the rule `modules` already follows.
///
/// Both an unknown flag and a value outside a flag's own vocabulary are tested.
/// The second is the one that is easy to regress: --severity has to reject
/// "NOPE" with 129 rather than accepting any string and deferring it, because
/// an agent that typos a severity deserves to find out at parse time rather
/// than after a walk.
#[test]
fn an_unparsable_scan_command_line_exits_129() {
    let unknown_flag = run_piped(&["scan", "--no-such-flag"]);
    assert_eq!(unknown_flag.code(), 129);
    assert_eq!(
        unknown_flag.stdout, "",
        "clap's usage error must not land on stdout under --json semantics"
    );
    assert!(
        !unknown_flag.stderr.is_empty(),
        "a bad flag that reports nothing is a bad flag nobody can debug"
    );

    let bad_value = run_piped(&["scan", "--severity", "NOPE"]);
    assert_eq!(
        bad_value.code(),
        129,
        "a value outside the severity ladder is bad usage, not a deferred flag"
    );
    assert_eq!(bad_value.stdout, "");

    // --diff without --baseline cannot mean anything, and saying so at parse
    // time is better than deferring a request that could never be met.
    let orphan_diff = run_piped(&["scan", "--diff"]);
    assert_eq!(orphan_diff.code(), 129);
    assert_eq!(orphan_diff.stdout, "");
    assert!(
        orphan_diff.stderr.contains("baseline"),
        "{:?}",
        orphan_diff.stderr
    );
}

/// The four AGENTS.md section 3 flags that exist before their behaviour does
/// must refuse, and refuse honestly.
///
/// What is pinned here is the refusal itself: exit 1 (a check that could not
/// run, not a card that passed), one envelope under --json, and a `data` block
/// saying `"implemented": false` and `"card_touched": false`. The failure mode
/// these rules out is a --score that returned 0 because the scorer is
/// unwritten, which would be indistinguishable from a clean card.
#[test]
fn every_deferred_scan_flag_refuses_without_touching_a_card() {
    let cases: [(&[&str], &str); 4] = [
        (&["scan", "--score", "--json"], "--score"),
        (&["scan", "--severity", "high", "--json"], "--severity high"),
        (
            &["scan", "--baseline", "saved.json", "--json"],
            "--baseline saved.json",
        ),
        (
            &["scan", "--baseline", "saved.json", "--diff", "--json"],
            "--baseline saved.json",
        ),
    ];

    for (args, expected_flag) in cases {
        let run = run_piped(args);
        assert_eq!(run.code(), 1, "{args:?} exited {:?}", run.status);

        let envelope = assert_exactly_one_envelope(&run.stdout, contract::ExitCode::Findings);
        let data = envelope.payload().data();
        assert_eq!(
            data["implemented"],
            serde_json::Value::Bool(false),
            "{args:?}"
        );
        assert_eq!(data["scanned"], serde_json::Value::Bool(false), "{args:?}");
        assert_eq!(
            data["card_touched"],
            serde_json::Value::Bool(false),
            "{args:?} claimed it contacted a card"
        );
        assert_eq!(data["flag"], serde_json::json!(expected_flag), "{args:?}");
        assert!(
            envelope.payload().message().contains("not implemented yet"),
            "{args:?}: {:?}",
            envelope.payload().message()
        );
        assert!(
            run.stderr.contains("not implemented yet"),
            "{args:?}: {:?}",
            run.stderr
        );
    }
}

/// The same refusals without --json print nothing at all on stdout.
///
/// Under --json stdout is the envelope, so a refusal is a document there. In
/// the human modes stdout is a report, and a refusal has no report to give -
/// the sentence belongs on stderr. Asserting this is what keeps a refusal from
/// being a half-written result on stdout.
#[test]
fn a_deferred_scan_flag_without_json_writes_nothing_to_stdout() {
    let run = run_piped(&["scan", "--score"]);

    assert_eq!(run.code(), 1);
    assert_eq!(run.stdout, "", "{:?}", run.stdout);
    assert!(
        run.stderr.contains("--score is not implemented yet"),
        "{:?}",
        run.stderr
    );
}

/// A SIGINT on `scan` exits 130 with one interrupted envelope and no partial
/// tree, on a machine with no card at all.
///
/// This runs everywhere, card or no card, because the first checkpoint is
/// before the reader is opened. That placement is the point: an operator who
/// hits Ctrl-C while the tool is still finding hardware is not made to wait
/// for a card, and - more importantly - a run that is interrupted before it
/// has anything to report still emits exactly one envelope carrying 130 and an
/// empty `data`, never half a tree.
#[test]
#[cfg(unix)]
fn interrupting_a_scan_exits_130_and_emits_no_partial_tree() {
    let run = interrupt(&["scan", "--json"]);

    assert_eq!(
        run.status.signal(),
        None,
        "the process died of the signal instead of handling it, so exit code 130 is not being produced by this crate at all"
    );
    assert_eq!(run.code(), 130);

    let envelope = assert_exactly_one_envelope(&run.stdout, contract::ExitCode::Interrupted);
    assert_eq!(envelope.kind(), sim_doctor::scan::KIND);
    assert_eq!(envelope.payload().message(), contract::INTERRUPTED_MESSAGE);
    assert_eq!(
        envelope.payload().data(),
        &contract::interrupted_data(),
        "an interrupted scan must not carry a partial tree, a count, or the \
         reader it had found"
    );
    assert!(run.stderr.contains("interrupted"), "{:?}", run.stderr);
}

/// Issue #6's third acceptance criterion: generated completions build cleanly.
///
/// "Build cleanly" is asserted two ways. Every shell `clap_complete` supports
/// produces a script that names this binary, and the script is syntactically
/// whole: the bash one is checked with `bash -n` when bash is on PATH, because a
/// completion script that does not parse is exactly the failure a golden-file
/// comparison would not catch.
///
/// The second assertion is the one about the contract: every AGENTS.md section
/// 3 flag has to appear in the script. An agent that types "sim-doctor scan --"
/// and hits tab must see --score and --baseline, because a flag that exists and
/// says "not yet" is the whole point of having them. A completion script that
/// hid the unimplemented half of the surface would reintroduce the missing-flag
/// problem in a place nobody looks.
#[test]
fn completions_build_for_every_shell_and_name_the_whole_flag_surface() {
    for shell in SHELLS {
        let run = run_piped(&["completions", shell]);

        assert_eq!(run.code(), 0, "completions {shell} exited {:?}", run.status);
        assert_eq!(
            run.stderr, "",
            "generating a completion script writes nothing to stderr: {:?}",
            run.stderr
        );
        assert!(
            run.stdout.contains("sim-doctor"),
            "the {shell} script never names the binary it completes"
        );
        assert!(!run.stdout.trim().is_empty(), "the {shell} script is empty");
    }

    // The flag surface, asserted once against one shell so the failure message
    // is about the contract rather than about shell quoting.
    let zsh = run_piped(&["completions", "zsh"]);
    for flag in [
        "--json",
        "--dialect",
        "--reader",
        "--score",
        "--severity",
        "--baseline",
        "--diff",
    ] {
        assert!(
            zsh.stdout.contains(flag),
            "the completion script omits {flag}, so an agent cannot discover it"
        );
    }

    // A shell that does not exist is bad usage, not an empty script.
    let bogus = run_piped(&["completions", "not-a-shell"]);
    assert_eq!(bogus.code(), 129);
    assert_eq!(bogus.stdout, "");

    // Parse check, when there is a bash to parse with. Skipped rather than
    // failed off a platform without one: the fixture gate in AGENTS.md section
    // 2 is about cards, and a missing /bin/bash is not a defect in this crate.
    if which("bash").is_some() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "sim-doctor-completions-{}.bash",
            std::process::id()
        ));
        let write = std::fs::write(&path, run_piped(&["completions", "bash"]).stdout.as_bytes());
        assert!(
            write.is_ok(),
            "could not write the script to {}",
            path.display()
        );
        let parsed = Command::new("bash")
            .arg("-n")
            .arg(&path)
            .stdin(Stdio::null())
            .output()
            .expect("bash should run");
        let _ = std::fs::remove_file(&path);
        assert!(
            parsed.status.success(),
            "the generated bash script does not parse: {}",
            String::from_utf8_lossy(&parsed.stderr)
        );
    }
}

/// Whether a program is on PATH, so a test can skip rather than fail when the
/// platform does not ship it.
fn which(program: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
}

/// `scan` --help has to say the two things that decide whether a result can be
/// trusted, and the process is the only place that text is observable.
///
/// The first is that the default candidate set can MISS a file. The second is
/// that every flag whose behaviour is not built says so where the operator will
/// read it. Both are pinned by quoting, because prose that is merely present is
/// prose the next person rewords.
#[test]
fn scan_help_states_what_the_defaults_cannot_guarantee() {
    let run = run_piped(&["scan", "--help"]);
    assert_eq!(run.code(), 0);
    assert_eq!(run.stderr, "");

    // Truncation is the requirement an agent scripting against this tool most
    // needs stated, so it is in the long help rather than only in a flag. The
    // second assertion is the sharper one: an agent that gated on
    // `payload.code` alone would read a partial walk as a clean card, so the
    // help has to name `data.complete` as the thing to gate on.
    assert!(
        run.stdout.contains("Truncation is always reported"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("limits_hit"), "{}", run.stdout);
    assert!(
        run.stdout
            .contains("GATE ON data.complete, NOT ON payload.code"),
        "the help must say which field an agent gates on: {}",
        run.stdout
    );

    // The candidate-set under-report, in the flag that governs it.
    assert!(
        run.stdout
            .contains("THE DEFAULT CANDIDATE SET CAN MISS A FILE"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("INVISIBLE"),
        "the warning has to say the file is invisible, not merely unlisted: {}",
        run.stdout
    );

    // The dialect assumption, and the flag that lets the operator state it.
    assert!(run.stdout.contains("--dialect"), "{}", run.stdout);
    assert!(
        run.stdout.contains("assumption"),
        "the --dialect help must say the default is an assumption: {}",
        run.stdout
    );

    // Every unimplemented flag says so, in the place an operator will read it.
    for flag in ["--score", "--severity", "--baseline", "--diff"] {
        assert!(run.stdout.contains(flag), "{flag} is missing from --help");
    }
    assert_eq!(
        run.stdout.matches("NOT IMPLEMENTED YET").count(),
        4,
        "all four deferred flags must say so: {}",
        run.stdout
    );
}
