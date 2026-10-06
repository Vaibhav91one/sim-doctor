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

/// Serializes every process this file spawns.
///
/// **Descriptors are process-global state, and this file mutates them.** The
/// closed-stdout handshake creates a raw pipe, closes one end and hands the
/// other to a child, which is a sequence of operations on descriptor numbers
/// every other thread in the process shares. One test doing that while another
/// is mid-spawn is how a handshake ends up measuring something other than what
/// it claims: the symptom observed in CI was a run against a closed stdout that
/// exited 0 having written nothing, i.e. the pipe had a reader after all.
/// Close-on-exec closes the inheritance route (see
/// `the_closed_stdout_handshake_marks_both_pipe_ends_close_on_exec`), but
/// descriptor NUMBERS are shared regardless, and a property that depends on
/// which thread happens to be where is not a property.
///
/// Serializing costs this file well under a second and makes every spawn
/// deterministic. Poisoning is recovered from rather than propagated: a
/// previous test panicking says nothing about whether the lock is usable, and
/// the alternative is every later test failing for an unrelated reason.
static SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Takes [`SPAWN_LOCK`], recovering from a poisoned lock.
fn spawn_lock() -> std::sync::MutexGuard<'static, ()> {
    SPAWN_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Runs the binary with stderr captured, and stdout replaced if asked.
///
/// **Callers hold [`SPAWN_LOCK`]**, which is why this does not take it itself: the
/// closed-stdout handshake has to hold the lock across pipe creation and spawn,
/// and a lock taken in here as well would be taken twice by one thread.
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
    let _guard = spawn_lock();
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
    let _guard = spawn_lock();
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
    run_with_a_closed_stdout(&["modules", "--json"])
}

/// [`undeliverable`], parameterised so a second test can prove the same property
/// on a different payload without copying the unsafe handshake.
///
/// Parameterised rather than duplicated because the handshake is the delicate
/// part: a second copy is a second set of raw descriptors to keep correct, and
/// nothing about the property under test depends on which command produced the
/// bytes.
fn run_with_a_closed_stdout(args: &[&str]) -> Run {
    let _guard = spawn_lock();
    let (read_end, write_end) = pipe_with_a_protected_read_end();

    // SAFETY: `read_end` is a descriptor this process opened moments ago and
    // nobody else can hold it, now that it is close-on-exec, so closing it
    // cannot affect any other descriptor.
    unsafe { libc::close(read_end) };

    // SAFETY: `write_end` is a fresh descriptor owned by nobody else, so the
    // resulting `Stdio` is its only owner and no double close is possible.
    let stdout = unsafe { Stdio::from_raw_fd(write_end) };
    run(args, stdout)
}

/// Marks one descriptor close-on-exec, and fails the test if it cannot.
///
/// Not ignored on failure: a handshake whose descriptors can still leak is a
/// handshake that silently measures nothing, and the failure it produces is a
/// green run with a meaningless exit code in it. Better to stop here.
///
/// # Panics
///
/// Panics if `F_GETFD` or `F_SETFD` fails, naming the descriptor.
fn set_close_on_exec(fd: libc::c_int) {
    // SAFETY: `fd` is a descriptor this process opened moments ago and nobody
    // else holds. F_GETFD only reads a flag off it.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(
        flags >= 0,
        "F_GETFD on descriptor {fd} failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: as above, and `flags` came back from the kernel moments ago.
    let set = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    assert!(
        set >= 0,
        "F_SETFD on descriptor {fd} failed: {}",
        std::io::Error::last_os_error()
    );
}

/// Creates the pipe [`run_with_a_closed_stdout`] hands to a child, with
/// both ends marked close-on-exec before it returns.
///
/// **Why the flag is set here and not by the caller.** `libc::pipe()` creates two
/// descriptors that survive every later fork+exec in this process, and this test
/// binary runs its tests in parallel while spawning children constantly. So
/// between `pipe()` and the `close()` of the read end there is a window in which
/// an UNRELATED child can be spawned, and it inherits the read end. That child
/// then holds the pipe open long enough for the run under test to write to it
/// SUCCESSFULLY, and the run exits 0 having delivered nothing: precisely the
/// silent success this handshake exists to manufacture a failure for. Whether it
/// ever happens is pure timing, which is why it reads as a platform difference
/// rather than as a bug - observed as `left: 0` on a loaded Linux runner with
/// the same binary returning 1 on macOS.
///
/// The write end is marked too, deliberately and harmlessly: `Stdio` arranges
/// for it to reach this test's own child as fd 1, and the marker is undone by
/// that arrangement rather than relied upon to be undone.
///
/// `pipe2(O_CLOEXEC)` would do both in one call but is Linux-only and this suite
/// runs on macOS. `fcntl` is the portable spelling of the same flag, and it goes
/// on BEFORE anything else so the window is empty from the first instruction.
///
/// One function rather than inline code, because
/// `the_closed_stdout_handshake_marks_both_pipe_ends_close_on_exec` reads the
/// flag back off the descriptors this returns. Removing the flag therefore fails
/// that test with a message naming the race, instead of quietly re-opening it.
fn pipe_with_a_protected_read_end() -> (libc::c_int, libc::c_int) {
    let mut ends = [0 as libc::c_int; 2];
    // SAFETY: `ends` is a two-element array of exactly the type `pipe` writes
    // into, and `pipe` either fills both slots or fails without touching them.
    let piped = unsafe { libc::pipe(ends.as_mut_ptr()) };
    assert_eq!(
        piped,
        0,
        "could not create a pipe: {}",
        std::io::Error::last_os_error()
    );
    set_close_on_exec(ends[0]);
    set_close_on_exec(ends[1]);
    (ends[0], ends[1])
}

/// Proves the handshake marks BOTH ends of its pipe close-on-exec, and fails the
/// moment it stops doing so.
///
/// This is the test that makes the fix visible. The race it guards is timing
/// dependent and its symptom is a bare `left: 0` with nothing written, which took
/// a full CI cycle to attribute; a comment would not have stopped the next person
/// from deleting two lines and re-opening it. Reading the flag back off the
/// descriptors [`pipe_with_a_protected_read_end`] returns fails deterministically,
/// on every platform, with no other test having to lose a race first.
///
/// It checks the FLAG rather than trying to observe an exec, deliberately. An
/// earlier version of this test did observe one, by listing `/dev/fd` inside a
/// spawned shell, and it was wrong twice over: the kernel reuses the number of a
/// close-on-exec descriptor for the probe's own pipe, so the listing reported an
/// inherited descriptor that was not inherited; and parsing `ls -l` output for
/// numbers is parsing a human-readable table. The flag is the thing the fix
/// actually sets, so that is the thing worth asserting.
#[test]
fn the_closed_stdout_handshake_marks_both_pipe_ends_close_on_exec() {
    let (read_end, write_end) = pipe_with_a_protected_read_end();

    for (label, fd) in [("read", read_end), ("write", write_end)] {
        // SAFETY: `fd` is a descriptor this process opened moments ago and nobody
        // else holds it; F_GETFD only reads a flag off it.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(
            flags >= 0,
            "F_GETFD on the {label} end failed: {}",
            std::io::Error::last_os_error()
        );
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "the {label} end of the handshake's pipe is inheritable again. A child \
             spawned inside the handshake window in run_with_a_closed_stdout can \
             then hold the read end open, the run under test writes successfully, \
             and a_run_that_cannot_write_its_report_exits_1_and_explains_itself_on_stderr \
             fails with a bare left: 0 and nothing on stdout. Restore the \
             set_close_on_exec calls in pipe_with_a_protected_read_end."
        );
    }

    // SAFETY: both are descriptors this process opened moments ago and nobody
    // else holds them.
    unsafe {
        libc::close(read_end);
        libc::close(write_end);
    }
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

    // The message carries the child's own stderr and its raw status on purpose.
    // This test went red once with left: 0 on the Ubuntu runner and green on
    // macOS with the same binary, and the only thing the assertion said about
    // it was which two numbers disagreed. A failure here should now be
    // diagnosable from the failure message alone.
    assert_eq!(
        run.code(),
        1,
        "an unwritable stdout must be exit 1, never 101 (a println! panic) and          never 0, which would tell an agent the run succeeded while delivering          nothing. status {:?}, stderr {:?}",
        run.status,
        run.stderr
    );
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

/// --baseline and --diff are implemented, and the process says so.
///
/// **They were the last two.** AGENTS.md section 3 required `--score`,
/// `--severity`, `--baseline` and `--diff` to exist on the surface from day
/// one, and each refused honestly until it was built. Issue #12 built the last
/// two, so the `"implemented": false` document is now reachable from
/// **nothing** on the command surface.
///
/// What is pinned is the KIND of document, not the exit code. On a cardless
/// machine `--baseline` still exits 1, but as a *failed scan* at
/// `Pcsc::readers`: `card_touched: false` and an `error.kind`, which is a
/// different document from a refusal. Under `--diff` it refuses at the file,
/// with an `error.kind` of its own, and does so BEFORE a reader is opened.
///
/// The failure mode these rules out is the one the pattern started with: a
/// `--baseline` that returned 0 because the comparison is unwritten would be
/// indistinguishable from a clean card.
#[test]
fn the_baseline_flags_no_longer_refuse_as_unimplemented() {
    for args in [
        &["scan", "--baseline", "saved.json", "--json"][..],
        &["scan", "--baseline", "saved.json", "--diff", "--json"][..],
    ] {
        let run = run_piped(args);
        let envelope = assert_exactly_one_envelope_for(args, &run.stdout);
        let data = envelope.payload().data();

        assert!(
            data.get("implemented").is_none(),
            "{args:?} is refusing, so the flag went back to deferred: {data}"
        );
        assert_eq!(
            data["scanned"],
            serde_json::Value::Bool(false),
            "{args:?}: no card was scanned"
        );
        assert_eq!(
            data["card_touched"],
            serde_json::Value::Bool(false),
            "{args:?} claimed it contacted a card"
        );
        // A refusal and a failed scan are different documents, and the `error`
        // key is what tells them apart. That is the discriminator the exit-
        // code table leans on and the one issue #12 relies on for its own exits.
        assert!(
            data.get("error").is_some(),
            "{args:?} neither refused nor failed: {data}"
        );
        assert_eq!(
            envelope.payload().code().process_code(),
            u8::try_from(run.code()).expect("an exit code fits in a byte"),
            "{args:?}: payload.code must stay the number the process exits with"
        );
    }
}

/// A `--diff` against a file that is not there refuses on the FILE, before a
/// reader is ever opened.
///
/// **This is the property that makes `--diff` safe to script.** The baseline is
/// read at the top of `run_scan`, before `Pcsc::readers`, so an agent whose
/// baseline path is wrong - a stale checkout, a job that never downloaded the
/// artifact - finds out in milliseconds instead of after a walk of a card it was
/// never going to compare against. `error.kind` names which refusal it is, so
/// the agent does not have to parse the sentence.
#[test]
fn a_diff_against_a_missing_baseline_refuses_on_the_file_and_says_which() {
    let missing = std::env::temp_dir().join("sim-doctor-no-such-baseline.json");
    let _ = std::fs::remove_file(&missing);
    let path = missing.display().to_string();

    let run = run_piped(&["scan", "--diff", "--json", "--baseline", &path]);

    assert_eq!(run.code(), 1);
    let envelope = assert_exactly_one_envelope_for(&["scan", "--diff"], &run.stdout);
    let data = envelope.payload().data();
    assert_eq!(
        data["error"]["kind"],
        serde_json::json!("baseline-unreadable")
    );
    // A refusal is a refusal: no findings, and no diff that could be read as
    // one.
    assert!(data.get("findings").is_none(), "{data}");
    assert!(data.get("diff").is_none(), "{data}");
    assert!(
        run.stderr.contains("baseline"),
        "the sentence has to name what went wrong: {:?}",
        run.stderr
    );
}

/// The same refusal in the human mode writes nothing at all to stdout.
///
/// Under `--json` stdout is the envelope, so a refusal is a document there. In
/// the human modes stdout is a report, and a refusal has no report to give, so
/// the sentence belongs on stderr. Asserting this is what keeps a refusal from
/// being a half-written result on stdout.
#[test]
fn a_refusal_without_json_writes_nothing_to_stdout() {
    // --diff, not --baseline alone: the file is only READ when a comparison
    // was asked for, so a bare --baseline goes on to look for a card and fails
    // there. Both are refusals; this one is about the one that happens first.
    let run = run_piped(&["scan", "--diff", "--baseline", "/no/such/dir/baseline.json"]);

    assert_eq!(run.code(), 1);
    assert_eq!(run.stdout, "", "{:?}", run.stdout);
    assert!(run.stderr.contains("baseline"), "{:?}", run.stderr);
}
/// --score and --severity are implemented, and the process says so.
///
/// Before issue #14 both refused with `"implemented": false` in one envelope.
/// That is the honest answer for a flag whose behaviour is unwritten, and it
/// is now the WRONG answer for these two: what they say is about a card, so
/// they need a reader, and on a machine with no card the run fails at
/// `pick_reader` instead of at the flag check.
///
/// What is asserted is the difference in KIND, not the exit code - both are 1
/// here, and on a machine with a reader the implemented pair is 0. A refusal
/// carries `"implemented": false`; a failed scan carries `"card_touched":
/// false` and an `error.kind`. Asserting that `--score --json` is not one of
/// the refusals is what would fail if somebody re-deferred the flag, and it
/// fails identically whether this machine has a card in it or not.
#[test]
fn implemented_flags_are_no_longer_deferred() {
    for args in [
        &["scan", "--score", "--json"][..],
        &["scan", "--severity", "high", "--json"][..],
        &["scan", "--severity", "info", "--score", "--json"][..],
    ] {
        let run = run_piped(args);
        let envelope = assert_exactly_one_envelope_for(args, &run.stdout);
        let data = envelope.payload().data();

        assert!(
            data.get("implemented").is_none(),
            "{args:?} is refusing, so the flag went back to deferred: {data}"
        );
        assert_eq!(
            data["card_touched"],
            serde_json::Value::Bool(false),
            "{args:?} claimed it contacted a card"
        );
        assert_eq!(
            envelope.payload().code().process_code(),
            u8::try_from(run.code()).expect("an exit code fits in a byte"),
            "{args:?}: payload.code must stay the number the process exits with"
        );
    }
}

/// Asserts one envelope on stdout and returns it, without pinning the code.
///
/// The purity half of [`assert_exactly_one_envelope`] on its own, for the
/// tests whose point is WHICH envelope rather than that there is exactly one.
fn assert_exactly_one_envelope_for(args: &[&str], raw: &str) -> contract::Envelope {
    assert!(
        raw.ends_with('\n'),
        "{args:?}: stdout must end with the one newline that terminates the envelope: {raw:?}"
    );
    assert_eq!(
        raw.matches('\n').count(),
        1,
        "{args:?}: stdout is not a single line, so it is not a single envelope: {raw:?}"
    );

    let body = raw.strip_suffix('\n').expect("checked above");
    let envelope: contract::Envelope = serde_json::from_str(body)
        .unwrap_or_else(|e| panic!("{args:?}: stdout is not one JSON envelope: {e}\n{body:?}"));
    assert_eq!(
        envelope.to_json().unwrap(),
        body,
        "{args:?}: the envelope does not re-serialise to the bytes that are on stdout"
    );
    envelope
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

    // Every flag is on the surface, whatever its state.
    for flag in ["--score", "--severity", "--baseline", "--diff"] {
        assert!(run.stdout.contains(flag), "{flag} is missing from --help");
    }

    // **None.** --score and --severity shipped in issue #14 and --baseline and
    // --diff in issue #12, so every flag AGENTS.md section 3 requires is built.
    // Zero is a stronger assertion than a count: a flag quietly going back to
    // refusing puts a number back here, and a NEW unimplemented flag is only
    // reachable by also adding a flag, which the loop above catches.
    assert_eq!(
        run.stdout.matches("NOT IMPLEMENTED YET").count(),
        0,
        "no flag on the surface defers any more: {}",
        run.stdout
    );

    // The baseline flags describe what they do, and - the point of issue #12 -
    // they publish the refusals they can make, because a gate is useless
    // without knowing when it will refuse.
    for phrase in [
        "SAVING IS NOT A GATE",
        "EXIT 1 WHEN THE DIFF REGRESSES",
        "THE DIFF REFUSES RATHER THAN GUESSES",
        "A RENAMED RULE READS AS A RENAME",
        "A HAND-EDITED OR HOSTILE BASELINE IS REFUSED",
    ] {
        assert!(
            run.stdout.contains(phrase),
            "the --baseline/--diff help must state {phrase:?}: {}",
            run.stdout
        );
    }

    // An implemented flag says what it does, and - the point of issue #14 - it
    // publishes the formula rather than asking the reader to find the source.
    for phrase in [
        "max(0, 100 - sum of one penalty per finding)",
        "info 1, low 3, medium 10, high 25, critical 50",
        "data.findings.severity_threshold",
    ] {
        assert!(
            run.stdout.contains(phrase),
            "the --score/--severity help must state {phrase:?}: {}",
            run.stdout
        );
    }
}

/// Issue #14 acceptance criterion 4: stdout purity holds across the flag
/// matrix, asserted against the real binary.
///
/// The rule is one sentence: under `--json`, stdout carries one envelope and
/// not one byte else, and `payload.code` is the number the process exits with.
/// The matrix is the whole of `scan`'s AGENTS.md section 3 flag surface,
/// because purity is a property of the COMBINATION and not of any one flag -
/// a score printed to stderr, or a severity echoed to stdout by a path that
/// only runs when both are present, is exactly the regression a single-flag
/// test cannot see.
///
/// Every combination is expected to exit 1 on a machine with no reader, and
/// that is not asserted against: the code differs legitimately between a
/// machine with a card, a deferred flag and a failed walk. What IS asserted
/// is the same three things for all of them, which is what makes this a
/// matrix rather than a list of cases - one newline, one parseable envelope
/// that round-trips to the same bytes, and a code that matches the process.
#[test]
fn json_stdout_is_one_envelope_across_the_whole_flag_matrix() {
    // Every rung of the ladder appears, because a spelling that parses at one
    // level and not another is a flag-level bug a cardless machine would
    // otherwise report as a reader failure rather than as a parse failure.
    let matrix: [(&[&str], &str); 18] = [
        (&["--json"], "bare"),
        (&["--json", "--score"], "score"),
        (&["--json", "--severity", "info"], "the lowest severity"),
        (&["--json", "--severity", "low"], "low"),
        (&["--json", "--severity", "medium"], "medium"),
        (&["--json", "--severity", "high"], "high"),
        (
            &["--json", "--severity", "critical"],
            "the highest severity",
        ),
        (
            &["--json", "--score", "--severity", "low"],
            "score and the lowest rung",
        ),
        (
            &["--json", "--score", "--severity", "high"],
            "score and severity",
        ),
        (
            &["--json", "--score", "--severity", "info"],
            "score over everything",
        ),
        (
            &["--json", "--score", "--severity", "critical"],
            "score over the worst",
        ),
        (
            &["--json", "--dialect", "iec-7816-4-table-42", "--score"],
            "a declared dialect and a score",
        ),
        (
            &["--json", "--max-depth", "1", "--score"],
            "a bound and a score",
        ),
        (
            &["--json", "--max-children", "16", "--severity", "medium"],
            "a bound and a severity",
        ),
        (
            &[
                "--json",
                "--score",
                "--severity",
                "high",
                "--max-nodes",
                "4",
                "--max-directories",
                "2",
            ],
            "everything at once",
        ),
        (&["--json", "--baseline", "saved.json"], "a deferred flag"),
        (
            &["--json", "--baseline", "saved.json", "--diff"],
            "both deferred flags",
        ),
        (
            &["--json", "--score", "--baseline", "saved.json"],
            "an implemented flag beside a deferred one",
        ),
    ];

    for (flags, what) in matrix {
        let mut args = vec!["scan"];
        args.extend_from_slice(flags);
        let run = run_piped(&args);
        let envelope = assert_exactly_one_envelope_for(&args, &run.stdout);

        assert_eq!(
            envelope.kind(),
            sim_doctor::scan::KIND,
            "{what}: the envelope must identify itself as a scan"
        );
        assert_eq!(
            envelope.payload().code().process_code(),
            u8::try_from(run.code()).expect("an exit code fits in a byte"),
            "{what}: payload.code must stay the number the process exits with"
        );
    }
}

/// The same matrix, in the human mode, keeps stdout a report and diagnostics
/// on stderr.
///
/// A scan that cannot run has no report to print, so the human mode of a
/// failing combination writes nothing at all to stdout. That is the rule; it
/// is here so that the --json matrix above is not the only one being checked,
/// and so that a `println!` added to the human path is caught by the same
/// failure message an operator would see.
#[test]
fn the_human_modes_of_the_same_matrix_print_no_report_when_the_scan_cannot_run() {
    for flags in [
        &["--score"][..],
        &["--severity", "high"],
        &["--score", "--severity", "high"],
        &["--baseline", "saved.json"],
    ] {
        let mut args = vec!["scan"];
        args.extend_from_slice(flags);
        let run = run_piped(&args);

        assert_eq!(run.code(), 1, "{args:?}");
        assert_eq!(run.stdout, "", "{args:?} wrote a report: {:?}", run.stdout);
        assert!(
            !run.stderr.is_empty(),
            "{args:?} failed silently: nothing on stderr either"
        );
    }
}

/// Issue #46: the rule catalog needs no card, so these run the binary bare.
mod rule_catalog {
    use super::*;

    const RULE: &str = "gsma/msl-zero-allowed";

    fn saved_envelope(name: &str, body: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("sim-doctor-{name}-{}.json", std::process::id()));
        std::fs::write(&path, body).expect("write the temp file");
        path
    }

    #[test]
    fn rules_list_json_is_one_envelope_naming_the_rule() {
        let run = run_piped(&["rules", "list", "--json"]);
        assert_eq!(run.code(), 0, "{:?}", run.stderr);
        let envelope = assert_exactly_one_envelope(&run.stdout, contract::ExitCode::Success);
        assert_eq!(envelope.kind(), "rules");
        let rules = envelope.payload().data()["rules"]
            .as_array()
            .expect("rules array");
        let rule = rules
            .iter()
            .find(|rule| rule["id"] == RULE)
            .unwrap_or_else(|| panic!("{RULE} not listed: {rules:?}"));
        assert!(
            rule["remediation"]
                .as_str()
                .is_some_and(|text| !text.trim().is_empty()),
            "{rule}"
        );
    }

    #[test]
    fn rules_explain_prints_summary_and_remediation() {
        let run = run_piped(&["rules", "explain", RULE]);
        assert_eq!(run.code(), 0, "{:?}", run.stderr);
        assert!(run.stdout.contains(RULE), "{}", run.stdout);
        assert!(run.stdout.contains("What it means"), "{}", run.stdout);
        assert!(run.stdout.contains("How to fix"), "{}", run.stdout);
    }

    #[test]
    fn rules_explain_unknown_id_refuses_and_suggests_the_near_miss() {
        let run = run_piped(&["rules", "explain", "gsma/msl-zero-allowd", "--json"]);
        assert_eq!(run.code(), 1, "{:?}", run.stderr);
        let envelope = assert_exactly_one_envelope(&run.stdout, contract::ExitCode::Findings);
        let data = envelope.payload().data();
        assert!(data["error"].is_string(), "{data}");
        assert!(data.to_string().contains(RULE), "no suggestion: {data}");
    }

    #[test]
    fn why_a_saved_envelope_explains_the_rules_in_its_findings() {
        let path = saved_envelope(
            "why-ok",
            r#"{"type":"scan","payload":{"code":0,"message":"ok","data":{"findings":{"findings":[{"rule":"gsma/msl-zero-allowed","severity":"high","message":"TAR 000000 accepted"}]}}}}"#,
        );
        let run = run_piped(&["why", path.to_str().unwrap()]);
        let _ = std::fs::remove_file(&path);
        assert_eq!(run.code(), 0, "{:?}", run.stderr);
        assert!(run.stdout.contains(RULE), "{}", run.stdout);
        assert!(run.stdout.contains("How to fix"), "{}", run.stdout);
    }

    #[test]
    fn why_garbage_file_refuses() {
        let path = saved_envelope("why-bad", "this is not an envelope");
        let run = run_piped(&["why", path.to_str().unwrap()]);
        let _ = std::fs::remove_file(&path);
        assert_eq!(run.code(), 1, "{:?}", run.stderr);
        assert_eq!(run.stdout, "");
    }

    fn saved_with_rule(name: &str, rule: &str) -> std::path::PathBuf {
        let body = serde_json::json!({"type":"scan","payload":{"code":0,"message":"ok","data":{
            "findings":{"findings":[{"rule":rule,"severity":"high","message":"m"}]}}}});
        saved_envelope(name, &body.to_string())
    }

    #[test]
    fn why_json_success_is_one_envelope() {
        let path = saved_with_rule("why-json-ok", RULE);
        let run = run_piped(&["why", path.to_str().unwrap(), "--json"]);
        let _ = std::fs::remove_file(&path);
        assert_eq!(run.code(), 0, "{:?}", run.stderr);
        let envelope = assert_exactly_one_envelope(&run.stdout, contract::ExitCode::Success);
        assert_eq!(envelope.kind(), "rules");
        assert_eq!(envelope.payload().data()["rules"][0]["id"], RULE);
    }

    #[test]
    fn why_json_refusal_is_one_envelope() {
        let path = saved_envelope("why-json-bad", "garbage");
        let run = run_piped(&["why", path.to_str().unwrap(), "--json"]);
        let _ = std::fs::remove_file(&path);
        assert_eq!(run.code(), 1, "{:?}", run.stderr);
        let envelope = assert_exactly_one_envelope(&run.stdout, contract::ExitCode::Findings);
        assert!(envelope.payload().data()["error"].is_string());
    }

    #[test]
    fn why_a_missing_file_or_a_directory_names_the_path() {
        let missing = std::env::temp_dir().join("sim-doctor-no-such-scan.json");
        let dir = std::env::temp_dir();
        for target in [missing.to_str().unwrap(), dir.to_str().unwrap()] {
            let run = run_piped(&["why", target]);
            assert_eq!(run.code(), 1, "{target}: {:?}", run.stderr);
            assert!(run.stderr.contains(target), "{target}: {}", run.stderr);
            assert!(!run.stderr.contains("unknown rule"), "{}", run.stderr);
        }
        let run = run_piped(&["why", "scan.jsn.json"]);
        assert_eq!(run.code(), 1);
        assert!(run.stderr.contains("scan.jsn.json") && !run.stderr.contains("unknown rule"));
    }

    #[test]
    fn why_a_rule_this_build_does_not_know_says_so() {
        let path = saved_with_rule("why-unknown", "other/not-here");
        let run = run_piped(&["why", path.to_str().unwrap()]);
        let _ = std::fs::remove_file(&path);
        assert_eq!(run.code(), 0, "{:?}", run.stderr);
        assert!(run.stdout.contains("other/not-here"), "{}", run.stdout);
        assert!(run.stdout.contains("no catalog entry"), "{}", run.stdout);
    }

    #[test]
    fn why_never_prints_control_characters_from_the_file() {
        let path = saved_with_rule("why-esc", "gsma/\u{1b}[2Jx");
        let run = run_piped(&["why", path.to_str().unwrap()]);
        let _ = std::fs::remove_file(&path);
        assert_eq!(run.code(), 0, "{:?}", run.stderr);
        assert!(!run.stdout.as_bytes().contains(&0x1b), "{:?}", run.stdout);
    }
}
