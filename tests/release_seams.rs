//! A release build has no test seams.
//!
//! `SIM_DOCTOR_TEST_REPLAY` (answer `scan` from a recorded log instead of a reader),
//! `SIM_DOCTOR_TEST_SIGNAL_HOLD_MS` and `SIM_DOCTOR_TEST_WEDGE` (park a run at its first
//! interrupt checkpoint) are compiled only with the `test-seams` feature. `cargo test` turns it on
//! through the dev-dependency on this package; `cargo build --release` does not. This test builds
//! the release binary the way a release is built and checks, on the bytes and on the behaviour,
//! that the variables are not there. It builds the whole crate in release mode, so it is
//! `#[ignore]`d and CI runs it on its own: `cargo test --test release_seams -- --ignored`.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SEAMS: [&str; 3] = [
    "SIM_DOCTOR_TEST_REPLAY",
    "SIM_DOCTOR_TEST_SIGNAL_HOLD_MS",
    "SIM_DOCTOR_TEST_WEDGE",
];

fn contains(bytes: &[u8], needle: &str) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
#[ignore = "builds the crate in release mode; run with --ignored (CI does)"]
fn a_release_build_ignores_the_test_seams() {
    // The control: the binary `cargo test` built has the seams, so the check below can fail.
    let test_binary = std::fs::read(env!("CARGO_BIN_EXE_sim-doctor")).unwrap();
    for seam in SEAMS {
        assert!(contains(&test_binary, seam), "the test build lost {seam}");
    }

    let target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("release-seams");
    let built = Command::new(env!("CARGO"))
        .args([
            "build",
            "--release",
            "--locked",
            "--bin",
            "sim-doctor",
            "--target-dir",
        ])
        .arg(&target)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .unwrap();
    assert!(built.success(), "cargo build --release failed");
    let binary = target.join("release").join("sim-doctor");

    let bytes = std::fs::read(&binary).unwrap();
    for seam in SEAMS {
        assert!(!contains(&bytes, seam), "the release binary names {seam}");
    }

    // And behaviour: a hold that would park `modules` for a minute, and a replay log that would
    // answer `scan` (here an empty one, which a seam would reject as "replay diverged").
    let empty_log = target.join("empty.log");
    std::fs::write(&empty_log, "").unwrap();
    let started = Instant::now();
    let held = Command::new(&binary)
        .args(["modules", "--json"])
        .env("SIM_DOCTOR_TEST_SIGNAL_HOLD_MS", "60000")
        .env("SIM_DOCTOR_TEST_WEDGE", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the hold was honoured"
    );
    assert!(held.status.success());
    assert!(!String::from_utf8_lossy(&held.stderr).contains("parked"));
    let scan = Command::new(&binary)
        .args(["scan", "--json"])
        .env("SIM_DOCTOR_TEST_REPLAY", &empty_log)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&scan.stdout),
        String::from_utf8_lossy(&scan.stderr)
    );
    assert!(
        !text.contains("replay"),
        "the replay log was honoured: {text}"
    );
}
