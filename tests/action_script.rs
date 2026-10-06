//! Script logic of the GitHub Action (issue #43): `scripts/sim-doctor-action.sh`
//! run against a FAKE `sim-doctor` that prints a canned envelope and exits with
//! a canned code. No card, no reader. What this proves is the gate mapping, the
//! argv the script builds, the summary and the sanitising; the real build, the
//! software card and the SARIF upload are proved only by the action-selftest
//! workflow on a hosted runner.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Run {
    code: i32,
    summary: String,
    argv: String,
    outputs: String,
    stdout: String,
    out: PathBuf,
}

/// Run the real script with a fake sim-doctor that prints `body` and exits `rc`.
/// `baseline` creates the baseline file the script is pointed at.
fn run(name: &str, rc: i32, body: &str, baseline: bool, sarif: bool) -> Run {
    let dir = std::env::temp_dir().join(format!("sd-action-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("body.json"), body).unwrap();
    let fake = dir.join("fake-sim-doctor");
    // The fake records its argv, honours --sarif only when asked, and prints the canned body.
    fs::write(
        &fake,
        r#"#!/usr/bin/env bash
printf '%s\n' "$@" > "$FAKE_DIR/argv"
if [ "${FAKE_SARIF:-0}" = 1 ]; then
  while [ $# -gt 0 ]; do [ "$1" = --sarif ] && echo '{"version":"2.1.0"}' > "$2"; shift; done
fi
cat "$FAKE_DIR/body.json"
exit "$FAKE_RC"
"#,
    )
    .unwrap();
    Command::new("chmod").arg("+x").arg(&fake).status().unwrap();
    let base = dir.join("baseline.json");
    if baseline {
        fs::write(&base, "{}").unwrap();
    }
    let out = dir.join("out");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/sim-doctor-action.sh");
    let o = Command::new("bash")
        .arg(script)
        .env("SIM_DOCTOR", &fake)
        .env("BASELINE", &base)
        .env("OUT", &out)
        .env("GITHUB_OUTPUT", dir.join("gh_output"))
        .env("GITHUB_STEP_SUMMARY", dir.join("gh_summary"))
        .env("FAKE_DIR", &dir)
        .env("FAKE_RC", rc.to_string())
        .env("FAKE_SARIF", if sarif { "1" } else { "0" })
        .output()
        .unwrap();
    let read = |p: PathBuf| fs::read_to_string(p).unwrap_or_default();
    Run {
        code: o.status.code().unwrap_or(-1),
        summary: read(out.join("summary.md")),
        argv: read(dir.join("argv")),
        outputs: read(dir.join("gh_output")),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        out,
    }
}

const CLEAN: &str = r#"{"type":"scan","payload":{"code":0,"message":"ok","data":{"findings":{"count":2,"findings":[{"severity":"high"},{"severity":"low"}]},"score":{"value":89}}}}"#;
const DIFF: &str = r#"{"type":"scan","payload":{"code":1,"message":"regressed","data":{"findings":{"count":3,"findings":[{"severity":"high"},{"severity":"high"},{"severity":"low"}]},"diff":{"regressed":true,"counts":{"new":2,"fixed":0,"persisting":1}}}}}"#;

fn error_body(msg: &str) -> String {
    serde_json::json!({"type":"scan","payload":{"code":1,"message":"x","data":{"error":{"kind":"no-reader","message":msg}}}}).to_string()
}

#[test]
fn exit_0_is_ok_and_the_summary_carries_the_marker_table_and_score() {
    let r = run("clean", 0, CLEAN, false, false);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(
        r.summary.starts_with("<!-- sim-doctor -->"),
        "{}",
        r.summary
    );
    assert!(r.summary.contains("| high | 1 |"), "{}", r.summary);
    assert!(r.summary.contains("89"), "{}", r.summary);
    assert!(r
        .outputs
        .contains(&format!("summary={}", r.out.join("summary.md").display())));
}

#[test]
fn a_regressed_diff_fails_the_gate_and_names_the_new_count() {
    let r = run("gate", 1, DIFF, true, false);
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(r.summary.contains("GATE FAILED"), "{}", r.summary);
    assert!(r.summary.contains("New findings | 2"), "{}", r.summary);
}

#[test]
fn a_refusal_with_data_error_is_a_tool_failure_exit_2() {
    let r = run("refusal", 1, &error_body("no reader"), false, false);
    assert_eq!(r.code, 2, "{}", r.stdout);
    assert!(r.summary.contains("TOOL FAILURE"), "{}", r.summary);
    assert!(r.summary.contains("no reader"), "{}", r.summary);
}

#[test]
fn exit_129_and_unknown_exits_are_tool_failures() {
    assert_eq!(run("e129", 129, "", false, false).code, 2);
    assert_eq!(run("e130", 130, "", false, false).code, 2);
    assert_eq!(run("e7", 7, CLEAN, false, false).code, 2);
    // exit 1 with an envelope that is neither a diff nor an error is not a gate
    assert_eq!(run("e1bare", 1, CLEAN, false, false).code, 2);
}

#[test]
fn no_baseline_file_means_no_baseline_or_diff_flag() {
    let r = run("nobase", 0, CLEAN, false, false);
    assert!(
        !r.argv.contains("--baseline") && !r.argv.contains("--diff"),
        "{}",
        r.argv
    );
    assert!(r.argv.contains("--json"), "{}", r.argv);
}

#[test]
fn a_baseline_file_means_both_flags() {
    let r = run("base", 0, CLEAN, true, false);
    assert!(r.argv.contains("--baseline\n"), "{}", r.argv);
    assert!(r.argv.contains("--diff\n"), "{}", r.argv);
}

#[test]
fn the_sarif_path_is_passed_and_published_only_when_written() {
    let r = run("sarif", 0, CLEAN, false, true);
    let want = r.out.join("sim-doctor.sarif");
    assert!(
        r.argv.contains(&format!("--sarif\n{}", want.display())),
        "{}",
        r.argv
    );
    assert!(
        r.outputs.contains(&format!("sarif={}", want.display())),
        "{}",
        r.outputs
    );
    let r = run("nosarif", 0, CLEAN, false, false);
    assert!(!r.outputs.contains("sarif="), "{}", r.outputs);
}

#[test]
fn hostile_error_text_never_appears_raw() {
    let evil = "`id` | @octocat\n::add-mask::secret\r::error::boom";
    let r = run("hostile", 1, &error_body(evil), false, false);
    assert_eq!(r.code, 2);
    for text in [&r.summary, &r.stdout] {
        assert!(!text.contains('`'), "{text}");
        assert!(!text.contains("@octocat"), "{text}");
        assert!(!text.contains("::add-mask::"), "{text}");
        assert!(!text.contains('\r'), "{text}");
        assert!(
            !text.lines().any(|l| l.starts_with("::")
                && !l.starts_with("::error::sim-doctor")
                && !l.starts_with("::notice::no baseline")),
            "{text}"
        );
        assert!(!text.contains("::error::boom"), "{text}");
    }
    // the only pipes on the error row are the table's own
    let row = r
        .summary
        .lines()
        .find(|l| l.starts_with("| Error"))
        .unwrap_or("");
    assert!(row.matches('|').count() == 3, "{row}");
}
