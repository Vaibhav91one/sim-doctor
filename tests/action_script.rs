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

struct Case {
    name: &'static str,
    rc: i32,
    body: Vec<u8>,
    baseline: bool,
    sarif: bool,
    stale: bool,
    /// Extra env; the value `<unset>` removes the variable.
    env: Vec<(&'static str, String)>,
}

fn case(name: &'static str, rc: i32, body: impl AsRef<[u8]>) -> Case {
    Case {
        name,
        rc,
        body: body.as_ref().to_vec(),
        baseline: false,
        sarif: false,
        stale: false,
        env: vec![],
    }
}

impl Case {
    fn baseline(mut self) -> Self {
        self.baseline = true;
        self
    }
    fn sarif(mut self) -> Self {
        self.sarif = true;
        self
    }
    fn stale(mut self) -> Self {
        self.stale = true;
        self
    }
    fn env(mut self, k: &'static str, v: &str) -> Self {
        self.env.push((k, v.to_owned()));
        self
    }

    /// Run the real script with a fake sim-doctor that prints the body and exits `rc`.
    fn run(self) -> Run {
        let dir =
            std::env::temp_dir().join(format!("sd-action-{}-{}", std::process::id(), self.name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("body.json"), &self.body).unwrap();
        let fake = dir.join("fake-sim-doctor");
        // The fake records its argv, writes the SARIF only when asked, and prints the canned body.
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
        if self.baseline {
            fs::write(&base, "{}").unwrap();
        }
        let out = dir.join("out");
        if self.stale {
            fs::create_dir_all(&out).unwrap();
            fs::write(out.join("sim-doctor.sarif"), "STALE").unwrap();
            fs::write(out.join("summary.md"), "STALE").unwrap();
        }
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/sim-doctor-action.sh");
        let mut cmd = Command::new("bash");
        cmd.arg(script)
            .env("SIM_DOCTOR", &fake)
            .env("BASELINE", &base)
            .env("REQUIRE_BASELINE", "false")
            .env_remove("READER")
            .env_remove("SEVERITY")
            .env("OUT", &out)
            .env("GITHUB_OUTPUT", dir.join("gh_output"))
            .env("GITHUB_STEP_SUMMARY", dir.join("gh_summary"))
            .env("FAKE_DIR", &dir)
            .env("FAKE_RC", self.rc.to_string())
            .env("FAKE_SARIF", if self.sarif { "1" } else { "0" });
        for (k, v) in &self.env {
            if v == "<unset>" {
                cmd.env_remove(k);
            } else {
                cmd.env(k, v);
            }
        }
        let o = cmd.output().unwrap();
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
}

const CLEAN: &str = r#"{"type":"scan","payload":{"code":0,"message":"ok","data":{"findings":{"count":2,"findings":[{"severity":"high"},{"severity":"low"}]},"score":{"value":89}}}}"#;
const DIFF: &str = r#"{"type":"scan","payload":{"code":1,"message":"regressed","data":{"findings":{"count":3,"findings":[{"severity":"high"},{"severity":"high"},{"severity":"low"}]},"diff":{"regressed":true,"counts":{"new":2,"fixed":0,"persisting":1}}}}}"#;
const DIFF_OK: &str = r#"{"type":"scan","payload":{"code":0,"message":"ok","data":{"findings":{"count":1,"findings":[{"severity":"low"}]},"diff":{"regressed":false,"counts":{"new":0,"fixed":1,"persisting":1}}}}}"#;

fn error_body(msg: &str) -> String {
    serde_json::json!({"type":"scan","payload":{"code":1,"message":"x","data":{"error":{"kind":"no-reader","message":msg}}}}).to_string()
}

fn has_row(r: &Run, row: &str) -> bool {
    r.summary.lines().any(|l| l == row)
}

#[test]
fn exit_0_is_ok_and_the_summary_carries_the_marker_table_and_score() {
    let r = case("clean", 0, CLEAN).run();
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(
        r.summary.starts_with("<!-- sim-doctor -->"),
        "{}",
        r.summary
    );
    assert!(has_row(&r, "| high | 1 |"), "{}", r.summary);
    assert!(has_row(&r, "| Score | 89 |"), "{}", r.summary);
    assert!(r
        .outputs
        .contains(&format!("summary={}", r.out.join("summary.md").display())));
}

#[test]
fn a_regressed_diff_fails_the_gate_and_names_the_new_count() {
    let r = case("gate", 1, DIFF).baseline().run();
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(has_row(&r, "| Result | GATE FAILED |"), "{}", r.summary);
    assert!(has_row(&r, "| New findings | 2 |"), "{}", r.summary);
}

#[test]
fn a_gated_exit_0_with_a_diff_is_ok() {
    let r = case("gated-ok", 0, DIFF_OK).baseline().run();
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(has_row(&r, "| New findings | 0 |"), "{}", r.summary);
}

#[test]
fn a_gated_exit_0_without_a_diff_is_a_tool_failure_not_ok() {
    let r = case("failopen", 0, CLEAN).baseline().run();
    assert_eq!(r.code, 2, "{}", r.stdout);
    assert!(r.summary.contains("did not report a diff"), "{}", r.summary);
}

#[test]
fn exit_0_with_data_error_is_a_tool_failure() {
    for (n, gated) in [("e0err", false), ("e0errg", true)] {
        let c = case(n, 0, error_body("boom"));
        let r = if gated { c.baseline() } else { c }.run();
        assert_eq!(r.code, 2, "{}", r.stdout);
        assert!(has_row(&r, "| Result | TOOL FAILURE |"), "{}", r.summary);
    }
}

#[test]
fn a_refusal_with_data_error_is_a_tool_failure_exit_2() {
    let r = case("refusal", 1, error_body("no reader")).run();
    assert_eq!(r.code, 2, "{}", r.stdout);
    assert!(r.summary.contains("TOOL FAILURE"), "{}", r.summary);
    assert!(r.summary.contains("no reader"), "{}", r.summary);
}

#[test]
fn exit_129_130_and_unknown_exits_are_tool_failures() {
    assert_eq!(case("e129", 129, "").run().code, 2);
    assert_eq!(case("e130", 130, "").run().code, 2);
    assert_eq!(case("e130b", 130, CLEAN).run().code, 2);
    assert_eq!(case("e7", 7, CLEAN).run().code, 2);
    // exit 1 with an envelope that is neither a diff nor an error is not a gate
    assert_eq!(case("e1bare", 1, CLEAN).run().code, 2);
}

#[test]
fn an_unparsable_or_unexpected_envelope_is_a_tool_failure_with_a_summary() {
    let two = format!("{CLEAN}\n{CLEAN}");
    let bodies: Vec<(&str, Vec<u8>)> = vec![
        ("nonutf8", vec![0xff, 0xfe, 0x80, b'{']),
        ("empty", vec![]),
        ("two", two.into_bytes()),
        (
            "findstr",
            br#"{"payload":{"data":{"findings":"oops"}}}"#.to_vec(),
        ),
        (
            "findlist",
            br#"{"payload":{"data":{"findings":["x"]}}}"#.to_vec(),
        ),
        ("notobj", br#"[1,2]"#.to_vec()),
    ];
    for (n, b) in bodies {
        for rc in [0, 1] {
            let name: &'static str = Box::leak(format!("{n}{rc}").into_boxed_str());
            let r = case(name, rc, &b).run();
            assert_eq!(r.code, 2, "{name}: {}", r.stdout);
            assert!(
                has_row(&r, "| Result | TOOL FAILURE |"),
                "{name}: {}",
                r.summary
            );
        }
    }
}

#[test]
fn no_baseline_file_means_no_baseline_or_diff_flag() {
    let r = case("nobase", 0, CLEAN).run();
    assert!(
        !r.argv.contains("--baseline") && !r.argv.contains("--diff"),
        "{}",
        r.argv
    );
    assert!(r.argv.contains("--json"), "{}", r.argv);
}

#[test]
fn a_baseline_file_means_both_flags() {
    let r = case("base", 0, DIFF_OK).baseline().run();
    assert!(r.argv.contains("--baseline\n"), "{}", r.argv);
    assert!(r.argv.contains("--diff\n"), "{}", r.argv);
}

#[test]
fn a_missing_baseline_is_refused_by_default_and_when_required() {
    for (n, v) in [("reqdefault", "<unset>"), ("reqtrue", "true")] {
        let r = case(n, 0, CLEAN).env("REQUIRE_BASELINE", v).run();
        assert_eq!(r.code, 2, "{}", r.stdout);
        assert!(r.stdout.contains("::error::"), "{}", r.stdout);
        assert!(r.argv.is_empty(), "the scan must not run: {}", r.argv);
        let row = r
            .summary
            .lines()
            .find(|l| l.starts_with("| Error"))
            .unwrap_or("");
        assert!(row.contains("baseline.json"), "{}", r.summary);
    }
}

#[test]
fn a_directory_as_baseline_is_refused_when_required() {
    let dir = std::env::temp_dir();
    let r = case("basedir", 0, CLEAN)
        .env("REQUIRE_BASELINE", "true")
        .env("BASELINE", dir.to_str().unwrap())
        .run();
    assert_eq!(r.code, 2, "{}", r.stdout);
}

#[test]
fn a_missing_baseline_when_not_required_reports_loudly_without_a_gate() {
    let r = case("optional", 0, CLEAN).run();
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(r.stdout.contains("::warning::"), "{}", r.stdout);
    assert!(
        has_row(
            &r,
            "| NOT GATED | no baseline file, this run cannot fail on new findings |"
        ),
        "{}",
        r.summary
    );
}

#[test]
fn the_sarif_path_is_passed_and_published_only_when_written() {
    let r = case("sarif", 0, CLEAN).sarif().run();
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
    let r = case("nosarif", 0, CLEAN).run();
    assert!(!r.outputs.contains("sarif="), "{}", r.outputs);
}

#[test]
fn stale_files_from_an_earlier_run_are_never_published() {
    let r = case("stale", 0, CLEAN).stale().run();
    assert!(!r.outputs.contains("sarif="), "{}", r.outputs);
    assert!(!r.out.join("sim-doctor.sarif").exists());
    assert!(
        r.summary.starts_with("<!-- sim-doctor -->"),
        "{}",
        r.summary
    );
}

#[test]
fn severity_and_reader_reach_argv_and_a_leading_dash_reader_is_refused() {
    let r = case("sevreader", 0, CLEAN)
        .env("SEVERITY", "high")
        .env("READER", "My Reader 0")
        .run();
    assert!(r.argv.contains("--severity\nhigh\n"), "{}", r.argv);
    assert!(r.argv.contains("--reader\nMy Reader 0\n"), "{}", r.argv);
    let r = case("noreader", 0, CLEAN).run();
    assert!(
        !r.argv.contains("--reader") && !r.argv.contains("--severity"),
        "{}",
        r.argv
    );
    let r = case("dashreader", 0, CLEAN).env("READER", "--evil").run();
    assert_eq!(r.code, 2, "{}", r.stdout);
    assert!(r.argv.is_empty(), "{}", r.argv);
}

fn assert_clean(text: &str) {
    let text = &text.replace("<!-- sim-doctor -->", "");
    for bad in ['`', '\r', '[', ']', '<', '>'] {
        assert!(!text.contains(bad), "{bad:?} in {text}");
    }
    for bad in ["@octocat", "::add-mask::", "::error::boom", "](", "<img"] {
        assert!(!text.contains(bad), "{bad} in {text}");
    }
    let ok = |l: &str| {
        l.starts_with("::error::sim-doctor")
            || l.starts_with("::warning::")
            || l.starts_with("::notice::")
    };
    assert!(
        !text.lines().any(|l| l.starts_with("::") && !ok(l)),
        "{text}"
    );
}

#[test]
fn hostile_error_text_never_appears_raw() {
    let evil = "`id` | @octocat\n::add-mask::secret\r::error::boom [x](http://evil) <img src=x>";
    let r = case("hostile", 1, error_body(evil)).run();
    assert_eq!(r.code, 2);
    assert_clean(&r.summary);
    assert_clean(&r.stdout);
    // the only pipes on the error row are the table's own
    let row = r
        .summary
        .lines()
        .find(|l| l.starts_with("| Error"))
        .unwrap_or("");
    assert!(row.matches('|').count() == 3, "{row}");
}

#[test]
fn hostile_severity_and_diff_counts_never_appear_raw() {
    let body = serde_json::json!({"payload":{"code":1,"data":{
        "findings":{"findings":[{"severity":"<img src=x>\n@octocat [x](http://evil)"}]},
        "diff":{"counts":{"new":"`id`\n::add-mask::z|@octocat","fixed":"[x](http://evil)"}}}}})
    .to_string();
    let r = case("hostile2", 1, body).baseline().run();
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert_clean(&r.summary);
    assert_clean(&r.stdout);
}

#[test]
fn a_hostile_baseline_path_is_not_shown_raw() {
    let r = case("hostilepath", 0, CLEAN)
        .env("REQUIRE_BASELINE", "true")
        .env("BASELINE", "x`id`@octocat[a](http://evil)")
        .run();
    assert_eq!(r.code, 2);
    assert_clean(&r.summary);
    assert_clean(&r.stdout);
}
