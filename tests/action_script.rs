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
            .env_remove("FAIL_ON")
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

const CLEAN: &str = r#"{"schema":"doctor/1","tool":"sim-doctor","version":"0.3.0","exit_code":0,"score":{"value":89,"label":"needs work","model":"sim/1","coverage_gaps":0},"findings":[{"severity":"high"},{"severity":"low"}],"data":{}}"#;
const NEW: &str = r#"{"schema":"doctor/1","tool":"sim-doctor","version":"0.3.0","exit_code":3,"score":{"value":40,"label":"critical","model":"sim/1","coverage_gaps":0},"findings":[{"severity":"high","baseline_state":"new"},{"severity":"high","baseline_state":"new"},{"severity":"low","baseline_state":"unchanged"}],"baseline":{"new":2,"unchanged":1,"fixed":0},"data":{}}"#;
const NEW_OK: &str = r#"{"schema":"doctor/1","tool":"sim-doctor","version":"0.3.0","exit_code":0,"score":{"value":97,"label":"good","model":"sim/1","coverage_gaps":0},"findings":[{"severity":"low","baseline_state":"unchanged"}],"baseline":{"new":0,"unchanged":1,"fixed":1},"data":{}}"#;

fn error_body(msg: &str) -> String {
    serde_json::json!({"schema":"doctor/1","tool":"sim-doctor","exit_code":2,"score":{"value":0},"findings":[],"data":{"error":{"kind":"no-reader","message":msg}}}).to_string()
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
fn a_new_finding_against_the_baseline_fails_the_gate_and_names_the_new_count() {
    let r = case("gate", 3, NEW).baseline().run();
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(has_row(&r, "| Result | GATE FAILED |"), "{}", r.summary);
    assert!(has_row(&r, "| New findings | 2 |"), "{}", r.summary);
}

#[test]
fn a_gated_exit_0_with_a_baseline_block_is_ok() {
    let r = case("gated-ok", 0, NEW_OK).baseline().run();
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(has_row(&r, "| New findings | 0 |"), "{}", r.summary);
}

#[test]
fn a_gated_exit_0_without_a_baseline_block_is_a_tool_failure_not_ok() {
    let r = case("failopen", 0, CLEAN).baseline().run();
    assert_eq!(r.code, 2, "{}", r.stdout);
    assert!(
        r.summary.contains("did not report a baseline comparison"),
        "{}",
        r.summary
    );
}

#[test]
fn an_ungated_exit_1_is_reported_not_failed() {
    let body = CLEAN.replace(r#""exit_code":0"#, r#""exit_code":1"#);
    let r = case("ungated1", 1, body).run();
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(
        r.summary.contains("NOT GATED"),
        "findings above --fail-on without a baseline are shown, not failed: {}",
        r.summary
    );
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
    let r = case("refusal", 2, error_body("no reader")).run();
    assert_eq!(r.code, 2, "{}", r.stdout);
    assert!(r.summary.contains("TOOL FAILURE"), "{}", r.summary);
    assert!(r.summary.contains("no reader"), "{}", r.summary);
}

#[test]
fn exit_2_129_130_and_unknown_exits_are_tool_failures() {
    assert_eq!(case("e2", 2, "").run().code, 2);
    assert_eq!(case("e129", 129, "").run().code, 2);
    assert_eq!(case("e130", 130, "").run().code, 2);
    assert_eq!(case("e130b", 130, CLEAN).run().code, 2);
    assert_eq!(case("e7", 7, CLEAN).run().code, 2);
    // exit 1 under a baseline is not a baseline result (it would be 3 or 0)
    assert_eq!(case("e1gated", 1, CLEAN).baseline().run().code, 2);
    // exit 3 without a baseline cannot happen
    assert_eq!(case("e3bare", 3, CLEAN).run().code, 2);
    // an envelope whose exit_code disagrees with the status is not trusted
    assert_eq!(case("e0lie", 3, CLEAN).baseline().run().code, 2);
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
            br#"{"schema":"doctor/1","exit_code":0,"data":{},"findings":"oops"}"#.to_vec(),
        ),
        (
            "lpac",
            br#"{"type":"scan","payload":{"code":0,"message":"ok","data":{}}}"#.to_vec(),
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
fn no_baseline_file_means_no_baseline_flag() {
    let r = case("nobase", 0, CLEAN).run();
    assert!(!r.argv.contains("--baseline"), "{}", r.argv);
    assert!(r.argv.contains("--json"), "{}", r.argv);
}

#[test]
fn a_baseline_file_means_the_baseline_flag_and_no_diff_flag() {
    let r = case("base", 0, NEW_OK).baseline().run();
    assert!(r.argv.contains("--baseline\n"), "{}", r.argv);
    assert!(!r.argv.contains("--diff"), "{}", r.argv);
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
fn hostile_severity_and_baseline_counts_never_appear_raw() {
    let body = serde_json::json!({"schema":"doctor/1","exit_code":3,"data":{},
        "findings":[{"severity":"<img src=x>\n@octocat [x](http://evil)"}],
        "baseline":{"new":"`id`\n::add-mask::z|@octocat","fixed":"[x](http://evil)"}})
    .to_string();
    let r = case("hostile2", 3, body).baseline().run();
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

/// The baseline the Action offers for committing is REDUCED: rule ids,
/// fingerprints, severities and the run record. No ATR, ICCID, IMSI, EF contents
/// or key bytes, wherever they sit in the envelope.
#[test]
fn the_baseline_the_action_writes_holds_no_card_data() {
    if Command::new("jq").arg("--version").output().is_err() {
        eprintln!("jq is not installed; skipping");
        return;
    }
    const SECRETS: [&str; 5] = [
        "3b9f96801fc78031a073be21136743200718000001a5",
        "8988211000000123456",
        "001010123456789",
        "00112233445566778899aabbccddeeff",
        "secret-message-text",
    ];
    let body = serde_json::json!({
        "schema":"doctor/1","tool":"sim-doctor","version":"0.3.0","exit_code":1,
        "score":{"value":75,"label":"needs work","model":"sim/1","coverage_gaps":0},
        "findings":[{"id":"filesystem/sensitive-ef-always","fingerprint":"0123456789abcdef","severity":"high",
            "message":"secret-message-text IMSI 001010123456789","category":"filesystem",
            "location":{"kind":"card-path","ref":"3F00/7F20/6F07"},
            "location_detail":{"kind":"file","path":"3F00/7F20/6F07"},
            "evidence":[{"ref":"text","value":"ICCID 8988211000000123456"}],"remedy":null}],
        "data":{
            "atr":SECRETS[0],
            "ef_contents":[{"ef":"EF.Keys","fields":{"ki":SECRETS[3],"iccid":SECRETS[1]}}],
            "run":{"reader":"fake reader","dialect":"ts-102-221","candidates":"sim-families",
                   "severity_threshold":null,"tar_selection":"off","complete":true,
                   "truncated_by":null,"limits_hit":[],"rules_run":1,
                   "rules":[{"id":"filesystem/sensitive-ef-always","evidence":true}]}}
    })
    .to_string();
    let r = case("reduced", 1, body.clone()).run();
    assert_eq!(r.code, 0, "{}", r.stdout);
    let reduced = fs::read_to_string(r.out.join("baseline.json")).expect("a reduced baseline");
    for secret in SECRETS {
        assert!(body.contains(secret), "the fixture must hold {secret}");
        assert!(
            !reduced.contains(secret),
            "{secret} leaked into the baseline: {reduced}"
        );
    }
    let v: serde_json::Value = serde_json::from_str(&reduced).unwrap();
    assert_eq!(v["schema"], "doctor/1");
    assert_eq!(
        v["findings"],
        serde_json::json!([{"id":"filesystem/sensitive-ef-always","fingerprint":"0123456789abcdef","severity":"high"}])
    );
    assert_eq!(v["data"]["run"]["rules_run"], 1);
    assert_eq!(
        v["data"].as_object().unwrap().len(),
        1,
        "only data.run survives"
    );
    assert!(r.outputs.contains("baseline="), "{}", r.outputs);
}

#[test]
fn a_failed_run_writes_no_baseline() {
    let r = case("nobl", 2, error_body("no reader")).run();
    assert_eq!(r.code, 2);
    assert!(!r.out.join("baseline.json").exists());
}
