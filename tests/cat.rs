//! `sim-doctor cat decode` as the built binary: no card, no reader.

use std::io::Write;
use std::process::{Command, Stdio};

const DISPLAY_TEXT: &str = "D0 0F 81 03 01 21 80 82 02 81 02 8D 04 04 48 49 21";

fn run(args: &[&str], stdin: Option<&str>) -> (Option<i32>, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(["cat", "decode"])
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(text) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_proactive_command_is_named_and_its_fields_are_decoded() {
    let (code, out, _) = run(&[DISPLAY_TEXT], None);
    assert_eq!(code, Some(0));
    assert!(out.starts_with("proactive-command: DISPLAY TEXT"), "{out}");
    assert!(
        out.contains("wait for user to clear message") && out.contains("text=HI!"),
        "{out}"
    );
}

#[test]
fn json_is_one_cat_envelope_and_stdin_takes_one_object_per_line() {
    let (code, out, _) = run(
        &["--json"],
        Some(&format!(
            "# a comment\n{DISPLAY_TEXT}\n81 03 01 21 80 82 02 82 81 83 01 00\n"
        )),
    );
    assert_eq!(code, Some(0));
    assert_eq!(out.lines().count(), 1, "one envelope");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["type"], "cat");
    let objects = &v["payload"]["data"]["objects"];
    assert_eq!(objects[0]["name"], "DISPLAY TEXT");
    assert_eq!(objects[1]["kind"], "terminal-response");
    assert_eq!(
        objects[1]["elements"][2]["fields"]["general_result"]["name"],
        "performed successfully"
    );
    assert_eq!(v["payload"]["data"]["card_touched"], false);
}

#[test]
fn bad_input_is_exit_one_with_a_sentence_and_no_output() {
    for bad in ["zz", "D0 05 81", "D0 03 81 03 01"] {
        let (code, out, err) = run(&[bad], None);
        assert_eq!(code, Some(1), "{bad}");
        assert!(out.is_empty(), "{bad}: {out}");
        assert!(err.contains("sim-doctor:"), "{bad}: {err}");
    }
    let (code, _, err) = run(&[], Some("\n"));
    assert_eq!(code, Some(1));
    assert!(err.contains("no CAT data"));
}
