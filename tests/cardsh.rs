//! `sim-doctor card` as the built binary, over recorded card sessions (tests/corpus/cardsh_*.jsonl,
//! generated from the shell's own test card and checked for drift by a unit test in src/cardsh).
//! The replay seam (`SIM_DOCTOR_TEST_REPLAY`) is compiled in test builds only.

use std::process::{Command, Output};

fn card(fixture: &str, args: &[&str]) -> Output {
    let log = format!("{}/tests/corpus/{fixture}", env!("CARGO_MANIFEST_DIR"));
    Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("card")
        .args(args)
        .env("SIM_DOCTOR_TEST_REPLAY", log)
        .output()
        .expect("the binary runs")
}

fn lines(out: &Output) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{l}: {e}")))
        .collect()
}

#[test]
fn channel_state_persists_across_commands_in_one_process() {
    let out = card(
        "cardsh_channels.jsonl",
        &[
            "--json",
            "-c",
            "open_channel; status; channel 0; status; close_channel 1; status",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r.len(), 6);
    assert_eq!(r[0]["data"]["channel"], 1);
    assert_eq!(
        r[1]["data"]["channel"], 1,
        "the channel opened by the first command is still in use"
    );
    assert_eq!(r[1]["data"]["open_channels"], serde_json::json!([0, 1]));
    assert_eq!(r[3]["data"]["channel"], 0);
    assert_eq!(r[5]["data"]["open_channels"], serde_json::json!([0]));
    assert!(r.iter().all(|v| v["ok"] == true));
}

#[test]
fn a_failed_command_is_exit_one_and_the_rest_still_run() {
    let out = card(
        "cardsh_channels.jsonl",
        &["-c", "channel 3; open_channel; status"],
    );
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("channel 1 opened and in use"), "{text}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("channel 3 is not open"));
}

#[test]
fn commands_come_from_stdin_when_not_a_terminal_and_quit_stops() {
    let log = format!(
        "{}/tests/corpus/cardsh_channels.jsonl",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(["card", "--json"])
        .env("SIM_DOCTOR_TEST_REPLAY", log)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"open_channel\n# a comment\nstatus\nquit\nstatus\n")
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        lines(&out).len(),
        3,
        "open, status, quit; the comment is skipped and nothing runs after quit"
    );
}

#[test]
fn help_lists_the_commands() {
    let out = card("cardsh_channels.jsonl", &["-c", "help"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    for name in [
        "equip",
        "status",
        "open_channel",
        "close_channel",
        "channel",
        "quit",
    ] {
        assert!(text.contains(name), "{name} missing:\n{text}");
    }
}

#[test]
fn apdu_dry_runs_then_sends_with_yes_and_checks_expectations() {
    // The recording holds the SELECT, the READ BINARY and the one UPDATE that was sent with --yes: a
    // dry run reaches the card never, so a replay that diverged would fail the whole run.
    let out = card(
        "cardsh_apdu.jsonl",
        &[
            "--json",
            "-c",
            "apdu 00A4000C022FE2; apdu 00B000000A --expect-response-regex ^9810; apdu 00D6000001AA; \
             apdu --yes 00D6000001AA --expect-sw 6Dxx",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[1]["data"]["data"], "98101032547698103254");
    assert_eq!(
        r[2]["data"]["sent"], false,
        "a write is a dry run without --yes"
    );
    assert_eq!(r[3]["data"]["sw"], "6D00");

    // The same card, a wrong expectation: the command fails, the exit code says so, and the response is kept.
    let out = card(
        "cardsh_apdu.jsonl",
        &[
            "--json",
            "-c",
            "apdu 00A4000C022FE2; apdu 00B000000A --expect-sw 6A82",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let r = lines(&out);
    assert_eq!(r[1]["ok"], false);
    assert_eq!(r[1]["data"]["sw"], "9000");
}
