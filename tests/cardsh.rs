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

#[test]
fn select_keeps_the_path_between_commands_in_one_process() {
    let out = card(
        "cardsh_select.jsonl",
        &[
            "--json",
            "-c",
            "select 3F00; select 7F20; select 6F07; select 3F00; select 3F00/7F10/6F3A; select ADF.USIM; \
             select EF.IMSI; select_path 6FAD; select 2FE2",
        ],
    );
    // The last SELECT is 2FE2 inside the ADF: the card says 6A82, so one failure and exit 1.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    let paths: Vec<&str> = r
        .iter()
        .map(|v| v["data"]["path"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(
        paths,
        [
            "3F00",
            "3F00/7F20",
            "3F00/7F20/6F07",
            "3F00",
            "3F00/7F10/6F3A",
            "3F00/ADF:A0000000871002FF49FF0589",
            "3F00/ADF:A0000000871002FF49FF0589/6F07",
            "3F00/ADF:A0000000871002FF49FF0589/6FAD",
            "",
        ]
    );
    assert_eq!(r[2]["data"]["size"], 9);
    assert_eq!(r[4]["data"]["records"], 3);
    assert_eq!(r[8]["ok"], false);
}

#[test]
fn read_commands_return_what_the_selected_file_holds() {
    let out = card(
        "cardsh_read.jsonl",
        &[
            "--json",
            "-c",
            "select 2FE2; read_binary; read_binary --offset 2 --length 3; read_binary --length 20; select 3F00/7F10/6F3A; \
             read_record 1; read_records; read_record 4; select 3F00/7F10/6F99; read_binary",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "read_record 4 is past the last record"
    );
    let r = lines(&out);
    assert_eq!(r[1]["data"]["data"], "98101032547698103254");
    assert_eq!(r[2]["data"]["data"], "103254");
    assert_eq!(r[3]["data"]["length"], 10);
    assert_eq!(r[5]["data"]["length"], 28);
    assert_eq!(r[6]["data"]["count"], 3);
    assert_eq!(r[7]["ok"], false);
    assert!(r[7]["error"].as_str().unwrap().contains("6A83"));
    assert_eq!(r[9]["data"]["length"], 300);
}

#[test]
fn decoded_reads_name_the_standard_file_and_decode_it() {
    let out = card(
        "cardsh_decoded.jsonl",
        &[
            "--json",
            "-c",
            "select ADF.USIM; select EF.IMSI; read_binary_decoded; select EF.AD; read_binary_decoded; \
             select 3F00/7F10/6F3A; read_records_decoded; select 3F00/2FE2; read_binary_decoded",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[2]["data"]["ef"], "EF.IMSI");
    assert_eq!(r[2]["data"]["decoded"]["imsi"], "001010123456789");
    assert_eq!(r[4]["data"]["decoded"]["mnc_len"], 2);
    assert_eq!(r[6]["data"]["decoded"]["records"][0]["alpha"], "Ann");
    assert_eq!(r[8]["data"]["decoded"]["iccid"], "89010123456789012345");
}

#[test]
fn files_and_decode_work_without_a_card() {
    // No SIM_DOCTOR_TEST_REPLAY and no reader: `card` cannot open one, so these run through the library path
    // of the same grammar via an empty replay log.
    let dir = std::env::temp_dir().join("cardsh-offline.jsonl");
    std::fs::write(&dir, "").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args([
            "card",
            "--json",
            "-c",
            "decode EF.SPN 01414253FFFF; files IMSI",
        ])
        .env("SIM_DOCTOR_TEST_REPLAY", &dir)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["data"]["decoded"]["name"], "ABS");
    assert!(r[1]["data"]["count"].as_u64().unwrap() >= 2);
}

fn card_chv(fixture: &str, secrets: &str, args: &[&str]) -> Output {
    let log = format!("{}/tests/corpus/{fixture}", env!("CARGO_MANIFEST_DIR"));
    Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .arg("card")
        .args(args)
        .env("SIM_DOCTOR_TEST_REPLAY", log)
        .env("SIMDOC_TEST_CHV", secrets)
        .output()
        .expect("the binary runs")
}

#[test]
fn verify_chv_takes_its_value_from_the_environment_and_never_prints_it() {
    let secrets = "pin1=1234; pin2=0000; puk1=12345678; new-pin1=4321";
    let out = card_chv(
        "cardsh_chv.jsonl",
        secrets,
        &[
            "--json",
            "--yes",
            "--chv-env",
            "SIMDOC_TEST_CHV",
            "-c",
            "verify_chv; verify_chv --pin-nr 2; verify_chv --pin-nr 2",
        ],
    );
    // PIN1 verifies; PIN2 is wrong twice (2, then 1 try left): two failures.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["data"]["verified"], true);
    assert!(r[1]["error"].as_str().unwrap().contains("2 tries left"));
    assert!(r[2]["error"].as_str().unwrap().contains("1 tries left"));
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for secret in ["1234", "0000", "31323334", "30303030"] {
        assert!(!all.contains(secret), "{secret} leaked:\n{all}");
    }

    // Without --yes: a dry run, and the replay log is never touched (an empty one is enough).
    let empty = std::env::temp_dir().join("cardsh-chv-empty.jsonl");
    std::fs::write(&empty, "").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args([
            "card",
            "--json",
            "--chv-env",
            "SIMDOC_TEST_CHV",
            "-c",
            "verify_chv",
        ])
        .env("SIM_DOCTOR_TEST_REPLAY", &empty)
        .env("SIMDOC_TEST_CHV", secrets)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(lines(&out)[0]["data"]["sent"], false);
}

#[test]
fn a_bad_pin_source_is_exit_two_before_any_reader_is_opened() {
    for args in [
        vec!["--chv-file", "/nonexistent/chv.txt"],
        vec!["--chv-env", "SIMDOC_NO_SUCH_VAR"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
            .arg("card")
            .args(&args)
            .args(["-c", "status"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
    let out = card_chv(
        "cardsh_chv.jsonl",
        "pin1=12",
        &["--chv-env", "SIMDOC_TEST_CHV", "-c", "status"],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("pin1=12"),
        "the value is not quoted"
    );
}

#[test]
fn unblock_chv_sends_the_puk_once_and_masks_it() {
    let secrets = "pin1=1234; pin2=0000; puk1=12345678; new-pin1=4321";
    let out = card_chv(
        "cardsh_unblock.jsonl",
        secrets,
        &[
            "--json",
            "--yes",
            "--chv-env",
            "SIMDOC_TEST_CHV",
            "-c",
            "unblock_chv; verify_chv",
        ],
    );
    // The PUK works and sets PIN1 to 4321, so verifying with the old 1234 fails: exit 1, one failure.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = lines(&out);
    assert_eq!(r[0]["data"]["unblocked"], true);
    assert_eq!(r[1]["ok"], false);
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for secret in ["12345678", "4321", "3132333435363738", "34333231"] {
        assert!(!all.contains(secret), "{secret} leaked:\n{all}");
    }
}
