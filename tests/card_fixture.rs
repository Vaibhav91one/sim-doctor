//! The card-backed half of issue #4: prove this crate can actually drive a
//! card through the real PC/SC stack, not just that a reader is listed.
//!
//! Everything here is behind two gates, both deliberate:
//!
//! 1. The card-fixture cargo feature. With it off the whole file compiles to
//!    nothing, so cargo test on a laptop with no reader, no pcscd and no
//!    card stays green. That is the AGENTS.md section 2 requirement.
//! 2. #[ignore]. Even cargo test --all-features skips the test rather than
//!    failing it, so enabling the feature by accident is harmless.
//!
//! To actually run it, start the fixture (see docs/swsim-fixture.md) and then:
//!
//!     cargo test --features card-fixture --test card_fixture -- --ignored --nocapture
//!
//! There is deliberately no "skip if no reader" branch. A fixture test that
//! quietly passes with no card is exactly the failure mode this issue exists to
//! rule out, so "no reader" here is a failure carrying the reader list in the
//! message.

#![cfg(feature = "card-fixture")]

use sim_doctor::apdu::StatusWord;
use sim_doctor::transport::{pcsc::Pcsc, pcsc::PcscSession, CardSession, ReaderProvider};

/// SELECT MF (3F00) with P2 = 0x0C, meaning "select it, return no FCP".
///
/// ISO/IEC 7816-4 clause 7.5.1: bit b4 of P2 set means no response data.
/// swSIM implements both forms. P2 = 0x04 selects the file and queues the
/// capabilities template behind a 61 xx; P2 = 0x0C answers immediately with
/// no body.
const SELECT_MF: [u8; 7] = [0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00];

/// SELECT MF (3F00) with P2 = 0x04, meaning "select it and return the FCP".
const SELECT_MF_WITH_FCP: [u8; 7] = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];

/// FETCH, the ETSI/3GPP class. P1 and P2 must both be 00 and Le must be the
/// exact length of the pending proactive command, so the length byte is
/// filled in at run time.
const FETCH_PREFIX: [u8; 4] = [0x80, 0x12, 0x00, 0x00];

/// GET RESPONSE for the queued FCP, requesting the advertised length.
///
/// CLA 0xA0 is the proprietary GSM class swSIM dispatches GET RESPONSE from:
/// src/apduh.c routes INS 0xC0 at CLA 0xA0 to the same response queue the
/// 3GPP SELECT filled. CLA 00 INS 0xC0 is not routed at all.
const GET_RESPONSE_PREFIX: [u8; 4] = [0xA0, 0xC0, 0x00, 0x00];

/// SELECT the DF GSM (7F20) from the MF, no FCP. Proves selection walks the
/// file system rather than just answering the first thing it is asked.
const SELECT_DF_GSM: [u8; 7] = [0x00, 0xA4, 0x00, 0x0C, 0x02, 0x7F, 0x20];

/// SELECT EF.DIR (2F00) under the MF, no FCP.
const SELECT_EF_DIR: [u8; 7] = [0x00, 0xA4, 0x00, 0x0C, 0x02, 0x2F, 0x00];

/// READ BINARY, offset 0, 15 bytes. EF.DIR's first record in the swSIM USIM
/// profile is exactly that long.
const READ_EF_DIR: [u8; 5] = [0x00, 0xB0, 0x00, 0x00, 0x0F];

/// Renders bytes as spaced uppercase hex, the form every reader of this repo's
/// logs already expects.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Joins reader names for a log line, quoting each so an empty list is visible.
fn reader_list(names: &[sim_doctor::transport::ReaderName]) -> String {
    if names.is_empty() {
        return "(none)".to_owned();
    }
    names
        .iter()
        .map(|name| format!("{:?}", name.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Runs one command and returns the card's bytes verbatim.
///
/// Everything the transport returns is logged, not just what is asserted, so a
/// failing CI run says what the card actually said instead of only what was
/// expected.
fn exchange(session: &mut PcscSession, command: &[u8], what: &str) -> Vec<u8> {
    let response = session
        .transmit(command)
        .unwrap_or_else(|error| panic!("{what}: transport failed: {error}"));
    println!("{what}\n  -> {}\n  <- {}", hex(command), hex(&response));
    response
}

/// Whether the response is a bare status word, i.e. carries no response data.
#[track_caller]
fn assert_no_response_data(what: &str, response: &[u8]) {
    assert_eq!(
        response.len(),
        2,
        "{what} should carry no response data, got {}",
        hex(response)
    );
}

/// Asserts the response is a bare status word in the ISO/IEC 7816-4 normal
/// processing class.
///
/// This asserts the rule, not one literal pair. SW1 0x90 is success with
/// nothing to add. SW1 0x91 to 0x9F is the same class and means a proactive
/// command is available; 0x9F is the ISO spelling and 0x91, 0x92 and 0x93 are
/// the 3GPP variants, which carry the pending command's length in SW2.
///
/// swSIM leans on the 9x form hard. At the end of every command
/// src/apduh.c:sim_apduh_demux calls proactive_step() and then, if the
/// command's own status was 90 00 and a proactive command is pending,
/// REWRITES it to 91 followed by that length. So a perfectly successful SELECT
/// MF answers 91 80 on this profile. Hard-coding 90 00 here would make this a
/// test of the simulator's mood rather than of the exchange, which is the
/// failure mode this whole fixture exists to rule out.
#[track_caller]
fn assert_normal_processing(what: &str, response: &[u8]) {
    assert_no_response_data(what, response);
    assert!(
        (0x90..=0x9F).contains(&response[0]),
        "{what}: SW1 {:02X} is not normal processing: {}",
        response[0],
        hex(response)
    );
}

/// Asserts the response ends in a bare 90 00.
#[track_caller]
fn assert_success_only(what: &str, response: &[u8]) {
    assert_eq!(
        hex(response),
        "90 00",
        "{what} should be exactly 90 00 with no response data"
    );
    let status = StatusWord::from_bytes([response[0], response[1]]);
    assert!(
        status.is_success(),
        "{what}: the crate's own status word disagrees: {status}"
    );
}

/// Asserts a response is body_len bytes followed by a normal processing status.
#[track_caller]
fn assert_body_then_normal_processing(what: &str, response: &[u8], body_len: usize) {
    assert_eq!(
        response.len(),
        body_len + 2,
        "{what} should carry {body_len} bytes of data then a status word, got {}",
        hex(response)
    );
    assert_no_response_data(&format!("{what} status word"), &response[body_len..]);
    assert!(
        (0x90..=0x9F).contains(&response[body_len]),
        "{what}: SW1 {:02X} is not normal processing: {}",
        response[body_len],
        hex(response)
    );
}

/// SW1 of a bare status word response.
fn sw1(response: &[u8]) -> u8 {
    response[response.len() - 2]
}

/// SW2 of a bare status word response.
fn sw2(response: &[u8]) -> u8 {
    response[response.len() - 1]
}

/// True when SW1 says a proactive command is waiting and SW2 is its length.
fn proactive_pending(response: &[u8]) -> bool {
    (0x91..=0x9F).contains(&sw1(response)) && sw2(response) > 0
}

/// Fetches the pending proactive command so it stops rewriting status words.
///
/// swSIM src/apduh.c:apduh_etsi_cat_fetch requires Le to equal the pending
/// command's length exactly, and zeroes command_length once it has returned it.
fn drain_proactive_command(session: &mut PcscSession, length: u8, what: &str) {
    let mut command = FETCH_PREFIX.to_vec();
    command.push(length);
    let response = exchange(session, &command, what);
    assert_body_then_normal_processing(what, &response, usize::from(length));
    assert!(
        response[..usize::from(length)]
            .iter()
            .any(|byte| *byte != 0x00),
        "{what}: a proactive command of all zeros is not a command"
    );
}

/// SELECT MF until the card answers a plain 90 00, draining anything it pushes
/// at us on the way.
///
/// The drain is what makes the literal 90 00 assertion honest rather than
/// lucky. 90 00 is only reachable once nothing else is pending, and a card is
/// allowed to have something pending at any moment. Four attempts is generous:
/// swSIM has one proactive application and it stops after the first FETCH.
fn select_mf_and_settle(session: &mut PcscSession) {
    for attempt in 1..=4u8 {
        let response = exchange(session, &SELECT_MF, "SELECT MF (3F00), no FCP");
        assert_normal_processing("SELECT MF (3F00), no FCP", &response);
        if !proactive_pending(&response) {
            assert_success_only("SELECT MF (3F00), no FCP", &response);
            println!("SELECT MF settled on 90 00 after {attempt} attempt(s)");
            return;
        }
        println!(
            "SW1 {:02X} says a proactive command of {} bytes is pending; fetching it",
            sw1(&response),
            sw2(&response)
        );
        drain_proactive_command(
            session,
            sw2(&response),
            &format!("FETCH proactive command, attempt {attempt}"),
        );
    }
    panic!("SELECT MF never settled on 90 00 in four attempts");
}

/// The whole acceptance bar in one test: context, readers, connect, and real
/// APDU round trips against a live card.
#[test]
#[ignore = "needs the swSIM fixture; see docs/swsim-fixture.md"]
fn drives_a_real_card_through_the_pcsc_transport() {
    // 1. A PC/SC context exists and the fixture's reader is in it.
    let readers = Pcsc::readers().expect("could not enumerate PC/SC readers");
    println!("readers: {}", reader_list(&readers));
    let reader = readers
        .iter()
        .find(|name| name.as_str().to_ascii_lowercase().contains("swicc"))
        .unwrap_or_else(|| {
            panic!(
                "the swICC virtual reader is not present. Readers seen: {}. \
                 Is pcscd running with the swicc-pcsc driver installed?",
                reader_list(&readers)
            )
        });
    println!("using reader: {reader}");

    // 2. Connect to the card in it.
    let mut session = PcscSession::open(reader)
        .unwrap_or_else(|error| panic!("could not connect to {reader}: {error}"));
    let atr = session
        .atr()
        .unwrap_or_else(|error| panic!("could not read the ATR: {error}"));
    println!("ATR: {}", hex(&atr));
    assert!(!atr.is_empty(), "a card with no ATR is not a card");

    // 3. SELECT MF (3F00) and settle on a plain 90 00 with no response data.
    //    This is the headline assertion and the one the issue names.
    select_mf_and_settle(&mut session);

    // 4. SELECT MF again asking for the FCP, and read it back. This is the
    //    part that cannot be faked by a stub: the body has to be the file's
    //    own capabilities template, tagged with the file ID that was asked for.
    //    SW1 0x61 is asserted literally because swSIM only rewrites 90 00.
    let response = exchange(
        &mut session,
        &SELECT_MF_WITH_FCP,
        "SELECT MF (3F00) with FCP",
    );
    assert_eq!(response[0], 0x61, "SELECT MF with FCP: {}", hex(&response));
    let fcp_len = sw2(&response);
    assert!(fcp_len > 0, "an empty FCP would prove nothing");

    let mut get_response = GET_RESPONSE_PREFIX.to_vec();
    get_response.push(fcp_len);
    let response = exchange(&mut session, &get_response, "GET RESPONSE (FCP)");
    assert_body_then_normal_processing("GET RESPONSE (FCP)", &response, usize::from(fcp_len));
    let fcp = &response[..usize::from(fcp_len)];
    assert!(
        fcp.windows(2).any(|pair| pair == [0x3F, 0x00]),
        "the FCP should carry the selected file ID 3F00, got {}",
        hex(fcp)
    );

    // 5. Walk one level down, so the exchange is not just answering the first
    //    command it is given.
    let response = exchange(&mut session, &SELECT_DF_GSM, "SELECT DF GSM (7F20)");
    assert_normal_processing("SELECT DF GSM (7F20)", &response);

    // 6. Select a file and read its bytes. This is the assertion that cannot
    //    pass with a stub or an absent card: the payload has to be the
    //    profile's own application template.
    let response = exchange(&mut session, &SELECT_EF_DIR, "SELECT EF.DIR (2F00)");
    assert_normal_processing("SELECT EF.DIR (2F00)", &response);
    let response = exchange(&mut session, &READ_EF_DIR, "READ BINARY EF.DIR, 15 bytes");
    assert_body_then_normal_processing(
        "READ BINARY EF.DIR",
        &response,
        usize::from(READ_EF_DIR[4]),
    );
    let contents = &response[..usize::from(READ_EF_DIR[4])];
    assert_eq!(
        contents[0],
        0x61,
        "EF.DIR should open with the 61 application template, got {}",
        hex(contents)
    );

    // 7. Give the card back, then prove releasing twice is the no-op the trait
    //    promises.
    session
        .disconnect()
        .unwrap_or_else(|error| panic!("disconnect failed: {error}"));
    session
        .disconnect()
        .expect("a second disconnect is specified to be a no-op");
    println!("card released");
}
