//! The card-backed half of issue #4: prove this crate can actually drive a
//! card through the real PC/SC stack, not just that a reader is listed.
//!
//! Everything here is behind two gates, both deliberate:
//!
//! 1. The `card-fixture` cargo feature. With it off the whole file compiles to
//!    nothing, so `cargo test` on a laptop with no reader, no pcscd and no
//!    card stays green. That is the AGENTS.md section 2 requirement.
//! 2. `#[ignore]`. Even `cargo test --all-features` skips the test rather
//!    than failing it, so enabling the feature by accident is harmless.
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
/// ISO/IEC 7816-4 clause 7.5.1: bit b4 of P2 set means no response data. swSIM
/// implements exactly that: P2 = 0x00 selects the file but leaves the FCP in the
/// GET RESPONSE queue and answers 61 xx, while P2 = 0x0C answers 90 00. Both
/// are conformant, and the "no data" form is what gets a clean 90 00.
const SELECT_MF: [u8; 7] = [0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00];

/// SELECT MF (3F00) with P2 = 0x04, meaning "select it and return the FCP".
///
/// The card answers 61 xx here and queues the file capabilities template for a
/// GET RESPONSE. Chasing that is issue #5's job, not the transport's, so this
/// test issues the GET RESPONSE itself.
const SELECT_MF_WITH_FCP: [u8; 7] = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];

/// GET RESPONSE for the queued FCP, requesting the advertised length.
///
/// CLA 0xA0 is the proprietary GSM class swSIM dispatches GET RESPONSE from:
/// src/apduh.c routes INS 0xC0 at CLA 0xA0 to the same response queue the
/// 3GPP SELECT filled. The length byte is filled in from SW2 at run time.
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

/// Asserts a response is exactly two status bytes equal to 90 00.
///
/// The length is checked as well as the pair. A response that carried an FCP
/// and still ended 90 00 would pass a status-word-only check, and the point of
/// the P2 = 0x0C form is that it returns no data at all.
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
                "the swICC virtual reader is not present. Readers seen: {}.                  Is pcscd running with the swicc-pcsc driver installed?",
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

    // 3. SELECT MF (3F00), expect 90 00 and nothing else.
    let response = exchange(&mut session, &SELECT_MF, "SELECT MF (3F00), no FCP");
    assert_success_only("SELECT MF (3F00), no FCP", &response);

    // 4. SELECT MF again asking for the FCP, and read it back. This is the
    //    part that cannot be faked by a stub: the body has to be the file's
    //    own capabilities template, tagged with the file ID that was asked for.
    let response = exchange(
        &mut session,
        &SELECT_MF_WITH_FCP,
        "SELECT MF (3F00) with FCP",
    );
    assert_eq!(
        response.len(),
        2,
        "a FCP-bearing SELECT should answer 61 xx and nothing else, got {}",
        hex(&response)
    );
    assert_eq!(
        response[0],
        0x61,
        "SELECT MF with FCP should queue data for GET RESPONSE, got {}",
        hex(&response)
    );
    let fcp_len = response[1];
    assert!(fcp_len > 0, "an empty FCP would prove nothing");

    let mut get_response = GET_RESPONSE_PREFIX.to_vec();
    get_response.push(fcp_len);
    let response = exchange(&mut session, &get_response, "GET RESPONSE (FCP)");
    assert_eq!(
        response.len(),
        usize::from(fcp_len) + 2,
        "GET RESPONSE should return the {fcp_len} advertised bytes plus 90 00, got {}",
        hex(&response)
    );
    let fcp = &response[..response.len() - 2];
    assert_success_only(
        "GET RESPONSE (FCP) status word",
        &response[response.len() - 2..],
    );
    assert!(
        fcp.windows(2).any(|pair| pair == [0x3F, 0x00]),
        "the FCP should carry the selected file ID 3F00, got {}",
        hex(fcp)
    );

    // 5. Walk one level down, so the exchange is not just answering the first
    //    command it is given.
    let response = exchange(&mut session, &SELECT_DF_GSM, "SELECT DF GSM (7F20)");
    assert_success_only("SELECT DF GSM (7F20)", &response);

    // 6. Select a file and read its bytes. This is the assertion that cannot
    //    pass with a stub or an absent card: the payload has to be the
    //    profile's own application template.
    let response = exchange(&mut session, &SELECT_EF_DIR, "SELECT EF.DIR (2F00)");
    assert_success_only("SELECT EF.DIR (2F00)", &response);
    let response = exchange(&mut session, &READ_EF_DIR, "READ BINARY EF.DIR, 15 bytes");
    assert_eq!(
        response.len(),
        usize::from(READ_EF_DIR[4]) + 2,
        "READ BINARY should return the 15 requested bytes plus 90 00, got {}",
        hex(&response)
    );
    let contents = &response[..response.len() - 2];
    assert_success_only("READ BINARY status word", &response[response.len() - 2..]);
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
}
