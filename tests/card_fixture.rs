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

//! **These tests must run serially.** A card has one current directory and
//! one response queue. swSIM clears the queue on every command that is not
//! GET RESPONSE \\[V], swicc `src/apduh.c:swicc_apdu_rc_reset` at `421c8cdd`, so
//! two tests exchanging APDUs at the same time take each other's queued
//! capabilities templates. The card-fixture workflow passes
//! `--test-threads=1`, and this note is here so the next person who "speeds
//! the fixture up" learns why they cannot.

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

/// SELECT EF.IMSI (2FE2) under the MF, asking for the FCP so the test can
/// learn the file's real size instead of assuming one.
///
/// 2FE2 is the one child of the MF in the swSIM USIM profile that is both
/// transparent and has real content. EF.DIR (2F00) is record-structured, and
/// READ BINARY on a record-structured EF is not a command a card may accept,
/// which step 6e asserts rather than works around.
const SELECT_EF_IMSI_WITH_FCP: [u8; 7] = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2];

/// SELECT EF.DIR (2F00) under the MF, no FCP. 2F00 is a child of the MF and a
/// RECORD-structured EF, which is what makes the READ BINARY in step 6e a
/// real protocol assertion rather than a happy path.
const SELECT_EF_DIR: [u8; 7] = [0x00, 0xA4, 0x00, 0x0C, 0x02, 0x2F, 0x00];

/// READ BINARY, offset 0, with Le filled in at run time.
const READ_BINARY_PREFIX: [u8; 4] = [0x00, 0xB0, 0x00, 0x00];

/// The tag table this card answers SELECT with.
///
/// **These are swICC's numbers, not ISO/IEC 7816-4's**, and the test now says
/// so by *passing* them rather than by hard-coding a tag at each use site.
/// swICC documents its own mapping in its FCP builder, src/3gpp.c:
///
///     0x80, /* '62': File size,        'A5': UICC characteristics. */
///     0x81, /* '62': Total file size,  'A5': App power consumption. */
///     0x82, /* '62': File descriptor,  'A5': Min app clock frequency. */
///     0x83, /* '62': File ID,          ... */
///
/// ISO/IEC 7816-4 table 42 uses 0x82 for the file size and 0x83 for the file
/// descriptor, so the two disagree. Reading an swSIM FCP as if it were the ISO
/// table yields a nonsense file size, which is exactly what happened the first
/// time this test ran. [V] for swSIM, read at the pinned commit. A real card
/// may follow the ISO table instead, which is why the mapping is a value this
/// test supplies and not a default anywhere in the library: see
/// `sim_doctor::fcp::TagSet`.
///
/// Issue #11 replaced the four-byte window scan this test used to do with a
/// real walk over the template. The window scan searched for the byte pattern
/// `tag 02 xx xx` anywhere in the response, including straddling an atom
/// boundary, so a value that happened to contain those four octets could
/// satisfy the assertion; walking the template cannot produce a match that is
/// not an atom.
fn swicc_tags() -> sim_doctor::fcp::TagSet {
    sim_doctor::fcp::TagSet::swicc()
}

/// Parses a file capabilities template under the dialect the test was told
/// the card uses.
///
/// The dialect is passed in rather than built here because
/// `fcp::Template<'a>` borrows it: the mapping is owned by whoever is reading
/// the card, which is the whole point of it being caller-supplied.
fn parse_fcp<'a>(
    body: &'a [u8],
    dialect: &'a sim_doctor::fcp::TagSet,
) -> sim_doctor::fcp::Template<'a> {
    sim_doctor::fcp::Template::parse(body, dialect).unwrap_or_else(|error| {
        panic!(
            "the FCP is not a usable template: {error}, was {}",
            hex(body)
        )
    })
}

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
    // Which tag table this card answers SELECT with. Stated once, here,
    // because it is a property of the card rather than of the format.
    let dialect = swicc_tags();

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
    let template = parse_fcp(fcp, &dialect);
    assert_eq!(
        template
            .file_id()
            .unwrap_or_else(|error| panic!("file ID unreadable: {error}, FCP was {}", hex(fcp))),
        Some([0x3F, 0x00]),
        "the FCP file ID should be 3F00, FCP was {}",
        hex(fcp)
    );

    // 5. Walk one level down, so the exchange is not just answering the first
    //    command it is given, then come back up. 2F00 and 2FE2 are children of
    //    the MF, not of DF GSM.
    let response = exchange(&mut session, &SELECT_DF_GSM, "SELECT DF GSM (7F20)");
    assert_normal_processing("SELECT DF GSM (7F20)", &response);
    let response = exchange(&mut session, &SELECT_MF, "SELECT MF (3F00) again");
    assert_normal_processing("SELECT MF (3F00) again", &response);

    // 6. Read a real file. The length is taken from the FCP rather than
    //    assumed, because the point of the FCP is that the card tells you the
    //    size.
    let response = exchange(
        &mut session,
        &SELECT_EF_IMSI_WITH_FCP,
        "SELECT EF.IMSI (2FE2) with FCP",
    );
    assert_eq!(
        response[0],
        0x61,
        "SELECT EF.IMSI with FCP: {}",
        hex(&response)
    );
    let fcp_len = sw2(&response);
    let mut get_response = GET_RESPONSE_PREFIX.to_vec();
    get_response.push(fcp_len);
    let response = exchange(&mut session, &get_response, "GET RESPONSE (FCP of EF.IMSI)");
    assert_body_then_normal_processing(
        "GET RESPONSE (FCP of EF.IMSI)",
        &response,
        usize::from(fcp_len),
    );
    let fcp = &response[..usize::from(fcp_len)];
    let template = parse_fcp(fcp, &dialect);
    assert_eq!(
        template
            .file_id()
            .unwrap_or_else(|error| panic!("file ID unreadable: {error}, FCP was {}", hex(fcp))),
        Some([0x2F, 0xE2]),
        "the FCP file ID should be 2FE2, FCP was {}",
        hex(fcp)
    );
    let size = template
        .file_size()
        .unwrap_or_else(|error| panic!("file size unreadable: {error}, FCP was {}", hex(fcp)))
        .unwrap_or_else(|| panic!("the FCP has no file size tag: {}", hex(fcp)))
        .octets();
    // The read length comes from the card, not from a guess, and a short APDU
    // data field cannot carry more than 255 bytes, so cap rather than fail if
    // a future profile has a larger EF.
    let read_len = usize::from(u8::try_from(size).unwrap_or(u8::MAX));
    assert!(read_len > 0, "EF.IMSI reports a size of zero");
    println!("EF.IMSI reports a size of {size} bytes, reading {read_len}");

    let mut read = READ_BINARY_PREFIX.to_vec();
    read.push(read_len as u8);
    let response = exchange(
        &mut session,
        &read,
        &format!("READ BINARY EF.IMSI, {read_len} bytes"),
    );
    assert_body_then_normal_processing("READ BINARY EF.IMSI", &response, read_len);
    let contents = &response[..read_len];
    // A fill pattern would mean the card sent padding rather than content.
    assert!(
        contents.iter().any(|byte| *byte != 0x00 && *byte != 0xFF),
        "EF.IMSI came back as a fill pattern, which is not content: {}",
        hex(contents)
    );

    // 6e. READ BINARY must NOT succeed on a record-structured EF. EF.DIR is
    //     linear-fixed in the profile, and swICC refuses it:
    //     lib/swicc/src/apduh.c:apduh_bin_read falls through to
    //     SWICC_APDU_SW1_CHER_CMD with SW2 0x81, "Command incompatible with
    //     file structure". Asserting the CLASS keeps the rule in the test and
    //     the simulator's particular choice of code out of it.
    let response = exchange(&mut session, &SELECT_EF_DIR, "SELECT EF.DIR (2F00)");
    assert_normal_processing("SELECT EF.DIR (2F00)", &response);
    let mut read_dir = READ_BINARY_PREFIX.to_vec();
    read_dir.push(0x0F);
    let response = exchange(&mut session, &read_dir, "READ BINARY EF.DIR, 15 bytes");
    assert_no_response_data("READ BINARY on EF.DIR", &response);
    assert!(
        (0x60..=0x6F).contains(&response[0]),
        "READ BINARY on a record-structured EF should be refused with a 6X status, got {}",
        hex(&response)
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

/// The tag table the swSIM fixture answers SELECT with, and the one
/// [`sim_doctor::walk::walk`] reads every template under.
///
/// Named by the software that was observed writing it rather than by a
/// specification, because a real UICC may use the ISO table instead and the
/// walker's whole job is to make that choice visible rather than hard-coded.
/// See [`sim_doctor::fcp::TagSet`] and docs/swsim-fixture.md.
fn swicc_dialect() -> sim_doctor::fcp::TagSet {
    sim_doctor::fcp::TagSet::swicc()
}

/// Issues issue #7's whole scope against a live card: select the master file,
/// probe every identifier of every SIM family underneath it, descend into the
/// dedicated files, and hand back the tree.
///
/// **What this test is for.** The unit tests in [`sim_doctor::walk`] prove the
/// walker's rules against a software card this repository controls. They cannot
/// prove three things, and only a card can:
///
///   1. that the SELECT forms the walker puts on the wire are forms swSIM
///      routes - the unit tests assert the bytes, this asserts the answers,
///   2. that a real tree of real capabilities templates decodes,
///   3. that the walk terminates on a card nobody designed it against.
///
/// **What it deliberately does not assert.** That a forbidden file is found.
/// swICC's selection path never evaluates an access condition
/// \\[V], `src/fs/va.c:va_select_file`, and its status table has no code for
/// "access denied", so no fixture run can produce that answer. The
/// absent/forbidden distinction is therefore proved by the unit tests and is
/// reported here only as "nothing on this card was reported forbidden", which
/// is itself the assertion a scan has to make.
#[test]
#[ignore = "needs the swSIM fixture; see docs/swsim-fixture.md"]
fn walks_the_file_system_of_a_real_card() {
    let readers = Pcsc::readers().expect("could not enumerate PC/SC readers");
    let reader = readers
        .iter()
        .find(|name| name.as_str().to_ascii_lowercase().contains("swicc"))
        .unwrap_or_else(|| {
            panic!(
                "the swICC virtual reader is not present. Readers seen: {}",
                reader_list(&readers)
            )
        });

    let session = PcscSession::open(reader)
        .unwrap_or_else(|error| panic!("could not connect to {reader}: {error}"));

    // Every exchange is logged, so a failing run says what the card actually
    // answered rather than only what was expected. The walk itself logs
    // nothing, so the wire trace is the only way to see what it asked for.
    let mut traced = Traced {
        inner: session,
        exchanges: 0,
    };

    let dialect = swicc_dialect();
    let options = sim_doctor::walk::Options {
        candidates: sim_doctor::walk::Candidates::SimFamilies,
        ..sim_doctor::walk::Options::default()
    };
    // The count is generated here, not typed in and not read from a capacity
    // hint. This line is output a machine reads: reporting a candidate count
    // the walk did not use would be the same class of defect as reading a
    // status word with the wrong meaning.
    let (candidates, truncated) = options.candidates.clone().identifiers(usize::MAX);
    println!(
        "walking the card with {} candidate identifiers per directory (bound {}{}), under the {:?} tag table",
        candidates.len(),
        options.limits.max_children,
        if truncated { ", truncated" } else { "" },
        dialect.name()
    );

    let tree = sim_doctor::walk::walk(&mut traced, &dialect, &options)
        .unwrap_or_else(|error| panic!("the walk failed: {error}"));
    println!(
        "the walk issued {} exchanges and returned {} nodes",
        traced.exchanges,
        tree.len()
    );
    for node in tree.nodes() {
        if node.state().is_selected() {
            println!("  SELECTED  {}", node.path());
        }
    }

    // 1. It terminates. On this card it terminates by hitting a bound, and
    //    that is not a defect in the walk - it is the defect in the card.
    //
    //    swSIM's "select by path from the MF" walks the path one segment at a
    //    time with `swicc_disk_file_foreach`, and that iterator runs its
    //    callback on the starting file itself before its children
    //    \\[[V], swicc \`src/fs/disk.c\`, the function's own comment says
    //    "including the file itself". So asking for 3F00/7F20/7F20 searches
    //    the children of 7F20 for 7F20, matches 7F20 itself on the very first
    //    callback, and succeeds. Every further identical segment does the
    //    same, so the card describes an unbounded tree of DF.GSM.
    //
    //    This is the exact case `walk::Note::RepeatedAncestor` and
    //    `Limits::max_depth` exist for, and it is why the walk does not treat
    //    a repeated identifier as a cycle: a file identifier repeats legally
    //    across directories, so refusing to descend would hide files, and the
    //    only sound stopper is a bound.
    let report = tree.report();
    println!(
        "report: {} selected, {} absent, {} forbidden, {} refused, {} directories, {} repeated identifiers, truncated by {:?}",
        report.selected,
        report.absent,
        report.forbidden,
        report.refused,
        report.directories,
        report.repeated_ancestors,
        report.truncated_by
    );
    assert!(
        report.repeated_ancestors > 0,
        "a card that answers SELECT for 3F00/7F20/7F20 must be reported as \
         repeating an ancestor rather than silently absorbed"
    );
    // A bound that stopped the walk is always recorded on a node, so a caller
    // reporting this tree cannot mistake "stopped here" for "that is all".
    for limit in tree.limits_hit() {
        let limit = *limit;
        assert!(
            tree.nodes().iter().any(|node| node
                .notes()
                .contains(&sim_doctor::walk::Note::Limit { limit })),
            "the walk stopped at {limit} and said so on the node it stopped at"
        );
    }
    println!(
        "bounds the walk hit: {:?}; first of them {:?}",
        tree.limits_hit(),
        report.truncated_by
    );
    // 1b. The bound is not hiding anything real. The USIM profile in
    //     data/usim.json is two levels deep under the master file, and every
    //     selected file the walk reports past depth 2 is one of the 7F20
    //     repeats the card's path resolver answers for itself. If a real file
    //     ever turns up below the bound, this fails and says which.
    let real_depth = tree
        .nodes()
        .iter()
        .filter(|node| node.state().is_selected())
        .filter(|node| {
            !node
                .notes()
                .iter()
                .any(|note| matches!(note, sim_doctor::walk::Note::RepeatedAncestor { .. }))
        })
        .map(|node| node.path().depth())
        .max()
        .unwrap_or(0);
    println!("the deepest file the card actually holds is {real_depth} levels below 3F00");
    assert_eq!(
        real_depth, 2,
        "a real USIM profile is two levels below the master file; anything \
         deeper that is not a repeated-ancestor artifact means the depth bound \
         is hiding a real file"
    );
    assert!(
        real_depth < options.limits.max_depth,
        "the default depth bound must leave room for a real card"
    );

    // And the bounds themselves held.
    assert!(
        report.nodes <= options.limits.max_nodes,
        "{} nodes is past the bound of {}",
        report.nodes,
        options.limits.max_nodes
    );
    assert!(
        report.directories <= options.limits.max_directories,
        "{} directories is past the bound of {}",
        report.directories,
        options.limits.max_directories
    );

    // 2. It found the master file, and it knows it is the master file.
    let root = tree
        .node(tree.root())
        .expect("a walk always returns its root");
    assert_eq!(root.path().to_string(), "3F00");
    assert_eq!(root.path().depth(), 1);
    assert!(
        root.state().is_selected(),
        "SELECT MF: {:?} / {:?}",
        root.state(),
        root.notes()
    );
    assert_eq!(
        root.state().kind(),
        Some(sim_doctor::walk::Kind::MasterFile),
        "3F00 is the master file by address"
    );

    // 3. It reached the dedicated files this profile is known to hold, by the
    //    full path a scan would report. Every path the walk produces is
    //    absolute, which is the property "correct paths" is really about.
    let directory: sim_doctor::fs::Path = "3F00/7F20".parse().expect("a valid path");
    let node = tree.at(&directory).unwrap_or_else(|| {
        panic!(
            "3F00/7F20 was not reached. The walk found:\n{}",
            tree_dump(&tree)
        )
    });
    assert!(
        node.state().is_selected(),
        "3F00/7F20: {:?} / {:?}",
        node.state(),
        node.notes()
    );
    assert_eq!(
        node.state().kind(),
        Some(sim_doctor::walk::Kind::Reported(
            sim_doctor::fs::FileKind::DedicatedFile
        )),
        "7F20 is a dedicated file and the card's descriptor said so"
    );
    assert!(node.state().kind().expect("selected").is_container());

    // Every child of the master file this profile is known to hold. EF.DIR
    // (2F00), EF.PL (2F05) and EF.ICCID (2FE2) are all direct children of
    // 3F00 in data/usim.json, and 7F20 is the only directory among them.
    for expected in ["3F00/2F00", "3F00/2F05", "3F00/2FE2"] {
        let path: sim_doctor::fs::Path = expected.parse().expect("a valid path");
        let node = tree.at(&path).unwrap_or_else(|| {
            panic!(
                "{expected} was not reached. The walk found:\n{}",
                tree_dump(&tree)
            )
        });
        assert!(
            node.state().is_selected(),
            "{expected}: {:?} / {:?}",
            node.state(),
            node.notes()
        );
    }

    // 4. It distinguished an elementary file from a directory by the card's own
    //    descriptor, not by guessing from where it was found.
    let imsi: sim_doctor::fs::Path = "3F00/2FE2".parse().expect("a valid path");
    let node = tree.at(&imsi).unwrap_or_else(|| {
        panic!(
            "3F00/2FE2 was not reached. The walk found:\n{}",
            tree_dump(&tree)
        )
    });
    assert!(node.state().is_selected(), "3F00/2FE2: {:?}", node.state());
    let kind = node.state().kind().expect("a selected file has a kind");
    assert_eq!(
        kind,
        sim_doctor::walk::Kind::Reported(sim_doctor::fs::FileKind::ElementaryFile),
        "2FE2 is transparent, so the descriptor's category bits say elementary"
    );
    assert!(!kind.is_container(), "an elementary file holds nothing");

    // 5. It read real metadata through the caller's tag table, which is the
    //    thing the swICC table exists for. EF.ICCID in data/usim.json is ten
    //    octets, and reading this under the ISO table instead would report
    //    2337.
    let capabilities = node.state().capabilities().expect("selected");
    let size = capabilities
        .size
        .reported()
        .unwrap_or_else(|| {
            panic!(
                "EF.ICCID reported no size under the {} table: {:?}",
                dialect.name(),
                capabilities
            )
        })
        .octets();
    assert_eq!(
        size, 10,
        "EF.ICCID is ten octets in the swSIM USIM profile, and the file size \
         lives in tag 80 on this card"
    );
    let descriptor = capabilities
        .descriptor
        .reported()
        .unwrap_or_else(|| panic!("EF.ICCID reported no file descriptor: {:?}", capabilities));
    assert_eq!(
        descriptor.structure,
        sim_doctor::fcp::Structure::Transparent
    );
    assert!(
        capabilities.unknown_tags.is_empty(),
        "the swICC table explains every tag this card sends for an elementary \
         file, so a tag here would mean the mapping has drifted: {:?}",
        capabilities.unknown_tags
    );

    // 6. The absent and forbidden answers came back apart, and neither was
    //    invented. Every identifier the profile does not hold must read as
    //    absent, and the count of them must be exactly the number of
    //    identifiers that were not found.
    assert_eq!(
        report.forbidden, 0,
        "swICC evaluates no access condition on SELECT, so nothing on this card \
         can be forbidden. A non-zero count here would mean the walk invented a \
         finding."
    );
    // A tag the mapping cannot read is named rather than dropped. swSIM sends
    // a C6 PIN status template for every folder `[V]`, swSIM `src/3gpp.c`
    // `o3gpp_select_res` at the pinned commit, and `TagSet::swicc()` has no tag
    // for it, so a dedicated file's capabilities must carry it in the
    // forward-compatibility list rather than losing it.
    let folder = tree.at(&directory).expect("3F00/7F20 is in the tree");
    let folder_unknown = &folder
        .state()
        .capabilities()
        .expect("a selected folder has capabilities")
        .unknown_tags;
    assert!(
        folder_unknown.iter().any(|tag| tag.octet() == 0xC6),
        "the PIN status template the card sent is named, not dropped: {:?}",
        folder_unknown
    );

    // Every identifier probed under the master file produced exactly one
    // answer, and every answer is one of the four states. Nothing was skipped
    // and nothing was invented.
    let probed: Vec<&sim_doctor::walk::Node> = tree
        .nodes()
        .iter()
        .filter(|node| node.path().depth() == 2)
        .collect();
    // The master file was probed exactly once per candidate the walker was
    // given, in order, until a bound said it could not go on. Asserted as a
    // prefix of the candidate set rather than as a count, so narrowing or
    // widening Candidates does not break a test that is about the walker and
    // not about a number: a walker that skipped an identifier or probed one
    // twice fails this, and a walker that simply stopped early does not.
    let (candidates, _) = options.candidates.clone().identifiers(usize::MAX);
    let observed: Vec<sim_doctor::fs::FileId> =
        probed.iter().map(|node| node.path().leaf()).collect();
    assert_eq!(
        observed,
        candidates[..observed.len()],
        "the master file was probed once per candidate, in order, and stopped \
         where a bound stopped it"
    );
    assert!(
        observed.len() * 2 > candidates.len(),
        "only {} of {} candidates were probed: a bound cut the walk short before \
         it had enumerated anything useful",
        observed.len(),
        candidates.len()
    );
    assert_eq!(
        probed.len(),
        observed.len(),
        "one node per probe, and no other node at this depth"
    );
    let counted = probed
        .iter()
        .filter(|node| node.state().is_selected())
        .count()
        + probed
            .iter()
            .filter(|node| matches!(node.state(), sim_doctor::walk::NodeState::Absent))
            .count()
        + probed
            .iter()
            .filter(|node| matches!(node.state(), sim_doctor::walk::NodeState::Forbidden { .. }))
            .count()
        + probed
            .iter()
            .filter(|node| matches!(node.state(), sim_doctor::walk::NodeState::Refused { .. }))
            .count();
    assert_eq!(
        counted,
        probed.len(),
        "every identifier probed under the master file produced exactly one \
         answer, and no answer was dropped"
    );
    assert!(
        report.absent > 0,
        "probing the SIM identifier space must find most of it missing"
    );

    // 7. Nothing under a file the card did not describe, and nothing past a
    //    bound: both would mean the tree is not what it claims to be.
    //
    //    The depth rule is that `max_depth` is the deepest path the walk
    //    descends INTO, so a node at the bound has been descended and a node
    //    one past it is the last one recorded. Every one of those carries the
    //    bound on itself, so nothing is silently cut.
    let past_the_bound = options.limits.max_depth + 1;
    for node in tree.nodes() {
        if let sim_doctor::walk::NodeState::Selected {
            kind: sim_doctor::walk::Kind::Unreported,
            ..
        } = node.state()
        {
            assert!(
                node.children().is_empty(),
                "{} was not described and was not descended",
                node.path()
            );
        }
        assert!(
            node.path().depth() <= past_the_bound,
            "{} is past the depth bound",
            node.path()
        );
        if node.path().depth() == past_the_bound {
            assert!(
                node.children().is_empty(),
                "{} is one past the depth bound and must not have been descended",
                node.path()
            );
            assert!(
                node.notes().contains(&sim_doctor::walk::Note::Limit {
                    limit: sim_doctor::walk::Limit::Depth,
                }),
                "{} is one past the depth bound and must say so",
                node.path()
            );
        }
    }

    traced.inner.disconnect().expect("disconnect failed");
    println!("card released after {} exchanges", traced.exchanges);
}

/// A transport that logs every exchange, because a walk logs nothing itself.
///
/// A thin wrapper rather than a change to [`PcscSession`] so that what a
/// failing fixture run prints is the wire transcript and nothing else.
struct Traced {
    inner: PcscSession,
    exchanges: usize,
}

impl std::fmt::Debug for Traced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Traced")
            .field("reader", &self.inner.reader())
            .field("exchanges", &self.exchanges)
            .finish()
    }
}

impl CardSession for Traced {
    fn reader(&self) -> &sim_doctor::transport::ReaderName {
        self.inner.reader()
    }

    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, sim_doctor::transport::Error> {
        self.exchanges += 1;
        let response = self.inner.transmit(command)?;
        println!("  -> {}\n  <- {}", hex(command), hex(&response));
        Ok(response)
    }

    fn disconnect(&mut self) -> Result<(), sim_doctor::transport::Error> {
        self.inner.disconnect()
    }
}

/// A verdict over the findings a scan produces today: none, from no rule.
///
/// The card fixture is about the WALK and the binary, so it renders with the
/// verdict a bare `sim-doctor scan --json` produces. The verdict itself is
/// covered by `src/scan.rs` and, end to end through the built binary, by
/// `the_score_and_severity_flags_reach_the_envelope_against_a_real_card`
/// below - which is the only place a real card can show that --score puts a
/// score block on stdout, because that needs a card in the first place.
fn verdict() -> sim_doctor::scan::Verdict {
    sim_doctor::scan::Verdict::new(
        sim_doctor::rules::Findings::complete(Vec::new()),
        sim_doctor::scan::rules_run(),
    )
}

/// Every path the walk returned, selected ones only, for a failure message.
fn tree_dump(tree: &sim_doctor::walk::Tree) -> String {
    tree.nodes()
        .iter()
        .filter(|node| node.state().is_selected())
        .map(|node| format!("  {} {:?}", node.path(), node.state()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Issue #6's acceptance criterion, run against a live card: `sim-doctor scan`
/// opens a real PC/SC session, selects the master file, walks the tree, and
/// emits its report - in one process, through the same code path an operator
/// gets.
///
/// **What only a card can prove, and why the library half is still here.**
/// [`walks_the_file_system_of_a_real_card`] already proved that the walker
/// works on real hardware. What this adds is everything *around* it, and none
/// of it can be proved without a card:
///
///   1. reader discovery and `PcscSession::open` feeding a walk, which is the
///      composition that did not exist anywhere before this issue,
///   2. the report that walk produces surviving `serde_json` on a real card's
///      real capabilities templates, rather than on a hand-written fixture,
///   3. **the built binary** running the whole thing and exiting 0 with one
///      envelope on stdout. The unit tests prove the renderers; only this
///      proves the command.
///
/// **What it deliberately does not prove.** That a forbidden file is found.
/// swICC evaluates no access condition on SELECT \[V], swicc
/// `src/fs/va.c:va_select_file`, so no fixture run can produce that status.
/// The absent/forbidden separation is asserted here as "nothing on this card
/// was reported forbidden, and every refusal landed in exactly one of the
/// three arrays", which is the part a card can say anything about at all.
#[test]
#[ignore = "needs the swSIM fixture; see docs/swsim-fixture.md"]
fn scans_a_real_card_end_to_end() {
    let readers = Pcsc::readers().expect("could not enumerate PC/SC readers");
    let reader = readers
        .iter()
        .find(|name| name.as_str().to_ascii_lowercase().contains("swicc"))
        .unwrap_or_else(|| {
            panic!(
                "the swICC virtual reader is not present. Readers seen: {}",
                reader_list(&readers)
            )
        });
    println!("scan: using reader {reader}");

    let dialect = swicc_dialect();
    let options = sim_doctor::walk::Options::default();
    let mut session = PcscSession::open(reader)
        .unwrap_or_else(|error| panic!("could not connect to {reader}: {error}"));
    let atr = session.atr().expect("could not read the ATR");

    let tree = sim_doctor::walk::walk(&mut session, &dialect, &options)
        .unwrap_or_else(|error| panic!("the walk failed: {error}"));
    println!(
        "scan: walked {} nodes, {} selected, {} absent, {} forbidden, bounds hit {:?}",
        tree.report().nodes,
        tree.report().selected,
        tree.report().absent,
        tree.report().forbidden,
        tree.limits_hit()
    );

    let context = sim_doctor::scan::Context::new(
        reader.as_str(),
        Some(&atr),
        sim_doctor::scan::Dialect::Swicc,
        options.candidates.clone(),
        options.limits,
    );

    // 1. The dialect the scan ran under is named, in both renderings. This is
    //    the assertion that would fail if someone picked a TagSet silently: the
    //    name in the output has to be the name of the table that was handed to
    //    the walk, not a constant.
    let data = sim_doctor::scan::to_json(&tree, &context, &verdict());
    println!(
        "scan: report names the dialect {:?} / {:?}",
        data["dialect"]["id"], data["dialect"]["name"]
    );
    assert_eq!(data["dialect"]["id"], serde_json::json!("swicc"));
    assert_eq!(
        data["dialect"]["name"],
        serde_json::json!(dialect.name()),
        "the JSON must name the very table the walk ran under"
    );
    assert_eq!(
        data["dialect"]["tags"]["file_size"],
        serde_json::json!(dialect.file_size().map(|tag| tag.to_string()).unwrap()),
        "swICC reads the file size out of 80, not out of the ISO table's 82"
    );
    assert_eq!(data["reader"], serde_json::json!(reader.as_str()));
    assert_eq!(
        data["addressing"],
        serde_json::json!("path-from-master-file")
    );

    // 2. Truncation reaches the output. On this card the walk stops because the
    //    card's own path resolver answers for a repeated 7F20 at every depth -
    //    see the note in walks_the_file_system_of_a_real_card - so a truncated
    //    report is the *expected* shape here and asserting it is meaningful
    //    rather than convenient.
    assert!(
        !tree.is_complete(),
        "this card describes an unbounded tree, so the walk is expected to \
         truncate; if it did not, the bounds changed and this test must be \
         reconsidered"
    );
    assert_eq!(data["complete"], serde_json::Value::Bool(false));
    assert_eq!(data["truncated"], serde_json::Value::Bool(true));
    assert!(
        data["truncated_by"].is_string(),
        "the first bound that fired has to be named: {data:#}"
    );
    assert!(
        !data["limits_hit"]
            .as_array()
            .expect("limits_hit is an array")
            .is_empty(),
        "the full list of bounds has to be carried, not only the first: {data:#}"
    );
    println!(
        "scan: reported truncated_by {:?} with limits_hit {:?}",
        data["truncated_by"], data["limits_hit"]
    );

    let human = sim_doctor::scan::to_human(&tree, &context, &verdict());
    assert!(
        human.starts_with("!! TRUNCATED"),
        "the human report opens with the cut: {}",
        human.lines().next().unwrap_or_default()
    );
    assert!(
        human.contains("Every bound hit:"),
        "the human report names every bound, not only the first"
    );

    // 3. The candidate set's coverage is stated. Nothing on this card falls
    //    outside the five GSM families, so the walk lost no coverage here - and
    //    the output still has to say so, because a reader cannot know that from
    //    a file count.
    assert_eq!(data["candidates"]["set"], serde_json::json!("sim-families"));
    assert_eq!(
        data["candidates"]["exhaustive"],
        serde_json::Value::Bool(false)
    );
    assert_eq!(
        data["candidates"]["warning"],
        serde_json::json!(sim_doctor::scan::CANDIDATE_WARNING),
        "the under-report warning travels with the report"
    );

    // 4. Absent and forbidden stayed in three separate arrays, and nothing was
    //    invented into the forbidden one.
    assert_eq!(
        tree.report().forbidden,
        0,
        "swICC evaluates no access condition on SELECT, so a non-zero \
         forbidden count here would mean the scan invented a finding"
    );
    assert!(
        data["forbidden"]
            .as_array()
            .expect("forbidden is an array")
            .is_empty(),
        "{data:#}"
    );
    assert!(
        !data["absent"]
            .as_array()
            .expect("absent is an array")
            .is_empty(),
        "probing the SIM identifier space must have found most of it missing"
    );
    assert!(data["refused"]
        .as_array()
        .expect("refused is an array")
        .is_empty());
    assert!(
        data["files"]
            .as_array()
            .expect("files is an array")
            .iter()
            .all(|file| {
                matches!(
                    file["state"].as_str(),
                    Some("selected" | "absent" | "forbidden" | "refused")
                )
            }),
        "every node has exactly one of the four state names: {data:#}"
    );

    // 5. It found what this profile holds, by absolute path, which is what a
    //    scan reports and what an agent reads.
    let selected: Vec<&str> = data["selected"]
        .as_array()
        .expect("selected is an array")
        .iter()
        .filter_map(|value| value.as_str())
        .collect();
    println!("scan: selected {:?}", selected);
    for expected in ["3F00", "3F00/2F00", "3F00/2F05", "3F00/2FE2", "3F00/7F20"] {
        assert!(
            selected.contains(&expected),
            "{expected} was not selected. The scan selected: {selected:?}"
        );
    }
    // And EF.ICCID's size came out of the swicc table as ten octets, which is
    // what data/usim.json says. Under the ISO table this is the number that
    // reads 2337, so it is the single most valuable line in this test.
    let iccid = data["files"]
        .as_array()
        .expect("files is an array")
        .iter()
        .find(|file| file["path"] == serde_json::json!("3F00/2FE2"))
        .expect("3F00/2FE2 is in the report");
    assert_eq!(
        iccid["size"]["value"]["octets"],
        serde_json::json!(10),
        "EF.ICCID is ten octets and the size lives in tag 80 on this card; \
         a different number means the dialect the scan ran under is wrong"
    );

    // 6. The whole document renders as one line, because that is what --json
    //    puts on stdout.
    let rendered = serde_json::to_string(&data).expect("the report renders");
    assert!(!rendered.contains('\n'), "the report must be one line");
    println!(
        "scan: the report renders as {} bytes on one line",
        rendered.len()
    );

    session.disconnect().expect("disconnect failed");

    // 7. And the binary itself, which is the actual acceptance criterion.
    //    `CARGO_BIN_EXE_sim-doctor` is resolved by cargo at compile time, so
    //    this is the binary cargo built rather than a path guessed at run time.
    //    **The exit-0 assertion below is a STATED contract decision, and issue
    //    #24 re-took it with a rule in place.** Issue #14 decided it while no
    //    rule ran, so the question was not yet observable; issue #24 is the
    //    first issue where a scan can produce a finding at all, which withdrew
    //    reason 1 of the three AGENTS.md records and left reasons 2 and 3
    //    standing. It decided no again, for a reason that did not exist
    //    before: exit 1 is reachable from six conditions already (no reader,
    //    unknown reader, reader unavailable, walk failed, rule misattribution,
    //    a deferred flag) and every one of them emits a *refusal* document
    //    carrying `data.error` and NO `data.findings` key. A scan that found
    //    something emits the opposite shape. Giving one code two mutually
    //    exclusive document schemas is the wrong trade for a tool whose whole
    //    promise is that an agent can branch on the status.
    //
    //    So it stays asserting success, and the finding it would have covered
    //    is covered by `data.score` and `data.complete` instead. If somebody
    //    flips FINDINGS_FAIL_A_SCAN in src/main.rs, this assertion goes red on
    //    purpose; the message on it names the other three places that have to
    //    move with it.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(["scan", "--json", "--reader", reader.as_str()])
        .output()
        .expect("the binary should run");
    assert!(
        output.status.success(),
        concat!(
            "sim-doctor scan --json exited {:?}. That is the assertion AGENTS.md ",
            "section 3 names as moving IF a scan that produces findings is ever made ",
            "to exit 1: change FINDINGS_FAIL_A_SCAN in src/main.rs, the exit code ",
            "table, the GATE ON data.complete sentence in SCAN_LONG_ABOUT and this ",
            "line together, or the tool will say two different things. ",
            "stderr: {}\nstdout: {}"
        ),
        output.status,
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.ends_with('\n'),
        "one envelope and the newline that terminates it"
    );
    assert_eq!(
        stdout.matches('\n').count(),
        1,
        "stdout is not a single line, so it is not a single envelope: {stdout}"
    );
    let envelope: serde_json::Value =
        serde_json::from_str(stdout.trim_end_matches('\n')).expect("stdout is one envelope");
    assert_eq!(envelope["type"], serde_json::json!("scan"));
    assert_eq!(envelope["payload"]["code"], serde_json::json!(0));
    assert_eq!(
        envelope["payload"]["data"]["dialect"]["name"],
        serde_json::json!(dialect.name()),
        "the binary reported the dialect it ran under"
    );
    assert_eq!(
        envelope["payload"]["data"]["truncated"],
        serde_json::Value::Bool(true),
        "the binary reported the same truncation the library run did"
    );
    println!(
        "scan: the binary emitted one envelope of {} bytes and exited 0",
        stdout.trim_end().len()
    );
}

/// Issue #14 against a real card: `--score` and `--severity` reach the
/// envelope, and the score block can be rebuilt from the document it arrives
/// in.
///
/// **Why this is a card test and not a process test.** On a machine with no
/// reader, `--score` and `--severity` fail at reader discovery, so
/// `tests/process_contract.rs` can only prove they are no longer *deferred*.
/// Whether they actually put a `score` block and a filtered `findings` array
/// on stdout needs a card, and this is the only place in the repository that
/// has one.
///
/// **What it now proves, and what it still cannot.** Issue #24 registered the
/// first rule, so `rules_run` is 1 and the score block carries no warning. On
/// this card the rule finds nothing - swSIM has no TAR check at all, which is
/// what ``the_tar_audit_meets_a_card_with_no_tar_check`` below
/// demonstrates from the wire - so `scored_findings` is 0 and the score is
/// still 100. **Those four facts together are the assertion this issue
/// turned this test into**: one rule ran, it looked, it found nothing, and the
/// 100 is therefore a verdict rather than the absence of one. That is the
/// exact confusion `NO_RULES_WARNING` existed to prevent, and it cannot now
/// arise on a real scan.
///
/// **What it still cannot prove:** that a dirty card scores below 100. That
/// needs a card that accepts TAR zero, and no fixture this repository has
/// produces one - swSIM implements no MSL. The arithmetic is proved in
/// `src/rules.rs`, the rendering in `src/scan.rs`, and the shape of the
/// finding in `src/scan.rs`s` own tests.
#[test]
#[ignore = "needs the swSIM fixture; see docs/swsim-fixture.md"]
fn the_score_and_severity_flags_reach_the_envelope_against_a_real_card() {
    let readers = Pcsc::readers().expect("could not enumerate PC/SC readers");
    let reader = readers
        .iter()
        .find(|name| name.as_str().to_ascii_lowercase().contains("swicc"))
        .unwrap_or_else(|| {
            panic!(
                "the swICC virtual reader is not present. Readers seen: {}",
                reader_list(&readers)
            )
        });

    /// Runs the built binary and returns its exit code, stdout and parsed
    /// envelope. One helper so every case below is held to the same purity
    /// check rather than one of them being allowed to skip it.
    fn scan(args: &[&str]) -> (i32, String, serde_json::Value) {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("the binary should run");
        let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
        assert!(
            stdout.ends_with('\n'),
            "{args:?}: stdout must end with the one newline that terminates the envelope: {stdout}"
        );
        assert_eq!(
            stdout.matches('\n').count(),
            1,
            "{args:?}: stdout is not a single line: {stdout}"
        );
        let envelope: serde_json::Value =
            serde_json::from_str(stdout.trim_end_matches('\n')).expect("one envelope");
        assert_eq!(envelope["type"], serde_json::json!("scan"), "{args:?}");
        (
            output
                .status
                .code()
                .expect("the process chose an exit code"),
            stdout.clone(),
            envelope,
        )
    }

    let base = ["scan", "--json", "--reader", reader.as_str()];

    // A bare run carries a findings block and no score: the score is a
    // deliberate act, not something every report carries.
    let (code, _, bare) = scan(&base);
    println!("severity/score: scanning with {reader}");
    assert_eq!(code, 0, "{bare:#}");
    println!("severity/score: a bare run carries a findings block and no score");
    assert!(
        bare["payload"]["data"]["findings"].is_object(),
        "every scan carries a findings block: {bare:#}"
    );
    assert_eq!(
        bare["payload"]["data"]["findings"]["severity_threshold"],
        serde_json::Value::Null,
        "no --severity means no threshold, which is not the same as \"info\""
    );
    assert!(
        bare["payload"]["data"].get("score").is_none(),
        "--score was not asked for, so there is no score: {bare:#}"
    );

    // --severity on its own: the threshold is reported, and it is reported
    // even when it removed nothing, because a short list is otherwise
    // indistinguishable from a quiet card.
    let mut filtered = base.to_vec();
    filtered.extend_from_slice(&["--severity", "high"]);
    let (code, _, high) = scan(&filtered);
    assert_eq!(code, 0, "{high:#}");
    println!("severity/score: --severity high reported the threshold it applied");
    assert_eq!(
        high["payload"]["data"]["findings"]["severity_threshold"],
        serde_json::json!("high")
    );
    assert_eq!(
        high["payload"]["data"]["findings"]["count"],
        high["payload"]["data"]["findings"]["findings"]
            .as_array()
            .expect("findings is an array")
            .len() as u64,
        "count and the array beside it are the same set"
    );

    // --score, and the number a reader would rebuild from this document.
    let mut scored = base.to_vec();
    scored.extend_from_slice(&["--score"]);
    let (code, _, with_score) = scan(&scored);
    assert_eq!(code, 0, "{with_score:#}");
    let block = &with_score["payload"]["data"]["score"];
    assert_eq!(
        block["formula"],
        serde_json::json!(sim_doctor::rules::SCORE_FORMULA)
    );
    assert_eq!(
        block["max"],
        serde_json::json!(sim_doctor::rules::SCORE_MAX),
        "the ceiling travels with the value"
    );
    assert_eq!(
        block["rules_run"],
        serde_json::json!(sim_doctor::scan::rules_run())
    );

    // The four facts, asserted together rather than one at a time, because it
    // is the COMBINATION that says what the 100 means.
    //
    //   rules_run 1          a rule really evaluated this card
    //   scored_findings 0    it looked and found nothing
    //   value 100 penalty 0  so nothing was subtracted
    //   warning null         and this 100 is a verdict, not an absence of one
    //
    // The last one is the whole point. Before issue #24 this line asserted the
    // warning WAS present, which said the opposite: nothing had been checked.
    // Both are 100 with rules_run beside them; only one of them is a card that
    // passed.
    assert_eq!(
        block["scored_findings"],
        serde_json::json!(0),
        "the one rule this crate has found nothing on this card, which is the          right answer for a card with no TAR check"
    );
    assert_eq!(
        block["value"],
        serde_json::json!(sim_doctor::rules::SCORE_MAX)
    );
    assert_eq!(block["penalty"], serde_json::json!(0));
    // rules_run is 1, so a rule DID run - but `--tar` defaults to off, so
    // the audit probed nothing and the rule had nothing to look at. That is
    // the no-evidence case, not the earned-100 case, and the warning has to
    // say so. A null here would claim the card was checked for MSL 0 when no
    // TAR was ever sent, which is the one thing this field must never do.
    assert_eq!(
        block["warning"],
        serde_json::json!(sim_doctor::scan::NO_TAR_EVIDENCE_WARNING),
        "the audit probed nothing, so this 100 is not a verdict about MSL 0"
    );
    assert_eq!(
        block["rules_run"],
        serde_json::json!(1),
        "gsma/msl-zero-allowed is registered; a scan that evaluated zero rules          is the regression this assertion exists to catch"
    );

    // The table travels too, so the number can be rebuilt without the source.
    println!(
        "severity/score: --score emitted value {} penalty {} over {} finding(s) with rules_run {}",
        block["value"], block["penalty"], block["scored_findings"], block["rules_run"]
    );
    println!(
        "severity/score: rules_run is 1 but the audit probed nothing, so the 100 carries the no-evidence warning rather than the earned-100 null"
    );

    let penalties = block["penalties"]
        .as_object()
        .expect("the penalty table is an object");
    assert_eq!(penalties.len(), sim_doctor::rules::SCORE_PENALTY.len());
    for severity in sim_doctor::rules::Severity::LADDER {
        assert_eq!(
            penalties[severity.id()],
            serde_json::json!(sim_doctor::rules::SCORE_PENALTY[severity.rank() as usize]),
            "the published table disagrees with the constant at {}",
            severity.id()
        );
    }

    // Both flags together, which is the combination the flag matrix cannot
    // reach without a card: the score is taken from the FILTERED set.
    let mut both = base.to_vec();
    both.extend_from_slice(&["--severity", "critical", "--score"]);
    let (code, _, both) = scan(&both);
    assert_eq!(code, 0, "{both:#}");
    assert_eq!(
        both["payload"]["data"]["score"]["scored_findings"],
        both["payload"]["data"]["findings"]["count"],
        "the score counts what the report shows, not what the scan found"
    );
    assert_eq!(
        both["payload"]["data"]["findings"]["severity_threshold"],
        serde_json::json!("critical")
    );

    // The human mode, so the score is not JSON-only. A report a person
    println!("severity/score: --severity critical --score scored what the report shows");

    // cannot check is the same defect in a different font.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sim-doctor"))
        .args(["scan", "--score", "--reader", reader.as_str()])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the binary should run");
    let human = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(
        output.status.success(),
        "human mode exited {:?}",
        output.status
    );
    assert!(
        human.contains(sim_doctor::rules::SCORE_FORMULA),
        "the human report prints the formula beside the number: {human}"
    );
    assert!(
        !human.contains(sim_doctor::scan::NO_RULES_WARNING),
        "the human report must not claim nothing was checked either: {human}"
    );
    println!("severity/score: the human report printed the formula and no no-rules warning");
}
