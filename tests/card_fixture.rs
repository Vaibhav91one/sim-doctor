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
    println!(
        "walking the card with {} candidate identifiers per directory, under the {:?} tag table",
        sim_doctor::walk::DEFAULT_MAX_CHILDREN,
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

    // 1. It terminates, and it says so if it did not. A walk that ran to a
    //    bound has not seen the whole card and must not be reported as if it
    //    had.
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
        !report.is_truncated(),
        "the whole card should fit inside the default bounds: {:?}",
        report.truncated_by
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
    assert_eq!(
        probed.len(),
        sim_doctor::walk::DEFAULT_MAX_CHILDREN,
        "the master file was probed for the whole SIM identifier space"
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
            node.path().depth() <= options.limits.max_depth,
            "{} is deeper than the bound",
            node.path()
        );
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

/// Every path the walk returned, selected ones only, for a failure message.
fn tree_dump(tree: &sim_doctor::walk::Tree) -> String {
    tree.nodes()
        .iter()
        .filter(|node| node.state().is_selected())
        .map(|node| format!("  {} {:?}", node.path(), node.state()))
        .collect::<Vec<_>>()
        .join("\n")
}
