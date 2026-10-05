//! TAR (Terminal Adaptor Request) scanning: which TARs a card will execute,
//! and the evidence the `gsma/msl-zero-allowed` rule is built on.
//!
//! **Owns.** The TAR value space, the ways to select a subset of it, the
//! bounded probe loop that puts a TAR on a card, the differential that decides
//! whether a card accepted one, and the `Audit` both of those become.
//!
//! **Does not own.** The rule. `gsma/msl-zero-allowed` is registered in
//! [`crate::scan`], beside every other rule, and reads this module's output.
//! This module knows nothing about the finding vocabulary; it produces
//! measurements and the rule turns them into findings.
//!
//! # How a TAR reaches a card at all [V]
//!
//! There is no TAR in a bare command header. A TAR is three octets inside a
//! 3GPP TS 23.040 SMS-DELIVER TPDU, inside an ISO/IEC 7816-4 SMS-PP-DOWNLOAD
//! envelope (BER-TLV tag `D1`), inside an ENVELOPE command. SIMTester builds
//! exactly that chain and is the reference this module reproduces, at the
//! pinned commit `d197fef`:
//!
//! | Layer | Built by |
//! |---|---|
//! | TS 03.48 Command Packet holding the TAR | [`CommandPacket.setTAR`](https://github.com/srlabs/SIMTester/blob/d197fef/SIMLibrary/src/de/srlabs/simlib/CommandPacket.java) `_formatMessage` |
//! | SMS-DELIVER TPDU carrying that packet | [`SMSDeliverTPDU.setTPUD`](https://github.com/srlabs/SIMTester/blob/d197fef/SIMLibrary/src/de/srlabs/simlib/SMSDeliverTPDU.java) `getBytes` |
//! | `D1` envelope payload | [`EnvelopeSMSPPDownload`](https://github.com/srlabs/SIMTester/blob/d197fef/SIMLibrary/src/de/srlabs/simlib/EnvelopeSMSPPDownload.java) |
//! | ENVELOPE APDU | [`Envelope.getAPDU`](https://github.com/srlabs/SIMTester/blob/d197fef/SIMLibrary/src/de/srlabs/simlib/Envelope.java) |
//!
//! Every octet below is reproduced from those four files, and the tests at the
//! bottom pin the result.
//!
//! **The swSIM fixture receives ENVELOPE at `80 C2 00 00` and nowhere else.**
//! [V] swSIM `src/apduh.c`, `sim_apduh_demux`: `case 0xC2: /* ENVELOPE */`
//! is dispatched only when `cmd->hdr->cla.raw == 0x80`, which is the
//! three-generation form SIMTester's `Envelope.getAPDU` builds. So
//! [`Class::Etsi`] is the default, and [`CLASS_ASSUMPTION`] says in the
//! output that `Class::Gsm` is not selectable yet rather than leaving that to
//! be discovered on a 2G card.
//!
//! # Why this module never moves on while the card is mid-command
//!
//! **A TAR probe is an ENVELOPE, and swSIM answers `61 Lc` to every one
//! before it reads a single byte of it.** [V] swSIM `src/apduh.c`,
//! `apduh_etsi_cat_envelope`: when `procedure_count == 0` and
//! `*cmd->p3 > 0` it sets `SWICC_APDU_SW1_PROC_ACK_ALL`, copies nothing out
//! of `cmd->data`, and returns. The data field therefore arrives on a
//! *second* exchange, not the first.
//!
//! A scanner that transmits the whole envelope in one APDU and moves on leaves
//! the card holding half a command: the next APDU it sends is swallowed as
//! this one's continuation, and every probe after that is answering about the
//! wrong TAR. That is worse than not probing at all.
//!
//! So [`probe`] sends the opening `CLA INS P1 P2 Lc`, waits for the card to
//! ask for the data, sends exactly that many octets, and **abandons the whole
//! scan rather than continue** if the card asks for anything else. The
//! invariant is the one that matters: the card is never left mid-command, even
//! when the probe itself fails.
//!
//! # What "the card accepted this TAR" means
//!
//! **It means the response to this TAR differs from the response this card
//! gives to TARs it has no opinion about.** That is a differential, and it is
//! SIMTester's own algorithm rather than an invention: `-stbs` runs
//! `TARScanner.tryBeingSmart`, which probes twenty TARs, counts the
//! responses, and declares **the most common one to be the false response**
//! ([source](https://github.com/srlabs/SIMTester/blob/d197fef/SIMTester/src/de/srlabs/simtester/TARScanner.java)).
//!
//! The differential is not decoration; it is the only criterion that cannot
//! manufacture findings, and the swSIM fixture proves why.
//!
//! swSIM's proactive application recognises exactly one envelope root tag,
//! `D3`, Menu Selection [V] (swSIM `src/proactive.c`,
//! `proactive_app_default__envelope`: `root_tag = {0xD3}`). It has no notion
//! of `D1`, no notion of a TAR, and **no notion of an MSL at all** -
//! grepping swSIM for a TAR allow-list finds nothing. So every
//! SMS-PP-DOWNLOAD envelope on that card, TAR zero included, is swallowed and
//! answered `90 00`. A scanner that read `90 00` as "TAR accepted" would
//! emit a critical MSL=0 finding for every TAR it probed: dozens of
//! manufactured findings on a card with no TAR check to find.
//!
//! The differential absorbs that. The modal response across twenty calibration
//! TARs is `90 00`, so `90 00` becomes refused-by-default and nothing is
//! reported. **A card that answers every TAR identically reports nothing**,
//! and on a card with no TAR check that is the correct answer rather than a
//! miss.
//!
//! ## No status word is hard-coded as "refused"
//!
//! This module will not name a status word meaning "this TAR is not allowed",
//! because it cannot cite one. AGENTS.md blocker 2 records that no 3GPP TS
//! 31.111 text has been read here, and the one card this project has talked to
//! actively contradicts the obvious guess: swSIM answers GSM SELECT of a
//! missing file with `94 04` [V] (swSIM `src/apduh.c`,
//! `apduh_gsm_select`: `res->sw1 = 0x94; res->sw2 = 0x04; /* "File ID not
//! found" */`). On the only card this project can test, `94 04`
//! demonstrably does **not** mean "the TAR was refused". Treating it as though
//! it did would be exactly the invented protocol fact AGENTS.md section 2
//! forbids.
//!
//! So the baseline is measured, never assumed. See [`Baseline`].

/// This module's name, as recorded in [`crate::MODULES`].
///
/// Referenced by value rather than re-spelt as a literal so that the module
/// table cannot name a module that does not exist.
pub const NAME: &str = "tar";

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{json, Value};

use crate::apdu::{Command, Le, Response, StatusWord, CLA_FETCH_ETSI};
use crate::session::{self, Policy};
use crate::transport::{CardSession, Error as TransportError};

/// The smallest TAR, `0x000000`.
///
/// Also the TAR this module is named for: a card that accepts TAR zero is
/// running at MSL 0, which is the finding.
pub const TAR_MIN: u32 = 0x00_00_00;

/// The largest TAR, `0xFFFFFF`.
///
/// [V] SIMTester `TARScanner.java` at `d197fef`:
/// `private final static int HIGHEST_TAR = 16777215; // this is 0xFFFFFF`.
pub const TAR_MAX: u32 = 0xFF_FF_FF;

/// The most TAR values one scan may put on a card.
///
/// **This is the answer to "the full sweep is 16.7 million values and is not
/// something to send to a card blindly".** SIMTester's `-st full` does sweep
/// all 16 777 216, prints a progress line every hundred, and says "go get a
/// (few) coffee(s)"; its `-stbs` smart mode exists precisely because the naive
/// sweep is impractical. This crate will not ship an unbounded probe loop
/// behind a flag, so the bound is a constant and it is published:
///
/// - the focused default set is [`FOCUSED_PROBES`] values and fits inside it,
/// - `full` scans from zero and **stops at this bound**, reporting
///   `"stopped": "probe budget"` rather than pretending it finished,
/// - and a run that hit the bound is not complete, so [`Audit::is_complete`]
///   says so and every finding raised from it is marked
///   [`crate::rules::Coverage::Partial`] rather than read as exhaustive.
pub const MAX_PROBES: usize = 4096;

/// How many TARs the calibration pass probes to establish the baseline.
///
/// [V] SIMTester `TARScanner.java`: `private final static int _smart_count =
/// 20;`.
pub const CALIBRATION_PROBES: usize = 20;

/// The TAR values the calibration pass probes.
///
/// **Fixed, not random.** SIMTester draws its twenty with `Math.random()`
/// (`TARScanner.tryBeingSmart`). This module does not, because everything
/// else this crate reports is deterministic - AGENTS.md section 3 makes the
/// score a function of the findings alone, so a CI threshold is an integer
/// comparison - and a baseline that moved between two runs of the same card
/// would make the finding move with it. These values are spread across the
/// space so the modal response is not an artefact of one region.
pub const CALIBRATION_TARS: [u32; CALIBRATION_PROBES] = [
    0x0000_00, 0x0000_FF, 0x0001_00, 0x0001_0F, 0x0002_00, 0x0002_0F, 0x0003_00, 0x0003_0F,
    0x0004_00, 0x0004_0F, 0x0005_00, 0x0005_0F, 0x3F00_00, 0x3F00_3F, 0x8000_00, 0x8000_FF,
    0xA000_00, 0xA000_FF, 0xBF_FF_00, 0xFF_FF_FF,
];

/// The bands the focused default set is built from.
///
/// **SIMTester's own band list, narrowed on purpose.** [V]
/// `TARScanner.prepareTARlist` at `d197fef` builds `-str` from two
/// families: every three-character permutation of printable ASCII - which is
/// where real OTA service TARs come from, since a TAR is chosen to look like an
/// SMS originator address - and these hexadecimal bands:
///
/// | Band | TARs |
/// |---|---|
/// | `0x000000`-`0x0000FF` | 256 |
/// | `0x000100`-`0x00050F`, five bands of 16 | 80 |
/// | `0x3F0000`-`0x3F003F` | 64 |
/// | `0x800000`-`0x8000FF`, `0xA00000`-`0xA000FF`, `0xB00000`-`0xB000FF`, `0xC00000`-`0xC000FF`, `0xD00000`-`0xD000FF` | 5 x 256 |
/// | `0xBFFF00`-`0xBFFFFF` | 256 |
/// | `0xEED000`-`0xEEEFFF`, `0xFFFF00`-`0xFFFFFF` | 2 x 256 |
///
/// The focused set takes the bands that carry TAR zero, the low bands, and the
/// all-`B` pattern operators use as a wildcard. It **drops** the printable
/// permutations because SIMTester's list of them is over 400 000 values, which
/// does not fit inside [`MAX_PROBES`] and is the reason `-str` takes coffee.
/// An operator who wants them says `range:0x200000-0x7FFFFF`, which covers
/// every printable ASCII triple, and the report says whether that scan
/// finished.
pub const FOCUSED_BANDS: [(u32, u32); 8] = [
    (0x0000_00, 0x0000_FF),
    (0x0001_00, 0x0001_0F),
    (0x0002_00, 0x0002_0F),
    (0x0003_00, 0x0003_0F),
    (0x0004_00, 0x0004_0F),
    (0x0005_00, 0x0005_0F),
    (0x3F00_00, 0x3F00_3F),
    (0xBF_FF_00, 0xBF_FF_FF),
];

/// How many TARs the focused default set probes.
///
/// [`FOCUSED_BANDS`] sums to 592 and this says so, so a test checks the two
/// against each other rather than either being a number somebody typed.
pub const FOCUSED_PROBES: usize = 592;

/// The class byte an ENVELOPE is sent at.
///
/// Named after the class rather than after a use, because which of the two a
/// card routes is a property of the card, not of this tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Class {
    /// CLA `0x80`, ETSI TS 102 221 clause 10.1.2. The default.
    ///
    /// [V] swSIM `src/apduh.c`, `sim_apduh_demux`, dispatches INS `0xC2`
    /// at this class and at no other proprietary class.
    #[default]
    Etsi,

    /// CLA `0xA0`, GSM 11.11.
    ///
    /// [V] SIMTester `Envelope.getAPDU`: the `A0` form is what it builds
    /// when `third_gen_apdu` is false, i.e. for a 2G SIM.
    Gsm,
}

impl Class {
    /// Every class this module can send an ENVELOPE at.
    pub const ALL: [Self; 2] = [Self::Etsi, Self::Gsm];

    /// The octet on the wire.
    pub const fn octet(self) -> u8 {
        match self {
            Self::Etsi => 0x80,
            Self::Gsm => 0xA0,
        }
    }

    /// The spelling the report carries.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Etsi => "etsi",
            Self::Gsm => "gsm",
        }
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:02X})", self.id(), self.octet())
    }
}

/// What a report says about the class byte it used.
///
/// Published rather than assumed away, for the same reason the FCP dialect is:
/// an ENVELOPE sent at the wrong class is refused before the card reaches the
/// TAR, and a scan reporting "no TAR accepted" from a wrongly-addressed
/// envelope would be reporting a fact about its own addressing as though it
/// were a fact about the card.
pub const CLASS_ASSUMPTION: &str = "the ENVELOPE was sent at CLA 80 (etsi), the only class swSIM dispatches ENVELOPE at; a 2G card routes ENVELOPE at CLA A0 (gsm) and that is not selectable yet, so a scan that found no accepted TAR on a 2G card has not shown the card refuses TARs, only that nothing arrived where this tool sent it";

/// INS of the ENVELOPE command.
///
/// [V] two independent sources agree: SIMTester `Envelope.getAPDU` builds
/// `(byte) 0xC2`, and swSIM `src/apduh.c`, `sim_apduh_demux`, has
/// `case 0xC2: /* ENVELOPE */`. ISO/IEC 7816-4 numbers the same command
/// `CA`; the two disagree, and this crate follows the two implementations
/// rather than specification text it has not read.
pub const INS_ENVELOPE: u8 = 0xC2;

/// BER-TLV tag of an SMS-PP-DOWNLOAD envelope payload.
///
/// [V] SIMTester `EnvelopeSMSPPDownload`:
/// `InnerTLV.getInnerTLV((byte) 0xD1, smspp_data)`, whose own comment cites
/// TS 101 220 clause 7.1.2 for the length encoding reproduced by
/// [`inner_tlv`].
pub const TAG_SMS_PP_DOWNLOAD: u8 = 0xD1;

/// The user data the TAR probe carries.
///
/// `A0 A4 00 00 02 3F 00`, which is SIMTester's SELECT of the master file
/// ([V] `TARScanner.testTAR`:
/// `cp.setUserData(HexToolkit.fromString("A0A40000023F00"))`).
///
/// **Nothing depends on the card understanding it.** The probe asks "will you
/// route this TAR", not "what will you do with the packet"; a card that routes
/// the TAR and then fails on the payload has still routed the TAR. A
/// well-formed command is used precisely because a malformed one would let a
/// card's *parser* rather than its TAR check decide the answer.
pub const PROBE_USER_DATA: [u8; 7] = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];

/// The 3GPP TS 03.48 Command Packet Header SIMTester writes.
///
/// [V] `CommandPacket.CPH = {0x02, 0x70, 0x00}`. The third octet is the
/// version and flags byte, written `00` for a CP whose integrity is not
/// cryptographically protected.
const COMMAND_PACKET_HEADER: [u8; 3] = [0x02, 0x70, 0x00];

/// The SPI1 octet of the probe's Command Packet.
///
/// [V] `TARScanner.testTAR` sets only `setCounterManegement(CNTR_NO_CNTR_AVAILABLE)`,
/// which writes `SPI1 |= 0`; the field starts at `0x00`. No ciphering, no
/// cryptographic checksum.
const SPI1_PLAIN: u8 = 0x00;

/// The SPI2 octet of the probe's Command Packet.
///
/// [V] `TARScanner.testTAR` sets, in order: `setPoR(true)` gives
/// `SPI2 |= 0x01`; `setPoRSecurity(POR_SECURITY_CC)` with
/// `POR_SECURITY_CC = 0x2` gives `SPI2 |= (2 << 2) & 0x0C = 0x08`;
/// `setPoRMode(POR_MODE_SMS_SUBMIT)` with `POR_MODE_SMS_SUBMIT = 0x1` gives
/// `SPI2 |= (1 << 5) & 0x20 = 0x20`. So `0x01 | 0x08 | 0x20 = 0x29`.
const SPI2_PROBE: u8 = 0x29;

/// The key set the probe's KIC and KID name.
///
/// [V] `CommandPacket.setKeyset(0)` writes `KIC |= 0 << 4` and
/// `KID |= 0 << 4`, so both stay `0x00`. The low nibble is the algorithm
/// selector, and `0x00` is `KIC_ALGO_IMPLICIT`.
const KEY_SET: u8 = 0x00;

/// The counter the probe's Command Packet carries.
///
/// [V] `TARScanner.testTAR` calls `setCounter(1)`, and
/// `CommandPacket.setCounter` writes `CNTR[4 - i] = (byte)(counter >>>
/// (i * 8))`, so one is `00 00 00 00 01` big-endian.
const COMMAND_COUNTER: [u8; 5] = [0x00, 0x00, 0x00, 0x00, 0x01];

/// The command header length of a Command Packet with no cryptographic
/// checksum.
///
/// [V] `CommandPacket._formatMessage`:
/// `int _chl = 13; // 2b (SPI) + 1b (KIC) + 1b (KID) + 3b (TAR) + 5b (CNTR)
/// + 1b (PCNTR)`, plus eight when `isCryptographicChecksumEnabled()`. The
/// probe sets neither, so it is thirteen.
const COMMAND_HEADER_LEN: u8 = 13;

/// The SMS-DELIVER TPDU first octet the probe sends.
///
/// [V] `SMSDeliverTPDU.getFirstOctet` ORs six masked fields. The `OTASMS`
/// constructor calls `setTPUDHI(true)`, which is bit 6; `TPMMS` defaults to
/// `0x4`, which is bit 2; the rest default to zero. `0x40 | 0x04 = 0x44`.
///
/// **The quirk this reproduces, deliberately.** `OTASMS` sets the User Data
/// Header Indicator and then `SMSDeliverTPDU.setTPUD` writes the Command
/// Packet straight into TP-UD with **no user data header after the flag**. A
/// strict card may reject the TPDU before it reaches the TAR. This module
/// reproduces the bytes rather than "fixing" them, because the reference
/// implementation's behaviour is the thing `-st` is verified against, and
/// changing it would make this tool's results incomparable with SIMTester's.
/// Recorded so the next reader does not assume it is an arithmetic mistake
/// here.
const SMS_DELIVER_FIRST_OCTET: u8 = 0x44;

/// TP-Originating-Address the probe sends.
///
/// [V] `SMSDeliverTPDU.TPOA = {0x05, 0x00, 0x21, 0x43, 0xF5}`.
const SMS_DELIVER_TPOA: [u8; 5] = [0x05, 0x00, 0x21, 0x43, 0xF5];

/// TP-Protocol-Identifier the probe sends: `1111111`, "(U)SIM Data download".
///
/// [V] `SMSDeliverTPDU.TPPID = (byte) 0x7F`, whose own comment reads
/// `111111 (U)SIM Data download`.
const SMS_DELIVER_TPPID: u8 = 0x7F;

/// TP-Data-Coding-Scheme the probe sends.
///
/// [V] `SMSDeliverTPDU.TPDCS = (byte) 0xF6`.
const SMS_DELIVER_TPDCS: u8 = 0xF6;

/// The 7-octet TP-Service-Centre-Time-Stamp: all zero.
///
/// [V] `SMSDeliverTPDU.TPSCTS = new byte[7]` and no setter is called by
/// `OTASMS`. The card cannot route on a timestamp that says 1970, which is
/// fine: the probe is not an SMS, it is a TAR request.
const SMS_DELIVER_SCTS: [u8; 7] = [0, 0, 0, 0, 0, 0, 0];

/// Device identities of a 3G SMS-PP-DOWNLOAD envelope.
///
/// [V] SIMTester `OTASMS.send`, 3G branch:
/// `new DeviceIdentities(TYPE_3G, DI_NETWORK, DI_UICC)`, and
/// `DeviceIdentities.getBytes` writes type, length `0x02`, source,
/// destination, with `TYPE_3G = 0x82`, `DI_NETWORK = 0x83`,
/// `DI_UICC = 0x81`.
const DEVICE_IDENTITIES_3G: [u8; 4] = [0x82, 0x02, 0x83, 0x81];

/// Device identities of a GSM SMS-PP-DOWNLOAD envelope.
///
/// [V] SIMTester `OTASMS.send`, 2G branch, with `TYPE_GSM = 0x02`.
const DEVICE_IDENTITIES_GSM: [u8; 4] = [0x02, 0x02, 0x83, 0x81];

/// The originating address SIMTester puts in a 3G envelope.
///
/// [V] `OTASMS.send`, 3G branch:
/// `new Address(HexToolkit.fromString("86050021436587"))`, and
/// `Address.getBytes` writes tag, length, TON/NPI, then the dialing string:
/// tag `0x86` (TYPE_3G), length `0x08`, TON/NPI `0x91`.
const ADDRESS_3G: [u8; 10] = [0x86, 0x08, 0x91, 0x86, 0x50, 0x02, 0x14, 0x36, 0x58, 0x7F];

/// The originating address SIMTester puts in a GSM envelope.
///
/// [V] `OTASMS.send`, 2G branch:
/// `new Address(HexToolkit.fromString("06050021436587"))`, with
/// `TYPE_GSM = 0x06`.
const ADDRESS_GSM: [u8; 10] = [0x06, 0x08, 0x91, 0x06, 0x50, 0x02, 0x14, 0x36, 0x58, 0x7F];

/// A TAR as six uppercase hexadecimal digits.
///
/// **Six digits, always.** That is SIMTester's `-str` spelling
/// ([V] `setStartingTAR`: `!startingTAR.matches("[0-9A-F]+") ||
/// startingTAR.length() != 6`) and it is what a regular expression is matched
/// against, so `^ABC$` means one TAR rather than "anything containing ABC".
pub fn hex(tar: u32) -> String {
    format!("{tar:06X}")
}

/// BER-TLV with the TS 101 220 clause 7.1.2 length encoding.
///
/// [V] SIMTester `InnerTLV.getInnerTLV`: short form below `128`, `81 xx`
/// to `255`, `82 xx xx`, `83 xx xx xx`. This crate's [`crate::tlv`] makes
/// the same choice for the same reasons, so the two cannot drift about what
/// they accept.
///
/// Returns `None` for a body above `0xFF_FF_FF` octets, which would need a
/// fourth length octet no APDU can carry. Nothing in this crate builds one:
/// the probe's envelope is [`PROBE_ENVELOPE_LEN`] octets.
pub fn inner_tlv(tag: u8, data: &[u8]) -> Option<Vec<u8>> {
    let len = data.len();
    let mut out = Vec::with_capacity(len + 4);
    out.push(tag);
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len <= 0xFF_FF_FF {
        out.push(0x83);
        out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    } else {
        return None;
    }
    out.extend_from_slice(data);
    Some(out)
}

/// The 3GPP TS 03.48 Command Packet carrying `tar`.
///
/// [V] `CommandPacket._formatMessage` at `d197fef`: `CPH || CPL || CHL ||
/// SPI1 SPI2 KIC KID TAR CNTR PCNTR || UD`, with `CPL` big-endian over
/// `1 + CHL + len(UD)`.
///
/// # Panics
///
/// Never. `cpl` is a fixed 21 and CPL is two octets wide; the conversion is
/// written out rather than left to a debug assertion so that the arithmetic is
/// visible in the code that depends on it.
pub fn command_packet(tar: u32) -> Vec<u8> {
    let ud = PROBE_USER_DATA;
    let cpl = u16::try_from(1 + usize::from(COMMAND_HEADER_LEN) + ud.len())
        .expect("the probe user data is seven octets, so CPL is 21");

    let mut out = Vec::with_capacity(usize::from(cpl) + COMMAND_PACKET_HEADER.len());
    out.extend_from_slice(&COMMAND_PACKET_HEADER);
    out.extend_from_slice(&cpl.to_be_bytes());
    out.push(COMMAND_HEADER_LEN);
    out.push(SPI1_PLAIN);
    out.push(SPI2_PROBE);
    out.push(KEY_SET);
    out.push(KEY_SET);
    out.extend_from_slice(&tar.to_be_bytes()[1..]);
    out.extend_from_slice(&COMMAND_COUNTER);
    out.push(0x00);
    out.extend_from_slice(&ud);
    out
}

/// The SMS-DELIVER TPDU carrying `user_data`.
///
/// [V] `SMSDeliverTPDU.getBytes` at `d197fef`: first octet, TP-OA, TP-PID,
/// TP-DCS, TP-SCTS, TP-UDL, TP-UD - in that order, with TP-UDL set by
/// `setTPUD` to `userData.length`.
///
/// Returns `None` for anything TP-UDL's single octet cannot count, written
/// out rather than assumed so a longer input cannot silently wrap it.
pub fn sms_deliver_tpdu(user_data: &[u8]) -> Option<Vec<u8>> {
    let udl = u8::try_from(user_data.len()).ok()?;
    let mut out = Vec::with_capacity(
        1 + SMS_DELIVER_TPOA.len() + 2 + SMS_DELIVER_SCTS.len() + 1 + user_data.len(),
    );
    out.push(SMS_DELIVER_FIRST_OCTET);
    out.extend_from_slice(&SMS_DELIVER_TPOA);
    out.push(SMS_DELIVER_TPPID);
    out.push(SMS_DELIVER_TPDCS);
    out.extend_from_slice(&SMS_DELIVER_SCTS);
    out.push(udl);
    out.extend_from_slice(user_data);
    Some(out)
}

/// The ENVELOPE data field that puts `tar` on the card.
///
/// [V] `OTASMS.send` to `EnvelopeSMSPPDownload` to
/// `InnerTLV.getInnerTLV(0xD1, device_identities || address || tpdu)`.
pub fn envelope_data(tar: u32, class: Class) -> Option<Vec<u8>> {
    let tpdu = sms_deliver_tpdu(&command_packet(tar))?;
    let (identities, address) = match class {
        Class::Etsi => (&DEVICE_IDENTITIES_3G[..], &ADDRESS_3G[..]),
        Class::Gsm => (&DEVICE_IDENTITIES_GSM[..], &ADDRESS_GSM[..]),
    };
    let mut body = Vec::with_capacity(identities.len() + address.len() + tpdu.len());
    body.extend_from_slice(identities);
    body.extend_from_slice(address);
    body.extend_from_slice(&tpdu);
    inner_tlv(TAG_SMS_PP_DOWNLOAD, &body)
}

/// How many octets the probe's ENVELOPE data field is.
///
/// Named because the whole probe's wire sequence depends on it and a test
/// pins it against the octets rather than against this number.
pub const PROBE_ENVELOPE_LEN: usize = 58;

/// The two halves of one ENVELOPE exchange.
///
/// **Not one command, and that is the point.** See the module documentation:
/// swSIM answers the opening with `61 Lc` before reading a byte of the data
/// field, so the data arrives on the second exchange. Sending both in one
/// APDU and moving on leaves the card holding half a command.
///
/// Returned as a pair rather than sent here so that a test can assert both
/// halves with no card, which is the only way the invariant is provable on a
/// machine with no reader.
pub fn envelope_exchange(tar: u32, class: Class) -> Option<(Vec<u8>, Vec<u8>)> {
    let data = envelope_data(tar, class)?;
    let len = u8::try_from(data.len()).ok()?;
    let opening = vec![class.octet(), INS_ENVELOPE, 0x00, 0x00, len];
    Some((opening, data))
}

/// Which TARs a scan probes.
///
/// The three shapes mirror SIMTester's `-st` modes [V] (AGENTS.md 5.2 records
/// `-st full`, `-str`, `-stbs`, `-stre`):
///
/// | This crate | SIMTester | Meaning |
/// |---|---|---|
/// | [`Mode::Full`] | `-st full` | the whole 16 777 216-value space, **capped at [`MAX_PROBES`]** |
/// | [`Mode::Range`] | `-str` | an inclusive first..=last band |
/// | [`Mode::Regex`] | `-stre` | a pattern over the six-hex-digit spelling |
///
/// [`Mode::Focused`] is this crate's addition and not a SIMTester mode: the
/// bounded default set in [`FOCUSED_BANDS`], which is what makes a scan that
/// checks for MSL=0 possible at all without an operator first timing a full
/// sweep.
///
/// **A `Full` selection does not sweep 16.7 million values.** It stops at
/// [`MAX_PROBES`] and reports that it did, because an unbounded probe loop
/// behind a flag is the thing AGENTS.md section 2 is arguing against: the
/// swSIM card is cooperative and a real card is not.
#[derive(Debug, Clone)]
pub enum Mode {
    /// Probe nothing. The TAR block is still reported, saying why it is empty.
    Off,

    /// The bounded default set in [`FOCUSED_BANDS`].
    Focused,

    /// Everything from [`TAR_MIN`] upwards, capped at [`MAX_PROBES`].
    Full,

    /// An inclusive band.
    Range {
        /// The lowest TAR probed.
        first: u32,
        /// The highest TAR probed, inclusive.
        last: u32,
    },

    /// A regular expression over [`hex`].
    Regex {
        /// The pattern, as typed.
        pattern: String,
        /// The compiled form.
        ///
        /// Held next to the text rather than recompiled per candidate, and a
        /// second copy on purpose: validating against a compiled pattern the
        /// caller then discards would let the two disagree about what matched.
        compiled: regex::Regex,
    },
}

/// **Equality is written out rather than derived, because the compiled
/// pattern is in the type.** `regex::Regex` implements neither
/// `PartialEq` nor `Eq`, and the two obvious workarounds are both
/// wrong: comparing the pattern text alone would say two selections are
/// equal when only one of them ever compiled, and keeping a second
/// interned form to hash would make equality depend on an internal
/// representation this crate does not own. So two modes are equal when they
/// would **probe the same TARs**, which is decidable from the pattern text:
/// the compiled form is a cache, not a second answer.
impl PartialEq for Mode {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Off, Self::Off) | (Self::Focused, Self::Focused) | (Self::Full, Self::Full) => {
                true
            }
            (
                Self::Range { first, last },
                Self::Range {
                    first: other_first,
                    last: other_last,
                },
            ) => first == other_first && last == other_last,
            (
                Self::Regex { pattern, .. },
                Self::Regex {
                    pattern: other_pattern,
                    ..
                },
            ) => pattern == other_pattern,
            _ => false,
        }
    }
}

impl Eq for Mode {}

impl Mode {
    /// The name a report carries.
    pub const fn id(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Focused => "focused",
            Self::Full => "full",
            Self::Range { .. } => "range",
            Self::Regex { .. } => "regex",
        }
    }
}

/// A `--tar` value that is not one this module knows.
///
/// The message lists the forms, because an agent that typed one and got a
/// refusal has to be able to learn the grammar from the refusal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "{0:?} is not a TAR selection; expected off, focused, full, range:FIRST-LAST      or regex:PATTERN, where FIRST and LAST are six hexadecimal digits, e.g.      range:000000-000FFF or regex:^EDR$"
)]
pub struct UnknownSelection(pub String);

/// One parsed `--tar` value: a mode, and the class byte to probe at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// Which TARs to probe.
    pub mode: Mode,

    /// The class byte the ENVELOPE is sent at.
    pub class: Class,
}

impl Default for Selection {
    /// The focused set at the ETSI class, which is what makes a scan check for
    /// MSL=0 without an operator having to ask for it.
    fn default() -> Self {
        Self {
            mode: Mode::Focused,
            class: Class::Etsi,
        }
    }
}

impl fmt::Display for Selection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.mode {
            Mode::Off => f.write_str("off"),
            Mode::Focused => f.write_str("focused"),
            Mode::Full => f.write_str("full"),
            Mode::Range { first, last } => write!(f, "range:{}-{}", hex(*first), hex(*last)),
            Mode::Regex { pattern, .. } => write!(f, "regex:{pattern}"),
        }
    }
}

impl std::str::FromStr for Selection {
    type Err = UnknownSelection;

    /// Parses `off`, `focused`, `full`, `range:FIRST-LAST` or
    /// `regex:PATTERN`.
    ///
    /// Case-insensitive on the mode word and on the hexadecimal digits,
    /// because the mode word is typed by a person and the digits appear in
    /// both cases in every document about TARs. **A regular expression is
    /// taken exactly as typed**: it is a pattern, and quietly rewriting one an
    /// operator typed would make the report answer a question they did not ask.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        let refuse = || UnknownSelection(text.to_owned());

        let (mode, class) = match text.to_ascii_lowercase().as_str() {
            "off" => (Mode::Off, Class::Etsi),
            "focused" | "default" => (Mode::Focused, Class::Etsi),
            "full" => (Mode::Full, Class::Etsi),
            "range" | "all" => (
                Mode::Range {
                    first: TAR_MIN,
                    last: TAR_MAX,
                },
                Class::Etsi,
            ),
            other => {
                if let Some(rest) = other.strip_prefix("range:") {
                    let (first, last) = rest.split_once('-').ok_or_else(refuse)?;
                    (
                        Mode::Range {
                            first: parse_tar(first)?,
                            last: parse_tar(last)?,
                        },
                        Class::Etsi,
                    )
                } else if let Some(rest) = text.strip_prefix("regex:") {
                    if rest.is_empty() {
                        return Err(refuse());
                    }
                    let compiled =
                        regex::Regex::new(rest).map_err(|_| UnknownSelection(text.to_owned()))?;
                    (
                        Mode::Regex {
                            pattern: rest.to_owned(),
                            compiled,
                        },
                        Class::Etsi,
                    )
                } else {
                    return Err(refuse());
                }
            }
        };

        if let Mode::Range { first, last } = mode {
            if first > last {
                return Err(UnknownSelection(text.to_owned()));
            }
        }

        Ok(Self { mode, class })
    }
}

/// One TAR value written as six hexadecimal digits.
///
/// Accepts an optional `0x` so an operator copying from a document that uses
/// it is not punished for it, and refuses anything longer than six digits
/// rather than truncating: a TAR that does not fit in three octets is not a
/// TAR.
fn parse_tar(text: &str) -> Result<u32, UnknownSelection> {
    let digits = text.trim();
    let digits = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
        .unwrap_or(digits);
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(UnknownSelection(text.to_owned()));
    }
    u32::from_str_radix(digits, 16).map_err(|_| UnknownSelection(text.to_owned()))
}

/// The TARs a selection resolves to, and whether it had more.
///
/// The pair is (values, exhausted), where exhausted is false when the
/// selection had TARs left over at the limit. **It is the whole of the "a
/// scan that stopped early must say so" rule at this level**: a caller that
/// drops the flag reports a partial answer as an exhaustive one, so
/// [`Audit::is_complete`] carries it all the way to the output.
pub fn candidates(selection: &Selection, limit: usize) -> (Vec<u32>, bool) {
    let cap = limit.min(MAX_PROBES);
    let mut out = Vec::new();

    match &selection.mode {
        Mode::Off => (out, true),
        Mode::Focused => {
            for &(first, last) in &FOCUSED_BANDS {
                for tar in first..=last {
                    if out.len() == cap {
                        return (out, false);
                    }
                    out.push(tar);
                }
            }
            (out, true)
        }
        Mode::Range { first, last } => {
            let mut tar = *first;
            while tar <= *last {
                if out.len() == cap {
                    return (out, false);
                }
                out.push(tar);
                // checked rather than incremented, so a last above TAR_MAX
                // stops rather than wrapping to zero and re-probing the bottom.
                match tar.checked_add(1) {
                    Some(next) => tar = next,
                    None => break,
                }
            }
            (out, true)
        }
        Mode::Full => {
            let mut tar = TAR_MIN;
            loop {
                if out.len() == cap {
                    return (out, false);
                }
                out.push(tar);
                match tar.checked_add(1) {
                    Some(next) => tar = next,
                    None => return (out, true),
                }
            }
        }
        Mode::Regex { compiled, .. } => {
            // Swept, not generated: a pattern such as EDR has no closed form,
            // so the only honest enumeration is the whole 24-bit space. The
            // sweep stops as soon as the cap is reached, so a pattern that
            // matches everything still terminates at the bound rather than
            // running for hours.
            // The buffer is reused rather than allocated per candidate: this
            // loop runs up to 16 777 216 times, and a String per iteration
            // turns a one-second sweep into a minute. Capacity six is what
            // [%06X] needs and never grows.
            let mut spelled = String::with_capacity(6);
            let mut tar = TAR_MIN;
            loop {
                spelled.clear();
                let _ = fmt::write(&mut spelled, format_args!("{tar:06X}"));
                if compiled.is_match(&spelled) {
                    if out.len() == cap {
                        return (out, false);
                    }
                    out.push(tar);
                }
                match tar.checked_add(1) {
                    Some(next) => tar = next,
                    None => return (out, true),
                }
            }
        }
    }
}

/// What the card said to one TAR.
///
/// Deliberately coarse. The point of the differential is to compare responses,
/// so the finest thing that can be compared without being defeated by a card
/// that echoes the TAR back in a Proof-of-Response body is the **status word**.
///
/// **The response body is not part of the comparison, and that is the
/// conservative choice.** A card that accepts a TAR answers with a 3GPP TS
/// 03.48 Response Packet, and a Response Packet *carries the TAR back*
/// ([V] `ResponsePacket.parse`: `System.arraycopy(data, 6, TAR, 0, 3)`). So
/// comparing whole responses byte for byte would make every TAR look different
/// from every other one on exactly the cards the tool is looking for, and a
/// critical finding would be raised for each. Only the body *length* is kept,
/// so a card that returns data for one TAR and not another is still visible.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Signature {
    status: Option<[u8; 2]>,
    body_len: usize,
}

impl Signature {
    /// Builds a signature from a parsed response.
    pub fn of(response: &Response) -> Self {
        Self {
            status: match response.status() {
                Some(status) => Some(status.to_bytes()),
                None => None,
            },
            body_len: response.body().len(),
        }
    }

    /// The status word, when the response carried one.
    pub const fn status(&self) -> Option<StatusWord> {
        match self.status {
            Some([sw1, sw2]) => Some(StatusWord::new(sw1, sw2)),
            None => None,
        }
    }

    /// How many response-data octets the card sent alongside it.
    ///
    /// Carried because a card that answers one TAR with data and another
    /// without has said something the status word alone cannot, and a report
    /// that dropped it would hide the only evidence there is.
    pub const fn body_len(&self) -> usize {
        self.body_len
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            Some([sw1, sw2]) => write!(f, "{sw1:02X}{sw2:02X}")?,
            None => f.write_str("(no status word)")?,
        }
        if self.body_len > 0 {
            write!(f, " + {} data", self.body_len)?;
        }
        Ok(())
    }
}

/// The response this card gives to TARs it has no opinion about.
///
/// **Measured, not assumed.** See the module documentation: this project cannot
/// cite a status word meaning "TAR not allowed", and the one card it has talked
/// to contradicts the obvious guess, so the baseline is whatever the
/// calibration probes produced most often - which is what SIMTester's
/// `tryBeingSmart` does.
///
/// **A tie resolves to no baseline, which refuses nothing.** With twenty
/// samples and two equally common responses, neither is *the* false response;
/// the scan says so rather than picking one and reporting whatever the other
/// one answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Baseline {
    signature: Option<Signature>,
    count: usize,
    sampled: usize,
    histogram: BTreeMap<Signature, usize>,
}

impl Baseline {
    /// Builds a baseline from the calibration responses.
    ///
    /// A response with no status word at all never becomes the baseline: that
    /// is a card which has stopped answering coherently, and calling "no
    /// answer" the false response would refuse everything the scan then sees.
    pub fn of(responses: &[Option<Signature>]) -> Self {
        let mut histogram: BTreeMap<Signature, usize> = BTreeMap::new();
        for signature in responses.iter().flatten() {
            if signature.status().is_none() {
                continue;
            }
            *histogram.entry(signature.clone()).or_insert(0) += 1;
        }

        let sampled = responses.len();
        // `BTreeMap` iterates in key order, so ranking on the count alone
        // is deterministic, and the tie is then detected explicitly rather
        // than broken here: a tie must resolve to no baseline at all.
        let best = histogram
            .iter()
            .max_by_key(|(_, count)| **count)
            .map(|(signature, count)| (signature.clone(), *count));
        let tied = best.as_ref().is_some_and(|(_, count)| {
            histogram.values().filter(|other| **other == *count).count() > 1
        });

        Self {
            signature: if tied {
                None
            } else {
                best.as_ref().map(|(s, _)| s.clone())
            },
            count: if tied {
                0
            } else {
                best.map_or(0, |(_, count)| count)
            },
            sampled,
            histogram,
        }
    }

    /// The signature a refused TAR is expected to produce.
    pub const fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    /// How many calibration probes produced it.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// How many calibration probes were sent.
    pub const fn sampled(&self) -> usize {
        self.sampled
    }

    /// Every distinct signature and its count, in status-word order.
    pub fn histogram(&self) -> impl Iterator<Item = (&Signature, usize)> {
        self.histogram
            .iter()
            .map(|(signature, count)| (signature, *count))
    }

    /// Whether the baseline was established.
    ///
    /// False means the responses tied, or every calibration probe came back
    /// with no status word. Either way **this scan cannot distinguish an
    /// accepted TAR from a refused one**, and the audit says exactly that
    /// rather than reporting anything.
    pub const fn is_established(&self) -> bool {
        self.signature.is_some()
    }

    /// Whether `signature` is the response of a TAR this card does not
    /// accept.
    pub fn refuses(&self, signature: &Signature) -> bool {
        self.signature.as_ref() == Some(signature)
    }
}

impl fmt::Display for Baseline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.signature {
            Some(signature) => write!(
                f,
                "{} ({}/{} calibration probes)",
                signature, self.count, self.sampled
            ),
            None => write!(
                f,
                "(not established: {} calibration probes, no majority response)",
                self.sampled
            ),
        }
    }
}

/// What the scanner concluded about one TAR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// The card's answer to this TAR differed from its baseline answer.
    ///
    /// **This is the finding**, and the status word travels with it so a reader
    /// can see what "differed" means rather than having to trust it.
    Accepted {
        /// The status word the card answered with.
        status: Option<StatusWord>,
        /// How many response-data octets accompanied it.
        body_len: usize,
    },

    /// The card answered exactly as it does for TARs it has no opinion about.
    Refused {
        /// The status word it answered with, which is the baseline's.
        status: Option<StatusWord>,
    },
}

impl Verdict {
    /// The status word either way.
    pub const fn status(&self) -> Option<StatusWord> {
        match self {
            Self::Accepted { status, .. } | Self::Refused { status } => *status,
        }
    }

    /// Whether this TAR was accepted.
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    /// The wire name a report carries.
    pub const fn id(&self) -> &'static str {
        match self {
            Self::Accepted { .. } => "accepted",
            Self::Refused { .. } => "refused",
        }
    }
}

/// One TAR's probe, with what is needed to argue about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The TAR probed.
    pub tar: u32,
    /// What the card did with it.
    pub verdict: Verdict,
}

impl Probe {
    /// This probe as one `tar.probes[]` object.
    pub fn to_json(&self) -> Value {
        let body_len = match self.verdict {
            Verdict::Accepted { body_len, .. } => body_len,
            Verdict::Refused { .. } => 0,
        };
        json!({
            "tar": hex(self.tar),
            "tar_decimal": self.tar,
            "outcome": self.verdict.id(),
            "status": self.verdict.status().map(|status| status.to_string()),
            "response_octets": self.verdict.status().is_some() as usize + body_len,
        })
    }
}

/// Everything one TAR audit concluded, and everything it did not.
///
/// **Nothing here is a finding.** The rule is
/// `gsma/msl-zero-allowed` and it lives in [`crate::scan`]; this is the
/// measurement under it. An accepted TAR other than zero is *reported* here and
/// is not raised as a finding, because no rule ID has been agreed for "this
/// card's TAR allow-list is wider than expected" and inventing one under the
/// MSL=0 ID would be the same category of mistake as flipping the exit code
/// without moving the table that describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audit {
    /// What was asked for.
    pub selection: Selection,
    /// The TARs probed, in the order they were probed.
    pub probes: Vec<Probe>,
    /// The response this card gives to TARs it has no opinion about.
    pub baseline: Baseline,
    /// Whether the selection was exhausted.
    ///
    /// False means the probe budget fired and there were TARs left. The whole
    /// audit is then partial, and every finding raised from it says so.
    pub exhausted: bool,
    /// Why the audit stopped early, when it did.
    pub stopped: Option<String>,
    /// How many exchanges the probes took, for a report an operator can cost
    /// out before re-running one.
    pub exchanges: usize,
}

impl Audit {
    /// An audit of nothing, for a scan that did not probe.
    pub fn not_run(reason: impl Into<String>) -> Self {
        Self {
            selection: Selection::default(),
            probes: Vec::new(),
            baseline: Baseline::of(&[]),
            exhausted: true,
            stopped: Some(reason.into()),
            exchanges: 0,
        }
    }

    /// Whether this audit looked at everything it was asked to look at.
    ///
    /// False when the probe budget fired or the scan was interrupted. **A
    /// finding raised from a partial audit is still true**; what cannot be
    /// claimed is that the card holds no other accepted TAR, and that is what
    /// [`crate::rules::Coverage::Partial`] carries.
    pub fn is_complete(&self) -> bool {
        self.stopped.is_none() && self.exhausted
    }

    /// The TARs the card accepted.
    pub fn accepted(&self) -> impl Iterator<Item = u32> + '_ {
        self.probes
            .iter()
            .filter(|probe| probe.verdict.is_accepted())
            .map(|probe| probe.tar)
    }

    /// How many TARs the card accepted.
    pub fn accepted_count(&self) -> usize {
        self.probes
            .iter()
            .filter(|probe| probe.verdict.is_accepted())
            .count()
    }

    /// Whether TAR zero was accepted, which is MSL 0.
    ///
    /// **Named, not inferred.** A card at MSL 0 executes any command under any
    /// TAR with no cryptographic verification, and TAR zero is the one value
    /// that says so by definition; every other accepted TAR is a different
    /// problem with a different rule ID that has not been agreed.
    pub fn msl_zero_allowed(&self) -> bool {
        self.probes
            .iter()
            .any(|probe| probe.tar == TAR_MIN && probe.verdict.is_accepted())
    }

    /// What to say about this audit when it could not decide anything.
    ///
    /// `None` when it could, which is the only case in which a TAR result may
    /// be reported at all.
    pub fn blind_spot(&self) -> Option<&'static str> {
        if matches!(self.selection.mode, Mode::Off) || self.probes.is_empty() {
            return None;
        }
        if !self.baseline.is_established() {
            return Some(
                "every calibration probe answered the same, or with no status word at all, so this card's answer to an ACCEPTED TAR cannot be told apart from its answer to an UNKNOWN one; no TAR is reported as accepted, and that is not a clean card",
            );
        }
        if !self.is_complete() {
            return Some("the TAR scan did not finish, so the TARs it did not probe are neither accepted nor refused");
        }
        None
    }

    /// The `tar` block a scan report carries.
    pub fn to_json(&self) -> Value {
        let mut histogram = serde_json::Map::new();
        for (signature, count) in self.baseline.histogram() {
            histogram.insert(signature.to_string(), json!(count));
        }

        let accepted: Vec<Value> = self
            .accepted()
            .map(|tar| json!({ "tar": hex(tar), "tar_decimal": tar }))
            .collect();

        let mut block = json!({
            "selection": self.selection.mode.id(),
            "selection_detail": self.selection.to_string(),
            "class": self.selection.class.id(),
            "class_octet": format!("{:02X}", self.selection.class.octet()),
            "class_assumption": CLASS_ASSUMPTION,
            "max_probes": MAX_PROBES,
            "probed": self.probes.len(),
            "exchanges": self.exchanges,
            "exhausted": self.exhausted,
            "complete": self.is_complete(),
            "stopped": self.stopped,
            "calibration_probes": self.baseline.sampled(),
            "baseline": match self.baseline.signature() {
                Some(signature) => json!({
                    "established": true,
                    "status": signature.status().map(|status| status.to_string()),
                    "response_octets": signature.body_len(),
                    "count": self.baseline.count(),
                    "histogram": histogram,
                }),
                None => json!({
                    "established": false,
                    "status": Value::Null,
                    "response_octets": 0,
                    "count": 0,
                    "histogram": histogram,
                }),
            },
            "accepted": accepted,
            "accepted_count": self.accepted_count(),
            "msl_zero_allowed": self.msl_zero_allowed(),
            "blind_spot": self.blind_spot(),
            "probes": self.probes.iter().map(Probe::to_json).collect::<Vec<Value>>(),
        });
        if let Some(object) = block.as_object_mut() {
            object.insert("probes".to_owned(), json!(self.probe_sample()));
        }
        block
    }

    /// The per-TAR probe records a report carries, bounded.
    ///
    /// **Bounded on purpose.** `probes` is capped at
    /// [`MAX_PROBES`] entries, and even that is more than a human reads in a
    /// CI log. The first `MAX_PROBE_SAMPLE`] are reported, and
    /// `probes_shown` says how many there were, so a reader can tell a
    /// truncated sample from a short scan.
    pub fn probe_sample(&self) -> Vec<Value> {
        self.probes
            .iter()
            .take(MAX_PROBE_SAMPLE)
            .map(Probe::to_json)
            .collect()
    }

    /// The TAR block as a person reads it.
    pub fn to_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "TAR SELECTION: {} at CLA {}",
            self.selection, self.selection.class
        ));
        if matches!(self.selection.class, Class::Etsi) {
            out.push_str(NEWLINE);
            out.push_str("  NOTE: ");
            out.push_str(CLASS_ASSUMPTION);
            out.push_str(NEWLINE);
        }

        // **No probes is a different state from zero TARs accepted, and it is
        // printed as one sentence rather than as an empty result.** A reader
        // who saw "TAR PROBES: 0" next to "TAR BASELINE: not established"
        // would be reading two warnings about a card; what happened is that
        // no TAR was probed at all, and that is a fact about the scan.
        if self.probes.is_empty() {
            out.push_str(NEWLINE);
            out.push_str("TAR SCAN: NOT RUN");
            if let Some(reason) = self.stopped.as_deref() {
                out.push_str(" - ");
                out.push_str(reason);
            }
            out.push_str(NEWLINE);
            return out;
        }

        out.push_str(NEWLINE);
        out.push_str(&format!(
            "TAR PROBES: {} (cap {}, {} exchange(s))",
            self.probes.len(),
            MAX_PROBES,
            self.exchanges
        ));
        out.push_str(NEWLINE);
        for probe in self.probes.iter().take(MAX_PROBE_SAMPLE) {
            out.push_str(&format!(
                "  {}  {}  status {}",
                hex(probe.tar),
                probe.verdict.id(),
                probe
                    .verdict
                    .status()
                    .map_or_else(|| "(none)".to_owned(), |status| status.to_string())
            ));
            out.push_str(NEWLINE);
        }
        if self.probes.len() > MAX_PROBE_SAMPLE {
            out.push_str(&format!(
                "  ... and {} more; a report lists at most {} of them",
                self.probes.len() - MAX_PROBE_SAMPLE,
                MAX_PROBE_SAMPLE
            ));
            out.push_str(NEWLINE);
        }

        out.push_str(NEWLINE);
        out.push_str(&format!("TAR BASELINE: {}", self.baseline));
        out.push_str(NEWLINE);
        out.push_str(&format!(
            "  from {} calibration probe(s): this is the answer a TAR the card has no opinion about gets",
            self.baseline.sampled()
        ));
        out.push_str(NEWLINE);
        if !self.baseline.is_established() {
            out.push_str(
                "  !! A TAR SCAN WITH NO BASELINE CANNOT DISTINGUISH ACCEPTED FROM REFUSED.",
            );
            out.push_str(NEWLINE);
        }

        let accepted = self.accepted_count();
        out.push_str(NEWLINE);
        out.push_str(&format!("TARs ACCEPTED: {accepted}"));
        out.push_str(NEWLINE);
        if accepted == 0 {
            out.push_str("  (none)");
            out.push_str(NEWLINE);
        }
        for tar in self.accepted() {
            out.push_str(&format!("  {}", hex(tar)));
            out.push_str(NEWLINE);
        }
        out.push_str(NEWLINE);
        out.push_str(&format!(
            "MSL 0 (TAR 000000 accepted): {}",
            yes_no(self.msl_zero_allowed())
        ));
        out.push_str(NEWLINE);

        if let Some(reason) = self.stopped.as_deref() {
            out.push_str(&format!("!! TAR scan did not finish: {reason}"));
            out.push_str(NEWLINE);
        }
        if let Some(reason) = self.blind_spot() {
            out.push_str("!! ");
            out.push_str(reason);
            out.push_str(NEWLINE);
        }
        out
    }
}

/// How many per-TAR records a report lists.
///
/// Sixty-four, the same number as [`crate::rules::MAX_EVIDENCE_BYTES`, and
/// for the same reason: a bound a reader can predict beats no bound at all.
pub const MAX_PROBE_SAMPLE: usize = 64;

/// Yes or no, in the two words this report uses everywhere else.
fn yes_no(yes: bool) -> &'static str {
    if yes {
        "yes"
    } else {
        "no"
    }
}

/// Everything that can go wrong while putting a TAR on a card.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The envelope could not be built.
    ///
    /// Unreachable with the constants this module ships - the envelope is
    /// [`PROBE_ENVELOPE_LEN`] octets and every field is fixed size - but a
    /// rule that cannot answer has to say so rather than probe nothing in
    /// silence.
    #[error("the SMS-PP-DOWNLOAD envelope for this TAR could not be built: {0}")]
    UnbuildableEnvelope(&'static str),

    /// The reader reported a failure.
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// A response could not be parsed as an ISO/IEC 7816-4 response.
    #[error(transparent)]
    Response(#[from] crate::apdu::ParseError),
}

/// Why the probe loop stopped before the selection ran out.
///
/// Reported rather than swallowed, because each of these leaves the card in a
/// state a caller has to know about before it does anything else with it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Stop {
    /// The caller asked to stop (SIGINT).
    Interrupted,

    /// The card is not accepting envelopes in the shape this module sends.
    ///
    /// **The scan stops here rather than continuing**, because the alternative
    /// is to keep sending into a card that is not answering: the card may be
    /// holding half a command, and every later probe would then be answering
    /// about the wrong TAR.
    CardNotAnswering(String),

    /// The reader failed mid-scan.
    Reader(String),
}

/// One ENVELOPE exchange's worth of answer, reduced to what the differential
/// needs.
#[derive(Debug)]
struct Reply {
    signature: Signature,
    exchanges: usize,
}

/// Sends one TAR to a card and reads what it says.
///
/// **Two exchanges, deliberately.** The opening is the five octets
/// `CLA INS P1 P2 Lc`; a card that answers with a procedure byte is then sent
/// exactly `Lc` octets, and the status word it answers that with is the one
/// this TAR is judged on.
///
/// Three things are refused rather than guessed at, because guessing is how a
/// scanner leaves a card holding half a command:
///
/// 1. **A procedure byte whose length is not the envelope's.** The card wants
///    a different amount of data than this module has, so sending the envelope
///    anyway would corrupt the exchange.
/// 2. **No status word at all after the data.** There is nothing to compare,
///    and continuing would mean treating silence as an answer.
/// 3. **A status word that is an error is an answer like any other.** A card
///    refusing the envelope is evidence; refusing to record it because it is
///    unwelcome is how a scanner misses the thing it was built to find.
///
/// Nothing here retries. Every extra exchange is one the card asked for.
fn probe<S: CardSession + ?Sized>(
    session: &mut S,
    tar: u32,
    class: Class,
    policy: &Policy,
) -> Result<Result<Reply, String>, Error> {
    let Some((opening, data)) = envelope_exchange(tar, class) else {
        return Err(Error::UnbuildableEnvelope(
            "the SMS-PP-DOWNLOAD envelope does not fit a short APDU data field",
        ));
    };

    // 1. The opening.
    let first = session.transmit(&opening)?;
    let first = Response::parse(&first)?;

    let Some(requested) = advertised_data_octets(&first) else {
        // The card answered without asking for the data, which means it is not
        // running the envelope protocol this module speaks. Its answer is
        // returned as-is rather than inventing a second exchange.
        return Ok(Ok(Reply {
            signature: Signature::of(&first),
            exchanges: 1,
        }));
    };

    if requested != data.len() {
        return Ok(Err(format!(
            "the card asked for {requested} octets of envelope data and this tool has {}; \
             the exchange was abandoned rather than sent mismatched",
            data.len()
        )));
    }

    // 2. The data, in one block of exactly the size the card named.
    let second = session.transmit(&data)?;
    let second = Response::parse(&second)?;

    if second.status().is_none() {
        return Ok(Err(
            "the card answered the envelope data with a procedure byte rather than a status \
             word; the scan stopped rather than leave the card mid-command"
                .to_owned(),
        ));
    }

    let mut exchanges = 2;

    // 3. swSIM rewrites a completed command's 9000 into 91 <length> whenever a
    //    proactive command is waiting, and the NEXT command answers
    //    differently depending on whether it was drained. So it is drained here
    //    rather than left for the next probe to trip over - the swSIM
    //    behaviour AGENTS.md section 2 records, read here for what it is
    //    rather than as a failure. The FETCH goes through [crate::session] so
    //    the follow-up policy is the tested one.
    if matches!(
        second.status().map(StatusWord::sw1),
        Some(0x91 | 0x92 | 0x93)
    ) {
        let Some(length) = second
            .status()
            .and_then(StatusWord::proactive_command_length)
        else {
            return Ok(Err(
                "the card signalled a pending proactive command with a length this crate will \
                 not guess at; the scan stopped rather than leave it undrained"
                    .to_owned(),
            ));
        };
        let Some(le) = Le::for_byte_count(u32::from(length)) else {
            return Ok(Err(
                "the pending proactive command advertised a length no Le can express; the scan \
                 stopped rather than leave it undrained"
                    .to_owned(),
            ));
        };
        let _ = session::send(session, &Command::fetch(CLA_FETCH_ETSI, le), policy);
        exchanges += 1;
    }

    Ok(Ok(Reply {
        signature: Signature::of(&second),
        exchanges,
    }))
}

/// How many data octets a card is asking for, or None if it is not asking.
///
/// **Only SW1 `61` counts.** That is ISO/IEC 7816-4 clause 9.1.1's ACK-ALL
/// form, and it is what swSIM's ENVELOPE handler emits
/// (`SWICC_APDU_SW1_PROC_ACK_ALL`, [V] swSIM `src/apduh.c`,
/// `apduh_etsi_cat_envelope`). A `9x` is deliberately not counted: on this
/// card a `9x` means a proactive command is pending, and answering one with
/// an envelope's worth of bytes would be a different exchange entirely.
fn advertised_data_octets(response: &Response) -> Option<usize> {
    let advertised = response.status()?.response_data_length()?;
    Some(usize::try_from(advertised).unwrap_or(usize::MAX))
}

/// Probes a card's TAR accept-list and reports what it found.
///
/// **Bounded twice.** By the selection, and by the caller: `interrupt` is
/// polled before every calibration probe and before every probe, so a SIGINT
/// during a long sweep is acted on rather than queued. The caller turns the
/// `stopped` this produces into exit 130 **before rendering anything**, which
/// is the checkpoint rule in AGENTS.md section 3.
///
/// **Nothing is retried and nothing is re-ordered.** The probes are in the
/// order the selection produced them, so two runs of the same card against the
/// same selection produce the same audit.
pub fn audit<S: CardSession + ?Sized>(
    session: &mut S,
    selection: &Selection,
    policy: &Policy,
    interrupt: &mut dyn FnMut() -> bool,
) -> Result<Audit, Error> {
    if matches!(selection.mode, Mode::Off) {
        return Ok(Audit {
            selection: selection.clone(),
            probes: Vec::new(),
            baseline: Baseline::of(&[]),
            exhausted: true,
            stopped: Some("the operator asked for no TAR probing".to_owned()),
            exchanges: 0,
        });
    }

    let (tars, selection_exhausted) = candidates(selection, MAX_PROBES);
    let mut exchanges = 0usize;
    let mut halted: Option<Stop> = None;

    if tars.is_empty() {
        return Ok(Audit {
            selection: selection.clone(),
            probes: Vec::new(),
            baseline: Baseline::of(&[]),
            exhausted: selection_exhausted,
            stopped: Some(format!("the selection {selection} matched no TAR")),
            exchanges: 0,
        });
    }

    // 1. The calibration pass, which is what makes the differential possible.
    let mut calibration: Vec<Option<Signature>> = Vec::with_capacity(CALIBRATION_PROBES);
    for tar in CALIBRATION_TARS {
        if interrupt() {
            halted = Some(Stop::Interrupted);
            break;
        }
        match probe(session, tar, selection.class, policy) {
            Ok(Ok(reply)) => {
                exchanges += reply.exchanges;
                calibration.push(Some(reply.signature));
            }
            Ok(Err(reason)) => {
                exchanges += 2;
                halted = Some(Stop::CardNotAnswering(reason));
                break;
            }
            Err(Error::Transport(err)) => {
                halted = Some(Stop::Reader(err.to_string()));
                break;
            }
            Err(other) => return Err(other),
        }
    }

    let baseline = Baseline::of(&calibration);

    // 2. The probes themselves.
    let mut probes = Vec::with_capacity(tars.len());
    if halted.is_none() {
        for tar in tars {
            if interrupt() {
                halted = Some(Stop::Interrupted);
                break;
            }
            match probe(session, tar, selection.class, policy) {
                Ok(Ok(reply)) => {
                    exchanges += reply.exchanges;
                    let verdict = if baseline.refuses(&reply.signature) {
                        Verdict::Refused {
                            status: reply.signature.status(),
                        }
                    } else {
                        Verdict::Accepted {
                            status: reply.signature.status(),
                            body_len: reply.signature.body_len(),
                        }
                    };
                    probes.push(Probe { tar, verdict });
                }
                Ok(Err(reason)) => {
                    halted = Some(Stop::CardNotAnswering(reason));
                    break;
                }
                Err(Error::Transport(err)) => {
                    halted = Some(Stop::Reader(err.to_string()));
                    break;
                }
                Err(other) => return Err(other),
            }
        }
    }

    let exhausted = selection_exhausted && halted.is_none();
    let stopped = if exhausted {
        None
    } else if let Some(reason) = halted {
        Some(match reason {
            Stop::Interrupted => "the scan was interrupted".to_owned(),
            Stop::CardNotAnswering(reason) => {
                format!("the card stopped answering envelopes: {reason}")
            }
            Stop::Reader(reason) => format!("the reader failed: {reason}"),
        })
    } else {
        Some(format!(
            "the probe budget of {MAX_PROBES} TARs was reached and the selection had more"
        ))
    };

    Ok(Audit {
        selection: selection.clone(),
        probes,
        baseline,
        exhausted,
        stopped,
        exchanges,
    })
}

/// Both halves of one probe's APDU, as a person reads them.
///
/// Exists so a report can name what was sent and a test can prove the wire
/// sequence without a card. Not a shortcut around [probe], which is the only
/// thing that puts bytes on a wire.
pub fn describe_exchange(tar: u32, class: Class) -> String {
    match envelope_exchange(tar, class) {
        Some((opening, data)) => format!("{}  /  {}", octets(&opening), octets(&data)),
        None => "(could not be built)".to_owned(),
    }
}

/// A newline, named so a long block of pushed fragments reads as text.
const NEWLINE: &str = "\n";

/// Octets as spaced uppercase hex, the form every other log here uses.
fn octets(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|octet| format!("{octet:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::collections::VecDeque;

    use crate::transport::{Error as TransportError, ReaderName};

    /// A card that answers from a script and records everything it was sent.
    ///
    /// Doubles as the proof that the TAR scanner is testable with no reader,
    /// no daemon and no card - the property AGENTS.md section 2 asks for, and
    /// the only reason the rule can be tested at all before a fixture is
    /// wired up.
    struct Scripted {
        reader: ReaderName,
        replies: VecDeque<Vec<u8>>,
        sent: RefCell<Vec<Vec<u8>>>,
        released: bool,
    }

    impl Scripted {
        /// Answers @BT@script@BT@ in order, repeating the last reply once the
        /// script runs out so a runaway loop is bounded by the policy rather
        /// than by the fake's patience.
        fn new(script: &[&[u8]]) -> Self {
            let mut replies: VecDeque<Vec<u8>> = script.iter().map(|r| r.to_vec()).collect();
            if let Some(last) = script.last() {
                for _ in 0..8 {
                    replies.push_back(last.to_vec());
                }
            }
            Self {
                reader: ReaderName::new("loopback").expect("a reader name"),
                replies,
                sent: RefCell::new(Vec::new()),
                released: false,
            }
        }

        /// Every command this card was sent, in order.
        fn sent(&self) -> Vec<Vec<u8>> {
            self.sent.borrow().clone()
        }
    }

    impl CardSession for Scripted {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }

        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.sent.borrow_mut().push(command.to_vec());
            Ok(self.replies.pop_front().unwrap_or_else(|| vec![0x6D, 0x00]))
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            self.released = true;
            Ok(())
        }
    }

    /// No interrupt, ever.
    fn never() -> bool {
        false
    }

    fn signature(sw1: u8, sw2: u8) -> Option<Signature> {
        let bytes = vec![sw1, sw2];
        Some(Signature::of(
            &Response::parse(&bytes).expect("two octets are a response"),
        ))
    }

    // -----------------------------------------------------------------------
    // The wire bytes, pinned against SIMTester's constants
    // -----------------------------------------------------------------------

    /// The Command Packet is built exactly as
    /// [`CommandPacket._formatMessage`](https://github.com/srlabs/SIMTester/blob/d197fef/SIMLibrary/src/de/srlabs/simlib/CommandPacket.java)
    /// builds it at the pinned commit.
    ///
    /// Every octet below is traceable to a constant in that file, quoted in
    /// the module: CPH 02 70 00, CPL 00 15, CHL 0D, SPI1 00, SPI2 29, KIC and
    /// KID 00, the three TAR octets, CNTR 00 00 00 00 01, PCNTR 00 and the
    /// seven-octet user data.
    #[test]
    fn the_command_packet_is_the_one_simtester_builds() {
        assert_eq!(
            spaced(&command_packet(0x00_00_00)),
            "02 70 00 00 15 0D 00 29 00 00 00 00 00 00 00 00 00 01 00 A0 A4 00 00 02 3F 00"
        );
    }

    /// Only the three TAR octets move, and they move in the right three
    /// places - the packet is not rebuilt from a template that happens to have
    /// the TAR somewhere else.
    #[test]
    fn the_tar_is_where_simtester_puts_it() {
        let zero = command_packet(0x00_00_00);
        let some = command_packet(0xAB_CD_EF);
        assert_eq!(
            &zero[10..13],
            &[0x00, 0x00, 0x00],
            "SPI1 SPI2 KIC KID TAR: the TAR is octets 9..12"
        );
        assert_eq!(&some[10..13], &[0xAB, 0xCD, 0xEF]);
        assert_eq!(zero.len(), some.len());
        assert_eq!(zero.iter().filter(|b| **b == 0xA0).count(), 1);
    }

    /// The SMS-DELIVER TPDU is built as [`SMSDeliverTPDU.getBytes`](https://github.com/srlabs/SIMTester/blob/d197fef/SIMLibrary/src/de/srlabs/simlib/SMSDeliverTPDU.java)
    /// builds it: first octet 44, TP-OA 05 00 21 43 F5, TP-PID 7F, TP-DCS F6,
    /// seven zero SCTS octets, TP-UDL and then the packet.
    #[test]
    fn the_tpdu_is_the_one_simtester_builds() {
        let packet = command_packet(0x00_00_00);
        let tpdu = sms_deliver_tpdu(&packet).expect("26 octets fits TP-UDL");
        assert_eq!(tpdu.len(), 1 + 5 + 1 + 1 + 7 + 1 + packet.len());
        assert_eq!(
            &tpdu[..16],
            &[
                0x44, 0x05, 0x00, 0x21, 0x43, 0xF5, 0x7F, 0xF6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x1A
            ]
        );
        assert_eq!(&tpdu[16..], &packet[..]);
    }

    /// The whole ENVELOPE, and the two exchanges it is sent as.
    ///
    /// **The split is the assertion that matters here.** [`apduh_etsi_cat_envelope`]
    /// answers the opening with @BT@61 Lc@BT@ and returns before reading the
    /// data field, so the data cannot be in the opening: an exchange that put
    /// it there would leave this card holding half a command.
    #[test]
    fn the_envelope_is_two_exchanges_and_never_one() {
        let (opening, data) = envelope_exchange(0x00_00_00, Class::Etsi).expect("built");

        // CLA 80, INS C2, P1 00, P2 00, Lc 3A - and nothing else.
        assert_eq!(opening, vec![0x80, 0xC2, 0x00, 0x00, 0x3A]);
        assert_eq!(
            opening.len(),
            5,
            "the opening declares Lc and carries no data: swSIM sends 61 Lc \
             back and reads nothing until the next exchange"
        );
        assert_eq!(
            usize::from(opening[4]),
            data.len(),
            "the Lc the opening declares is the length of the data that follows"
        );
        assert_eq!(data.len(), PROBE_ENVELOPE_LEN);
        assert_eq!(data[0], TAG_SMS_PP_DOWNLOAD, "D1, SMS-PP-DOWNLOAD");
        assert_eq!(data[1] as usize, data.len() - 2, "short-form TLV length");

        // The device identities, the address and then the TPDU, in that order.
        assert_eq!(&data[2..6], &DEVICE_IDENTITIES_3G);
        assert_eq!(&data[6..16], &ADDRESS_3G);
        assert_eq!(data[16], SMS_DELIVER_FIRST_OCTET);
    }

    /// The 2G class changes only the class byte, the device identities and the
    /// address, and the envelope is otherwise identical.
    #[test]
    fn the_gsm_class_is_the_same_envelope_addressed_differently() {
        let (etsi, etsi_data) = envelope_exchange(0x00_00_00, Class::Etsi).expect("built");
        let (gsm, gsm_data) = envelope_exchange(0x00_00_00, Class::Gsm).expect("built");
        assert_eq!(etsi[0], Class::Etsi.octet());
        assert_eq!(gsm[0], Class::Gsm.octet());
        assert_eq!(etsi[1..], gsm[1..]);
        assert_ne!(etsi_data, gsm_data);
        assert_eq!(etsi_data[2..16], gsm_data[2..16]);
        // The TAR is in the same place in both, because only the addressing
        // changed - a TAR scanner that missed the second class would be a TAR
        // scanner that did not look.
        assert_eq!(
            etsi_data
                .windows(3)
                .position(|w| w == [0x00, 0x00, 0x00])
                .map(|at| etsi_data[at..at + 3] == gsm_data[at..at + 3]),
            Some(true)
        );
    }

    /// The length encoding is TS 101 220 clause 7.1.2, the same one
    /// [`InnerTLV`](https://github.com/srlabs/SIMTester/blob/d197fef/SIMLibrary/src/de/srlabs/simlib/InnerTLV.java)
    /// writes and the same one this crate's `tlv` module accepts.
    #[test]
    fn inner_tlv_uses_the_three_length_forms() {
        assert_eq!(inner_tlv(0xD1, &[0u8; 0]).unwrap(), vec![0xD1, 0x00]);
        assert_eq!(inner_tlv(0xD1, &[0u8; 127]).unwrap()[..2], [0xD1, 0x7F]);
        assert_eq!(
            inner_tlv(0xD1, &[0u8; 128]).unwrap()[..3],
            [0xD1, 0x81, 0x80]
        );
        assert_eq!(
            inner_tlv(0xD1, &[0u8; 255]).unwrap()[..3],
            [0xD1, 0x81, 0xFF]
        );
        assert_eq!(
            inner_tlv(0xD1, &[0u8; 256]).unwrap()[..4],
            [0xD1, 0x82, 0x01, 0x00]
        );
    }

    // -----------------------------------------------------------------------
    // Selection: ranged and regex both work, with no card
    // -----------------------------------------------------------------------

    #[test]
    fn selection_parses_every_form_it_documents() {
        let off: Selection = "off".parse().expect("off");
        assert_eq!(off.mode, Mode::Off);
        assert_eq!(off.to_string(), "off");

        let focused: Selection = "focused".parse().expect("focused");
        assert_eq!(focused.mode, Mode::Focused);
        assert_eq!(focused.class, Class::Etsi);

        let full: Selection = "full".parse().expect("full");
        assert_eq!(full.mode, Mode::Full);

        let ranged: Selection = "range:000000-0000FF".parse().expect("range");
        assert_eq!(
            ranged.mode,
            Mode::Range {
                first: 0,
                last: 0xFF
            }
        );
        assert_eq!(ranged.to_string(), "range:000000-0000FF");

        let prefixed: Selection = "range:0x10-0x1F".parse().expect("0x is accepted");
        assert_eq!(
            prefixed.mode,
            Mode::Range {
                first: 0x10,
                last: 0x1F
            }
        );

        let upper: Selection = "RANGE:ABCDEF-ABCDEF".parse().expect("case insensitive");
        assert_eq!(
            upper.mode,
            Mode::Range {
                first: 0xAB_CDEF,
                last: 0xAB_CDEF
            }
        );

        let regexed: Selection = "regex:^EDR$".parse().expect("a pattern");
        assert!(matches!(regexed.mode, Mode::Regex { .. }));
        assert_eq!(regexed.to_string(), "regex:^EDR$");
    }

    #[test]
    fn a_selection_it_cannot_honour_is_refused_with_the_grammar_in_the_message() {
        for bad in [
            "",
            "sweep",
            "range:",
            "range:ZZ",
            "range:000000",
            "range:000000-",
            "range:000000-0000FF-0000FF",
            "range:FFFFFF-000000",
            "regex:",
            "regex:[",
        ] {
            let refused = bad.parse::<Selection>().unwrap_err().to_string();
            assert!(
                refused.contains("range:FIRST-LAST") && refused.contains("regex:PATTERN"),
                "{bad:?} must be refused with the grammar: {refused}"
            );
        }
    }

    /// **Issue #24 acceptance criterion 2: ranged selection works, and it is
    /// unit-tested with no card.** Inclusive at both ends.
    #[test]
    fn a_ranged_selection_is_inclusive_at_both_ends() {
        let selection: Selection = "range:000010-000012".parse().expect("range");
        let (tars, exhausted) = candidates(&selection, MAX_PROBES);
        assert_eq!(tars, vec![0x10, 0x11, 0x12]);
        assert!(exhausted);
    }

    /// **Issue #24 acceptance criterion 2: regex selection works.** The
    /// pattern is matched against the six-hex-digit spelling, so @BT@^EDR$@BT@ is
    /// one TAR and not "anything containing EDR".
    #[test]
    fn a_regex_selection_matches_the_six_digit_spelling() {
        let selection: Selection = "regex:^EDR$".parse().expect("a pattern");
        let (tars, exhausted) = candidates(&selection, MAX_PROBES);
        assert_eq!(tars, vec![0x00_45_44_52]);
        assert!(exhausted, "the space was swept and nothing was left over");

        // And one that matches nothing says so rather than silently returning
        // the whole space.
        let none: Selection = "regex:^QQQ$".parse().expect("a pattern");
        let (tars, exhausted) = candidates(&none, MAX_PROBES);
        assert!(tars.is_empty());
        assert!(exhausted);
    }

    #[test]
    fn the_focused_default_is_inside_the_probe_bound() {
        let (tars, exhausted) = candidates(&Selection::default(), MAX_PROBES);
        assert_eq!(tars.len(), FOCUSED_PROBES);
        assert!(exhausted);
        assert!(
            FOCUSED_PROBES <= MAX_PROBES,
            "the default set has to fit inside the bound or it is not a default"
        );
        assert_eq!(tars[0], TAR_MIN, "MSL 0 is in the default set");
        assert!(
            tars.windows(2).all(|w| w[0] < w[1]),
            "the focused bands are ascending and do not overlap"
        );
        assert!(
            tars.contains(&0xBF_FF_FF),
            "the all-B band is in there"
        );
    }

    #[test]
    fn off_probes_nothing() {
        let off: Selection = "off".parse().expect("off");
        let (tars, exhausted) = candidates(&off, MAX_PROBES);
        assert!(tars.is_empty());
        assert!(exhausted);
    }

    /// **The bound is a real bound.** `full` is not 16 777 216 probes; it is
    /// [`MAX_PROBES`] and says it stopped.
    #[test]
    fn a_full_selection_stops_at_the_probe_bound_and_says_so() {
        let full: Selection = "full".parse().expect("full");
        let (tars, exhausted) = candidates(&full, MAX_PROBES);
        assert_eq!(tars.len(), MAX_PROBES);
        assert!(
            !exhausted,
            "a full sweep has TARs left over and must say so"
        );
        assert_eq!(tars[0], TAR_MIN);
        assert_eq!(*tars.last().expect("non-empty"), (MAX_PROBES - 1) as u32);
    }

    /// The bound holds even when a caller asks for more than it is allowed.
    #[test]
    fn the_bound_is_not_the_callers_to_raise() {
        let full: Selection = "full".parse().expect("full");
        let (tars, exhausted) = candidates(&full, 10 * MAX_PROBES);
        assert_eq!(tars.len(), MAX_PROBES);
        assert!(!exhausted);
    }

    // -----------------------------------------------------------------------
    // The differential
    // -----------------------------------------------------------------------

    #[test]
    fn the_baseline_is_the_most_common_calibration_response() {
        let baseline = Baseline::of(&[
            signature(0x94, 0x04),
            signature(0x94, 0x04),
            signature(0x94, 0x04),
            signature(0x6D, 0x00),
        ]);
        assert!(baseline.is_established());
        assert_eq!(baseline.count(), 3);
        assert_eq!(baseline.sampled(), 4);
        assert!(baseline.refuses(&signature(0x94, 0x04).expect("built")));
        assert!(!baseline.refuses(&signature(0x6D, 0x00).expect("built")));
    }

    /// **A tie is no baseline, and no baseline refuses nothing.** Picking one
    /// of two equally common responses would report every TAR that drew the
    /// other one.
    #[test]
    fn a_tied_baseline_refuses_nothing() {
        let baseline = Baseline::of(&[
            signature(0x94, 0x04),
            signature(0x94, 0x04),
            signature(0x6D, 0x00),
            signature(0x6D, 0x00),
        ]);
        assert!(!baseline.is_established());
        assert!(!baseline.refuses(&signature(0x94, 0x04).expect("built")));
        assert!(!baseline.refuses(&signature(0x6D, 0x00).expect("built")));
        assert!(baseline.to_string().contains("not established"));
    }

    /// A response with no status word never becomes the baseline. A card that
    /// has stopped answering coherently is not a card whose silence means
    /// "refused".
    #[test]
    fn a_silent_card_has_no_baseline() {
        let baseline = Baseline::of(&[None, None, signature(0x6D, 0x00)]);
        assert_eq!(baseline.count(), 1);
        assert!(baseline.is_established());
        assert!(baseline.refuses(&signature(0x6D, 0x00).expect("built")));

        let silent = Baseline::of(&[None, None, None]);
        assert!(!silent.is_established());
        assert_eq!(silent.sampled(), 3);
    }

    // -----------------------------------------------------------------------
    // The probe loop, against a card that answers from a script
    // -----------------------------------------------------------------------

    /// The happy path, and the shape of the exchange.
    ///
    /// The card answers the opening with @BT@61 3A@BT@ - the ACK-ALL procedure
    /// byte, one octet on the wire - and then a status word once it has the
    /// envelope.
    #[test]
    fn a_probe_is_the_opening_then_the_envelope_then_the_answer() {
        let mut card = Scripted::new(&[&[0x61, 0x3A], &[0x90, 0x00]]);
        let reply = probe(&mut card, 0, Class::Etsi, &Policy::default())
            .expect("no transport error")
            .expect("the card cooperated");

        let sent = card.sent();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0], vec![0x80, 0xC2, 0x00, 0x00, 0x3A]);
        assert_eq!(sent[1].len(), PROBE_ENVELOPE_LEN);
        assert_eq!(reply.exchanges, 2);
        assert_eq!(
            reply.signature.status().expect("a status").to_string(),
            "9000"
        );
    }

    /// **The invariant.** A card that asks for a different amount of data than
    /// the envelope holds is not sent a mismatched exchange, and the probe
    /// says so rather than continuing into a card that is mid-command.
    #[test]
    fn a_card_that_wants_a_different_length_stops_the_probe() {
        let mut card = Scripted::new(&[&[0x61, 0x10]]);
        let reason = probe(&mut card, 0, Class::Etsi, &Policy::default())
            .expect("no transport error")
            .expect_err("the card wanted 16 octets, not 58");
        assert!(reason.contains("16 octets"), "{reason}");
        assert!(
            reason.contains("abandoned rather than sent mismatched"),
            "{reason}"
        );
        assert_eq!(
            card.sent().len(),
            1,
            "the envelope was never sent into a card waiting for a different \
             length, because the next APDU would be swallowed as its \
             continuation"
        );
    }

    /// A card that never asks for the data has answered, and its answer is
    /// used. It is not a second exchange this tool invents.
    #[test]
    fn a_card_that_does_not_ask_for_data_is_taken_at_its_word() {
        let mut card = Scripted::new(&[&[0x6D, 0x00]]);
        let reply = probe(&mut card, 0, Class::Etsi, &Policy::default())
            .expect("no transport error")
            .expect("the card answered");
        assert_eq!(reply.exchanges, 1);
        assert_eq!(card.sent().len(), 1);
        assert_eq!(
            reply.signature.status().expect("a status").to_string(),
            "6D00"
        );
    }

    /// **AGENTS.md section 2's second fixture fact, obeyed.** A @BT@91 xx@BT@ is
    /// not a failure and is not a success: the card completed the command and
    /// is holding something, so it is drained before the next probe rather than
    /// left for the next probe to trip over.
    #[test]
    fn a_pending_proactive_command_is_drained_before_the_next_probe() {
        // Opening, 91 80 (a proactive command of 128 octets is pending), the
        // 128 data octets, then the FETCH and its answer.
        let fetch_answer = [0xD0u8, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00];
        let mut card = Scripted::new(&[&[0x61, 0x3A], &[0x91, 0x80], &fetch_answer]);
        let reply = probe(&mut card, 0, Class::Etsi, &Policy::default())
            .expect("no transport error")
            .expect("the card cooperated");

        let sent = card.sent();
        assert_eq!(sent.len(), 4, "opening, data, FETCH, FETCH answer");
        assert_eq!(
            &sent[2][..4],
            &[0x80, 0x12, 0x00, 0x00],
            "FETCH is CLA 80 INS 12 P1 00 P2 00, which is what swSIM routes"
        );
        assert_eq!(sent[2][4], 0x80, "Le equals the advertised length exactly");
        assert_eq!(
            reply.signature.status().expect("a status").to_string(),
            "9180",
            "the verdict is made on the envelope's own status word, not on the \
             drain"
        );
        assert_eq!(reply.exchanges, 3);
    }

    /// **A full audit against a card that answers every TAR the same way
    /// reports nothing accepted.** This is the property that keeps the rule
    /// from manufacturing findings on the swSIM fixture, which has no TAR
    /// check at all.
    #[test]
    fn a_card_that_answers_every_tar_identically_reports_nothing_accepted() {
        // 61 3A then 9000, forever.
        let mut card = Scripted::new(&[&[0x61, 0x3A], &[0x90, 0x00]]);
        let audit = audit(
            &mut card,
            &Selection::default(),
            &Policy::default(),
            &mut never,
        )
        .expect("no transport error");

        assert!(audit.baseline.is_established());
        assert_eq!(
            audit
                .baseline
                .signature()
                .expect("a baseline")
                .status()
                .expect("a status")
                .to_string(),
            "9000"
        );
        assert_eq!(audit.accepted_count(), 0);
        assert!(!audit.msl_zero_allowed(), "MSL 0 must not be reported");
        assert!(audit.is_complete());
        assert!(audit.blind_spot().is_none());
        assert_eq!(audit.probes.len(), FOCUSED_PROBES);
    }

    /// The other end: a card that answers TAR zero differently **is** reported
    /// as MSL 0, with the evidence beside it.
    #[test]
    fn a_card_that_answers_tar_zero_differently_is_msl_zero() {
        let mut card = SwimsMsZero::new();
        let selection: Selection = "range:000000-000003".parse().expect("range");
        let audit = audit(&mut card, &selection, &Policy::default(), &mut never)
            .expect("no transport error");

        assert_eq!(
            audit.baseline.signature().expect("a baseline").to_string(),
            "9404"
        );
        assert!(audit.msl_zero_allowed(), "TAR zero drew 6D00, not 9404");
        assert_eq!(
            audit.accepted().collect::<Vec<u32>>(),
            vec![0],
            "and nothing else did"
        );
        assert_eq!(
            audit.probes[0]
                .verdict
                .status()
                .expect("a status")
                .to_string(),
            "6D00"
        );
        assert_eq!(audit.probes[1].verdict.id(), "refused");
    }

    /// **The interrupt actually stops the scan**, and the audit says it did not
    /// finish rather than rendering a shorter one as a whole.
    #[test]
    fn an_interrupted_tar_scan_is_reported_as_interrupted_not_as_short() {
        let mut card = Scripted::new(&[&[0x61, 0x3A], &[0x90, 0x00]]);
        let mut calls = 0usize;
        let audit = audit(
            &mut card,
            &Selection::default(),
            &Policy::default(),
            &mut || {
                calls += 1;
                calls > 3
            },
        )
        .expect("no transport error");

        assert!(calls > 3, "the interrupt was polled, not ignored");
        assert!(!audit.is_complete());
        assert_eq!(audit.stopped.as_deref(), Some("the scan was interrupted"));
        assert_eq!(audit.probes.len(), 0, "it stopped during calibration");
    }

    /// A card that stops answering envelopes ends the scan with the reason,
    /// rather than this tool continuing to send into it.
    #[test]
    fn a_card_that_stops_answering_ends_the_scan_with_a_reason() {
        // 61 3A, then a procedure byte where a status word belongs.
        let mut card = Scripted::new(&[&[0x61, 0x3A], &[0x60]]);
        let audit = audit(
            &mut card,
            &Selection::default(),
            &Policy::default(),
            &mut never,
        )
        .expect("no transport error");

        assert!(!audit.is_complete());
        let stopped = audit.stopped.clone().expect("a reason");
        assert!(stopped.contains("mid-command"), "{stopped}");
        assert!(audit.blind_spot().is_some());
    }

    /// A reader that fails is an error, not a finding.
    #[test]
    fn a_reader_failure_is_reported_not_swallowed() {
        let mut card = Broken::new();
        let err = audit(
            &mut card,
            &Selection::default(),
            &Policy::default(),
            &mut never,
        )
        .expect_err("the reader is gone");
        assert!(matches!(err, Error::Transport(_)), "{err}");
    }

    /// The block a report carries names the bound, the baseline and the class
    /// it assumed, so a reader never has to take any of them on trust.
    #[test]
    fn the_report_block_carries_the_bound_the_class_and_the_baseline() {
        let mut card = Scripted::new(&[&[0x61, 0x3A], &[0x90, 0x00]]);
        let audit = audit(
            &mut card,
            &Selection::default(),
            &Policy::default(),
            &mut never,
        )
        .expect("no transport error");
        let block = audit.to_json();

        assert_eq!(block["selection"], "focused");
        assert_eq!(block["class"], "etsi");
        assert_eq!(block["class_octet"], "80");
        assert_eq!(block["class_assumption"], CLASS_ASSUMPTION);
        assert_eq!(block["max_probes"], MAX_PROBES);
        assert_eq!(block["probed"], FOCUSED_PROBES);
        assert_eq!(block["accepted_count"], 0);
        assert_eq!(block["msl_zero_allowed"], false);
        assert_eq!(block["baseline"]["established"], true);
        assert_eq!(block["baseline"]["status"], "9000");
        assert_eq!(block["baseline"]["histogram"]["9000"], 20);
        assert_eq!(block["blind_spot"], Value::Null);
        assert_eq!(block["complete"], true);
    }

    /// The per-probe list is bounded, and the block says how long it really is.
    #[test]
    fn the_probe_list_a_report_carries_is_bounded() {
        let mut card = Scripted::new(&[&[0x61, 0x3A], &[0x90, 0x00]]);
        let audit = audit(
            &mut card,
            &Selection::default(),
            &Policy::default(),
            &mut never,
        )
        .expect("no transport error");
        let block = audit.to_json();
        let listed = block["probes"].as_array().expect("an array");
        assert_eq!(listed.len(), MAX_PROBE_SAMPLE);
        assert!(
            listed.len() < audit.probes.len(),
            "a bounded list of a longer scan, not a truncated scan read as \
             the whole thing"
        );
        assert_eq!(block["probed"], FOCUSED_PROBES);
    }

    #[test]
    fn a_hex_tar_is_six_digits_whatever_its_value() {
        assert_eq!(hex(TAR_MIN), "000000");
        assert_eq!(hex(TAR_MAX), "FFFFFF");
        assert_eq!(hex(0x45_44_52), "454452");
        assert_eq!(hex(1), "000001");
    }

    #[test]
    fn an_audit_that_never_ran_says_so_in_one_line() {
        let audit = Audit::not_run("the caller attached nothing");
        let human = audit.to_human();
        assert!(human.contains("TAR SCAN: NOT RUN"), "{human}");
        assert!(!human.contains("NO BASELINE"), "{human}");
        assert!(human.contains("the caller attached nothing"), "{human}");
    }

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    /// A card that refuses every TAR with @BT@94 04@BT@ except TAR zero, which
    /// it answers with @BT@6D 00@BT@ - "instruction not supported", the answer
    /// a card gives once a command has got past any TAR check it has.
    ///
    /// **This is the shape of a real MSL=0 finding**, and it is the only place
    /// in this module where a TAR is expected to be accepted.
    struct SwimsMsZero {
        inner: Scripted,
    }

    impl SwimsMsZero {
        fn new() -> Self {
            Self {
                inner: Scripted::new(&[&[0x61, 0x3A]]),
            }
        }
    }

    impl CardSession for SwimsMsZero {
        fn reader(&self) -> &ReaderName {
            self.inner.reader()
        }

        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            // The opening is five octets and ends in Lc; the data exchange is
            // the one that carries a TAR, at the offset the envelope pins.
            let answer = if command.len() == 5 {
                vec![0x61, command[4]]
            } else if command.windows(3).any(|w| w == [0x00, 0x00, 0x00])
                && command[16] == SMS_DELIVER_FIRST_OCTET
                && is_zero_tar(command)
            {
                vec![0x6D, 0x00]
            } else {
                vec![0x94, 0x04]
            };
            self.inner.sent.borrow_mut().push(command.to_vec());
            Ok(answer)
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            self.inner.disconnect()
        }
    }

    /// Whether an ENVELOPE data field carries TAR zero.
    ///
    /// Spelled out rather than reusing a constant so this cannot accidentally
    /// track a change to the layout and quietly start answering wrongly.
    fn is_zero_tar(data: &[u8]) -> bool {
        let tpdu_at = 2 + 4 + 10;
        // TPDU: FO, TP-OA(5), TP-PID, TP-DCS, TP-SCTS(7), TP-UDL, then the CP:
        // CPH(3), CPL(2), CHL, SPI1, SPI2, KIC, KID, TAR(3).
        let tar_at = tpdu_at + 1 + 5 + 1 + 1 + 7 + 1 + 3 + 2 + 1 + 1 + 1 + 1 + 1;
        data.get(tar_at..tar_at + 3) == Some(&[0x00, 0x00, 0x00])
    }

    /// A reader that has gone away.
    /// A reader that has gone away.
    ///
    /// Carries its reader name in a field rather than rebuilding one per call,
    /// so the error it raises names one reader and not two.
    struct Broken {
        reader: ReaderName,
    }

    impl Broken {
        fn new() -> Self {
            Self {
                reader: ReaderName::new("broken").expect("a reader name"),
            }
        }
    }

    impl CardSession for Broken {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }

        fn transmit(&mut self, _: &[u8]) -> Result<Vec<u8>, TransportError> {
            Err(TransportError::CardGone {
                reader: self.reader.clone(),
            })
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }
    fn spaced(bytes: &[u8]) -> String {
        octets(bytes)
    }
}
