//! Elementary-file decoders: what the security-relevant EFs hold, as bounded,
//! full-value evidence.
//!
//! **Owns.** A map from a walked file to the decoder that reads it
//! ([`classify`]), the pure decoders over bytes ([`decode`]), and the one
//! read-only step that fetches the bytes ([`read`]: SELECT, READ BINARY and
//! READ RECORD, nothing else). Issues #108 and #102.
//!
//! **Does not own.** The tree ([`crate::walk`]), access conditions
//! ([`crate::access`], whose SELECT helper this reuses) or the rules that judge
//! a file ([`crate::scan`]).
//!
//! # Full visibility
//!
//! sim-doctor is an authorized tool run on the owner's own card, so nothing
//! here is masked: IMSI, ICCID and MSISDN show every digit, and EF.Keys,
//! EF.KeysPS (and any other key file) are read like any other EF with SELECT
//! and READ BINARY and shown as hex. A read the card refuses is reported with
//! its status word and never retried. Real card data is still never committed
//! to the repo; tests use synthetic values.
//!
//! # Sources
//!
//! Layouts are from 3GPP TS 31.102 (USIM) and ETSI TS 51.011 (SIM) and ETSI
//! TS 102 221, cited per decoder, cross-checked against pySim
//! (`osmocom/pysim@3c437d4`, `ts_31_102.py`, GPL: layouts read, code written
//! here). Each decoder's tests use bytes synthesised from the clause's layout.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "ef";

use std::fmt;

use serde_json::{json, Value};

use crate::access::{self, Access};
use crate::apdu::{Command, Header, Le};
use crate::fs::{FileId, Path};
use crate::session::{self, Policy};
use crate::tlv::Stream;
use crate::transport::CardSession;
use crate::walk::{ContentRead, Node, Tree};

/// The most records of one linear fixed EF read (EF.DIR and EF.MSISDN hold a
/// handful). A phonebook (EF.ADN, EF.FDN) is read only up to this many records.
const MAX_RECORDS: usize = 16;
/// The most octets of one transparent EF read. The longest decoded here is a
/// service table (19 octets covers 146 UST services).
const MAX_BINARY: u32 = 64;
/// The most items an evidence string lists before saying "+N more".
const EVIDENCE_ITEMS: usize = 24;

/// A decoder could not read the bytes it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed(pub &'static str);

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Decimal digits that identify a subscriber or a card.
///
/// Holds the whole value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Digits(String);

impl Digits {
    /// The full value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// How many digits.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no digits (an unprovisioned file).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The EFs this module understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ef {
    /// EF.ICCID `2FE2`, under the master file.
    Iccid,
    /// EF.DIR `2F00`, under the master file.
    Dir,
    /// EF.IMSI `6F07`.
    Imsi,
    /// EF.MSISDN `6F40`.
    Msisdn,
    /// EF.AD `6FAD`.
    Ad,
    /// EF.SPN `6F46`.
    Spn,
    /// EF.UST `6F38`, under an application.
    Ust,
    /// EF.EST `6F56`, under an application.
    Est,
    /// EF.Keys `6F08`, read as raw bytes.
    Keys,
    /// EF.KeysPS `6F09`, read as raw bytes.
    KeysPs,
    /// EF.FPLMN `6F7B`.
    Fplmn,
    /// EF.OPLMNwAcT `6F61`.
    OplmnWact,
    /// EF.HPLMNwAcT `6F62`.
    HplmnWact,
    /// EF.LOCI `6F7E`.
    Loci,
    /// EF.PSLOCI `6F73`.
    Psloci,
    /// EF.EPSLOCI `6FE3`.
    Epsloci,
    /// EF.ACC `6F78`.
    Acc,
    /// EF.ADN `6F3A`, or `4F3A` in a phonebook.
    Adn,
    /// EF.FDN `6F3B`.
    Fdn,
    /// ISIM EF.IMPI `6F02`.
    Impi,
    /// ISIM EF.IMPU `6F04`.
    Impu,
    /// ISIM EF.P-CSCF `6F09`.
    Pcscf,
    /// EF.MANUAREA `0002` under the master file, read as raw bytes. Not a
    /// 3GPP/ETSI file: SIMTester reads it where a card has it (issue #102).
    ManuArea,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    Transparent,
    LinearFixed,
}

impl Ef {
    /// The name evidence and JSON use.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Iccid => "EF.ICCID",
            Self::Dir => "EF.DIR",
            Self::Imsi => "EF.IMSI",
            Self::Msisdn => "EF.MSISDN",
            Self::Ad => "EF.AD",
            Self::Spn => "EF.SPN",
            Self::Ust => "EF.UST",
            Self::Est => "EF.EST",
            Self::Keys => "EF.Keys",
            Self::KeysPs => "EF.KeysPS",
            Self::Fplmn => "EF.FPLMN",
            Self::OplmnWact => "EF.OPLMNwAcT",
            Self::HplmnWact => "EF.HPLMNwAcT",
            Self::Loci => "EF.LOCI",
            Self::Psloci => "EF.PSLOCI",
            Self::Epsloci => "EF.EPSLOCI",
            Self::Acc => "EF.ACC",
            Self::Adn => "EF.ADN",
            Self::Fdn => "EF.FDN",
            Self::Impi => "EF.IMPI",
            Self::Impu => "EF.IMPU",
            Self::Pcscf => "EF.P-CSCF",
            Self::ManuArea => "EF.MANUAREA",
        }
    }

    const fn shape(self) -> Shape {
        match self {
            Self::Dir | Self::Msisdn | Self::Adn | Self::Fdn | Self::Impu | Self::Pcscf => {
                Shape::LinearFixed
            }
            _ => Shape::Transparent,
        }
    }
}

/// Which decoder, if any, reads the file at `path`.
///
/// By identifier plus where it sits, because an identifier is only meaningful
/// under its directory: `6F38` is EF.UST under an application and EF.SST under
/// DF.GSM `7F20` (not decoded here). An application is a path with an AID or,
/// as the corpus cards and `7FFF` aliases have it, a directory `7FFF`.
pub fn classify(path: &Path) -> Option<Ef> {
    let seg = path.segments();
    let leaf = path.leaf().to_bytes();
    // The ISIM application, by AID (RID A000000087, PIX 1004): the identifiers
    // 6F02/6F04/6F09 mean something else under the USIM, and `7FFF` cannot say.
    let isim = path
        .adf()
        .is_some_and(|aid| aid.starts_with(&[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04]));
    // A phonebook directory `5F3A` under DF.TELECOM or an application.
    let phonebook = seg.len() >= 3
        && seg[seg.len() - 2].to_bytes() == [0x5F, 0x3A]
        && (path.adf().is_some() && seg.len() == 3
            || seg.len() >= 4
                && matches!(seg[seg.len() - 3].to_bytes(), [0x7F, 0x10] | [0x7F, 0xFF]));
    let (adf, gsm, telecom, mf) = match seg.len() {
        2 => (path.adf().is_some(), false, false, path.adf().is_none()),
        n if n >= 3 => {
            let parent = seg[n - 2].to_bytes();
            (
                parent == [0x7F, 0xFF],
                parent == [0x7F, 0x20],
                parent == [0x7F, 0x10],
                false,
            )
        }
        _ => return None,
    };
    match leaf {
        [0x6F, 0x02] if isim => Some(Ef::Impi),
        [0x6F, 0x04] if isim => Some(Ef::Impu),
        [0x6F, 0x09] if isim => Some(Ef::Pcscf),
        [0x4F, 0x3A] if phonebook => Some(Ef::Adn),
        [0x00, 0x02] if mf => Some(Ef::ManuArea),
        [0x2F, 0xE2] if mf => Some(Ef::Iccid),
        [0x2F, 0x00] if mf => Some(Ef::Dir),
        [0x6F, 0x07] if adf || gsm => Some(Ef::Imsi),
        [0x6F, 0xAD] if adf || gsm => Some(Ef::Ad),
        [0x6F, 0x46] if adf || gsm => Some(Ef::Spn),
        [0x6F, 0x40] if adf || telecom => Some(Ef::Msisdn),
        [0x6F, 0x38] if adf => Some(Ef::Ust),
        [0x6F, 0x56] if adf => Some(Ef::Est),
        [0x6F, 0x08] if adf => Some(Ef::Keys),
        [0x6F, 0x09] if adf => Some(Ef::KeysPs),
        [0x6F, 0x7B] if adf || gsm => Some(Ef::Fplmn),
        [0x6F, 0x61] if adf => Some(Ef::OplmnWact),
        [0x6F, 0x62] if adf => Some(Ef::HplmnWact),
        [0x6F, 0x7E] if adf || gsm => Some(Ef::Loci),
        [0x6F, 0x73] if adf => Some(Ef::Psloci),
        [0x6F, 0xE3] if adf => Some(Ef::Epsloci),
        [0x6F, 0x78] if adf || gsm => Some(Ef::Acc),
        [0x6F, 0x3A] if telecom => Some(Ef::Adn),
        [0x6F, 0x3B] if adf || telecom => Some(Ef::Fdn),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Decoders (pure)
// ---------------------------------------------------------------------------

/// Digits from nibbles, stopping at the `F` filler.
fn digits_of(nibbles: impl Iterator<Item = u8>) -> Result<String, Malformed> {
    let mut out = String::new();
    for n in nibbles {
        match n {
            0..=9 => out.push(char::from(b'0' + n)),
            0xF => break,
            _ => return Err(Malformed("a nibble that is not a decimal digit")),
        }
    }
    Ok(out)
}

/// Low nibble first, then high, for each octet (swapped-nibble BCD).
fn swapped(bytes: &[u8]) -> impl Iterator<Item = u8> + '_ {
    bytes.iter().flat_map(|b| [b & 0x0F, b >> 4])
}

/// EF.ICCID: ETSI TS 102 221 clause 13.2. Ten octets, up to 20 digits, swapped
/// nibbles, `F`-padded (ITU-T E.118).
pub fn decode_iccid(bytes: &[u8]) -> Result<Digits, Malformed> {
    if bytes.len() != 10 {
        return Err(Malformed("EF.ICCID is 10 octets"));
    }
    digits_of(swapped(bytes)).map(Digits)
}

/// EF.IMSI: 3GPP TS 31.102 clause 4.2.2 / ETSI TS 51.011 clause 10.3.2, whose
/// octet 2 onward is the TS 24.008 clause 10.5.1.4 mobile identity: octet 1 the
/// number of octets that follow, octet 2 the first digit in b8..b5 with the
/// odd/even indicator in b4 and type of identity `001` in b3..b1, then two
/// digits per octet, low nibble first, an even count ending in `F`.
pub fn decode_imsi(bytes: &[u8]) -> Result<Digits, Malformed> {
    let (&len, rest) = bytes.split_first().ok_or(Malformed("EF.IMSI is empty"))?;
    if len == 0 || len == 0xFF {
        return Ok(Digits(String::new()));
    }
    let body = rest
        .get(..usize::from(len))
        .ok_or(Malformed("EF.IMSI is shorter than its length octet"))?;
    if body[0] & 0x07 != 0x01 {
        return Err(Malformed("EF.IMSI type of identity is not IMSI"));
    }
    let odd = body[0] & 0x08 != 0;
    let nibbles = std::iter::once(body[0] >> 4).chain(swapped(&body[1..]));
    let digits = digits_of(nibbles)?;
    if digits.len() > 15 || digits.len() % 2 != usize::from(odd) {
        return Err(Malformed("EF.IMSI digit count disagrees with its parity"));
    }
    Ok(Digits(digits))
}

/// One used EF.MSISDN record (TS 31.102 clause 4.2.26 / TS 51.011 clause
/// 10.5.5: alpha identifier, then 14 octets: BCD length, TON/NPI, 10 octets of
/// number, capability id, extension id). EF.ADN (TS 51.011 clause 10.5.1) and
/// EF.FDN (the same clause's layout, per pySim; USIM clause not verified here) share it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Msisdn {
    /// The alpha identifier (printable ASCII; empty when absent or UCS-2).
    pub alpha: String,
    /// Type of number and numbering plan identification octet.
    pub ton_npi: u8,
    /// The dialling number (`*`, `#` and `a`..`c` kept as written).
    pub number: Digits,
}

/// `None` for an unused record. BCD of a dialling number: `A` `*`, `B` `#`, `C` pause.
pub fn decode_msisdn_record(record: &[u8]) -> Result<Option<Msisdn>, Malformed> {
    let tail = record
        .len()
        .checked_sub(14)
        .map(|at| &record[at..])
        .ok_or(Malformed("EF.MSISDN record shorter than 14 octets"))?;
    let (len, ton_npi) = (tail[0], tail[1]);
    if len == 0 || len == 0xFF {
        return Ok(None);
    }
    // The length counts the TON/NPI octet and the number octets.
    let number = tail[2..12]
        .get(..usize::from(len) - 1)
        .ok_or(Malformed("EF.MSISDN BCD length exceeds the number field"))?;
    let mut out = String::new();
    for n in swapped(number) {
        match n {
            0..=9 => out.push(char::from(b'0' + n)),
            0xA => out.push('*'),
            0xB => out.push('#'),
            0xC => out.push('p'),
            0xF => break,
            _ => return Err(Malformed("EF.MSISDN reserved BCD nibble")),
        }
    }
    Ok(Some(Msisdn {
        alpha: alpha_text(&record[..record.len() - 14]),
        ton_npi,
        number: Digits(out),
    }))
}

/// One application EF.DIR lists (ETSI TS 102 221 clause 13.1: an application
/// template `61` holding the AID in `4F` and optionally a label in `50`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Application {
    /// The AID, 5 to 16 octets.
    pub aid: Vec<u8>,
    /// The label, printable ASCII only, at most 16 characters.
    pub label: Option<String>,
}

/// `None` for an unused (`FF`-padded) record.
pub fn decode_dir_record(record: &[u8]) -> Result<Option<Application>, Malformed> {
    if record.first().is_none_or(|b| *b == 0xFF) {
        return Ok(None);
    }
    let bad = Malformed("EF.DIR record is not an application template");
    let template = crate::tlv::Tlv::decode(record).map_err(|_| bad)?.0;
    if template.tag().octet() != 0x61 {
        return Err(bad);
    }
    let (mut aid, mut label) = (None, None);
    let mut atoms = Stream::new(template.value());
    while let Ok(Some(atom)) = atoms.next_atom() {
        match atom.tag().octet() {
            0x4F => aid = Some(atom.value().to_vec()),
            0x50 => label = Some(printable(atom.value(), 16)),
            _ => {}
        }
    }
    match aid {
        Some(aid) if (5..=16).contains(&aid.len()) => Ok(Some(Application { aid, label })),
        _ => Err(Malformed("EF.DIR application has no AID of 5 to 16 octets")),
    }
}

/// Printable ASCII, other octets as `?`, at most `max` characters.
fn printable(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .map(|b| {
            if (0x20..0x7F).contains(b) {
                char::from(*b)
            } else {
                '?'
            }
        })
        .collect()
}

/// What mode EF.AD says the terminal operates in (TS 31.102 clause 4.2.18;
/// values as in pySim's `EF_AD.OP_MODE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationMode {
    /// `00`.
    Normal,
    /// `80`.
    TypeApproval,
    /// `01`.
    NormalSpecificFacilities,
    /// `81`.
    TypeApprovalSpecificFacilities,
    /// `02`.
    MaintenanceOffLine,
    /// `04`.
    CellTest,
    /// Any other value, as read.
    Other(u8),
}

impl OperationMode {
    const fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::TypeApproval => "type-approval",
            Self::NormalSpecificFacilities => "normal-specific-facilities",
            Self::TypeApprovalSpecificFacilities => "type-approval-specific-facilities",
            Self::MaintenanceOffLine => "maintenance-off-line",
            Self::CellTest => "cell-test",
            Self::Other(_) => "other",
        }
    }
}

/// EF.AD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ad {
    /// Octet 1.
    pub mode: OperationMode,
    /// The ciphering indicator, octet 3 b1. Decoded but NOT emitted in evidence
    /// or JSON while unverified. [U] Position taken from pySim's
    /// `EF_AD` test vector `01000102` (octets 2-3 read as a 16-bit flag word
    /// whose bit 0 is the indicator), not from the spec text.
    pub ciphering_indicator: bool,
    /// Octet 4 b4..b1, when present and 2 or 3: the length of the MNC in the IMSI.
    pub mnc_len: Option<u8>,
}

/// EF.AD: at least octets 1 to 3.
pub fn decode_ad(bytes: &[u8]) -> Result<Ad, Malformed> {
    let [mode, _, info, rest @ ..] = bytes else {
        return Err(Malformed("EF.AD is shorter than 3 octets"));
    };
    Ok(Ad {
        mode: match mode {
            0x00 => OperationMode::Normal,
            0x80 => OperationMode::TypeApproval,
            0x01 => OperationMode::NormalSpecificFacilities,
            0x81 => OperationMode::TypeApprovalSpecificFacilities,
            0x02 => OperationMode::MaintenanceOffLine,
            0x04 => OperationMode::CellTest,
            other => OperationMode::Other(*other),
        },
        ciphering_indicator: info & 1 == 1,
        mnc_len: rest
            .first()
            .map(|b| b & 0x0F)
            .filter(|n| (2..=3).contains(n)),
    })
}

/// EF.SPN (TS 31.102 clause 4.2.12): octet 1 the display condition, octets 2..
/// the name, `FF`-padded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spn {
    /// Octet 1, as read.
    pub display_condition: u8,
    /// The name; printable ASCII only. A name in UCS-2 (first octet `80`..`82`)
    /// is not decoded and reads as empty. ponytail: SMS default alphabet is
    /// treated as ASCII; add the GSM 03.38 table if a card needs it.
    pub name: String,
}

/// EF.SPN.
pub fn decode_spn(bytes: &[u8]) -> Result<Spn, Malformed> {
    let (&display_condition, name) = bytes.split_first().ok_or(Malformed("EF.SPN is empty"))?;
    let end = name.iter().position(|b| *b == 0xFF).unwrap_or(name.len());
    let name = &name[..end];
    Ok(Spn {
        display_condition,
        name: if name.first().is_some_and(|b| (0x80..=0x82).contains(b)) {
            String::new()
        } else {
            printable(name, 16)
        },
    })
}

/// An alpha identifier: printable ASCII up to the `FF` padding. UCS-2 (first
/// octet `80`..`82`, TS 31.102 annex A) is not decoded and reads as empty.
fn alpha_text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0xFF).unwrap_or(bytes.len());
    let bytes = &bytes[..end];
    if bytes.first().is_some_and(|b| (0x80..=0x82).contains(b)) {
        String::new()
    } else {
        printable(bytes, 32)
    }
}

/// A PLMN: MCC and MNC digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plmn {
    /// Three digits.
    pub mcc: String,
    /// Two or three digits.
    pub mnc: String,
}

impl fmt::Display for Plmn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.mcc, self.mnc)
    }
}

/// A PLMN in three octets (TS 24.008 clause 10.5.1.13, used by TS 31.102 for
/// EF.FPLMN and the PLMN files): octet 1 = MCC digit 2 | MCC digit 1, octet 2 = MNC digit 3 | MCC digit 3, octet 3 = MNC digit 2 |
/// MNC digit 1; MNC digit 3 `F` means a two-digit MNC. `FFFFFF` is unused (`None`).
pub fn decode_plmn(b: [u8; 3]) -> Result<Option<Plmn>, Malformed> {
    if b == [0xFF; 3] {
        return Ok(None);
    }
    let digit = |n: u8| match n {
        0..=9 => Ok(char::from(b'0' + n)),
        _ => Err(Malformed("a PLMN nibble that is not a decimal digit")),
    };
    let mcc = [b[0] & 0x0F, b[0] >> 4, b[1] & 0x0F]
        .into_iter()
        .map(digit)
        .collect::<Result<String, _>>()?;
    let mut mnc = [b[2] & 0x0F, b[2] >> 4]
        .into_iter()
        .map(digit)
        .collect::<Result<String, _>>()?;
    if b[1] >> 4 != 0xF {
        mnc.push(digit(b[1] >> 4)?);
    }
    Ok(Some(Plmn { mcc, mnc }))
}

/// One used entry of a PLMN list, with its access technologies when the file has them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlmnEntry {
    /// The network.
    pub plmn: Plmn,
    /// The two AcT octets (TS 31.102 clause 4.2.5), for the `wAcT` files.
    pub act: Option<[u8; 2]>,
}

impl PlmnEntry {
    /// Access technology names from the AcT bits (TS 31.102 clause 4.2.5:
    /// octet 1 b8 UTRAN, b7 E-UTRAN, b6 NG-RAN; octet 2 b8 GSM, b7 GSM COMPACT,
    /// b6 cdma2000 HRPD, b5 cdma2000 1xRTT). Unnamed bits are not listed.
    pub fn act_names(&self) -> Vec<&'static str> {
        const NAMES: [(usize, u8, &str); 6] = [
            (0, 0x80, "UTRAN"),
            (0, 0x40, "E-UTRAN"),
            (0, 0x20, "NG-RAN"),
            (1, 0x80, "GSM"),
            (1, 0x40, "GSM COMPACT"),
            (1, 0x20, "cdma2000 HRPD"),
        ];
        let act = self.act.unwrap_or_default();
        let mut out: Vec<&'static str> = NAMES
            .iter()
            .filter(|(i, bit, _)| act[*i] & bit != 0)
            .map(|(_, _, n)| *n)
            .collect();
        if act[1] & 0x10 != 0 {
            out.push("cdma2000 1xRTT");
        }
        out
    }
}

/// A PLMN list file: `entry` octets per entry, 3 for EF.FPLMN (TS 31.102
/// EF.FPLMN; its clause number is not verified here) and 5 for
/// EF.OPLMNwAcT / EF.HPLMNwAcT (PLMN, then the two AcT octets; TS 51.011
/// clauses 10.3.35 to 10.3.37, USIM clause numbers not verified here).
/// Unused entries (`FFFFFF`) are dropped.
pub fn decode_plmn_list(bytes: &[u8], entry: usize) -> Result<Vec<PlmnEntry>, Malformed> {
    if bytes.is_empty() || bytes.len() % entry != 0 {
        return Err(Malformed("a PLMN list is not a whole number of entries"));
    }
    let mut out = Vec::new();
    for e in bytes.chunks_exact(entry) {
        if let Some(plmn) = decode_plmn([e[0], e[1], e[2]])? {
            out.push(PlmnEntry {
                plmn,
                act: (entry == 5).then(|| [e[3], e[4]]),
            });
        }
    }
    Ok(out)
}

/// EF.ACC (TS 31.102 clause 4.2.15 / TS 51.011 clause 10.3.13): two octets, a
/// bit per access class, class 15 = octet 1 b8 down to class 0 = octet 2 b1.
/// Returns the classes set, ascending.
pub fn decode_acc(bytes: &[u8]) -> Result<Vec<u8>, Malformed> {
    let [hi, lo, ..] = bytes else {
        return Err(Malformed("EF.ACC is shorter than 2 octets"));
    };
    let word = u16::from_be_bytes([*hi, *lo]);
    Ok((0..16u8).filter(|c| word >> c & 1 == 1).collect())
}

/// A location-information file (EF.LOCI, EF.PSLOCI, EF.EPSLOCI): the fields in
/// the clause's order, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The temporary identity (TMSI, P-TMSI or GUTI) as hex.
    pub tmp_id: String,
    /// The P-TMSI signature (EF.PSLOCI only), as hex.
    pub signature: Option<String>,
    /// The registered PLMN of the LAI, RAI or TAI; `None` when unset.
    pub plmn: Option<Plmn>,
    /// The LAC, or LAC and RAC (RAI), or TAC.
    pub area: String,
    /// The update status octet's b3..b1.
    pub status: u8,
}

impl Registration {
    /// The status as the clauses name it: 0 updated, 1 not updated; 2 PLMN (or
    /// roaming) not allowed; 3 location/routing area not allowed (not for EPS).
    pub fn status_label(&self, ef: Ef) -> &'static str {
        match self.status {
            0 => "updated",
            1 => "not-updated",
            2 if ef == Ef::Epsloci => "roaming-not-allowed",
            2 => "plmn-not-allowed",
            3 if ef != Ef::Epsloci => "area-not-allowed",
            _ => "reserved",
        }
    }
}

/// EF.LOCI: TS 31.102 clause 4.2.17 is 11 octets: TMSI
/// (4), LAI (PLMN 3 + LAC 2), TMSI TIME (1), location update status (1, b3..b1).
pub fn decode_loci(bytes: &[u8]) -> Result<Registration, Malformed> {
    let [t0, t1, t2, t3, p0, p1, p2, l0, l1, _time, status, ..] = bytes else {
        return Err(Malformed("EF.LOCI is shorter than 11 octets"));
    };
    Ok(Registration {
        tmp_id: hex(&[*t0, *t1, *t2, *t3]),
        signature: None,
        plmn: decode_plmn([*p0, *p1, *p2])?,
        area: hex(&[*l0, *l1]),
        status: status & 0x07,
    })
}

/// EF.PSLOCI: TS 31.102 clause 4.2.23 (the clause the sensitive-EF rule cites), 14 octets: P-TMSI (4), P-TMSI signature
/// (3), RAI (PLMN 3 + LAC 2 + RAC 1), routing area update status (1, b3..b1).
pub fn decode_psloci(bytes: &[u8]) -> Result<Registration, Malformed> {
    let (Some(ptmsi), Some(sig), Some(rai), Some(&status)) = (
        bytes.get(..4),
        bytes.get(4..7),
        bytes.get(7..13),
        bytes.get(13),
    ) else {
        return Err(Malformed("EF.PSLOCI is shorter than 14 octets"));
    };
    Ok(Registration {
        tmp_id: hex(ptmsi),
        signature: Some(hex(sig)),
        plmn: decode_plmn([rai[0], rai[1], rai[2]])?,
        area: hex(&rai[3..]),
        status: status & 0x07,
    })
}

/// EF.EPSLOCI: TS 31.102 clause 4.2.91 (as pySim cites it), 18 octets: GUTI (12), last visited
/// registered TAI (PLMN 3 + TAC 2), EPS update status (1, b3..b1: 0 updated,
/// 1 not updated, 2 roaming not allowed).
pub fn decode_epsloci(bytes: &[u8]) -> Result<Registration, Malformed> {
    let (Some(guti), Some(tai), Some(&status)) =
        (bytes.get(..12), bytes.get(12..17), bytes.get(17))
    else {
        return Err(Malformed("EF.EPSLOCI is shorter than 18 octets"));
    };
    Ok(Registration {
        tmp_id: hex(guti),
        signature: None,
        plmn: decode_plmn([tai[0], tai[1], tai[2]])?,
        area: hex(&tai[3..]),
        status: status & 0x07,
    })
}

/// A `80 <len> <value>` object as ISIM files hold them (TS 31.103 clauses
/// 4.2.2, 4.2.4, 4.2.8); `None` for an unused (`FF`) record.
fn tag80(bytes: &[u8]) -> Result<Option<&[u8]>, Malformed> {
    let bad = Malformed("an ISIM record is not a tag 80 object");
    match bytes {
        [] | [0xFF, ..] => Ok(None),
        [0x80, 0x81, len, rest @ ..] => rest.get(..usize::from(*len)).map(Some).ok_or(bad),
        [0x80, len, rest @ ..] if *len < 0x80 => rest.get(..usize::from(*len)).map(Some).ok_or(bad),
        _ => Err(bad),
    }
}

/// UTF-8 text from the card, control characters as `?`.
fn utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// EF.IMPI: TS 31.103 clause 4.2.2, tag `80` holding the NAI in UTF-8. `None`
/// when the file is unprovisioned.
pub fn decode_impi(bytes: &[u8]) -> Result<Option<String>, Malformed> {
    Ok(tag80(bytes)?.map(utf8))
}

/// One EF.IMPU record: TS 31.103 clause 4.2.4, tag `80` holding a SIP or tel URI.
pub fn decode_impu_record(record: &[u8]) -> Result<Option<String>, Malformed> {
    Ok(tag80(record)?.map(utf8))
}

/// One EF.P-CSCF record: TS 31.103 clause 4.2.8, tag `80` holding an address
/// type octet (`00` FQDN, `01` IPv4, `02` IPv6) and the address.
pub fn decode_pcscf_record(record: &[u8]) -> Result<Option<String>, Malformed> {
    let Some(value) = tag80(record)? else {
        return Ok(None);
    };
    let bad = Malformed("EF.P-CSCF address does not match its type");
    Ok(Some(match value {
        [0x00, name @ ..] if !name.is_empty() => utf8(name),
        [0x01, a, b, c, d] => std::net::Ipv4Addr::new(*a, *b, *c, *d).to_string(),
        [0x02, rest @ ..] if rest.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rest);
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => return Err(bad),
    }))
}

/// Which service table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    /// EF.UST, TS 31.102 clause 4.2.8.
    Ust,
    /// EF.EST, TS 31.102 clause 4.2.47.
    Est,
}

/// The services a table marks available (UST) or enabled (EST).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Services {
    /// Which table.
    pub table: Table,
    /// Service numbers, ascending. Service `n` is bit `((n-1) % 8) + 1` of
    /// octet `((n-1) / 8) + 1` (TS 31.102 clause 4.2.8).
    pub enabled: Vec<u16>,
}

/// EF.UST / EF.EST.
pub fn decode_services(table: Table, bytes: &[u8]) -> Result<Services, Malformed> {
    if bytes.is_empty() {
        return Err(Malformed("a service table is empty"));
    }
    let enabled = bytes
        .iter()
        .enumerate()
        .flat_map(|(i, b)| {
            (0..8)
                .filter(move |bit| b >> bit & 1 == 1)
                .map(move |bit| (i * 8 + bit + 1) as u16)
        })
        .collect();
    Ok(Services { table, enabled })
}

/// The name of a service, for the ones a security report cares about
/// (TS 31.102 clause 4.2.8 table; names as in pySim `EF_UST_map` / `EF_EST_map`).
/// The other numbers are listed without a name rather than guessed.
pub fn service_name(table: Table, n: u16) -> Option<&'static str> {
    match (table, n) {
        (Table::Ust, 2) | (Table::Est, 1) => Some("Fixed Dialling Numbers (FDN)"),
        (Table::Ust, 6) | (Table::Est, 2) => Some("Barred Dialling Numbers (BDN)"),
        (Table::Ust, 35) | (Table::Est, 3) => Some("APN Control List (ACL)"),
        (Table::Ust, 10) => Some("Short Message Storage (SMS)"),
        (Table::Ust, 19) => Some("Service Provider Name"),
        (Table::Ust, 21) => Some("MSISDN"),
        (Table::Ust, 27) => Some("GSM Access"),
        (Table::Ust, 28) => Some("Data download via SMS-PP"),
        (Table::Ust, 29) => Some("Data download via SMS-CB"),
        (Table::Ust, 30) => Some("Call Control by USIM"),
        (Table::Ust, 31) => Some("MO-SMS Control by USIM"),
        (Table::Ust, 32) => Some("RUN AT COMMAND command"),
        (Table::Ust, 34) => Some("Enabled Services Table"),
        (Table::Ust, 38) => Some("GSM security context"),
        (Table::Ust, 68) => Some("Generic Bootstrapping Architecture (GBA)"),
        (Table::Ust, 70) => Some("Data download via USSD and USSD application mode"),
        (Table::Ust, 85) => Some("EPS Mobility Management Information"),
        (Table::Ust, 122) => Some("5GS Mobility Management Information"),
        (Table::Ust, 123) => Some("5G Security Parameters"),
        (Table::Ust, 124) => Some("Subscription identifier privacy support"),
        (Table::Ust, 125) => Some("SUCI calculation by the USIM"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Decoded values, evidence and JSON
// ---------------------------------------------------------------------------

/// A decoded EF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    /// EF.ICCID.
    Iccid(Digits),
    /// EF.IMSI and the MNC length EF.AD gave for it, when it did.
    Imsi(Digits, Option<u8>),
    /// The used records of EF.MSISDN.
    Msisdn(Vec<Msisdn>),
    /// The applications EF.DIR lists.
    Dir(Vec<Application>),
    /// EF.AD.
    Ad(Ad),
    /// EF.SPN.
    Spn(Spn),
    /// A key file (EF.Keys, EF.KeysPS): the bytes as read.
    Raw(Vec<u8>),
    /// EF.UST or EF.EST.
    Services(Services),
    /// EF.FPLMN, EF.OPLMNwAcT or EF.HPLMNwAcT: the used entries.
    Plmns(Ef, Vec<PlmnEntry>),
    /// EF.ACC: the access classes set.
    Acc(Vec<u8>),
    /// EF.LOCI, EF.PSLOCI or EF.EPSLOCI.
    Registration(Ef, Registration),
    /// The used records of EF.ADN or EF.FDN.
    Numbers(Ef, Vec<Msisdn>),
    /// EF.IMPI (`None` when unprovisioned).
    Impi(Option<String>),
    /// The used records of EF.IMPU or EF.P-CSCF.
    Uris(Ef, Vec<String>),
}

/// Decodes the bytes read from an EF `ef` (a record per element for a linear
/// fixed EF). `mnc_len` is EF.AD's, used only to split the IMSI into MCC/MNC.
///
/// # Errors
///
/// [`Malformed`] when the bytes are not the layout the clause gives. A caller
/// reports that; it never treats it as "no data".
pub fn decode(ef: Ef, records: &[Vec<u8>], mnc_len: Option<u8>) -> Result<Decoded, Malformed> {
    let first = records.first().map_or(&[][..], Vec::as_slice);
    Ok(match ef {
        Ef::Iccid => Decoded::Iccid(decode_iccid(first)?),
        Ef::Imsi => Decoded::Imsi(decode_imsi(first)?, mnc_len),
        Ef::Ad => Decoded::Ad(decode_ad(first)?),
        Ef::Spn => Decoded::Spn(decode_spn(first)?),
        Ef::Ust => Decoded::Services(decode_services(Table::Ust, first)?),
        Ef::Est => Decoded::Services(decode_services(Table::Est, first)?),
        Ef::Msisdn => Decoded::Msisdn(
            records
                .iter()
                .map(|r| decode_msisdn_record(r))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect(),
        ),
        Ef::Dir => Decoded::Dir(
            records
                .iter()
                .map(|r| decode_dir_record(r))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect(),
        ),
        Ef::Fplmn => Decoded::Plmns(ef, decode_plmn_list(first, 3)?),
        Ef::OplmnWact | Ef::HplmnWact => Decoded::Plmns(ef, decode_plmn_list(first, 5)?),
        Ef::Acc => Decoded::Acc(decode_acc(first)?),
        Ef::Loci => Decoded::Registration(ef, decode_loci(first)?),
        Ef::Psloci => Decoded::Registration(ef, decode_psloci(first)?),
        Ef::Epsloci => Decoded::Registration(ef, decode_epsloci(first)?),
        Ef::Adn | Ef::Fdn => Decoded::Numbers(
            ef,
            records
                .iter()
                .map(|r| decode_msisdn_record(r))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect(),
        ),
        Ef::Impi => Decoded::Impi(decode_impi(first)?),
        Ef::Impu | Ef::Pcscf => Decoded::Uris(
            ef,
            records
                .iter()
                .map(|r| {
                    if ef == Ef::Impu {
                        decode_impu_record(r)
                    } else {
                        decode_pcscf_record(r)
                    }
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect(),
        ),
        Ef::ManuArea => Decoded::Raw(first.to_vec()),
        Ef::Keys | Ef::KeysPs if first.is_empty() => {
            return Err(Malformed("key file read back empty"))
        }
        Ef::Keys | Ef::KeysPs => Decoded::Raw(first.to_vec()),
    })
}

fn aid_hex(aid: &[u8]) -> String {
    aid.iter().map(|b| format!("{b:02X}")).collect()
}

fn imsi_head(mnc_len: Option<u8>) -> usize {
    3 + usize::from(mnc_len.unwrap_or(2))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

impl Decoded {
    /// The short, bounded, full-value line a finding or a report shows.
    pub fn evidence(&self) -> String {
        match self {
            Self::Iccid(d) => format!("ICCID {}", d.as_str()),
            Self::Imsi(d, _) => format!("IMSI {}", d.as_str()),
            Self::Msisdn(list) | Self::Numbers(_, list) => format!(
                "{} number(s){}",
                list.len(),
                list.first().map_or(String::new(), |m| format!(
                    ", first: TON/NPI {:02X}, {}",
                    m.ton_npi,
                    m.number.as_str()
                ))
            ),
            Self::Plmns(_, list) => {
                let shown: Vec<String> = list
                    .iter()
                    .take(EVIDENCE_ITEMS)
                    .map(|e| match e.act {
                        Some(_) => format!("{} [{}]", e.plmn, e.act_names().join("+")),
                        None => e.plmn.to_string(),
                    })
                    .collect();
                format!(
                    "{} PLMN(s): {}{}",
                    list.len(),
                    if shown.is_empty() {
                        "none".to_owned()
                    } else {
                        shown.join(", ")
                    },
                    list.len()
                        .checked_sub(EVIDENCE_ITEMS)
                        .filter(|n| *n > 0)
                        .map_or(String::new(), |n| format!(" (+{n} more)"))
                )
            }
            Self::Acc(classes) => format!(
                "{} access class(es): {}",
                classes.len(),
                if classes.is_empty() {
                    "none".to_owned()
                } else {
                    classes
                        .iter()
                        .map(u8::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                }
            ),
            Self::Registration(ef, r) => format!(
                "{} {} PLMN {} area {} status={}",
                match ef {
                    Ef::Loci => "TMSI",
                    Ef::Psloci => "P-TMSI",
                    _ => "GUTI",
                },
                r.tmp_id,
                r.plmn.as_ref().map_or("unset".to_owned(), Plmn::to_string),
                r.area,
                r.status_label(*ef)
            ),
            Self::Impi(nai) => format!("IMPI {}", nai.as_deref().unwrap_or("unprovisioned")),
            Self::Uris(ef, list) => format!(
                "{} {}(s): {}",
                list.len(),
                if *ef == Ef::Impu { "IMPU" } else { "P-CSCF" },
                list.iter()
                    .take(EVIDENCE_ITEMS)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Raw(b) => hex(b),
            Self::Dir(apps) => {
                let mut out = format!("{} application(s)", apps.len());
                for a in apps.iter().take(EVIDENCE_ITEMS) {
                    out += &format!(
                        " {}{}",
                        aid_hex(&a.aid),
                        a.label
                            .as_ref()
                            .map_or(String::new(), |l| format!(" ({l})"))
                    );
                }
                out
            }
            Self::Ad(ad) => format!(
                "mode={} mnc_len={}",
                ad.mode.label(),
                ad.mnc_len.map_or("absent".to_owned(), |n| n.to_string())
            ),
            Self::Spn(s) => format!(
                "display_condition={:02X} name={:?}",
                s.display_condition, s.name
            ),
            Self::Services(s) => {
                let shown: Vec<String> = s
                    .enabled
                    .iter()
                    .take(EVIDENCE_ITEMS)
                    .map(u16::to_string)
                    .collect();
                let more = s.enabled.len().saturating_sub(EVIDENCE_ITEMS);
                format!(
                    "{} {} service(s): {}{}",
                    s.enabled.len(),
                    match s.table {
                        Table::Ust => "available",
                        Table::Est => "enabled",
                    },
                    if shown.is_empty() {
                        "none".to_owned()
                    } else {
                        shown.join(",")
                    },
                    if more > 0 {
                        format!(" (+{more} more)")
                    } else {
                        String::new()
                    }
                )
            }
        }
    }

    /// The typed fields as JSON, full value, as in [`Decoded::evidence`].
    pub fn fields(&self) -> Value {
        match self {
            Self::Iccid(d) => json!({
                "digits": d.len(),
                "iccid": d.as_str(),
            }),
            Self::Imsi(d, mnc) => {
                let head = imsi_head(*mnc);
                json!({
                    "digits": d.len(),
                    "imsi": d.as_str(),
                    "mcc_mnc": d.as_str().get(..head),
                    "mnc_len_source": if mnc.is_some() { "EF.AD" } else { "assumed 2" },
                })
            }
            Self::Msisdn(list) | Self::Numbers(_, list) => json!({
                "used_records": list.len(),
                "numbers": list.iter().map(|m| json!({
                    "alpha": m.alpha,
                    "ton_npi": format!("{:02X}", m.ton_npi),
                    "digits": m.number.len(),
                    "number": m.number.as_str(),
                })).collect::<Vec<_>>(),
            }),
            Self::Plmns(_, list) => json!({
                "count": list.len(),
                "plmns": list.iter().map(|e| json!({
                    "mcc": e.plmn.mcc,
                    "mnc": e.plmn.mnc,
                    "act": e.act.map(|a| hex(&a)),
                    "act_names": e.act.map(|_| e.act_names()),
                })).collect::<Vec<_>>(),
            }),
            Self::Acc(classes) => json!({ "classes": classes }),
            Self::Registration(ef, r) => json!({
                "kind": match ef {
                    Ef::Loci => "TMSI",
                    Ef::Psloci => "P-TMSI",
                    _ => "GUTI",
                },
                "identity": r.tmp_id,
                "signature": r.signature,
                "mcc": r.plmn.as_ref().map(|p| p.mcc.clone()),
                "mnc": r.plmn.as_ref().map(|p| p.mnc.clone()),
                "area": r.area,
                "status": r.status_label(*ef),
                "status_value": r.status,
            }),
            Self::Impi(nai) => json!({ "impi": nai }),
            Self::Uris(_, list) => json!({ "count": list.len(), "values": list }),
            Self::Raw(b) => json!({ "bytes": b.len(), "hex": hex(b) }),
            Self::Dir(apps) => json!({
                "applications": apps.iter().map(|a| json!({
                    "aid": aid_hex(&a.aid),
                    "label": a.label,
                })).collect::<Vec<_>>(),
            }),
            Self::Ad(ad) => json!({
                "mode": ad.mode.label(),
                "mode_octet": match ad.mode {
                    OperationMode::Other(b) => Some(format!("{b:02X}")),
                    _ => None,
                },
                "mnc_len": ad.mnc_len,
            }),
            Self::Spn(s) => json!({
                "display_condition": format!("{:02X}", s.display_condition),
                "name": s.name,
            }),
            Self::Services(s) => json!({
                "table": match s.table { Table::Ust => "UST", Table::Est => "EST" },
                "count": s.enabled.len(),
                "enabled": s.enabled,
                "named": s.enabled.iter().filter_map(|n| {
                    service_name(s.table, *n).map(|name| json!({ "service": n, "name": name }))
                }).collect::<Vec<_>>(),
            }),
        }
    }
}

/// What became of one recognised EF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Not read: the FCP gave no size, the read was not reached, or the walk stopped.
    NotRead,
    /// The card refused the SELECT or READ.
    Refused(Option<crate::apdu::StatusWord>),
    /// Read, and not the layout the clause gives.
    Malformed(Malformed),
    /// Read and decoded.
    Decoded(Decoded),
}

/// One recognised EF of a walked card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Where it is.
    pub path: Path,
    /// Which EF.
    pub ef: Ef,
    /// Its READ and UPDATE conditions, when they decode.
    pub access: Option<Access>,
    /// What reading it came to.
    pub outcome: Outcome,
}

/// Every recognised EF in the tree, decoded from what [`read`] stored.
/// Pure: sends nothing.
pub fn entries(tree: &Tree) -> Vec<Entry> {
    let mut out: Vec<Entry> = tree
        .selected()
        .filter_map(|node| Some((node, classify(node.path())?)))
        .map(|(node, ef)| entry(tree, node.path(), ef, access::access_of(tree, node)))
        .collect();
    // EF.MANUAREA is outside the walk's candidate families, so [`read`] probes
    // it directly; it is listed only when that probe found the file.
    let manu = manuarea_path();
    if tree.content_read(&manu).is_some() && !out.iter().any(|e| e.path == manu) {
        out.push(entry(tree, &manu, Ef::ManuArea, None));
    }
    out
}

fn entry(tree: &Tree, path: &Path, ef: Ef, access: Option<Access>) -> Entry {
    let outcome = match tree.content_read(path) {
        None => Outcome::NotRead,
        Some(ContentRead::Refused(sw)) => Outcome::Refused(*sw),
        Some(ContentRead::Records(records)) => match decode(ef, records, ad_mnc_len(tree, path)) {
            Ok(d) => Outcome::Decoded(d),
            Err(m) => Outcome::Malformed(m),
        },
    };
    Entry {
        access,
        path: path.clone(),
        ef,
        outcome,
    }
}

/// `3F00/0002`.
fn manuarea_path() -> Path {
    Path::master_file()
        .child(FileId::from_bytes([0x00, 0x02]))
        .expect("0002 is not the master file")
}

/// The full decoded value of the EF at `path`, when it was read and decoded
/// (what a finding about that file appends to its message and evidence).
pub fn decoded_evidence(tree: &Tree, path: &Path) -> Option<String> {
    entries(tree).into_iter().find_map(|e| match e.outcome {
        Outcome::Decoded(d) if &e.path == path => Some(d.evidence()),
        _ => None,
    })
}

/// The MNC length EF.AD (next to `imsi_path`) gives.
fn ad_mnc_len(tree: &Tree, imsi_path: &Path) -> Option<u8> {
    let ad = imsi_path
        .parent()?
        .child(FileId::from_bytes([0x6F, 0xAD]))
        .ok()?;
    let ContentRead::Records(records) = tree.content_read(&ad)? else {
        return None;
    };
    decode_ad(records.first()?).ok()?.mnc_len
}

impl Entry {
    /// The entry as the `ef_contents` element of the scan JSON.
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "path": self.path.to_string(),
            "ef": self.ef.name(),
            "access": self.access.map(|a| json!({
                "read": a.read.label(),
                "update": a.update.label(),
            })),
        });
        let (read, extra): (&str, Vec<(&str, Value)>) = match &self.outcome {
            Outcome::NotRead => ("not-read", vec![]),
            Outcome::Refused(sw) => (
                "refused",
                vec![("status", json!(sw.map(|s| s.to_string())))],
            ),
            Outcome::Malformed(m) => ("malformed", vec![("reason", json!(m.0))]),
            Outcome::Decoded(d) => (
                "decoded",
                vec![("evidence", json!(d.evidence())), ("fields", d.fields())],
            ),
        };
        v["read"] = json!(read);
        for (k, val) in extra {
            v[k] = val;
        }
        v
    }
}

/// The `ef_contents` array of the scan JSON.
pub fn to_json(tree: &Tree) -> Value {
    Value::Array(entries(tree).iter().map(Entry::to_json).collect())
}

// ---------------------------------------------------------------------------
// The read (the only part that touches a card)
// ---------------------------------------------------------------------------

/// Reads every recognised EF once and stores the bytes on the tree. Sends only
/// SELECT, READ BINARY (`B0`) and READ RECORD (`B2`), key files included. A
/// refusal is recorded and not retried.
///
/// # Errors
///
/// Whatever [`session::send`] returns.
pub fn read<S: CardSession + ?Sized>(
    session: &mut S,
    tree: &mut Tree,
    policy: &Policy,
) -> Result<(), session::Error> {
    let wanted: Vec<(Path, Shape, (u16, u8))> = tree
        .selected()
        .filter_map(|node| {
            let shape = classify(node.path())?.shape();
            Some((node.path().clone(), shape, plan(node, shape)?))
        })
        .collect();
    for (path, shape, (length, count)) in wanted {
        let outcome = read_one(session, &path, shape, length, count, policy)?;
        tree.record_content_read(path, outcome);
    }
    read_manuarea(session, tree, policy)
}

/// EF.MANUAREA: SELECT `3F00/0002`, then READ BINARY of up to [`MAX_BINARY`]
/// octets (one `6C xx` correction, the standard short-file answer). A file the
/// card will not SELECT is taken as absent, never as an error: `0002` is not a
/// standard identifier, so most cards do not have it.
fn read_manuarea<S: CardSession + ?Sized>(
    session: &mut S,
    tree: &mut Tree,
    policy: &Policy,
) -> Result<(), session::Error> {
    let path = manuarea_path();
    if tree.content_read(&path).is_some() || access::select_file(session, &path, policy)?.is_err() {
        return Ok(());
    }
    let header = Header::new(0x00, 0xB0, 0x00, 0x00);
    let mut le = Le::for_byte_count(MAX_BINARY).expect("a non-zero short length");
    let mut read = session::send(session, &Command::case2(header, le), policy)?;
    if let Some(sw) = read.status().filter(|s| s.sw1() == 0x6C && s.sw2() != 0) {
        le = Le::for_byte_count(u32::from(sw.sw2())).expect("non-zero");
        read = session::send(session, &Command::case2(header, le), policy)?;
    }
    tree.record_content_read(
        path,
        if read.status().is_some_and(|s| s.is_normal_processing()) {
            ContentRead::Records(vec![read.data().to_vec()])
        } else {
            ContentRead::Refused(read.status())
        },
    );
    Ok(())
}

/// (octets per read, records) from the FCP; `None` when it does not say.
fn plan(node: &Node, shape: Shape) -> Option<(u16, u8)> {
    let caps = node.state().capabilities()?;
    match shape {
        Shape::Transparent => {
            let size = caps.size.reported()?.octets().min(MAX_BINARY);
            Some((u16::try_from(size).ok().filter(|s| *s > 0)?, 1))
        }
        Shape::LinearFixed => match caps.descriptor.reported()?.octets.as_slice() {
            [_, _, hi, lo, count, ..] => Some((u16::from_be_bytes([*hi, *lo]), *count)),
            _ => None,
        },
    }
}

fn read_one<S: CardSession + ?Sized>(
    session: &mut S,
    path: &Path,
    shape: Shape,
    length: u16,
    count: u8,
    policy: &Policy,
) -> Result<ContentRead, session::Error> {
    if let Err(sw) = access::select_file(session, path, policy)? {
        return Ok(ContentRead::Refused(sw));
    }
    let Some(le) = Le::for_byte_count(u32::from(length)).filter(|_| length > 0) else {
        return Ok(ContentRead::Records(Vec::new()));
    };
    let mut records = Vec::new();
    let reads = if shape == Shape::Transparent {
        1
    } else {
        usize::from(count).min(MAX_RECORDS)
    };
    for number in 1..=reads {
        let header = if shape == Shape::Transparent {
            // READ BINARY, offset 0 (TS 102 221 clause 11.1.3).
            Header::new(0x00, 0xB0, 0x00, 0x00)
        } else {
            // READ RECORD, absolute mode; `number` is at most 16.
            Header::new(0x00, 0xB2, u8::try_from(number).unwrap_or(0xFF), 0x04)
        };
        let read = session::send(session, &Command::case2(header, le), policy)?;
        if !read.status().is_some_and(|s| s.is_normal_processing()) {
            return Ok(if records.is_empty() {
                ContentRead::Refused(read.status())
            } else {
                ContentRead::Records(records)
            });
        }
        records.push(read.data().to_vec());
    }
    Ok(ContentRead::Records(records))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthesised from each clause's layout; the digits are a test network
    // (MCC 001 / MNC 01) or obviously fictional.

    #[test]
    fn iccid_swapped_nibbles_with_f_padding() {
        // 19 digits 8999991234567890123, padded with F (TS 102 221 clause 13.2).
        let d =
            decode_iccid(&[0x98, 0x99, 0x99, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0xF3]).unwrap();
        assert_eq!(d.as_str(), "8999991234567890123");
        assert_eq!(Decoded::Iccid(d).evidence(), "ICCID 8999991234567890123");
        assert!(decode_iccid(&[0x98; 9]).is_err());
        assert!(decode_iccid(&[0xAB; 10]).is_err());
    }

    #[test]
    fn imsi_odd_even_and_unset() {
        // 15 digits 001010123456789: len 8, octet 2 = digit 1 + (odd, IMSI) = 09.
        let odd = decode_imsi(&[0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98]).unwrap();
        assert_eq!(odd.as_str(), "001010123456789");
        // 14 digits 00101012345678: octet 2 = 01 (even), last nibble F.
        let even = decode_imsi(&[0x08, 0x01, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0xF8]).unwrap();
        assert_eq!(even.as_str(), "00101012345678");
        assert!(decode_imsi(&[0x00, 0xFF, 0xFF]).unwrap().is_empty());
        assert!(
            decode_imsi(&[0x08, 0x09]).is_err(),
            "shorter than its length"
        );
        assert!(
            decode_imsi(&[0x08, 0x08, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98]).is_err(),
            "type of identity is not IMSI"
        );
        assert!(
            decode_imsi(&[0x08, 0x01, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98]).is_err(),
            "even flag on 15 digits"
        );
    }

    #[test]
    fn full_imsi_iccid_msisdn_reach_evidence_json_and_debug() {
        let imsi = decode_imsi(&[0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98]).unwrap();
        let iccid =
            decode_iccid(&[0x98, 0x99, 0x99, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0xF3]).unwrap();
        let msisdn = decode_msisdn_record(&msisdn_record()).unwrap().unwrap();
        let all = [
            Decoded::Imsi(imsi.clone(), Some(2)),
            Decoded::Iccid(iccid.clone()),
            Decoded::Msisdn(vec![msisdn.clone()]),
        ];
        for (d, full) in all
            .iter()
            .zip([imsi.as_str(), iccid.as_str(), msisdn.number.as_str()])
        {
            let text = format!("{} {} {d:?}", d.evidence(), d.fields());
            assert!(text.contains(full), "{full} missing from: {text}");
            assert!(d.evidence().contains(full));
        }
        assert_eq!(all[0].evidence(), "IMSI 001010123456789");
        assert_eq!(all[0].fields()["mcc_mnc"], "00101");
        assert_eq!(Decoded::Imsi(imsi, Some(3)).fields()["mcc_mnc"], "001010");
    }

    #[test]
    fn key_files_decode_to_their_bytes() {
        let d = decode(Ef::Keys, &[vec![0x07, 0xAB, 0xCD]], None).unwrap();
        assert_eq!(d.evidence(), "07ABCD");
        assert_eq!(d.fields()["hex"], "07ABCD");
    }

    fn msisdn_record() -> Vec<u8> {
        // Alpha "FF FF", then len 7, TON/NPI 91, 15555550100, padding, CCP, ext.
        let mut r = vec![0xFF, 0xFF, 0x07, 0x91, 0x51, 0x55, 0x55, 0x05, 0x01, 0xF0];
        r.extend([0xFF; 4]);
        r.extend([0xFF, 0xFF]);
        r
    }

    #[test]
    fn msisdn_used_and_unused_records() {
        let m = decode_msisdn_record(&msisdn_record()).unwrap().unwrap();
        assert_eq!(m.ton_npi, 0x91);
        assert_eq!(m.number.as_str(), "15555550100");
        assert_eq!(decode_msisdn_record(&[0xFF; 16]).unwrap(), None);
        assert!(decode_msisdn_record(&[0x07; 5]).is_err());
        let mut long = msisdn_record();
        long[2] = 0x0C;
        assert!(decode_msisdn_record(&long).is_err());
    }

    #[test]
    fn dir_application_template() {
        // 61 0F { 4F 07 A0000000871002, 50 04 "USIM" } (TS 102 221 clause 13.1).
        let record = [
            0x61, 0x0F, 0x4F, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x50, 0x04, b'U',
            b'S', b'I', b'M', 0xFF, 0xFF,
        ];
        let app = decode_dir_record(&record).unwrap().unwrap();
        assert_eq!(aid_hex(&app.aid), "A0000000871002");
        assert_eq!(app.label.as_deref(), Some("USIM"));
        assert_eq!(decode_dir_record(&[0xFF; 8]).unwrap(), None);
        assert!(decode_dir_record(&[0x62, 0x00]).is_err());
        assert!(decode_dir_record(&[0x61, 0x04, 0x4F, 0x02, 0x01, 0x02]).is_err());
    }

    #[test]
    fn ad_matches_pysim_vectors() {
        let normal = decode_ad(&[0x00, 0x00, 0x00, 0x02]).unwrap();
        assert_eq!(normal.mode, OperationMode::Normal);
        assert_eq!(
            (normal.ciphering_indicator, normal.mnc_len),
            (false, Some(2))
        );
        let specific = decode_ad(&[0x01, 0x00, 0x01, 0x02]).unwrap();
        assert_eq!(specific.mode, OperationMode::NormalSpecificFacilities);
        assert!(specific.ciphering_indicator);
        assert_eq!(decode_ad(&[0x04, 0, 0]).unwrap().mnc_len, None);
        assert_eq!(
            decode_ad(&[0x04, 0, 0]).unwrap().mode,
            OperationMode::CellTest
        );
        assert_eq!(
            decode_ad(&[0x55, 0, 0, 0x07]).unwrap().mode,
            OperationMode::Other(0x55)
        );
        assert_eq!(decode_ad(&[0, 0, 0, 0x07]).unwrap().mnc_len, None);
        assert!(decode_ad(&[0, 0]).is_err());
    }

    #[test]
    fn spn_name_and_padding() {
        let s = decode_spn(&[0x01, b'T', b'e', b's', b't', 0xFF, 0xFF, 0xFF]).unwrap();
        assert_eq!((s.display_condition, s.name.as_str()), (1, "Test"));
        assert_eq!(decode_spn(&[0x00, 0x80, 0x00, 0x41]).unwrap().name, "");
        assert_eq!(decode_spn(&[0x00, 0xFF]).unwrap().name, "");
        assert!(decode_spn(&[]).is_err());
    }

    #[test]
    fn service_tables() {
        // TS 31.102 clause 4.2.8: service n is b((n-1)%8+1) of octet (n-1)/8+1.
        let typical = decode_services(Table::Ust, &[0x9E, 0x1D, 0x01, 0x08]).unwrap();
        assert_eq!(typical.enabled, [2, 3, 4, 5, 8, 9, 11, 12, 13, 17, 28]);
        let off = decode_services(Table::Ust, &[0x00; 17]).unwrap();
        assert!(off.enabled.is_empty());
        assert_eq!(
            Decoded::Services(off).evidence(),
            "0 available service(s): none"
        );
        assert!(decode_services(Table::Est, &[]).is_err());
        let est = decode_services(Table::Est, &[0b101]).unwrap();
        assert_eq!(est.enabled, [1, 3]);
        assert_eq!(
            service_name(Table::Est, 1),
            Some("Fixed Dialling Numbers (FDN)")
        );
        assert_eq!(
            service_name(Table::Ust, 28),
            Some("Data download via SMS-PP")
        );
        assert_eq!(service_name(Table::Ust, 3), None);
    }

    #[test]
    fn long_service_lists_are_bounded() {
        let all = decode_services(Table::Ust, &[0xFF; 19]).unwrap();
        let line = Decoded::Services(all).evidence();
        assert!(
            line.contains("152 available") && line.ends_with("(+128 more)"),
            "{line}"
        );
    }

    #[test]
    fn classification_is_by_identifier_and_place() {
        let p = |s: &str| s.parse::<Path>().unwrap();
        assert_eq!(classify(&p("3F00/2FE2")), Some(Ef::Iccid));
        assert_eq!(classify(&p("3F00/7FFF/6F07")), Some(Ef::Imsi));
        assert_eq!(classify(&p("3F00/7F20/6F07")), Some(Ef::Imsi));
        assert_eq!(classify(&p("3F00/7F10/6F40")), Some(Ef::Msisdn));
        assert_eq!(classify(&p("3F00/7FFF/6F38")), Some(Ef::Ust));
        // EF.SST under DF.GSM and an IMSI under an unrelated DF are not these EFs.
        assert_eq!(classify(&p("3F00/7F20/6F38")), None);
        assert_eq!(classify(&p("3F00/5F3A/6F07")), None);
        assert_eq!(classify(&p("3F00/7FFF/5F3B/6F07")), None);
        assert_eq!(classify(&p("3F00/7FFF/6F08")), Some(Ef::Keys));
        assert_eq!(classify(&Path::master_file()), None);
    }

    // --- issue #108 remaining decoders: synthetic vectors, each with a valid,
    // a truncated and an all-0xFF (unused) case ---

    const PLMN_001_01: [u8; 3] = [0x00, 0xF1, 0x10];
    const PLMN_310_410: [u8; 3] = [0x13, 0x00, 0x14];

    #[test]
    fn plmn_two_and_three_digit_mnc() {
        let a = decode_plmn(PLMN_001_01).unwrap().unwrap();
        assert_eq!((a.mcc.as_str(), a.mnc.as_str()), ("001", "01"));
        let b = decode_plmn(PLMN_310_410).unwrap().unwrap();
        assert_eq!(b.to_string(), "310-410");
        assert_eq!(decode_plmn([0xFF; 3]).unwrap(), None);
        assert!(decode_plmn([0xAB, 0xF1, 0x10]).is_err());
    }

    #[test]
    fn fplmn_list() {
        let bytes = [PLMN_001_01, [0xFF; 3], PLMN_310_410, [0xFF; 3]].concat();
        let d = decode(Ef::Fplmn, &[bytes], None).unwrap();
        assert_eq!(d.evidence(), "2 PLMN(s): 001-01, 310-410");
        assert_eq!(d.fields()["plmns"][1]["mnc"], "410");
        let unused = decode(Ef::Fplmn, &[vec![0xFF; 12]], None).unwrap();
        assert_eq!(unused.evidence(), "0 PLMN(s): none");
        assert!(decode(Ef::Fplmn, &[vec![0x00, 0xF1, 0x10, 0x00]], None).is_err());
        assert!(decode(Ef::Fplmn, &[], None).is_err());
    }

    #[test]
    fn plmn_with_act_files() {
        // UTRAN + GSM, then E-UTRAN only, then an unused entry.
        let bytes = [
            [PLMN_001_01.as_slice(), &[0x80, 0x80]].concat(),
            [PLMN_310_410.as_slice(), &[0x40, 0x00]].concat(),
            vec![0xFF; 5],
        ]
        .concat();
        for ef in [Ef::OplmnWact, Ef::HplmnWact] {
            let d = decode(ef, std::slice::from_ref(&bytes), None).unwrap();
            assert_eq!(
                d.evidence(),
                "2 PLMN(s): 001-01 [UTRAN+GSM], 310-410 [E-UTRAN]"
            );
            assert_eq!(d.fields()["plmns"][0]["act"], "8080");
            assert!(decode(ef, &[bytes[..7].to_vec()], None).is_err());
            assert_eq!(
                decode(ef, &[vec![0xFF; 10]], None).unwrap().evidence(),
                "0 PLMN(s): none"
            );
        }
    }

    #[test]
    fn acc_classes() {
        // Octet 1 b3 = class 10, octet 2 b1 = class 0 (TS 51.011 clause 10.3.15).
        assert_eq!(decode_acc(&[0x04, 0x01]).unwrap(), [0, 10]);
        assert_eq!(
            Decoded::Acc(decode_acc(&[0x00, 0x00]).unwrap()).evidence(),
            "0 access class(es): none"
        );
        assert_eq!(decode_acc(&[0xFF, 0xFF]).unwrap().len(), 16);
        assert!(decode_acc(&[0x04]).is_err());
    }

    fn loci() -> Vec<u8> {
        // TMSI 12345678, LAI 001-01 LAC 002A, TMSI TIME FF, status 0.
        let mut v = vec![0x12, 0x34, 0x56, 0x78];
        v.extend(PLMN_001_01);
        v.extend([0x00, 0x2A, 0xFF, 0x00]);
        v
    }

    #[test]
    fn loci_psloci_epsloci() {
        let d = decode(Ef::Loci, &[loci()], None).unwrap();
        assert_eq!(
            d.evidence(),
            "TMSI 12345678 PLMN 001-01 area 002A status=updated"
        );
        let mut not_allowed = loci();
        not_allowed[10] = 0x02;
        assert_eq!(
            decode_loci(&not_allowed).unwrap().status_label(Ef::Loci),
            "plmn-not-allowed"
        );
        assert!(decode_loci(&loci()[..10]).is_err());
        let unused = decode(Ef::Loci, &[vec![0xFF; 11]], None).unwrap();
        assert_eq!(unused.fields()["identity"], "FFFFFFFF");
        assert!(unused.fields()["mcc"].is_null());

        // P-TMSI A1B2C3D4, signature 010203, RAI 001-01 LAC 002A RAC 05, status 1.
        let mut ps = vec![0xA1, 0xB2, 0xC3, 0xD4, 0x01, 0x02, 0x03];
        ps.extend(PLMN_001_01);
        ps.extend([0x00, 0x2A, 0x05, 0x01]);
        let d = decode(Ef::Psloci, &[ps.clone()], None).unwrap();
        assert_eq!(
            d.evidence(),
            "P-TMSI A1B2C3D4 PLMN 001-01 area 002A05 status=not-updated"
        );
        assert_eq!(d.fields()["signature"], "010203");
        assert!(decode_psloci(&ps[..13]).is_err());
        assert!(decode(Ef::Psloci, &[vec![0xFF; 14]], None).is_ok());

        // GUTI (12 octets), TAI 001-01 TAC 0102, status 2 (roaming not allowed).
        // Opaque here: 12 octets, shown as hex.
        let mut eps = vec![0x0B, 0xF6];
        eps.extend(PLMN_001_01);
        eps.extend([0x80, 0x01, 0x01, 0xDE, 0xAD, 0xBE, 0xEF]);
        eps.extend(PLMN_001_01);
        eps.extend([0x01, 0x02, 0x02]);
        let d = decode(Ef::Epsloci, &[eps.clone()], None).unwrap();
        assert_eq!(
            d.evidence(),
            "GUTI 0BF600F110800101DEADBEEF PLMN 001-01 area 0102 status=roaming-not-allowed"
        );
        assert!(decode_epsloci(&eps[..17]).is_err());
        assert!(decode(Ef::Epsloci, &[vec![0xFF; 18]], None).is_ok());
    }

    fn adn_record() -> Vec<u8> {
        // Alpha "Bob" + FF padding, then len 7, TON/NPI 91, 15555550100, CCP, ext.
        let mut r = vec![b'B', b'o', b'b', 0xFF, 0xFF, 0xFF];
        r.extend([
            0x07, 0x91, 0x51, 0x55, 0x55, 0x05, 0x01, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF,
        ]);
        r.extend([0xFF, 0xFF]);
        r
    }

    #[test]
    fn adn_and_fdn_records() {
        for ef in [Ef::Adn, Ef::Fdn] {
            let d = decode(ef, &[adn_record(), vec![0xFF; 20]], None).unwrap();
            assert_eq!(d.evidence(), "1 number(s), first: TON/NPI 91, 15555550100");
            assert_eq!(d.fields()["numbers"][0]["alpha"], "Bob");
            assert_eq!(
                decode(ef, &[vec![0xFF; 20]], None).unwrap().evidence(),
                "0 number(s)"
            );
            assert!(decode(ef, &[vec![0x07; 5]], None).is_err());
        }
        // A UCS-2 alpha identifier is not decoded.
        let mut ucs2 = adn_record();
        ucs2[..3].copy_from_slice(&[0x80, 0x00, 0x42]);
        assert_eq!(
            decode_msisdn_record(&ucs2).unwrap().unwrap().alpha,
            String::new()
        );
    }

    #[test]
    fn isim_files() {
        let nai = b"001010123456789@ims.mnc001.mcc001.3gppnetwork.org";
        let mut impi = vec![0x80, nai.len() as u8];
        impi.extend(nai);
        impi.resize(80, 0xFF);
        assert_eq!(
            decode(Ef::Impi, &[impi.clone()], None).unwrap().evidence(),
            "IMPI 001010123456789@ims.mnc001.mcc001.3gppnetwork.org"
        );
        assert_eq!(
            decode(Ef::Impi, &[vec![0xFF; 16]], None)
                .unwrap()
                .evidence(),
            "IMPI unprovisioned"
        );
        assert!(decode(Ef::Impi, &[impi[..10].to_vec()], None).is_err());
        assert!(decode(Ef::Impi, &[vec![0x81, 0x01, 0x00]], None).is_err());

        let impu = [&[0x80, 11][..], b"sip:a@b.org", &[0xFF; 5]].concat();
        let d = decode(Ef::Impu, &[impu.clone(), vec![0xFF; 16]], None).unwrap();
        assert_eq!(d.evidence(), "1 IMPU(s): sip:a@b.org");
        assert!(decode(Ef::Impu, &[impu[..6].to_vec()], None).is_err());

        let fqdn = [&[0x80, 9, 0x00][..], b"pcscf.ex", &[0xFF; 4]].concat();
        let v4 = vec![0x80, 5, 0x01, 10, 0, 0, 1, 0xFF];
        let mut v6 = vec![0x80, 17, 0x02];
        v6.extend([0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let d = decode(Ef::Pcscf, &[fqdn, v4, v6, vec![0xFF; 8]], None).unwrap();
        assert_eq!(d.evidence(), "3 P-CSCF(s): pcscf.ex, 10.0.0.1, 2001:db8::1");
        assert!(decode(Ef::Pcscf, &[vec![0x80, 4, 0x01, 10, 0, 0]], None).is_err());
        assert!(decode(Ef::Pcscf, &[vec![0x80, 2, 0x07, 1]], None).is_err());
    }

    #[test]
    fn manuarea_is_raw_bytes() {
        let d = decode(Ef::ManuArea, &[vec![0x01, 0xAB]], None).unwrap();
        assert_eq!(d.evidence(), "01AB");
        assert!(decode(Ef::ManuArea, &[vec![]], None).is_ok());
    }

    #[test]
    fn new_files_are_classified_by_place_and_application() {
        let p = |s: &str| s.parse::<Path>().unwrap();
        assert_eq!(classify(&p("3F00/0002")), Some(Ef::ManuArea));
        assert_eq!(classify(&p("3F00/7FFF/6F7B")), Some(Ef::Fplmn));
        assert_eq!(classify(&p("3F00/7F20/6F7B")), Some(Ef::Fplmn));
        assert_eq!(classify(&p("3F00/7FFF/6F61")), Some(Ef::OplmnWact));
        assert_eq!(classify(&p("3F00/7FFF/6F62")), Some(Ef::HplmnWact));
        assert_eq!(classify(&p("3F00/7FFF/6F78")), Some(Ef::Acc));
        assert_eq!(classify(&p("3F00/7FFF/6F7E")), Some(Ef::Loci));
        assert_eq!(classify(&p("3F00/7FFF/6F73")), Some(Ef::Psloci));
        assert_eq!(classify(&p("3F00/7FFF/6FE3")), Some(Ef::Epsloci));
        assert_eq!(classify(&p("3F00/7F10/6F3A")), Some(Ef::Adn));
        assert_eq!(classify(&p("3F00/7F10/5F3A/4F3A")), Some(Ef::Adn));
        assert_eq!(classify(&p("3F00/7FFF/5F3A/4F3A")), Some(Ef::Adn));
        assert_eq!(classify(&p("3F00/7FFF/6F3B")), Some(Ef::Fdn));
        // Not these files: another directory, or the ISIM identifiers on a USIM.
        assert_eq!(classify(&p("3F00/5F3A/4F3A")), None);
        assert_eq!(classify(&p("3F00/7FFF/6F02")), None);
        assert_eq!(classify(&p("3F00/7FFF/6F3A")), None);
        let isim = "3F00/ADF:A0000000871004";
        assert_eq!(classify(&p(&format!("{isim}/6F02"))), Some(Ef::Impi));
        assert_eq!(classify(&p(&format!("{isim}/6F04"))), Some(Ef::Impu));
        // 6F09 is EF.P-CSCF under the ISIM and EF.KeysPS under the USIM.
        assert_eq!(classify(&p(&format!("{isim}/6F09"))), Some(Ef::Pcscf));
        assert_eq!(
            classify(&p("3F00/ADF:A0000000871002/6F09")),
            Some(Ef::KeysPs)
        );
        assert_eq!(classify(&p("3F00/ADF:A0000000871002/6F02")), None);
    }

    #[test]
    fn long_plmn_lists_are_bounded() {
        let d = decode(Ef::Fplmn, &[PLMN_001_01.repeat(30)], None).unwrap();
        assert!(d.evidence().starts_with("30 PLMN(s): "));
        assert!(d.evidence().ends_with("(+6 more)"), "{}", d.evidence());
    }
}
