//! ES10x, the eUICC-side local interface of SGP.22: the generic STORE DATA
//! transport, and the request encoders and response decoders of ES10b and
//! ES10c. Library only: **nothing here sends a byte unless a caller hands it
//! a session**, and no command in this module is ever issued by the CLI.
//!
//! **Owns.** STORE DATA segmentation ([`blocks`], [`bpp_blocks`]), sending
//! and response reassembly through [`crate::session::send`] ([`store_data`],
//! [`load_bound_profile_package`]), the request encoders, and the typed
//! response decoders.
//!
//! **Does not own.** Signature or certificate checking, BPP construction or
//! protection (that is [`crate::scp03t`]), the ES9+ HTTPS half, or any
//! decision to talk to a card. The live card used during development is a
//! plain operator USIM, not an eUICC, so every test here is encode/decode
//! only.
//!
//! **Why this does not use [`crate::tlv`].** [`crate::tlv`] reads a one-octet
//! tag by design. ES10x payloads are full of two-octet tags (`BF 2D`,
//! `9F 70`), so this module carries its own small BER reader and writer with
//! tags up to four octets.
//!
//! # Provenance
//!
//! Every clause below is `[V] SGP.22 v2.5` checked against the public PDF
//! (`https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2023/05/SGP.22-v2.5.pdf`,
//! page numbers per the PDF) on 2026-10-07. The earlier "section numbers
//! come from euicc-rsp" provenance note on issue #18 is superseded by that
//! primary check (blocker 2 in AGENTS.md section 6).
//!
//! | Function | Clause | Request tag | Response tag |
//! |---|---|---|---|
//! | STORE DATA transport | 5.7.2 (Tables 47, 48), 2.5.5 | | |
//! | PrepareDownload | 5.7.5 | `BF21` | `BF21` |
//! | LoadBoundProfilePackage | 5.7.6, 2.5.5 | BPP segments | none or `BF37` |
//! | GetEUICCChallenge | 5.7.7 | `BF2E` | `BF2E` |
//! | GetEUICCInfo (EUICCInfo1, EUICCInfo2) | 5.7.8 | `BF20`, `BF22` | `BF20`, `BF22` |
//! | AuthenticateServer | 5.7.13 | `BF38` | `BF38` |
//! | CancelSession | 5.7.14 | `BF41` | `BF41` |
//! | GetProfilesInfo | 5.7.15 | `BF2D` | `BF2D` |
//! | EnableProfile | 5.7.16 | `BF31` | `BF31` |
//! | DeleteProfile | 5.7.18 | `BF33` | `BF33` |
//!
//! Where issue #18 differs from the spec: the issue says "`<=255` data bytes"
//! under 5.7.2, but Table 47 gives Lc as "Var." and the 255-byte rule is
//! stated in 5.7.6 and 2.5.5 (blocks of 255 bytes, a last block that MAY be
//! shorter). The numbers are otherwise as the issue lists them.
//!
//! # Tagging
//!
//! Annex H is `AUTOMATIC TAGS`. A CHOICE or SEQUENCE none of whose members is
//! tagged gets context tags `[0]`, `[1]`, ... on its members, which is why
//! `ProfileInfoListResponse` carries its list under `A0` and its error under
//! `81`, and why `CancelSessionRequest` is `80 <transactionId> 81 <reason>`.
//! Where a member is tagged explicitly (`[APPLICATION 55]`, `[0]`), the
//! untagged ones keep their universal tags (`30`, `04`, `02`). The expected
//! bytes in the tests were produced by an ASN.1 compiler over the module text,
//! not by this code.
//!
//! # Not implemented
//!
//! The "alternative case 3" form of EnableProfile and DeleteProfile (P1 `90`,
//! no response data, 5.7.16 and 5.7.18), and the ES10a, notification,
//! DisableProfile, eUICCMemoryReset, GetEID and SetNickname functions. None is
//! in issue #18. Decoders preserve tags they do not know in `unknown` fields
//! instead of dropping them.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "es10";

use std::fmt;

use crate::apdu::{Command, Header, Le};
use crate::session::{self, Exchange, Policy};
use crate::transport::CardSession;

/// STORE DATA, the one instruction every ES10x function rides on
/// ([SGP.22 v2.5 §5.7.2], Table 47).
pub const INS_STORE_DATA: u8 = 0xE2;

/// P1 of a STORE DATA block with more blocks to follow: BER-TLV data, case 4
/// ([SGP.22 v2.5 §5.7.2], Table 48).
pub const P1_MORE_BLOCKS: u8 = 0x11;

/// P1 of the last STORE DATA block ([SGP.22 v2.5 §5.7.2], Table 48).
pub const P1_LAST_BLOCK: u8 = 0x91;

/// Largest data field of one STORE DATA block
/// ([SGP.22 v2.5 §5.7.6] and §2.5.5: "blocks of 255 bytes or less").
pub const MAX_BLOCK_DATA: usize = 255;

/// Whether `cla` is one STORE DATA may use: `80`-`83` or `C0`-`CF`
/// ([SGP.22 v2.5 §5.7.2], Table 47).
pub const fn is_valid_class(cla: u8) -> bool {
    matches!(cla, 0x80..=0x83 | 0xC0..=0xCF)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A request that cannot be put on the wire.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// A field is outside the size its ASN.1 type allows.
    #[error("{field} must be {min} to {max} bytes, got {got}")]
    FieldLength {
        /// The ASN.1 field name.
        field: &'static str,
        /// Smallest allowed length.
        min: usize,
        /// Largest allowed length.
        max: usize,
        /// The length supplied.
        got: usize,
    },
    /// The class byte is not `80`-`83` or `C0`-`CF`.
    #[error("STORE DATA class {0:02X} is not 80-83 or C0-CF")]
    BadClass(u8),
    /// STORE DATA with no data.
    #[error("a STORE DATA block needs at least one data byte")]
    EmptyData,
    /// P2 is one byte, so one segment can hold at most 256 blocks.
    #[error("{bytes} bytes need {blocks} blocks, more than the 256 P2 can number")]
    TooManyBlocks {
        /// Bytes in the segment.
        bytes: usize,
        /// Blocks it would take.
        blocks: usize,
    },
}

/// Everything that can go wrong sending a STORE DATA sequence.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The data could not be segmented.
    #[error(transparent)]
    Encode(#[from] EncodeError),
    /// The exchange failed below the level this module reasons about.
    #[error(transparent)]
    Session(#[from] session::Error),
}

/// A response that is not what the function's ASN.1 says.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The data ended inside a field.
    #[error("response ends inside a field: needed {needed} more bytes, {available} left")]
    Truncated {
        /// Bytes the field still wanted.
        needed: usize,
        /// Bytes left.
        available: usize,
    },
    /// A length of `80` (indefinite), or one wider than three octets.
    #[error("unsupported BER length form {0:02X}")]
    UnsupportedLength(u8),
    /// A tag wider than four octets.
    #[error("tag wider than four octets")]
    UnsupportedTag,
    /// Bytes after the one TLV the response consists of.
    #[error("{0} bytes of trailing data")]
    TrailingData(usize),
    /// The outer tag is not the function's response tag.
    #[error("expected tag {expected:X}, found {found:X}")]
    WrongTag {
        /// The tag the function defines.
        expected: u32,
        /// The tag found.
        found: u32,
    },
    /// A tag that is not allowed at this position.
    #[error("unexpected tag {found:X} in {context}")]
    UnexpectedTag {
        /// Where it was found.
        context: &'static str,
        /// The tag found.
        found: u32,
    },
    /// A mandatory field is absent.
    #[error("mandatory field {0} is missing")]
    MissingField(&'static str),
    /// A field has a size its ASN.1 type does not allow.
    #[error("{field} must be {expected} bytes, got {got}")]
    BadLength {
        /// The ASN.1 field name.
        field: &'static str,
        /// What the type requires.
        expected: &'static str,
        /// The length found.
        got: usize,
    },
    /// A UTF8String that is not UTF-8.
    #[error("{0} is not valid UTF-8")]
    BadUtf8(&'static str),
    /// A BIT STRING whose unused-bits octet is impossible.
    #[error("{0} is not a valid BIT STRING")]
    BadBitString(&'static str),
}

// ---------------------------------------------------------------------------
// STORE DATA segmentation and sending
// ---------------------------------------------------------------------------

/// Cuts one data object into STORE DATA blocks: 255 bytes each, a last block
/// that may be shorter, P1 `11` on every block but the last and `91` on the
/// last, P2 counting from 0 ([SGP.22 v2.5 §5.7.2] Tables 47 and 48, §5.7.6,
/// §2.5.5). Every block is case 4 with Le `00`, as Table 47 gives.
///
/// A data object of exactly 255 bytes is one block with P1 `91`, not a full
/// block followed by an empty one.
///
/// # Errors
///
/// [`EncodeError::BadClass`], [`EncodeError::EmptyData`], and
/// [`EncodeError::TooManyBlocks`] above 256 blocks (65280 bytes).
pub fn blocks(cla: u8, data: &[u8]) -> Result<Vec<Command>, EncodeError> {
    if !is_valid_class(cla) {
        return Err(EncodeError::BadClass(cla));
    }
    if data.is_empty() {
        return Err(EncodeError::EmptyData);
    }
    let count = data.len().div_ceil(MAX_BLOCK_DATA);
    if count > 256 {
        return Err(EncodeError::TooManyBlocks {
            bytes: data.len(),
            blocks: count,
        });
    }
    Ok(data
        .chunks(MAX_BLOCK_DATA)
        .enumerate()
        .map(|(index, chunk)| {
            let p1 = if index + 1 == count {
                P1_LAST_BLOCK
            } else {
                P1_MORE_BLOCKS
            };
            // `index` < 256 was checked above.
            let header = Header::new(cla, INS_STORE_DATA, p1, index as u8);
            Command::case4(header, chunk, Le::Short(0x00))
        })
        .collect())
}

/// Cuts a Bound Profile Package, already split into segments by the caller,
/// into STORE DATA blocks: each segment is its own sequence, ending in P1
/// `91`, with the block number reset to 0 at its start ([SGP.22 v2.5 §5.7.6],
/// §2.5.5). Where the segment boundaries fall is the caller's job (and
/// [`crate::scp03t`]'s); this does not parse the BPP.
///
/// # Errors
///
/// Whatever [`blocks`] raises for any segment.
pub fn bpp_blocks<T: AsRef<[u8]>>(
    cla: u8,
    segments: &[T],
) -> Result<Vec<Vec<Command>>, EncodeError> {
    segments
        .iter()
        .map(|segment| blocks(cla, segment.as_ref()))
        .collect()
}

/// What sending one data object as a STORE DATA sequence did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    /// One logical exchange per block sent, in order. Each already includes
    /// the card's `61 xx` GET RESPONSE follow-ups.
    pub exchanges: Vec<Exchange>,
    /// Whether every block was sent. `false` means the card did not answer a
    /// non-final block with normal processing and the rest were **not** sent.
    pub complete: bool,
}

impl Sent {
    /// The response data of the last block sent. Intermediate blocks carry
    /// none ([SGP.22 v2.5 §5.7.6]); the last block carries the whole
    /// function response, reassembled across `61 xx` by [`session::send`].
    pub fn data(&self) -> &[u8] {
        self.exchanges.last().map_or(&[], Exchange::data)
    }
}

/// Sends one data object as a STORE DATA sequence and returns what the card
/// said. Nothing is retried; a non-final block the card does not accept with
/// normal processing (`90 00` or `91 xx`) ends the sequence early.
///
/// `policy.get_response_class` should match the channel the card is on;
/// the default is the GSM class, which an ISD-R on a logical channel will not
/// answer. This function does no card-safety checking: do not call it on a
/// card that is not an eUICC.
///
/// # Errors
///
/// [`Error::Encode`] from [`blocks`], [`Error::Session`] from
/// [`session::send`].
pub fn store_data<S: CardSession + ?Sized>(
    session: &mut S,
    cla: u8,
    data: &[u8],
    policy: &Policy,
) -> Result<Sent, Error> {
    send_blocks(session, blocks(cla, data)?, policy)
}

/// Sends a Bound Profile Package segment by segment ([`bpp_blocks`]) and
/// returns one [`Sent`] per segment sent. Stops at the first segment the card
/// does not accept; the Profile Installation Result, if any, is in the last
/// [`Sent::data`] ([SGP.22 v2.5 §5.7.6], §2.5.6).
///
/// # Errors
///
/// As [`store_data`]. All segments are cut before the first is sent, so a bad
/// segment sends nothing.
pub fn load_bound_profile_package<S: CardSession + ?Sized, T: AsRef<[u8]>>(
    session: &mut S,
    cla: u8,
    segments: &[T],
    policy: &Policy,
) -> Result<Vec<Sent>, Error> {
    let mut sent = Vec::new();
    for segment in bpp_blocks(cla, segments)? {
        let one = send_blocks(session, segment, policy)?;
        let done = one.complete
            && one
                .exchanges
                .last()
                .is_some_and(Exchange::is_normal_processing);
        sent.push(one);
        if !done {
            break;
        }
    }
    Ok(sent)
}

fn send_blocks<S: CardSession + ?Sized>(
    session: &mut S,
    commands: Vec<Command>,
    policy: &Policy,
) -> Result<Sent, Error> {
    let total = commands.len();
    let mut exchanges = Vec::with_capacity(total);
    for (index, command) in commands.iter().enumerate() {
        let exchange = session::send(session, command, policy)?;
        let accepted = exchange.is_normal_processing();
        exchanges.push(exchange);
        if !accepted && index + 1 < total {
            return Ok(Sent {
                exchanges,
                complete: false,
            });
        }
    }
    Ok(Sent {
        exchanges,
        complete: true,
    })
}

// ---------------------------------------------------------------------------
// BER writer and reader (multi-octet tags)
// ---------------------------------------------------------------------------

fn push_tlv(out: &mut Vec<u8>, tag: u32, value: &[u8]) {
    let bytes = tag.to_be_bytes();
    let skip = bytes.iter().take(3).take_while(|b| **b == 0).count();
    out.extend_from_slice(&bytes[skip..]);
    match value.len() {
        0..=0x7F => out.push(value.len() as u8),
        0x80..=0xFF => out.extend_from_slice(&[0x81, value.len() as u8]),
        0x100..=0xFFFF => {
            out.push(0x82);
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        n => {
            out.push(0x83);
            out.extend_from_slice(&(n as u32).to_be_bytes()[1..]);
        }
    }
    out.extend_from_slice(value);
}

fn tlv(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    push_tlv(&mut out, tag, value);
    out
}

/// One TLV found in a response: its tag, its contents, and its whole encoding.
#[derive(Clone, Copy)]
struct Node<'a> {
    tag: u32,
    value: &'a [u8],
    raw: &'a [u8],
}

fn parse(mut input: &[u8]) -> Result<Vec<Node<'_>>, DecodeError> {
    let mut nodes = Vec::new();
    while !input.is_empty() {
        let whole = input;
        let mut tag = u32::from(input[0]);
        let mut at = 1;
        if input[0] & 0x1F == 0x1F {
            loop {
                let next = *input.get(at).ok_or(DecodeError::Truncated {
                    needed: 1,
                    available: 0,
                })?;
                at += 1;
                if at > 4 {
                    return Err(DecodeError::UnsupportedTag);
                }
                tag = (tag << 8) | u32::from(next);
                if next & 0x80 == 0 {
                    break;
                }
            }
        }
        let first = *input.get(at).ok_or(DecodeError::Truncated {
            needed: 1,
            available: 0,
        })?;
        at += 1;
        let len = match first {
            0x00..=0x7F => usize::from(first),
            0x81..=0x83 => {
                let count = usize::from(first & 0x7F);
                let bytes = input.get(at..at + count).ok_or(DecodeError::Truncated {
                    needed: count,
                    available: input.len().saturating_sub(at),
                })?;
                at += count;
                bytes.iter().fold(0usize, |n, b| (n << 8) | usize::from(*b))
            }
            other => return Err(DecodeError::UnsupportedLength(other)),
        };
        let value = input.get(at..at + len).ok_or(DecodeError::Truncated {
            needed: len,
            available: input.len().saturating_sub(at),
        })?;
        nodes.push(Node {
            tag,
            value,
            raw: &whole[..at + len],
        });
        input = &input[at + len..];
    }
    Ok(nodes)
}

/// The contents of the one TLV `data` consists of, which must carry `tag`.
fn only<'a>(data: &'a [u8], tag: u32) -> Result<Vec<Node<'a>>, DecodeError> {
    let outer = parse(data)?;
    let Some(node) = outer.first() else {
        return Err(DecodeError::Truncated {
            needed: 1,
            available: 0,
        });
    };
    if outer.len() > 1 {
        return Err(DecodeError::TrailingData(data.len() - node.raw.len()));
    }
    if node.tag != tag {
        return Err(DecodeError::WrongTag {
            expected: tag,
            found: node.tag,
        });
    }
    parse(node.value)
}

/// The value of the one TLV `data` consists of, which must carry `tag`. For
/// the ES9+ layer ([`crate::es9`]), which gets whole TLVs inside base64.
pub(crate) fn single_value(data: &[u8], tag: u32) -> Result<&[u8], DecodeError> {
    let outer = parse(data)?;
    let Some(node) = outer.first() else {
        return Err(DecodeError::Truncated {
            needed: 1,
            available: 0,
        });
    };
    if outer.len() > 1 {
        return Err(DecodeError::TrailingData(data.len() - node.raw.len()));
    }
    if node.tag != tag {
        return Err(DecodeError::WrongTag {
            expected: tag,
            found: node.tag,
        });
    }
    Ok(node.value)
}

/// A TLV a decoder did not recognise, kept whole so nothing is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unknown {
    /// The tag, as read (`0xBF22`, `0x99`, ...).
    pub tag: u32,
    /// The value octets.
    pub value: Vec<u8>,
}

fn keep(unknown: &mut Vec<Unknown>, node: Node<'_>) {
    unknown.push(Unknown {
        tag: node.tag,
        value: node.value.to_vec(),
    });
}

fn exact<const N: usize>(value: &[u8], field: &'static str) -> Result<[u8; N], DecodeError> {
    value.try_into().map_err(|_| DecodeError::BadLength {
        field,
        expected: match N {
            3 => "3",
            16 => "16",
            _ => "a fixed number of",
        },
        got: value.len(),
    })
}

fn ranged(
    value: &[u8],
    field: &'static str,
    expected: &'static str,
    ok: std::ops::RangeInclusive<usize>,
) -> Result<Vec<u8>, DecodeError> {
    if ok.contains(&value.len()) {
        Ok(value.to_vec())
    } else {
        Err(DecodeError::BadLength {
            field,
            expected,
            got: value.len(),
        })
    }
}

fn utf8(value: &[u8], field: &'static str) -> Result<String, DecodeError> {
    String::from_utf8(value.to_vec()).map_err(|_| DecodeError::BadUtf8(field))
}

/// A one-octet INTEGER, which is all any code or enumeration here needs.
fn small_int(value: &[u8], field: &'static str) -> Result<u8, DecodeError> {
    match value {
        [byte] => Ok(*byte),
        _ => Err(DecodeError::BadLength {
            field,
            expected: "1",
            got: value.len(),
        }),
    }
}

fn require<T>(value: Option<T>, field: &'static str) -> Result<T, DecodeError> {
    value.ok_or(DecodeError::MissingField(field))
}

/// A decoded ASN.1 BIT STRING: the unused-bit count and the octets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitString {
    /// Unused low bits of the last octet, 0 to 7.
    pub unused_bits: u8,
    /// The octets after the unused-bits octet.
    pub bytes: Vec<u8>,
}

impl BitString {
    fn decode(value: &[u8], field: &'static str) -> Result<Self, DecodeError> {
        match value.split_first() {
            Some((&unused, rest)) if unused <= 7 && !(rest.is_empty() && unused != 0) => Ok(Self {
                unused_bits: unused,
                bytes: rest.to_vec(),
            }),
            _ => Err(DecodeError::BadBitString(field)),
        }
    }

    /// Named bit `n` in ASN.1 numbering: bit 0 is the most significant bit of
    /// the first octet. Bits past the end read as `false`, as DER trims
    /// trailing zeros.
    pub fn bit(&self, n: usize) -> bool {
        let used = (self.bytes.len() * 8).saturating_sub(usize::from(self.unused_bits));
        n < used && self.bytes[n / 8] & (0x80 >> (n % 8)) != 0
    }
}

/// `code_enum!` makes an ASN.1 INTEGER enumeration that keeps values the
/// spec does not name.
macro_rules! code_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident = $value:expr),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $(#[doc = stringify!($variant)] $variant,)+
            /// A value the specification does not define.
            Unknown(u8),
        }

        impl $name {
            /// Reads the enumeration from its INTEGER value.
            pub const fn from_code(code: u8) -> Self {
                match code {
                    $($value => Self::$variant,)+
                    other => Self::Unknown(other),
                }
            }

            /// The INTEGER value.
            pub const fn code(self) -> u8 {
                match self {
                    $(Self::$variant => $value,)+
                    Self::Unknown(code) => code,
                }
            }
        }
    };
}

code_enum! {
    /// `CancelSessionReason` ([SGP.22 v2.5 §5.7.14]).
    CancelSessionReason {
        EndUserRejection = 0, Postponed = 1, Timeout = 2, PprNotAllowed = 3,
        MetadataMismatch = 4, LoadBppExecutionError = 5, UndefinedReason = 127,
    }
}
code_enum! {
    /// `cancelSessionResponseError` ([SGP.22 v2.5 §5.7.14]).
    CancelSessionError { InvalidTransactionId = 5, UndefinedError = 127 }
}
code_enum! {
    /// `DownloadErrorCode` ([SGP.22 v2.5 §5.7.5]).
    DownloadErrorCode {
        InvalidCertificate = 1, InvalidSignature = 2, UnsupportedCurve = 3,
        NoSessionContext = 4, InvalidTransactionId = 5, UndefinedError = 127,
    }
}
code_enum! {
    /// `AuthenticateErrorCode` ([SGP.22 v2.5 §5.7.13]).
    AuthenticateErrorCode {
        InvalidCertificate = 1, InvalidSignature = 2, UnsupportedCurve = 3,
        NoSessionContext = 4, InvalidOid = 5, EuiccChallengeMismatch = 6,
        CiPkUnknown = 7, UndefinedError = 127,
    }
}
code_enum! {
    /// `ProfileState` ([SGP.22 v2.5 §5.7.15]).
    ProfileState { Disabled = 0, Enabled = 1 }
}
code_enum! {
    /// `ProfileClass` ([SGP.22 v2.5 §5.7.15]).
    ProfileClass { Test = 0, Provisioning = 1, Operational = 2 }
}
code_enum! {
    /// `IconType` ([SGP.22 v2.5 §5.7.15]).
    IconType { Jpg = 0, Png = 1 }
}
code_enum! {
    /// `ProfileInfoListError` ([SGP.22 v2.5 §5.7.15]).
    ProfileInfoListError { IncorrectInputValues = 1, UndefinedError = 127 }
}
code_enum! {
    /// `enableResult` ([SGP.22 v2.5 §5.7.16]).
    EnableResult {
        Ok = 0, IccidOrAidNotFound = 1, ProfileNotInDisabledState = 2,
        DisallowedByPolicy = 3, WrongProfileReenabling = 4, CatBusy = 5,
        UndefinedError = 127,
    }
}
code_enum! {
    /// `deleteResult` ([SGP.22 v2.5 §5.7.18]).
    DeleteResult {
        Ok = 0, IccidOrAidNotFound = 1, ProfileNotInDisabledState = 2,
        DisallowedByPolicy = 3, UndefinedError = 127,
    }
}
code_enum! {
    /// `euiccCategory` ([SGP.22 v2.5 §5.7.8]).
    EuiccCategory { Other = 0, BasicEuicc = 1, MediumEuicc = 2, ContactlessEuicc = 3 }
}

// ---------------------------------------------------------------------------
// Request encoders
// ---------------------------------------------------------------------------

fn check(value: &[u8], field: &'static str, min: usize, max: usize) -> Result<(), EncodeError> {
    if (min..=max).contains(&value.len()) {
        Ok(())
    } else {
        Err(EncodeError::FieldLength {
            field,
            min,
            max,
            got: value.len(),
        })
    }
}

/// `GetEuiccChallengeRequest`: `BF 2E 00` ([SGP.22 v2.5 §5.7.7]).
pub fn get_euicc_challenge_request() -> Vec<u8> {
    tlv(0xBF2E, &[])
}

/// `GetEuiccInfo1Request`: `BF 20 00` ([SGP.22 v2.5 §5.7.8]).
pub fn get_euicc_info1_request() -> Vec<u8> {
    tlv(0xBF20, &[])
}

/// `GetEuiccInfo2Request`: `BF 22 00` ([SGP.22 v2.5 §5.7.8]).
pub fn get_euicc_info2_request() -> Vec<u8> {
    tlv(0xBF22, &[])
}

/// `GetEuiccDataRequest` asking for the EID only, `BF3E 03 5C 01 5A`
/// ([SGP.22 v2.5 §5.7.20], the frame pySim sends).
pub fn get_eid_request() -> Vec<u8> {
    tlv(0xBF3E, &tlv(0x5C, &[0x5A]))
}

/// `ListNotificationRequest` with no filter, `BF28 00`: every pending
/// notification's metadata, nothing retrieved or removed ([SGP.22 v2.5 §5.7.11]).
pub fn list_notification_request() -> Vec<u8> {
    tlv(0xBF28, &[])
}

/// `PrepareDownloadRequest`, `BF21` ([SGP.22 v2.5 §5.7.5]). The signed and
/// certificate parts come from the SM-DP+ (`ES9+.GetBoundProfilePackage`
/// input) and are passed through as DER, because the signature covers their
/// exact bytes.
#[derive(Debug, Clone, Copy)]
pub struct PrepareDownloadRequest<'a> {
    /// `smdpSigned2`, complete DER including its `30` header.
    pub smdp_signed2: &'a [u8],
    /// `smdpSignature2`, the value of tag `5F37`.
    pub smdp_signature2: &'a [u8],
    /// `hashCc`, 32 bytes, when a confirmation code is required.
    pub hash_cc: Option<&'a [u8]>,
    /// `smdpCertificate` (CERT.DPpb.ECDSA), complete DER.
    pub smdp_certificate: &'a [u8],
}

impl PrepareDownloadRequest<'_> {
    /// The STORE DATA data field.
    ///
    /// # Errors
    ///
    /// [`EncodeError::FieldLength`] when `hash_cc` is not 32 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut body = self.smdp_signed2.to_vec();
        push_tlv(&mut body, 0x5F37, self.smdp_signature2);
        if let Some(hash) = self.hash_cc {
            check(hash, "hashCc", 32, 32)?;
            push_tlv(&mut body, 0x04, hash);
        }
        body.extend_from_slice(self.smdp_certificate);
        Ok(tlv(0xBF21, &body))
    }
}

/// `AuthenticateServerRequest`, `BF38` ([SGP.22 v2.5 §5.7.13]). Like
/// [`PrepareDownloadRequest`], the server-supplied parts are DER passed
/// through.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticateServerRequest<'a> {
    /// `serverSigned1`, complete DER including its `30` header.
    pub server_signed1: &'a [u8],
    /// `serverSignature1`, the value of tag `5F37`.
    pub server_signature1: &'a [u8],
    /// `euiccCiPKIdToBeUsed`, the value of a SubjectKeyIdentifier.
    pub euicc_ci_pk_id_to_be_used: &'a [u8],
    /// `serverCertificate` (CERT.XXauth.ECDSA), complete DER.
    pub server_certificate: &'a [u8],
    /// `ctxParams1`, complete DER including its `A0` header.
    pub ctx_params1: &'a [u8],
}

impl AuthenticateServerRequest<'_> {
    /// The STORE DATA data field.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = self.server_signed1.to_vec();
        push_tlv(&mut body, 0x5F37, self.server_signature1);
        push_tlv(&mut body, 0x04, self.euicc_ci_pk_id_to_be_used);
        body.extend_from_slice(self.server_certificate);
        body.extend_from_slice(self.ctx_params1);
        tlv(0xBF38, &body)
    }
}

/// `CancelSessionRequest`, `BF41` ([SGP.22 v2.5 §5.7.14]):
/// `80 <transactionId> 81 <reason>`.
///
/// # Errors
///
/// [`EncodeError::FieldLength`] unless `transaction_id` is 1 to 16 bytes
/// (Annex H, `TransactionId`).
pub fn cancel_session_request(
    transaction_id: &[u8],
    reason: CancelSessionReason,
) -> Result<Vec<u8>, EncodeError> {
    check(transaction_id, "transactionId", 1, 16)?;
    let mut body = tlv(0x80, transaction_id);
    push_tlv(&mut body, 0x81, &[reason.code()]);
    Ok(tlv(0xBF41, &body))
}

/// A profile named by ISD-P AID or by ICCID, as EnableProfile and
/// DeleteProfile take it ([SGP.22 v2.5 §5.7.16], §5.7.18).
#[derive(Debug, Clone, Copy)]
pub enum ProfileIdentifier<'a> {
    /// The ISD-P AID, 1 to 16 bytes, tag `4F`.
    IsdpAid(&'a [u8]),
    /// The ICCID as coded in EF ICCID (swapped nibbles), exactly 10 bytes,
    /// tag `5A`.
    Iccid(&'a [u8]),
}

impl ProfileIdentifier<'_> {
    fn encode(self) -> Result<Vec<u8>, EncodeError> {
        match self {
            Self::IsdpAid(aid) => {
                check(aid, "isdpAid", 1, 16)?;
                Ok(tlv(0x4F, aid))
            }
            Self::Iccid(iccid) => {
                check(iccid, "iccid", 10, 10)?;
                Ok(tlv(0x5A, iccid))
            }
        }
    }
}

/// `EnableProfileRequest`, `BF31` ([SGP.22 v2.5 §5.7.16]):
/// `A0 <identifier> 81 <refreshFlag>`, the flag `FF` for true.
///
/// # Errors
///
/// [`EncodeError::FieldLength`] for a malformed identifier.
pub fn enable_profile_request(
    profile: ProfileIdentifier<'_>,
    refresh: bool,
) -> Result<Vec<u8>, EncodeError> {
    let mut body = tlv(0xA0, &profile.encode()?);
    push_tlv(&mut body, 0x81, &[if refresh { 0xFF } else { 0x00 }]);
    Ok(tlv(0xBF31, &body))
}

/// `DeleteProfileRequest`, `BF33` ([SGP.22 v2.5 §5.7.18]): the identifier
/// directly, `4F` or `5A`.
///
/// # Errors
///
/// [`EncodeError::FieldLength`] for a malformed identifier.
pub fn delete_profile_request(profile: ProfileIdentifier<'_>) -> Result<Vec<u8>, EncodeError> {
    Ok(tlv(0xBF33, &profile.encode()?))
}

/// The `searchCriteria` of GetProfilesInfo ([SGP.22 v2.5 §5.7.15]).
#[derive(Debug, Clone, Copy)]
pub enum SearchCriteria<'a> {
    /// By ISD-P AID, tag `4F`.
    IsdpAid(&'a [u8]),
    /// By ICCID, tag `5A`.
    Iccid(&'a [u8]),
    /// By profile class, tag `95`.
    ProfileClass(ProfileClass),
}

/// `ProfileInfoListRequest`, `BF2D` ([SGP.22 v2.5 §5.7.15]).
///
/// `tag_list` is the tags to return per profile, as numbers (`0x5A`,
/// `0x9F70`); tags up to `0xFF` are one octet, above that two. With neither
/// argument the result is the spec's `BF2D 00` example.
///
/// # Errors
///
/// [`EncodeError::FieldLength`] for a malformed AID or ICCID.
pub fn get_profiles_info_request(
    criteria: Option<SearchCriteria<'_>>,
    tag_list: Option<&[u16]>,
) -> Result<Vec<u8>, EncodeError> {
    let mut body = Vec::new();
    if let Some(criteria) = criteria {
        let inner = match criteria {
            SearchCriteria::IsdpAid(aid) => ProfileIdentifier::IsdpAid(aid).encode()?,
            SearchCriteria::Iccid(iccid) => ProfileIdentifier::Iccid(iccid).encode()?,
            SearchCriteria::ProfileClass(class) => tlv(0x95, &[class.code()]),
        };
        push_tlv(&mut body, 0xA0, &inner);
    }
    if let Some(tags) = tag_list {
        let mut list = Vec::new();
        for tag in tags {
            if *tag > 0xFF {
                list.extend_from_slice(&tag.to_be_bytes());
            } else {
                list.push(*tag as u8);
            }
        }
        push_tlv(&mut body, 0x5C, &list);
    }
    Ok(tlv(0xBF2D, &body))
}

// ---------------------------------------------------------------------------
// Response decoders
// ---------------------------------------------------------------------------

/// `GetEuiccChallengeResponse` ([SGP.22 v2.5 §5.7.7]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EuiccChallenge {
    /// `euiccChallenge`, 16 random bytes.
    pub challenge: [u8; 16],
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of GetEUICCChallenge.
///
/// # Errors
///
/// A [`DecodeError`] when the data is not a `BF2E` holding a 16-byte `80`.
pub fn decode_get_euicc_challenge(data: &[u8]) -> Result<EuiccChallenge, DecodeError> {
    let mut challenge = None;
    let mut unknown = Vec::new();
    for node in only(data, 0xBF2E)? {
        match node.tag {
            0x80 if challenge.is_none() => challenge = Some(exact(node.value, "euiccChallenge")?),
            _ => keep(&mut unknown, node),
        }
    }
    Ok(EuiccChallenge {
        challenge: require(challenge, "euiccChallenge")?,
        unknown,
    })
}

fn key_id_list(value: &[u8], context: &'static str) -> Result<Vec<Vec<u8>>, DecodeError> {
    parse(value)?
        .into_iter()
        .map(|node| {
            if node.tag == 0x04 {
                Ok(node.value.to_vec())
            } else {
                Err(DecodeError::UnexpectedTag {
                    context,
                    found: node.tag,
                })
            }
        })
        .collect()
}

/// `EUICCInfo1` ([SGP.22 v2.5 §5.7.8]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EuiccInfo1 {
    /// `svn`, the SGP.22 version supported, major/minor/revision.
    pub svn: [u8; 3],
    /// `euiccCiPKIdListForVerification`, most preferred first.
    pub ci_pk_id_for_verification: Vec<Vec<u8>>,
    /// `euiccCiPKIdListForSigning`, most preferred first.
    pub ci_pk_id_for_signing: Vec<Vec<u8>>,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of GetEUICCInfo for EUICCInfo1 (`BF20`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_euicc_info1(data: &[u8]) -> Result<EuiccInfo1, DecodeError> {
    let (mut svn, mut verification, mut signing) = (None, None, None);
    let mut unknown = Vec::new();
    for node in only(data, 0xBF20)? {
        match node.tag {
            0x82 if svn.is_none() => svn = Some(exact(node.value, "svn")?),
            0xA9 if verification.is_none() => {
                verification = Some(key_id_list(node.value, "euiccCiPKIdListForVerification")?);
            }
            0xAA if signing.is_none() => {
                signing = Some(key_id_list(node.value, "euiccCiPKIdListForSigning")?);
            }
            _ => keep(&mut unknown, node),
        }
    }
    Ok(EuiccInfo1 {
        svn: require(svn, "svn")?,
        ci_pk_id_for_verification: require(verification, "euiccCiPKIdListForVerification")?,
        ci_pk_id_for_signing: require(signing, "euiccCiPKIdListForSigning")?,
        unknown,
    })
}

/// `CertificationDataObject` ([SGP.22 v2.5 §5.7.8]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificationDataObject {
    /// `platformLabel`.
    pub platform_label: String,
    /// `discoveryBaseURL`, possibly empty.
    pub discovery_base_url: String,
}

/// `EUICCInfo2` ([SGP.22 v2.5 §5.7.8]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EuiccInfo2 {
    /// `profileVersion`, major/minor/revision.
    pub profile_version: [u8; 3],
    /// `svn`.
    pub svn: [u8; 3],
    /// `euiccFirmwareVer`.
    pub euicc_firmware_ver: [u8; 3],
    /// `extCardResource`, raw (ETSI TS 102 226).
    pub ext_card_resource: Vec<u8>,
    /// `uiccCapability`; named bits are defined by the TCA profile package.
    pub uicc_capability: BitString,
    /// `ts102241Version`.
    pub ts102241_version: Option<[u8; 3]>,
    /// `globalplatformVersion`.
    pub globalplatform_version: Option<[u8; 3]>,
    /// `rspCapability`: bit 0 additionalProfile, 1 crlSupport, 2 rpmSupport,
    /// 3 testProfileSupport, 4 deviceInfoExtensibilitySupport, 5
    /// serviceSpecificDataSupport.
    pub rsp_capability: BitString,
    /// `euiccCiPKIdListForVerification`, most preferred first.
    pub ci_pk_id_for_verification: Vec<Vec<u8>>,
    /// `euiccCiPKIdListForSigning`, most preferred first.
    pub ci_pk_id_for_signing: Vec<Vec<u8>>,
    /// `euiccCategory`.
    pub euicc_category: Option<EuiccCategory>,
    /// `forbiddenProfilePolicyRules` (`PprIds`: bit 0 pprUpdateControl, 1
    /// ppr1, 2 ppr2).
    pub forbidden_profile_policy_rules: Option<BitString>,
    /// `ppVersion`, the Protection Profile version.
    pub pp_version: [u8; 3],
    /// `sasAcreditationNumber`.
    pub sas_accreditation_number: String,
    /// `certificationDataObject`.
    pub certification_data_object: Option<CertificationDataObject>,
    /// `treProperties`: bit 0 isDiscrete, 1 isIntegrated, 2 usesRemoteMemory.
    pub tre_properties: Option<BitString>,
    /// `treProductReference`.
    pub tre_product_reference: Option<String>,
    /// `additionalEuiccProfilePackageVersions`.
    pub additional_euicc_profile_package_versions: Vec<[u8; 3]>,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of GetEUICCInfo for EUICCInfo2 (`BF22`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_euicc_info2(data: &[u8]) -> Result<EuiccInfo2, DecodeError> {
    info2_from_nodes(only(data, 0xBF22)?)
}

fn info2_from_nodes(nodes: Vec<Node<'_>>) -> Result<EuiccInfo2, DecodeError> {
    let mut profile_version = None;
    let mut svn = None;
    let mut firmware = None;
    let mut ext_card_resource = None;
    let mut uicc_capability = None;
    let mut ts102241 = None;
    let mut gp = None;
    let mut rsp_capability = None;
    let mut verification = None;
    let mut signing = None;
    let mut category = None;
    let mut forbidden = None;
    let mut pp_version = None;
    let mut sas = None;
    let mut cert_object = None;
    let mut tre_properties = None;
    let mut tre_reference = None;
    let mut additional = Vec::new();
    let mut unknown = Vec::new();
    for node in nodes {
        let v = node.value;
        match node.tag {
            0x81 if profile_version.is_none() => {
                profile_version = Some(exact(v, "profileVersion")?)
            }
            0x82 if svn.is_none() => svn = Some(exact(v, "svn")?),
            0x83 if firmware.is_none() => firmware = Some(exact(v, "euiccFirmwareVer")?),
            0x84 if ext_card_resource.is_none() => ext_card_resource = Some(v.to_vec()),
            0x85 if uicc_capability.is_none() => {
                uicc_capability = Some(BitString::decode(v, "uiccCapability")?);
            }
            0x86 if ts102241.is_none() => ts102241 = Some(exact(v, "ts102241Version")?),
            0x87 if gp.is_none() => gp = Some(exact(v, "globalplatformVersion")?),
            0x88 if rsp_capability.is_none() => {
                rsp_capability = Some(BitString::decode(v, "rspCapability")?);
            }
            0xA9 if verification.is_none() => {
                verification = Some(key_id_list(v, "euiccCiPKIdListForVerification")?);
            }
            0xAA if signing.is_none() => {
                signing = Some(key_id_list(v, "euiccCiPKIdListForSigning")?);
            }
            0x8B if category.is_none() => {
                category = Some(EuiccCategory::from_code(small_int(v, "euiccCategory")?));
            }
            0x99 if forbidden.is_none() => {
                forbidden = Some(BitString::decode(v, "forbiddenProfilePolicyRules")?);
            }
            // ppVersion and sasAcreditationNumber are untagged in the module,
            // so they keep their universal tags.
            0x04 if pp_version.is_none() => pp_version = Some(exact(v, "ppVersion")?),
            0x0C if sas.is_none() => sas = Some(utf8(v, "sasAcreditationNumber")?),
            0xAC if cert_object.is_none() => {
                let (mut label, mut url) = (None, None);
                for inner in parse(v)? {
                    match inner.tag {
                        0x80 if label.is_none() => {
                            label = Some(utf8(inner.value, "platformLabel")?)
                        }
                        0x81 if url.is_none() => url = Some(utf8(inner.value, "discoveryBaseURL")?),
                        found => {
                            return Err(DecodeError::UnexpectedTag {
                                context: "certificationDataObject",
                                found,
                            })
                        }
                    }
                }
                cert_object = Some(CertificationDataObject {
                    platform_label: require(label, "platformLabel")?,
                    discovery_base_url: require(url, "discoveryBaseURL")?,
                });
            }
            0x8D if tre_properties.is_none() => {
                tre_properties = Some(BitString::decode(v, "treProperties")?);
            }
            0x8E if tre_reference.is_none() => {
                tre_reference = Some(utf8(v, "treProductReference")?);
            }
            0xAF if additional.is_empty() => {
                for inner in parse(v)? {
                    if inner.tag != 0x04 {
                        return Err(DecodeError::UnexpectedTag {
                            context: "additionalEuiccProfilePackageVersions",
                            found: inner.tag,
                        });
                    }
                    additional.push(exact(inner.value, "additionalEuiccProfilePackageVersions")?);
                }
            }
            _ => keep(&mut unknown, node),
        }
    }
    Ok(EuiccInfo2 {
        profile_version: require(profile_version, "profileVersion")?,
        svn: require(svn, "svn")?,
        euicc_firmware_ver: require(firmware, "euiccFirmwareVer")?,
        ext_card_resource: require(ext_card_resource, "extCardResource")?,
        uicc_capability: require(uicc_capability, "uiccCapability")?,
        ts102241_version: ts102241,
        globalplatform_version: gp,
        rsp_capability: require(rsp_capability, "rspCapability")?,
        ci_pk_id_for_verification: require(verification, "euiccCiPKIdListForVerification")?,
        ci_pk_id_for_signing: require(signing, "euiccCiPKIdListForSigning")?,
        euicc_category: category,
        forbidden_profile_policy_rules: forbidden,
        pp_version: require(pp_version, "ppVersion")?,
        sas_accreditation_number: require(sas, "sasAcreditationNumber")?,
        certification_data_object: cert_object,
        tre_properties,
        tre_product_reference: tre_reference,
        additional_euicc_profile_package_versions: additional,
        unknown,
    })
}

/// Decodes the response data of GetEuiccData asked for tag `5A` only: the
/// 16-byte EID ([SGP.22 v2.5 §5.7.20]).
///
/// # Errors
///
/// A [`DecodeError`] when the data is not a `BF3E` holding a 16-byte `5A`.
pub fn decode_get_eid(data: &[u8]) -> Result<[u8; 16], DecodeError> {
    let mut eid = None;
    for node in only(data, 0xBF3E)? {
        if node.tag == 0x5A && eid.is_none() {
            eid = Some(exact(node.value, "eidValue")?);
        }
    }
    require(eid, "eidValue")
}

/// One `NotificationMetadata` (`BF2F`) of a ListNotification response
/// ([SGP.22 v2.5 §5.7.11]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMetadata {
    /// `seqNumber`.
    pub seq_number: u32,
    /// `profileManagementOperation`: bit 0 install, 1 enable, 2 disable, 3 delete.
    pub operation: BitString,
    /// `notificationAddress`, the SM-DP+ or other recipient.
    pub address: String,
    /// `iccid`, tag `5A`, when present.
    pub iccid: Option<Vec<u8>>,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// `ListNotificationResponse` ([SGP.22 v2.5 §5.7.11]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListNotificationResponse {
    /// `notificationMetadataList` (`A0`); empty when none are pending.
    Ok(Vec<NotificationMetadata>),
    /// `listNotificationsResultError` (`81`), 127 being undefinedError.
    Error(u8),
}

/// Decodes the response data of ListNotification (`BF28`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed structure.
pub fn decode_list_notification(data: &[u8]) -> Result<ListNotificationResponse, DecodeError> {
    let outer = only(data, 0xBF28)?;
    let [choice] = outer.as_slice() else {
        return Err(DecodeError::MissingField("listNotificationResponse"));
    };
    match choice.tag {
        0x81 => Ok(ListNotificationResponse::Error(small_int(
            choice.value,
            "listNotificationsResultError",
        )?)),
        0xA0 => parse(choice.value)?
            .into_iter()
            .map(|node| match node.tag {
                0xBF2F => decode_notification_metadata(node.value),
                found => Err(DecodeError::UnexpectedTag {
                    context: "notificationMetadataList",
                    found,
                }),
            })
            .collect::<Result<_, _>>()
            .map(ListNotificationResponse::Ok),
        found => Err(DecodeError::UnexpectedTag {
            context: "ListNotificationResponse",
            found,
        }),
    }
}

fn decode_notification_metadata(value: &[u8]) -> Result<NotificationMetadata, DecodeError> {
    let (mut seq, mut operation, mut address, mut iccid) = (None, None, None, None);
    let mut unknown = Vec::new();
    for node in parse(value)? {
        let v = node.value;
        match node.tag {
            0x80 if seq.is_none() => {
                if v.is_empty() || v.len() > 4 {
                    return Err(DecodeError::BadLength {
                        field: "seqNumber",
                        expected: "1 to 4",
                        got: v.len(),
                    });
                }
                seq = Some(v.iter().fold(0u32, |n, b| (n << 8) | u32::from(*b)));
            }
            0x81 if operation.is_none() => {
                operation = Some(BitString::decode(v, "profileManagementOperation")?);
            }
            0x0C if address.is_none() => address = Some(utf8(v, "notificationAddress")?),
            0x5A if iccid.is_none() => iccid = Some(ranged(v, "iccid", "10", 10..=10)?),
            _ => keep(&mut unknown, node),
        }
    }
    Ok(NotificationMetadata {
        seq_number: require(seq, "seqNumber")?,
        operation: require(operation, "profileManagementOperation")?,
        address: require(address, "notificationAddress")?,
        iccid,
        unknown,
    })
}

/// `PrepareDownloadResponse` ([SGP.22 v2.5 §5.7.5]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareDownloadResponse {
    /// `downloadResponseOk` (`A0`).
    Ok(PrepareDownloadOk),
    /// `downloadResponseError` (`A1`).
    Error(PrepareDownloadError),
}

/// `PrepareDownloadResponseOk`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareDownloadOk {
    /// `euiccSigned2`, complete DER: the exact bytes `euiccSignature2` covers.
    pub euicc_signed2: Vec<u8>,
    /// `euiccSigned2.transactionId`.
    pub transaction_id: Vec<u8>,
    /// `euiccSigned2.euiccOtpk` (otPK.EUICC.ECKA), tag `5F49`.
    pub euicc_otpk: Vec<u8>,
    /// `euiccSigned2.hashCc`, when present.
    pub hash_cc: Option<Vec<u8>>,
    /// `euiccSignature2`, tag `5F37`.
    pub euicc_signature2: Vec<u8>,
    /// Tags this decoder does not know, at either level.
    pub unknown: Vec<Unknown>,
}

/// `PrepareDownloadResponseError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareDownloadError {
    /// `transactionId`.
    pub transaction_id: Vec<u8>,
    /// `downloadErrorCode`.
    pub code: DownloadErrorCode,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of PrepareDownload (`BF21`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_prepare_download(data: &[u8]) -> Result<PrepareDownloadResponse, DecodeError> {
    let outer = only(data, 0xBF21)?;
    let [choice] = outer.as_slice() else {
        return Err(DecodeError::MissingField("downloadResponse"));
    };
    let inner = parse(choice.value)?;
    let mut unknown = Vec::new();
    match choice.tag {
        0xA0 => {
            let (mut signed, mut signature) = (None, None);
            for node in inner {
                match node.tag {
                    0x30 if signed.is_none() => signed = Some(node),
                    0x5F37 if signature.is_none() => signature = Some(node.value.to_vec()),
                    _ => keep(&mut unknown, node),
                }
            }
            let signed = require(signed, "euiccSigned2")?;
            let (mut tid, mut otpk, mut hash) = (None, None, None);
            for node in parse(signed.value)? {
                match node.tag {
                    0x80 if tid.is_none() => {
                        tid = Some(ranged(node.value, "transactionId", "1 to 16", 1..=16)?);
                    }
                    0x5F49 if otpk.is_none() => otpk = Some(node.value.to_vec()),
                    0x04 if hash.is_none() => {
                        hash = Some(ranged(node.value, "hashCc", "32", 32..=32)?)
                    }
                    _ => keep(&mut unknown, node),
                }
            }
            Ok(PrepareDownloadResponse::Ok(PrepareDownloadOk {
                euicc_signed2: signed.raw.to_vec(),
                transaction_id: require(tid, "transactionId")?,
                euicc_otpk: require(otpk, "euiccOtpk")?,
                hash_cc: hash,
                euicc_signature2: require(signature, "euiccSignature2")?,
                unknown,
            }))
        }
        0xA1 => {
            let (mut tid, mut code) = (None, None);
            for node in inner {
                match node.tag {
                    0x80 if tid.is_none() => {
                        tid = Some(ranged(node.value, "transactionId", "1 to 16", 1..=16)?);
                    }
                    0x02 if code.is_none() => {
                        code = Some(DownloadErrorCode::from_code(small_int(
                            node.value,
                            "downloadErrorCode",
                        )?));
                    }
                    _ => keep(&mut unknown, node),
                }
            }
            Ok(PrepareDownloadResponse::Error(PrepareDownloadError {
                transaction_id: require(tid, "transactionId")?,
                code: require(code, "downloadErrorCode")?,
                unknown,
            }))
        }
        found => Err(DecodeError::UnexpectedTag {
            context: "PrepareDownloadResponse",
            found,
        }),
    }
}

/// `AuthenticateServerResponse` ([SGP.22 v2.5 §5.7.13]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticateServerResponse {
    /// `authenticateResponseOk` (`A0`).
    Ok(Box<AuthenticateServerOk>),
    /// `authenticateResponseError` (`A1`).
    Error(AuthenticateServerError),
}

/// `AuthenticateResponseOk`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticateServerOk {
    /// `euiccSigned1`, complete DER: the exact bytes `euiccSignature1` covers.
    pub euicc_signed1: Vec<u8>,
    /// `euiccSigned1.transactionId`.
    pub transaction_id: Vec<u8>,
    /// `euiccSigned1.serverAddress`.
    pub server_address: String,
    /// `euiccSigned1.serverChallenge`.
    pub server_challenge: [u8; 16],
    /// `euiccSigned1.euiccInfo2`.
    pub euicc_info2: EuiccInfo2,
    /// `euiccSigned1.ctxParams1`, complete DER including its header.
    pub ctx_params1: Vec<u8>,
    /// `euiccSignature1`, tag `5F37`.
    pub euicc_signature1: Vec<u8>,
    /// `euiccCertificate` (CERT.EUICC.ECDSA), complete DER.
    pub euicc_certificate: Vec<u8>,
    /// `eumCertificate` (CERT.EUM.ECDSA), complete DER.
    pub eum_certificate: Vec<u8>,
    /// Tags this decoder does not know, at either level.
    pub unknown: Vec<Unknown>,
}

/// `AuthenticateResponseError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticateServerError {
    /// `transactionId`.
    pub transaction_id: Vec<u8>,
    /// `authenticateErrorCode`.
    pub code: AuthenticateErrorCode,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of AuthenticateServer (`BF38`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_authenticate_server(data: &[u8]) -> Result<AuthenticateServerResponse, DecodeError> {
    let outer = only(data, 0xBF38)?;
    let [choice] = outer.as_slice() else {
        return Err(DecodeError::MissingField("authenticateServerResponse"));
    };
    let inner = parse(choice.value)?;
    let mut unknown = Vec::new();
    match choice.tag {
        0xA0 => {
            let mut signed = None;
            let mut signature = None;
            let mut certs = Vec::new();
            for node in inner {
                match node.tag {
                    0x30 if signed.is_none() => signed = Some(node),
                    0x5F37 if signature.is_none() => signature = Some(node.value.to_vec()),
                    0x30 if certs.len() < 2 => certs.push(node.raw.to_vec()),
                    _ => keep(&mut unknown, node),
                }
            }
            let signed = require(signed, "euiccSigned1")?;
            let (mut tid, mut address, mut challenge, mut info2, mut ctx) =
                (None, None, None, None, None);
            for node in parse(signed.value)? {
                match node.tag {
                    0x80 if tid.is_none() => {
                        tid = Some(ranged(node.value, "transactionId", "1 to 16", 1..=16)?);
                    }
                    0x83 if address.is_none() => address = Some(utf8(node.value, "serverAddress")?),
                    0x84 if challenge.is_none() => {
                        challenge = Some(exact(node.value, "serverChallenge")?)
                    }
                    0xBF22 if info2.is_none() => {
                        info2 = Some(info2_from_nodes(parse(node.value)?)?)
                    }
                    0xA0 if ctx.is_none() => ctx = Some(node.raw.to_vec()),
                    _ => keep(&mut unknown, node),
                }
            }
            let mut certs = certs.into_iter();
            Ok(AuthenticateServerResponse::Ok(Box::new(
                AuthenticateServerOk {
                    euicc_signed1: signed.raw.to_vec(),
                    transaction_id: require(tid, "transactionId")?,
                    server_address: require(address, "serverAddress")?,
                    server_challenge: require(challenge, "serverChallenge")?,
                    euicc_info2: require(info2, "euiccInfo2")?,
                    ctx_params1: require(ctx, "ctxParams1")?,
                    euicc_signature1: require(signature, "euiccSignature1")?,
                    euicc_certificate: require(certs.next(), "euiccCertificate")?,
                    eum_certificate: require(certs.next(), "eumCertificate")?,
                    unknown,
                },
            )))
        }
        0xA1 => {
            let (mut tid, mut code) = (None, None);
            for node in inner {
                match node.tag {
                    0x80 if tid.is_none() => {
                        tid = Some(ranged(node.value, "transactionId", "1 to 16", 1..=16)?);
                    }
                    0x02 if code.is_none() => {
                        code = Some(AuthenticateErrorCode::from_code(small_int(
                            node.value,
                            "authenticateErrorCode",
                        )?));
                    }
                    _ => keep(&mut unknown, node),
                }
            }
            Ok(AuthenticateServerResponse::Error(AuthenticateServerError {
                transaction_id: require(tid, "transactionId")?,
                code: require(code, "authenticateErrorCode")?,
                unknown,
            }))
        }
        found => Err(DecodeError::UnexpectedTag {
            context: "AuthenticateServerResponse",
            found,
        }),
    }
}

/// `CancelSessionResponse` ([SGP.22 v2.5 §5.7.14]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelSessionResponse {
    /// `cancelSessionResponseOk` (`A0`).
    Ok(CancelSessionOk),
    /// `cancelSessionResponseError` (`81`).
    Error(CancelSessionError),
}

/// `CancelSessionResponseOk`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelSessionOk {
    /// `euiccCancelSessionSigned`, complete DER: what the signature covers.
    pub euicc_cancel_session_signed: Vec<u8>,
    /// `transactionId`.
    pub transaction_id: Vec<u8>,
    /// `smdpOid`, the OID content octets (not the whole TLV).
    pub smdp_oid: Vec<u8>,
    /// `reason`.
    pub reason: CancelSessionReason,
    /// `euiccCancelSessionSignature`, tag `5F37`.
    pub euicc_cancel_session_signature: Vec<u8>,
    /// Tags this decoder does not know, at either level.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of CancelSession (`BF41`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_cancel_session(data: &[u8]) -> Result<CancelSessionResponse, DecodeError> {
    let outer = only(data, 0xBF41)?;
    let [choice] = outer.as_slice() else {
        return Err(DecodeError::MissingField("cancelSessionResponse"));
    };
    match choice.tag {
        0x81 => Ok(CancelSessionResponse::Error(CancelSessionError::from_code(
            small_int(choice.value, "cancelSessionResponseError")?,
        ))),
        0xA0 => {
            let mut unknown = Vec::new();
            let (mut signed, mut signature) = (None, None);
            for node in parse(choice.value)? {
                match node.tag {
                    0x30 if signed.is_none() => signed = Some(node),
                    0x5F37 if signature.is_none() => signature = Some(node.value.to_vec()),
                    _ => keep(&mut unknown, node),
                }
            }
            let signed = require(signed, "euiccCancelSessionSigned")?;
            let (mut tid, mut oid, mut reason) = (None, None, None);
            for node in parse(signed.value)? {
                match node.tag {
                    0x80 if tid.is_none() => {
                        tid = Some(ranged(node.value, "transactionId", "1 to 16", 1..=16)?);
                    }
                    0x81 if oid.is_none() => oid = Some(node.value.to_vec()),
                    0x82 if reason.is_none() => {
                        reason = Some(CancelSessionReason::from_code(small_int(
                            node.value, "reason",
                        )?));
                    }
                    _ => keep(&mut unknown, node),
                }
            }
            Ok(CancelSessionResponse::Ok(CancelSessionOk {
                euicc_cancel_session_signed: signed.raw.to_vec(),
                transaction_id: require(tid, "transactionId")?,
                smdp_oid: require(oid, "smdpOid")?,
                reason: require(reason, "reason")?,
                euicc_cancel_session_signature: require(signature, "euiccCancelSessionSignature")?,
                unknown,
            }))
        }
        found => Err(DecodeError::UnexpectedTag {
            context: "CancelSessionResponse",
            found,
        }),
    }
}

/// One `ProfileInfo` (`E3`) of a GetProfilesInfo response
/// ([SGP.22 v2.5 §5.7.15]). Every field is optional: the eUICC returns only
/// the tags asked for, and omits any it does not hold.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfileInfo {
    /// `iccid`, tag `5A`, as coded in EF ICCID.
    pub iccid: Option<Vec<u8>>,
    /// `isdpAid`, tag `4F`.
    pub isdp_aid: Option<Vec<u8>>,
    /// `profileState`, tag `9F70`.
    pub profile_state: Option<ProfileState>,
    /// `profileNickname`, tag `90`.
    pub profile_nickname: Option<String>,
    /// `serviceProviderName`, tag `91`.
    pub service_provider_name: Option<String>,
    /// `profileName`, tag `92`.
    pub profile_name: Option<String>,
    /// `iconType`, tag `93`.
    pub icon_type: Option<IconType>,
    /// `icon`, tag `94`.
    pub icon: Option<Vec<u8>>,
    /// `profileClass`, tag `95`.
    pub profile_class: Option<ProfileClass>,
    /// `notificationConfigurationInfo` (`B6`), contents left as DER.
    pub notification_configuration_info: Option<Vec<u8>>,
    /// `profileOwner` (`B7`), contents left as DER.
    pub profile_owner: Option<Vec<u8>>,
    /// `dpProprietaryData` (`B8`), contents left as DER.
    pub dp_proprietary_data: Option<Vec<u8>>,
    /// `profilePolicyRules`, tag `99` (`PprIds`: bit 0 pprUpdateControl, 1
    /// ppr1, 2 ppr2).
    pub profile_policy_rules: Option<BitString>,
    /// Tags this decoder does not know (for example `BF22`, service-specific
    /// data).
    pub unknown: Vec<Unknown>,
}

/// `ProfileInfoListResponse` ([SGP.22 v2.5 §5.7.15]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileInfoListResponse {
    /// `profileInfoListOk` (`A0`); empty when no profile matches.
    Ok {
        /// The profiles, in the order returned.
        profiles: Vec<ProfileInfo>,
        /// Non-`E3` tags found in the list.
        unknown: Vec<Unknown>,
    },
    /// `profileInfoListError` (`81`).
    Error(ProfileInfoListError),
}

/// Decodes the response data of GetProfilesInfo (`BF2D`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed structure.
pub fn decode_profiles_info(data: &[u8]) -> Result<ProfileInfoListResponse, DecodeError> {
    let outer = only(data, 0xBF2D)?;
    let [choice] = outer.as_slice() else {
        return Err(DecodeError::MissingField("profileInfoListResponse"));
    };
    match choice.tag {
        0x81 => Ok(ProfileInfoListResponse::Error(
            ProfileInfoListError::from_code(small_int(choice.value, "profileInfoListError")?),
        )),
        0xA0 => {
            let mut profiles = Vec::new();
            let mut unknown = Vec::new();
            for node in parse(choice.value)? {
                if node.tag == 0xE3 {
                    profiles.push(decode_profile_info(node.value)?);
                } else {
                    keep(&mut unknown, node);
                }
            }
            Ok(ProfileInfoListResponse::Ok { profiles, unknown })
        }
        found => Err(DecodeError::UnexpectedTag {
            context: "ProfileInfoListResponse",
            found,
        }),
    }
}

fn decode_profile_info(value: &[u8]) -> Result<ProfileInfo, DecodeError> {
    let mut info = ProfileInfo::default();
    for node in parse(value)? {
        let v = node.value;
        match node.tag {
            0x5A if info.iccid.is_none() => info.iccid = Some(ranged(v, "iccid", "10", 10..=10)?),
            0x4F if info.isdp_aid.is_none() => {
                info.isdp_aid = Some(ranged(v, "isdpAid", "1 to 16", 1..=16)?)
            }
            0x9F70 if info.profile_state.is_none() => {
                info.profile_state = Some(ProfileState::from_code(small_int(v, "profileState")?));
            }
            0x90 if info.profile_nickname.is_none() => {
                info.profile_nickname = Some(utf8(v, "profileNickname")?)
            }
            0x91 if info.service_provider_name.is_none() => {
                info.service_provider_name = Some(utf8(v, "serviceProviderName")?);
            }
            0x92 if info.profile_name.is_none() => {
                info.profile_name = Some(utf8(v, "profileName")?)
            }
            0x93 if info.icon_type.is_none() => {
                info.icon_type = Some(IconType::from_code(small_int(v, "iconType")?));
            }
            0x94 if info.icon.is_none() => info.icon = Some(v.to_vec()),
            0x95 if info.profile_class.is_none() => {
                info.profile_class = Some(ProfileClass::from_code(small_int(v, "profileClass")?));
            }
            0xB6 if info.notification_configuration_info.is_none() => {
                info.notification_configuration_info = Some(v.to_vec());
            }
            0xB7 if info.profile_owner.is_none() => info.profile_owner = Some(v.to_vec()),
            0xB8 if info.dp_proprietary_data.is_none() => {
                info.dp_proprietary_data = Some(v.to_vec())
            }
            0x99 if info.profile_policy_rules.is_none() => {
                info.profile_policy_rules = Some(BitString::decode(v, "profilePolicyRules")?);
            }
            _ => keep(&mut info.unknown, node),
        }
    }
    Ok(info)
}

/// `EnableProfileResponse` ([SGP.22 v2.5 §5.7.16]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnableProfileResponse {
    /// `enableResult`, tag `80`.
    pub result: EnableResult,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of EnableProfile (`BF31`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_enable_profile(data: &[u8]) -> Result<EnableProfileResponse, DecodeError> {
    let (result, unknown) = result_code(data, 0xBF31, "enableResult")?;
    Ok(EnableProfileResponse {
        result: EnableResult::from_code(result),
        unknown,
    })
}

/// `DeleteProfileResponse` ([SGP.22 v2.5 §5.7.18]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteProfileResponse {
    /// `deleteResult`, tag `80`.
    pub result: DeleteResult,
    /// Tags this decoder does not know.
    pub unknown: Vec<Unknown>,
}

/// Decodes the response data of DeleteProfile (`BF33`).
///
/// # Errors
///
/// A [`DecodeError`] for a malformed or incomplete structure.
pub fn decode_delete_profile(data: &[u8]) -> Result<DeleteProfileResponse, DecodeError> {
    let (result, unknown) = result_code(data, 0xBF33, "deleteResult")?;
    Ok(DeleteProfileResponse {
        result: DeleteResult::from_code(result),
        unknown,
    })
}

fn result_code(
    data: &[u8],
    tag: u32,
    field: &'static str,
) -> Result<(u8, Vec<Unknown>), DecodeError> {
    let mut result = None;
    let mut unknown = Vec::new();
    for node in only(data, tag)? {
        match node.tag {
            0x80 if result.is_none() => result = Some(small_int(node.value, field)?),
            _ => keep(&mut unknown, node),
        }
    }
    Ok((require(result, field)?, unknown))
}

impl fmt::Display for BitString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.bytes {
            write!(f, "{byte:02X}")?;
        }
        write!(f, "/{}", self.unused_bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Error as TransportError, ReaderName};
    use std::collections::VecDeque;

    // -- Test-vector provenance ------------------------------------------
    //
    // Requests, and the responses fed to the decoders, were produced by
    // compiling the SGP.22 ASN.1 module with `asn1tools` 0.169.0 and encoding
    // the values given beside each test. The module is lpac's
    // `docs/asn1/rsp.asn` at estkme-group/lpac
    // 82ada9e53251c7f0cb08bfd9060b17019a30242c (SGP.22 Annex H, v2.2 field
    // set), with the three v2.5 EUICCInfo2 fields `treProperties [13]`,
    // `treProductReference [14]` and `additionalEuiccProfilePackageVersions
    // [15]` added exactly as SGP.22 v2.5 section 5.7.8 gives them. The
    // certificate is `CERT_S_SM_DPauth_ECDSA_NIST.der` (SGP.26 v3 test PKI)
    // from osmocom/pysim 3c437d41e025b2a735e19588e937e578f17a8cd6,
    // `tests/unittests/smdpp_data/certs/DPauth/`. Spec examples are quoted
    // from SGP.22 v2.5 and marked as such. None of this is captured from a
    // card; there is no public captured ProfileInfoListResponse.

    const CERT: &str = "30820238308201DFA00302010202020100300A06082A8648CE3D04030230443110300E06035504030C07546573742043493111300F060355040B0C0854455354434552543110300E060355040A0C0752535054455354310B3009060355040613024954301E170D3230303430313038333133305A170D3330303333303038333133305A3025310D300B060355040A0C0441434D453114301206035504030C0B5445535420534D2D44502B3059301306072A8648CE3D020106082A8648CE3D030107034200044DFED4F4694791BF1695CEA0307A35B418019695387BB75B7D2447B6B5209F0445AE4E5E521CD13888D75FE07C8580222AE20DBAAC1D77CD76304993421BD739A381DF3081DC301F0603551D23041830168014F54172BDF98A95D65CBEB88A38A1C11D800A85C3301D0603551D0E04160414BD5A82CC1A96602118BA7560A1FF83A78B210BE5300E0603551D1104073005880388370A300E0603551D0F0101FF04040302078030170603551D200101FF040D300B300906076781120102010430610603551D1F045A3058302AA028A0268624687474703A2F2F63692E746573742E6578616D706C652E636F6D2F43524C2D412E63726C302AA028A0268624687474703A2F2F63692E746573742E6578616D706C652E636F6D2F43524C2D422E63726C300A06082A8648CE3D040302034700304402200823EE7DFA5E3DD07838E930F81BC34AE99F06CBA35927FE9E502C464DC1FEE302200D2D4087DB01A5382D21690AC0488B15067FB2460D336332446CA99F08A8A4EF";
    const TID: &str = "0102030405060708090A0B0C0D0E0F10";
    const ICCID: &str = "98001032547698103214";
    const AID: &str = "A0000005591010FFFFFFFF8900001000";
    const SKI: &str = "81370F5125D0B1D408D4C3B232E6D25E795BEBFB";

    fn h(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str.replace(' ', "")).unwrap()
    }

    fn cat(parts: &[&str]) -> Vec<u8> {
        h(&parts.concat())
    }

    // -- Segmentation ----------------------------------------------------

    fn reassembled(commands: &[Command]) -> Vec<u8> {
        commands.iter().flat_map(|c| c.data().to_vec()).collect()
    }

    #[test]
    fn one_block_is_the_get_eid_frame_pysim_uses() {
        // osmocom/pysim 3c437d41 tests/unittests/test_globalplatform.py:88,
        // `get_eid_cmd_plain` (GetEID, ES10c, BF3E 03 5C 01 5A).
        let data = h("BF3E035C015A");
        let sent = blocks(0x80, &data).unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].encode().unwrap(), h("80E2910006BF3E035C015A00"));
        // Same file: tests/pySim-shell_test/utils.py:126 uses CLA 81
        // (logical channel 1), here with the Le Table 47 requires.
        let channel = blocks(0x81, &data).unwrap();
        assert_eq!(channel[0].encode().unwrap(), h("81E2910006BF3E035C015A00"));
    }

    #[test]
    fn block_counts_at_the_255_boundaries() {
        for (len, expect) in [
            (1usize, vec![1usize]),
            (254, vec![254]),
            (255, vec![255]),
            (256, vec![255, 1]),
            (510, vec![255, 255]),
            (511, vec![255, 255, 1]),
            (5000, [vec![255; 19], vec![155]].concat()),
        ] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let cmds = blocks(0x80, &data).unwrap();
            let sizes: Vec<usize> = cmds.iter().map(|c| c.data().len()).collect();
            assert_eq!(sizes, expect, "len {len}");
            assert_eq!(reassembled(&cmds), data, "len {len}");
            for (i, cmd) in cmds.iter().enumerate() {
                let last = i + 1 == cmds.len();
                let header = cmd.header();
                assert_eq!(header.instruction(), INS_STORE_DATA);
                assert_eq!(
                    header.parameter_1(),
                    if last { 0x91 } else { 0x11 },
                    "len {len} block {i}"
                );
                assert_eq!(header.parameter_2(), i as u8);
                assert_eq!(cmd.le(), Some(Le::Short(0)));
            }
        }
    }

    #[test]
    fn exactly_256_blocks_fit_and_one_more_byte_does_not() {
        let fits = vec![0xAB; 255 * 256];
        let cmds = blocks(0x80, &fits).unwrap();
        assert_eq!(cmds.len(), 256);
        assert_eq!(cmds[255].header().parameter_2(), 0xFF);
        assert_eq!(cmds[255].header().parameter_1(), 0x91);
        let too_big = vec![0xAB; 255 * 256 + 1];
        assert_eq!(
            blocks(0x80, &too_big),
            Err(EncodeError::TooManyBlocks {
                bytes: 255 * 256 + 1,
                blocks: 257
            })
        );
    }

    #[test]
    fn class_and_empty_data_are_refused() {
        for cla in [0x80, 0x81, 0x82, 0x83, 0xC0, 0xCF] {
            assert!(is_valid_class(cla));
            assert!(blocks(cla, &[1]).is_ok());
        }
        for cla in [0x00, 0x7F, 0x84, 0xA0, 0xBF, 0xD0, 0xFF] {
            assert_eq!(blocks(cla, &[1]), Err(EncodeError::BadClass(cla)));
        }
        assert_eq!(blocks(0x80, &[]), Err(EncodeError::EmptyData));
    }

    #[test]
    fn each_bpp_segment_restarts_block_numbering() {
        let big: Vec<u8> = (0..600).map(|i| i as u8).collect();
        let segments = vec![vec![0xBF, 0x36, 0x03], big.clone(), vec![0x87, 0x01, 0x02]];
        let all = bpp_blocks(0x80, &segments).unwrap();
        assert_eq!(all.len(), 3);
        for (segment, cmds) in segments.iter().zip(&all) {
            assert_eq!(&reassembled(cmds), segment);
            assert_eq!(cmds[0].header().parameter_2(), 0);
            let last = cmds.last().unwrap().header();
            assert_eq!(last.parameter_1(), 0x91);
            assert_eq!(usize::from(last.parameter_2()), cmds.len() - 1);
        }
        assert_eq!(all[1].len(), 3);
        assert_eq!(all[1][0].header().parameter_1(), 0x11);
    }

    // -- Sending ---------------------------------------------------------

    struct Scripted {
        reader: ReaderName,
        replies: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl Scripted {
        fn new(replies: Vec<Vec<u8>>) -> Self {
            Self {
                reader: ReaderName::new("scripted eUICC").unwrap(),
                replies: replies.into(),
                sent: Vec::new(),
            }
        }
    }

    impl CardSession for Scripted {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.sent.push(command.to_vec());
            Ok(self.replies.pop_front().unwrap_or_else(|| vec![0x90, 0x00]))
        }
        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    fn channel_policy() -> Policy {
        Policy {
            get_response_class: 0x00,
            ..Policy::default()
        }
    }

    #[test]
    fn many_blocks_reach_the_card_in_order_and_reassemble() {
        let data: Vec<u8> = (0..700).map(|i| (i % 251) as u8).collect();
        let mut card = Scripted::new(vec![]);
        let sent = store_data(&mut card, 0x80, &data, &channel_policy()).unwrap();
        assert!(sent.complete);
        assert_eq!(sent.exchanges.len(), 3);
        let on_wire: Vec<u8> = card
            .sent
            .iter()
            .flat_map(|apdu| {
                // header 4, Lc, data, Le
                apdu[5..apdu.len() - 1].to_vec()
            })
            .collect();
        assert_eq!(on_wire, data);
        let p1p2: Vec<(u8, u8)> = card.sent.iter().map(|a| (a[2], a[3])).collect();
        assert_eq!(p1p2, vec![(0x11, 0), (0x11, 1), (0x91, 2)]);
        assert!(card
            .sent
            .iter()
            .all(|a| a[0] == 0x80 && a[1] == 0xE2 && *a.last().unwrap() == 0));
    }

    #[test]
    fn a_61xx_on_the_last_block_is_followed_with_get_response() {
        // A GetEUICCChallenge response read back through GET RESPONSE.
        let response = h("BF2E128010A0A1A2A3A4A5A6A7A8A9AAABACADAEAF");
        let mut reply = response.clone();
        reply.extend_from_slice(&[0x90, 0x00]);
        let mut card = Scripted::new(vec![vec![0x61, response.len() as u8], reply]);
        let sent = store_data(
            &mut card,
            0x80,
            &get_euicc_challenge_request(),
            &channel_policy(),
        )
        .unwrap();
        assert!(sent.complete);
        assert_eq!(sent.data(), response.as_slice());
        assert_eq!(card.sent[0], h("80E291 00 03 BF2E00 00"));
        assert_eq!(card.sent[1], h("00C0000015"));
        assert_eq!(
            decode_get_euicc_challenge(sent.data()).unwrap().challenge[0],
            0xA0
        );
    }

    #[test]
    fn a_refused_intermediate_block_stops_the_sequence() {
        let mut card = Scripted::new(vec![vec![0x6A, 0x88]]);
        let sent = store_data(&mut card, 0x80, &[0u8; 600], &channel_policy()).unwrap();
        assert!(!sent.complete);
        assert_eq!(sent.exchanges.len(), 1);
        assert_eq!(card.sent.len(), 1, "no block after a refusal");
    }

    #[test]
    fn load_bound_profile_package_sends_segments_and_stops_on_refusal() {
        let segments = vec![vec![1u8; 10], vec![2u8; 300], vec![3u8; 5]];
        let mut card = Scripted::new(vec![]);
        let sent =
            load_bound_profile_package(&mut card, 0x80, &segments, &channel_policy()).unwrap();
        assert_eq!(sent.len(), 3);
        // 1 + 2 + 1 blocks, with P2 restarting at each segment.
        let p2: Vec<u8> = card.sent.iter().map(|a| a[3]).collect();
        assert_eq!(p2, vec![0, 0, 1, 0]);
        let p1: Vec<u8> = card.sent.iter().map(|a| a[2]).collect();
        assert_eq!(p1, vec![0x91, 0x11, 0x91, 0x91]);

        let mut card = Scripted::new(vec![vec![0x90, 0x00], vec![0x69, 0x85]]);
        let sent =
            load_bound_profile_package(&mut card, 0x80, &segments, &channel_policy()).unwrap();
        assert_eq!(sent.len(), 2, "the third segment is not sent after a 6985");
    }

    // -- Request encoders ------------------------------------------------

    #[test]
    fn argument_free_requests() {
        assert_eq!(get_euicc_challenge_request(), h("BF2E00"));
        assert_eq!(get_euicc_info1_request(), h("BF2000"));
        assert_eq!(get_euicc_info2_request(), h("BF2200"));
    }

    #[test]
    fn cancel_session_request_bytes() {
        let tid = h(TID);
        assert_eq!(
            cancel_session_request(&tid, CancelSessionReason::EndUserRejection).unwrap(),
            cat(&["BF4115 8010", TID, "810100"])
        );
        assert_eq!(
            cancel_session_request(&tid, CancelSessionReason::UndefinedReason).unwrap(),
            cat(&["BF4115 8010", TID, "81017F"])
        );
        assert!(cancel_session_request(&[], CancelSessionReason::Timeout).is_err());
        assert!(cancel_session_request(&[0; 17], CancelSessionReason::Timeout).is_err());
    }

    #[test]
    fn enable_and_delete_request_bytes() {
        let (iccid, aid) = (h(ICCID), h(AID));
        assert_eq!(
            enable_profile_request(ProfileIdentifier::Iccid(&iccid), true).unwrap(),
            cat(&["BF3111 A00C 5A0A", ICCID, "8101FF"])
        );
        assert_eq!(
            enable_profile_request(ProfileIdentifier::IsdpAid(&aid), false).unwrap(),
            cat(&["BF3117 A012 4F10", AID, "810100"])
        );
        assert_eq!(
            delete_profile_request(ProfileIdentifier::Iccid(&iccid)).unwrap(),
            cat(&["BF330C 5A0A", ICCID])
        );
        assert_eq!(
            delete_profile_request(ProfileIdentifier::IsdpAid(&aid)).unwrap(),
            cat(&["BF3312 4F10", AID])
        );
        assert!(delete_profile_request(ProfileIdentifier::Iccid(&iccid[..9])).is_err());
        assert!(delete_profile_request(ProfileIdentifier::IsdpAid(&[])).is_err());
        assert!(delete_profile_request(ProfileIdentifier::IsdpAid(&[0; 17])).is_err());
    }

    #[test]
    fn get_profiles_info_request_matches_the_spec_examples() {
        // SGP.22 v2.5 section 5.7.15, "Example of use", verbatim.
        assert_eq!(get_profiles_info_request(None, None).unwrap(), h("BF2D 00"));
        let aid = h("A0 00 00 05 59 10 10 FF FF FF FF 89 00 00 10 00");
        assert_eq!(
            get_profiles_info_request(
                Some(SearchCriteria::IsdpAid(&aid)),
                Some(&[0x5A, 0x4F, 0x9F70, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0xB6, 0xB7, 0xB8, 0x99]),
            )
            .unwrap(),
            h("BF2D 24 A0 12 4F 10 A0 00 00 05 59 10 10 FF FF FF FF 89 00 00 10 00 5C 0E 5A 4F 9F70 90 91 92 93 94 95 B6 B7 B8 99")
        );
        assert_eq!(
            get_profiles_info_request(None, Some(&[0x5A, 0x9F70])).unwrap(),
            h("BF 2D 05 5C 03 5A 9F70")
        );
    }

    #[test]
    fn get_profiles_info_request_other_criteria() {
        let iccid = h(ICCID);
        assert_eq!(
            get_profiles_info_request(Some(SearchCriteria::Iccid(&iccid)), None).unwrap(),
            cat(&["BF2D0E A00C 5A0A", ICCID])
        );
        assert_eq!(
            get_profiles_info_request(
                Some(SearchCriteria::ProfileClass(ProfileClass::Operational)),
                Some(&[0x5A, 0x9F70])
            )
            .unwrap(),
            h("BF2D0A A003 950102 5C03 5A9F70")
        );
    }

    #[test]
    fn prepare_download_request_bytes() {
        let signed2 = cat(&[
            "305980",
            "10",
            TID,
            "0101FF5F4941",
            (1..=0x41)
                .map(|b| format!("{b:02X}"))
                .collect::<String>()
                .as_str(),
        ]);
        let sig2: Vec<u8> = (0x10..0x50).collect();
        let hash: Vec<u8> = (0x60..0x80).collect();
        let cert = h(CERT);
        let with = PrepareDownloadRequest {
            smdp_signed2: &signed2,
            smdp_signature2: &sig2,
            hash_cc: Some(&hash),
            smdp_certificate: &cert,
        };
        let expected = cat(&[
            "BF218202FC",
            &hex::encode_upper(&signed2),
            "5F3740",
            &hex::encode_upper(&sig2),
            "0420",
            &hex::encode_upper(&hash),
            CERT,
        ]);
        assert_eq!(with.encode().unwrap(), expected);
        let without = PrepareDownloadRequest {
            hash_cc: None,
            ..with
        };
        let expected = cat(&[
            "BF218202DA",
            &hex::encode_upper(&signed2),
            "5F3740",
            &hex::encode_upper(&sig2),
            CERT,
        ]);
        assert_eq!(without.encode().unwrap(), expected);
        assert!(PrepareDownloadRequest {
            hash_cc: Some(&hash[..31]),
            ..with
        }
        .encode()
        .is_err());
    }

    #[test]
    fn authenticate_server_request_bytes() {
        let server_signed1 = cat(&[
            "304880 10",
            TID,
            "8110 202122232425262728292A2B2C2D2E2F",
            "8310 736D64702E6578616D706C652E636F6D",
            "8410 404142434445464748494A4B4C4D4E4F",
        ]);
        let ctx = h("A01380074D415443482D31A108800435290611A100");
        let sig: Vec<u8> = (0x80..0xC0).collect();
        let (ski, cert) = (h(SKI), h(CERT));
        let request = AuthenticateServerRequest {
            server_signed1: &server_signed1,
            server_signature1: &sig,
            euicc_ci_pk_id_to_be_used: &ski,
            server_certificate: &cert,
            ctx_params1: &ctx,
        };
        let expected = cat(&[
            "BF388202F4",
            &hex::encode_upper(&server_signed1),
            "5F3740",
            &hex::encode_upper(&sig),
            "0414",
            SKI,
            CERT,
            "A01380074D415443482D31A108800435290611A100",
        ]);
        assert_eq!(request.encode(), expected);
    }

    // -- Response decoders -----------------------------------------------

    #[test]
    fn challenge_response() {
        let data = h("BF2E128010A0A1A2A3A4A5A6A7A8A9AAABACADAEAF");
        let got = decode_get_euicc_challenge(&data).unwrap();
        assert_eq!(got.challenge.to_vec(), (0xA0..=0xAF).collect::<Vec<u8>>());
        assert!(got.unknown.is_empty());
        assert!(decode_get_euicc_challenge(&h("BF2E03 800100")).is_err());
        assert!(decode_get_euicc_challenge(&h("BF2000")).is_err());
        assert!(matches!(
            decode_get_euicc_challenge(&h("BF2E00")),
            Err(DecodeError::MissingField("euiccChallenge"))
        ));
    }

    #[test]
    fn euicc_info1_response() {
        let data = cat(&[
            "BF204B 8203020500 A92C 0414",
            SKI,
            "0414 000102030405060708090A0B0C0D0E0F10111213 AA16 0414",
            SKI,
        ]);
        let got = decode_euicc_info1(&data).unwrap();
        assert_eq!(got.svn, [2, 5, 0]);
        assert_eq!(
            got.ci_pk_id_for_verification,
            vec![h(SKI), (0..20).collect::<Vec<u8>>()]
        );
        assert_eq!(got.ci_pk_id_for_signing, vec![h(SKI)]);
        assert!(got.unknown.is_empty());
    }

    /// The GetEUICCInfo2 response in lpac's stdio driver documentation,
    /// estkme-group/lpac 82ada9e53251c7f0cb08bfd9060b17019a30242c
    /// `driver/apdu/stdio.c:205`, status word removed.
    const LPAC_INFO2: &str = "BF2281C6810302010082030202008303040600840F8101008204000628248304000019228504067F36C08603090200870302030088020490A916041481370F5125D0B1D408D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB990206C004030000010C0D47492D42412D55502D30343139AC48801F312E322E3834302E313233343536372F6D79506C6174666F726D4C6162656C812568747470733A2F2F6D79636F6D70616E792E636F6D2F6D79444C4F41526567697374726172";

    #[test]
    fn euicc_info2_from_a_published_response() {
        let data = h(LPAC_INFO2);
        assert_eq!(data.len(), 202);
        let got = decode_euicc_info2(&data).unwrap();
        // Field values cross-checked against asn1tools decoding the same
        // bytes with the Annex H module.
        assert_eq!(got.profile_version, [2, 1, 0]);
        assert_eq!(got.svn, [2, 2, 0]);
        assert_eq!(got.euicc_firmware_ver, [4, 6, 0]);
        assert_eq!(got.ext_card_resource, h("8101008204000628248304000019 22"));
        assert_eq!(
            got.uicc_capability,
            BitString {
                unused_bits: 6,
                bytes: h("7F36C0")
            }
        );
        assert_eq!(got.ts102241_version, Some([9, 2, 0]));
        assert_eq!(got.globalplatform_version, Some([2, 3, 0]));
        assert_eq!(
            got.rsp_capability,
            BitString {
                unused_bits: 4,
                bytes: vec![0x90]
            }
        );
        assert!(got.rsp_capability.bit(0), "additionalProfile");
        assert!(!got.rsp_capability.bit(1), "crlSupport");
        assert!(got.rsp_capability.bit(3), "testProfileSupport");
        assert!(!got.rsp_capability.bit(4), "past the end of the named bits");
        assert_eq!(got.ci_pk_id_for_verification, vec![h(SKI)]);
        assert_eq!(got.ci_pk_id_for_signing, vec![h(SKI)]);
        assert_eq!(got.euicc_category, None);
        let ppr = got.forbidden_profile_policy_rules.unwrap();
        assert!(
            ppr.bit(0) && ppr.bit(1) && !ppr.bit(2),
            "pprUpdateControl and ppr1"
        );
        assert_eq!(got.pp_version, [0, 0, 1]);
        assert_eq!(got.sas_accreditation_number, "GI-BA-UP-0419");
        assert_eq!(
            got.certification_data_object,
            Some(CertificationDataObject {
                platform_label: "1.2.840.1234567/myPlatformLabel".into(),
                discovery_base_url: "https://mycompany.com/myDLOARegistrar".into(),
            })
        );
        assert!(got.unknown.is_empty());
    }

    const INFO2_V25: &str = "BF2281B781030201008203020500830304060084158101008204000628248304000019228504067F36C0850200FF86030300008703020301880204B0A916041481370F5125D0B1D408D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB8B0102990202C004030000010C0D47492D42412D55502D30343139AC1E80056C6162656C811568747470733A2F2F646C6F612E6578616D706C652F8D0205408E075452452D524546AF050403030200";

    #[test]
    fn euicc_info2_with_the_v25_fields() {
        let got = decode_euicc_info2(&h(INFO2_V25)).unwrap();
        assert_eq!(got.euicc_category, Some(EuiccCategory::MediumEuicc));
        assert_eq!(
            got.tre_properties,
            Some(BitString {
                unused_bits: 5,
                bytes: vec![0x40]
            })
        );
        assert!(got.tre_properties.as_ref().unwrap().bit(1), "isIntegrated");
        assert_eq!(got.tre_product_reference.as_deref(), Some("TRE-REF"));
        assert_eq!(
            got.additional_euicc_profile_package_versions,
            vec![[3, 2, 0]]
        );
        assert_eq!(
            got.rsp_capability,
            BitString {
                unused_bits: 4,
                bytes: vec![0xB0]
            }
        );
        assert!(
            got.rsp_capability.bit(0) && got.rsp_capability.bit(2) && got.rsp_capability.bit(3)
        );
    }

    #[test]
    fn unknown_tags_are_kept_not_dropped() {
        // INFO2_V25 with an extra `9F 8F 01 02 AA BB` and a repeated `82`
        // appended inside BF22 (length 0xB7 grows by 6 + 5).
        let mut data = h(INFO2_V25);
        data[3] += 11;
        data.extend_from_slice(&h("9F8F0102AABB 8203010203"));
        // 0xB7 + 11 = 0xC2, still a one-octet 0x81 length.
        let got = decode_euicc_info2(&data).unwrap();
        assert_eq!(
            got.unknown,
            vec![
                Unknown {
                    tag: 0x9F8F01,
                    value: vec![0xAA, 0xBB]
                },
                Unknown {
                    tag: 0x82,
                    value: vec![1, 2, 3]
                },
            ]
        );
        assert_eq!(got.svn, [2, 5, 0], "the first of a repeated field wins");
    }

    #[test]
    fn info2_rejects_damage() {
        let data = h(INFO2_V25);
        for cut in [1, 3, 10, data.len() - 1] {
            assert!(decode_euicc_info2(&data[..cut]).is_err(), "cut at {cut}");
        }
        // BF22 with only a version: mandatory fields missing.
        assert!(matches!(
            decode_euicc_info2(&h("BF2205 8103020100")),
            Err(DecodeError::MissingField("svn"))
        ));
        let mut trailing = data.clone();
        trailing.extend_from_slice(&[0, 0]);
        assert!(matches!(
            decode_euicc_info2(&trailing),
            Err(DecodeError::TrailingData(2))
        ));
        assert!(matches!(
            decode_euicc_info1(&data),
            Err(DecodeError::WrongTag { .. })
        ));
    }

    #[test]
    fn prepare_download_responses() {
        let ok = cat(&[
            "BF2181C0 A081BD 3078 8010", TID,
            "5F4941 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F4041",
            "0420 606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
            "5F3740 101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
        ]);
        let PrepareDownloadResponse::Ok(got) = decode_prepare_download(&ok).unwrap() else {
            panic!("expected Ok");
        };
        assert_eq!(got.transaction_id, h(TID));
        assert_eq!(got.euicc_otpk, (1..=0x41).collect::<Vec<u8>>());
        assert_eq!(got.hash_cc, Some((0x60..0x80).collect()));
        assert_eq!(got.euicc_signature2, (0x10..0x50).collect::<Vec<u8>>());
        assert_eq!(got.euicc_signed2.len(), 2 + 0x78);
        assert_eq!(&got.euicc_signed2[..2], &[0x30, 0x78]);
        assert!(got.unknown.is_empty());

        let error = cat(&["BF2117 A115 8010", TID, "020102"]);
        assert_eq!(
            decode_prepare_download(&error).unwrap(),
            PrepareDownloadResponse::Error(PrepareDownloadError {
                transaction_id: h(TID),
                code: DownloadErrorCode::InvalidSignature,
                unknown: vec![],
            })
        );
    }

    #[test]
    fn authenticate_server_responses() {
        let sig: Vec<u8> = (0x80..0xC0).collect();
        let euicc_signed1_inner = cat(&[
            "8010",
            TID,
            "8310 736D64702E6578616D706C652E636F6D",
            "8410 404142434445464748494A4B4C4D4E4F",
            INFO2_V25,
            "A01380074D415443482D31A108800435290611A100",
        ]);
        let signed1 = [
            vec![
                0x30,
                0x82,
                (euicc_signed1_inner.len() >> 8) as u8,
                euicc_signed1_inner.len() as u8,
            ],
            euicc_signed1_inner,
        ]
        .concat();
        assert_eq!(signed1.len(), 4 + 0x106);
        let inner = cat(&[
            &hex::encode_upper(&signed1),
            "5F3740",
            &hex::encode_upper(&sig),
            CERT,
            CERT,
        ]);
        let data = [
            vec![
                0xBF,
                0x38,
                0x82,
                ((inner.len() + 4) >> 8) as u8,
                (inner.len() + 4) as u8,
                0xA0,
                0x82,
                (inner.len() >> 8) as u8,
                inner.len() as u8,
            ],
            inner,
        ]
        .concat();
        assert_eq!(data.len(), 1486, "BF38 8205C9 A0 8205C5 ...");
        let AuthenticateServerResponse::Ok(got) = decode_authenticate_server(&data).unwrap() else {
            panic!("expected Ok");
        };
        assert_eq!(got.transaction_id, h(TID));
        assert_eq!(got.server_address, "smdp.example.com");
        assert_eq!(
            got.server_challenge.to_vec(),
            (0x40..0x50).collect::<Vec<u8>>()
        );
        assert_eq!(got.euicc_info2.svn, [2, 5, 0]);
        assert_eq!(
            got.euicc_info2.tre_product_reference.as_deref(),
            Some("TRE-REF")
        );
        assert_eq!(
            got.ctx_params1,
            h("A01380074D415443482D31A108800435290611A100")
        );
        assert_eq!(got.euicc_signature1, sig);
        assert_eq!(got.euicc_signed1, signed1);
        assert_eq!(got.euicc_certificate, h(CERT));
        assert_eq!(got.eum_certificate, h(CERT));
        assert!(got.unknown.is_empty());

        let error = cat(&["BF3817 A115 8010", TID, "020106"]);
        assert_eq!(
            decode_authenticate_server(&error).unwrap(),
            AuthenticateServerResponse::Error(AuthenticateServerError {
                transaction_id: h(TID),
                code: AuthenticateErrorCode::EuiccChallengeMismatch,
                unknown: vec![],
            })
        );
    }

    #[test]
    fn cancel_session_responses() {
        let sig: Vec<u8> = (0x10..0x50).collect();
        let ok = cat(&[
            "BF4161 A05F 301A 8010",
            TID,
            "810388370A 820101",
            "5F3740",
            &hex::encode_upper(&sig),
        ]);
        let CancelSessionResponse::Ok(got) = decode_cancel_session(&ok).unwrap() else {
            panic!("expected Ok");
        };
        assert_eq!(got.transaction_id, h(TID));
        assert_eq!(got.smdp_oid, h("88370A"));
        assert_eq!(got.reason, CancelSessionReason::Postponed);
        assert_eq!(got.euicc_cancel_session_signature, sig);
        assert_eq!(got.euicc_cancel_session_signed.len(), 2 + 0x1A);

        assert_eq!(
            decode_cancel_session(&h("BF4103 810105")).unwrap(),
            CancelSessionResponse::Error(CancelSessionError::InvalidTransactionId)
        );
    }

    #[test]
    fn profiles_info_responses() {
        // asn1tools encoding of ProfileInfoListResponse with two profiles.
        let data = cat(&[
            "BF2D5E A05C E348 5A0A", ICCID, "4F10", AID,
            "9F7001 01 9004 6E69636B 9108 4F70657261746F72 9204 50726F66 9301 01 9404 89504E47 9501 02 9902 0540",
            "E310 5A0A 98001032547698103215 9F7001 00",
        ]);
        let ProfileInfoListResponse::Ok { profiles, unknown } =
            decode_profiles_info(&data).unwrap()
        else {
            panic!("expected Ok");
        };
        assert!(unknown.is_empty());
        assert_eq!(profiles.len(), 2);
        let first = &profiles[0];
        assert_eq!(first.iccid, Some(h(ICCID)));
        assert_eq!(first.isdp_aid, Some(h(AID)));
        assert_eq!(first.profile_state, Some(ProfileState::Enabled));
        assert_eq!(first.profile_nickname.as_deref(), Some("nick"));
        assert_eq!(first.service_provider_name.as_deref(), Some("Operator"));
        assert_eq!(first.profile_name.as_deref(), Some("Prof"));
        assert_eq!(first.icon_type, Some(IconType::Png));
        assert_eq!(first.icon, Some(h("89504E47")));
        assert_eq!(first.profile_class, Some(ProfileClass::Operational));
        assert!(first.profile_policy_rules.as_ref().unwrap().bit(1), "ppr1");
        assert_eq!(profiles[1].iccid, Some(h("98001032547698103215")));
        assert_eq!(profiles[1].profile_state, Some(ProfileState::Disabled));
        assert_eq!(profiles[1].profile_name, None);

        assert_eq!(
            decode_profiles_info(&h("BF2D02 A000")).unwrap(),
            ProfileInfoListResponse::Ok {
                profiles: vec![],
                unknown: vec![]
            }
        );
        assert_eq!(
            decode_profiles_info(&h("BF2D03 810101")).unwrap(),
            ProfileInfoListResponse::Error(ProfileInfoListError::IncorrectInputValues)
        );
    }

    #[test]
    fn profile_info_keeps_tags_it_does_not_know() {
        // `BF22` (service-specific data) is in the 5.7.15 tag list and is not
        // modelled; it must survive.
        let data = cat(&["BF2D13 A011 E30F 5A0A", ICCID, "BF2200"]);
        let ProfileInfoListResponse::Ok { profiles, .. } = decode_profiles_info(&data).unwrap()
        else {
            panic!("expected Ok");
        };
        assert_eq!(
            profiles[0].unknown,
            vec![Unknown {
                tag: 0xBF22,
                value: vec![]
            }]
        );
    }

    #[test]
    fn enable_and_delete_responses() {
        assert_eq!(
            decode_enable_profile(&h("BF3103 800100")).unwrap().result,
            EnableResult::Ok
        );
        assert_eq!(
            decode_enable_profile(&h("BF3103 800102")).unwrap().result,
            EnableResult::ProfileNotInDisabledState
        );
        assert_eq!(
            decode_enable_profile(&h("BF3103 80017F")).unwrap().result,
            EnableResult::UndefinedError
        );
        assert_eq!(
            decode_enable_profile(&h("BF3103 800163")).unwrap().result,
            EnableResult::Unknown(0x63)
        );
        assert_eq!(
            decode_delete_profile(&h("BF3303 800100")).unwrap().result,
            DeleteResult::Ok
        );
        assert_eq!(
            decode_delete_profile(&h("BF3303 800103")).unwrap().result,
            DeleteResult::DisallowedByPolicy
        );
        assert!(decode_delete_profile(&h("BF3100")).is_err());
        assert!(matches!(
            decode_delete_profile(&h("BF3300")),
            Err(DecodeError::MissingField("deleteResult"))
        ));
        let extra = decode_enable_profile(&h("BF3106 800100 840100")).unwrap();
        assert_eq!(
            extra.unknown,
            vec![Unknown {
                tag: 0x84,
                value: vec![0]
            }]
        );
    }

    #[test]
    fn code_enums_round_trip_every_code() {
        for code in 0..=255u8 {
            assert_eq!(CancelSessionReason::from_code(code).code(), code);
            assert_eq!(EnableResult::from_code(code).code(), code);
            assert_eq!(ProfileClass::from_code(code).code(), code);
        }
    }

    #[test]
    fn ber_reader_handles_the_length_forms() {
        let long = [vec![0x04, 0x81, 0x80], vec![7; 128]].concat();
        assert_eq!(parse(&long).unwrap()[0].value.len(), 128);
        let longer = [vec![0x04, 0x82, 0x01, 0x00], vec![7; 256]].concat();
        assert_eq!(parse(&longer).unwrap()[0].value.len(), 256);
        assert_eq!(
            parse(&h("04 80 00 00")).err(),
            Some(DecodeError::UnsupportedLength(0x80))
        );
        assert!(matches!(
            parse(&h("04 05 01")),
            Err(DecodeError::Truncated { .. })
        ));
        assert!(matches!(
            parse(&h("BF")),
            Err(DecodeError::Truncated { .. })
        ));
        assert_eq!(tlv(0xBF2D, &[0u8; 200])[..4], [0xBF, 0x2D, 0x81, 200]);
    }
}
