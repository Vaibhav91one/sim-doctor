//! The typed ISO/IEC 7816-4 command header and the two-byte status word.
//!
//! **Owns.** The whole byte-level codec. The four octets every command
//! starts with (CLA, INS, P1, P2); the Le/Lc/data body that follows them in
//! short or extended form; the body and SW1/SW2 a response carries back; the
//! single-octet procedure byte a card answers with when it wants more command
//! data; and the classification that says what a caller may do next.
//!
//! **Does not own.** The transport. Nothing here opens a reader, holds a
//! session, or moves bytes off the machine, and nothing here retries anything.
//! Deciding *which* follow-up exchange a status word earns needs a card and a
//! policy, so it lives in [`crate::session`] one layer up. This module holds
//! the typed values that layer operates on.
//!
//! **Does not own the transport.** There is no `pcsc` dependency here and no
//! session, reader or reader list. A [`Header`] is four integers;
//! [`crate::transport`] moves bytes and cannot see this module, and this
//! module cannot see it.
//!
//! **Why P1 and P2 are not validated.** ISO/IEC 7816-4 does not assign meaning
//! to P1 and P2; their meaning is set by INS. A SELECT uses `00 00`,
//! VERIFY uses a reference number, MANAGE CHANNEL uses a channel number.
//! [`Header::new`] therefore accepts every value rather than encoding one
//! command's opinion of the octet range, and the type's whole job is to make
//! "which byte was that" a compile-time question.

/// This module's name, as recorded in [`crate::MODULES`].
///
/// Referenced by value rather than re-spelt as a literal so that the module
/// table cannot name a module that does not exist.
pub const NAME: &str = "apdu";

use std::fmt;

/// The four octets that begin every ISO/IEC 7816-4 command APDU.
///
/// Exactly four octets, in the order CLA, INS, P1, P2. Holding them as one
/// value is what stops a caller from accidentally passing the instruction byte
/// where the class byte belongs, which is silent on the wire and the single
/// most common mistake in hand-rolled SIM tooling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Header {
    class: u8,
    instruction: u8,
    parameter_1: u8,
    parameter_2: u8,
}

impl Header {
    /// Builds a header from its four octets.
    ///
    /// No octet is rejected. See the module documentation for why.
    pub const fn new(class: u8, instruction: u8, parameter_1: u8, parameter_2: u8) -> Self {
        Self {
            class,
            instruction,
            parameter_1,
            parameter_2,
        }
    }

    /// Reads a header back from its four octets, in wire order.
    pub const fn from_bytes(bytes: [u8; 4]) -> Self {
        Self::new(bytes[0], bytes[1], bytes[2], bytes[3])
    }

    /// The class byte, CLA.
    pub const fn class(self) -> u8 {
        self.class
    }

    /// The instruction byte, INS.
    pub const fn instruction(self) -> u8 {
        self.instruction
    }

    /// The first parameter byte, P1.
    pub const fn parameter_1(self) -> u8 {
        self.parameter_1
    }

    /// The second parameter byte, P2.
    pub const fn parameter_2(self) -> u8 {
        self.parameter_2
    }

    /// The header as it appears on the wire.
    pub const fn to_bytes(self) -> [u8; 4] {
        [
            self.class,
            self.instruction,
            self.parameter_1,
            self.parameter_2,
        ]
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [cla, ins, p1, p2] = self.to_bytes();
        write!(f, "{cla:02X} {ins:02X} {p1:02X} {p2:02X}")
    }
}

/// The two octets that end every ISO/IEC 7816-4 response APDU.
///
/// A status word is always exactly two bytes, so this type cannot represent a
/// partial one. Constructing one never fails, which is deliberate: every one of
/// the 65536 pairs is a legal status word, and rejecting any of them would be
/// guessing at a card's behaviour rather than modelling the protocol. Deciding
/// what a given pair *means for a caller* is [`Outcome::of`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatusWord {
    sw1: u8,
    sw2: u8,
}

impl StatusWord {
    /// Builds a status word from SW1 and SW2.
    pub const fn new(sw1: u8, sw2: u8) -> Self {
        Self { sw1, sw2 }
    }

    /// Reads a status word from its two octets, in wire order.
    pub const fn from_bytes(bytes: [u8; 2]) -> Self {
        Self::new(bytes[0], bytes[1])
    }

    /// The first status byte, SW1.
    pub const fn sw1(self) -> u8 {
        self.sw1
    }

    /// The second status byte, SW2.
    pub const fn sw2(self) -> u8 {
        self.sw2
    }

    /// The status word as it appears on the wire.
    pub const fn to_bytes(self) -> [u8; 2] {
        [self.sw1, self.sw2]
    }

    /// Whether the card reported the command as successfully completed.
    ///
    /// True for `90 00` and nothing else. `90 01` is not a success with extra
    /// information attached; SW2 is a distinct status byte and a card that
    /// wants to say "done, with a warning" says `62 xx`.
    ///
    /// A `91 xx` is not a success either, and deliberately so. swSIM rewrites a
    /// completed command's `90 00` into `91 <length>` whenever a proactive
    /// command is waiting, so a success test that accepted `91 xx` would report
    /// a pending proactive command as a finished exchange. [V], swSIM
    /// `src/apduh.c:sim_apduh_demux`. Ask
    /// [`StatusWord::is_normal_processing`] instead when "the command worked"
    /// is the question and "there is nothing more" is not.
    pub const fn is_success(self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }

    /// Whether the card says the command worked, whether or not it has
    /// something else to hand over.
    ///
    /// True for `90` and for the four pending spellings `91`, `92`, `93` and
    /// `9F`. False for `94` and `98`, which are GSM 11.11 failures that sit in
    /// the same octet range and are the reason this is a list and not a range
    /// test.
    pub const fn is_normal_processing(self) -> bool {
        matches!(self.sw1, 0x90 | 0x91 | 0x92 | 0x93 | 0x9F)
    }

    /// How severe this status word is, independently of what it asks for.
    pub const fn class(self) -> StatusClass {
        StatusClass::of(self)
    }

    /// How many RESPONSE DATA bytes the card says are waiting.
    ///
    /// Only SW1 `61` says that. ISO/IEC 7816-4 clause 9.1.1 gives `61 xx` that
    /// meaning with SW2 as the length, `61 00` standing for 256.
    ///
    /// `None` for every other SW1, deliberately including `9F`: a 9x SW2 is not
    /// a response-data length as far as ISO is concerned, and on the cards this
    /// crate has talked to that byte is counting something else. See
    /// [`StatusWord::proactive_command_length`] and [`Pending`].
    pub const fn response_data_length(self) -> Option<u32> {
        if self.sw1 != 0x61 {
            return None;
        }
        if self.sw2 == 0 {
            Some(Le::SHORT_MAX)
        } else {
            Some(self.sw2 as u32)
        }
    }

    /// The Le the card says it would have accepted, when it says so at all.
    ///
    /// Only SW1 `6C` carries one. This exists rather than reading
    /// [`Outcome::WrongLength::available`] straight out of the enum because that
    /// field is a faithful copy of SW2 and `6C 00` is not a usable length: an
    /// Le of `00` encodes 256, so substituting it would send a longer command
    /// than the card asked for. swSIM's FETCH answers exactly `6C 00` when Le
    /// is not the pending command's length [V].
    pub const fn corrected_length(self) -> Option<CorrectedLength> {
        if self.sw1 != 0x6C {
            return None;
        }
        if self.sw2 == 0 {
            Some(CorrectedLength::Unusable)
        } else {
            Some(CorrectedLength::Accepts(self.sw2))
        }
    }

    /// The length of a PENDING PROACTIVE COMMAND, when SW1 says that is what
    /// SW2 is counting.
    ///
    /// Only the three 3GPP spellings `91`, `92` and `93` are read that way,
    /// because those are the ones that define SW2 as the pending command's
    /// length. [V] for swSIM, which writes exactly `91 <length>` when a
    /// proactive command is waiting.
    ///
    /// `None` for `9F` on purpose. ISO/IEC 7816-4 clause 9.1 calls 9F "normal
    /// processing, proactive command available" without a length, and swSIM
    /// uses `9F <length>` to mean a different thing entirely. See [`Pending`].
    pub const fn proactive_command_length(self) -> Option<u8> {
        Pending::of(self).proactive_command_length()
    }

    /// How a caller should treat the exchange that produced this status word.
    pub const fn outcome(self) -> Outcome {
        Outcome::of(self)
    }
}

impl fmt::Display for StatusWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X}{:02X}", self.sw1, self.sw2)
    }
}

/// What a caller must do next, given a [`StatusWord`].
///
/// This answers exactly one question: can the caller move on, or does it owe
/// the card another exchange? Everything richer - which instruction byte was
/// refused, what a `6A 82` means for the file the caller was trying to open -
/// belongs to the rule layer, not here. The coarser "how bad is this" view is
/// [`StatusClass`], and the two disagree on purpose: a `6C xx` owes a
/// follow-up *and* is a retriable refusal, and which question a caller is
/// asking decides which answer it gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// `90 00`. The card processed the command and has nothing more to add.
    Success,

    /// `61 xx`. The card processed the command and has `available` more
    /// response bytes waiting. The caller owes a GET RESPONSE before it can
    /// read the rest.
    MoreDataAvailable {
        /// The length SW2 is reporting.
        available: u8,
    },

    /// `91 xx`, `92 xx`, `93 xx` or `9F xx`. Normal processing with something
    /// still held by the card.
    ///
    /// Not a failure, and not a success either. What is held, and which
    /// instruction drains it, is in `pending`: the same status word means two
    /// different things on the two cards this crate has actually talked to,
    /// and only the caller knows which command it sent. See [`Pending`].
    Pending {
        /// What the card is holding.
        pending: Pending,
    },

    /// `6C xx`. The card refused the command's Le and reports that it would
    /// have accepted `available` bytes. Retrying with that Le is the caller's
    /// decision, not an automatic retry: some cards want a shorter read and
    /// some report the total remaining length.
    WrongLength {
        /// The length SW2 is reporting.
        available: u8,
    },

    /// `6F 00`. The card rejected the command and declined to say why.
    ///
    /// Worth its own variant because it is the shape a scanner has to report
    /// rather than swallow: a card that answers `6F 00` to every command is a
    /// finding, not a card that happens to be locked.
    NoPreciseDiagnosis,

    /// Any other status word. SW1 and SW2 are carried through untouched.
    ///
    /// Deliberately not subdivided. The ISO/IEC 7816-4 status table splits
    /// these into warning, memory-management, and instruction-error classes,
    /// but which of those matter depends on the command that was sent, and
    /// this module cannot see commands.
    Other {
        /// The first status byte.
        sw1: u8,
        /// The second status byte.
        sw2: u8,
    },
}

impl Outcome {
    /// Classifies a status word.
    pub const fn of(status: StatusWord) -> Self {
        match (status.sw1(), status.sw2()) {
            (0x90, 0x00) => Self::Success,
            (0x61, available) => Self::MoreDataAvailable { available },
            (0x91..=0x93, _) | (0x9F, _) => Self::Pending {
                pending: Pending::of(status),
            },
            (0x6C, available) => Self::WrongLength { available },
            (0x6F, 0x00) => Self::NoPreciseDiagnosis,
            (sw1, sw2) => Self::Other { sw1, sw2 },
        }
    }

    /// Whether the caller owes the card another exchange before moving on.
    ///
    /// True for the three "there is more" statuses. `61 xx` and `6C xx` carry
    /// a byte count and `9x` says something is pending. None of them is
    /// finished, and none of them is a failure either.
    pub const fn needs_follow_up(self) -> bool {
        matches!(
            self,
            Self::MoreDataAvailable { .. } | Self::Pending { .. } | Self::WrongLength { .. }
        )
    }

    /// Whether the card completed the command successfully.
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

/// INS of ISO/IEC 7816-4 GET RESPONSE.
///
/// The instruction byte is not in doubt. The class byte it has to arrive at is,
/// which is why [`Command::get_response`] takes one rather than picking one.
/// [V] for swSIM: `src/apduh.c` dispatches INS `0xC0` only under
/// `SWICC_APDU_CLA_TYPE_PROPRIETARY`, and within that only at CLA `0xA0`, so
/// the ISO-conformant same-CLA form is not routed at all on that card.
pub const INS_GET_RESPONSE: u8 = 0xC0;

/// INS of ETSI TS 102 221 clause 11.2.3 FETCH, the instruction that hands
/// back a pending proactive command.
///
/// [V] for swSIM: `src/apduh.c:apduh_etsi_cat_fetch` requires P1 and P2 both
/// `00` and requires Le to equal the pending command's length exactly, so a
/// FETCH built with any other Le is answered `6C xx` rather than the command.
pub const INS_FETCH: u8 = 0x12;

/// The class byte swSIM dispatches GET RESPONSE from, and the default this
/// crate uses.
///
/// [V], read at the pinned swSIM commit: INS `0xC0` is routed at CLA `0xA0`
/// only. That is the proprietary GSM class of GSM 11.11 / 3GPP TS 51.011,
/// not the ISO interindustry class, so it is a card-specific default rather
/// than the standard's, and [`crate::session::Policy`] lets a caller replace it.
pub const CLA_GET_RESPONSE_GSM: u8 = 0xA0;

/// The ISO interindustry class byte, CLA `0x00`.
///
/// A card may dispatch GET RESPONSE here instead of at
/// [`CLA_GET_RESPONSE_GSM`], and swSIM does not. Named as a constant because
/// it is the other half of the choice a follow-up policy has to make.
pub const CLA_GET_RESPONSE_ISO: u8 = 0x00;

/// The class byte swSIM dispatches FETCH from.
///
/// [V] for swSIM: `src/apduh.c` routes INS `0x12` at CLA `0x80` exactly, which
/// is the ETSI proprietary class of ETSI TS 102 221 clause 10.1.1.
pub const CLA_FETCH_ETSI: u8 = 0x80;

/// The NULL procedure byte of ISO/IEC 7816-3 clause 10.3.3 table 11.
///
/// [V] for swICC: `src/apdu.c:swicc_apdu_res_deparse` sizes a response carrying
/// this status at one octet on the wire, not two.
pub const PROCEDURE_BYTE_NULL: u8 = 0x60;

/// Number of octets in an ISO/IEC 7816-4 command header.
pub const HEADER_LEN: usize = 4;

/// Largest data field the short Lc form can describe.
pub const SHORT_DATA_MAX: usize = 0xFF;

/// Largest data field any APDU length field can describe.
///
/// The extended form writes a two-octet count, so this is what a 16-bit length
/// can hold rather than a protocol constant of its own.
pub const EXTENDED_DATA_MAX: usize = 0xFFFF;

/// Le, the number of response bytes the caller expects back.
///
/// Two representations, because ISO/IEC 7816-4 has two and on the wire neither
/// is a superset of the other. `Short` is one octet whose value `00` encodes
/// 256; `Extended` is two octets preceded by a `00` marker whose `0000`
/// encodes 65536. Holding the form the card will see, rather than a byte count
/// that both forms could express, is what makes [`Command`] round-trip byte for
/// byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Le {
    /// The short one-octet form. The value `0` encodes 256 response bytes.
    Short(u8),
    /// The extended two-octet form. The value `0` encodes 65536 response bytes.
    Extended(u16),
}

impl Le {
    /// Largest response length the short form can express, counting the `00`
    /// spelling of 256.
    pub const SHORT_MAX: u32 = 256;

    /// Largest response length the extended form can express, counting the
    /// `0000` spelling of 65536.
    pub const EXTENDED_MAX: u32 = 65536;

    /// The number of response bytes this asks for, with `0` resolved.
    pub const fn byte_count(self) -> u32 {
        match self {
            Self::Short(value) => {
                if value == 0 {
                    Self::SHORT_MAX
                } else {
                    value as u32
                }
            }
            Self::Extended(value) => {
                if value == 0 {
                    Self::EXTENDED_MAX
                } else {
                    value as u32
                }
            }
        }
    }

    /// The shortest Le that asks for `bytes` response bytes.
    ///
    /// `None` for zero, which is not a length a card can act on, and for
    /// anything above the extended form's 65536.
    ///
    /// Shortest is not the same as only: 256 is requested with the short
    /// form's `00`, not with the extended form's `01 00`, because a card that
    /// expects one shape and is handed the other may answer `6C xx`.
    pub const fn for_byte_count(bytes: u32) -> Option<Self> {
        if bytes == 0 || bytes > Self::EXTENDED_MAX {
            None
        } else if bytes < Self::SHORT_MAX {
            Some(Self::Short(bytes as u8))
        } else if bytes == Self::SHORT_MAX {
            Some(Self::Short(0))
        } else if bytes == Self::EXTENDED_MAX {
            Some(Self::Extended(0))
        } else {
            Some(Self::Extended(bytes as u16))
        }
    }
}

impl fmt::Display for Le {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short(value) => write!(f, "{value:02X}"),
            Self::Extended(value) => write!(f, "00 {value:04X}"),
        }
    }
}

/// Everything in a command APDU after the four-octet header.
///
/// The four variants are the four cases of ISO/IEC 7816-4 clause 5.1, named by
/// the case numbers the standard gives them, because "case 4" is what every
/// reference to this grammar calls it and a caller should not have to
/// rediscover that the difference between two of these variants is whether a
/// trailing Le exists.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Body {
    /// Case 1: header only. Neither a data field nor an expected length.
    Empty,
    /// Case 2: an expected response length and no data field.
    Le(Le),
    /// Case 3: a data field and no expected response length.
    Data(Vec<u8>),
    /// Case 4: a data field and an expected response length.
    DataAndLe(Vec<u8>, Le),
}

impl Body {
    /// The command's data field, empty when it has none.
    ///
    /// Cases 1 and 2 carry no data at all. This returns an empty slice rather
    /// than an `Option` because every caller of a data field wants the bytes,
    /// and a zero-length read of them is the correct answer.
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Data(data) | Self::DataAndLe(data, _) => data,
            Self::Empty | Self::Le(_) => &[],
        }
    }

    /// The expected response length, if this body carries one.
    pub const fn le(&self) -> Option<Le> {
        match self {
            Self::Le(le) | Self::DataAndLe(_, le) => Some(*le),
            Self::Empty | Self::Data(_) => None,
        }
    }
}

/// A complete ISO/IEC 7816-4 command APDU: a header and a body.
///
/// Encodes and decodes byte for byte for every APDU this crate produces, and
/// for every canonical APDU it is handed. "Canonical" is load-bearing and means
/// the encoder's own choice of length form: a data field of 255 bytes or
/// fewer always gets the short Lc, and an Le of 256 always gets the short
/// `00`. A card that receives the other form is entitled to answer `6C xx`,
/// so this crate does not emit it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Command {
    header: Header,
    body: Body,
}

impl Command {
    /// Builds a command from a header and a body.
    pub const fn new(header: Header, body: Body) -> Self {
        Self { header, body }
    }

    /// ISO/IEC 7816-4 case 1: a header and nothing else.
    pub const fn case1(header: Header) -> Self {
        Self::new(header, Body::Empty)
    }

    /// ISO/IEC 7816-4 case 2: a header and an expected response length.
    pub const fn case2(header: Header, le: Le) -> Self {
        Self::new(header, Body::Le(le))
    }

    /// ISO/IEC 7816-4 case 3: a header and a data field.
    pub fn case3(header: Header, data: impl Into<Vec<u8>>) -> Self {
        Self::new(header, Body::Data(data.into()))
    }

    /// ISO/IEC 7816-4 case 4: a header, a data field, and an expected length.
    pub fn case4(header: Header, data: impl Into<Vec<u8>>, le: Le) -> Self {
        Self::new(header, Body::DataAndLe(data.into(), le))
    }

    /// A GET RESPONSE for `length` bytes, in the class byte the caller names.
    ///
    /// P1 and P2 are both zero because that is the only form the instruction
    /// has: ISO/IEC 7816-4 clause 7.2.4 defines none other, and swSIM refuses
    /// any other P1/P2 or any data field with `6B 00` [V].
    ///
    /// The class byte is a parameter, never a constant chosen here, because
    /// the instruction is not dispatched at the same class on every card. See
    /// [`CLA_GET_RESPONSE_GSM`] for what was observed and why this cannot be a
    /// one-line constant.
    pub fn get_response(class: u8, length: Le) -> Self {
        Self::case2(Header::new(class, INS_GET_RESPONSE, 0x00, 0x00), length)
    }

    /// A FETCH for `length` bytes, in the class byte the caller names.
    ///
    /// P1 and P2 are both zero because ETSI TS 102 221 clause 11.2.3 requires
    /// it; swSIM answers `6A 86` otherwise [V].
    pub fn fetch(class: u8, length: Le) -> Self {
        Self::case2(Header::new(class, INS_FETCH, 0x00, 0x00), length)
    }

    /// The four-octet header.
    pub const fn header(&self) -> Header {
        self.header
    }

    /// The body: the length fields and data that follow the header.
    pub const fn body(&self) -> &Body {
        &self.body
    }

    /// The command's data field, empty when it has none.
    pub fn data(&self) -> &[u8] {
        self.body.data()
    }

    /// The command's expected response length, if it has one.
    pub const fn le(&self) -> Option<Le> {
        self.body.le()
    }

    /// The bytes this command puts on the wire.
    ///
    /// # Errors
    ///
    /// [`EncodeError::EmptyDataField`] for a [`Body::Data`] or
    /// [`Body::DataAndLe`] carrying no bytes, which no Lc form describes, and
    /// [`EncodeError::DataTooLong`] above 65535 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut bytes = Vec::with_capacity(HEADER_LEN + self.data().len() + 3);
        bytes.extend_from_slice(&self.header.to_bytes());
        match &self.body {
            Body::Empty => {}
            Body::Le(Le::Short(value)) => bytes.push(*value),
            Body::Le(Le::Extended(value)) => {
                bytes.push(0x00);
                bytes.extend_from_slice(&value.to_be_bytes());
            }
            Body::Data(data) => push_data_field(&mut bytes, data)?,
            Body::DataAndLe(data, le) => {
                push_data_field(&mut bytes, data)?;
                push_le(&mut bytes, *le);
            }
        }
        Ok(bytes)
    }

    /// Reads a command back out of its wire bytes.
    ///
    /// # Errors
    ///
    /// [`ParseError::CommandTooShort`] below four octets, and the length
    /// errors on [`ParseError`] when the declared length and the bytes
    /// present disagree.
    pub fn decode(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < HEADER_LEN {
            return Err(ParseError::CommandTooShort { len: bytes.len() });
        }
        let header = Header::from_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let rest = &bytes[HEADER_LEN..];
        let body = if rest.is_empty() {
            Body::Empty
        } else if rest.len() == 1 {
            Body::Le(Le::Short(rest[0]))
        } else if rest[0] != 0x00 {
            decode_data_field(rest)?
        } else if rest.len() == 3 {
            Body::Le(Le::Extended(u16::from_be_bytes([rest[1], rest[2]])))
        } else {
            decode_data_field(rest)?
        };
        Ok(Self { header, body })
    }

    /// Splits a command whose data field is longer than one exchange carries.
    ///
    /// The first part is a real case 3 or case 4 command holding the opening
    /// slice of the data field and the command's Le. The rest are
    /// [`CommandPart::Data`]: bare data blocks with no header, which
    /// ISO/IEC 7816-3 clause 10.3.3 sends after a procedure byte and which are
    /// therefore not APDUs at all.
    ///
    /// This is pure data partitioning and invents nothing on the wire. Which
    /// slice to send next, and whether the card wants one byte or all the
    /// rest, is decided by the procedure byte it answers with, so `max_data`
    /// is an upper bound and not a promise the card honours.
    ///
    /// A command that already fits comes back as one [`CommandPart::Command`]
    /// equal to `self`, unchanged.
    ///
    /// # Errors
    ///
    /// [`EncodeError::ZeroChunkSize`] for a `max_data` of zero, and whatever
    /// [`Command::encode`] raises.
    pub fn split(&self, max_data: usize) -> Result<Vec<CommandPart>, EncodeError> {
        if max_data == 0 {
            return Err(EncodeError::ZeroChunkSize);
        }
        let data = self.data();
        if data.len() <= max_data {
            return Ok(vec![CommandPart::Command(self.clone())]);
        }
        let opening = match &self.body {
            Body::Data(_) => Body::Data(data[..max_data].to_vec()),
            Body::DataAndLe(_, le) => Body::DataAndLe(data[..max_data].to_vec(), *le),
            // An empty body has an empty data field, which is never longer
            // than a non-zero chunk size, so the arm above returns first.
            // Spelled out rather than unwrapped so that adding a variant
            // cannot silently make split() produce no parts at all.
            Body::Empty | Body::Le(_) => {
                return Ok(vec![CommandPart::Command(self.clone())]);
            }
        };
        let mut parts = Vec::with_capacity(data.len().div_ceil(max_data));
        parts.push(CommandPart::Command(Command::new(self.header, opening)));
        for chunk in data[max_data..].chunks(max_data) {
            parts.push(CommandPart::Data(chunk.to_vec()));
        }
        Ok(parts)
    }
}

/// Writes a case 3 or case 4 data field, short Lc where that fits.
fn push_data_field(bytes: &mut Vec<u8>, data: &[u8]) -> Result<(), EncodeError> {
    if data.is_empty() {
        return Err(EncodeError::EmptyDataField);
    }
    if data.len() > EXTENDED_DATA_MAX {
        return Err(EncodeError::DataTooLong { len: data.len() });
    }
    if data.len() <= SHORT_DATA_MAX {
        bytes.push(data.len() as u8);
    } else {
        bytes.push(0x00);
        bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
    }
    bytes.extend_from_slice(data);
    Ok(())
}

/// Writes a trailing Le field, short where that fits.
fn push_le(bytes: &mut Vec<u8>, le: Le) {
    match le {
        Le::Short(value) => bytes.push(value),
        Le::Extended(value) => {
            bytes.push(0x00);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
}

/// Reads a data field plus its optional trailing Le out of `rest`, the bytes
/// after the header. `rest` is known to be at least two octets long and to
/// start with a non-zero or extended length marker.
fn decode_data_field(rest: &[u8]) -> Result<Body, ParseError> {
    let (declared, data_start) = if rest[0] != 0x00 {
        (usize::from(rest[0]), 1)
    } else {
        if rest.len() < 3 {
            return Err(ParseError::CommandTooShort { len: rest.len() + HEADER_LEN });
        }
        let declared = usize::from(u16::from_be_bytes([rest[1], rest[2]]));
        if declared == 0 {
            return Err(ParseError::ZeroExtendedLength);
        }
        (declared, 3)
    };
    let data_end = data_start + declared;
    if rest.len() < data_end {
        return Err(ParseError::LengthMismatch {
            declared,
            present: rest.len() - data_start,
        });
    }
    let data = rest[data_start..data_end].to_vec();
    let tail = &rest[data_end..];
    let le = match tail {
        [] => None,
        [value] => Some(Le::Short(*value)),
        [0x00, high, low] => Some(Le::Extended(u16::from_be_bytes([*high, *low]))),
        _ => return Err(ParseError::TrailingBytes { len: tail.len() }),
    };
    Ok(match le {
        None => Body::Data(data),
        Some(le) => Body::DataAndLe(data, le),
    })
}

/// One exchange's worth of a command that does not fit in a single exchange.
///
/// The distinction is not cosmetic. ISO/IEC 7816-3 clause 10.3.3 continues a
/// chained command by sending raw data with no CLA, INS, P1, P2 and no length
/// prefix, so a continuation handed to [`Command::decode`] is not a command
/// and must not be decoded as one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CommandPart {
    /// The opening APDU, carrying the first slice of the data field.
    Command(Command),
    /// A bare block of command data, sent in answer to a procedure byte.
    Data(Vec<u8>),
}

impl CommandPart {
    /// The bytes this part puts on the wire.
    ///
    /// # Errors
    ///
    /// Whatever [`Command::encode`] raises, for the [`CommandPart::Command`]
    /// variant.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        match self {
            Self::Command(command) => command.encode(),
            Self::Data(data) => Ok(data.clone()),
        }
    }

    /// The command data this part carries.
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Command(command) => command.data(),
            Self::Data(data) => data,
        }
    }
}

/// One response APDU, split into what it carries and how it finished.
///
/// Two shapes, because two are real. The common one is response data followed
/// by a status word. The other is a single procedure byte: ISO/IEC 7816-3
/// clause 10.3.3 tells the terminal to send more command data, and that
/// response carries no status word at all. [V] for swICC:
/// `src/apdu.c:swicc_apdu_res_deparse` sizes the response at `data.len() + 1`
/// for a procedure-byte status and writes a single octet. A parser that
/// assumed the last two octets are always SW1 SW2 would read a procedure byte
/// followed by nothing as a status word.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Response {
    /// Response data followed by SW1 and SW2.
    Complete {
        /// Everything before the last two octets.
        body: Vec<u8>,
        /// The last two octets.
        status: StatusWord,
    },
    /// A single procedure byte with no status word.
    Procedure {
        /// The one octet the card sent.
        byte: u8,
    },
}

impl Response {
    /// Splits response bytes into data and status word.
    ///
    /// # Errors
    ///
    /// [`ParseError::ResponseTooShort`] for an empty response. A card that
    /// says nothing at all has not answered, and inventing a status for it
    /// would put a fabricated finding into a scan report.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        match bytes.len() {
            0 => Err(ParseError::ResponseTooShort { len: 0 }),
            1 => Ok(Self::Procedure { byte: bytes[0] }),
            len => Ok(Self::Complete {
                body: bytes[..len - 2].to_vec(),
                status: StatusWord::from_bytes([bytes[len - 2], bytes[len - 1]]),
            }),
        }
    }

    /// The response data, empty for a procedure byte.
    pub fn body(&self) -> &[u8] {
        match self {
            Self::Complete { body, .. } => body,
            Self::Procedure { .. } => &[],
        }
    }

    /// The status word, absent for a procedure byte.
    ///
    /// `None` rather than a fabricated value: a procedure byte is not a
    /// status, and a caller has to be able to tell the two apart.
    pub const fn status(&self) -> Option<StatusWord> {
        match self {
            Self::Complete { status, .. } => Some(*status),
            Self::Procedure { .. } => None,
        }
    }

    /// The procedure byte, absent for a complete response.
    pub const fn procedure_byte(&self) -> Option<u8> {
        match self {
            Self::Procedure { byte } => Some(*byte),
            Self::Complete { .. } => None,
        }
    }

    /// Whether this response carries a status word.
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }

    /// What the procedure byte asks for, given the instruction it answers.
    ///
    /// `None` when this response is complete. The instruction byte is a
    /// parameter because a procedure byte *is* an instruction-derived value: a
    /// positive acknowledgement is the instruction itself, so the octet cannot
    /// be read without knowing what was sent.
    pub const fn procedure_action(&self, instruction: u8) -> Option<ProcedureAction> {
        match *self {
            Self::Procedure { byte } => Some(ProcedureAction::decode(byte, instruction)),
            Self::Complete { .. } => None,
        }
    }
}

/// What a procedure byte asks the terminal to send next.
///
/// [V] for swICC, from `src/apdu.c:swicc_apdu_res_deparse` and the
/// `swicc_apdu_sw1_et` enumeration in `include/swicc/apdu.h`, which names the
/// three and points at ISO/IEC 7816-3 clause 10.3.3 table 11.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcedureAction {
    /// `60`: send the next slice and take no action.
    NextChunk,
    /// A positive acknowledgement, which is the instruction byte echoed back:
    /// send the whole rest of the command data.
    SendAll,
    /// A negative acknowledgement, which is the instruction byte inverted: send
    /// exactly one more byte.
    SendOne,
    /// An octet this crate does not recognise as any of the three.
    ///
    /// [U] A deprecated ISO/IEC 7816-3 edition also spelled ACK-one as the
    /// instruction OR 1. No card in this project's fixture does that, so the
    /// octet is carried through rather than guessed at, and a caller that
    /// meets it can match on it.
    Unrecognised(u8),
}

impl ProcedureAction {
    /// Reads a procedure byte in the context of the instruction it answers.
    pub const fn decode(byte: u8, instruction: u8) -> Self {
        if byte == PROCEDURE_BYTE_NULL {
            Self::NextChunk
        } else if byte == instruction {
            Self::SendAll
        } else if byte == instruction ^ 0xFF {
            Self::SendOne
        } else {
            Self::Unrecognised(byte)
        }
    }
}

/// What a `91 xx`, `92 xx`, `93 xx` or `9F xx` status says the card is
/// holding, and what that means for SW2.
///
/// The whole reason this type exists is that `9F xx` is two different things
/// on two cards this crate has read the source of, and a single accessor would
/// have to pick one and be wrong half the time.
///
/// - **swSIM, `91 <length>`:** a proactive CAT command is pending. FETCH
///   hands it back and clears it. [V], `src/apduh.c:sim_apduh_demux`
///   rewrites every completed `90 00` into `91 <length>` when
///   `proactive.command_length > 0`, with a static_assert that the buffer
///   is at most 256 bytes.
/// - **swSIM, `9F <length>`:** response data is pending, not a proactive
///   command. Its GSM SELECT handler and its AUTHENTICATE handler both
///   `swicc_apdu_rc_enq` their result into the GET RESPONSE queue and answer
///   `9F <response length>`. [V], read at the pinned commit.
/// - **GSM 11.11** puts a *proactive command* length in `9F xx`. [U] That
///   clause is not available to this project; see AGENTS.md section 6.
///
/// So `9F xx` is left undetermined rather than guessed. Deciding it needs
/// the command that was sent, which this module cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pending {
    /// SW1 `91`, `92` or `93`, with SW2 the pending proactive command's
    /// length. Drain it with FETCH.
    ProactiveCommand {
        /// The command's length.
        length: u8,
    },
    /// SW1 `9F`, with SW2 this crate refuses to interpret.
    Undetermined {
        /// SW2 as the card wrote it, carried through untouched.
        sw2: u8,
    },
    /// Any other SW1. A status word is not "pending" and this constructor says
    /// so rather than inventing a variant for it.
    None,
}

impl Pending {
    /// Reads the pending thing, if this status word names one.
    pub const fn of(status: StatusWord) -> Self {
        match status.sw1() {
            0x91..=0x93 => Self::ProactiveCommand {
                length: status.sw2(),
            },
            0x9F => Self::Undetermined { sw2: status.sw2() },
            _ => Self::None,
        }
    }

    /// The proactive command's length, when this is a proactive command.
    pub const fn proactive_command_length(self) -> Option<u8> {
        match self {
            Self::ProactiveCommand { length } => Some(length),
            Self::Undetermined { .. } | Self::None => None,
        }
    }

    /// Whether the card is holding something a follow-up exchange can fetch.
    pub const fn is_pending(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// What a `6C xx` status offers as a corrected Le.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CorrectedLength {
    /// SW2 holds the Le the card would have accepted, 1 to 255 bytes.
    ///
    /// This is the only variant safe to put back into a command. See
    /// `Unusable`.
    Accepts(u8),
    /// The card answered `6C 00`, so it named no usable length.
    ///
    /// ISO/IEC 7816-4 clause 9.1.1 defines `6C xx` with `xx` the correct Le
    /// and says nothing about `xx` being zero. swSIM's FETCH answers
    /// exactly `6C 00` when Le is not the pending command's length [V], `
    /// src/apduh.c:apduh_etsi_cat_fetch`. An Le of `00` encodes 256, so
    /// copying this `00` back into a command would send a longer one than
    /// the card asked for. That is why it is a variant and not an `Accepts(0)`.
    Unusable,
}

/// How bad a status word is, independent of what it asks the caller to do.
///
/// This is the rule layer's view and `Outcome`'s is the session layer's, and
/// they are allowed to disagree: a `6C xx` owes a follow-up *and* is a
/// retriable refusal. Ask whichever question you actually have.
///
/// The SW1 assignments below are ISO/IEC 7816-4 clause 9.1 table 42 and the
/// GSM 11.11 additions swSIM implements. Two of them are load-bearing
/// corrections to a tempting simplification, and both are marked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatusClass {
    /// `90 00` and nothing else.
    Success,
    /// Normal processing with the card still holding something: `61 xx`, or
    /// one of the pending spellings `91`, `92`, `93`, `9F`.
    ///
    /// Also `60`, which is a procedure byte rather than a status at all and
    /// means the card wants more command data.
    ///
    /// Not a failure. A scanner that files this as an error reports every
    /// healthy card as broken.
    FollowUpRequired,
    /// `62 xx` and `63 xx`: the command ran, with a caveat.
    Warning,
    /// A refusal a caller may sensibly try again with a change: `67 xx`
    /// wrong length, `68 xx` function in class unsupported, `6A xx` and
    /// `6B xx` wrong parameters, `6C xx` wrong Le, `6D xx` instruction
    /// not supported, `6E xx` class not supported.
    Retriable,
    /// A failure retrying the same command will not fix.
    Error,
    /// SW1 outside `0x60..=0x9F`. Proprietary and unclassified.
    Proprietary,
}

impl StatusClass {
    /// Classifies a status word.
    ///
    /// Two GSM 11.11 values inside the `0x90..=0x9F` octet range are
    /// failures and are classified as such here even though the range looks
    /// like normal processing:
    ///
    /// - `94 xx`, which swSIM uses for `"File ID not found"`,
    ///   `"No EF selected"` and `"File is inconsistent with the command"`.
    ///   [V], `src/apduh.c`.
    /// - `98 xx`, which swSIM uses for `"Authentication error, incorrect
    ///   MAC"`, citing 3GPP TS 31.102 clause 7.3.1. [V], `src/apduh.c`.
    ///
    /// So `0x91` to `0x9F` is *not* a range test, and `0x95`..=0x97` and
    /// `0x99` are deliberately `Proprietary` rather than being folded into
    /// whichever neighbour seemed nearest.
    pub const fn of(status: StatusWord) -> Self {
        match status.sw1() {
            0x90 => {
                if status.sw2() == 0x00 {
                    Self::Success
                } else {
                    Self::Warning
                }
            }
            0x61 | 0x91..=0x93 | 0x9F | 0x60 => Self::FollowUpRequired,
            0x62 | 0x63 => Self::Warning,
            0x67 | 0x68 | 0x6A..=0x6E => Self::Retriable,
            0x64..=0x66 | 0x69 | 0x6F | 0x94..=0x98 => Self::Error,
            _ => Self::Proprietary,
        }
    }

    /// Whether this is a failure, as opposed to a warning or a hand-back.
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Retriable | Self::Error)
    }

    /// Whether the card processed the command rather than refusing it.
    pub const fn is_normal_processing(self) -> bool {
        matches!(self, Self::Success | Self::FollowUpRequired)
    }
}

/// Why a command could not be turned into bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncodeError {
    /// A data field longer than any APDU length field can describe.
    ///
    /// 65535 bytes is the ceiling: the extended Lc form writes a two-octet
    /// count, so there is no third length form to fall back on.
    DataTooLong {
        /// The length that could not be encoded.
        len: usize,
    },
    /// A data field of zero bytes, which no Lc form describes.
    ///
    /// An empty command body is case 1 or case 2, which is what a caller who
    /// wants no data should build.
    EmptyDataField,
    /// A chaining chunk size of zero.
    ZeroChunkSize,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataTooLong { len } => write!(
                f,
                "a data field of {len} bytes exceeds the {EXTENDED_DATA_MAX} an APDU length field can describe"
            ),
            Self::EmptyDataField => f.write_str("a data field of zero bytes has no length encoding"),
            Self::ZeroChunkSize => f.write_str("a chaining chunk size of zero cannot make progress"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Why a command or a response could not be read back.
///
/// Every variant names the mismatch rather than reporting "malformed", because
/// the usual cause of hitting one is a caller who assumed a length form the
/// card did not use, and the byte counts are what tell them which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ParseError {
    /// Fewer than four octets, so there is no header.
    CommandTooShort {
        /// How many octets were present.
        len: usize,
    },
    /// The declared Lc does not account for the octets that followed it.
    LengthMismatch {
        /// The count the length field declared.
        declared: usize,
        /// The count actually present.
        present: usize,
    },
    /// Octets after the data field that ISO/IEC 7816-4 does not put anywhere.
    TrailingBytes {
        /// How many unaccounted-for octets followed the data field.
        len: usize,
    },
    /// An extended Lc of `00 00`, which is not a command.
    ZeroExtendedLength,
    /// An empty response: no data and no status word and no procedure byte.
    ResponseTooShort {
        /// How many octets were present.
        len: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandTooShort { len } => {
                write!(f, "a command needs {HEADER_LEN} header octets, got {len}")
            }
            Self::LengthMismatch {
                declared,
                present,
            } => write!(
                f,
                "the length field declares {declared} data octets but {present} are present"
            ),
            Self::TrailingBytes { len } => write!(
                f,
                "{len} octet(s) follow the data field where ISO/IEC 7816-4 allows none"
            ),
            Self::ZeroExtendedLength => f.write_str("an extended length field of zero is not a command"),
            Self::ResponseTooShort { len } => {
                write!(f, "a response needs a status word, got {len} octet(s)")
            }
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_round_trips_through_its_four_octets() {
        // SELECT MF, the first command any scan issues.
        let header = Header::new(0x00, 0xA4, 0x00, 0x00);
        assert_eq!(header.to_bytes(), [0x00, 0xA4, 0x00, 0x00]);
        assert_eq!(Header::from_bytes([0x00, 0xA4, 0x00, 0x00]), header);
        assert_eq!(header.to_string(), "00 A4 00 00");
    }

    #[test]
    fn header_accessors_name_the_octets_they_return() {
        // A swapped pair is the classic hand-rolled-APDU bug, so each accessor
        // is checked against a header whose four octets are all distinct.
        let header = Header::from_bytes([0x11, 0x22, 0x33, 0x44]);
        assert_eq!(header.class(), 0x11);
        assert_eq!(header.instruction(), 0x22);
        assert_eq!(header.parameter_1(), 0x33);
        assert_eq!(header.parameter_2(), 0x44);
    }

    #[test]
    fn every_class_byte_is_accepted() {
        // ISO/IEC 7816-4 assigns no universal meaning to CLA and no range to
        // P1/P2. A constructor that rejected a value here would be inventing a
        // rule the standard does not have, and would one day refuse a real
        // card. Asserting this keeps the choice deliberate.
        for class in u8::MIN..=u8::MAX {
            assert_eq!(Header::new(class, 0x00, 0x00, 0x00).class(), class);
        }
    }

    #[test]
    fn exactly_one_status_word_is_a_success() {
        // Exhausts all 65536 pairs: 90 00 is the sole success and no other
        // SW2 under SW1 0x90 may be mistaken for one.
        let mut successes: Vec<[u8; 2]> = Vec::new();
        for raw in 0u32..=u16::MAX as u32 {
            let bytes = [((raw >> 8) & 0xFF) as u8, (raw & 0xFF) as u8];
            if StatusWord::from_bytes(bytes).is_success() {
                successes.push(bytes);
            }
        }
        assert_eq!(successes, vec![[0x90, 0x00]]);
    }

    #[test]
    fn follow_up_statuses_report_their_byte_count() {
        for count in 0u8..=u8::MAX {
            let more = StatusWord::new(0x61, count).outcome();
            assert_eq!(
                more,
                Outcome::MoreDataAvailable { available: count },
                "61 {count:02X} must report its count"
            );
            assert!(more.needs_follow_up());
            assert!(!more.is_success());

            assert_eq!(
                StatusWord::new(0x6C, count).outcome(),
                Outcome::WrongLength { available: count },
            );
        }
    }

    #[test]
    fn no_precise_diagnosis_is_distinguished_from_other_6f_statuses() {
        assert_eq!(
            StatusWord::new(0x6F, 0x00).outcome(),
            Outcome::NoPreciseDiagnosis
        );
        // 6F XX with a non-zero XX is not "no precise diagnosis"; it must stay
        // visible as a distinct pair rather than being flattened.
        assert_eq!(
            StatusWord::new(0x6F, 0x81).outcome(),
            Outcome::Other {
                sw1: 0x6F,
                sw2: 0x81
            }
        );
    }

    #[test]
    fn other_statuses_keep_both_bytes() {
        // 6A 82 is "file not found" and 6D 00 is "instruction not supported";
        // the module above has to be able to see the difference.
        for (sw1, sw2) in [(0x6A, 0x82), (0x6D, 0x00), (0x67, 0x00), (0x63, 0xC0)] {
            let outcome = StatusWord::new(sw1, sw2).outcome();
            assert_eq!(outcome, Outcome::Other { sw1, sw2 });
            assert!(!outcome.needs_follow_up());
            assert!(!outcome.is_success());
        }
    }

    #[test]
    fn a_status_word_round_trips_and_renders_as_two_uppercase_hex_digits() {
        let status = StatusWord::from_bytes([0x9F, 0x17]);
        assert_eq!(status.to_bytes(), [0x9F, 0x17]);
        assert_eq!(status.to_string(), "9F17");
        assert_eq!(status.sw1(), 0x9F);
        assert_eq!(status.sw2(), 0x17);
    }
}
