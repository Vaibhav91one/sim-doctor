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
    /// a pending proactive command as a finished exchange. \\\[V], swSIM
    /// `src/apduh.c:sim_apduh_demux`. Ask
    /// [`StatusWord::is_normal_processing`] instead when "the command worked"
    /// is the question and "there is nothing more" is not.
    pub const fn is_success(self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }

    /// Whether the card reported normal processing, whether or not something
    /// is still outstanding.
    ///
    /// True for `90 00`, for `61 xx`, which ISO/IEC 7816-4 clause 9.1.1
    /// defines as normal processing with response bytes available, and for the
    /// four pending spellings `91 xx`, `92 xx`, `93 xx` and `9F xx`.
    ///
    /// False for `90 xx` with a non-zero SW2, because clause 9.1 defines no
    /// SW2 for SW1 `90` and calling that normal processing would be a silent
    /// assumption about a status byte nobody has documented. False for `94`
    /// and `98`, which are GSM 11.11 failures inside the same octet range and
    /// are the reason this is a list and not a range test.
    ///
    /// Agrees with [`StatusClass::is_normal_processing`] for all 65536 status
    /// words, which a test asserts: two definitions of one phrase that
    /// disagreed on `61 xx` would be a trap for whichever caller read the
    /// other one first.
    pub const fn is_normal_processing(self) -> bool {
        match self.sw1 {
            0x90 => self.sw2 == 0x00,
            0x61 | 0x91 | 0x92 | 0x93 | 0x9F => true,
            _ => false,
        }
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
    /// [`Outcome::WrongLength::corrected`] straight out of the enum because that
    /// field is a faithful copy of SW2 and `6C 00` is not a usable length: an
    /// Le of `00` encodes 256, so substituting it would send a longer command
    /// than the card asked for. swSIM's FETCH answers exactly `6C 00` when Le
    /// is not the pending command's length \\\[V].
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
    /// The octet the card wrote, including a zero. Nothing this project can
    /// cite defines what a `91 00` means, and [`Le::for_byte_count`] refuses
    /// a zero, so a caller building a follow-up from one has to notice rather
    /// than this crate quietly substituting 256 the way `61 00` does.
    ///
    /// Only the three 3GPP spellings `91`, `92` and `93` are read that way,
    /// because those are the ones that define SW2 as the pending command's
    /// length. \\\[V] for swSIM, which writes exactly `91 <length>` when a
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
        /// How many RESPONSE DATA bytes are still waiting, 1 to 256.
        ///
        /// A count, not a copy of SW2. `61 00` means 256 per
        /// ISO/IEC 7816-4 clause 9.1.1, and handing the zero on would invite
        /// a caller to ask for no bytes at all. [`StatusWord::
        /// response_data_length`] resolves the same byte the same way without
        /// the caller having to match on the enum.
        available: u16,
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

    /// `6C xx`. The card refused the command's Le and puts SW2 in `corrected`.
    /// Retrying with that Le is the caller's decision, not an automatic
    /// retry: some cards want a shorter read and some report the total
    /// remaining length.
    WrongLength {
        /// The SW2 octet, verbatim, 0 to 255.
        ///
        /// Named for what it holds rather than `available`, because SW2 here
        /// is a third thing again - a *corrected Le* - while `61 xx` and
        /// `9x xx` put two other numbers in the same byte. Unlike `61 xx`
        /// there is no `00` spelling to resolve: `6C 00` is not 256, it is a
        /// card naming no usable length at all. [`CorrectedLength`] says so,
        /// and [`StatusWord::corrected_length`] returns it.
        corrected: u8,
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
            (0x61, advertised) => Self::MoreDataAvailable {
                // `61 00` is 256, per ISO/IEC 7816-4 clause 9.1.1.
                available: if advertised == 0 {
                    Le::SHORT_MAX as u16
                } else {
                    advertised as u16
                },
            },
            (0x91..=0x93, _) | (0x9F, _) => Self::Pending {
                pending: Pending::of(status),
            },
            (0x6C, corrected) => Self::WrongLength { corrected },
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
/// \\\[V] for swSIM: `src/apduh.c` dispatches INS `0xC0` only under
/// `SWICC_APDU_CLA_TYPE_PROPRIETARY`, and within that only at CLA `0xA0`, so
/// the ISO-conformant same-CLA form is not routed at all on that card.
pub const INS_GET_RESPONSE: u8 = 0xC0;

/// INS of ETSI TS 102 221 clause 11.2.3 FETCH, the instruction that hands
/// back a pending proactive command.
///
/// \\\[V] for swSIM: `src/apduh.c:apduh_etsi_cat_fetch` requires P1 and P2 both
/// `00` and requires Le to equal the pending command's length exactly, so a
/// FETCH built with any other Le is answered `6C xx` rather than the command.
pub const INS_FETCH: u8 = 0x12;

/// The class byte swSIM dispatches GET RESPONSE from, and the default this
/// crate uses.
///
/// \\\[V], read at the pinned swSIM commit: INS `0xC0` is routed at CLA `0xA0`
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
/// \\\[V] for swSIM: `src/apduh.c` routes INS `0x12` at CLA `0x80` exactly, which
/// is the ETSI proprietary class of ETSI TS 102 221 clause 10.1.1.
pub const CLA_FETCH_ETSI: u8 = 0x80;

/// Highest logical channel number ([`class_on_channel`]).
pub const MAX_LOGICAL_CHANNEL: u8 = 19;

/// The class byte for `cla` addressed to logical channel `channel` (0 is the
/// basic channel), keeping whether the command is an ISO (`0x`) or a
/// GlobalPlatform (`8x`) command and whether secure messaging is indicated.
/// `None` for a channel above [`MAX_LOGICAL_CHANNEL`] or a class byte that is
/// neither first nor further interindustry (for example the GSM `A0`).
///
/// GlobalPlatform Card Specification v2.3.1 section 11.1.4: channels 0 to 3 use
/// the first interindustry coding (`b2 b1` is the channel, `b3` or `b4` is secure
/// messaging, Table 11-11); channels 4 to 19 use the further interindustry
/// coding (`b7` set, `b6` is secure messaging, `b4..b1` is the channel minus 4,
/// Table 11-12), so a GlobalPlatform command is `C0..CF` or, with secure
/// messaging, `E0..EF`. Applying it twice gives the same byte, so it is safe on
/// a command that was already adjusted (a MAC'd one). pySim
/// `lchan_nr_to_cla` agrees for channels 1 to 3 and refuses a GlobalPlatform
/// class above 3, which the specification allows.
pub const fn class_on_channel(cla: u8, channel: u8) -> Option<u8> {
    if channel > MAX_LOGICAL_CHANNEL {
        return None;
    }
    let proprietary = cla & 0x80;
    let secure = if cla & 0x70 == 0x00 {
        cla & 0x0C != 0
    } else if cla & 0x50 == 0x40 {
        cla & 0x20 != 0
    } else {
        return None;
    };
    Some(if channel < 4 {
        proprietary | if secure { 0x04 } else { 0 } | channel
    } else {
        proprietary | 0x40 | if secure { 0x20 } else { 0 } | (channel - 4)
    })
}

/// The NULL procedure byte of ISO/IEC 7816-3 clause 10.3.3 table 11.
///
/// \\\[V] for swICC: `src/apdu.c:swicc_apdu_res_deparse` sizes a response carrying
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
    /// any other P1/P2 or any data field with `6B 00` \\\[V].
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
    /// it; swSIM answers `6A 86` otherwise \\\[V].
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
            return Err(ParseError::TruncatedLengthField {
                present: rest.len(),
            });
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
/// response carries no status word at all. \\\[V] for swICC:
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
/// \\\[V] for swICC, from `src/apdu.c:swicc_apdu_res_deparse` and the
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
    /// \\\[U] A deprecated ISO/IEC 7816-3 edition also spelled ACK-one as the
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
///   hands it back and clears it. \\\[V], `src/apduh.c:sim_apduh_demux`
///   rewrites every completed `90 00` into `91 <length>` when
///   `proactive.command_length > 0`, with a static_assert that the buffer
///   is at most 256 bytes.
/// - **swSIM, `9F <length>`:** response data is pending, not a proactive
///   command. Its GSM SELECT handler and its AUTHENTICATE handler both
///   `swicc_apdu_rc_enq` their result into the GET RESPONSE queue and answer
///   `9F <response length>`. \\\[V], read at the pinned commit.
/// - **GSM 11.11** puts a *proactive command* length in `9F xx`. \\\[U] That
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
    /// exactly `6C 00` when Le is not the pending command's length \\\[V], `
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
    /// Not a failure. A scanner that files this as an error reports every
    /// healthy card as broken.
    FollowUpRequired,
    /// `62 xx` and `63 xx`: the command ran, with a caveat. Also `90 xx` with
    /// a non-zero SW2, for which ISO/IEC 7816-4 clause 9.1 defines no meaning
    /// at all: the card reported normal processing and then a status byte this
    /// crate cannot read, which is a caveat rather than a refusal.
    ///
    /// Not a failure, and not [`Self::is_normal_processing`] either, because
    /// the card did not say the command was refused and did not say it was
    /// finished cleanly.
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
    ///   \\\[V], `src/apduh.c`.
    /// - `98 xx`, which swSIM uses for `"Authentication error, incorrect
    ///   MAC"`, citing 3GPP TS 31.102 clause 7.3.1. \\\[V], `src/apduh.c`.
    ///
    /// So `0x91` to `0x9F` is *not* a range test. `0x95`, `0x96`, `0x97` and
    /// `0x99` are deliberately `Proprietary` rather than folded into whichever
    /// neighbour seemed nearest, because nothing this project can cite defines
    /// them.
    ///
    /// `0x60` is `Proprietary` here too, and that is not an oversight: it is
    /// the ISO/IEC 7816-3 procedure byte, which a card sends as a one-octet
    /// response rather than as a two-octet status word, so [`Response`] models
    /// it separately and [`ProcedureAction`] is what reads one. Classifying it
    /// here would have made this enum claim a follow-up was owed while
    /// [`Outcome`] said none was.
    pub const fn of(status: StatusWord) -> Self {
        match status.sw1() {
            0x90 => {
                if status.sw2() == 0x00 {
                    Self::Success
                } else {
                    Self::Warning
                }
            }
            0x61 | 0x91..=0x93 | 0x9F => Self::FollowUpRequired,
            0x62 | 0x63 => Self::Warning,
            0x67 | 0x68 | 0x6A..=0x6E => Self::Retriable,
            0x64..=0x66 | 0x69 | 0x6F | 0x94 | 0x98 => Self::Error,
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
    /// A two-octet length field that ran out of octets.
    ///
    /// ISO/IEC 7816-4 writes an extended Lc or Le as a `00` marker followed
    /// by two more octets. A command that stops after the marker announced a
    /// length and then did not send it, which is a different fault from
    /// having no header at all. Reporting it as a four-octet command that
    /// arrived with six octets named neither the fault nor the remedy.
    TruncatedLengthField {
        /// How many octets followed the header where a three-octet length
        /// field was needed: the `00` marker alone, or the marker plus one
        /// more.
        present: usize,
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
            Self::TruncatedLengthField { present } => write!(
                f,
                "an extended length field needs 2 octets after its 00 marker, got {present}"
            ),
            Self::LengthMismatch { declared, present } => write!(
                f,
                "the length field declares {declared} data octets but {present} are present"
            ),
            Self::TrailingBytes { len } => write!(
                f,
                "{len} octet(s) follow the data field where ISO/IEC 7816-4 allows none"
            ),
            Self::ZeroExtendedLength => {
                f.write_str("an extended length field of zero is not a command")
            }
            Self::ResponseTooShort { len } => {
                write!(f, "a response needs a status word, got {len} octet(s)")
            }
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    #[test]
    fn class_byte_carries_the_logical_channel() {
        // GP Card Spec v2.3.1 Tables 11-11 and 11-12: GlobalPlatform 8x / Cx / Ex,
        // ISO 0x / 4x / 6x; secure messaging b3 (first) or b6 (further).
        let cases: [(u8, u8, u8); 14] = [
            (0x80, 0, 0x80),
            (0x80, 1, 0x81),
            (0x80, 3, 0x83),
            (0x84, 2, 0x86),
            (0x00, 3, 0x03),
            (0x80, 4, 0xC0),
            (0x80, 19, 0xCF),
            (0x84, 4, 0xE0),
            (0x84, 19, 0xEF),
            (0x00, 4, 0x40),
            (0x00, 19, 0x4F),
            (0xC3, 0, 0x80),
            (0xE1, 1, 0x85),
            (0x41, 2, 0x02),
        ];
        for (cla, ch, want) in cases {
            assert_eq!(class_on_channel(cla, ch), Some(want), "{cla:02X} on {ch}");
            // idempotent
            assert_eq!(class_on_channel(want, ch), Some(want));
        }
        assert_eq!(class_on_channel(0x80, 20), None);
        assert_eq!(class_on_channel(0xA0, 1), None);
    }

    use super::*;

    /// Every status word there is, as a two-octet pair.
    ///
    /// Classifying a status word is cheap and a status word is only two
    /// octets, so "every one of them" costs less than the false confidence a
    /// spot check would buy.
    fn all_status_words() -> impl Iterator<Item = StatusWord> {
        (0u32..=u32::from(u16::MAX))
            .map(|raw| StatusWord::from_bytes([((raw >> 8) & 0xFF) as u8, (raw & 0xFF) as u8]))
    }

    /// Data-field lengths that straddle both length forms.
    ///
    /// 255 and 256 are where the short Lc stops being expressible, so a matrix
    /// that misses them tests the easy middle only.
    const LENGTH_BOUNDARIES: [usize; 10] = [1, 2, 254, 255, 256, 257, 258, 1000, 65534, 65535];

    // --- header ------------------------------------------------------------

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
    fn every_octet_value_survives_a_header_in_every_position() {
        // ISO/IEC 7816-4 assigns no universal meaning to CLA and no range to
        // P1/P2. A constructor that rejected a value would be inventing a rule
        // the standard does not have, and would one day refuse a real card.
        for position in 0..HEADER_LEN {
            for octet in 0u8..=u8::MAX {
                let mut bytes = [0x00; HEADER_LEN];
                bytes[position] = octet;
                let header = Header::from_bytes(bytes);
                assert_eq!(
                    header.to_bytes(),
                    bytes,
                    "position {position}, octet {octet:02X}"
                );
            }
        }
    }

    #[test]
    fn a_header_always_renders_as_four_uppercase_hex_digits() {
        // The rendering is what an operator greps and a scanner diffs, so its
        // shape is a property rather than a sample.
        for octet in 0u8..=u8::MAX {
            let rendered = Header::new(octet, octet, octet, octet).to_string();
            assert_eq!(rendered.len(), 11, "{rendered}");
            assert_eq!(rendered, rendered.to_uppercase(), "{rendered}");
        }
    }

    // --- Le ----------------------------------------------------------------

    #[test]
    fn every_le_spelling_reports_the_byte_count_it_encodes() {
        // The two zero spellings are the whole reason this type exists: a
        // short `00` is 256 and an extended `0000` is 65536, so neither
        // form is a superset of the other and the count has to be resolved.
        for raw in 0u8..=u8::MAX {
            let expected = if raw == 0 {
                Le::SHORT_MAX
            } else {
                u32::from(raw)
            };
            assert_eq!(Le::Short(raw).byte_count(), expected, "short {raw:02X}");
        }
        for raw in 0u16..=u16::MAX {
            let expected = if raw == 0 {
                Le::EXTENDED_MAX
            } else {
                u32::from(raw)
            };
            assert_eq!(
                Le::Extended(raw).byte_count(),
                expected,
                "extended {raw:04X}"
            );
        }
    }

    #[test]
    fn for_byte_count_asks_for_the_shortest_form_that_names_the_same_number() {
        // A card that expects one shape and is handed the other may answer
        // `6C xx`, so this is a correctness property and not a tidiness one.
        let header = Header::new(0x00, 0xB0, 0x00, 0x00);
        for count in 1u32..=Le::EXTENDED_MAX {
            let le = Le::for_byte_count(count).unwrap_or_else(|| panic!("{count}"));
            assert_eq!(le.byte_count(), count, "{count}");
            let wire = match le {
                Le::Short(_) => 1,
                Le::Extended(_) => 3,
            };
            let encoded = Command::case2(header, le).encode().unwrap();
            assert_eq!(encoded.len(), HEADER_LEN + wire, "{count}");
        }
    }

    #[test]
    fn for_byte_count_refuses_a_count_no_card_can_act_on() {
        // Zero is not "ask for nothing": an Le of `00` encodes 256, so there
        // is no way to write a request for zero bytes and pretending otherwise
        // would put a number on the wire that means something else.
        assert_eq!(Le::for_byte_count(0), None);
        assert_eq!(Le::for_byte_count(Le::EXTENDED_MAX + 1), None);
        assert_eq!(Le::for_byte_count(u32::MAX), None);
    }

    // --- command codec -----------------------------------------------------

    /// Every body shape, at every length boundary that changes its encoding.
    fn canonical_commands() -> Vec<Command> {
        let header = Header::new(0x00, 0xA4, 0x00, 0x00);
        let mut commands = vec![Command::case1(header)];

        for raw in [0u8, 1, 127, 254, 255] {
            commands.push(Command::case2(header, Le::Short(raw)));
        }
        for raw in [0u16, 1, 255, 256, 65535] {
            commands.push(Command::case2(header, Le::Extended(raw)));
        }
        for len in LENGTH_BOUNDARIES {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            commands.push(Command::case3(header, data.clone()));
            commands.push(Command::case4(header, data.clone(), Le::Short(0)));
            commands.push(Command::case4(header, data, Le::Extended(0x1234)));
        }
        commands
    }

    #[test]
    fn every_canonical_command_round_trips_byte_for_byte() {
        // The acceptance criterion as a property rather than a table of
        // expected hex: whatever this crate encodes, it decodes back to the
        // same value and re-encodes to the same bytes.
        for command in canonical_commands() {
            let encoded = command.encode().unwrap();
            let decoded = Command::decode(&encoded)
                .unwrap_or_else(|e| panic!("{command:?} encoded to {encoded:02X?}: {e}"));
            assert_eq!(decoded, command, "{encoded:02X?}");
            assert_eq!(decoded.encode().unwrap(), encoded, "{encoded:02X?}");
        }
    }

    #[test]
    fn decoding_never_invents_or_loses_a_data_octet() {
        for command in canonical_commands() {
            let encoded = command.encode().unwrap();
            let decoded = Command::decode(&encoded).unwrap();
            assert_eq!(decoded.data(), command.data(), "{encoded:02X?}");
            assert_eq!(decoded.le(), command.le(), "{encoded:02X?}");
        }
    }

    #[test]
    fn the_encoder_only_emits_the_length_form_a_card_will_accept() {
        // Asserted by reading the encoded bytes back, not by trusting the
        // encoder to have done what it meant to.
        let header = Header::new(0x00, 0xA4, 0x00, 0x00);
        for len in LENGTH_BOUNDARIES {
            let data = vec![0x5Au8; len];
            let encoded = Command::case3(header, data).encode().unwrap();
            let lc_len = if len <= SHORT_DATA_MAX { 1 } else { 3 };
            assert_eq!(encoded.len(), HEADER_LEN + lc_len + len, "data of {len}");
            if len <= SHORT_DATA_MAX {
                assert_eq!(encoded[HEADER_LEN] as usize, len);
            } else {
                assert_eq!(encoded[HEADER_LEN], 0x00, "extended Lc marker");
                assert_eq!(
                    u16::from_be_bytes([encoded[HEADER_LEN + 1], encoded[HEADER_LEN + 2]]) as usize,
                    len
                );
            }
        }
    }

    #[test]
    fn a_data_field_of_zero_bytes_has_no_length_encoding() {
        let header = Header::new(0x00, 0xA4, 0x00, 0x00);
        // A caller who wants no data builds case 1 or case 2; a data field that
        // declares itself empty is a mistake the encoder refuses to guess at.
        assert_eq!(
            Command::case3(header, Vec::new()).encode(),
            Err(EncodeError::EmptyDataField)
        );
        assert_eq!(
            Command::case4(header, Vec::new(), Le::Short(0)).encode(),
            Err(EncodeError::EmptyDataField)
        );
    }

    #[test]
    fn a_data_field_longer_than_any_length_field_is_refused() {
        let header = Header::new(0x00, 0xA4, 0x00, 0x00);
        let len = EXTENDED_DATA_MAX + 1;
        assert_eq!(
            Command::case3(header, vec![0u8; len]).encode(),
            Err(EncodeError::DataTooLong { len })
        );
    }

    #[test]
    fn a_command_without_a_header_cannot_be_decoded() {
        for len in 0..HEADER_LEN {
            assert_eq!(
                Command::decode(&vec![0x00; len]),
                Err(ParseError::CommandTooShort { len }),
                "{len} octets"
            );
        }
    }

    #[test]
    fn a_length_field_that_stops_after_its_marker_is_named_for_what_it_is() {
        // The `00` marker promises two more octets. Reporting this as "a
        // command needs 4 header octets, got 6" would name neither the fault
        // nor the remedy.
        let truncated = [0x00, 0xA4, 0x00, 0x00, 0x00, 0x05];
        assert_eq!(
            Command::decode(&truncated),
            Err(ParseError::TruncatedLengthField { present: 2 })
        );
    }

    #[test]
    fn a_declared_length_the_bytes_do_not_cover_is_reported_with_both_counts() {
        // Says which number disagreed with which, because the usual cause is a
        // caller who assumed a length form the card did not use.
        let short = [0x00, 0xA4, 0x00, 0x00, 0x05, 0x01, 0x02];
        assert_eq!(
            Command::decode(&short),
            Err(ParseError::LengthMismatch {
                declared: 5,
                present: 2
            })
        );
        let long = [0x00, 0xA4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02];
        assert_eq!(
            Command::decode(&long),
            Err(ParseError::LengthMismatch {
                declared: 256,
                present: 2
            })
        );
    }

    #[test]
    fn octets_after_the_data_field_that_iso_places_nowhere_are_refused() {
        let bytes = [0x00, 0xA4, 0x00, 0x00, 0x01, 0xAA, 0x00, 0x10, 0x00, 0x00];
        assert_eq!(
            Command::decode(&bytes),
            Err(ParseError::TrailingBytes { len: 4 })
        );
    }

    #[test]
    fn an_extended_length_of_zero_is_not_a_command() {
        let bytes = [0x00, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA];
        assert_eq!(Command::decode(&bytes), Err(ParseError::ZeroExtendedLength));
    }

    // --- response codec ----------------------------------------------------

    #[test]
    fn a_response_splits_into_exactly_its_body_and_its_last_two_octets() {
        // Exhaustive over the shape rather than over the bytes: for any
        // response of two octets or more the status is the tail and the body
        // is everything in front of it, with nothing reinterpreted.
        for len in 2usize..=300 {
            let raw: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let parsed = Response::parse(&raw).unwrap();
            let status = parsed
                .status()
                .expect("two octets or more is a status word");
            assert_eq!(status.to_bytes(), [raw[len - 2], raw[len - 1]], "{len}");
            assert_eq!(parsed.body(), &raw[..len - 2], "{len}");
            assert!(parsed.is_complete());
            assert_eq!(parsed.procedure_byte(), None);
        }
    }

    #[test]
    fn a_one_octet_response_is_a_procedure_byte_and_never_a_status_word() {
        // swICC sizes a procedure-byte response at data.len() + 1 and writes a
        // single octet, so a parser that always took the last two octets as
        // SW1 SW2 would read a procedure byte followed by nothing as a status
        // word. \\[V], swICC src/apdu.c:swicc_apdu_res_deparse.
        for byte in 0u8..=u8::MAX {
            let parsed = Response::parse(&[byte]).unwrap();
            assert_eq!(parsed.procedure_byte(), Some(byte));
            assert_eq!(parsed.status(), None);
            assert_eq!(parsed.body(), &[] as &[u8]);
            assert!(!parsed.is_complete());
        }
    }

    #[test]
    fn an_empty_response_is_an_error_rather_than_a_fabricated_status() {
        // A card that says nothing has not answered. Inventing a status for it
        // would put a fabricated finding into a scan report.
        assert_eq!(
            Response::parse(&[]),
            Err(ParseError::ResponseTooShort { len: 0 })
        );
    }

    #[test]
    fn a_procedure_byte_is_read_against_the_instruction_it_answers() {
        // A positive acknowledgement is the instruction byte echoed back, so
        // the same octet means different things for different commands. Every
        // instruction against every octet, because that is the whole domain.
        for instruction in 0u8..=u8::MAX {
            for byte in 0u8..=u8::MAX {
                let parsed = Response::parse(&[byte]).unwrap();
                let action = parsed.procedure_action(instruction).unwrap();
                let expected = if byte == PROCEDURE_BYTE_NULL {
                    ProcedureAction::NextChunk
                } else if byte == instruction {
                    ProcedureAction::SendAll
                } else if byte == instruction ^ 0xFF {
                    ProcedureAction::SendOne
                } else {
                    ProcedureAction::Unrecognised(byte)
                };
                assert_eq!(action, expected, "INS {instruction:02X}, byte {byte:02X}");
            }
        }
    }

    #[test]
    fn a_complete_response_has_no_procedure_byte_action() {
        for instruction in 0u8..=u8::MAX {
            assert_eq!(
                Response::parse(&[0x90, 0x00])
                    .unwrap()
                    .procedure_action(instruction),
                None
            );
        }
    }

    // --- status words ------------------------------------------------------

    #[test]
    fn exactly_one_status_word_is_a_success() {
        // Exhausts all 65536 pairs: `90 00` is the sole success and no other
        // SW2 under SW1 0x90 may be mistaken for one.
        let successes: Vec<[u8; 2]> = all_status_words()
            .filter(|status| status.is_success())
            .map(StatusWord::to_bytes)
            .collect();
        assert_eq!(successes, vec![[0x90, 0x00]]);
    }

    #[test]
    fn a_status_word_round_trips_and_renders_as_two_uppercase_hex_digits() {
        for raw in 0u8..=u8::MAX {
            for status in [
                StatusWord::new(0x9F, raw),
                StatusWord::new(0x00, raw),
                StatusWord::new(raw, 0xFF),
            ] {
                assert_eq!(StatusWord::from_bytes(status.to_bytes()), status);
                let rendered = status.to_string();
                assert_eq!(rendered.len(), 4, "{rendered}");
                assert_eq!(rendered, rendered.to_uppercase());
            }
        }
    }

    #[test]
    fn the_3gpp_pending_spellings_are_never_a_failure_and_never_a_success() {
        // The fact the swSIM fixture proved by exchanging APDUs rather than by
        // reading a spec, and the one AGENTS.md section 2 records: swSIM
        // rewrites a completed command's `90 00` into `91 <length>` whenever
        // a proactive command is waiting, so a scanner that files `91 xx` as
        // an error reports every healthy card as broken. Asserted as a
        // property over the SW2 space, so a card whose pending command is a
        // different length still passes.
        for sw1 in 0x91u8..=0x93 {
            for sw2 in 0u8..=u8::MAX {
                let status = StatusWord::new(sw1, sw2);
                assert!(!status.is_success(), "{status}");
                assert!(!status.class().is_failure(), "{status}");
                assert!(status.class().is_normal_processing(), "{status}");
                assert!(status.is_normal_processing(), "{status}");
                assert_eq!(status.proactive_command_length(), Some(sw2), "{status}");
                assert!(
                    matches!(
                        status.outcome(),
                        Outcome::Pending {
                            pending: Pending::ProactiveCommand { length },
                        } if length == sw2
                    ),
                    "{status}"
                );
            }
        }
    }

    #[test]
    fn a_9f_status_is_undetermined_and_still_not_a_failure() {
        // 0x9F is ISO/IEC 7816-4 "normal processing, proactive command
        // available" and swSIM uses `9F <length>` for response data queued
        // behind GET RESPONSE. Either way it is not a refusal, and this crate
        // refuses to guess which of the two SW2 meanings applies.
        for sw2 in 0u8..=u8::MAX {
            let status = StatusWord::new(0x9F, sw2);
            assert!(!status.class().is_failure(), "{status}");
            assert!(status.class().is_normal_processing(), "{status}");
            assert!(status.is_normal_processing(), "{status}");
            assert!(!status.is_success(), "{status}");
            assert_eq!(
                status.outcome(),
                Outcome::Pending {
                    pending: Pending::Undetermined { sw2 },
                },
                "{status}"
            );
            assert_eq!(status.proactive_command_length(), None, "{status}");
            assert_eq!(status.response_data_length(), None, "{status}");
            assert_eq!(status.corrected_length(), None, "{status}");
        }
    }

    #[test]
    fn the_three_numbers_that_share_sw2_are_never_read_out_of_one_status() {
        // AGENTS.md section 2: `61 xx` is a response-data length, 9x xx may
        // be a proactive-command length and `6C xx` is a corrected length.
        // Three different numbers sharing a byte. So for all 65536 status
        // words at most one of the three accessors may answer, and the set that
        // answers must be exactly the SW1 values that define one.
        for status in all_status_words() {
            let answered = [
                status.response_data_length().is_some(),
                status.proactive_command_length().is_some(),
                status.corrected_length().is_some(),
            ]
            .iter()
            .filter(|has| **has)
            .count();
            let expected = match status.sw1() {
                0x61 | 0x91..=0x93 | 0x6C => 1,
                _ => 0,
            };
            assert_eq!(answered, expected, "{status}");
        }
    }

    #[test]
    fn a_response_data_length_is_a_count_and_a_corrected_length_is_an_octet() {
        // Both carry a byte out of the same position and mean different
        // things, so each is asserted against the whole SW2 space and against
        // the one spelling where the two would have disagreed.
        for sw2 in 0u8..=u8::MAX {
            let advertised = StatusWord::new(0x61, sw2)
                .response_data_length()
                .unwrap_or_else(|| panic!("61 {sw2:02X}"));
            let expected = if sw2 == 0 {
                Le::SHORT_MAX
            } else {
                u32::from(sw2)
            };
            assert_eq!(advertised, expected, "61 {sw2:02X}");
            assert!(
                (1..=Le::SHORT_MAX).contains(&advertised),
                "a follow-up must ask for at least one byte"
            );

            assert_eq!(
                StatusWord::new(0x6C, sw2).corrected_length(),
                Some(if sw2 == 0 {
                    CorrectedLength::Unusable
                } else {
                    CorrectedLength::Accepts(sw2)
                }),
                "6C {sw2:02X}"
            );
        }
    }

    #[test]
    fn an_outstanding_length_is_askable_unless_the_octet_is_zero() {
        // 61 xx resolves its zero to 256 because ISO/IEC 7816-4 clause 9.1.1
        // says so. The 9x family has no clause available to this project, so a
        // zero there stays a zero and the accessor hands back the octet the
        // card wrote. A session building a follow-up from one has to notice
        // that Le::for_byte_count refuses, rather than this crate quietly
        // substituting a number.
        for status in all_status_words() {
            if let Some(count) = status.response_data_length() {
                assert!(
                    Le::for_byte_count(count).is_some(),
                    "{status} advertises {count}"
                );
            }
            if let Some(octet) = status.proactive_command_length() {
                assert_eq!(
                    Le::for_byte_count(u32::from(octet)).is_none(),
                    octet == 0,
                    "{status} advertises {octet}"
                );
            }
        }
    }

    #[test]
    fn the_two_definitions_of_normal_processing_never_disagree() {
        // Two accessors on the same type answering the same question with
        // different answers is worse than either one being absent, because the
        // caller cannot tell which one it read.
        for status in all_status_words() {
            assert_eq!(
                status.is_normal_processing(),
                status.class().is_normal_processing(),
                "{status}"
            );
        }
    }

    #[test]
    fn the_success_class_is_exactly_the_one_success_status_word() {
        for status in all_status_words() {
            assert_eq!(
                status.class() == StatusClass::Success,
                status.is_success(),
                "{status}"
            );
        }
    }

    #[test]
    fn no_status_word_is_both_a_failure_and_a_normal_processing_one() {
        for status in all_status_words() {
            let class = status.class();
            assert!(
                !(class.is_failure() && class.is_normal_processing()),
                "{status} is both"
            );
        }
    }

    #[test]
    fn an_octet_nobody_defines_is_not_folded_into_a_neighbour() {
        // 0x95, 0x96, 0x97 and 0x99 sit inside the normal-processing range and
        // have no definition this project can cite, and 0x60 is the ISO/IEC
        // 7816-3 procedure byte, which a card sends as a one-octet response
        // rather than a status word. Classifying any of them would be a guess,
        // and the guess would report healthy cards as broken.
        for sw1 in [0x95u8, 0x96, 0x97, 0x99, 0x60] {
            for sw2 in 0u8..=u8::MAX {
                let status = StatusWord::new(sw1, sw2);
                assert_eq!(status.class(), StatusClass::Proprietary, "{status}");
                assert!(!status.class().is_failure(), "{status}");
            }
        }

        // The two GSM 11.11 values inside that range that are failures stay
        // failures: `94 xx` is swSIM's file-ID-not-found and `98 xx` is its
        // authentication-error-incorrect-MAC. \\[V], swSIM src/apduh.c.
        for sw1 in [0x94u8, 0x98] {
            for sw2 in 0u8..=u8::MAX {
                let status = StatusWord::new(sw1, sw2);
                assert_eq!(status.class(), StatusClass::Error, "{status}");
                assert!(status.class().is_failure(), "{status}");
                assert!(!status.is_normal_processing(), "{status}");
            }
        }
    }

    #[test]
    fn a_wrong_length_is_a_refusal_and_a_follow_up_at_the_same_time() {
        // The two views disagree on purpose, and which one answers depends on
        // the question asked: the card did refuse the Le, and the caller still
        // owes it another exchange. This crate never takes the second reading
        // as permission to re-send anything.
        for sw2 in 0u8..=u8::MAX {
            let status = StatusWord::new(0x6C, sw2);
            assert_eq!(
                status.outcome(),
                Outcome::WrongLength { corrected: sw2 },
                "{status}"
            );
            assert!(status.outcome().needs_follow_up(), "{status}");
            assert!(!status.outcome().is_success(), "{status}");
            assert_eq!(status.class(), StatusClass::Retriable, "{status}");
            assert!(status.class().is_failure(), "{status}");
            assert!(!status.class().is_normal_processing(), "{status}");
        }
    }

    #[test]
    fn a_follow_up_is_owed_exactly_when_something_is_still_outstanding() {
        for status in all_status_words() {
            let outcome = status.outcome();
            let outstanding = matches!(
                outcome,
                Outcome::MoreDataAvailable { .. }
                    | Outcome::Pending { .. }
                    | Outcome::WrongLength { .. }
            );
            assert_eq!(outcome.needs_follow_up(), outstanding, "{status}");
            assert_eq!(outcome.is_success(), status.is_success(), "{status}");
        }
    }

    #[test]
    fn a_pending_status_names_only_what_the_card_has_told_us() {
        // `Pending::None` exists so a status word that names nothing pending
        // is not given a variant; nothing invents one.
        for status in all_status_words() {
            let expected = match status.sw1() {
                0x91..=0x93 => Pending::ProactiveCommand {
                    length: status.sw2(),
                },
                0x9F => Pending::Undetermined { sw2: status.sw2() },
                _ => Pending::None,
            };
            assert_eq!(Pending::of(status), expected, "{status}");
            assert_eq!(
                Pending::of(status).is_pending(),
                expected != Pending::None,
                "{status}"
            );
        }
    }

    #[test]
    fn more_data_available_reports_a_count_rather_than_a_sw2_copy() {
        // `61 00` is 256 bytes waiting, so the enum carries the number. A
        // caller that pattern-matched the variant and used the field as a byte
        // count would otherwise ask for no bytes at all.
        for sw2 in 0u8..=u8::MAX {
            let expected = if sw2 == 0 {
                Le::SHORT_MAX
            } else {
                u32::from(sw2)
            };
            assert_eq!(
                StatusWord::new(0x61, sw2).outcome(),
                Outcome::MoreDataAvailable {
                    available: expected as u16,
                },
                "61 {sw2:02X}"
            );
        }
    }

    #[test]
    fn no_precise_diagnosis_is_distinguished_from_other_6f_statuses() {
        assert_eq!(
            StatusWord::new(0x6F, 0x00).outcome(),
            Outcome::NoPreciseDiagnosis
        );
        // `6F XX` with a non-zero XX is not "no precise diagnosis"; it must
        // stay visible as a distinct pair rather than being flattened.
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
        // `6A 82` is "file not found" and `6D 00` is "instruction not
        // supported"; the module above has to see the difference.
        for (sw1, sw2) in [(0x6A, 0x82), (0x6D, 0x00), (0x67, 0x00), (0x63, 0xC0)] {
            let outcome = StatusWord::new(sw1, sw2).outcome();
            assert_eq!(outcome, Outcome::Other { sw1, sw2 });
            assert!(!outcome.needs_follow_up());
            assert!(!outcome.is_success());
        }
    }

    // --- chaining ----------------------------------------------------------

    #[test]
    fn splitting_reproduces_the_data_field_exactly() {
        // The chunks are a partitioning and nothing more: put them back
        // together in order and the command data field is unchanged, no chunk
        // is empty, and each one is encodable on its own.
        let header = Header::new(0x00, 0xA4, 0x00, 0x00);
        for len in LENGTH_BOUNDARIES {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            for chunk in [1usize, 2, 17, 255] {
                let command = Command::case4(header, data.clone(), Le::Short(0));
                let parts = command.split(chunk).unwrap();
                assert!(!parts.is_empty(), "len {len}, chunk {chunk}");

                let rejoined: Vec<u8> =
                    parts.iter().flat_map(|part| part.data().to_vec()).collect();
                assert_eq!(rejoined, data, "len {len}, chunk {chunk}");
                assert!(
                    matches!(parts[0], CommandPart::Command(_)),
                    "the first part is always a real APDU"
                );
                for part in &parts {
                    assert!(!part.data().is_empty(), "len {len}, chunk {chunk}");
                    part.encode().expect("every part is encodable");
                }
                let expected_parts = if len <= chunk { 1 } else { len.div_ceil(chunk) };
                assert_eq!(parts.len(), expected_parts, "len {len}, chunk {chunk}");
            }
        }
    }

    #[test]
    fn a_command_that_already_fits_is_left_untouched() {
        let header = Header::new(0x00, 0xA4, 0x00, 0x00);
        for command in [Command::case1(header), Command::case2(header, Le::Short(0))] {
            for chunk in [1usize, 8, 255, 4096] {
                let parts = command.split(chunk).unwrap();
                assert_eq!(parts, vec![CommandPart::Command(command.clone())]);
            }
        }

        let command = Command::case3(header, vec![0x11u8; 10]);
        assert_eq!(
            command.split(10).unwrap(),
            vec![CommandPart::Command(command)]
        );
    }

    #[test]
    fn a_chunk_size_of_zero_cannot_make_progress() {
        let header = Header::new(0x00, 0xA4, 0x00, 0x00);
        assert_eq!(
            Command::case3(header, vec![0u8; 4]).split(0),
            Err(EncodeError::ZeroChunkSize)
        );
        // Checked before the early return, so a command with no data cannot
        // slip past a bound the caller got wrong.
        assert_eq!(
            Command::case1(header).split(0),
            Err(EncodeError::ZeroChunkSize)
        );
    }

    // --- follow-up construction --------------------------------------------

    #[test]
    fn the_class_byte_of_a_follow_up_is_the_callers_to_choose() {
        // swSIM dispatches INS 0xC0 only at CLA 0xA0 and does not route
        // CLA 0x00 INS 0xC0 at all; a card may dispatch it at either. So the
        // class byte is a parameter and never a constant chosen here.
        // \\[V], swSIM src/apduh.c.
        for class in 0u8..=u8::MAX {
            assert_eq!(
                Command::get_response(class, Le::Short(0x10))
                    .encode()
                    .unwrap(),
                vec![class, INS_GET_RESPONSE, 0x00, 0x00, 0x10]
            );
            assert_eq!(
                Command::fetch(class, Le::Short(0x80)).encode().unwrap(),
                vec![class, INS_FETCH, 0x00, 0x00, 0x80]
            );
        }
    }

    #[test]
    fn a_follow_up_never_carries_a_data_field_or_a_nonzero_p1_p2() {
        // ISO/IEC 7816-4 clause 7.2.4 defines no other P1/P2 for GET RESPONSE
        // and ETSI TS 102 221 clause 11.2.3 requires both zero for FETCH.
        for class in [CLA_GET_RESPONSE_GSM, CLA_GET_RESPONSE_ISO, CLA_FETCH_ETSI] {
            let get_response = Command::get_response(class, Le::Short(1)).encode().unwrap();
            assert_eq!(&get_response[..4], &[class, INS_GET_RESPONSE, 0x00, 0x00]);
            assert_eq!(get_response.len(), 5, "a GET RESPONSE is a case 2 APDU");

            let fetch = Command::fetch(class, Le::Short(1)).encode().unwrap();
            assert_eq!(&fetch[..4], &[class, INS_FETCH, 0x00, 0x00]);
            assert_eq!(fetch.len(), 5, "a FETCH is a case 2 APDU");
        }
    }

    #[test]
    fn the_two_get_response_class_bytes_are_distinct_and_both_named() {
        // CLA 0xA0 is the GSM proprietary class swSIM routes GET RESPONSE
        // from; CLA 0x00 is the ISO interindustry class a card may use
        // instead. Both are constants so the choice is visible at the call
        // site rather than hidden inside a helper.
        assert_eq!(CLA_GET_RESPONSE_GSM, 0xA0);
        assert_eq!(CLA_GET_RESPONSE_ISO, 0x00);
        assert_ne!(CLA_GET_RESPONSE_GSM, CLA_GET_RESPONSE_ISO);
        assert_eq!(CLA_FETCH_ETSI, 0x80);
        assert_ne!(CLA_FETCH_ETSI, CLA_GET_RESPONSE_GSM);
        assert_ne!(CLA_FETCH_ETSI, CLA_GET_RESPONSE_ISO);
    }
}
