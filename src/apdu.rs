//! The typed ISO/IEC 7816-4 command header and the two-byte status word.
//!
//! **Owns.** The four octets every command starts with (CLA, INS, P1, P2), the
//! two octets every response ends with (SW1, SW2), and the classification that
//! says whether a caller may treat an exchange as finished.
//!
//! **Does not own.** The bytes around the header. Encoding a header into a
//! full APDU, splitting an extended-length command into several exchanges, and
//! reading SW1/SW2 back out of a response body are all issue #5. This module
//! holds the typed values those operations produce, not the operations.
//!
//! **Does not own the transport.** There is no `pcsc` dependency here and no
//! session, reader or reader list. A [`Header`] is four integers;
//! [`crate::transport`] moves bytes and cannot see this module.
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
    pub const fn is_success(self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
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
/// This is the only classification in the crate, and it answers one question:
/// can the caller move on, or does it owe the card another exchange? Everything
/// richer - which instruction byte was refused, what a `6A 82` means for the
/// file the caller was trying to open - belongs to the rule layer, not here.
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
            (0x6C, available) => Self::WrongLength { available },
            (0x6F, 0x00) => Self::NoPreciseDiagnosis,
            (sw1, sw2) => Self::Other { sw1, sw2 },
        }
    }

    /// Whether the caller owes the card another exchange before moving on.
    ///
    /// True only for the two "there is more" statuses. `61 xx` and `6C xx` both
    /// carry a byte count and both need a follow-up; nothing else in this enum
    /// does.
    pub const fn needs_follow_up(self) -> bool {
        matches!(
            self,
            Self::MoreDataAvailable { .. } | Self::WrongLength { .. }
        )
    }

    /// Whether the card completed the command successfully.
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

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
