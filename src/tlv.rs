//! BER-TLV tag, length and value atoms.
//!
//! **Owns.** The structural half of BER-TLV: a one-octet [`Tag`], a BER
//! [`Length`] in either its short or long form, and the three together as a
//! borrowed [`Tlv`] that points into the bytes it was decoded from.
//!
//! **Does not own.** The meaning of any tag. Tag `82` is a file length inside
//! an EF and a length inside a BPP payload and something else again inside a
//! GlobalPlatform proprietary template; that dictionary is card domain
//! knowledge and lives with whoever is decoding the response, starting with
//! [`crate::fs`]. This module only answers "is there a length here, and how
//! long is the value".
//!
//! **Does not own a stream decoder.** [`Tlv::decode`] reads exactly one atom
//! and reports how many octets it took. Walking a whole file body, handling
//! trailing data, and mapping tags to fields is issue #11.
//!
//! **Why this is not built on `der`.** AGENTS.md 4.2 records that `der` 0.8.2
//! is strict DER and rejects the non-minimal BER lengths that real SIM and
//! SGP.22 BPP payloads carry. That is a property of DER, not a defect in the
//! data: the same length `05` written as `81 05` is the same five bytes. So
//! [`Length::decode`] accepts the long form whatever value it encodes, and
//! [`Length::encode`] always writes the short form back. `iso7816-tlv` and
//! `flexiber` are the crates AGENTS.md 4.2 nominates; neither is used yet,
//! because issue #11 is what actually needs a whole-stream decoder and this is
//! only the atom.
//!
//! **What is deliberately absent.** [`Tag`] does not decode a tag class or tag
//! number. The class bits mean one thing under BER's reading of the identifier
//! octet and another under ISO/IEC 7816-4's own table, this repository has not
//! verified which applies to a given SIM payload, and AGENTS.md section 2 says
//! not to build on an unverified fact. Add `class()` and `number()` when
//! someone has the table in front of them, not before. Real SIM tooling
//! matches tags by literal octet anyway.

/// This module's name, as recorded in [`crate::MODULES`].
///
/// Referenced by value rather than re-spelt as a literal so that the module
/// table cannot name a module that does not exist.
pub const NAME: &str = "tlv";

use std::fmt;

/// One octet of a BER identifier.
///
/// Opened up as far as this crate can justify. Bit 6 of the identifier octet is
/// the constructed bit and it means the same thing under every TLV convention,
/// so [`Tag::is_constructed`] is safe. The class bits and the tag number are
/// not exposed; see the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Tag(u8);

impl Tag {
    /// Wraps a single identifier octet.
    ///
    /// Every octet is accepted. A value whose low five bits are all set starts
    /// a multi-octet tag under BER, but deciding that needs the class-bit
    /// question the module documentation leaves open, so this module does not
    /// guess and does not reject.
    pub const fn new(octet: u8) -> Self {
        Self(octet)
    }

    /// The identifier octet as it appears on the wire.
    pub const fn octet(self) -> u8 {
        self.0
    }

    /// Whether this tag introduces a constructed value that contains further
    /// atoms.
    ///
    /// Bit 6 of the identifier octet. The FCP templates a SELECT returns
    /// (`6F`, `62`, `73`) are constructed; the leaves inside them (`84`, `82`)
    /// are not.
    pub const fn is_constructed(self) -> bool {
        self.0 & 0b0010_0000 != 0
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X}", self.0)
    }
}

/// Which BER length form a [`Length`] was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Form {
    /// A single octet, high bit clear: the value is that octet, 0 through 127.
    Short,
    /// One count octet plus that many value octets.
    Long {
        /// How many octets followed the count octet.
        octets: u8,
    },
}

/// A BER length value together with the form it was encoded in.
///
/// The form is kept because it is part of the wire bytes and callers re-
/// encoding a decoded atom need to know whether a decoder had to be tolerant.
/// [`Length::value`] is deliberately tolerant of encoding: `05`, `81 05` and
/// `82 00 05` all mean five. [`Length::encode`] is not, and always emits the
/// short form, so a non-minimal input normalizes on the way out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Length {
    value: u16,
    form: Form,
}

impl Length {
    /// Builds a length from a value, choosing the minimal form.
    ///
    /// The recorded form has to match what [`Length::encode`] will write, or
    /// `encoded_len` would disagree with the bytes it describes: a value below
    /// 256 needs one long-form octet, not two.
    pub const fn new(value: u16) -> Self {
        let form = if value < 0x80 {
            Form::Short
        } else if value <= 0xFF {
            Form::Long { octets: 1 }
        } else {
            Form::Long { octets: 2 }
        };
        Self { value, form }
    }

    /// The number of value octets this length describes.
    pub const fn value(self) -> u16 {
        self.value
    }

    /// Whether this length was encoded in the single-octet short form.
    pub const fn is_short_form(self) -> bool {
        matches!(self.form, Form::Short)
    }

    /// How many octets this length occupies in an encoding.
    ///
    /// One for the short form, one plus the count octet for the long form.
    pub const fn encoded_len(self) -> usize {
        match self.form {
            Form::Short => 1,
            Form::Long { octets } => 1 + octets as usize,
        }
    }

    /// Reads a BER length, returning it and how many octets it occupied.
    ///
    /// Both BER forms are accepted, including encodings that are not minimal.
    /// See the module documentation for why that is load-bearing rather than
    /// merely lax.
    pub fn decode(input: &[u8]) -> Result<(Self, usize), Error> {
        let Some(&first) = input.first() else {
            return Err(Error::UnexpectedEof {
                needed: 1,
                available: 0,
            });
        };

        // High bit clear: the octet is the length.
        if first & 0x80 == 0 {
            return Ok((
                Self {
                    value: u16::from(first),
                    form: Form::Short,
                },
                1,
            ));
        }

        let count = (first & 0x7F) as usize;
        if count == 0 {
            return Err(Error::IndefiniteLength);
        }
        if count > MAX_LENGTH_OCTETS {
            return Err(Error::LengthTooLarge {
                octets: count,
                max: MAX_LENGTH_OCTETS,
            });
        }

        let available = input.len() - 1;
        if available < count {
            return Err(Error::UnexpectedEof {
                needed: count,
                available,
            });
        }

        let mut value: u16 = 0;
        for &octet in &input[1..=count] {
            value = (value << 8) | u16::from(octet);
        }
        Ok((
            Self {
                value,
                form: Form::Long {
                    octets: count as u8,
                },
            },
            1 + count,
        ))
    }

    /// Writes this length in its minimal BER form.
    ///
    /// A length that was decoded from a longer-than-necessary encoding comes
    /// back shorter than it went in. That is the point: the decoder is
    /// permissive and the encoder is canonical.
    pub fn encode(self) -> Vec<u8> {
        if self.value < 0x80 {
            vec![self.value as u8]
        } else if self.value <= 0xFF {
            vec![0x81, self.value as u8]
        } else {
            vec![0x82, (self.value >> 8) as u8, self.value as u8]
        }
    }
}

impl fmt::Display for Length {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// The widest length this module will decode, in octets.
///
/// Two octets is 65535, which is also the widest data field an extended-length
/// APDU carries. A longer length field would describe more bytes than can
/// travel in one ISO 7816-4 command or response, so accepting it would mean
/// this module believed something the transport cannot deliver.
const MAX_LENGTH_OCTETS: usize = 2;

/// One BER-TLV atom: a tag, a length, and that many octets of value.
///
/// Borrowed rather than owned. An EF body is up to 65535 octets and a scan
/// decodes dozens of them; copying every value out of the buffer would double
/// the allocation for no benefit, since the caller wants to look at the bytes
/// where they already are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tlv<'a> {
    tag: Tag,
    length: Length,
    value: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Reads the first atom in `input`.
    ///
    /// Returns the atom and how many octets it occupied, which is what lets a
    /// caller walk a body without this module having to guess whether the
    /// buffer holds one atom or many. Trailing octets are not an error here;
    /// the caller decides what to do with them.
    pub fn decode(input: &'a [u8]) -> Result<(Self, usize), Error> {
        let Some((&tag_octet, after_tag)) = input.split_first() else {
            return Err(Error::UnexpectedEof {
                needed: 1,
                available: 0,
            });
        };

        let tag = Tag::new(tag_octet);
        let (length, length_octets) = Length::decode(after_tag)?;

        let start = 1 + length_octets;
        let available = input.len() - start;
        let wanted = usize::from(length.value());
        if available < wanted {
            return Err(Error::UnexpectedEof {
                needed: wanted,
                available,
            });
        }

        Ok((
            Self {
                tag,
                length,
                value: &input[start..start + wanted],
            },
            start + wanted,
        ))
    }

    /// The atom's tag.
    pub const fn tag(&self) -> Tag {
        self.tag
    }

    /// The atom's length, including the form it arrived in.
    pub const fn length(&self) -> Length {
        self.length
    }

    /// The atom's value octets.
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// Whether the atom's tag introduces a constructed value.
    pub const fn is_constructed(&self) -> bool {
        self.tag.is_constructed()
    }

    /// How many octets this atom's length describes.
    pub const fn len(&self) -> usize {
        self.value.len()
    }

    /// Whether the atom's value is empty.
    ///
    /// A zero-length atom is legal and common - an absent optional field is
    /// often encoded as `80 00` rather than omitted - so this is not the same
    /// as "the atom is missing".
    pub const fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// How many octets this atom occupies in its encoding.
    pub const fn encoded_len(&self) -> usize {
        1 + self.length.encoded_len() + self.value.len()
    }

    /// Writes this atom in canonical BER: a one-octet tag and a minimal length.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.push(self.tag.octet());
        out.extend_from_slice(&self.length.encode());
        out.extend_from_slice(self.value);
        out
    }
}

/// Everything that can go wrong while decoding BER-TLV.
///
/// `#[non_exhaustive]` because issue #11 adds stream-level failures, and
/// downstream matches should not have to be rewritten when it does.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The buffer ran out before the field being read did.
    #[error("BER-TLV field needs {needed} octets but only {available} remain")]
    UnexpectedEof {
        /// Octets the field still wanted.
        needed: usize,
        /// Octets actually left in the buffer.
        available: usize,
    },

    /// The length field was `80`.
    #[error("indefinite BER length (0x80) is not used in ISO 7816-4 file data")]
    IndefiniteLength,

    /// The length field declared more octets than one APDU data field can hold.
    #[error("a BER-TLV length of {octets} octets exceeds the {max} an APDU data field can carry")]
    LengthTooLarge {
        /// Octets the length field declared.
        octets: usize,
        /// The widest length this crate accepts.
        max: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_short_form_covers_zero_through_127() {
        for value in 0u16..=127 {
            let octet = value as u8;
            let (length, consumed) = Length::decode(&[octet]).unwrap();
            assert_eq!(length.value(), value, "{octet:02X} must decode to {value}");
            assert_eq!(consumed, 1);
            assert!(length.is_short_form());
        }
    }

    #[test]
    fn the_long_form_carries_lengths_the_short_form_cannot() {
        let (length, consumed) = Length::decode(&[0x81, 0x80]).unwrap();
        assert_eq!(length.value(), 128);
        assert_eq!(consumed, 2);
        assert!(!length.is_short_form());

        let (length, consumed) = Length::decode(&[0x82, 0x01, 0x00]).unwrap();
        assert_eq!(length.value(), 256);
        assert_eq!(consumed, 3);

        let (length, _) = Length::decode(&[0x82, 0xFF, 0xFF]).unwrap();
        assert_eq!(length.value(), u16::MAX);
    }

    #[test]
    fn non_minimal_lengths_are_accepted() {
        // This is AGENTS.md 4.2 in code. A strict DER decoder rejects 81 05
        // because the short form was available; real SIM and SGP.22 payloads
        // carry exactly that, so a decoder that rejected it would reject real
        // cards. The value is the same five bytes either way.
        for (encoded, value, consumed) in [
            (&[0x81, 0x05][..], 5u16, 2usize),
            (&[0x82, 0x00, 0x05][..], 5, 3),
            (&[0x82, 0x00, 0x80][..], 128, 3),
            (&[0x81, 0x00][..], 0, 2),
        ] {
            let (length, read) = Length::decode(encoded).unwrap();
            assert_eq!(length.value(), value, "{encoded:02X?}");
            assert_eq!(read, consumed, "{encoded:02X?}");
            assert_eq!(length.encoded_len(), consumed);
        }
    }

    #[test]
    fn a_non_minimal_length_re_encodes_minimally() {
        // The decoder is permissive and the encoder is canonical, so a decoded
        // atom normalizes on the way back out.
        let (length, _) = Length::decode(&[0x82, 0x00, 0x05]).unwrap();
        assert_eq!(length.encode(), vec![0x05]);

        let (length, _) = Length::decode(&[0x82, 0x00, 0x80]).unwrap();
        assert_eq!(length.encode(), vec![0x81, 0x80]);

        // 256 genuinely does not fit in one long-form octet, so three octets is
        // already minimal and must be left alone.
        let (length, _) = Length::decode(&[0x82, 0x01, 0x00]).unwrap();
        assert_eq!(length.encode(), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn encoding_picks_the_shortest_form_that_fits() {
        assert_eq!(Length::new(0).encode(), vec![0x00]);
        assert_eq!(Length::new(127).encode(), vec![0x7F]);
        assert_eq!(Length::new(128).encode(), vec![0x81, 0x80]);
        assert_eq!(Length::new(255).encode(), vec![0x81, 0xFF]);
        assert_eq!(Length::new(256).encode(), vec![0x82, 0x01, 0x00]);

        // Every length this module can encode must decode back to itself, and
        // encoded_len must agree with the bytes encode() actually writes.
        for value in (0u16..=u16::MAX).step_by(97) {
            let length = Length::new(value);
            let encoded = length.encode();
            let (decoded, consumed) = Length::decode(&encoded).unwrap();
            assert_eq!(decoded.value(), value);
            assert_eq!(consumed, encoded.len());
            assert_eq!(length.encoded_len(), encoded.len());
        }
    }

    #[test]
    fn indefinite_length_is_rejected() {
        assert_eq!(Length::decode(&[0x80]), Err(Error::IndefiniteLength));
    }

    #[test]
    fn a_length_wider_than_an_apdu_data_field_is_rejected() {
        assert_eq!(
            Length::decode(&[0x83, 0x01, 0x00, 0x00]),
            Err(Error::LengthTooLarge {
                octets: 3,
                max: MAX_LENGTH_OCTETS
            })
        );
        // The largest count octet, which would claim a 127-octet length.
        assert!(matches!(
            Length::decode(&[0xFF; 4]),
            Err(Error::LengthTooLarge { .. })
        ));
    }

    #[test]
    fn a_truncated_field_reports_what_was_missing() {
        assert_eq!(
            Length::decode(&[]),
            Err(Error::UnexpectedEof {
                needed: 1,
                available: 0
            })
        );
        assert_eq!(
            Length::decode(&[0x82, 0x01]),
            Err(Error::UnexpectedEof {
                needed: 2,
                available: 1
            })
        );
        // Tag present, length says ten bytes, only three are there.
        assert_eq!(
            Tlv::decode(&[0x84, 0x0A, 0x2F, 0xE2, 0x00]),
            Err(Error::UnexpectedEof {
                needed: 10,
                available: 3
            })
        );
    }

    #[test]
    fn an_atom_borrows_its_value_out_of_the_buffer() {
        // A SELECT response fragment: a FileDescriptor template holding a
        // two-octet file identifier.
        let body = [0x6F, 0x04, 0x84, 0x02, 0x2F, 0xE2];
        let (atom, consumed) = Tlv::decode(&body).unwrap();

        assert_eq!(consumed, body.len());
        assert_eq!(atom.tag(), Tag::new(0x6F));
        assert_eq!(atom.tag().to_string(), "6F");
        assert_eq!(atom.length().value(), 4);
        assert_eq!(atom.value(), &[0x84, 0x02, 0x2F, 0xE2]);
        assert_eq!(atom.len(), 4);
        assert!(!atom.is_empty());
        assert_eq!(atom.encoded_len(), body.len());
    }

    #[test]
    fn the_constructed_bit_is_bit_six() {
        for octet in u8::MIN..=u8::MAX {
            assert_eq!(
                Tag::new(octet).is_constructed(),
                octet & 0b0010_0000 != 0,
                "{octet:02X}"
            );
        }
        // The two shapes that matter: FCP templates are constructed, their
        // leaves are not.
        assert!(Tag::new(0x6F).is_constructed());
        assert!(Tag::new(0x73).is_constructed());
        assert!(!Tag::new(0x84).is_constructed());
        assert!(!Tag::new(0x82).is_constructed());
    }

    #[test]
    fn a_zero_length_atom_is_legal_and_distinct_from_no_atom() {
        let body = [0x80, 0x00];
        let (atom, consumed) = Tlv::decode(&body).unwrap();
        assert_eq!(consumed, 2);
        assert!(atom.is_empty());
        assert_eq!(atom.len(), 0);
        assert_eq!(atom.value(), &[] as &[u8]);
    }

    #[test]
    fn encoding_an_atom_rewrites_a_non_minimal_length() {
        // 84 81 02 2F E2: the same two-octet file identifier, written with a
        // long-form length for two. Decoding then encoding normalizes it.
        let body = [0x84, 0x81, 0x02, 0x2F, 0xE2];
        let (atom, consumed) = Tlv::decode(&body).unwrap();
        assert_eq!(consumed, body.len());
        assert_eq!(atom.value(), &[0x2F, 0xE2]);
        assert_eq!(atom.encode(), vec![0x84, 0x02, 0x2F, 0xE2]);
    }
}
