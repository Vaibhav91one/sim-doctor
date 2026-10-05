//! Strict DER: the encoding rules that reject what BER accepts.
//!
//! **Owns.** A decoder for the subset of BER-TLV that DER permits: definite
//! lengths, written in the shortest form that can hold the value. That is all
//! it owns, and it owns it as a **separate type in a separate module**, which
//! is the whole point of the module existing.
//!
//! # Why this is not a flag on [`crate::tlv`]
//!
//! AGENTS.md 4.2 records the trap this crate was built to make impossible to
//! fall into again: `der` 0.8.2 is strict DER, it rejects the non-minimal BER
//! lengths that real SIM and SGP.22 payloads carry, and it is therefore not a
//! drop-in BPP parser. `der` stays declared for certificates. What that
//! leaves is a second decoding rule inside this crate, and the shape of it
//! is the decision:
//!
//! - [`Der`] is not [`crate::tlv::Tlv`], there is no `From` in either
//!   direction, and nothing in this module imports `crate::tlv`. A strict-DER
//!   caller cannot reach the BER path because there is no edge to it. A
//!   `strict: bool` parameter would have made that call a runtime branch on
//!   a flag, which is exactly how a BER parser ends up being used on a
//!   certificate,
//! - the errors are a separate enum, so a caller that only wants
//!   `NonMinimalLength` is forced to say which rule it applied,
//! - the module is declared at layer 0 with no dependencies in [`crate::MODULES`],
//!
//! The practical shape of the difference, which the tests assert from both
//! sides:
//!
//! ```text
//! 30 81 03 02 01 05      this module rejects it, tlv accepts it
//! ```
//!
//! Both are the same five bytes of INTEGER. The short form was available, so
//! the long form is not DER, and a certificate that arrives that way has
//! something to say about whoever produced it.
//!
//! # The separation is checked by the compiler
//!
//! The claim above - that a strict-DER caller cannot reach the BER path -
//! is not left as prose. These are `compile_fail` doctests, so `cargo test`
//! fails if any of them ever starts compiling:
//!
//! ```compile_fail
//! use sim_doctor::{der, tlv};
//!
//! // A strict value is not a BER atom, and there is no conversion between
//! // them in either direction.
//! let strict = der::Der::decode(&[0x30, 0x00]).unwrap();
//! let (atom, _) = tlv::Tlv::decode(&strict.encode()).unwrap();
//! let _: tlv::Tlv<'_> = atom.into();
//! ```
//!
//! ```compile_fail
//! use sim_doctor::{der, tlv};
//!
//! // And the other direction fails too.
//! let (atom, _) = tlv::Tlv::decode(&[0x30, 0x00]).unwrap();
//! let _: der::Der<'_> = atom.into();
//! ```
//!
//! ```compile_fail
//! use sim_doctor::tlv::Tlv;
//!
//! // There is no strictness flag. A caller cannot ask the BER layer to be
//! // strict, because the BER layer has no such mode to ask for.
//! let (atom, _) = Tlv::decode_strict(&[0x30, 0x03, 0x02, 0x01, 0x05]).unwrap();
//! ```
//!
//! # What this does not own
//!
//! It does not own the tag classes or the tag number, for the same reason
//! [`crate::tlv`] does not: the class bits mean one thing under BER's reading
//! of the identifier octet and another under ISO/IEC 7816-4's own table, and
//! this repository has not verified which applies to a given payload. It
//! reads bit 6, the constructed bit, which means the same thing under every
//! convention.
//!
//! It also does not own X.509. The octets a [`Der`] hands back are the input
//! a caller feeds to the `der` crate's own `Decode` implementations once this
//! type has established that the encoding rules were obeyed; this crate does
//! not wrap that crate's API, because doing so on an API this repository has
//! not read would be building on an unverified fact.

/// This module's name, as recorded in [`crate::MODULES`].
///
/// Referenced by value rather than re-spelt as a literal so that the module
/// table cannot name a module that does not exist.
pub const NAME: &str = "der";

use std::fmt;

/// The widest length this module will decode, in octets.
///
/// Two, which is 65535, the widest data field an extended-length APDU
/// carries and also the widest a DER value this crate will be handed. Same
/// ceiling, and the same reason, as [`crate::tlv`].
const MAX_LENGTH_OCTETS: usize = 2;

/// The widest length octet that can still be minimal.
///
/// `7F` is the last short-form length. Anything below that fits in one
/// octet, so anything at or above it must use the long form.
const MAX_SHORT_FORM: u8 = 0x7F;

/// One strictly encoded DER value: a tag, a length, and that many octets.
///
/// Deliberately not [`crate::tlv::Tlv`] and not convertible into one. See the
/// module documentation; the short form of the argument is that a decoder
/// which can be talked into the lax rule is a decoder that will be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Der<'a> {
    tag: u8,
    header: usize,
    value: &'a [u8],
}

impl<'a> Der<'a> {
    /// Decodes exactly one DER value, and requires the input to be only that.
    ///
    /// Strict about the envelope as well as the encoding: a caller who has
    /// been handed a buffer and wants to know whether the buffer is one DER
    /// value gets that answered rather than being handed the value and the
    /// leftover.
    ///
    /// # Errors
    ///
    /// Any [`Error`], including [`Error::TrailingData`].
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let start = 0;
        let (value, consumed) = Self::decode_first(input)?;
        let remaining = input.len().saturating_sub(consumed);
        if remaining != 0 {
            return Err(Error::TrailingData {
                at: start + consumed,
                remaining,
            });
        }
        Ok(value)
    }

    /// Decodes the first DER value in `input`, reporting how much it took.
    ///
    /// The walking half, for a body that holds several values. Trailing
    /// octets are left to the caller, exactly as in the BER layer.
    ///
    /// # Errors
    ///
    /// Any [`Error`] except [`Error::TrailingData`].
    pub fn decode_first(input: &'a [u8]) -> Result<(Self, usize), Error> {
        let Some((&tag, after_tag)) = input.split_first() else {
            return Err(Error::UnexpectedEof {
                needed: 1,
                available: 0,
            });
        };

        let (length, length_octets) = Self::decode_length(after_tag)?;
        let header = 1 + length_octets;
        let available = input.len() - header;
        if available < length {
            return Err(Error::UnexpectedEof {
                needed: length,
                available,
            });
        }

        Ok((
            Self {
                tag,
                header,
                value: &input[header..header + length],
            },
            header + length,
        ))
    }

    /// Reads a DER length, which must be definite and written minimally.
    ///
    /// This is the rule that separates the two decoders. `05` is fine.
    /// `81 05` is the same five bytes and is **not** DER, because one octet
    /// was available, and a certificate encoded that way is a finding.
    ///
    /// Returns the length and how many octets the length field occupied.
    ///
    /// # Errors
    ///
    /// [`Error::IndefiniteLength`] for `80`, [`Error::NonMinimalLength`] for a
    /// long form that the short form could have carried, and
    /// [`Error::LengthTooLarge`] for a length field wider than one APDU data
    /// field.
    fn decode_length(input: &[u8]) -> Result<(usize, usize), Error> {
        let Some((&first, after_first)) = input.split_first() else {
            return Err(Error::UnexpectedEof {
                needed: 1,
                available: 0,
            });
        };

        // High bit clear: the short form, and the only form for 0..=0x7F.
        if first & 0x80 == 0 {
            return Ok((usize::from(first), 1));
        }

        let count = usize::from(first & 0x7F);
        if count == 0 {
            return Err(Error::IndefiniteLength);
        }
        if count > MAX_LENGTH_OCTETS {
            return Err(Error::LengthTooLarge {
                octets: count,
                max: MAX_LENGTH_OCTETS,
            });
        }
        if after_first.len() < count {
            return Err(Error::UnexpectedEof {
                needed: count,
                available: after_first.len(),
            });
        }

        let mut value: u16 = 0;
        for &octet in &after_first[..count] {
            value = (value << 8) | u16::from(octet);
        }

        // Minimality. A long form is only minimal when the octet above the
        // last non-zero one is zero.
        //
        // The `_` arm returns rather than asserting: `count` was already
        // checked against MAX_LENGTH_OCTETS above, so it is unreachable today,
        // and a parser that panics on an unreachable arm is a parser that will
        // panic the day someone widens the ceiling.
        let minimal = match count {
            1 => after_first[0] > MAX_SHORT_FORM,
            2 => after_first[0] != 0,
            other => {
                return Err(Error::LengthTooLarge {
                    octets: other,
                    max: MAX_LENGTH_OCTETS,
                });
            }
        };
        if !minimal {
            return Err(Error::NonMinimalLength {
                declared: value,
                encoded_octets: count as u8,
            });
        }

        Ok((usize::from(value), 1 + count))
    }

    /// The identifier octet.
    pub const fn tag(&self) -> u8 {
        self.tag
    }

    /// Whether the value contains further DER values.
    ///
    /// Bit 6 of the identifier octet, which means the same thing under every
    /// TLV convention. The tag number and class are not decoded; see the
    /// module documentation.
    pub const fn is_constructed(&self) -> bool {
        self.tag & 0b0010_0000 != 0
    }

    /// The value octets.
    pub fn value(&self) -> &'a [u8] {
        self.value
    }

    /// How many value octets this value holds.
    pub const fn len(&self) -> usize {
        self.value.len()
    }

    /// Whether the value is empty.
    pub const fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// How many octets the tag and length fields together occupy.
    pub const fn header_len(&self) -> usize {
        self.header
    }

    /// How many octets this value occupies in its encoding.
    pub const fn encoded_len(&self) -> usize {
        self.header + self.value.len()
    }

    /// Re-emits this value.
    ///
    /// Round-trips byte for byte. A [`Der`] was decoded from minimal lengths,
    /// so writing it back minimally is writing back exactly what came in, and
    /// the test asserts that rather than asserting it in prose.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.push(self.tag);
        let length = self.value.len();
        if length <= usize::from(MAX_SHORT_FORM) {
            out.push(length as u8);
        } else if length <= 0xFF {
            out.push(0x81);
            out.push(length as u8);
        } else {
            out.push(0x82);
            out.push((length >> 8) as u8);
            out.push(length as u8);
        }
        out.extend_from_slice(self.value);
        out
    }

    /// Decodes every DER value inside a constructed value.
    ///
    /// # Errors
    ///
    /// [`Error::NotConstructed`] if this value is primitive, and any decoding
    /// error otherwise. Every child is checked by the same rules, so a
    /// non-minimal length anywhere in the tree is caught rather than skipped.
    pub fn children(&self) -> Result<Vec<Self>, Error> {
        if !self.is_constructed() {
            return Err(Error::NotConstructed { tag: self.tag });
        }
        Self::walk(self.value)
    }

    /// Decodes every DER value in `input`, which must hold nothing else.
    ///
    /// # Errors
    ///
    /// Any [`Error`], including [`Error::TrailingData`] if the body ends
    /// mid-value.
    pub fn walk(input: &'a [u8]) -> Result<Vec<Self>, Error> {
        let mut values = Vec::new();
        let mut offset = 0;
        while offset < input.len() {
            let (value, consumed) = Self::decode_first(&input[offset..])?;
            values.push(value);
            offset += consumed;
        }
        Ok(values)
    }
}

impl fmt::Display for Der<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X} len {} constructed={}",
            self.tag,
            self.value.len(),
            self.is_constructed()
        )
    }
}

/// Everything that can go wrong while decoding DER.
///
/// A separate enum from [`crate::tlv::Error`] on purpose: a caller that
/// matches on `NonMinimalLength` has thereby said it applied the DER rule, and
/// a shared error type would let that fact stay unstated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The buffer ran out before the value being read did.
    #[error("DER value needs {needed} octets but only {available} remain")]
    UnexpectedEof {
        /// Octets the value still wanted.
        needed: usize,
        /// Octets actually left in the buffer.
        available: usize,
    },

    /// The length field was `80`.
    ///
    /// DER has no indefinite form. The BER decoder in [`crate::tlv`] rejects
    /// it too, for a different reason - ISO 7816-4 file data does not use it -
    /// and the two errors staying separate is the point.
    #[error("indefinite length (0x80) is not permitted in DER")]
    IndefiniteLength,

    /// A length was written in a longer form than it needed.
    ///
    /// The acceptance criterion for this issue, from the other direction: this
    /// is the error a strict decoder raises on exactly the bytes the BER
    /// decoder accepts.
    #[error("length {declared} is written in {encoded_octets} octets but DER requires the shortest form")]
    NonMinimalLength {
        /// The length the field encoded.
        declared: u16,
        /// How many octets the length field used.
        encoded_octets: u8,
    },

    /// The length field declared more octets than one APDU data field holds.
    #[error("a DER length of {octets} octets exceeds the {max} this crate will read")]
    LengthTooLarge {
        /// Octets the length field declared.
        octets: usize,
        /// The widest length this crate accepts.
        max: usize,
    },

    /// Octets remained where exactly one value was required.
    #[error("{remaining} octets of trailing data at offset {at}")]
    TrailingData {
        /// Where the unconsumed octets start.
        at: usize,
        /// How many octets were left over.
        remaining: usize,
    },

    /// A primitive value was asked for its children.
    #[error("the primitive value {tag:02X} contains no further values")]
    NotConstructed {
        /// The identifier octet of the value that was asked.
        tag: u8,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SEQUENCE { INTEGER 5 }`, DER.
    const SEQUENCE: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x05];

    #[test]
    fn der_accepts_what_it_should() {
        let value = Der::decode(&SEQUENCE).unwrap();
        assert_eq!(value.tag(), 0x30);
        assert!(value.is_constructed());
        assert_eq!(value.len(), 3);
        assert_eq!(value.header_len(), 2);
        assert_eq!(value.encoded_len(), SEQUENCE.len());
        assert_eq!(value.encode(), SEQUENCE.to_vec());

        let children = value.children().unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].tag(), 0x02);
        assert!(!children[0].is_constructed());
        assert_eq!(children[0].value(), &[0x05]);
    }

    #[test]
    fn a_non_minimal_length_is_rejected_where_the_ber_decoder_accepts_it() {
        // The acceptance criterion, from both sides. Same five bytes.
        let non_minimal = [0x30u8, 0x81, 0x03, 0x02, 0x01, 0x05];

        assert_eq!(
            Der::decode(&non_minimal),
            Err(Error::NonMinimalLength {
                declared: 3,
                encoded_octets: 1
            })
        );
        // And the inner length is caught too, so a non-minimal length buried
        // in a constructed value cannot hide behind a minimal outer one.
        assert_eq!(
            Der::decode(&[0x30, 0x04, 0x02, 0x81, 0x01, 0x05])
                .unwrap()
                .children(),
            Err(Error::NonMinimalLength {
                declared: 1,
                encoded_octets: 1
            })
        );

        // The BER layer takes the same bytes, which is the property the two
        // types exist to keep apart. Asserted through the public API so it
        // keeps holding if either decoder is rewritten.
        let (atom, _) = crate::tlv::Tlv::decode(&non_minimal).unwrap();
        assert_eq!(atom.value(), &[0x02, 0x01, 0x05]);
    }

    /// A well-formed body holding an octet string of `length` octets, with
    /// `length` written the way the caller asked for.
    fn octet_string(length: usize, encoded: &[u8]) -> Vec<u8> {
        let mut body = vec![0x04];
        body.extend_from_slice(encoded);
        body.resize(body.len() + length, 0xAA);
        body
    }

    #[test]
    fn minimality_is_decided_by_the_octets_not_by_the_value() {
        // Two octets is minimal when the high octet is non-zero, whatever
        // the low one is.
        assert!(Der::decode(&octet_string(128, &[0x81, 0x80])).is_ok());
        assert_eq!(
            Der::decode(&octet_string(128, &[0x82, 0x00, 0x80])),
            Err(Error::NonMinimalLength {
                declared: 128,
                encoded_octets: 2
            })
        );
        // `81 00` is zero written the long way. Zero fits in the short form.
        assert_eq!(
            Der::decode(&[0x04, 0x81, 0x00]),
            Err(Error::NonMinimalLength {
                declared: 0,
                encoded_octets: 1
            })
        );
        // 127 is the last short-form length, so `81 7F` is over-long and
        // `7F` is right.
        let mut body = vec![0x04, 0x7F];
        body.extend_from_slice(&[0u8; 127]);
        assert!(Der::decode(&body).is_ok());
        assert_eq!(
            Der::decode(&[0x04, 0x81, 0x7F]),
            Err(Error::NonMinimalLength {
                declared: 127,
                encoded_octets: 1
            })
        );
    }

    #[test]
    fn indefinite_and_over_wide_lengths_are_rejected() {
        assert_eq!(Der::decode(&[0x30, 0x80]), Err(Error::IndefiniteLength));
        assert_eq!(
            Der::decode(&[0x30, 0x83, 0x01, 0x00, 0x00]),
            Err(Error::LengthTooLarge {
                octets: 3,
                max: MAX_LENGTH_OCTETS
            })
        );
        assert!(matches!(
            Der::decode(&[0xFF; 4]),
            Err(Error::LengthTooLarge { .. })
        ));
    }

    #[test]
    fn truncation_and_trailing_data_are_separate_findings() {
        // Says three octets, supplies one.
        assert_eq!(
            Der::decode(&[0x30, 0x03, 0x02]),
            Err(Error::UnexpectedEof {
                needed: 3,
                available: 1
            })
        );
        // A complete value followed by rubbish.
        let mut with_rubbish = SEQUENCE.to_vec();
        with_rubbish.extend_from_slice(&[0xAA]);
        assert_eq!(
            Der::decode(&with_rubbish),
            Err(Error::TrailingData {
                at: SEQUENCE.len(),
                remaining: 1
            })
        );
        // `decode_first` leaves the caller's decision open, as the BER layer
        // does.
        let (value, consumed) = Der::decode_first(&with_rubbish).unwrap();
        assert_eq!(consumed, SEQUENCE.len());
        assert_eq!(value.value(), &[0x02, 0x01, 0x05]);
    }

    #[test]
    fn asking_a_primitive_value_for_children_is_an_error() {
        let integer = Der::decode(&[0x02, 0x01, 0x05]).unwrap();
        assert_eq!(integer.children(), Err(Error::NotConstructed { tag: 0x02 }));

        // An empty constructed value is constructed and simply has no
        // children; that is not the same as being primitive.
        let empty = Der::decode(&[0x30, 0x00]).unwrap();
        assert!(empty.is_constructed());
        assert_eq!(empty.children().unwrap(), Vec::<Der<'_>>::new());
    }

    #[test]
    fn every_value_this_module_encodes_decodes_back_unchanged() {
        for length in [0usize, 1, 127, 128, 255, 256, 65535] {
            let source = octet_string(length, &minimal_length_octets(length));
            let value = Der::decode(&source).unwrap();
            assert_eq!(value.len(), length);
            // A `Der` was decoded from minimal lengths, so writing it back
            // minimally reproduces the input byte for byte. That is a
            // property of the type, asserted rather than asserted in prose.
            assert_eq!(value.encode(), source, "{length} octets did not round-trip");
            assert_eq!(value.encoded_len(), source.len());
        }
    }

    /// The minimal length octets for `length`, which is what this module
    /// writes and therefore what it must read back.
    fn minimal_length_octets(length: usize) -> Vec<u8> {
        if length <= usize::from(MAX_SHORT_FORM) {
            vec![length as u8]
        } else if length <= 0xFF {
            vec![0x81, length as u8]
        } else {
            vec![0x82, (length >> 8) as u8, length as u8]
        }
    }

    #[test]
    fn no_three_octet_der_value_can_panic_the_decoder() {
        // Exhaustive. A certificate arrives from a remote server, so the
        // decoder is a parser of untrusted input and the property that
        // matters is that it always answers.
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                for c in 0u16..=255 {
                    let body = [a as u8, b as u8, c as u8];
                    if let Ok(value) = Der::decode(&body) {
                        assert!(value.encoded_len() <= body.len());
                        assert_eq!(value.encode().len(), value.encoded_len());
                    }
                }
            }
        }
    }
}
