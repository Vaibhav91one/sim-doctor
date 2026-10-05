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
//! [`crate::fcp`]. This module only answers "is there a length here, and how
//! long is the value".
//!
//! **Owns a stream decoder, and nothing else.** [`Tlv::decode`] reads
//! exactly one atom and reports how many octets it took. [`Stream`] composes
//! that into a walk over a whole body: atom after atom, in wire order, with
//! truncation and trailing data decided here rather than re-decided by every
//! caller. Mapping tags to fields is still not owned here; that is
//! [`crate::fcp`], and it is where the tag-dialect question is answered.
//!
//! **Why this is not built on `der`.** AGENTS.md 4.2 records that `der` 0.8.2
//! is strict DER and rejects the non-minimal BER lengths that real SIM and
//! SGP.22 BPP payloads carry. That is a property of DER, not a defect in the
//! data: the same length `05` written as `81 05` is the same five bytes. So
//! [`Length::decode`] accepts the long form whatever value it encodes, and
//! [`Length::encode`] always writes the short form back.
//!
//! **Why neither nominated BER crate was adopted.** AGENTS.md 4.2 offers
//! `iso7816-tlv` 0.4.4 or `flexiber` 0.2.0 for this job. Issue #11 read both
//! at the versions this project pins and removed them from `Cargo.toml`
//! rather than adopt one. The reasons, stated once and in full:
//!
//! - `iso7816-tlv` 0.4.4 reads an indefinite length (`80`) as *length zero*
//!   rather than rejecting it. A decoder that answers a question instead of
//!   reporting that it cannot is the worst failure mode this crate has,
//! - it owns and copies every value into nested `Vec`s, where a card file
//!   body is up to 65535 octets and a scan walks dozens of them,
//! - it decodes the identifier octet as a multi-octet BER tag and rejects a
//!   single-octet tag whose low five bits are all set, which is the exact
//!   class-bit question [`Tag`] deliberately leaves open,
//! - its encoder writes a non-minimal long form for exactly 127 octets
//!   (`l < 0x7f` rather than `l <= 0x7f`), so a re-encode would not be
//!   canonical,
//! - `flexiber` 0.2.0's length rules are behaviourally identical to the ones
//!   above, which is real validation, but it keeps the parsed length only, not
//!   the *form* it arrived in, and that form is part of what [`Length`] exists
//!   to preserve. It is also BER-only, so it could not have supplied the
//!   strict-DER half either; that is [`crate::der`], written separately,
//! - and the decisive one: the acceptance criterion is that the non-minimal
//!   tolerance be *tested here*. Delegating the decoder delegates the
//!   property, and a property nobody here can assert is not a property this
//!   project has.
//!
//! Both were therefore removed from `Cargo.toml` rather than left declared and
//! unused for a third issue.
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

/// A cursor over a BER-TLV body: one atom at a time, in wire order.
///
/// The composition layer over [`Tlv::decode`]. A file body, a file
/// capabilities template and a SGP.22 payload all ask the same question -
/// what are all the atoms in these bytes, in the order they appear - and
/// none of them should have to re-answer the parts that are easy to get
/// wrong:
///
/// - **Truncation.** A length that runs past the end of the body is an
///   error, not a short read and not a panic.
/// - **Trailing data.** [`Stream::finish`] is what decides whether octets
///   left over are rubbish or simply not part of this structure. Which of
///   the two it is depends on the caller, so it stays the caller's call.
/// - **Re-entry after failure.** A stream that failed stops. Handing out
///   the same broken position again would let a `while` loop spin forever on
///   a card that sent one bad length.
///
/// Borrows, like [`Tlv`]: walking a 65535-octet body costs no allocation.
#[derive(Debug, Clone)]
pub struct Stream<'a> {
    body: &'a [u8],
    offset: usize,
    stopped: bool,
}

impl<'a> Stream<'a> {
    /// Starts a walk at the beginning of `body`.
    ///
    /// An empty body is not an error and not one atom. It is zero atoms,
    /// which is what a card sends for a template with no content, and
    /// [`Stream::finish`] accepts it.
    pub const fn new(body: &'a [u8]) -> Self {
        Self {
            body,
            offset: 0,
            stopped: false,
        }
    }

    /// Reads the next atom, or `None` once the body is exhausted.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`Error`] if the atom at the current position
    /// is truncated, carries an indefinite length, or declares a length wider
    /// than one APDU data field. The stream stops afterwards; see the type
    /// documentation for why.
    pub fn next_atom(&mut self) -> Result<Option<Tlv<'a>>, Error> {
        if self.stopped || self.offset >= self.body.len() {
            return Ok(None);
        }
        match Tlv::decode(&self.body[self.offset..]) {
            Ok((atom, consumed)) => {
                // `Tlv::decode` reports how many octets it read, so this
                // cannot run past the end of the body.
                self.offset += consumed;
                Ok(Some(atom))
            }
            Err(error) => {
                self.stopped = true;
                Err(error)
            }
        }
    }

    /// How many octets have been consumed so far.
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// The octets not yet walked.
    pub fn remaining(&self) -> &'a [u8] {
        // `offset` only ever advances by an amount `Tlv::decode`
        // already checked, but a slice index is bounds-checked anyway
        // and the clamp keeps that fact from being load-bearing.
        &self.body[self.offset.min(self.body.len())..]
    }

    /// The whole body this stream was built over.
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Whether every octet has been walked, or the stream has stopped.
    pub const fn is_exhausted(&self) -> bool {
        self.stopped || self.offset >= self.body.len()
    }

    /// Whether this stream already reported a failure and stopped.
    pub const fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Requires that the body ended exactly here.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TrailingData`] if octets remain. This is the check
    /// that turns 'I read one template' into 'the response was exactly one
    /// template', which is a claim worth making when the answer decides
    /// whether a card is well-behaved.
    ///
    /// A stream that already failed returns `Ok`. The failure was reported by
    /// [`Stream::next_atom`] and this method's only question is trailing
    /// data; raising the same error twice would help nobody.
    pub fn finish(self) -> Result<(), Error> {
        if self.stopped {
            return Ok(());
        }
        let remaining = self.body.len().saturating_sub(self.offset);
        if remaining == 0 {
            Ok(())
        } else {
            Err(Error::TrailingData {
                at: self.offset,
                remaining,
            })
        }
    }

    /// Walks the whole body and collects every atom, in wire order.
    ///
    /// # Errors
    ///
    /// The first malformed atom stops the walk. Trailing data is impossible
    /// here by construction, which is why this and [`Stream::finish`] are
    /// different calls.
    pub fn collect_atoms(self) -> Result<Vec<Tlv<'a>>, Error> {
        let mut atoms = Vec::new();
        let mut stream = self;
        while let Some(atom) = stream.next_atom()? {
            atoms.push(atom);
        }
        Ok(atoms)
    }

    /// Iterates the atoms, stopping at the first malformed one.
    pub fn atoms(self) -> Atoms<'a> {
        Atoms { stream: self }
    }
}

/// The iterator half of [`Stream`]. Yields `Err` once, then ends.
///
/// See [`Stream::atoms`].
#[derive(Debug, Clone)]
pub struct Atoms<'a> {
    stream: Stream<'a>,
}

impl<'a> Iterator for Atoms<'a> {
    type Item = Result<Tlv<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.stream.next_atom() {
            Ok(Some(atom)) => Some(Ok(atom)),
            // A stopped stream answers `Ok(None)`, so a caller that keeps
            // pulling after an error gets one error and then the end rather
            // than an unbounded stream of the same failure.
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }
}

/// Everything that can go wrong while decoding BER-TLV.
///
/// `#[non_exhaustive]` because the surface grows as later issues reach
/// further into card payloads, and downstream matches should not have to
/// be rewritten when it does.
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

    /// Octets remained where a complete structure was required.
    ///
    /// Only [`Stream::finish`] raises this. One atom followed by rubbish is
    /// a different situation from one atom followed by a second atom, and
    /// which of the two a caller has depends on what it asked for.
    #[error("{remaining} octets of trailing data at offset {at}")]
    TrailingData {
        /// Where the unconsumed octets start.
        at: usize,
        /// How many octets were left over.
        remaining: usize,
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

    /// A three-atom body, the shape every FCP template has:
    /// a file size, a file identifier and a life cycle status.
    const FCP_FIELDS: [u8; 14] = [
        0x82, 0x02, 0x09, 0x21, // file descriptor
        0x83, 0x02, 0x2F, 0xE2, // file identifier
        0x8A, 0x01, 0x05, // life cycle status
        0x80, 0x01, 0x0A, // file size
    ];

    #[test]
    fn a_stream_hands_back_every_atom_in_wire_order() {
        let atoms = Stream::new(&FCP_FIELDS).collect_atoms().unwrap();
        let tags: Vec<_> = atoms.iter().map(|a| a.tag().octet()).collect();
        assert_eq!(tags, vec![0x82, 0x83, 0x8A, 0x80]);
        assert_eq!(atoms[0].value(), &[0x09, 0x21]);
        assert_eq!(atoms[1].value(), &[0x2F, 0xE2]);
        assert_eq!(atoms[2].value(), &[0x05]);
        assert_eq!(atoms[3].value(), &[0x0A]);

        // Order is the contract: a scanner that reads a template twice must
        // see the same sequence, and an implementation that sorted or
        // deduplicated would pass the length check above and fail this.
        let again = Stream::new(&FCP_FIELDS).collect_atoms().unwrap();
        assert_eq!(atoms, again);
    }

    #[test]
    fn an_empty_body_is_zero_atoms_not_an_error() {
        let mut stream = Stream::new(&[]);
        assert_eq!(stream.next_atom().unwrap(), None);
        assert!(stream.is_exhausted());
        assert!(stream.finish().is_ok());
        assert_eq!(Stream::new(&[]).collect_atoms().unwrap(), vec![]);
    }

    #[test]
    fn a_stream_over_one_atom_advances_by_exactly_that_atom() {
        let mut stream = Stream::new(&FCP_FIELDS);
        let first = stream.next_atom().unwrap().unwrap();
        assert_eq!(first.encoded_len(), 4);
        assert_eq!(stream.offset(), 4);
        assert_eq!(stream.remaining().len(), FCP_FIELDS.len() - 4);

        let mut walked = 0;
        while stream.next_atom().unwrap().is_some() {
            walked += 1;
        }
        assert_eq!(walked, 3);
        assert_eq!(stream.offset(), FCP_FIELDS.len());
        assert_eq!(stream.remaining(), &[] as &[u8]);
    }

    #[test]
    fn a_non_minimal_length_still_walks_as_one_atom() {
        // The same three atoms, the first with its length written long-form
        // for two. This is the acceptance criterion: a stream built on the
        // atom layer must not re-impose DER minimality on the way through.
        let body = [0x82, 0x81, 0x02, 0x09, 0x21, 0x83, 0x02, 0x2F, 0xE2];
        let atoms = Stream::new(&body).collect_atoms().unwrap();
        assert_eq!(atoms.len(), 2);
        assert_eq!(atoms[0].value(), &[0x09, 0x21]);
        assert_eq!(atoms[0].tag().octet(), 0x82);
        assert_eq!(atoms[1].value(), &[0x2F, 0xE2]);
    }

    #[test]
    fn truncation_is_an_error_and_not_a_short_read() {
        // The last atom claims four octets of value and supplies two.
        let body = [0x82, 0x02, 0x09, 0x21, 0x83, 0x04, 0x2F, 0xE2];
        let mut stream = Stream::new(&body);
        assert!(stream.next_atom().unwrap().is_some());
        assert_eq!(
            stream.next_atom(),
            Err(Error::UnexpectedEof {
                needed: 4,
                available: 2
            })
        );
    }

    #[test]
    fn a_truncated_length_field_is_an_error_not_a_zero_length_atom() {
        // `81` promises a length octet and the buffer ends. Decoding this as
        // length zero would silently invent an empty atom where the card
        // meant to send something.
        let body = [0x82, 0x81];
        assert_eq!(
            Stream::new(&body).collect_atoms(),
            Err(Error::UnexpectedEof {
                needed: 1,
                available: 0
            })
        );
    }

    #[test]
    fn a_stream_that_failed_stops_instead_of_looping() {
        // The property that keeps a `while let Some(..) = ..` caller from
        // spinning: one error, then the end. Without the stop flag the same
        // bad position is handed back forever and the caller never advances.
        let body = [0x84, 0x0A, 0x2F, 0xE2];
        let mut stream = Stream::new(&body);
        assert!(stream.next_atom().is_err());
        assert!(stream.is_stopped());
        assert_eq!(stream.next_atom().unwrap(), None);
        assert_eq!(stream.next_atom().unwrap(), None);

        let mut pulls = 0;
        for outcome in Stream::new(&body).atoms() {
            pulls += 1;
            assert!(outcome.is_err());
        }
        assert_eq!(pulls, 1);
    }

    #[test]
    fn trailing_data_is_reported_only_by_the_caller_that_asked() {
        let body = [0x6F, 0x00, 0x84, 0x02, 0x2F, 0xE2];

        // Reading the outer template and nothing else: there is more to
        // come, and whether that is rubbish or a second field is not this
        // module's call.
        let mut stream = Stream::new(&body);
        assert!(stream.next_atom().unwrap().is_some());
        assert_eq!(stream.offset(), 2);
        assert_eq!(
            stream.finish(),
            Err(Error::TrailingData {
                at: 2,
                remaining: 4
            })
        );

        // Walking the whole body is a different promise, and it is kept.
        assert_eq!(Stream::new(&body).collect_atoms().unwrap().len(), 2);
        let mut walked = Stream::new(&body);
        while walked.next_atom().unwrap().is_some() {}
        assert!(walked.finish().is_ok());

        // `finish` asks whether anything is left, so on a stream that
        // has not been walked it says yes: the whole body is left.
        assert_eq!(
            Stream::new(&body).finish(),
            Err(Error::TrailingData {
                at: 0,
                remaining: body.len()
            })
        );
        assert!(Stream::new(&[]).finish().is_ok());
    }

    #[test]
    fn finish_does_not_re_report_a_failure_the_caller_already_saw() {
        let body = [0x84, 0x0A, 0x2F, 0xE2];
        let mut stream = Stream::new(&body);
        assert!(stream.next_atom().is_err());
        // finish() is asked about trailing data, and the trailing-data
        // answer here is that the failure was already reported.
        assert!(stream.finish().is_ok());
    }

    #[test]
    fn no_two_byte_body_can_panic_the_stream() {
        // Exhaustive over every two-octet body. A card is an untrusted input
        // source, so the property asserted here is 'never panics', not 'gets
        // the right answer', which the focused tests above cover.
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                let body = [a as u8, b as u8];
                let collected = Stream::new(&body).collect_atoms();
                assert!(
                    collected.as_ref().map(Vec::len).unwrap_or(0) <= 2,
                    "{body:02X?} produced {collected:?}"
                );
                // Whatever it decided, the offset can never leave the body.
                let mut stream = Stream::new(&body);
                while let Ok(Some(atom)) = stream.next_atom() {
                    let _ = atom;
                    assert!(stream.offset() <= body.len());
                }
            }
        }
    }
}
