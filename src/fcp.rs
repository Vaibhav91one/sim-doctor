//! The tag dictionary of a card's file capabilities template, supplied by the
//! caller rather than assumed by this crate.
//!
//! **Owns.** The meaning side of a SELECT response: which BER tag reports the
//! file size, which reports the file identifier, which reports the file
//! status, and how to read the file descriptor, the security attributes and
//! the access conditions out of whatever the card actually sent.
//!
//! **Does not own.** The tag, length and value octets themselves. Those are
//! [`crate::tlv`], and this module is built on the stream decoder that module
//! now provides. It also does not own the file system vocabulary; a file
//! identifier as an addressable thing is [`crate::fs`].
//!
//! # The tag table is not the protocol, and there is more than one of them
//!
//! This is the finding AGENTS.md section 2 records, and it is the reason this
//! module exists in the shape it does. Inside a file capabilities template,
//! ISO/IEC 7816-4 table 42 and the FCP builder in swSIM's `src/3gpp.c`
//! **disagree** about what three of the tags mean:
//!
//! | Field | ISO/IEC 7816-4 table 42 | swSIM `src/3gpp.c` |
//! |---|---|---|
//! | file size | `82` | `80` |
//! | file descriptor | `83` | `82` |
//! | file identifier | `84` | `83` |
//!
//! Reading an swSIM FCP against the ISO table gives a file size of `0x0921`
//! for EF.IMSI. Reading it against swSIM's table gives `80 = 0x000A = 10`,
//! which is the file's real length. That was not a rounding error; it was a
//! card reported as absurd. \[V] for the swSIM column, read in `src/3gpp.c` at
//! swsim commit `281da8c6`; the ISO column is recorded in AGENTS.md section 2
//! and `docs/swsim-fixture.md` and is not re-derived here.
//!
//! So the design decision this module exists to enforce is: **there is no
//! default mapping.** [`Template::parse`] takes a [`TagSet`], and the only
//! way to get one is to name it - [`TagSet::iec_7816_4_table_42`],
//! [`TagSet::swicc`], or [`TagSet::named`] plus builders for a card nobody
//! has characterised yet. [`TagSet`] deliberately has no `Default` and no
//! constructor that invents tags, so a decoder cannot be reached without a
//! decision having been recorded about which dialect it is reading. Every
//! [`TagSet`] carries the name it was given, so a scan can report the
//! assumption it ran under instead of burying it.
//!
//! Each field is an `Option<Tag>`, not a `Tag`, and that is load-bearing
//! rather than decoration. swSIM's master-file FCP carries no file size at
//! all, because a master file has no size; a mapping that must invent a tag
//! for it would report something the card never sent. A caller that wants
//! `df_name` under the ISO table, where this repository has not verified
//! which tag carries it, supplies one.
//!
//! # What is verified and what is not
//!
//! Everything this module decodes past the tags themselves comes from one
//! of two sources, and the difference is stated at each use:
//!
//! - **\[V]** the octets swSIM writes, read in its source at the pinned
//!   commits. The file descriptor byte layout, the life cycle status values
//!   and the compact security attributes shape are all in this category.
//! - **\[U]** a reading of the standards that this repository has not
//!   checked against the spec text. The security-condition two-bit meanings
//!   are the notable one, so they are deliberately *not* encoded: this
//!   module exposes the raw octets and the bit groups and leaves the
//!   naming to whoever has the clause open.
//!
//! # Why this is not `der`, and not the nominated BER crates
//!
//! AGENTS.md 4.2. `der` 0.8.2 is strict DER and rejects the non-minimal BER
//! lengths that real SIM and SGP.22 payloads carry; it stays for
//! certificates, and its strict counterpart in this crate is [`crate::der`],
//!
//! `iso7816-tlv` 0.4.4 and `flexiber` 0.2.0 were both read at these versions
//! and both removed from `Cargo.toml`. The full reasoning is in
//! [`crate::tlv`]'s module documentation; the one-line version is that
//! neither can hand back borrowed tag-by-tag slices with the *form* of each
//! length preserved, and `iso7816-tlv` additionally reads an indefinite
//! length as zero rather than rejecting it.

/// This module's name, as recorded in [`crate::MODULES`].
///
/// Referenced by value rather than re-spelt as a literal so that the module
/// table cannot name a module that does not exist.
pub const NAME: &str = "fcp";

use std::{borrow::Cow, fmt};

use crate::tlv::{self, Tag, Tlv};

/// The tag octets one card source uses to report each file capabilities field.
///
/// A value the caller supplies, never one this crate falls back to. See the
/// module documentation for why the two known tables disagree and why that
/// matters; the short version is that reading an FCP against the wrong one
/// turns a ten-octet file into a 2337-octet one.
///
/// Every field is an [`Option`] because a table need not define every field,
/// and a card need not send every field. `None` means *this mapping says
/// nothing is reported here*, which is different from *the card sent nothing*
/// and is not a value a decoder may substitute.
///
/// There is no [`Default`] implementation. That is the point: the absence of a
/// default is what makes [`Template::parse`] unable to run until somebody has
/// said which dialect is being read.
///
/// # Example
///
/// ```
/// use sim_doctor::{fcp::TagSet, tlv::Tag};
///
/// let swicc = TagSet::swicc();
/// assert_eq!(swicc.file_size().map(|t| t.octet()), Some(0x80));
///
/// // A card nobody has characterised yet: start empty, fill in what you know.
/// let probe = TagSet::named("unidentified card")
///     .with_file_size(Tag::new(0x80))
///     .with_file_id(Tag::new(0x84));
/// assert_eq!(probe.name(), "unidentified card");
/// assert!(probe.file_descriptor().is_none());
/// ```
///
/// There is no `Default` and no way to get a populated mapping without naming
/// one, which is the mechanism rather than an omission:
///
/// ```compile_fail
/// use sim_doctor::fcp::TagSet;
///
/// // There is no default mapping, because there is no universal one.
/// let tags = TagSet::default();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TagSet {
    name: Cow<'static, str>,
    file_size: Option<Tag>,
    file_descriptor: Option<Tag>,
    file_id: Option<Tag>,
    life_cycle_status: Option<Tag>,
    access_conditions: Option<Tag>,
    short_file_id: Option<Tag>,
    df_name: Option<Tag>,
    proprietary: Option<Tag>,
}

impl TagSet {
    /// An empty mapping with a name, for a card this repository has not
    /// characterised.
    ///
    /// Nothing is filled in. Every [`Template`] lookup against it returns
    /// `None`, which is the honest answer for a mapping nobody has written
    /// down yet and is why this is useful for probing: read a card's raw
    /// atoms, decide what they are, and come back with a mapping.
    pub fn named(name: impl Into<Cow<'static, str>>) -> Self {
        Self {
            name: name.into(),
            file_size: None,
            file_descriptor: None,
            file_id: None,
            life_cycle_status: None,
            access_conditions: None,
            short_file_id: None,
            df_name: None,
            proprietary: None,
        }
    }

    /// The mapping in ISO/IEC 7816-4 table 42.
    ///
    /// `82` file size, `83` file descriptor, `84` file identifier, `88` short
    /// file identifier, `8A` life cycle status, `8C` compact access
    /// conditions, `A5` proprietary information. \[U] beyond the three
    /// entries AGENTS.md section 2 states, which this repository records
    /// rather than re-derives; `df_name` is left unset precisely because
    /// this repository has not verified which tag carries it here.
    pub fn iec_7816_4_table_42() -> Self {
        Self::named("IEC 7816-4 table 42")
            .with_file_size(Tag::new(0x82))
            .with_file_descriptor(Tag::new(0x83))
            .with_file_id(Tag::new(0x84))
            .with_short_file_id(Tag::new(0x88))
            .with_life_cycle_status(Tag::new(0x8A))
            .with_access_conditions(Tag::new(0x8C))
            .with_proprietary(Tag::new(0xA5))
    }

    /// The mapping swSIM writes, from the FCP builder in its `src/3gpp.c`.
    ///
    /// `80` file size, `82` file descriptor, `83` file identifier, `84` DF
    /// name, `88` short file identifier, `8A` life cycle status, `8C`
    /// compact security attributes, `A5` proprietary information, `C6` PIN
    /// status template. \[V], read at swsim commit
    /// `281da8c63398ece9a5126cad969674f4f413ab63`.
    ///
    /// Named after the software that was observed writing it rather than
    /// after a specification, because a real UICC follows 3GPP TS 31.102 or
    /// ETSI TS 102 221 clause 11.1.1.3 - which swICC's own comments cite and
    /// this repository has not read. A card that follows that document and a
    /// card that follows swICC will agree here; if one does not, the caller
    /// builds a [`TagSet::named`] for it.
    pub fn swicc() -> Self {
        Self::named("swICC FCP builder (swsim 281da8c)")
            .with_file_size(Tag::new(0x80))
            .with_file_descriptor(Tag::new(0x82))
            .with_file_id(Tag::new(0x83))
            .with_df_name(Tag::new(0x84))
            .with_short_file_id(Tag::new(0x88))
            .with_life_cycle_status(Tag::new(0x8A))
            .with_access_conditions(Tag::new(0x8C))
            .with_proprietary(Tag::new(0xA5))
    }

    /// The name this mapping was given, for a scan to report.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The tag this mapping reads the file size from.
    pub const fn file_size(&self) -> Option<Tag> {
        self.file_size
    }

    /// The tag this mapping reads the file descriptor from.
    pub const fn file_descriptor(&self) -> Option<Tag> {
        self.file_descriptor
    }

    /// The tag this mapping reads the file identifier from.
    pub const fn file_id(&self) -> Option<Tag> {
        self.file_id
    }

    /// The tag this mapping reads the life cycle status from.
    pub const fn life_cycle_status(&self) -> Option<Tag> {
        self.life_cycle_status
    }

    /// The tag this mapping reads the access conditions from.
    pub const fn access_conditions(&self) -> Option<Tag> {
        self.access_conditions
    }

    /// The tag this mapping reads the short file identifier from.
    pub const fn short_file_id(&self) -> Option<Tag> {
        self.short_file_id
    }

    /// The tag this mapping reads the DF name from.
    pub const fn df_name(&self) -> Option<Tag> {
        self.df_name
    }

    /// The tag this mapping reads the proprietary template from.
    pub const fn proprietary(&self) -> Option<Tag> {
        self.proprietary
    }

    /// Sets the tag the file size is read from.
    #[must_use]
    pub const fn with_file_size(mut self, tag: Tag) -> Self {
        self.file_size = Some(tag);
        self
    }

    /// Sets the tag the file descriptor is read from.
    #[must_use]
    pub const fn with_file_descriptor(mut self, tag: Tag) -> Self {
        self.file_descriptor = Some(tag);
        self
    }

    /// Sets the tag the file identifier is read from.
    #[must_use]
    pub const fn with_file_id(mut self, tag: Tag) -> Self {
        self.file_id = Some(tag);
        self
    }

    /// Sets the tag the life cycle status is read from.
    #[must_use]
    pub const fn with_life_cycle_status(mut self, tag: Tag) -> Self {
        self.life_cycle_status = Some(tag);
        self
    }

    /// Sets the tag the access conditions are read from.
    #[must_use]
    pub const fn with_access_conditions(mut self, tag: Tag) -> Self {
        self.access_conditions = Some(tag);
        self
    }

    /// Sets the tag the short file identifier is read from.
    #[must_use]
    pub const fn with_short_file_id(mut self, tag: Tag) -> Self {
        self.short_file_id = Some(tag);
        self
    }

    /// Sets the tag the DF name is read from.
    #[must_use]
    pub const fn with_df_name(mut self, tag: Tag) -> Self {
        self.df_name = Some(tag);
        self
    }

    /// Sets the tag the proprietary template is read from.
    #[must_use]
    pub const fn with_proprietary(mut self, tag: Tag) -> Self {
        self.proprietary = Some(tag);
        self
    }
}

impl fmt::Display for TagSet {
    /// Writes the mapping's name, so a report can say which table was
    /// assumed rather than leaving the reader to guess.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// One file capabilities template, parsed with the caller's tag mapping.
///
/// Built by [`Template::parse`], which is the only way in, and which cannot
/// be called without a [`TagSet`]. Everything here borrows out of the buffer
/// the card's response was read into, so walking a whole file system costs
/// one allocation per template rather than one per field.
///
/// The design brief for this type was issue #7's scanner walking a tree, so
/// it is built to be walked: [`Template::atoms`] gives every atom in wire
/// order, [`Template::tags_without_meaning`] names the ones this mapping
/// does not cover, and a field a card omitted reads as `None` rather than as
/// a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template<'a> {
    dialect: &'a TagSet,
    envelope: Option<Tlv<'a>>,
    body: &'a [u8],
    atoms: Vec<Tlv<'a>>,
}

impl<'a> Template<'a> {
    /// Parses a SELECT response body under `dialect`.
    ///
    /// # Envelope
    ///
    /// ISO/IEC 7816-4 clause 7.5.1 has SELECT answer with one template: an
    /// FCP template or an FCI template, both constructed. swSIM answers `62`
    /// and a card following the FCI route answers `6F`. Rather than hard-code
    /// either, this unwraps a body that is *exactly one constructed atom*
    /// and leaves anything else alone, so both work and so does a caller
    /// that already stripped the wrapper. The unwrapped atom stays available
    /// through [`Template::envelope`], because which envelope a card uses is
    /// itself a fact worth reporting.
    ///
    /// # Errors
    ///
    /// [`Error::Tlv`] if the body, or the unwrapped template inside it, is
    /// not well-formed BER-TLV. Unwrapping is one level deep and does not
    /// recurse, so a hostile body cannot drive unbounded nesting.
    pub fn parse(body: &'a [u8], dialect: &'a TagSet) -> Result<Self, Error> {
        let top = tlv::Stream::new(body).collect_atoms()?;
        let (envelope, body, atoms) = match top.as_slice() {
            [only] if only.is_constructed() => (
                Some(*only),
                only.value(),
                tlv::Stream::new(only.value()).collect_atoms()?,
            ),
            _ => (None, body, top),
        };
        Ok(Self {
            dialect,
            envelope,
            body,
            atoms,
        })
    }

    /// The mapping this template was read under.
    pub const fn dialect(&self) -> &TagSet {
        self.dialect
    }

    /// The constructed atom that wrapped the template, if one did.
    ///
    /// `62` for swSIM, `6F` on the FCI route, `None` when the caller handed
    /// over the fields already unwrapped.
    pub const fn envelope(&self) -> Option<Tlv<'a>> {
        self.envelope
    }

    /// The octets the fields were read from, envelope removed.
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Every atom of the template, in wire order.
    pub fn atoms(&self) -> &[Tlv<'a>] {
        &self.atoms
    }

    /// The first atom carrying `tag`, if any.
    ///
    /// First, not last: a card that sends a tag twice has not been made to
    /// choose for us, and [`Template::atoms`] shows both so the caller can
    /// decide that is a finding.
    pub fn find(&self, tag: Tag) -> Option<Tlv<'a>> {
        self.atoms.iter().find(|atom| atom.tag() == tag).copied()
    }

    /// Tags this mapping gives no meaning to, in wire order, repeats kept.
    ///
    /// A scanner's forward-compatibility list: what the card sent that this
    /// crate does not know about. Proprietary templates are full of it, and
    /// silently dropping them would make a card look simpler than it is.
    pub fn tags_without_meaning(&self) -> Vec<Tag> {
        self.atoms
            .iter()
            .map(Tlv::tag)
            .filter(|tag| !self.dialect.claims(*tag))
            .collect()
    }

    /// The file size the card reported, if this mapping has a tag for it and
    /// the card used it.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedField`] if the atom is not one to four octets long,
    /// which is the shape a card sends and a size that fits a `u32`.
    pub fn file_size(&self) -> Result<Option<FileSize>, Error> {
        let Some(tag) = self.dialect.file_size() else {
            return Ok(None);
        };
        match self.find(tag) {
            None => Ok(None),
            Some(atom) => FileSize::decode(atom.value(), tag).map(Some),
        }
    }

    /// The two octets the card reported as the selected file's identifier.
    ///
    /// Raw octets rather than a [`crate::fs::FileId`], because this module
    /// does not own the file system vocabulary and must not depend on it.
    /// Turning them into something addressable is one call away.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedField`] if the atom is not exactly two octets. A
    /// wrong-sized identifier is an error and not a truncation: reading the
    /// first two octets would fabricate an address the card never sent.
    pub fn file_id(&self) -> Result<Option<[u8; 2]>, Error> {
        let Some(tag) = self.dialect.file_id() else {
            return Ok(None);
        };
        match self.find(tag) {
            None => Ok(None),
            Some(atom) => {
                let bytes: [u8; FILE_ID_OCTETS] = atom.value().try_into().map_err(|_| {
                    Error::malformed("file identifier", tag, atom.len(), "two octets")
                })?;
                Ok(Some(bytes))
            }
        }
    }

    /// The file descriptor: kind, structure and the octets themselves.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedField`] if the atom holds fewer than the two octets
    /// a file descriptor block needs.
    pub fn file_descriptor(&self) -> Result<Option<FileDescriptor<'a>>, Error> {
        let Some(tag) = self.dialect.file_descriptor() else {
            return Ok(None);
        };
        match self.find(tag) {
            None => Ok(None),
            Some(atom) => FileDescriptor::decode(atom.value(), tag).map(Some),
        }
    }

    /// The life cycle status the card reported, if it reported one.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedField`] if the atom is not exactly one octet.
    pub fn life_cycle_status(&self) -> Result<Option<LifeCycleStatus>, Error> {
        let Some(tag) = self.dialect.life_cycle_status() else {
            return Ok(None);
        };
        match self.find(tag) {
            None => Ok(None),
            Some(atom) => {
                let &[byte] = atom.value() else {
                    return Err(Error::malformed(
                        "life cycle status",
                        tag,
                        atom.len(),
                        "one octet",
                    ));
                };
                Ok(Some(LifeCycleStatus::from_byte(byte)))
            }
        }
    }

    /// The access conditions the card reported, if it reported them.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedField`] if the compact form is not eight octets.
    pub fn access_conditions(&self) -> Result<Option<AccessConditions<'a>>, Error> {
        let Some(tag) = self.dialect.access_conditions() else {
            return Ok(None);
        };
        match self.find(tag) {
            None => Ok(None),
            Some(atom) => AccessConditions::decode(atom.value(), tag).map(Some),
        }
    }
}

impl TagSet {
    /// Whether this mapping gives `tag` any meaning at all.
    ///
    /// Used by [`Template::tags_without_meaning`]. A tag that two fields
    /// both claim counts as claimed once; the two lookups resolve it.
    fn claims(&self, tag: Tag) -> bool {
        [
            self.file_size,
            self.file_descriptor,
            self.file_id,
            self.life_cycle_status,
            self.access_conditions,
            self.short_file_id,
            self.df_name,
            self.proprietary,
        ]
        .contains(&Some(tag))
    }
}

/// How many octets of a file size atom this module will read.
///
/// Four, because that is what a `u32` holds and a wider value would be a
/// number no elementary file on a card this crate can address could have.
const MAX_FILE_SIZE_OCTETS: usize = 4;

/// How many octets a file identifier atom must hold.
const FILE_ID_OCTETS: usize = 2;

/// The fewest octets a file descriptor block can occupy.
///
/// Two: the first carries the category, structure and sharing bits, the
/// second the data coding. swSIM writes two or three. \[V], read in swicc
/// `src/fs.c` `swicc_fs_file_descr` at swicc commit `421c8cdd`.
const MIN_FILE_DESCRIPTOR_OCTETS: usize = 2;

/// How many octets the compact form of the access conditions holds.
///
/// Eight. \[V], read in swsim `src/3gpp.c` `data_sec_attr_compact` at swsim
/// commit `281da8c6`, which is an eight-element array.
const COMPACT_ACCESS_CONDITION_OCTETS: usize = 8;

/// How many two-bit groups eight octets hold.
const ACCESS_CONDITION_GROUPS: usize = COMPACT_ACCESS_CONDITION_OCTETS * 4;

/// A file's size in octets, as the card reported it.
///
/// A newtype rather than a bare `u32`, so a size cannot be passed where a
/// file identifier is expected and quietly used as one. That mistake is
/// exactly how the EF.IMSI FCP first read as 2337 octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileSize(u32);

impl FileSize {
    /// A size of `octets` octets.
    pub const fn from_octets(octets: u32) -> Self {
        Self(octets)
    }

    /// The size in octets.
    pub const fn octets(self) -> u32 {
        self.0
    }

    /// Reads a big-endian size of one to four octets.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedField`] if the atom is empty or longer than four
    /// octets. Both are a card being wrong about a shape, and both are
    /// reported rather than rounded.
    pub fn decode(value: &[u8], tag: Tag) -> Result<Self, Error> {
        if value.is_empty() || value.len() > MAX_FILE_SIZE_OCTETS {
            return Err(Error::malformed(
                "file size",
                tag,
                value.len(),
                "one to four octets",
            ));
        }
        let mut octets: u32 = 0;
        for &octet in value {
            octets = (octets << 8) | u32::from(octet);
        }
        Ok(Self(octets))
    }
}

impl fmt::Display for FileSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} octets", self.0)
    }
}

/// The category bits of a file descriptor: what kind of file this is.
///
/// Read from bits 5 to 3 of the descriptor's first octet. swSIM's builder
/// sets `111` for the master file, a dedicated file and an application
/// dedicated file, and `001` for an elementary file. \[V], read in swicc
/// `src/fs.c` `swicc_fs_file_descr_byte` at swicc commit `421c8cdd`, whose
/// own comment cites ISO/IEC 7816-4:2020 clause 7.4.5 table 12.
///
/// This is a coarser answer than [`crate::fs::FileKind`], and on purpose:
/// the descriptor does not distinguish the master file from a dedicated
/// file, so a decoder that claims to is reading something the card did not
/// send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    /// Category `111`: the master file, a dedicated file or an application
    /// dedicated file. All three, because the descriptor does not say which.
    Directory,
    /// Category `001`: an internal elementary file.
    Elementary,
    /// A category value this crate has not verified, kept as the raw bits.
    Unknown(u8),
}

/// The structure bits of a file descriptor: how a file's contents are laid
/// out.
///
/// Read from bits 2 to 0 of the descriptor's first octet.
///
/// `Transparent`, `LinearFixed` and `Cyclic` are \[V]: those are the three
/// encodings swSIM's builder writes, read in swicc `src/fs.c`
/// `swicc_fs_file_descr_byte` at swicc commit `421c8cdd`.
/// `LinearVariable` is \[U], the value this ladder implies for the slot
/// between them, which no source in this repository has been read to confirm;
/// it is present because a scanner meeting one needs to say what it saw, and
/// [`Structure::Unknown`] remains available for anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Structure {
    /// `001`: one flat run of octets, read with READ BINARY.
    Transparent,
    /// `010`: fixed-length records, read with READ RECORD.
    LinearFixed,
    /// `011`: variable-length records. \[U], see the type documentation.
    LinearVariable,
    /// `110`: a cyclic file, written with UPDATE BINARY and a cyclic record
    /// pointer.
    Cyclic,
    /// A structure value this crate has not verified, kept as the raw bits.
    Unknown(u8),
}

impl Structure {
    /// Whether files of this structure are read record by record rather than
    /// as one run of octets.
    ///
    /// The rule that makes a scanner's READ BINARY attempt on EF.DIR a
    /// finding rather than a mystery: swSIM answers 69 81, command
    /// incompatible with file structure, and that is the correct answer.
    pub const fn is_record_structured(self) -> bool {
        !matches!(self, Self::Transparent)
    }
}

/// A file descriptor block: what kind of file this is and how it is laid out.
///
/// The octets a card puts in its file descriptor atom, borrowed and
/// unaltered, with the two views a scanner actually needs decoded out of
/// them: [`FileDescriptor::file_type`] and [`FileDescriptor::structure`].
/// Both come from the first octet.
///
/// The bit positions below are \[V] as swICC writes them, read in swicc
/// `src/fs.c` `swicc_fs_file_descr_byte` at swicc commit `421c8cdd`, whose own
/// comment cites ISO/IEC 7816-4:2020 clause 7.4.5 table 12:
///
/// ```text
/// octet 1   bit 8      0 = file not shareable
/// octet 1   bits 5-3   DF or EF category
/// octet 1   bits 2-0   EF structure
/// octet 2+             data coding and, for a linear-fixed file, the record
///                      length
/// ```
///
/// The second octet is exposed as [`FileDescriptor::data_coding`] and is
/// deliberately not decoded further. The one thing this repository can say
/// about it \[V] is that swICC writes `0x21` for every file, commenting that
/// it means EFs of BER-TLV structure are supported, the write function is
/// proprietary, `FF` is invalid as a first tag octet, and the data unit is
/// one byte. A scanner that needs those four bits wants clause 12.2.2.9
/// open, and this module does not want to be the thing that guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileDescriptor<'a> {
    octets: &'a [u8],
}

impl<'a> FileDescriptor<'a> {
    /// Reads a descriptor out of an atom's value octets.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedField`] if fewer than two octets are present. One
    /// octet cannot carry a descriptor block, and a card that sent one has not
    /// sent a descriptor this crate should read bits out of.
    pub fn decode(value: &'a [u8], tag: Tag) -> Result<Self, Error> {
        if value.len() < MIN_FILE_DESCRIPTOR_OCTETS {
            return Err(Error::malformed(
                "file descriptor",
                tag,
                value.len(),
                "at least two octets",
            ));
        }
        Ok(Self { octets: value })
    }

    /// The descriptor octets exactly as the card sent them.
    pub const fn octets(self) -> &'a [u8] {
        self.octets
    }

    /// Whether the card marked the file shareable.
    ///
    /// Bit 8 of the first octet. swICC writes zero for every file, so on that
    /// card this is always false; \[V] for the write, \[U] for the general
    /// meaning.
    pub const fn is_shareable(self) -> bool {
        self.octets[0] & 0b1000_0000 != 0
    }

    /// The category bits, as the three octet-1 bits 5 to 3.
    pub const fn category_bits(self) -> u8 {
        (self.octets[0] >> 3) & 0b111
    }

    /// The structure bits, as the three octet-1 bits 2 to 0.
    pub const fn structure_bits(self) -> u8 {
        self.octets[0] & 0b111
    }

    /// What kind of file this is.
    pub const fn file_type(self) -> FileType {
        match self.category_bits() {
            0b111 => FileType::Directory,
            0b001 => FileType::Elementary,
            other => FileType::Unknown(other),
        }
    }

    /// How the file's contents are laid out.
    pub const fn structure(self) -> Structure {
        match self.structure_bits() {
            0b001 => Structure::Transparent,
            0b010 => Structure::LinearFixed,
            0b011 => Structure::LinearVariable,
            0b110 => Structure::Cyclic,
            other => Structure::Unknown(other),
        }
    }

    /// The data coding octet, if the card sent one.
    pub const fn data_coding(self) -> Option<u8> {
        if self.octets.len() >= 2 {
            Some(self.octets[1])
        } else {
            None
        }
    }
}

/// A file's life cycle status, the one octet a card sends to say what state
/// the file is in.
///
/// A newtype over the raw octet rather than an enum, because this repository
/// can verify only three values. swICC's `swicc_fs_file_lcs` writes `05` for
/// a file whose lifecycle is operating-activated, `04` for
/// operating-deactivated and `0C` for terminated. \[V], read at swicc commit
/// `421c8cdd`. Everything else is preserved and rendered as hex, so an
/// unrecognised state is reported rather than dropped or, worse, mapped onto
/// the nearest known one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LifeCycleStatus(u8);

impl LifeCycleStatus {
    /// `05`, the value swICC writes for an operating-activated file.
    pub const OPERATING_ACTIVATED: Self = Self(0x05);

    /// `04`, the value swICC writes for an operating-deactivated file.
    pub const OPERATING_DEACTIVATED: Self = Self(0x04);

    /// `0C`, the value swICC writes for a terminated file.
    pub const TERMINATED: Self = Self(0x0C);

    /// Wraps whatever octet the card sent.
    pub const fn from_byte(byte: u8) -> Self {
        Self(byte)
    }

    /// The octet exactly as the card sent it.
    pub const fn byte(self) -> u8 {
        self.0
    }
}

impl fmt::Display for LifeCycleStatus {
    /// Names the three verified values and renders anything else as hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::OPERATING_ACTIVATED => f.write_str("05 operating activated"),
            Self::OPERATING_DEACTIVATED => f.write_str("04 operating deactivated"),
            Self::TERMINATED => f.write_str("0C terminated"),
            other => write!(f, "{:02X}", other.byte()),
        }
    }
}

/// How a card reported the conditions under which a file may be used.
///
/// Two shapes reach a scanner and this type keeps them apart, because
/// collapsing them would lose the fact that one of them is a fixed eight
/// octets and the other is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessConditions<'a> {
    /// The compact form: exactly eight octets, decoded into two-bit groups
    /// but not into named conditions. See [`CompactSecurityAttributes`].
    Compact(CompactSecurityAttributes<'a>),
    /// The expanded form: a template this crate hands over untouched.
    ///
    /// The octets stay borrowed and no attempt is made to read them, because
    /// the expanded form is a tag-numbered template whose tag numbering has
    /// the same dialect problem this module exists to avoid.
    Expanded(&'a [u8]),
}

impl<'a> AccessConditions<'a> {
    /// Reads a value octet run as either the compact or the expanded form.
    ///
    /// The eight-octet compact form is recognised by its **length alone**, and
    /// that is a heuristic, stated here rather than hidden: an expanded
    /// template that happens to be exactly eight octets would be read as
    /// compact. It is length rather than tag because the expanded form's own
    /// tag is a tag-table question - exactly the one this module refuses to
    /// answer on the caller's behalf - and guessing it here would be the bug
    /// this module exists to prevent.
    ///
    /// `tag` is used only to name the tag in a
    /// [`Error::MalformedField`], so the failure points at the octets that
    /// were wrong rather than at the field.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedField`] if the compact form was intended and is not
    /// exactly eight octets.
    pub fn decode(value: &'a [u8], tag: Tag) -> Result<Self, Error> {
        if value.len() == COMPACT_ACCESS_CONDITION_OCTETS {
            CompactSecurityAttributes::decode(value, tag).map(Self::Compact)
        } else {
            Ok(Self::Expanded(value))
        }
    }

    /// The octets, whichever form this is.
    pub const fn octets(self) -> &'a [u8] {
        match self {
            Self::Compact(compact) => compact.octets(),
            Self::Expanded(value) => value,
        }
    }

    /// Whether this is the eight-octet compact form.
    pub const fn is_compact(self) -> bool {
        matches!(self, Self::Compact(_))
    }
}

/// Eight octets of two-bit security conditions.
///
/// The octets are always available, and the two-bit groups they encode are
/// always available, and **this crate does not name the groups**. That is a
/// deliberate refusal rather than an omission.
///
/// What is \[V]: swSIM writes exactly eight octets here, the first being
/// `0b01111111` and the other seven zero, and comments that this means every
/// operation is allowed and that the remaining octets each indicate an
/// always condition. Read in swsim `src/3gpp.c` `data_sec_attr_compact` at
/// swsim commit `281da8c6`.
///
/// What is \[U]: the ISO/IEC 7816-4 clause 7.3.2 reading of those two-bit
/// groups as access-mode and card-holder-verification conditions with
/// ALW/CHV/NEV values. This repository has not read that clause, and
/// AGENTS.md section 2 says not to build on an unverified fact. So a caller
/// that needs `ALW` gets [`CompactSecurityAttributes::conditions`] and does
/// the naming with the document open, and a caller that only needs to compare
/// two cards gets [`CompactSecurityAttributes::octets`] and nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompactSecurityAttributes<'a> {
    octets: &'a [u8; COMPACT_ACCESS_CONDITION_OCTETS],
}

impl<'a> CompactSecurityAttributes<'a> {
    /// Reads the eight octets.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedField`] if the value is not exactly eight octets.
    pub fn decode(value: &'a [u8], tag: Tag) -> Result<Self, Error> {
        let octets: &'a [u8; COMPACT_ACCESS_CONDITION_OCTETS] = value.try_into().map_err(|_| {
            Error::malformed(
                "access conditions",
                tag,
                value.len(),
                "eight octets in the compact form",
            )
        })?;
        Ok(Self { octets })
    }

    /// The eight octets exactly as the card sent them.
    pub const fn octets(self) -> &'a [u8; COMPACT_ACCESS_CONDITION_OCTETS] {
        self.octets
    }

    /// The 32 two-bit groups, in wire order, most significant pair first.
    ///
    /// Undecoded on purpose; see the type documentation.
    pub fn conditions(self) -> [u8; ACCESS_CONDITION_GROUPS] {
        let mut groups = [0u8; ACCESS_CONDITION_GROUPS];
        for (index, group) in groups.iter_mut().enumerate() {
            let octet = self.octets[index / 4];
            *group = (octet >> (6 - 2 * (index % 4))) & 0b11;
        }
        groups
    }
}

/// Everything that can go wrong while reading a file capabilities template.
///
/// Separate from [`tlv::Error`] on purpose. A body that is not well-formed
/// BER-TLV and a body that is well-formed but says something impossible are
/// different findings, and a scanner reports them differently.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The body was not well-formed BER-TLV.
    #[error("the template body is not well-formed BER-TLV: {0}")]
    Tlv(#[from] tlv::Error),

    /// A field was present but not a shape a field can take.
    #[error("the {field} atom {tag} holds {found} octets, {expected}")]
    MalformedField {
        /// Which field was being read.
        field: &'static str,
        /// The tag the value came from, where the caller supplied one.
        tag: Tag,
        /// How many octets the atom actually held.
        found: usize,
        /// What shape the field requires.
        expected: &'static str,
    },
}

impl Error {
    /// Builds a [`Error::MalformedField`].
    ///
    /// One constructor so the wording is identical everywhere a field is
    /// rejected, which is what makes the message worth reading.
    const fn malformed(
        field: &'static str,
        tag: Tag,
        found: usize,
        expected: &'static str,
    ) -> Self {
        Self::MalformedField {
            field,
            tag,
            found,
            expected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SELECT EF.IMSI on swSIM, exactly as docs/swsim-fixture.md records it.
    ///
    /// Tag `62` FCP template; `82` file descriptor `09 21`; `83` file
    /// identifier `2F E2`; `A5` proprietary, empty; `8A` life cycle status
    /// `05`; `8C` compact access conditions; `80` file size `00 0A`.
    const EF_IMSI_FCP: [u8; 29] = [
        0x62, 0x1B, // FCP template
        0x82, 0x02, 0x09, 0x21, // file descriptor
        0x83, 0x02, 0x2F, 0xE2, // file identifier
        0xA5, 0x00, // proprietary information, empty
        0x8A, 0x01, 0x05, // life cycle status
        0x8C, 0x08, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // access conditions
        0x80, 0x02, 0x00, 0x0A, // file size
    ];

    /// SELECT MF on swSIM, shortened to the part this module reads.
    ///
    /// The master file's FCP carries no `80` at all: a master file has no
    /// size. That is why every tag in a [`TagSet`] is an `Option`.
    const MF_FCP: [u8; 10] = [
        0x62, 0x08, // FCP template
        0x82, 0x02, 0x38, 0x21, // file descriptor
        0x83, 0x02, 0x3F, 0x00, // file identifier
    ];

    #[test]
    fn the_two_known_tables_disagree_and_the_caller_chooses() {
        let swicc = TagSet::swicc();
        let iso = TagSet::iec_7816_4_table_42();

        // The finding, as code: the same three fields, three different tags.
        assert_eq!(swicc.file_size().map(Tag::octet), Some(0x80));
        assert_eq!(iso.file_size().map(Tag::octet), Some(0x82));
        assert_eq!(swicc.file_descriptor().map(Tag::octet), Some(0x82));
        assert_eq!(iso.file_descriptor().map(Tag::octet), Some(0x83));
        assert_eq!(swicc.file_id().map(Tag::octet), Some(0x83));
        assert_eq!(iso.file_id().map(Tag::octet), Some(0x84));

        // The two mappings are not interchangeable, and saying so is free.
        assert_ne!(swicc, iso);
        assert_ne!(swicc.name(), iso.name());
        assert_eq!(swicc.to_string(), swicc.name());
    }

    #[test]
    fn reading_a_card_with_the_wrong_table_reports_nonsense_not_nothing() {
        let body = &EF_IMSI_FCP[..];
        let swicc = TagSet::swicc();
        let iso = TagSet::iec_7816_4_table_42();

        let right = Template::parse(body, &swicc).unwrap();
        assert_eq!(right.file_size().unwrap().unwrap().octets(), 10);
        assert_eq!(right.file_id().unwrap(), Some([0x2F, 0xE2]));

        // The same bytes under the ISO table. The file identifier is simply
        // absent, because swSIM put it in `83`. The file size is not absent,
        // it is the file descriptor, read as a size, giving 2337: the exact
        // number docs/swsim-fixture.md records as the first failure of the
        // last leg of the fixture.
        let wrong = Template::parse(body, &iso).unwrap();
        assert_eq!(wrong.file_id().unwrap(), None);
        assert_eq!(wrong.file_size().unwrap().unwrap().octets(), 0x0921);
        assert_ne!(wrong.file_size().unwrap().unwrap().octets(), 10);
    }

    #[test]
    fn a_template_reports_the_dialect_it_was_read_under() {
        let swicc = TagSet::swicc();
        let template = Template::parse(&EF_IMSI_FCP, &swicc).unwrap();
        assert_eq!(template.dialect().name(), swicc.name());
        assert_eq!(template.dialect(), &swicc);
    }

    #[test]
    fn a_single_constructed_atom_is_unwrapped_as_a_template() {
        let swicc = TagSet::swicc();
        let template = Template::parse(&EF_IMSI_FCP, &swicc).unwrap();

        // The envelope is kept, because which one a card uses is a fact.
        assert_eq!(template.envelope().map(|a| a.tag().octet()), Some(0x62));
        // And the body is the fields, not the wrapper.
        assert_eq!(template.body().len(), 0x1B);
        assert_eq!(template.atoms().len(), 6);
        assert_eq!(
            template
                .atoms()
                .iter()
                .map(|a| a.tag().octet())
                .collect::<Vec<_>>(),
            vec![0x82, 0x83, 0xA5, 0x8A, 0x8C, 0x80]
        );
    }

    #[test]
    fn several_top_level_atoms_are_the_fields_and_are_not_unwrapped() {
        let swicc = TagSet::swicc();
        // The same fields with the template tag already stripped, which is
        // what a caller that unwrapped by hand has.
        let fields = &EF_IMSI_FCP[2..];
        let template = Template::parse(fields, &swicc).unwrap();
        assert_eq!(template.envelope(), None);
        assert_eq!(template.atoms().len(), 6);
        assert_eq!(template.file_id().unwrap(), Some([0x2F, 0xE2]));

        // One primitive atom is a single field, not an envelope.
        let one = [0x83, 0x02, 0x2F, 0xE2];
        let single = Template::parse(&one, &swicc).unwrap();
        assert_eq!(single.envelope(), None);
        assert_eq!(single.file_id().unwrap(), Some([0x2F, 0xE2]));
    }

    #[test]
    fn an_empty_template_parses_to_nothing_rather_than_failing() {
        let swicc = TagSet::swicc();
        let body = [0x62, 0x00];
        let template = Template::parse(&body, &swicc).unwrap();
        assert!(template.atoms().is_empty());
        assert_eq!(template.file_size().unwrap(), None);
        assert_eq!(template.file_id().unwrap(), None);

        // An empty body is the same answer.
        let bare = Template::parse(&[], &swicc).unwrap();
        assert!(bare.atoms().is_empty());
        assert!(bare.envelope().is_none());
    }

    #[test]
    fn a_truncated_template_is_an_error_and_never_a_partial_read() {
        let swicc = TagSet::swicc();
        // The template claims 27 octets and supplies 20.
        let body = &EF_IMSI_FCP[..22];
        assert!(matches!(Template::parse(body, &swicc), Err(Error::Tlv(_))));

        // Truncation inside the unwrapped template is caught too, not
        // silently treated as the end of the fields.
        let inner = [0x62, 0x04, 0x82, 0x02, 0x09];
        assert!(matches!(
            Template::parse(&inner, &swicc),
            Err(Error::Tlv(_))
        ));
    }

    #[test]
    fn a_non_minimal_length_inside_a_template_is_accepted() {
        const BODY: [u8; 15] = [
            0x62, 0x0D, // FCP template
            0x82, 0x81, 0x02, 0x09, 0x21, // file descriptor, long-form length
            0x83, 0x02, 0x2F, 0xE2, // file identifier
            0x80, 0x81, 0x01, 0x0A, // file size, long-form length
        ];
        let swicc = TagSet::swicc();
        let template = Template::parse(&BODY, &swicc).unwrap();
        assert_eq!(template.atoms().len(), 3);
        assert_eq!(template.file_size().unwrap().unwrap().octets(), 10);
        assert_eq!(
            template.file_descriptor().unwrap().unwrap().octets(),
            &[0x09, 0x21]
        );
    }

    #[test]
    fn a_master_file_has_no_size_and_the_decoder_says_so() {
        let swicc = TagSet::swicc();
        let template = Template::parse(&MF_FCP, &swicc).unwrap();
        assert_eq!(template.file_size().unwrap(), None);
        assert_eq!(template.file_id().unwrap(), Some([0x3F, 0x00]));

        let descriptor = template.file_descriptor().unwrap().unwrap();
        assert_eq!(descriptor.file_type(), FileType::Directory);

        // And a mapping that claims no file-size tag at all also reports
        // None, rather than borrowing another field's tag to fill the gap.
        let bare = TagSet::named("size unknown on this card");
        assert_eq!(
            Template::parse(&EF_IMSI_FCP, &bare)
                .unwrap()
                .file_size()
                .unwrap(),
            None
        );
    }

    #[test]
    fn the_file_descriptor_distinguishes_a_directory_from_a_transparent_file() {
        let swicc = TagSet::swicc();

        // MF: `38 21`. Category 111, structure 000, not shareable.
        let mf = Template::parse(&MF_FCP, &swicc).unwrap();
        let mf_descriptor = mf.file_descriptor().unwrap().unwrap();
        assert_eq!(mf_descriptor.octets(), &[0x38, 0x21]);
        assert_eq!(mf_descriptor.file_type(), FileType::Directory);
        assert!(!mf_descriptor.is_shareable());
        assert_eq!(mf_descriptor.data_coding(), Some(0x21));

        // EF.IMSI: `09 21`. Category 001, structure 001.
        let ef = Template::parse(&EF_IMSI_FCP, &swicc).unwrap();
        let ef_descriptor = ef.file_descriptor().unwrap().unwrap();
        assert_eq!(ef_descriptor.octets(), &[0x09, 0x21]);
        assert_eq!(ef_descriptor.file_type(), FileType::Elementary);
        assert_eq!(ef_descriptor.structure(), Structure::Transparent);
        assert!(!ef_descriptor.structure().is_record_structured());

        // A linear-fixed EF is category `001` with structure `010`, which is
        // the shape that makes READ BINARY the wrong command. swSIM answers
        // EF.DIR that way and answers `69 81` to READ BINARY.
        //
        // Octet 1 laid out: 0 | category 001 | structure 010 = 0b0000_1010.
        let linear_fixed = [0b0000_1010u8, 0x21];
        let dir = FileDescriptor::decode(&linear_fixed, Tag::new(0x82)).unwrap();
        assert_eq!(dir.structure(), Structure::LinearFixed);
        assert!(dir.structure().is_record_structured());
        assert_eq!(dir.file_type(), FileType::Elementary);
    }

    #[test]
    fn the_descriptor_bits_are_where_swicc_puts_them() {
        // Property, not a table of literals: for every octet, the two
        // decoded views are exactly the bit fields they claim to be. A
        // decoder that shifted by the wrong amount fails here for 256
        // inputs rather than for the two the card happens to send.
        for octet in u8::MIN..=u8::MAX {
            let bytes = [octet, 0x21];
            let descriptor = FileDescriptor::decode(&bytes, Tag::new(0x82)).unwrap();
            assert_eq!(
                descriptor.category_bits(),
                (octet >> 3) & 0b111,
                "{octet:02X}"
            );
            assert_eq!(descriptor.structure_bits(), octet & 0b111, "{octet:02X}");
            assert_eq!(descriptor.is_shareable(), octet & 0x80 != 0, "{octet:02X}");
            // A structure this crate cannot name carries its own bits, so
            // nothing is ever silently dropped.
            if let Structure::Unknown(raw) = descriptor.structure() {
                assert_eq!(raw, octet & 0b111);
            }
        }
    }

    #[test]
    fn a_file_size_is_one_to_four_big_endian_octets() {
        for (encoded, expected) in [
            (&[0x0Au8][..], 10u32),
            (&[0x00, 0x0A], 10),
            (&[0x01, 0x00, 0x00], 65536),
            (&[0xFF, 0xFF, 0xFF, 0xFF], u32::MAX),
            (&[0x00], 0),
        ] {
            let size = FileSize::decode(encoded, Tag::new(0x80)).unwrap();
            assert_eq!(size.octets(), expected);
            assert_eq!(size.to_string(), format!("{expected} octets"));
        }

        // Empty is not zero, and five octets is a value this module refuses
        // to invent a type for. Both are reported, not rounded.
        for bad in [&[] as &[u8], &[0x01, 0x02, 0x03, 0x04, 0x05]] {
            assert_eq!(
                FileSize::decode(bad, Tag::new(0x80)),
                Err(Error::malformed(
                    "file size",
                    Tag::new(0x80),
                    bad.len(),
                    "one to four octets",
                ))
            );
        }
    }

    #[test]
    fn a_wrong_sized_field_is_an_error_naming_the_tag_it_came_from() {
        let swicc = TagSet::swicc();

        // A three-octet file identifier is not an identifier, and reading
        // the first two octets would fabricate an address.
        let body = [0x62, 0x05, 0x83, 0x03, 0x2F, 0xE2, 0x00];
        assert_eq!(
            Template::parse(&body, &swicc).unwrap().file_id(),
            Err(Error::malformed(
                "file identifier",
                Tag::new(0x83),
                3,
                "two octets",
            ))
        );

        // A one-octet file descriptor is not a descriptor block.
        let short = [0x62, 0x03, 0x82, 0x01, 0x09];
        assert_eq!(
            Template::parse(&short, &swicc)
                .unwrap()
                .file_descriptor()
                .map(|descriptor| descriptor.map(|d| d.octets().to_vec())),
            Err(Error::malformed(
                "file descriptor",
                Tag::new(0x82),
                1,
                "at least two octets",
            ))
        );

        // A two-octet life cycle status is not one octet.
        let status = [0x62, 0x04, 0x8A, 0x02, 0x05, 0x00];
        assert_eq!(
            Template::parse(&status, &swicc)
                .unwrap()
                .life_cycle_status(),
            Err(Error::malformed(
                "life cycle status",
                Tag::new(0x8A),
                2,
                "one octet",
            ))
        );
    }

    #[test]
    fn the_life_cycle_status_keeps_values_it_cannot_name() {
        let swicc = TagSet::swicc();
        assert_eq!(
            Template::parse(&EF_IMSI_FCP, &swicc)
                .unwrap()
                .life_cycle_status()
                .unwrap()
                .unwrap(),
            LifeCycleStatus::OPERATING_ACTIVATED
        );

        // A value this repository has not verified is kept whole and
        // rendered as hex. Mapping it onto the nearest known status would
        // be a scanner reporting something the card never said.
        let odd = [0x62, 0x03, 0x8A, 0x01, 0x7F];
        let status = Template::parse(&odd, &swicc)
            .unwrap()
            .life_cycle_status()
            .unwrap()
            .unwrap();
        assert_eq!(status.byte(), 0x7F);
        assert_eq!(status.to_string(), "7F");
        assert_ne!(status, LifeCycleStatus::OPERATING_ACTIVATED);
        assert_eq!(LifeCycleStatus::from_byte(status.byte()), status);
    }

    #[test]
    fn access_conditions_keep_both_shapes_apart() {
        let swicc = TagSet::swicc();
        let template = Template::parse(&EF_IMSI_FCP, &swicc).unwrap();
        let conditions = template.access_conditions().unwrap().unwrap();

        assert!(conditions.is_compact());
        assert_eq!(
            conditions.octets(),
            &[0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );

        // Anything that is not the eight-octet form is handed over whole.
        // Collapsing the two would lose the fact that one of them is fixed
        // length and the other is not.
        let expanded = [0x62, 0x03, 0x8C, 0x01, 0x9F];
        let other = Template::parse(&expanded, &swicc).unwrap();
        let other = other.access_conditions().unwrap().unwrap();
        assert_eq!(other, AccessConditions::Expanded(&[0x9F]));
        assert!(!other.is_compact());
        assert_eq!(other.octets(), &[0x9F]);
    }

    #[test]
    fn the_compact_conditions_are_eight_octets_and_the_groups_are_their_bits() {
        let bytes = [0x7Fu8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let compact = CompactSecurityAttributes::decode(&bytes, Tag::new(0x8C)).unwrap();
        assert_eq!(compact.octets(), &bytes);

        // Property over every octet and every group index: the group is the
        // two bits at that position and nothing else. This is what makes the
        // groups safe to hand to a caller that has the clause open, even
        // though this crate has not read it.
        for octet in u8::MIN..=u8::MAX {
            let mut value = [0u8; 8];
            value[3] = octet;
            let compact = CompactSecurityAttributes::decode(&value, Tag::new(0x8C)).unwrap();
            for index in 12..16 {
                let shift = 6 - 2 * (index % 4);
                assert_eq!(
                    compact.conditions()[index],
                    (octet >> shift) & 0b11,
                    "{octet:02X}"
                );
            }
        }

        // swSIM's first octet, read as four groups: `01 11 11 11`, then
        // seven octets of zeros. Asserted as bits, not as a meaning.
        assert_eq!(&compact.conditions()[..4], &[0b01, 0b11, 0b11, 0b11]);
        assert!(compact.conditions()[4..].iter().all(|group| *group == 0));

        // Seven octets is not the compact form.
        assert_eq!(
            CompactSecurityAttributes::decode(&bytes[..7], Tag::new(0x8C)),
            Err(Error::malformed(
                "access conditions",
                Tag::new(0x8C),
                7,
                "eight octets in the compact form",
            ))
        );
    }

    #[test]
    fn tags_this_mapping_does_not_cover_are_listed_not_dropped() {
        let swicc = TagSet::swicc();
        let template = Template::parse(&EF_IMSI_FCP, &swicc).unwrap();
        // Everything in the captured FCP is claimed by the swICC mapping.
        assert!(template.tags_without_meaning().is_empty());

        // An atom the mapping says nothing about survives in `atoms` and
        // shows up here. Proprietary templates are full of these, and
        // dropping them would make a card look simpler than it is.
        let body = [0x62, 0x07, 0x82, 0x02, 0x38, 0x21, 0xF1, 0x01, 0xAA];
        let template = Template::parse(&body, &swicc).unwrap();
        assert_eq!(template.tags_without_meaning(), vec![Tag::new(0xF1)]);
        assert!(template.find(Tag::new(0xF1)).is_some());

        // A mapping that claims nothing claims nothing.
        let bare = TagSet::named("nothing mapped");
        let template = Template::parse(&EF_IMSI_FCP, &bare).unwrap();
        assert_eq!(template.tags_without_meaning().len(), 6);
        assert_eq!(template.file_id().unwrap(), None);
    }

    #[test]
    fn a_caller_can_supply_a_mapping_for_a_card_nobody_has_characterised() {
        // The design the module exists for: the mapping is a value, so a
        // scanner told which card it is reading can hand over the right one.
        let custom = TagSet::named("unidentified card")
            .with_file_id(Tag::new(0x83))
            .with_file_size(Tag::new(0x80));
        let template = Template::parse(&EF_IMSI_FCP, &custom).unwrap();
        assert_eq!(template.file_id().unwrap(), Some([0x2F, 0xE2]));
        assert_eq!(template.file_size().unwrap().unwrap().octets(), 10);
        // And the fields it says nothing about are simply not read.
        assert_eq!(template.life_cycle_status().unwrap(), None);
        assert_eq!(template.dialect().name(), "unidentified card");
    }

    #[test]
    fn no_short_body_panics_the_parser() {
        // Exhaustive over every three-octet body, both dialects. The property
        // is 'never panics and never returns something impossible': a card is
        // an untrusted input source and a decode path is reachable with
        // whatever bytes it felt like sending.
        let swicc = TagSet::swicc();
        let iso = TagSet::iec_7816_4_table_42();
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                for c in 0u16..=255 {
                    let body = [a as u8, b as u8, c as u8];
                    for dialect in [&swicc, &iso] {
                        let Ok(template) = Template::parse(&body, dialect) else {
                            continue;
                        };
                        // The atoms the walk handed back account for exactly
                        // the octets of the region it walked. A decoder that
                        // dropped an atom, invented one, or ran off the end
                        // fails here for some three-octet body.
                        let walked: usize = template.atoms().iter().map(Tlv::encoded_len).sum();
                        assert_eq!(walked, template.body().len(), "{body:02X?}");
                        assert!(template.body().len() <= body.len());
                    }
                }
            }
        }
    }
}
