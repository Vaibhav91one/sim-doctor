//! File identifiers, file kinds and file paths on a SIM.
//!
//! **Owns.** The vocabulary of the card file system: what a file is called
//! ([`FileId`]), whether it can hold other files ([`FileKind`]), and how a
//! file is addressed from the root ([`Path`]). This is the only module allowed
//! to depend on [`crate::apdu`] and [`crate::fcp`], because it is the only one
//! that knows both vocabularies at once: it can say "SELECT this file" and it
//! can read the file descriptor a card hands back.
//!
//! **Does not own.** Walking the tree, which is issue #7. This module can
//! address a file and read one identifier out of a response; it cannot list a
//! directory, enumerate children, or decide what a scan found. Decoding a file
//! capabilities template is [`crate::fcp`]'s, and [`selected_file_id`] is a
//! two-line adapter over it rather than a second TLV walker.
//!
//! **What `Path` deliberately does not know.** A path is a sequence of file
//! identifiers, and a sequence alone does not say whether the last segment is
//! a dedicated file or an elementary file - only the card knows, by answering
//! SELECT. So [`Path`] carries identifiers only and offers no `kind()` method,
//! rather than guessing and being wrong on every card whose layout differs.
//! [`FileKind::contains`] exists so that the caller which does know can check
//! the tree as it walks.

/// This module name, as recorded in [`crate::MODULES`].
///
/// Referenced by value rather than re-spelt as a literal so that the module
/// table cannot name a module that does not exist.
pub const NAME: &str = "fs";

use std::{fmt, str::FromStr};

use crate::{apdu, fcp};

/// The separator between file identifiers in a rendered [`Path`].
const SEPARATOR: char = '/';

/// A two-octet SIM file identifier.
///
/// Two octets, exactly, which is what makes it addressable. SIM tooling
/// writes them as four uppercase hex digits - `3F00`, `2FE2`, `6F3A` - and
/// this type follows that convention in both directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileId([u8; 2]);

impl FileId {
    /// The master file, the root of the file system, selected by `3F00`.
    ///
    /// Every path starts here, because a card has exactly one of them and a
    /// scanner starts at the top rather than at wherever it happens to be
    /// selected.
    pub const MASTER_FILE: Self = Self([0x3F, 0x00]);

    /// Builds a file identifier from its two octets, in wire order.
    pub const fn from_bytes(bytes: [u8; 2]) -> Self {
        Self(bytes)
    }

    /// The identifier as it appears on the wire.
    pub const fn to_bytes(self) -> [u8; 2] {
        self.0
    }

    /// Whether this is the master file.
    pub fn is_master_file(self) -> bool {
        self == Self::MASTER_FILE
    }
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X}{:02X}", self.0[0], self.0[1])
    }
}

impl FromStr for FileId {
    type Err = Error;

    /// Parses four hex digits, in either case.
    ///
    /// A file path is typed by a human at a prompt, so both cases are
    /// accepted; [`FileId`]'s own `Display` always emits uppercase.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.len() != 4 {
            return Err(Error::MalformedFileId {
                segment: text.to_owned(),
            });
        }
        let mut octets = [0u8; 2];
        for (index, octet) in octets.iter_mut().enumerate() {
            let digits = &text[index * 2..index * 2 + 2];
            *octet = u8::from_str_radix(digits, 16).map_err(|_| Error::MalformedFileId {
                segment: text.to_owned(),
            })?;
        }
        Ok(Self(octets))
    }
}

/// What a file is, in terms of what it can contain.
///
/// The master file and a dedicated file are the same kind of thing - a node
/// in the tree - and are kept apart only because `3F00` is genuinely special:
/// it is the root, it cannot be created, and it cannot be deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FileKind {
    /// The root of the file system, selected by `3F00`.
    MasterFile,
    /// A directory. Holds dedicated files and elementary files.
    DedicatedFile,
    /// A leaf. Holds data and nothing else.
    ElementaryFile,
}

impl FileKind {
    /// Whether files of this kind can hold other files.
    pub const fn is_container(self) -> bool {
        !matches!(self, Self::ElementaryFile)
    }

    /// Whether a file of this kind may directly contain a file of `child`.
    ///
    /// This is the tree rule a scanner walks: descend through dedicated
    /// files, read through elementary files, never into them. The master file
    /// is not a legal child of anything, including itself.
    pub const fn contains(self, child: Self) -> bool {
        self.is_container() && !matches!(child, Self::MasterFile)
    }
}

impl fmt::Display for FileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::MasterFile => "MF",
            Self::DedicatedFile => "DF",
            Self::ElementaryFile => "EF",
        };
        f.write_str(name)
    }
}

/// A file address from the root of the file system.
///
/// Always rooted at the master file and always including it, because that is
/// how a card addresses a file and because a scanner wants an absolute path
/// it can print, store, and compare against a saved baseline.
///
/// The identifiers alone. Which of them is a dedicated file and which is an
/// elementary file is not knowable from the path; see the module
/// documentation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Path {
    segments: Vec<FileId>,
}

impl Path {
    /// The path to the master file, which every other path extends.
    pub fn master_file() -> Self {
        Self {
            segments: vec![FileId::MASTER_FILE],
        }
    }

    /// Builds a path from a sequence of identifiers, first one first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotRootedAtMasterFile`] if the first identifier is
    /// not `3F00` and [`Error::NestedMasterFile`] if `3F00` appears again
    /// later. A path that starts somewhere else is not a path, it is a
    /// relative reference that would resolve differently depending on what
    /// the card had selected.
    pub fn from_segments(segments: impl IntoIterator<Item = FileId>) -> Result<Self, Error> {
        let segments: Vec<FileId> = segments.into_iter().collect();
        let Some((first, rest)) = segments.split_first() else {
            return Err(Error::NotRootedAtMasterFile { found: None });
        };
        if !first.is_master_file() {
            return Err(Error::NotRootedAtMasterFile {
                found: Some(*first),
            });
        }
        if let Some(duplicate) = rest.iter().find(|id| id.is_master_file()) {
            return Err(Error::NestedMasterFile { found: *duplicate });
        }
        Ok(Self { segments })
    }

    /// The path to a file directly inside this one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NestedMasterFile`] if `id` is the master file, which
    /// can only ever be the first segment.
    pub fn child(&self, id: FileId) -> Result<Self, Error> {
        if id.is_master_file() {
            return Err(Error::NestedMasterFile { found: id });
        }
        let mut segments = self.segments.clone();
        segments.push(id);
        Ok(Self { segments })
    }

    /// The path to the file containing this one, if there is one.
    ///
    /// `None` at the master file, which has no parent on the card.
    pub fn parent(&self) -> Option<Self> {
        if self.segments.len() <= 1 {
            return None;
        }
        Some(Self {
            segments: self.segments[..self.segments.len() - 1].to_vec(),
        })
    }

    /// The identifiers along the path, master file first.
    pub fn segments(&self) -> &[FileId] {
        &self.segments
    }

    /// The last identifier on the path.
    pub fn leaf(&self) -> FileId {
        // Construction keeps the master file at index 0 and `child` never
        // pushes onto an empty list, so this is always populated.
        self.segments[self.segments.len() - 1]
    }

    /// How many identifiers the path holds, counting the master file.
    ///
    /// A bare `3F00` has depth 1; `3F00/2FE2/6F3A` has depth 3.
    pub fn depth(&self) -> usize {
        self.segments.len()
    }

    /// Whether this is the master file and nothing below it.
    pub fn is_master_file(&self) -> bool {
        self.segments.len() == 1
    }
}

impl fmt::Display for Path {
    /// Renders as slash-separated uppercase hex, `3F00/2FE2/6F3A`.
    ///
    /// The rendering pySim and SIMTester both use. It is a convention rather
    /// than a mandated syntax, and [`FromStr`] reads back what this writes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, id) in self.segments.iter().enumerate() {
            if index > 0 {
                f.write_str("/")?;
            }
            write!(f, "{id}")?;
        }
        Ok(())
    }
}

impl FromStr for Path {
    type Err = Error;

    /// Parses a slash-separated path such as `3F00/2FE2/6F3A`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedFileId`] for a segment that is not four hex
    /// digits, including an empty one.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let segments = text
            .split(SEPARATOR)
            .map(FileId::from_str)
            .collect::<Result<Vec<_>, _>>()?;
        Path::from_segments(segments)
    }
}

/// The four-octet header of a SELECT command in the GSM 11.11 class.
///
/// `00 A4 00 00`, with the target file identifier in the data field. GSM
/// 11.11 sends that identifier unadorned, not wrapped in a TLV, which is why
/// this hands back an [`apdu::Header`] and an identifier rather than a
/// [`crate::tlv::Tlv`].
///
/// A free function rather than a method because there is exactly one SELECT
/// command; it is the same whether the target is the master file, a dedicated
/// file, or an elementary file, and only the data field changes.
pub fn select_header() -> apdu::Header {
    apdu::Header::new(0x00, 0xA4, 0x00, 0x00)
}

/// The header of a SELECT that asks for the file's capabilities template.
///
/// `00 A4 00 04`. P1 is the GSM 11.11 "select by file identifier" coding and
/// P2's bit b2 selects the file capabilities template as the response data.
///
/// **Issue #7 added this beside [`select_header`] because the two are not
/// interchangeable and only one of them is answerable by a UICC.** P2 `00` asks
/// for a file control information template, which ISO/IEC 7816-4 clause 7.5.1
/// allows and which swSIM answers, but swSIM's own 3GPP SELECT handler treats a
/// P2 that is neither `04` (FCP) nor `0C` (no response data) as RFU and answers
/// `6A 86` \\\[V], read in swSIM `src/apduh.c:apduh_3gpp_select` at swsim commit
/// `281da8c63398ece9a5126cad969674f4f413ab63`. A walk that wants a file's own
/// capabilities has to say so in P2, and saying so is this header.
///
/// [`select_header`] is left alone because its own test states the GSM 11.11
/// spelling rather than claiming a card will answer it.
pub fn select_capabilities_header() -> apdu::Header {
    apdu::Header::new(0x00, 0xA4, 0x00, 0x04)
}

/// The header of a SELECT addressed by an absolute path from the master file.
///
/// `00 A4 08 04`. P1 `08` is the 3GPP "select by path from the MF" coding and
/// the command data is the whole path with the master file's own identifier
/// removed, so the deepest file a walker addresses needs four octets of data.
///
/// This exists because a two-octet file identifier is not an absolute address.
/// GSM 11.11 reads a SELECT by file identifier against the master file, so on a
/// card that follows it, asking for a file inside a dedicated file by
/// identifier alone either resolves somewhere else or not at all. The path
/// form does not care what the card currently has selected.
///
/// swSIM answers both forms \\\[V], read in `src/apduh.c:apduh_3gpp_select` and
/// `src/fs/va.c:swicc_va_select_file_path` at swsim commit `281da8c6`: P1 `08`
/// walks the path one segment at a time from `3F00`, and a path the card does
/// not hold comes back `6A 82`. It needs at least one identifier in the data
/// field, so the master file itself cannot be addressed this way and
/// [`select_capabilities_header`] is used for it instead.
pub fn select_path_header() -> apdu::Header {
    apdu::Header::new(0x00, 0xA4, 0x08, 0x04)
}

/// The file identifier a SELECT response reports back, if it reports one.
///
/// Most SIM files do not echo their identifier, in which case this returns
/// `None` and the caller already knows which file it asked for. A card that
/// does echo it puts a two-octet FileID atom inside the file capabilities
/// template at the top of the response.
///
/// **Which tag that is, is the caller's decision.** `dialect` says which
/// table the card being read follows: [`fcp::TagSet::ts_102_221`] puts the
/// file identifier in `83`, and a hand-built [`fcp::TagSet::named`] can put it
/// anywhere. Hard-coding one is the bug AGENTS.md section 2 records, and the
/// parameter is how this function refuses to do it.
///
/// This reads one identifier and nothing else. Interpreting file size, file
/// type or access conditions is [`fcp`]'s, and deciding what a scan found is
/// issue #7's; this is the one adapter between the two vocabularies.
///
/// # Errors
///
/// Returns [`Error::Fcp`] if the body is not well-formed BER-TLV, or if the
/// file identifier atom holds anything other than two octets. The latter is
/// reported rather than truncated: reading the first two octets of a
/// three-octet value would fabricate an address the card never sent.
///
/// # Example
///
/// ```
/// use sim_doctor::{fcp::TagSet, fs};
///
/// // swSIM answers SELECT EF.IMSI with its identifier in `83`.
/// let body = [0x62, 0x04, 0x83, 0x02, 0x2F, 0xE2];
/// let id = fs::selected_file_id(&body, &TagSet::swicc())?;
/// assert_eq!(id.unwrap().to_string(), "2FE2");
/// # Ok::<(), fs::Error>(())
/// ```
pub fn selected_file_id(
    response_body: &[u8],
    dialect: &fcp::TagSet,
) -> Result<Option<FileId>, Error> {
    let Some(bytes) = fcp::Template::parse(response_body, dialect)?.file_id()? else {
        return Ok(None);
    };
    Ok(Some(FileId::from_bytes(bytes)))
}

/// Everything that can go wrong while naming a file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A path did not begin at the master file.
    #[error("a file path must start at the master file 3F00")]
    NotRootedAtMasterFile {
        /// The first identifier supplied, if there was one.
        found: Option<FileId>,
    },

    /// The master file appeared somewhere other than the start.
    #[error("the master file {found} may only be the first segment of a path")]
    NestedMasterFile {
        /// The misplaced master file.
        found: FileId,
    },

    /// A segment of a parsed path was not four hex digits.
    #[error("file identifier {segment:?} is not four hex digits")]
    MalformedFileId {
        /// The rejected segment.
        segment: String,
    },

    /// The response body was not usable as a file capabilities template.
    ///
    /// Either not well-formed BER-TLV, or well formed but carrying a file
    /// identifier of the wrong shape. [`crate::fcp::Error`] distinguishes the
    /// two, and a scan wants to as well.
    #[error("the response body is not a usable file capabilities template: {0}")]
    Fcp(#[from] fcp::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GSM 11.11 SIMFS: EF IMSI under DF GS, reached through DF TELECOM.
    const IMSI: &str = "3F00/2FE2/6F07";

    #[test]
    fn a_file_identifier_round_trips_and_renders_as_four_uppercase_digits() {
        let id = FileId::from_bytes([0x6F, 0x07]);
        assert_eq!(id.to_bytes(), [0x6F, 0x07]);
        assert_eq!(id.to_string(), "6F07");
        assert_eq!("6F07".parse::<FileId>().unwrap(), id);
        // A path is typed by a person, so either case parses; Display stays
        // canonical so that two runs print the same string.
        assert_eq!("6f07".parse::<FileId>().unwrap(), id);
        assert_eq!("6f07".parse::<FileId>().unwrap().to_string(), "6F07");
    }

    #[test]
    fn only_the_master_file_is_the_master_file() {
        assert!(FileId::MASTER_FILE.is_master_file());
        assert_eq!(FileId::MASTER_FILE.to_string(), "3F00");
        assert!(!FileId::from_bytes([0x3F, 0x01]).is_master_file());
        assert!(!FileId::from_bytes([0x2F, 0x00]).is_master_file());
    }

    #[test]
    fn a_malformed_file_identifier_is_named_in_the_error() {
        for text in ["", "3F", "3F000", "ZZZZ", "3F 0", "3F-0"] {
            assert_eq!(
                text.parse::<FileId>(),
                Err(Error::MalformedFileId {
                    segment: text.to_owned(),
                }),
                "{text:?} should not parse",
            );
        }
    }

    #[test]
    fn a_path_is_always_rooted_at_the_master_file() {
        let root = Path::master_file();
        assert_eq!(root.to_string(), "3F00");
        assert!(root.is_master_file());
        assert_eq!(root.depth(), 1);
        assert_eq!(root.leaf(), FileId::MASTER_FILE);

        // Not rooted: the first identifier names something else. As a
        // relative reference it would resolve differently depending on what
        // the card happened to have selected.
        assert_eq!(
            Path::from_segments([FileId::from_bytes([0x2F, 0x00])]),
            Err(Error::NotRootedAtMasterFile {
                found: Some(FileId::from_bytes([0x2F, 0x00])),
            }),
        );
        assert_eq!(
            Path::from_segments([]),
            Err(Error::NotRootedAtMasterFile { found: None }),
        );

        // Rooted, but wrapping back to the master file partway down.
        assert_eq!(
            Path::from_segments([FileId::MASTER_FILE, FileId::MASTER_FILE]),
            Err(Error::NestedMasterFile {
                found: FileId::MASTER_FILE,
            }),
        );
        assert_eq!(
            Path::master_file().child(FileId::MASTER_FILE),
            Err(Error::NestedMasterFile {
                found: FileId::MASTER_FILE,
            }),
        );
    }

    #[test]
    fn descending_and_climbing_a_path_are_inverses() {
        let imsi: Path = IMSI.parse().unwrap();
        assert_eq!(imsi.to_string(), IMSI);
        assert_eq!(imsi.depth(), 3);
        assert_eq!(imsi.leaf(), FileId::from_bytes([0x6F, 0x07]));
        assert!(!imsi.is_master_file());

        let gs = imsi.parent().unwrap();
        assert_eq!(gs.to_string(), "3F00/2FE2");
        assert_eq!(Path::master_file().child(gs.leaf()).unwrap(), gs);

        assert_eq!(gs.parent().unwrap(), Path::master_file());
        assert_eq!(Path::master_file().parent(), None);
    }

    #[test]
    fn a_parsed_path_normalizes_to_uppercase_and_round_trips() {
        let lower = "3f00/2fe2/6f07".parse::<Path>().unwrap();
        assert_eq!(lower.to_string(), IMSI);
        assert_eq!(lower.to_string().parse::<Path>().unwrap(), lower);
    }

    #[test]
    fn only_a_container_can_hold_a_file() {
        // The tree rule a scanner walks: descend through dedicated files,
        // read through elementary files, never into them.
        for parent in [FileKind::MasterFile, FileKind::DedicatedFile] {
            assert!(parent.is_container(), "{parent}");
            assert!(parent.contains(FileKind::DedicatedFile), "{parent} > DF");
            assert!(parent.contains(FileKind::ElementaryFile), "{parent} > EF");
            assert!(!parent.contains(FileKind::MasterFile), "{parent} > MF");
        }

        assert!(!FileKind::ElementaryFile.is_container());
        let every_kind = [
            FileKind::MasterFile,
            FileKind::DedicatedFile,
            FileKind::ElementaryFile,
        ];
        for child in every_kind {
            assert!(
                !FileKind::ElementaryFile.contains(child),
                "an EF holds nothing, not even {child}"
            );
        }

        assert_eq!(FileKind::MasterFile.to_string(), "MF");
        assert_eq!(FileKind::DedicatedFile.to_string(), "DF");
        assert_eq!(FileKind::ElementaryFile.to_string(), "EF");
    }

    #[test]
    fn select_is_the_one_command_every_file_opens_with() {
        let header = select_header();
        assert_eq!(header.to_string(), "00 A4 00 00");
        assert_eq!(header.to_bytes(), [0x00, 0xA4, 0x00, 0x00]);
    }

    #[test]
    fn a_response_that_echoes_its_identifier_is_read_out_of_the_template() {
        // A FileDescriptor template holding a two-octet FileID atom, which is
        // the shape a card answers SELECT with when it echoes at all. Tag 84
        // is not the standard FID tag, so the caller says so.
        let body = [0x6F, 0x07, 0x84, 0x02, 0x2F, 0xE2, 0x82, 0x01, 0x02];
        let iso = fcp::TagSet::named("fid in 84").with_file_id(crate::tlv::Tag::new(0x84));
        assert_eq!(
            selected_file_id(&body, &iso).unwrap(),
            Some(FileId::from_bytes([0x2F, 0xE2])),
        );
    }

    #[test]
    fn the_same_bytes_read_under_the_wrong_table_yield_nothing() {
        // The finding, as code: tag 84 is the file identifier under one table
        // and nothing at all under the other. Returning `None` rather than a
        // guess is the whole reason the mapping is a parameter.
        let body = [0x62, 0x04, 0x83, 0x02, 0x2F, 0xE2];
        assert_eq!(
            selected_file_id(&body, &fcp::TagSet::swicc()).unwrap(),
            Some(FileId::from_bytes([0x2F, 0xE2])),
        );

        let iso = fcp::TagSet::named("fid in 84").with_file_id(crate::tlv::Tag::new(0x84));
        assert_eq!(selected_file_id(&body, &iso).unwrap(), None);
    }

    #[test]
    fn a_response_that_echoes_nothing_returns_nothing() {
        // Most SIM files do not echo their identifier; the caller already
        // knows which file it asked for.
        let dialect = fcp::TagSet::swicc();
        let body = [0x62, 0x00];
        assert_eq!(selected_file_id(&body, &dialect).unwrap(), None);
        assert_eq!(selected_file_id(&[], &dialect).unwrap(), None);
    }

    #[test]
    fn an_echoed_identifier_of_the_wrong_size_is_an_error_not_a_guess() {
        // Three octets is not a file identifier, and reading the first two
        // would fabricate an identifier the card never sent.
        let dialect = fcp::TagSet::swicc();
        let body = [0x6F, 0x05, 0x83, 0x03, 0x2F, 0xE2, 0x00];
        let error = selected_file_id(&body, &dialect).unwrap_err();
        assert!(
            matches!(
                error,
                Error::Fcp(fcp::Error::MalformedField { found: 3, .. })
            ),
            "{error}"
        );
    }

    #[test]
    fn a_malformed_response_body_surfaces_the_tlv_failure() {
        // The template claims six octets and supplies three. The caller needs
        // to know the bytes were unusable, not that no file was found.
        let dialect = fcp::TagSet::ts_102_221();
        let body = [0x6F, 0x06, 0x84, 0x02];
        assert!(matches!(
            selected_file_id(&body, &dialect),
            Err(Error::Fcp(fcp::Error::Tlv(_)))
        ));
    }
}
