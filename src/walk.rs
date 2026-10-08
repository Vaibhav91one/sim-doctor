//! Walking a card's file system, and everything a hostile card can do while.
//
//! **Owns.** The traversal: select the master file, probe every candidate
//! identifier underneath, decide which children are directories and which are
//! elementary, descend, and hand back a typed tree that a later scan serialises.
//! That is issue #7.
//
//! **Does not own.** Any of the vocabulary it uses. What a file is called is
//! [`crate::fs`]'s, what its capabilities template says is [`crate::fcp`]'s,
//! how a command is put on the wire and reassembled is [`crate::session`]'s, and
//! what a status word means is [`crate::apdu`]'s. This module issues commands
//! through [`crate::session::send`] and never re-issues a raw APDU, because the
//! session layer is where chaining, `61 xx` following and proactive-command
//! draining already live.
//
//! **The rule that shaped everything here: a file that is not there and a file
//! we are not allowed to read are different answers.** Collapsing them into one
//! "unreadable" turns a security finding into a formatting difference, so they
//! are separate variants of [`NodeState`] with no shared payload, a `match` has
//! to name both, and the status word that produced the difference is preserved
//! on the variants that carry one.
//
//! **No recursion, and bounds rather than a cycle detector.** The traversal is
//! an explicit stack of frames, so "how deep can this go" is answered by that
//! stack and not by the call stack, and a card that describes an infinite tree
//! cannot exhaust memory. Three independent bounds stop that case and all three
//! are reported rather than silently applied:
//
//! 1. a path deeper than [`Limits::max_depth`] is recorded with
////!       [`Note::Limit`] and not descended,
//! 2. the tree as a whole is capped by [`Limits::max_nodes`] and the number of
////!       directories expanded by [`Limits::max_directories`],
//! 3. the candidate identifiers of one directory are de-duplicated before the
////!       first probe, so a card that names a child twice creates one path, not
////!       two.
//!
//! **A repeated identifier is not a cycle, and that distinction matters.** A file
//! identifier is unique inside a directory and *not* across a card, so a
//! directory holding a child with the same two octets as one of its own
//! ancestors is describing a legal file. The walk records that as
//! [`Note::RepeatedAncestor`] and descends into it as usual.
//!
//! **There is no visited set to get wrong.** A path cannot be reached twice: the
//! node vector is the visited set, each directory probes a candidate
//! identifier exactly once, and a path is determined by its parent and its leaf.
//
//! **What it reads as "not there".** Only what a caller has said.
//! [`StatusMeaning`] is a table the caller supplies, and the one entry this
//! repository has verified is `6A 82`. Every other refusal keeps its status word
//! in [`NodeState::Refused`], because a decoder that answers a question instead
//! of saying it cannot is the worst failure mode available, and inventing an
//! "access denied" this project cannot cite would turn every protected file on
//! a real card into a finding it cannot justify.
//
//! **Not implemented here, deliberately.** Reading a directory's own listing,
//! EF.DIR. It is the efficient enumeration, and it is unavailable on the one
//! card this repository can test against: swSIM's GET RESPONSE rejects any P1
//! other than `00` `[V]`, swicc `src/apduh.c:apduh_res_get` at swicc commit
//! `421c8cdd`, while the 3GPP directory read is GET RESPONSE with P1 `81`. A
//! walker that used it would find nothing on the fixture and would look like a
//! broken walker rather than an unsupported strategy.
//!
//! **The cost of probing is deliberate, and here is the reason.** 1280
//! exchanges per directory against about twenty files that exist is a very poor
//! ratio, and the next person to read this will assume it is a mistake. It is
//! not. A directory's listing is a list the card chooses, and a file the card
//! holds but does not advertise is precisely the kind of hidden file a
//! security scan exists to find. Reading the listing is the *scanner*; probing
//! is the *audit*, and this is the audit. Anyone who wants the cheap path
//! builds it on top of [`Tree`] as a second [`Candidates`] strategy, next to
//! this one, rather than replacing it.
//!
//! **The cost is bounded in time as well as memory.** Every probe creates
//! exactly one node, but [`Limits::max_nodes`] counts only the files the card
//! selected (issue #90): an absent probe is recorded in the tree and costs an
//! exchange, yet spends no budget, because a real card has ~30 directories and
//! 1280 absent probes in each would exhaust any sane budget on nothing. The
//! time bound is instead [`Limits::max_directories`] x [`Limits::max_children`]
//! probes (64 x 1280 by default), since only an expanded directory is probed.
//! (Applications from EF.DIR add one SELECT for EF.DIR up front, up to sixteen
//! READ RECORDs, and a second SELECT per probe under an application.)
//!
//! **Applications.** A UICC exposes USIM and ISIM as applications selected by
//! AID, listed in EF.DIR (`2F00`, ETSI TS 102 221 clause 13.1), not as a DF under
//! the master file. The walk reads EF.DIR (READ RECORD only), SELECTs each AID
//! (P1 `04`) and probes its children by path from that application (P1 `09`). The
//! application is a child of the master file in the tree, walked before the
//! master file's other children, and its path reads `3F00/ADF:<AID hex>/6F07`
//! ([`fs::Path::adf`]).
//!
//! **And the default candidate set can miss a file.** [`Candidates::SimFamilies`]
//! probes the five GSM 11.11 identifier families and nothing else. Every
//! identifier on the swSIM profile is inside one of them, so it lost no coverage
//! there, and a card that puts a file anywhere else is **invisible to this
//! walk** rather than reported missing. A caller who has to be sure uses
//! [`Candidates::Range`] over the whole two-octet space.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "walk";

use std::{fmt, vec::IntoIter};

use crate::apdu::{Command, Header, Le, StatusWord};
use crate::fcp::{self, FileSize, LifeCycleStatus, TagSet};
use crate::fs::{self, FileId, FileKind, Path};
use crate::session::{self, Exchange, StopReason};
use crate::tlv::{Stream, Tag, Tlv};
use crate::transport::CardSession;

/// How many identifiers a directory is probed for unless told otherwise.
///
/// 1280: the five GSM 11.11 identifier families `2Fxx`, `4Fxx`, `5Fxx`,
/// `6Fxx` and `7Fxx`, 256 each. A UICC addresses a child by one of those five
/// first octets in practice, and probing the whole two-octet space instead would
/// be 65536 round trips per directory for no additional file.
pub const DEFAULT_MAX_CHILDREN: usize = 1280;

/// How deep below the master file a walk descends unless told otherwise.
///
/// Sixteen. A SIM file system is a handful of levels deep, so no real card
/// reaches this, and shallow enough that the walk's own stack cannot grow
/// without a caller having asked for it.
pub const DEFAULT_MAX_DEPTH: usize = 16;

/// How many files a walk records unless told otherwise.
///
/// Sixteen thousand files the card SELECTED; absent probes do not count. A card
/// with a full USIM application is a few hundred files, so this is two orders
/// of magnitude above a real card and exists only so that a card advertising an
/// unbounded tree produces a bounded tree and a [`Note::Limit`].
pub const DEFAULT_MAX_NODES: usize = 16_384;

/// How many directories a walk expands unless told otherwise.
///
/// Sixty-four. Every expanded directory costs one full probe of its identifier
/// space, so this is the real bound on how long a walk runs against a hostile
/// card.
pub const DEFAULT_MAX_DIRECTORIES: usize = 64;

/// How a walk asks the card for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Addressing {
    /// SELECT by file identifier: P1 `00`, two octets of data.
    ///
    /// The GSM 11.11 coding, and the one [`fs::select_capabilities_header`]
    /// builds. What a two-octet identifier means depends on the card: swSIM
    /// resolves it against the whole card `[V]`, `src/fs/va.c:
    /// swicc_va_select_file_id` calls `swicc_disk_lutid_lookup` over every
    /// tree, so under this addressing a file inside an application directory is
    /// reachable from the master file and the resulting tree is not the one the
    /// card's directory structure describes.
    Identifier,

    /// SELECT by path from the master file: P1 `08`, the absolute path with
    /// the master file's own identifier removed.
    ///
    /// The default. It is the only form that names a file unambiguously
    /// regardless of what the card currently has selected, which is what a tree
    /// of absolute paths has to be built from. The master file itself has no
    /// path to be named by, so it falls back to [`Addressing::Identifier`]
    /// whichever variant is in force.
    PathFromMasterFile,
}

impl fmt::Display for Addressing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Identifier => "SELECT by file identifier",
            Self::PathFromMasterFile => "SELECT by path from the master file",
        })
    }
}

/// Which identifiers a walk probes underneath one directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Candidates {
    /// Every identifier between `first` and `last`, inclusive.
    ///
    /// A range over the whole two-octet space builds 65536 identifiers before
    /// the budget truncates it, which is a quarter of a megabyte per
    /// directory. That is a caller asking for it and the walk survives it, but
    /// [`Candidates::SimFamilies`] is the shape that actually covers a card.
    Range {
        /// The lowest identifier probed.
        first: FileId,
        /// The highest identifier probed.
        last: FileId,
    },

    /// The five GSM 11.11 families: every identifier of the form `xFxx` for
    /// `x` in 2, 4, 5, 6 and 7. 1280 identifiers.
    ///
    /// The default, and the only enumeration that works on the swSIM fixture,
    /// for the reason the module documentation gives.
    ///
    /// **This default can miss files, and that is a choice rather than an
    /// oversight.** Every identifier on the swSIM USIM profile falls inside one
    /// of these five families, so narrowing to them cost no coverage *on that
    /// card* `[V]`. A card that puts a file anywhere else - an identifier whose
    /// first octet is not 2, 4, 5, 6 or 7 - is **invisible to this walk**, and
    /// the walk cannot report it missing, because no probe ever happened. A
    /// caller who needs certainty uses [`Candidates::Range`] over the whole
    /// two-octet space, or a [`Candidates::List`] built from the card's own
    /// directory listing.
    #[default]
    SimFamilies,

    /// Exactly these identifiers, in identifier order, duplicates dropped.
    List(Vec<FileId>),
}

impl Candidates {
    /// The identifiers to probe, in the order they will be tried, and whether
    /// anything was lost to the budget.
    ///
    /// Public because a caller has to be able to know what a walk is going to
    /// ask for. A scan that cannot enumerate its own candidate set cannot
    /// report that it covered everything, and `Candidates` is where a card
    /// outside the default families would otherwise go unnoticed.
    ///
    /// The master file is *not* removed here even though it can never be a
    /// child. A caller who lists `3F00` deserves to be told the walk refused
    /// the probe, which is [`Note::NotAChild`, rather than to find it quietly
    /// missing from a candidate list they wrote.
    ///
    /// Duplicate identifiers are dropped here. A card that answers the same
    /// probe twice would otherwise create two identical paths, and the second
    /// one is the first one re-entered.
    ///
    /// Truncated to `budget` identifiers, and the second element says whether
    /// anything was lost. A range wider than the budget loses its high end, and
    /// the walk records that on the directory rather than reporting a partial
    /// listing as a whole one.
    pub fn identifiers(self, budget: usize) -> (Vec<FileId>, bool) {
        let mut out: Vec<FileId> = match self {
            Self::Range { first, last } => {
                let first = u16::from_be_bytes(first.to_bytes());
                let last = u16::from_be_bytes(last.to_bytes());
                if first > last {
                    return (Vec::new(), false);
                }
                (first..=last)
                    .map(|value| FileId::from_bytes(value.to_be_bytes()))
                    .collect()
            }
            Self::SimFamilies => {
                let mut families = Vec::with_capacity(DEFAULT_MAX_CHILDREN);
                for family in [0x2Fu8, 0x4F, 0x5F, 0x6F, 0x7F] {
                    for low in 0u16..=0xFF {
                        families.push(FileId::from_bytes([family, low as u8]));
                    }
                }
                families
            }
            Self::List(ids) => ids,
        };
        out.sort_unstable();
        out.dedup();
        let truncated = out.len() > budget;
        out.truncate(budget);
        (out, truncated)
    }
}

/// The two meanings a refusal can carry, kept apart because a scan reports them
/// apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalKind {
    /// The file is not on the card.
    Absent,

    /// The file is on the card and this terminal is not allowed to have it.
    Forbidden,
}

impl fmt::Display for RefusalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Absent => "absent",
            Self::Forbidden => "forbidden",
        })
    }
}

/// Which status words a walk reads as what, supplied by the caller.
///
/// A table rather than a built-in mapping, for the same reason
/// [`crate::fcp::TagSet`] is: a card decides which of its status words means
/// "not there", and this repository has read exactly one of them.
///
/// The [`Default`] implementation carries that one verified entry and nothing
/// else. `6A 82` is "file not found" in ISO/IEC 7816-4 clause 9.1.2 and swSIM
/// writes it with the comment `0x82, /* "Not found" */` `[V]`, read in swicc
/// `src/apduh.c:apduh_select` at swicc commit `421c8cdd`. Nothing else is
/// classified, so every other refusal reaches the caller as
/// [`NodeState::Refused`] with its status word intact.
///
/// A caller who has read their card's own table adds to it:
///
/// ```
/// use sim_doctor::{apdu::StatusWord, walk::{RefusalKind, StatusMeaning}};
///
/// let meaning = StatusMeaning::default().with_forbidden(StatusWord::new(0x94, 0x03));
/// assert_eq!(
///     meaning.meaning(StatusWord::new(0x6A, 0x82)),
///     Some(RefusalKind::Absent)
/// );
/// assert_eq!(
///     meaning.meaning(StatusWord::new(0x94, 0x03)),
///     Some(RefusalKind::Forbidden)
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusMeaning {
    absent: Vec<StatusWord>,
    forbidden: Vec<StatusWord>,
}

impl Default for StatusMeaning {
    /// The one classification this repository has verified: `6A 82` is absent.
    fn default() -> Self {
        Self {
            absent: vec![StatusWord::new(0x6A, 0x82)],
            forbidden: Vec::new(),
        }
    }
}

impl StatusMeaning {
    /// A table that classifies nothing, so every refusal is
    /// [`NodeState::Refused`] with its status word attached.
    ///
    /// For a card nobody has characterised. [`Default`] is
    /// [`StatusMeaning::file_not_found`] because one verified entry is better
    /// than none and is still only one entry; this is the zero of that.
    pub const fn unverified() -> Self {
        Self {
            absent: Vec::new(),
            forbidden: Vec::new(),
        }
    }

    /// The one classification this repository has verified: `6A 82` means
    /// absent. See the type documentation.
    pub fn file_not_found() -> Self {
        Self::default()
    }

    /// Adds a status word this card uses to mean "not there".
    pub fn with_absent(mut self, status: StatusWord) -> Self {
        self.absent.push(status);
        self
    }

    /// Adds a status word this card uses to mean "not allowed to read".
    ///
    /// No such status word is known here, which is exactly why this is a
    /// builder and not a constant. A real card distinguishes a protected file
    /// from a missing one, and 3GPP TS 102 221 assigns meanings in the `94 xx`
    /// range, but this repository has not read that table and the GSMA login
    /// problem in CONTEXT.md section 6 is about a neighbouring one. Guessing
    /// would turn every protected file on a real card into a finding this
    /// project cannot justify. The caller who has the table says so; nothing
    /// else does.
    pub fn with_forbidden(mut self, status: StatusWord) -> Self {
        self.forbidden.push(status);
        self
    }

    /// What `status` means, or `None` if this table says nothing about it.
    ///
    /// Absent is checked first. A status word in both lists is a caller error,
    /// and resolving it towards "not there" is the reading that cannot invent a
    /// finding.
    pub fn meaning(&self, status: StatusWord) -> Option<RefusalKind> {
        if self.absent.contains(&status) {
            Some(RefusalKind::Absent)
        } else if self.forbidden.contains(&status) {
            Some(RefusalKind::Forbidden)
        } else {
            None
        }
    }

    /// The status words this table reads as absent.
    pub fn absent(&self) -> &[StatusWord] {
        &self.absent
    }

    /// The status words this table reads as forbidden.
    pub fn forbidden(&self) -> &[StatusWord] {
        &self.forbidden
    }
}

/// The bounds a walk runs inside.
///
/// Every one of these exists because the card is assumed hostile. A default is a
/// number, never an absence of a bound, and [`Limits::validate`] refuses a zero
/// rather than letting one quietly mean "expand nothing".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Limits {
    /// Deepest path below the master file that will be descended into.
    pub max_depth: usize,

    /// Most identifiers probed under one directory.
    pub max_children: usize,

    /// Most files the card selected, across the whole walk (absent probes are
    /// recorded but not counted).
    pub max_nodes: usize,

    /// Most directories whose children will be enumerated.
    pub max_directories: usize,
}

impl Default for Limits {
    /// [`DEFAULT_MAX_DEPTH`], [`DEFAULT_MAX_CHILDREN`],
    /// [`DEFAULT_MAX_NODES`] and [`DEFAULT_MAX_DIRECTORIES`].
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_children: DEFAULT_MAX_CHILDREN,
            max_nodes: DEFAULT_MAX_NODES,
            max_directories: DEFAULT_MAX_DIRECTORIES,
        }
    }
}

/// One of the bounds a walk can hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Limit {
    /// [`Limits::max_depth`].
    Depth,

    /// [`Limits::max_children`].
    Children,

    /// [`Limits::max_nodes`].
    Nodes,

    /// [`Limits::max_directories`].
    Directories,
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Depth => "maximum path depth",
            Self::Children => "maximum identifiers per directory",
            Self::Nodes => "maximum number of files",
            Self::Directories => "maximum number of directories",
        })
    }
}

impl Limits {
    /// Checks that every bound is at least one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroLimit`] naming the field, because a zero bound
    /// means "expand nothing" or "record nothing", and a caller who meant
    /// "unlimited" should be told rather than handed an empty tree.
    pub const fn validate(&self) -> Result<(), Error> {
        if self.max_depth == 0 {
            return Err(Error::ZeroLimit { field: "max_depth" });
        }
        if self.max_children == 0 {
            return Err(Error::ZeroLimit {
                field: "max_children",
            });
        }
        if self.max_nodes == 0 {
            return Err(Error::ZeroLimit { field: "max_nodes" });
        }
        if self.max_directories == 0 {
            return Err(Error::ZeroLimit {
                field: "max_directories",
            });
        }
        Ok(())
    }
}

/// How a walk is configured.
///
/// There is a [`Default`], unlike [`crate::fcp::TagSet`] which deliberately has
/// none, and the difference is the point. A tag table decides what a number in
/// a capabilities template *means* and two cards disagree about that; a status
/// word's meaning is fixed by the standards both cards answer to, and the one
/// this repository has verified is the same everywhere. So the defaults are
/// named, every one is a constant on this module, and every one can be replaced
/// by a caller who has read further.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// How files are addressed. Defaults to
    /// [`Addressing::PathFromMasterFile`].
    pub addressing: Addressing,

    /// Which identifiers are probed. Defaults to [`Candidates::SimFamilies`].
    ///
    /// **The default can miss a file on a card that does not follow GSM 11.11's
    /// identifier families.** See that variant's documentation. A scan that has
    /// to be sure replaces this.
    pub candidates: Candidates,

    /// Which status words mean what. Defaults to [`StatusMeaning::default`].
    pub meaning: StatusMeaning,

    /// The bounds. Defaults to [`Limits::default`].
    pub limits: Limits,

    /// How the session layer chains, follows up and drains. Defaults to
    /// [`session::Policy::default`], the policy the swSIM fixture exercises.
    pub session: session::Policy,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            addressing: Addressing::PathFromMasterFile,
            candidates: Candidates::default(),
            meaning: StatusMeaning::default(),
            limits: Limits::default(),
            session: session::Policy::default(),
        }
    }
}

/// What a card said about one field of a capabilities template.
///
/// Three answers, because two of them are findings and collapsing them is how a
/// scanner ends up reporting a card as simpler than it is: the card said it and
/// it decoded, the card did not say it, or the card said it and it did not
/// decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reported<T> {
    /// The card sent the field and it decoded.
    Reported(T),

    /// The card did not send the field, or the supplied tag table has no tag
    /// for it. The two are not told apart because the tag table is the
    /// caller's own statement, and a caller who needs that difference has the
    /// table in front of them.
    NotReported,

    /// The card sent the field and it was not a shape the field can take.
    Unreadable(fcp::Error),
}

impl<T> Default for Reported<T> {
    /// Nothing was reported, which is the answer a card gives by omission.
    fn default() -> Self {
        Self::NotReported
    }
}

impl<T> Reported<T> {
    /// The value, if the card sent one that decoded.
    pub fn reported(&self) -> Option<&T> {
        match self {
            Self::Reported(value) => Some(value),
            Self::NotReported | Self::Unreadable(_) => None,
        }
    }

    /// Whether the card sent this field at all, whether or not it decoded.
    pub fn is_reported(&self) -> bool {
        matches!(self, Self::Reported(_) | Self::Unreadable(_))
    }

    /// The reason the field could not be read, if it was sent and unreadable.
    pub fn unreadable(&self) -> Option<&fcp::Error> {
        match self {
            Self::Unreadable(error) => Some(error),
            Self::Reported(_) | Self::NotReported => None,
        }
    }

    /// Maps the value, leaving the two non-value answers alone.
    pub fn map<U>(self, map: impl FnOnce(T) -> U) -> Reported<U> {
        match self {
            Self::Reported(value) => Reported::Reported(map(value)),
            Self::NotReported => Reported::NotReported,
            Self::Unreadable(error) => Reported::Unreadable(error),
        }
    }
}

/// A file descriptor block, copied out of the response buffer.
///
/// The octets are kept as well as the decoded bits, because a scanner that meets
/// a structure value this crate does not know wants the card's own bytes and not
/// a re-encoding of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// The descriptor octets exactly as the card sent them.
    pub octets: Vec<u8>,

    /// What kind of file the card says this is.
    pub file_type: fcp::FileType,

    /// How the file's contents are laid out.
    pub structure: fcp::Structure,

    /// Whether the card marked the file shareable.
    pub shareable: bool,

    /// The data coding octet, when the card sent one.
    pub data_coding: Option<u8>,
}

/// Everything one selected file said about itself.
///
/// Owned, not borrowed: a capabilities template borrows the response buffer it
/// was read out of, and a tree outlives every exchange that built it. The
/// fields are public because this is a plain record of what the card sent, with
/// no invariant a constructor could break.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// The constructed atom the template arrived wrapped in: `62` on the
    /// swSIM route, `6F` on the FCI route, `None` when the card sent the
    /// fields unwrapped.
    pub envelope: Option<Tag>,

    /// The identifier the card echoed back.
    pub reported_file_id: Reported<[u8; 2]>,

    /// The file size.
    pub size: Reported<FileSize>,

    /// The file descriptor block.
    pub descriptor: Reported<Descriptor>,

    /// The life cycle status.
    pub life_cycle: Reported<LifeCycleStatus>,

    /// The access condition octets, exactly as sent.
    pub access_conditions: Reported<Vec<u8>>,

    /// The dedicated file's name, trimmed of the padding a card writes.
    pub name: Reported<Vec<u8>>,

    /// The value of the referenced security attributes DO (`8B`), exactly as
    /// sent. Decoded by [`crate::access`].
    pub security_reference: Option<Vec<u8>>,

    /// The value of the expanded security attributes DO (`AB`), exactly as sent.
    pub security_expanded: Option<Vec<u8>>,

    /// The value of the PIN status template DO (`C6`), exactly as sent.
    pub pin_status: Option<Vec<u8>>,

    /// Tags the supplied mapping gives no meaning to, in wire order.
    pub unknown_tags: Vec<Tag>,
}

/// What kind of file a selected file is, and how sure the walk is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// The master file, by address: only `3F00` is one.
    MasterFile,

    /// The card's file descriptor said.
    Reported(FileKind),

    /// The card sent no descriptor this mapping can read, so nothing says
    /// whether the file holds other files.
    Unreported,
}

impl Kind {
    /// Whether a walk should descend into a file of this kind.
    ///
    /// False for [`Kind::Unreported`, deliberately. A card that does not say
    /// what a file is has not been told it is a directory, and descending on the
    /// strength of anything else would be guessing with a card's own storage on
    /// the other side.
    pub const fn is_container(self) -> bool {
        match self {
            Self::MasterFile | Self::Reported(FileKind::DedicatedFile) => true,
            Self::Reported(_) | Self::Unreported => false,
        }
    }

    /// The file kind, when the card said one.
    pub const fn as_file_kind(self) -> Option<FileKind> {
        match self {
            Self::MasterFile => Some(FileKind::MasterFile),
            Self::Reported(kind) => Some(kind),
            Self::Unreported => None,
        }
    }
}

/// What happened when the walk asked the card for a file.
///
/// `Absent` and `Forbidden` are separate variants with no shared payload. A
/// caller cannot match on "not selectable" without also matching on both, which
/// is the type-level half of the requirement that a scan reports a file that is
/// not there differently from a file it is not allowed to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeState {
    /// The card selected the file and said what it is.
    ///
    /// The capabilities are boxed because they are two orders of magnitude
    /// larger than the refusal variants, and a caller matching on this enum
    /// would otherwise have to copy one of them.
    Selected {
        /// What kind of file it is, and how that was decided.
        kind: Kind,
        /// What its capabilities template said.
        capabilities: Box<Capabilities>,
    },

    /// The card said the file is not there.
    Absent,

    /// The card said the file is there and this terminal may not have it.
    Forbidden {
        /// The status word that said so.
        status: StatusWord,
    },

    /// The card refused in some other way.
    ///
    /// The status word is kept verbatim so a caller can classify it itself
    /// rather than being handed a category this project cannot justify.
    /// `None` when the card answered with no status word at all, which is what
    /// a response ending on a procedure byte looks like.
    Refused {
        /// The status word, when there was one.
        status: Option<StatusWord>,
    },
}

impl NodeState {
    /// Whether the card selected the file.
    pub const fn is_selected(&self) -> bool {
        matches!(self, Self::Selected { .. })
    }

    /// Why the card did not select the file, or `None` when it did or when the
    /// walk could not classify the refusal.
    ///
    /// `None` for [`NodeState::Refused`] on purpose: a refusal this crate
    /// cannot classify is not an absent file and is not a forbidden one, and the
    /// two questions it cannot answer should not be answered by returning
    /// `None` from a function whose name implies one of them.
    pub const fn refusal(&self) -> Option<RefusalKind> {
        match self {
            Self::Absent => Some(RefusalKind::Absent),
            Self::Forbidden { .. } => Some(RefusalKind::Forbidden),
            Self::Selected { .. } | Self::Refused { .. } => None,
        }
    }

    /// The status word the card answered with, if it answered with one.
    pub const fn status(&self) -> Option<StatusWord> {
        match self {
            Self::Forbidden { status } => Some(*status),
            Self::Refused { status } => *status,
            Self::Selected { .. } | Self::Absent => None,
        }
    }

    /// The capabilities the card reported, when it selected the file.
    pub fn capabilities(&self) -> Option<&Capabilities> {
        match self {
            Self::Selected { capabilities, .. } => Some(capabilities),
            Self::Absent | Self::Forbidden { .. } | Self::Refused { .. } => None,
        }
    }

    /// What kind of file this is, when the card said.
    pub const fn kind(&self) -> Option<Kind> {
        match self {
            Self::Selected { kind, .. } => Some(*kind),
            Self::Absent | Self::Forbidden { .. } | Self::Refused { .. } => None,
        }
    }
}

/// Something the walk did not do, and why.
///
/// Notes are the reason a tree is not a complete picture of a card, and every
/// one of them is reachable from the node it belongs to. A scan that reports a
/// tree without reporting these reports a smaller card than the one it met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// This file's identifier repeats one already on the path leading to it.
    ///
    /// **Not a cycle, and not a reason to stop.** A file identifier is unique
    /// inside a directory and not across a card, so this is a legal file and
    /// the walk descends into it as usual. It is recorded because a card that
    /// puts a directory inside itself is worth a finding, and because a walk
    /// that stopped here would silently hide half of a legal card.
    RepeatedAncestor {
        /// The identifier that was repeated.
        id: FileId,
        /// The node whose identifier it repeats.
        ancestor: Path,
    },

    /// A bound stopped the walk here.
    Limit {
        /// Which bound.
        limit: Limit,
    },

    /// A probed identifier cannot be a child of the directory it was found
    /// under, which today means it named the master file.
    NotAChild {
        /// The identifier that could not be a child.
        id: FileId,
    },

    /// Nothing under this directory could be selected, and every probe drew a
    /// status this walk does not read as "not there".
    ///
    /// This is the difference between "this directory is empty" and "this card
    /// did not understand the question", and without it the first would be
    /// reported whenever the second happened. A directory whose probes were
    /// uniformly `6A 82` does not raise it, because that *is* the answer.
    EnumerationRefused {
        /// The status word every probe drew.
        status: StatusWord,
        /// How many identifiers were probed.
        probed: usize,
    },

    /// The selection did not end on a clean answer.
    IncompleteSelection {
        /// Why the session layer stopped issuing exchanges.
        stop: StopReason,
    },

    /// The card selected the file but its capabilities template would not parse,
    /// so nothing is known about it beyond its address.
    ///
    /// A selected file with an unreadable template is still a selected file: the
    /// address, the kind the walk decided and the rest of the tree around it all
    /// survive. Only the capabilities are missing, and saying so is the point.
    UnreadableTemplate {
        /// The decoding failure, verbatim.
        error: fcp::Error,
    },

    /// The card echoed a file identifier that is not the one that was asked for.
    ///
    /// Either the card answered with a different file than the one named, or the
    /// tag table reads the wrong tag. Both are worth a finding and neither is
    /// this crate's to resolve.
    IdentityMismatch {
        /// The identifier that was asked for.
        requested: FileId,
        /// The identifier the card echoed.
        reported: FileId,
    },
}

/// A handle to one node of a [`Tree`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(usize);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// One file the walk reached, or tried to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    id: NodeId,
    path: Path,
    state: NodeState,
    children: Vec<NodeId>,
    notes: Vec<Note>,
    subtree: usize,
}

impl Node {
    /// This node's handle in the tree that holds it.
    pub const fn id(&self) -> NodeId {
        self.id
    }

    /// The absolute path, rooted at the master file.
    pub const fn path(&self) -> &Path {
        &self.path
    }

    /// What the card said about this file.
    pub const fn state(&self) -> &NodeState {
        &self.state
    }

    /// The files probed underneath this one, in identifier order.
    pub fn children(&self) -> &[NodeId] {
        &self.children
    }

    /// Everything the walk did not do at or under this node.
    pub fn notes(&self) -> &[Note] {
        &self.notes
    }

    /// Whether this node carries any note at all.
    pub fn is_complete(&self) -> bool {
        self.notes.is_empty()
    }
}

/// What a walk found, counted.
///
/// Not [`Copy`], because the set of bounds a walk hit is a small heap vector
/// and copying it into every accessor was not worth a field that a caller could
/// forget to propagate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalkReport {
    /// Files recorded, including the ones that were not selected.
    pub nodes: usize,

    /// Directories whose children were enumerated.
    pub directories: usize,

    /// Files the card selected.
    pub selected: usize,

    /// Files the card said are not there.
    pub absent: usize,

    /// Files the card said we may not read.
    pub forbidden: usize,

    /// Files refused in some other way.
    pub refused: usize,

    /// Identifiers that repeated one already on their own path.
    pub repeated_ancestors: usize,

    /// Every bound the walk hit, in the order it hit them.
    ///
    /// **A caller that reports a tree has to report this.** A walk that stopped
    /// early did not see the whole card, and a file list an agent reads as a
    /// card's complete contents hides every file below the point where the walk
    /// stopped. That is a silent under-report of the attack surface, which is
    /// worse for this tool than refusing to produce a result at all, so the
    /// reason cannot be dropped on the way out: [`Tree::is_complete`] is false
    /// whenever this is not empty, and the JSON envelope in issue #8 has to
    /// carry it.
    ///
    /// Every entry is one of four values and the list is de-duplicated, so this
    /// is bounded whatever the card does. One entry is the ordinary case; more
    /// than one means a card that defeats several bounds at once, which is a
    /// finding in its own right.
    pub limits_hit: Vec<Limit>,

    /// The first bound that stopped the walk, if one did.
    ///
    /// Shorthand for the head of `limits_hit`. **Not the whole answer**: a walk
    /// that hit the depth bound and then ran out of node budget afterwards is
    /// reported here as depth alone, which understates how much of the card was
    /// missed. Read `limits_hit` to report it honestly.
    pub truncated_by: Option<Limit>,
}

impl WalkReport {
    /// Whether the tree is the whole card, or stopped early.
    pub fn is_truncated(&self) -> bool {
        !self.limits_hit.is_empty()
    }

    /// Whether one specific bound stopped the walk.
    pub fn hit(&self, limit: Limit) -> bool {
        self.limits_hit.contains(&limit)
    }
}

/// The result of a walk: a typed tree of every identifier that was asked about.
///
/// **Shape.** Nodes are held in pre-order, so a node and everything beneath it
/// is one contiguous slice. That is what lets [`Tree::descendants`] answer
/// without a second index, and it is a property of the traversal rather than a
/// promise: the walk builds a directory's whole subtree before it returns to the
/// directory's parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    nodes: Vec<Node>,
    report: WalkReport,
    addressing: Addressing,
    meaning: StatusMeaning,
    limits: Limits,
    dialect: String,
    access_rule_files: Vec<(Path, Vec<Vec<u8>>)>,
    content_reads: Vec<(Path, ContentRead)>,
}

/// What one read-only attempt at an EF's contents came back with
/// ([`crate::ef::read`]).
///
/// `Debug` prints the octets in full (full-visibility policy, issue #128).
#[derive(Clone, PartialEq, Eq)]
pub enum ContentRead {
    /// The card answered; one element for a transparent EF, one per record
    /// (record 1 first) for a linear fixed EF.
    Records(Vec<Vec<u8>>),
    /// The card refused the SELECT or the READ, with this status word.
    Refused(Option<StatusWord>),
}

impl fmt::Debug for ContentRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Records(r) => write!(f, "Records({r:02X?})"),
            Self::Refused(sw) => write!(f, "Refused({sw:?})"),
        }
    }
}

impl Tree {
    /// The master file, which every walk starts at.
    pub fn root(&self) -> NodeId {
        NodeId(0)
    }

    /// Whether this is the whole card, or the part of it the walk reached.
    ///
    /// **Checked before this tree is reported, never after.** A truncated walk
    /// is a finding about the walk, not a footnote: a caller that shows a file
    /// list without saying it stopped has told an agent the card holds fewer
    /// files than it does. See [`WalkReport::limits_hit`].
    pub fn is_complete(&self) -> bool {
        self.report.limits_hit.is_empty()
    }

    /// Every bound the walk hit, in the order it hit them.
    pub fn limits_hit(&self) -> &[Limit] {
        &self.report.limits_hit
    }

    /// The first bound that stopped the walk, if one did.
    ///
    /// Shorthand for [`Tree::report`]'s field of the same name, named because a
    /// caller reporting this tree should have to type the word *truncated*.
    /// Prefer [`Tree::limits_hit`], which does not hide a second bound.
    pub const fn truncated_by(&self) -> Option<Limit> {
        self.report.truncated_by
    }

    /// One node by handle.
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(id.0)
    }

    /// How many files were recorded.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree holds nothing, which a successful walk never does.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Every node in pre-order, the master file first.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// The nodes directly beneath `id`, in identifier order.
    pub fn children(&self, id: NodeId) -> impl Iterator<Item = &Node> {
        let children = self.node(id).map_or(&[][..], Node::children);
        children.iter().filter_map(|child| self.node(*child))
    }

    /// `id` and everything beneath it, in pre-order.
    pub fn descendants(&self, id: NodeId) -> &[Node] {
        let Some(node) = self.node(id) else {
            return &[];
        };
        let start = id.0;
        let end = (start + node.subtree).min(self.nodes.len());
        &self.nodes[start..end]
    }

    /// Every file the card selected, in pre-order.
    pub fn selected(&self) -> impl Iterator<Item = &Node> {
        self.nodes.iter().filter(|node| node.state.is_selected())
    }

    /// Every file refused for the given reason.
    ///
    /// Separate iterators rather than one filtered by a flag, because a caller
    /// reporting absent files and a caller reporting forbidden ones should not
    /// have to re-derive the distinction this crate made.
    pub fn refused(&self, kind: RefusalKind) -> impl Iterator<Item = &Node> {
        self.nodes
            .iter()
            .filter(move |node| node.state.refusal() == Some(kind))
    }

    /// Every file refused in a way the walk could not classify.
    pub fn unclassified_refusals(&self) -> impl Iterator<Item = &Node> {
        self.nodes
            .iter()
            .filter(|node| matches!(node.state, NodeState::Refused { .. }))
    }

    /// Whether a path was reached, whatever the card said about it.
    pub fn contains(&self, path: &Path) -> bool {
        self.nodes.iter().any(|node| node.path == *path)
    }

    /// The node at `path`, when the walk reached it.
    pub fn at(&self, path: &Path) -> Option<&Node> {
        self.nodes.iter().find(|node| node.path == *path)
    }

    /// Records the records read from an access rule reference file
    /// (EF.ARR) at `path`, replacing any earlier read of the same file.
    ///
    /// The card is read by [`crate::access::resolve`]; this only stores what
    /// came back, so rules stay pure functions of the tree.
    pub fn record_access_rules(&mut self, path: Path, records: Vec<Vec<u8>>) {
        self.access_rule_files.retain(|(known, _)| *known != path);
        self.access_rule_files.push((path, records));
    }

    /// The records read from the access rule reference file at `path`, if
    /// [`crate::access::resolve`] read it. Record 1 is element 0.
    pub fn access_rule_records(&self, path: &Path) -> Option<&[Vec<u8>]> {
        self.access_rule_files
            .iter()
            .find(|(known, _)| known == path)
            .map(|(_, records)| records.as_slice())
    }

    /// Records what [`crate::ef::read`] got back from the EF at `path`.
    pub fn record_content_read(&mut self, path: Path, read: ContentRead) {
        self.content_reads.retain(|(known, _)| *known != path);
        self.content_reads.push((path, read));
    }

    /// What [`crate::ef::read`] got back from the EF at `path`, if it tried.
    pub fn content_read(&self, path: &Path) -> Option<&ContentRead> {
        self.content_reads
            .iter()
            .find(|(known, _)| known == path)
            .map(|(_, read)| read)
    }

    /// What was found.
    pub const fn report(&self) -> &WalkReport {
        &self.report
    }

    /// How this tree's files were addressed.
    pub const fn addressing(&self) -> Addressing {
        self.addressing
    }

    /// Which status words this tree was read under.
    pub const fn meaning(&self) -> &StatusMeaning {
        &self.meaning
    }

    /// The bounds this walk ran inside.
    pub const fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The name of the tag table every capabilities template was read under,
    /// so a scan can report the assumption it ran with.
    pub fn dialect_name(&self) -> &str {
        &self.dialect
    }
}

/// Everything that can go wrong while walking.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The session layer could not complete a command.
    ///
    /// A transport failure or a response this crate cannot parse. Either way the
    /// walk stops rather than continuing to send commands to a card that has
    /// stopped making sense.
    #[error("a command could not be completed: {0}")]
    Session(#[from] session::Error),

    /// The master file itself is not on this card.
    ///
    /// Separate from [`Error::MasterFileForbidden`] because a card with no
    /// master file and a card we may not read the master file of are different
    /// situations and a scan reports them differently.
    #[error("the card has no master file 3F00: it answered {status}")]
    MasterFileAbsent {
        /// The status word that said so.
        status: StatusWord,
    },

    /// The master file is on this card and we may not read it.
    #[error("the card will not let this terminal read the master file 3F00: it answered {status}")]
    MasterFileForbidden {
        /// The status word that said so.
        status: StatusWord,
    },

    /// The master file could not be selected for some other reason.
    #[error("the master file 3F00 could not be selected: {status:?}")]
    MasterFileUnselected {
        /// The status word, when the card sent one at all.
        status: Option<StatusWord>,
    },

    /// A bound was set to zero.
    ///
    /// Zero does not mean unlimited here; it means expand nothing, and a caller
    /// who wanted no limit should raise the other bounds instead.
    #[error("limit {field} is zero, which would stop the walk before it starts")]
    ZeroLimit {
        /// The field that was zero.
        field: &'static str,
    },

    /// A candidate range runs backwards.
    #[error("the candidate range starts at {first} which is above its end {last}")]
    InvertedCandidates {
        /// The low end.
        first: FileId,
        /// The high end.
        last: FileId,
    },
}

/// Selects the master file and walks everything under it.
///
/// Issues every command through [`session::send`], so command chaining, the
/// `61 xx` follow-up and the `91 xx` proactive drain all happen where
/// [`crate::session`] already implements them, and a proactive command left
/// pending by the supplied policy shows up as a [`Note::IncompleteSelection`] on
/// the node rather than as a failed selection.
///
/// **The card is the untrusted party.** Every exchange is bounded, every status
/// word is either classified by the caller's own table or kept verbatim, and no
/// response body is indexed without having been parsed first. There is no path
/// from a card response to a panic and no path from a card response to an
/// unbounded allocation.
///
/// # Errors
///
/// Returns [`Error::MasterFileAbsent`], [`Error::MasterFileForbidden`] or
/// [`Error::MasterFileUnselected`] when the master file itself cannot be
/// selected, which are three different answers to three different situations.
/// Returns [`Error::Session`] when a command could not be completed at all; the
/// walk stops rather than sending more commands to a card that has stopped
/// making sense. Returns [`Error::ZeroLimit`] and [`Error::InvertedCandidates`]
/// for options that could not produce a meaningful walk.
///
/// The card is left with whatever file the walk last selected. Restoring it is
/// not attempted: a walker that selected thousands of files has no reason to
/// guess which one the caller wanted back.
///
/// # Example
///
/// Building the options needs no card, and nothing in them defaults to a tag
/// table:
///
/// ```
/// use sim_doctor::{
///     fcp::TagSet,
///     fs::FileId,
///     walk::{walk, Candidates, Options},
/// };
///
/// let dialect = TagSet::swicc();
/// let options = Options {
///     candidates: Candidates::List(vec![
///         "2FE2".parse::<FileId>()?,
///         "7F20".parse::<FileId>()?,
///     ]),
///     ..Options::default()
/// };
///
/// // With any `impl CardSession` in hand:
/// //
/// //     let tree = walk::walk(&mut session, &dialect, &options)?;
/// //     for file in tree.selected() {
/// //         println!("{} {:?}", file.path(), file.state());
/// //     }
/// # Ok::<(), sim_doctor::fs::Error>(())
/// ```
pub fn walk<S: CardSession + ?Sized>(
    session: &mut S,
    dialect: &TagSet,
    options: &Options,
) -> Result<Tree, Error> {
    options.limits.validate()?;
    if let Candidates::Range { first, last } = options.candidates {
        if u16::from_be_bytes(first.to_bytes()) > u16::from_be_bytes(last.to_bytes()) {
            return Err(Error::InvertedCandidates { first, last });
        }
    }

    let root = Path::master_file();
    let selection = select(session, options, dialect, &root, &mut None)?;
    match selection.state {
        NodeState::Selected { .. } => {}
        // Absent and forbidden are separate errors for the same reason they are
        // separate node states: a card with no file system and a card we may not
        // look at are different situations.
        NodeState::Absent => {
            return match selection.status {
                Some(status) => Err(Error::MasterFileAbsent { status }),
                None => Err(Error::MasterFileUnselected { status: None }),
            }
        }
        NodeState::Forbidden { status } => return Err(Error::MasterFileForbidden { status }),
        NodeState::Refused { status } => return Err(Error::MasterFileUnselected { status }),
    }

    let mut builder = Builder::new(options, dialect);
    let root_id = builder.push(root.clone(), selection.state, selection.notes);
    let mut root_frame = Frame::new(root_id, root, vec![FileId::MASTER_FILE], options);
    // Applications are listed in EF.DIR and are walked before the master file's
    // other children: the node budget is spent in order, and a real card's
    // USIM/ISIM files are not reachable any other way (see `applications`).
    root_frame.pending = applications(session, options, dialect)?.into_iter();
    let mut stack = vec![root_frame];
    let mut current_adf: Option<Vec<u8>> = None;

    // The traversal itself. A frame is one directory waiting to be enumerated;
    // it is popped, contributes at most one child, and goes back on the stack,
    // so a child frame pushed on top of it is finished before its parent moves
    // on. That is what makes the node vector pre-order, and it means this loop
    // is the only place a tree grows. Nothing here calls itself.
    while let Some(mut frame) = stack.pop() {
        let aid = frame.pending.next();
        let in_adf = frame.path.adf().is_some();
        let next = if aid.is_none() {
            // Inside an application 7FF0..=7FFF are aliases of it, never
            // children (see `is_application_alias`): skip them without a probe.
            frame
                .remaining
                .by_ref()
                .find(|id| !(in_adf && is_application_alias(*id)))
        } else {
            None
        };
        if next.is_none() && aid.is_none() {
            builder.finish(frame);
            continue;
        }

        if builder.selected >= options.limits.max_nodes {
            frame.stopped_by = Some(Limit::Nodes);
            builder.finish(frame);
            continue;
        }

        let child_path = match (next, aid) {
            (Some(id), _) => match frame.path.child(id) {
                Ok(path) => path,
                Err(_) => {
                    frame.notes.push(Note::NotAChild { id });
                    stack.push(frame);
                    continue;
                }
            },
            (None, Some(aid)) => Path::application(aid),
            (None, None) => continue,
        };

        let selection = select(session, options, dialect, &child_path, &mut current_adf)?;
        frame.observe(&selection);
        let within_depth = child_path.depth() <= options.limits.max_depth;

        let mut notes = selection.notes;
        // Only a file the card actually selected has an identity to repeat.
        // An absent identifier is not a file, and calling one a repeat of its
        // parent would be a finding about a file that does not exist.
        if let Some(id) =
            next.filter(|id| selection.state.is_selected() && frame.ancestors.contains(id))
        {
            // Recorded, not obeyed. See Note::RepeatedAncestor: a file
            // identifier repeats across directories legally, and refusing to
            // descend here would hide files rather than protect the walk.
            notes.push(Note::RepeatedAncestor {
                id,
                ancestor: frame.path.clone(),
            });
        }
        let kind = selection.state.kind();
        let child = builder.push(child_path.clone(), selection.state, notes);
        builder.link(frame.dir, child);
        if !within_depth {
            builder.note_limit(child, Limit::Depth);
        }

        // Under an application a DF that repeats an ancestor is the card answering
        // for itself (a lax resolver), not a deeper directory: do not follow it.
        let repeats_in_adf = child_path.adf().is_some()
            && builder.nodes[child.0]
                .notes
                .iter()
                .any(|n| matches!(n, Note::RepeatedAncestor { .. }));
        if !within_depth || repeats_in_adf || !kind.is_some_and(Kind::is_container) {
            stack.push(frame);
            continue;
        }
        if !builder.can_expand() {
            builder.note_limit(child, Limit::Directories);
            stack.push(frame);
            continue;
        }

        let mut ancestors = frame.ancestors.clone();
        ancestors.extend(next);
        stack.push(frame);
        builder.expanded();
        stack.push(Frame::new(child, child_path, ancestors, options));
    }

    Ok(builder.into_tree())
}

/// Whether `id` is in 7FF0..=7FFF, which this walk treats, beneath an
/// application, as an alias of that application rather than a child file
/// (issue #90). Under the master file they are still probed: swSIM exposes its
/// USIM as `3F00/7FFF` and the corpus cards do the same.
///
/// ETSI TS 102 221 clause 8.3 defines 7FFF as the special file identifier that
/// selects the ADF of the current application (verified against V14.2.0). The
/// wider 7FF0-7FFF range is treated the same way on the strength of a live
/// card, whose ADF answered SELECT 7FF0 as a DF and re-presented the whole
/// application beneath it (39% of a truncated walk); the spec text for the
/// range beyond 7FFF was not checked. A real DF at one of these identifiers
/// would be invisible to the walk, the same trade-off as the candidate set.
fn is_application_alias(id: FileId) -> bool {
    let [high, low] = id.to_bytes();
    high == 0x7F && low >= 0xF0
}

/// One answer to one SELECT, plus what had to be noted to reach it.
struct Selection {
    /// What the card said, as a node state.
    state: NodeState,
    /// The status word the exchange ended on, when it ended on one.
    status: Option<StatusWord>,
    /// Anything about the exchange itself a caller should know.
    notes: Vec<Note>,
}

/// Runs one SELECT and reads the answer.
fn select<S: CardSession + ?Sized>(
    session: &mut S,
    options: &Options,
    dialect: &TagSet,
    path: &Path,
    current_adf: &mut Option<Vec<u8>>,
) -> Result<Selection, Error> {
    let mut commands = select_commands(options.addressing, path);
    // `current_adf` is the application known to be the current DF. Under it the
    // SELECT by AID is already done, which halves the exchanges of a walk.
    if commands.len() == 2 && path.adf() == current_adf.as_deref() {
        commands.remove(0);
    }
    let last = commands.len() - 1;
    if path.adf().is_none() {
        *current_adf = None;
    }
    for (index, command) in commands.iter().enumerate() {
        let exchange = session::send(session, command, &options.session)?;
        // A failed step (the application is not there) answers for the file.
        let failed = !exchange.status().is_some_and(|s| s.is_normal_processing());
        let by_aid = path.adf().is_some() && command.header().parameter_1() == 0x04;
        if by_aid {
            *current_adf = (!failed).then(|| path.adf().unwrap_or_default().to_vec());
        }
        if index == last || failed {
            let selection = classify(&exchange, &options.meaning, dialect, path);
            // A selected DF, or one whose kind is unknown, becomes the current
            // DF; only a known EF leaves the application current.
            if selection.state.is_selected()
                && !by_aid
                && !matches!(
                    selection.state.kind(),
                    Some(Kind::Reported(FileKind::ElementaryFile))
                )
            {
                *current_adf = None;
            }
            return Ok(selection);
        }
    }
    unreachable!("select_commands returns at least one command")
}

/// The most EF.DIR records read. EF.DIR lists a handful of applications.
const MAX_DIR_RECORDS: usize = 16;

/// The AIDs EF.DIR (`2F00`) lists, in record order, without duplicates.
///
/// Sends SELECT and READ RECORD only. EF.DIR must be a selectable linear fixed
/// file (ETSI TS 102 221 clause 13.1); otherwise there is nothing to read. A refused read stops with the records read so far.
fn applications<S: CardSession + ?Sized>(
    session: &mut S,
    options: &Options,
    dialect: &TagSet,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut aids: Vec<Vec<u8>> = Vec::new();
    let Ok(path) = Path::master_file().child(FileId::from_bytes([0x2F, 0x00])) else {
        return Ok(aids);
    };
    let dir = select(session, options, dialect, &path, &mut None)?;
    let Some(shape) = dir
        .state
        .capabilities()
        .and_then(|c| c.descriptor.reported())
        .and_then(|d| match d.octets.as_slice() {
            [_, _, hi, lo, count, ..] => Some((u16::from_be_bytes([*hi, *lo]), *count)),
            _ => None,
        })
    else {
        return Ok(aids);
    };
    let (length, count) = shape;
    let Some(le) = Le::for_byte_count(u32::from(length)).filter(|_| length > 0) else {
        return Ok(aids);
    };
    for number in 1..=usize::from(count).min(MAX_DIR_RECORDS) {
        // `number` is at most 16 here.
        let header = Header::new(0x00, 0xB2, u8::try_from(number).unwrap_or(0xFF), 0x04);
        let read = session::send(session, &Command::case2(header, le), &options.session)?;
        if !read.status().is_some_and(|s| s.is_normal_processing()) {
            break;
        }
        if let Some(aid) = application_id(read.data()) {
            if !aids.contains(&aid) {
                aids.push(aid);
            }
        }
    }
    Ok(aids)
}

/// The AID (tag `4F`) of one EF.DIR record, an application template (tag `61`).
fn application_id(record: &[u8]) -> Option<Vec<u8>> {
    let (template, _) = Tlv::decode(record).ok()?;
    if template.tag().octet() != 0x61 {
        return None;
    }
    let mut atoms = Stream::new(template.value());
    while let Ok(Some(atom)) = atoms.next_atom() {
        if atom.tag().octet() == 0x4F {
            // ETSI TS 101 220: an AID is 5 to 16 octets.
            return (5..=16)
                .contains(&atom.value().len())
                .then(|| atom.value().to_vec());
        }
    }
    None
}

/// Turns one finished exchange into a node state.
///
/// **A `91 xx` is a success here.** The test is
/// [`apdu::StatusWord::is_normal_processing`], which is what AGENTS.md section 2
/// records the fixture proving: swSIM rewrites a completed command's `90 00`
/// into `91 <length>` whenever a proactive command is waiting, so a selection
/// test written against `90 00` would report a healthy card as broken.
fn classify(
    exchange: &Exchange,
    meaning: &StatusMeaning,
    dialect: &TagSet,
    path: &Path,
) -> Selection {
    let status = exchange.status();
    let mut notes = Vec::new();
    let stop = exchange.stop_reason();
    if stop != StopReason::Answered {
        notes.push(Note::IncompleteSelection { stop });
    }

    let state = match status {
        Some(status) if status.is_normal_processing() => {
            let (kind, capabilities) =
                read_capabilities(path, exchange.data(), dialect, &mut notes);
            NodeState::Selected {
                kind,
                capabilities: Box::new(capabilities),
            }
        }
        Some(status) => match meaning.meaning(status) {
            Some(RefusalKind::Absent) => NodeState::Absent,
            Some(RefusalKind::Forbidden) => NodeState::Forbidden { status },
            None => NodeState::Refused {
                status: Some(status),
            },
        },
        // No status word at all: a response that ended on a procedure byte.
        // Not a refusal this crate can classify and not a selection.
        None => NodeState::Refused { status: None },
    };

    Selection {
        state,
        status,
        notes,
    }
}

/// Reads a capabilities template into an owned record.
///
/// Nothing here indexes the response. Every field goes through
/// [`fcp::Template`], which walks the body with [`crate::tlv::Stream`] and
/// reports a body it cannot read, so a card that answers a SELECT with anything
/// other than a template produces [`Note::UnreadableTemplate`] and a node with
/// empty capabilities rather than a panic.
fn read_capabilities(
    path: &Path,
    body: &[u8],
    dialect: &TagSet,
    notes: &mut Vec<Note>,
) -> (Kind, Capabilities) {
    let template = match fcp::Template::parse(body, dialect) {
        Ok(template) => template,
        Err(error) => {
            notes.push(Note::UnreadableTemplate { error });
            return (Kind::Unreported, Capabilities::default());
        }
    };

    let capabilities = Capabilities {
        envelope: template.envelope().map(|atom| atom.tag()),
        reported_file_id: field(template.file_id()),
        size: field(template.file_size()),
        descriptor: field(template.file_descriptor()).map(|descriptor| Descriptor {
            octets: descriptor.octets().to_vec(),
            file_type: descriptor.file_type(),
            structure: descriptor.structure(),
            shareable: descriptor.is_shareable(),
            data_coding: descriptor.data_coding(),
        }),
        life_cycle: field(template.life_cycle_status()),
        access_conditions: field(template.access_conditions())
            .map(|conditions| conditions.octets().to_vec()),
        name: field(dedicated_file_name(&template, dialect)).map(|name| name.to_vec()),
        security_reference: template.security_reference().map(<[u8]>::to_vec),
        security_expanded: template.security_expanded().map(<[u8]>::to_vec),
        pin_status: template.pin_status().map(<[u8]>::to_vec),
        unknown_tags: template.tags_without_meaning(),
    };

    // An application directory is selected by AID, so its own identifier is not
    // the path's leaf.
    let by_aid = path.adf().is_some() && path.segments().len() == 1;
    if let Some(reported) = capabilities
        .reported_file_id
        .reported()
        .copied()
        .filter(|_| !by_aid)
    {
        if FileId::from_bytes(reported) != path.leaf() {
            notes.push(Note::IdentityMismatch {
                requested: path.leaf(),
                reported: FileId::from_bytes(reported),
            });
        }
    }

    (kind_of(path, &capabilities), capabilities)
}

/// The kind of a selected file, and how sure that is.
fn kind_of(path: &Path, capabilities: &Capabilities) -> Kind {
    if path.is_master_file() {
        return Kind::MasterFile;
    }
    match capabilities
        .descriptor
        .reported()
        .map(|descriptor| descriptor.file_type)
    {
        Some(fcp::FileType::Directory) => Kind::Reported(FileKind::DedicatedFile),
        Some(fcp::FileType::Elementary) => Kind::Reported(FileKind::ElementaryFile),
        // A category this crate has not verified, and a card that sent no
        // descriptor, are the same answer for a walker: it does not know, and
        // it does not descend.
        Some(fcp::FileType::Unknown(_)) | None => Kind::Unreported,
    }
}

/// Reads the dedicated file name, trimmed of the padding a card writes.
///
/// A card writes a fixed-width name and fills the rest with `00` or `FF`
/// depending on the card, so the trailing filler is stripped and the rest is
/// kept byte for byte. No encoding is assumed: this is not ASCII, it is
/// whatever the card put there.
///
/// Returns `Ok(None)` when the supplied tag table has no tag for a name, which
/// is the honest answer for a mapping that says nothing about names rather than
/// a failure.
fn dedicated_file_name<'a>(
    template: &fcp::Template<'a>,
    dialect: &TagSet,
) -> Result<Option<&'a [u8]>, fcp::Error> {
    let Some(tag) = dialect.df_name() else {
        return Ok(None);
    };
    Ok(template
        .find(tag)
        .map(|atom| trim_filler(atom.value()))
        .filter(|name| !name.is_empty()))
}

/// Strips the `00` and `FF` a card pads a fixed-width name with.
fn trim_filler(mut name: &[u8]) -> &[u8] {
    while let Some((last, rest)) = name.split_last() {
        if *last == 0x00 || *last == 0xFF {
            name = rest;
        } else {
            break;
        }
    }
    name
}

/// Lifts a fcp accessor that can fail into a [`Reported`].
fn field<T>(read: Result<Option<T>, fcp::Error>) -> Reported<T> {
    match read {
        Ok(Some(value)) => Reported::Reported(value),
        Ok(None) => Reported::NotReported,
        Err(error) => Reported::Unreadable(error),
    }
}

/// The SELECT command that names `path`.
///
/// The master file has no path to be named by under the path coding, so it is
/// always addressed by identifier, whichever variant the caller chose.
/// The commands that select `path`: one, or for a path through an application
/// the SELECT by AID followed by a SELECT by path from that application.
pub(crate) fn select_commands(addressing: Addressing, path: &Path) -> Vec<Command> {
    let Some(aid) = path.adf() else {
        return vec![select_command(addressing, path)];
    };
    let mut commands = vec![Command::case3(fs::select_aid_header(), aid.to_vec())];
    let below: Vec<u8> = path.segments()[1..]
        .iter()
        .flat_map(|id| id.to_bytes())
        .collect();
    if !below.is_empty() {
        commands.push(Command::case3(fs::select_from_current_df_header(), below));
    }
    commands
}

fn select_command(addressing: Addressing, path: &Path) -> Command {
    let below_master_file = path.segments().get(1..).filter(|rest| !rest.is_empty());
    match (addressing, below_master_file) {
        (Addressing::PathFromMasterFile, Some(rest)) => {
            let data: Vec<u8> = rest.iter().flat_map(|id| id.to_bytes()).collect();
            Command::case3(fs::select_path_header(), data)
        }
        _ => Command::case3(
            fs::select_capabilities_header(),
            path.leaf().to_bytes().to_vec(),
        ),
    }
}

/// One directory the walk still has to enumerate.
struct Frame {
    dir: NodeId,
    path: Path,
    ancestors: Vec<FileId>,
    remaining: IntoIter<FileId>,
    notes: Vec<Note>,
    refusals: Uniform,
    /// Application AIDs read from EF.DIR, still to be selected.
    pending: IntoIter<Vec<u8>>,
    selected: usize,
    probed: usize,
    stopped_by: Option<Limit>,
}

impl Frame {
    fn new(dir: NodeId, path: Path, ancestors: Vec<FileId>, options: &Options) -> Self {
        let (candidates, truncated) = options
            .candidates
            .clone()
            .identifiers(options.limits.max_children);
        // The truncation is carried in `stopped_by`, and `Builder::finish`
        // turns that into the note on this node. Recording it here as well
        // would print it twice.
        Self {
            dir,
            path,
            ancestors,
            remaining: candidates.into_iter(),
            notes: Vec::new(),
            refusals: Uniform::None,
            pending: Vec::new().into_iter(),
            selected: 0,
            probed: 0,
            stopped_by: truncated.then_some(Limit::Children),
        }
    }

    /// Folds one child answer into the directory's tally.
    fn observe(&mut self, selection: &Selection) {
        self.probed += 1;
        if selection.state.is_selected() {
            self.selected += 1;
        } else if let Some(status) = selection.status {
            self.refusals.observe(status);
        }
    }
}

/// The single status every probe under one directory drew, while they agree.
#[derive(Debug, Clone, Copy)]
enum Uniform {
    None,
    Same(StatusWord),
    Mixed,
}

impl Uniform {
    fn observe(&mut self, status: StatusWord) {
        *self = match *self {
            Uniform::None => Uniform::Same(status),
            Uniform::Same(previous) if previous == status => Uniform::Same(status),
            _ => Uniform::Mixed,
        };
    }
}

/// Grows the tree, and only the tree.
struct Builder<'a> {
    options: &'a Options,
    dialect: &'a TagSet,
    nodes: Vec<Node>,
    /// Selected nodes that are not repeated-ancestor answers: all `max_nodes` counts.
    selected: usize,
    directories: usize,
    truncated_by: Option<Limit>,
    limits_hit: Vec<Limit>,
}

impl<'a> Builder<'a> {
    fn new(options: &'a Options, dialect: &'a TagSet) -> Self {
        Self {
            options,
            dialect,
            nodes: Vec::new(),
            selected: 0,
            // The master file is already being enumerated.
            directories: 1,
            truncated_by: None,
            limits_hit: Vec::new(),
        }
    }

    fn push(&mut self, path: Path, state: NodeState, notes: Vec<Note>) -> NodeId {
        let id = NodeId(self.nodes.len());
        self.selected += usize::from(
            state.is_selected()
                && !notes
                    .iter()
                    .any(|n| matches!(n, Note::RepeatedAncestor { .. })),
        );
        self.nodes.push(Node {
            id,
            path,
            state,
            children: Vec::new(),
            notes,
            subtree: 1,
        });
        id
    }

    fn link(&mut self, parent: NodeId, child: NodeId) {
        self.nodes[parent.0].children.push(child);
    }

    fn note_limit(&mut self, node: NodeId, limit: Limit) {
        self.mark_truncated(limit);
        self.nodes[node.0].notes.push(Note::Limit { limit });
    }

    fn mark_truncated(&mut self, limit: Limit) {
        self.truncated_by.get_or_insert(limit);
        if !self.limits_hit.contains(&limit) {
            self.limits_hit.push(limit);
        }
    }

    /// Whether another directory may be expanded.
    fn can_expand(&self) -> bool {
        self.directories < self.options.limits.max_directories
    }

    /// Records that one more directory has been taken on.
    fn expanded(&mut self) {
        self.directories += 1;
    }

    /// Closes a directory: its subtree is now complete and contiguous.
    fn finish(&mut self, frame: Frame) {
        let mut notes = frame.notes;
        if let Some(limit) = frame.stopped_by {
            // The reason has to be on the node as well as in the report. A
            // caller rendering one directory cannot see the report, and a
            // directory that is missing children because a bound ran out is
            // the most misleading thing this tool could draw.
            self.mark_truncated(limit);
            notes.push(Note::Limit { limit });
        }
        if frame.selected == 0 && frame.probed > 0 {
            if let Uniform::Same(status) = frame.refusals {
                // A directory whose probes were all "not there" really is
                // empty. A directory whose probes were all something this walk
                // cannot read is a card that did not answer the question, and
                // reporting that as empty would be the one mistake here that
                // invents a finding.
                if self.options.meaning.meaning(status) != Some(RefusalKind::Absent) {
                    notes.push(Note::EnumerationRefused {
                        status,
                        probed: frame.probed,
                    });
                }
            }
        }
        // Everything under this directory was created while its frame sat on
        // top of this one's, and nothing after it was.
        let subtree = self.nodes.len() - frame.dir.0;
        let node = &mut self.nodes[frame.dir.0];
        node.subtree = subtree;
        node.notes.extend(notes);
    }

    fn into_tree(self) -> Tree {
        let report = self.report();
        Tree {
            nodes: self.nodes,
            report,
            addressing: self.options.addressing,
            meaning: self.options.meaning.clone(),
            limits: self.options.limits,
            dialect: self.dialect.name().to_owned(),
            access_rule_files: Vec::new(),
            content_reads: Vec::new(),
        }
    }

    fn report(&self) -> WalkReport {
        let mut report = WalkReport {
            nodes: self.nodes.len(),
            directories: self.directories.min(self.nodes.len()),
            truncated_by: self.truncated_by,
            limits_hit: self.limits_hit.clone(),
            ..WalkReport::default()
        };
        for node in &self.nodes {
            match node.state {
                NodeState::Selected { .. } => report.selected += 1,
                NodeState::Absent => report.absent += 1,
                NodeState::Forbidden { .. } => report.forbidden += 1,
                NodeState::Refused { .. } => report.refused += 1,
            }
            if node
                .notes
                .iter()
                .any(|note| matches!(note, Note::RepeatedAncestor { .. }))
            {
                report.repeated_ancestors += 1;
            }
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};

    use super::*;
    use crate::apdu::StatusWord;
    use crate::transport::{Error as TransportError, ReaderName};

    /// Wraps one atom in a short-form length, which is all any of these need.
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, body.len() as u8];
        out.extend_from_slice(body);
        out
    }

    /// The file descriptor swICC writes for a directory. `[V]`, swicc
    /// `src/fs.c` at swicc commit `421c8cdd`: category `111`, structure
    /// unassigned.
    const DIRECTORY_DESCRIPTOR: [u8; 2] = [0x38, 0x21];

    /// The file descriptor swICC writes for a transparent elementary file:
    /// category `001`, structure `001`.
    const TRANSPARENT_DESCRIPTOR: [u8; 2] = [0x09, 0x21];

    /// Builds a capabilities template under the swICC tag table, which is what
    /// every fixture in this file is written in.
    fn fcp(fid: FileId, descriptor: [u8; 2], size: Option<u16>) -> Vec<u8> {
        let mut body = Vec::new();
        if let Some(size) = size {
            body.extend(tlv(0x80, &size.to_be_bytes()));
        }
        body.extend(tlv(0x82, &descriptor));
        body.extend(tlv(0x83, &fid.to_bytes()));
        body.extend(tlv(0x8A, &[0x05]));
        tlv(0x62, &body)
    }

    fn id(text: &str) -> FileId {
        text.parse().expect("four hex digits")
    }

    fn path_of(text: &str) -> Path {
        text.parse().expect("a slash separated file path")
    }

    /// The path a test wrote, as bytes, master file included.
    fn path_segments(path: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for segment in path.split('/') {
            out.extend(id(segment).to_bytes());
        }
        out
    }

    /// The swICC tag table.
    fn dialect() -> TagSet {
        TagSet::swicc()
    }

    /// One file the fake card holds.
    #[derive(Debug, Clone)]
    struct Held {
        fcp: Vec<u8>,
        refusal: Option<[u8; 2]>,
    }

    /// A software card, in as much detail as a walker can tell.
    ///
    /// It models the two behaviours the walk depends on: a SELECT that finds a
    /// file queues its capabilities template and answers `61 xx`, and a SELECT
    /// that does not find one answers a refusal with no data. It answers GET
    /// RESPONSE from that queue the way a card does, so a walk that never
    /// follows up shows up here as the truncation it is.
    #[derive(Debug)]
    struct FakeCard {
        files: HashMap<Vec<u8>, Held>,
        queued: VecDeque<Vec<u8>>,
        scripted: HashMap<Vec<u8>, VecDeque<Vec<u8>>>,
        reader: ReaderName,
        sent: Vec<Vec<u8>>,
        /// Applications: AID and the key their root is held under.
        adfs: Vec<(Vec<u8>, Vec<u8>)>,
        current_adf: Option<Vec<u8>>,
    }

    impl Default for FakeCard {
        fn default() -> Self {
            Self {
                files: HashMap::new(),
                queued: VecDeque::new(),
                scripted: HashMap::new(),
                reader: ReaderName::new("fake card").expect("a valid reader name"),
                sent: Vec::new(),
                adfs: Vec::new(),
                current_adf: None,
            }
        }
    }

    impl FakeCard {
        /// Adds a file the card will select successfully.
        fn with(mut self, path: &str, fcp: Vec<u8>) -> Self {
            self.files
                .insert(path_segments(path), Held { fcp, refusal: None });
            self
        }

        /// Adds a file the card refuses with `status`.
        fn refusing(mut self, path: &str, fcp: Vec<u8>, status: [u8; 2]) -> Self {
            self.files.insert(
                path_segments(path),
                Held {
                    fcp,
                    refusal: Some(status),
                },
            );
            self
        }

        /// Makes the card answer `command` with `response`, whatever it would
        /// otherwise have done.
        fn script(mut self, command: &[u8], response: &[u8]) -> Self {
            self.scripted
                .entry(command.to_vec())
                .or_default()
                .push_back(response.to_vec());
            self
        }

        /// The commands whose INS byte is `instruction`.
        fn with_instruction(&self, instruction: u8) -> Vec<Vec<u8>> {
            self.sent
                .iter()
                .filter(|command| command.get(1) == Some(&instruction))
                .cloned()
                .collect()
        }

        /// Decodes the target of one SELECT command into a path, the way swSIM
        /// does: the path form walks down from the master file and the
        /// identifier form resolves against the whole card.
        fn select_target(&self, command: &[u8]) -> Option<Vec<u8>> {
            // CLA INS P1 P2 Lc, then the data field after Lc.
            let body = command.get(5..)?;
            // P1 08 is the "select by path from the MF" coding; P1 00 is
            // the GSM 11.11 "select by file identifier" one. P2 is 04 either
            // way, which is what asks for the capabilities template.
            match (command.get(1), command.get(2), command.get(3)) {
                (Some(0xA4), Some(0x08), Some(0x04)) if body.len() >= 2 && body.len() % 2 == 0 => {
                    let mut path = FileId::MASTER_FILE.to_bytes().to_vec();
                    path.extend_from_slice(body);
                    Some(path)
                }
                (Some(0xA4), Some(0x00), Some(0x04)) if body.len() == 2 => {
                    let fid = FileId::from_bytes([body[0], body[1]]);
                    self.files
                        .iter()
                        .find(|(_, held)| file_ident(held) == Some(fid))
                        .map(|(path, _)| path.clone())
                }
                _ => None,
            }
        }
    }

    /// The identifier a file's template echoes, read the way fcp reads it.
    fn file_ident(held: &Held) -> Option<FileId> {
        let dialect = TagSet::swicc();
        fcp::Template::parse(&held.fcp, &dialect)
            .ok()?
            .file_id()
            .ok()?
            .map(FileId::from_bytes)
    }

    impl CardSession for FakeCard {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }

        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.sent.push(command.to_vec());
            if let Some(response) = self
                .scripted
                .get_mut(command)
                .and_then(|queue| queue.pop_front())
            {
                return Ok(response);
            }
            if command.get(1) == Some(&0xC0) {
                return Ok(match self.queued.pop_front() {
                    Some(body) => {
                        let mut response = body;
                        response.extend_from_slice(&[0x90, 0x00]);
                        response
                    }
                    None => vec![0x6F, 0x00],
                });
            }
            if command.get(1) == Some(&0x12) {
                // FETCH hands back a proactive command. The walk only sends
                // one because the card asked for it, so a non-empty answer is
                // enough to prove it was sent.
                let length = usize::from(command.get(4).copied().unwrap_or(0));
                let mut response = vec![0xA0; length];
                response.extend_from_slice(&[0x90, 0x00]);
                return Ok(response);
            }
            // SELECT by AID names an application; P1 09 then resolves below it.
            let adf_target = match (command.get(1), command.get(2)) {
                (Some(0xA4), Some(0x04)) => {
                    let aid = command.get(5..).unwrap_or_default();
                    let root = self
                        .adfs
                        .iter()
                        .find(|(a, _)| a == aid)
                        .map(|(_, k)| k.clone());
                    if root.is_some() {
                        self.current_adf = root.clone();
                    }
                    Some(root)
                }
                (Some(0xA4), Some(0x09)) => Some(self.current_adf.as_ref().map(|root| {
                    let mut key = root.clone();
                    key.extend_from_slice(command.get(5..).unwrap_or_default());
                    key
                })),
                _ => None,
            };
            let target = match adf_target {
                Some(found) => found,
                None => self.select_target(command),
            };
            if let Some(path) = target {
                return Ok(match self.files.get(&path) {
                    Some(held) => match held.refusal {
                        Some(status) => status.to_vec(),
                        None => {
                            self.queued.push_back(held.fcp.clone());
                            vec![0x61, self.queued.back().map_or(0, Vec::len) as u8]
                        }
                    },
                    None => vec![0x6A, 0x82],
                });
            }
            Ok(vec![0x6D, 0x00])
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    #[test]
    fn applications_listed_in_ef_dir_are_selected_by_aid_and_walked() {
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xFF, 0xFF];
        let mut record = tlv(0x61, &[tlv(0x4F, &aid), tlv(0x50, b"USIM")].concat());
        record.resize(0x20, 0xFF);
        let mut response = record;
        response.extend_from_slice(&[0x90, 0x00]);
        let mut card = FakeCard::default()
            .with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None))
            .with(
                "3F00/2F00",
                // linear fixed, one record of 0x20 octets
                tlv(
                    0x62,
                    &[
                        tlv(0x82, &[0x42, 0x21, 0x00, 0x20, 0x01]),
                        tlv(0x83, &[0x2F, 0x00]),
                    ]
                    .concat(),
                ),
            )
            // The fake keys an application's root under a stand-in identifier.
            .with("3F00/7FF0", fcp(id("7FF0"), DIRECTORY_DESCRIPTOR, None))
            .with(
                "3F00/7FF0/6F07",
                fcp(id("6F07"), TRANSPARENT_DESCRIPTOR, Some(9)),
            )
            .script(&[0x00, 0xB2, 0x01, 0x04, 0x20], &response);
        card.adfs.push((aid.to_vec(), path_segments("3F00/7FF0")));

        let tree = walk(&mut card, &dialect(), &options_for(&["2F00", "6F07"])).unwrap();

        let app = "3F00/ADF:A0000000871002FFFF";
        assert!(tree.at(&path_of(app)).unwrap().state().is_selected());
        let file = path_of(&format!("{app}/6F07"));
        assert!(tree.at(&file).unwrap().state().is_selected());
        // The path survives a round trip, and the profile calls it 7FD0.
        assert_eq!(file.to_string().parse::<Path>().unwrap(), file);
        assert!(crate::ts48::observe(&tree).contains_key("3F00/7FD0/6F07"));
        // Reading EF.DIR is read-only.
        assert!(card.with_instruction(0xD6).is_empty());
    }

    #[test]
    fn a_directory_that_answers_for_its_own_identifier_under_an_application_is_not_followed() {
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xFF, 0xFF];
        let mut record = tlv(0x61, &tlv(0x4F, &aid));
        record.resize(0x20, 0xFF);
        record.extend_from_slice(&[0x90, 0x00]);
        let mut card = FakeCard::default()
            .with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None))
            .with(
                "3F00/2F00",
                tlv(
                    0x62,
                    &[
                        tlv(0x82, &[0x42, 0x21, 0x00, 0x20, 0x01]),
                        tlv(0x83, &[0x2F, 0x00]),
                    ]
                    .concat(),
                ),
            )
            .with("3F00/7FF0", fcp(id("7FF0"), DIRECTORY_DESCRIPTOR, None))
            .script(&[0x00, 0xB2, 0x01, 0x04, 0x20], &record);
        // 5F3B answers inside 5F3B, to ten levels.
        let mut key = String::from("3F00/7FF0");
        for _ in 0..10 {
            key.push_str("/5F3B");
            card = card.with(&key, fcp(id("5F3B"), DIRECTORY_DESCRIPTOR, None));
        }
        card.adfs.push((aid.to_vec(), path_segments("3F00/7FF0")));

        let tree = walk(&mut card, &dialect(), &options_for(&["5F3B"])).unwrap();

        let deepest = tree.nodes().iter().map(|n| n.path().depth()).max().unwrap();
        assert_eq!(deepest, 4, "ADF, 5F3B, and the one repeat that is recorded");
        assert!(tree.report().repeated_ancestors > 0);
    }

    /// Options that probe exactly the leaves of the paths a test names, so a
    /// test says precisely which files its card holds.
    fn options_for(leaves: &[&str]) -> Options {
        Options {
            candidates: Candidates::List(leaves.iter().copied().map(id).collect()),
            ..Options::default()
        }
    }

    /// A master file with a dedicated file under it, an elementary file under
    /// that, a second elementary file at the top, and one refusal of each kind
    /// the walk has to keep apart.
    fn sample_card() -> FakeCard {
        FakeCard::default()
            .with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None))
            .with("3F00/7F20", fcp(id("7F20"), DIRECTORY_DESCRIPTOR, None))
            .with(
                "3F00/7F20/6F3A",
                fcp(id("6F3A"), TRANSPARENT_DESCRIPTOR, Some(10)),
            )
            .with(
                "3F00/2FE2",
                fcp(id("2FE2"), TRANSPARENT_DESCRIPTOR, Some(10)),
            )
            .refusing("3F00/2F01", Vec::new(), [0x94, 0x03])
    }

    /// The paths of a slice of nodes, in pre-order.
    fn paths_of(nodes: &[Node]) -> Vec<String> {
        nodes.iter().map(|node| node.path().to_string()).collect()
    }

    // ----------------------------------------------------------------- shape

    #[test]
    fn a_walk_returns_the_master_file_and_the_tree_under_it() {
        let mut card = sample_card();
        let tree = walk(
            &mut card,
            &dialect(),
            &options_for(&["7F20", "6F3A", "2FE2"]),
        )
        .expect("the walk completes");

        assert_eq!(tree.root(), NodeId(0));
        let root = tree.node(tree.root()).expect("the root exists");
        assert_eq!(root.path().to_string(), "3F00");
        assert_eq!(root.state().kind(), Some(Kind::MasterFile));
        assert!(root.state().is_selected());

        // Every path the tree reports is absolute and rooted at the master
        // file, which is what "correct paths" in the issue actually means.
        for node in tree.nodes() {
            assert_eq!(
                node.path().segments().first(),
                Some(&FileId::MASTER_FILE),
                "{node:?} is not rooted at the master file"
            );
        }

        assert!(tree.contains(&path_of("3F00/7F20/6F3A")));
        assert!(
            !tree
                .at(&path_of("3F00/6F3A"))
                .expect("the probe was recorded")
                .state()
                .is_selected(),
            "6F3A is under 7F20, so asking for it at the top finds nothing"
        );
    }

    #[test]
    fn a_directory_and_an_elementary_file_are_told_apart_by_the_card_descriptor() {
        let mut card = sample_card();
        let tree = walk(
            &mut card,
            &dialect(),
            &options_for(&["7F20", "6F3A", "2FE2"]),
        )
        .unwrap();

        let directory = tree.at(&path_of("3F00/7F20")).unwrap();
        assert_eq!(
            directory.state().kind(),
            Some(Kind::Reported(FileKind::DedicatedFile))
        );
        assert!(directory.state().kind().unwrap().is_container());

        let elementary = tree.at(&path_of("3F00/2FE2")).unwrap();
        assert_eq!(
            elementary.state().kind(),
            Some(Kind::Reported(FileKind::ElementaryFile))
        );
        assert!(!elementary.state().kind().unwrap().is_container());
        assert_eq!(directory.path().depth(), 2);
        assert_eq!(
            tree.at(&path_of("3F00/7F20/6F3A")).unwrap().path().depth(),
            3
        );
    }

    #[test]
    fn per_file_metadata_is_collected_from_the_capabilities_template() {
        let mut card = sample_card();
        let tree = walk(&mut card, &dialect(), &options_for(&["7F20", "6F3A"])).unwrap();

        let capabilities = tree
            .at(&path_of("3F00/7F20/6F3A"))
            .unwrap()
            .state()
            .capabilities()
            .expect("a selected file has capabilities");
        assert_eq!(
            capabilities.size.reported().map(|size| size.octets()),
            Some(10)
        );
        let descriptor = capabilities
            .descriptor
            .reported()
            .expect("the card sent a descriptor");
        assert_eq!(descriptor.file_type, fcp::FileType::Elementary);
        assert_eq!(descriptor.structure, fcp::Structure::Transparent);
        assert!(!descriptor.shareable);
        assert_eq!(descriptor.data_coding, Some(0x21));
        assert_eq!(
            capabilities
                .life_cycle
                .reported()
                .map(|status| status.byte()),
            Some(0x05)
        );
        assert_eq!(
            capabilities.reported_file_id.reported().copied(),
            Some(id("6F3A").to_bytes())
        );
        assert_eq!(
            capabilities.envelope.map(|tag| tag.octet()),
            Some(0x62),
            "the card wrapped the template in 62"
        );
        assert!(
            capabilities.unknown_tags.is_empty(),
            "the swICC table explains every tag the sample card sent"
        );
    }

    #[test]
    fn a_file_the_card_never_describes_is_not_descended_into() {
        // No descriptor, so nothing says whether this file holds others.
        let body = {
            let mut body = tlv(0x83, &id("7F20").to_bytes());
            body.extend(tlv(0x8A, &[0x05]));
            tlv(0x62, &body)
        };
        let mut card = FakeCard::default()
            .with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None))
            .with("3F00/7F20", body)
            .with(
                "3F00/7F20/6F3A",
                fcp(id("6F3A"), TRANSPARENT_DESCRIPTOR, Some(1)),
            );

        let tree = walk(&mut card, &dialect(), &options_for(&["7F20", "6F3A"])).unwrap();
        let directory = tree.at(&path_of("3F00/7F20")).unwrap();
        assert_eq!(directory.state().kind(), Some(Kind::Unreported));
        assert_eq!(directory.state().kind().unwrap().as_file_kind(), None);
        assert!(
            directory.children().is_empty(),
            "an undescribed file is never descended"
        );
        assert!(
            !tree.contains(&path_of("3F00/7F20/6F3A")),
            "nothing below an undescribed file was reached"
        );
    }

    // ---------------------------------------------------- absent vs forbidden

    #[test]
    fn a_file_that_is_not_there_and_a_file_we_may_not_read_are_different_answers() {
        let mut card = sample_card();
        let options = Options {
            candidates: Candidates::List(vec![id("2FE2"), id("2F01"), id("0000")]),
            meaning: StatusMeaning::default().with_forbidden(StatusWord::new(0x94, 0x03)),
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &options).unwrap();

        let absent = tree.at(&path_of("3F00/0000")).unwrap();
        assert_eq!(absent.state(), &NodeState::Absent);
        assert_eq!(absent.state().refusal(), Some(RefusalKind::Absent));

        let forbidden = tree.at(&path_of("3F00/2F01")).unwrap();
        assert_eq!(
            forbidden.state(),
            &NodeState::Forbidden {
                status: StatusWord::new(0x94, 0x03)
            }
        );
        assert_eq!(forbidden.state().refusal(), Some(RefusalKind::Forbidden));
        assert_eq!(
            forbidden.state().status(),
            Some(StatusWord::new(0x94, 0x03)),
            "the status word that decided it is kept"
        );

        // The whole point: separate variants, separate counters, separate
        // iterators, so a scan cannot report one as the other.
        assert_ne!(absent.state(), forbidden.state());
        assert_eq!(tree.report().absent, 1);
        assert_eq!(tree.report().forbidden, 1);
        assert_eq!(tree.refused(RefusalKind::Absent).count(), 1);
        assert_eq!(
            tree.refused(RefusalKind::Forbidden)
                .map(|node| node.path().to_string())
                .collect::<Vec<_>>(),
            vec!["3F00/2F01".to_owned()]
        );
        assert_eq!(tree.selected().count(), 2, "the refused file is not one");
    }

    #[test]
    fn without_a_rule_a_forbidden_file_is_never_reported_as_an_absent_one() {
        // The same card, read by a caller who has not written down what
        // 94 03 means. Nothing may collapse: both answers become unclassified
        // and keep their status words.
        let mut card = sample_card();
        let options = Options {
            candidates: Candidates::List(vec![id("2F01"), id("0000")]),
            meaning: StatusMeaning::unverified(),
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &options).unwrap();

        let statuses: Vec<Option<StatusWord>> = tree.nodes()[1..]
            .iter()
            .map(|node| node.state().status())
            .collect();
        assert_eq!(
            statuses,
            vec![
                Some(StatusWord::new(0x6A, 0x82)),
                Some(StatusWord::new(0x94, 0x03))
            ]
        );
        assert_eq!(tree.report().absent, 0, "nothing was called absent");
        assert_eq!(tree.report().forbidden, 0);
        assert_eq!(tree.report().refused, 2, "both were left unclassified");
        assert_eq!(tree.unclassified_refusals().count(), 2);
    }

    #[test]
    fn the_status_meaning_table_is_the_caller_statement_it_says_it_is() {
        let default = StatusMeaning::default();
        assert_eq!(
            default.meaning(StatusWord::new(0x6A, 0x82)),
            Some(RefusalKind::Absent),
            "6A 82 is the one entry this repository has verified"
        );
        assert_eq!(default.meaning(StatusWord::new(0x94, 0x04)), None);
        assert!(default.forbidden().is_empty(), "nothing is guessed");
        assert!(StatusMeaning::unverified().absent().is_empty());
        assert_eq!(
            StatusMeaning::unverified().meaning(StatusWord::new(0x6A, 0x82)),
            None
        );

        // Absent wins a status word in both lists, because the reading that
        // cannot invent a finding is the one that says "not there".
        let both = StatusMeaning::default()
            .with_forbidden(StatusWord::new(0x6A, 0x82))
            .with_absent(StatusWord::new(0x6A, 0x82));
        assert_eq!(
            both.meaning(StatusWord::new(0x6A, 0x82)),
            Some(RefusalKind::Absent)
        );
    }

    #[test]
    fn a_master_file_that_is_forbidden_is_a_different_error_from_one_that_is_absent() {
        let options = Options {
            meaning: StatusMeaning::default().with_forbidden(StatusWord::new(0x94, 0x03)),
            ..Options::default()
        };
        let mut forbidden =
            FakeCard::default().script(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &[0x94, 0x03]);
        let error = walk(&mut forbidden, &dialect(), &options).unwrap_err();
        assert!(
            matches!(error, Error::MasterFileForbidden { .. }),
            "{error}"
        );

        let mut absent =
            FakeCard::default().script(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &[0x6A, 0x82]);
        let error = walk(&mut absent, &dialect(), &options).unwrap_err();
        assert!(matches!(error, Error::MasterFileAbsent { .. }), "{error}");
    }

    #[test]
    fn a_master_file_the_card_refuses_some_other_way_is_neither_of_those() {
        let mut card =
            FakeCard::default().script(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &[0x6D, 0x00]);
        let error = walk(&mut card, &dialect(), &Options::default()).unwrap_err();
        assert!(
            matches!(
                error,
                Error::MasterFileUnselected { status: Some(status) } if status == StatusWord::new(0x6D, 0x00)
            ),
            "{error}"
        );
    }

    // ---------------------------------------------------------------- cycles

    #[test]
    fn a_directory_that_holds_a_file_with_its_own_identifier_terminates() {
        // The card says 7F20 is a child of 7F20. The path 3F00/7F20/7F20 is a
        // legal file, not a loop, so the walk descends; what stops the card
        // from being followed forever is the depth bound.
        let depth = 6;
        let directory = fcp(id("7F20"), DIRECTORY_DESCRIPTOR, None);
        let mut card =
            FakeCard::default().with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None));
        for level in 1..=depth {
            let mut path = String::from("3F00");
            for _ in 0..level {
                path.push_str("/7F20");
            }
            card = card.with(&path, directory.clone());
        }

        let options = Options {
            candidates: Candidates::List(vec![id("7F20")]),
            limits: Limits {
                max_depth: 4,
                ..Limits::default()
            },
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &options).unwrap();

        // It really did descend, and it really did record why.
        let repeat = tree.at(&path_of("3F00/7F20/7F20")).expect("recorded");
        assert!(
            repeat.notes().contains(&Note::RepeatedAncestor {
                id: id("7F20"),
                ancestor: path_of("3F00/7F20")
            }),
            "{:?}",
            repeat.notes()
        );
        assert!(!repeat.children().is_empty(), "and it descended");
        assert_eq!(tree.report().repeated_ancestors, 3);

        // And it stopped, at the bound, with the stop recorded on the node
        // that was not descended.
        assert_eq!(tree.report().truncated_by, Some(Limit::Depth));
        let deepest = tree
            .nodes()
            .iter()
            .max_by_key(|node| node.path().depth())
            .expect("not empty");
        assert_eq!(deepest.path().to_string(), "3F00/7F20/7F20/7F20/7F20");
        assert!(deepest.notes().contains(&Note::Limit {
            limit: Limit::Depth
        }));
        assert!(deepest.children().is_empty());
        assert!(
            tree.nodes().iter().all(|node| node.path().depth() <= 5),
            "nothing past the bound exists"
        );
    }

    #[test]
    fn two_directories_that_name_each_other_both_appear_in_the_tree() {
        let a = fcp(id("5F01"), DIRECTORY_DESCRIPTOR, None);
        let b = fcp(id("5F02"), DIRECTORY_DESCRIPTOR, None);
        let mut card = FakeCard::default()
            .with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None))
            .with("3F00/5F01", a.clone())
            .with("3F00/5F01/5F02", b.clone())
            .with("3F00/5F01/5F02/5F01", a)
            .with("3F00/5F02", b);
        let tree = walk(&mut card, &dialect(), &options_for(&["5F01", "5F02"])).unwrap();

        // Both are real paths and both are recorded, which is what makes the
        // repeat a note rather than a reason to throw a file away.
        assert!(tree
            .at(&path_of("3F00/5F01"))
            .unwrap()
            .state()
            .is_selected());
        assert!(tree
            .at(&path_of("3F00/5F01/5F02"))
            .unwrap()
            .state()
            .is_selected());
        assert_eq!(tree.report().repeated_ancestors, 1);
        assert!(tree
            .at(&path_of("3F00/5F01/5F02/5F01"))
            .unwrap()
            .notes()
            .iter()
            .any(|note| matches!(note, Note::RepeatedAncestor { .. })));
        // The repeat is a legal file, so it is descended into like any
        // other, and what is under it is probed as usual.
        let repeat = tree.at(&path_of("3F00/5F01/5F02/5F01")).unwrap();
        assert!(repeat.state().is_selected());
        assert_eq!(
            tree.at(&path_of("3F00/5F01/5F02/5F01/5F02"))
                .expect("probed")
                .state(),
            &NodeState::Absent
        );
    }

    #[test]
    fn the_same_identifier_under_two_different_directories_is_two_files() {
        // Not a cycle. A file identifier is unique inside a directory, not
        // across the card, and a walker that treated a repeat as a cycle would
        // miss half of a real card.
        let shared = fcp(id("2FE2"), TRANSPARENT_DESCRIPTOR, Some(10));
        let mut card = FakeCard::default()
            .with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None))
            .with("3F00/7F20", fcp(id("7F20"), DIRECTORY_DESCRIPTOR, None))
            .with("3F00/7F20/2FE2", shared.clone())
            .with("3F00/2FE2", shared.clone())
            .with("3F00/7F10", fcp(id("7F10"), DIRECTORY_DESCRIPTOR, None))
            .with("3F00/7F10/2FE2", shared);
        let tree = walk(
            &mut card,
            &dialect(),
            &options_for(&["7F20", "7F10", "2FE2"]),
        )
        .unwrap();

        assert_eq!(tree.report().repeated_ancestors, 0);
        assert!(tree.contains(&path_of("3F00/2FE2")));
        assert!(tree.contains(&path_of("3F00/7F20/2FE2")));
        assert!(tree.contains(&path_of("3F00/7F10/2FE2")));
    }

    #[test]
    fn the_same_identifier_listed_twice_under_one_directory_is_probed_once() {
        let mut card = FakeCard::default()
            .with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None))
            .with(
                "3F00/2FE2",
                fcp(id("2FE2"), TRANSPARENT_DESCRIPTOR, Some(10)),
            );
        let options = Options {
            candidates: Candidates::List(vec![id("2FE2"), id("2FE2"), id("2FE2")]),
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &options).unwrap();
        assert_eq!(tree.len(), 2, "the master file and one child");
    }

    // --------------------------------------------------------------- limits

    #[test]
    fn every_bound_stops_the_walk_and_says_which_one() {
        let mut card = sample_card();
        let children = Options {
            candidates: Candidates::List(vec![id("7F20"), id("6F3A"), id("2FE2")]),
            limits: Limits {
                max_children: 1,
                ..Limits::default()
            },
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &children).unwrap();
        assert_eq!(tree.report().truncated_by, Some(Limit::Children));
        assert_eq!(
            tree.node(tree.root()).unwrap().notes(),
            &[Note::Limit {
                limit: Limit::Children
            }]
        );

        let mut card = sample_card();
        let nodes = Options {
            candidates: Candidates::List(vec![id("7F20"), id("6F3A"), id("2FE2")]),
            limits: Limits {
                max_nodes: 3,
                ..Limits::default()
            },
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &nodes).unwrap();
        assert_eq!(tree.report().truncated_by, Some(Limit::Nodes));
        assert_eq!(
            tree.report().selected,
            3,
            "the budget counts selected files and stops at the bound, not past it"
        );

        let mut card = sample_card();
        let directories = Options {
            candidates: Candidates::List(vec![id("7F20"), id("6F3A"), id("2FE2")]),
            limits: Limits {
                max_directories: 1,
                ..Limits::default()
            },
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &directories).unwrap();
        assert_eq!(tree.report().truncated_by, Some(Limit::Directories));
        assert!(
            tree.at(&path_of("3F00/7F20"))
                .unwrap()
                .notes()
                .contains(&Note::Limit {
                    limit: Limit::Directories
                }),
            "the directory that was not expanded says so"
        );
        assert!(!tree.contains(&path_of("3F00/7F20/6F3A")));
    }

    #[test]
    fn a_tree_deeper_than_the_limit_stops_and_says_so() {
        // A chain of directories with no cycle in it at all, so the only thing
        // that can stop the walk is the bound.
        let depth = 8;
        let mut card =
            FakeCard::default().with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None));
        for level in 1..=depth {
            let mut path = String::from("3F00");
            for step in 1..=level {
                path.push('/');
                path.push_str(&format!("5F{step:02X}"));
            }
            card = card.with(
                &path,
                fcp(
                    FileId::from_bytes([0x5F, level as u8]),
                    DIRECTORY_DESCRIPTOR,
                    None,
                ),
            );
        }

        let options = Options {
            candidates: Candidates::List(
                (1..=depth)
                    .map(|level| FileId::from_bytes([0x5F, level as u8]))
                    .collect(),
            ),
            limits: Limits {
                max_depth: 4,
                ..Limits::default()
            },
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &options).unwrap();

        assert_eq!(
            tree.report().repeated_ancestors,
            0,
            "a chain of distinct directories repeats nothing"
        );
        assert_eq!(tree.report().truncated_by, Some(Limit::Depth));
        let deepest = tree
            .nodes()
            .iter()
            .max_by_key(|node| node.path().depth())
            .expect("the tree is not empty");
        assert_eq!(deepest.path().depth(), 5, "one past the bound, recorded");
        assert!(deepest.notes().contains(&Note::Limit {
            limit: Limit::Depth
        }));
        assert!(
            tree.nodes().iter().all(|node| node.path().depth() <= 5),
            "nothing past the bound was created"
        );
    }

    #[test]
    fn a_zero_bound_is_refused_rather_than_silently_meaning_nothing() {
        for (limits, field) in [
            (
                Limits {
                    max_depth: 0,
                    ..Limits::default()
                },
                "max_depth",
            ),
            (
                Limits {
                    max_children: 0,
                    ..Limits::default()
                },
                "max_children",
            ),
            (
                Limits {
                    max_nodes: 0,
                    ..Limits::default()
                },
                "max_nodes",
            ),
            (
                Limits {
                    max_directories: 0,
                    ..Limits::default()
                },
                "max_directories",
            ),
        ] {
            let error = limits.validate().unwrap_err();
            assert!(
                matches!(error, Error::ZeroLimit { field: named } if named == field),
                "{error}"
            );
        }
        assert!(Limits::default().validate().is_ok());
    }

    #[test]
    fn a_candidate_range_that_runs_backwards_is_refused_before_anything_is_sent() {
        let mut card = sample_card();
        let options = Options {
            candidates: Candidates::Range {
                first: id("7F00"),
                last: id("2F00"),
            },
            ..Options::default()
        };
        let error = walk(&mut card, &dialect(), &options).unwrap_err();
        assert!(matches!(error, Error::InvertedCandidates { .. }));
        assert_eq!(card.sent.len(), 0, "nothing was sent to the card");
    }

    #[test]
    fn the_master_file_is_never_its_own_child_and_the_refusal_is_recorded() {
        let mut card = sample_card();
        let tree = walk(&mut card, &dialect(), &options_for(&["3F00", "2FE2"])).unwrap();

        assert!(
            tree.node(tree.root())
                .unwrap()
                .notes()
                .contains(&Note::NotAChild {
                    id: FileId::MASTER_FILE
                }),
            "the refused probe is recorded rather than dropped"
        );
        assert!(tree.nodes().iter().all(|node| node
            .path()
            .segments()
            .iter()
            .skip(1)
            .all(|id| !id.is_master_file())));
    }

    // --------------------------------------------------------- hostile cards

    #[test]
    fn a_capabilities_template_that_will_not_parse_is_a_note_and_not_a_panic() {
        // The card selects the file and then sends bytes that are not a
        // template at all.
        let garbage = [0xFFu8, 0xFF, 0xFF, 0x90, 0x00];
        let mut card = sample_card()
            .script(&[0x00, 0xA4, 0x08, 0x04, 0x02, 0x2F, 0xE2], &[0x61, 0x03])
            .script(&[0xA0, 0xC0, 0x00, 0x00, 0x03], &garbage);

        let tree = walk(&mut card, &dialect(), &options_for(&["2FE2"])).unwrap();
        let file = tree.at(&path_of("3F00/2FE2")).expect("still recorded");
        assert!(
            file.state().is_selected(),
            "the card did select it; only the template is unreadable"
        );
        assert!(file
            .notes()
            .iter()
            .any(|note| matches!(note, Note::UnreadableTemplate { .. })));
        assert_eq!(
            file.state().capabilities().unwrap().size,
            Reported::NotReported
        );
        assert!(!file.state().kind().unwrap().is_container());
    }

    #[test]
    fn a_card_that_answers_nothing_at_all_stops_the_walk_with_an_error() {
        // An empty response is not a status word and not a procedure byte.
        // Guessing either would put a fabricated finding into a report.
        let mut card = sample_card().script(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &[]);
        let error = walk(&mut card, &dialect(), &Options::default()).unwrap_err();
        assert!(matches!(error, Error::Session(_)), "{error}");
    }

    #[test]
    fn a_lone_procedure_byte_is_recorded_as_an_unclassified_refusal() {
        // One octet parses as a procedure byte, which is not a status word.
        // The walk must not turn that into an absent file.
        let mut card = sample_card().script(&[0x00, 0xA4, 0x08, 0x04, 0x02, 0x2F, 0xE2], &[0x60]);
        let tree = walk(&mut card, &dialect(), &options_for(&["2FE2"])).unwrap();
        let file = tree.at(&path_of("3F00/2FE2")).unwrap();
        assert_eq!(
            file.state(),
            &NodeState::Refused { status: None },
            "no status word means no classification"
        );
        assert_eq!(file.state().refusal(), None);
        assert_eq!(tree.report().absent, 0);
        assert_eq!(tree.report().refused, 1);
    }

    #[test]
    fn a_proactive_command_pending_during_a_selection_is_drained_and_the_file_is_found() {
        // swSIM rewrites a completed 90 00 into 91 <length> whenever a
        // proactive command is waiting. AGENTS.md section 2 says treating that
        // as failure reports every healthy card as broken.
        let mut card = sample_card()
            .script(&[0x00, 0xA4, 0x08, 0x04, 0x02, 0x2F, 0xE2], &[0x91, 0x03])
            .script(
                &[0x80, 0x12, 0x00, 0x00, 0x03],
                &[0xA0, 0xA0, 0xA0, 0x90, 0x00],
            )
            .script(&[0xA0, 0xC0, 0x00, 0x00, 0x03], &[0x90, 0x00]);

        let tree = walk(&mut card, &dialect(), &options_for(&["2FE2"])).unwrap();
        let file = tree.at(&path_of("3F00/2FE2")).unwrap();
        assert!(
            file.state().is_selected(),
            "a 91 xx is normal processing, not a failure: {:?}",
            file.state()
        );
        assert!(card
            .with_instruction(0x12)
            .contains(&vec![0x80, 0x12, 0x00, 0x00, 0x03]));
    }

    #[test]
    fn a_proactive_status_the_policy_leaves_alone_is_an_incomplete_selection() {
        let mut card =
            sample_card().script(&[0x00, 0xA4, 0x08, 0x04, 0x02, 0x2F, 0xE2], &[0x91, 0x80]);
        let options = Options {
            candidates: Candidates::List(vec![id("2FE2")]),
            session: session::Policy {
                proactive_command: session::PendingFollowUp::Ignore,
                ..session::Policy::default()
            },
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &options).unwrap();
        let file = tree.at(&path_of("3F00/2FE2")).unwrap();
        assert!(
            file.state().is_selected(),
            "the card completed the select and is holding something"
        );
        assert!(file.notes().contains(&Note::IncompleteSelection {
            stop: StopReason::PendingIgnored
        }));
        assert!(
            card.with_instruction(0x12).is_empty(),
            "nothing was drained"
        );
    }

    #[test]
    fn a_card_that_echoes_the_wrong_identifier_is_reported_rather_than_believed() {
        let wrong = fcp(id("2FE3"), TRANSPARENT_DESCRIPTOR, Some(10));
        let mut card = sample_card()
            .script(
                &[0x00, 0xA4, 0x08, 0x04, 0x02, 0x2F, 0xE2],
                &[0x61, wrong.len() as u8],
            )
            .script(
                &[0xA0, 0xC0, 0x00, 0x00, wrong.len() as u8],
                &[wrong.as_slice(), &[0x90, 0x00]].concat(),
            );
        let tree = walk(&mut card, &dialect(), &options_for(&["2FE2"])).unwrap();
        let file = tree.at(&path_of("3F00/2FE2")).unwrap();
        assert!(file.notes().contains(&Note::IdentityMismatch {
            requested: id("2FE2"),
            reported: id("2FE3"),
        }));
    }

    #[test]
    fn a_field_the_card_omitted_is_not_the_same_as_a_field_the_card_got_wrong() {
        let mut body = tlv(0x82, &TRANSPARENT_DESCRIPTOR);
        body.extend(tlv(0x83, &id("2FE2").to_bytes()));
        // Five octets is not a shape a file size can take, so this is a
        // finding rather than an omission.
        body.extend(tlv(0x80, &[0x01, 0x02, 0x03, 0x04, 0x05]));
        let broken = tlv(0x62, &body);

        let mut card = sample_card()
            .script(
                &[0x00, 0xA4, 0x08, 0x04, 0x02, 0x2F, 0xE2],
                &[0x61, broken.len() as u8],
            )
            .script(
                &[0xA0, 0xC0, 0x00, 0x00, broken.len() as u8],
                &[broken.as_slice(), &[0x90, 0x00]].concat(),
            );
        let tree = walk(&mut card, &dialect(), &options_for(&["2FE2"])).unwrap();

        let capabilities = tree
            .at(&path_of("3F00/2FE2"))
            .unwrap()
            .state()
            .capabilities()
            .unwrap();
        assert!(
            capabilities.size.unreadable().is_some(),
            "a field the card sent and this crate cannot read is kept"
        );
        assert!(capabilities.size.is_reported(), "it was sent");
        assert_eq!(
            capabilities.life_cycle,
            Reported::NotReported,
            "a field the card never sent is a different answer"
        );
        assert!(!capabilities.life_cycle.is_reported());
    }

    #[test]
    fn a_directory_the_card_never_understood_is_not_reported_as_empty() {
        // Every probe draws 6A 86, which this crate does not read as "not
        // there". Reporting that directory as empty would be inventing a
        // finding, so the walk says the enumeration did not work.
        let mut card = FakeCard::default()
            .with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None))
            .with("3F00/7F20", fcp(id("7F20"), DIRECTORY_DESCRIPTOR, None))
            .script(&[0x00, 0xA4, 0x08, 0x04, 0x02, 0x7F, 0x20], &[0x6A, 0x86]);
        let tree = walk(&mut card, &dialect(), &options_for(&["7F20"])).unwrap();

        // The note belongs to the directory whose enumeration failed, which is
        // the master file here: it is the frame that drew the refusals.
        let directory = tree.node(tree.root()).unwrap();
        assert!(
            directory.notes().contains(&Note::EnumerationRefused {
                status: StatusWord::new(0x6A, 0x86),
                probed: 1
            }),
            "and the walk says why: {:?}",
            directory.notes()
        );
        assert_eq!(
            tree.at(&path_of("3F00/7F20")).unwrap().state(),
            &NodeState::Refused {
                status: Some(StatusWord::new(0x6A, 0x86))
            }
        );
    }

    #[test]
    fn a_directory_whose_probes_all_say_not_there_is_empty_and_says_nothing() {
        let mut card = FakeCard::default()
            .with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None))
            .with("3F00/7F20", fcp(id("7F20"), DIRECTORY_DESCRIPTOR, None));
        let tree = walk(&mut card, &dialect(), &options_for(&["7F20"])).unwrap();

        // 7F20 has no children at all, so its one probe drew 6A 82, which is
        // the answer rather than a caveat.
        let directory = tree.at(&path_of("3F00/7F20")).unwrap();
        let children: Vec<String> = tree
            .children(directory.id())
            .map(|node| format!("{} {:?}", node.path(), node.state()))
            .collect();
        assert_eq!(children, vec!["3F00/7F20/7F20 Absent".to_owned()]);
        assert!(
            !directory
                .notes()
                .iter()
                .any(|note| matches!(note, Note::EnumerationRefused { .. })),
            "an empty directory is a fact, not a caveat: {:?}",
            directory.notes()
        );
        assert!(
            !tree
                .node(tree.root())
                .unwrap()
                .notes()
                .iter()
                .any(|note| matches!(note, Note::EnumerationRefused { .. })),
            "the master file found a directory, so its enumeration worked"
        );
        assert!(!tree.report().is_truncated());
    }

    // ------------------------------------------------------------- the wire

    #[test]
    fn the_path_form_names_a_file_by_where_it_is_and_the_identifier_form_by_what_it_is() {
        let mut card = sample_card();
        walk(&mut card, &dialect(), &options_for(&["7F20", "6F3A"])).unwrap();

        let selects = card.with_instruction(0xA4);
        assert!(
            selects.contains(&vec![0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]),
            "the master file is always named by identifier: {selects:X?}"
        );
        assert!(selects.contains(&vec![0x00, 0xA4, 0x08, 0x04, 0x02, 0x7F, 0x20]));
        assert!(selects.contains(&vec![0x00, 0xA4, 0x08, 0x04, 0x04, 0x7F, 0x20, 0x6F, 0x3A]));
    }

    #[test]
    fn the_identifier_form_asks_for_two_octets_at_every_level() {
        let mut card = sample_card();
        let options = Options {
            addressing: Addressing::Identifier,
            candidates: Candidates::List(vec![id("7F20"), id("6F3A")]),
            ..Options::default()
        };
        walk(&mut card, &dialect(), &options).unwrap();

        let selects = card.with_instruction(0xA4);
        assert!(selects.contains(&vec![0x00, 0xA4, 0x00, 0x04, 0x02, 0x7F, 0x20]));
        assert!(selects.contains(&vec![0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3A]));
        assert!(
            !selects.iter().any(|command| command.get(3) == Some(&0x08)),
            "this form never asks by path"
        );
    }

    #[test]
    fn the_walk_asks_for_capabilities_and_not_the_control_information_template() {
        // P2 04 and not P2 00: swSIM's 3GPP SELECT treats anything other than
        // 04 or 0C as RFU and answers 6A 86, which is the failure this shape
        // exists to avoid.
        let mut card = sample_card();
        walk(&mut card, &dialect(), &options_for(&["2FE2"])).unwrap();
        for command in card.with_instruction(0xA4) {
            assert_eq!(
                command.get(3),
                Some(&0x04),
                "P2 must ask for the capabilities template: {command:02X?}"
            );
        }
    }

    #[test]
    fn every_queued_template_is_followed_up_exactly_once() {
        let mut card = sample_card();
        let tree = walk(
            &mut card,
            &dialect(),
            &options_for(&["7F20", "6F3A", "2FE2"]),
        )
        .unwrap();
        assert_eq!(
            card.with_instruction(0xC0).len(),
            tree.selected().count(),
            "one GET RESPONSE per selected file"
        );
        assert!(
            card.with_instruction(0xC0)
                .iter()
                .all(|command| command.first() == Some(&0xA0)),
            "GET RESPONSE goes at the class swSIM dispatches it from"
        );
    }

    // ---------------------------------------------------------- tree shape

    #[test]
    fn the_tree_is_pre_order_so_a_subtree_is_one_contiguous_slice() {
        let mut card = sample_card();
        let tree = walk(
            &mut card,
            &dialect(),
            &options_for(&["7F20", "6F3A", "2FE2"]),
        )
        .unwrap();

        assert_eq!(
            paths_of(tree.descendants(tree.root())),
            vec![
                "3F00".to_owned(),
                "3F00/2FE2".to_owned(),
                "3F00/6F3A".to_owned(),
                "3F00/7F20".to_owned(),
                "3F00/7F20/2FE2".to_owned(),
                "3F00/7F20/6F3A".to_owned(),
                "3F00/7F20/7F20".to_owned(),
            ]
        );
        for (index, node) in tree.nodes().iter().enumerate() {
            assert_eq!(node.id(), NodeId(index));
            for child in tree.children(node.id()) {
                assert_eq!(
                    child.path().depth(),
                    node.path().depth() + 1,
                    "{child:?} is not one level under {node:?}"
                );
                assert_eq!(child.path().parent().as_ref(), Some(node.path()));
            }
        }
    }

    #[test]
    fn every_node_is_reachable_from_the_root_and_nothing_points_outside_the_tree() {
        let mut card = sample_card();
        let tree = walk(
            &mut card,
            &dialect(),
            &options_for(&["7F20", "6F3A", "2FE2"]),
        )
        .unwrap();
        let mut seen = vec![false; tree.len()];
        let mut stack = vec![tree.root()];
        while let Some(id) = stack.pop() {
            let node = tree.node(id).expect("a handle from the tree is inside it");
            assert!(!seen[id.0], "{node:?} was reached twice");
            seen[id.0] = true;
            stack.extend(node.children().iter().copied());
        }
        assert!(seen.iter().all(|reached| *reached));
        assert_eq!(tree.descendants(tree.root()).len(), tree.len());
        assert!(tree.node(NodeId(tree.len() + 100)).is_none());
        assert_eq!(tree.descendants(NodeId(tree.len() + 100)), &[] as &[Node]);
    }

    #[test]
    fn the_tree_reports_the_dialect_and_the_assumptions_it_ran_under() {
        let mut card = sample_card();
        let options = Options {
            meaning: StatusMeaning::unverified().with_forbidden(StatusWord::new(0x94, 0x03)),
            ..options_for(&["2FE2"])
        };
        let tree = walk(&mut card, &dialect(), &options).unwrap();
        assert_eq!(tree.dialect_name(), TagSet::swicc().name());
        assert_eq!(tree.addressing(), Addressing::PathFromMasterFile);
        assert_eq!(tree.limits(), &options.limits);
        assert_eq!(
            tree.meaning().meaning(StatusWord::new(0x94, 0x03)),
            Some(RefusalKind::Forbidden),
            "the table the tree was read under is available to a scan"
        );
    }

    #[test]
    fn the_candidate_set_is_the_five_sim_families_and_the_walk_stays_inside_the_bound() {
        let (candidates, truncated) = Candidates::SimFamilies.identifiers(usize::MAX);
        assert!(!truncated);
        assert_eq!(candidates.len(), DEFAULT_MAX_CHILDREN);
        for family in [0x2Fu8, 0x4F, 0x5F, 0x6F, 0x7F] {
            assert!(
                candidates.contains(&FileId::from_bytes([family, 0x00])),
                "family {family:02X}xx is missing"
            );
        }
        assert!(
            !candidates.contains(&FileId::MASTER_FILE),
            "the master file is not in any SIM family"
        );

        let (bounded, truncated) = Candidates::SimFamilies.identifiers(10);
        assert!(truncated);
        assert_eq!(bounded.len(), 10);

        let mut card = sample_card();
        let bounded = Options {
            candidates: Candidates::SimFamilies,
            limits: Limits {
                max_children: 3,
                ..Limits::default()
            },
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &bounded).unwrap();
        assert_eq!(
            card.with_instruction(0xA4).len(),
            5,
            "the EF.DIR probe, the master file and three"
        );
        assert_eq!(tree.len(), 4);
        assert_eq!(tree.report().truncated_by, Some(Limit::Children));
    }

    #[test]
    fn a_candidate_range_spans_exactly_what_it_says() {
        let (candidates, truncated) = Candidates::Range {
            first: id("2F00"),
            last: id("2F03"),
        }
        .identifiers(usize::MAX);
        assert!(!truncated);
        assert_eq!(
            candidates,
            vec![id("2F00"), id("2F01"), id("2F02"), id("2F03")]
        );
        assert!(!candidates.contains(&FileId::MASTER_FILE));
    }

    #[test]
    fn the_report_counts_what_was_found_and_agrees_with_the_tree() {
        let mut card = sample_card();
        let options = Options {
            candidates: Candidates::List(vec![
                id("7F20"),
                id("6F3A"),
                id("2FE2"),
                id("2F01"),
                id("0000"),
            ]),
            meaning: StatusMeaning::default().with_forbidden(StatusWord::new(0x94, 0x03)),
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &options).unwrap();
        let report = tree.report();

        assert_eq!(report.nodes, tree.len());
        assert_eq!(report.selected, tree.selected().count());
        assert_eq!(report.absent, tree.refused(RefusalKind::Absent).count());
        assert_eq!(
            report.forbidden,
            tree.refused(RefusalKind::Forbidden).count()
        );
        assert_eq!(report.refused, tree.unclassified_refusals().count());
        assert_eq!(
            report.nodes,
            report.selected + report.absent + report.forbidden + report.refused
        );
        assert!(report.directories >= 2);
        assert!(!report.is_truncated());
    }

    #[test]
    fn a_reported_field_that_decodes_is_not_a_field_that_was_omitted_or_broken() {
        let value = Reported::Reported(7u8);
        assert_eq!(value.reported(), Some(&7));
        assert!(value.is_reported());
        assert!(value.unreadable().is_none());
        assert_eq!(value.clone().map(|v| v * 2), Reported::Reported(14));

        let missing: Reported<u8> = Reported::NotReported;
        assert_eq!(missing.reported(), None);
        assert!(!missing.is_reported());
        assert_eq!(missing.clone().map(|v| v * 2), Reported::NotReported);

        let broken: Reported<u8> =
            Reported::Unreadable(fcp::Error::Tlv(crate::tlv::Error::IndefiniteLength));
        assert!(broken.is_reported(), "it was sent");
        assert_eq!(broken.reported(), None);
        assert!(broken.unreadable().is_some());
        assert!(matches!(
            broken.map(|v| v * 2),
            Reported::Unreadable(fcp::Error::Tlv(crate::tlv::Error::IndefiniteLength))
        ));
        assert_eq!(Reported::<u8>::default(), Reported::NotReported);
    }

    #[test]
    fn a_dedicated_file_name_is_trimmed_of_the_padding_a_card_writes() {
        let mut body = tlv(0x82, &DIRECTORY_DESCRIPTOR);
        body.extend(tlv(0x83, &id("7F20").to_bytes()));
        let mut padded = b"TELECOM".to_vec();
        padded.extend(std::iter::repeat_n(0u8, 8));
        body.extend(tlv(0x84, &padded));
        let named = tlv(0x62, &body);

        let mut card = sample_card()
            .script(
                &[0x00, 0xA4, 0x08, 0x04, 0x02, 0x7F, 0x20],
                &[0x61, named.len() as u8],
            )
            .script(
                &[0xA0, 0xC0, 0x00, 0x00, named.len() as u8],
                &[named.as_slice(), &[0x90, 0x00]].concat(),
            );
        let tree = walk(&mut card, &dialect(), &options_for(&["7F20"])).unwrap();
        assert_eq!(
            tree.at(&path_of("3F00/7F20"))
                .unwrap()
                .state()
                .capabilities()
                .unwrap()
                .name,
            Reported::Reported(b"TELECOM".to_vec())
        );
    }

    #[test]
    fn a_name_under_a_mapping_that_has_no_tag_for_one_is_not_reported() {
        // A hand-built mapping may leave df_name unset; the card's `84` is then
        // an unexplained tag, not a name.
        let mut body = tlv(0x82, &DIRECTORY_DESCRIPTOR);
        body.extend(tlv(0x84, b"TELECOM\0\0"));
        body.extend(tlv(0x83, &id("7F20").to_bytes()));
        // C6 is a tag neither table in this crate claims, which is exactly the
        // gap this assertion is about.
        body.extend(tlv(0xC6, &[0x01, 0x02]));
        let named = tlv(0x62, &body);

        let mut card = sample_card()
            .script(
                &[0x00, 0xA4, 0x08, 0x04, 0x02, 0x7F, 0x20],
                &[0x61, named.len() as u8],
            )
            .script(
                &[0xA0, 0xC0, 0x00, 0x00, named.len() as u8],
                &[named.as_slice(), &[0x90, 0x00]].concat(),
            );
        let tree = walk(
            &mut card,
            &TagSet::named("no df_name")
                .with_file_descriptor(Tag::new(0x82))
                .with_file_id(Tag::new(0x83)),
            &options_for(&["7F20"]),
        )
        .unwrap();
        let capabilities = tree
            .at(&path_of("3F00/7F20"))
            .unwrap()
            .state()
            .capabilities()
            .unwrap();
        assert_eq!(capabilities.name, Reported::NotReported);
        assert!(
            !capabilities.unknown_tags.is_empty(),
            "and a tag the mapping could not read is named rather than dropped"
        );
    }

    #[test]
    fn kinds_report_what_the_card_said_and_nothing_more() {
        assert!(Kind::MasterFile.is_container());
        assert_eq!(Kind::MasterFile.as_file_kind(), Some(FileKind::MasterFile));
        assert!(Kind::Reported(FileKind::DedicatedFile).is_container());
        assert!(!Kind::Reported(FileKind::ElementaryFile).is_container());
        assert!(!Kind::Unreported.is_container());
        assert_eq!(Kind::Unreported.as_file_kind(), None);
        assert_eq!(
            Kind::Reported(FileKind::ElementaryFile).as_file_kind(),
            Some(FileKind::ElementaryFile)
        );
    }

    #[test]
    fn node_states_say_exactly_one_thing() {
        let selected = NodeState::Selected {
            kind: Kind::MasterFile,
            capabilities: Box::new(Capabilities::default()),
        };
        assert!(selected.is_selected());
        assert_eq!(selected.refusal(), None);
        assert_eq!(selected.status(), None);
        assert!(selected.capabilities().is_some());
        assert_eq!(selected.kind(), Some(Kind::MasterFile));

        assert_eq!(NodeState::Absent.refusal(), Some(RefusalKind::Absent));
        assert_eq!(NodeState::Absent.status(), None);
        assert!(!NodeState::Absent.is_selected());

        let forbidden = NodeState::Forbidden {
            status: StatusWord::new(0x94, 0x03),
        };
        assert_eq!(forbidden.refusal(), Some(RefusalKind::Forbidden));
        assert_eq!(forbidden.status(), Some(StatusWord::new(0x94, 0x03)));

        // An unclassified refusal is neither absent nor forbidden, and says so
        // by having no refusal at all rather than by guessing one.
        let refused = NodeState::Refused {
            status: Some(StatusWord::new(0x68, 0x00)),
        };
        assert_eq!(refused.refusal(), None);
        assert_eq!(refused.status(), Some(StatusWord::new(0x68, 0x00)));
        assert!(!refused.is_selected());
        assert!(refused.capabilities().is_none());
        assert_eq!(NodeState::Refused { status: None }.status(), None);
    }

    #[test]
    fn refusal_kinds_limits_and_addressing_render_for_a_terminal_and_an_agent() {
        assert_eq!(RefusalKind::Absent.to_string(), "absent");
        assert_eq!(RefusalKind::Forbidden.to_string(), "forbidden");
        assert_eq!(Limit::Depth.to_string(), "maximum path depth");
        assert_eq!(
            Addressing::PathFromMasterFile.to_string(),
            "SELECT by path from the master file"
        );
        assert_eq!(NodeId(7).to_string(), "#7");
    }

    #[test]
    fn a_truncated_walk_is_distinguishable_from_a_complete_one() {
        let mut complete_card = FakeCard::default()
            .with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None))
            .with(
                "3F00/2FE2",
                fcp(id("2FE2"), TRANSPARENT_DESCRIPTOR, Some(1)),
            );
        let complete = walk(&mut complete_card, &dialect(), &options_for(&["2FE2"])).unwrap();
        assert!(complete.is_complete());
        assert_eq!(complete.truncated_by(), None);
        assert!(!complete.report().is_truncated());

        let mut deep_card =
            FakeCard::default().with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None));
        for level in 1..=6u8 {
            let path = "3F00".to_owned() + &"/5F01".repeat(usize::from(level));
            deep_card = deep_card.with(&path, fcp(id("5F01"), DIRECTORY_DESCRIPTOR, None));
        }
        let truncated = walk(
            &mut deep_card,
            &dialect(),
            &Options {
                candidates: Candidates::List(vec![id("5F01")]),
                limits: Limits {
                    max_depth: 3,
                    ..Limits::default()
                },
                ..Options::default()
            },
        )
        .unwrap();

        // The two trees are not distinguishable by their contents, only by
        // this. A caller that reports the files without it is under-reporting.
        assert!(!truncated.is_complete());
        assert_eq!(truncated.truncated_by(), Some(Limit::Depth));
        assert!(truncated.report().is_truncated());

        // And the reason is on a node, not only in the report, so a caller that
        // renders one node can still say why that node has no children.
        let stopped = truncated
            .nodes()
            .iter()
            .find(|node| {
                node.notes().contains(&Note::Limit {
                    limit: Limit::Depth,
                })
            })
            .expect("the node the walk stopped at carries the reason");
        assert_eq!(stopped.path().depth(), 4);
        assert!(stopped.children().is_empty());

        // The two are not equal as values, so a baseline or a diff built on
        // Tree cannot confuse one for the other either.
        assert_ne!(complete, truncated);
    }

    #[test]
    fn application_aliases_7ff0_to_7fff_are_not_followed_inside_an_application() {
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xFF, 0xFF];
        let mut record = tlv(0x61, &tlv(0x4F, &aid));
        record.resize(0x20, 0xFF);
        record.extend_from_slice(&[0x90, 0x00]);
        let mut card = FakeCard::default()
            .with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None))
            .with(
                "3F00/2F00",
                tlv(
                    0x62,
                    &[
                        tlv(0x82, &[0x42, 0x21, 0x00, 0x20, 0x01]),
                        tlv(0x83, &[0x2F, 0x00]),
                    ]
                    .concat(),
                ),
            )
            .with("3F00/7FF0", fcp(id("7FF0"), DIRECTORY_DESCRIPTOR, None))
            .with(
                "3F00/7FF0/6F07",
                fcp(id("6F07"), TRANSPARENT_DESCRIPTOR, Some(9)),
            )
            .with(
                "3F00/7FF0/7FF0",
                fcp(id("7FF0"), DIRECTORY_DESCRIPTOR, None),
            )
            .with(
                "3F00/7FF0/7FFF",
                fcp(id("7FFF"), DIRECTORY_DESCRIPTOR, None),
            )
            .script(&[0x00, 0xB2, 0x01, 0x04, 0x20], &record);
        card.adfs.push((aid.to_vec(), path_segments("3F00/7FF0")));

        let tree = walk(
            &mut card,
            &dialect(),
            &options_for(&["2F00", "6F07", "7FF0", "7FFF"]),
        )
        .unwrap();

        let app = "3F00/ADF:A0000000871002FFFF";
        assert!(tree.contains(&path_of(&format!("{app}/6F07"))));
        for alias in ["7FF0", "7FFF"] {
            assert!(
                !tree.contains(&path_of(&format!("{app}/{alias}"))),
                "{alias} inside an application is an alias, not a child"
            );
        }
    }

    #[test]
    fn absent_probes_do_not_spend_the_node_budget() {
        // Four files exist; the default candidates probe 1280 identifiers per
        // directory. A budget of 5 files must complete (issue #90).
        let mut card = sample_card();
        let options = Options {
            limits: Limits {
                max_nodes: 5,
                ..Limits::default()
            },
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &options).unwrap();
        assert!(tree.len() > 1000, "absent probes are still recorded");
        assert!(tree.is_complete(), "{:?}", tree.limits_hit());
    }

    #[test]
    fn the_number_of_exchanges_a_walk_issues_is_bounded_by_directories_times_children() {
        // A card that answers every single probe with a directory. Absent
        // probes spend no node budget (issue #90), so the exchange bound is
        // max_directories x max_children and a hostile card cannot make a scan
        // long in time as well as in memory.
        let mut card =
            FakeCard::default().with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None));
        for high in [0x2Fu8, 0x4F, 0x5F, 0x6F, 0x7F] {
            for low in 0..=0xFFu16 {
                let id = FileId::from_bytes([high, low as u8]);
                let mut path = Vec::from(FileId::MASTER_FILE.to_bytes());
                path.extend(id.to_bytes());
                card.files.insert(
                    path,
                    Held {
                        fcp: fcp(id, DIRECTORY_DESCRIPTOR, None),
                        refusal: None,
                    },
                );
            }
        }

        let limits = Limits {
            max_nodes: 64,
            max_directories: 64,
            max_depth: 64,
            ..Limits::default()
        };
        let options = Options {
            candidates: Candidates::SimFamilies,
            limits,
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &options).unwrap();

        let selects = card.with_instruction(0xA4).len();
        // Plus the master file and the EF.DIR probe that finds applications.
        let bound = limits.max_directories * limits.max_children + 2;
        assert!(
            selects <= bound,
            "{selects} SELECTs against a bound of {bound}"
        );
        assert!(!tree.is_complete());
        assert!(tree.truncated_by().is_some());
    }

    #[test]
    fn a_repeated_identifier_is_recorded_and_still_descended() {
        // The case the fixture card actually presents: SELECT resolves
        // 3F00/7F20/7F20 to DF.GSM itself. The walk must record the repeat, keep
        // the file in the tree, and rely on the depth bound to stop.
        let directory = fcp(id("7F20"), DIRECTORY_DESCRIPTOR, None);
        let mut card = FakeCard::default()
            .with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None))
            .with("3F00/7F20", directory.clone())
            .with("3F00/7F20/7F20", directory);
        let options = Options {
            candidates: Candidates::List(vec![id("7F20")]),
            limits: Limits {
                max_depth: 2,
                ..Limits::default()
            },
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &options).unwrap();

        let repeat = tree.at(&path_of("3F00/7F20/7F20")).unwrap();
        assert!(repeat.state().is_selected(), "it is a real file here");
        assert!(repeat.notes().contains(&Note::RepeatedAncestor {
            id: id("7F20"),
            ancestor: path_of("3F00/7F20"),
        }));
        assert_eq!(tree.report().repeated_ancestors, 1);
        assert!(
            repeat.children().is_empty(),
            "and the depth bound is what stopped it, not the repeat"
        );
        assert!(repeat.notes().contains(&Note::Limit {
            limit: Limit::Depth
        }));
    }

    #[test]
    fn every_bound_a_walk_hit_is_reported_not_just_the_first() {
        // A card that is deep enough to hit the depth bound and big enough to
        // hit the node bound afterwards must report both. Reporting only the
        // first understates how much of the card was missed.
        let mut card =
            FakeCard::default().with("3F00", fcp(FileId::MASTER_FILE, DIRECTORY_DESCRIPTOR, None));
        // Breadth: 512 directories directly under the master file, which is
        // what makes the node bound reachable.
        for high in [0x5Fu8, 0x6F] {
            for low in 0..=0xFFu16 {
                let id = FileId::from_bytes([high, low as u8]);
                let mut path = Vec::from(FileId::MASTER_FILE.to_bytes());
                path.extend(id.to_bytes());
                card.files.insert(
                    path,
                    Held {
                        fcp: fcp(id, DIRECTORY_DESCRIPTOR, None),
                        refusal: None,
                    },
                );
            }
        }
        // And depth: a chain under one of them, deeper than max_depth, which
        // is what makes the depth bound reachable. Breadth alone never
        // descends, because a leaf has nothing under it.
        for (level, low) in [0x01u8, 0x02, 0x03, 0x04].into_iter().enumerate() {
            let mut path = Vec::from(FileId::MASTER_FILE.to_bytes());
            path.extend([0x5F, 0x00]);
            for step in 0..=level {
                path.extend([0x5F, low + u8::try_from(step).unwrap_or(0)]);
            }
            card.files.insert(
                path,
                Held {
                    fcp: fcp(FileId::from_bytes([0x5F, low]), DIRECTORY_DESCRIPTOR, None),
                    refusal: None,
                },
            );
        }

        let options = Options {
            candidates: Candidates::List(
                [0x5Fu8, 0x6F]
                    .into_iter()
                    .flat_map(|high| {
                        (0..=0xFFu16).map(move |low| FileId::from_bytes([high, low as u8]))
                    })
                    .collect(),
            ),
            limits: Limits {
                max_depth: 3,
                // Deep enough to reach the depth bound first, small enough that
                // the node bound is then hit as well. The point of the test is
                // that BOTH are reported.
                max_nodes: 300,
                max_directories: 64,
                ..Limits::default()
            },
            ..Options::default()
        };
        let tree = walk(&mut card, &dialect(), &options).unwrap();

        assert!(!tree.is_complete());
        assert!(
            tree.limits_hit().contains(&Limit::Depth),
            "the chain is deeper than max_depth: {:?}",
            tree.limits_hit()
        );
        assert!(
            tree.limits_hit().contains(&Limit::Nodes),
            "and 512 directories is more than max_nodes: {:?}",
            tree.limits_hit()
        );
        // The first is still the first, and the headline does not hide the rest.
        assert_eq!(tree.truncated_by(), tree.limits_hit().first().copied());
        for limit in tree.limits_hit() {
            assert!(tree
                .nodes()
                .iter()
                .any(|node| node.notes().contains(&Note::Limit { limit: *limit })));
        }
        assert!(tree.report().hit(Limit::Nodes));
        assert!(tree.report().hit(Limit::Depth));
        assert!(!tree.report().hit(Limit::Children));
    }

    #[test]
    fn the_defaults_are_named_and_bounded() {
        let options = Options::default();
        assert_eq!(options.addressing, Addressing::PathFromMasterFile);
        assert_eq!(options.candidates, Candidates::SimFamilies);
        assert_eq!(options.meaning, StatusMeaning::file_not_found());
        assert_eq!(options.limits.max_depth, DEFAULT_MAX_DEPTH);
        assert_eq!(options.limits.max_children, DEFAULT_MAX_CHILDREN);
        assert_eq!(options.limits.max_nodes, DEFAULT_MAX_NODES);
        assert_eq!(options.limits.max_directories, DEFAULT_MAX_DIRECTORIES);
        assert_eq!(options.session, session::Policy::default());
        assert_eq!(Options::default().candidates, Candidates::default());
    }
}
