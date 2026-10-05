//! Namespaced `plugin/rule` identifiers, the severity ladder, what a
//! finding is, and the registry that binds an identifier to the code that
//! emits it.
//!
//! **Owns.** The vocabulary every other module speaks: what a finding is
//! *called* ([RuleId]), how bad it is ([Severity]), what a finding *is*
//! ([Finding] and its [Location] and [Evidence]), and the table that binds an
//! identifier to the code that produces it ([Registry]). All of it is part of
//! the contract in AGENTS.md section 3, so all of it is validated here rather
//! than at each call site.
//!
//! **Does not own.** The rule logic. A [Registry] is generic over whatever its
//! rules are handed - a registry over a DF tree in a filesystem module, a
//! registry over an exchange log in an APDU module - precisely so the binding
//! can live here while this module names no type belonging to a card. This
//! module has no dependencies on any other module in the crate and must not
//! acquire any: rule IDs and findings appear in every command's output, so
//! anything they depended on would be pulled into the surface of every command.
//!
//! **Does not own the envelope.** [crate::contract] owns the shape of the JSON
//! a command returns; this module owns the shape of the object that goes
//! *inside* `payload.data`. Neither names the other. A finding reaches the
//! envelope by being serialized into a [serde_json::Value] the caller already
//! had, which is the whole reason `contract` carries an opaque `data`; see
//! [Finding::to_json]. That is why this module now derives `Serialize`: the
//! finding's own keys are this module's to choose, and the wrapper around them
//! is not.
//!
//! **Why rule IDs are validated at all.** AGENTS.md section 3 says rule IDs are
//! addressable by agents and must never be renamed casually, which only works
//! if the set of well-formed IDs is small and a typo is impossible to miss. A
//! loose `String` would let `Filesystem/unreadable_ef` reach an output file
//! and silently never match a baseline.
//!
//! **Why a duplicate ID cannot be registered.** Agents address rules by ID, so
//! two rules sharing one makes every answer about that ID ambiguous from then
//! on: no output can say which of the two fired, and a baseline cannot say
//! which one it was comparing. [Registry::register] refuses before it mutates,
//! and [Registry::evaluate] additionally refuses a producer that emits an ID it
//! was not registered under, which is the same ambiguity arriving by a back
//! door.
//!
//! **Why a finding carries its own coverage.** A finding from a scan that hit a
//! bound may still be *true*, and this project will not call it false - but a
//! consumer that treats the findings of a truncated scan as exhaustive is
//! reading a smaller card than the one that was met. So incompleteness is a
//! field on the finding itself ([Coverage]) and not only a property of the
//! report, because an agent that greps for one rule ID reads one object and
//! never sees the report header. [Findings::partial] is what makes saying so
//! unavoidable rather than optional.
//!
//! **Why evidence is bounded.** Evidence is bytes read off a card, and both of a
//! finding's other two homes - a terminal and an agent's stdout - are places a
//! rule must not be able to fill. [MAX_EVIDENCE_BYTES] and [MAX_EVIDENCE_CHARS]
//! are enforced *at construction*, by types with private fields, so naming a
//! variant directly cannot bypass them, and whatever was dropped is counted
//! and reported rather than silently discarded.

/// This module's name, as recorded in [`crate::MODULES`].
///
/// Referenced by value rather than re-spelt as a literal so that the module
/// table cannot name a module that does not exist.
pub const NAME: &str = "rules";

use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

/// The separator between a plugin namespace and a rule name.
const SEPARATOR: char = '/';

/// A namespaced finding identifier of the form `plugin/rule`.
///
/// The three examples in AGENTS.md section 3 - `filesystem/unreadable-ef`,
/// `auth/scp03-missing-mac`, `gsma/msl-zero-allowed` - are the shapes this type
/// accepts and the shapes every later rule must follow.
///
/// A [`RuleId`] is an identity, not a label. It is compared against saved
/// baselines across runs and across releases, which is why the character set is
/// narrow and checked: lowercase ASCII alphanumerics and single hyphens, with
/// both segments starting and ending on an alphanumeric. Nothing here is
/// negotiable after a release ships.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleId(String);

impl RuleId {
    /// Validates and wraps a `plugin/rule` identifier.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] naming the specific way the identifier is not of
    /// the form `plugin/rule`.
    pub fn new(id: impl Into<String>) -> Result<Self, Error> {
        let id = id.into();
        let mut segments = id.split(SEPARATOR);

        let plugin = segments.next().unwrap_or_default();
        let rule = segments
            .next()
            .ok_or_else(|| Error::MissingSeparator { id: id.clone() })?;
        if segments.next().is_some() {
            return Err(Error::NestedSeparator { id });
        }

        validate_segment(plugin, "plugin", &id)?;
        validate_segment(rule, "rule", &id)?;

        Ok(Self(id))
    }

    /// The identifier as it was validated.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The plugin namespace, the half before the separator.
    pub fn plugin(&self) -> &str {
        // new() guarantees exactly two segments around one separator.
        self.0.split(SEPARATOR).next().unwrap_or_default()
    }

    /// The rule name, the half after the separator.
    pub fn rule(&self) -> &str {
        // new() guarantees exactly two segments around one separator.
        self.0.split(SEPARATOR).nth(1).unwrap_or_default()
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for RuleId {
    /// Serializes as the bare string, so a consumer reads
    /// `finding["rule"] == "filesystem/unreadable-ef"` without a nested
    /// object to unwrap.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RuleId {
    /// **Re-validates on the way in.**
    ///
    /// A rule ID read back from a baseline file has been through a text editor
    /// and possibly through nothing at all, and this crate will not hold an ID
    /// it could have refused to construct. Without this, a baseline naming
    /// `Filesystem/Unreadable_EF` would parse into a `RuleId` that no
    /// registry could ever have produced, and the comparison it feeds would be
    /// against a rule that does not exist.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Checks one half of a `plugin/rule` identifier.
///
/// Separate from [`RuleId::new`] only to keep that function readable; the
/// label is carried into the error so a caller sees which half was wrong.
fn validate_segment(segment: &str, label: &str, id: &str) -> Result<(), Error> {
    let empty = if label == "plugin" {
        Error::EmptyPlugin { id: id.to_owned() }
    } else {
        Error::EmptyRule { id: id.to_owned() }
    };

    if segment.is_empty() {
        return Err(empty);
    }
    if let Some(character) = segment.chars().find(|c| !is_allowed(*c)) {
        return Err(Error::IllegalCharacter {
            id: id.to_owned(),
            character,
        });
    }
    let first = segment.chars().next().expect("checked non-empty");
    let last = segment.chars().next_back().expect("checked non-empty");
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return Err(Error::MisplacedHyphen {
            id: id.to_owned(),
            segment: segment.to_owned(),
        });
    }
    if segment.contains("--") {
        return Err(Error::RepeatedHyphen { id: id.to_owned() });
    }
    Ok(())
}

/// Whether a character may appear inside a plugin or rule name.
///
/// Deliberately not `char::is_alphanumeric`: that is true for non-ASCII
/// letters, and a rule ID is something an agent types, greps, and puts in a
/// shell pipeline. ASCII only.
const fn is_allowed(character: char) -> bool {
    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
}

/// Everything that can go wrong when validating a [`RuleId`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No `/` at all.
    #[error("rule ID {id:?} has no {SEPARATOR:?}; expected plugin{SEPARATOR}rule")]
    MissingSeparator {
        /// The rejected identifier.
        id: String,
    },

    /// More than one `/`.
    #[error("rule ID {id:?} has more than one {SEPARATOR:?}; namespacing is exactly one level")]
    NestedSeparator {
        /// The rejected identifier.
        id: String,
    },

    /// Nothing before the `/`.
    #[error("rule ID {id:?} has an empty plugin namespace")]
    EmptyPlugin {
        /// The rejected identifier.
        id: String,
    },

    /// Nothing after the `/`.
    #[error("rule ID {id:?} has an empty rule name")]
    EmptyRule {
        /// The rejected identifier.
        id: String,
    },

    /// A character outside lowercase ASCII alphanumerics and `-`.
    #[error(
        "rule ID {id:?} contains {character:?}, which is not lowercase ASCII, a digit, or a hyphen"
    )]
    IllegalCharacter {
        /// The rejected identifier.
        id: String,
        /// The first offending character.
        character: char,
    },

    /// A segment that starts or ends with a hyphen.
    #[error("rule ID {id:?} has segment {segment:?} starting or ending with a hyphen")]
    MisplacedHyphen {
        /// The rejected identifier.
        id: String,
        /// The offending segment.
        segment: String,
    },

    /// A segment containing `--`.
    #[error("rule ID {id:?} contains a doubled hyphen")]
    RepeatedHyphen {
        /// The rejected identifier.
        id: String,
    },
}

/// How serious a finding is, ordered from least to most serious.
///
/// The declaration order *is* the ladder, which is what makes the derived
/// [`Ord`] correct and what `--severity <level>` filters against. Reordering
/// these variants silently changes what a threshold means, so the order is
/// part of the contract and [`Severity::LADDER`] exists to make a mistake
/// visible in a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Severity {
    /// Worth reporting, not worth failing a build over.
    #[default]
    Info,
    /// A real weakness with limited impact.
    Low,
    /// A real weakness worth acting on.
    Medium,
    /// A weakness that should be fixed before shipping.
    High,
    /// A weakness that makes the card unfit for its purpose.
    Critical,
}

impl Severity {
    /// Every severity, least to most serious.
    ///
    /// The ordering is the filter contract: `--severity high` keeps `High`
    /// and `Critical` and drops everything below. Iterate this to build a
    /// parser rather than matching on the variants by hand.
    pub const LADDER: [Self; 5] = [
        Self::Info,
        Self::Low,
        Self::Medium,
        Self::High,
        Self::Critical,
    ];

    /// Whether this severity is at least as serious as `threshold`.
    ///
    /// This is the whole of what `--severity` does.
    pub const fn at_least(self, threshold: Self) -> bool {
        (self as u8) >= (threshold as u8)
    }

    /// The severity's position on the ladder, counting from zero.
    ///
    /// Stable within a release. Intended for putting an ordering into JSON that
    /// something other than this crate has to compare.
    pub const fn rank(self) -> u8 {
        self as u8
    }

    /// The severity's own name, lowercase.
    ///
    /// The spelling `--severity` accepts and the JSON carries. [`Severity::rank`]
    /// is the number; this is the word. Both are in every finding, because one
    /// is what a person reads and the other is what something other than this
    /// crate compares.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// The lowest severity a filter keeps.
    pub const MIN: Self = Self::Info;

    /// The highest severity on the ladder.
    pub const MAX: Self = Self::Critical;
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Matches the spelling `FromStr` accepts, so Display and FromStr are
        // inverse for every case-insensitive spelling.
        f.write_str(self.id())
    }
}

impl Serialize for Severity {
    /// Serializes as the name, not the number.
    ///
    /// The number is carried alongside as `severity_rank` rather than instead
    /// of this, because an agent filtering a report reads the word and a
    /// program sorting one reads the number.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.id())
    }
}

impl<'de> Deserialize<'de> for Severity {
    /// Rejects anything off the ladder, whatever its case.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

impl FromStr for Severity {
    type Err = UnknownSeverity;

    /// Parses a severity as typed on a command line.
    ///
    /// Case-insensitive, unlike [`RuleId`]: a severity arrives from a human
    /// typing `--severity HIGH`, whereas a rule ID arrives from a baseline
    /// file where exact spelling is what is being matched.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(UnknownSeverity(text.to_owned())),
        }
    }
}

/// A severity name that is not on the ladder.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a severity; expected one of info, low, medium, high, critical")]
pub struct UnknownSeverity(pub String);

// ---------------------------------------------------------------------------
// What a card answered with
// ---------------------------------------------------------------------------

/// The two octets a card answered with, verbatim.
///
/// **This type classifies nothing, on purpose.** There is no `is_success`
/// here, and that is the decision rather than the omission. AGENTS.md section
/// 2 records that `91 xx` is not a failure, and that
/// [`crate::apdu::StatusWord::is_success`] answering `false` for it is
/// correct: deciding whether a given 9x status is acceptable needs the command
/// that was sent, which is a rule-layer question and belongs in a rule. This
/// type is the rule layer's input, not its answer, so it hands the two octets
/// over unaltered and lets the rule decide.
///
/// Deliberately **not** [`crate::apdu::StatusWord`]: this module is a leaf and
/// may not name a type belonging to another one. The rendering below is
/// byte-for-byte identical to that type's `Display`, so a status word in a
/// finding reads the same as a status word in a scan report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Status([u8; 2]);

impl Status {
    /// Builds a status word from its two octets, SW1 and SW2.
    pub const fn new(sw1: u8, sw2: u8) -> Self {
        Self([sw1, sw2])
    }

    /// Builds a status word from the two octets a card sent.
    pub const fn from_bytes(bytes: [u8; 2]) -> Self {
        Self(bytes)
    }

    /// The two octets, as they arrived.
    pub const fn to_bytes(self) -> [u8; 2] {
        self.0
    }

    /// SW1, the procedure byte.
    pub const fn sw1(self) -> u8 {
        self.0[0]
    }

    /// SW2, which carries a length in the 9x, 61 and 6C ranges.
    pub const fn sw2(self) -> u8 {
        self.0[1]
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X}{:02X}", self.0[0], self.0[1])
    }
}

impl Serialize for Status {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Status {
    /// Accepts exactly four hexadecimal digits, in either case.
    ///
    /// Anything else refuses, because a baseline written by a future version
    /// must not be read back as a status word this crate never saw.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let digits = raw.as_bytes();
        if digits.len() != 4 {
            return Err(serde::de::Error::custom(format!(
                "{raw:?} is not a status word; expected four hexadecimal digits"
            )));
        }
        let mut bytes = [0u8; 2];
        for (index, octet) in bytes.iter_mut().enumerate() {
            let pair = &digits[index * 2..index * 2 + 2];
            *octet = (hex_digit(pair[0]).ok_or_else(|| malformed(&raw))? << 4)
                | hex_digit(pair[1]).ok_or_else(|| malformed(&raw))?;
        }
        Ok(Self(bytes))
    }
}

/// One hexadecimal digit as its value.
const fn hex_digit(character: u8) -> Option<u8> {
    match character {
        b'0'..=b'9' => Some(character - b'0'),
        b'a'..=b'f' => Some(character - b'a' + 10),
        b'A'..=b'F' => Some(character - b'A' + 10),
        _ => None,
    }
}

/// The error a string that is not four hexadecimal digits gets.
///
/// Generic in the caller's error type because `serde::de::Error` is a trait,
/// not a type, and this is the message both refusal paths below share.
fn malformed<E: serde::de::Error>(raw: &str) -> E {
    E::custom(format!(
        "{raw:?} is not a status word; expected four hexadecimal digits"
    ))
}

// ---------------------------------------------------------------------------
// Where a finding is
// ---------------------------------------------------------------------------

/// How a card answered when it was asked for a file.
///
/// The four spellings are the four [`crate::walk::NodeState`] refusals, and
/// they are carried unchanged into JSON so that one vocabulary describes a walk
/// and a finding: an agent that branches on `data.files[].state` and one that
/// branches on `findings[].location.access` see the same words.
///
/// **They are not interchangeable, and this is the reason the type exists.** A
/// file that is not there is not a vulnerability; a file that is there and that
/// this terminal may not read may be either an access control working correctly
/// or the most valuable thing on the card. A rule that produces a finding from
/// a forbidden file and a rule that produces one from an absent file have
/// found different things, and a consumer has to be able to tell them apart
/// without reading the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAccess {
    /// The card selected the file and described it.
    Selected,
    /// The card said the file is not there.
    Absent,
    /// The card said the file is there and this terminal may not have it.
    Forbidden,
    /// The card refused in a way nothing has classified.
    Refused,
}

impl FileAccess {
    /// Every access state, in the order a walk reports them.
    pub const ALL: [Self; 4] = [Self::Selected, Self::Absent, Self::Forbidden, Self::Refused];
}

impl fmt::Display for FileAccess {
    /// The same four words the JSON carries.
    ///
    /// The name this prints is the one the JSON carries, and a test asserts
    /// the two never drift, because a human report and the JSON that an agent
    /// parses have to call the same file the same thing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(access_name(*self))
    }
}

/// Where on the card a finding is, in the vocabulary of the thing itself.
///
/// Not a sentence and not a path into a general string. An agent that wants to
/// go and look at what a finding is about needs an address it can hand to
/// another command, so every variant names a thing a card actually has, and
/// the `File` variant keeps absent, forbidden and refused apart because the
/// three mean different things to a reader.
///
/// The `kind` field is present on every rendering, including
/// `{"kind":"card"}`, so a consumer can branch on it without first checking
/// which keys exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Location {
    /// The card as a whole, where the rule has nothing more specific to say.
    Card,

    /// A file in the card's file system.
    ///
    /// **Prefer the four named constructors** - [`Location::selected_file`],
    /// [`Location::absent_file`], [`Location::forbidden_file`] and
    /// [`Location::refused_file`] - over naming this variant. A card that
    /// selected a file, or said it was not there, gives no status word to
    /// record, and a hand-built variant can pair `selected` with a status
    /// word without anything downstream being able to object. The constructors
    /// cannot.
    File {
        /// The path, as the walk prints it: `3F00/2F00/6F07`.
        path: String,
        /// What happened when the card was asked for it.
        access: FileAccess,
        /// The status word the card answered with, when it answered with one.
        ///
        /// `null` for a file the card selected, and for a refusal that
        /// carried no status word at all.
        status: Option<Status>,
    },

    /// A TAR, addressed the way a scanner addresses one.
    Tar {
        /// The TAR number. JSON carries the number, not the hex spelling, so
        /// an agent can compare it without parsing.
        tar: u32,
    },

    /// One APDU exchange.
    ///
    /// A finding about a status word is about the *exchange*, never the status
    /// word alone: whether `91 xx` is acceptable depends on what was sent.
    /// See [Status].
    Apdu {
        /// How the rule names this exchange, e.g. `READ BINARY`.
        exchange: String,
    },

    /// Somewhere else, named by the rule that found it.
    Other {
        /// What sort of thing this is, in the thing's own vocabulary: a
        /// profile, an ICCID, a key set.
        subject: String,
        /// Which one of them.
        value: String,
    },
}

impl Location {
    /// A file the card selected.
    #[must_use]
    pub fn selected_file(path: impl Into<String>) -> Self {
        Self::file(path, FileAccess::Selected, None)
    }

    /// A file the card said is not there.
    #[must_use]
    pub fn absent_file(path: impl Into<String>) -> Self {
        Self::file(path, FileAccess::Absent, None)
    }

    /// A file the card said is there and this terminal may not have.
    ///
    /// A finding built here is about an access control, which is a different
    /// claim from the same finding built by [Location::absent_file].
    #[must_use]
    pub fn forbidden_file(path: impl Into<String>, status: Status) -> Self {
        Self::file(path, FileAccess::Forbidden, Some(status))
    }

    /// A file the card refused in a way nothing has classified.
    #[must_use]
    pub fn refused_file(path: impl Into<String>, status: Option<Status>) -> Self {
        Self::file(path, FileAccess::Refused, status)
    }

    /// A file, with its access state and status word stated outright.
    ///
    /// The general form; the four named constructors above are the ones that
    /// cannot produce a combination the card never could.
    #[must_use]
    pub fn file(path: impl Into<String>, access: FileAccess, status: Option<Status>) -> Self {
        Self::File {
            path: path.into(),
            access,
            status,
        }
    }

    /// A TAR.
    #[must_use]
    pub const fn tar(tar: u32) -> Self {
        Self::Tar { tar }
    }

    /// One APDU exchange.
    #[must_use]
    pub fn apdu(exchange: impl Into<String>) -> Self {
        Self::Apdu {
            exchange: exchange.into(),
        }
    }

    /// Somewhere else, named by the rule.
    #[must_use]
    pub fn other(subject: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Other {
            subject: subject.into(),
            value: value.into(),
        }
    }

    /// The access state, for a location that is a file.
    pub const fn file_access(&self) -> Option<FileAccess> {
        match self {
            Self::File { access, .. } => Some(*access),
            Self::Card | Self::Tar { .. } | Self::Apdu { .. } | Self::Other { .. } => None,
        }
    }

    /// Whether this location names a file the card refused to give up.
    pub const fn is_forbidden(&self) -> bool {
        matches!(
            self,
            Self::File {
                access: FileAccess::Forbidden,
                ..
            }
        )
    }

    /// Whether this location names a file the card said is not there.
    pub const fn is_absent(&self) -> bool {
        matches!(
            self,
            Self::File {
                access: FileAccess::Absent,
                ..
            }
        )
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Card => f.write_str("card"),
            Self::Tar { tar } => write!(f, "tar:{tar:08x}"),
            Self::Apdu { exchange } => write!(f, "apdu:{exchange}"),
            Self::Other { subject, value } => write!(f, "{subject}:{value}"),
            Self::File {
                path,
                access,
                status,
            } => {
                write!(f, "file:{path} {}", access_name(*access))?;
                if let Some(status) = status {
                    write!(f, " {status}")?;
                }
                Ok(())
            }
        }
    }
}

/// The JSON spelling of an access state, kept beside [FileAccess] so the two
/// cannot drift.
const fn access_name(access: FileAccess) -> &'static str {
    match access {
        FileAccess::Selected => "selected",
        FileAccess::Absent => "absent",
        FileAccess::Forbidden => "forbidden",
        FileAccess::Refused => "refused",
    }
}

/// The most octets of raw card data one piece of evidence may carry.
///
/// Sixty-four is enough to show the tag and the value that decided a rule, and
/// small enough that a scan which raised every rule it has still prints
/// something a person reads. It is a limit on *one* piece of evidence, not on a
/// finding: nothing in this crate adds evidence together, so the bound is the
/// bound.
pub const MAX_EVIDENCE_BYTES: usize = 64;

/// The most characters of rule-authored text one piece of evidence may carry.
///
/// Evidence text is a decoded value - `"MSL=0"`, `"9804"`, `"EF.SMS"` -
/// not a sentence, and the message beside it is where prose belongs. Bounded
/// for the same reason as [MAX_EVIDENCE_BYTES]: this also reaches a terminal.
pub const MAX_EVIDENCE_CHARS: usize = 64;

/// Raw octets read off a card, bounded at construction.
///
/// Private fields on purpose. If the octets were a public field of a public
/// enum variant then `Evidence::Bytes { octets: body_of_a_64_kilobyte_ef, .. }`
/// would compile and the bound would be advisory. The bound is the point, so it
/// is a property of the type rather than a rule authors are asked to remember.
///
/// Octets past [MAX_EVIDENCE_BYTES] are dropped and **counted**: a truncated
/// evidence is reported as truncated, because silently handing back the first
/// sixty-four bytes of a longer value is how a scan comes to report a card
/// saying something it did not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBytes {
    /// The octets kept, at most [MAX_EVIDENCE_BYTES] of them.
    #[serde(with = "hex_octets")]
    octets: Vec<u8>,
    /// How many octets were dropped.
    omitted: usize,
}

impl EvidenceBytes {
    /// Takes octets, keeping at most [MAX_EVIDENCE_BYTES] and counting the rest.
    pub fn new(octets: impl Into<Vec<u8>>) -> Self {
        let octets = octets.into();
        let omitted = octets.len().saturating_sub(MAX_EVIDENCE_BYTES);
        let octets = if omitted == 0 {
            octets
        } else {
            octets.into_iter().take(MAX_EVIDENCE_BYTES).collect()
        };
        Self { octets, omitted }
    }

    /// The octets kept.
    pub fn as_slice(&self) -> &[u8] {
        &self.octets
    }

    /// How many octets were dropped to stay within [MAX_EVIDENCE_BYTES].
    pub const fn omitted(&self) -> usize {
        self.omitted
    }

    /// How many octets the rule handed over, kept or not.
    pub fn offered(&self) -> usize {
        self.octets.len() + self.omitted
    }

    /// Whether anything was dropped.
    pub const fn is_truncated(&self) -> bool {
        self.omitted > 0
    }
}

impl fmt::Display for EvidenceBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for octet in &self.octets {
            write!(f, "{octet:02x}")?;
        }
        if self.omitted > 0 {
            write!(f, " (+{} octets)", self.omitted)?;
        }
        Ok(())
    }
}

/// Rule-authored text, bounded at construction.
///
/// See [EvidenceBytes] for why this is a type rather than a bare `String`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceText {
    /// The text kept, at most [MAX_EVIDENCE_CHARS] characters.
    value: String,
    /// How many characters were dropped.
    omitted: usize,
}

impl EvidenceText {
    /// Takes text, keeping at most [MAX_EVIDENCE_CHARS] characters.
    pub fn new(value: impl Into<String>) -> Self {
        let value = value.into();
        let count = value.chars().count();
        if count <= MAX_EVIDENCE_CHARS {
            return Self { value, omitted: 0 };
        }
        let kept: String = value.chars().take(MAX_EVIDENCE_CHARS).collect();
        Self {
            value: kept,
            omitted: count - MAX_EVIDENCE_CHARS,
        }
    }

    /// The text kept.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// How many characters were dropped to stay within [MAX_EVIDENCE_CHARS].
    pub const fn omitted(&self) -> usize {
        self.omitted
    }

    /// Whether anything was dropped.
    pub const fn is_truncated(&self) -> bool {
        self.omitted > 0
    }
}

impl fmt::Display for EvidenceText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)?;
        if self.omitted > 0 {
            write!(f, " (+{} chars)", self.omitted)?;
        }
        Ok(())
    }
}

/// What a rule found, and the bytes or values that made it say so.
///
/// Three cases because a rule has three kinds of support: nothing beyond the
/// message, a decoded value it chose to name, and octets straight off the card.
/// Only the last can be large, and it is bounded at construction.
///
/// The `kind` field is present on every rendering, so `{"kind":"none"}` is
/// distinguishable from a missing evidence rather than having to be guessed
/// from the absence of a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    /// Nothing beyond the message itself supports the finding.
    None,
    /// Raw octets read off the card.
    Bytes(EvidenceBytes),
    /// A decoded value the rule named.
    Text(EvidenceText),
}

impl Evidence {
    /// Raw octets read off the card, bounded by [MAX_EVIDENCE_BYTES].
    #[must_use]
    pub fn bytes(octets: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(EvidenceBytes::new(octets))
    }

    /// A decoded value, bounded by [MAX_EVIDENCE_CHARS].
    #[must_use]
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(EvidenceText::new(value))
    }

    /// The octets, when this is octets.
    pub const fn as_bytes(&self) -> Option<&EvidenceBytes> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            Self::None | Self::Text(_) => None,
        }
    }

    /// The text, when this is text.
    pub const fn as_text(&self) -> Option<&EvidenceText> {
        match self {
            Self::Text(text) => Some(text),
            Self::None | Self::Bytes(_) => None,
        }
    }

    /// Whether anything was dropped to stay within the bound.
    pub const fn is_truncated(&self) -> bool {
        match self {
            Self::Bytes(bytes) => bytes.is_truncated(),
            Self::Text(text) => text.is_truncated(),
            Self::None => false,
        }
    }
}

impl fmt::Display for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => Ok(()),
            Self::Bytes(bytes) => write!(f, "{bytes}"),
            Self::Text(text) => write!(f, "{text}"),
        }
    }
}

/// Serde adapter: octets as one lowercase hex string, no separators.
///
/// Hex rather than an array of numbers because evidence is compared byte for
/// byte across runs by whatever gates the build, and `a40a` is something
/// `grep`, `jq -r` and a baseline diff all handle without a formatter. Lower
/// case because that is the spelling `tr` and shell pipelines expect.
mod hex_octets {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Writes octets as lowercase hex.
    pub(super) fn serialize<S: Serializer>(
        octets: &[u8],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        const DIGITS: [u8; 16] = *b"0123456789abcdef";
        let mut hex = String::with_capacity(octets.len() * 2);
        for octet in octets {
            hex.push(char::from(DIGITS[usize::from(octet >> 4)]));
            hex.push(char::from(DIGITS[usize::from(octet & 0x0f)]));
        }
        serializer.serialize_str(&hex)
    }

    /// Reads lowercase or uppercase hex back into octets.
    ///
    /// Refuses an odd length and anything that is not a hexadecimal digit, so
    /// a baseline edited by hand is rejected rather than read as a different
    /// card.
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let raw = String::deserialize(deserializer)?;
        if raw.len() % 2 != 0 {
            return Err(serde::de::Error::custom(format!(
                "{raw:?} is not hex octets; expected an even number of digits"
            )));
        }
        let digits = raw.as_bytes();
        let mut octets = Vec::with_capacity(digits.len() / 2);
        for pair in digits.chunks_exact(2) {
            let high = digit(pair[0]).ok_or_else(|| bad(&raw))?;
            let low = digit(pair[1]).ok_or_else(|| bad(&raw))?;
            octets.push((high << 4) | low);
        }
        Ok(octets)
    }

    /// One hexadecimal digit as its value.
    const fn digit(character: u8) -> Option<u8> {
        match character {
            b'0'..=b'9' => Some(character - b'0'),
            b'a'..=b'f' => Some(character - b'a' + 10),
            b'A'..=b'F' => Some(character - b'A' + 10),
            _ => None,
        }
    }

    /// The error a string that is not hex octets gets.
    fn bad<E: serde::de::Error>(raw: &str) -> E {
        E::custom(format!(
            "{raw:?} is not hex octets; expected hexadecimal digits"
        ))
    }
}

// ---------------------------------------------------------------------------
// Whether a finding is the whole picture
// ---------------------------------------------------------------------------

/// Whether a rule was able to answer its own question completely.
///
/// **This says something about the scan, not about the finding.** A finding
/// raised from a walk that hit a depth bound may be entirely true; the card
/// really did hold that file. What cannot be claimed is that the card holds no
/// others, and that is the claim a consumer makes when it reads a list of
/// findings as exhaustive.
///
/// So it travels on the finding itself and not only on the report. An agent
/// that greps for one rule ID reads one object; the report header is something
/// it may never look at, and the worst outcome available is a truncated scan's
/// findings being read as the whole card. [Findings::partial] is what makes
/// marking them unavoidable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Coverage {
    /// The rule looked at everything it was asked to look at.
    Complete,

    /// Something stopped the scan before that question was fully asked.
    Partial {
        /// Why. Carried verbatim so a consumer can tell a bound that fired
        /// from a transport that failed, which are very different problems
        /// with the same consequence.
        reason: String,
    },
}

impl Coverage {
    /// Whether the scan reached the end of what it was asked to read.
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    /// Why the scan did not, when it did not.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Complete => None,
            Self::Partial { reason } => Some(reason),
        }
    }
}

impl fmt::Display for Coverage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete => f.write_str("complete"),
            Self::Partial { reason } => write!(f, "partial ({reason})"),
        }
    }
}

/// One thing a rule found.
///
/// Five fields, and the argument is which of them an agent actually scripts
/// against. **The [Finding::rule] ID is the address**: a baseline names it, a
/// suppression names it, a CI filter names it, and nothing else about a
/// finding identifies it. That is why it is a validated [`RuleId`] rather
/// than a string, and why [`Registry`] refuses two rules claiming one.
///
/// The rest exist so that a finding can be *checked*:
///
/// - [Finding::severity] is what `--severity` filters and what an exit code
///   is chosen from,
/// - [Finding::location] says where on the card, in the thing's own
///   vocabulary, and keeps a forbidden file apart from an absent one
///   ([Location::is_forbidden]),
/// - [Finding::evidence] is what made the rule say so, bounded so that it
///   cannot fill a terminal,
/// - [Finding::coverage] says whether the scan that produced it reached the end
///   of what it was asked to read ([Coverage`]).
///
/// **Fields are private** for the same reason [`crate::contract::Envelope`]'s
/// are: a finding built by a literal could carry an ID that never validated and
/// an evidence that was never bounded.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Finding {
    rule: RuleId,
    severity: Severity,
    message: String,
    location: Location,
    evidence: Evidence,
    coverage: Coverage,
}

impl Finding {
    /// Builds a finding the scan reached the end of its question for.
    ///
    /// [`Coverage::Complete`] is the default and is also the *honest* one to
    /// have to change: a rule author has to go and say that a scan was
    /// truncated, which is the direction that errs towards telling the truth.
    /// [`Findings::partial`] does it for a whole set at once.
    #[must_use]
    pub fn new(
        rule: RuleId,
        severity: Severity,
        message: impl Into<String>,
        location: Location,
        evidence: Evidence,
    ) -> Self {
        Self {
            rule,
            severity,
            message: message.into(),
            location,
            evidence,
            coverage: Coverage::Complete,
        }
    }

    /// The same finding, marked as raised from a scan that did not finish.
    ///
    /// Returns a new value rather than taking `&mut self`, so a rule
    /// producing a `Vec` can map over it without an index in sight.
    #[must_use]
    pub fn partial(mut self, reason: impl Into<String>) -> Self {
        if self.coverage.is_complete() {
            self.coverage = Coverage::Partial {
                reason: reason.into(),
            };
        }
        self
    }

    /// The rule that produced this finding. The stable public address.
    pub const fn rule(&self) -> &RuleId {
        &self.rule
    }

    /// How serious it is.
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// What the rule said, in a sentence.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Where on the card it is.
    pub const fn location(&self) -> &Location {
        &self.location
    }

    /// What made the rule say so.
    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// Whether the scan that produced this reached the end of its question.
    pub const fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// Whether this finding is at least as serious as `threshold`.
    ///
    /// The whole of what `--severity` does.
    pub const fn at_least(&self, threshold: Severity) -> bool {
        self.severity.at_least(threshold)
    }

    /// The file access state, when the finding is about a file.
    ///
    /// A finding produced from a forbidden file and one produced from an
    /// absent file are different findings, and this is how a caller - or a
    /// consumer reading the JSON - tells them apart without reading the
    /// message.
    pub const fn access(&self) -> Option<FileAccess> {
        self.location.file_access()
    }

    /// Whether this finding is about a file the card refused to give up.
    pub const fn is_forbidden(&self) -> bool {
        self.location.is_forbidden()
    }

    /// Whether this finding is about a file the card said is not there.
    pub const fn is_absent(&self) -> bool {
        self.location.is_absent()
    }

    /// The finding as the object that goes inside `payload.data`.
    ///
    /// This is how a finding reaches the envelope: the caller puts this value
    /// in `contract::Envelope::new` and nothing about the envelope changes.
    /// [`crate::contract`] does not know this type exists and must not - see
    /// the layering note in [`crate`].
    ///
    /// A JSON object, never a map keyed by rule ID. A rule can legitimately
    /// fire many times in one scan - one per TAR, one per file - and a map
    /// would have to either drop the repeats or invent a suffix on the key,
    /// both of which break the address.
    ///
    /// **Key order in the rendered JSON is not part of the contract.**
    /// `serde_json` orders an object's keys itself once the value exists, so
    /// what reaches stdout is not in the order written below. The names are.
    /// `scan` has always emitted `json!` objects the same way, so no
    /// consumer is being asked to cope with anything new.
    ///
    /// The shape is asserted in the tests and is part of the contract:
    ///
    /// ```json
    /// {
    ///   "rule": "filesystem/unreadable-ef",
    ///   "severity": "high",
    ///   "severity_rank": 3,
    ///   "message": "EF.ICCID could not be selected: 9804",
    ///   "location": {
    ///     "kind": "file",
    ///     "path": "3F00/2F00/6F07",
    ///     "access": "forbidden",
    ///     "status": "9804"
    ///   },
    ///   "evidence": { "kind": "bytes", "octets": "a4000a", "omitted": 0 },
    ///   "coverage": { "status": "complete" }
    /// }
    /// ```
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|error| {
            // Every field is a string, an integer, a bounded octet vector or a
            // plain map, none of which serde_json can refuse. A test asserts
            // that this branch is unreachable; it is here so that a future
            // field added without thought cannot take the process down.
            unreachable!("a finding is always renderable: {error}")
        })
    }
}

impl Serialize for Finding {
    /// Hand-written for one reason: the emitted object carries
    /// `severity_rank` beside `severity`, and a derived `Serialize` can
    /// only emit the fields the struct has. Both are in the contract - the word
    /// is what a person or a flag reads, the number is what something other
    /// than this crate sorts by - and keeping them adjacent here is what makes
    /// them impossible to emit apart.
    ///
    /// The **order below is the declaration order** and not a promise about
    /// what a consumer sees: a finding travels through the envelope as a
    /// [`serde_json::Value`], and `serde_json` orders an object's keys on its
    /// own. Only the key names are contract. `scan` has always emitted
    /// `json!` objects the same way, so nothing here is new to a consumer.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut finding = serializer.serialize_struct("Finding", 7)?;
        finding.serialize_field("rule", &self.rule)?;
        finding.serialize_field("severity", &self.severity)?;
        finding.serialize_field("severity_rank", &self.severity.rank())?;
        finding.serialize_field("message", &self.message)?;
        finding.serialize_field("location", &self.location)?;
        finding.serialize_field("evidence", &self.evidence)?;
        finding.serialize_field("coverage", &self.coverage)?;
        finding.end()
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} at {}", self.severity, self.rule, self.location)?;
        f.write_str(": ")?;
        f.write_str(&self.message)?;
        match &self.evidence {
            Evidence::None => {}
            evidence => write!(f, " [{evidence}]")?,
        }
        match &self.coverage {
            Coverage::Complete => Ok(()),
            coverage => write!(f, " ({coverage})"),
        }
    }
}

/// A set of findings, and whether the scan that produced them finished.
///
/// The set is the half that makes truncation hard to get wrong. A producer
/// hands findings over one at a time and has no way to know whether a bound
/// fired three rules later, so [`Findings::complete`] is not the only way
/// this type can be built - and [`Findings::partial`] is the one a scan that
/// hit a bound is meant to use. It marks every finding **and** the set, because
/// a consumer may read either, and it does not overwrite a reason a rule set
/// for itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Findings {
    entries: Vec<Finding>,
    coverage: Coverage,
}

impl Findings {
    /// Findings from a scan that reached the end of what it was asked to read.
    ///
    /// Takes the coverage from the findings themselves, so a rule that already
    /// knows it could not answer its own question keeps saying so.
    #[must_use]
    pub fn complete(entries: Vec<Finding>) -> Self {
        let coverage = match entries
            .iter()
            .find(|finding| !finding.coverage.is_complete())
        {
            Some(finding) => finding.coverage().clone(),
            None => Coverage::Complete,
        };
        Self { entries, coverage }
    }

    /// Findings from a scan that did **not** reach the end.
    ///
    /// Every finding that is still [Coverage::Complete] is marked
    /// [`Coverage::Partial`] with `reason`, and the set is marked with it
    /// too. A finding a rule already marked partial keeps its own reason,
    /// because a rule that knows why *it* could not answer knows more than the
    /// scan's headline bound does.
    #[must_use]
    pub fn partial(entries: Vec<Finding>, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        let entries: Vec<Finding> = entries
            .into_iter()
            .map(|finding| finding.partial(reason.clone()))
            .collect();
        Self {
            entries,
            coverage: Coverage::Partial { reason },
        }
    }

    /// The findings.
    pub fn as_slice(&self) -> &[Finding] {
        &self.entries
    }

    /// Iterates over the findings.
    pub fn iter(&self) -> std::slice::Iter<'_, Finding> {
        self.entries.iter()
    }

    /// How many findings there are.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether the scan that produced these reached the end of its question.
    ///
    /// `false` here means **the list may be short**, not that anything in it
    /// is wrong.
    pub const fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// Whether these findings may be read as the whole of what is there.
    pub const fn is_exhaustive(&self) -> bool {
        self.coverage.is_complete()
    }

    /// The most serious severity among them, if there are any.
    pub fn worst_severity(&self) -> Option<Severity> {
        self.entries.iter().map(Finding::severity).max()
    }

    /// Whether any of them is at least as serious as `threshold`.
    ///
    /// What a caller turning findings into
    /// [`crate::contract::ExitCode::Findings`] needs, and nothing more: the
    /// binary chooses the exit code, because the envelope and the process
    /// status are its to own.
    pub fn reaches(&self, threshold: Severity) -> bool {
        self.entries
            .iter()
            .any(|finding| finding.at_least(threshold))
    }

    /// The findings back out, for a caller that wants the bare `Vec`.
    #[must_use]
    pub fn into_vec(self) -> Vec<Finding> {
        self.entries
    }

    /// The set as the object that goes inside `payload.data`.
    ///
    /// `exhaustive` is the one word to read first. It is `false` when the
    /// scan hit a bound, and it means the list below it may be missing things
    /// - not that anything in it is untrue.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "count": self.entries.len(),
            "exhaustive": self.is_exhaustive(),
            "coverage": self.coverage,
            "findings": self.entries,
        })
    }
}

impl<'a> IntoIterator for &'a Findings {
    type Item = &'a Finding;
    type IntoIter = std::slice::Iter<'a, Finding>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

/// The code that produces a rule's findings.
///
/// Generic over what a rule is handed so that this module never has to name a
/// type belonging to a card: a filesystem module registers
/// `fn(&walk::Tree) -> Vec<Finding>`, an APDU module registers something
/// over its exchange log, and neither type is visible here. That is what keeps
/// this module a leaf while the binding lives in it.
pub type Producer<S> = fn(&S) -> Vec<Finding>;

/// What a rule is, apart from the code that runs it.
///
/// The declaration is the part an agent can read without running anything: the
/// ID it is addressed by, the severity it raises at, one sentence of what it
/// means and, optionally, what to do about it. It is deliberately *not* the
/// finding - a rule describes itself the same way on every card, a finding
/// describes one thing it found on one card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSpec {
    id: RuleId,
    severity: Severity,
    summary: String,
    remediation: Option<String>,
}

impl RuleSpec {
    /// Declares a rule: what it is called, how serious it is, what it means.
    ///
    /// The severity here is the one the rule raises at. A finding may carry a
    /// different one - a rule that usually finds something medium can find
    /// something worse - and the rule's declaration is what `--help`,
    /// documentation and a `sim-doctor rules` listing will show.
    pub fn new(id: RuleId, severity: Severity, summary: impl Into<String>) -> Self {
        Self {
            id,
            severity,
            summary: summary.into(),
            remediation: None,
        }
    }

    /// Adds what to do about it.
    #[must_use]
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// The stable public address.
    pub const fn id(&self) -> &RuleId {
        &self.id
    }

    /// The severity this rule raises at.
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// One sentence of what it means.
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// What to do about it, when there is something to say.
    pub fn remediation(&self) -> Option<&str> {
        self.remediation.as_deref()
    }
}

/// One registered rule: a declaration and the code that runs it.
pub struct Rule<S> {
    spec: RuleSpec,
    producer: Producer<S>,
}

impl<S> Rule<S> {
    /// Binds a declaration to the code that produces its findings.
    pub const fn new(spec: RuleSpec, producer: Producer<S>) -> Self {
        Self { spec, producer }
    }

    /// What the rule is called.
    pub const fn spec(&self) -> &RuleSpec {
        &self.spec
    }

    /// The rule's ID.
    pub const fn id(&self) -> &RuleId {
        self.spec.id()
    }

    /// The severity this rule raises at.
    pub const fn severity(&self) -> Severity {
        self.spec.severity()
    }

    /// Runs the rule.
    ///
    /// Does **not** check that the findings came back under this rule's own ID.
    /// [Registry::evaluate] does, because a bare `run` has nothing to check
    /// against; calling `run` directly is opting out of that check, and the
    /// returned findings are then no more trustworthy than the producer is.
    pub fn run(&self, subject: &S) -> Vec<Finding> {
        (self.producer)(subject)
    }
}

impl<S> fmt::Debug for Rule<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rule")
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

/// The rules this tool knows, keyed by the ID they are addressed by.
///
/// Generic over what the rules are handed; see [Producer]. A registry is the
/// answer to "which code produced `gsma/msl-zero-allowed`", and the reason it
/// is a type rather than a `HashMap` built as rules are written is that a
/// duplicate ID is a permanent contract break rather than a run-time nuisance:
///
/// - agents address rules by ID, so two rules under one ID make every answer
///   about that ID ambiguous from then on,
/// - a baseline records IDs, so it cannot say which of the two it was
///   comparing against,
/// - and nothing in the output would show it happening.
///
/// [Registry::register] therefore refuses before it mutates. [Registry::evaluate]
/// closes the other door: a producer that emits an ID it was not registered
/// under is the same ambiguity arriving at output time, and it is refused too.
#[derive(Debug)]
pub struct Registry<S> {
    rules: Vec<Rule<S>>,
}

impl<S> Default for Registry<S> {
    fn default() -> Self {
        Self { rules: Vec::new() }
    }
}

impl<S> Registry<S> {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a rule, or refuses because its ID is taken.
    ///
    /// # Errors
    ///
    /// [`RegistryError::DuplicateRule`] when `spec.id` is already
    /// registered. The registry is left exactly as it was: the check is before
    /// the insert, so a refused registration cannot half-happen.
    pub fn register(
        &mut self,
        spec: RuleSpec,
        producer: Producer<S>,
    ) -> Result<&Rule<S>, RegistryError> {
        if let Some(existing) = self.get(spec.id()) {
            return Err(RegistryError::DuplicateRule {
                id: spec.id().clone(),
                existing: existing.spec().summary().to_owned(),
            });
        }
        self.rules.push(Rule::new(spec, producer));
        // The push is the only fallible-looking line above and cannot fail.
        Ok(self.rules.last().expect("just pushed"))
    }

    /// The rule with this ID.
    pub fn get(&self, id: &RuleId) -> Option<&Rule<S>> {
        self.rules.iter().find(|rule| rule.id() == id)
    }

    /// Whether an ID is taken.
    pub fn contains(&self, id: &RuleId) -> bool {
        self.get(id).is_some()
    }

    /// Every registered rule, in registration order.
    pub fn rules(&self) -> &[Rule<S>] {
        &self.rules
    }

    /// How many rules are registered.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Every registered ID, in registration order.
    ///
    /// The set an agent scripts against, and the list a
    /// `sim-doctor rules` command would print.
    pub fn ids(&self) -> Vec<&RuleId> {
        self.rules.iter().map(Rule::id).collect()
    }

    /// Runs every rule over one subject and collects the findings.
    ///
    /// In registration order, which is the order a report should read in and
    /// the order two runs of the same build are diffed in.
    ///
    /// # Errors
    ///
    /// [`RegistryError::MisattributedFinding`] if a rule emits a finding
    /// labelled with another rule's ID. That is refused rather than passed on
    /// because it is the same defect [Registry::register] refuses: two things
    /// claiming one public address, and this time the check has come too late
    /// to stop it being written.
    pub fn evaluate(&self, subject: &S) -> Result<Vec<Finding>, RegistryError> {
        let mut findings = Vec::new();
        for rule in &self.rules {
            for finding in rule.run(subject) {
                if finding.rule() != rule.id() {
                    return Err(RegistryError::MisattributedFinding {
                        registered: rule.id().clone(),
                        claimed: finding.rule().clone(),
                    });
                }
                findings.push(finding);
            }
        }
        Ok(findings)
    }
}

/// Everything that can go wrong registering or running a rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// Two rules claiming one ID.
    ///
    /// Named `id` rather than `existing` alone because the message is what
    /// a person sees when a build breaks on this: the whole sentence is
    /// greppable and the ID in it is the exact string agents address.
    #[error(
        "rule ID {id} is already registered (as {existing:?}); two rules may not share an ID, because agents address findings by it"
    )]
    DuplicateRule {
        /// The ID both rules claim.
        id: RuleId,
        /// The summary of the rule already holding it, to say which one.
        existing: String,
    },

    /// A rule emitted a finding under an ID it was not registered as.
    #[error(
        "the rule registered as {registered} emitted a finding labelled {claimed}; a rule may only emit its own ID"
    )]
    MisattributedFinding {
        /// The ID the rule was registered under.
        registered: RuleId,
        /// The ID the finding claimed.
        claimed: RuleId,
    },
}

#[cfg(test)]
mod finding_tests {
    use super::*;

    /// A file identifier's worth of a finding, used wherever the detail does
    /// not matter.
    fn unreadable_ef() -> Finding {
        Finding::new(
            RuleId::new("filesystem/unreadable-ef").unwrap(),
            Severity::High,
            "EF.ICCID could not be selected: 9804",
            Location::forbidden_file("3F00/2F00/6F07", Status::new(0x98, 0x04)),
            Evidence::bytes([0xa4, 0x00, 0x0a, 0x4f]),
        )
    }

    /// The rules below look at nothing at all, which is the point: the registry
    /// is about the binding, and a real subject belongs to whichever module
    /// owns the rules.
    struct NoSubject;

    fn produce_one(_subject: &NoSubject) -> Vec<Finding> {
        vec![unreadable_ef()]
    }

    fn spec(id: &str) -> RuleSpec {
        RuleSpec::new(
            RuleId::new(id).unwrap(),
            Severity::High,
            "a file the card would not give up",
        )
    }

    #[test]
    fn a_finding_renders_to_the_documented_json_object() {
        // The exact bytes, in the order the Serialize impl declares. Every
        // name here is read by something, and a rename is a contract break
        // exactly as much as one in contract is.
        assert_eq!(
            serde_json::to_string(&unreadable_ef()).unwrap(),
            r#"{"rule":"filesystem/unreadable-ef","severity":"high","severity_rank":3,"message":"EF.ICCID could not be selected: 9804","location":{"kind":"file","path":"3F00/2F00/6F07","access":"forbidden","status":"9804"},"evidence":{"kind":"bytes","octets":"a4000a4f","omitted":0},"coverage":{"status":"complete"}}"#
        );

        // The same object as it arrives in the envelope. serde_json orders an
        // object's keys itself, so only the NAMES are contract here - which is
        // why the set below is pinned and the order is not.
        let as_value = unreadable_ef().to_json();
        let mut names: Vec<_> = as_value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "coverage",
                "evidence",
                "location",
                "message",
                "rule",
                "severity",
                "severity_rank",
            ]
        );
        assert_eq!(as_value["rule"], "filesystem/unreadable-ef");
        assert_eq!(as_value["severity"], "high");
        assert_eq!(as_value["severity_rank"], 3);
        assert_eq!(
            serde_json::from_value::<Finding>(as_value).unwrap(),
            unreadable_ef()
        );
    }

    #[test]
    fn to_json_agrees_with_the_derived_serializer_on_every_shape() {
        // to_json is built on the derive, so the two cannot drift unless one
        // of them stops using it. That is the only thing this test is for, and
        // it is also what makes to_json's unreachable! unreachable.
        let findings = [
            unreadable_ef(),
            Finding::new(
                RuleId::new("gsma/msl-zero-allowed").unwrap(),
                Severity::Critical,
                "TAR 00000042 is MSL=0",
                Location::tar(0x42),
                Evidence::text("MSL=0"),
            ),
            Finding::new(
                RuleId::new("auth/scp03-missing-mac").unwrap(),
                Severity::Medium,
                "the secure channel came up without a MAC",
                Location::apdu("READ BINARY"),
                Evidence::None,
            )
            .partial("max_nodes bound hit"),
            Finding::new(
                RuleId::new("euicc/profile-enabled").unwrap(),
                Severity::Low,
                "a second profile is enabled",
                Location::other("profile", "1"),
                Evidence::bytes(vec![0x45]),
            ),
        ];

        for finding in &findings {
            assert_eq!(
                finding.to_json(),
                serde_json::to_value(finding).expect("derives Serialize"),
                "{}",
                finding
            );
            // Every shape, every field, renderable. Nothing here can panic.
            let _ = finding.to_json().to_string();
        }
    }

    #[test]
    fn every_location_kind_carries_its_own_discriminator() {
        // A consumer must be able to branch on kind without first checking
        // which keys exist. Card is the case that would otherwise render as an
        // empty object and look malformed.
        let card = Finding::new(
            RuleId::new("fs/no-files").unwrap(),
            Severity::Info,
            "no elementary files were found",
            Location::Card,
            Evidence::None,
        );
        assert_eq!(
            card.to_json()["location"],
            serde_json::json!({ "kind": "card" })
        );
        assert_eq!(
            card.to_json()["evidence"],
            serde_json::json!({ "kind": "none" })
        );
        assert_eq!(
            card.to_json()["coverage"],
            serde_json::json!({ "status": "complete" })
        );
    }

    #[test]
    fn forbidden_and_absent_are_different_findings_and_stay_different_in_json() {
        // The distinction walk::NodeState keeps in the type, kept here. Two
        // findings with the same rule, the same severity and the same message
        // are still two different findings, and flattening them would report a
        // protected card as an empty one.
        let forbidden = Finding::new(
            RuleId::new("fs/unreadable-ef").unwrap(),
            Severity::High,
            "EF could not be read",
            Location::forbidden_file("3F00/2F00/6F07", Status::new(0x98, 0x04)),
            Evidence::None,
        );
        let absent = Finding::new(
            RuleId::new("fs/unreadable-ef").unwrap(),
            Severity::High,
            "EF could not be read",
            Location::absent_file("3F00/2F00/6F07"),
            Evidence::None,
        );

        assert_ne!(forbidden, absent);
        assert!(forbidden.is_forbidden());
        assert!(!forbidden.is_absent());
        assert!(absent.is_absent());
        assert!(!absent.is_forbidden());
        assert_eq!(forbidden.access(), Some(FileAccess::Forbidden));
        assert_eq!(absent.access(), Some(FileAccess::Absent));

        assert_eq!(
            forbidden.to_json()["location"]["access"],
            serde_json::json!("forbidden")
        );
        assert_eq!(
            absent.to_json()["location"]["access"],
            serde_json::json!("absent")
        );
        // The status word travels with the forbidden one and is null for the
        // absent one, so a consumer cannot confuse "no status word was given"
        // with "no status word was asked for".
        assert_eq!(forbidden.to_json()["location"]["status"], "9804");
        assert_eq!(
            absent.to_json()["location"]["status"],
            serde_json::Value::Null
        );

        // Refused is a third thing again and does not borrow either answer.
        let refused = Finding::new(
            RuleId::new("fs/unreadable-ef").unwrap(),
            Severity::High,
            "EF could not be read",
            Location::refused_file("3F00/2F00/6F07", None),
            Evidence::None,
        );
        assert_eq!(refused.access(), Some(FileAccess::Refused));
        assert!(!refused.is_forbidden() && !refused.is_absent());
    }

    #[test]
    fn a_file_status_word_renders_exactly_as_the_scan_renders_one() {
        // scan.rs writes StatusWord::to_string() into data.forbidden[]. A
        // finding has to read the same, and it cannot call that type because
        // this module is a leaf, so the rendering is pinned here instead.
        assert_eq!(Status::new(0x98, 0x04).to_string(), "9804");
        assert_eq!(Status::new(0x6a, 0x82).to_string(), "6A82");
        assert_eq!(Status::new(0x91, 0x80).to_string(), "9180");
        assert_eq!(Status::from_bytes([0x61, 0x10]).sw1(), 0x61);
        assert_eq!(Status::new(0x6c, 0x00).to_bytes(), [0x6c, 0x00]);
        assert_eq!(Status::new(0x91, 0x80).sw2(), 0x80);
    }

    #[test]
    fn access_names_agree_with_the_json_spelling() {
        // Two spellings of the same four words, kept beside each other on
        // purpose: the serde tag and the name Display prints. If serde ever
        // renames one and not the other, the human report and the JSON stop
        // agreeing about the same file. These are also the four
        // walk::NodeState spellings, unchanged.
        for access in FileAccess::ALL {
            let rendered = serde_json::to_string(&access).unwrap();
            assert_eq!(rendered, format!("\"{access}\""));
            assert_eq!(
                serde_json::from_str::<FileAccess>(&rendered).unwrap(),
                access
            );
        }
        assert_eq!(FileAccess::ALL.len(), 4);
        assert_eq!(
            FileAccess::ALL
                .iter()
                .map(|access| access.to_string())
                .collect::<Vec<_>>(),
            ["selected", "absent", "forbidden", "refused"]
        );
    }

    #[test]
    fn evidence_from_a_card_is_bounded_and_the_omission_is_counted() {
        // A 65 535-octet EF is a legal card answer and a rule that attached one
        // would make one line of scan output longer than the card.
        let body: Vec<u8> = (0..=255u8).cycle().take(65_535).collect();
        let evidence = Evidence::bytes(body.clone());

        let bytes = evidence.as_bytes().expect("is octets");
        assert_eq!(bytes.as_slice().len(), MAX_EVIDENCE_BYTES);
        assert_eq!(bytes.offered(), body.len());
        assert_eq!(bytes.offered(), MAX_EVIDENCE_BYTES + bytes.omitted());
        assert!(bytes.is_truncated());
        assert!(evidence.is_truncated());

        // Silently returning a prefix would be how a scan came to report a
        // card saying something it did not, so the loss is reported.
        assert_eq!(bytes.as_slice(), &body[..MAX_EVIDENCE_BYTES]);
        assert!(
            bytes
                .to_string()
                .ends_with(&format!("(+{} octets)", body.len() - MAX_EVIDENCE_BYTES)),
            "{bytes}"
        );
        assert_eq!(
            serde_json::to_value(&evidence).unwrap(),
            serde_json::json!({
                "kind": "bytes",
                "octets": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                "omitted": 65_471,
            })
        );

        // Short enough is untouched.
        let small = Evidence::bytes([0x90, 0x00]);
        assert!(!small.is_truncated());
        assert_eq!(small.as_bytes().expect("is octets").offered(), 2);
        assert_eq!(small.to_string(), "9000");
    }

    #[test]
    fn the_bound_cannot_be_bypassed_by_naming_the_variant() {
        // The reason EvidenceBytes has private fields. If octets were a public
        // field of a public variant this would compile with any length, and the
        // bound would be a request rather than a rule.
        let forged = Evidence::Bytes(EvidenceBytes::new(vec![0xa4; 4096]));
        assert!(forged.is_truncated());
        assert_eq!(
            forged.as_bytes().expect("is octets").as_slice().len(),
            MAX_EVIDENCE_BYTES
        );
        assert_eq!(
            forged.as_bytes().expect("is octets").offered(),
            4096,
            "the constructor still counted what it was given"
        );
    }

    #[test]
    fn evidence_text_is_bounded_the_same_way() {
        let long = "9".repeat(10_000);
        let evidence = Evidence::text(long.clone());
        let text = evidence.as_text().expect("is text");

        assert_eq!(text.as_str().len(), MAX_EVIDENCE_CHARS);
        assert_eq!(text.omitted(), 10_000 - MAX_EVIDENCE_CHARS);
        assert!(evidence.is_truncated());
        assert!(text
            .to_string()
            .ends_with(&format!("(+{} chars)", 10_000 - MAX_EVIDENCE_CHARS)));

        let short = Evidence::text("MSL=0");
        assert!(!short.is_truncated());
        assert_eq!(short.to_string(), "MSL=0");
        assert!(short.as_bytes().is_none());
    }

    #[test]
    fn a_finding_display_is_bounded_however_much_evidence_a_rule_attaches() {
        // The other home for evidence is a terminal, and a terminal has no size
        // limit either.
        let finding = Finding::new(
            RuleId::new("fs/huge-evidence").unwrap(),
            Severity::Low,
            "an enormous body was attached",
            Location::Card,
            Evidence::bytes(vec![0xff; 65_535]),
        )
        .partial("the scan stopped early");

        let rendered = finding.to_string();
        assert!(
            rendered.len() < 512,
            "Display grew to {} bytes; the bound is not holding",
            rendered.len()
        );
        assert!(
            rendered.contains("65471 octets"),
            "the count of dropped octets is what Display has to say: {rendered}"
        );
        assert!(rendered.contains("partial"), "{rendered}");
        assert!(
            rendered.starts_with("[low] fs/huge-evidence at card:"),
            "{rendered}"
        );
    }

    #[test]
    fn a_truncated_scan_marks_every_finding_and_the_set() {
        let set = Findings::partial(
            vec![
                unreadable_ef(),
                Finding::new(
                    RuleId::new("fs/unreadable-ef").unwrap(),
                    Severity::Low,
                    "another one",
                    Location::absent_file("3F00/2F01/6F07"),
                    Evidence::None,
                ),
            ],
            "max_depth bound hit",
        );

        assert!(!set.is_exhaustive());
        assert_eq!(set.len(), 2);
        for finding in &set {
            assert!(
                !finding.coverage().is_complete(),
                "{finding} survived a truncated scan still claiming completeness"
            );
            assert_eq!(finding.coverage().reason(), Some("max_depth bound hit"));
        }

        // The set says it too, because a consumer may read the set and never
        // look inside it.
        assert_eq!(
            set.to_json()["coverage"],
            serde_json::json!({ "status": "partial", "reason": "max_depth bound hit" })
        );
        assert_eq!(set.to_json()["exhaustive"], false);
        assert_eq!(set.to_json()["count"], 2);
        assert_eq!(
            set.to_json()["findings"][0]["coverage"],
            serde_json::json!({ "status": "partial", "reason": "max_depth bound hit" })
        );
        assert_eq!(set.coverage().to_string(), "partial (max_depth bound hit)");
    }

    #[test]
    fn a_rules_own_reason_survives_the_scans_headline_bound() {
        // The rule knows why it could not answer; the scan headline bound does
        // not. Keeping the more specific reason is why partial only marks the
        // findings still claiming completeness.
        let specific = Finding::new(
            RuleId::new("fs/unreadable-ef").unwrap(),
            Severity::High,
            "read three times, all refused",
            Location::Card,
            Evidence::None,
        )
        .partial("every READ BINARY drew 6F00");

        let set = Findings::partial(vec![specific], "max_depth bound hit");

        assert_eq!(
            set.iter().next().expect("one finding").coverage().reason(),
            Some("every READ BINARY drew 6F00")
        );
        assert_eq!(set.coverage().reason(), Some("max_depth bound hit"));
    }

    #[test]
    fn a_complete_scan_takes_its_coverage_from_the_findings() {
        let set = Findings::complete(vec![unreadable_ef()]);
        assert!(set.is_exhaustive());
        assert_eq!(set.coverage(), &Coverage::Complete);
        assert!(set.coverage().reason().is_none());
        assert_eq!(set.to_json()["exhaustive"], true);

        // A rule that already said it could not finish makes the set not
        // exhaustive, without anybody having to remember to say it twice.
        let marked = Findings::complete(vec![unreadable_ef().partial("the card stopped talking")]);
        assert!(!marked.is_exhaustive());
        assert_eq!(marked.coverage().reason(), Some("the card stopped talking"));

        assert!(Findings::complete(Vec::new()).is_empty());
        assert!(Findings::complete(Vec::new()).worst_severity().is_none());
        assert!(!Findings::complete(Vec::new()).reaches(Severity::MIN));
    }

    #[test]
    fn severity_decides_the_threshold_and_the_worst_of_a_set() {
        let low = Finding::new(
            RuleId::new("fs/a").unwrap(),
            Severity::Low,
            "low",
            Location::Card,
            Evidence::None,
        );
        let critical = Finding::new(
            RuleId::new("fs/b").unwrap(),
            Severity::Critical,
            "critical",
            Location::Card,
            Evidence::None,
        );

        let set = Findings::complete(vec![low.clone(), critical.clone()]);
        assert_eq!(set.worst_severity(), Some(Severity::Critical));
        assert!(set.reaches(Severity::High));
        assert!(set.reaches(Severity::Critical));
        assert!(!low.at_least(Severity::High));
        assert!(critical.at_least(Severity::MIN));

        let only_low = Findings::complete(vec![low]);
        assert_eq!(only_low.worst_severity(), Some(Severity::Low));
        assert!(!only_low.reaches(Severity::Medium));
        assert_eq!(only_low.into_vec().len(), 1);
    }

    #[test]
    fn the_registry_refuses_two_rules_under_one_id() {
        let mut registry: Registry<NoSubject> = Registry::new();
        assert!(registry.is_empty());

        registry
            .register(spec("filesystem/unreadable-ef"), produce_one)
            .expect("first registration");

        let error = registry
            .register(
                spec("filesystem/unreadable-ef").with_remediation("a different rule entirely"),
                |_: &NoSubject| Vec::new(),
            )
            .expect_err("the second rule claims an ID that is taken");

        assert_eq!(
            error.to_string(),
            "rule ID filesystem/unreadable-ef is already registered (as \"a file the card would not give up\"); two rules may not share an ID, because agents address findings by it"
        );
        assert!(matches!(
            error,
            RegistryError::DuplicateRule { ref id, .. }
                if id.as_str() == "filesystem/unreadable-ef"
        ));

        // The refusal changed nothing: one rule, and it is still the first one.
        assert_eq!(registry.len(), 1);
        assert!(registry.contains(&RuleId::new("filesystem/unreadable-ef").unwrap()));
        assert!(registry.rules()[0].spec().remediation().is_none());

        // A different plugin namespace is a different ID and does register.
        registry
            .register(spec("auth/unreadable-ef"), |_: &NoSubject| Vec::new())
            .expect("a different namespace is a different rule");
        assert_eq!(registry.len(), 2);
        assert_eq!(
            registry.ids(),
            vec![
                &RuleId::new("filesystem/unreadable-ef").unwrap(),
                &RuleId::new("auth/unreadable-ef").unwrap(),
            ]
        );
        assert!(registry.get(&RuleId::new("fs/nothing").unwrap()).is_none());
    }

    #[test]
    fn the_registry_refuses_a_rule_that_emits_another_rules_id() {
        // The same ambiguity, arriving at output time. Catching it here is the
        // last point before it is written to a file an agent will diff.
        let mut registry: Registry<NoSubject> = Registry::new();
        registry
            .register(spec("auth/scp03-missing-mac"), |_: &NoSubject| {
                vec![Finding::new(
                    RuleId::new("gsma/msl-zero-allowed").unwrap(),
                    Severity::High,
                    "borrowed somebody elses ID",
                    Location::Card,
                    Evidence::None,
                )]
            })
            .expect("registration is fine; the producer is not");

        let error = registry
            .evaluate(&NoSubject)
            .expect_err("a rule may only emit its own ID");
        assert_eq!(
            error.to_string(),
            "the rule registered as auth/scp03-missing-mac emitted a finding labelled gsma/msl-zero-allowed; a rule may only emit its own ID"
        );
        assert!(matches!(error, RegistryError::MisattributedFinding { .. }));
    }

    #[test]
    fn registered_rules_run_in_order_and_keep_their_own_ids() {
        let mut registry: Registry<NoSubject> = Registry::new();
        registry
            .register(spec("fs/first"), |_: &NoSubject| {
                vec![
                    Finding::new(
                        RuleId::new("fs/first").unwrap(),
                        Severity::Low,
                        "first, twice",
                        Location::tar(1),
                        Evidence::None,
                    ),
                    Finding::new(
                        RuleId::new("fs/first").unwrap(),
                        Severity::High,
                        "first, again",
                        Location::tar(2),
                        Evidence::None,
                    ),
                ]
            })
            .expect("registers");
        registry
            .register(spec("fs/second"), |_: &NoSubject| {
                vec![Finding::new(
                    RuleId::new("fs/second").unwrap(),
                    Severity::Medium,
                    "second",
                    Location::Card,
                    Evidence::None,
                )]
            })
            .expect("registers");

        let findings = registry
            .evaluate(&NoSubject)
            .expect("nothing misattributed");
        assert_eq!(findings.len(), 3);

        let ids: Vec<_> = findings.iter().map(|f| f.rule().as_str()).collect();
        assert_eq!(ids, ["fs/first", "fs/first", "fs/second"]);
        assert_eq!(
            findings.iter().map(Finding::severity).collect::<Vec<_>>(),
            [Severity::Low, Severity::High, Severity::Medium],
            "registration order, not severity order, is what evaluate guarantees"
        );
        assert_eq!(registry.len(), 2);
        assert_eq!(registry.rules()[0].severity(), Severity::High);

        // The same set through the batch, and the batch's own JSON carries the
        // same per-finding coverage the findings do.
        let set = Findings::complete(findings);
        assert!(set.is_exhaustive());
        assert_eq!(set.to_json()["count"], 3);
        assert_eq!(set.to_json()["findings"][0]["rule"], "fs/first");
    }

    #[test]
    fn a_rule_id_survives_a_round_trip_and_a_forged_one_does_not() {
        // A baseline is read back through this. If deserialization trusted the
        // string, a baseline edited by hand could inject an ID that could never
        // have been registered, and the next comparison would be against a
        // rule that does not exist.
        let json = serde_json::to_string(&unreadable_ef()).unwrap();
        let parsed: Finding = serde_json::from_str(&json).expect("round trips");
        assert_eq!(parsed, unreadable_ef());

        let forged = json.replace("filesystem/unreadable-ef", "Filesystem/Unreadable_EF");
        let error =
            serde_json::from_str::<Finding>(&forged).expect_err("re-validated on the way in");
        assert!(error.to_string().contains("not lowercase ASCII"), "{error}");

        // An ID with no namespace at all is refused the same way.
        let unnamespaced = json.replace("filesystem/unreadable-ef", "unreadable-ef");
        assert!(serde_json::from_str::<Finding>(&unnamespaced).is_err());

        // An unknown field is ignored rather than refused: a baseline written
        // by a later version must still be readable by this one.
        let extended = json.replace(r#"{"rule":"#, r#"{"advisory":"ignore me","rule":"#);
        assert!(serde_json::from_str::<Finding>(&extended).is_ok());
    }

    #[test]
    fn a_status_word_round_trips_and_a_malformed_one_is_refused() {
        for octets in [[0x90u8, 0x00], [0x98, 0x04], [0x6c, 0xff]] {
            let status = Status::from_bytes(octets);
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, format!("\"{status}\""));
            assert_eq!(serde_json::from_str::<Status>(&json).unwrap(), status);
        }
        for bad in [r#""98""#, r#""980400""#, r#""zzzz""#, r#""""#] {
            assert!(
                serde_json::from_str::<Status>(bad).is_err(),
                "{bad} is not a status word"
            );
        }
    }

    #[test]
    fn evidence_hex_round_trips_and_refuses_junk() {
        let bytes = Evidence::bytes([0x00, 0x0f, 0xa0, 0xff]);
        let json = serde_json::to_string(&bytes).unwrap();
        assert_eq!(json, r#"{"kind":"bytes","octets":"000fa0ff","omitted":0}"#);
        assert_eq!(serde_json::from_str::<Evidence>(&json).unwrap(), bytes);

        // A baseline edited by hand is refused rather than read as a different
        // card.
        for bad in [
            r#"{"kind":"bytes","octets":"0","omitted":0}"#,
            r#"{"kind":"bytes","octets":"zz","omitted":0}"#,
        ] {
            assert!(serde_json::from_str::<Evidence>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn severity_serializes_as_the_word_and_the_rank_survives() {
        // Two spellings on purpose: the word is what a human and a flag read,
        // the rank is what something other than this crate compares.
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            r#""critical""#
        );
        assert_eq!(
            serde_json::from_str::<Severity>(r#""CRITICAL""#).unwrap(),
            Severity::Critical
        );
        assert!(serde_json::from_str::<Severity>(r#""fatal""#).is_err());
        assert_eq!(unreadable_ef().to_json()["severity_rank"], 3);
        assert_eq!(
            Severity::LADDER
                .into_iter()
                .map(|severity| severity.rank())
                .collect::<Vec<_>>(),
            [0, 1, 2, 3, 4]
        );
    }

    #[test]
    fn an_empty_set_renders_without_pretending_to_have_looked() {
        // The shape a clean run emits. It says exhaustive, and it says zero,
        // and both of those are claims somebody will gate a build on.
        let set = Findings::complete(Vec::new());
        assert_eq!(
            serde_json::to_string(&set.to_json()).unwrap(),
            r#"{"count":0,"coverage":{"status":"complete"},"exhaustive":true,"findings":[]}"#
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three identifiers AGENTS.md section 3 gives as the canonical shape.
    const EXAMPLES: [&str; 3] = [
        "filesystem/unreadable-ef",
        "auth/scp03-missing-mac",
        "gsma/msl-zero-allowed",
    ];

    #[test]
    fn the_documented_identifiers_validate_and_split() {
        for raw in EXAMPLES {
            let id = RuleId::new(raw).unwrap_or_else(|e| panic!("{raw} should validate: {e}"));
            assert_eq!(id.as_str(), raw);
            assert_eq!(id.to_string(), raw);

            let (plugin, rule) = raw
                .split_once(SEPARATOR)
                .expect("examples have a separator");
            assert_eq!(id.plugin(), plugin);
            assert_eq!(id.rule(), rule);
        }
    }

    #[test]
    fn every_malformed_identifier_names_its_own_failure() {
        // Each case below must fail for its own reason. A test that only
        // checked "it returned Err" would pass just as happily if every rule
        // collapsed into one catch-all variant.
        assert!(matches!(
            RuleId::new("filesystem"),
            Err(Error::MissingSeparator { .. })
        ));
        assert!(matches!(
            RuleId::new("filesystem/unreadable/ef"),
            Err(Error::NestedSeparator { .. })
        ));
        assert!(matches!(
            RuleId::new("/unreadable-ef"),
            Err(Error::EmptyPlugin { .. })
        ));
        assert!(matches!(
            RuleId::new("filesystem/"),
            Err(Error::EmptyRule { .. })
        ));
        assert!(matches!(RuleId::new("/"), Err(Error::EmptyPlugin { .. })));
        assert!(matches!(
            RuleId::new("filesystem/unreadable_ef"),
            Err(Error::IllegalCharacter { character: '_', .. }),
        ));
        assert!(matches!(
            RuleId::new("Filesystem/unreadable-ef"),
            Err(Error::IllegalCharacter { character: 'F', .. }),
        ));
        assert!(matches!(
            RuleId::new("file system/unreadable-ef"),
            Err(Error::IllegalCharacter { character: ' ', .. }),
        ));
        assert!(matches!(
            RuleId::new("filesystem/-unreadable"),
            Err(Error::MisplacedHyphen { .. }),
        ));
        assert!(matches!(
            RuleId::new("filesystem/unreadable-"),
            Err(Error::MisplacedHyphen { .. }),
        ));
        assert!(matches!(
            RuleId::new("filesystem/unreadable--ef"),
            Err(Error::RepeatedHyphen { .. }),
        ));
    }

    #[test]
    fn digits_are_allowed_and_unicode_letters_are_not() {
        assert!(RuleId::new("auth/scp03t-fips-2").is_ok());
        // A rule ID goes into a shell pipeline and a JSON key. Non-ASCII
        // letters would have to be quoted in one and escaped in the other.
        assert!(matches!(
            RuleId::new("filesystem/r\u{fc}gle"),
            Err(Error::IllegalCharacter { .. })
        ));
    }

    #[test]
    fn a_rule_id_error_quotes_the_input_so_it_can_be_grepped() {
        // The message reaches a terminal and often a CI log, and the whole
        // point of a rule ID is that it is greppable.
        let rendered = RuleId::new("filesystem/unreadable_ef")
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("filesystem/unreadable_ef"), "{rendered}");
        assert!(rendered.contains('_'), "{rendered}");
    }

    #[test]
    fn the_severity_ladder_is_strictly_ordered_end_to_end() {
        // Guards the declaration order, which is what makes the derived Ord
        // correct. A reorder would compile, pass every other test in this file,
        // and silently invert every --severity filter.
        for pair in Severity::LADDER.windows(2) {
            assert!(
                pair[0] < pair[1],
                "{:?} must sort below {:?}",
                pair[0],
                pair[1]
            );
            assert!(
                !pair[0].at_least(pair[1]),
                "{:?} must not clear {:?}",
                pair[0],
                pair[1]
            );
            assert!(
                pair[1].at_least(pair[0]),
                "{:?} must clear {:?}",
                pair[1],
                pair[0]
            );
        }

        for (rank, severity) in Severity::LADDER.iter().enumerate() {
            assert_eq!(usize::from(severity.rank()), rank);
        }
    }

    #[test]
    fn a_threshold_keeps_itself_and_everything_above() {
        let kept: Vec<_> = Severity::LADDER
            .into_iter()
            .filter(|s| s.at_least(Severity::High))
            .collect();
        assert_eq!(kept, [Severity::High, Severity::Critical]);

        // A filter at the bottom of the ladder keeps everything, including the
        // default, so --severity info is not the same as no threshold at all.
        let everything: Vec<_> = Severity::LADDER
            .into_iter()
            .filter(|s| s.at_least(Severity::MIN))
            .collect();
        assert_eq!(everything, Severity::LADDER);
        assert_eq!(Severity::default(), Severity::Info);
        assert!(Severity::Critical.at_least(Severity::MAX));
    }

    #[test]
    fn display_and_parsing_are_inverse_for_every_spelling() {
        for severity in Severity::LADDER {
            assert_eq!(Severity::from_str(&severity.to_string()).unwrap(), severity);
            assert_eq!(
                Severity::from_str(&severity.to_string().to_ascii_uppercase()).unwrap(),
                severity,
                "--severity is typed by a human, so case must not matter",
            );
        }
        assert_eq!(
            UnknownSeverity("fatal".to_owned()).to_string(),
            r#""fatal" is not a severity; expected one of info, low, medium, high, critical"#
        );
        assert_eq!(
            "fatal".parse::<Severity>().unwrap_err(),
            UnknownSeverity("fatal".to_owned())
        );
    }
}
