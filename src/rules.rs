//! Namespaced `plugin/rule` identifiers and the severity ladder.
//!
//! **Owns.** The two vocabularies every other module eventually speaks: what a
//! finding is *called* ([`RuleId`]) and how bad it is ([`Severity`]). Both are
//! part of the contract in AGENTS.md section 3, so both are validated here
//! rather than at each call site.
//!
//! **Does not own.** The findings themselves, the registry that maps a
//! [`RuleId`] to the code that produces it, or the rule logic. That is issue
//! #13. This module has no dependencies on any other module in the crate and
//! must not acquire any: rule IDs and severities appear in every command's
//! output, so anything they depended on would be pulled into the surface of
//! every command.
//!
//! **Does not own the wire format.** Nothing here derives `Serialize`. How a
//! finding reaches the JSON envelope is [`crate::contract`]'s problem, and it
//! is free to change that without these names moving.
//!
//! **Why rule IDs are validated at all.** AGENTS.md section 3 says rule IDs are
//! addressable by agents and must never be renamed casually, which only works
//! if the set of well-formed IDs is small and a typo is impossible to miss. A
//! loose `String` would let `Filesystem/unreadable_ef` reach an output file and
//! silently never match a baseline.

/// This module's name, as recorded in [`crate::MODULES`].
///
/// Referenced by value rather than re-spelt as a literal so that the module
/// table cannot name a module that does not exist.
pub const NAME: &str = "rules";

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

    /// The lowest severity a filter keeps.
    pub const MIN: Self = Self::Info;

    /// The highest severity on the ladder.
    pub const MAX: Self = Self::Critical;
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Matches the spelling `FromStr` accepts, so Display and FromStr are
        // inverse for every case-insensitive spelling.
        let name = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        f.write_str(name)
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
