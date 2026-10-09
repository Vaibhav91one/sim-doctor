//! Turning a walk into a report, and being honest about what the report
//! does not cover.
//!
//! **Owns.** The prose and the JSON that a [`crate::walk::Tree`] becomes. That
//! is the half of `sim-doctor scan` that has nothing to do with I/O, and it is
//! here rather than in `src/main.rs` because it is the half with the rules in
//! it, and rules need tests.
//!
//! **Does not own.** Walking ([`crate::walk`]), reading a card
//! ([`crate::transport`]), or the envelope ([`crate::contract`]). This module
//! produces a `serde_json::Value` and a `String`; wrapping either in an
//! envelope is the binary's job, because the envelope kind and the exit code
//! are the binary's to choose.
//!
//! **The rule this whole module exists to enforce: a truncated walk must say so
//! in the output.** Issue #6's gap analysis calls this the single most
//! important thing in the issue, and it is: a walk that stopped early did not
//! see the whole card, and a file list an agent reads as a card's complete
//! contents hides every file below the point where the walk stopped. That is a
//! silent under-report of the attack surface, which for a security tool is worse
//! than producing no result at all.
//!
//! Three separate things carry it, and all three are asserted here:
//!
//! 1. `"truncated"` and `"complete"`, as booleans a machine can branch on,
//! 2. `"limits_hit"`, the **full** list of bounds that fired, alongside
//!    `"truncated_by"`, which is only the **first** one. Reporting only the
//!    first understates how much of the card was missed,
//! 3. a banner in the human report that cannot be scrolled past silently.
//!
//! **Absent and forbidden are never merged.** `Tree` keeps them as separate
//! variants with separate iterators because "not there" and "not allowed to
//! read" are different security findings, and flattening them into one `failed`
//! list throws that away. [`to_json`] emits separate `absent`, `forbidden` and
//! `refused` arrays on top of the per-file `state` discriminant, so neither
//! shape can be read without noticing the distinction.
//!
//! **The dialect is reported, never assumed away.** `walk` takes a
//! [`crate::fcp::TagSet`] and there is deliberately no [`Default`] for it,
//! because two cards disagree about which tag means what and a scanner that
//! silently picked one would report a nonsense file size as though the card had
//! written it. [`Context`] therefore carries the [`Dialect`] the caller chose,
//! and both the JSON and the human report print it.
//!
//! **The candidate set is reported with its coverage.**
//! [`crate::walk::Candidates::SimFamilies`] is the default and it probes five
//! identifier families. A card holding a file anywhere else is **invisible** to
//! a walk using it, not reported missing, and a scanner that says "12 files"
//! without saying which twelve it looked for has under-reported.
//! `"candidates"."exhaustive"` says so in one boolean.
//!
//! **The `findings` block is reported, filtered and scored rather than
//! assumed.** The severity threshold travels beside the list, because a
//! shorter list is indistinguishable from a quieter card unless the filter
//! that produced it is on the page, and the score travels with the penalty
//! table that produced it, because a number nobody can reconstruct is worse
//! than no number. See [`Verdict`].

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "scan";

use std::fmt;
use std::str::FromStr;

use serde_json::{json, Value};

use crate::access;
use crate::baseline;
use crate::contract::{self, ExitCode};
use crate::ef;
use crate::fcp::{self, TagSet};
use crate::fs;
use crate::rules;
use crate::scp03;
use crate::tar;
use crate::tlv::Tag;
use crate::walk::{self, Candidates, Limit, Limits, Node, NodeState, Note, Tree};

/// The `type` a scan envelope carries.
///
/// `scan`, not [`crate::contract::DEFAULT_KIND`]. The field exists to say
/// which response this is, and `modules` and `scan` are different responses:
/// an agent that pipes both into one parser has to be able to tell them apart
/// without reading `data`. This is the one place the string is written.
pub const KIND: &str = "scan";

/// Which tag table a capabilities template is read under.
///
/// An enum of the two mappings this repository has actually read, so choosing
/// one is a decision somebody types rather than a fallback that happens
/// somewhere nobody looks. A card nobody has characterised builds its own
/// [`TagSet::named`] and needs neither variant; that is the case `scan` does
/// not offer yet, and saying so here beats inventing a third "unknown" arm that
/// would render an empty table as though it meant something.
///
/// The spellings are what an operator types. [`fmt::Display`] and [`FromStr`] are
/// inverses for every one of them, which is the property the `--help` output
/// and the parser both rely on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Dialect {
    /// ETSI TS 102 221 clause 11.1.1.3: `80` size, `82` descriptor, `83` FID.
    /// The default; real UICCs and swSIM both write this layout.
    #[default]
    Ts102221,

    /// swICC's FCP builder, as observed in swSIM at the pinned commit. The
    /// same tags as [`Dialect::Ts102221`], kept as a distinct name so a
    /// baseline taken under it stays a distinct run.
    Swicc,
}

impl Dialect {
    /// Every dialect `--dialect` accepts, not counting the deprecated alias.
    pub const ALL: [Self; 2] = [Self::Ts102221, Self::Swicc];

    /// The spelling `--dialect` takes and the JSON reports.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Ts102221 => "ts-102-221",
            Self::Swicc => "swicc",
        }
    }

    /// The tag table the walk runs under.
    ///
    /// A fresh value every call, because [`crate::fcp::Template::parse`]
    /// borrows the mapping out of the response buffer and a caller that built
    /// one here and a second one for the report could report a table the walk
    /// did not use.
    pub fn tag_set(self) -> TagSet {
        match self {
            Self::Ts102221 => TagSet::ts_102_221(),
            Self::Swicc => TagSet::swicc(),
        }
    }
}

/// The spelling the wrong "ISO/IEC 7816-4 table 42" mapping was reachable by
/// before issue #69. Still accepted, and now means [`Dialect::Ts102221`].
pub const DEPRECATED_TABLE_42: &str = "iec-7816-4-table-42";

impl fmt::Display for Dialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

impl FromStr for Dialect {
    type Err = UnknownDialect;

    /// Parses a dialect as typed on a command line.
    ///
    /// Case-insensitive, because an operator types `--dialect SWICC` and
    /// because this is a human-facing flag rather than something compared
    /// against a stored identifier.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.to_ascii_lowercase().as_str() {
            "ts-102-221" | DEPRECATED_TABLE_42 => Ok(Self::Ts102221),
            "swicc" => Ok(Self::Swicc),
            _ => Err(UnknownDialect(text.to_owned())),
        }
    }
}

/// A `--dialect` value that names no mapping this repository has read.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0:?} is not a known FCP dialect; expected ts-102-221 or swicc")]
pub struct UnknownDialect(pub String);

/// The sentence `--help` and every report use to say that the default
/// candidate set can miss a file.
///
/// One constant so the flag's help text, the human report and the JSON
/// `warning` field cannot drift apart, and so a test can assert that the help
/// an operator reads is the same claim the output makes.
pub const CANDIDATE_WARNING: &str = "the default candidate set (SimFamilies) probes the five GSM 11.11 identifier families 2Fxx/4Fxx/5Fxx/6Fxx/7Fxx only; a file whose identifier starts outside those families is INVISIBLE to this scan rather than reported missing, so a clean result is not proof the card holds nothing else";

/// The name of a candidate set, as the JSON reports it.
pub const fn candidate_name(candidates: &Candidates) -> &'static str {
    match candidates {
        Candidates::Range { .. } => "range",
        Candidates::SimFamilies => "sim-families",
        Candidates::List(_) => "list",
    }
}

/// Whether a candidate set covers the whole two-octet identifier space.
///
/// False for everything except a [`Candidates::Range`] spanning it. Only `true`
/// here means "a file that was not selected does not exist"; for every other
/// set a missing file is indistinguishable from an unprobed one, which is the
/// whole of [`CANDIDATE_WARNING`].
pub const fn candidates_exhaustive(candidates: &Candidates) -> bool {
    match candidates {
        Candidates::Range { first, last } => {
            u16::from_be_bytes(first.to_bytes()) == 0
                && u16::from_be_bytes(last.to_bytes()) == 0xFFFF
        }
        Candidates::SimFamilies | Candidates::List(_) => false,
    }
}

/// Everything a report knows that the tree itself does not.
///
/// The tree says what the card said. This says what this process did: which
/// reader, which tag table, which identifier set, which bounds. All of it is
/// an assumption somebody made, and a report that does not carry its own
/// assumptions is a report an agent cannot audit.
///
/// **The dialect here must be the one the walk ran under.** It cannot be
/// checked from inside this module, because `walk` does not hand back the
/// `TagSet` it was given, only the name. So [`Context::new`] takes both and the
/// caller builds them from one [`Dialect`] value; see [`Dialect::tag_set`].
///
/// Built through a constructor rather than as a literal so the fields stay in
/// one place if this grows.
pub struct Context<'a> {
    reader: &'a str,
    atr: Option<&'a [u8]>,
    dialect: Dialect,
    candidates: Candidates,
    limits: Limits,
    stopped: Option<String>,
}

impl<'a> Context<'a> {
    /// Builds the context for one scan of one card.
    ///
    /// **Addressing is not a parameter, deliberately.** [`Tree`] already records
    /// the mode its own walk used, and a report free to print a caller's request
    /// beside the walk's observation could print the one that is wrong. Both
    /// [`to_json`] and [`to_human`] read [`Tree::addressing`] instead.
    pub fn new(
        reader: &'a str,
        atr: Option<&'a [u8]>,
        dialect: Dialect,
        candidates: Candidates,
        limits: Limits,
    ) -> Self {
        Self {
            reader,
            atr,
            dialect,
            candidates,
            limits,
            stopped: None,
        }
    }

    /// Records that the walk did not reach the end of what it was asked to read.
    ///
    /// The walk says *which bound* fired through
    /// [`walk::WalkReport::limits_hit`]; this says *why the walk as a whole
    /// stopped*, which is a different and higher-level fact - a transport that
    /// failed mid-walk, say, or an operator who cancelled it.
    #[must_use]
    pub fn stopped_by(mut self, reason: impl Into<String>) -> Self {
        self.stopped = Some(reason.into());
        self
    }

    /// The reader this scan ran against.
    pub const fn reader(&self) -> &str {
        self.reader
    }

    /// The tag table this scan ran under.
    pub const fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// Whether the walk finished on its own terms.
    pub fn stopped(&self) -> Option<&str> {
        self.stopped.as_deref()
    }

    /// Which identifiers this scan probed.
    pub const fn candidates(&self) -> &Candidates {
        &self.candidates
    }

    /// The bounds this scan ran inside.
    pub const fn limits(&self) -> Limits {
        self.limits
    }
}

/// The warning a score carries while no rule is implemented.
///
/// A named constant rather than a sentence written at each call site, so the
/// flag help, the JSON and the human report cannot drift apart, and so a test
/// can quote it instead of matching on a fragment of it.
pub const NO_RULES_WARNING: &str =
    "rules_run is 0: no rule has been implemented yet, so nothing on this card was checked. This score is 100 because there is nothing to subtract, NOT because the card is clean";

/// The warning a score carries when a rule ran but gathered no evidence.
///
/// **This is the case `--tar off` produces, and it is not the same as the one
/// above.** A rule is registered, so `rules_run` is 1, and the rule looked -
/// but the TAR audit probed nothing, so it had nothing to look at. The score
/// from that is not a verdict on MSL 0 either (it is 100 only when no other
/// rule found anything): it says the MSL 0 check did not run.
///
/// The default is `off` because an ENVELOPE probe leaves swicc-pcsc unable to
/// start a transaction for any later process. Turning the audit on is an
/// explicit operator decision, and while it is off this sentence is the honest
/// description of what the number means.
pub const NO_TAR_EVIDENCE_WARNING: &str =
    "the TAR audit probed nothing, so the MSL 0 check did not run: this score says nothing about whether the card refuses TAR 0, because no TAR was probed. Run with --tar focused to check";

// ---------------------------------------------------------------------------
// What a scan concluded
// ---------------------------------------------------------------------------

/// What every rule in this scan is handed.
///
/// **A subject, not a tree.** One scan now looks at two things about a card -
/// the DF tree and its TAR accept-list - and a rule may need either, both or
/// neither. [`crate::rules::Registry`] is generic over exactly this reason: a
/// rule is a function of whatever the scan knows, so the scan is what says
/// what the rules are handed.
#[derive(Debug, Clone, Copy)]
pub struct Subject<'a> {
    /// The walked card.
    pub tree: &'a Tree,
    /// What the TAR audit concluded.
    pub tar: &'a tar::Audit,
    /// Recorded SCP03 exchanges, if any. `None` on every scan today: nothing
    /// sends SCP03 to a card (issue #22 is forbidden on the live SIM).
    pub scp03: Option<&'a scp03::Audit>,
}

/// The ID of the TAR rule, exactly as AGENTS.md section 3 spells it.
///
/// A constant rather than a literal at each call site, because it is a public
/// address: a baseline records it, a suppression names it, a CI filter greps
/// for it, and a typo in it would produce a finding nobody can address.
pub const MSL_ZERO_RULE: &str = "gsma/msl-zero-allowed";

/// How serious MSL 0 is on this crate's ladder, and why.
///
/// **Critical, and the ladder is the reason rather than the mood.**
/// [`rules::SCORE_PENALTY`] gives critical 50 points, half the scale, so one of
/// these saturates a CI threshold on its own. That is the intended reading: a
/// card running at MSL 0 executes any command under any TAR with no
/// cryptographic verification, which is not a hardening gap but the absence of
/// the control.
fn msl_zero(subject: &Subject<'_>, reason: &str) -> rules::Finding {
    let accepted = subject
        .tar
        .probes
        .iter()
        .find(|probe| probe.tar == tar::TAR_MIN)
        .and_then(|probe| probe.verdict.status())
        .map_or_else(
            || "(no status word)".to_owned(),
            |status| status.to_string(),
        );
    let baseline = subject
        .tar
        .baseline
        .signature()
        .map_or_else(|| "(none)".to_owned(), ToString::to_string);

    let finding = rules::Finding::new(
        rules::RuleId::new(MSL_ZERO_RULE).expect("a validated constant"),
        rules::Severity::Critical,
        format!(
            "TAR 000000 was accepted: the card answered this TAR with {accepted}, which is not \
             how it answers TARs it has no opinion about ({baseline}), so MSL is 0 and any \
             command under any TAR may be run without cryptographic verification"
        ),
        rules::Location::tar(tar::TAR_MIN),
        rules::Evidence::text(format!("accepted={accepted} baseline={baseline}")),
    );
    finding.partial(reason)
}

/// The MSL=0 rule: TAR zero was accepted.
///
/// **This is a differential rule and it says so in its evidence.** It does not
/// ask whether `90 00` means accepted or `94 04` means refused, because this
/// project can cite neither: AGENTS.md blocker 2 records that no 3GPP TS 31.111
/// text has been read here, and the only card it has talked to answers GSM
/// SELECT of a missing file with `94 04` [V] (swSIM `src/apduh.c`,
/// `apduh_gsm_select`), so on that card `94 04` demonstrably does not mean
/// "the TAR was refused". What it asks instead is whether **this** TAR's
/// response differs from **this** card's response to TARs it has no opinion
/// about - which is SIMTester's own `-stbs` algorithm, and the only criterion
/// that can turn a card with no TAR check into a critical finding.
///
/// **A TAR accepted other than zero is not raised here.** It is reported in the
/// `tar` block of the scan with its status word, because it is a different
/// problem; and there is no agreed rule ID for it. Raising it under this ID
/// would be the same category of mistake as flipping the exit code without
/// moving the table that describes it.
fn msl_zero_allowed(subject: &Subject<'_>) -> Vec<rules::Finding> {
    if !subject.tar.msl_zero_allowed() {
        return Vec::new();
    }
    let reason = if subject.tar.is_complete() {
        TAR_PARTIAL_REASON.to_owned()
    } else {
        subject
            .tar
            .stopped
            .clone()
            .unwrap_or_else(|| TAR_PARTIAL_REASON.to_owned())
    };
    vec![msl_zero(subject, &reason)]
}

/// The reason a TAR finding carries when the TAR scan did not finish.
///
/// **Both halves of the scan are named in one string, because
/// [`crate::rules::Coverage`] carries exactly one.** The TAR scan is the
/// half that matters for this particular finding - TAR zero was accepted,
/// and that does not stop being true because the walk truncated - but a
/// reader told only about the TAR scan would be left thinking the rest of
/// the report is whole, which is the mistake AGENTS.md section 2 records
/// at length.
const TAR_PARTIAL_REASON: &str =
    "the TAR scan did not finish, so this TAR is known to be accepted but the card may hold
     others this scan never probed; this report is a list of what was found, not of everything
     there is";

/// The ID of the PIN rule.
pub const PIN1_DISABLED_RULE: &str = "auth/pin1-disabled";

/// The ID of the identity-readable rule.
pub const IDENTITY_READABLE_RULE: &str = "identity/readable-without-pin";

/// EF.MSISDN readable under ALWays (low).
///
/// EF.MSISDN is READ PIN in TS 31.102 clause 4.2.26. Decided from the access
/// rule alone, so it needs no read of the file. **The IMSI is deliberately not
/// here**: `filesystem/sensitive-ef-always` already owns it, and a second
/// finding would score one fact twice. Evidence is the path, the access
/// rule and, when the file was read, its full decoded value (issue #128).
fn identity_readable(subject: &Subject<'_>) -> Vec<rules::Finding> {
    subject
        .tree
        .selected()
        .filter_map(|node| {
            let ef = ef::classify(node.path())?;
            if ef != ef::Ef::Msisdn {
                return None;
            }
            let severity = rules::Severity::Low;
            let access = access::access_of(subject.tree, node)?;
            (access.read == access::Condition::Always).then(|| {
                let value = ef::decoded_evidence(subject.tree, node.path());
                rules::Finding::new(
                    rules::RuleId::new(IDENTITY_READABLE_RULE).expect("a validated constant"),
                    severity,
                    format!(
                        "{} is readable without a PIN, so the subscriber identity is open to anyone holding the card{}",
                        ef.name(),
                        value.as_ref().map_or(String::new(), |v| format!(" ({v})"))
                    ),
                    rules::Location::selected_file(node.path().to_string()),
                    rules::Evidence::text(with_value(
                        format!("read={} update={}", access.read.label(), access.update.label()),
                        value,
                    )),
                )
            })
        })
        .collect()
}

/// `access` with the file's full decoded value appended, when it was read.
fn with_value(access: String, value: Option<String>) -> String {
    value.map_or(access.clone(), |v| format!("{access} {v}"))
}

fn identity_evidence(subject: &Subject<'_>) -> bool {
    subject.tree.selected().any(|node| {
        ef::classify(node.path()) == Some(ef::Ef::Msisdn)
            && access::access_of(subject.tree, node).is_some()
    })
}

/// The ID of the sensitive-EF access rule.
pub const SENSITIVE_EF_RULE: &str = "filesystem/sensitive-ef-always";

/// The EFs whose READ and UPDATE conditions 3GPP TS 31.102 V17.8.0 never sets to
/// ALWays, as (the directory the identifier is only meaningful under, EF, name).
///
/// Clause 4.2.2 EF.IMSI: READ PIN, UPDATE ADM. Clauses 4.2.3 EF.Keys, 4.2.4
/// EF.KeysPS, 4.2.17 EF.LOCI and 4.2.23 EF.PSLOCI: READ PIN, UPDATE PIN, and
/// they hold the ciphering/integrity keys or the TMSI and location. Clauses
/// 4.4.3.1 EF.Kc and 4.4.3.2 EF.KcGPRS (under DF.GSM-ACCESS `5F3B`): READ PIN,
/// UPDATE PIN. A `None` parent means "any directory below the master file";
/// `4F20` is also an unrelated linear fixed EF in DF.GRAPHICS, which is why
/// those two are pinned to `5F3B`.
/// (required parent directory, file identifier, name).
type SensitiveEf = (Option<[u8; 2]>, [u8; 2], &'static str);

const SENSITIVE_EFS: [SensitiveEf; 7] = [
    (None, [0x6F, 0x07], "EF.IMSI"),
    (None, [0x6F, 0x08], "EF.Keys"),
    (None, [0x6F, 0x09], "EF.KeysPS"),
    (None, [0x6F, 0x7E], "EF.LOCI"),
    (None, [0x6F, 0x73], "EF.PSLOCI"),
    (Some([0x5F, 0x3B]), [0x4F, 0x20], "EF.Kc"),
    (Some([0x5F, 0x3B]), [0x4F, 0x52], "EF.KcGPRS"),
];

/// The name of the sensitive EF a node is, if it is one.
fn sensitive_name(node: &walk::Node) -> Option<&'static str> {
    let segments = node.path().segments();
    let [.., parent, leaf] = segments else {
        return None;
    };
    // Not by `Kind::Reported(ElementaryFile)`: a live USIM's EF descriptors read as
    // `Kind::Unreported`, and the identifier plus the parent already name the file.
    if node.path().depth() < 3 || node.state().kind().is_none_or(walk::Kind::is_container) {
        return None;
    }
    SENSITIVE_EFS
        .iter()
        .find(|(under, id, _)| {
            leaf.to_bytes() == *id && under.is_none_or(|u| parent.to_bytes() == u)
        })
        .map(|(_, _, name)| *name)
}

/// Sensitive EFs readable or updatable without any verification.
///
/// **High when UPDATE is open, medium when only READ is.** Open UPDATE lets
/// anyone holding the card rewrite the identity or the keys; open READ only
/// exposes them. Evidence is the file path (the location), the decoded
/// access rule and, when the file was read, its full decoded value.
fn sensitive_ef_always(subject: &Subject<'_>) -> Vec<rules::Finding> {
    subject
        .tree
        .selected()
        .filter_map(|node| {
            let name = sensitive_name(node)?;
            let access = access::access_of(subject.tree, node)?;
            let read_open = access.read == access::Condition::Always;
            let update_open = access.update == access::Condition::Always;
            if !read_open && !update_open {
                return None;
            }
            let (severity, what) = match (read_open, update_open) {
                (true, true) => (rules::Severity::High, "readable and updatable"),
                (false, true) => (rules::Severity::High, "updatable"),
                _ => (rules::Severity::Medium, "readable"),
            };
            let value = ef::decoded_evidence(subject.tree, node.path());
            Some(rules::Finding::new(
                rules::RuleId::new(SENSITIVE_EF_RULE).expect("a validated constant"),
                severity,
                format!(
                    "{name} is {what} without verification: TS 31.102 gives it a PIN or ADM condition, not ALWays{}",
                    value.as_ref().map_or(String::new(), |v| format!(" ({v})"))
                ),
                rules::Location::selected_file(node.path().to_string()),
                rules::Evidence::text(with_value(
                    format!("read={} update={}", access.read.label(), access.update.label()),
                    value,
                )),
            ))
        })
        .collect()
}

fn sensitive_ef_evidence(subject: &Subject<'_>) -> bool {
    subject.tree.selected().any(|node| {
        sensitive_name(node).is_some() && access::access_of(subject.tree, node).is_some()
    })
}

/// PIN Appl 1 listed as disabled in the PIN status templates.
///
/// **One finding per scan, not one per directory.** Key reference `01` is a
/// global PIN (TS 102 221 table 9.3, level 1) and every directory under the
/// master file repeats the same template (a live USIM sends it in 11 of 11), so
/// a finding per directory would score one fact eleven times. The finding is
/// located at the first directory in walk order that lists it disabled, and its
/// evidence says how many of the templates listing key reference `01` agree.
///
/// **Medium, and the reasoning is the exposure, not the setting.** A disabled
/// PIN is a legitimate configuration on many operator SIMs, so this is not a
/// defect in the card; it is that everything whose READ or UPDATE needs PIN1
/// (the IMSI, the keys and the location files above, per TS 31.102) can be
/// used by whoever holds the card. That is a real weakness with limited impact
/// (it needs physical possession), which is the ladder's medium. A disabled
/// PIN1 is not counted when an enabled universal PIN is in use in its place
/// (TS 102 221 table 9.0d).
fn pin1_disabled(subject: &Subject<'_>) -> Vec<rules::Finding> {
    let states: Vec<(&walk::Node, bool)> = subject
        .tree
        .selected()
        .filter_map(|node| Some((node, access::pin1_disabled(&pin_status(node)?)?)))
        .collect();
    let disabled = states.iter().filter(|(_, off)| *off).count();
    let Some((first, _)) = states.iter().find(|(_, off)| *off) else {
        return Vec::new();
    };
    vec![rules::Finding::new(
        rules::RuleId::new(PIN1_DISABLED_RULE).expect("a validated constant"),
        rules::Severity::Medium,
        "PIN Appl 1 (key reference 01) is disabled, so files that need PIN1 are open to anyone holding the card",
        rules::Location::selected_file(first.path().to_string()),
        rules::Evidence::text(format!(
            "key reference 01 disabled in {disabled} of {} PIN status templates",
            states.len()
        )),
    )]
}

fn pin_status(node: &walk::Node) -> Option<Vec<access::PinEntry>> {
    let raw = node.state().capabilities()?.pin_status.as_deref()?;
    access::parse_pin_status(raw)
}

fn pin1_evidence(subject: &Subject<'_>) -> bool {
    subject.tree.selected().any(|node| {
        pin_status(node)
            .and_then(|e| access::pin1_disabled(&e))
            .is_some()
    })
}

/// The rules this scan runs over one card.
///
/// **One rule today, and that is what makes the score mean something.**
/// Issue #13 built the vocabulary a rule needs and shipped none, because a
/// rule that guessed would manufacture findings this repository cannot justify.
/// Issue #24 adds the first one, `gsma/msl-zero-allowed`.
///
/// **Which is why the score carries `rules_run`.** A score of 100 from an empty
/// set is indistinguishable from a card that passed, which is precisely the
/// failure [`NO_RULES_WARNING`] was written to prevent. A scan that now runs a
/// rule and finds nothing has earned its 100, and the warning going null is
/// what says so - see [`Verdict::fields`].
fn rules<'a>() -> rules::Registry<Subject<'a>> {
    let mut registry = rules::Registry::new();
    // Registration cannot fail: the ID is a constant and the registry is built
    // fresh here. Expect rather than a silent fallback, because a duplicate
    // would be a mistake visible right here and there is nothing sensible to
    // fall back to.
    registry
        .register(
            rules::RuleSpec::new(
                rules::RuleId::new(MSL_ZERO_RULE).expect("a validated constant"),
                rules::Severity::Critical,
                "the card accepted TAR 000000, so it runs at MSL 0",
            )
            .with_remediation(
                "raise MSL and load the card's TAR allow-list, then re-scan; a card at MSL 0 \
                 accepts any command under any TAR with no cryptographic verification",
            ),
            msl_zero_allowed,
            msl_zero_evidence,
        )
        .expect("the TAR rule ID is unique in this registry");
    registry
        .register(
            scp03::missing_mac_spec(),
            |subject| subject.scp03.map_or_else(Vec::new, scp03::missing_mac),
            |subject| subject.scp03.is_some_and(scp03::had_evidence),
        )
        .expect("the SCP03 rule ID is unique in this registry");
    registry
        .register(
            rules::RuleSpec::new(
                rules::RuleId::new(PIN1_DISABLED_RULE).expect("a validated constant"),
                rules::Severity::Medium,
                "PIN Appl 1 is disabled, so files protected by PIN1 are open to anyone holding the card",
            )
            .with_remediation(
                "enable PIN1 (key reference 01) on the application, or confirm the universal PIN is enabled and in use, then re-scan",
            ),
            pin1_disabled,
            pin1_evidence,
        )
        .expect("the PIN rule ID is unique in this registry");
    registry
        .register(
            rules::RuleSpec::new(
                rules::RuleId::new(SENSITIVE_EF_RULE).expect("a validated constant"),
                rules::Severity::High,
                "a file holding the IMSI, ciphering keys or location (TS 31.102 gives them PIN or ADM conditions) is readable or updatable under ALWays",
            )
            .with_remediation(
                "set the file's READ and UPDATE access rule (its EF.ARR record) back to the TS 31.102 conditions, PIN for READ and PIN or ADM for UPDATE, then re-scan",
            ),
            sensitive_ef_always,
            sensitive_ef_evidence,
        )
        .expect("the sensitive EF rule ID is unique in this registry");
    registry
        .register(
            rules::RuleSpec::new(
                rules::RuleId::new(IDENTITY_READABLE_RULE).expect("a validated constant"),
                rules::Severity::Medium,
                "the MSISDN is readable without a PIN (TS 31.102 gives it a PIN READ condition)",
            )
            .with_remediation(
                "set the file's READ access rule (its EF.ARR record) to PIN, then re-scan",
            ),
            identity_readable,
            identity_evidence,
        )
        .expect("the identity rule ID is unique in this registry");
    registry
}

/// Whether the MSL 0 rule had a TAR audit to decide from.
///
/// **False on the default `--tar off`, and that is the whole point.** The rule
/// is registered on every scan and evaluates on every scan; with no probes
/// there is nothing for it to compare a response against, so it is not a rule
/// that looked and found nothing, it is a rule that could not look. A baseline
/// written from such a run records `evidence: false` beside this rule's ID, and
/// a later `--baseline` refuses rather than reporting the first real MSL 0 finding
/// as a regression. See [`crate::rules::HadEvidence`].
fn msl_zero_evidence(subject: &Subject<'_>) -> bool {
    !subject.tar.probes.is_empty()
}

/// How many rules a scan evaluates over one card.
///
/// One today, and reported next to every score for the reason above.
pub fn rules_run() -> usize {
    rules().len()
}

/// The declarations of every rule a scan knows, in registration order.
///
/// This is the catalog `sim-doctor rules list` and `sim-doctor rules explain`
/// read from, without a card: a [RuleSpec](crate::rules::RuleSpec) is the part
/// of a rule an agent can read without running anything, so the whole registry
/// is publishable headlessly.
pub fn specs() -> Vec<rules::RuleSpec> {
    rules()
        .rules()
        .iter()
        .map(|rule| rule.spec().clone())
        .collect()
}

/// The findings one card produces, before any filtering.
///
/// Coverage is taken from **both** halves of the scan, not just the walk. A
/// finding raised from a walk that hit `max_depth` may be entirely true, but
/// the list cannot be read as the whole of the card, and
/// [`rules::Findings::partial`] is how that travels on every finding rather
/// than only on the report.
///
/// # Errors
///
/// [`rules::RegistryError::MisattributedFinding`] when a rule emits a finding
/// under another rule's ID. The caller turns that into a failed scan rather
/// than into a report: a finding nobody can address is not a finding, and
/// [`rules::Registry`] already refuses it at every other boundary.
pub fn findings(subject: &Subject<'_>) -> Result<rules::Findings, rules::RegistryError> {
    let found = rules().evaluate(subject)?;
    Ok(if subject.tree.is_complete() {
        rules::Findings::complete(found)
    } else {
        rules::Findings::partial(found, TRUNCATION_REASON)
    })
}

/// The coverage reason a walk that hit a bound hands its findings.
const TRUNCATION_REASON: &str = "the walk stopped at a bound, so this list may be short";

/// Everything a saved baseline has to record about the run that wrote it.
///
/// **Every field is something this report already publishes**, so a reader can
/// check each one against the scan a baseline came from instead of taking this
/// module's word for it: the reader name, the dialect, the candidate set and
/// the TAR selection are in `data`, `complete` / `truncated_by` /
/// `limits_hit` are the walk's own words, the severity threshold is in
/// `data.findings`, and the rule list comes from the same registry that
/// produced the findings.
///
/// The two numbers `scan::to_json` renders beside the findings are taken from
/// here rather than recomputed, so a baseline and the report it was written
/// from cannot disagree about how many rules ran or which identifiers were
/// probed.
#[must_use]
pub fn run_facts(tree: &Tree, context: &Context<'_>, verdict: &Verdict) -> baseline::RunFacts {
    let complete = tree.is_complete() && context.stopped.is_none();
    let (probed, _) = context
        .candidates
        .clone()
        .identifiers(context.limits.max_children);

    baseline::RunFacts::new(
        context.reader,
        context.dialect.id(),
        // The candidate set AND how many identifiers it actually yielded.
        // `--max-children` is what changes the second from inside the first, so
        // recording only the set would let two runs with different budgets call
        // themselves comparable.
        format!(
            "{} ({} probed, exhaustive={})",
            candidate_name(&context.candidates),
            probed.len(),
            candidates_exhaustive(&context.candidates),
        ),
        verdict.threshold(),
        verdict.tar().selection.fingerprint(),
        complete,
        tree.truncated_by()
            .map(|limit| limit_name(limit).to_owned()),
        tree.limits_hit()
            .iter()
            .copied()
            .map(|limit| limit_name(limit).to_owned())
            .collect(),
        // The registry is rebuilt here rather than threaded through from
        // `findings`, because it is the same construction and therefore the
        // same list in the same order; a registry that could differ between the
        // run that produced the findings and the one that names them would be a
        // baseline that says a rule ran when it did not.
        rules().runs(&Subject {
            tree,
            tar: verdict.tar(),
            scp03: None,
        }),
    )
}

/// What one scan concluded: the findings, the threshold they were filtered
/// to, and the score.
///
/// **The filter runs first and the score is taken from what is reported.**
/// That ordering is the whole of "a score must not hide a finding": the
/// score is a function of the `findings` array the reader can see, so the two
/// can never disagree about what was found. `scan --severity high --score`
/// scores the findings at or above `high` and reports `scored_findings` as
/// how many that was. It does not quietly discount the lows and hand back a
/// number that does not match the document beside it, because a number an
/// agent cannot reproduce from the output is a number the agent should not
/// gate a build on.
///
/// Built through [`Verdict::new`] and the two `with_*` builders so the order
/// the flags are applied in is the order they are read in, and so an unset
/// filter has exactly one representation: [`None`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    findings: rules::Findings,
    rules_run: usize,
    threshold: Option<rules::Severity>,
    score: bool,
    tar: tar::Audit,
    diff: Option<baseline::Diff>,
}

impl Verdict {
    /// A verdict over the findings a scan produced, with no filter and no
    /// score asked for.
    ///
    /// `rules_run` is a parameter rather than a call to [`rules_run`] so that a
    /// test can put findings in front of a scanner that has implemented no
    /// rules and assert the *rendered* behaviour rather than the arithmetic,
    /// which [`crate::rules`] already owns.
    #[must_use]
    pub fn new(findings: rules::Findings, rules_run: usize) -> Self {
        Self {
            findings,
            rules_run,
            threshold: None,
            score: false,
            // The default is an audit that did not run, rather than one that
            // ran and found nothing. A caller that forgets to attach the
            // evidence must not leave the report claiming a TAR check with no
            // evidence in it.
            tar: tar::Audit::not_run("no TAR audit was attached to this verdict"),
            // Same reasoning, same direction: a verdict nobody diffed says so
            // by having no diff, rather than by carrying an empty one that
            // reads as a comparison that found nothing.
            diff: None,
        }
    }

    /// The findings this verdict was built from, unfiltered.
    ///
    /// Only useful for reporting how much the filter removed. Nothing that
    /// renders output should read it: the rendered output is
    /// [`Verdict::findings`].
    pub const fn unfiltered(&self) -> &rules::Findings {
        &self.findings
    }

    /// Drops every finding below `level`, the whole of `--severity`.
    ///
    /// Applied here rather than at each render so the JSON and the human
    /// report cannot disagree about which findings survived. A filtered-out
    /// finding leaves no entry, no count and no rule ID anywhere in either.
    #[must_use]
    pub fn at_least(mut self, level: Option<rules::Severity>) -> Self {
        self.findings = match level {
            Some(level) => self.findings.filtered(level),
            None => self.findings,
        };
        self.threshold = level;
        self
    }

    /// Whether `--score` was asked for.
    ///
    /// Off by default. A score in every report would be a number an operator
    /// learns to skim past, and the flag exists so that asking for it is a
    /// deliberate act.
    #[must_use]
    pub fn scored(mut self, score: bool) -> Self {
        self.score = score;
        self
    }

    /// Attaches what the TAR audit concluded.
    ///
    /// The evidence the TAR rule was decided from, so it travels beside the
    /// finding rather than being somewhere else in the report: a reader who
    /// greps for `gsma/msl-zero-allowed` reads one finding, and that
    /// finding's own claim ("the card answered this TAR with 94 00, which is
    /// not how it answers TARs it has no opinion about") is only checkable
    /// against these numbers.
    #[must_use]
    pub fn tar_audit(mut self, audit: tar::Audit) -> Self {
        self.tar = audit;
        self
    }

    /// Attaches the comparison against a saved run.
    ///
    /// **Only under `--baseline`.** A scan with no `--baseline` carries no `diff` key at
    /// all rather than an empty one, because an empty `diff` reads as a
    /// comparison that was made and found nothing, and this one was never made.
    /// That is the rule `--severity` follows when it removes a finding rather
    /// than blanking it, for the same reason: a set one consumer can still see
    /// in the document is a set the other is counting wrong.
    #[must_use]
    pub fn compared_against(mut self, diff: baseline::Diff) -> Self {
        self.diff = Some(diff);
        self
    }

    /// What the TAR audit concluded.
    pub const fn tar(&self) -> &tar::Audit {
        &self.tar
    }

    /// The comparison against a saved run, when one was asked for.
    pub const fn diff(&self) -> Option<&baseline::Diff> {
        self.diff.as_ref()
    }

    /// Whether this run is worse than the baseline it was compared against.
    ///
    /// **The one place `scan` turns a diff into a verdict**, and it is a verdict
    /// rather than a count: `true` means at least one finding is new relative to
    /// a baseline these two runs were comparable against. See
    /// [`crate::baseline::Diff::regressed`].
    pub fn regressed(&self) -> bool {
        self.diff.as_ref().is_some_and(baseline::Diff::regressed)
    }

    /// The findings this report carries, after the filter.
    pub const fn findings(&self) -> &rules::Findings {
        &self.findings
    }

    /// The `--severity` level in force, or `None` when nothing was filtered.
    pub const fn threshold(&self) -> Option<rules::Severity> {
        self.threshold
    }

    /// How many rules produced the findings above.
    pub const fn rules_run(&self) -> usize {
        self.rules_run
    }

    /// The score over the findings this report carries, if one was asked for.
    ///
    /// `None` when `--score` was not passed. The score is computed over the
    /// **filtered** set, so this and [`Verdict::findings`] can never describe
    /// different sets of findings.
    pub fn score(&self) -> Option<rules::Score> {
        self.score.then(|| self.findings.score())
    }

    /// The process exit code this verdict maps to under doctor/1 (contract
    /// section 4), given the `--fail-on` threshold.
    ///
    /// Without a baseline: 1 when any finding in the report is at or above
    /// `fail_on`. With one, only NEW findings count, and the code is 3 rather
    /// than 1. The report is already filtered by `--severity`, so a finding
    /// that filter removed cannot fail the gate.
    #[must_use]
    pub fn exit_code(&self, fail_on: rules::Severity) -> ExitCode {
        match &self.diff {
            Some(diff) if diff.new_findings().iter().any(|f| f.at_least(fail_on)) => {
                ExitCode::NewFindings
            }
            Some(_) => ExitCode::Success,
            None if self.findings.reaches(fail_on) => ExitCode::Findings,
            None => ExitCode::Success,
        }
    }

    /// The score block, always computed (the `--score` flag only decides
    /// whether the legacy `data.score` and the human report show it).
    ///
    /// Reported under `data.score_detail` in the doctor/1 envelope; the
    /// top-level `score` is the shared shape built by [`contract::doctor_score`].
    #[must_use]
    pub fn score_detail(&self) -> Value {
        let score = self.findings.score();
        json!({
            "value": score.value(),
            "max": score.max(),
            "penalty": score.penalty(),
            "scored_findings": score.scored(),
            "rules_run": self.rules_run,
            "formula": rules::SCORE_FORMULA,
            "penalties": penalties_json(),
            // Null as soon as one rule runs, which is now the case
            // for every real scan. That is the whole point of the
            // field: a 100 from an empty finding set because a rule
            // looked and found nothing is a verdict, and a 100 from
            // no rule having looked is not. A scan that somehow ran
            // zero rules still gets the sentence, so the constant
            // stays live rather than becoming dead code.
            // THREE ways this 100 is not a verdict, not one. No rule
            // has been implemented; a rule ran but the TAR audit probed
            // nothing, which is the default because an ENVELOPE leaves
            // swicc-pcsc unable to start a transaction; or a scan that
            // somehow ran zero rules. Each gets its own sentence, because
            // "nothing was checked" and "checked, found nothing" are
            // different claims and an operator has to be able to tell
            // them apart.
            "warning": if self.rules_run == 0 {
                Some(NO_RULES_WARNING)
            } else if self.tar.probes.is_empty() {
                Some(NO_TAR_EVIDENCE_WARNING)
            } else {
                None
            },
        })
    }

    /// The fields a scan report carries from a verdict: `findings`, and
    /// `score` when one was asked for.
    ///
    /// Returned as a [`serde_json::Map`] rather than a [`Value`] because the
    /// caller splices them into a report it has already built, and a `Map` is
    /// what can be spliced without every field being named on both sides. A
    /// field added here therefore cannot be half-added, which is the failure
    /// a duplicated literal invites.
    ///
    /// `severity_threshold` sits inside the findings block rather than beside
    /// it because it is a property of the list: a reader comparing two reports
    /// needs to know they are looking at the same list before comparing
    /// anything in it. `null` when nothing was filtered, which is different
    /// from a threshold of `info` - the first is every finding, the second is
    /// every finding the ladder can spell.
    ///
    /// The score block carries the penalty table that produced it, so the
    /// number can be reconstructed from the document alone and not only from
    /// a reader who has found the formula in AGENTS.md.
    #[must_use]
    pub fn fields(&self) -> serde_json::Map<String, Value> {
        let mut findings = self.findings.to_json();
        findings["severity_threshold"] = match self.threshold {
            Some(level) => json!(level.id()),
            None => Value::Null,
        };

        let mut fields = serde_json::Map::new();
        fields.insert("findings".to_owned(), findings);
        fields.insert("tar".to_owned(), self.tar.to_json());

        // `diff` is spliced here rather than built at the call site so that a
        // report carrying a diff cannot be one where the diff is a different
        // object than the one whose counts the envelope published, and so that
        // its absence is a single well-defined thing: no --baseline was asked for.
        if let Some(diff) = &self.diff {
            fields.insert("diff".to_owned(), diff.to_json());
        }

        if self.score {
            fields.insert("score".to_owned(), self.score_detail());
        }
        fields
    }

    /// The TAR audit as a person reads it.
    ///
    /// Printed before the findings and not after, because a finding an
    /// operator cannot check is the failure this crate keeps designing
    /// against: the TAR numbers come first and the verdict reads as a reading
    /// of them.
    #[must_use]
    pub fn tar_to_human(&self) -> String {
        self.tar.to_human()
    }

    /// The findings and score as a person reads them.
    ///
    /// The same information as [`Verdict::fields`] and no more: the score is
    /// shown with the penalty it subtracted and the table it came from, so a
    /// person reading a CI log can check the number rather than trust it.
    /// Printed at the end of the report, after the walk, because the banner
    /// has to stay first and a long file list is what the reader scrolls
    /// past.
    #[must_use]
    pub fn to_human(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!("FINDINGS: {}", self.findings.len()));
        match self.threshold {
            Some(level) => out.push_str(&format!(" at or above {level}")),
            None => out.push_str(" (no severity filter)"),
        }
        out.push('\n');
        if self.findings.is_empty() {
            out.push_str("  (none)\n");
        }
        for finding in self.findings.iter() {
            out.push_str(&format!("  {finding}\n"));
        }
        if !self.findings.is_exhaustive() {
            out.push_str(&format!("  coverage: {}\n", self.findings.coverage()));
        }

        if let Some(score) = self.score() {
            out.push_str(&format!("\nSCORE {}\n", score));
            out.push_str(&format!("  formula: {}\n", rules::SCORE_FORMULA));
            out.push_str(&format!("  from {} finding(s)\n", score.scored()));
            if self.rules_run == 0 {
                out.push_str(&format!("  WARNING: {NO_RULES_WARNING}\n"));
            }
        }

        out
    }
}

/// The published penalty table as the JSON object a score block carries.
///
/// Built by walking [`rules::Severity::LADDER`] so that the keys are the
/// ladder's own spellings and a severity added to the ladder cannot be
/// missing from the table.
fn penalties_json() -> Value {
    let mut table = serde_json::Map::new();
    for severity in rules::Severity::LADDER {
        table.insert(severity.id().to_owned(), json!(rules::penalty(severity)));
    }
    Value::Object(table)
}

/// How many parts of the card, or of the rule set, this run did not cover
/// (doctor/1 `score.coverage_gaps`).
///
/// One for each bound the walk hit (at least one when the walk is incomplete
/// for any reason, e.g. `stopped`), one for a TAR scan that did not finish, one
/// when no rule ran, and one for each rule that ran with nothing to look at (the
/// MSL 0 rule under `--tar off`). A 100 with a gap is `incomplete`, not `good`.
#[must_use]
pub fn coverage_gaps(
    tree: &Tree,
    context: &Context<'_>,
    verdict: &Verdict,
    facts: &baseline::RunFacts,
) -> usize {
    let walk = if tree.is_complete() && context.stopped.is_none() {
        0
    } else {
        tree.limits_hit().len().max(1)
    };
    walk + usize::from(verdict.tar().stopped.is_some())
        + usize::from(verdict.rules_run() == 0)
        + facts
            .rule_runs()
            .iter()
            .filter(|run| !run.had_evidence())
            .count()
}

/// The category of a rule id: the part before the first `/`, which is how every
/// rule here is namespaced (`gsma/msl-zero-allowed` is `gsma`).
fn category(rule: &str) -> &str {
    rule.split('/').next().unwrap_or(rule)
}

/// One finding in the doctor/1 shape (contract section 2).
///
/// The old finding keys that have no contract name travel as extra keys
/// (`severity_rank`, `coverage`, `location_detail`): consumers ignore unknown
/// keys, and nothing the old finding said is lost.
fn doctor_finding(finding: &rules::Finding, remedy: Option<&str>, state: Option<&str>) -> Value {
    let old = finding.to_json();
    let location = match finding.location() {
        rules::Location::File { path, .. } => json!({"kind": "card-path", "ref": path}),
        rules::Location::Card => json!({"kind": "none", "ref": "card"}),
        other => json!({"kind": "card-path", "ref": other.to_string()}),
    };
    let evidence: Vec<Value> = match &old["evidence"] {
        Value::Object(map) => {
            let kind = map
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("evidence");
            let value = map.get("octets").or_else(|| map.get("value"));
            value.map_or_else(Vec::new, |v| vec![json!({"ref": kind, "value": v})])
        }
        _ => Vec::new(),
    };
    let mut out = json!({
        "id": finding.rule().as_str(),
        "fingerprint": crate::sarif::fingerprint(finding),
        "severity": finding.severity().id(),
        "category": category(finding.rule().as_str()),
        "message": finding.message(),
        "location": location,
        "evidence": evidence,
        "remedy": remedy,
        "severity_rank": finding.severity().rank(),
        "coverage": old["coverage"],
        "location_detail": old["location"],
    });
    if let Some(state) = state {
        out["baseline_state"] = json!(state);
    }
    out
}

/// The doctor/1 `score` object of this run, shared by the envelope and the SARIF
/// run properties.
#[must_use]
pub fn doctor_score(
    tree: &Tree,
    context: &Context<'_>,
    verdict: &Verdict,
    facts: &baseline::RunFacts,
) -> Value {
    contract::doctor_score(
        verdict.findings().score().value(),
        SCORE_MODEL,
        coverage_gaps(tree, context, verdict, facts),
    )
}

/// The doctor/1 envelope for a finished scan (docs/doctor-contract.md).
///
/// `findings` and `score` are the shared top-level shapes; everything else the
/// old `data` carried is still under `data`: the walk, the TAR audit, the old
/// findings block as `findings_detail` (count, exhaustive, coverage,
/// `severity_threshold`), the old score block as `score_detail`, the walk
/// record a later `--baseline` run compares as `run`, and `diff` when a
/// baseline was given.
pub fn doctor_json(
    tree: &Tree,
    context: &Context<'_>,
    verdict: &Verdict,
    facts: &baseline::RunFacts,
    exit_code: ExitCode,
) -> Value {
    let mut data = to_json(tree, context, verdict);
    if let Some(map) = data.as_object_mut() {
        if let Some(detail) = map.remove("findings") {
            map.insert("findings_detail".to_owned(), detail);
        }
        map.remove("score");
        map.insert("score_detail".to_owned(), verdict.score_detail());
        map.insert("run".to_owned(), facts.to_json());
    }

    let specs = specs();
    let remedy_of = |id: &str| {
        specs
            .iter()
            .find(|spec| spec.id().as_str() == id)
            .and_then(rules::RuleSpec::remediation)
    };

    // Which of this run's findings the baseline already had: a multiset match on
    // fingerprint, the same key the comparison used.
    let mut unchanged: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    if let Some(diff) = verdict.diff() {
        for finding in diff.persisting() {
            *unchanged
                .entry(crate::sarif::fingerprint(finding))
                .or_default() += 1;
        }
    }
    let (mut new, mut same) = (0usize, 0usize);
    let mut findings: Vec<Value> = verdict
        .findings()
        .iter()
        .map(|finding| {
            let state = verdict.diff().map(|_| {
                match unchanged.get_mut(&crate::sarif::fingerprint(finding)) {
                    Some(left) if *left > 0 => {
                        *left -= 1;
                        same += 1;
                        "unchanged"
                    }
                    _ => {
                        new += 1;
                        "new"
                    }
                }
            });
            doctor_finding(finding, remedy_of(finding.rule().as_str()), state)
        })
        .collect();
    findings.sort_by(|a, b| {
        let key = |v: &Value| {
            (
                std::cmp::Reverse(v["severity_rank"].as_u64()),
                v["id"].as_str().map(str::to_owned),
                v["fingerprint"].as_str().map(str::to_owned),
            )
        };
        key(a).cmp(&key(b))
    });

    let baseline = verdict
        .diff()
        .map(|diff| json!({"new": new, "unchanged": same, "fixed": diff.fixed().len()}));
    let score = doctor_score(tree, context, verdict, facts);
    contract::doctor_envelope(exit_code, score, findings, data, baseline)
}

/// The doctor/1 `score.model` of this tool: the penalty ladder in
/// [`rules::SCORE_PENALTY`] and [`rules::SCORE_FORMULA`]. Changes (`sim/2`)
/// whenever either does.
pub const SCORE_MODEL: &str = "sim/1";

/// Renders a walk as the `data` a scan envelope carries.
///
/// One call, one [`Value`]. The caller puts it in
/// [`crate::contract::Envelope::new`] with [`KIND`] and writes it; nothing here
/// touches stdout, so the stdout-purity rule in `src/main.rs` is a property of
/// the binary and not of this function.
///
/// # Truncation
///
/// `data.truncated` and `data.complete` are the same fact stated twice, on
/// purpose. A consumer branching on `"truncated": true` and a consumer
/// branching on `"complete": false` should agree, and `"complete"` reads
/// correctly in an assertion about a clean run while `"truncated"` reads
/// correctly in an alarm. `data.truncated_by` is the **first** bound only;
/// `data.limits_hit` is the **full** list, and reporting the head alone is how
/// a scan understates how much of the card it missed.
///
/// # Refusals
///
/// `data.absent`, `data.forbidden` and `data.refused` are three separate arrays
/// and are never merged. `data.files` carries the same distinction as a
/// per-entry `"state"` discriminant. An agent that wants "what is on this card"
/// reads `data.selected`; one that wants "what is there but not readable" reads
/// `data.forbidden`, and neither has to subtract anything.
pub fn to_json(tree: &Tree, context: &Context<'_>, verdict: &Verdict) -> Value {
    let report = tree.report();
    let dialect_tags = context.dialect.tag_set();

    let mut selected: Vec<String> = Vec::new();
    let mut absent: Vec<String> = Vec::new();
    let mut forbidden: Vec<Value> = Vec::new();
    let mut refused: Vec<Value> = Vec::new();
    let mut files: Vec<Value> = Vec::with_capacity(tree.len());
    let mut notes: Vec<Value> = Vec::new();

    for node in tree.nodes() {
        let path = node.path().to_string();
        match node.state() {
            NodeState::Selected { .. } => selected.push(path.clone()),
            NodeState::Absent => absent.push(path.clone()),
            NodeState::Forbidden { status } => {
                forbidden.push(json!({ "path": path.clone(), "status": status.to_string() }));
            }
            NodeState::Refused { status } => {
                refused.push(json!({
                    "path": path.clone(),
                    "status": status.map(|status| status.to_string()),
                }));
            }
        }

        files.push(node_json(node));

        for note in node.notes() {
            notes.push(json!({
                "path": path,
                "note": note_json(note),
            }));
        }
    }

    let limits_hit: Vec<&'static str> = tree
        .limits_hit()
        .iter()
        .map(|limit| limit_name(*limit))
        .collect();
    let (candidate_count, candidates_truncated) = context
        .candidates
        .clone()
        .identifiers(context.limits.max_children);
    let exhaustive = candidates_exhaustive(&context.candidates);

    let mut report = json!({
        "reader": context.reader,
        "atr": context.atr.map(hex),
        "dialect": {
            "id": context.dialect.id(),
            "name": dialect_tags.name(),
            "tags": {
                "file_size": dialect_tags.file_size().map(|tag| tag.to_string()),
                "file_descriptor": dialect_tags.file_descriptor().map(|tag| tag.to_string()),
                "file_id": dialect_tags.file_id().map(|tag| tag.to_string()),
                "life_cycle_status": dialect_tags.life_cycle_status().map(|tag| tag.to_string()),
                "access_conditions": dialect_tags.access_conditions().map(|tag| tag.to_string()),
                "short_file_id": dialect_tags.short_file_id().map(|tag| tag.to_string()),
                "df_name": dialect_tags.df_name().map(|tag| tag.to_string()),
                "proprietary": dialect_tags.proprietary().map(|tag| tag.to_string()),
            },
        },
        "addressing": addressing_name(tree.addressing()),
        "candidates": {
            "set": candidate_name(&context.candidates),
            "probed": candidate_count.len(),
            "budget": context.limits.max_children,
            "truncated_by_budget": candidates_truncated,
            "exhaustive": exhaustive,
            "warning": if exhaustive { Value::Null } else { json!(CANDIDATE_WARNING) },
        },
        "limits": {
            "max_depth": context.limits.max_depth,
            "max_children": context.limits.max_children,
            "max_nodes": context.limits.max_nodes,
            "max_directories": context.limits.max_directories,
        },
        "complete": tree.is_complete() && context.stopped.is_none(),
        "truncated": !tree.is_complete() || context.stopped.is_some(),
        "truncated_by": tree.truncated_by().map(limit_name),
        "limits_hit": limits_hit,
        "stopped": context.stopped,
        "walk": {
            "nodes": report.nodes,
            "directories": report.directories,
            "selected": report.selected,
            "absent": report.absent,
            "forbidden": report.forbidden,
            "refused": report.refused,
            "repeated_ancestors": report.repeated_ancestors,
        },
        "selected": selected,
        "absent": absent,
        "forbidden": forbidden,
        "refused": refused,
        "notes": notes,
        "files": files,
        // Additive: the security-relevant EFs, decoded, full values (src/ef.rs).
        "ef_contents": ef::to_json(tree),
    });

    // The verdict is spliced in rather than named in the literal above, so
    // there is one place that knows what a walk renders and one that knows
    // what a verdict renders, and a field added to either cannot be half
    // added. `as_object_mut` is `Some` because the literal above is an
    // object; there is no shape here that silently drops the findings.
    if let Some(fields) = report.as_object_mut() {
        fields.extend(verdict.fields());
    }
    report
}

/// Renders a walk as the report a person reads.
///
/// Not a table of every probed identifier: a walk probes 1280 identifiers per
/// directory to find the twenty that exist, and printing the misses would bury
/// the answer. What is printed is what the card actually holds, plus every
/// refusal and every note, plus a banner when the walk stopped early.
///
/// The banner is the requirement, not decoration. It goes **first**, before the
/// reader name, because a truncated scan read from the bottom up is a truncated
/// scan that was skimmed.
pub fn to_human(tree: &Tree, context: &Context<'_>, verdict: &Verdict) -> String {
    let report = tree.report();
    let dialect_tags = context.dialect.tag_set();
    let mut out = String::new();

    let complete = tree.is_complete() && context.stopped.is_none();
    if complete {
        out.push_str("COMPLETE: this walk reached the end of what it was asked to read.\n");
    } else {
        out.push_str("!! TRUNCATED: this walk did NOT see the whole card.\n");
        out.push_str("!! Everything below is the part it reached. Any file outside it is\n");
        out.push_str("!! neither present nor absent here - it was never asked about.\n");
        match tree.truncated_by() {
            Some(first) => out.push_str(&format!("!! First bound hit: {}\n", limit_name(first))),
            None => out.push_str("!! No bound fired; see stopped for why the walk ended.\n"),
        }
        let limits_hit: Vec<&str> = tree.limits_hit().iter().copied().map(limit_name).collect();
        if !limits_hit.is_empty() {
            out.push_str(&format!("!! Every bound hit: {}\n", limits_hit.join(", ")));
        }
        if let Some(reason) = context.stopped() {
            out.push_str(&format!("!! Walk stopped: {reason}\n"));
        }
    }
    out.push('\n');

    out.push_str(&format!("reader           {}\n", context.reader));
    match context.atr {
        Some(atr) => out.push_str(&format!("ATR              {}\n", hex(atr))),
        None => out.push_str("ATR              (not read)\n"),
    }
    out.push_str(&format!(
        "FCP dialect      {}  ({})\n",
        context.dialect.id(),
        dialect_tags.name()
    ));
    out.push_str(&format!(
        "                 file size {}, descriptor {}, file id {}\n",
        tag_or_none(dialect_tags.file_size()),
        tag_or_none(dialect_tags.file_descriptor()),
        tag_or_none(dialect_tags.file_id())
    ));
    out.push_str(&format!("addressing       {}\n", tree.addressing()));
    let (candidate_count, candidates_truncated) = context
        .candidates
        .clone()
        .identifiers(context.limits.max_children);
    out.push_str(&format!(
        "candidates       {} ({} identifiers per directory{})\n",
        candidate_name(&context.candidates),
        candidate_count.len(),
        if candidates_truncated {
            ", truncated to the budget"
        } else {
            ""
        }
    ));
    if !candidates_exhaustive(&context.candidates) {
        out.push_str(&format!("                 WARNING: {CANDIDATE_WARNING}\n"));
    }
    out.push_str(&format!(
        "bounds           depth {}, children {}, nodes {}, directories {}\n",
        context.limits.max_depth,
        context.limits.max_children,
        context.limits.max_nodes,
        context.limits.max_directories
    ));
    out.push('\n');

    out.push_str(&format!(
        "walk             {} files, {} directories, {} selected, {} absent, {} forbidden, {} refused, {} repeated identifiers\n\n",
        report.nodes,
        report.directories,
        report.selected,
        report.absent,
        report.forbidden,
        report.refused,
        report.repeated_ancestors
    ));

    out.push_str("SELECTED FILES\n");
    if tree.selected().next().is_none() {
        out.push_str("  (none)\n");
    }
    for node in tree.selected() {
        out.push_str(&format!("  {}\n", selected_line(node)));
    }

    out.push_str("\nFORBIDDEN FILES (present, not readable by this terminal)\n");
    let mut any_forbidden = false;
    for node in tree.refused(walk::RefusalKind::Forbidden) {
        any_forbidden = true;
        let status = node
            .state()
            .status()
            .map(|status| status.to_string())
            .unwrap_or_else(|| "(no status word)".to_owned());
        out.push_str(&format!("  {}  status {status}\n", node.path()));
    }
    if !any_forbidden {
        out.push_str("  (none)\n");
    }

    out.push_str("\nREFUSED FOR ANOTHER REASON\n");
    let mut any_refused = false;
    for node in tree.unclassified_refusals() {
        any_refused = true;
        match node.state().status() {
            Some(status) => out.push_str(&format!("  {}  status {status}\n", node.path())),
            None => out.push_str(&format!("  {}  (no status word)\n", node.path())),
        }
    }
    if !any_refused {
        out.push_str("  (none)\n");
    }

    let noted: Vec<&Node> = tree
        .nodes()
        .iter()
        .filter(|node| !node.is_complete())
        .collect();
    out.push_str("\nNOTES\n");
    if noted.is_empty() {
        out.push_str("  (none)\n");
    }
    for node in noted {
        for note in node.notes() {
            out.push_str(&format!("  {}  {}\n", node.path(), note_line(note)));
        }
    }

    // Last, and after a blank line, because the walk is the long part and the
    // findings and the score are what the reader came for.
    // The TAR block comes before the findings on purpose: a finding an
    // operator cannot check against something is the failure this crate
    // keeps designing against, so the evidence is on the page first and
    // the verdict reads as a reading of it.
    out.push('\n');
    out.push_str(&verdict.tar_to_human());
    out.push('\n');
    out.push_str(&verdict.to_human());

    // Everything above includes text the card chose (file names, labels, a
    // finding's message). A report that reaches a terminal must not carry an
    // escape sequence or a bidi override from it.
    contract::sanitize_lines(&out)
}

/// One selected file, on one line: address, kind, size, descriptor, life cycle.
fn selected_line(node: &Node) -> String {
    let Some(capabilities) = node.state().capabilities() else {
        // Written rather than unwrapped so a future variant of NodeState
        // cannot turn this into a panic on a hostile card.
        return format!("{}  (selected, no capabilities)", node.path());
    };
    let size = match capabilities.size.reported() {
        Some(size) => format!("{} octets", size.octets()),
        None if capabilities.size.is_reported() => "size unreadable".to_owned(),
        None => "no size reported".to_owned(),
    };
    let life_cycle = match capabilities.life_cycle.reported() {
        Some(status) => status.to_string(),
        None if capabilities.life_cycle.is_reported() => "life cycle unreadable".to_owned(),
        None => String::new(),
    };
    let descriptor = match capabilities.descriptor.reported() {
        Some(descriptor) => format!(
            "{}/{}",
            file_type_name(descriptor.file_type),
            structure_name(descriptor.structure)
        ),
        None => "descriptor not reported".to_owned(),
    };
    let mut line = format!(
        "{:<24} {:<14} {:<16} {:<24} {}",
        node.path().to_string(),
        kind_name(node.state().kind()),
        size,
        descriptor,
        life_cycle
    );
    if !capabilities.unknown_tags.is_empty() {
        let tags: Vec<String> = capabilities
            .unknown_tags
            .iter()
            .map(|tag| tag.to_string())
            .collect();
        line.push_str(&format!(
            "  [tags this dialect does not explain: {}]",
            tags.join(" ")
        ));
    }
    for note in node.notes() {
        line.push_str(&format!("  ({})", note_line(note)));
    }
    line
}

/// The JSON record for one node, whatever state it is in.
fn node_json(node: &Node) -> Value {
    let mut value = json!({
        "path": node.path().to_string(),
        "state": state_name(node),
    });

    let NodeState::Selected { kind, capabilities } = node.state() else {
        if let Some(status) = node.state().status() {
            value["status"] = json!(status.to_string());
        }
        return value;
    };

    value["kind"] = json!(kind_name(Some(*kind)));
    if let Some(file_kind) = kind.as_file_kind() {
        value["file_kind"] = json!(file_kind.to_string());
        value["container"] = json!(kind.is_container());
    }
    value["size"] = reported_json(
        capabilities
            .size
            .reported()
            .map(|size| json!({ "octets": size.octets() })),
        capabilities.size.is_reported(),
        capabilities.size.unreadable().map(ToString::to_string),
    );
    value["life_cycle"] = reported_json(
        capabilities
            .life_cycle
            .reported()
            .map(|status| json!(status.to_string())),
        capabilities.life_cycle.is_reported(),
        capabilities
            .life_cycle
            .unreadable()
            .map(ToString::to_string),
    );
    value["descriptor"] = reported_json(
        capabilities.descriptor.reported().map(|descriptor| {
            json!({
                "octets": hex(&descriptor.octets),
                "file_type": file_type_name(descriptor.file_type),
                "structure": structure_name(descriptor.structure),
                "shareable": descriptor.shareable,
                "data_coding": descriptor.data_coding.map(|octet| format!("{octet:02X}")),
            })
        }),
        capabilities.descriptor.is_reported(),
        capabilities
            .descriptor
            .unreadable()
            .map(ToString::to_string),
    );
    value["name"] = reported_json(
        capabilities
            .name
            .reported()
            .map(|name| json!(String::from_utf8_lossy(trim_padding(name)))),
        capabilities.name.is_reported(),
        capabilities.name.unreadable().map(ToString::to_string),
    );
    value["reported_file_id"] = reported_json(
        capabilities
            .reported_file_id
            .reported()
            .map(|id| json!(hex(id))),
        capabilities.reported_file_id.is_reported(),
        capabilities
            .reported_file_id
            .unreadable()
            .map(ToString::to_string),
    );
    value["unknown_tags"] = json!(capabilities
        .unknown_tags
        .iter()
        .map(|tag| tag.to_string())
        .collect::<Vec<String>>());
    value
}

/// The JSON shape of a [`walk::Reported`]: which of the three answers this is.
///
/// Three states rather than a bare null, because "the card did not send this
/// field" and "the card sent it and it did not decode" are different findings
/// and a nullable field would collapse them.
fn reported_json(value: Option<Value>, was_reported: bool, unreadable: Option<String>) -> Value {
    match (value, unreadable) {
        (Some(value), _) => json!({ "state": "reported", "value": value }),
        (None, Some(error)) => json!({ "state": "unreadable", "error": error }),
        (None, None) if was_reported => json!({ "state": "unreadable" }),
        (None, None) => json!({ "state": "not-reported" }),
    }
}

/// The wire name of a node's state.
///
/// Three refusal names, never one. `absent` is "the card says it is not there";
/// `forbidden` is "the card says it is there and this terminal may not read it";
/// `refused` is "the card said something this crate will not classify". The
/// whole point of [`walk::NodeState`] surviving into the output is that a
/// caller can still tell them apart here.
const fn state_name(node: &Node) -> &'static str {
    match node.state() {
        NodeState::Selected { .. } => "selected",
        NodeState::Absent => "absent",
        NodeState::Forbidden { .. } => "forbidden",
        NodeState::Refused { .. } => "refused",
    }
}

/// The wire name of a kind.
fn kind_name(kind: Option<walk::Kind>) -> &'static str {
    match kind {
        Some(walk::Kind::MasterFile) => "master-file",
        Some(walk::Kind::Reported(fs::FileKind::MasterFile)) => "master-file",
        Some(walk::Kind::Reported(fs::FileKind::DedicatedFile)) => "directory",
        Some(walk::Kind::Reported(fs::FileKind::ElementaryFile)) => "elementary-file",
        Some(walk::Kind::Unreported) | None => "unreported",
    }
}

/// The wire name of an [`fcp::FileType`].
const fn file_type_name(file_type: fcp::FileType) -> &'static str {
    match file_type {
        fcp::FileType::Directory => "directory",
        fcp::FileType::Elementary => "elementary",
        fcp::FileType::Unknown(_) => "unknown",
    }
}

/// The wire name of an [`fcp::Structure`].
const fn structure_name(structure: fcp::Structure) -> &'static str {
    match structure {
        fcp::Structure::Transparent => "transparent",
        fcp::Structure::LinearFixed => "linear-fixed",
        fcp::Structure::LinearVariable => "linear-variable",
        fcp::Structure::Cyclic => "cyclic",
        fcp::Structure::Unknown(_) => "unknown",
    }
}

/// The wire name of a bound. One function, used by every consumer.
const fn limit_name(limit: Limit) -> &'static str {
    match limit {
        Limit::Depth => "depth",
        Limit::Children => "children",
        Limit::Nodes => "nodes",
        Limit::Directories => "directories",
    }
}

/// The wire name of an addressing mode.
const fn addressing_name(addressing: walk::Addressing) -> &'static str {
    match addressing {
        walk::Addressing::Identifier => "identifier",
        walk::Addressing::PathFromMasterFile => "path-from-master-file",
    }
}

/// The JSON record for one [`walk::Note`], as a tagged object.
///
/// A tag rather than a bare string so a consumer can branch on `note` and read
/// the fields that variant carries without string-matching.
fn note_json(note: &Note) -> Value {
    match note {
        Note::RepeatedAncestor { id, ancestor } => json!({
            "note": "repeated-ancestor",
            "id": id.to_string(),
            "ancestor": ancestor.to_string(),
        }),
        Note::Limit { limit } => json!({ "note": "limit", "limit": limit_name(*limit) }),
        Note::NotAChild { id } => json!({ "note": "not-a-child", "id": id.to_string() }),
        Note::EnumerationRefused { status, probed } => json!({
            "note": "enumeration-refused",
            "status": status.to_string(),
            "probed": probed,
        }),
        Note::IncompleteSelection { stop } => {
            json!({ "note": "incomplete-selection", "stop": stop.to_string() })
        }
        Note::UnreadableTemplate { error } => {
            json!({ "note": "unreadable-template", "error": error.to_string() })
        }
        Note::IdentityMismatch {
            requested,
            reported,
        } => json!({
            "note": "identity-mismatch",
            "requested": requested.to_string(),
            "reported": reported.to_string(),
        }),
    }
}

/// The same note, in a sentence.
fn note_line(note: &Note) -> String {
    match note {
        Note::RepeatedAncestor { id, ancestor } => format!(
            "identifier {id} repeats an ancestor at {ancestor} (a legal file, not a cycle)"
        ),
        Note::Limit { limit } => format!("{limit} bound stopped the walk here"),
        Note::NotAChild { id } => {
            format!("{id} cannot be a child of the directory it was found under")
        }
        Note::EnumerationRefused { status, probed } => format!(
            "nothing under this directory could be selected: all {probed} probes drew {status}, which this tool does not read as 'not there'"
        ),
        Note::IncompleteSelection { stop } => {
            format!("selection did not end cleanly: {stop}")
        }
        Note::UnreadableTemplate { error } => {
            format!("the capabilities template did not decode: {error}")
        }
        Note::IdentityMismatch { requested, reported } => {
            format!("asked for {requested} and the card echoed {reported}")
        }
    }
}

/// Trims the trailing padding a card writes after a directory name.
fn trim_padding(name: &[u8]) -> &[u8] {
    let end = name
        .iter()
        .rposition(|octet| *octet != 0x00 && *octet != 0xFF)
        .map_or(0, |last| last + 1);
    &name[..end]
}

/// Renders bytes as spaced uppercase hex, the form every other log in this
/// repository uses.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|octet| format!("{octet:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Renders an optional tag for the human report.
fn tag_or_none(tag: Option<Tag>) -> String {
    tag.map_or_else(|| "(none)".to_owned(), |tag| tag.to_string())
}

/// Builds the refusal for a `--reader` naming nothing that is attached.
///
/// **A value rather than a sentence, so both forms come from one place.** The
/// human report and the JSON `data.error.message` are rendered from the same
/// fields, and the list of what *is* attached is in both - "no reader named X"
/// on its own sends the next person looking at the driver rather than at the
/// machine.
pub fn unknown_reader(requested: &str, available: &[&str]) -> UnknownReader {
    UnknownReader {
        requested: requested.to_owned(),
        available: available.iter().map(|name| (*name).to_owned()).collect(),
    }
}

/// A `--reader` that names a reader this machine does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownReader {
    /// What the operator asked for.
    pub requested: String,
    /// What is actually attached, in driver order.
    pub available: Vec<String>,
}

impl fmt::Display for UnknownReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let available = if self.available.is_empty() {
            "none".to_owned()
        } else {
            self.available.join(", ")
        };
        write!(
            f,
            "no reader named {:?} is attached; readers available: {available}",
            self.requested
        )
    }
}

/// The card could not be scanned at all.
///
/// Distinct from "the scan found nothing", which is a result, and from "the
/// flags asked for are not implemented", which never got as far as a card.
/// Every one of these ends in exit code 1 under AGENTS.md section 3: a check
/// that could not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// One sentence saying what failed.
    pub message: String,
    /// A short machine-readable tag for the same failure.
    pub kind: &'static str,
}

impl Failure {
    /// A failure that names what could not be established.
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind,
        }
    }

    /// The machine-readable version of the failure.
    pub fn data(&self) -> Value {
        json!({
            "scanned": false,
            "card_touched": false,
            "error": { "kind": self.kind, "message": self.message },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};

    use crate::apdu::StatusWord;
    use crate::fs::{FileId, Path};
    use crate::transport::{CardSession, Error as TransportError, ReaderName};

    /// The file descriptor swICC writes for a directory. [V], swicc
    /// `src/fs.c:swicc_fs_file_descr_byte` at `421c8cdd`, category bits
    /// `111`.
    const DIRECTORY_DESCRIPTOR: [u8; 2] = [0x38, 0x21];

    /// The file descriptor swICC writes for a transparent elementary file:
    /// category `001`, structure `001`, not shareable.
    const ELEMENTARY_DESCRIPTOR: [u8; 2] = [0x09, 0x21];

    /// One BER-TLV atom in the short length form, which is every atom this
    /// fixture contains.
    fn atom(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, u8::try_from(body.len()).expect("a short body")];
        out.extend_from_slice(body);
        out
    }

    /// A capabilities template under the swICC tag table: file size in `80`,
    /// descriptor in `82`, file id in `83`.
    fn fcp(fid: &str, descriptor: [u8; 2], size: Option<u16>) -> Vec<u8> {
        let mut body = Vec::new();
        if let Some(size) = size {
            body.extend(atom(0x80, &size.to_be_bytes()));
        }
        body.extend(atom(0x82, &descriptor));
        body.extend(atom(0x83, &id(fid).to_bytes()));
        atom(0x62, &body)
    }

    fn id(text: &str) -> FileId {
        text.parse().expect("a four-hex-digit identifier")
    }

    /// The absolute path of `path`, as a sequence of two-octet identifiers.
    fn segments(path: &str) -> Vec<u8> {
        path.split('/')
            .flat_map(|segment| id(segment).to_bytes())
            .collect()
    }

    /// A software card that answers SELECT by path the way swSIM does.
    #[derive(Debug)]
    struct FakeCard {
        files: HashMap<Vec<u8>, Vec<u8>>,
        refusals: HashMap<Vec<u8>, [u8; 2]>,
        queued: VecDeque<Vec<u8>>,
        reader: ReaderName,
    }

    impl Default for FakeCard {
        fn default() -> Self {
            Self {
                files: HashMap::new(),
                refusals: HashMap::new(),
                queued: VecDeque::new(),
                reader: ReaderName::new("fake card").expect("a valid reader name"),
            }
        }
    }

    impl FakeCard {
        /// Adds a file the card will select successfully.
        fn with(mut self, path: &str, template: Vec<u8>) -> Self {
            self.files.insert(segments(path), template);
            self
        }

        /// Adds a file the card refuses with `status`.
        fn refusing(mut self, path: &str, status: [u8; 2]) -> Self {
            self.refusals.insert(segments(path), status);
            self
        }
    }

    impl CardSession for FakeCard {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }

        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
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
            let path = self.select_target(command);
            if let Some(status) = self.refusals.get(&path) {
                return Ok(status.to_vec());
            }
            match self.files.get(&path) {
                Some(template) => {
                    let length = u8::try_from(template.len()).expect("a short template");
                    self.queued.push_back(template.clone());
                    Ok(vec![0x61, length])
                }
                None => Ok(vec![0x6A, 0x82]),
            }
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    impl FakeCard {
        /// The absolute path a SELECT names, the way swSIM resolves one.
        ///
        /// P1 08 is the path form: the data field is the absolute path with the
        /// master file's own identifier removed, so it goes back on the front.
        /// P1 00 is the GSM 11.11 identifier form, which swSIM resolves against
        /// the whole card, so it is matched against the leaf of every path held.
        /// The master file is selected by identifier and has no path form.
        fn select_target(&self, command: &[u8]) -> Vec<u8> {
            let body = command.get(5..).unwrap_or_default();
            if command.get(2) == Some(&0x08) {
                let mut path = FileId::MASTER_FILE.to_bytes().to_vec();
                path.extend_from_slice(body);
                return path;
            }
            if body.len() == 2 {
                return self
                    .files
                    .keys()
                    .chain(self.refusals.keys())
                    .find(|path| path.len() >= 2 && path[path.len() - 2..] == *body)
                    .cloned()
                    .unwrap_or_else(|| body.to_vec());
            }
            body.to_vec()
        }
    }

    fn context(candidates: Candidates, limits: Limits) -> Context<'static> {
        Context::new(
            "fake card",
            Some(&[0x3B, 0x16]),
            Dialect::Swicc,
            candidates,
            limits,
        )
    }

    /// A verdict over the findings a scan produces today: none, from no rule.
    ///
    /// Every test above is about the WALK, so it renders with the verdict a
    /// bare `sim-doctor scan --json` produces - no threshold, no score - and
    /// the verdict itself is tested in its own section further down. Putting
    /// findings in front of the walk tests here would make a failure in
    /// either half point at the other.
    fn verdict() -> Verdict {
        Verdict::new(rules::Findings::complete(Vec::new()), rules_run())
    }

    /// The two-octet space, for the exhaustive-candidate tests.
    fn whole_space() -> Candidates {
        Candidates::Range {
            first: FileId::from_bytes([0x00, 0x00]),
            last: FileId::from_bytes([0xFF, 0xFF]),
        }
    }

    /// A card with a directory, an elementary file under the master file, a
    /// directory with a child of its own, and a file the card will not let this
    /// terminal read.
    ///
    /// The forbidden case is scripted in rather than produced by an access
    /// condition, because no software card can produce one: swICC evaluates no
    /// access condition on SELECT. See the card-fixture test for what that
    /// means for what is card-verified.
    fn sample_card() -> FakeCard {
        FakeCard::default()
            .with("3F00", fcp("3F00", DIRECTORY_DESCRIPTOR, Some(2337)))
            .with("3F00/2FE2", fcp("2FE2", ELEMENTARY_DESCRIPTOR, Some(10)))
            .with("3F00/7F20", fcp("7F20", DIRECTORY_DESCRIPTOR, None))
            .with(
                "3F00/7F20/6F07",
                fcp("6F07", ELEMENTARY_DESCRIPTOR, Some(4)),
            )
            .refusing("3F00/6F03", [0x98, 0x04])
    }

    /// The candidates every test probes: exactly the leaves this fixture
    /// holds, plus one that is not there at all.
    fn probe_set() -> Candidates {
        Candidates::List(vec![id("2F01"), id("2FE2"), id("6F03"), id("7F20")])
    }

    fn walk_sample(card: &mut FakeCard, limits: Limits) -> Tree {
        let options = walk::Options {
            candidates: probe_set(),
            limits,
            // Only `6A 82` is classified out of the box, so the fixture's
            // forbidden case needs the caller to say what 98 04 means here.
            // That is the point of StatusMeaning being a table rather than a
            // built-in mapping: a refusal this crate cannot cite must be
            // classified by whoever has read their card's own table.
            meaning: walk::StatusMeaning::default().with_forbidden(StatusWord::new(0x98, 0x04)),
            ..walk::Options::default()
        };
        walk::walk(card, &Dialect::Swicc.tag_set(), &options)
            .expect("the walk reaches the master file")
    }

    /// The selected paths the JSON reports, in order.
    fn selected_paths(data: &Value) -> Vec<String> {
        data["selected"]
            .as_array()
            .expect("selected is an array")
            .iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect()
    }

    /// One file record out of the report, by path.
    fn file(data: &Value, path: &str) -> Value {
        data["files"]
            .as_array()
            .expect("files is an array")
            .iter()
            .find(|file| file["path"] == json!(path))
            .unwrap_or_else(|| panic!("{path} is not in the report"))
            .clone()
    }

    // --- Requirement 1: truncation must reach the output. ---

    #[test]
    fn a_truncated_walk_is_unmistakable_in_the_json() {
        // Depth 1 means the walk may not descend into 3F00/7F20, so the
        // directory's child is never reached and the depth bound fires.
        let mut card = sample_card();
        let limits = Limits {
            max_depth: 1,
            ..Limits::default()
        };
        let tree = walk_sample(&mut card, limits);
        assert!(!tree.is_complete(), "this fixture must actually truncate");

        let data = to_json(&tree, &context(probe_set(), limits), &verdict());

        assert_eq!(data["truncated"], json!(true));
        assert_eq!(data["complete"], json!(false));
        assert_eq!(data["truncated_by"], json!("depth"));
        assert_eq!(data["limits_hit"], json!(["depth"]));

        // And the file list is shorter because of it, which is the whole point:
        // a consumer that ignored those fields would under-report.
        let selected = selected_paths(&data);
        assert_eq!(selected, vec!["3F00", "3F00/2FE2", "3F00/7F20"]);
        assert!(
            !selected.contains(&"3F00/7F20/6F07".to_owned()),
            "the file under the cut must not be in the list, which is exactly \
             why the cut has to be visible"
        );
    }

    #[test]
    fn a_complete_walk_says_so_in_the_json() {
        // The other end of the same fact. Without this pair, "truncated: false"
        // could mean "the walk finished" or "nothing sets it", and only one of
        // those is a clean card.
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        assert!(tree.is_complete());

        let data = to_json(&tree, &context(probe_set(), limits), &verdict());
        assert_eq!(data["truncated"], json!(false));
        assert_eq!(data["complete"], json!(true));
        assert_eq!(data["truncated_by"], Value::Null);
        assert_eq!(data["limits_hit"], json!([]));
    }

    #[test]
    fn every_bound_hit_is_reported_not_just_the_first() {
        // Depth 1 plus a two-node ceiling is the combination that fires two
        // bounds at once, which is the case `truncated_by` alone understates.
        let mut card = sample_card();
        let limits = Limits {
            max_depth: 1,
            max_nodes: 2,
            ..Limits::default()
        };
        let tree = walk_sample(&mut card, limits);
        assert!(
            tree.limits_hit().len() > 1,
            "this fixture must defeat two bounds, found {:?}",
            tree.limits_hit()
        );

        let data = to_json(&tree, &context(probe_set(), limits), &verdict());
        let hit: Vec<&str> = data["limits_hit"]
            .as_array()
            .expect("limits_hit is an array")
            .iter()
            .filter_map(|value| value.as_str())
            .collect();
        assert_eq!(
            hit,
            tree.limits_hit()
                .iter()
                .map(|limit| limit_name(*limit))
                .collect::<Vec<_>>(),
            "the JSON must carry every bound, in order, not just the first"
        );
        assert!(
            hit.contains(&"nodes"),
            "the node bound must be listed: {hit:?}"
        );
        assert!(
            data["truncated_by"].is_string(),
            "the first bound is a separate field and must be present"
        );
    }

    #[test]
    fn a_truncated_walk_says_so_at_the_top_of_the_human_report() {
        let mut card = sample_card();
        let limits = Limits {
            max_depth: 1,
            ..Limits::default()
        };
        let tree = walk_sample(&mut card, limits);
        let report = to_human(&tree, &context(probe_set(), limits), &verdict());

        let first_line = report.lines().next().unwrap_or_default();
        assert!(
            first_line.starts_with("!! TRUNCATED"),
            "the banner must be the first thing an operator reads, got {first_line:?}"
        );
        assert!(report.contains("First bound hit: depth"), "{report}");
        assert!(report.contains("Every bound hit: depth"), "{report}");
    }

    #[test]
    fn a_complete_human_report_says_complete_first() {
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        let report = to_human(&tree, &context(probe_set(), limits), &verdict());

        assert!(
            report.starts_with("COMPLETE:"),
            "{}",
            report.lines().next().unwrap_or_default()
        );
        assert!(
            !report.contains("!!"),
            "a clean run carries no banner: {report}"
        );
    }

    // --- Requirement 2: the dialect is chosen out loud. ---

    #[test]
    fn the_json_reports_the_dialect_the_walk_ran_under() {
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);

        for dialect in Dialect::ALL {
            let tags = dialect.tag_set();
            let context = Context::new("fake card", None, dialect, probe_set(), limits);
            let data = to_json(&tree, &context, &verdict());

            assert_eq!(data["dialect"]["id"], json!(dialect.id()));
            assert_eq!(data["dialect"]["name"], json!(tags.name()));
            // The reported tags are the ones the walk was handed, not a
            // re-derivation. swICC and ISO disagree on all three of these.
            assert_eq!(
                data["dialect"]["tags"]["file_size"],
                json!(tags.file_size().map(|tag| tag.to_string()))
            );
            assert_eq!(
                data["dialect"]["tags"]["file_descriptor"],
                json!(tags.file_descriptor().map(|tag| tag.to_string()))
            );
            assert_eq!(
                data["dialect"]["tags"]["file_id"],
                json!(tags.file_id().map(|tag| tag.to_string()))
            );
        }
    }

    #[test]
    fn the_two_dialects_are_told_apart_by_name() {
        // If this ever stopped holding, reporting the name would be reporting
        // nothing at all.
        let swicc = Dialect::Swicc.tag_set();
        let std = Dialect::Ts102221.tag_set();
        assert_ne!(swicc.name(), std.name());
    }

    #[test]
    fn the_human_report_names_the_dialect_and_its_tags() {
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        let report = to_human(&tree, &context(probe_set(), limits), &verdict());

        assert!(report.contains("FCP dialect      swicc"), "{report}");
        assert!(report.contains("swICC FCP builder"), "{report}");
        assert!(report.contains("file size 80"), "{report}");
    }

    // --- Requirement 3: absent and forbidden stay apart. ---

    #[test]
    fn absent_and_forbidden_are_three_separate_arrays() {
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        let data = to_json(&tree, &context(probe_set(), limits), &verdict());

        let absent: Vec<String> = data["absent"]
            .as_array()
            .expect("absent is an array")
            .iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect();
        let forbidden = data["forbidden"].as_array().expect("forbidden is an array");
        let refused = data["refused"].as_array().expect("refused is an array");

        assert_eq!(forbidden.len(), 1, "{data:#}");
        assert_eq!(forbidden[0]["path"], json!("3F00/6F03"));
        assert_eq!(forbidden[0]["status"], json!("9804"));
        assert!(refused.is_empty(), "nothing refused in an unclassified way");

        // The decisive assertion: a file the card will not let us read is never
        // reported as missing.
        assert!(
            !absent.contains(&"3F00/6F03".to_owned()),
            "a forbidden file must never appear as absent: {absent:?}"
        );
        assert!(
            absent.contains(&"3F00/2F01".to_owned()),
            "an identifier the card does not hold is absent: {absent:?}"
        );
    }

    #[test]
    fn every_node_carries_a_state_that_names_its_own_kind_of_refusal() {
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        let data = to_json(&tree, &context(probe_set(), limits), &verdict());

        let states: Vec<&str> = data["files"]
            .as_array()
            .expect("files is an array")
            .iter()
            .map(|file| file["state"].as_str().expect("state is a string"))
            .collect();
        assert!(states.contains(&"selected"), "{states:?}");
        assert!(states.contains(&"absent"), "{states:?}");
        assert!(states.contains(&"forbidden"), "{states:?}");
        assert!(
            !states.contains(&"failed"),
            "there is no flattened failure state: {states:?}"
        );
    }

    // --- Requirement 4: the default candidate set can under-report. ---

    #[test]
    fn the_candidate_coverage_is_reported_and_the_warning_is_attached() {
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);

        let sim_families = to_json(&tree, &context(Candidates::SimFamilies, limits), &verdict());
        assert_eq!(sim_families["candidates"]["set"], json!("sim-families"));
        assert_eq!(sim_families["candidates"]["probed"], json!(1280));
        assert_eq!(sim_families["candidates"]["exhaustive"], json!(false));
        assert_eq!(
            sim_families["candidates"]["warning"],
            json!(CANDIDATE_WARNING)
        );

        // Only a range over the whole two-octet space can say "exhaustive", and
        // then the warning is null rather than present-and-empty, so a consumer
        // branching on it sees the difference.
        let whole = to_json(&tree, &context(whole_space(), limits), &verdict());
        assert_eq!(whole["candidates"]["set"], json!("range"));
        assert_eq!(whole["candidates"]["exhaustive"], json!(true));
        assert_eq!(whole["candidates"]["warning"], Value::Null);
    }

    #[test]
    fn the_human_report_carries_the_under_report_warning() {
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        let report = to_human(&tree, &context(Candidates::SimFamilies, limits), &verdict());

        assert!(report.contains("WARNING: "), "{report}");
        assert!(report.contains("INVISIBLE"), "{report}");
        assert!(report.contains("2Fxx/4Fxx/5Fxx/6Fxx/7Fxx"), "{report}");
    }

    #[test]
    fn an_exhaustive_candidate_set_does_not_carry_the_warning() {
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        let report = to_human(&tree, &context(whole_space(), limits), &verdict());
        assert!(!report.contains("INVISIBLE"), "{report}");
    }

    // --- The dialect and the flags as a command line sees them. ---

    #[test]
    fn dialect_spellings_round_trip_and_reject_the_rest() {
        for dialect in Dialect::ALL {
            assert_eq!(dialect.id().parse::<Dialect>().unwrap(), dialect);
            assert_eq!(dialect.to_string().parse::<Dialect>().unwrap(), dialect);
        }
        assert!("SWICC".parse::<Dialect>().is_ok(), "case-insensitive");
        assert_eq!(
            DEPRECATED_TABLE_42.parse::<Dialect>().unwrap(),
            Dialect::Ts102221,
            "the old spelling is an alias for the corrected table"
        );
        assert_eq!(Dialect::default(), Dialect::Ts102221);
        assert!("iec7816".parse::<Dialect>().is_err());
        assert!("".parse::<Dialect>().is_err());
    }

    #[test]
    fn a_refusal_never_looks_like_a_score_and_says_nothing_was_scanned() {
        // The shape every failure in this module shares, asserted once on the
        // type that builds it. `Deferred` used to be the other producer of this
        // document and was removed with --baseline and --diff in issue #12: the
        // refusal shape did not go with it, and it is now reachable from a
        // missing card, an unreadable baseline and an incomparable pair alike.
        // If this changes, the rule an agent branches on has changed.
        let failure = Failure::new("no-reader", "no PC/SC reader is attached");
        let data = failure.data();

        assert!(data.get("score").is_none(), "{data}");
        assert!(data.get("findings").is_none(), "{data}");
        assert_eq!(data["scanned"], json!(false));
        assert_eq!(data["card_touched"], json!(false));
        assert_eq!(data["error"]["kind"], json!("no-reader"));
    }

    #[test]
    fn an_unknown_reader_lists_what_is_actually_there() {
        let error = unknown_reader("nope", &["swICC virtual", "Identiv SCR3500"]);
        let rendered = error.to_string();
        assert!(rendered.contains("nope"), "{rendered}");
        assert!(rendered.contains("swICC virtual"), "{rendered}");
        assert!(rendered.contains("Identiv SCR3500"), "{rendered}");

        let empty = unknown_reader("nope", &[]);
        assert!(empty.to_string().contains("none"), "{empty}");
    }

    // --- The shape of a file record. ---

    #[test]
    fn a_selected_file_reports_its_metadata_under_the_named_dialect() {
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        let data = to_json(&tree, &context(probe_set(), limits), &verdict());

        let imsi = file(&data, "3F00/2FE2");
        assert_eq!(imsi["state"], json!("selected"));
        assert_eq!(imsi["kind"], json!("elementary-file"));
        assert_eq!(imsi["size"]["state"], json!("reported"));
        // Ten octets, because the swICC table reads the size out of 80. Under
        // the ISO table this would be a nonsense number.
        assert_eq!(imsi["size"]["value"]["octets"], json!(10));
        assert_eq!(
            imsi["descriptor"]["value"]["structure"],
            json!("transparent")
        );
        assert_eq!(
            imsi["descriptor"]["value"]["file_type"],
            json!("elementary")
        );
    }

    #[test]
    fn a_field_the_card_never_sent_is_not_reported_rather_than_null() {
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        let data = to_json(&tree, &context(probe_set(), limits), &verdict());

        // Not null: "the card did not send it" is a different statement from
        // "the card sent it and it is empty", and Reported is a three-way type.
        assert_eq!(
            file(&data, "3F00/2FE2")["life_cycle"],
            json!({ "state": "not-reported" })
        );
        assert_eq!(
            file(&data, "3F00/2FE2")["name"],
            json!({ "state": "not-reported" })
        );
    }

    #[test]
    fn notes_are_reported_with_the_path_they_belong_to() {
        let mut card = sample_card();
        let limits = Limits {
            max_depth: 1,
            ..Limits::default()
        };
        let tree = walk_sample(&mut card, limits);
        let data = to_json(&tree, &context(probe_set(), limits), &verdict());

        let notes = data["notes"].as_array().expect("notes is an array");
        // Every node one past the bound carries the note, not only the first.
        let limited: Vec<&Value> = notes
            .iter()
            .filter(|note| note["note"]["note"] == json!("limit"))
            .collect();
        assert!(
            limited.len() > 1,
            "one note per node past the bound: {notes:?}"
        );
        for note in &limited {
            assert_eq!(note["note"]["limit"], json!("depth"), "{note}");
            assert_eq!(
                note["note"].get("path"),
                None,
                "the path is beside the note"
            );
        }
        assert!(
            limited
                .iter()
                .any(|note| note["path"] == json!("3F00/7F20")),
            "the directory the walk could not descend into must say so: {notes:?}"
        );
    }

    #[test]
    fn the_report_carries_the_reader_atr_addressing_and_bounds_it_ran_under() {
        let mut card = sample_card();
        let limits = Limits {
            max_depth: 3,
            max_children: 7,
            max_nodes: 11,
            max_directories: 13,
        };
        let tree = walk_sample(&mut card, limits);
        let data = to_json(&tree, &context(probe_set(), limits), &verdict());

        assert_eq!(data["reader"], json!("fake card"));
        assert_eq!(data["atr"], json!("3B 16"));
        assert_eq!(data["addressing"], json!("path-from-master-file"));
        assert_eq!(data["limits"]["max_depth"], json!(3));
        assert_eq!(data["limits"]["max_children"], json!(7));
        assert_eq!(data["limits"]["max_nodes"], json!(11));
        assert_eq!(data["limits"]["max_directories"], json!(13));
        assert_eq!(data["walk"]["nodes"], json!(tree.report().nodes));
        assert_eq!(data["walk"]["selected"], json!(tree.report().selected));
        assert_eq!(
            data["candidates"]["budget"],
            json!(7),
            "the candidate count is reported against the budget it was given"
        );
    }

    #[test]
    fn a_walk_that_stopped_for_a_reason_other_than_a_bound_is_not_called_complete() {
        let mut card = sample_card();
        let tree = walk_sample(&mut card, Limits::default());
        assert!(tree.is_complete());

        let limits = Limits::default();
        let context = context(probe_set(), limits).stopped_by("the card was removed mid-walk");
        let data = to_json(&tree, &context, &verdict());

        assert_eq!(data["complete"], json!(false));
        assert_eq!(data["truncated"], json!(true));
        assert_eq!(data["limits_hit"], json!([]));
        assert_eq!(data["truncated_by"], Value::Null);
        assert_eq!(data["stopped"], json!("the card was removed mid-walk"));
        assert_eq!(context.stopped(), Some("the card was removed mid-walk"));
    }

    #[test]
    fn the_json_is_serialisable_and_is_one_line() {
        // A Value that will not render would make the whole command fail at the
        // last step, which is the worst possible place to find that out.
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        let data = to_json(&tree, &context(probe_set(), limits), &verdict());

        let rendered = serde_json::to_string(&data).expect("the report renders");
        assert!(!rendered.contains('\n'), "the report is one line");
        let parsed: Value = serde_json::from_str(&rendered).expect("and parses back");
        assert_eq!(parsed, data);
    }

    #[test]
    fn one_function_names_every_enumeration_so_they_cannot_drift() {
        assert_eq!(limit_name(Limit::Depth), "depth");
        assert_eq!(limit_name(Limit::Children), "children");
        assert_eq!(limit_name(Limit::Nodes), "nodes");
        assert_eq!(limit_name(Limit::Directories), "directories");

        assert_eq!(addressing_name(walk::Addressing::Identifier), "identifier");
        assert_eq!(
            addressing_name(walk::Addressing::PathFromMasterFile),
            "path-from-master-file"
        );

        assert_eq!(candidate_name(&Candidates::SimFamilies), "sim-families");
        assert_eq!(candidate_name(&Candidates::List(Vec::new())), "list");
        assert_eq!(candidate_name(&whole_space()), "range");
    }

    #[test]
    fn a_failure_carries_no_card_touched_claim() {
        let failure = Failure::new("no-reader", "no PC/SC reader is available");
        let data = failure.data();
        assert_eq!(data["scanned"], json!(false));
        assert_eq!(data["card_touched"], json!(false));
        assert_eq!(data["error"]["kind"], json!("no-reader"));
        assert_eq!(
            data["error"]["message"],
            json!("no PC/SC reader is available")
        );
    }

    #[test]
    fn paths_render_the_way_the_rest_of_the_repository_renders_them() {
        let path: Path = "3F00/7F20/6F07".parse().expect("a valid path");
        assert_eq!(path.to_string(), "3F00/7F20/6F07");
    }

    // --- The verdict: what --severity and --score render. ---
    //
    // Every test below puts a Verdict in front of a real walked tree, because
    // the two halves are only meaningful together: the question is not "does
    // the filter work" but "what does the document a reader receives say", and
    // a document is the walk rendered with a verdict spliced into it.

    /// One finding at `severity`, under a rule ID that names it, so a test can
    /// prove the finding is gone by grepping for the ID rather than by counting.
    fn found(severity: rules::Severity) -> rules::Finding {
        rules::Finding::new(
            rules::RuleId::new(format!("test/severity-{}", severity.id())).expect("documented ID"),
            severity,
            format!("a finding at {severity}"),
            rules::Location::tar(0x1234),
            rules::Evidence::text("evidence"),
        )
    }

    /// A walked sample card, rendered under `verdict`.
    fn rendered(verdict: &Verdict) -> Value {
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        to_json(&tree, &context(probe_set(), limits), verdict)
    }

    /// One finding at each of three rungs, and the ID of the one that must
    /// disappear.
    fn mixed() -> rules::Findings {
        rules::Findings::complete(vec![
            found(rules::Severity::Critical),
            found(rules::Severity::Medium),
            found(rules::Severity::Info),
        ])
    }

    #[test]
    fn a_filtered_finding_leaves_no_trace_anywhere_in_the_document() {
        // The sharpest form of "filter, not mask", and the one that matters:
        // a placeholder carrying the ID, a zeroed entry or a `suppressed: true`
        // flag would all pass a count assertion and all fail this one.
        let verdict = Verdict::new(mixed(), 3).at_least(Some(rules::Severity::High));
        let data = rendered(&verdict);

        assert_eq!(data["findings"]["severity_threshold"], json!("high"));
        assert_eq!(data["findings"]["count"], json!(1));
        let survivors = json!([found(rules::Severity::Critical).to_json()]);
        assert_eq!(data["findings"]["findings"], survivors);

        // Not in the findings array, not in the count, and not anywhere else in
        // the rendered document either - which is why this greps the whole
        // serialisation rather than one field.
        let rendered = serde_json::to_string(&data).expect("the report renders");
        for dropped in [rules::Severity::Medium, rules::Severity::Info] {
            let id = format!("test/severity-{}", dropped.id());
            assert!(
                !rendered.contains(&id),
                "{id} survived the filter somewhere in the document: {rendered}"
            );
        }
        assert!(
            rendered.contains("test/severity-critical"),
            "the surviving rule ID must still be there: {rendered}"
        );
    }

    #[test]
    fn no_threshold_means_no_filter_and_a_null_one_says_so() {
        // `null` and `"info"` are different answers and both have to be
        // reachable: the first is every finding, the second is every finding
        // the ladder can spell, and a document that cannot tell them apart
        // cannot say which one it is.
        let bare = rendered(&Verdict::new(mixed(), 3));
        assert_eq!(bare["findings"]["severity_threshold"], Value::Null);
        assert_eq!(bare["findings"]["count"], json!(3));

        let every = rendered(&Verdict::new(mixed(), 3).at_least(Some(rules::Severity::Info)));
        assert_eq!(every["findings"]["severity_threshold"], json!("info"));
        assert_eq!(every["findings"]["count"], json!(3));
    }

    #[test]
    fn the_filter_does_not_touch_the_walk() {
        // Raising the level must never be able to make a truncated scan look
        // like a whole one, which is the only way this flag could lie.
        let mut card = sample_card();
        let limits = Limits {
            max_depth: 1,
            ..Limits::default()
        };
        let tree = walk_sample(&mut card, limits);
        let context = context(probe_set(), limits);

        let unfiltered = to_json(&tree, &context, &Verdict::new(mixed(), 3));
        let filtered = to_json(
            &tree,
            &context,
            &Verdict::new(mixed(), 3).at_least(Some(rules::Severity::Critical)),
        );

        for field in [
            "complete",
            "truncated",
            "truncated_by",
            "limits_hit",
            "walk",
            "selected",
            "files",
        ] {
            assert_eq!(
                filtered[field], unfiltered[field],
                "--severity changed the walk report field {field:?}"
            );
        }
    }

    #[test]
    fn the_score_block_carries_everything_needed_to_rebuild_the_number() {
        // The acceptance criterion: not that a number appears, but that a
        // reader holding only this document can reconstruct it. So the block
        // is checked by arithmetic, here, from the fields it published.
        let verdict = Verdict::new(mixed(), 3).scored(true);
        let data = rendered(&verdict);
        let score = &data["score"];

        assert_eq!(score["value"], json!(39), "100 - (50 + 10 + 1)");
        assert_eq!(score["max"], json!(rules::SCORE_MAX));
        assert_eq!(score["penalty"], json!(61));
        assert_eq!(score["scored_findings"], json!(3));
        assert_eq!(score["rules_run"], json!(3));
        assert_eq!(score["formula"], json!(rules::SCORE_FORMULA));

        // The table, keyed by the ladder's own spellings.
        let penalties = score["penalties"].as_object().expect("a table");
        assert_eq!(penalties.len(), rules::SCORE_PENALTY.len());
        for severity in rules::Severity::LADDER {
            assert_eq!(
                penalties[severity.id()],
                json!(rules::SCORE_PENALTY[severity.rank() as usize]),
                "the published table disagrees with the constant at {}",
                severity.id()
            );
        }

        // The reader's arithmetic, from the document alone: sum the published
        // penalties of the severities actually present, and subtract from the
        // published maximum. No call into Score happens here, which is the
        // point - this is the reconstruction a reader would do by hand.
        let from_document: u64 = data["findings"]["findings"]
            .as_array()
            .expect("findings is an array")
            .iter()
            .map(|finding| {
                let rank = usize::try_from(finding["severity_rank"].as_u64().expect("a rank"))
                    .expect("a rank fits a usize");
                let rung = rules::Severity::LADDER
                    .get(rank)
                    .expect("a rank inside the published ladder");
                penalties[rung.id()].as_u64().expect("a whole penalty")
            })
            .sum();
        assert_eq!(
            from_document,
            score["penalty"].as_u64().expect("a total"),
            "the published total is not the sum of the published table over the published findings"
        );
        assert_eq!(
            u64::from(rules::SCORE_MAX) - from_document,
            score["value"].as_u64().expect("a whole score"),
            "the score does not follow from the findings and the table printed beside it"
        );
    }

    #[test]
    fn a_score_with_nothing_to_score_says_so_rather_than_reading_as_a_clean_card() {
        // The question a 100 cannot answer on its own. Three fields have to
        // agree before it is answerable at all: rules_run is 0,
        // scored_findings is 0, and the warning is a string rather than null.
        let verdict = Verdict::new(rules::Findings::complete(Vec::new()), 0).scored(true);
        let score = &rendered(&verdict)["score"].clone();

        assert_eq!(score["value"], json!(rules::SCORE_MAX));
        assert_eq!(score["penalty"], json!(0));
        assert_eq!(score["scored_findings"], json!(0));
        assert_eq!(score["rules_run"], json!(0));
        assert_eq!(score["warning"], json!(NO_RULES_WARNING));
        assert!(
            score["warning"]
                .as_str()
                .expect("a warning")
                .contains("NOT because the card is clean"),
            "the warning has to say what the 100 does not mean: {}",
            score["warning"]
        );

        // A 100 from a scan that RAN rules is a different claim - but only
        // if it also had EVIDENCE to look at. `Verdict::new` attaches
        // `tar::Audit::not_run`, so rules having run is not on its own enough
        // to call this a verdict: a rule that ran against a TAR audit that
        // probed nothing looked at nothing. That gets its own sentence.
        let ran_no_evidence = Verdict::new(rules::Findings::complete(Vec::new()), 2).scored(true);
        let ran_no_evidence = rendered(&ran_no_evidence)["score"].clone();
        assert_eq!(ran_no_evidence["rules_run"], json!(2));
        assert_eq!(ran_no_evidence["warning"], json!(NO_TAR_EVIDENCE_WARNING));

        // With an audit that actually probed, it IS a verdict and the
        // warning goes null - which is the whole point of the field.
        let probed = tar::Audit {
            selection: tar::Selection::focused(),
            probes: vec![tar::Probe {
                tar: 0,
                verdict: tar::Verdict::Refused { status: None },
            }],
            baseline: tar::Baseline::of(&[]),
            exhausted: true,
            stopped: None,
            exchanges: 2,
            terminal_profile: None,
        };
        let ran = Verdict::new(rules::Findings::complete(Vec::new()), 2)
            .scored(true)
            .tar_audit(probed);
        let ran = rendered(&ran)["score"].clone();
        assert_eq!(ran["value"], json!(rules::SCORE_MAX));
        assert_eq!(ran["rules_run"], json!(2));
        assert_eq!(ran["warning"], Value::Null);
    }

    #[test]
    fn the_filter_runs_before_the_score_so_the_two_cannot_disagree() {
        // --severity high --score. The score is a function of the array
        // printed beside it, so the number and the document cannot come apart.
        let verdict = Verdict::new(mixed(), 3)
            .at_least(Some(rules::Severity::High))
            .scored(true);
        let data = rendered(&verdict);

        assert_eq!(data["findings"]["count"], json!(1));
        assert_eq!(data["score"]["scored_findings"], json!(1));
        assert_eq!(
            data["score"]["value"],
            json!(50),
            "the two critical and medium findings were discounted, which is the bug"
        );
    }

    #[test]
    fn the_human_report_prints_the_score_its_formula_and_its_warning() {
        // The human mode is a view over the same data, so a score a person
        // cannot check is the same defect in a different font.
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        let context = context(probe_set(), limits);

        let scored = to_human(
            &tree,
            &context,
            &Verdict::new(rules::Findings::complete(Vec::new()), 0).scored(true),
        );
        assert!(scored.contains(rules::SCORE_FORMULA), "{scored}");
        assert!(scored.contains("SCORE 100/100"), "{scored}");
        assert!(scored.contains(NO_RULES_WARNING), "{scored}");

        // The findings block names the threshold and the count it applied to.
        let filtered = to_human(
            &tree,
            &context,
            &Verdict::new(mixed(), 3).at_least(Some(rules::Severity::High)),
        );
        assert!(
            filtered.contains("FINDINGS: 1 at or above high"),
            "{filtered}"
        );
        assert!(
            !filtered.contains("test/severity-info"),
            "a dropped rule reached the human report: {filtered}"
        );

        // And with no --score there is no score at all: it is a deliberate
        // act, not something every report carries.
        let bare = to_human(&tree, &context, &Verdict::new(mixed(), 3));
        assert!(!bare.contains("SCORE "), "{bare}");
    }
    // -----------------------------------------------------------------------
    // The TAR rule: gsma/msl-zero-allowed
    // -----------------------------------------------------------------------

    /// A TAR audit in which the card refused everything except TAR zero.
    ///
    /// The shape is the one only a card with a real TAR check can produce: a
    /// baseline of 9404 and one TAR that answered differently.
    fn msl_zero_audit() -> tar::Audit {
        let refused = tar::Verdict::Refused {
            status: Some(StatusWord::new(0x94, 0x04)),
        };
        let accepted = tar::Verdict::Accepted {
            status: Some(StatusWord::new(0x6D, 0x00)),
            body_len: 0,
        };
        let baseline = tar::Baseline::of(&[
            Some(tar::Signature::of(
                &crate::apdu::Response::parse(&[0x94, 0x04]).expect("a response"),
            )),
            Some(tar::Signature::of(
                &crate::apdu::Response::parse(&[0x94, 0x04]).expect("a response"),
            )),
        ]);
        tar::Audit {
            selection: tar::Selection::default(),
            probes: vec![
                tar::Probe {
                    tar: tar::TAR_MIN,
                    verdict: accepted,
                },
                tar::Probe {
                    tar: 0x00_00_01,
                    verdict: refused,
                },
            ],
            baseline,
            exhausted: true,
            stopped: None,
            exchanges: 4,
            terminal_profile: None,
        }
    }

    /// A TAR audit in which nothing was accepted, which is what a card with
    /// no TAR check at all produces.
    fn quiet_audit() -> tar::Audit {
        let signature =
            tar::Signature::of(&crate::apdu::Response::parse(&[0x90, 0x00]).expect("a response"));
        tar::Audit {
            selection: tar::Selection::default(),
            probes: vec![tar::Probe {
                tar: tar::TAR_MIN,
                verdict: tar::Verdict::Refused {
                    status: Some(StatusWord::new(0x90, 0x00)),
                },
            }],
            baseline: tar::Baseline::of(&[Some(signature)]),
            exhausted: true,
            stopped: None,
            exchanges: 2,
            terminal_profile: None,
        }
    }

    #[test]
    fn the_tar_rule_is_registered_under_exactly_the_documented_id() {
        // **Spelling is the contract.** AGENTS.md section 3 names
        // gsma/msl-zero-allowed as one of the three rule IDs and an agent
        // greps for that string, so a rule registered under anything else is
        // a finding nobody can address.
        assert_eq!(MSL_ZERO_RULE, "gsma/msl-zero-allowed");
        let id = rules::RuleId::new(MSL_ZERO_RULE).expect("a validated ID");
        assert_eq!(id.plugin(), "gsma");
        assert_eq!(id.rule(), "msl-zero-allowed");

        let registry = rules();
        assert_eq!(registry.len(), 5, "five rules are registered over a card");
        let rule = registry.get(&id).expect("the rule is registered");
        assert_eq!(rule.severity(), rules::Severity::Critical);
        assert!(
            rule.spec().remediation().is_some(),
            "a finding an operator cannot act on is half a finding"
        );
    }

    #[test]
    fn the_scp03_rule_fires_from_a_recorded_exchange_and_has_no_evidence_without_one() {
        let mut card = sample_card();
        let tree = walk_sample(&mut card, Limits::default());
        let audit = quiet_audit();
        let recorded = scp03::Audit {
            probes: vec![scp03::Probe {
                kind: scp03::ProbeKind::CommandWithoutMac,
                status: crate::apdu::StatusWord::new(0x90, 0x00),
            }],
        };
        let subject = Subject {
            tree: &tree,
            tar: &audit,
            scp03: Some(&recorded),
        };
        let found = findings(&subject).expect("no misattribution");
        assert_eq!(found.len(), 1);
        assert_eq!(found.as_slice()[0].rule().as_str(), scp03::MISSING_MAC_RULE);

        let id = rules::RuleId::new(scp03::MISSING_MAC_RULE).unwrap();
        let registry = rules();
        let rule = registry.get(&id).expect("registered");
        assert!(rule.had_evidence(&subject));
        let none = Subject {
            scp03: None,
            ..subject
        };
        assert!(!rule.had_evidence(&none));
        assert!(rule.run(&none).is_empty());
    }

    #[test]
    fn a_scan_evaluates_its_rules_so_the_no_rules_warning_cannot_fire() {
        // **The warning going null here is CORRECT rather than defeated.**
        // rules_run is 1 because a rule really ran, so the 100 it sits beside
        // is a score over an audit rather than an absence of one. That is the
        // whole difference NO_RULES_WARNING was written to make visible.
        assert_eq!(rules_run(), 5);

        let mut card = sample_card();
        let tree = walk_sample(&mut card, Limits::default());
        let audit = quiet_audit();
        let found = findings(&Subject {
            tree: &tree,
            tar: &audit,
            scp03: None,
        })
        .expect("no misattribution");
        assert!(
            found.is_empty(),
            "a card that refused every TAR found nothing"
        );

        // The audit has to be attached, not merely used above: without it
        // the verdict reports no evidence and carries the no-evidence warning,
        // which is the correct thing to say about a 100 with nothing behind it.
        let verdict = Verdict::new(found, rules_run())
            .scored(true)
            .tar_audit(audit);
        let block = verdict.fields();
        let score = &block["score"];
        assert_eq!(score["rules_run"], serde_json::json!(5));
        assert_eq!(score["value"], serde_json::json!(rules::SCORE_MAX));
        assert_eq!(
            score["warning"],
            serde_json::Value::Null,
            "a 100 from a rule that looked is a verdict, and the warning is what \
             distinguishes it from a 100 from nothing looking"
        );
    }

    #[test]
    fn tar_zero_accepted_is_reported_as_msl_zero_with_the_evidence_beside_it() {
        let mut card = sample_card();
        let tree = walk_sample(&mut card, Limits::default());
        let audit = msl_zero_audit();
        let found = findings(&Subject {
            tree: &tree,
            tar: &audit,
            scp03: None,
        })
        .expect("no misattribution");

        assert_eq!(found.len(), 1, "one finding, for the one TAR that differed");
        let finding = &found.as_slice()[0];
        assert_eq!(finding.rule().as_str(), MSL_ZERO_RULE);
        assert_eq!(finding.severity(), rules::Severity::Critical);
        assert_eq!(finding.location(), &rules::Location::tar(tar::TAR_MIN));
        assert!(
            finding.message().contains("6D00") && finding.message().contains("9404"),
            "the message carries both status words, so it can be checked rather than \
             believed: {}",
            finding.message()
        );
        assert_eq!(
            finding
                .evidence()
                .as_text()
                .expect("text evidence")
                .as_str(),
            "accepted=6D00 baseline=9404"
        );
        // The TAR audit finished; the WALK did not, and this fixture
        // describes an unbounded tree. So the finding is partial because of the
        // walk, and the reason on it says so rather than blaming the TAR scan.
        // A scan that got both right carries complete here.
        assert!(
            !finding.coverage().is_complete(),
            "this fixture's walk truncates, and coverage says so"
        );
        assert_eq!(
            finding.coverage().reason(),
            Some(TAR_PARTIAL_REASON),
            "the TAR rule own reason wins, and it names both halves of the scan"
        );

        // And the score subtracts for it, which is the first time a real card
        // has moved that number.
        let verdict = Verdict::new(found, rules_run()).scored(true);
        let block = verdict.fields();
        assert_eq!(block["score"]["value"], serde_json::json!(50));
        assert_eq!(block["score"]["penalty"], serde_json::json!(50));
        assert_eq!(block["score"]["scored_findings"], serde_json::json!(1));
    }

    #[test]
    fn a_tar_audit_that_did_not_finish_marks_its_finding_partial() {
        let mut card = sample_card();
        let tree = walk_sample(&mut card, Limits::default());
        let mut audit = msl_zero_audit();
        audit.stopped = Some("the probe budget of 4096 TARs was reached".to_owned());
        let found = findings(&Subject {
            tree: &tree,
            tar: &audit,
            scp03: None,
        })
        .expect("no misattribution");

        // **The finding is still true.** TAR zero was accepted, and that does
        // not stop being true because the scan stopped at 4096 of 16 777 216.
        // What cannot be claimed is that nothing else is accepted, and that is
        // what coverage says.
        assert_eq!(found.len(), 1);
        let finding = &found.as_slice()[0];
        assert_eq!(
            finding.coverage(),
            &rules::Coverage::Partial {
                reason: "the probe budget of 4096 TARs was reached".to_owned()
            }
        );
        assert!(!found.is_exhaustive());
    }

    #[test]
    fn a_tar_accepted_that_is_not_zero_is_reported_but_not_raised() {
        let mut card = sample_card();
        let tree = walk_sample(&mut card, Limits::default());
        let mut audit = msl_zero_audit();
        audit.probes.push(tar::Probe {
            tar: 0x45_44_52,
            verdict: tar::Verdict::Accepted {
                status: Some(StatusWord::new(0x90, 0x00)),
                body_len: 16,
            },
        });
        let found = findings(&Subject {
            tree: &tree,
            tar: &audit,
            scp03: None,
        })
        .expect("no misattribution");

        // One finding, not two. An over-broad TAR allow-list is a real
        // problem, but no rule ID has been agreed for it and raising it under
        // msl-zero-allowed would be a rule ID that lies about itself.
        assert_eq!(found.len(), 1);
        // It is still visible: the tar block lists it.
        let block = audit.to_json();
        assert_eq!(block["accepted_count"], serde_json::json!(2));
        assert_eq!(block["accepted"][1]["tar"], serde_json::json!("454452"));
    }

    // -----------------------------------------------------------------------
    // doctor/1 (docs/doctor-contract.md)
    // -----------------------------------------------------------------------

    /// The doctor/1 envelope of the sample card under `verdict`.
    fn doctor_of(verdict: &Verdict, fail_on: rules::Severity) -> Value {
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        let context = context(probe_set(), limits);
        let facts = run_facts(&tree, &context, verdict);
        doctor_json(&tree, &context, verdict, &facts, verdict.exit_code(fail_on))
    }

    /// Contract section 9: top-level keys, finding keys and enums, a 16-hex
    /// fingerprint, `exit_code` equal to the mapped code, deterministic
    /// output apart from `data`, and the sort order.
    #[test]
    fn the_envelope_conforms_to_doctor_1() {
        let verdict = Verdict::new(mixed(), 3);
        let a = doctor_of(&verdict, rules::Severity::Critical);
        let b = doctor_of(&verdict, rules::Severity::Critical);

        let mut keys: Vec<&str> = a.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "data",
                "exit_code",
                "findings",
                "schema",
                "score",
                "tool",
                "version"
            ]
        );
        assert_eq!(a["schema"], "doctor/1");
        assert_eq!(a["tool"], "sim-doctor");
        assert_eq!(a["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            a["exit_code"], 1,
            "a critical finding at --fail-on critical"
        );

        let findings = a["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 3);
        for f in findings {
            for key in [
                "id",
                "fingerprint",
                "severity",
                "category",
                "message",
                "location",
                "remedy",
            ] {
                assert!(f.get(key).is_some(), "{key} missing: {f}");
            }
            let fp = f["fingerprint"].as_str().unwrap();
            assert!(
                fp.len() == 16
                    && fp
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            assert!(["critical", "high", "medium", "low", "info"]
                .contains(&f["severity"].as_str().unwrap()));
            assert_eq!(f["location"]["kind"], "card-path");
            assert!(f["location"]["ref"].is_string());
            assert!(f.get("baseline_state").is_none(), "no --baseline, no state");
        }
        let order: Vec<&str> = findings
            .iter()
            .map(|f| f["severity"].as_str().unwrap())
            .collect();
        assert_eq!(order, ["critical", "medium", "info"], "critical first");

        let score = &a["score"];
        assert_eq!(score["model"], SCORE_MODEL);
        assert_eq!(score["value"], json!(100 - 50 - 10 - 1));
        assert_eq!(score["label"], "critical", "39 is below 60");
        assert!(score["coverage_gaps"].is_u64());

        // Nothing run-varying outside `data`.
        let strip = |mut v: Value| {
            v.as_object_mut().unwrap().remove("data");
            v
        };
        assert_eq!(strip(a.clone()), strip(b));
        assert!(a["data"]["findings_detail"]["findings"].is_array());
        assert!(a["data"]["score_detail"]["formula"].is_string());
        assert!(a["data"]["run"]["rules"].is_array());
    }

    /// `--fail-on` decides the exit code; `--severity` has already removed
    /// what it removes.
    #[test]
    fn fail_on_gates_the_exit_code() {
        let v = Verdict::new(mixed(), 3);
        assert_eq!(v.exit_code(rules::Severity::Critical), ExitCode::Findings);
        assert_eq!(v.exit_code(rules::Severity::Info), ExitCode::Findings);
        let only_medium = Verdict::new(mixed(), 3).at_least(Some(rules::Severity::Info));
        assert_eq!(
            only_medium.exit_code(rules::Severity::Critical),
            ExitCode::Findings
        );
        let quiet = Verdict::new(
            rules::Findings::complete(vec![found(rules::Severity::Medium)]),
            3,
        );
        assert_eq!(quiet.exit_code(rules::Severity::High), ExitCode::Success);
        assert_eq!(quiet.exit_code(rules::Severity::Medium), ExitCode::Findings);
        assert_eq!(
            Verdict::new(rules::Findings::complete(Vec::new()), 3).exit_code(rules::Severity::Info),
            ExitCode::Success
        );
    }

    /// Under a baseline only new findings gate, with exit 3, each finding
    /// carries its state and the counts are on the envelope.
    #[test]
    fn a_baseline_gates_on_new_findings_only() {
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        let context = context(probe_set(), limits);

        let old = Verdict::new(mixed(), 3);
        let facts = run_facts(&tree, &context, &old);
        let saved = baseline::Baseline::new(facts.clone(), old.findings().as_slice());

        // Same findings: all unchanged, nothing gates even though a critical
        // finding is present.
        let same = old.clone().compared_against(
            baseline::Diff::compare(&saved, &facts, old.findings().as_slice()).unwrap(),
        );
        assert_eq!(same.exit_code(rules::Severity::Critical), ExitCode::Success);
        let doc = doctor_json(&tree, &context, &same, &facts, ExitCode::Success);
        assert_eq!(
            doc["baseline"],
            json!({"new": 0, "unchanged": 3, "fixed": 0})
        );
        assert!(doc["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["baseline_state"] == "unchanged"));

        // One finding gone and one new: 3 at --fail-on high, 0 at critical.
        let newer = Verdict::new(
            rules::Findings::complete(vec![
                found(rules::Severity::Medium),
                found(rules::Severity::High),
            ]),
            3,
        );
        let diff = baseline::Diff::compare(&saved, &facts, newer.findings().as_slice()).unwrap();
        let newer = newer.compared_against(diff);
        assert_eq!(
            newer.exit_code(rules::Severity::High),
            ExitCode::NewFindings
        );
        assert_eq!(
            newer.exit_code(rules::Severity::Critical),
            ExitCode::Success
        );
        let doc = doctor_json(&tree, &context, &newer, &facts, ExitCode::NewFindings);
        assert_eq!(
            doc["baseline"],
            json!({"new": 1, "unchanged": 1, "fixed": 2})
        );
    }

    /// Contract section 8: an ESC sequence (and a bidi override) in card text
    /// does not reach the human report.
    #[test]
    fn card_text_cannot_drive_the_terminal() {
        let mut card = sample_card();
        let limits = Limits::default();
        let tree = walk_sample(&mut card, limits);
        let hostile = rules::Finding::new(
            rules::RuleId::new("test/escape").unwrap(),
            rules::Severity::High,
            "boom \u{1b}[31mRED\u{1b}]0;title\u{7} \u{202e}evil \u{200b}x",
            rules::Location::tar(1),
            rules::Evidence::None,
        );
        let verdict = Verdict::new(rules::Findings::complete(vec![hostile]), 1);
        let text = to_human(&tree, &context(probe_set(), limits), &verdict);
        assert!(text.contains("boom"), "{text}");
        for bad in ['\u{1b}', '\u{7}', '\u{202e}', '\u{200b}'] {
            assert!(
                !text.contains(bad),
                "U+{:04X} reached the report: {text:?}",
                bad as u32
            );
        }
        assert!(
            text.ends_with('\n') && text.contains('\n'),
            "line structure kept"
        );
    }

    /// Coverage gaps: a truncated walk is incomplete, and a 100 with a gap is
    /// not `good`.
    #[test]
    fn a_truncated_walk_is_a_coverage_gap() {
        let mut card = sample_card();
        let limits = Limits {
            max_depth: 1,
            ..Limits::default()
        };
        let tree = walk_sample(&mut card, limits);
        let context = context(probe_set(), limits);
        let verdict = Verdict::new(rules::Findings::complete(Vec::new()), 3);
        let facts = run_facts(&tree, &context, &verdict);
        let score = doctor_score(&tree, &context, &verdict, &facts);
        assert!(score["coverage_gaps"].as_u64().unwrap() >= 1);
        assert_eq!(score["value"], 100);
        assert_eq!(score["label"], "incomplete");
    }
}
