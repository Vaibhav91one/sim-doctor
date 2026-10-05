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

use crate::fcp::{self, TagSet};
use crate::fs;
use crate::rules;
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
    /// swICC's FCP builder, as observed in swSIM at the pinned commit.
    ///
    /// The default, and **not** the ISO table: swICC puts the file size in
    /// `80` where ISO/IEC 7816-4 table 42 puts it in `82`, and reading an
    /// swSIM FCP with the ISO table reported a 10-octet EF.ICCID as 2337 octets.
    #[default]
    Swicc,

    /// ISO/IEC 7816-4 table 42, which is what a real UICC is more likely to
    /// follow.
    Iec7816_4Table42,
}

impl Dialect {
    /// Every dialect `--dialect` accepts.
    pub const ALL: [Self; 2] = [Self::Swicc, Self::Iec7816_4Table42];

    /// The spelling `--dialect` takes and the JSON reports.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Swicc => "swicc",
            Self::Iec7816_4Table42 => "iec-7816-4-table-42",
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
            Self::Swicc => TagSet::swicc(),
            Self::Iec7816_4Table42 => TagSet::iec_7816_4_table_42(),
        }
    }
}

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
            "swicc" => Ok(Self::Swicc),
            "iec-7816-4-table-42" => Ok(Self::Iec7816_4Table42),
            _ => Err(UnknownDialect(text.to_owned())),
        }
    }
}

/// A `--dialect` value that names no mapping this repository has read.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0:?} is not a known FCP dialect; expected swicc or iec-7816-4-table-42")]
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

// ---------------------------------------------------------------------------
// What a scan concluded
// ---------------------------------------------------------------------------

/// The rules this scan runs over one walked card.
///
/// **Empty today, and that is the state of the project rather than a
/// placeholder.** Issue #13 built the vocabulary a rule needs - the ID, the
/// severity, what a finding is, and the registry that binds one to the other -
/// and shipped no rule, because a rule that guessed would manufacture
/// findings this repository cannot justify. So a scan evaluates zero rules and
/// produces zero findings, and says so rather than letting an empty list read
/// as a clean card.
///
/// **Which is why the score carries `rules_run`.** A score of 100 from an
/// empty set is otherwise indistinguishable from a card that passed, which is
/// precisely the failure [`NO_RULES_WARNING`] was written to prevent, and
/// precisely the one [`Deferred::Score`] used to refuse rather than risk.
/// Registering the first rule is the only change this function needs.
fn rules() -> rules::Registry<Tree> {
    rules::Registry::new()
}

/// How many rules a scan evaluates over one walked card.
///
/// Zero today, and reported next to every score for the reason above.
pub fn rules_run() -> usize {
    rules().len()
}

/// The findings one walked card produces, before any filtering.
///
/// Coverage is taken from the walk, not left at the default. A finding raised
/// from a walk that hit `max_depth` may be entirely true, but the list
/// cannot be read as the whole of the card, and [`rules::Findings::partial`]
/// is how that travels on every finding rather than only on the report.
///
/// # Errors
///
/// [`rules::RegistryError::MisattributedFinding`] when a rule emits a finding
/// under another rule's ID. The caller turns that into a failed scan rather
/// than into a report: a finding nobody can address is not a finding, and
/// [`rules::Registry`] already refuses it at every other boundary.
pub fn findings(tree: &Tree) -> Result<rules::Findings, rules::RegistryError> {
    let found = rules().evaluate(tree)?;
    Ok(if tree.is_complete() {
        rules::Findings::complete(found)
    } else {
        rules::Findings::partial(found, TRUNCATION_REASON)
    })
}

/// The coverage reason a walk that hit a bound hands its findings.
const TRUNCATION_REASON: &str = "the walk stopped at a bound, so this list may be short";

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

        if let Some(score) = self.score() {
            fields.insert(
                "score".to_owned(),
                json!({
                    "value": score.value(),
                    "max": score.max(),
                    "penalty": score.penalty(),
                    "scored_findings": score.scored(),
                    "rules_run": self.rules_run,
                    "formula": rules::SCORE_FORMULA,
                    "penalties": penalties_json(),
                    "warning": (self.rules_run == 0).then_some(NO_RULES_WARNING),
                }),
            );
        }
        fields
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
    out.push('\n');
    out.push_str(&verdict.to_human());

    out
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

/// One of the AGENTS.md section 3 flags that exists on the command surface but
/// whose behaviour is not built yet.
///
/// **Why this type exists at all.** AGENTS.md section 3 requires `--score`,
/// `--severity`, `--baseline` and `--diff` to be present on the surface from day
/// one, and issue #6's gap analysis says why: agents script against the
/// contract, and a flag that exists and answers "not yet" is found at design
/// time, while a flag that does not exist is found at runtime, in production, by
/// whoever wrote the script.
///
/// So a scan given one of these refuses, in one envelope, with code 1 and a
/// message naming the flag - **before** a reader is opened, so an agent finds
/// out in milliseconds rather than after a walk. It never produces a plausible
/// number. A `--score` that returned 0 because the scorer was not written yet
/// would be indistinguishable from a card that passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deferred {
    /// `--baseline <file>`, awaiting saved-run comparison.
    Baseline(String),

    /// `--diff`, awaiting the baseline it diffs against.
    Diff,
}

impl Deferred {
    /// The flag as an operator typed it, including its value where it takes one.
    pub fn flag(&self) -> String {
        match self {
            Self::Baseline(path) => format!("--baseline {path}"),
            Self::Diff => "--diff".to_owned(),
        }
    }

    /// One sentence saying why it is not implemented and what will implement it.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Baseline(_) => "saving and comparing a run is issue #9",
            Self::Diff => "diffing against a baseline is issue #9",
        }
    }

    /// The machine-readable version of the same refusal.
    ///
    /// `"implemented": false` is the field an agent should branch on, and
    /// `"tracking_issue"` is the one a person reading a CI log needs.
    pub fn data(&self) -> Value {
        json!({
            "implemented": false,
            "flag": self.flag(),
            "reason": self.reason(),
            "tracking_issue": match self {
                Self::Baseline(_) | Self::Diff => "#9",
            },
            "scanned": false,
            "card_touched": false,
        })
    }
}

/// Renders a deferred flag as the whole envelope's `data`.
///
/// Returned rather than built here so this module never sees
/// [`crate::contract`], which is a leaf that must not acquire a dependency on
/// anything that depends on a card.
pub fn deferred_json(deferred: &Deferred) -> Value {
    deferred.data()
}

/// The human-facing sentence for a deferred flag.
pub fn deferred_message(deferred: &Deferred) -> String {
    format!(
        "{} is not implemented yet: {}. The scan was not run and no card was contacted.",
        deferred.flag(),
        deferred.reason()
    )
}

/// A reader name an operator asked for that is not attached.
///
/// Built as a value so both the human and the JSON form come from one place,
/// and so a test can assert the list of what *is* attached is in both.
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
    fn the_two_dialects_really_are_different_tables() {
        // If this ever stopped holding, reporting the name would be reporting
        // nothing at all.
        let swicc = Dialect::Swicc.tag_set();
        let iso = Dialect::Iec7816_4Table42.tag_set();
        assert_ne!(swicc.file_size(), iso.file_size());
        assert_ne!(swicc.file_descriptor(), iso.file_descriptor());
        assert_ne!(swicc.file_id(), iso.file_id());
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
            "iec-7816-4-table-42".parse::<Dialect>().unwrap(),
            Dialect::Iec7816_4Table42
        );
        assert!("iec7816".parse::<Dialect>().is_err());
        assert!("".parse::<Dialect>().is_err());
    }

    #[test]
    fn every_deferred_flag_names_itself_and_admits_nothing_was_scanned() {
        // --score and --severity are NOT here: they are implemented as of issue
        // #14 and reach the envelope, so a refusal for them would be the bug.
        let flags = [
            Deferred::Baseline("baseline.json".to_owned()),
            Deferred::Diff,
        ];
        for deferred in flags {
            let message = deferred_message(&deferred);
            assert!(message.contains(&deferred.flag()), "{message}");
            assert!(message.contains("not implemented yet"), "{message}");
            assert!(message.contains("no card was contacted"), "{message}");

            let data = deferred_json(&deferred);
            assert_eq!(data["implemented"], json!(false));
            assert_eq!(data["scanned"], json!(false));
            assert_eq!(data["card_touched"], json!(false));
            assert!(data["tracking_issue"].is_string(), "{data}");
        }
    }

    #[test]
    fn a_deferred_refusal_never_looks_like_a_score() {
        // The failure mode this type exists to prevent: a number that could be
        // read as a verdict. There is no number anywhere in the refusal, and
        // that is still true of the two flags left in it.
        for deferred in [
            Deferred::Baseline("baseline.json".to_owned()),
            Deferred::Diff,
        ] {
            let data = deferred_json(&deferred);
            assert!(data.get("score").is_none(), "{data}");
            assert_eq!(data["implemented"], json!(false));
        }
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

        // A 100 from a scan that RAN rules is a different claim, and it does
        // not carry the warning - otherwise the warning stops meaning
        // anything.
        let ran = Verdict::new(rules::Findings::complete(Vec::new()), 2).scored(true);
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
        assert!(scored.contains(&rules::SCORE_FORMULA), "{scored}");
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
}
