//! Saving a run and comparing a later one against it: the baseline format,
//! the comparability rules, and the diff.
//!
//! **Owns.** Everything that is true of a *pair* of runs rather than of one.
//! [`crate::scan`] turns a card into a report and knows nothing about what a
//! report looked like last week; this module is the half that needs both.
//!
//! **Does not own.** A scan ([`crate::scan`]), a finding ([`crate::rules`]), or
//! the envelope ([`crate::contract`]). It reads and writes a file, compares two
//! sets of findings, and renders the comparison as a [`serde_json::Value`] the
//! caller splices into the report it already has.
//!
//! # A rule ID is the address, and a rename has to look like a rename
//!
//! A finding is matched across runs by its rule ID together with the thing it
//! is about. A rule ID a baseline holds and this run does
//! not know is **not** reported as fixed, and one this run knows and the
//! baseline does not is **not** reported as new. Both go under `diff.rules`
//! with their findings attached and a sentence saying why. See [`Diff`].
//!
//! AGENTS.md section 3 says an ID "must never be renamed casually" precisely
//! because a baseline outlives the release that wrote it. This is where that
//! rule gets enforced: rename the rule and the diff says so, rather than
//! reporting a fix that never happened alongside a new finding that was always
//! there.
//!
//! # A diff is only as good as its baseline
//!
//! **The central hazard, and the whole reason this module refuses rather than
//! reports.** If the baseline was written by a truncated scan, or by one that
//! ran fewer rules, then almost everything reads as new, nothing reads as
//! fixed, and neither word means anything. A gate wired to that output does not
//! fail; it fails *randomly*, which is worse.
//!
//! So [`RunFacts`] records what the run that wrote a baseline actually did,
//! and [`Diff::compare`] refuses to compare against a baseline it cannot
//! honestly compare with. Six axes, each one a way two runs can ask different
//! questions of the same card:
//!
//! | Axis | Why |
//! |---|---|
//! | walk completeness | a truncated walk did not see the whole card, so a finding absent from it may simply be below where it stopped |
//! | the rule list | a rule this run runs and the baseline did not can raise anything; its findings are a first check, not a regression |
//! | per-rule **evidence** | a rule that ran with **nothing to look at** cannot have found nothing; `--tar off` is the default, and a baseline made by such a run knows nothing about MSL 0 |
//! | the severity threshold | the two runs filtered different sets out, so a finding the baseline never held is not new |
//! | the FCP dialect | the FCP tag table decides what a file size means; two runs that disagree read the same bytes differently |
//! | the TAR selection | the TAR rule answers about the TARs it probed, and two runs probed different ones |
//!
//! **Refusal is a refusal, not a diff.** Every one of these ends in the same
//! shape as "no reader attached" - `data.error`, exit 1, no `data.findings`
//! and no `data.diff` - so the rule AGENTS.md section 3 leans on survives
//! intact: `code == 1` carrying an `error` is a check that could not run, and
//! `code == 1` carrying a `diff` is a check that ran and the card regressed.
//!
//! # Evidence is bounded on the way IN as well as out
//!
//! **A baseline file is untrusted input.** [`rules::Evidence`] is bounded by
//! its types because a rule must not be able to fill a terminal - but a
//! hand-edited baseline does not go through those constructors, and a finding
//! `message` is an unbounded [`String`] everywhere. [`Baseline::parse`] walks
//! the whole document and refuses any single string over [`MAX_TEXT_CHARS`],
//! any array over [`MAX_RECORDS`], and any file over [`MAX_BASELINE_BYTES`] -
//! before the typed parse, so the refusal happens on the raw value and names
//! where it found it. [`Baseline::save`] applies the same limit going out and
//! **refuses** rather than truncating: a baseline that cannot be reloaded is
//! not a baseline, and silently writing a shortened message would make the
//! diff compare text the file does not contain.
//!
//! [`rules::RuleId`] re-validates itself on the way in, which is issue #13's
//! deliberate choice and the reason reading one back is safe at all; this
//! module relies on it rather than re-implementing it.
//!
//! # What a baseline does and does not contain
//!
//! **Findings, and the facts needed to decide whether they can be compared.
//! Nothing else.** Not the ATR, not the file tree, not the notes, not the APDU
//! log. A baseline is a local artifact that lands in a CI workspace and is read
//! back by an agent, and the narrower it is the less of the card it carries
//! around. A test asserts the key set, so a field cannot be added by accident.
//!
//! Unknown JSON fields are **ignored**, not refused: a baseline written by a
//! later version has to stay readable by this one. The strictness goes on the
//! forward path - the values are bounded and re-validated - not the backward
//! one. CONTEXT.md section 3 records that rule from issue #13 and this module
//! does not reopen it.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "baseline";

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::rules;

/// The version written into every baseline this build produces.
///
/// Bumped when the *meaning* of a field changes, never when one is added.
/// [`Baseline::parse`] refuses a file whose number is not this one rather than
/// guessing, because a diff computed against a shape it is guessing at is
/// exactly the kind of plausible-looking number AGENTS.md section 3 forbids:
/// it would report new and fixed findings and mean something else entirely.
pub const VERSION: u32 = 1;

/// The most octets this tool will read out of one baseline file.
///
/// A megabyte is far more than any real scan produces - a finding is bounded
/// at 64 octets of evidence and the record count is capped below too - and it
/// is here so that a hostile or accidental file cannot make the process read
/// its way to the end of the disk. Read through a [`Read::take`], never with
/// `fs::read`, so the ceiling is enforced while reading rather than after.
pub const MAX_BASELINE_BYTES: usize = 1024 * 1024;

/// The most findings one baseline may carry, and the most items in any one
/// array inside it.
///
/// **Output-boundedness, which is the reason the number exists.** The rules in
/// this crate bound what a rule can *produce*; nothing bounds what a hand-edited
/// file can *assert*. Without this, a 64 KB message repeated a hundred thousand
/// times would be a hundred thousand findings rendered into a CI log by a
////! command whose whole promise is that it is safe to script. A card this tool
/// can walk does not produce 4096 findings, and if one ever does the refusal
/// will say so in words rather than truncate.
pub const MAX_RECORDS: usize = 4096;

/// The most characters in any one string inside a baseline file.
///
/// Covers the finding `message`, the coverage `reason`, every path a location
/// carries and every short string in [`RunFacts`] - one limit for all of them,
/// checked by walking the parsed document rather than by listing the fields,
/// so a field added later cannot arrive unbounded.
///
/// 1024 characters is several times longer than the sentence a rule is expected
/// to produce, and short enough that 4096 of them cannot fill a terminal.
pub const MAX_TEXT_CHARS: usize = 1024;

/// How a finding is matched to a finding in the baseline.
///
/// **The rule ID alone is not enough, and neither is the message.** A rule can
/// legitimately fire many times in one scan - once per TAR, once per file - and
////! [`crate::rules::Finding::to_json`] says in as many words that it is an array
////! and not a map keyed by ID for exactly that reason. Keying on the ID alone
////! would call a tenth unreadable EF a duplicate of the first.
///
/// [`rules::Location`]`s [`fmt::Display`] is the discriminator, and it is used
////! rather than a re-render of the JSON because it is the spelling the human
////! report already prints (`tar:00000000`, `file:3F00/6F07 selected 9804`) and so
////! is one string a person can read in the refusal when two runs disagree.
fn matching_key(finding: &rules::Finding) -> String {
    format!("{} at {}", finding.rule(), finding.location())
}

// ---------------------------------------------------------------------------
// What the run that wrote a baseline actually did
// ---------------------------------------------------------------------------

/// Everything about a run that decides whether its findings can be compared
/// to another run's.
///
/// **Not a score, not a card description, and deliberately small.** Each field
/// exists because leaving it out makes a diff lie in a specific way, and the
/// six axes are listed in the module documentation. A field that answers no
/// comparison question does not belong here: a test asserts the key set, so
/// one cannot be added by accident.
///
/// The same type describes both sides. A baseline stores one; the current run
/// builds one before it is compared. Neither is privileged, which is what stops
/// the comparison from being "the old file versus whatever happened today".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunFacts {
    reader: String,
    dialect: String,
    candidates: String,
    severity: Option<rules::Severity>,
    tar_selection: String,
    complete: bool,
    truncated_by: Option<String>,
    limits_hit: Vec<String>,
    rules: Vec<rules::RuleRun>,
}

impl RunFacts {
    /// Builds the facts for one scan, from what that scan did.
    ///
    /// Every argument is a fact the report already publishes, so a reader of a
    /// baseline can check each one against the scan it came from: the reader
    /// name, the dialect, the candidate set and the TAR selection are printed
    /// by `scan`, and `complete` / `truncated_by` / `limits_hit` are the walk's
    /// own words. Nothing here is a judgement this module makes about the card.
    ///
    /// Nine arguments rather than a struct literal, because the struct's fields
    /// are private and the nine are the nine comparability axes. A caller that
    /// could spell one without the others is a caller that will.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reader: impl Into<String>,
        dialect: impl Into<String>,
        candidates: impl Into<String>,
        severity: Option<rules::Severity>,
        tar_selection: impl Into<String>,
        complete: bool,
        truncated_by: Option<String>,
        limits_hit: Vec<String>,
        rules: Vec<rules::RuleRun>,
    ) -> Self {
        Self {
            reader: reader.into(),
            dialect: dialect.into(),
            candidates: candidates.into(),
            severity,
            tar_selection: tar_selection.into(),
            complete,
            truncated_by,
            limits_hit,
            rules,
        }
    }

    /// Which PC/SC reader was used. Recorded, and **not** a refusal axis.
    ///
    /// Moving a card to a different reader is an ordinary thing for an operator
    /// to do and says nothing about what the card holds. It is in the file
    /// because a diff that suddenly changed is helped by knowing the reader
    /// changed too, and it is not compared because that would make a gate fail
    /// on a machine upgrade.
    pub fn reader(&self) -> &str {
        &self.reader
    }

    /// The FCP tag table the walk ran under.
    pub fn dialect(&self) -> &str {
        &self.dialect
    }

    /// Which identifier set the walk probed.
    pub fn candidates(&self) -> &str {
        &self.candidates
    }

    /// The `--severity` level in force, or `None` when nothing was filtered.
    pub const fn severity(&self) -> Option<rules::Severity> {
        self.severity
    }

    /// The whole `--tar` selection including its class byte.
    pub fn tar_selection(&self) -> &str {
        &self.tar_selection
    }

    /// Whether the walk finished on its own terms.
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Which bound fired first, when one did.
    pub fn truncated_by(&self) -> Option<&str> {
        self.truncated_by.as_deref()
    }

    /// Every bound that fired.
    pub fn limits_hit(&self) -> &[String] {
        &self.limits_hit
    }

    /// Which bounds fired, in words, for a refusal to quote.
    ///
    /// **All of them rather than the first**, for the reason the scan report
    /// lists the full set: reporting only `truncated_by` understates how much
    /// of the card was missed, and a refusal that understates it sends an
    /// operator to raise one bound and straight into another. An empty list is
    /// not a lie either - a walk can be cut short by something that is not a
    /// bound - so it says so rather than implying nothing fired.
    pub fn bounds_summary(&self) -> String {
        if !self.limits_hit.is_empty() {
            return self.limits_hit.join(", ");
        }
        match self.truncated_by.as_deref() {
            Some(by) => by.to_owned(),
            None => "no bound was recorded".to_owned(),
        }
    }

    /// Every rule that ran, and whether it had anything to look at.
    pub fn rule_runs(&self) -> &[rules::RuleRun] {
        &self.rules
    }

    /// How many rules ran.
    pub fn rules_run(&self) -> usize {
        self.rules.len()
    }

    /// The evidence flag recorded for one rule, if it ran.
    pub fn evidence_of(&self, id: &rules::RuleId) -> Option<bool> {
        self.rules
            .iter()
            .find(|run| run.id() == id)
            .map(rules::RuleRun::had_evidence)
    }

    /// A one-line summary for a human reading a refusal.
    pub fn describe(&self) -> String {
        let mut out = format!(
            "the walk was {} on reader {:?} under the {} tag table, ",
            if self.complete {
                "complete"
            } else {
                "TRUNCATED"
            },
            self.reader,
            self.dialect,
        );
        out.push_str(&format!(
            "probing the {} candidate set, --tar {}, --severity {}, {} rule(s) run",
            self.candidates,
            self.tar_selection,
            self.severity
                .map_or_else(|| "none".to_owned(), |level| level.id().to_owned()),
            self.rules.len(),
        ));
        out
    }

    /// As the object a baseline file carries.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "reader": self.reader,
            "dialect": self.dialect,
            "candidates": self.candidates,
            "severity_threshold": self.severity.map(rules::Severity::id),
            "tar_selection": self.tar_selection,
            "complete": self.complete,
            "truncated_by": self.truncated_by,
            "limits_hit": self.limits_hit,
            "rules_run": self.rules_run(),
            "rules": self
                .rules
                .iter()
                .map(rules::RuleRun::to_json)
                .collect::<Vec<_>>(),
        })
    }
}

// ---------------------------------------------------------------------------
// The file
// ---------------------------------------------------------------------------

/// A saved run: when it happened, what it did, and what it found.
///
/// **The finding objects are the same ones the report carries**, not a
/// projection of them, which is what makes the round trip lossless and keeps
////! one definition of what a finding is. The bounds on the way back in are in
////! [`Baseline::parse`], not here, because a value that arrived from a file was
////! never constructed through [`rules::Finding::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    sim_doctor_baseline: u32,
    created: String,
    run: RunFacts,
    findings: Vec<rules::Finding>,
}

impl Baseline {
    /// Builds a baseline from a finished scan.
    ///
    /// **The findings are the reported set**, after `--severity`. A baseline
    /// of what a run *said* is the only one a diff can compare against a later
    /// run's reported set; holding the unfiltered findings as well would let a
    /// comparison use a set the report never showed and count a finding an
    /// operator was never shown. The filter in force is recorded in
    /// the severity threshold and refusing a mismatch is what keeps the two
    /// comparable.
    ///
    /// **Stamped with the current time**, which is the only part of a baseline
    /// that is not a property of the card. Nothing reads a clock during a scan,
    ////! so the file is the one place time enters, and it enters here where a
    ////! reader looking for it will find it.
    #[must_use]
    pub fn new(run: RunFacts, findings: &[rules::Finding]) -> Self {
        Self {
            sim_doctor_baseline: VERSION,
            created: timestamp(),
            run,
            findings: findings.to_vec(),
        }
    }

    /// When the saved run happened, as an RFC 3339 instant.
    pub fn created(&self) -> &str {
        &self.created
    }

    /// What that run did.
    pub const fn run(&self) -> &RunFacts {
        &self.run
    }

    /// What that run found, after any severity filter.
    pub fn findings(&self) -> &[rules::Finding] {
        &self.findings
    }

    /// The document, as JSON.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            // Doubles as the version marker and as the answer to "is this
            // file a sim-doctor baseline at all": a random JSON document
            // handed to --diff is refused on this key rather than failing
            // somewhere less legible.
            "sim_doctor_baseline": self.sim_doctor_baseline,
            "created": self.created,
            "run": self.run.to_json(),
            "findings": self.findings,
        })
    }

    /// Reads a baseline out of a document, refusing anything it cannot read
    /// honestly.
    ///
    /// **Untrusted input, and this is where the limits are applied.** A
    /// baseline file has been through a text editor and possibly through nothing
    /// at all, so every value is checked before it becomes a typed object:
    ///
    /// 1. a walk over the whole [`Value`] refuses any string over
    ///    [`MAX_TEXT_CHARS`] or any array over [`MAX_RECORDS`]. It runs on the
    ///    raw value rather than the typed one so that it covers every string in
    ///    the document - including the ones a future field adds - without this
    ///    function having to know what they are called,
    /// 2. the typed parse, which re-validates every [`rules::RuleId`] through
    ///    `RuleId::new` (issue #13, deliberate), every status word as four hex
    ///    digits and every evidence string against its own bound,
    /// 3. the version, which must be this build's,
    /// 4. the finding count, separately, because it is the one array whose
    ///    length is a contract question rather than a sanity check.
    ///
    /// Unknown fields are **ignored**. A baseline written by a later version
    /// has to stay readable by this one; the strictness above is on the values,
    /// not on the key set.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] when the bytes are not JSON or not shaped like a
    /// baseline, [`Error::Version`] when the format version is another one, and
    /// the two bound errors when a value is over its limit.
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_BASELINE_BYTES {
            return Err(Error::TooLarge {
                size: text.len(),
                limit: MAX_BASELINE_BYTES,
            });
        }

        let value: Value =
            serde_json::from_str(text).map_err(|error| Error::Malformed(error.to_string()))?;
        bounded(&value)?;

        let baseline: Self =
            serde_json::from_value(value).map_err(|error| Error::Malformed(error.to_string()))?;

        if baseline.sim_doctor_baseline != VERSION {
            return Err(Error::Version {
                found: baseline.sim_doctor_baseline,
                expected: VERSION,
            });
        }
        if baseline.findings.len() > MAX_RECORDS {
            return Err(Error::TooManyRecords {
                found: baseline.findings.len(),
                limit: MAX_RECORDS,
            });
        }
        Ok(baseline)
    }

    /// Reads a baseline from a path, refusing a file over [`MAX_BASELINE_BYTES`].
    ///
    /// **Through a `take`, not `fs::read`.** The ceiling has to be enforced
    /// while reading, because the whole point of having one is that a hostile
    /// file cannot make this process allocate its way to the end of the disk;
    /// checking the length afterwards means the allocation already happened.
    /// One extra byte is read past the limit so that a file of exactly
    /// [`MAX_BASELINE_BYTES`] is accepted rather than refused for being one
    /// byte short of the next.
    ///
    /// # Errors
    ///
    /// [`Error::Unreadable`] when the file cannot be opened or read, and
    /// everything [`Baseline::parse`] returns.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let file = fs::File::open(path)
            .map_err(|error| Error::Unreadable(format!("{}: {error}", path.display())))?;
        let mut text = String::new();
        let read = file
            .take(u64::try_from(MAX_BASELINE_BYTES).expect("a megabyte fits in u64") + 1)
            .read_to_string(&mut text)
            .map_err(|error| Error::Unreadable(format!("{}: {error}", path.display())))?;
        if read > MAX_BASELINE_BYTES {
            return Err(Error::TooLarge {
                size: read,
                limit: MAX_BASELINE_BYTES,
            });
        }
        Self::parse(&text)
    }

    /// Writes this baseline to a path, atomically.
    ///
    /// **Through a temporary file and a rename**, because the failure this
    /// avoids is a baseline half-written by a machine that lost power between
    /// the write and the rename. That file would parse, or would not, and
    ////! whichever it did it would be a baseline no run chose. The rename is
    ////! atomic on the platforms this crate runs on - it talks to PC/SC - so a
    ////! reader either sees the old baseline or the new one.
    ///
    /// **Refuses rather than truncating a long message.** Every string this
    /// writes is bounded by [`MAX_TEXT_CHARS`] so that what goes in is what
    /// [`Baseline::parse`] will accept; a finding over the limit is a refusal
    /// naming the rule, because a baseline holding a shortened message would
    /// compare against text the file does not contain.
    ///
    /// # Errors
    ///
    /// [`Error::MessageTooLong`] when a finding cannot be recorded within the
    /// limits, [`Error::Unwritable`] when the file cannot be created or
    /// renamed, and [`Error::Render`] when the document cannot be serialised,
    /// which in practice cannot happen.
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        for finding in &self.findings {
            let length = finding.message().chars().count();
            if length > MAX_TEXT_CHARS {
                return Err(Error::MessageTooLong {
                    rule: finding.rule().to_string(),
                    length,
                    limit: MAX_TEXT_CHARS,
                });
            }
        }

        let text = serde_json::to_string_pretty(&self.to_json())
            .map_err(|error| Error::Render(error.to_string()))?;

        // The temporary name carries this process id so that two runs writing
        // the same baseline path concurrently cannot share a scratch file and
        // rename each other's half-written document over each other.
        let temporary = temporary_path(path);
        let write = || -> std::io::Result<()> {
            fs::write(&temporary, text.as_bytes())?;
            fs::rename(&temporary, path)
        };
        if let Err(error) = write() {
            // Best effort: the scratch file is not the operator's document and
            // leaving one behind on every failure would be its own litter.
            let _ = fs::remove_file(&temporary);
            return Err(Error::Unwritable(format!("{}: {error}", path.display())));
        }
        Ok(())
    }
}

/// The scratch path a save writes through, beside the real one.
///
/// Beside rather than in the system temporary directory because a rename
/// across filesystems is not atomic, and the atomicity is the whole point of
/// the two-step write.
fn temporary_path(path: &Path) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(|| "baseline".as_ref(), std::ffi::OsStr::new)
        .to_os_string();
    name.push(format!(".tmp-{}", std::process::id()));
    path.with_file_name(name)
}

/// Refuses a document holding a value over this module's limits.
///
/// **A walk over the raw [`Value`], not over typed fields, and that is the
/// point.** A finding's `message` is an unbounded [`String`] in the wire type,
/// a location carries three of them, and a field added to a finding next year
/// would arrive unbounded without anyone editing this function. Walking the
/// parsed document means one rule covers every string in the file, present and
/// future, and that the path in the error is the one an operator can find in
/// their editor.
///
/// Numbers are left to the typed parse: a JSON number too large for `u32` is
/// refused there, with serde's own message, which is better than a second
/// spelling of the same check here.
fn bounded(value: &Value) -> Result<(), Error> {
    match value {
        Value::String(text) => {
            let length = text.chars().count();
            if length > MAX_TEXT_CHARS {
                return Err(Error::TextTooLong { length });
            }
        }
        Value::Array(items) => {
            if items.len() > MAX_RECORDS {
                return Err(Error::TooManyRecords {
                    found: items.len(),
                    limit: MAX_RECORDS,
                });
            }
            for item in items {
                bounded(item)?;
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                bounded(item)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

/// The instant a baseline was written, as RFC 3339 in UTC.
///
/// **The only clock a scan reads.** The score in the same report is an integer
/// chosen so that nothing reads a clock, a hash order or an environment
/// variable, and that property is worth more than the timestamp; keeping the
/// clock to this one line preserves it. A fixed fallback rather than a panic,
/// because a baseline with no timestamp is still a usable baseline and losing
/// one is not a reason to fail a run.
fn timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ---------------------------------------------------------------------------
// Why a baseline cannot be compared against
// ---------------------------------------------------------------------------

/// A baseline this run refuses to be compared against, and why.
///
/// **One shape, seven causes, and all of them are refusals.** Every variant ends
/// a run the same way - `data.error`, exit 1, no `data.findings` and no
/// `data.diff` - because a comparison this tool cannot make honestly is a
/// check that could not run, and AGENTS.md section 3 already has a shape for
/// that. What each variant adds is a sentence naming the specific mismatch,
/// because "incomparable baseline" sends an operator looking through a file
/// when the answer is on the command line.
///
/// The order [`Diff::compare`] checks them is the order an operator can act on:
/// was either run whole, then did both ask the same question, then did they ask
/// it with the same evidence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Incomparable {
    /// The baseline was written by a walk that did not finish.
    ///
    /// **The first check, and the one most likely to fire on a real machine.**
    /// `--max-depth 1` is the documented way to see what a truncated report
    /// looks like, so a truncated scan is something an operator will save. Its
    /// findings may all be true; what it cannot say is that the card holds no
    /// others, so nearly everything this run finds reads as new and nothing
    /// reads as fixed.
    #[error("this baseline was written by a scan whose walk did not finish ({by}); a walk that stopped at a bound did not see the whole card, so almost every finding this run raises would read as new and none as fixed. Save a baseline from a complete scan")]
    BaselineTruncated {
        /// Which bounds fired, in words.
        by: String,
    },

    /// This run's walk did not finish.
    ///
    /// **The mirror of the above, and the one that matters most.** Everything
    /// the baseline found and this run does not have would read as fixed, and
    /// the reason it is missing is that the walk never got there. A diff that
    /// reported improvements against a walk that stopped early is worse than no
    /// diff at all: it tells an operator a card got better.
    #[error("this scan's walk did not finish ({by}), so a finding the baseline recorded and this run does not have would read as fixed when it is only unvisited. Raise the bound, or diff a scan whose complete field is true")]
    ThisRunTruncated {
        /// Which bounds fired, in words.
        by: String,
    },

    /// The two runs filtered at different severities.
    ///
    /// **Both directions are lies, which is why it is a refusal and not a
    /// warning.** A baseline saved at `--severity high` has never heard of the
    /// low findings, so every one this run reports is new; and this run at
    /// `--severity high` has filtered out every low finding the baseline
    /// holds, so every one of them reads as fixed. Neither list is wrong and
    /// the numbers are both wrong, which is the specific thing a diff must not
    /// do.
    #[error("the baseline was saved at --severity {baseline} and this run is at --severity {this_run}; the two runs reported different sets, so a finding one of them never held is not new and one the other filtered out is not fixed. Save the baseline at the same level")]
    Severity {
        /// The level in force when the baseline was written.
        baseline: String,
        /// The level in force now.
        this_run: String,
    },

    /// The two walks read the same FCP bytes through different tag tables.
    ///
    /// **A different question, not a different answer.** A walk under a
    /// table that puts the file size in the wrong tag reports a 10-octet
    /// EF.ICCID as some other number. Every finding either run makes about that file is about a different
    /// number, so a diff across the two compares answers to two questions.
    #[error("the baseline was taken under the {baseline} FCP tag table and this run under {this_run}; the two read the same bytes differently, so the findings are not about the same things. Re-scan with the same --dialect")]
    Dialect {
        /// The tag table the baseline ran under.
        baseline: String,
        /// The tag table this run uses.
        this_run: String,
    },

    /// The two walks probed different identifier sets.
    ///
    /// **This one fires for a reason a caller cannot see from the flag alone.**
    /// `--max-children` changes how many identifiers are probed out of the
    /// chosen set, so two runs can pass different numbers and both still be in
    /// `sim-families`; the one that probed fewer will find less, and what it
    /// does not find reads as fixed. The report publishes how many were
    /// probed and whether the set was exhaustive, and those two together are
    /// what a comparison needs.
    #[error("the baseline probed {baseline} and this run probed {this_run}; a file one of them never probed cannot be called new, and one the other never probed cannot be called fixed. Use the same identifier set and the same --max-children")]
    Candidates {
        /// The candidate set and budget the baseline used.
        baseline: String,
        /// The candidate set and budget this run uses.
        this_run: String,
    },

    /// The two runs probed different TARs.
    ///
    /// **The MSL 0 rule answers about the TARs it probed.** A selection is
    /// compared whole - band and class byte both - because
    /// `range:000000-000FFF` and `range:3F0000-3F003F` contain different TARs
    /// and a card can accept one and not the other, and because the same TAR at
    /// a different class byte is a different exchange to the card.
    #[error("the baseline probed --tar {baseline} and this run probed --tar {this_run}; the MSL 0 rule answers about the TARs it probed, so these are two answers to two questions. Use the same --tar")]
    TarSelection {
        /// The selection the baseline probed.
        baseline: String,
        /// The selection this run probes.
        this_run: String,
    },

    /// A rule had evidence on one run and none on the other.
    ///
    /// **The default case, and the reason this module exists.** `--tar off` is
    /// the default because an ENVELOPE probe leaves swicc-pcsc unable to start
    /// a transaction. So the common baseline is one where
    /// `gsma/msl-zero-allowed` ran with nothing to look at, and the first scan
    /// run with `--tar focused` finds a critical finding on a card that has
    /// been at MSL 0 the whole time. A baseline that recorded only the rule ID
    /// would report that as a regression and fail a build over a check that had
    /// never been made.
    ///
    /// Both directions are refusals: without evidence this run cannot claim a
    /// fix the baseline held, and with evidence where the baseline had none
    /// this run cannot claim a regression.
    #[error("rule {rule} had {baseline_evidence} on this baseline and {this_evidence} on this run; a rule with nothing to look at cannot have found nothing, so a finding from it is a first check rather than a change. Re-take the baseline with the same evidence")]
    Evidence {
        /// The rule whose evidence differed.
        rule: rules::RuleId,
        /// Whether the baseline's run had evidence for it.
        baseline_evidence: bool,
        /// Whether this run has evidence for it.
        this_evidence: bool,
    },
}

impl Incomparable {
    /// The machine-readable tag, beside `data.error.kind` in the refusal.
    ///
    /// One word per cause so an agent can branch on the reason without parsing
    /// a sentence, and a different word per cause so that "your baseline is
    /// truncated" and "your baseline asked a different question" are not the
    /// same failure to a script.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::BaselineTruncated { .. } => "baseline-truncated",
            Self::ThisRunTruncated { .. } => "run-truncated",
            Self::Severity { .. } => "severity-mismatch",
            Self::Dialect { .. } => "dialect-mismatch",
            Self::Candidates { .. } => "candidate-mismatch",
            Self::TarSelection { .. } => "tar-selection-mismatch",
            Self::Evidence { .. } => "evidence-mismatch",
        }
    }

    /// Both sides in one sentence, so a refusal says what each run actually was.
    pub fn explain(&self, baseline: &Baseline, this_run: &RunFacts) -> String {
        format!(
            "{self}. The baseline ran as: {}. This run ran as: {}.",
            baseline.run.describe(),
            this_run.describe(),
        )
    }
}

// ---------------------------------------------------------------------------
// The comparison
// ---------------------------------------------------------------------------

/// One rule this run and the baseline disagree about, and the findings it
/// cost.
///
/// **This is what a rename looks like, and it is deliberately not two other
/// things.** A rule ID that disappears reads as a fix and one that appears
/// reads as a regression; together they are a claim the file cannot support and
/// that AGENTS.md section 3 exists to prevent, because an ID must never be
/// renamed casually. So an ID in exactly one of the two runs is reported here,
/// with the findings it carried attached, and counted as neither new nor
/// fixed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleDrift {
    id: rules::RuleId,
    direction: Direction,
    findings: Vec<rules::Finding>,
}

/// Which run knew about the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// The baseline ran it; this run does not know it.
    ///
    /// A rename, or a rule that was withdrawn. Nothing else can tell those
    /// apart, and the sentence in `diff.rules.warning` says so rather than
    /// picking one.
    Retired,

    /// This run runs it; the baseline never did.
    ///
    /// A rename, or a rule added since the baseline was taken. Its findings are
    /// a first check, not a regression: the card may have had this problem
    /// since the day it was provisioned and the baseline simply could not see
    /// it.
    Added,
}

impl RuleDrift {
    /// The rule in question.
    pub const fn id(&self) -> &rules::RuleId {
        &self.id
    }

    /// Which run knew it.
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// The findings it carried, so nothing is silently dropped.
    pub fn findings(&self) -> &[rules::Finding] {
        &self.findings
    }

    fn to_json(&self) -> Value {
        json!({
            "id": self.id.as_str(),
            "direction": self.direction,
            "findings": self.findings,
        })
    }
}

/// Two runs, compared: what appeared, what went away, what stayed, and what
/// the two runs could not be asked the same question about.
///
/// **The three lists are disjoint, and that is the contract.** Every finding
/// in exactly one run is in exactly one of `new` or `fixed`; every finding in
/// both is in `persisting`; and a finding whose rule only one run knows is in
/// neither, but is listed under `diff.rules` in the rendered report so that it
/// is still printed. Nothing is counted twice and nothing disappears, which is
/// what a regression gate is read by.
///
/// **A multiset, not a set.** Two findings of the same rule at the same
/// location are two findings - a rule may legitimately fire once per TAR or
/// once per file - so findings are matched off by rule ID and location in order,
/// and the surplus on either side is new or fixed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diff {
    baseline_created: String,
    baseline_findings: usize,
    current_findings: usize,
    threshold: Option<rules::Severity>,
    new: Vec<rules::Finding>,
    fixed: Vec<rules::Finding>,
    persisting: Vec<rules::Finding>,
    rules: Vec<RuleDrift>,
}

impl Diff {
    /// Compares a saved run against this one, or refuses to.
    ///
    /// **Every refusal is checked before any finding is classified**, and that
    /// order matters: a partial classification computed and then thrown away is
    /// a diff that exists for a moment, and a diff that exists for a moment is
    /// a diff somebody could read.
    ///
    /// # Errors
    ///
    /// [`Incomparable`], naming the axis the two runs disagree on. Checked in
    /// this order: either walk truncated, severity, dialect, identifier set, TAR
    /// selection, then evidence rule by rule.
    pub fn compare(
        baseline: &Baseline,
        this_run: &RunFacts,
        current: &[rules::Finding],
    ) -> Result<Self, Incomparable> {
        if !baseline.run.complete {
            return Err(Incomparable::BaselineTruncated {
                by: baseline.run.bounds_summary(),
            });
        }
        if !this_run.complete {
            return Err(Incomparable::ThisRunTruncated {
                by: this_run.bounds_summary(),
            });
        }

        if baseline.run.severity != this_run.severity {
            return Err(Incomparable::Severity {
                baseline: severity_name(baseline.run.severity),
                this_run: severity_name(this_run.severity),
            });
        }
        if baseline.run.dialect != this_run.dialect {
            return Err(Incomparable::Dialect {
                baseline: baseline.run.dialect.clone(),
                this_run: this_run.dialect.clone(),
            });
        }
        if baseline.run.candidates != this_run.candidates {
            return Err(Incomparable::Candidates {
                baseline: baseline.run.candidates.clone(),
                this_run: this_run.candidates.clone(),
            });
        }
        if baseline.run.tar_selection != this_run.tar_selection {
            return Err(Incomparable::TarSelection {
                baseline: baseline.run.tar_selection.clone(),
                this_run: this_run.tar_selection.clone(),
            });
        }
        // Per rule rather than one flag for the run: a baseline that gave one
        // rule evidence and another none cannot speak about the one it gave
        // none, whatever the first one did.
        for run in this_run.rule_runs() {
            let here = this_run.evidence_of(run.id()).unwrap_or(false);
            if let Some(was) = baseline.run.evidence_of(run.id()) {
                if was != here {
                    return Err(Incomparable::Evidence {
                        rule: run.id().clone(),
                        baseline_evidence: was,
                        this_evidence: here,
                    });
                }
            }
        }

        Ok(Self::classify(baseline, this_run, current))
    }

    /// The classification itself, run once the two runs are comparable.
    fn classify(baseline: &Baseline, this_run: &RunFacts, current: &[rules::Finding]) -> Self {
        let drift = rule_drift(baseline, this_run);
        let withheld: Vec<&rules::RuleId> = drift.iter().map(|d| &d.id).collect();

        let was = index(baseline.findings());
        let now = index(current);
        let mut new = Vec::new();
        let mut fixed = Vec::new();
        let mut persisting = Vec::new();

        // Keys are sorted by construction (BTreeMap), so the three lists come
        // out in a stable order on every run and `diff` is byte-identical for
        // the same card and the same baseline. "JSON-stable across runs" is one
        // of issue #12's acceptance criteria and it is a property of this map,
        // not of the order a rule happened to fire in.
        //
        // One pass over the union of the keys, in key order. Both sides of a
        // key that exists in BOTH runs are handled here, surplus included: two
        // findings of one rule at one location are two findings, so the surplus
        // on the current side is new and the surplus on the baseline side is
        // fixed. A key only one side has is new or fixed outright, unless its
        // rule drifted - then it is withheld and appears under `rules` instead.
        for key in was
            .keys()
            .chain(now.keys())
            .collect::<std::collections::BTreeSet<_>>()
        {
            let then = was.get(key).map(Vec::as_slice).unwrap_or(&[]);
            let here = now.get(key).map(Vec::as_slice).unwrap_or(&[]);
            if let Some(rule) = then
                .first()
                .or_else(|| here.first())
                .map(rules::Finding::rule)
            {
                if withheld.contains(&rule) {
                    continue;
                }
            }

            let pairs = then.len().min(here.len());
            persisting.extend(here[..pairs].iter().cloned());
            new.extend(here[pairs..].iter().cloned());
            fixed.extend(then[pairs..].iter().cloned());
        }

        Self {
            baseline_created: baseline.created().to_owned(),
            baseline_findings: baseline.findings().len(),
            current_findings: current.len(),
            threshold: this_run.severity(),
            new,
            fixed,
            persisting,
            rules: drift,
        }
    }

    /// Whether this run is worse than the baseline.
    ///
    /// **New findings only.** A fix is not a regression, and a gate that exited
    /// non-zero because a card improved would be a gate nobody turns on. The
    /// list compared is the one `--severity` already filtered, so the threshold
    /// is the operator's own rather than a second knob.
    pub fn regressed(&self) -> bool {
        !self.new.is_empty()
    }

    /// Findings this run has that the baseline did not.
    pub fn new_findings(&self) -> &[rules::Finding] {
        &self.new
    }

    /// How many findings are new.
    ///
    /// **Named apart from [`Diff::new_findings`] because a field and a
    /// constructor are different things**, and a `Diff::new` accessor beside a
    /// `new_findings_len` reads as if it built one.
    pub fn new_findings_len(&self) -> usize {
        self.new.len()
    }

    /// Findings the baseline had that this run does not.
    pub fn fixed(&self) -> &[rules::Finding] {
        &self.fixed
    }

    /// Findings both runs have.
    pub fn persisting(&self) -> &[rules::Finding] {
        &self.persisting
    }

    /// Rules one run knew and the other did not.
    pub fn rule_drift(&self) -> &[RuleDrift] {
        &self.rules
    }

    /// The `--severity` level in force for both runs, which is the gate.
    pub const fn threshold(&self) -> Option<rules::Severity> {
        self.threshold
    }

    /// The sentence under `diff.rules.warning`, when there is something to say.
    ///
    /// **Names the rename rather than resolving it.** One ID leaving and one
    /// arriving is what a renamed rule looks like and what a withdrawn rule plus
    /// an unrelated new one looks like, and nothing in two files can tell those
    /// apart. The diff says both are possible and asks the reader, rather than
    /// guessing and reporting a fix that never happened.
    pub fn rules_warning(&self) -> Option<String> {
        if self.rules.is_empty() {
            return None;
        }
        let retired: Vec<&str> = self
            .rules
            .iter()
            .filter(|d| d.direction == Direction::Retired)
            .map(|d| d.id.as_str())
            .collect();
        let added: Vec<&str> = self
            .rules
            .iter()
            .filter(|d| d.direction == Direction::Added)
            .map(|d| d.id.as_str())
            .collect();
        Some(format!(
            concat!(
                "{} rule ID(s) are in one run and not the other, and their findings are counted 
                 as neither new nor fixed. An ID that leaves and one that arrives together is 
                 what a RENAME looks like, and what withdrawing a rule and adding an unrelated 
                 one looks like; two files cannot tell those apart, so neither is claimed here. 
                 AGENTS.md section 3 says a rule ID must never be renamed casually, and this 
                 is where that bites. Retired: [{}]. New in this scan: [{}]."
            ),
            self.rules.len(),
            retired.join(", "),
            added.join(", "),
        ))
    }

    /// The diff as the JSON block `payload.data.diff` carries.
    ///
    /// **Sorted keys inside `serde_json`, and sorted lists here**, so two runs
    /// of the same card against the same baseline produce the same bytes. A
    /// regression gate whose own output reorders itself between runs cannot be
    /// compared by a human reading two CI logs, and that is the failure this
    /// ordering exists to prevent.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "baseline": {
                "created": self.baseline_created,
                "findings": self.baseline_findings,
            },
            "current": {
                "findings": self.current_findings,
            },
            // The threshold the gate used, beside the answer, so a reader never
            // has to infer which level produced this verdict.
            "threshold": self.threshold.map(rules::Severity::id),
            "regressed": self.regressed(),
            "counts": {
                "new": self.new_findings_len(),
                "fixed": self.fixed.len(),
                "persisting": self.persisting.len(),
            },
            "new": self.new,
            "fixed": self.fixed,
            "persisting": self.persisting,
            "rules": {
                "changed": self.rules.iter().map(RuleDrift::to_json).collect::<Vec<_>>(),
                "warning": self.rules_warning(),
            },
        })
    }

    /// The diff as a person reads it, for the human mode.
    ///
    /// **Printed after the scan report, not before it**, for the reason the TAR
    /// block is printed before the findings there: a comparison whose inputs are
    /// somewhere else on the page is a claim rather than a reading. `scan`
    /// prints the run's own facts first and this block last, so the new and
    /// fixed lists are read against the numbers that produced them.
    #[must_use]
    pub fn to_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "DIFF against the baseline taken {}\n",
            self.baseline_created
        ));
        out.push_str(&format!(
            "  NEW        {} (the baseline held {}, this run holds {})\n",
            self.new_findings_len(),
            self.baseline_findings,
            self.current_findings,
        ));
        out.push_str(&format!("  FIXED      {}\n", self.fixed.len()));
        out.push_str(&format!("  PERSISTING {}\n", self.persisting.len()));
        match self.threshold {
            Some(level) => out.push_str(&format!("  threshold: {level}\n")),
            None => out.push_str("  threshold: none (every finding counts)\n"),
        }
        for finding in &self.new {
            out.push_str(&format!("  + {finding}\n"));
        }
        for finding in &self.fixed {
            out.push_str(&format!("  - {finding}\n"));
        }
        if let Some(warning) = self.rules_warning() {
            out.push_str(&format!("  WARNING: {warning}\n"));
        }
        out
    }
}

/// The severity a run filtered at, as the word an operator typed.
fn severity_name(level: Option<rules::Severity>) -> String {
    level.map_or_else(|| "none".to_owned(), |level| level.id().to_owned())
}

/// Findings grouped by [`matching_key`], each group in report order.
///
/// A [`BTreeMap`] rather than a [`std::collections::HashMap`] because the
/// iteration order is the output order, and a hash order would make the diff
/// reorder itself between runs.
fn index(findings: &[rules::Finding]) -> BTreeMap<String, Vec<rules::Finding>> {
    let mut grouped: BTreeMap<String, Vec<rules::Finding>> = BTreeMap::new();
    for finding in findings {
        grouped
            .entry(matching_key(finding))
            .or_default()
            .push(finding.clone());
    }
    grouped
}

/// Rules one run ran and the other did not, with the findings they carried.
///
/// **Only from the baseline, or from this run, never both**, and that asymmetry
/// is the whole design. A rule in both is comparable; a rule in exactly one is
/// not, and its findings are withheld from `new` and `fixed` rather than
/// guessed at. The `Added` arm carries no findings of its own - it describes
/// this run, and this run's findings are already in `new` and `persisting` -
/// but it is listed because an ID nobody recognises is exactly what an
/// operator has to be told about.
fn rule_drift(baseline: &Baseline, this_run: &RunFacts) -> Vec<RuleDrift> {
    let mut drift: Vec<RuleDrift> = Vec::new();

    for run in baseline.run.rule_runs() {
        if this_run.evidence_of(run.id()).is_none() {
            drift.push(RuleDrift {
                id: run.id().clone(),
                direction: Direction::Retired,
                findings: findings_of(baseline.findings(), run.id()),
            });
        }
    }
    for run in this_run.rule_runs() {
        if baseline.run.evidence_of(run.id()).is_none() {
            drift.push(RuleDrift {
                id: run.id().clone(),
                direction: Direction::Added,
                findings: Vec::new(),
            });
        }
    }
    drift
}

/// Every finding a saved run holds under one rule, in report order.
fn findings_of(findings: &[rules::Finding], id: &rules::RuleId) -> Vec<rules::Finding> {
    findings
        .iter()
        .filter(|finding| finding.rule() == id)
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Everything that can go wrong reading or writing the file
// ---------------------------------------------------------------------------

/// Why a baseline could not be read or written.
///
/// **Every one of these is a refusal**, never a warning and never an empty
/// baseline. A baseline this tool cannot read is not a card with no findings;
/// treating it as one would report a clean build over a file that was not
/// there.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The file could not be opened or read.
    #[error("the baseline file could not be read: {0}")]
    Unreadable(String),

    /// The file is over [`MAX_BASELINE_BYTES`].
    #[error("the baseline file is over the {limit}-octet ceiling this tool will read (it had morethan {limit}); a baseline is a list of rule IDs and bounded findings, and a filelarger than that is not one")]
    TooLarge {
        /// How many octets were read, when the count is known.
        size: usize,
        /// The ceiling.
        limit: usize,
    },

    /// The bytes are not JSON, or not shaped like a baseline.
    #[error("this is not a readable sim-doctor baseline: {0}")]
    Malformed(String),

    /// The file was written by a different format version.
    #[error("this baseline is format version {found} and this build reads version {expected}; abaseline outlives the release that wrote it, so the two are compared rather thanguessed at. Re-take the baseline with this build")]
    Version {
        /// The version in the file.
        found: u32,
        /// The version this build reads.
        expected: u32,
    },

    /// One string in the file is over [`MAX_TEXT_CHARS`].
    #[error("this baseline holds a {length}-character string and the ceiling is {MAX_TEXT_CHARS};evidence is bounded so that a scan cannot fill a terminal, and the bound applies to abaseline read back as much as to one a rule produces")]
    TextTooLong {
        /// How many characters it had.
        length: usize,
    },

    /// One array in the file is over [`MAX_RECORDS`].
    #[error("this baseline holds an array of {found} items and the ceiling is {limit}; a card thistool can walk does not produce that many findings")]
    TooManyRecords {
        /// How many items it held.
        found: usize,
        /// The ceiling.
        limit: usize,
    },

    /// A finding is too long to be recorded within the limits.
    #[error("finding {rule} carries a {length}-character message and the ceiling is {limit}; abaseline that cannot be reloaded is not a baseline, and shortening the message herewould make the diff compare text the file does not contain")]
    MessageTooLong {
        /// The rule that produced it.
        rule: String,
        /// How many characters the message had.
        length: usize,
        /// The ceiling.
        limit: usize,
    },

    /// The file could not be created or renamed into place.
    #[error("the baseline could not be written: {0}")]
    Unwritable(String),

    /// The document could not be serialised.
    #[error("the baseline could not be rendered: {0}")]
    Render(String),
}

impl Error {
    /// The machine-readable tag, beside `data.error.kind` in the refusal.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Unreadable(_) => "baseline-unreadable",
            Self::TooLarge { .. } => "baseline-too-large",
            Self::Malformed(_) => "baseline-malformed",
            Self::Version { .. } => "baseline-version",
            Self::TextTooLong { .. } => "baseline-text-too-long",
            Self::TooManyRecords { .. } => "baseline-too-many-records",
            Self::MessageTooLong { .. } => "finding-message-too-long",
            Self::Unwritable(_) => "baseline-unwritable",
            Self::Render(_) => "baseline-render-failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The MSL 0 rule, with and without a TAR audit to look at.
    const TAR_RULE: &str = "gsma/msl-zero-allowed";

    /// A different rule ID, for the rename case.
    const RENAMED_RULE: &str = "gsma/msl-zero-accepted";

    /// A rule ID no registry could ever have produced. `RuleId` refuses it.
    const IMPOSSIBLE_RULE: &str = "GSMA/msl-zero-allowed";

    fn rule(text: &str) -> rules::RuleId {
        rules::RuleId::new(text).expect("a validated constant")
    }

    fn msl_zero() -> rules::Finding {
        rules::Finding::new(
            rule(TAR_RULE),
            rules::Severity::Critical,
            "TAR 000000 was accepted: MSL is 0",
            rules::Location::tar(0),
            rules::Evidence::text("accepted=9404 baseline=9000"),
        )
    }

    fn unreadable(path: &str) -> rules::Finding {
        rules::Finding::new(
            rule("filesystem/unreadable-ef"),
            rules::Severity::High,
            "EF.ICCID could not be selected",
            rules::Location::forbidden_file(path, rules::Status::from_bytes([0x98, 0x04])),
            rules::Evidence::bytes(b"a4000a4f"),
        )
    }

    /// Facts for a run that checked the card properly.
    ///
    /// `evidence: true` is the one that matters: a `--tar focused` sweep, so
    /// the MSL 0 rule had something to decide from.
    fn good(evidence: bool) -> RunFacts {
        RunFacts::new(
            "fake card",
            "swicc",
            "sim-families (1280 probed, exhaustive=false)",
            None,
            "focused@00",
            true,
            None,
            Vec::new(),
            vec![rules::RuleRun::new(rule(TAR_RULE), evidence)],
        )
    }

    /// The same run with one axis changed, for the refusal tests.
    fn facts_with(
        reader: &str,
        dialect: &str,
        candidates: &str,
        severity: Option<rules::Severity>,
        tar: &str,
        complete: bool,
        evidence: bool,
    ) -> RunFacts {
        RunFacts::new(
            reader,
            dialect,
            candidates,
            severity,
            tar,
            complete,
            (!complete).then(|| "max-depth".to_owned()),
            (!complete)
                .then(|| "max-depth".to_owned())
                .into_iter()
                .collect(),
            vec![rules::RuleRun::new(rule(TAR_RULE), evidence)],
        )
    }

    /// A saved run: the facts plus the findings it reported.
    fn saved(facts: RunFacts, findings: &[rules::Finding]) -> Baseline {
        Baseline::new(facts, findings)
    }

    /// A run saves and reloads losslessly.
    ///
    /// **Issue #12 acceptance criterion 1, and lossless means the findings, not
    /// a projection of them.** The same `rules::Finding` values come back,
    /// evidence and coverage included, because the baseline stores the objects
    /// the report carries rather than re-spelling them.
    #[test]
    fn a_run_saves_and_reloads_losslessly() {
        let found = vec![msl_zero(), unreadable("3F00/2F00/6F07")];
        let original = saved(good(true), &found);

        let text = serde_json::to_string_pretty(&original.to_json()).expect("renderable");
        let reloaded = Baseline::parse(&text).expect("this build wrote it");

        assert_eq!(reloaded.findings(), found.as_slice());
        assert_eq!(reloaded.run(), original.run());
        assert_eq!(reloaded.created(), original.created());
        assert_eq!(reloaded, original);
    }

    /// The file holds findings and comparability facts, and nothing else.
    ///
    /// **The constraint the issue states directly: a baseline is a local
    /// artifact and must not carry card secrets.** A scan report holds the ATR,
    /// the whole DF tree and per-file notes; none of those belong in a file
    /// that lands in a CI workspace and is read back by an agent. Asserting the
    /// key set is what stops one being added by accident.
    #[test]
    fn a_baseline_records_nothing_the_diff_does_not_need() {
        let text = serde_json::to_string_pretty(&saved(good(true), &[msl_zero()]).to_json())
            .expect("renderable");

        for key in ["sim_doctor_baseline", "created", "run", "findings"] {
            assert!(text.contains(key), "{key} is missing from {text}");
        }
        for forbidden in [
            r#""atr""#,
            r#""files""#,
            r#""notes""#,
            r#""selected""#,
            r#""keys""#,
            r#""probes""#,
        ] {
            assert!(
                !text.contains(forbidden),
                "a baseline must not carry {forbidden}: {text}"
            );
        }
    }

    /// New, fixed and persisting are reported separately and correctly.
    ///
    /// **Issue #12 acceptance criterion 2.** Three findings move between the
    /// two lists in three different ways and each has to land in exactly one,
    /// because a gate reads those three numbers and nothing else.
    #[test]
    fn new_fixed_and_persisting_are_separate_and_correct() {
        let one = unreadable("3F00/2F00/6F07");
        let two = unreadable("3F00/6F38");
        let three = unreadable("3F00/6F3A");

        // The baseline holds one, two and three. This run holds one and three,
        // plus a fourth that is new and minus two.
        let then = saved(good(true), &[one.clone(), two.clone(), three.clone()]);
        let now = vec![one.clone(), three.clone(), msl_zero()];
        let diff = Diff::compare(&then, &good(true), &now).expect("two comparable runs");

        assert_eq!(diff.persisting(), &[one, three][..]);
        assert_eq!(diff.fixed(), &[two][..]);
        assert_eq!(
            diff.new_findings(),
            &[msl_zero()][..],
            "a finding the baseline never held is new"
        );
        assert!(diff.regressed());

        // And the counts in the JSON agree with the lists beside them, because
        // a gate reads the counts.
        let json = diff.to_json();
        assert_eq!(json["counts"]["new"], serde_json::json!(1));
        assert_eq!(json["counts"]["fixed"], serde_json::json!(1));
        assert_eq!(json["counts"]["persisting"], serde_json::json!(2));
        assert_eq!(json["regressed"], serde_json::json!(true));
    }

    /// A run that is no worse than its baseline does not regress.
    ///
    /// **A fix must never fail a build.** A gate that exits non-zero when a
    /// card improved is a gate nobody turns on, and this is the half of
    /// `regressed` that a test written only for the failing case would miss.
    #[test]
    fn a_card_that_got_better_does_not_regress() {
        let one = unreadable("3F00/6F38");
        let then = saved(good(true), &[one.clone(), msl_zero()]);
        let diff = Diff::compare(&then, &good(true), &[msl_zero()]).expect("comparable");

        assert_eq!(diff.fixed(), &[one][..]);
        assert!(diff.new_findings().is_empty());
        assert!(!diff.regressed(), "a fix is not a regression");
        assert_eq!(diff.to_json()["regressed"], serde_json::json!(false));
    }

    /// Two findings of one rule at the same location are two findings.
    ///
    /// A rule may legitimately fire many times in one scan - once per TAR, once
    /// per file - and `Finding::to_json` is an array for exactly that reason.
    /// Keying on the rule ID alone would call the second unreadable EF a
    /// duplicate of the first and report a card that regressed when nothing did.
    #[test]
    fn two_findings_of_one_rule_at_one_location_are_two() {
        let mut pair = unreadable("3F00/6F38");
        pair = rules::Finding::new(
            pair.rule().clone(),
            rules::Severity::Medium,
            "EF.PSMS could not be selected either",
            pair.location().clone(),
            rules::Evidence::None,
        );
        let then = saved(good(true), &[pair.clone()]);
        let diff = Diff::compare(&then, &good(true), &[pair.clone(), pair]).expect("comparable");

        assert_eq!(diff.persisting().len(), 1);
        assert_eq!(diff.new_findings().len(), 1);
        assert_eq!(diff.fixed().len(), 0);
    }

    /// The same two runs produce the same diff bytes.
    ///
    /// **Issue #12 acceptance criterion 3.** Findings are grouped through a
    /// `BTreeMap`, so the order is the key order and not the order a rule
    /// happened to fire in; without that, two CI logs of the same card would
    /// not diff and the output of a regression gate would be unreviewable.
    #[test]
    fn the_diff_is_stable_across_runs_of_the_same_pair() {
        let findings = vec![
            unreadable("3F00/6F3A"),
            unreadable("3F00/2F00/6F07"),
            msl_zero(),
            unreadable("3F00/6F38"),
        ];
        // Two baselines built independently, so their `created` differs and
        // nothing else may.
        let first = saved(good(true), &findings);
        let second = saved(good(true), &findings);

        let a = Diff::compare(&first, &good(true), &findings).expect("comparable");
        let b = Diff::compare(&second, &good(true), &findings).expect("comparable");

        // Two baselines taken a few microseconds apart carry different
        // timestamps, and that is the ONE field allowed to differ: it is a
        // fact about when the run happened, not about what it found.
        let mut a_json = a.to_json();
        let mut b_json = b.to_json();
        assert_ne!(a_json["baseline"]["created"], b_json["baseline"]["created"]);
        a_json["baseline"]["created"] = json!("normalized");
        b_json["baseline"]["created"] = json!("normalized");
        assert_eq!(a_json, b_json);

        // And with the findings supplied in a different order, because that is
        // what a re-ordered registry would look like.
        let mut shuffled = findings.clone();
        shuffled.reverse();
        let c = Diff::compare(&first, &good(true), &shuffled).expect("comparable");
        assert_eq!(a.to_json(), c.to_json());
    }

    /// A RENAMED RULE READS AS A RENAME, not as a fix plus a new finding.
    ///
    /// **The property AGENTS.md section 3 buys with "an ID must never be renamed
    /// casually", and the reason a baseline outlives the release that wrote
    /// it.** The baseline recorded a critical MSL 0 finding under the old ID;
    /// this run raises it under the new one. A naive diff reports a FIX (the
    /// old ID is gone) and a NEW (the new ID appeared), which says the card was
    /// fixed and regressed in the same breath and is a claim no file supports.
    ///
    /// So neither list carries it, and the rules block carries both IDs with
    /// the findings they held and a warning naming what cannot be told apart.
    #[test]
    fn a_renamed_rule_is_neither_fixed_nor_new() {
        let renamed = rules::Finding::new(
            rule(RENAMED_RULE),
            rules::Severity::Critical,
            "TAR 000000 was accepted: MSL is 0",
            rules::Location::tar(0),
            rules::Evidence::text("accepted=9404 baseline=9000"),
        );

        let baseline_facts = RunFacts::new(
            "fake card",
            "swicc",
            "sim-families (1280 probed, exhaustive=false)",
            None,
            "focused@00",
            true,
            None,
            Vec::new(),
            vec![rules::RuleRun::new(rule(TAR_RULE), true)],
        );
        let this_facts = RunFacts::new(
            "fake card",
            "swicc",
            "sim-families (1280 probed, exhaustive=false)",
            None,
            "focused@00",
            true,
            None,
            Vec::new(),
            vec![rules::RuleRun::new(rule(RENAMED_RULE), true)],
        );

        let then = saved(baseline_facts, &[msl_zero()]);
        let diff = Diff::compare(&then, &this_facts, &[renamed]).expect("comparable");

        assert!(
            diff.new_findings().is_empty(),
            "a rename is not a regression: {:?}",
            diff.new_findings()
        );
        assert!(
            diff.fixed().is_empty(),
            "a rename is not a fix: {:?}",
            diff.fixed()
        );
        assert!(!diff.regressed(), "a rename must not fail a build");

        // Both sides are reported, and the withheld finding is still printed,
        // so nothing is silently dropped either.
        let drift = diff.rule_drift();
        assert_eq!(drift.len(), 2);
        assert_eq!(drift[0].id(), &rule(TAR_RULE));
        assert_eq!(drift[0].direction(), Direction::Retired);
        assert_eq!(drift[0].findings(), &[msl_zero()][..]);
        assert_eq!(drift[1].id(), &rule(RENAMED_RULE));
        assert_eq!(drift[1].direction(), Direction::Added);

        // And the warning says what it is, without claiming to have resolved it.
        let warning = diff.rules_warning().expect("there is something to say");
        assert!(warning.contains("RENAME"), "{warning}");
        assert!(warning.contains(TAR_RULE), "{warning}");
        assert!(warning.contains(RENAMED_RULE), "{warning}");

        let json = diff.to_json();
        assert_eq!(json["rules"]["changed"].as_array().map(Vec::len), Some(2));
        assert_eq!(json["counts"]["new"], serde_json::json!(0));
        assert_eq!(json["counts"]["fixed"], serde_json::json!(0));
        assert_eq!(json["regressed"], serde_json::json!(false));
    }

    /// A rule only this run knows is a first check, not a regression.
    ///
    /// The card may have had the problem since the day it was provisioned and
    /// the baseline simply could not see it. Calling that new would fail every
    /// build on the day the rule lands.
    #[test]
    fn a_rule_the_baseline_never_ran_does_not_regress_a_build() {
        let baseline_facts = RunFacts::new(
            "fake card",
            "swicc",
            "sim-families (1280 probed, exhaustive=false)",
            None,
            "focused@00",
            true,
            None,
            Vec::new(),
            vec![rules::RuleRun::new(rule(TAR_RULE), true)],
        );
        let this_facts = RunFacts::new(
            "fake card",
            "swicc",
            "sim-families (1280 probed, exhaustive=false)",
            None,
            "focused@00",
            true,
            None,
            Vec::new(),
            vec![
                rules::RuleRun::new(rule(TAR_RULE), true),
                rules::RuleRun::new(rule("filesystem/unreadable-ef"), true),
            ],
        );

        let then = saved(baseline_facts, &[]);
        let diff =
            Diff::compare(&then, &this_facts, &[unreadable("3F00/6F38")]).expect("comparable");

        assert!(diff.new_findings().is_empty());
        assert!(!diff.regressed());
        assert_eq!(diff.rule_drift().len(), 1);
        assert_eq!(diff.rule_drift()[0].direction(), Direction::Added);
    }

    /// A TRUNCATED BASELINE IS REFUSED, not compared.
    ///
    /// **The first half of "a diff is only as good as its baseline".** A walk
    /// that stopped at a bound did not see the whole card, so every finding
    /// this run raises would read as new and none as fixed. Both numbers would
    /// be wrong and neither would look wrong.
    #[test]
    fn a_truncated_baseline_is_refused_rather_than_compared() {
        let facts = facts_with(
            "fake card",
            "swicc",
            "sim-families (1280 probed, exhaustive=false)",
            None,
            "focused@00",
            false,
            true,
        );
        let then = saved(facts, &[]);
        let now = good(true);

        let error = Diff::compare(&then, &now, &[msl_zero()])
            .expect_err("a truncated baseline cannot say the card is clean");
        assert_eq!(error.kind(), "baseline-truncated");
        assert!(
            error.to_string().contains("max-depth"),
            "the refusal must name the bound: {error}"
        );
        assert!(
            error
                .explain(&then, &now)
                .contains("Save a baseline from a complete scan"),
            "{}",
            error.explain(&then, &now)
        );
    }

    /// A TRUNCATED CURRENT RUN IS REFUSED, and this is the dangerous direction.
    ///
    /// Everything the baseline found and this run does not have would read as
    /// fixed, and the reason it is missing is that the walk never got there. A
    /// diff that reported improvements against a walk that stopped early tells
    /// an operator a card got better, which is worse than reporting nothing.
    #[test]
    fn a_truncated_run_is_refused_rather_than_reported_as_improvements() {
        let then = saved(good(true), &[msl_zero()]);
        let now = facts_with(
            "fake card",
            "swicc",
            "sim-families (1280 probed, exhaustive=false)",
            None,
            "focused@00",
            false,
            true,
        );

        let error = Diff::compare(&then, &now, &[]).expect_err("a truncated run invents fixes");
        assert_eq!(error.kind(), "run-truncated");
        assert!(error.to_string().contains("max-depth"), "{error}");
    }

    /// A rule with evidence on one run and none on the other is refused.
    ///
    /// **The default case, and the reason this module exists.** The default TAR
    /// selection is off, so the common baseline is one where the MSL 0 rule
    /// ran with nothing to look at. A baseline recording only the rule ID would
    /// report the first real MSL 0 finding as a regression and fail a build
    /// over a check that had never been made.
    #[test]
    fn the_default_tar_off_baseline_cannot_be_diffed_against_a_tar_sweep() {
        // What a scan writes today with the default flags: the rule is
        // registered, it evaluates, and it has nothing to evaluate against.
        let baseline_facts = good(false);
        let this_facts = good(true);

        let error = Diff::compare(
            &saved(baseline_facts.clone(), &[]),
            &this_facts,
            &[msl_zero()],
        )
        .expect_err("the baseline never checked MSL 0");
        assert_eq!(error.kind(), "evidence-mismatch");
        let sentence = error.to_string();
        assert!(sentence.contains(TAR_RULE), "{sentence}");
        assert!(
            sentence.contains("first check rather than a change"),
            "{sentence}"
        );

        // And the other direction: a baseline that DID check, against a run that
        // does not, cannot claim fixes either.
        let error = Diff::compare(&saved(this_facts, &[msl_zero()]), &baseline_facts, &[])
            .expect_err("this run looked at less than the baseline did");
        assert_eq!(error.kind(), "evidence-mismatch");
    }

    /// The other four axes refuse as well, each naming itself.
    ///
    /// One test for all of them because they are one rule - two runs that asked
    /// different questions are not comparable - and four near-identical tests
    /// would say the same thing four times. The differing half is the severity
    /// one, where a mismatch lies in both directions.
    #[test]
    fn two_runs_that_asked_different_questions_are_refused() {
        let then = saved(good(true), &[]);
        let cases: [(RunFacts, &str); 4] = [
            (
                facts_with(
                    "fake card",
                    "ts-102-221",
                    "sim-families (1280 probed, exhaustive=false)",
                    None,
                    "focused@00",
                    true,
                    true,
                ),
                "dialect-mismatch",
            ),
            (
                facts_with(
                    "fake card",
                    "swicc",
                    "sim-families (16 probed, exhaustive=false)",
                    None,
                    "focused@00",
                    true,
                    true,
                ),
                "candidate-mismatch",
            ),
            (
                facts_with(
                    "fake card",
                    "swicc",
                    "sim-families (1280 probed, exhaustive=false)",
                    None,
                    "off@00",
                    true,
                    true,
                ),
                "tar-selection-mismatch",
            ),
            (
                facts_with(
                    "fake card",
                    "swicc",
                    "sim-families (1280 probed, exhaustive=false)",
                    Some(rules::Severity::High),
                    "focused@00",
                    true,
                    true,
                ),
                "severity-mismatch",
            ),
        ];

        for (this_facts, kind) in cases {
            let error = Diff::compare(&then, &this_facts, &[msl_zero()])
                .expect_err("two different questions are not comparable");
            assert_eq!(error.kind(), kind);
            // And the refusal says what each side was, so an operator does not
            // have to open the file to find out which axis moved.
            let explained = error.explain(&then, &this_facts);
            assert!(explained.contains("The baseline ran as:"), "{explained}");
            assert!(explained.contains("This run ran as:"), "{explained}");
        }
    }

    /// A reader name is recorded but never a reason to refuse.
    ///
    /// Moving a card to a different reader is an ordinary thing for an operator
    /// to do. Making it a refusal would fail every build on a machine upgrade,
    /// and the field is in the file because a diff that suddenly changed is
    /// helped by knowing the reader changed too.
    #[test]
    fn moving_the_card_to_another_reader_is_not_a_refusal() {
        let then = saved(good(true), &[]);
        let other = facts_with(
            "Identiv SCR3500",
            "swicc",
            "sim-families (1280 probed, exhaustive=false)",
            None,
            "focused@00",
            true,
            true,
        );

        assert!(Diff::compare(&then, &other, &[]).is_ok());
    }

    /// A hand-edited baseline cannot inject a rule ID no registry could make.
    ///
    /// **Issue #13 made this deliberate** - `RuleId` re-validates on the way
    /// back in - and a baseline is the input it was designed for. The refusal
    /// is the point: a file naming `GSMA/msl-zero-allowed` must not be compared
    /// against, because nothing could ever have produced that finding.
    #[test]
    fn a_hand_edited_rule_id_is_refused_rather_than_compared() {
        let text = format!(
            r#"{{"sim_doctor_baseline":1,"created":"2026-01-01T00:00:00Z",
            "run":{{"reader":"fake","dialect":"swicc",
            "candidates":"sim-families","severity_threshold":null,
            "tar_selection":"focused@00","complete":true,"truncated_by":null,
            "limits_hit":[],"rules_run":1,
            "rules":[{{"id":"{IMPOSSIBLE_RULE}","evidence":true}}]}},
            "findings":[]}}"#
        );
        let error = Baseline::parse(&text).expect_err("no registry could have made that ID");
        assert_eq!(error.kind(), "baseline-malformed");
    }

    /// A baseline from another format version is refused, not guessed at.
    ///
    /// A diff computed against a shape it is guessing at would report new and
    /// fixed findings and mean something else entirely, which is the exact
    /// failure AGENTS.md section 3 forbids: a plausible-looking number for
    /// something that was not done.
    #[test]
    fn a_baseline_from_another_format_version_is_refused() {
        let text = format!(
            r#"{{"sim_doctor_baseline":{},"created":"2026-01-01T00:00:00Z",
            "run":{{"reader":"fake","dialect":"swicc",
            "candidates":"sim-families","severity_threshold":null,
            "tar_selection":"focused@00","complete":true,"truncated_by":null,
            "limits_hit":[],"rules_run":0,"rules":[]}},
            "findings":[]}}"#,
            VERSION + 1
        );
        let error = Baseline::parse(&text).expect_err("the shapes are not the same");
        assert_eq!(error.kind(), "baseline-version");
        assert!(
            error.to_string().contains("Re-take the baseline"),
            "{error}"
        );
    }

    /// Unknown FIELDS are ignored; unknown values are not.
    ///
    /// CONTEXT.md section 3 records this from issue #13: a baseline written by a
    /// later version has to stay readable by this one, so the strictness goes on
    /// the values and not on the key set. A file that is not a baseline at all
    /// is still refused, which is what the version key is for.
    #[test]
    fn a_field_from_a_later_version_is_ignored_and_a_foreign_document_is_not() {
        let original = saved(good(true), &[msl_zero()]);
        let mut document = original.to_json();
        document
            .as_object_mut()
            .expect("an object")
            .insert("written_by".to_owned(), json!("a future build"));

        let reloaded = Baseline::parse(&document.to_string()).expect("readable");
        assert_eq!(reloaded, original);

        // And the document is still refused for the right reason rather than
        // being read as an empty baseline.
        let error = Baseline::parse(r#"{"hello":"world"}"#).expect_err("not a baseline");
        assert_eq!(error.kind(), "baseline-malformed");
    }

    /// A HOSTILE BASELINE CANNOT PRODUCE UNBOUNDED OUTPUT.
    ///
    /// **Evidence is bounded on the way IN as well as out.** A finding's
    /// message is an unbounded string in the wire type, so a hand-edited file
    /// carrying a megabyte in one message would otherwise be rendered into a CI
    /// log by a command whose whole promise is that it is safe to script. The
    /// check walks the raw document before the typed parse, so it also covers
    /// the location paths and the coverage reason, and it covers a field added
    /// next year without anyone editing this function.
    #[test]
    fn a_hostile_baseline_cannot_produce_unbounded_output() {
        let huge = "x".repeat(MAX_TEXT_CHARS + 1);
        let template = |message: &str| {
            format!(
                r#"{{"sim_doctor_baseline":1,"created":"2026-01-01T00:00:00Z",
                "run":{{"reader":"fake","dialect":"swicc",
                "candidates":"sim-families","severity_threshold":null,
                "tar_selection":"focused@00","complete":true,"truncated_by":null,
                "limits_hit":[],"rules_run":1,
                "rules":[{{"id":"{TAR_RULE}","evidence":true}}]}},
                "findings":[{{"rule":"{TAR_RULE}","severity":"critical",
                "severity_rank":4,"message":"{message}",
                "location":{{"kind":"tar","tar":0}},
                "evidence":{{"kind":"none"}},
                "coverage":{{"status":"complete"}}}}]}}"#
            )
        };

        // Inside the limit: read, so the refusal above is about the bound and
        // not about the shape.
        assert!(Baseline::parse(&template(&"x".repeat(MAX_TEXT_CHARS))).is_ok());

        let error = Baseline::parse(&template(&huge)).expect_err("a megabyte of message");
        assert_eq!(error.kind(), "baseline-text-too-long");
        assert!(
            error.to_string().contains(&MAX_TEXT_CHARS.to_string()),
            "{error}"
        );

        // And the same bound applies to a location path, which is a different
        // field with the same risk.
        let long_path = "A".repeat(MAX_TEXT_CHARS + 1);
        let text = format!(
            r#"{{"sim_doctor_baseline":1,"created":"2026-01-01T00:00:00Z",
            "run":{{"reader":"fake","dialect":"swicc",
            "candidates":"sim-families","severity_threshold":null,
            "tar_selection":"focused@00","complete":true,"truncated_by":null,
            "limits_hit":[],"rules_run":1,
            "rules":[{{"id":"{TAR_RULE}","evidence":true}}]}},
            "findings":[{{"rule":"filesystem/unreadable-ef","severity":"high",
            "severity_rank":3,"message":"short",
            "location":{{"kind":"file","path":"{long_path}","access":"forbidden",
            "status":"9804"}},
            "evidence":{{"kind":"none"}},
            "coverage":{{"status":"complete"}}}}]}}"#
        );
        assert_eq!(
            Baseline::parse(&text)
                .expect_err("a megabyte of path")
                .kind(),
            "baseline-text-too-long"
        );
    }

    /// Too many findings, and too many of anything, are refused.
    ///
    /// The record count is a contract question rather than a sanity check: a
    /// card this tool can walk does not produce 4096 findings, and if one ever
    /// does the refusal says so in words rather than truncating.
    #[test]
    fn an_oversized_record_set_is_refused_rather_than_truncated() {
        let many: Vec<serde_json::Value> = (0..=MAX_RECORDS)
            .map(|i| {
                json!({
                    "rule": "filesystem/unreadable-ef",
                    "severity": "high",
                    "severity_rank": 3,
                    "message": format!("EF {i} could not be selected"),
                    "location": { "kind": "tar", "tar": i },
                    "evidence": { "kind": "none" },
                    "coverage": { "status": "complete" },
                })
            })
            .collect();

        let document = json!({
            "sim_doctor_baseline": VERSION,
            "created": "2026-01-01T00:00:00Z",
            "run": {
                "reader": "fake", "dialect": "swicc",
                "candidates": "sim-families", "severity_threshold": null,
                "tar_selection": "focused@00", "complete": true,
                "truncated_by": null, "limits_hit": [],
                "rules_run": 1,
                "rules": [{ "id": TAR_RULE, "evidence": true }],
            },
            "findings": many,
        });

        let error = Baseline::parse(&document.to_string())
            .expect_err("no card this tool can walk produces that many");
        assert_eq!(error.kind(), "baseline-too-many-records");
        assert!(
            error.to_string().contains(&(MAX_RECORDS + 1).to_string()),
            "{error}"
        );
    }

    /// A file over the byte ceiling is refused while it is read, not after.
    ///
    /// **The ceiling has to be enforced while reading**, because the whole point
    /// of having one is that a hostile file cannot make this process allocate
    /// its way to the end of the disk; checking the length afterwards means the
    /// allocation already happened.
    #[test]
    fn a_file_over_the_byte_ceiling_is_refused() {
        let path = std::env::temp_dir().join("sim-doctor-too-big-baseline.json");
        std::fs::write(&path, "x".repeat(MAX_BASELINE_BYTES + 1)).expect("a file to refuse");
        let error = Baseline::load(&path).expect_err("over the ceiling");
        let _ = std::fs::remove_file(&path);

        assert_eq!(error.kind(), "baseline-too-large");
    }

    /// A finding too long to record is refused on the way OUT, not truncated.
    ///
    /// A baseline holding a shortened message would be compared against text
    /// the file does not contain, and the next run would diff against a
    /// sentence that was never written. Failing loudly, naming the rule, is the
    /// honest answer.
    #[test]
    fn saving_refuses_a_message_it_could_not_read_back() {
        let long = rules::Finding::new(
            rule(TAR_RULE),
            rules::Severity::Critical,
            "x".repeat(MAX_TEXT_CHARS + 1),
            rules::Location::tar(0),
            rules::Evidence::None,
        );
        let path = std::env::temp_dir().join("sim-doctor-long-message-baseline.json");
        let error = saved(good(true), &[long])
            .save(&path)
            .expect_err("that message would not survive the round trip");
        assert!(
            !path.exists(),
            "a save that refused must not have created the file"
        );
        assert_eq!(error.kind(), "finding-message-too-long");
        assert!(error.to_string().contains(TAR_RULE), "{error}");
    }

    /// A save leaves the real file untouched when it fails.
    ///
    /// The write goes through a temporary file and a rename precisely so that a
    /// machine which dies between the two cannot leave a half-written baseline
    /// that the next diff reads as though somebody chose it. This is the
    /// in-process version of the same property.
    #[test]
    fn a_failed_save_leaves_the_previous_baseline_intact() {
        let directory = std::env::temp_dir().join("sim-doctor-baseline-atomicity");
        std::fs::create_dir_all(&directory).expect("a scratch directory");
        let path = directory.join("baseline.json");

        let good_one = saved(good(true), &[msl_zero()]);
        good_one.save(&path).expect("the first save works");
        let before = std::fs::read(&path).expect("the first save landed");

        let too_long = rules::Finding::new(
            rule(TAR_RULE),
            rules::Severity::Critical,
            "x".repeat(MAX_TEXT_CHARS + 1),
            rules::Location::tar(0),
            rules::Evidence::None,
        );
        assert!(saved(good(true), &[too_long]).save(&path).is_err());

        assert_eq!(
            std::fs::read(&path).expect("still there"),
            before,
            "a refused save must not have touched the file an operator already had"
        );
        // And no scratch file is left lying beside it.
        let leftovers: Vec<String> = std::fs::read_dir(&directory)
            .expect("readable")
            .filter_map(|entry| {
                entry
                    .ok()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
            })
            .filter(|name| name.contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A saved baseline reloads from the path it was written to.
    ///
    /// The end-to-end half: `save` then `load`, across a real filesystem,
    /// which is the only way to prove the temporary-file-and-rename dance did
    /// not lose anything on the way.
    #[test]
    fn a_saved_baseline_reloads_from_the_path_it_was_written_to() {
        let directory = std::env::temp_dir().join("sim-doctor-baseline-roundtrip");
        std::fs::create_dir_all(&directory).expect("a scratch directory");
        let path = directory.join("baseline.json");

        let found = vec![msl_zero(), unreadable("3F00/2F00/6F07")];
        let original = saved(good(true), &found);
        original.save(&path).expect("saved");

        let reloaded = Baseline::load(&path).expect("read back");
        assert_eq!(reloaded.findings(), found.as_slice());
        assert_eq!(reloaded.run(), original.run());

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// The threshold in force is carried beside the verdict.
    ///
    /// A reader must never have to infer which severity level produced a diff,
    /// because the same new finding is a regression at `high` and not one at
    /// `info`.
    #[test]
    fn the_diff_carries_the_threshold_that_decided_it() {
        let facts = facts_with(
            "fake card",
            "swicc",
            "sim-families (1280 probed, exhaustive=false)",
            Some(rules::Severity::High),
            "focused@00",
            true,
            true,
        );
        let diff =
            Diff::compare(&saved(facts.clone(), &[]), &facts, &[msl_zero()]).expect("comparable");

        assert_eq!(diff.threshold(), Some(rules::Severity::High));
        assert_eq!(
            diff.to_json()["threshold"],
            serde_json::json!("high"),
            "the gate and the threshold it used travel together"
        );
    }
}
