//! Comparing a card's walked file system with the public GSMA TS.48 test profile.
//
//! **Owns.** The expected file list (a committed JSON fixture derived from the
//! public SAIP profile package), the extractor that derives it, the diff
//! between that list and a walked [`Tree`], and the three `ts48/...` rules the
//! diff reports through. Issue #25.
//
//! **Does not own.** The walk (that is [`crate::walk`]), the finding model
//! ([`crate::rules`]) or the envelope ([`crate::contract`]).
//
//! **What TS.48 is.** GSMA publishes the Generic eUICC Test Profile for Device
//! Testing under Apache-2.0 at
//! `https://github.com/GSMATerminals/Generic-eUICC-Test-Profile-for-Device-Testing-Public`
//! (AGENTS.md section 6, blocker 5). It is a *test profile* - the file system,
//! applications and test keys a test eUICC carries - and not a list of APDU
//! test cases. **A card whose file system matches it has not thereby passed
//! GCF or PTCRB; this module does not test conformance.** An operator SIM is
//! not a TS.48 card, so differences are the expected answer and are reported
//! as low or informational findings, never as a failed run.
//
//! **What is committed, and what is not.** The profile package carries public
//! test keys. AGENTS.md forbids committing card secrets, so the package is
//! never committed; `tests/corpus/ts48/ts48-v7.0-files.json` holds only the
//! derived file list (path, type, layout, size, record length, the access rule
//! reference) with the source repository, the pinned commit and the licence.
//! The ignored test `regenerates_the_fixture_from_a_downloaded_profile`
//! re-derives it from a downloaded copy.
//
//! **Extraction.** The package is DER per the SIMalliance/TCA eUICC Profile
//! Package (SAIP) ASN.1, but only the file list is read, with a small local reader
//! and without the ASN.1 module. The tags used are the ones observed in the
//! pinned package, cross-checked against its `.txt` value notation and the
//! profile-structure spreadsheet: every template profile element holds file
//! elements whose `A1` child is an FCP (`82` descriptor, `83` file identifier,
//! `80` size, `8B` referenced access rule), and the `genericFileManagement`
//! element (`A1`) holds `80` file paths followed by `62` create-FCPs. A
//! template profile element is recognised by its `81` template OID in the
//! `2.23.143.1.2` arc. The tree position of a template file is implied by the
//! template, so it is derived: a `7Fxx` directory is an application root under
//! the master file, a `5Fxx` directory sits under the latest root, and files
//! belong to the latest directory of their element.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "ts48";

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::fcp::Structure;
use crate::fs::FileKind;
use crate::rules::{self, Evidence, Finding, Location, RuleId, RuleSpec, Severity};
use crate::walk::{NodeState, Tree};

/// The envelope `type` of `sim-doctor ts48 compare --json`.
pub const KIND: &str = "ts48";

/// The sentence every report carries, because the opposite reading is the
/// obvious one.
pub const NOT_CONFORMANCE: &str =
    "Matching the TS.48 file structure is not GCF or PTCRB conformance; \
     this compares a file system against a public test profile and certifies nothing.";

/// A file the card holds that the profile does not.
pub const EXTRA_RULE: &str = "ts48/file-extra";
/// A file the profile has that the card does not.
pub const MISSING_RULE: &str = "ts48/file-missing";
/// A file both have, that differs in kind, layout, size or record length.
pub const DIFFERENT_RULE: &str = "ts48/file-different";

const FIXTURE: &str = include_str!("../tests/corpus/ts48/ts48-v7.0-files.json");

/// DF or EF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    /// A directory (DF or ADF).
    #[serde(rename = "DF")]
    Df,
    /// An elementary file.
    #[serde(rename = "EF")]
    Ef,
}

/// How an EF's contents are laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Layout {
    /// One run of octets.
    Transparent,
    /// Fixed-length records.
    LinearFixed,
    /// Variable-length records.
    LinearVariable,
    /// Cyclic records.
    Cyclic,
}

/// One file the profile defines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedFile {
    /// `3F00/7F10/6F44`, the way the walk prints paths.
    pub path: String,
    /// DF or EF.
    pub kind: Kind,
    /// EF layout; absent for a DF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<Layout>,
    /// EF size in octets, when the profile states or implies one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    /// Record length of a record-structured EF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_len: Option<u32>,
    /// The access rule reference (`EF.ARR` id and record, hex). Recorded, never
    /// compared: a card's rule records are its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arr: Option<String>,
}

/// Where the list came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    /// The public repository.
    pub repo: String,
    /// The pinned commit.
    pub commit: String,
    /// The licence of that repository.
    pub licence: String,
    /// The package member the list was derived from.
    pub file: String,
    /// What was derived and what was not.
    pub note: String,
}

/// The committed fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fixture {
    /// Provenance.
    pub source: Source,
    /// Sorted by path.
    pub files: Vec<ExpectedFile>,
}

impl Fixture {
    /// The fixture compiled into this binary.
    ///
    /// # Errors
    ///
    /// Only if the committed file is not a fixture, which a unit test prevents.
    pub fn bundled() -> Result<Self, serde_json::Error> {
        serde_json::from_str(FIXTURE)
    }

    /// The committed text form: the header pretty-printed, one file per line.
    pub fn to_text(&self) -> String {
        let mut text = String::from("{\n  \"source\": ");
        let source = serde_json::to_string_pretty(&self.source).unwrap_or_default();
        text.push_str(&source.replace('\n', "\n  "));
        text.push_str(",\n  \"files\": [\n");
        let lines: Vec<String> = self
            .files
            .iter()
            .map(|file| format!("    {}", serde_json::to_string(file).unwrap_or_default()))
            .collect();
        text.push_str(&lines.join(",\n"));
        text.push_str("\n  ]\n}\n");
        text
    }
}

// ---------------------------------------------------------------------------
// Extraction from the SAIP package
// ---------------------------------------------------------------------------

/// Why a package could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtractError {
    /// The TLV structure is broken.
    #[error("profile package is not well-formed TLV at offset {0} of an element")]
    Malformed(usize),
    /// Two elements define one path differently, which means this extractor
    /// misread the package.
    #[error("{0} is defined twice with different attributes")]
    Conflict(String),
}

/// `2.23.143.1.2` as DER content octets: the TS.48 / SAIP template OID arc.
const TEMPLATE_ARC: [u8; 5] = [0x67, 0x81, 0x0F, 0x01, 0x02];

/// One BER/DER element. Local rather than [`crate::tlv`] because SAIP uses tag
/// numbers above 30 (`BF xx`), which that reader, built for single-octet card
/// tags, does not model. `tag` is the identifier octets packed big-endian, so a
/// single-octet tag is itself (`0xA1`).
struct Atom<'a> {
    tag: u32,
    constructed: bool,
    value: &'a [u8],
}

/// Splits `body` into its elements, or says at which offset it stopped making
/// sense. Definite lengths up to four octets; indefinite length is refused.
fn atoms(body: &[u8]) -> Result<Vec<Atom<'_>>, ExtractError> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let bad = || ExtractError::Malformed(at);
        let first = body[at];
        let mut tag = u32::from(first);
        let mut i = at + 1;
        if first & 0x1F == 0x1F {
            loop {
                let next = *body.get(i).ok_or_else(bad)?;
                tag = tag.checked_shl(8).ok_or_else(bad)? | u32::from(next);
                i += 1;
                if next & 0x80 == 0 {
                    break;
                }
            }
        }
        let length = *body.get(i).ok_or_else(bad)?;
        i += 1;
        let length = if length < 0x80 {
            usize::from(length)
        } else {
            let n = usize::from(length & 0x7F);
            if n == 0 || n > 4 {
                return Err(bad());
            }
            let octets = body.get(i..i + n).ok_or_else(bad)?;
            i += n;
            octets
                .iter()
                .fold(0usize, |len, b| len << 8 | usize::from(*b))
        };
        let value = body
            .get(i..i.checked_add(length).ok_or_else(bad)?)
            .ok_or_else(bad)?;
        out.push(Atom {
            tag,
            constructed: first & 0x20 != 0,
            value,
        });
        at = i + length;
    }
    Ok(out)
}

struct Fcp {
    descriptor: Option<Vec<u8>>,
    fid: Option<[u8; 2]>,
    size: Option<u32>,
    arr: Option<Vec<u8>>,
}

fn parse_fcp(body: &[u8]) -> Result<Fcp, ExtractError> {
    let mut fcp = Fcp {
        descriptor: None,
        fid: None,
        size: None,
        arr: None,
    };
    for atom in atoms(body)? {
        match (atom.tag, atom.value) {
            (0x82, v) => fcp.descriptor = Some(v.to_vec()),
            (0x83, &[a, b]) => fcp.fid = Some([a, b]),
            (0x80, v) if (1..=4).contains(&v.len()) => {
                fcp.size = Some(v.iter().fold(0, |n, b| (n << 8) | u32::from(*b)));
            }
            (0x8B, v) => fcp.arr = Some(v.to_vec()),
            _ => {}
        }
    }
    Ok(fcp)
}

fn path_text(segments: &[[u8; 2]]) -> String {
    segments
        .iter()
        .map(|id| format!("{:02X}{:02X}", id[0], id[1]))
        .collect::<Vec<_>>()
        .join("/")
}

/// The file an FCP defines at `parent`, or `None` for the master file's own
/// element (no identifier).
fn expected_file(parent: &[[u8; 2]], fcp: &Fcp) -> Option<ExpectedFile> {
    let fid = fcp.fid?;
    let mut segments = parent.to_vec();
    segments.push(fid);
    let path = path_text(&segments);
    let descriptor = fcp.descriptor.as_deref();
    // 0x78 is a DF's descriptor byte; a template DF carries no descriptor.
    let is_df = descriptor.is_none_or(|d| d.first().is_some_and(|b| b & 0x38 == 0x38));
    if is_df {
        return Some(ExpectedFile {
            path,
            kind: Kind::Df,
            layout: None,
            size: None,
            record_len: None,
            arr: fcp.arr.as_deref().map(hex),
        });
    }
    let descriptor = descriptor?;
    let layout = match descriptor.first()? & 0x07 {
        1 => Layout::Transparent,
        2 => Layout::LinearFixed,
        3 => Layout::LinearVariable,
        6 => Layout::Cyclic,
        _ => return None,
    };
    let record_len = (layout != Layout::Transparent && descriptor.len() >= 4)
        .then(|| u32::from(descriptor[2]) << 8 | u32::from(descriptor[3]));
    Some(ExpectedFile {
        path,
        kind: Kind::Ef,
        layout: Some(layout),
        size: fcp.size,
        record_len,
        arr: fcp.arr.as_deref().map(hex),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn insert(
    files: &mut BTreeMap<String, ExpectedFile>,
    file: ExpectedFile,
) -> Result<(), ExtractError> {
    match files.get(&file.path) {
        Some(existing) if *existing != file => Err(ExtractError::Conflict(file.path)),
        _ => {
            files.insert(file.path.clone(), file);
            Ok(())
        }
    }
}

/// Reads the expected file list out of a DER-encoded SAIP profile package.
///
/// # Errors
///
/// [`ExtractError`] when the package is not well-formed TLV or defines one path
/// two ways.
pub fn extract(der: &[u8]) -> Result<Vec<ExpectedFile>, ExtractError> {
    const MF: [u8; 2] = [0x3F, 0x00];
    let mut files = BTreeMap::new();
    let mut root = vec![MF];

    for element in atoms(der)?.into_iter() {
        let children = atoms(element.value)?;

        // genericFileManagement: `80` file path, then `62` create-FCPs.
        if element.tag == 0xA1 {
            for group in children.iter().filter(|t| t.tag == 0xA1) {
                let mut current = vec![MF];
                for item in atoms(group.value)? {
                    for step in atoms(item.value)? {
                        match step.tag {
                            0x80 => {
                                current = std::iter::once(MF)
                                    .chain(step.value.chunks_exact(2).map(|c| [c[0], c[1]]))
                                    .collect();
                            }
                            0x62 => {
                                let fcp = parse_fcp(step.value)?;
                                if let Some(file) = expected_file(&current, &fcp) {
                                    insert(&mut files, file)?;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            continue;
        }

        let is_template = children
            .iter()
            .any(|t| t.tag == 0x81 && t.value.starts_with(&TEMPLATE_ARC));
        if !is_template {
            continue;
        }
        let mut current = root.clone();
        for file_element in children.iter().filter(|t| t.constructed) {
            let parts = atoms(file_element.value)?;
            let Some(fcp_atom) = parts.iter().find(|t| t.tag == 0xA1) else {
                continue;
            };
            let fcp = parse_fcp(fcp_atom.value)?;
            let Some(file) = expected_file(&current, &fcp) else {
                continue;
            };
            if file.kind == Kind::Df {
                // A 5Fxx directory sits under the latest application root;
                // any other directory is a new root under the master file.
                let fid = fcp.fid.unwrap_or(MF);
                let new_root = fid[0] != 0x5F;
                let parent = if new_root { vec![MF] } else { root.clone() };
                if let Some(file) = expected_file(&parent, &fcp) {
                    insert(&mut files, file)?;
                }
                current = parent;
                current.push(fid);
                if new_root {
                    root = current.clone();
                }
                continue;
            }
            insert(&mut files, file)?;
        }
    }
    Ok(files.into_values().collect())
}

// ---------------------------------------------------------------------------
// The comparison
// ---------------------------------------------------------------------------

/// What the walk saw at one path, reduced to what a comparison reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observed {
    /// The card selected it.
    Selected {
        /// DF or EF, when the card's descriptor said.
        kind: Option<Kind>,
        /// EF layout, when reported.
        layout: Option<Layout>,
        /// Size, when reported.
        size: Option<u32>,
        /// Record length, when reported.
        record_len: Option<u32>,
    },
    /// The card holds it and would not say more (forbidden or unclassified
    /// refusal). Its subtree was not walked.
    Blocked,
}

/// Reduces a walked tree to [`Observed`] per path. The master file is left out.
pub fn observe(tree: &Tree) -> BTreeMap<String, Observed> {
    let mut seen = BTreeMap::new();
    for node in tree.nodes() {
        if node.path().is_master_file() {
            continue;
        }
        let observed = match node.state() {
            NodeState::Selected { kind, capabilities } => {
                let descriptor = capabilities.descriptor.reported();
                let layout = descriptor.and_then(|d| match d.structure {
                    Structure::Transparent => Some(Layout::Transparent),
                    Structure::LinearFixed => Some(Layout::LinearFixed),
                    Structure::LinearVariable => Some(Layout::LinearVariable),
                    Structure::Cyclic => Some(Layout::Cyclic),
                    Structure::Unknown(_) => None,
                });
                Observed::Selected {
                    kind: kind.as_file_kind().map(|k| match k {
                        FileKind::ElementaryFile => Kind::Ef,
                        FileKind::MasterFile | FileKind::DedicatedFile => Kind::Df,
                    }),
                    layout: layout
                        .filter(|_| kind.as_file_kind() == Some(FileKind::ElementaryFile)),
                    size: capabilities.size.reported().map(|s| s.octets()),
                    record_len: descriptor
                        .filter(|d| d.octets.len() >= 4 && layout != Some(Layout::Transparent))
                        .map(|d| u32::from(d.octets[2]) << 8 | u32::from(d.octets[3])),
                }
            }
            NodeState::Forbidden { .. } | NodeState::Refused { .. } => Observed::Blocked,
            NodeState::Absent => continue,
        };
        seen.insert(node.path().to_string(), observed);
    }
    seen
}

/// One file present in both, and what differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Difference {
    /// The profile's file.
    pub expected: ExpectedFile,
    /// What the card said.
    pub observed: Observed,
    /// Which of `kind`, `layout`, `size`, `record_len` differ.
    pub fields: Vec<&'static str>,
}

/// The diff between the profile and a card.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Comparison {
    /// How many files the profile defines.
    pub expected: usize,
    /// Present in both and equal in everything compared.
    pub matched: usize,
    /// In the profile, not on the card.
    pub missing: Vec<ExpectedFile>,
    /// On the card, not in the profile.
    pub extra: Vec<String>,
    /// In both, with differences.
    pub different: Vec<Difference>,
    /// In the profile, but the card (or an ancestor) refused the walk, so
    /// neither present nor absent can be claimed.
    pub unverified: Vec<String>,
}

/// Diffs `expected` against what a walk observed.
pub fn compare(expected: &[ExpectedFile], observed: &BTreeMap<String, Observed>) -> Comparison {
    let mut out = Comparison {
        expected: expected.len(),
        ..Comparison::default()
    };
    let known: std::collections::BTreeSet<&str> =
        expected.iter().map(|f| f.path.as_str()).collect();
    for file in expected {
        match observed.get(&file.path) {
            Some(Observed::Selected {
                kind,
                layout,
                size,
                record_len,
            }) => {
                let mut fields = Vec::new();
                if kind.is_some_and(|k| k != file.kind) {
                    fields.push("kind");
                }
                if file.kind == Kind::Ef && kind.is_none_or(|k| k == Kind::Ef) {
                    if layout.zip(file.layout).is_some_and(|(a, b)| a != b) {
                        fields.push("layout");
                    }
                    if size.zip(file.size).is_some_and(|(a, b)| a != b) {
                        fields.push("size");
                    }
                    if record_len.zip(file.record_len).is_some_and(|(a, b)| a != b) {
                        fields.push("record_len");
                    }
                }
                if fields.is_empty() {
                    out.matched += 1;
                } else {
                    out.different.push(Difference {
                        expected: file.clone(),
                        observed: observed[&file.path].clone(),
                        fields,
                    });
                }
            }
            Some(Observed::Blocked) => out.unverified.push(file.path.clone()),
            None => {
                // Not seen. If an ancestor was refused, the walk never looked.
                let blocked = ancestors(&file.path)
                    .any(|a| matches!(observed.get(a), Some(Observed::Blocked)));
                if blocked {
                    out.unverified.push(file.path.clone());
                } else {
                    out.missing.push(file.clone());
                }
            }
        }
    }
    out.extra = observed
        .iter()
        .filter(|(path, seen)| {
            matches!(seen, Observed::Selected { .. }) && !known.contains(path.as_str())
        })
        .map(|(path, _)| path.clone())
        .collect();
    out
}

fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/').map(move |(i, _)| &path[..i])
}

fn describe(
    kind: Kind,
    layout: Option<Layout>,
    size: Option<u32>,
    record_len: Option<u32>,
) -> String {
    let mut text = format!("{kind:?}").to_uppercase();
    if let Some(layout) = layout {
        text.push_str(&format!(" {layout:?}"));
    }
    if let Some(size) = size {
        text.push_str(&format!(" size {size}"));
    }
    if let Some(len) = record_len {
        text.push_str(&format!(" record {len}"));
    }
    text
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// The three rules, for `rules list` and `rules explain`.
pub fn specs() -> Vec<RuleSpec> {
    let id = |text: &str| RuleId::new(text).expect("a validated constant");
    vec![
        RuleSpec::new(
            id(MISSING_RULE),
            Severity::Low,
            "the TS.48 test profile defines a file the card does not have",
        )
        .with_remediation(
            "expected for an operator SIM, which is not a TS.48 card; matching TS.48 is not GCF or PTCRB conformance",
        ),
        RuleSpec::new(
            id(DIFFERENT_RULE),
            Severity::Low,
            "a file exists on the card and in the TS.48 profile but differs in type, layout, size or record length",
        )
        .with_remediation(
            "expected for an operator SIM, which is not a TS.48 card; matching TS.48 is not GCF or PTCRB conformance",
        ),
        RuleSpec::new(
            id(EXTRA_RULE),
            Severity::Info,
            "the card holds a file the TS.48 test profile does not define",
        )
        .with_remediation(
            "expected for an operator SIM, which is not a TS.48 card; matching TS.48 is not GCF or PTCRB conformance",
        ),
    ]
}

/// The comparison as findings. `partial` carries the reason a truncated walk
/// makes the list short.
pub fn findings(comparison: &Comparison, partial: Option<&str>) -> rules::Findings {
    let id = |text: &str| RuleId::new(text).expect("a validated constant");
    let mut found = Vec::new();
    for file in &comparison.missing {
        found.push(Finding::new(
            id(MISSING_RULE),
            Severity::Low,
            format!(
                "TS.48 defines {} ({}) and the card does not have it",
                file.path,
                describe(file.kind, file.layout, file.size, file.record_len)
            ),
            Location::absent_file(&file.path),
            Evidence::None,
        ));
    }
    for diff in &comparison.different {
        let Observed::Selected {
            kind,
            layout,
            size,
            record_len,
        } = &diff.observed
        else {
            continue;
        };
        let file = &diff.expected;
        found.push(Finding::new(
            id(DIFFERENT_RULE),
            Severity::Low,
            format!(
                "{} differs from TS.48 in {}: profile {}, card {}",
                file.path,
                diff.fields.join(", "),
                describe(file.kind, file.layout, file.size, file.record_len),
                kind.map_or_else(
                    || "unreported type".to_owned(),
                    |k| describe(k, *layout, *size, *record_len)
                ),
            ),
            Location::selected_file(&file.path),
            Evidence::text(diff.fields.join(",")),
        ));
    }
    for path in &comparison.extra {
        found.push(Finding::new(
            id(EXTRA_RULE),
            Severity::Info,
            format!("{path} is on the card and not defined by TS.48"),
            Location::selected_file(path),
            Evidence::None,
        ));
    }
    match partial {
        Some(reason) => rules::Findings::partial(found, reason),
        None => rules::Findings::complete(found),
    }
}

/// The `data` body of the envelope.
pub fn to_json(
    fixture: &Fixture,
    comparison: &Comparison,
    findings: &rules::Findings,
    reader: &str,
    dialect: &str,
    complete: bool,
) -> serde_json::Value {
    serde_json::json!({
        "reader": reader,
        "dialect": dialect,
        "complete": complete,
        "profile": fixture.source,
        "not_conformance": NOT_CONFORMANCE,
        "summary": {
            "expected": comparison.expected,
            "matched": comparison.matched,
            "missing": comparison.missing.len(),
            "extra": comparison.extra.len(),
            "different": comparison.different.len(),
            "unverified": comparison.unverified.len(),
        },
        "unverified": comparison.unverified,
        "findings": findings.to_json(),
    })
}

/// The comparison as a person reads it.
pub fn to_human(comparison: &Comparison, findings: &rules::Findings, complete: bool) -> String {
    let mut out = String::new();
    if !complete {
        out.push_str("TRUNCATED: the walk stopped at a bound, so this comparison may be short.\n");
    }
    out.push_str(&format!(
        "TS.48 compare: {} defined, {} matched, {} missing, {} extra, {} different, {} unverified\n",
        comparison.expected,
        comparison.matched,
        comparison.missing.len(),
        comparison.extra.len(),
        comparison.different.len(),
        comparison.unverified.len(),
    ));
    out.push_str(NOT_CONFORMANCE);
    out.push('\n');
    for finding in findings.iter() {
        out.push_str(&format!("  {finding}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ef(path: &str, layout: Layout, size: u32) -> ExpectedFile {
        ExpectedFile {
            path: path.to_owned(),
            kind: Kind::Ef,
            layout: Some(layout),
            size: Some(size),
            record_len: None,
            arr: None,
        }
    }

    fn df(path: &str) -> ExpectedFile {
        ExpectedFile {
            path: path.to_owned(),
            kind: Kind::Df,
            layout: None,
            size: None,
            record_len: None,
            arr: None,
        }
    }

    fn seen(layout: Layout, size: u32) -> Observed {
        Observed::Selected {
            kind: Some(Kind::Ef),
            layout: Some(layout),
            size: Some(size),
            record_len: None,
        }
    }

    fn dir() -> Observed {
        Observed::Selected {
            kind: Some(Kind::Df),
            layout: None,
            size: None,
            record_len: None,
        }
    }

    #[test]
    fn the_bundled_fixture_loads_and_round_trips() {
        let fixture = Fixture::bundled().expect("the committed fixture parses");
        assert!(fixture.files.len() > 200, "{} files", fixture.files.len());
        assert_eq!(fixture.source.licence, "Apache-2.0");
        assert_eq!(fixture.source.commit.len(), 40);
        assert!(fixture.files.windows(2).all(|w| w[0].path < w[1].path));
        let iccid = fixture
            .files
            .iter()
            .find(|f| f.path == "3F00/2FE2")
            .unwrap();
        assert_eq!(
            (iccid.kind, iccid.layout),
            (Kind::Ef, Some(Layout::Transparent))
        );
        assert_eq!(
            fixture.to_text(),
            FIXTURE,
            "the file is in the canonical form"
        );
    }

    #[test]
    fn every_rule_id_is_valid_and_unique() {
        let specs = specs();
        assert_eq!(specs.len(), 3);
        let ids: std::collections::BTreeSet<_> = specs.iter().map(|s| s.id().as_str()).collect();
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn identical_trees_match() {
        let expected = [
            df("3F00/7F10"),
            ef("3F00/7F10/6F44", Layout::Transparent, 4),
        ];
        let observed = BTreeMap::from([
            ("3F00/7F10".to_owned(), dir()),
            ("3F00/7F10/6F44".to_owned(), seen(Layout::Transparent, 4)),
        ]);
        let result = compare(&expected, &observed);
        assert_eq!(result.matched, 2);
        assert!(
            result.missing.is_empty() && result.extra.is_empty() && result.different.is_empty()
        );
    }

    #[test]
    fn a_file_only_in_the_profile_is_missing_and_only_on_the_card_is_extra() {
        let expected = [ef("3F00/2FE2", Layout::Transparent, 10)];
        let observed = BTreeMap::from([("3F00/6F99".to_owned(), seen(Layout::Transparent, 1))]);
        let result = compare(&expected, &observed);
        assert_eq!(result.missing.len(), 1);
        assert_eq!(result.extra, vec!["3F00/6F99".to_owned()]);
        assert_eq!(result.matched, 0);
    }

    #[test]
    fn a_size_or_type_mismatch_is_different() {
        let expected = [
            ef("3F00/2FE2", Layout::Transparent, 10),
            ef("3F00/2F05", Layout::Transparent, 6),
        ];
        let observed = BTreeMap::from([
            ("3F00/2FE2".to_owned(), seen(Layout::Transparent, 12)),
            ("3F00/2F05".to_owned(), dir()),
        ]);
        let result = compare(&expected, &observed);
        assert_eq!(result.different.len(), 2);
        assert_eq!(result.different[0].fields, vec!["size"]);
        assert_eq!(result.different[1].fields, vec!["kind"]);
        let found = findings(&result, None);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|f| f.rule().as_str() == DIFFERENT_RULE));
    }

    #[test]
    fn a_refused_directory_makes_its_children_unverified_not_missing() {
        let expected = [
            df("3F00/7F10"),
            ef("3F00/7F10/6F44", Layout::Transparent, 4),
        ];
        let observed = BTreeMap::from([("3F00/7F10".to_owned(), Observed::Blocked)]);
        let result = compare(&expected, &observed);
        assert_eq!(result.unverified.len(), 2);
        assert!(result.missing.is_empty());
    }

    #[test]
    fn a_field_the_card_did_not_report_is_not_a_difference() {
        let expected = [ef("3F00/2FE2", Layout::Transparent, 10)];
        let observed = BTreeMap::from([(
            "3F00/2FE2".to_owned(),
            Observed::Selected {
                kind: None,
                layout: None,
                size: None,
                record_len: None,
            },
        )]);
        assert_eq!(compare(&expected, &observed).matched, 1);
    }

    /// A tiny package: header, an MF template with one EF, a telecom template
    /// with a DF, a 5Fxx child DF and an EF under each, and a gfm element.
    #[test]
    fn extraction_derives_paths_from_the_templates_and_the_file_manager() {
        fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut out = vec![tag, u8::try_from(body.len()).unwrap()];
            out.extend_from_slice(body);
            out
        }
        let cat = |parts: &[Vec<u8>]| parts.concat();
        let fcp_ef = |fid: [u8; 2], size: u8| {
            tlv(
                0xA1,
                &cat(&[
                    tlv(0x82, &[0x41, 0x21]),
                    tlv(0x83, &fid),
                    tlv(0x8B, &[0x2F, 0x06, 0x01]),
                    tlv(0x80, &[size]),
                ]),
            )
        };
        let fcp_df = |fid: [u8; 2]| {
            tlv(
                0xA1,
                &cat(&[tlv(0x83, &fid), tlv(0x8B, &[0x2F, 0x06, 0x01])]),
            )
        };
        let template = tlv(0x81, &TEMPLATE_ARC);

        let mf = tlv(
            0xB0,
            &cat(&[
                template.clone(),
                tlv(0xA2, &tlv(0xA1, &tlv(0x8B, &[1]))),
                tlv(0xA3, &fcp_ef([0x2F, 0xE2], 10)),
            ]),
        );
        let telecom = tlv(
            0xB2,
            &cat(&[
                template,
                tlv(0xA2, &fcp_df([0x7F, 0x10])),
                tlv(0xA3, &fcp_ef([0x6F, 0x06], 20)),
                tlv(0xA4, &fcp_df([0x5F, 0x50])),
                tlv(0xA5, &fcp_ef([0x4F, 0x20], 10)),
            ]),
        );
        let gfm = tlv(
            0xA1,
            &tlv(
                0xA1,
                &tlv(
                    0x30,
                    &cat(&[
                        tlv(0x80, &[0x7F, 0x10, 0x5F, 0x3A]),
                        tlv(
                            0x62,
                            &cat(&[
                                tlv(0x82, &[0x42, 0x21, 0x00, 0x0D]),
                                tlv(0x83, &[0x4F, 0x09]),
                                tlv(0x80, &[0x1A]),
                            ]),
                        ),
                    ]),
                ),
            ),
        );
        let header = tlv(0xA0, &tlv(0x80, &[2]));
        let der = cat(&[header, mf, telecom, gfm]);

        let files = extract(&der).unwrap();
        let paths: Vec<_> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "3F00/2FE2",
                "3F00/7F10",
                "3F00/7F10/5F3A/4F09",
                "3F00/7F10/5F50",
                "3F00/7F10/5F50/4F20",
                "3F00/7F10/6F06",
            ]
        );
        let record = files.iter().find(|f| f.path.ends_with("4F09")).unwrap();
        assert_eq!(
            (record.layout, record.size, record.record_len),
            (Some(Layout::LinearFixed), Some(0x1A), Some(13))
        );
        assert_eq!(files[0].arr.as_deref(), Some("2F0601"));
    }

    /// Re-derives the fixture from a downloaded copy of the public package.
    ///
    /// ```text
    /// curl -LO https://raw.githubusercontent.com/GSMATerminals/Generic-eUICC-Test-Profile-for-Device-Testing-Public/<commit>/TS48%20V7.0%20eSIM_GTP_SAIP2.3.zip
    /// unzip it into an EMPTY directory (treat it as untrusted data), then:
    /// SIM_DOCTOR_TS48_DER='<dir>/TS48 V7.0 eSIM_GTP_SAIP2.3_NoBERTLV.rename2der' \
    ///   cargo test regenerates_the_fixture -- --ignored          # check
    /// SIM_DOCTOR_TS48_WRITE=1 ...                                # rewrite it
    /// ```
    #[test]
    #[ignore = "needs a downloaded TS.48 SAIP package; see the doc comment"]
    fn regenerates_the_fixture_from_a_downloaded_profile() {
        let der = std::fs::read(std::env::var("SIM_DOCTOR_TS48_DER").expect("SIM_DOCTOR_TS48_DER"))
            .expect("the package is readable");
        let mut fixture = Fixture::bundled().expect("the committed fixture parses");
        fixture.files = extract(&der).expect("the package parses");
        if std::env::var("SIM_DOCTOR_TS48_WRITE").is_ok() {
            let path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/corpus/ts48/ts48-v7.0-files.json"
            );
            std::fs::write(path, fixture.to_text()).expect("fixture written");
            return;
        }
        assert_eq!(fixture.to_text(), FIXTURE, "the committed fixture is stale");
    }
}
