//! Precision/recall gate over generated cards (issue #47).
//!
//! Every case is a card built in code (no real dumps, AGENTS.md section 2), run through
//! the same walk -> TAR audit -> rules pipeline `sim-doctor scan` uses, over an in-process
//! `CardSession`. It runs in plain `cargo test` on every OS; no swSIM, no reader.
//! How to add a case or a rule: tests/corpus/README.md.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use sim_doctor::rules::Location;
use sim_doctor::scan::{self, Dialect, Subject};
use sim_doctor::session::Policy;
use sim_doctor::tar::{self, Class, Selection};
use sim_doctor::transport::{CardSession, Error, ReaderName};
use sim_doctor::walk::{self, Candidates, Limits};

// ---------------------------------------------------------------------------
// A generated card
// ---------------------------------------------------------------------------

/// Answers SELECT by path (as swSIM does), GET RESPONSE, and the two-step ENVELOPE of a
/// TAR probe. `msl0` makes TAR 000000 answer `6D 00`; every other TAR gets `94 04`.
struct Card {
    files: HashMap<Vec<u8>, Vec<u8>>,
    queued: VecDeque<Vec<u8>>,
    msl0: bool,
    reader: ReaderName,
}

fn atom(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, u8::try_from(body.len()).unwrap()];
    out.extend_from_slice(body);
    out
}

/// Which FCP tag numbering a generated file is written in.
#[derive(Clone, Copy)]
enum Fcp {
    Swicc,
    Table42,
}

const DIR: [u8; 2] = [0x38, 0x21];
const EF: [u8; 2] = [0x09, 0x21];

impl Card {
    fn new(msl0: bool) -> Self {
        Self {
            files: HashMap::new(),
            queued: VecDeque::new(),
            msl0,
            reader: ReaderName::new("corpus card").unwrap(),
        }
    }

    /// Adds `path` (`3F00/7F20/6F07`) with an FCP in `dialect`; `size` None for a directory.
    fn file(mut self, path: &str, dialect: Fcp, size: Option<u16>) -> Self {
        let ids: Vec<u8> = path
            .split('/')
            .flat_map(|s| u16::from_str_radix(s, 16).unwrap().to_be_bytes())
            .collect();
        let leaf = &ids[ids.len() - 2..];
        let (size_tag, desc_tag, id_tag) = match dialect {
            Fcp::Swicc => (0x80, 0x82, 0x83),
            Fcp::Table42 => (0x82, 0x83, 0x84),
        };
        let mut body = Vec::new();
        if let Some(size) = size {
            body.extend(atom(size_tag, &size.to_be_bytes()));
        }
        body.extend(atom(desc_tag, if size.is_some() { &EF } else { &DIR }));
        body.extend(atom(id_tag, leaf));
        self.files.insert(ids.clone(), atom(0x62, &body));
        self
    }

    fn target(&self, command: &[u8]) -> Vec<u8> {
        let body = command.get(5..).unwrap_or_default();
        if command.get(2) == Some(&0x08) {
            let mut path = vec![0x3F, 0x00];
            path.extend_from_slice(body);
            return path;
        }
        self.files
            .keys()
            .find(|p| p.len() >= 2 && p[p.len() - 2..] == *body)
            .cloned()
            .unwrap_or_else(|| body.to_vec())
    }
}

impl CardSession for Card {
    fn reader(&self) -> &ReaderName {
        &self.reader
    }

    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
        match command.get(1) {
            Some(0xC0) => Ok(match self.queued.pop_front() {
                Some(mut body) => {
                    body.extend_from_slice(&[0x90, 0x00]);
                    body
                }
                None => vec![0x6F, 0x00],
            }),
            Some(0xA4) => Ok(match self.files.get(&self.target(command)) {
                Some(fcp) => {
                    self.queued.push_back(fcp.clone());
                    vec![0x61, u8::try_from(fcp.len()).unwrap()]
                }
                None => vec![0x6A, 0x82],
            }),
            // ENVELOPE opening: swSIM asks for the data before reading it.
            Some(0xC2) if command.len() == 5 => Ok(vec![0x61, command[4]]),
            // ENVELOPE data field.
            _ => {
                let zero = tar::envelope_data(tar::TAR_MIN, Class::Etsi).unwrap();
                Ok(if self.msl0 && command == zero.as_slice() {
                    vec![0x6D, 0x00]
                } else {
                    vec![0x94, 0x04]
                })
            }
        }
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

struct Case {
    name: &'static str,
    card: Card,
    dialect: Dialect,
    limits: Limits,
    /// (rule ID, location as `Location` displays it) the scan must raise, exactly.
    expected: Vec<(&'static str, String)>,
    /// Whether the walk must finish without hitting a bound.
    complete: bool,
    /// How many files the walk must record.
    nodes: usize,
}

/// The same shape in every case: MF, an EF, a DF with an EF below it.
fn tree(msl0: bool, dialect: Fcp) -> Card {
    let mut card = Card::new(msl0);
    for (path, size) in [
        ("3F00", None),
        ("3F00/2FE2", Some(10)),
        ("3F00/7F20", None),
        ("3F00/7F20/6F07", Some(4)),
    ] {
        card = card.file(path, dialect, size);
    }
    card
}

fn msl0_finding() -> (&'static str, String) {
    (scan::MSL_ZERO_RULE, Location::tar(tar::TAR_MIN).to_string())
}

fn corpus() -> Vec<Case> {
    let case = |name, card, dialect, limits, expected, complete, nodes| Case {
        name,
        card,
        dialect,
        limits,
        expected,
        complete,
        nodes,
    };
    let tight = Limits {
        max_nodes: 2,
        ..Limits::default()
    };
    let (swicc, iso) = (Dialect::Swicc, Dialect::Iec7816_4Table42);
    vec![
        case(
            "clean",
            tree(false, Fcp::Swicc),
            swicc,
            Limits::default(),
            vec![],
            true,
            9,
        ),
        case(
            "msl0",
            tree(true, Fcp::Swicc),
            swicc,
            Limits::default(),
            vec![msl0_finding()],
            true,
            9,
        ),
        case(
            "truncated-walk-msl0",
            tree(true, Fcp::Swicc),
            swicc,
            tight,
            vec![msl0_finding()],
            false,
            2,
        ),
        case(
            "odd-dialect-table42",
            tree(false, Fcp::Table42),
            iso,
            Limits::default(),
            vec![],
            true,
            9,
        ),
        case(
            "odd-dialect-table42-msl0",
            tree(true, Fcp::Table42),
            iso,
            Limits::default(),
            vec![msl0_finding()],
            true,
            9,
        ),
    ]
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// Minimum (precision, recall) per rule. A rule not listed must score 1.0 on both.
/// Lower a number here only with a reason in the PR; never to make a regression pass.
const THRESHOLDS: &[(&str, f64, f64)] = &[];

#[derive(Default, Debug, PartialEq)]
struct Counts {
    tp: usize,
    fp: usize,
    fn_: usize,
}

/// (rule ID, location)
type Found = (String, String);

/// Per-rule counts. Only rules some case expects are scored; the rest are returned
/// separately as warnings, so a rule added elsewhere cannot break the gate before it has cases.
fn tally(runs: &[(Vec<Found>, Vec<Found>)]) -> (BTreeMap<String, Counts>, BTreeSet<String>) {
    let scored: BTreeSet<&str> = runs
        .iter()
        .flat_map(|(expected, _)| expected.iter().map(|f| f.0.as_str()))
        .collect();
    let mut counts: BTreeMap<String, Counts> = BTreeMap::new();
    let mut unscored = BTreeSet::new();
    for (expected, actual) in runs {
        for f in expected {
            let c = counts.entry(f.0.clone()).or_default();
            if actual.contains(f) {
                c.tp += 1;
            } else {
                c.fn_ += 1;
            }
        }
        for f in actual {
            if scored.contains(f.0.as_str()) {
                if !expected.contains(f) {
                    counts.entry(f.0.clone()).or_default().fp += 1;
                }
            } else {
                unscored.insert(f.0.clone());
            }
        }
    }
    (counts, unscored)
}

#[allow(clippy::cast_precision_loss)]
fn ratio(num: usize, den: usize) -> f64 {
    if den == 0 {
        1.0
    } else {
        num as f64 / den as f64
    }
}

/// The table, and whether every rule met its thresholds.
fn report(counts: &BTreeMap<String, Counts>) -> (String, bool) {
    let mut table = format!(
        "{:<28} {:>3} {:>3} {:>3} {:>9} {:>7}\n",
        "rule", "TP", "FP", "FN", "precision", "recall"
    );
    let mut ok = true;
    for (rule, c) in counts {
        let (p, r) = (ratio(c.tp, c.tp + c.fp), ratio(c.tp, c.tp + c.fn_));
        let (min_p, min_r) = THRESHOLDS
            .iter()
            .find(|t| t.0 == rule)
            .map_or((1.0, 1.0), |t| (t.1, t.2));
        let pass = p >= min_p && r >= min_r;
        ok &= pass;
        table += &format!(
            "{rule:<28} {:>3} {:>3} {:>3} {p:>9.2} {r:>7.2}  {}\n",
            c.tp,
            c.fp,
            c.fn_,
            if pass { "ok" } else { "FAIL (below minimum)" }
        );
    }
    (table, ok)
}

/// Runs one case; returns (expected, actual, shape problems).
fn run(mut case: Case) -> (Vec<Found>, Vec<Found>, Vec<String>) {
    let mut problems = Vec::new();
    let options = walk::Options {
        candidates: Candidates::List(
            ["2F01", "2FE2", "6F07", "7F20"]
                .map(|s| s.parse().unwrap())
                .to_vec(),
        ),
        limits: case.limits,
        ..walk::Options::default()
    };
    let tree = walk::walk(&mut case.card, &case.dialect.tag_set(), &options).expect("walk");
    let audit = tar::audit(
        &mut case.card,
        &Selection::focused(),
        &Policy::default(),
        &mut || false,
    )
    .expect("tar audit");
    let found = scan::findings(&Subject {
        tree: &tree,
        tar: &audit,
        scp03: None,
    })
    .expect("rules");

    if tree.is_complete() != case.complete {
        problems.push(format!(
            "{}: walk complete={} expected {}",
            case.name,
            tree.is_complete(),
            case.complete
        ));
    }
    if tree.len() != case.nodes {
        problems.push(format!(
            "{}: walk recorded {} files, expected {}",
            case.name,
            tree.len(),
            case.nodes
        ));
    }
    let actual = found
        .iter()
        .map(|f| (f.rule().as_str().to_owned(), f.location().to_string()))
        .collect();
    let expected = case
        .expected
        .iter()
        .map(|(r, l)| ((*r).to_owned(), l.clone()))
        .collect();
    (expected, actual, problems)
}

#[test]
fn every_rule_meets_its_precision_and_recall_thresholds() {
    let mut runs = Vec::new();
    let mut problems = Vec::new();
    for case in corpus() {
        let (expected, actual, p) = run(case);
        runs.push((expected, actual));
        problems.extend(p);
    }
    let (counts, unscored) = tally(&runs);
    let (table, ok) = report(&counts);

    let registered: BTreeSet<String> = scan::specs()
        .iter()
        .map(|s| s.id().as_str().to_owned())
        .collect();
    for rule in registered
        .iter()
        .filter(|r| !counts.contains_key(*r))
        .chain(unscored.iter())
    {
        eprintln!(
            "warning: rule {rule} has no corpus case (tests/corpus/README.md), so it is not gated"
        );
    }
    assert!(
        problems.is_empty(),
        "corpus case shape drifted:\n{}\n{table}",
        problems.join("\n")
    );
    assert!(ok, "a rule fell below its threshold:\n{table}");
    eprintln!("{table}");
}

#[test]
fn the_gate_fails_on_a_missed_finding_and_on_a_spurious_one() {
    let f = |r: &str| (r.to_owned(), "card".to_owned());
    let (missed, _) = tally(&[(vec![f("a/x")], vec![])]);
    assert!(!report(&missed).1, "a miss must fail on recall");
    let (spurious, _) = tally(&[(vec![f("a/x")], vec![f("a/x")]), (vec![], vec![f("a/x")])]);
    assert!(
        !report(&spurious).1,
        "a false positive must fail on precision"
    );
    let (_, unscored) = tally(&[(vec![], vec![f("b/y")])]);
    assert!(
        unscored.contains("b/y"),
        "a rule with no case is a warning, not a score"
    );
}
