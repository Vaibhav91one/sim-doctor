//! Precision/recall gate over generated cards (issue #47).
//!
//! Every case is a card built in code (no real dumps, AGENTS.md section 2), run through
//! the same walk -> TAR audit -> rules pipeline `sim-doctor scan` uses, over an in-process
//! `CardSession`. It runs in plain `cargo test` on every OS; no swSIM, no reader.
//! How to add a case or a rule: tests/corpus/README.md.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use sim_doctor::access;
use sim_doctor::rules::Location;
use sim_doctor::scan::{self, Dialect, Subject};
use sim_doctor::session::Policy;
use sim_doctor::tar::{self, Class, Selection};
use sim_doctor::transport::{CardSession, Error, ReaderName};
use sim_doctor::walk::{self, Candidates, Limits};

// ---------------------------------------------------------------------------
// A generated card
// ---------------------------------------------------------------------------

/// Answers SELECT by path (as swSIM does), GET RESPONSE, and the whole-APDU ENVELOPE of a
/// TAR probe. `msl0` makes TAR 000000 answer `6D 00`; every other TAR gets `94 04`.
struct Card {
    files: HashMap<Vec<u8>, Vec<u8>>,
    /// Records of a linear fixed EF, by path.
    records: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    /// What the last SELECT chose, for READ RECORD.
    current: Vec<u8>,
    queued: VecDeque<Vec<u8>>,
    msl0: bool,
    /// Answers every ENVELOPE `6F 00`, as a card does until it has had a TERMINAL PROFILE.
    generic_envelope: bool,
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
    Ts102221,
}

fn path_bytes(path: &str) -> Vec<u8> {
    path.split('/')
        .flat_map(|s| u16::from_str_radix(s, 16).unwrap().to_be_bytes())
        .collect()
}

const DIR: [u8; 2] = [0x38, 0x21];
const EF: [u8; 2] = [0x09, 0x21];

impl Card {
    fn new(msl0: bool) -> Self {
        Self {
            files: HashMap::new(),
            records: HashMap::new(),
            current: Vec::new(),
            queued: VecDeque::new(),
            msl0,
            generic_envelope: false,
            reader: ReaderName::new("corpus card").unwrap(),
        }
    }

    /// This card answers every ENVELOPE `6F 00` (issue #98).
    fn generic_envelope(mut self) -> Self {
        self.generic_envelope = true;
        self
    }

    /// Adds `path` (`3F00/7F20/6F07`) with an FCP in `dialect`; `size` None for a directory.
    fn file(self, path: &str, dialect: Fcp, size: Option<u16>) -> Self {
        let descriptor = if size.is_some() { EF } else { DIR };
        self.described(path, dialect, size, &descriptor, &[])
    }

    /// `file` with an explicit descriptor and extra FCP atoms (security attributes, PIN status).
    fn described(
        mut self,
        path: &str,
        dialect: Fcp,
        size: Option<u16>,
        descriptor: &[u8],
        extra: &[u8],
    ) -> Self {
        let ids = path_bytes(path);
        let leaf = &ids[ids.len() - 2..];
        let (size_tag, desc_tag, id_tag) = match dialect {
            Fcp::Swicc => (0x80, 0x82, 0x83),
            Fcp::Ts102221 => (0x80, 0x82, 0x83),
        };
        let mut body = Vec::new();
        if let Some(size) = size {
            body.extend(atom(size_tag, &size.to_be_bytes()));
        }
        body.extend(atom(desc_tag, descriptor));
        body.extend(atom(id_tag, leaf));
        body.extend_from_slice(extra);
        self.files.insert(ids.clone(), atom(0x62, &body));
        self
    }

    /// Adds a linear fixed EF.ARR (`path`) holding `records`, each padded with `FF` to 32 octets.
    fn arr(mut self, path: &str, records: &[&[u8]]) -> Self {
        let count = u8::try_from(records.len()).unwrap();
        let descriptor = [0x0A, 0x21, 0x00, 0x20, count];
        self = self.described(
            path,
            Fcp::Ts102221,
            Some(32 * u16::from(count)),
            &descriptor,
            &[],
        );
        let padded = records
            .iter()
            .map(|r| {
                let mut r = r.to_vec();
                r.resize(32, 0xFF);
                r
            })
            .collect();
        self.records.insert(path_bytes(path), padded);
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
            Some(0xB2) => {
                let record = self
                    .records
                    .get(&self.current)
                    .and_then(|r| r.get(usize::from(command[2]).checked_sub(1)?));
                Ok(match record {
                    Some(record) => [record.as_slice(), &[0x90, 0x00]].concat(),
                    None => vec![0x6A, 0x83],
                })
            }
            Some(0xA4) => Ok(match self.files.get(&self.target(command)) {
                Some(fcp) => {
                    self.current = self.target(command);
                    self.queued.push_back(fcp.clone());
                    vec![0x61, u8::try_from(fcp.len()).unwrap()]
                }
                None => vec![0x6A, 0x82],
            }),
            // ENVELOPE as one complete APDU, the way a real reader takes it.
            Some(0xC2) if self.generic_envelope => Ok(vec![0x6F, 0x00]),
            Some(0xC2) => {
                let zero = tar::envelope_data(tar::TAR_MIN, Class::Etsi).unwrap();
                Ok(if self.msl0 && command.get(5..) == Some(zero.as_slice()) {
                    vec![0x6D, 0x00]
                } else {
                    vec![0x94, 0x04]
                })
            }
            _ => Ok(vec![0x6D, 0x00]),
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
    /// The identifiers probed in every directory.
    probe: &'static [&'static str],
}

const BASIC_PROBE: &[&str] = &["2F01", "2FE2", "6F07", "7F20"];
const USIM_PROBE: &[&str] = &[
    "2F06", "6F06", "7FFF", "5F3B", "5F3C", "4F20", "6F07", "6F08", "6F73", "6F7E",
];

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

/// ARR record: READ and UPDATE both ALWays (TS 102 221 annex F: AM_DO `80`, SC_DO `90`).
const ARR_ALWAYS: &[u8] = &[0x80, 0x01, 0x03, 0x90, 0x00];
/// ARR record: READ PIN Appl 1, UPDATE ADM1 (key references 01 and 0A, usage qualifier 08).
const ARR_PIN_ADM: &[u8] = &[
    0x80, 0x01, 0x01, 0xA4, 0x06, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08, 0x80, 0x01, 0x02, 0xA4, 0x06,
    0x83, 0x01, 0x0A, 0x95, 0x01, 0x08,
];
/// ARR record: READ ALWays, UPDATE ADM1.
const ARR_READ_OPEN: &[u8] = &[
    0x80, 0x01, 0x01, 0x90, 0x00, 0x80, 0x01, 0x02, 0xA4, 0x06, 0x83, 0x01, 0x0A, 0x95, 0x01, 0x08,
];

/// `8B` referencing record `record` of the EF.ARR `file`.
fn arr_ref(file: [u8; 2], record: u8) -> Vec<u8> {
    atom(0x8B, &[file[0], file[1], record])
}

/// A PIN status template: PIN Appl 1 and the universal PIN, each enabled or not.
fn pin_status(pin1: bool, universal: bool) -> Vec<u8> {
    let bitmap = u8::from(pin1) << 7 | u8::from(universal) << 6;
    let mut body = atom(0x90, &[bitmap]);
    body.extend(atom(0x83, &[0x01]));
    body.extend(atom(0x95, &[0x08]));
    body.extend(atom(0x83, &[0x11]));
    atom(0xC6, &body)
}

/// A USIM-shaped card: an EF.ARR at the MF, an application directory `7FFF` with its own
/// EF.ARR, and the sensitive EFs of TS 31.102 below it, each with the given FCP atoms.
fn usim(pin: Vec<u8>, efs: &[(&str, Vec<u8>)], arr_mf: &[&[u8]], arr_adf: &[&[u8]]) -> Card {
    let mut card = Card::new(false)
        .file("3F00", Fcp::Ts102221, None)
        .arr("3F00/2F06", arr_mf)
        .described("3F00/7FFF", Fcp::Ts102221, None, &DIR, &pin)
        .arr("3F00/7FFF/6F06", arr_adf)
        .file("3F00/7FFF/5F3B", Fcp::Ts102221, None)
        .file("3F00/7FFF/5F3C", Fcp::Ts102221, None);
    for (path, extra) in efs {
        card = card.described(path, Fcp::Ts102221, Some(9), &EF, extra);
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
        probe: BASIC_PROBE,
    };
    let tight = Limits {
        max_nodes: 2,
        ..Limits::default()
    };
    let (swicc, iso) = (Dialect::Swicc, Dialect::Ts102221);
    let file = |path: &str| Location::selected_file(path).to_string();
    let usim_case = |name, card, expected, nodes| Case {
        name,
        card,
        dialect: iso,
        limits: Limits::default(),
        expected,
        complete: true,
        nodes,
        probe: USIM_PROBE,
    };
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
        // Every envelope answered 6F00: the baseline is withheld (a blind spot), the sweep
        // is not sent, and nothing is raised.
        case(
            "no-terminal-profile-6f00",
            tree(false, Fcp::Swicc).generic_envelope(),
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
            // Two selected files spend the budget of 2; the probe that finds
            // the budget spent is recorded too.
            3,
        ),
        case(
            "dialect-ts-102-221",
            tree(false, Fcp::Ts102221),
            iso,
            Limits::default(),
            vec![],
            true,
            9,
        ),
        case(
            "dialect-ts-102-221-msl0",
            tree(true, Fcp::Ts102221),
            iso,
            Limits::default(),
            vec![msl0_finding()],
            true,
            9,
        ),
        // The access rules (issue #40): every EF's security attributes are in its FCP or
        // in an EF.ARR the scan reads with READ RECORD, never in file contents.
        usim_case(
            "usim-open",
            usim(
                pin_status(false, false),
                &[
                    ("3F00/7FFF/6F07", arr_ref([0x6F, 0x06], 2)),
                    ("3F00/7FFF/6F08", atom(0x8C, &[0x7F, 0, 0, 0, 0, 0, 0, 0])),
                    ("3F00/7FFF/6F73", arr_ref([0x2F, 0x06], 2)),
                    ("3F00/7FFF/6F7E", arr_ref([0x6F, 0x06], 1)),
                    (
                        "3F00/7FFF/5F3B/4F20",
                        atom(
                            0xAB,
                            &[
                                0x80, 0x01, 0x01, 0xA4, 0x06, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08,
                                0x80, 0x01, 0x02, 0x90, 0x00,
                            ],
                        ),
                    ),
                    // 4F20 is only sensitive under 5F3B; below 5F3C it is another EF.
                    (
                        "3F00/7FFF/5F3C/4F20",
                        atom(0x8C, &[0x7F, 0, 0, 0, 0, 0, 0, 0]),
                    ),
                ],
                &[ARR_ALWAYS, ARR_PIN_ADM],
                &[ARR_ALWAYS, ARR_READ_OPEN],
            ),
            vec![
                (scan::PIN1_DISABLED_RULE, file("3F00/7FFF")),
                (scan::SENSITIVE_EF_RULE, file("3F00/7FFF/6F07")),
                (scan::SENSITIVE_EF_RULE, file("3F00/7FFF/6F08")),
                (scan::SENSITIVE_EF_RULE, file("3F00/7FFF/6F7E")),
                (scan::SENSITIVE_EF_RULE, file("3F00/7FFF/5F3B/4F20")),
            ],
            41,
        ),
        usim_case(
            "usim-protected",
            usim(
                pin_status(true, false),
                &[
                    ("3F00/7FFF/6F07", arr_ref([0x6F, 0x06], 2)),
                    ("3F00/7FFF/6F08", atom(0x8C, &[0x03, 0x10, 0x10])),
                    // Points at a record the EF.ARR does not have: unknown, not a finding.
                    ("3F00/7FFF/6F73", arr_ref([0x6F, 0x06], 9)),
                    // Points at an EF.ARR the card does not hold.
                    ("3F00/7FFF/6F7E", arr_ref([0x6F, 0x99], 1)),
                    ("3F00/7FFF/5F3B/4F20", atom(0xAB, ARR_PIN_ADM)),
                ],
                &[ARR_ALWAYS, ARR_PIN_ADM],
                &[ARR_PIN_ADM, ARR_PIN_ADM],
            ),
            vec![],
            41,
        ),
        usim_case(
            "usim-pin1-off-universal-in-use",
            usim(pin_status(false, true), &[], &[ARR_ALWAYS], &[ARR_ALWAYS]),
            vec![],
            41,
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
            case.probe
                .iter()
                .map(|s| s.parse().unwrap())
                .collect::<Vec<_>>(),
        ),
        limits: case.limits,
        ..walk::Options::default()
    };
    let mut tree = walk::walk(&mut case.card, &case.dialect.tag_set(), &options).expect("walk");
    access::resolve(&mut case.card, &mut tree, &Policy::default()).expect("access rules");
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
