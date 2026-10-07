//! APDU discovery: which CLA and INS values a card answers to at all.
//!
//! **Owns.** Level 1 (CLA discovery) and level 2 (CLA+INS discovery), both
//! bounded, both quick-mode-capable, and the classification of a candidate by
//! its status word.
//!
//! **Does not own.** The OTA/SMS fuzz sweep. AGENTS.md 5.2 records the
//! distinction this module exists to keep: SIMTester's `FuzzerFactory.java` is
//! a fuzzer factory, not an APDU fuzzer factory, and APDU discovery is the
//! separate `APDUScanner.java` (`-sa LEVEL 1` for CLA, `-sal2` for CLA+INS).
//! [`crate::fuzz`] is the former; this module is the latter. Neither module
//! imports the other.
//!
//! # Every probe is a CASE 1 header, and that is deliberate
//!
//! A discovery probe asks one question - "does this CLA/INS pair exist at
//! all" - and a data field or a non-zero P1/P2 would let a command's *parser*
//! answer instead of its dispatcher. So every candidate is sent as ISO/IEC
//! 7816-4 case 1: four octets, `CLA INS 00 00`, no Lc, no data, no Le. That is
//! [`crate::apdu::Command::case1`], and nothing in this module builds any
//! other case.
//!
//! # Classification is the status word's class, not a guess at meaning
//!
//! Three outcomes, read straight off SW1/SW2 and nothing else:
//!
//! - `6E 00` - ISO/IEC 7816-4 clause 9.1: class not supported. The CLA is
//!   refused before the card looks at INS.
//! - `6D 00` - instruction code not supported, or not supported for the
//!   class given. The CLA was accepted; this particular INS was not.
//! - anything else - the pair reached a handler. [`Outcome::Interesting`]
//!   carries whatever status word came back, because "reached a handler" is
//!   the finding regardless of whether that handler then refused for a
//!   different reason (wrong length, wrong state, security condition).
//!
//! No other status word is read as meaning anything beyond this. AGENTS.md
//! section 2 forbids inventing a protocol fact this project has not verified
//! for a specific card, and "this status is something other than refused" is
//! the only claim level 1 and level 2 make.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "apdu_scan";

/// The `type` every `fuzz apdu` envelope carries.
pub const KIND: &str = "apdu_scan";

use serde_json::{json, Value};

use crate::apdu::{Command, Header, StatusWord};
use crate::session::{self, Policy};
use crate::transport::CardSession;

/// The most candidates one discovery run may probe.
///
/// Mirrors [`crate::tar::MAX_PROBES`]: a bound that is a published constant
/// rather than an unbounded loop behind a flag. Level 1's whole space is 256
/// values and fits inside this with room to spare; level 2 over several
/// classes is where the cap actually bites.
pub const MAX_PROBES: usize = 4096;

/// CLA values level 1's quick mode probes.
///
/// **A documented small subset, not a guess.** These are the classes
/// AGENTS.md section 5 and this crate's own code already name: `00` (ISO
/// interindustry), `80` (ETSI proprietary, the class ENVELOPE answers at),
/// `A0` (GSM 11.11), `A4`/`A2` (industry-assigned ranges adjacent to it), and
/// `90`/`94`/`C0` (hit in practice against swSIM - see AGENTS.md's status-word
/// notes). Quick mode exists so an operator - or `card-fixture` CI - can run
/// discovery in milliseconds rather than the 256-probe full sweep.
pub const QUICK_CLAS: [u8; 8] = [0x00, 0x80, 0xA0, 0xA4, 0xA2, 0x90, 0x94, 0xC0];

/// INS values level 2's quick mode probes, within one class.
///
/// A documented small subset: the instructions this crate already sends
/// (`A4` SELECT, `C0` GET RESPONSE, `B0` READ BINARY, `B2` READ RECORD, `F2`
/// STATUS, `CA`/`CB` GET DATA, `12` FETCH, `C2` ENVELOPE) plus a few bare
/// numbers (`00`, `FF`) that are never assigned, so a quick run always has at
/// least one "not supported" data point to contrast against.
pub const QUICK_INS: [u8; 10] = [0x00, 0xA4, 0xC0, 0xB0, 0xB2, 0xF2, 0xCA, 0xCB, 0x12, 0xFF];

/// What a probe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// `6E 00`: the class is not supported.
    ClassNotSupported,
    /// `6D 00`: the instruction is not supported (for this class).
    InsNotSupported,
    /// Anything else, including no status word at all (a procedure byte).
    /// The pair reached something other than the two refusals above.
    Interesting {
        /// The status word, when the card gave one.
        status: Option<StatusWord>,
    },
}

impl Outcome {
    fn of(status: Option<StatusWord>) -> Self {
        match status {
            Some(sw) if sw.sw1() == 0x6E && sw.sw2() == 0x00 => Self::ClassNotSupported,
            Some(sw) if sw.sw1() == 0x6D && sw.sw2() == 0x00 => Self::InsNotSupported,
            status => Self::Interesting { status },
        }
    }

    /// The wire name a report carries.
    pub const fn id(&self) -> &'static str {
        match self {
            Self::ClassNotSupported => "class-not-supported",
            Self::InsNotSupported => "ins-not-supported",
            Self::Interesting { .. } => "interesting",
        }
    }

    /// Whether this is the "reached a handler" outcome.
    pub const fn is_interesting(&self) -> bool {
        matches!(self, Self::Interesting { .. })
    }

    const fn status(&self) -> Option<StatusWord> {
        match self {
            Self::Interesting { status } => *status,
            Self::ClassNotSupported | Self::InsNotSupported => None,
        }
    }
}

/// Which candidates a discovery run probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The documented small subset ([`QUICK_CLAS`] or [`QUICK_INS`]).
    Quick,
    /// The whole 256-value space of the level being run.
    Full,
}

impl Mode {
    /// The wire name a report carries.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Full => "full",
        }
    }
}

/// One candidate's probe, with what is needed to argue about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe<T> {
    /// The candidate probed: a CLA for level 1, an INS for level 2.
    pub candidate: T,
    /// What the card said.
    pub outcome: Outcome,
}

impl Probe<u8> {
    fn render(&self, key: &str) -> Value {
        json!({
            key: format!("{:02X}", self.candidate),
            "outcome": self.outcome.id(),
            "status": self.outcome.status().map(|s| s.to_string()),
        })
    }
}

/// Everything one CLA discovery (level 1) run found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaAudit {
    /// `"quick"` or `"full"`.
    pub mode: Mode,
    /// Every CLA probed, in probe order.
    pub probes: Vec<Probe<u8>>,
    /// False when [`MAX_PROBES`] fired before the mode's candidate list ran
    /// out. Level 1's lists never reach the cap, so this is always true
    /// today; it is published for the same reason [`crate::tar::Audit`]
    /// publishes it - so a future, larger candidate list cannot silently
    /// start under-reporting.
    pub exhausted: bool,
}

impl ClaAudit {
    /// The CLAs that reached a handler rather than being refused outright.
    pub fn interesting(&self) -> impl Iterator<Item = u8> + '_ {
        self.probes
            .iter()
            .filter(|probe| probe.outcome.is_interesting())
            .map(|probe| probe.candidate)
    }

    /// The `apdu_scan.cla` block a report carries.
    pub fn to_json(&self) -> Value {
        json!({
            "mode": self.mode.id(),
            "probed": self.probes.len(),
            "max_probes": MAX_PROBES,
            "exhausted": self.exhausted,
            "probes": self.probes.iter().map(|p| p.render("cla")).collect::<Vec<_>>(),
        })
    }
}

/// Everything one CLA+INS discovery (level 2) run found, for one class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsAudit {
    /// The CLA every probe in this audit was sent at.
    pub class: u8,
    /// `"quick"` or `"full"`.
    pub mode: Mode,
    /// Every INS probed, in probe order.
    pub probes: Vec<Probe<u8>>,
    /// False when [`MAX_PROBES`] fired before the mode's candidate list ran
    /// out.
    pub exhausted: bool,
}

impl InsAudit {
    /// The INS values that reached a handler.
    pub fn interesting(&self) -> impl Iterator<Item = u8> + '_ {
        self.probes
            .iter()
            .filter(|probe| probe.outcome.is_interesting())
            .map(|probe| probe.candidate)
    }

    /// The `apdu_scan.ins` block a report carries.
    pub fn to_json(&self) -> Value {
        json!({
            "class": format!("{:02X}", self.class),
            "mode": self.mode.id(),
            "probed": self.probes.len(),
            "max_probes": MAX_PROBES,
            "exhausted": self.exhausted,
            "probes": self.probes.iter().map(|p| p.render("ins")).collect::<Vec<_>>(),
        })
    }
}

/// Sends one CASE 1 header and classifies the answer.
fn probe<S: CardSession + ?Sized>(
    session: &mut S,
    class: u8,
    instruction: u8,
    policy: &Policy,
) -> Result<Outcome, session::Error> {
    let command = Command::case1(Header::new(class, instruction, 0x00, 0x00));
    let exchange = session::send(session, &command, policy)?;
    Ok(Outcome::of(exchange.status()))
}

/// Runs CLA discovery (SIMTester's level 1) over one session.
///
/// Bounded by `mode`: [`Mode::Quick`] probes [`QUICK_CLAS`], [`Mode::Full`]
/// probes every CLA `00`..=`FF`. Both fit comfortably under [`MAX_PROBES`].
/// `interrupt` is polled before every probe, same contract as
/// [`crate::tar::audit`].
pub fn cla_discovery<S: CardSession + ?Sized>(
    session: &mut S,
    mode: Mode,
    policy: &Policy,
    interrupt: &mut dyn FnMut() -> bool,
) -> Result<ClaAudit, session::Error> {
    let candidates: Vec<u8> = match mode {
        Mode::Quick => QUICK_CLAS.to_vec(),
        Mode::Full => (0x00..=0xFF).collect(),
    };
    let capped: Vec<u8> = candidates.into_iter().take(MAX_PROBES).collect();
    let exhausted = capped.len() <= MAX_PROBES;

    let mut probes = Vec::with_capacity(capped.len());
    for class in capped {
        if interrupt() {
            break;
        }
        let outcome = probe(session, class, 0x00, policy)?;
        probes.push(Probe {
            candidate: class,
            outcome,
        });
    }

    Ok(ClaAudit {
        mode,
        probes,
        exhausted,
    })
}

/// Runs CLA+INS discovery (SIMTester's level 2) over one session, for one
/// class.
///
/// `class` is normally one [`cla_discovery`] already found interesting (or
/// not refused), named explicitly rather than inferred, because an operator
/// who already knows their card's class should not have to re-run level 1 to
/// run level 2. [`Mode::Quick`] probes [`QUICK_INS`]; [`Mode::Full`] probes
/// every INS `00`..=`FF`, which still fits under [`MAX_PROBES`] on its own.
pub fn ins_discovery<S: CardSession + ?Sized>(
    session: &mut S,
    class: u8,
    mode: Mode,
    policy: &Policy,
    interrupt: &mut dyn FnMut() -> bool,
) -> Result<InsAudit, session::Error> {
    let candidates: Vec<u8> = match mode {
        Mode::Quick => QUICK_INS.to_vec(),
        Mode::Full => (0x00..=0xFF).collect(),
    };
    let capped: Vec<u8> = candidates.into_iter().take(MAX_PROBES).collect();
    let exhausted = capped.len() <= MAX_PROBES;

    let mut probes = Vec::with_capacity(capped.len());
    for instruction in capped {
        if interrupt() {
            break;
        }
        let outcome = probe(session, class, instruction, policy)?;
        probes.push(Probe {
            candidate: instruction,
            outcome,
        });
    }

    Ok(InsAudit {
        class,
        mode,
        probes,
        exhausted,
    })
}

/// A CLA this crate already sends on purpose, and so does not count as an
/// undocumented discovery when level 1 finds it interesting.
///
/// `00` (ISO interindustry, GET RESPONSE/SELECT), `80` (ETSI, ENVELOPE) and
/// `A0` (GSM 11.11, this crate's TAR probe's GSM class). Anything else that
/// answers is a CLA nothing in this codebase expected.
pub const DOCUMENTED_CLAS: [u8; 3] = [0x00, 0x80, 0xA0];

/// An (INS) this crate already sends on purpose, within any class, and so
/// does not count as undocumented when level 2 finds it interesting.
///
/// SELECT (`A4`), GET RESPONSE (`C0`), READ BINARY (`B0`), READ RECORD
/// (`B2`), STATUS (`F2`), GET DATA (`CA`/`CB`) - the WORKER_RULES allow-list
/// for what this crate already sends to a live card - plus FETCH (`12`) and
/// ENVELOPE (`C2`), which [`crate::tar`] sends under supervision.
pub const DOCUMENTED_INS: [u8; 9] = [0xA4, 0xC0, 0xB0, 0xB2, 0xF2, 0xCA, 0xCB, 0x12, 0xC2];

/// A namespaced rule ID: `apdu/undocumented-cla-accepted`.
pub const UNDOCUMENTED_CLA_RULE: &str = "apdu/undocumented-cla-accepted";

/// A namespaced rule ID: `apdu/undocumented-ins-accepted`.
pub const UNDOCUMENTED_INS_RULE: &str = "apdu/undocumented-ins-accepted";

/// The [`crate::rules::RuleSpec`]s for this module's two rules, so
/// `sim-doctor rules list`/`rules explain` know about them without a card.
pub fn specs() -> Vec<crate::rules::RuleSpec> {
    vec![
        crate::rules::RuleSpec::new(
            crate::rules::RuleId::new(UNDOCUMENTED_CLA_RULE).expect("a validated constant"),
            crate::rules::Severity::Medium,
            "a CLA byte outside this crate's documented set (00, 80, A0) reached a handler \
             rather than being refused with 6E00",
        )
        .with_remediation(
            "confirm this class is intentionally exposed; an undocumented class a tool can \
             discover is one an attacker can too",
        ),
        crate::rules::RuleSpec::new(
            crate::rules::RuleId::new(UNDOCUMENTED_INS_RULE).expect("a validated constant"),
            crate::rules::Severity::Medium,
            "an INS byte outside this crate's documented set reached a handler at a class that \
             accepts commands, rather than being refused with 6D00",
        )
        .with_remediation(
            "confirm this instruction is intentionally exposed on this card; an undocumented \
             instruction a tool can discover is one an attacker can too",
        ),
    ]
}

/// Findings for every CLA [`ClaAudit`] found interesting and not in
/// [`DOCUMENTED_CLAS`].
pub fn cla_findings(audit: &ClaAudit) -> Vec<crate::rules::Finding> {
    use crate::rules::{Evidence, Finding, Location, RuleId, Severity};
    let rule = RuleId::new(UNDOCUMENTED_CLA_RULE).expect("a validated constant");
    audit
        .interesting()
        .filter(|cla| !DOCUMENTED_CLAS.contains(cla))
        .map(|cla| {
            let status = audit
                .probes
                .iter()
                .find(|p| p.candidate == cla)
                .and_then(|p| p.outcome.status());
            let evidence = match status {
                Some(sw) => Evidence::text(sw.to_string()),
                None => Evidence::None,
            };
            Finding::new(
                rule.clone(),
                Severity::Medium,
                format!("CLA {cla:02X} reached a handler rather than being refused with 6E00"),
                Location::apdu(format!("CLA {cla:02X} 00 00 00")),
                evidence,
            )
        })
        .collect()
}

/// Findings for every INS [`InsAudit`] found interesting and not in
/// [`DOCUMENTED_INS`].
pub fn ins_findings(audit: &InsAudit) -> Vec<crate::rules::Finding> {
    use crate::rules::{Evidence, Finding, Location, RuleId, Severity};
    let rule = RuleId::new(UNDOCUMENTED_INS_RULE).expect("a validated constant");
    audit
        .interesting()
        .filter(|ins| !DOCUMENTED_INS.contains(ins))
        .map(|ins| {
            let status = audit
                .probes
                .iter()
                .find(|p| p.candidate == ins)
                .and_then(|p| p.outcome.status());
            let evidence = match status {
                Some(sw) => Evidence::text(sw.to_string()),
                None => Evidence::None,
            };
            Finding::new(
                rule.clone(),
                Severity::Medium,
                format!(
                    "INS {ins:02X} reached a handler at CLA {:02X} rather than being refused with 6D00",
                    audit.class
                ),
                Location::apdu(format!("CLA {:02X} INS {ins:02X} 00 00", audit.class)),
                evidence,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::collections::VecDeque;

    use crate::transport::{Error as TransportError, ReaderName};

    struct Scripted {
        reader: ReaderName,
        replies: RefCell<VecDeque<Vec<u8>>>,
        sent: RefCell<Vec<Vec<u8>>>,
    }

    impl Scripted {
        fn new(script: &[&[u8]]) -> Self {
            Self {
                reader: ReaderName::new("loopback").expect("a reader name"),
                replies: RefCell::new(script.iter().map(|r| r.to_vec()).collect()),
                sent: RefCell::new(Vec::new()),
            }
        }
    }

    impl CardSession for Scripted {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }

        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.sent.borrow_mut().push(command.to_vec());
            Ok(self
                .replies
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| vec![0x6D, 0x00]))
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    #[test]
    fn every_probe_is_a_bare_four_octet_case_1_header() {
        let mut card = Scripted::new(&[&[0x90, 0x00]]);
        let outcome = probe(&mut card, 0x00, 0xA4, &Policy::default()).unwrap();
        assert_eq!(card.sent.borrow()[0], vec![0x00, 0xA4, 0x00, 0x00]);
        assert!(outcome.is_interesting());
    }

    #[test]
    fn class_not_supported_is_classified() {
        let mut card = Scripted::new(&[&[0x6E, 0x00]]);
        let outcome = probe(&mut card, 0xFE, 0x00, &Policy::default()).unwrap();
        assert_eq!(outcome, Outcome::ClassNotSupported);
        assert_eq!(outcome.id(), "class-not-supported");
    }

    #[test]
    fn ins_not_supported_is_classified() {
        let mut card = Scripted::new(&[&[0x6D, 0x00]]);
        let outcome = probe(&mut card, 0x00, 0xFE, &Policy::default()).unwrap();
        assert_eq!(outcome, Outcome::InsNotSupported);
    }

    #[test]
    fn anything_else_is_interesting() {
        let mut card = Scripted::new(&[&[0x69, 0x82]]);
        let outcome = probe(&mut card, 0x00, 0xA4, &Policy::default()).unwrap();
        assert!(outcome.is_interesting());
    }

    #[test]
    fn quick_cla_discovery_probes_exactly_the_documented_subset() {
        let replies: Vec<Vec<u8>> = QUICK_CLAS.iter().map(|_| vec![0x6E, 0x00]).collect();
        let script: Vec<&[u8]> = replies.iter().map(|v| v.as_slice()).collect();
        let mut card = Scripted::new(&script);
        let audit =
            cla_discovery(&mut card, Mode::Quick, &Policy::default(), &mut || false).unwrap();
        assert_eq!(audit.probes.len(), QUICK_CLAS.len());
        assert!(audit.exhausted);
        assert_eq!(audit.interesting().count(), 0);
    }

    #[test]
    fn full_cla_discovery_probes_the_whole_256_value_space() {
        let replies: Vec<Vec<u8>> = (0..=255u16).map(|_| vec![0x6E, 0x00]).collect();
        let script: Vec<&[u8]> = replies.iter().map(|v| v.as_slice()).collect();
        let mut card = Scripted::new(&script);
        let audit =
            cla_discovery(&mut card, Mode::Full, &Policy::default(), &mut || false).unwrap();
        assert_eq!(audit.probes.len(), 256);
        assert!(audit.exhausted);
    }

    #[test]
    fn interrupt_stops_discovery_early_and_is_not_exhausted() {
        let replies: Vec<Vec<u8>> = (0..=255u16).map(|_| vec![0x6E, 0x00]).collect();
        let script: Vec<&[u8]> = replies.iter().map(|v| v.as_slice()).collect();
        let mut card = Scripted::new(&script);
        let mut probed = 0;
        let audit = cla_discovery(&mut card, Mode::Full, &Policy::default(), &mut || {
            probed += 1;
            probed > 3
        })
        .unwrap();
        assert_eq!(audit.probes.len(), 3);
    }

    #[test]
    fn ins_discovery_sends_the_requested_class_every_time() {
        let replies: Vec<Vec<u8>> = QUICK_INS.iter().map(|_| vec![0x6D, 0x00]).collect();
        let script: Vec<&[u8]> = replies.iter().map(|v| v.as_slice()).collect();
        let mut card = Scripted::new(&script);
        let audit = ins_discovery(
            &mut card,
            0xA0,
            Mode::Quick,
            &Policy::default(),
            &mut || false,
        )
        .unwrap();
        assert_eq!(audit.class, 0xA0);
        for sent in card.sent.borrow().iter() {
            assert_eq!(sent[0], 0xA0);
        }
        assert_eq!(audit.probes.len(), QUICK_INS.len());
    }

    #[test]
    fn documented_lists_are_what_the_rest_of_this_crate_actually_sends() {
        // Pinned so a rename of a documented value cannot drift silently -
        // the same reason `tar::FOCUSED_PROBES` is checked against its own
        // band list.
        assert!(DOCUMENTED_CLAS.contains(&0x00));
        assert!(DOCUMENTED_CLAS.contains(&0x80));
        assert!(DOCUMENTED_CLAS.contains(&0xA0));
        assert!(DOCUMENTED_INS.contains(&0xA4));
        assert!(DOCUMENTED_INS.contains(&0xC0));
    }
}
