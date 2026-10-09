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
//! 7816-4 case 1: `CLA INS 00 00`, no Lc, no data, no Le (on the T=0 wire that
//! is five octets, P3 = 00, see `probe`). That is
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

use crate::apdu::{Command, Header, Response, StatusWord};
use crate::transport::{CardSession, Error as TransportError};

/// The most candidates one discovery run may probe.
///
/// Mirrors [`crate::tar::MAX_PROBES`]: a bound that is a published constant
/// rather than an unbounded loop behind a flag. Level 1's whole space is 256
/// values and fits inside this with room to spare; level 2 over several
/// classes is where the cap actually bites.
pub const MAX_PROBES: usize = 4096;

/// How many times one run re-establishes the session after a transport
/// failure before it stops and reports what it has.
///
/// A fuzzer has to survive a candidate that resets the card or wedges the
/// PC/SC transaction; it must not loop on one either. Each failure is
/// recorded against its own candidate, the session is re-opened, and the run
/// moves on to the NEXT candidate - the failed one is never retried.
pub const MAX_RECONNECTS: usize = 3;

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
    /// The transport failed on this candidate (a card reset, or the PC/SC
    /// layer losing its transaction). A result for the candidate, not a
    /// reason to abort: see [`MAX_RECONNECTS`].
    TransportError,
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
            Self::TransportError => "transport-error",
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
            Self::ClassNotSupported | Self::InsNotSupported | Self::TransportError => None,
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
    /// False when the run stopped before the candidate list ran out:
    /// interrupted, or a transport failure survived [`MAX_RECONNECTS`] times.
    /// Level 1's lists never reach [`MAX_PROBES`], so that cap is never why
    /// this is false; it is published for the same reason
    /// [`crate::tar::Audit`] publishes its own `exhausted` - so a larger
    /// candidate list added later cannot silently start under-reporting.
    pub exhausted: bool,
    /// Why the run stopped early, when it did.
    pub stopped: Option<String>,
    /// How many times the session was re-established after a transport
    /// failure.
    pub reconnects: usize,
    /// The transport error behind each `transport-error` probe, in the
    /// shape `"<candidate hex>: <error>"`, in probe order.
    pub transport_errors: Vec<String>,
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
            "stopped": self.stopped,
            "reconnects": self.reconnects,
            "max_reconnects": MAX_RECONNECTS,
            "transport_errors": self.transport_errors,
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
    /// False when the run stopped before the candidate list ran out.
    pub exhausted: bool,
    /// Why the run stopped early, when it did.
    pub stopped: Option<String>,
    /// How many times the session was re-established after a transport
    /// failure.
    pub reconnects: usize,
    /// The transport error behind each `transport-error` probe, in the
    /// shape `"<candidate hex>: <error>"`, in probe order.
    pub transport_errors: Vec<String>,
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
            "stopped": self.stopped,
            "reconnects": self.reconnects,
            "max_reconnects": MAX_RECONNECTS,
            "transport_errors": self.transport_errors,
            "probes": self.probes.iter().map(|p| p.render("ins")).collect::<Vec<_>>(),
        })
    }
}

/// Sends one CASE 1 header and classifies the answer.
fn probe<S: CardSession + ?Sized>(
    session: &mut S,
    class: u8,
    instruction: u8,
) -> Result<Outcome, TransportError> {
    // A single raw transmit, deliberately NOT crate::session::send. That
    // function may issue a GET RESPONSE or FETCH follow-up, or re-send the
    // command at a different class, for a status word discovery exists to
    // classify in the first place (6E00/6D00) - so going through it would
    // turn one CASE 1 probe into an unpredictable number of exchanges,
    // which is exactly the ENVELOPE-shaped hazard AGENTS.md and tar.rs's
    // module documentation warn about: an extra, unneeded exchange is how a
    // scanner leaves swicc-pcsc unable to track the transaction at all
    // (`transmitting ... failed ... An attempt was made to end a
    // non-existent transaction`, seen in the card-fixture job before this
    // was fixed). Discovery sends exactly one APDU per candidate and reads
    // exactly one response; nothing here drains a 61xx or a 9x.
    let command = Command::case1(Header::new(class, instruction, 0x00, 0x00));
    let mut bytes = command
        .encode()
        .expect("a CASE 1 command has no data field and cannot fail to encode");
    // The session is opened with Protocols::T0 (src/transport/pcsc.rs), and a
    // T=0 command header is always five octets: CLA INS P1 P2 P3. ISO/IEC
    // 7816-3 sends case 1 as P3 = 00 with no data. Every other command this
    // crate sends is at least five octets, which is why only discovery hit
    // this: the swicc-pcsc driver rejected the bare four-octet form on the
    // very first probe ("An attempt was made to end a non-existent
    // transaction"), for every candidate.
    bytes.push(0x00);
    let raw = session.transmit(&bytes)?;
    let status = Response::parse(&raw)
        .ok()
        .and_then(|response| response.status());
    Ok(Outcome::of(status))
}

/// What one sweep over a candidate list produced.
struct Swept {
    probes: Vec<Probe<u8>>,
    stopped: Option<String>,
    reconnects: usize,
    transport_errors: Vec<String>,
}

/// Probes `candidates` in order, surviving transport failures.
///
/// **A fuzzer has to survive exactly this.** A single candidate can reset
/// the card or leave the underlying PC/SC transaction unusable (observed
/// against the real swSIM card: `An attempt was made to end a non-existent
/// transaction`), and a scanner that propagates that as a hard error throws
/// away every finding the run had already made. So a failed probe is
/// recorded as [`Outcome::TransportError`] **for that candidate** rather
/// than aborting, `reconnect` re-establishes the session in place, and the
/// sweep moves on to the NEXT candidate - the failed one is never retried.
/// After [`MAX_RECONNECTS`] re-establishments, or a reconnect that itself
/// fails, the sweep stops and says why; every candidate probed before that
/// is still in the result.
fn sweep<S: CardSession + ?Sized>(
    session: &mut S,
    candidates: Vec<u8>,
    header_for: impl Fn(u8) -> (u8, u8),
    reconnect: &mut dyn FnMut(&mut S) -> Result<(), TransportError>,
    interrupt: &mut dyn FnMut() -> bool,
) -> Swept {
    let mut out = Swept {
        probes: Vec::with_capacity(candidates.len()),
        stopped: None,
        reconnects: 0,
        transport_errors: Vec::new(),
    };
    for candidate in candidates.into_iter().take(MAX_PROBES) {
        if interrupt() {
            out.stopped = Some("the run was interrupted".to_owned());
            break;
        }
        let (class, instruction) = header_for(candidate);
        match probe(session, class, instruction) {
            Ok(outcome) => out.probes.push(Probe { candidate, outcome }),
            Err(error) => {
                out.probes.push(Probe {
                    candidate,
                    outcome: Outcome::TransportError,
                });
                out.transport_errors
                    .push(format!("{candidate:02X}: {error}"));
                if out.reconnects == MAX_RECONNECTS {
                    out.stopped = Some(format!(
                        "the transport failed again after {MAX_RECONNECTS} reconnects; \
                         stopped with the results so far"
                    ));
                    break;
                }
                out.reconnects += 1;
                if let Err(error) = reconnect(session) {
                    out.stopped = Some(format!("the session could not be re-established: {error}"));
                    break;
                }
            }
        }
    }
    out
}

/// Runs CLA discovery (SIMTester's level 1) over one session.
///
/// Bounded by `mode`: [`Mode::Quick`] probes [`QUICK_CLAS`], [`Mode::Full`]
/// probes every CLA `00`..=`FF`. Both fit comfortably under [`MAX_PROBES`].
/// `interrupt` is polled before every probe, same contract as
/// [`crate::tar::audit`]. `reconnect` re-opens the session in place after a
/// transport failure; see [`sweep`] for why one candidate surviving that is
/// the whole point.
pub fn cla_discovery<S: CardSession + ?Sized>(
    session: &mut S,
    mode: Mode,
    reconnect: &mut dyn FnMut(&mut S) -> Result<(), TransportError>,
    interrupt: &mut dyn FnMut() -> bool,
) -> ClaAudit {
    let candidates: Vec<u8> = match mode {
        Mode::Quick => QUICK_CLAS.to_vec(),
        Mode::Full => (0x00..=0xFF).collect(),
    };
    let swept = sweep(session, candidates, |cla| (cla, 0x00), reconnect, interrupt);
    ClaAudit {
        mode,
        exhausted: swept.stopped.is_none(),
        probes: swept.probes,
        stopped: swept.stopped,
        reconnects: swept.reconnects,
        transport_errors: swept.transport_errors,
    }
}

/// Runs CLA+INS discovery (SIMTester's level 2) over one session, for one
/// class.
///
/// `class` is normally one [`cla_discovery`] already found interesting (or
/// not refused), named explicitly rather than inferred, because an operator
/// who already knows their card's class should not have to re-run level 1 to
/// run level 2. [`Mode::Quick`] probes [`QUICK_INS`]; [`Mode::Full`] probes
/// every INS `00`..=`FF`, which still fits under [`MAX_PROBES`] on its own.
/// `reconnect` is [`sweep`]'s, same as [`cla_discovery`].
pub fn ins_discovery<S: CardSession + ?Sized>(
    session: &mut S,
    class: u8,
    mode: Mode,
    reconnect: &mut dyn FnMut(&mut S) -> Result<(), TransportError>,
    interrupt: &mut dyn FnMut() -> bool,
) -> InsAudit {
    let candidates: Vec<u8> = match mode {
        Mode::Quick => QUICK_INS.to_vec(),
        Mode::Full => (0x00..=0xFF).collect(),
    };
    let swept = sweep(
        session,
        candidates,
        |ins| (class, ins),
        reconnect,
        interrupt,
    );
    InsAudit {
        class,
        mode,
        exhausted: swept.stopped.is_none(),
        probes: swept.probes,
        stopped: swept.stopped,
        reconnects: swept.reconnects,
        transport_errors: swept.transport_errors,
    }
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
        )
        .with_cwe("CWE-912")
        .with_reference("ISO/IEC 7816-4 clauses 5.1 and 7.1 (class and instruction bytes)"),
        crate::rules::RuleSpec::new(
            crate::rules::RuleId::new(UNDOCUMENTED_INS_RULE).expect("a validated constant"),
            crate::rules::Severity::Medium,
            "an INS byte outside this crate's documented set reached a handler at a class that \
             accepts commands, rather than being refused with 6D00",
        )
        .with_remediation(
            "confirm this instruction is intentionally exposed on this card; an undocumented \
             instruction a tool can discover is one an attacker can too",
        )
        .with_cwe("CWE-912")
        .with_reference("ISO/IEC 7816-4 clauses 5.1 and 7.1 (class and instruction bytes)"),
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
    fn every_probe_is_a_t0_case_1_header_with_p3_zero_and_no_data() {
        let mut card = Scripted::new(&[&[0x90, 0x00]]);
        let outcome = probe(&mut card, 0x00, 0xA4).unwrap();
        assert_eq!(card.sent.borrow()[0], vec![0x00, 0xA4, 0x00, 0x00, 0x00]);
        assert!(outcome.is_interesting());
    }

    #[test]
    fn class_not_supported_is_classified() {
        let mut card = Scripted::new(&[&[0x6E, 0x00]]);
        let outcome = probe(&mut card, 0xFE, 0x00).unwrap();
        assert_eq!(outcome, Outcome::ClassNotSupported);
        assert_eq!(outcome.id(), "class-not-supported");
    }

    #[test]
    fn ins_not_supported_is_classified() {
        let mut card = Scripted::new(&[&[0x6D, 0x00]]);
        let outcome = probe(&mut card, 0x00, 0xFE).unwrap();
        assert_eq!(outcome, Outcome::InsNotSupported);
    }

    #[test]
    fn anything_else_is_interesting() {
        let mut card = Scripted::new(&[&[0x69, 0x82]]);
        let outcome = probe(&mut card, 0x00, 0xA4).unwrap();
        assert!(outcome.is_interesting());
    }

    /// Does nothing and never fails: the reconnect every test that expects
    /// no transport failure passes.
    fn never_reconnects(_: &mut Scripted) -> Result<(), TransportError> {
        Ok(())
    }

    #[test]
    fn quick_cla_discovery_probes_exactly_the_documented_subset() {
        let replies: Vec<Vec<u8>> = QUICK_CLAS.iter().map(|_| vec![0x6E, 0x00]).collect();
        let script: Vec<&[u8]> = replies.iter().map(|v| v.as_slice()).collect();
        let mut card = Scripted::new(&script);
        let audit = cla_discovery(&mut card, Mode::Quick, &mut never_reconnects, &mut || false);
        assert_eq!(audit.probes.len(), QUICK_CLAS.len());
        assert!(audit.exhausted);
        assert_eq!(audit.interesting().count(), 0);
    }

    #[test]
    fn full_cla_discovery_probes_the_whole_256_value_space() {
        let replies: Vec<Vec<u8>> = (0..=255u16).map(|_| vec![0x6E, 0x00]).collect();
        let script: Vec<&[u8]> = replies.iter().map(|v| v.as_slice()).collect();
        let mut card = Scripted::new(&script);
        let audit = cla_discovery(&mut card, Mode::Full, &mut never_reconnects, &mut || false);
        assert_eq!(audit.probes.len(), 256);
        assert!(audit.exhausted);
    }

    #[test]
    fn interrupt_stops_discovery_early_and_is_not_exhausted() {
        let replies: Vec<Vec<u8>> = (0..=255u16).map(|_| vec![0x6E, 0x00]).collect();
        let script: Vec<&[u8]> = replies.iter().map(|v| v.as_slice()).collect();
        let mut card = Scripted::new(&script);
        let mut probed = 0;
        let audit = cla_discovery(&mut card, Mode::Full, &mut never_reconnects, &mut || {
            probed += 1;
            probed > 3
        });
        assert_eq!(audit.probes.len(), 3);
        assert!(!audit.exhausted);
        assert_eq!(audit.stopped.as_deref(), Some("the run was interrupted"));
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
            &mut never_reconnects,
            &mut || false,
        );
        assert_eq!(audit.class, 0xA0);
        for sent in card.sent.borrow().iter() {
            assert_eq!(sent[0], 0xA0);
        }
        assert_eq!(audit.probes.len(), QUICK_INS.len());
    }

    /// A card that answers with a transport error on one specific INS and
    /// is fine on every other one - the shape of the real swSIM failure this
    /// is a regression test for: a single candidate leaving the PC/SC
    /// transaction unusable, not the card itself.
    struct FailsOnOneIns {
        reader: ReaderName,
        /// `Some(ins)` fails that one INS and answers every other
        /// normally; `None` fails every single probe, modelling a card that
        /// never comes back once the transaction is wedged.
        poison: Option<u8>,
        reconnected: RefCell<usize>,
    }

    impl CardSession for FailsOnOneIns {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }

        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            let fails = match self.poison {
                Some(poison) => command[1] == poison,
                None => true,
            };
            if fails {
                return Err(TransportError::Transmit {
                    reader: self.reader.clone(),
                    detail: "An attempt was made to end a non-existent transaction".to_owned(),
                });
            }
            Ok(vec![0x90, 0x00])
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    #[test]
    fn a_transport_failure_on_one_candidate_is_recorded_and_the_sweep_continues() {
        let mut card = FailsOnOneIns {
            reader: ReaderName::new("loopback").expect("a reader name"),
            poison: Some(QUICK_INS[3]),
            reconnected: RefCell::new(0),
        };
        let audit = ins_discovery(
            &mut card,
            0x00,
            Mode::Quick,
            &mut |c: &mut FailsOnOneIns| {
                *c.reconnected.borrow_mut() += 1;
                Ok(())
            },
            &mut || false,
        );

        // Every candidate was still probed - the poisoned one and everything
        // after it - which is the whole point: one failing INS does not
        // truncate the run.
        assert_eq!(audit.probes.len(), QUICK_INS.len());
        assert!(audit.exhausted, "{:?}", audit.stopped);
        assert_eq!(*card.reconnected.borrow(), 1);
        assert_eq!(audit.reconnects, 1);

        let poisoned = audit
            .probes
            .iter()
            .find(|p| p.candidate == QUICK_INS[3])
            .expect("the poisoned candidate is still in the results");
        assert_eq!(poisoned.outcome, Outcome::TransportError);
        assert_eq!(poisoned.outcome.id(), "transport-error");
        assert_eq!(audit.transport_errors.len(), 1);
        assert!(audit.transport_errors[0].contains("non-existent transaction"));

        // Every other candidate reached its ordinary classification.
        for probe in &audit.probes {
            if probe.candidate != QUICK_INS[3] {
                assert!(probe.outcome.is_interesting(), "{probe:?}");
            }
        }
    }

    #[test]
    fn repeated_transport_failures_stop_the_sweep_after_max_reconnects_and_say_so() {
        let mut card = FailsOnOneIns {
            reader: ReaderName::new("loopback").expect("a reader name"),
            // Every INS fails: a card that never comes back.
            poison: None, // every candidate fails
            reconnected: RefCell::new(0),
        };
        let mut reconnects = 0;
        let audit = ins_discovery(
            &mut card,
            0x00,
            Mode::Quick,
            &mut |_: &mut FailsOnOneIns| {
                reconnects += 1;
                Ok(())
            },
            &mut || false,
        );

        assert!(!audit.exhausted);
        assert_eq!(audit.reconnects, MAX_RECONNECTS);
        assert_eq!(reconnects, MAX_RECONNECTS);
        // MAX_RECONNECTS reconnects means MAX_RECONNECTS + 1 candidates were
        // attempted: the sweep tries once more after the last reconnect
        // before giving up.
        assert_eq!(audit.probes.len(), MAX_RECONNECTS + 1);
        assert!(audit
            .stopped
            .as_deref()
            .expect("a stopped reason")
            .contains("reconnects"));
        // Never retried: every probe names a distinct candidate from QUICK_INS,
        // in order, never the same one twice.
        let seen: Vec<u8> = audit.probes.iter().map(|p| p.candidate).collect();
        assert_eq!(seen, QUICK_INS[..MAX_RECONNECTS + 1]);
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
