//! A mutation fuzzer for the observational APDU space (issue #134).
//!
//! **Owns.** Generating malformed variations of a fixed set of read-only
//! commands, sending them over a [`CardSession`], recording every APDU with its
//! status word, and raising `fuzz/malformed-command-accepted` when a card
//! answers success to a command its specification says to reject.
//!
//! **Does not own.** APDU discovery ([`crate::apdu_scan`]) or the OTA sweep
//! ([`crate::fuzz`]). Neither is changed by this module.
//!
//! # The allowlist is structural, not a filter
//!
//! A [`Case`] has private fields and its only constructor is [`Case::build`],
//! which takes a [`Kind`]. The INS byte is [`Kind::fixed_ins`] for the six
//! read-only kinds, or one of [`UNASSIGNED_INS`] for [`Kind::UnknownIns`]. No
//! generator path accepts an INS from anywhere else, so the generator cannot
//! produce a command outside [`ALLOWED_INS`] + [`UNASSIGNED_INS`]; nothing is
//! generated and then discarded. [`send_guard`] re-checks every APDU
//! immediately before transmit against the same lists and against [`DENIED`]
//! (defence in depth: if a future edit broke the construction rule the run
//! refuses rather than transmits).
//!
//! # Why each command is in
//!
//! Instruction codes are from ETSI TS 102 221 V17.4.0 Table 10.5 (clause
//! 10.1.2): SELECT `A4`, STATUS `F2`, READ BINARY `B0`, READ RECORD `B2`,
//! GET RESPONSE `C0`; the same values this crate already sends elsewhere
//! ([`crate::apdu_scan::DOCUMENTED_INS`]). The spec's SELECT P1 values are
//! `00 01 03 04 08 09` (Table 11.1); `05`-`07` are used as reserved values.
//!
//! - `A4` SELECT: selects a file or application. Changes only the card's
//!   current-file / current-application state, which is volatile.
//! - `B0` READ BINARY, `B2` READ RECORD: read file content. `B2` with a
//!   "next/previous" mode moves a record pointer, which is volatile too.
//! - `F2` STATUS: returns the current DF's FCP (TS 102 221 clause 11.1.2).
//!   P1 `04` (the terminal will terminate the application, Table 11.8) and
//!   the unassigned `02` are never generated.
//! - `CA`/`CB` GET DATA: a read of a data object, ISO/IEC 7816-4 clause 7.4.
//!   TS 102 221 does not define GET DATA; its `CB` is RETRIEVE DATA (also a
//!   read). Both are reads, so both are allowed.
//! - `C0` GET RESPONSE: fetches pending response bytes (TS 102 221 clause
//!   12.1.1).
//!
//! # Why the rest are out
//!
//! [`DENIED`] lists, with the reason, the instruction codes that change
//! persistent state or consume a counter: PIN verify/change/disable/enable/
//! unblock (retry counters), UPDATE BINARY/RECORD, APPEND/STORE DATA, INCREASE,
//! ACTIVATE/DEACTIVATE FILE (lifecycle), AUTHENTICATE and the GlobalPlatform
//! authentication commands (SQN / key counters), PUT KEY, DELETE, INSTALL,
//! MANAGE CHANNEL (can close channels), and the proactive-command commands.
//! The list is a cross-check of the allowlist, not the thing that makes the
//! generator safe.
//!
//! # Scope of this module
//!
//! Wired only to the replay transport and [`MockCard`]. There is no
//! real-reader code path here; running it against a reader is a follow-up
//! that would sit behind the `fuzz_opt_in` interlock.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "apdu_fuzz";

/// The `type` every `fuzz mutate` envelope carries.
pub const KIND: &str = "apdu_fuzz";

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::apdu::Response;
use crate::transport::{CardSession, Error as TransportError, ReaderName};

/// Largest `--max-cases`. A published constant, as with
/// [`crate::apdu_scan::MAX_PROBES`].
pub const MAX_CASES: usize = 10_000;

/// Default `--max-cases`.
pub const DEFAULT_MAX_CASES: usize = 1_000;

/// Class bytes generated: `00` (TS 102 221 `0X`, channel 0) and `A0` (GSM
/// 11.11). Both use the same INS values for the allowlisted commands. No class
/// with a logical-channel or secure-messaging bit is used.
pub const CLAS: [u8; 2] = [0x00, 0xA0];

/// The INS of every read-only kind. See the module documentation.
pub const ALLOWED_INS: [u8; 7] = [0xA4, 0xB0, 0xB2, 0xF2, 0xCA, 0xCB, 0xC0];

/// INS values with no assignment in TS 102 221 or ISO/IEC 7816-4, used to
/// confirm a card answers `6D00`. `00` and `FF` are the values
/// [`crate::apdu_scan::QUICK_INS`] already treats as never assigned.
pub const UNASSIGNED_INS: [u8; 2] = [0x00, 0xFF];

/// Instruction codes this fuzzer must never send, with the reason.
pub const DENIED: &[(u8, &str)] = &[
    (0x04, "DEACTIVATE FILE: changes file lifecycle state"),
    (0x10, "TERMINAL PROFILE: changes the card's session state"),
    (0x12, "FETCH: consumes a proactive command"),
    (0x14, "TERMINAL RESPONSE: answers a proactive command"),
    (0x20, "VERIFY PIN: decrements a retry counter on failure"),
    (0x24, "CHANGE PIN: writes the PIN; retry counter"),
    (0x26, "DISABLE PIN: writes PIN state; retry counter"),
    (0x28, "ENABLE PIN: writes PIN state; retry counter"),
    (0x2C, "UNBLOCK PIN: decrements the unblock counter"),
    (0x32, "INCREASE: writes a cyclic file"),
    (0x44, "ACTIVATE FILE: changes file lifecycle state"),
    (0x50, "INITIALIZE UPDATE (GlobalPlatform): starts SCP"),
    (0x70, "MANAGE CHANNEL: can close a channel"),
    (0x73, "MANAGE SECURE CHANNEL"),
    (0x75, "TRANSACT DATA"),
    (0x76, "SUSPEND UICC"),
    (0x82, "EXTERNAL AUTHENTICATE: key retry counter"),
    (0x84, "GET CHALLENGE"),
    (
        0x88,
        "AUTHENTICATE: can advance the SQN / consume a counter",
    ),
    (0x89, "AUTHENTICATE (alternate coding)"),
    (0xA2, "SEARCH RECORD"),
    (0xC2, "ENVELOPE: delivers an event or OTA message"),
    (0xD6, "UPDATE BINARY: writes a file"),
    (0xD8, "PUT KEY (GlobalPlatform): writes keys"),
    (0xDC, "UPDATE RECORD: writes a file"),
    (0xE2, "APPEND RECORD / STORE DATA: writes"),
    (0xE4, "DELETE (GlobalPlatform)"),
    (0xE6, "INSTALL (GlobalPlatform)"),
];

/// The denylist reason for `ins`, if it is denied.
pub fn denied(ins: u8) -> Option<&'static str> {
    DENIED.iter().find(|(i, _)| *i == ins).map(|(_, r)| *r)
}

/// The kinds of command the generator can build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// SELECT (`A4`).
    Select,
    /// READ BINARY (`B0`).
    ReadBinary,
    /// READ RECORD (`B2`).
    ReadRecord,
    /// STATUS (`F2`).
    Status,
    /// GET DATA (`CA`/`CB`).
    GetData,
    /// GET RESPONSE (`C0`).
    GetResponse,
    /// An INS from [`UNASSIGNED_INS`].
    UnknownIns,
}

impl Kind {
    /// Every kind, in generation order.
    pub const ALL: [Kind; 7] = [
        Kind::Select,
        Kind::ReadBinary,
        Kind::ReadRecord,
        Kind::Status,
        Kind::GetData,
        Kind::GetResponse,
        Kind::UnknownIns,
    ];

    /// The wire name a report carries.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::ReadBinary => "read-binary",
            Self::ReadRecord => "read-record",
            Self::Status => "status",
            Self::GetData => "get-data",
            Self::GetResponse => "get-response",
            Self::UnknownIns => "unknown-ins",
        }
    }
}

/// splitmix64: a few lines, no dependency, and the sequence is fixed by the
/// algorithm rather than by a crate version, so a seed stays reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn byte(&mut self) -> u8 {
        self.next() as u8
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

/// One generated APDU. Only [`Case::build`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    kind: Kind,
    bytes: Vec<u8>,
    /// Why a conforming card must reject this APDU, when the specification
    /// says so. `None` means the case is only observed.
    reject: Option<&'static str>,
}

/// SELECT P1 values ISO/IEC 7816-4 leaves reserved (RFU).
const SELECT_RFU_P1: [u8; 3] = [0x05, 0x06, 0x07];

impl Case {
    /// The raw APDU.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The kind this case was built as.
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// Why a conforming card must reject this, if the spec says so.
    pub const fn reject_reason(&self) -> Option<&'static str> {
        self.reject
    }

    /// Builds one malformed-or-boundary variation of `kind`. This is the only
    /// way to make a [`Case`]: the INS comes from `kind`, never from `rng`
    /// except to choose among [`UNASSIGNED_INS`].
    fn build(kind: Kind, rng: &mut Rng) -> Self {
        let cla = rng.pick(&CLAS);
        let ins = match kind {
            Kind::Select => 0xA4,
            Kind::ReadBinary => 0xB0,
            Kind::ReadRecord => 0xB2,
            Kind::Status => 0xF2,
            Kind::GetData => rng.pick(&[0xCA, 0xCB]),
            Kind::GetResponse => 0xC0,
            Kind::UnknownIns => rng.pick(&UNASSIGNED_INS),
        };
        let boundary = [0x00u8, 0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF];
        let mut p1 = if rng.below(3) == 0 {
            rng.byte()
        } else {
            rng.pick(&boundary)
        };
        let p2 = if rng.below(3) == 0 {
            rng.byte()
        } else {
            rng.pick(&boundary)
        };
        match kind {
            // STATUS P1 04 (TS 102 221 Table 11.8) tells the card the terminal
            // will terminate the application; 02 is unassigned. Neither is generated.
            Kind::Status if p1 == 0x02 || p1 == 0x04 => p1 = 0x00,
            // Valid-ish SELECT P1 most of the time, RFU values otherwise.
            Kind::Select if rng.below(2) == 0 => {
                p1 = rng.pick(&[0x00, 0x03, 0x04, 0x08, 0x09, 0x05, 0x06, 0x07]);
            }
            Kind::GetResponse if rng.below(2) == 0 => p1 = 0,
            _ => {}
        }
        let p2 = if kind == Kind::GetResponse && rng.below(2) == 0 {
            0
        } else {
            p2
        };

        let mut reject = None;
        let mut tail = Vec::new();
        // 0 case 1, 1 Le only, 2 Lc+data, 3 Lc+data+Le, 4 truncated, 5 oversize
        let shape = rng.below(6);
        let data = |rng: &mut Rng, n: usize| (0..n).map(|_| rng.byte()).collect::<Vec<u8>>();
        match shape {
            0 => tail.push(0x00),
            1 => tail.push(rng.pick(&boundary)),
            2 | 3 => {
                let n = rng.pick(&[1usize, 2, 7, 16, 32, 255]);
                tail.push(n as u8);
                tail.extend(data(rng, n));
                if shape == 3 {
                    tail.push(rng.pick(&boundary));
                }
            }
            4 if kind == Kind::Select => {
                // Lc claims n >= 2 bytes; fewer than n (but at least one) follow.
                let n = rng.pick(&[2usize, 7, 16, 255]);
                let sent = 1 + rng.below(n - 1);
                tail.push(n as u8);
                tail.extend(data(rng, sent));
                reject = Some("SELECT whose data field is shorter than Lc");
            }
            5 if kind == Kind::Select => {
                // Lc claims n; n + 2 or more bytes follow.
                let n = rng.pick(&[1usize, 2, 7, 16]);
                tail.push(n as u8);
                let extra = rng.below(3);
                tail.extend(data(rng, n + 2 + extra));
                reject = Some("SELECT whose data field is longer than Lc");
            }
            _ => tail.push(0x00),
        }

        if reject.is_none() {
            reject = match kind {
                Kind::UnknownIns => Some("an unassigned INS must be refused with 6D00"),
                Kind::Select if SELECT_RFU_P1.contains(&p1) => {
                    Some("SELECT with a reserved P1 value")
                }
                // GET RESPONSE is P1=P2=00 with no data field (ISO/IEC 7816-4
                // clause 7.2.4; swSIM answers anything else 6B00, see
                // Command::get_response).
                Kind::GetResponse if p1 != 0 || p2 != 0 => {
                    Some("GET RESPONSE with a non-zero P1/P2")
                }
                Kind::GetResponse if tail.len() > 1 => Some("GET RESPONSE with a data field"),
                _ => None,
            };
        }

        let mut bytes = vec![cla, ins, p1, p2];
        bytes.extend(tail);
        Self {
            kind,
            bytes,
            reject,
        }
    }
}

/// Why [`send_guard`] refused an APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused(pub String);

/// The last check before transmit. Returns an error for anything not in
/// [`ALLOWED_INS`] / [`UNASSIGNED_INS`], or anything in [`DENIED`].
pub fn send_guard(bytes: &[u8]) -> Result<(), Refused> {
    let Some(&ins) = bytes.get(1) else {
        return Err(Refused("APDU shorter than a header".to_owned()));
    };
    if let Some(reason) = denied(ins) {
        return Err(Refused(format!("INS {ins:02X} is denied: {reason}")));
    }
    if !ALLOWED_INS.contains(&ins) && !UNASSIGNED_INS.contains(&ins) {
        return Err(Refused(format!("INS {ins:02X} is not on the allowlist")));
    }
    if !CLAS.contains(&bytes[0]) {
        return Err(Refused(format!(
            "CLA {:02X} is not on the allowlist",
            bytes[0]
        )));
    }
    Ok(())
}

/// Run parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// PRNG seed; the whole case list is a function of it.
    pub seed: u64,
    /// Cases to send, at most [`MAX_CASES`].
    pub max_cases: usize,
    /// Wall-clock budget for the send loop.
    pub timeout: Option<Duration>,
    /// Stop after the first finding.
    pub stop_on_first_finding: bool,
}

impl Config {
    /// Validates the case cap.
    ///
    /// # Errors
    ///
    /// `max_cases` of zero or above [`MAX_CASES`].
    pub fn new(
        seed: u64,
        max_cases: usize,
        timeout: Option<Duration>,
        stop_on_first_finding: bool,
    ) -> Result<Self, String> {
        if max_cases == 0 || max_cases > MAX_CASES {
            return Err(format!("--max-cases must be between 1 and {MAX_CASES}"));
        }
        Ok(Self {
            seed,
            max_cases,
            timeout,
            stop_on_first_finding,
        })
    }
}

/// The planned case list for `config`: a pure function of the seed and cap.
/// `--dry-run` prints this and sends nothing.
pub fn plan(config: &Config) -> Vec<Case> {
    let mut rng = Rng(config.seed);
    (0..config.max_cases.min(MAX_CASES))
        .map(|i| Case::build(Kind::ALL[i % Kind::ALL.len()], &mut rng))
        .collect()
}

/// One sent APDU and what came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchange {
    /// Position in the plan.
    pub index: usize,
    /// The case that was sent.
    pub case: Case,
    /// The raw response, if the transport returned one.
    pub response: Option<Vec<u8>>,
    /// The transport error, if it did not.
    pub error: Option<String>,
}

impl Exchange {
    fn status(&self) -> Option<(u8, u8)> {
        let r = Response::parse(self.response.as_deref()?).ok()?;
        r.status().map(|s| (s.sw1(), s.sw2()))
    }

    /// Whether the card answered success (`9000`, `61xx`, `91xx`, `9Fxx`).
    pub fn accepted(&self) -> bool {
        matches!(self.status(), Some((0x90, 0x00) | (0x61 | 0x91 | 0x9F, _)))
    }

    fn to_json(&self) -> Value {
        json!({
            "index": self.index,
            "kind": self.case.kind.id(),
            "command": hex::encode(&self.case.bytes),
            "response": self.response.as_ref().map(hex::encode),
            "sw": self.status().map(|(a, b)| format!("{a:02X}{b:02X}")),
            "expect_reject": self.case.reject,
            "error": self.error,
        })
    }
}

/// Everything one run sent and saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// The parameters.
    pub config: Config,
    /// Every APDU sent, in order.
    pub exchanges: Vec<Exchange>,
    /// Why the run ended before the plan did.
    pub stopped: Option<String>,
}

impl Run {
    /// The `apdu_fuzz` block a report carries: parameters plus every APDU/SW.
    pub fn to_json(&self) -> Value {
        json!({
            "dry_run": false,
            "seed": self.config.seed,
            "max_cases": self.config.max_cases,
            "max_cases_limit": MAX_CASES,
            "sent": self.exchanges.len(),
            "exhausted": self.stopped.is_none(),
            "stopped": self.stopped,
            "exchanges": self.exchanges.iter().map(Exchange::to_json).collect::<Vec<_>>(),
        })
    }
}

/// The `--dry-run` report: the planned space, nothing sent.
pub fn plan_json(config: &Config) -> Value {
    let cases = plan(config);
    let by_kind: Vec<Value> = Kind::ALL
        .iter()
        .map(|k| json!({"kind": k.id(), "cases": cases.iter().filter(|c| c.kind == *k).count()}))
        .collect();
    json!({
        "dry_run": true,
        "seed": config.seed,
        "max_cases": config.max_cases,
        "max_cases_limit": MAX_CASES,
        "allowed_ins": ALLOWED_INS.iter().map(|i| format!("{i:02X}")).collect::<Vec<_>>(),
        "unassigned_ins": UNASSIGNED_INS.iter().map(|i| format!("{i:02X}")).collect::<Vec<_>>(),
        "denied_ins": DENIED.iter().map(|(i, r)| json!({"ins": format!("{i:02X}"), "reason": r})).collect::<Vec<_>>(),
        "by_kind": by_kind,
        "planned": cases.iter().enumerate().map(|(i, c)| json!({
            "index": i, "kind": c.kind.id(), "command": hex::encode(&c.bytes),
            "expect_reject": c.reject,
        })).collect::<Vec<_>>(),
    })
}

/// Sends the plan over `session`, one APDU per case, no follow-ups.
///
/// Stops at the cap, at `timeout`, on `interrupt`, on the first transport
/// error, on a [`send_guard`] refusal, or (if asked) on the first finding.
pub fn run<S: CardSession + ?Sized>(
    session: &mut S,
    config: &Config,
    interrupt: &mut dyn FnMut() -> bool,
) -> Run {
    let started = Instant::now();
    let mut out = Run {
        config: *config,
        exchanges: Vec::new(),
        stopped: None,
    };
    for (index, case) in plan(config).into_iter().enumerate() {
        if interrupt() {
            out.stopped = Some("the run was interrupted".to_owned());
            break;
        }
        if config.timeout.is_some_and(|t| started.elapsed() >= t) {
            out.stopped = Some("the --timeout elapsed".to_owned());
            break;
        }
        if let Err(Refused(why)) = send_guard(&case.bytes) {
            out.stopped = Some(format!("refused to send: {why}"));
            break;
        }
        let (response, error) = match session.transmit(&case.bytes) {
            Ok(r) => (Some(r), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let failed = error.is_some();
        out.exchanges.push(Exchange {
            index,
            case,
            response,
            error,
        });
        if failed {
            out.stopped = Some("the transport failed; stopped with the results so far".to_owned());
            break;
        }
        if config.stop_on_first_finding && out.exchanges.last().is_some_and(is_finding) {
            out.stopped = Some("stopped at the first finding".to_owned());
            break;
        }
    }
    out
}

fn is_finding(e: &Exchange) -> bool {
    e.case.reject.is_some() && e.accepted()
}

/// A namespaced rule ID: `fuzz/malformed-command-accepted`.
pub const MALFORMED_ACCEPTED_RULE: &str = "fuzz/malformed-command-accepted";

/// This module's [`crate::rules::RuleSpec`]s.
pub fn specs() -> Vec<crate::rules::RuleSpec> {
    vec![crate::rules::RuleSpec::new(
        crate::rules::RuleId::new(MALFORMED_ACCEPTED_RULE).expect("a validated constant"),
        crate::rules::Severity::Medium,
        "the card answered success to an APDU its specification says to reject (an unassigned \
         INS, a reserved SELECT P1, a SELECT whose data length disagrees with Lc, or a GET \
         RESPONSE with parameters)",
    )
    .with_remediation(
        "report the exchange to the card vendor; a card that accepts malformed input is \
         not validating it, and the same parser sees OTA-delivered commands",
    )
    .with_cwe("CWE-20")
    .with_reference("ISO/IEC 7816-4 clauses 5.1, 7.1, 7.2.4; ETSI TS 102 221 clause 10")]
}

/// One finding per accepted-but-malformed exchange.
pub fn findings(run: &Run) -> Vec<crate::rules::Finding> {
    use crate::rules::{Evidence, Finding, Location, RuleId, Severity};
    let rule = RuleId::new(MALFORMED_ACCEPTED_RULE).expect("a validated constant");
    run.exchanges
        .iter()
        .filter(|e| is_finding(e))
        .map(|e| {
            let (a, b) = e.status().unwrap_or((0, 0));
            Finding::new(
                rule.clone(),
                Severity::Medium,
                format!(
                    "{} accepted with {a:02X}{b:02X}: {}",
                    e.case.kind.id(),
                    e.case.reject.unwrap_or("")
                ),
                Location::apdu(hex::encode_upper(&e.case.bytes)),
                Evidence::text(format!("{a:02X}{b:02X}")),
            )
        })
        .collect()
}

/// A scripted card for tests and `fuzz mutate --mock`. Not a model of any
/// real card: it validates only what [`Case::build`] marks as rejectable.
#[derive(Debug)]
pub struct MockCard {
    reader: ReaderName,
    /// When set, answers `9000` to every SELECT, malformed or not.
    pub accepts_any_select: bool,
}

impl MockCard {
    /// A mock that rejects every malformed case.
    pub fn strict() -> Self {
        Self {
            reader: ReaderName::new("mock").expect("a fixed valid name"),
            accepts_any_select: false,
        }
    }
}

impl CardSession for MockCard {
    fn reader(&self) -> &ReaderName {
        &self.reader
    }

    fn transmit(&mut self, c: &[u8]) -> Result<Vec<u8>, TransportError> {
        let sw = |a: u8, b: u8| Ok(vec![a, b]);
        let well_formed = c.len() == 5 || {
            let lc = c[4] as usize;
            c.len() == 5 + lc || c.len() == 6 + lc
        };
        match c[1] {
            0xA4 if self.accepts_any_select => sw(0x90, 0x00),
            0xA4 if SELECT_RFU_P1.contains(&c[2]) => sw(0x6A, 0x86),
            0xA4 if !well_formed => sw(0x67, 0x00),
            0xC0 if c[2] != 0 || c[3] != 0 || c.len() > 5 => sw(0x6B, 0x00),
            0xC0 => sw(0x69, 0x85),
            ins if ALLOWED_INS.contains(&ins) => sw(0x90, 0x00),
            _ => sw(0x6D, 0x00),
        }
    }

    fn disconnect(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::replay::Replay;

    fn cfg(seed: u64, n: usize) -> Config {
        Config::new(seed, n, None, false).unwrap()
    }

    #[test]
    fn allowlist_and_denylist_are_disjoint() {
        for ins in ALLOWED_INS.iter().chain(&UNASSIGNED_INS) {
            assert!(denied(*ins).is_none(), "{ins:02X}");
        }
    }

    #[test]
    fn generator_never_emits_anything_outside_the_allowlist_across_many_seeds() {
        for seed in 0..300u64 {
            for case in plan(&cfg(seed, 700)) {
                let b = case.bytes();
                assert!(b.len() >= 5, "{b:02X?}");
                assert!(CLAS.contains(&b[0]), "{b:02X?}");
                assert!(
                    ALLOWED_INS.contains(&b[1]) || UNASSIGNED_INS.contains(&b[1]),
                    "{b:02X?}"
                );
                assert!(denied(b[1]).is_none(), "{b:02X?}");
                // STATUS never announces application termination.
                assert!(
                    !(b[1] == 0xF2 && (b[2] == 0x02 || b[2] == 0x04)),
                    "{b:02X?}"
                );
                assert!(send_guard(b).is_ok());
            }
        }
    }

    #[test]
    fn send_guard_refuses_every_denied_ins_and_unlisted_ones() {
        for (ins, _) in DENIED {
            assert!(send_guard(&[0x00, *ins, 0, 0, 0]).is_err(), "{ins:02X}");
        }
        for ins in 0..=0xFFu8 {
            let listed = ALLOWED_INS.contains(&ins) || UNASSIGNED_INS.contains(&ins);
            assert_eq!(
                send_guard(&[0x00, ins, 0, 0, 0]).is_ok(),
                listed,
                "{ins:02X}"
            );
        }
        assert!(send_guard(&[0x80, 0xA4, 0, 0, 0]).is_err());
    }

    #[test]
    fn cap_is_respected_and_over_cap_is_refused() {
        let mut card = MockCard::strict();
        let run = run(&mut card, &cfg(1, 25), &mut || false);
        assert_eq!(run.exchanges.len(), 25);
        assert!(run.stopped.is_none());
        assert!(Config::new(1, 0, None, false).is_err());
        assert!(Config::new(1, MAX_CASES + 1, None, false).is_err());
        assert_eq!(plan(&cfg(1, MAX_CASES)).len(), MAX_CASES);
    }

    #[test]
    fn same_seed_same_plan_different_seed_different_plan() {
        assert_eq!(plan(&cfg(7, 200)), plan(&cfg(7, 200)));
        assert_ne!(plan(&cfg(7, 200)), plan(&cfg(8, 200)));
    }

    #[test]
    fn timeout_zero_sends_nothing() {
        let mut card = MockCard::strict();
        let c = Config::new(1, 10, Some(Duration::ZERO), false).unwrap();
        let r = run(&mut card, &c, &mut || false);
        assert!(r.exchanges.is_empty());
        assert_eq!(r.stopped.as_deref(), Some("the --timeout elapsed"));
    }

    #[test]
    fn a_strict_card_yields_no_findings_for_a_thousand_cases_across_seeds() {
        for seed in 0..20 {
            let mut card = MockCard::strict();
            let r = run(&mut card, &cfg(seed, 1000), &mut || false);
            assert_eq!(r.exchanges.len(), 1000);
            assert_eq!(findings(&r).len(), 0, "seed {seed}");
        }
    }

    #[test]
    fn a_card_that_accepts_a_malformed_select_becomes_exactly_one_finding() {
        // The malformed SELECT is the 1st (index 0) case of a search over seeds.
        let mut hit = None;
        for seed in 0..500 {
            let plan = plan(&cfg(seed, 1));
            if plan[0].kind() == Kind::Select && plan[0].reject_reason().is_some() {
                hit = Some(seed);
                break;
            }
        }
        let seed = hit.expect("some seed starts with a malformed SELECT");
        let mut lax = MockCard::strict();
        lax.accepts_any_select = true;
        let r = run(&mut lax, &cfg(seed, 1), &mut || false);
        let f = findings(&r);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule().as_str(), MALFORMED_ACCEPTED_RULE);
        // The same case against a strict card is not a finding.
        let r = run(&mut MockCard::strict(), &cfg(seed, 1), &mut || false);
        assert!(findings(&r).is_empty());
    }

    #[test]
    fn stop_on_first_finding_stops() {
        let mut lax = MockCard::strict();
        lax.accepts_any_select = true;
        let c = Config::new(3, 500, None, true).unwrap();
        let r = run(&mut lax, &c, &mut || false);
        assert_eq!(findings(&r).len(), 1);
        assert_eq!(r.stopped.as_deref(), Some("stopped at the first finding"));
    }

    #[test]
    fn a_run_is_reproducible_through_the_replay_transport() {
        let c = cfg(11, 150);
        let first = run(&mut MockCard::strict(), &c, &mut || false);
        let log: String = first
            .exchanges
            .iter()
            .map(|e| {
                format!(
                    "{{\"command\":\"{}\",\"response\":\"{}\"}}\n",
                    hex::encode(e.case.bytes()),
                    hex::encode(e.response.as_ref().unwrap())
                )
            })
            .collect();
        let mut replay = Replay::from_log(&log).unwrap();
        let again = run(&mut replay, &c, &mut || false);
        assert_eq!(first.exchanges, again.exchanges);
        assert_eq!(replay.remaining(), 0);
    }

    #[test]
    fn dry_run_plans_without_a_session() {
        let v = plan_json(&cfg(5, 40));
        assert_eq!(v["dry_run"], json!(true));
        assert_eq!(v["planned"].as_array().unwrap().len(), 40);
    }
}
