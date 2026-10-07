//! OTA/SMS fuzzing: a bounded TAR x keyset x mechanism sweep.
//!
//! **Owns.** The sweep loop and its bound, built directly on
//! [`crate::tar`]'s envelope builder ([`crate::tar::envelope_exchange_with`])
//! and wire mechanics ([`crate::tar::probe_envelope`]), and the differential
//! ([`crate::tar::Baseline`]) that decides whether a (TAR, keyset, mechanism)
//! triple got a response unlike the one this card gives to combinations it
//! has no opinion about.
//!
//! **Does not own.** APDU discovery - that is [`crate::apdu_scan`], a
//! different scanner entirely; see its module documentation for the
//! SIMTester distinction (`APDUScanner.java` vs `FuzzerFactory.java`) this
//! crate keeps apart. This module is the latter: AGENTS.md 5.2's "Base
//! fuzzer: ~130 TARs x 15 keysets x 16 mechanisms".
//!
//! # Why this reuses `tar.rs` rather than re-deriving the wire format
//!
//! Every fact [`crate::tar`]'s module documentation records about the
//! ENVELOPE protocol - the two-exchange `61 Lc` handshake, draining a pending
//! proactive command before the next probe, abandoning the scan rather than
//! continuing on a mismatched length - applies here unchanged. The only thing
//! an OTA fuzz sweep varies that a TAR audit does not is the keyset and the
//! SPI1/SPI2 "mechanism" octets inside the Command Packet, so [`tar`] exposes
//! that as parameters ([`tar::command_packet_with`],
//! [`tar::envelope_data_with`], [`tar::envelope_exchange_with`]) instead of
//! this module rebuilding the TS 03.48 / TS 23.040 / `D1` chain a second time.
//!
//! # The mechanism table is unverified, and says so
//!
//! AGENTS.md section 2 forbids silent protocol facts. SIMTester's own
//! `FuzzerFactory.java` was **not** read in this session - unlike
//! [`crate::tar`], which cites `TARScanner.java` line for line - so
//! [`MECHANISMS`] is `[U]`: sixteen SPI1/SPI2 combinations chosen to span the
//! bit space [`crate::tar::command_packet`] leaves fixed at zero (ciphering
//! requested or not, Proof-of-Response requested or not, PoR security and PoR
//! mode varied), not sixteen values copied out of SIMTester's own table. A
//! later issue that reads `FuzzerFactory.java` at a pinned commit should
//! replace this table and upgrade this note to `[V]`.
//!
//! # Bounded exactly like `tar.rs`
//!
//! [`MAX_PROBES`] caps one sweep, whatever `--quick` or the TAR selection
//! asks for, for the same reason [`crate::tar::MAX_PROBES`] exists: this tool
//! will not put an unbounded loop behind a flag. A sweep that hit the cap
//! reports [`Audit::is_complete`] as false and marks every finding partial.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "fuzz";

/// The `type` every `fuzz ota` envelope carries.
pub const KIND: &str = "fuzz";

use serde_json::{json, Value};

use crate::apdu::StatusWord;
use crate::session::Policy;
use crate::tar::{self, Baseline, Class, Signature};
use crate::transport::CardSession;

/// The most (TAR, keyset, mechanism) triples one sweep may probe.
///
/// Same number as [`crate::tar::MAX_PROBES`], for the same reason: a bound
/// that is a constant, published, rather than invented per call site.
pub const MAX_PROBES: usize = 4096;

/// The keysets a full sweep probes: `0`..=`14`, fifteen values.
///
/// \[V] AGENTS.md 5.2, citing SIMTester's own base fuzzer: "~130 TARs x 15
/// keysets x 16 mechanisms". [`crate::tar::command_packet_with`] writes
/// `keyset << 4` into both KIC and KID, the same encoding
/// `CommandPacket.setKeyset` uses.
pub const KEYSETS: [u8; 15] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

/// Keysets `--quick` probes: `0`, `1`, `2`.
pub const QUICK_KEYSETS: [u8; 3] = [0, 1, 2];

/// Sixteen (SPI1, SPI2) combinations a full sweep probes.
///
/// `[U]` - see the module documentation's "mechanism table is unverified"
/// section. Spans: SPI1 bit 0 (ciphering requested), and SPI2's PoR-requested
/// bit (0x01) combined with PoR security 0 vs 2 (bits 2-3) and PoR mode 0 vs
/// 1 (bit 5) - the same fields [`crate::tar::SPI2_PROBE`]'s doc comment
/// derives the TAR probe's own fixed value from.
pub const MECHANISMS: [(u8, u8); 16] = [
    (0x00, 0x00),
    (0x00, 0x01),
    (0x00, 0x08),
    (0x00, 0x09),
    (0x00, 0x20),
    (0x00, 0x21),
    (0x00, 0x28),
    (0x00, 0x29),
    (0x01, 0x00),
    (0x01, 0x01),
    (0x01, 0x08),
    (0x01, 0x09),
    (0x01, 0x20),
    (0x01, 0x21),
    (0x01, 0x28),
    (0x01, 0x29),
];

/// Mechanisms `--quick` probes: the first four of [`MECHANISMS`].
pub const QUICK_MECHANISMS: [(u8, u8); 4] =
    [MECHANISMS[0], MECHANISMS[1], MECHANISMS[2], MECHANISMS[3]];

/// TARs a full sweep probes: [`crate::tar::FOCUSED_BANDS`], the same
/// bounded default a TAR audit uses, for the same reason - the full
/// 16 777 216-value space does not fit any budget this tool will ship.
pub fn tars(quick: bool) -> Vec<u32> {
    if quick {
        tar::CALIBRATION_TARS[..5].to_vec()
    } else {
        let (candidates, _) = tar::candidates(&tar::Selection::focused(), tar::MAX_PROBES);
        candidates
    }
}

/// One sweep's selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sweep {
    /// Fewer TARs, keysets and mechanisms, so a run finishes in milliseconds.
    pub quick: bool,
    /// The ENVELOPE class, same meaning as [`crate::tar::Class`].
    pub class: Class,
}

impl Default for Sweep {
    fn default() -> Self {
        Self {
            quick: false,
            class: Class::Etsi,
        }
    }
}

/// One (TAR, keyset, mechanism) probe and what the card said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The TAR probed.
    pub tar: u32,
    /// The keyset probed.
    pub keyset: u8,
    /// The (SPI1, SPI2) mechanism probed.
    pub mechanism: (u8, u8),
    /// Whether the card's answer differed from its baseline answer.
    pub accepted: bool,
    /// The status word the card answered with, when it gave one.
    pub status: Option<StatusWord>,
}

impl Probe {
    fn to_json(&self) -> Value {
        json!({
            "tar": tar::hex(self.tar),
            "tar_decimal": self.tar,
            "keyset": self.keyset,
            "mechanism": { "spi1": format!("{:02X}", self.mechanism.0), "spi2": format!("{:02X}", self.mechanism.1) },
            "outcome": if self.accepted { "accepted" } else { "refused" },
            "status": self.status.map(|s| s.to_string()),
        })
    }
}

/// Everything one OTA fuzz sweep found, and everything it did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audit {
    /// What was asked for.
    pub sweep: Sweep,
    /// Every triple probed, in probe order.
    pub probes: Vec<Probe>,
    /// The response this card gives to a triple it has no opinion about.
    pub baseline: Baseline,
    /// False when [`MAX_PROBES`] fired with triples left over.
    pub exhausted: bool,
    /// Why the sweep stopped early, when it did.
    pub stopped: Option<String>,
}

impl Audit {
    /// Whether this audit looked at everything it was asked to.
    pub fn is_complete(&self) -> bool {
        self.stopped.is_none() && self.exhausted
    }

    /// The triples the card accepted.
    pub fn accepted(&self) -> impl Iterator<Item = &Probe> {
        self.probes.iter().filter(|probe| probe.accepted)
    }

    /// The `fuzz.ota` block a report carries.
    pub fn to_json(&self) -> Value {
        json!({
            "quick": self.sweep.quick,
            "class": self.sweep.class.id(),
            "max_probes": MAX_PROBES,
            "probed": self.probes.len(),
            "exhausted": self.exhausted,
            "complete": self.is_complete(),
            "stopped": self.stopped,
            "baseline_established": self.baseline.is_established(),
            "accepted": self.accepted().map(Probe::to_json).collect::<Vec<_>>(),
            "probes": self.probes.iter().map(Probe::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Sends one (TAR, keyset, mechanism) triple and reads the signature.
fn probe_triple<S: CardSession + ?Sized>(
    session: &mut S,
    tar: u32,
    keyset: u8,
    mechanism: (u8, u8),
    class: Class,
    policy: &Policy,
) -> Result<Result<(Signature, usize), String>, tar::Error> {
    let (spi1, spi2) = mechanism;
    let Some((opening, data)) = tar::envelope_exchange_with(tar, class, keyset, spi1, spi2) else {
        return Err(tar::Error::UnbuildableEnvelope(
            "the SMS-PP-DOWNLOAD envelope for this triple does not fit a short APDU data field",
        ));
    };
    match tar::probe_envelope(session, &opening, &data, policy) {
        Ok(Ok(reply)) => Ok(Ok((reply.signature, reply.exchanges))),
        Ok(Err(reason)) => Ok(Err(reason)),
        Err(err) => Err(err),
    }
}

/// Runs the OTA/SMS fuzz sweep over one card.
///
/// Bounded twice, same contract as [`crate::tar::audit`]: by `sweep` and by
/// [`MAX_PROBES`]. `interrupt` is polled before every probe including the
/// calibration pass.
pub fn audit<S: CardSession + ?Sized>(
    session: &mut S,
    sweep: Sweep,
    policy: &Policy,
    interrupt: &mut dyn FnMut() -> bool,
) -> Result<Audit, tar::Error> {
    let tar_list = tars(sweep.quick);
    let keysets: &[u8] = if sweep.quick {
        &QUICK_KEYSETS
    } else {
        &KEYSETS
    };
    let mechanisms: &[(u8, u8)] = if sweep.quick {
        &QUICK_MECHANISMS
    } else {
        &MECHANISMS
    };

    // 1. Calibration: the TAR audit's own baseline TARs, at keyset 0 and the
    // first mechanism, which is enough to tell "this card answers everything
    // alike" apart from "this card has an opinion" before the sweep spends
    // its budget finding out triple by triple.
    let mut calibration: Vec<Option<Signature>> = Vec::with_capacity(tar::CALIBRATION_PROBES);
    for &tar_value in &tar::CALIBRATION_TARS {
        if interrupt() {
            break;
        }
        match probe_triple(session, tar_value, 0, mechanisms[0], sweep.class, policy) {
            Ok(Ok((signature, _))) => calibration.push(Some(signature)),
            Ok(Err(_)) => break,
            Err(tar::Error::Transport(_)) => break,
            Err(other) => return Err(other),
        }
    }
    let baseline = Baseline::of(&calibration);

    // 2. The sweep itself, TAR outer, keyset middle, mechanism inner, capped
    // and halted on the first sign the card is not answering coherently -
    // the same "abandon rather than guess" rule tar.rs's probe loop follows.
    let mut probes = Vec::new();
    let mut stopped: Option<String> = None;
    let mut triples_seen = 0usize;
    'sweep: for &tar_value in &tar_list {
        for &keyset in keysets {
            for &mechanism in mechanisms {
                triples_seen += 1;
                if probes.len() == MAX_PROBES {
                    stopped = Some(format!(
                        "the probe budget of {MAX_PROBES} triples was reached"
                    ));
                    break 'sweep;
                }
                if interrupt() {
                    stopped = Some("the sweep was interrupted".to_owned());
                    break 'sweep;
                }
                match probe_triple(session, tar_value, keyset, mechanism, sweep.class, policy) {
                    Ok(Ok((signature, _))) => {
                        let accepted = !baseline.refuses(&signature);
                        probes.push(Probe {
                            tar: tar_value,
                            keyset,
                            mechanism,
                            accepted,
                            status: signature.status(),
                        });
                    }
                    Ok(Err(reason)) => {
                        stopped = Some(format!("the card stopped answering envelopes: {reason}"));
                        break 'sweep;
                    }
                    Err(tar::Error::Transport(reason)) => {
                        stopped = Some(format!(
                            "the reader stopped answering part way through: {reason}"
                        ));
                        break 'sweep;
                    }
                    Err(other) => return Err(other),
                }
            }
        }
    }

    let total_triples = tar_list.len() * keysets.len() * mechanisms.len();
    let exhausted = stopped.is_none() && triples_seen >= total_triples;

    Ok(Audit {
        sweep,
        probes,
        baseline,
        exhausted,
        stopped,
    })
}

/// A namespaced rule ID: `fuzz/ota-mechanism-accepted`.
pub const OTA_MECHANISM_ACCEPTED_RULE: &str = "fuzz/ota-mechanism-accepted";

/// The [`crate::rules::RuleSpec`] for [`OTA_MECHANISM_ACCEPTED_RULE`], so
/// `sim-doctor rules list`/`rules explain` know about it without a card.
pub fn specs() -> Vec<crate::rules::RuleSpec> {
    vec![crate::rules::RuleSpec::new(
        crate::rules::RuleId::new(OTA_MECHANISM_ACCEPTED_RULE).expect("a validated constant"),
        crate::rules::Severity::High,
        "the card answered a (TAR, keyset, mechanism) OTA triple differently from the way it \
         answers triples it has no opinion about, under an explicit opt-in sweep",
    )
    .with_remediation(
        "confirm this TAR/keyset/mechanism combination is one this card is meant to accept; if \
         not, tighten the TAR allow-list or the keyset's SPI requirements and re-run with \
         --i-understand-this-can-brick-the-card against the software card only",
    )]
}

/// Findings for every accepted triple in `audit`.
///
/// One finding per accepted triple, [`crate::rules::Location::tar`] addressed
/// (the TAR is the part of the triple a baseline and a TAR audit both already
/// address), with the keyset and mechanism folded into the message so a
/// reader does not have to cross-reference `data.fuzz.ota.accepted` to know
/// which one fired.
pub fn findings(audit: &Audit) -> Vec<crate::rules::Finding> {
    use crate::rules::{Evidence, Finding, Location, RuleId, Severity};
    let rule = RuleId::new(OTA_MECHANISM_ACCEPTED_RULE).expect("a validated constant");
    let mut found: Vec<Finding> = audit
        .accepted()
        .map(|probe| {
            let message = format!(
                "TAR {} accepted a mechanism SPI1={:02X} SPI2={:02X} under keyset {} that \
                 differs from this card's baseline answer",
                tar::hex(probe.tar),
                probe.mechanism.0,
                probe.mechanism.1,
                probe.keyset,
            );
            let evidence = match probe.status {
                Some(status) => Evidence::text(status.to_string()),
                None => Evidence::None,
            };
            Finding::new(
                rule.clone(),
                Severity::High,
                message,
                Location::tar(probe.tar),
                evidence,
            )
        })
        .collect();
    if !audit.is_complete() {
        found = found
            .into_iter()
            .map(|finding| {
                finding.partial(
                    audit
                        .stopped
                        .clone()
                        .unwrap_or_else(|| "the sweep did not finish".to_owned()),
                )
            })
            .collect();
    }
    found
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
        fn cycling(script: &[&[u8]]) -> Self {
            let mut replies: VecDeque<Vec<u8>> = VecDeque::new();
            for _ in 0..2048 {
                for item in script {
                    replies.push_back(item.to_vec());
                }
            }
            Self {
                reader: ReaderName::new("loopback").expect("a reader name"),
                replies: RefCell::new(replies),
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
                .unwrap_or_else(|| vec![0x90, 0x00]))
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// A card like swSIM: it has no notion of a TAR at all and answers every
    /// envelope `61 Lc` then `90 00`, so every probe looks alike and nothing
    /// is reported accepted. Mirrors `tar.rs`'s own fixture-shaped test.
    fn swsim_like() -> Scripted {
        Scripted::cycling(&[&[0x61, 0x3A], &[0x90, 0x00]])
    }

    #[test]
    fn quick_sweep_stays_within_its_own_small_budget() {
        let mut card = swsim_like();
        let audit = audit(
            &mut card,
            Sweep {
                quick: true,
                class: Class::Etsi,
            },
            &Policy::default(),
            &mut || false,
        )
        .unwrap();
        let expected = tars(true).len() * QUICK_KEYSETS.len() * QUICK_MECHANISMS.len();
        assert_eq!(audit.probes.len(), expected);
        assert!(expected < MAX_PROBES);
    }

    #[test]
    fn a_card_with_no_tar_check_reports_nothing_accepted() {
        let mut card = swsim_like();
        let audit = audit(
            &mut card,
            Sweep {
                quick: true,
                class: Class::Etsi,
            },
            &Policy::default(),
            &mut || false,
        )
        .unwrap();
        assert_eq!(audit.accepted().count(), 0);
        assert!(findings(&audit).is_empty());
    }

    #[test]
    fn interrupt_halts_the_sweep_and_marks_it_incomplete() {
        let mut card = swsim_like();
        let mut calls = 0;
        let audit = audit(
            &mut card,
            Sweep {
                quick: false,
                class: Class::Etsi,
            },
            &Policy::default(),
            &mut || {
                calls += 1;
                calls > 40
            },
        )
        .unwrap();
        assert!(!audit.is_complete());
        assert!(audit.stopped.is_some());
    }

    #[test]
    fn full_sweep_never_exceeds_max_probes() {
        let mut card = swsim_like();
        let audit = audit(
            &mut card,
            Sweep {
                quick: false,
                class: Class::Etsi,
            },
            &Policy::default(),
            &mut || false,
        )
        .unwrap();
        assert!(audit.probes.len() <= MAX_PROBES);
    }

    #[test]
    fn specs_register_the_rule_id() {
        let specs = specs();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].id().as_str(), OTA_MECHANISM_ACCEPTED_RULE);
    }
}
