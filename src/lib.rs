//! `sim-doctor` as a library: the layers every later feature plugs into.
//!
//! The binary in `src/main.rs` is a thin view over this crate. Nothing here
//! touches a terminal, a reader, or stdout, so the whole tool is drivable
//! headless, which is the agent-first requirement in AGENTS.md section 2. A
//! finding only a human in a terminal can see is a finding that is not done.
//!
//! # Layering
//!
//! Dependencies point one way only: a module may depend on modules listed
//! below it in this table and on nothing else. The table is not aspirational,
//! it is data in [`MODULES`], and a unit test in this file fails if a declared
//! dependency names a module that does not exist.
//!
//! ```text
//! layer 0  tlv        tag, length and value atoms, and a stream over them
//! layer 0  der        strict DER: minimal lengths, definite, certificates only
//! layer 0  apdu       CLA INS P1 P2 and the two-byte status word
//! layer 0  transport  bytes to a card and bytes back
//! layer 0  rules      plugin/rule identifiers and the severity ladder
//! layer 0  contract   JSON envelope and process exit codes
//! layer 0  signals    the SIGINT flag, and when it may be acted on
//! layer 1  fcp        the caller-supplied tag table of a file capabilities
//!                template, and the file metadata read through it
//! layer 1  fs         file identifiers, file kinds and paths over apdu + fcp
//! layer 1  session     typed exchanges: chaining, follow-ups, reassembly
//! layer 1  walk        the DF-tree walk: probe, descend, bound, report
//! layer 1  scan        a walk turned into a report that admits what it missed
//! ```
//!
//! Three consequences worth stating out loud, because later issues will
//! press on all of them:
//!
//! - `transport` does **not** know about `apdu`. The transport moves opaque
//!   bytes; APDU chaining is built one layer up. Issue #10 wants chaining in
//!   the transport, so it belongs in a session facade that composes the two,
//! - `contract` does **not** know about `rules`. The envelope carries
//!   `serde_json::Value`, so once issue #13 adds findings, they are serialized
//!   into it by `rules` rather than wrapped in it. That is what keeps the
//!   envelope shape free to change without dragging the rule model along.
//! - `der` and `tlv` are both layer 0 and neither depends on the other. That
//!   is the structural half of AGENTS.md 4.2: a strict-DER caller cannot
//!   reach the BER path, because there is no path to reach.
//!
//! # What this crate does not contain yet
//!
//! This is Phase 1: module boundaries and the vocabulary that crosses them.
//! Every module doc comment names the issue that fills it in. What is absent
//! on purpose, stated precisely so the list does not rot:
//!
//! - a human-facing session facade over [`session`] (#10). The composition
//!   layer landed with #5: [`session`] chains a long command, follows a
//!   `61 xx` with GET RESPONSE, drains a pending proactive command with FETCH
//!   and reassembles the response. `sim-doctor scan` drives it end to end since
//!   #6, but a command an operator can hold a session open in is still #10's,
//!   and the rule wiring on top of it is #13's,
//! - the `pcsc`-backed transport beyond opening a reader and moving bytes
//!   (#10). [`transport::pcsc`] does establish a context, list readers,
//!   connect and exchange APDUs, which is what issue #4's fixture needs. What
//!   is still missing is the typed encode/decode that makes a session useful
//!   for scanning (#5, landed in [`apdu`]), and the human-facing session
//!   facade (#10, on top of [`session`]).
//! - turning findings into an exit code (#13). Issue #6 landed the
//!   command: `sim-doctor scan` walks a card and reports it, and it exits 0
//!   whenever the walk finished, because there is nothing to threshold yet.
//!   What is still missing is the half that reads a scan's findings and picks
//!   between 0 and 1, which needs rules that produce findings. Until then
//!   `--score`, `--severity`, `--baseline` and `--diff` exist on the surface
//!   and refuse with an honest `"implemented": false` rather than pretending,
//!   which is the AGENTS.md section 3 contract taken literally,
//! - saving a run and comparing it against a later one (#9). [`scan::Deferred`]
//!   is where both halves refuse today,
//! - asking [`scan`] for a candidate set other than the default. The report
//!   states the default's coverage in three places because it can MISS a file,
//!   but `--candidates` does not exist yet, so an operator who needs
//!   certainty has no way to ask for it from the command line. Recorded on
//!   `--max-children` rather than left to be discovered;
//! - findings and the rule registry (#13). [`rules`] has the identifiers and
//!   the severity ladder and no code that produces either,
//! - anything on the non-TLV side of the crypto stack. Issue #11 landed the
//!   BER-TLV stream decoder ([`tlv::Stream`]), the caller-supplied file
//!   capabilities tag table and the file metadata read through it ([`fcp`]),
//!   and the strict DER path as its own type ([`der`]). Still missing: an
//!   SGP.22 BPP builder, and a certificate parser that hands validated bytes
//!   to the `der` crate.

#![deny(missing_docs)]

pub mod apdu;
pub mod contract;
pub mod der;
pub mod fcp;
pub mod fs;
pub mod rules;
pub mod scan;
pub mod session;
pub mod signals;
pub mod tlv;
pub mod transport;
pub mod walk;

/// One module root: what it is called, what it owns, and what it may use.
///
/// This is the layering rule in machine-readable form. It exists so that
/// `sim-doctor modules` can describe the crate without a second hand-written
/// list that drifts, and so that a test can check the graph.
pub struct ModuleInfo {
    /// The module's name, taken from that module's own `NAME` constant so it
    /// cannot be mistyped here.
    pub name: &'static str,
    /// One sentence stating the module's single responsibility.
    pub owns: &'static str,
    /// Modules this one is allowed to depend on. Every entry must name a
    /// module that exists, and layers never point back up.
    pub depends_on: &'static [&'static str],
}

/// Every module root of the crate, lowest layer first.
///
/// Modules with no dependencies come first because they are the ones a later
/// feature can build on without inheriting anyone else's assumptions.
pub const MODULES: &[ModuleInfo] = &[
    ModuleInfo {
        name: tlv::NAME,
        owns: "BER-TLV tag, length and value atoms for ISO 7816-4 files and SGP.22 payloads.",
        depends_on: &[],
    },
    ModuleInfo {
        name: der::NAME,
        owns: "Strict DER for certificates: minimal lengths, definite form, a different type from tlv.",
        depends_on: &[],
    },
    ModuleInfo {
        name: apdu::NAME,
        owns: "The typed ISO 7816-4 command header and the two-byte status word.",
        depends_on: &[],
    },
    ModuleInfo {
        name: transport::NAME,
        owns: "Moving opaque bytes to a card and back over a reader session.",
        depends_on: &[],
    },
    ModuleInfo {
        name: rules::NAME,
        owns: "Namespaced plugin/rule identifiers and the severity ladder.",
        depends_on: &[],
    },
    ModuleInfo {
        name: contract::NAME,
        owns: "The lpac-shaped JSON envelope and the four process exit codes.",
        depends_on: &[],
    },
    ModuleInfo {
        name: signals::NAME,
        owns: "The SIGINT handler: one atomic flag, checked at a checkpoint, that becomes exit code 130.",
        depends_on: &[],
    },
    ModuleInfo {
        name: fcp::NAME,
        owns: "The caller-supplied tag table of a file capabilities template, and the file metadata read through it.",
        depends_on: &[tlv::NAME],
    },
    ModuleInfo {
        name: fs::NAME,
        owns: "File identifiers, file kinds and paths over the card's file system.",
        depends_on: &[apdu::NAME, fcp::NAME],
    },
    ModuleInfo {
        name: session::NAME,
        owns: "Typed exchanges over a card: chaining, follow-ups, reassembly.",
        depends_on: &[apdu::NAME, transport::NAME],
    },
    ModuleInfo {
        name: walk::NAME,
        owns: "The DF-tree walk: select the master file, probe identifiers, descend, and keep absent apart from forbidden.",
        depends_on: &[tlv::NAME, apdu::NAME, transport::NAME, fcp::NAME, fs::NAME, session::NAME],
    },
    ModuleInfo {
        name: scan::NAME,
        owns: "A walk rendered as JSON or prose, carrying the dialect it ran under and every bound it hit.",
        depends_on: &[tlv::NAME, apdu::NAME, fcp::NAME, fs::NAME, walk::NAME],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_module_name_is_unique() {
        let names: Vec<_> = MODULES.iter().map(|m| m.name).collect();
        let unique: HashSet<_> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len(), "duplicate module in MODULES");
    }

    #[test]
    fn every_declared_dependency_is_a_real_module() {
        for module in MODULES {
            for dependency in module.depends_on {
                assert!(
                    MODULES.iter().any(|m| m.name == *dependency),
                    "{} depends on {}, which is not a module root",
                    module.name,
                    dependency
                );
            }
        }
    }

    #[test]
    fn layering_never_points_back_up() {
        // Modules are declared in layer order, so a dependency on a later
        // entry would mean a module reaches back up the stack.
        for (index, module) in MODULES.iter().enumerate() {
            for dependency in module.depends_on {
                let target = MODULES
                    .iter()
                    .position(|m| m.name == *dependency)
                    .expect("checked by every_declared_dependency_is_a_real_module");
                assert!(
                    target < index,
                    "{} depends on {}, which is declared above it",
                    module.name,
                    dependency
                );
            }
        }
    }

    #[test]
    fn contract_and_rules_stay_leaves() {
        // The two layers every other module's types eventually serialize into.
        // If either grows a dependency, the envelope and the rule vocabulary
        // have stopped being independent surfaces.
        for name in [contract::NAME, rules::NAME] {
            let module = MODULES.iter().find(|m| m.name == name).unwrap();
            assert!(module.depends_on.is_empty(), "{} must stay a leaf", name);
        }
    }

    #[test]
    fn every_module_states_its_responsibility() {
        for module in MODULES {
            assert!(
                !module.owns.is_empty(),
                "{} has no stated responsibility",
                module.name
            );
        }
    }
}
