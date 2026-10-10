//! The agent skill: how a coding agent runs `sim-doctor scan --json` and reads the envelope.
//!
//! **Moved.** `sim-doctor install` is the kit's: the files and their bodies are
//! `SimDoctor::agent_files` in `src/kit.rs` (text in `src/skill_body.md`), written and merged
//! (`<!-- sim-doctor:start -->` ... `<!-- sim-doctor:end -->` in `AGENTS.md`) by
//! `doctor_kit::install`. This module keeps its name in [`crate::MODULES`] and, deprecated, the
//! agent enum; `Target`, `targets`, `upsert_block` and `install` are gone.

/// The module's name, as `sim-doctor modules` reports it.
pub const NAME: &str = "skill";

/// An agent we can write guidance for.
#[deprecated(since = "0.4.0", note = "use `doctor_kit::install::Agent`")]
pub use doctor_kit::install::Agent;
