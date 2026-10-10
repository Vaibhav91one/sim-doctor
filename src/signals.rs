//! Turning a real SIGINT into exit code 130: **moved to `doctor_kit::interrupt`**.
//!
//! The handler (one atomic flag, a second signal restores the default disposition and re-raises,
//! `SA_RESTART`) was ported to the kit and is shared with the other doctors; this module keeps
//! the old public names for one minor release. The interruption *policy* (which checkpoints a
//! `scan` has, the watchdog that ends a wedged exchange, what an interrupted envelope holds)
//! stays in `src/main.rs` and `src/kit.rs`: this module never owned it.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "signals";

/// Installs the SIGINT and SIGTERM handlers for this process (idempotent).
#[deprecated(since = "0.4.0", note = "use `doctor_kit::interrupt::install`")]
pub fn install() -> Result<(), Error> {
    doctor_kit::interrupt::install();
    Ok(())
}

/// Whether a SIGINT or SIGTERM has been delivered since [`install`] was called.
#[deprecated(since = "0.4.0", note = "use `doctor_kit::interrupt::interrupted`")]
pub fn interrupted() -> bool {
    doctor_kit::interrupt::interrupted()
}

/// Everything that can go wrong while installing the interrupt handler. Never returned any more:
/// the kit ignores a refusal from the kernel (a run that cannot be interrupted cleanly still
/// produces correct output).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The kernel refused the SIGINT disposition.
    #[error("the SIGINT/SIGTERM handlers could not be installed: {0}")]
    Install(#[source] std::io::Error),
}
