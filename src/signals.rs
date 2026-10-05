//! Turning a real SIGINT into exit code 130, without doing anything unsafe to do it.
//!
//! **Owns.** One atomic flag and one POSIX signal handler. Nothing else. This
//! module does not print, does not choose an exit code, and does not know what
//! an envelope is. AGENTS.md section 3's four numbers belong to
//! [`crate::contract`], and the binary decides what to do with them once this
//! module has told it that a signal arrived.
//!
//! **Does not own.** The interruption *policy*. That is the binary's job (see
//! `run_modules` in `src/main.rs`), because "what does an interrupted run
//! print" is an output-contract question and this module deliberately holds no
//! opinion about output. Keeping the two apart is what lets issue #9 add a
//! `scan` command that checks this flag mid-walk without touching the
//! contract.
//!
//! # Why the handler does nothing but set a flag
//!
//! A signal handler runs on an arbitrary thread, at an arbitrary point, with
//! whatever locks the interrupted code happened to be holding. POSIX requires
//! it to be *async-signal-safe*: it may not allocate, take a lock, write to a
//! stream, format, or do anything that could deadlock against the code it
//! interrupted. The canonical safe shape is exactly this one: the handler
//! performs a single atomic store, and ordinary code polls the result at a
//! checkpoint and unwinds normally. Everything expensive then happens off the
//! signal stack, where unwinding, flushing and destructors all still work.
//!
//! That shape is also why the process exits 130 *itself* rather than dying of
//! the signal. On Unix a process killed by SIGINT reports `code() == None` and
//! `signal() == Some(SIGINT)`; a process that handled SIGINT reports
//! `code() == Some(130)`. `tests/process_contract.rs` asserts the second form,
//! so the test fails if the handler is ever deleted and the default disposition
//! is left to do the work. That is the failure mode this module exists to
//! prevent.
//!
//! # Ordering
//!
//! `SeqCst`, not `Relaxed`. The store happens on whichever thread the kernel
//! picked and the load happens on whichever thread owns the scan, so this is a
//! genuine cross-thread hand-off, and the weaker ordering would be a
//! deliberate bet that the flag cannot be missed. There is no performance
//! argument to make against a single store that happens once per run.
//!
//! # The second Ctrl-C
//!
//! Installing a handler replaces the default disposition, so after this module
//! runs SIGINT no longer kills the process. That is a hazard of its own: an
//! operator mashing Ctrl-C at a wedged card exchange would get nothing back.
//! So the second and every later SIGINT restores `SIG_DFL` and re-raises, which
//! is what would have happened without a handler at all. Both `sigaction` and
//! `raise` are on POSIX's async-signal-safe list, so this costs nothing in
//! safety terms.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "signals";

/// Set by the handler, read at every checkpoint.
///
/// Plain `bool`, not an enum, because the handler must not be able to
/// distinguish states: the only two states the rest of the program cares about
/// are "nothing has happened" and "something has".
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// How many SIGINTs this process has seen, saturating at one.
///
/// `AtomicU8` wraps on overflow in a release build, so a pathological flood of
/// signals must not be able to wrap the count back to zero and make the
/// *first* interrupt look like a later one. Saturating at 1 sidesteps the
/// arithmetic entirely: the only distinction drawn is "zero" against
/// "not zero".
static INTERRUPTS: AtomicU8 = AtomicU8::new(0);

/// What the handler decided to do about one SIGINT.
///
/// Returned as data rather than acted on inside the handler, so that the
/// decision can be unit-tested without raising a signal and so that the
/// handler itself is three lines of match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reaction {
    /// First signal: the flag is set and the run unwinds at its next checkpoint.
    Recorded,
    /// A later signal: put the default disposition back and let it happen.
    Reraise,
}

/// Records one SIGINT and says whether the handler should also re-raise it.
///
/// Called from the signal handler, so it does two atomic operations and
/// nothing else. Deliberately free of `unsafe`, of syscalls beyond the atomics
/// themselves, and of anything that can allocate.
fn record_interrupt() -> Reaction {
    if INTERRUPTS.load(Ordering::SeqCst) == 0 {
        INTERRUPTS.store(1, Ordering::SeqCst);
        INTERRUPTED.store(true, Ordering::SeqCst);
        Reaction::Recorded
    } else {
        Reaction::Reraise
    }
}

/// The installed SIGINT handler.
///
/// Async-signal-safe: it calls `record_interrupt`, which is two atomic loads
/// and stores and nothing else, and on a repeat interrupt two POSIX
/// async-signal-safe calls. No allocation, no lock, no I/O, no unwinding.
extern "C" fn handle_sigint(signal: libc::c_int) {
    match record_interrupt() {
        Reaction::Recorded => {}
        Reaction::Reraise => unsafe { re_raise_with_default_disposition(signal) },
    }
}

/// Builds a `sigaction` whose only settings are the handler and the flags.
///
/// The all-zero starting point matters here. `libc::sigaction` has four fields
/// on Linux glibc (including a `sa_restorer` the kernel fills in) and three on
/// Apple platforms, so a struct literal naming all four does not compile on
/// both. An all-zero `sigaction` is the portable way to spell "no flags, no
/// restorer, and an empty signal mask", which is exactly what both dispositions
/// in this module want: SIGINT is blocked while its own handler runs, so the
/// default action takes effect as soon as the disposition is restored.
fn disposition(handler: libc::sighandler_t, flags: libc::c_int) -> libc::sigaction {
    // SAFETY: an all-zero `sigaction` is a valid action on every unix target
    // libc supports: zero is `SIG_DFL`, an empty `sigset_t` and no flags. Every
    // field the struct has is then set explicitly below except the restorer,
    // which is written by the kernel and not by us.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handler;
    action.sa_flags = flags;
    action
}

/// Restores the default SIGINT disposition and re-raises the signal.
///
/// Only called from inside the handler, on a second or later SIGINT. POSIX
/// lists both `sigaction` and `raise` as async-signal-safe.
///
/// # Safety
///
/// Must only be called from a signal handler, for the signal currently being
/// handled. Calling it from ordinary code would terminate the process, which
/// is the whole point.
unsafe fn re_raise_with_default_disposition(signal: libc::c_int) {
    let default = disposition(libc::SIG_DFL, 0);
    // SAFETY: `default` is a fully initialised `sigaction` whose mask is a
    // valid empty set, and the null third argument asks libc not to write the
    // previous action back out.
    unsafe { libc::sigaction(signal, &default, std::ptr::null_mut()) };
    // SAFETY: raising a signal whose disposition is SIG_DFL terminates the
    // process. If it somehow returns, the run continues as interrupted, which
    // is still a clean outcome: no unwinding happens on the signal stack
    // either way.
    unsafe { libc::raise(signal) };
}

/// Installs the SIGINT handler for this process.
///
/// Call once, early, from `main`. Until it is called SIGINT keeps its default
/// disposition and terminates the process; after it is called SIGINT sets a
/// flag that [`interrupted`] reports and the process decides what to do.
///
/// Replacing an already-installed handler is harmless: `sigaction` overwrites
/// rather than stacks, so calling this twice is not an error.
///
/// # Errors
///
/// Returns [`Error::Install`] if the kernel refuses the disposition. The
/// binary treats that as a diagnostic rather than as a failed run: a tool that
/// cannot be interrupted cleanly still produces correct output, and failing
/// every run would turn one unhappy platform into a total outage.
pub fn install() -> Result<(), Error> {
    // SA_RESTART, not its absence. The handler does nothing except set a
    // flag, so there is no interruption for the kernel to deliver to a
    // blocked syscall; restarting the syscall keeps the meaning of EINTR out
    // of the card code entirely. On a SIM that matters for a second reason:
    // an APDU exchange abandoned half-way can leave the reader and the card
    // disagreeing about which command is in flight. Finishing the transaction
    // and then noticing the flag at the next checkpoint is the safe order.
    let action = disposition(
        handle_sigint as *const () as libc::sighandler_t,
        libc::SA_RESTART,
    );

    // SAFETY: `action` is fully initialised, its mask is a valid empty set,
    // and a null third argument means libc writes nothing back. `sigaction`
    // returning non-zero becomes `Error::Install` below, and the only errno a
    // well-formed SIGINT disposition produces is EFAULT from a bad handler
    // pointer, which a plain `extern "C" fn` cannot be.
    if unsafe { libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) } == 0 {
        Ok(())
    } else {
        Err(Error::Install(std::io::Error::last_os_error()))
    }
}

/// Whether a SIGINT has been delivered since [`install`] was called.
///
/// This is the checkpoint call. Every loop that can run for a while (today's
/// `modules`, tomorrow issue #9's `scan` walk) calls it where stopping is
/// safe, and turns a `true` into [`crate::contract::ExitCode::Interrupted`].
/// Cheap enough to call once per iteration: one atomic load.
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// Everything that can go wrong while installing the interrupt handler.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The kernel refused the SIGINT disposition.
    #[error("the SIGINT handler could not be installed: {0}")]
    Install(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Restores the process-wide state this module's tests mutate.
    ///
    /// There is exactly one such test on purpose: the statics are global to
    /// the test binary and cargo runs test functions on parallel threads, so
    /// two tests poking `INTERRUPTED` would race each other rather than
    /// prove anything.
    fn reset() {
        INTERRUPTS.store(0, Ordering::SeqCst);
        INTERRUPTED.store(false, Ordering::SeqCst);
    }

    #[test]
    fn the_first_signal_is_recorded_and_every_later_one_goes_back_to_the_kernel() {
        reset();
        assert!(!interrupted(), "no signal has been sent yet");

        // The decision half of the handler, called directly. The wiring half
        // - that sigaction really routes SIGINT here - is what
        // tests/process_contract.rs proves, by sending a real signal to a real
        // process and reading its exit status.
        assert_eq!(record_interrupt(), Reaction::Recorded);
        assert!(interrupted());

        for later in 2..=4 {
            assert_eq!(
                record_interrupt(),
                Reaction::Reraise,
                "signal {later} should go back to the default disposition"
            );
            assert!(interrupted(), "the flag never clears");
        }

        reset();
        assert!(!interrupted());
    }
}
