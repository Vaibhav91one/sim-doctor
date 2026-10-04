//! The `pcsc`-backed implementation of [`ReaderProvider`] and [`CardSession`].
//!
//! **Owns.** Talking to the PC/SC layer: establishing a context, listing
//! readers, connecting to the card in one, and moving one buffer of bytes in
//! each direction per [`CardSession::transmit`] call.
//!
//! **Does not own.** Typed APDUs, status words and chaining. This module
//! still cannot see [`crate::apdu`], which is the whole point of the layering:
//! `transport` moves opaque bytes and `apdu` gives them meaning. A caller that
//! has to follow a `61 xx` with a GET RESPONSE does that itself, one layer up.
//!
//! **Why this module is not exercised by the default test run.** The traits
//! are also implemented by a loopback double in the parent module, which is how
//! a plain `cargo test` stays green on a laptop with no reader. This one needs a
//! real card and is only ever exercised by the opt-in `card-fixture` test in
//! `tests/card_fixture.rs`. See `docs/swsim-fixture.md` for how to run it.

use std::ffi::CString;
use std::fmt;

use ::pcsc::{Context, Disposition, Protocols, Scope, ShareMode};

use super::{CardSession, Error, ReaderName, ReaderProvider};

/// How many bytes of response one exchange is allowed to bring back.
///
/// SIM/UICC responses are small: a FCP template, a record, a binary read. The
/// largest thing this layer holds is a few hundred bytes, and [`crate::tlv`]
/// is what reasons about what is in them.
///
/// This is a ceiling, not a buffer to be filled. When the card has more to say
/// than fits, the driver reports [`::pcsc::Error::InsufficientBuffer`] and
/// this returns an error. It deliberately does **not** retry with a larger
/// buffer, because the command has already reached the card and executing it
/// twice is not safe.
const RESPONSE_BUFFER: usize = 512;

/// Enumerates the readers the PC/SC layer can see.
///
/// A unit struct on purpose. [`ReaderProvider::readers`] is an associated
/// function with no receiver, so there is nothing to carry: a PC/SC context is
/// cheap to establish, and this tool establishes one per operation rather than
/// holding a daemon-wide handle that could go stale.
///
/// Compiled but never executed, because it needs a running pcscd:
///
/// ```no_run
/// use sim_doctor::transport::{pcsc::Pcsc, Error, ReaderProvider};
///
/// # fn main() -> Result<(), Error> {
/// for reader in Pcsc::readers()? {
///     println!("{reader}");
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pcsc;

/// A live connection to one card through one reader.
///
/// The [`::pcsc::Card`] is held by value because that handle owns the PC/SC
/// context it was created from; dropping this value releases both.
///
/// `Debug` is written out rather than derived because `pcsc::Card` is an
/// opaque handle and deliberately does not implement it. What is worth seeing
/// in a log is which reader this is bound to and whether it is still open.
pub struct PcscSession {
    reader: ReaderName,
    /// The reader name exactly as the daemon spelled it, because that is the
    /// form [`Context::connect`] needs and re-encoding it cannot be guaranteed
    /// to produce the identical bytes.
    system_name: CString,
    /// `None` once [`CardSession::disconnect`] has run, which is what makes
    /// disconnecting twice a no-op rather than a double release.
    card: Option<::pcsc::Card>,
}

impl fmt::Debug for PcscSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PcscSession")
            .field("reader", &self.reader)
            .field("system_name", &self.system_name)
            .field("connected", &self.card.is_some())
            .finish()
    }
}

impl PcscSession {
    /// Connects to the card in `reader`.
    ///
    /// Shared access is requested rather than exclusive: two tools inspecting
    /// one card at the same time is normal, and a SIM has no locking mechanism
    /// this tool should be inventing.
    ///
    /// T=0 is requested because it is what a SIM speaks and what the swICC
    /// PC/SC driver implements; its `IFDHSetProtocolParameters` returns
    /// `IFD_PROTOCOL_NOT_SUPPORTED` for anything else.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ContextUnavailable`] when no PC/SC context can be
    /// established, [`Error::ReaderUnavailable`] when the reader exists but
    /// the card in it cannot be opened, and [`Error::Driver`] for any other
    /// refusal from the PC/SC layer.
    pub fn open(reader: &ReaderName) -> Result<Self, Error> {
        let context = Context::establish(Scope::System).map_err(|_| Error::ContextUnavailable)?;
        let system_name = CString::new(reader.as_str()).map_err(|_| Error::ReaderUnavailable {
            reader: reader.clone(),
        })?;
        let card = context
            .connect(&system_name, ShareMode::Shared, Protocols::T0)
            .map_err(|error| classify_connect(error, reader))?;
        Ok(Self {
            reader: reader.clone(),
            system_name,
            card: Some(card),
        })
    }

    /// The card's answer-to-reset bytes.
    ///
    /// An ATR is a property of the card and the link, not of the session's
    /// protocol, which is why it is asked for rather than derived. It is worth
    /// logging before anything else: an ATR that is not a SIM ATR is the
    /// fastest way to notice the fixture is wired up wrong.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Disconnected`] once the session has been released, and
    /// otherwise whatever the PC/SC layer reports as [`Error::Driver`].
    pub fn atr(&self) -> Result<Vec<u8>, Error> {
        let card = self.card.as_ref().ok_or_else(|| Error::Disconnected {
            reader: self.reader.clone(),
        })?;
        card.status2_owned()
            .map(|status| status.atr().to_vec())
            .map_err(|error| Error::Driver {
                reader: self.reader.clone(),
                detail: error.to_string(),
            })
    }

    /// The reader name this session was opened with, in the exact form the
    /// PC/SC layer will be asked for it again.
    ///
    /// Exposed so a caller can show an operator the string the daemon uses,
    /// which is not always the same as a display name once the platform
    /// appends a device suffix.
    pub fn system_name(&self) -> &str {
        self.system_name.to_str().unwrap_or_default()
    }
}

impl Drop for PcscSession {
    fn drop(&mut self) {
        // A caller that forgets to disconnect must not leak the handle. The
        // trait makes disconnect idempotent, so this is also the path a clean
        // disconnect() already took when card is None.
        let _ = self.disconnect();
    }
}

impl ReaderProvider for Pcsc {
    fn readers() -> Result<Vec<ReaderName>, Error> {
        let context = Context::establish(Scope::System).map_err(|_| Error::ContextUnavailable)?;
        let names = match context.list_readers_owned() {
            Ok(names) => names,
            // No readers is a normal answer, not a failure: the trait says an
            // empty list means nothing is plugged in, and the caller decides
            // whether that is an error.
            Err(::pcsc::Error::NoReadersAvailable) => return Ok(Vec::new()),
            Err(_) => return Err(Error::ContextUnavailable),
        };
        names
            .into_iter()
            // A driver-supplied name is not UTF-8 on every platform, and
            // ReaderName only promises to hold what it validated.
            .map(|name| ReaderName::new(name.to_string_lossy().into_owned()))
            .collect()
    }
}

impl CardSession for PcscSession {
    fn reader(&self) -> &ReaderName {
        &self.reader
    }

    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
        let card = self.card.as_ref().ok_or_else(|| Error::Disconnected {
            reader: self.reader.clone(),
        })?;
        let mut buffer = [0u8; RESPONSE_BUFFER];
        match card.transmit2(command, &mut buffer) {
            Ok(response) => Ok(response.to_vec()),
            // The command reached the card; only the answer did not fit. Say
            // so rather than silently re-sending it.
            Err((::pcsc::Error::InsufficientBuffer, needed)) => Err(Error::Transmit {
                reader: self.reader.clone(),
                detail: format!(
                    "the card answered with {needed} bytes, which does not fit the \
                     {RESPONSE_BUFFER}-byte transport buffer; the command was already \
                     executed and was not retried"
                ),
            }),
            Err((error, _)) => Err(classify_exchange(error, &self.reader)),
        }
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        let Some(card) = self.card.take() else {
            // Already released. The trait calls this a no-op on purpose so
            // cleanup paths do not have to track state.
            return Ok(());
        };
        match card.disconnect(Disposition::LeaveCard) {
            Ok(()) => Ok(()),
            // The card comes back on failure so the handle is still owned and
            // still gets dropped, rather than being leaked mid-release.
            Err((card, error)) => {
                let failure = classify_exchange(error, &self.reader);
                self.card = Some(card);
                Err(failure)
            }
        }
    }
}

/// Decides what a failed [`Context::connect`] means for a caller.
///
/// Split from [`classify_exchange`] because the two calls fail for different
/// reasons: connecting fails when there is nothing to connect to, transmitting
/// fails when the thing that was there went away.
fn classify_connect(error: ::pcsc::Error, reader: &ReaderName) -> Error {
    match error {
        ::pcsc::Error::UnknownReader
        | ::pcsc::Error::NoReadersAvailable
        | ::pcsc::Error::NoSmartcard
        | ::pcsc::Error::UnknownCard
        | ::pcsc::Error::ReaderUnavailable
        | ::pcsc::Error::RemovedCard
        | ::pcsc::Error::ResetCard
        | ::pcsc::Error::SharingViolation
        | ::pcsc::Error::NotReady
        | ::pcsc::Error::InsufficientBuffer
        | ::pcsc::Error::NotTransacted => Error::ReaderUnavailable {
            reader: reader.clone(),
        },
        other => Error::Driver {
            reader: reader.clone(),
            detail: other.to_string(),
        },
    }
}

/// Decides what a failed exchange means for a caller.
fn classify_exchange(error: ::pcsc::Error, reader: &ReaderName) -> Error {
    match error {
        // The card left, was reset, or the link to it broke. Each of these is
        // "the thing you were talking to is no longer there", which is a
        // different failure from "the command was refused".
        ::pcsc::Error::NoSmartcard
        | ::pcsc::Error::UnknownCard
        | ::pcsc::Error::RemovedCard
        | ::pcsc::Error::ResetCard
        | ::pcsc::Error::UnresponsiveCard
        | ::pcsc::Error::CommError
        | ::pcsc::Error::CommDataLost => Error::CardGone {
            reader: reader.clone(),
        },
        other => Error::Transmit {
            reader: reader.clone(),
            detail: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader the mapping tests pretend to be talking to.
    fn reader() -> ReaderName {
        ReaderName::new("swICC PC/SC IFD Driver v1.2.0 /dev/null 00 00").unwrap()
    }

    /// These are the only tests in this module, and they run in the default
    /// cargo test with no reader present.
    ///
    /// Which transport error a PC/SC code becomes is the part of this module
    /// that can be wrong without anyone noticing: the wire behaviour itself
    /// is only observable against a real card, but the mapping is pure, so it
    /// is checked here.
    #[test]
    fn connect_failures_that_mean_nothing_to_connect_to_become_reader_unavailable() {
        for code in [
            ::pcsc::Error::UnknownReader,
            ::pcsc::Error::NoReadersAvailable,
            ::pcsc::Error::NoSmartcard,
            ::pcsc::Error::UnknownCard,
            ::pcsc::Error::ReaderUnavailable,
            ::pcsc::Error::SharingViolation,
        ] {
            assert!(
                matches!(
                    classify_connect(code, &reader()),
                    Error::ReaderUnavailable { .. }
                ),
                "{code:?} should say the reader is unusable"
            );
        }
    }

    #[test]
    fn an_unmodelled_connect_failure_is_reported_as_the_driver_said_it() {
        // Not flattened into ReaderUnavailable: the point of the catch-all is
        // that an operator can see which PC/SC code actually happened.
        let mapped = classify_connect(::pcsc::Error::ServerTooBusy, &reader());
        match mapped {
            Error::Driver { reader, detail } => {
                assert_eq!(reader, self::reader());
                assert!(!detail.is_empty(), "the driver's own text must survive");
            }
            other => panic!("expected a Driver error, got {other:?}"),
        }
    }

    #[test]
    fn a_card_that_vanished_is_distinguished_from_a_refused_command() {
        // RemovedCard is the normal failure mode when swSIM is killed
        // mid-run, and it must not read as "the card said no".
        for code in [
            ::pcsc::Error::RemovedCard,
            ::pcsc::Error::ResetCard,
            ::pcsc::Error::UnknownCard,
            ::pcsc::Error::NoSmartcard,
            ::pcsc::Error::CommDataLost,
        ] {
            assert!(
                matches!(classify_exchange(code, &reader()), Error::CardGone { .. }),
                "{code:?} should say the card went away"
            );
        }
    }

    #[test]
    fn any_other_exchange_failure_keeps_the_driver_text() {
        let mapped = classify_exchange(::pcsc::Error::ProtoMismatch, &reader());
        assert!(
            matches!(&mapped, Error::Transmit { detail, .. } if !detail.is_empty()),
            "expected a Transmit error carrying detail, got {mapped:?}"
        );
    }
}
