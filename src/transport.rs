//! Card transport: the byte-level boundary between the tool and a card.
//!
//! **Owns.** Finding readers, holding a session open against one card, and
//! moving opaque bytes to that card and back.
//!
//! **Does not own.** Typed APDUs and status words, which are [`crate::apdu`].
//! This module must not depend on it: the transport moves bytes and every
//! layer above moves typed values. It also does not own chaining. Splitting
//! a command across several exchanges, and following a `61xx` or `9xxx`
//! response with GET RESPONSE, is apdu-shaped logic applied one layer up,
//! not a property of a byte pipe. Issue #10 asks for chaining in the
//! transport; it belongs in a session facade that composes the two modules,
//! not in a `transport` that depends on `apdu`.
//!
//! **Lands here now.** [`pcsc`] implements both traits against the real
//! PC/SC layer, added by issue #4 so the swSIM fixture can prove this crate
//! drives a real card. It lives in a submodule rather than in this file
//! because it is the one part of the transport that performs I/O, and keeping
//! it separate is what lets the tests in this file stay runnable with no
//! reader, no daemon and no card.

/// This module's name, as recorded in [`crate::MODULES`].
///
/// Referenced by value rather than re-spelt as a literal so that the module
/// table cannot name a module that does not exist.
pub const NAME: &str = "transport";

pub mod pcsc;

use std::fmt;

/// The name of a PC/SC reader, as the driver reports it.
///
/// Reader names come from the operating system, not from us, so this type
/// validates rather than assumes. An empty name cannot address anything, and
/// a name containing a control character would corrupt the terminal output
/// that every command may print. Rejecting both here keeps the display path
/// safe for every caller.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReaderName(String);

impl ReaderName {
    /// Validates and wraps a driver-supplied reader name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyReaderName`] for an empty name and
    /// [`Error::IllegalReaderNameCharacter`] for any name containing a control
    /// character.
    pub fn new(name: impl Into<String>) -> Result<Self, Error> {
        let name = name.into();
        if name.is_empty() {
            return Err(Error::EmptyReaderName);
        }
        if name.chars().any(|c| c.is_control()) {
            return Err(Error::IllegalReaderNameCharacter { name });
        }
        Ok(Self(name))
    }

    /// Borrows the name as it arrived from the driver.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Enumerates the readers visible to this process.
///
/// Separate from [`CardSession`] because discovery is not a property of a
/// connection: there is no session to ask before one exists. A caller picks a
/// reader by name, then opens a session against it.
pub trait ReaderProvider {
    /// Lists the readers currently visible, in driver order.
    ///
    /// An empty vector is a normal answer meaning "nothing is plugged in".
    /// The caller turns that into [`Error::NoReader`] when it asked for a
    /// specific reader; the provider itself does not.
    fn readers() -> Result<Vec<ReaderName>, Error>;
}

/// A live connection to one card through one reader.
///
/// The trait deals in `&[u8]` and `Vec<u8>` rather than [`crate::apdu`] types,
/// which is what keeps the layering one-directional: the layers above own the
/// meaning of the bytes, and this layer owns only the fact that they arrived.
pub trait CardSession {
    /// The reader this session is bound to.
    fn reader(&self) -> &ReaderName;

    /// Sends `command` and returns the card's response bytes verbatim.
    ///
    /// No interpretation happens here. A response of `61 10` comes back as
    /// those two bytes even though it is not a final status, and an error
    /// status comes back like any other. Deciding what a status word means
    /// belongs to [`crate::apdu`], which this module cannot see.
    ///
    /// Implementations must not retry. Whether to follow a response with
    /// another exchange is the caller's decision.
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, Error>;

    /// Releases the card back to the reader.
    ///
    /// Idempotent: releasing an already-released session is a no-op rather
    /// than an error, so cleanup paths do not have to track state.
    fn disconnect(&mut self) -> Result<(), Error>;
}

/// Everything that can go wrong at or below [`crate::fs`].
///
/// `#[non_exhaustive]` because the PC/SC layer has dozens of documented
/// failure codes and this enum models the handful an operator can act on.
/// Issue #4 added the mapping in [`pcsc`]; issue #10 extends it, and
/// downstream matches should not have to be rewritten when it does.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The PC/SC context could not be established at all.
    #[error("the PC/SC context could not be established")]
    ContextUnavailable,

    /// No reader is attached, or none matched the name asked for.
    #[error("no matching PC/SC reader is available")]
    NoReader,

    /// A reader exists but cannot be used, for example because another
    /// process already claims it.
    #[error("reader `{reader}` is present but could not be used")]
    ReaderUnavailable {
        /// The reader that could not be used.
        reader: ReaderName,
    },

    /// The card left mid-exchange.
    #[error("the card in reader `{reader}` was removed or reset during the exchange")]
    CardGone {
        /// The reader the card was in.
        reader: ReaderName,
    },

    /// An exchange failed below the level this tool reasons about.
    #[error("transmitting to reader `{reader}` failed in the PC/SC layer: {detail}")]
    Transmit {
        /// The reader that was being talked to.
        reader: ReaderName,
        /// The driver's own diagnostic text.
        detail: String,
    },

    /// The PC/SC layer refused an operation for a reason that is not one of
    /// the conditions modelled above.
    ///
    /// The catch-all exists so that an unmodelled refusal is reported as what
    /// it is instead of being flattened into a neighbouring variant. It is
    /// also where the driver's own words are kept, because that text is the
    /// only thing that tells an operator which of the dozens of PC/SC codes
    /// they hit.
    #[error("reader `{reader}` refused the PC/SC operation: {detail}")]
    Driver {
        /// The reader the operation was aimed at.
        reader: ReaderName,
        /// The driver's own diagnostic text.
        detail: String,
    },

    /// The session was already released, so there is nothing left to talk to.
    ///
    /// Distinct from `Error::CardGone` because nothing went wrong with a card:
    /// the caller asked a closed session to do one more thing, and saying
    /// "the card was removed" would send them looking at the hardware.
    #[error("the session with reader `{reader}` has already been disconnected")]
    Disconnected {
        /// The reader the closed session was bound to.
        reader: ReaderName,
    },

    /// The reader name could not be used as given.
    #[error("a reader name may not be empty")]
    EmptyReaderName,

    /// The reader name held a character that would corrupt terminal output.
    #[error("reader name {name:?} contains a control character")]
    IllegalReaderNameCharacter {
        /// The rejected name, quoted and escaped.
        name: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A software-only stand-in for a real reader.
    ///
    /// Doubles as the proof that [`CardSession`] is implementable without
    /// hardware, which both issue #4's fixture and issue #10's tests rely on.
    struct Loopback {
        reader: ReaderName,
        released: bool,
    }

    impl Loopback {
        fn new() -> Self {
            Self {
                reader: ReaderName::new("swICC virtual").unwrap(),
                released: false,
            }
        }
    }

    impl ReaderProvider for Loopback {
        fn readers() -> Result<Vec<ReaderName>, Error> {
            Ok(vec![ReaderName::new("swICC virtual").unwrap()])
        }
    }

    impl CardSession for Loopback {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }

        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
            match command {
                // SELECT MF
                [0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00] => Ok(vec![0x90, 0x00]),
                // A response the caller must follow up on.
                [0x00, 0xCA, 0x00, 0x00, 0x00] => Ok(vec![0x61, 0x10]),
                _ => Err(Error::CardGone {
                    reader: self.reader.clone(),
                }),
            }
        }

        fn disconnect(&mut self) -> Result<(), Error> {
            self.released = true;
            Ok(())
        }
    }

    #[test]
    fn reader_names_round_trip() {
        let name = ReaderName::new("swICC virtual reader 00 00").unwrap();
        assert_eq!(name.as_str(), "swICC virtual reader 00 00");
        assert_eq!(name.to_string(), "swICC virtual reader 00 00");
    }

    #[test]
    fn empty_reader_name_is_rejected() {
        assert!(matches!(ReaderName::new(""), Err(Error::EmptyReaderName)));
    }

    #[test]
    fn control_characters_in_reader_names_are_rejected() {
        // A reader name printed raw would let a hostile reader description
        // repaint the operator's terminal.
        for name in ["pcsc\nreader", "pcsc\tresc[2J", "pcsc\0", "pcsc\u{7}"] {
            assert!(
                matches!(
                    ReaderName::new(name),
                    Err(Error::IllegalReaderNameCharacter { .. })
                ),
                "{name:?} should be rejected"
            );
        }
    }

    #[test]
    fn errors_name_the_reader_they_came_from() {
        let rendered = Error::Transmit {
            reader: ReaderName::new("swICC 00").unwrap(),
            detail: "SCardTransmit returned 0x8010000E".to_owned(),
        }
        .to_string();
        assert!(rendered.contains("swICC 00"), "{rendered}");
        assert!(rendered.contains("0x8010000E"), "{rendered}");
    }

    #[test]
    fn a_session_can_be_implemented_without_hardware() {
        let mut session = Loopback::new();

        assert_eq!(Loopback::readers().unwrap().len(), 1);
        assert_eq!(session.reader().as_str(), "swICC virtual");
        assert_eq!(
            session
                .transmit(&[0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00])
                .unwrap(),
            vec![0x90, 0x00]
        );
        assert!(session.transmit(&[0x00, 0xA4, 0x00, 0x04]).is_err());

        session.disconnect().unwrap();
        assert!(session.released);
    }

    #[test]
    fn transmit_passes_status_bytes_back_untouched() {
        // 0x61xx means "more bytes available", not "done". A transport that
        // interpreted it, or that resolved it by retrying, would make the
        // chaining layer above it impossible to get right.
        let mut session = Loopback::new();
        let response = session.transmit(&[0x00, 0xCA, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(response, vec![0x61, 0x10]);
    }
}
