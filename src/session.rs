//! Typed exchanges over a card: command chaining, GET RESPONSE following,
//! and response reassembly.
//!
//! **Owns.** The composition of [`crate::apdu`] and [`crate::transport`].
//! [`crate::apdu`] can describe a command and read a response;
//! [`crate::transport`] can move bytes to a card and back. Neither can do
//! both, and neither may: apdu is a layer-0 leaf with no transport dependency,
//! and transport must not interpret a status word. So this is a new layer-1
//! module, which is what issue #10's human-facing session facade will sit on.
//!
//! **What it will not do.** It does not retry anything on its own initiative.
//! Every extra exchange it issues is one a caller asked for by naming a
//! [`Policy`]: which class byte to dial for GET RESPONSE, whether to follow a
//! 9x status at all, how many follow-ups to allow. A card that refuses a
//! command's Le is reported, never re-sent; [`Policy`] exists so that "try
//! again with this Le" stays a decision a rule layer can make deliberately.
//!
//! **The rule that shaped the design.** Nothing here reads a status word
//! without also knowing which command produced it. That is why
//! [`PendingFollowUp`] exists, why the class byte of GET RESPONSE is a
//! parameter with a documented default rather than a constant, and why
//! [`Exchange`] keeps the whole transcript instead of only the final answer.

/// This module's name, as recorded in [`crate::MODULES`].
///
/// Referenced by value rather than re-spelt as a literal so that the module
/// table cannot name a module that does not exist.
pub const NAME: &str = "session";

use std::fmt;

use crate::apdu::{
    Command, Le, Outcome, Pending, ProcedureAction, Response, StatusWord, CLA_FETCH_ETSI,
    CLA_GET_RESPONSE_GSM,
};
use crate::transport::CardSession;

/// Largest data field one exchange carries by default.
///
/// 255 is the short Lc ceiling, so a command longer than this needs the
/// extended form, and therefore needs a card willing to answer with a
/// procedure byte. Cards vary, so this is a policy field rather than a
/// constant baked into the codec.
pub const DEFAULT_MAX_DATA_PER_EXCHANGE: usize = 0xFF;

/// How many follow-up exchanges one logical command may issue by default.
///
/// Four is enough to clear one pending item and few enough that a card stuck
/// in a loop ends the exchange rather than the process. A caller that needs a
/// deeper drain raises it, and the budget is a policy field rather than a
/// constant because "deep enough" is a property of the card.
pub const DEFAULT_MAX_FOLLOW_UPS: usize = 4;

/// How many exchanges command chaining may use by default.
///
/// Every continuation is a separate round trip, so this bounds a single
/// [`send`] on a card that acknowledges without ever running out of data to
/// send.
pub const DEFAULT_MAX_COMMAND_EXCHANGES: usize = 8;

/// Which instruction drains a `91 xx`, `92 xx`, `93 xx` or `9F xx` status.
///
/// The status word alone does not say. On swSIM, `91 <length>` means a
/// proactive CAT command is pending and FETCH is what hands it back, while
/// `9F <length>` means response data is queued behind GET RESPONSE. \[V] both,
/// read in swSIM src/apduh.c. A tool that picked one of those instructions for
/// both would work on half the cards it met, which is why the default differs
/// between the two families and a [`Policy`] can override either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingFollowUp {
    /// GET RESPONSE, INS `0xC0`, asking for the advertised byte count.
    ///
    /// The default for a `9F xx`, because it is the instruction
    /// ISO/IEC 7816-4 defines for collecting response data and the one swSIM
    /// routes for `9F xx`.
    GetResponse,

    /// FETCH, INS `0x12`, whose Le must equal the pending length exactly.
    ///
    /// The default for a `91 xx`, `92 xx` or `93 xx`. \[V] for swSIM:
    /// apduh_etsi_cat_fetch answers `6C xx` when Le is not the pending
    /// length, so the length has to come from the status word rather than from
    /// a default.
    Fetch,

    /// Leave a 9x alone and report it as the exchange's status.
    ///
    /// The right answer when the pending thing is a proactive command this
    /// tool is not going to service, and the only safe answer for a card that
    /// uses `9F xx` for something a GET RESPONSE would not collect. Nothing
    /// is sent and the status word survives intact into
    /// [`Exchange::status`].
    Ignore,
}

/// Where the Le of a follow-up exchange comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingLength {
    /// Ask for exactly the byte count the status word advertises. The default.
    ///
    /// A 9x whose SW2 is `00` advertises nothing usable. Asking for the Le
    /// that `00` encodes, which is 256, is the one reading that is never
    /// shorter than what the card is holding; a card that means something else
    /// by `9F 00` wants [`PendingLength::Fixed`].
    ///
    /// A `91 00` is declined rather than resolved this way. Unlike
    /// `61 00`, nothing this project can cite defines what a zero means in
    /// the 3GPP pending family, and guessing it there would mean inventing a
    /// length rather than reusing a known one.
    Advertised,

    /// Ask for this Le, whatever the status word says.
    ///
    /// The escape hatch for a card that does not use SW2 as a length at all,
    /// and the way a caller takes responsibility for the number going on the
    /// wire.
    Fixed(Le),
}

/// How a session talks to a card.
///
/// Every field is a decision the card, not this crate, gets to make. The
/// defaults are the ones observed against swSIM and are written down rather
/// than inferred at the call site, but nothing here is a constant that cannot
/// be replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Policy {
    /// CLA for a GET RESPONSE follow-up. Defaults to [`CLA_GET_RESPONSE_GSM`].
    ///
    /// Both [`CLA_GET_RESPONSE_GSM`] and [`crate::apdu::CLA_GET_RESPONSE_ISO`]
    /// are supported because a card may dispatch INS `0xC0` at either and
    /// swSIM does not route the ISO one at all. \[V], swSIM src/apduh.c.
    pub get_response_class: u8,

    /// CLA for a FETCH follow-up. Defaults to [`CLA_FETCH_ETSI`].
    pub fetch_class: u8,

    /// What to do with a `91 xx`, `92 xx` or `93 xx`: a proactive
    /// command is pending and its length is in SW2. Defaults to
    /// [`PendingFollowUp::Fetch`].
    pub proactive_command: PendingFollowUp,

    /// What to do with a `9F xx`, whose SW2 this crate refuses to interpret.
    /// Defaults to [`PendingFollowUp::GetResponse`], which is what a card
    /// using `9F xx` for queued response data answers to.
    pub undetermined_pending: PendingFollowUp,

    /// Where a follow-up's Le comes from. Defaults to
    /// [`PendingLength::Advertised`].
    pub pending_length: PendingLength,

    /// Largest data field one exchange carries. Defaults to
    /// [`DEFAULT_MAX_DATA_PER_EXCHANGE`].
    pub max_data_per_exchange: usize,

    /// How many exchanges command chaining may use. Defaults to
    /// [`DEFAULT_MAX_COMMAND_EXCHANGES`].
    pub max_command_exchanges: usize,

    /// How many follow-ups one logical command may issue. Defaults to
    /// [`DEFAULT_MAX_FOLLOW_UPS`].
    pub max_follow_ups: usize,
}

impl Default for Policy {
    /// The policy the swSIM fixture exercises.
    fn default() -> Self {
        Self {
            get_response_class: CLA_GET_RESPONSE_GSM,
            fetch_class: CLA_FETCH_ETSI,
            proactive_command: PendingFollowUp::Fetch,
            undetermined_pending: PendingFollowUp::GetResponse,
            pending_length: PendingLength::Advertised,
            max_data_per_exchange: DEFAULT_MAX_DATA_PER_EXCHANGE,
            max_command_exchanges: DEFAULT_MAX_COMMAND_EXCHANGES,
            max_follow_ups: DEFAULT_MAX_FOLLOW_UPS,
        }
    }
}

/// One wire round trip, exactly as it happened.
///
/// Both halves are kept verbatim. Nothing is normalised, retried or elided,
/// because a transcript an operator cannot read back is not evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WireExchange {
    command: Vec<u8>,
    response: Vec<u8>,
}

impl WireExchange {
    /// The bytes handed to [`CardSession::transmit`].
    pub fn command(&self) -> &[u8] {
        &self.command
    }

    /// The bytes the card returned, untouched.
    pub fn response(&self) -> &[u8] {
        &self.response
    }
}

/// Why a [`send`] stopped issuing exchanges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StopReason {
    /// The last response answers the logical command. The ordinary case, and
    /// the only one where nothing is outstanding.
    Answered,

    /// A 9x was left alone because the policy said so. See
    /// [`PendingFollowUp::Ignore`].
    PendingIgnored,

    /// A pending status advertised a length no Le can express, so no follow-up
    /// was built. The status word is still in [`Exchange::status`].
    ///
    /// Only reachable for the 3GPP pending family with SW2 `00`; the
    /// response-data case resolves its zero to 256 because ISO/IEC 7816-4
    /// clause 9.1.1 says so.
    PendingLengthNotExpressible,

    /// The policy's follow-up budget ran out with something still pending.
    FollowUpsExhausted,

    /// The card stopped the command sequence before it finished.
    ///
    /// Three ways to get here, all reported rather than papered over: the card
    /// answered with a status word while command data was still unsent, it
    /// kept asking for command data the command did not hold, or it ended on a
    /// procedure byte with nothing left to send. In every case the bytes that
    /// did reach it are in the transcript.
    CommandSequenceStopped,

    /// Command chaining hit its exchange budget.
    CommandExchangesExhausted,

    /// The card sent a procedure byte this crate does not recognise as any of
    /// the three ISO/IEC 7816-3 forms. Carried through rather than guessed at,
    /// so a caller can match on it.
    UnrecognisedProcedureByte(u8),
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Answered => f.write_str("the card answered and nothing is outstanding"),
            Self::PendingIgnored => f.write_str("a pending status was left alone by policy"),
            Self::PendingLengthNotExpressible => {
                f.write_str("the pending status advertised a length no Le can express")
            }
            Self::FollowUpsExhausted => f.write_str("the follow-up budget ran out"),
            Self::CommandSequenceStopped => {
                f.write_str("the card asked for more command data than the command held")
            }
            Self::CommandExchangesExhausted => {
                f.write_str("command chaining hit its exchange budget")
            }
            Self::UnrecognisedProcedureByte(byte) => {
                write!(
                    f,
                    "the card sent the unrecognised procedure byte {byte:02X}"
                )
            }
        }
    }
}

/// One logical command and everything it took on the wire.
///
/// An exchange is not the same thing as an APDU. One command may have taken
/// several exchanges - command chaining, a GET RESPONSE, a FETCH - and the
/// response data is the concatenation of what each of them returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchange {
    command: Command,
    steps: Vec<WireExchange>,
    response: Response,
    data: Vec<u8>,
    stop: StopReason,
}

impl Exchange {
    /// The command that was asked for, before any splitting.
    pub const fn command(&self) -> &Command {
        &self.command
    }

    /// Every wire round trip, in order, verbatim.
    pub fn steps(&self) -> &[WireExchange] {
        &self.steps
    }

    /// How many round trips this logical command took.
    pub fn exchange_count(&self) -> usize {
        self.steps.len()
    }

    /// The last response, parsed.
    ///
    /// Not necessarily a success, and not necessarily a status word: a card
    /// that ends on a procedure byte ends on [`Response::Procedure`].
    pub const fn response(&self) -> &Response {
        &self.response
    }

    /// The status word of the last response, if it carried one.
    pub const fn status(&self) -> Option<StatusWord> {
        self.response.status()
    }

    /// The response data, reassembled across every exchange taken.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Why no further exchange was issued.
    pub const fn stop_reason(&self) -> StopReason {
        self.stop
    }

    /// Whether the card finished the command cleanly.
    ///
    /// Deliberately [`StatusWord::is_success`] and nothing wider, so a
    /// `91 xx` does not read as a finished exchange. A caller that wants
    /// "the command worked and there may be more" asks
    /// [`StatusWord::is_normal_processing`] instead.
    pub fn is_success(&self) -> bool {
        self.status().is_some_and(StatusWord::is_success)
    }

    /// Whether the card reported normal processing, whether or not something
    /// is still outstanding.
    pub fn is_normal_processing(&self) -> bool {
        self.status().is_some_and(StatusWord::is_normal_processing)
    }
}

/// Everything that can go wrong while running one logical command.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The command, or one of the chunks it was split into, could not be
    /// turned into bytes.
    #[error("a command could not be encoded: {0}")]
    Encode(#[from] crate::apdu::EncodeError),

    /// The card's response bytes are not a response this crate can read.
    #[error("a response could not be parsed: {0}")]
    Parse(#[from] crate::apdu::ParseError),

    /// The transport failed below the level this crate reasons about.
    #[error(transparent)]
    Transport(#[from] crate::transport::Error),
}

/// Runs one logical command against a card.
///
/// Sends `command`, chains it if the card asks for more command data, and
/// follows whatever the status word says it owes the card, all within
/// `policy`'s bounds. Every round trip is recorded in
/// [`Exchange::steps`].
///
/// **Nothing is retried.** A `6C xx` is reported in
/// [`Exchange::status`] and no command is re-sent, because whether to try
/// again with a corrected Le is a judgement about what the caller was doing,
/// and this function does not know that. A `91 xx` is likewise not a failure
/// and not a success: the card completed the command and is holding something,
/// and the policy decides whether to drain it.
///
/// # Errors
///
/// Returns [`Error::Encode`] for a command that cannot be put on the wire,
/// [`Error::Parse`] for response bytes that are not a response, and
/// [`Error::Transport`] for anything the reader reported. A card that stops
/// mid-sequence is not an error: it is a [`StopReason`].
pub fn send<S: CardSession + ?Sized>(
    session: &mut S,
    command: &Command,
    policy: &Policy,
) -> Result<Exchange, Error> {
    let parts = command.split(policy.max_data_per_exchange)?;
    let instruction = command.header().instruction();

    let mut steps: Vec<WireExchange> = Vec::new();
    let mut data: Vec<u8> = Vec::new();

    let opening = parts[0].encode()?;
    let mut response = exchange(session, &mut steps, opening)?;

    // Whatever the command still owes the card. `Command::split` guarantees
    // these parts concatenate to exactly the tail of the data field, so all
    // three procedure-byte actions can be served from this one buffer.
    let mut tail: Vec<u8> = parts[1..]
        .iter()
        .flat_map(|part| part.data().to_vec())
        .collect();
    let mut stop = StopReason::Answered;
    data.extend_from_slice(response.body());

    while !tail.is_empty() {
        if steps.len() >= policy.max_command_exchanges {
            stop = StopReason::CommandExchangesExhausted;
            break;
        }
        let next = match response.procedure_action(instruction) {
            Some(ProcedureAction::NextChunk) => take(&mut tail, policy.max_data_per_exchange),
            Some(ProcedureAction::SendAll) => std::mem::take(&mut tail),
            Some(ProcedureAction::SendOne) => take(&mut tail, 1),
            Some(ProcedureAction::Unrecognised(byte)) => {
                stop = StopReason::UnrecognisedProcedureByte(byte);
                break;
            }
            // A complete response before the command finished sending is the
            // card stopping the sequence. Reported, not papered over.
            None => {
                stop = StopReason::CommandSequenceStopped;
                break;
            }
        };
        if next.is_empty() {
            stop = StopReason::CommandSequenceStopped;
            break;
        }
        response = exchange(session, &mut steps, next)?;
        data.extend_from_slice(response.body());
    }

    // The chain ran out of command data. If the card is still asking, that is
    // a stopped sequence rather than an answered one, but only say so when no
    // more specific stop has already been recorded.
    if stop == StopReason::Answered && !response.is_complete() {
        stop = StopReason::CommandSequenceStopped;
    }

    follow_up(session, command, steps, response, data, stop, policy)
}

/// Issues the follow-up exchanges a status word says the card is owed.
fn follow_up<S: CardSession + ?Sized>(
    session: &mut S,
    command: &Command,
    mut steps: Vec<WireExchange>,
    mut response: Response,
    mut data: Vec<u8>,
    mut stop: StopReason,
    policy: &Policy,
) -> Result<Exchange, Error> {
    let mut follow_ups = 0usize;
    while let Some(status) = response.status() {
        let Some(choice) = follow_up_for(status, policy) else {
            break;
        };
        if choice == PendingFollowUp::Ignore {
            stop = StopReason::PendingIgnored;
            break;
        }
        if follow_ups >= policy.max_follow_ups {
            stop = StopReason::FollowUpsExhausted;
            break;
        }
        let Some(follow_up) = build_follow_up(choice, status, policy) else {
            stop = StopReason::PendingLengthNotExpressible;
            break;
        };
        response = exchange(session, &mut steps, follow_up.encode()?)?;
        follow_ups += 1;
        data.extend_from_slice(response.body());
    }

    Ok(Exchange {
        command: command.clone(),
        steps,
        response,
        data,
        stop,
    })
}

/// Which instruction, if any, this status word earns a follow-up with.
///
/// The one place a status word is read together with the rule about which of
/// the three numbers in SW2 this is. `61 xx` is a response-data length and
/// is always collected with GET RESPONSE; a 9x asks the policy, because the
/// two families mean different things and only the card knows which it is.
fn follow_up_for(status: StatusWord, policy: &Policy) -> Option<PendingFollowUp> {
    match status.outcome() {
        Outcome::MoreDataAvailable { .. } => Some(PendingFollowUp::GetResponse),
        Outcome::Pending {
            pending: Pending::ProactiveCommand { .. },
        } => Some(policy.proactive_command),
        Outcome::Pending {
            pending: Pending::Undetermined { .. },
        } => Some(policy.undetermined_pending),
        // Nothing else is outstanding to collect. A WrongLength is a refusal,
        // not a hand-back, and is deliberately absent: see `send`.
        _ => None,
    }
}

/// Builds the follow-up command a status word earned, or `None` to decline.
///
/// Returns `None` rather than a guess when the advertised length is one no Le
/// can express. The caller turns that into a
/// [`StopReason::PendingLengthNotExpressible`] and leaves the status word in
/// place, which is what a caller would have to do by hand anyway.
fn build_follow_up(
    choice: PendingFollowUp,
    status: StatusWord,
    policy: &Policy,
) -> Option<Command> {
    let le = match policy.pending_length {
        PendingLength::Fixed(le) => le,
        PendingLength::Advertised => match status.outcome() {
            // 61 xx: SW2 is a RESPONSE DATA length and `Outcome` has already
            // resolved the zero spelling to 256.
            Outcome::MoreDataAvailable { available } => Le::for_byte_count(u32::from(available))?,
            // 91, 92, 93 xx: SW2 is a PROACTIVE COMMAND length, and swSIM
            // wants Le to equal it exactly. A zero stays zero and declines:
            // nothing this project can cite defines what a 9x with a zero SW2
            // means, so inventing 256 here would be inventing a length.
            Outcome::Pending {
                pending: Pending::ProactiveCommand { length },
            } => Le::for_byte_count(u32::from(length))?,
            // 9F xx: SW2 is undetermined by design. The reading this crate
            // defaults to is swSIM's, where it is the queued response length.
            Outcome::Pending {
                pending: Pending::Undetermined { sw2 },
            } => Le::for_byte_count(advertised(sw2))?,
            _ => return None,
        },
    };

    Some(match choice {
        PendingFollowUp::GetResponse => Command::get_response(policy.get_response_class, le),
        PendingFollowUp::Fetch => Command::fetch(policy.fetch_class, le),
        PendingFollowUp::Ignore => return None,
    })
}

/// The byte count a 9x advertises, with the zero spelling resolved.
///
/// `61 00` is 256 by ISO/IEC 7816-4 clause 9.1.1 and the outcome variant has
/// already resolved it. The same reading is applied to a 9x as a documented
/// convention rather than a cited rule: ask for 256 when SW2 is zero, which is
/// never shorter than what the card is holding.
fn advertised(sw2: u8) -> u32 {
    if sw2 == 0 {
        Le::SHORT_MAX
    } else {
        u32::from(sw2)
    }
}

/// Removes up to `count` bytes from the front of `tail`.
fn take(tail: &mut Vec<u8>, count: usize) -> Vec<u8> {
    let count = count.min(tail.len());
    tail.drain(..count).collect()
}

/// One wire round trip, recorded verbatim.
fn exchange<S: CardSession + ?Sized>(
    session: &mut S,
    steps: &mut Vec<WireExchange>,
    command: Vec<u8>,
) -> Result<Response, Error> {
    let response = session.transmit(&command)?;
    steps.push(WireExchange {
        command,
        response: response.clone(),
    });
    Response::parse(&response).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::apdu::{
        Command, Header, CLA_GET_RESPONSE_ISO, HEADER_LEN, INS_FETCH, INS_GET_RESPONSE,
        PROCEDURE_BYTE_NULL,
    };
    use crate::transport::{Error as TransportError, ReaderName};

    /// A card that answers from a script and records everything it was sent.
    ///
    /// When the script runs out it repeats its last reply rather than failing,
    /// so a test about an unbounded loop asserts the policy's bound instead of
    /// the fake's patience. Every reply is fixed bytes, so assertions are made
    /// against the exact wire sequence rather than against "it worked".
    struct Scripted {
        reader: ReaderName,
        replies: VecDeque<Vec<u8>>,
        last: Vec<u8>,
        sent: Vec<Vec<u8>>,
    }

    impl Scripted {
        fn new(replies: impl IntoIterator<Item = Vec<u8>>) -> Self {
            let mut replies: VecDeque<Vec<u8>> = replies.into_iter().collect();
            if replies.is_empty() {
                replies.push_back(vec![0x90, 0x00]);
            }
            Self {
                last: replies[0].clone(),
                reader: ReaderName::new("swSIM scripted").unwrap(),
                replies,
                sent: Vec::new(),
            }
        }
    }

    impl CardSession for Scripted {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }

        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.sent.push(command.to_vec());
            // Pop the next scripted reply. Only when the script is exhausted
            // is the last reply put back, so a two-reply script answers twice
            // and then repeats rather than replaying its first line forever.
            let next = match self.replies.pop_front() {
                Some(next) => next,
                None => self.last.clone(),
            };
            self.last = next.clone();
            Ok(next)
        }

        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// A case 2 command with an instruction byte that is neither GET RESPONSE
    /// nor FETCH, so a follow-up can never be confused with it on the wire.
    fn probe() -> Command {
        Command::case2(Header::new(0x00, 0xB0, 0x00, 0x00), Le::Short(0x20))
    }

    /// The bytes a body-plus-status reply is made of.
    fn with_body(body: &[u8], sw1: u8, sw2: u8) -> Vec<u8> {
        let mut bytes = body.to_vec();
        bytes.push(sw1);
        bytes.push(sw2);
        bytes
    }

    /// A card that acknowledges `acknowledgements` continuations with the
    /// NULL procedure byte and then answers with `answer`.
    ///
    /// Chaining is driven by the card, so a test that wants to see the whole
    /// data field reach it has to script the acknowledgements rather than one
    /// lucky reply.
    fn chained(acknowledgements: usize, answer: Vec<u8>) -> Scripted {
        let mut replies = vec![vec![PROCEDURE_BYTE_NULL]; acknowledgements];
        replies.push(answer);
        Scripted::new(replies)
    }

    /// How many continuations a case 3 command of `len` octets needs when one
    /// exchange carries at most `chunk`.
    fn acknowledgements(len: usize, chunk: usize) -> usize {
        let rest = len.saturating_sub(chunk.min(len));
        rest.div_ceil(chunk)
    }

    // --- 61 xx: the acceptance criterion ------------------------------------

    #[test]
    fn a_61xx_is_followed_by_exactly_one_get_response_for_the_advertised_length() {
        // Every advertised length, including the zero spelling. Asserted over
        // the property the protocol promises - one follow-up, asking for what
        // the card said - rather than against one card's byte count.
        for sw2 in 0u8..=u8::MAX {
            let advertised = if sw2 == 0 { 0x00u8 } else { sw2 };
            let count = if sw2 == 0 { 256usize } else { usize::from(sw2) };
            let body: Vec<u8> = (0..count).map(|i| (i % 251) as u8).collect();

            let mut card = Scripted::new([vec![0x61, sw2], with_body(&body, 0x90, 0x00)]);
            let exchange = send(&mut card, &probe(), &Policy::default()).unwrap();

            assert_eq!(exchange.exchange_count(), 2, "61 {sw2:02X}");
            assert_eq!(
                exchange.steps()[1].command(),
                [
                    CLA_GET_RESPONSE_GSM,
                    INS_GET_RESPONSE,
                    0x00,
                    0x00,
                    advertised
                ],
                "61 {sw2:02X}"
            );
            assert_eq!(exchange.status(), Some(StatusWord::new(0x90, 0x00)));
            assert!(exchange.is_success(), "61 {sw2:02X}");
            assert_eq!(exchange.stop_reason(), StopReason::Answered);
            assert_eq!(exchange.data(), body.as_slice(), "61 {sw2:02X}");
        }
    }

    #[test]
    fn a_get_response_is_asked_for_at_whichever_class_the_policy_names() {
        // swSIM dispatches INS 0xC0 only at CLA 0xA0 and does not route the ISO
        // form at all, so the class byte is a parameter with a documented
        // default rather than a constant chosen inside a helper. [V], swSIM
        // src/apduh.c.
        for class in 0u8..=u8::MAX {
            let policy = Policy {
                get_response_class: class,
                ..Policy::default()
            };
            let mut card = Scripted::new([vec![0x61, 0x08], with_body(&[0u8; 8], 0x90, 0x00)]);
            let exchange = send(&mut card, &probe(), &policy).unwrap();

            assert_eq!(exchange.exchange_count(), 2, "CLA {class:02X}");
            assert_eq!(
                exchange.steps()[1].command(),
                [class, INS_GET_RESPONSE, 0x00, 0x00, 0x08],
                "CLA {class:02X}"
            );
            assert_eq!(exchange.data(), [0u8; 8]);
        }

        assert_eq!(Policy::default().get_response_class, CLA_GET_RESPONSE_GSM);
        assert_ne!(CLA_GET_RESPONSE_GSM, CLA_GET_RESPONSE_ISO);
    }

    // --- 9x: the two families, deliberately different -----------------------

    #[test]
    fn a_pending_proactive_command_is_drained_with_fetch_using_the_advertised_length() {
        // The swSIM transcript AGENTS.md section 2 records: the first SELECT MF
        // answers 91 80, FETCH 80 12 00 00 80 hands back the 128-byte proactive
        // command and clears it, and only then does a command answer a clean
        // 90 00. Modelled here rather than hard-coded, so a card whose pending
        // command is a different length still passes.
        for length in 1u8..=u8::MAX {
            let proactive: Vec<u8> = (0..usize::from(length)).map(|i| (i % 251) as u8).collect();

            let mut card = Scripted::new([vec![0x91, length], with_body(&proactive, 0x90, 0x00)]);
            let exchange = send(&mut card, &probe(), &Policy::default()).unwrap();

            assert_eq!(exchange.exchange_count(), 2, "91 {length:02X}");
            assert_eq!(
                exchange.steps()[1].command(),
                [CLA_FETCH_ETSI, INS_FETCH, 0x00, 0x00, length],
                "91 {length:02X}"
            );
            assert_eq!(exchange.data(), proactive.as_slice());
            assert!(exchange.is_success());
        }
    }

    #[test]
    fn draining_a_proactive_command_changes_the_next_commands_answer() {
        // The third fact the fixture proved, and the one a scanner that does
        // not drain proactive commands will read as a failure. One logical
        // command drains it; the next then needs no second exchange at all.
        let select = Command::case3(Header::new(0x00, 0xA4, 0x00, 0x0C), [0x3Fu8, 0x00]);
        let mut card = Scripted::new([
            vec![0x91, 0x80],
            with_body(&[0xAAu8; 0x80], 0x90, 0x00),
            vec![0x90, 0x00],
        ]);
        let policy = Policy::default();

        let first = send(&mut card, &select, &policy).unwrap();
        assert_eq!(first.exchange_count(), 2);
        assert_eq!(first.steps()[1].command(), [0x80, 0x12, 0x00, 0x00, 0x80]);
        assert!(first.is_success());

        let second = send(&mut card, &select, &policy).unwrap();
        assert_eq!(second.exchange_count(), 1, "nothing is pending any more");
        assert_eq!(second.status(), Some(StatusWord::new(0x90, 0x00)));
        assert!(second.is_success());
        assert!(second.data().is_empty());
    }

    #[test]
    fn an_undetermined_9f_is_collected_with_get_response_not_fetch() {
        // On swSIM 9F <length> is response data queued behind GET RESPONSE,
        // while 91 <length> is a proactive command behind FETCH. One tool that
        // picked one instruction for both would work on half the cards it met.
        for length in 0u8..=u8::MAX {
            let asked = if length == 0 { 0x00u8 } else { length };
            let count = if length == 0 {
                256usize
            } else {
                usize::from(length)
            };
            let body: Vec<u8> = (0..count).map(|i| (i % 251) as u8).collect();

            let mut card = Scripted::new([vec![0x9F, length], with_body(&body, 0x90, 0x00)]);
            let exchange = send(&mut card, &probe(), &Policy::default()).unwrap();

            assert_eq!(exchange.exchange_count(), 2, "9F {length:02X}");
            assert_eq!(
                exchange.steps()[1].command(),
                [CLA_GET_RESPONSE_GSM, INS_GET_RESPONSE, 0x00, 0x00, asked],
                "9F {length:02X}"
            );
            assert_eq!(exchange.data(), body.as_slice());
        }
    }

    #[test]
    fn a_policy_can_leave_a_9x_alone_and_the_status_word_survives_intact() {
        // The right answer when the pending thing is a proactive command this
        // tool is not going to service. Nothing is sent and the status is still
        // readable, which is what makes it a decision rather than a loss.
        for sw1 in [0x91u8, 0x92, 0x93, 0x9F] {
            for sw2 in 0u8..=u8::MAX {
                let policy = Policy {
                    proactive_command: PendingFollowUp::Ignore,
                    undetermined_pending: PendingFollowUp::Ignore,
                    ..Policy::default()
                };
                let mut card = Scripted::new([vec![sw1, sw2]]);
                let exchange = send(&mut card, &probe(), &policy).unwrap();

                assert_eq!(exchange.exchange_count(), 1, "{sw1:02X} {sw2:02X}");
                assert_eq!(
                    exchange.status(),
                    Some(StatusWord::new(sw1, sw2)),
                    "{sw1:02X} {sw2:02X}"
                );
                assert_eq!(exchange.stop_reason(), StopReason::PendingIgnored);
                assert!(!exchange.is_success(), "{sw1:02X} {sw2:02X}");
                assert!(exchange.is_normal_processing(), "{sw1:02X} {sw2:02X}");
            }
        }
    }

    #[test]
    fn the_follow_up_instruction_is_a_policy_choice_the_caller_makes_per_family() {
        // A card that puts response data behind FETCH is legal, and a card
        // that services a proactive command with GET RESPONSE is legal too.
        // Both directions have to work without touching the codec.
        for choice in [PendingFollowUp::GetResponse, PendingFollowUp::Fetch] {
            for sw1 in [0x91u8, 0x9F] {
                let policy = Policy {
                    proactive_command: choice,
                    undetermined_pending: choice,
                    ..Policy::default()
                };
                let mut card =
                    Scripted::new([vec![sw1, 0x10], with_body(&[0u8; 0x10], 0x90, 0x00)]);
                let exchange = send(&mut card, &probe(), &policy).unwrap();

                let expected_instruction = match choice {
                    PendingFollowUp::GetResponse => INS_GET_RESPONSE,
                    PendingFollowUp::Fetch => INS_FETCH,
                    PendingFollowUp::Ignore => unreachable!(),
                };
                assert_eq!(
                    exchange.steps()[1].command()[1],
                    expected_instruction,
                    "{sw1:02X} with {choice:?}"
                );
                assert_eq!(exchange.data(), [0u8; 0x10]);
            }
        }
    }

    // --- what this module will never do ------------------------------------

    #[test]
    fn no_status_word_ever_causes_the_callers_own_command_to_be_sent_twice() {
        // The load-bearing negative. Exhausts all 65536 answers a card could
        // give, on a command that no follow-up can be mistaken for, and
        // asserts that whatever else happened the caller's bytes went out
        // once. A 6C xx is in here as the case that most tempts a retry.
        let command = probe();
        let original = command.encode().unwrap();
        for raw in 0u32..=u32::from(u16::MAX) {
            let bytes = [((raw >> 8) & 0xFF) as u8, (raw & 0xFF) as u8];
            let mut card = Scripted::new([bytes.to_vec()]);
            let exchange = send(&mut card, &command, &Policy::default()).unwrap();

            let sent = exchange
                .steps()
                .iter()
                .filter(|step| step.command() == original.as_slice())
                .count();
            assert!(sent <= 1, "{bytes:02X?} was sent {sent} times");
        }
    }

    #[test]
    fn a_wrong_length_is_reported_and_nothing_is_re_sent() {
        for sw2 in 0u8..=u8::MAX {
            let mut card = Scripted::new([vec![0x6C, sw2]]);
            let exchange = send(&mut card, &probe(), &Policy::default()).unwrap();

            assert_eq!(exchange.exchange_count(), 1, "6C {sw2:02X}");
            assert_eq!(
                exchange.status(),
                Some(StatusWord::new(0x6C, sw2)),
                "6C {sw2:02X}"
            );
            assert!(!exchange.is_success());
            assert!(!exchange.is_normal_processing());
            // Nothing is outstanding, so this is an answered exchange whose
            // answer was a refusal, not an unfinished one.
            assert_eq!(exchange.stop_reason(), StopReason::Answered);
            assert!(exchange
                .stop_reason()
                .to_string()
                .contains("nothing is outstanding"));
        }
    }

    #[test]
    fn an_unexpected_failure_is_reported_rather_than_swallowed() {
        for sw1 in [0x6Au8, 0x6D, 0x6F, 0x94, 0x95, 0x98] {
            let mut card = Scripted::new([vec![sw1, 0x00]]);
            let exchange = send(&mut card, &probe(), &Policy::default()).unwrap();
            assert_eq!(exchange.exchange_count(), 1, "{sw1:02X}");
            assert_eq!(exchange.status(), Some(StatusWord::new(sw1, 0x00)));
            assert!(!exchange.is_success(), "{sw1:02X}");
        }
    }

    // --- bounds ------------------------------------------------------------

    #[test]
    fn the_follow_up_budget_bounds_the_exchange_count() {
        // A card stuck answering 61 xx must end the exchange, not the process.
        for budget in 0usize..=8 {
            let policy = Policy {
                max_follow_ups: budget,
                ..Policy::default()
            };
            let mut card = Scripted::new([vec![0x61, 0x10]]);
            let exchange = send(&mut card, &probe(), &policy).unwrap();

            assert_eq!(exchange.exchange_count(), budget + 1, "budget {budget}");
            assert_eq!(exchange.stop_reason(), StopReason::FollowUpsExhausted);
            assert_eq!(exchange.status(), Some(StatusWord::new(0x61, 0x10)));
        }
    }

    #[test]
    fn a_pending_status_with_no_askable_length_declines_the_follow_up() {
        // 91 00 advertises nothing this project can cite a meaning for, so no
        // Le is invented. The status word is still the caller's to read.
        let mut card = Scripted::new([vec![0x91, 0x00]]);
        let exchange = send(&mut card, &probe(), &Policy::default()).unwrap();
        assert_eq!(exchange.exchange_count(), 1);
        assert_eq!(
            exchange.stop_reason(),
            StopReason::PendingLengthNotExpressible
        );
        assert_eq!(exchange.status(), Some(StatusWord::new(0x91, 0x00)));

        // And a caller who knows better can still say so explicitly.
        let policy = Policy {
            pending_length: PendingLength::Fixed(Le::Short(1)),
            ..Policy::default()
        };
        let mut card = Scripted::new([vec![0x91, 0x00], vec![0x90, 0x00]]);
        let exchange = send(&mut card, &probe(), &policy).unwrap();
        assert_eq!(exchange.exchange_count(), 2);
        assert_eq!(
            exchange.steps()[1].command(),
            [CLA_FETCH_ETSI, INS_FETCH, 0x00, 0x00, 0x01]
        );
    }

    // --- command chaining --------------------------------------------------

    #[test]
    fn a_command_longer_than_one_exchange_is_split_and_its_data_reaches_the_card() {
        // Every chunk is within the bound, the chunks concatenate to exactly
        // the data the caller supplied, and the opening command carries the
        // first slice under the short Lc form where that fits.
        let select = Header::new(0x00, 0xA4, 0x00, 0x00);
        for len in [1usize, 2, 255, 256, 300, 1024] {
            for chunk in [1usize, 2, 17, 255, 4096] {
                let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let policy = Policy {
                    max_data_per_exchange: chunk,
                    // The budget has to leave room for every acknowledgement
                    // this command needs, or the test would be measuring the
                    // budget rather than the splitting.
                    max_command_exchanges: acknowledgements(len, chunk) + 2,
                    ..Policy::default()
                };
                let mut card = chained(acknowledgements(len, chunk), with_body(&data, 0x90, 0x00));
                let exchange = send(&mut card, &Command::case3(select, data.clone()), &policy)
                    .unwrap_or_else(|e| panic!("len {len}, chunk {chunk}: {e}"));

                // Read the length field back off the wire rather than
                // assuming the short form: past 255 the encoder is entitled
                // to use the extended one.
                let opening = exchange.steps()[0].command();
                let (declared, data_at) = if opening[HEADER_LEN] == 0 {
                    (
                        usize::from(u16::from_be_bytes([
                            opening[HEADER_LEN + 1],
                            opening[HEADER_LEN + 2],
                        ])),
                        HEADER_LEN + 3,
                    )
                } else {
                    (usize::from(opening[HEADER_LEN]), HEADER_LEN + 1)
                };
                assert_eq!(
                    opening.len(),
                    data_at + declared,
                    "len {len}, chunk {chunk}"
                );
                assert!(
                    declared <= chunk.min(len),
                    "len {len}, chunk {chunk} put {declared} in the first exchange"
                );
                assert_eq!(
                    &opening[data_at..data_at + declared],
                    &data[..declared],
                    "len {len}, chunk {chunk}"
                );

                let mut received = opening[data_at..data_at + declared].to_vec();
                for step in &exchange.steps()[1..] {
                    assert!(step.command().len() <= chunk, "len {len}, chunk {chunk}");
                    assert!(!step.command().is_empty(), "len {len}, chunk {chunk}");
                    received.extend_from_slice(step.command());
                }
                assert_eq!(received, data, "len {len}, chunk {chunk}");
                assert_eq!(exchange.stop_reason(), StopReason::Answered);
                assert_eq!(
                    exchange.exchange_count(),
                    acknowledgements(len, chunk) + 1,
                    "len {len}, chunk {chunk}"
                );
            }
        }
    }

    #[test]
    fn a_null_procedure_byte_takes_the_next_chunk_and_the_rest_is_still_sent() {
        let data: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
        let policy = Policy {
            max_data_per_exchange: 255,
            ..Policy::default()
        };
        let mut card = chained(
            acknowledgements(data.len(), 255),
            with_body(&data, 0x90, 0x00),
        );
        let exchange = send(
            &mut card,
            &Command::case3(Header::new(0x00, 0xA4, 0x00, 0x00), data),
            &policy,
        )
        .unwrap();

        // 255 in the opening command, then one continuation of 255 and one of
        // the remainder.
        assert_eq!(exchange.exchange_count(), 3);
        assert_eq!(exchange.steps()[1].command().len(), 255);
        assert_eq!(exchange.steps()[2].command().len(), 600 - 510);
        assert_eq!(exchange.steps()[2].command().len(), 90);
    }

    #[test]
    fn a_positive_acknowledgement_sends_the_whole_rest_of_the_command_data() {
        let data: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
        let policy = Policy {
            max_data_per_exchange: 255,
            ..Policy::default()
        };
        // INS 0xA4 echoed back is the positive acknowledgement.
        let mut card = Scripted::new([vec![0xA4], with_body(&data, 0x90, 0x00)]);
        let exchange = send(
            &mut card,
            &Command::case3(Header::new(0x00, 0xA4, 0x00, 0x00), data),
            &policy,
        )
        .unwrap();

        assert_eq!(exchange.exchange_count(), 2);
        assert_eq!(exchange.steps()[1].command().len(), 600 - 255);
    }

    #[test]
    fn a_negative_acknowledgement_sends_exactly_one_more_byte() {
        let data: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
        let policy = Policy {
            max_data_per_exchange: 255,
            ..Policy::default()
        };
        // 0xA4 inverted is the negative acknowledgement.
        let mut card = Scripted::new([
            vec![0xA4 ^ 0xFF],
            vec![0xA4 ^ 0xFF],
            with_body(&data, 0x90, 0x00),
        ]);
        let exchange = send(
            &mut card,
            &Command::case3(Header::new(0x00, 0xA4, 0x00, 0x00), data),
            &policy,
        )
        .unwrap();

        assert_eq!(exchange.exchange_count(), 3);
        assert_eq!(exchange.steps()[1].command().len(), 1);
        assert_eq!(exchange.steps()[2].command().len(), 1);
    }

    #[test]
    fn an_unrecognised_procedure_byte_is_carried_through_rather_than_guessed() {
        // Every octet that is not one of the three ISO/IEC 7816-3 forms stops
        // the chain and is named, rather than being treated as "send more".
        let data: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
        let policy = Policy {
            max_data_per_exchange: 255,
            ..Policy::default()
        };
        let recognised = [PROCEDURE_BYTE_NULL, 0xA4, 0xA4 ^ 0xFF];
        for byte in 0u8..=u8::MAX {
            if recognised.contains(&byte) {
                continue;
            }
            let mut card = Scripted::new([vec![byte], with_body(&data, 0x90, 0x00)]);
            let exchange = send(
                &mut card,
                &Command::case3(Header::new(0x00, 0xA4, 0x00, 0x00), data.clone()),
                &policy,
            )
            .unwrap();

            assert_eq!(
                exchange.stop_reason(),
                StopReason::UnrecognisedProcedureByte(byte),
                "{byte:02X}"
            );
            assert_eq!(exchange.exchange_count(), 1, "{byte:02X}");
        }
    }

    #[test]
    fn a_card_that_answers_before_the_command_is_fully_sent_is_reported() {
        // A complete response where a procedure byte was owed means the card
        // stopped the sequence. Reported, not papered over by sending the rest.
        let data: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
        let policy = Policy {
            max_data_per_exchange: 255,
            ..Policy::default()
        };
        let mut card = Scripted::new([with_body(&data, 0x90, 0x00)]);
        let exchange = send(
            &mut card,
            &Command::case3(Header::new(0x00, 0xA4, 0x00, 0x00), data),
            &policy,
        )
        .unwrap();

        assert_eq!(exchange.stop_reason(), StopReason::CommandSequenceStopped);
        assert_eq!(exchange.exchange_count(), 1);
        assert!(exchange.is_success());
    }

    #[test]
    fn the_command_exchange_budget_bounds_a_card_that_keeps_acknowledging() {
        let data: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        for budget in 1usize..=6 {
            let policy = Policy {
                max_data_per_exchange: 1,
                max_command_exchanges: budget,
                ..Policy::default()
            };
            let mut card = Scripted::new([vec![PROCEDURE_BYTE_NULL]]);
            let exchange = send(
                &mut card,
                &Command::case3(Header::new(0x00, 0xA4, 0x00, 0x00), data.clone()),
                &policy,
            )
            .unwrap();

            assert_eq!(exchange.exchange_count(), budget, "budget {budget}");
            assert_eq!(
                exchange.stop_reason(),
                StopReason::CommandExchangesExhausted,
                "budget {budget}"
            );
        }
    }

    #[test]
    fn a_follow_up_is_always_a_case_2_apdu_with_no_data_field() {
        // Guards the seam between the two phases: a follow-up is a case 2
        // APDU and must never arrive carrying a data field.
        for sw2 in 0u8..=u8::MAX {
            let mut card = Scripted::new([vec![0x61, sw2], vec![0x90, 0x00]]);
            let exchange = send(&mut card, &probe(), &Policy::default()).unwrap();
            for step in exchange.steps().iter().skip(1) {
                assert_eq!(step.command().len(), 5, "61 {sw2:02X}");
            }
        }
    }

    // --- the transcript ----------------------------------------------------

    #[test]
    fn a_card_that_ends_asking_for_more_data_is_reported_not_called_answered() {
        // The command fits one exchange, so there was never anything more to
        // send, and the card asked anyway. That is a stop, not a success, and
        // reporting it as answered would put a procedure byte into a path
        // callers read as a finished exchange.
        let policy = Policy {
            max_data_per_exchange: 255,
            ..Policy::default()
        };
        let mut card = Scripted::new([vec![PROCEDURE_BYTE_NULL]]);
        let exchange = send(
            &mut card,
            &Command::case3(Header::new(0x00, 0xA4, 0x00, 0x00), [0x3Fu8, 0x00]),
            &policy,
        )
        .unwrap();

        assert_eq!(exchange.exchange_count(), 1);
        assert_eq!(exchange.stop_reason(), StopReason::CommandSequenceStopped);
        assert_eq!(exchange.status(), None);
        assert_eq!(
            exchange.response().procedure_byte(),
            Some(PROCEDURE_BYTE_NULL)
        );
        assert!(!exchange.is_success());
        assert!(!exchange.is_normal_processing());
    }

    #[test]
    fn the_transcript_is_exactly_what_the_transport_saw_and_the_card_sent() {
        // Nothing is normalised, retried or elided. Compared against the fake's
        // own record of what it was handed and what it replied, so a mismatch
        // anywhere in the loop shows up here rather than in a scan report.
        let policy = Policy::default();
        let mut card = Scripted::new([
            vec![0x61, 0x04],
            with_body(&[1, 2, 3, 4], 0x91, 0x03),
            with_body(&[5, 6, 7], 0x90, 0x00),
        ]);
        let exchange = send(&mut card, &probe(), &policy).unwrap();

        assert_eq!(exchange.steps().len(), card.sent.len());
        for (step, sent) in exchange.steps().iter().zip(&card.sent) {
            assert_eq!(step.command(), sent.as_slice());
            assert!(!step.response().is_empty());
        }
        assert_eq!(exchange.exchange_count(), 3);
        assert_eq!(exchange.data(), [1, 2, 3, 4, 5, 6, 7]);
        assert!(exchange.is_success());
        assert_eq!(exchange.stop_reason(), StopReason::Answered);
    }

    #[test]
    fn an_empty_answer_from_the_card_is_an_error_rather_than_a_fabricated_status() {
        let mut card = Scripted::new([Vec::new()]);
        assert!(matches!(
            send(&mut card, &probe(), &Policy::default()),
            Err(Error::Parse(_))
        ));
    }

    #[test]
    fn a_transport_failure_is_surfaced_and_the_exchange_is_not_invented() {
        struct Broken;
        impl CardSession for Broken {
            fn reader(&self) -> &ReaderName {
                static NAME: std::sync::OnceLock<ReaderName> = std::sync::OnceLock::new();
                NAME.get_or_init(|| ReaderName::new("broken").unwrap())
            }
            fn transmit(&mut self, _: &[u8]) -> Result<Vec<u8>, TransportError> {
                Err(TransportError::Disconnected {
                    reader: self.reader().clone(),
                })
            }
            fn disconnect(&mut self) -> Result<(), TransportError> {
                Ok(())
            }
        }

        let mut card = Broken;
        assert!(matches!(
            send(&mut card, &probe(), &Policy::default()),
            Err(Error::Transport(_))
        ));
    }
}
