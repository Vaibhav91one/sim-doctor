//! Typed exchanges over a card: command chaining, GET RESPONSE following,
//! and response reassembly.
//!
//! **Owns.** The composition of [ZZTICKZZcrate::apduZZTICKZZ] and
//! [ZZTICKZZcrate::transportZZTICKZZ]. [ZZTICKZZcrate::apduZZTICKZZ] can describe a command and read
//! a response; [ZZTICKZZcrate::transportZZTICKZZ] can move bytes to a card and back. Neither
//! can do both, and neither may: apdu is a layer-0 leaf with no transport
//! dependency and transport must not interpret a status word. So this is a new
//! layer-1 module, which is what issue #10's session facade has to be.
//!
//! **What it will not do.** It does not retry anything on its own initiative.
//! Every extra exchange it issues is one the caller asked for by naming a
//! policy: which class byte to dial for GET RESPONSE, whether to follow a
//! ZZTICKZZ9xZZTICKZZ status at all, how many follow-ups to allow. A card that refuses a
//! command's Le is reported, not re-sent; [ZZTICKZZPolicyZZTICKZZ] exists so that "try again
//! with this Le" stays a decision a rule layer can make deliberately.
//!
//! **The rule that shaped the design.** Nothing here reads a status word
//! without also knowing which command produced it. That is why
//! [ZZTICKZZPendingFollowUpZZTICKZZ] exists, why the class byte of GET RESPONSE is a parameter
//! with a documented default rather than a constant, and why [ZZTICKZZExchangeZZTICKZZ] keeps
//! the whole transcript instead of only the final answer.

/// This module's name, as recorded in [ZZTICKZZcrate::MODULESZZTICKZZ].
///
/// Referenced by value rather than re-spelt as a literal so that the module
/// table cannot name a module that does not exist.
pub const NAME: &str = "session";

use crate::apdu::{
    Command, Header, Le, Outcome, Pending, ProcedureAction, Response, StatusWord,
    CLA_FETCH_ETSI, CLA_GET_RESPONSE_GSM, CLA_GET_RESPONSE_ISO, INS_FETCH, INS_GET_RESPONSE,
};
use crate::transport::{CardSession, ReaderName};
use std::fmt;

/// Largest data field one exchange carries by default.
///
/// 255 is the short Lc ceiling, so a command longer than this needs the
/// extended form, and therefore needs a card that is willing to answer with a
/// procedure byte. Cards vary, so this is a policy field rather than a
/// constant baked into the codec.
pub const DEFAULT_MAX_DATA_PER_EXCHANGE: usize = 0xFF;

/// How many follow-up exchanges one logical command may issue by default.
///
/// Four is the bound the swSIM card-backed test uses when it settles a SELECT
/// past a pending proactive command, and for the same reason: enough to clear
/// one pending item, few enough that a card stuck in a loop ends the exchange
/// rather than the process.
pub const DEFAULT_MAX_FOLLOW_UPS: usize = 4;

/// How many exchanges command chaining may use by default.
pub const DEFAULT_MAX_COMMAND_EXCHANGES: usize = 8;

/// Which instruction drains a ZZTICKZZ91 xxZZTICKZZ, ZZTICKZZ92 xxZZTICKZZ, ZZTICKZZ93 xxZZTICKZZ or ZZTICKZZ9F xxZZTICKZZ status.
///
/// The status word alone does not say. On swSIM, ZZTICKZZ91 <length>ZZTICKZZ means a
/// proactive CAT command is pending and FETCH is what hands it back, while
/// ZZTICKZZ9F <length>ZZTICKZZ means response data is queued behind GET RESPONSE. [V] both,
/// read in swSIM ZZTICKZZsrc/apduh.cZZTICKZZ. A tool that picked one of those
/// instructions for both would work on half the cards it met.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingFollowUp {
    /// GET RESPONSE, INS ZZTICKZZ0xC0ZZTICKZZ, asking for the advertised byte count.
    ///
    /// The default, because it is the instruction ISO/IEC 7816-4 defines for
    /// collecting response data and the one swSIM routes for ZZTICKZZ9F xxZZTICKZZ.
    GetResponse,
    /// FETCH, INS ZZTICKZZ0x12ZZTICKZZ, whose Le must equal the pending length
    /// exactly.
    ///
    /// [V] for swSIM: ZZTICKZZapduh_etsi_cat_fetchZZTICKZZ answers ZZTICKZZ6C xxZZTICKZZ when it
    /// is not, so the length has to come from the status word rather than from
    /// a default.
    Fetch,
    /// Leave a ZZTICKZZ9xZZTICKZZ alone and report it as the exchange's status.
    ///
    /// The right answer when the pending thing is a proactive command this
    /// tool is not going to service, and the only safe answer for a card that
    /// uses ZZTICKZZ9F xxZZTICKZZ for something a GET RESPONSE would not collect.
    Ignore,
}

/// Where the Le of a follow-up exchange comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingLength {
    /// Ask for exactly the byte count the status word advertises. The default.
    ///
    /// A ZZTICKZZ9xZZTICKZZ whose SW2 is ZZTICKZZ00ZZTICKZZ advertises nothing usable. Asking
    /// for the Le that ZZTICKZZ00ZZTICKZZ encodes, which is 256, is the one reading that is
    /// never shorter than what the card is holding; a card that means something
    /// else by ZZTICKZZ9F 00ZZTICKZZ wants [ZZTICKZZPendingLength::FixedZZTICKZZ].
    Advertised,
    /// Ask for this Le, whatever the status word says.
    Fixed(Le),
}
