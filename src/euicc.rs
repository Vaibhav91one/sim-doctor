//! eUICC, read-only: select the ISD-R on a logical channel and read what
//! ES10 will say without changing anything (issues #116, #132).
//!
//! **Owns.** The three read-only queries behind `sim-doctor euicc`: `info`
//! (GetEID, GetEuiccInfo1, GetEuiccInfo2, GetEuiccConfiguredAddresses),
//! `profiles` (GetProfilesInfo) and `notifications` (ListNotification,
//! metadata only), the JSON each produces and the sanitized human table. lpac
//! names: `chip info`, `profile list`, `notification list`. Also the one write,
//! [`nickname`] (SetNickname, lpac `profile nickname`) and [`set_state`]
//! (EnableProfile / DisableProfile, lpac `profile enable` / `disable`): each a
//! dry run by default, sent only when `apply` is set, and then verified by a
//! re-read.
//!
//! **Does not own, and never sends.** DeleteProfile,
//! RetrieveNotificationsList, RemoveNotificationFromList, the download
//! functions or anything over HTTPS. The only commands on the wire are MANAGE
//! CHANNEL (open, close), SELECT of the ISD-R, and STORE DATA carrying one of
//! the read requests above, or SetNickname / EnableProfile / DisableProfile
//! when applying. The channel is
//! closed again on every path, a failure included.
//!
//! **Card safety.** A card that is not an eUICC refuses the ISD-R SELECT; that
//! is reported as [`Failure`] `not-an-euicc` and no STORE DATA is sent.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "euicc";

use serde_json::{json, Value};

use crate::apdu::{Command, Header, Le};
use crate::contract::sanitize;
use crate::es10::{self, BitString};
use crate::session::{self, PendingFollowUp, Policy};
use crate::transport::CardSession;

/// The ISD-R AID (SGP.22 v2.5 section 4.1).
pub const ISDR_AID: [u8; 16] = [
    0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00,
];

/// Tags GetProfilesInfo is asked for: ICCID, ISD-P AID, state, nickname,
/// provider, name, class. The icon (`94`) is left out on purpose: it is large
/// and nothing here shows it.
const PROFILE_TAGS: [u16; 7] = [0x5A, 0x4F, 0x9F70, 0x90, 0x91, 0x92, 0x95];

/// STORE DATA data bytes per block unless `--max-segment` changes it: lpac's
/// default, since some eUICCs reject full 255-byte blocks.
pub const DEFAULT_MAX_SEGMENT: usize = 120;

/// Which read-only query to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Query {
    /// EID, EUICCInfo1 and EUICCInfo2 (lpac `chip info`).
    Info,
    /// GetProfilesInfo (lpac `profile list`).
    Profiles,
    /// ListNotification metadata (lpac `notification list`).
    Notifications,
}

impl Query {
    /// The subcommand name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Profiles => "profiles",
            Self::Notifications => "notifications",
        }
    }
}

/// Why a query produced no data: a stable `kind`, a message, and extra data.
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    /// Machine-checkable cause (`not-an-euicc`, `channel-unavailable`, ...).
    pub kind: &'static str,
    /// What to tell the operator.
    pub message: String,
    /// The envelope `data`, always holding `error.kind`.
    pub data: Value,
}

impl Failure {
    fn new(kind: &'static str, message: String, extra: Value) -> Self {
        let mut data = json!({ "error": { "kind": kind, "message": message } });
        if let (Some(into), Some(from)) = (data.as_object_mut(), extra.as_object()) {
            into.extend(from.clone());
        }
        Self {
            kind,
            message,
            data,
        }
    }
}

fn exchange_failed(err: impl std::fmt::Display) -> Failure {
    Failure::new("exchange-failed", err.to_string(), json!({}))
}

fn status_hex(ex: &session::Exchange) -> Value {
    ex.status()
        .map_or(Value::Null, |s| json!(hex::encode_upper(s.to_bytes())))
}

/// CLA for logical channel `n`: first interindustry for 0..=3 and 4..=19
/// (`0x40`), or, with `proprietary`, the `8x` / `Cx` classes STORE DATA uses.
fn channel_cla(proprietary: bool, n: u8) -> u8 {
    match (proprietary, n) {
        (false, 0..=3) => n,
        (false, _) => 0x40 | (n - 4),
        (true, 0..=3) => 0x80 | n,
        (true, _) => 0xC0 | (n - 4),
    }
}

/// Asks the ISD-R one ES10 function: the request goes out as STORE DATA, the
/// response data comes back. The `&'static str` names the function in errors.
type Ask<'a> = dyn FnMut(&'static str, Vec<u8>) -> Result<Vec<u8>, Failure> + 'a;

/// Runs `query` against the ISD-R with AID `aid` on a freshly opened logical
/// channel, and closes the channel afterwards.
///
/// # Errors
///
/// A [`Failure`]; the card refusing is data, not a panic.
pub fn run<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    query: Query,
) -> Result<Value, Failure> {
    run_with(session, aid, query, DEFAULT_MAX_SEGMENT)
}

/// [`run`] with at most `max_segment` data bytes per STORE DATA block.
///
/// # Errors
///
/// As [`run`].
pub fn run_with<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    query: Query,
    max_segment: usize,
) -> Result<Value, Failure> {
    in_channel(session, aid, max_segment, |ask| read_query(ask, query))
}

/// Opens a logical channel, selects the ISD-R, hands `body` a way to ask it
/// ES10 functions, then closes the channel on every path.
fn in_channel<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    max_segment: usize,
    body: impl FnOnce(&mut Ask<'_>) -> Result<Value, Failure>,
) -> Result<Value, Failure> {
    let (channel, open) = session::open_channel(session).map_err(exchange_failed)?;
    let Some(channel) = channel else {
        return Err(Failure::new(
            "channel-unavailable",
            format!(
                "the card did not open a logical channel (MANAGE CHANNEL status {}); \
                 it is probably not an eUICC",
                status_hex(&open).as_str().unwrap_or("none")
            ),
            json!({ "status": status_hex(&open) }),
        ));
    };
    let result = on_channel(session, channel, aid, max_segment, body);
    let closed = matches!(
        session::close_channel(session, channel),
        Ok(Some(ex)) if ex.is_success()
    );
    let mut data = result?;
    data["channel"] = json!({ "number": channel, "closed": closed });
    Ok(data)
}

fn on_channel<S: CardSession + ?Sized>(
    session: &mut S,
    channel: u8,
    aid: &[u8],
    max_segment: usize,
    body: impl FnOnce(&mut Ask<'_>) -> Result<Value, Failure>,
) -> Result<Value, Failure> {
    let policy = Policy {
        get_response_class: channel_cla(false, channel),
        proactive_command: PendingFollowUp::Ignore,
        ..Policy::default()
    };
    let select = Command::case4(
        Header::new(channel_cla(false, channel), 0xA4, 0x04, 0x00),
        aid,
        Le::Short(0),
    );
    let ex = session::send(session, &select, &policy).map_err(exchange_failed)?;
    if !ex.is_success() {
        return Err(Failure::new(
            "not-an-euicc",
            format!(
                "not an eUICC: the card refused SELECT of the ISD-R {} (status {})",
                hex::encode_upper(aid),
                status_hex(&ex).as_str().unwrap_or("none")
            ),
            json!({ "aid": hex::encode_upper(aid), "status": status_hex(&ex) }),
        ));
    }
    let cla = channel_cla(true, channel);
    let mut ask = |what: &'static str, request: Vec<u8>| -> Result<Vec<u8>, Failure> {
        let sent = es10::store_data_sized(session, cla, &request, max_segment, &policy)
            .map_err(exchange_failed)?;
        let last = sent.exchanges.last();
        if !sent.complete || !last.is_some_and(session::Exchange::is_success) {
            return Err(Failure::new(
                "es10-refused",
                format!(
                    "the ISD-R refused {what} (status {})",
                    last.map_or(Value::Null, status_hex)
                        .as_str()
                        .unwrap_or("none")
                ),
                json!({ "function": what }),
            ));
        }
        Ok(sent.data().to_vec())
    };
    let mut data = body(&mut ask)?;
    data["aid"] = json!(hex::encode_upper(aid));
    Ok(data)
}

fn bad(what: &'static str, e: es10::DecodeError) -> Failure {
    Failure::new(
        "decode-failed",
        format!("{what} response is malformed: {e}"),
        json!({ "function": what }),
    )
}

/// GetProfilesInfo for every profile, with [`PROFILE_TAGS`].
fn read_profiles(ask: &mut Ask<'_>) -> Result<Vec<es10::ProfileInfo>, Failure> {
    let request =
        es10::get_profiles_info_request(None, Some(&PROFILE_TAGS)).map_err(exchange_failed)?;
    match es10::decode_profiles_info(&ask("GetProfilesInfo", request)?)
        .map_err(|e| bad("GetProfilesInfo", e))?
    {
        es10::ProfileInfoListResponse::Ok { profiles, .. } => Ok(profiles),
        es10::ProfileInfoListResponse::Error(code) => Err(Failure::new(
            "es10-refused",
            format!("GetProfilesInfo returned error code {}", code.code()),
            json!({ "function": "GetProfilesInfo", "code": code.code() }),
        )),
    }
}

fn read_eid(ask: &mut Ask<'_>) -> Result<String, Failure> {
    let eid = es10::decode_get_eid(&ask("GetEID", es10::get_eid_request())?)
        .map_err(|e| bad("GetEID", e))?;
    Ok(hex::encode_upper(eid))
}

fn read_query(ask: &mut Ask<'_>, query: Query) -> Result<Value, Failure> {
    let mut data = json!({});
    match query {
        Query::Info => {
            let eid = read_eid(ask)?;
            let info1 =
                es10::decode_euicc_info1(&ask("GetEuiccInfo1", es10::get_euicc_info1_request())?)
                    .map_err(|e| bad("GetEuiccInfo1", e))?;
            let info2 =
                es10::decode_euicc_info2(&ask("GetEuiccInfo2", es10::get_euicc_info2_request())?)
                    .map_err(|e| bad("GetEuiccInfo2", e))?;
            let addresses = es10::decode_configured_addresses(&ask(
                "GetEuiccConfiguredAddresses",
                es10::get_euicc_configured_addresses_request(),
            )?)
            .map_err(|e| bad("GetEuiccConfiguredAddresses", e))?;
            data["eid"] = json!(eid);
            data["configured_addresses"] = json!({
                "default_smdp": addresses.default_dp_address,
                "root_smds": addresses.root_ds_address,
            });
            data["euicc_info1"] = info1_json(&info1);
            data["euicc_info2"] = info2_json(&info2);
        }
        Query::Profiles => {
            data["profiles"] = read_profiles(ask)?.iter().map(profile_json).collect();
        }
        Query::Notifications => {
            let response = es10::decode_list_notification(&ask(
                "ListNotification",
                es10::list_notification_request(),
            )?)
            .map_err(|e| bad("ListNotification", e))?;
            match response {
                es10::ListNotificationResponse::Ok(list) => {
                    data["notifications"] = list.iter().map(notification_json).collect();
                }
                es10::ListNotificationResponse::Error(code) => {
                    return Err(Failure::new(
                        "es10-refused",
                        format!("ListNotification returned error code {code}"),
                        json!({ "function": "ListNotification", "code": code }),
                    ));
                }
            }
        }
    }
    Ok(data)
}

/// An ICCID (18 to 20 decimal digits) as the 10 octets EF ICCID codes: BCD
/// with the nibbles swapped, padded with F (ETSI TS 102 221).
fn raw_iccid(iccid: &str) -> Result<[u8; 10], Failure> {
    if !(18..=20).contains(&iccid.len()) || !iccid.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Failure::new(
            "bad-iccid",
            format!("the ICCID must be 18 to 20 decimal digits, got {iccid:?}"),
            json!({}),
        ));
    }
    let mut padded = iccid.as_bytes().to_vec();
    padded.resize(20, b'F');
    let mut raw = [0u8; 10];
    for (out, pair) in raw.iter_mut().zip(padded.chunks(2)) {
        let nibble = |c: u8| if c == b'F' { 0xF } else { c - b'0' };
        *out = (nibble(pair[1]) << 4) | nibble(pair[0]);
    }
    Ok(raw)
}

/// A request to set one profile's nickname. Built by [`Nickname::new`], which
/// checks the ICCID and the name before anything touches a card.
#[derive(Debug, Clone)]
pub struct Nickname {
    iccid: String,
    raw_iccid: [u8; 10],
    name: String,
    /// Send SetNickname. `false` (the default of the CLI) reads the card and
    /// reports what would change, sending nothing that changes it.
    pub apply: bool,
}

impl Nickname {
    /// Validates `iccid` (18 to 20 decimal digits) and `name` (SGP.22 v2.5
    /// section 5.7.21: 0 to 64 bytes of UTF-8; an empty name clears the
    /// nickname; control characters are refused so the name cannot drive a
    /// terminal when it is shown).
    ///
    /// # Errors
    ///
    /// A [`Failure`] of kind `bad-iccid` or `bad-nickname`.
    pub fn new(iccid: &str, name: &str, apply: bool) -> Result<Self, Failure> {
        let raw_iccid = raw_iccid(iccid)?;
        if name.len() > es10::MAX_NICKNAME_BYTES {
            return Err(Failure::new(
                "bad-nickname",
                format!(
                    "the nickname is {} bytes of UTF-8; SGP.22 allows at most {}",
                    name.len(),
                    es10::MAX_NICKNAME_BYTES
                ),
                json!({ "bytes": name.len(), "max": es10::MAX_NICKNAME_BYTES }),
            ));
        }
        if name.chars().any(char::is_control) {
            return Err(Failure::new(
                "bad-nickname",
                "the nickname must not contain control characters".to_owned(),
                json!({}),
            ));
        }
        Ok(Self {
            iccid: iccid.to_owned(),
            raw_iccid,
            name: name.to_owned(),
            apply,
        })
    }
}

/// SetNickname (lpac `profile nickname`). Reads the EID and the profile list
/// first. Without [`Nickname::apply`] it stops there and reports the planned
/// change (`dry_run` true, `applied` false) having sent no write. With it, it
/// sends SetNickname, re-reads the profile list and fails with kind
/// `verify-failed` unless the nickname is now the requested one.
///
/// # Errors
///
/// A [`Failure`]; `iccid-not-found` when no profile has that ICCID (nothing is
/// written), `es10-refused` when the ISD-R rejects the change.
pub fn nickname<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    max_segment: usize,
    request: &Nickname,
) -> Result<Value, Failure> {
    in_channel(session, aid, max_segment, |ask| {
        let eid = read_eid(ask)?;
        let nickname_of = |profiles: &[es10::ProfileInfo]| {
            profiles
                .iter()
                .find(|p| p.iccid.as_deref() == Some(&request.raw_iccid[..]))
                .map(|p| p.profile_nickname.clone().unwrap_or_default())
        };
        let profiles = read_profiles(ask)?;
        let Some(current) = nickname_of(&profiles) else {
            return Err(Failure::new(
                "iccid-not-found",
                format!("no profile with ICCID {} on this eUICC", request.iccid),
                json!({
                    "eid": eid,
                    "iccid": request.iccid,
                    "iccids": profiles.iter().filter_map(|p| p.iccid.as_deref().map(iccid_text)).collect::<Vec<_>>(),
                }),
            ));
        };
        let mut data = json!({
            "eid": eid,
            "iccid": request.iccid,
            "current_nickname": current,
            "new_nickname": request.name,
            "dry_run": !request.apply,
            "applied": false,
        });
        if !request.apply {
            return Ok(data);
        }
        let frame = es10::set_nickname_request(&request.raw_iccid, &request.name)
            .map_err(exchange_failed)?;
        let result = es10::decode_set_nickname(&ask("SetNickname", frame)?)
            .map_err(|e| bad("SetNickname", e))?;
        if result == es10::SetNicknameResult::IccidNotFound {
            return Err(Failure::new(
                "iccid-not-found",
                format!("the ISD-R reports no profile with ICCID {}", request.iccid),
                json!({ "eid": data["eid"], "iccid": request.iccid }),
            ));
        }
        if result != es10::SetNicknameResult::Ok {
            return Err(Failure::new(
                "es10-refused",
                format!("SetNickname returned result code {}", result.code()),
                json!({ "function": "SetNickname", "code": result.code(), "eid": data["eid"] }),
            ));
        }
        let after = nickname_of(&read_profiles(ask)?);
        data["verified_nickname"] = json!(after);
        if after.as_deref() != Some(request.name.as_str()) {
            return Err(Failure::new(
                "verify-failed",
                format!(
                    "SetNickname was accepted but the profile list now shows {:?}, not {:?}",
                    after.as_deref().unwrap_or("(profile missing)"),
                    request.name
                ),
                json!({ "eid": data["eid"], "iccid": request.iccid, "expected": request.name, "actual": after }),
            ));
        }
        data["applied"] = json!(true);
        Ok(data)
    })
}

/// Which ES10c state change [`set_state`] makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// EnableProfile (lpac `profile enable`).
    Enable,
    /// DisableProfile (lpac `profile disable`).
    Disable,
}

/// A request to enable or disable one profile. Built by [`StateChange::new`],
/// which checks the identifier before anything touches a card.
#[derive(Debug, Clone)]
pub struct StateChange {
    action: Action,
    /// What the operator typed (the ICCID digits, or the AID in upper-case hex).
    target: String,
    iccid: Option<[u8; 10]>,
    aid: Option<Vec<u8>>,
    /// Send the request. `false` (the default of the CLI) reads the card and
    /// reports what would change, sending nothing that changes it.
    pub apply: bool,
}

impl StateChange {
    /// Validates `id`: 18 to 20 decimal digits are an ICCID, otherwise an
    /// ISD-P AID of 5 to 16 bytes written as hex (lpac takes 32 hex digits).
    ///
    /// # Errors
    ///
    /// A [`Failure`] of kind `bad-profile-id`.
    pub fn new(action: Action, id: &str, apply: bool) -> Result<Self, Failure> {
        let (iccid, aid, target) = if (18..=20).contains(&id.len())
            && id.bytes().all(|b| b.is_ascii_digit())
        {
            (Some(raw_iccid(id)?), None, id.to_owned())
        } else {
            match hex::decode(id) {
                Ok(aid) if (5..=16).contains(&aid.len()) => {
                    (None, Some(aid), id.to_ascii_uppercase())
                }
                _ => {
                    return Err(Failure::new(
                        "bad-profile-id",
                        format!(
                            "expected an ICCID (18 to 20 digits) or an ISD-P AID (10 to 32 hex digits), got {id:?}"
                        ),
                        json!({}),
                    ))
                }
            }
        };
        Ok(Self {
            action,
            target,
            iccid,
            aid,
            apply,
        })
    }

    fn matches(&self, p: &es10::ProfileInfo) -> bool {
        match (&self.iccid, &self.aid) {
            (Some(iccid), _) => p.iccid.as_deref() == Some(&iccid[..]),
            (_, Some(aid)) => p.isdp_aid.as_deref() == Some(&aid[..]),
            _ => false,
        }
    }

    fn identifier(&self) -> es10::ProfileIdentifier<'_> {
        match (&self.iccid, &self.aid) {
            (Some(iccid), _) => es10::ProfileIdentifier::Iccid(iccid),
            (_, Some(aid)) => es10::ProfileIdentifier::IsdpAid(aid),
            _ => unreachable!("StateChange::new sets one of iccid and aid"),
        }
    }
}

/// The refusal kind and wording for an ES10c result code other than ok(0)
/// (`enableResult` / `disableResult`, [SGP.22 v2.5 §5.7.16], §5.7.17; pySim
/// `rsp.asn`). `None` for a code neither function defines.
fn state_refusal(action: Action, code: u8) -> Option<(&'static str, &'static str)> {
    Some(match (code, action) {
        (1, _) => ("profile-not-found", "iccidOrAidNotFound"),
        (2, Action::Enable) => ("profile-not-in-disabled-state", "profileNotInDisabledState"),
        (2, Action::Disable) => ("profile-not-in-enabled-state", "profileNotInEnabledState"),
        (3, _) => ("disallowed-by-policy", "disallowedByPolicy"),
        (4, Action::Enable) => ("wrong-profile-reenabling", "wrongProfileReenabling"),
        (5, _) => ("cat-busy", "catBusy"),
        (127, _) => ("undefined-error", "undefinedError"),
        _ => return None,
    })
}

/// EnableProfile or DisableProfile (lpac `profile enable` / `profile disable`),
/// with REFRESH requested. Reads the EID and the profile list first and refuses,
/// sending nothing, an unknown profile (`profile-not-found`), enabling an enabled
/// profile (`already-enabled`) and disabling a disabled one (`already-disabled`).
/// Without [`StateChange::apply`] it stops there and reports the plan and its
/// `consequence` (`dry_run` true, `applied` false). With it, it sends the request,
/// maps every non-ok result code to its own error kind (see [`state_refusal`]),
/// re-reads the profile list and fails with `verify-failed` unless the profile is
/// now in the requested state.
///
/// # Errors
///
/// A [`Failure`].
pub fn set_state<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    max_segment: usize,
    request: &StateChange,
) -> Result<Value, Failure> {
    use es10::ProfileState::{Disabled, Enabled};
    let (want, name) = match request.action {
        Action::Enable => (Enabled, "EnableProfile"),
        Action::Disable => (Disabled, "DisableProfile"),
    };
    in_channel(session, aid, max_segment, |ask| {
        let eid = read_eid(ask)?;
        let profiles = read_profiles(ask)?;
        let Some(profile) = profiles.iter().find(|p| request.matches(p)) else {
            return Err(Failure::new(
                "profile-not-found",
                format!("no profile {} on this eUICC", request.target),
                json!({ "eid": eid, "profile": request.target,
                    "iccids": profiles.iter().filter_map(|p| p.iccid.as_deref().map(iccid_text)).collect::<Vec<_>>() }),
            ));
        };
        let current = profile.profile_state;
        if !matches!(current, Some(Enabled | Disabled)) {
            return Err(Failure::new(
                "profile-state-unknown",
                format!(
                    "profile {} reports no usable state; refusing",
                    request.target
                ),
                json!({ "eid": eid, "profile": request.target }),
            ));
        }
        if current == Some(want) {
            let (kind, word) = match want {
                Enabled => ("already-enabled", "enabled"),
                Disabled => ("already-disabled", "disabled"),
                es10::ProfileState::Unknown(_) => unreachable!(),
            };
            return Err(Failure::new(
                kind,
                format!("profile {} is already {word}; nothing sent", request.target),
                json!({ "eid": eid, "profile": request.target }),
            ));
        }
        let enabled = profiles
            .iter()
            .filter(|p| p.profile_state == Some(Enabled))
            .count();
        let consequence = match request.action {
            Action::Enable => "Enabling switches the active profile: the device loses its current connection until it re-attaches (REFRESH is requested).",
            Action::Disable if enabled == 1 => "Disabling the only enabled profile leaves the eUICC with no active profile: the device has no subscription until one is enabled (REFRESH is requested).",
            Action::Disable => "Disabling this profile leaves another profile enabled (REFRESH is requested).",
        };
        let state_text = |s: es10::ProfileState| if s == Enabled { "enabled" } else { "disabled" };
        let mut data = json!({
            "eid": eid,
            "action": match request.action { Action::Enable => "enable", Action::Disable => "disable" },
            "profile": request.target,
            "iccid": profile.iccid.as_deref().map(iccid_text),
            "isdp_aid": profile.isdp_aid.as_deref().map(hex::encode_upper),
            "current_state": current.map(state_text),
            "new_state": state_text(want),
            "refresh": true,
            "consequence": consequence,
            "dry_run": !request.apply,
            "applied": false,
        });
        if !request.apply {
            return Ok(data);
        }
        let frame = match request.action {
            Action::Enable => es10::enable_profile_request(request.identifier(), true),
            Action::Disable => es10::disable_profile_request(request.identifier(), true),
        }
        .map_err(exchange_failed)?;
        let response = ask(name, frame)?;
        let code = match request.action {
            Action::Enable => es10::decode_enable_profile(&response).map(|r| r.result.code()),
            Action::Disable => es10::decode_disable_profile(&response).map(|r| r.code()),
        }
        .map_err(|e| bad(name, e))?;
        if code != 0 {
            let (kind, word) =
                state_refusal(request.action, code).unwrap_or(("es10-refused", "unknown result"));
            return Err(Failure::new(
                kind,
                format!("{name} returned {word} (code {code}); the profile was not changed"),
                json!({ "function": name, "code": code, "eid": data["eid"], "profile": request.target }),
            ));
        }
        let after = read_profiles(ask)?
            .iter()
            .find(|p| request.matches(p))
            .and_then(|p| p.profile_state);
        data["verified_state"] = json!(after.map(state_text));
        if after != Some(want) {
            return Err(Failure::new(
                "verify-failed",
                format!(
                    "{name} was accepted but the profile list now shows {}, not {}",
                    after.map_or("(profile missing)", state_text),
                    state_text(want)
                ),
                json!({ "eid": data["eid"], "profile": request.target, "expected": state_text(want), "actual": after.map(state_text) }),
            ));
        }
        data["applied"] = json!(true);
        Ok(data)
    })
}

fn version(v: [u8; 3]) -> String {
    format!("{}.{}.{}", v[0], v[1], v[2])
}

fn hex_list(keys: &[Vec<u8>]) -> Value {
    keys.iter().map(hex::encode_upper).collect()
}

fn bits_json(b: &BitString, names: &[&str]) -> Value {
    let set: Vec<&str> = names
        .iter()
        .enumerate()
        .filter(|(i, _)| b.bit(*i))
        .map(|(_, n)| *n)
        .collect();
    json!({ "hex": hex::encode_upper(&b.bytes), "unused_bits": b.unused_bits, "set": set })
}

const RSP_CAPABILITY: [&str; 6] = [
    "additionalProfile",
    "crlSupport",
    "rpmSupport",
    "testProfileSupport",
    "deviceInfoExtensibilitySupport",
    "serviceSpecificDataSupport",
];

fn info1_json(i: &es10::EuiccInfo1) -> Value {
    json!({
        "svn": version(i.svn),
        "ci_pk_id_for_verification": hex_list(&i.ci_pk_id_for_verification),
        "ci_pk_id_for_signing": hex_list(&i.ci_pk_id_for_signing),
    })
}

fn info2_json(i: &es10::EuiccInfo2) -> Value {
    json!({
        "profile_version": version(i.profile_version),
        "svn": version(i.svn),
        "firmware_version": version(i.euicc_firmware_ver),
        "ext_card_resource": hex::encode_upper(&i.ext_card_resource),
        "uicc_capability": hex::encode_upper(&i.uicc_capability.bytes),
        "ts102241_version": i.ts102241_version.map(version),
        "globalplatform_version": i.globalplatform_version.map(version),
        "rsp_capability": bits_json(&i.rsp_capability, &RSP_CAPABILITY),
        "ci_pk_id_for_verification": hex_list(&i.ci_pk_id_for_verification),
        "ci_pk_id_for_signing": hex_list(&i.ci_pk_id_for_signing),
        "category": i.euicc_category.map(|c| match c {
            es10::EuiccCategory::Other => "other".to_owned(),
            es10::EuiccCategory::BasicEuicc => "basic".to_owned(),
            es10::EuiccCategory::MediumEuicc => "medium".to_owned(),
            es10::EuiccCategory::ContactlessEuicc => "contactless".to_owned(),
            es10::EuiccCategory::Unknown(n) => format!("unknown({n})"),
        }),
        "forbidden_profile_policy_rules": i.forbidden_profile_policy_rules.as_ref()
            .map(|b| bits_json(b, &["pprUpdateControl", "ppr1", "ppr2"])),
        "pp_version": version(i.pp_version),
        "sas_accreditation_number": i.sas_accreditation_number,
        "certification_data_object": i.certification_data_object.as_ref().map(|c| json!({
            "platform_label": c.platform_label,
            "discovery_base_url": c.discovery_base_url,
        })),
        "tre_properties": i.tre_properties.as_ref()
            .map(|b| bits_json(b, &["isDiscrete", "isIntegrated", "usesRemoteMemory"])),
        "tre_product_reference": i.tre_product_reference,
        "additional_profile_package_versions":
            i.additional_euicc_profile_package_versions.iter().map(|v| version(*v)).collect::<Vec<_>>(),
    })
}

/// The ICCID as digits (nibble-swapped, `F` padding dropped), falling back to
/// the raw hex if it is not decodable.
fn iccid_text(raw: &[u8]) -> String {
    crate::ef::decode_iccid(raw).map_or_else(|_| hex::encode_upper(raw), |d| d.as_str().to_owned())
}

fn profile_json(p: &es10::ProfileInfo) -> Value {
    use es10::{ProfileClass, ProfileState};
    json!({
        "iccid": p.iccid.as_deref().map(iccid_text),
        "isdp_aid": p.isdp_aid.as_deref().map(hex::encode_upper),
        "state": p.profile_state.map(|s| match s {
            ProfileState::Enabled => "enabled".to_owned(),
            ProfileState::Disabled => "disabled".to_owned(),
            ProfileState::Unknown(n) => format!("unknown({n})"),
        }),
        "nickname": p.profile_nickname,
        "provider": p.service_provider_name,
        "name": p.profile_name,
        "class": p.profile_class.map(|c| match c {
            ProfileClass::Test => "test".to_owned(),
            ProfileClass::Provisioning => "provisioning".to_owned(),
            ProfileClass::Operational => "operational".to_owned(),
            ProfileClass::Unknown(n) => format!("unknown({n})"),
        }),
    })
}

fn notification_json(n: &es10::NotificationMetadata) -> Value {
    let ops: Vec<&str> = ["install", "enable", "disable", "delete"]
        .iter()
        .enumerate()
        .filter(|(i, _)| n.operation.bit(*i))
        .map(|(_, s)| *s)
        .collect();
    json!({
        "seq_number": n.seq_number,
        "operation": ops,
        "address": n.address,
        "iccid": n.iccid.as_deref().map(iccid_text),
    })
}

/// The human report for `data` (as [`run`] returned it): `key: value` lines
/// and a table, every card-derived string through [`sanitize`].
pub fn to_human(query: Query, data: &Value) -> String {
    let text = |v: &Value| match v {
        Value::Null => "-".to_owned(),
        Value::String(s) => sanitize(s),
        other => sanitize(&other.to_string()),
    };
    let mut out = String::new();
    match query {
        Query::Info => {
            out += &format!("EID: {}\n", text(&data["eid"]));
            out += &format!(
                "SM-DP+ (default): {}\nSM-DS (root): {}\n",
                text(&data["configured_addresses"]["default_smdp"]),
                text(&data["configured_addresses"]["root_smds"]),
            );
            for (title, key) in [("EUICCInfo1", "euicc_info1"), ("EUICCInfo2", "euicc_info2")] {
                out += &format!("{title}:\n");
                if let Some(map) = data[key].as_object() {
                    for (k, v) in map {
                        let shown = match v {
                            Value::Array(a) => a.iter().map(&text).collect::<Vec<_>>().join(", "),
                            Value::Object(o) => o.values().map(&text).collect::<Vec<_>>().join(" "),
                            other => text(other),
                        };
                        out += &format!("  {k}: {shown}\n");
                    }
                }
            }
        }
        Query::Profiles => {
            out += "ICCID\tSTATE\tCLASS\tNICKNAME\tPROVIDER\tNAME\n";
            for p in data["profiles"].as_array().into_iter().flatten() {
                out += &format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\n",
                    text(&p["iccid"]),
                    text(&p["state"]),
                    text(&p["class"]),
                    text(&p["nickname"]),
                    text(&p["provider"]),
                    text(&p["name"]),
                );
            }
        }
        Query::Notifications => {
            out += "SEQ\tOPERATION\tICCID\tADDRESS\n";
            for n in data["notifications"].as_array().into_iter().flatten() {
                let ops = n["operation"]
                    .as_array()
                    .map(|a| a.iter().map(&text).collect::<Vec<_>>().join("+"))
                    .unwrap_or_default();
                out += &format!(
                    "{}\t{}\t{}\t{}\n",
                    text(&n["seq_number"]),
                    ops,
                    text(&n["iccid"]),
                    text(&n["address"]),
                );
            }
        }
    }
    out
}

/// The human report for [`nickname`]'s `data`.
pub fn nickname_to_human(data: &Value) -> String {
    let text = |v: &Value| match v {
        Value::Null => "-".to_owned(),
        Value::String(s) => sanitize(s),
        other => sanitize(&other.to_string()),
    };
    let mut out = format!(
        "EID: {}\nICCID: {}\nCurrent nickname: {:?}\nNew nickname: {:?}\n",
        text(&data["eid"]),
        text(&data["iccid"]),
        text(&data["current_nickname"]),
        text(&data["new_nickname"]),
    );
    out += if data["applied"] == true {
        "SetNickname sent; the profile list now shows the new nickname.\n"
    } else {
        "Dry run: nothing was sent. Re-run with --yes to set the nickname.\n"
    };
    out
}

/// The human report for [`set_state`]'s `data`.
pub fn state_to_human(data: &Value) -> String {
    let text = |v: &Value| match v {
        Value::Null => "-".to_owned(),
        Value::String(s) => sanitize(s),
        other => sanitize(&other.to_string()),
    };
    let verb = if data["action"] == "enable" {
        "Enable"
    } else {
        "Disable"
    };
    let mut out = format!(
        "EID: {}\nICCID: {}\nISD-P AID: {}\nState: {} -> {}\nConsequence: {}\n",
        text(&data["eid"]),
        text(&data["iccid"]),
        text(&data["isdp_aid"]),
        text(&data["current_state"]),
        text(&data["new_state"]),
        text(&data["consequence"]),
    );
    out += &if data["applied"] == true {
        format!("{verb}Profile sent; the profile list now shows the new state.\n")
    } else {
        format!(
            "Dry run: nothing was sent. Re-run with --yes to {}.\n",
            verb.to_lowercase()
        )
    };
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::replay::Replay;

    const EID: &str = "89049032123451234512345678901235";
    const ICCID_RAW: &str = "98001032547698103214";
    const ICCID: &str = "89000123456789012341";
    const SKI: &str = "81370F5125D0B1D408D4C3B232E6D25E795BEBFB";
    const INFO2: &str = "BF2281C6810302010082030202008303040600840F8101008204000628248304000019228504067F36C08603090200870302030088020490A916041481370F5125D0B1D408D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB990206C004030000010C0D47492D42412D55502D30343139AC48801F312E322E3834302E313233343536372F6D79506C6174666F726D4C6162656C812568747470733A2F2F6D79636F6D70616E792E636F6D2F6D79444C4F41526567697374726172";

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    /// STORE DATA on channel 1 (CLA 81) carrying `request`, as one block.
    fn store(request: &[u8]) -> String {
        format!(
            "81E29100{:02X}{}00",
            request.len(),
            hex::encode_upper(request)
        )
    }

    fn log(pairs: &[(String, String)]) -> String {
        pairs
            .iter()
            .map(|(c, r)| format!("{{\"command\":\"{c}\",\"response\":\"{r}\"}}\n"))
            .collect()
    }

    /// open, select, then the (request, response-with-SW) STORE DATA pairs,
    /// then close.
    fn script(select_sw: &str, steps: &[(Vec<u8>, String)]) -> Replay {
        let mut pairs = vec![
            ("0070000001".to_owned(), "019000".to_owned()),
            (
                format!(
                    "01A40400{:02X}{}00",
                    ISDR_AID.len(),
                    hex::encode_upper(ISDR_AID)
                ),
                select_sw.to_owned(),
            ),
        ];
        if select_sw == "9000" {
            for (req, resp) in steps {
                pairs.push((store(req), resp.clone()));
            }
        }
        pairs.push(("00708001".to_owned(), "9000".to_owned()));
        Replay::from_log(&log(&pairs)).unwrap()
    }

    fn ok(body: &str) -> String {
        format!("{}9000", body.replace(' ', ""))
    }

    #[test]
    fn info_reads_eid_info1_and_info2_and_closes_the_channel() {
        let info1 = format!("BF2035 82030202 00 A916 0414{SKI} AA16 0414{SKI}");
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), ok(&format!("BF3E12 5A10 {EID}"))),
                (es10::get_euicc_info1_request(), ok(&info1)),
                (es10::get_euicc_info2_request(), ok(INFO2)),
                (
                    es10::get_euicc_configured_addresses_request(),
                    ok(&format!(
                        "BF3C19 8007 {} 810E {}",
                        hex::encode("dp.exam"),
                        hex::encode("ds.example.org")
                    )),
                ),
            ],
        );
        let data = run(&mut card, &ISDR_AID, Query::Info).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["eid"], EID);
        assert_eq!(data["euicc_info1"]["svn"], "2.2.0");
        assert_eq!(data["euicc_info1"]["ci_pk_id_for_verification"][0], SKI);
        assert_eq!(data["euicc_info2"]["profile_version"], "2.1.0");
        assert_eq!(data["configured_addresses"]["default_smdp"], "dp.exam");
        assert_eq!(data["configured_addresses"]["root_smds"], "ds.example.org");
        assert_eq!(data["channel"], json!({ "number": 1, "closed": true }));
        let human = to_human(Query::Info, &data);
        assert!(human.starts_with(&format!("EID: {EID}\n")));
        assert!(human.contains("SM-DS (root): ds.example.org\n"));
    }

    /// A GetProfilesInfo response with one profile holding `nick` (none when
    /// empty) and the test ICCID.
    fn profile_response(nick: &str) -> String {
        let nick = if nick.is_empty() {
            String::new()
        } else {
            format!("90{:02X}{}", nick.len(), hex::encode(nick))
        };
        let body = format!(
            "5A0A{ICCID_RAW} 4F10A0000005591010FFFFFFFF89000010 00 9F700101 {nick} 9108 4F70657261746F72 9501 02"
        );
        ok(&fix_lengths(&body))
    }

    fn profiles_request() -> Vec<u8> {
        es10::get_profiles_info_request(None, Some(&PROFILE_TAGS)).unwrap()
    }

    fn eid_response() -> String {
        ok(&format!("BF3E12 5A10 {EID}"))
    }

    fn set_request(name: &str) -> Vec<u8> {
        es10::set_nickname_request(&h(ICCID_RAW), name).unwrap()
    }

    #[test]
    fn segment_size_cuts_the_store_data_blocks() {
        // GetProfilesInfo request is 12 bytes; at 5 bytes per block that is
        // three blocks: P1 11/11/91, P2 0/1/2, one logical exchange each.
        let request = profiles_request();
        let body = profile_response("nick");
        let mut pairs = vec![
            ("0070000001".to_owned(), "019000".to_owned()),
            (
                format!(
                    "01A40400{:02X}{}00",
                    ISDR_AID.len(),
                    hex::encode_upper(ISDR_AID)
                ),
                "9000".to_owned(),
            ),
        ];
        let chunks: Vec<&[u8]> = request.chunks(5).collect();
        for (i, c) in chunks.iter().enumerate() {
            let p1 = if i + 1 == chunks.len() { "91" } else { "11" };
            let resp = if i + 1 == chunks.len() {
                body.clone()
            } else {
                "9000".to_owned()
            };
            pairs.push((
                format!("81E2{p1}{i:02X}{:02X}{}00", c.len(), hex::encode_upper(c)),
                resp,
            ));
        }
        pairs.push(("00708001".to_owned(), "9000".to_owned()));
        let mut card = Replay::from_log(&log(&pairs)).unwrap();
        let data = run_with(&mut card, &ISDR_AID, Query::Profiles, 5).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["profiles"][0]["nickname"], "nick");
        assert!(chunks.len() > 1);
        // 0 and 256 are refused before anything is sent.
        let mut card = script("9000", &[]);
        assert_eq!(
            run_with(&mut card, &ISDR_AID, Query::Profiles, 0)
                .unwrap_err()
                .kind,
            "exchange-failed"
        );
    }

    #[test]
    fn nickname_dry_run_reads_and_sends_no_write() {
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), profile_response("old")),
            ],
        );
        let req = Nickname::new(ICCID, "new", false).unwrap();
        let data = nickname(&mut card, &ISDR_AID, 255, &req).unwrap();
        // open, select, GetEID, GetProfilesInfo, close; no SetNickname.
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["eid"], EID);
        assert_eq!(data["iccid"], ICCID);
        assert_eq!(data["current_nickname"], "old");
        assert_eq!(data["new_nickname"], "new");
        assert_eq!(data["dry_run"], true);
        assert_eq!(data["applied"], false);
        let human = nickname_to_human(&data);
        assert!(human.contains("Dry run: nothing was sent"));
        assert!(human.contains(&format!("ICCID: {ICCID}")));
    }

    #[test]
    fn nickname_with_yes_sends_set_nickname_then_verifies() {
        // Exact SetNickname frame, hand-written: BF29 11 5A0A <iccid> 9003 'n' 'e' 'w'.
        assert_eq!(
            set_request("new"),
            h(&format!("BF2911 5A0A{ICCID_RAW} 9003 6E6577"))
        );
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), profile_response("old")),
                (set_request("new"), ok("BF2903 8001 00")),
                (profiles_request(), profile_response("new")),
            ],
        );
        let req = Nickname::new(ICCID, "new", true).unwrap();
        let data = nickname(&mut card, &ISDR_AID, 255, &req).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["applied"], true);
        assert_eq!(data["dry_run"], false);
        assert_eq!(data["verified_nickname"], "new");
        assert!(nickname_to_human(&data).contains("SetNickname sent"));
    }

    #[test]
    fn nickname_accepted_but_not_visible_is_a_verify_failure() {
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), profile_response("old")),
                (set_request("new"), ok("BF2903 8001 00")),
                (profiles_request(), profile_response("old")),
            ],
        );
        let req = Nickname::new(ICCID, "new", true).unwrap();
        let failure = nickname(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "verify-failed");
        assert_eq!(failure.data["actual"], "old");
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn nickname_refused_by_the_isdr_is_es10_refused_and_not_verified() {
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), profile_response("old")),
                (set_request("new"), ok("BF2903 8001 7F")),
            ],
        );
        let req = Nickname::new(ICCID, "new", true).unwrap();
        let failure = nickname(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "es10-refused");
        assert_eq!(failure.data["code"], 127);
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn set_nickname_result_1_is_iccid_not_found() {
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), profile_response("old")),
                (set_request("new"), ok("BF2903800101")),
            ],
        );
        let req = Nickname::new(ICCID, "new", true).unwrap();
        let failure = nickname(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "iccid-not-found");
        assert_eq!(failure.data["iccid"], ICCID);
        assert_eq!(failure.data["eid"], EID);
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn nickname_for_an_unknown_iccid_sends_no_write() {
        let mut card = script(
            "9000",
            &[
                (es10::get_eid_request(), eid_response()),
                (profiles_request(), profile_response("old")),
            ],
        );
        let req = Nickname::new("89000123456789012349", "new", true).unwrap();
        let failure = nickname(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "iccid-not-found");
        assert_eq!(failure.data["iccids"], json!([ICCID]));
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn nickname_validation_happens_before_any_card_contact() {
        let long = "x".repeat(65);
        assert_eq!(
            Nickname::new(ICCID, &long, true).unwrap_err().kind,
            "bad-nickname"
        );
        assert_eq!(
            Nickname::new(ICCID, "a\u{1b}[31m", true).unwrap_err().kind,
            "bad-nickname"
        );
        assert_eq!(
            Nickname::new("1234", "ok", true).unwrap_err().kind,
            "bad-iccid"
        );
        assert_eq!(
            Nickname::new("8900012345678901234x", "ok", true)
                .unwrap_err()
                .kind,
            "bad-iccid"
        );
        assert!(Nickname::new(ICCID, &"x".repeat(64), true).is_ok());
        assert!(Nickname::new(ICCID, "", true).is_ok());
        // 19 digits pad with F in the last byte's high nibble.
        assert_eq!(
            Nickname::new("8900012345678901234", "a", false)
                .unwrap()
                .raw_iccid[9],
            0xF4
        );
    }

    const AID_HEX: &str = "A0000005591010FFFFFFFF8900001000";
    const OTHER_RAW: &str = "98001032547698103299";

    /// A GetProfilesInfo response with the test profile in `state` (0 disabled,
    /// 1 enabled) and, when `other` is set, a second profile in that state.
    fn states_response(state: u8, other: Option<u8>) -> String {
        let one = |raw: &str, aid: &str, st: u8| {
            let body = format!("5A0A{raw}4F10{aid}9F7001{st:02X}");
            format!("E3{:02X}{body}", body.len() / 2)
        };
        let mut list = one(ICCID_RAW, AID_HEX, state);
        if let Some(o) = other {
            list += &one(OTHER_RAW, "A0000005591010FFFFFFFF8900001001", o);
        }
        let a0 = format!("A0{:02X}{list}", list.len() / 2);
        ok(&format!("BF2D{:02X}{a0}", a0.len() / 2))
    }

    fn change_request(action: Action) -> Vec<u8> {
        let id = es10::ProfileIdentifier::Iccid(&h(ICCID_RAW));
        match action {
            Action::Enable => es10::enable_profile_request(id, true),
            Action::Disable => es10::disable_profile_request(id, true),
        }
        .unwrap()
    }

    fn eid_and_profiles(state: u8, other: Option<u8>) -> Vec<(Vec<u8>, String)> {
        vec![
            (es10::get_eid_request(), eid_response()),
            (profiles_request(), states_response(state, other)),
        ]
    }

    #[test]
    fn enable_and_disable_frames_are_the_hand_written_bytes() {
        assert_eq!(
            change_request(Action::Enable),
            h(&format!("BF3111 A00C 5A0A{ICCID_RAW} 8101FF"))
        );
        assert_eq!(
            change_request(Action::Disable),
            h(&format!("BF3211 A00C 5A0A{ICCID_RAW} 8101FF"))
        );
    }

    #[test]
    fn dry_run_reads_and_sends_nothing_for_both_actions() {
        for (action, from, other, needle) in [
            (Action::Enable, 0, Some(1), "switches the active profile"),
            (Action::Disable, 1, None, "no active profile"),
        ] {
            let mut card = script("9000", &eid_and_profiles(from, other));
            let req = StateChange::new(action, ICCID, false).unwrap();
            let data = set_state(&mut card, &ISDR_AID, 255, &req).unwrap();
            assert_eq!(card.remaining(), 0);
            assert_eq!(data["dry_run"], true);
            assert_eq!(data["applied"], false);
            assert_eq!(data["iccid"], ICCID);
            assert_eq!(data["isdp_aid"], AID_HEX);
            assert!(data["consequence"].as_str().unwrap().contains(needle));
            let human = state_to_human(&data);
            assert!(human.contains("Dry run: nothing was sent"));
            assert!(human.contains(needle));
        }
        // Disabling one of two enabled profiles does not say "no active profile".
        let mut card = script("9000", &eid_and_profiles(1, Some(1)));
        let req = StateChange::new(Action::Disable, ICCID, false).unwrap();
        let data = set_state(&mut card, &ISDR_AID, 255, &req).unwrap();
        assert!(!data["consequence"].as_str().unwrap().contains("no active"));
    }

    #[test]
    fn yes_sends_the_exact_frame_then_verifies_for_both_actions() {
        for (action, from, to) in [(Action::Enable, 0, 1), (Action::Disable, 1, 0)] {
            let (tag, name) = match action {
                Action::Enable => ("BF31", "enabled"),
                Action::Disable => ("BF32", "disabled"),
            };
            let mut steps = eid_and_profiles(from, None);
            steps.push((change_request(action), ok(&format!("{tag}03 8001 00"))));
            steps.push((profiles_request(), states_response(to, None)));
            let mut card = script("9000", &steps);
            let req = StateChange::new(action, ICCID, true).unwrap();
            let data = set_state(&mut card, &ISDR_AID, 255, &req).unwrap();
            assert_eq!(card.remaining(), 0);
            assert_eq!(data["applied"], true);
            assert_eq!(data["dry_run"], false);
            assert_eq!(data["verified_state"], name);
            assert!(state_to_human(&data).contains("Profile sent"));
        }
    }

    #[test]
    fn an_aid_names_the_profile_with_tag_4f() {
        let aid = h(AID_HEX);
        let frame =
            es10::enable_profile_request(es10::ProfileIdentifier::IsdpAid(&aid), true).unwrap();
        assert_eq!(frame, h(&format!("BF3117 A012 4F10{AID_HEX} 8101FF")));
        let mut steps = eid_and_profiles(0, None);
        steps.push((frame, ok("BF3103 8001 00")));
        steps.push((profiles_request(), states_response(1, None)));
        let mut card = script("9000", &steps);
        let req = StateChange::new(Action::Enable, &AID_HEX.to_lowercase(), true).unwrap();
        let data = set_state(&mut card, &ISDR_AID, 255, &req).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["verified_state"], "enabled");
    }

    #[test]
    fn every_result_code_is_its_own_kind_and_is_not_verified() {
        let cases: [(Action, &str, &str); 12] = [
            (Action::Enable, "01", "profile-not-found"),
            (Action::Enable, "02", "profile-not-in-disabled-state"),
            (Action::Enable, "03", "disallowed-by-policy"),
            (Action::Enable, "04", "wrong-profile-reenabling"),
            (Action::Enable, "05", "cat-busy"),
            (Action::Enable, "7F", "undefined-error"),
            (Action::Disable, "01", "profile-not-found"),
            (Action::Disable, "02", "profile-not-in-enabled-state"),
            (Action::Disable, "03", "disallowed-by-policy"),
            (Action::Disable, "05", "cat-busy"),
            (Action::Disable, "7F", "undefined-error"),
            (Action::Disable, "63", "es10-refused"),
        ];
        for (action, code, kind) in cases {
            let (tag, from) = match action {
                Action::Enable => ("BF31", 0),
                Action::Disable => ("BF32", 1),
            };
            let mut steps = eid_and_profiles(from, None);
            steps.push((change_request(action), ok(&format!("{tag}03 8001 {code}"))));
            let mut card = script("9000", &steps);
            let req = StateChange::new(action, ICCID, true).unwrap();
            let failure = set_state(&mut card, &ISDR_AID, 255, &req).unwrap_err();
            assert_eq!(failure.kind, kind, "{action:?} {code}");
            assert_eq!(failure.data["code"], i64::from_str_radix(code, 16).unwrap());
            assert_eq!(card.remaining(), 0, "no verify read after a refusal");
        }
    }

    #[test]
    fn accepted_but_unchanged_is_a_verify_failure() {
        let mut steps = eid_and_profiles(0, None);
        steps.push((change_request(Action::Enable), ok("BF3103 8001 00")));
        steps.push((profiles_request(), states_response(0, None)));
        let mut card = script("9000", &steps);
        let req = StateChange::new(Action::Enable, ICCID, true).unwrap();
        let failure = set_state(&mut card, &ISDR_AID, 255, &req).unwrap_err();
        assert_eq!(failure.kind, "verify-failed");
        assert_eq!(failure.data["actual"], "disabled");
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn wrong_state_is_refused_with_nothing_sent() {
        for (action, from, kind) in [
            (Action::Enable, 1, "already-enabled"),
            (Action::Disable, 0, "already-disabled"),
        ] {
            let mut card = script("9000", &eid_and_profiles(from, None));
            let req = StateChange::new(action, ICCID, true).unwrap();
            let failure = set_state(&mut card, &ISDR_AID, 255, &req).unwrap_err();
            assert_eq!(failure.kind, kind);
            assert_eq!(card.remaining(), 0);
        }
    }

    #[test]
    fn an_unknown_profile_is_refused_with_nothing_sent() {
        for id in ["89000123456789012349", "A0000005591010FFFFFFFF8900009999"] {
            let mut card = script("9000", &eid_and_profiles(0, None));
            let req = StateChange::new(Action::Enable, id, true).unwrap();
            let failure = set_state(&mut card, &ISDR_AID, 255, &req).unwrap_err();
            assert_eq!(failure.kind, "profile-not-found");
            assert_eq!(failure.data["iccids"], json!([ICCID]));
            assert_eq!(card.remaining(), 0);
        }
    }

    #[test]
    fn state_change_validation_happens_before_any_card_contact() {
        for bad in [
            "",
            "1234",
            "8900012345678901234x",
            "A000",
            "ZZ00000000",
            &"A0".repeat(17),
        ] {
            assert_eq!(
                StateChange::new(Action::Enable, bad, true)
                    .unwrap_err()
                    .kind,
                "bad-profile-id",
                "{bad:?}"
            );
        }
        assert!(StateChange::new(Action::Disable, AID_HEX, true).is_ok());
        assert!(StateChange::new(Action::Disable, "89000123456789012", true).is_err());
    }

    #[test]
    fn profiles_lists_state_nickname_provider_and_class() {
        let request = es10::get_profiles_info_request(None, Some(&PROFILE_TAGS)).unwrap();
        let body = format!(
            "BF2D32 A030 E32E 5A0A{ICCID_RAW} 4F10A0000005591010FFFFFFFF89000010 00 9F700101 9004 6E69636B 9108 4F70657261746F72 9501 02"
        );
        // Hand-built lengths are checked by the decoder, so size them honestly.
        let body = fix_lengths(&body);
        let mut card = script("9000", &[(request, ok(&body))]);
        let data = run(&mut card, &ISDR_AID, Query::Profiles).unwrap();
        assert_eq!(card.remaining(), 0);
        let p = &data["profiles"][0];
        assert_eq!(p["iccid"], ICCID);
        assert_eq!(p["state"], "enabled");
        assert_eq!(p["nickname"], "nick");
        assert_eq!(p["provider"], "Operator");
        assert_eq!(p["class"], "operational");
        let human = to_human(Query::Profiles, &data);
        assert!(human.contains(&format!("{ICCID}\tenabled\toperational\tnick\tOperator")));
    }

    /// Rebuilds `BF2D ln A0 ln E3 ln <profile>` around a profile body so the
    /// test does not hard-code three nested lengths.
    fn fix_lengths(spaced: &str) -> String {
        let flat = spaced.replace(' ', "");
        let inner = &flat[flat.find("5A0A").unwrap()..];
        let e3 = format!("E3{:02X}{inner}", inner.len() / 2);
        let a0 = format!("A0{:02X}{e3}", e3.len() / 2);
        format!("BF2D{:02X}{a0}", a0.len() / 2)
    }

    #[test]
    fn notifications_list_metadata_only() {
        let addr = "smdp.example.org";
        let meta = format!(
            "800105 8102 0480 0C{:02X}{} 5A0A{ICCID_RAW}",
            addr.len(),
            hex::encode(addr)
        )
        .replace(' ', "");
        let mut card = {
            let n = format!("BF2F{:02X}{meta}", meta.len() / 2);
            let a0 = format!("A0{:02X}{n}", n.len() / 2);
            let all = format!("BF28{:02X}{a0}", a0.len() / 2);
            script("9000", &[(es10::list_notification_request(), ok(&all))])
        };
        let data = run(&mut card, &ISDR_AID, Query::Notifications).unwrap();
        assert_eq!(card.remaining(), 0);
        let n = &data["notifications"][0];
        assert_eq!(n["seq_number"], 5);
        assert_eq!(n["operation"], json!(["install"]));
        assert_eq!(n["iccid"], ICCID);
        assert_eq!(n["address"], "smdp.example.org");
        assert!(to_human(Query::Notifications, &data).contains("install"));
    }

    #[test]
    fn a_61xx_answer_is_collected_with_get_response_on_the_channel() {
        let body = format!("BF3E12 5A10 {EID}").replace(' ', "");
        let pairs = vec![
            ("0070000001".to_owned(), "019000".to_owned()),
            (
                format!(
                    "01A40400{:02X}{}00",
                    ISDR_AID.len(),
                    hex::encode_upper(ISDR_AID)
                ),
                "9000".to_owned(),
            ),
            (store(&es10::get_eid_request()), "6114".to_owned()),
            ("01C0000014".to_owned(), format!("{body}9000")),
        ];
        let mut card = Replay::from_log(&log(&pairs)).unwrap();
        let policy = Policy {
            get_response_class: channel_cla(false, 1),
            proactive_command: PendingFollowUp::Ignore,
            ..Policy::default()
        };
        session::send(&mut card, &crate::session::manage_channel_open(), &policy).unwrap();
        let select = Command::case4(
            Header::new(0x01, 0xA4, 0x04, 0x00),
            &ISDR_AID[..],
            Le::Short(0),
        );
        session::send(&mut card, &select, &policy).unwrap();
        let sent = es10::store_data(&mut card, 0x81, &es10::get_eid_request(), &policy).unwrap();
        assert_eq!(es10::decode_get_eid(sent.data()).unwrap(), h(EID)[..]);
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn empty_lists_are_ok() {
        let mut card = script(
            "9000",
            &[(es10::list_notification_request(), ok("BF2802 A000"))],
        );
        let data = run(&mut card, &ISDR_AID, Query::Notifications).unwrap();
        assert_eq!(data["notifications"], json!([]));
    }

    #[test]
    fn a_non_euicc_card_is_a_clean_failure_and_gets_no_store_data() {
        let mut card = script("6A82", &[]);
        let failure = run(&mut card, &ISDR_AID, Query::Info).unwrap_err();
        assert_eq!(failure.kind, "not-an-euicc");
        assert!(failure.message.starts_with("not an eUICC"));
        assert_eq!(failure.data["error"]["kind"], "not-an-euicc");
        assert_eq!(failure.data["status"], "6A82");
        // open, select, close: the channel was closed and nothing else sent.
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn a_card_that_refuses_manage_channel_is_reported() {
        let log = log(&[("0070000001".to_owned(), "6881".to_owned())]);
        let mut card = Replay::from_log(&log).unwrap();
        let failure = run(&mut card, &ISDR_AID, Query::Info).unwrap_err();
        assert_eq!(failure.kind, "channel-unavailable");
        assert_eq!(failure.data["status"], "6881");
    }

    #[test]
    fn a_malformed_tlv_is_a_decode_failure_and_the_channel_still_closes() {
        // BF3E claims 0x12 bytes and holds 2.
        let mut card = script("9000", &[(es10::get_eid_request(), ok("BF3E12 5A10"))]);
        let failure = run(&mut card, &ISDR_AID, Query::Info).unwrap_err();
        assert_eq!(failure.kind, "decode-failed");
        assert_eq!(failure.data["function"], "GetEID");
        assert_eq!(card.remaining(), 0);
    }

    #[test]
    fn an_isdr_refusal_is_es10_refused() {
        let mut card = script("9000", &[(es10::get_eid_request(), "6985".to_owned())]);
        let failure = run(&mut card, &ISDR_AID, Query::Info).unwrap_err();
        assert_eq!(failure.kind, "es10-refused");
        assert_eq!(failure.data["function"], "GetEID");
    }

    #[test]
    fn card_text_cannot_drive_the_terminal() {
        let data = json!({ "profiles": [{ "iccid": "1", "state": "enabled", "class": "test",
            "nickname": "a\u{1b}[31mb\u{202e}c", "provider": null, "name": "x" }] });
        let human = to_human(Query::Profiles, &data);
        assert!(!human.contains('\u{1b}') && !human.contains('\u{202e}'));
    }

    #[test]
    fn logical_channel_classes() {
        assert_eq!(channel_cla(false, 1), 0x01);
        assert_eq!(channel_cla(true, 1), 0x81);
        assert_eq!(channel_cla(false, 4), 0x40);
        assert_eq!(channel_cla(true, 5), 0xC1);
    }

    #[test]
    fn requests_are_the_documented_frames() {
        assert_eq!(es10::get_eid_request(), h("BF3E035C015A"));
        assert_eq!(es10::list_notification_request(), h("BF2800"));
    }
}
