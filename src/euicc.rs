//! eUICC, read-only: select the ISD-R on a logical channel and read what
//! ES10 will say without changing anything (issues #116, #132).
//!
//! **Owns.** The three read-only queries behind `sim-doctor euicc`: `info`
//! (GetEID, GetEuiccInfo1, GetEuiccInfo2), `profiles` (GetProfilesInfo) and
//! `notifications` (ListNotification, metadata only), the JSON each produces
//! and the sanitized human table. lpac names: `chip info`, `profile list`,
//! `notification list`.
//!
//! **Does not own, and never sends.** EnableProfile, DeleteProfile,
//! RetrieveNotificationsList, RemoveNotificationFromList, the download
//! functions or anything over HTTPS. The only commands on the wire are MANAGE
//! CHANNEL (open, close), SELECT of the ISD-R, and STORE DATA carrying one of
//! the three requests above. The channel is closed again on every path, a
//! failure included.
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
    let result = on_channel(session, channel, aid, query);
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
    query: Query,
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
        let sent = es10::store_data(session, cla, &request, &policy).map_err(exchange_failed)?;
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
    let bad = |what: &'static str, e: es10::DecodeError| {
        Failure::new(
            "decode-failed",
            format!("{what} response is malformed: {e}"),
            json!({ "function": what }),
        )
    };
    let mut data = json!({ "aid": hex::encode_upper(aid) });
    match query {
        Query::Info => {
            let eid = es10::decode_get_eid(&ask("GetEID", es10::get_eid_request())?)
                .map_err(|e| bad("GetEID", e))?;
            let info1 =
                es10::decode_euicc_info1(&ask("GetEuiccInfo1", es10::get_euicc_info1_request())?)
                    .map_err(|e| bad("GetEuiccInfo1", e))?;
            let info2 =
                es10::decode_euicc_info2(&ask("GetEuiccInfo2", es10::get_euicc_info2_request())?)
                    .map_err(|e| bad("GetEuiccInfo2", e))?;
            data["eid"] = json!(hex::encode_upper(eid));
            data["euicc_info1"] = info1_json(&info1);
            data["euicc_info2"] = info2_json(&info2);
        }
        Query::Profiles => {
            let request = es10::get_profiles_info_request(None, Some(&PROFILE_TAGS))
                .map_err(exchange_failed)?;
            let response = es10::decode_profiles_info(&ask("GetProfilesInfo", request)?)
                .map_err(|e| bad("GetProfilesInfo", e))?;
            match response {
                es10::ProfileInfoListResponse::Ok { profiles, .. } => {
                    data["profiles"] = profiles.iter().map(profile_json).collect();
                }
                es10::ProfileInfoListResponse::Error(code) => {
                    return Err(Failure::new(
                        "es10-refused",
                        format!("GetProfilesInfo returned error code {}", code.code()),
                        json!({ "function": "GetProfilesInfo", "code": code.code() }),
                    ));
                }
            }
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
            ],
        );
        let data = run(&mut card, &ISDR_AID, Query::Info).unwrap();
        assert_eq!(card.remaining(), 0);
        assert_eq!(data["eid"], EID);
        assert_eq!(data["euicc_info1"]["svn"], "2.2.0");
        assert_eq!(data["euicc_info1"]["ci_pk_id_for_verification"][0], SKI);
        assert_eq!(data["euicc_info2"]["profile_version"], "2.1.0");
        assert_eq!(data["channel"], json!({ "number": 1, "closed": true }));
        let human = to_human(Query::Info, &data);
        assert!(human.starts_with(&format!("EID: {EID}\n")));
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
