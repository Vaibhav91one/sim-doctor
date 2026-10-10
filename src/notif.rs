//! Replaying a dumped eUICC notification to its operator (issue #119).
//!
//! **Owns.** Reading the file `sim-doctor euicc notifications dump` writes
//! ([`crate::euicc::dump_notifications`]; the full `--json` envelope of that
//! command is accepted too) and sending each `PendingNotification` to its
//! `notificationAddress` as ES9+.HandleNotification ([`crate::es9`], SGP.22
//! v2.5 §5.6.4: `POST /gsma/rsp2/es9plus/handleNotification`, answered `204`).
//!
//! **Does not own.** The card (nothing here opens a reader, and a replayed
//! notification is never removed from the eUICC: `notifications remove` is the
//! only thing that removes one), the transport (a caller passes an
//! [`Es9Transport`]) or the signature (the server judges that).
//!
//! **Safety.** Replaying tells the operator's server about a profile event
//! over the network, so [`replay`] sends nothing unless it is handed a
//! transport; with `None` it validates the file and reports the target of
//! each notification and what would be sent. The decoded fields in the file
//! are for reading only: the address and sequence number used are re-read from
//! the signed bytes (`pending_notification_hex`) with
//! [`es10::decode_pending_notification`], and every address is validated as an
//! FQDN ([`SmdpAddress`]) before the first request goes out.

/// This module's name.
pub const NAME: &str = "notif";

use serde_json::{json, Value};

use crate::es10::{self, PendingNotification};
use crate::es9::{self, Es9Transport, SmdpAddress};
use crate::euicc::{notification_json, Failure, DUMP_FORMAT};

/// Notifications in a dump file, from its text.
///
/// # Errors
///
/// `bad-dump` when the text is not a dump of this format, holds no
/// notification, or one of its `pending_notification_hex` does not decode.
pub fn load(text: &str) -> Result<Vec<PendingNotification>, Failure> {
    let bad = |message: String| Failure::new("bad-dump", message, json!({}));
    let root: Value =
        serde_json::from_str(text).map_err(|e| bad(format!("the dump is not JSON: {e}")))?;
    // The `--json` envelope of `notifications dump` wraps the same document.
    let doc = if root.get("data").is_some_and(Value::is_object) {
        &root["data"]
    } else {
        &root
    };
    if doc["format"] != DUMP_FORMAT {
        return Err(bad(format!(
            "not a notification dump: `format` is not {DUMP_FORMAT:?}"
        )));
    }
    let Some(entries) = doc["notifications"].as_array().filter(|a| !a.is_empty()) else {
        return Err(bad("the dump holds no notification".to_owned()));
    };
    entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let raw = entry["pending_notification_hex"]
                .as_str()
                .and_then(|h| hex::decode(h).ok())
                .ok_or_else(|| {
                    bad(format!(
                        "notification {i}: pending_notification_hex is missing or not hex"
                    ))
                })?;
            es10::decode_pending_notification(&raw)
                .map_err(|e| bad(format!("notification {i}: {e}")))
        })
        .collect()
}

/// Replays every notification in the dump `text`. `transport: None` is the
/// dry run: nothing is sent and the result lists the target of each. With a
/// transport each is POSTed in file order to
/// `https://<notificationAddress>/gsma/rsp2/es9plus/handleNotification`; the
/// first failure stops the run (`replay-failed`, with the ones already sent in
/// `notifications`). Nothing is ever removed from the card.
///
/// # Errors
///
/// A [`Failure`]: `bad-dump`, `bad-address` (before anything is sent) or
/// `replay-failed`.
pub fn replay(text: &str, transport: Option<&mut dyn Es9Transport>) -> Result<Value, Failure> {
    let list = load(text)?;
    let mut targets = Vec::new();
    for p in &list {
        let smdp = SmdpAddress::parse(&p.metadata.address).map_err(|e| {
            Failure::new(
                "bad-address",
                format!("notification {}: {e}; nothing sent", p.metadata.seq_number),
                json!({ "seq_number": p.metadata.seq_number }),
            )
        })?;
        targets.push(es9::handle_notification(&smdp, &p.raw));
    }
    let mut results: Vec<Value> = list
        .iter()
        .zip(&targets)
        .map(|(p, request)| {
            let mut v = notification_json(&p.metadata);
            v["url"] = json!(request.url);
            v["body_bytes"] = json!(request.body.len());
            v["sent"] = json!(false);
            v
        })
        .collect();
    let mut data = json!({
        "command": "notification-replay",
        "dry_run": transport.is_none(),
        "consequence": "Replaying tells the operator's server about this profile event over the network. The notification stays on the eUICC; remove it with `notifications remove`.",
        "notifications": [],
    });
    if let Some(transport) = transport {
        for (i, request) in targets.iter().enumerate() {
            let outcome = transport
                .post(
                    &request.url,
                    &es9::Request::headers(),
                    request.body.as_bytes(),
                )
                .map_err(|e| e.to_string())
                .and_then(|r| es9::parse_handle_notification(&r).map_err(|e| e.to_string()));
            if let Err(why) = outcome {
                data["notifications"] = json!(results);
                return Err(Failure::new(
                    "replay-failed",
                    format!(
                        "notification {} to {}: {why}; {i} sent before it",
                        list[i].metadata.seq_number, request.url
                    ),
                    json!({ "notifications": results, "failed_index": i }),
                ));
            }
            results[i]["sent"] = json!(true);
        }
    }
    data["notifications"] = json!(results);
    Ok(data)
}

/// The human report for [`replay`]; card-derived text goes through the sanitizer.
pub fn to_human(data: &Value) -> String {
    use crate::contract::sanitize;
    let mut out = String::new();
    for n in data["notifications"].as_array().into_iter().flatten() {
        out += &format!(
            "{} {} -> {} ({} bytes){}\n",
            sanitize(&n["seq_number"].to_string()),
            sanitize(n["iccid"].as_str().unwrap_or("-")),
            sanitize(n["url"].as_str().unwrap_or("-")),
            n["body_bytes"],
            if n["sent"] == true { " sent" } else { "" },
        );
    }
    out += &format!(
        "Consequence: {}\n",
        sanitize(data["consequence"].as_str().unwrap_or(""))
    );
    out += if data["dry_run"] == true {
        "Dry run: nothing was sent. Re-run with --yes to send.\n"
    } else {
        "Sent. The notifications are still on the eUICC.\n"
    };
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::es9::{Response, TransportError};

    // BF37 { BF27 { 80 TID, BF2F { 80 05, 81 04 80, 0C smdp.example.com, 5A ICCID } } 5F37 sig }
    const META: &str =
        "800105 810204 80 0C10736D64702E6578616D706C652E636F6D 5A0A98681032547698103254";
    fn pir() -> Vec<u8> {
        let meta = hex::decode(format!(
            "BF2F{:02X}{}",
            META.replace(' ', "").len() / 2,
            META.replace(' ', "")
        ))
        .unwrap();
        let mut data = vec![0x80, 0x02, 0xAB, 0xCD];
        data.extend(meta);
        let mut pir = vec![0xBF, 0x27, data.len() as u8];
        pir.extend(data);
        pir.extend([0x5F, 0x37, 0x02, 0x11, 0x22]);
        let mut out = vec![0xBF, 0x37, pir.len() as u8];
        out.extend(pir);
        out
    }

    fn dump(raw: &[u8]) -> String {
        json!({ "format": DUMP_FORMAT, "eid": "89", "notifications": [
            { "pending_notification_hex": hex::encode_upper(raw) } ] })
        .to_string()
    }

    struct Recorder(Vec<(String, Vec<u8>)>, u16);
    impl Es9Transport for Recorder {
        fn post(
            &mut self,
            url: &str,
            _h: &[(&str, &str)],
            body: &[u8],
        ) -> Result<Response, TransportError> {
            self.0.push((url.to_owned(), body.to_vec()));
            Ok(Response {
                status: self.1,
                headers: vec![],
                body: vec![],
            })
        }
    }

    #[test]
    fn dry_run_validates_and_sends_nothing() {
        let data = replay(&dump(&pir()), None).unwrap();
        assert_eq!(data["dry_run"], true);
        let n = &data["notifications"][0];
        assert_eq!(
            n["url"],
            "https://smdp.example.com/gsma/rsp2/es9plus/handleNotification"
        );
        assert_eq!(n["sent"], false);
        assert!(to_human(&data).contains("Dry run"));
    }

    #[test]
    fn yes_posts_the_signed_bytes_to_the_address() {
        let mut rec = Recorder(vec![], 204);
        let data = replay(&dump(&pir()), Some(&mut rec)).unwrap();
        assert_eq!(data["notifications"][0]["sent"], true);
        assert_eq!(rec.0.len(), 1);
        assert_eq!(
            rec.0[0].0,
            "https://smdp.example.com/gsma/rsp2/es9plus/handleNotification"
        );
        let body = String::from_utf8(rec.0[0].1.clone()).unwrap();
        assert_eq!(
            body,
            es9::handle_notification(&SmdpAddress::parse("smdp.example.com").unwrap(), &pir()).body
        );
    }

    #[test]
    fn a_refusing_server_is_replay_failed() {
        let mut rec = Recorder(vec![], 500);
        let f = replay(&dump(&pir()), Some(&mut rec)).unwrap_err();
        assert_eq!(f.kind, "replay-failed");
    }

    #[test]
    fn bad_files_and_addresses_are_refused_before_sending() {
        for text in [
            "nope",
            "{}",
            &dump(&[0x30, 0x00]),
            &dump(&[0xBF, 0x37, 0x00]),
        ] {
            assert_eq!(replay(text, None).unwrap_err().kind, "bad-dump", "{text}");
        }
        let mut rec = Recorder(vec![], 204);
        let evil = hex::decode(
            "30 19 BF2F 16 800105 810204 80 0C0D6578616D706C652E636F6D2F78".replace(' ', ""),
        );
        // address "example.com/x" is not an FQDN
        let f = replay(&dump(&evil.unwrap()), Some(&mut rec)).unwrap_err();
        assert_eq!(f.kind, "bad-address");
        assert!(rec.0.is_empty());
    }

    #[test]
    fn the_envelope_of_dump_is_accepted() {
        let wrapped = json!({ "type": "lpa", "payload": { "code": 0 }, "data": serde_json::from_str::<Value>(&dump(&pir())).unwrap() });
        assert_eq!(load(&wrapped.to_string()).unwrap().len(), 1);
    }
}
