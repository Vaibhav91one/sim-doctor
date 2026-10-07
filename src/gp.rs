//! GlobalPlatform, read-only: find the issuer security domain, read what it
//! will say with GET DATA, decode CPLC and the key information template, and
//! compute an AES key check value.
//!
//! **Owns.** The `gp info` data: SELECT of the ISD by AID, GET DATA for CPLC,
//! card data, key information, IIN and CIN, the decoders, the machine-readable
//! APDU trace, and [`aes_kcv`].
//!
//! **Does not own, and never sends.** INITIALIZE UPDATE, EXTERNAL AUTHENTICATE,
//! STORE DATA, INSTALL, LOAD, DELETE, PUT KEY, SET STATUS, MANAGE CHANNEL. The
//! only instructions built here are SELECT and GET DATA (plus the GET RESPONSE
//! that [`session::send`] adds for a `61 xx`). A `91 xx` is deliberately NOT
//! followed (no FETCH), and a refusal is recorded once, never retried.
//!
//! **Not done (issue #19 remainder).** CAP / IJC / ELF handling implies LOAD and
//! INSTALL, and validating a KCV against a card needs keys for that card.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "gp";

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use serde_json::{json, Value};

use crate::apdu::{Command, CorrectedLength, Header, Le};
use crate::session::{self, PendingFollowUp, Policy};
use crate::transport::CardSession;

/// Issuer security domain AIDs, tried in this order: GP default, then the
/// alternative some UICCs answer to.
pub const ISD_AIDS: [&[u8]; 2] = [
    &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00],
    &[0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00],
];

/// GET DATA objects read: name and the two tag bytes (P1 P2).
const OBJECTS: [(&str, [u8; 2]); 5] = [
    ("cplc", [0x9F, 0x7F]),
    ("card_data", [0x00, 0x66]),
    ("key_information", [0x00, 0xE0]),
    ("iin", [0x00, 0x42]),
    ("cin", [0x00, 0x45]),
];

/// CPLC field names and byte widths, in order (42 bytes). Source: GlobalPlatform
/// Card Specification v2.3.1 (CPLC data, GET DATA tag 9F7F), the same layout as
/// the Visa GlobalPlatform 2.1.1 CPLC and GlobalPlatformPro's `CPLC.java`.
pub const CPLC_FIELDS: [(&str, usize); 18] = [
    ("ic_fabricator", 2),
    ("ic_type", 2),
    ("os_id", 2),
    ("os_release_date", 2),
    ("os_release_level", 2),
    ("ic_fabrication_date", 2),
    ("ic_serial_number", 4),
    ("ic_batch_id", 2),
    ("ic_module_fabricator", 2),
    ("ic_module_packaging_date", 2),
    ("icc_manufacturer", 2),
    ("ic_embedding_date", 2),
    ("ic_prepersonalizer", 2),
    ("ic_prepersonalization_date", 2),
    ("ic_prepersonalization_equipment_id", 4),
    ("ic_personalizer", 2),
    ("ic_personalization_date", 2),
    ("ic_personalization_equipment_id", 4),
];

/// What `gp info` found.
pub struct Report {
    /// Whether an ISD answered a SELECT.
    pub isd_found: bool,
    /// The `data` of the envelope.
    pub data: Value,
}

/// Why a key check value could not be computed.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("an AES key is 16, 24 or 32 bytes, got {0}")]
pub struct KeyLength(pub usize);

/// GP key check value of an AES key: the first 3 bytes of the AES-ECB
/// encryption of 16 bytes of `0x01` (GP Card Spec Amendment D, key check
/// values for AES keys).
pub fn aes_kcv(key: &[u8]) -> Result<[u8; 3], KeyLength> {
    macro_rules! enc {
        ($cipher:ty) => {{
            let mut block = [0x01u8; 16].into();
            <$cipher>::new_from_slice(key)
                .unwrap()
                .encrypt_block(&mut block);
            <[u8; 16]>::from(block)
        }};
    }
    let block = match key.len() {
        16 => enc!(aes::Aes128),
        24 => enc!(aes::Aes192),
        32 => enc!(aes::Aes256),
        n => return Err(KeyLength(n)),
    };
    Ok([block[0], block[1], block[2]])
}

/// Splits `input` into `(tag, value)` pairs; tags of one or two bytes (a tag
/// whose low five bits are all set takes a second byte). `None` if malformed.
fn parse_tlvs(mut input: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    while !input.is_empty() {
        let mut tag = u16::from(input[0]);
        let mut at = 1;
        if input[0] & 0x1F == 0x1F {
            tag = (tag << 8) | u16::from(*input.get(1)?);
            at = 2;
        }
        let first = *input.get(at)?;
        at += 1;
        let len = match first {
            0..=0x7F => usize::from(first),
            0x81 => {
                at += 1;
                usize::from(*input.get(at - 1)?)
            }
            0x82 => {
                at += 2;
                usize::from(u16::from_be_bytes([
                    *input.get(at - 2)?,
                    *input.get(at - 1)?,
                ]))
            }
            _ => return None,
        };
        let value = input.get(at..at + len)?;
        out.push((tag, value));
        input = &input[at + len..];
    }
    Some(out)
}

/// Decodes CPLC (with or without the `9F7F 2A` header) into named hex fields.
pub fn decode_cplc(data: &[u8]) -> Result<Value, String> {
    let body = data.strip_prefix(&[0x9F, 0x7F, 0x2A]).unwrap_or(data);
    let total: usize = CPLC_FIELDS.iter().map(|(_, n)| n).sum();
    if body.len() != total {
        return Err(format!("CPLC is {} bytes, expected {total}", body.len()));
    }
    let mut at = 0;
    let mut map = serde_json::Map::new();
    for (name, n) in CPLC_FIELDS {
        map.insert(name.into(), json!(hex::encode_upper(&body[at..at + n])));
        at += n;
    }
    Ok(Value::Object(map))
}

/// Decodes the key information template (`E0` holding `C0` entries of key id,
/// key version, key type, key length) into one object per key.
pub fn decode_key_information(data: &[u8]) -> Result<Value, String> {
    let outer = parse_tlvs(data).ok_or("malformed TLV")?;
    let (_, inner) = outer
        .iter()
        .find(|(t, _)| *t == 0xE0)
        .ok_or("no E0 template")?;
    let keys = parse_tlvs(inner).ok_or("malformed TLV inside E0")?;
    let list: Vec<Value> = keys
        .iter()
        .filter(|(t, _)| *t == 0xC0)
        .map(|(_, v)| match v {
            [id, version, kind, length, ..] => json!({
                "key_id": id,
                "key_version": version,
                "key_type": format!("{kind:02X}"),
                "key_type_name": match kind { 0x80 => "DES", 0x88 => "AES", _ => "other" },
                "key_length": length,
            }),
            _ => json!({ "raw": hex::encode_upper(v) }),
        })
        .collect();
    Ok(Value::Array(list))
}

fn hex_of(bytes: &[u8]) -> Value {
    json!(hex::encode_upper(bytes))
}

/// Runs `gp info` over `session`: SELECT the ISD, then GET DATA.
///
/// # Errors
///
/// Only transport and encoding failures; a card refusal is data.
pub fn info<S: CardSession + ?Sized>(
    session: &mut S,
    trace: bool,
) -> Result<Report, session::Error> {
    let policy = Policy {
        proactive_command: PendingFollowUp::Ignore,
        ..Policy::default()
    };
    let mut steps: Vec<Value> = Vec::new();
    let mut run = |session: &mut S, label: &str, command: &Command| {
        let ex = session::send(session, command, &policy)?;
        for s in ex.steps() {
            steps.push(json!({
                "step": label,
                "command": hex_of(s.command()),
                "response": hex_of(s.response()),
            }));
        }
        Ok::<_, session::Error>(ex)
    };
    let status = |ex: &session::Exchange| ex.status().map(|s| hex::encode_upper(s.to_bytes()));

    let mut attempts = Vec::new();
    let mut selected: Option<Value> = None;
    for aid in ISD_AIDS {
        let select = Command::case4(Header::new(0x00, 0xA4, 0x04, 0x00), aid, Le::Short(0));
        let ex = run(session, "select", &select)?;
        let aid_hex = hex::encode_upper(aid);
        attempts.push(json!({ "aid": aid_hex, "status": status(&ex) }));
        if ex.is_success() {
            selected = Some(json!({ "aid": aid_hex, "fci": hex_of(ex.data()) }));
            break;
        }
    }

    let mut objects = Vec::new();
    if selected.is_some() {
        for (name, [p1, p2]) in OBJECTS {
            let get = Command::case2(Header::new(0x80, 0xCA, p1, p2), Le::Short(0));
            let mut ex = run(session, name, &get)?;
            // `6C xx` is the card naming the Le it wants, not a refusal: GET
            // DATA is read-only, so correct the Le once. Nothing else is retried.
            if let Some(CorrectedLength::Accepts(le)) =
                ex.status().and_then(|s| s.corrected_length())
            {
                let again = Command::case2(Header::new(0x80, 0xCA, p1, p2), Le::Short(le));
                ex = run(session, name, &again)?;
            }
            let mut item = json!({
                "name": name,
                "tag": hex::encode_upper([p1, p2]),
                "status": status(&ex),
                "data": Value::Null,
            });
            if ex.is_success() {
                item["data"] = hex_of(ex.data());
                let decoded = match name {
                    "cplc" => Some(decode_cplc(ex.data())),
                    "key_information" => Some(decode_key_information(ex.data())),
                    "card_data" => Some(Ok(json!({
                        "recognition_data_present": parse_tlvs(ex.data())
                            .and_then(|t| t.into_iter().find(|(t, _)| *t == 0x66))
                            .and_then(|(_, v)| parse_tlvs(v))
                            .is_some_and(|t| t.iter().any(|(t, _)| *t == 0x73)),
                    }))),
                    _ => None,
                };
                match decoded {
                    Some(Ok(v)) => item["decoded"] = v,
                    Some(Err(e)) => item["decode_error"] = json!(e),
                    None => {}
                }
            }
            objects.push(item);
        }
    }

    let isd_found = selected.is_some();
    let mut data = json!({
        "card_touched": true,
        "isd": selected,
        "isd_attempts": attempts,
        "get_data": objects,
    });
    if trace {
        data["trace"] = Value::Array(steps);
    }
    Ok(Report { isd_found, data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Error as TransportError, ReaderName};
    use std::collections::HashMap;

    /// A card answering from a command-hex -> response-hex table; anything else
    /// is `6D00`. Records what it was sent.
    struct Card {
        reader: ReaderName,
        table: HashMap<String, Vec<u8>>,
        sent: Vec<String>,
    }

    impl Card {
        fn new(rows: &[(&str, &str)]) -> Self {
            Self {
                reader: ReaderName::new("scripted").unwrap(),
                table: rows
                    .iter()
                    .map(|(c, r)| (c.to_string(), hex::decode(r).unwrap()))
                    .collect(),
                sent: Vec::new(),
            }
        }
    }

    impl CardSession for Card {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            let key = hex::encode_upper(command);
            self.sent.push(key.clone());
            Ok(self.table.get(&key).cloned().unwrap_or(vec![0x6D, 0x00]))
        }
        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    const SEL1: &str = "00A4040008A00000015100000000";
    const SEL2: &str = "00A4040008A00000000300000000";
    const CPLC_GET: &str = "80CA9F7F00";
    const KI_GET: &str = "80CA00E000";

    fn cplc_response() -> String {
        let body: Vec<u8> = (0u8..42).collect();
        format!("9F7F2A{}9000", hex::encode_upper(body))
    }

    #[test]
    fn isd_found_at_first_aid() {
        let cplc = cplc_response();
        let mut card = Card::new(&[(SEL1, "9000"), (CPLC_GET, &cplc)]);
        let report = info(&mut card, false).unwrap();
        assert!(report.isd_found);
        assert_eq!(report.data["isd"]["aid"], "A000000151000000");
        assert_eq!(report.data["isd_attempts"].as_array().unwrap().len(), 1);
        assert_eq!(report.data["get_data"][0]["status"], "9000");
        assert_eq!(report.data["get_data"][0]["decoded"]["os_id"], "0405");
        assert!(report.data.get("trace").is_none());
        // Only SELECT, GET DATA and GET RESPONSE ever reach the card.
        for sent in &card.sent {
            assert!(
                ["A4", "CA", "C0"].contains(&&sent[2..4]),
                "unexpected {sent}"
            );
        }
    }

    #[test]
    fn falls_back_to_second_aid() {
        let mut card = Card::new(&[(SEL1, "6A82"), (SEL2, "9000")]);
        let report = info(&mut card, false).unwrap();
        assert!(report.isd_found);
        assert_eq!(report.data["isd"]["aid"], "A000000003000000");
        assert_eq!(report.data["isd_attempts"][0]["status"], "6A82");
        // a refused GET DATA is recorded verbatim and sent once
        assert_eq!(report.data["get_data"][1]["status"], "6D00");
        assert_eq!(
            card.sent
                .iter()
                .filter(|s| s.starts_with("80CA9F7F"))
                .count(),
            1
        );
    }

    #[test]
    fn a_6c_gets_one_corrected_get_data_and_nothing_else_is_retried() {
        let cplc = cplc_response();
        let mut card = Card::new(&[
            (SEL1, "9000"),
            (CPLC_GET, "6C2D"),
            ("80CA9F7F2D", &cplc),
            (KI_GET, "6A88"),
        ]);
        let report = info(&mut card, false).unwrap();
        assert_eq!(report.data["get_data"][0]["status"], "9000");
        assert_eq!(report.data["get_data"][2]["status"], "6A88");
        assert_eq!(
            card.sent
                .iter()
                .filter(|s| s.starts_with("80CA00E0"))
                .count(),
            1
        );
    }

    #[test]
    fn neither_aid_found_sends_no_get_data() {
        let mut card = Card::new(&[(SEL1, "6A82"), (SEL2, "6A82")]);
        let report = info(&mut card, false).unwrap();
        assert!(!report.isd_found);
        assert!(report.data["isd"].is_null());
        assert_eq!(report.data["isd_attempts"].as_array().unwrap().len(), 2);
        assert!(report.data["get_data"].as_array().unwrap().is_empty());
        assert_eq!(card.sent.len(), 2);
    }

    #[test]
    fn cplc_decodes_into_named_fields() {
        let body: Vec<u8> = (0u8..42).collect();
        let v = decode_cplc(&body).unwrap();
        assert_eq!(v["ic_fabricator"], "0001");
        assert_eq!(v["ic_serial_number"], "0C0D0E0F");
        assert_eq!(v["ic_personalization_equipment_id"], "26272829");
        assert_eq!(v.as_object().unwrap().len(), 18);
        let with_header = [&[0x9F, 0x7F, 0x2A][..], &body].concat();
        assert_eq!(decode_cplc(&with_header).unwrap(), v);
        assert!(decode_cplc(&body[..41]).is_err());
    }

    #[test]
    fn key_information_decodes() {
        // E0 { C0 {01 30 88 10}, C0 {02 30 88 10} }
        let data = hex::decode("E00CC004013088".to_string() + "10C004023088" + "10").unwrap();
        let v = decode_key_information(&data).unwrap();
        assert_eq!(v[0]["key_id"], 1);
        assert_eq!(v[0]["key_version"], 0x30);
        assert_eq!(v[0]["key_type_name"], "AES");
        assert_eq!(v[1]["key_id"], 2);
        assert_eq!(v[1]["key_length"], 16);
    }

    #[test]
    fn key_information_flows_through_info() {
        let ki = "E00CC004013088".to_string() + "10C004023088" + "109000";
        let mut card = Card::new(&[(SEL1, "9000"), (KI_GET, &ki)]);
        let report = info(&mut card, false).unwrap();
        assert_eq!(report.data["get_data"][2]["decoded"][1]["key_id"], 2);
    }

    #[test]
    fn kcv_known_answer() {
        // GlobalPlatformPro prints "(KCV: 504A77)" for its default key
        // 404142434445464748494A4B4C4D4E4F (martinpaljak/GlobalPlatformPro
        // issues #248 and #306); recomputed independently with openssl
        // aes-128-ecb over sixteen 0x01 bytes.
        let key = hex::decode("404142434445464748494A4B4C4D4E4F").unwrap();
        assert_eq!(aes_kcv(&key).unwrap(), [0x50, 0x4A, 0x77]);
        assert_eq!(aes_kcv(&key[..15]), Err(KeyLength(15)));
    }

    #[test]
    fn trace_is_machine_readable() {
        let mut card = Card::new(&[(SEL1, "6A82"), (SEL2, "9000")]);
        let report = info(&mut card, true).unwrap();
        let trace = report.data["trace"].as_array().unwrap();
        assert_eq!(trace.len(), 2 + OBJECTS.len());
        assert_eq!(trace[0]["step"], "select");
        assert_eq!(trace[0]["command"], SEL1);
        assert_eq!(trace[0]["response"], "6A82");
        for t in trace {
            assert!(t["command"].is_string() && t["response"].is_string());
        }
        let text = serde_json::to_string(&report.data).unwrap();
        let _: Value = serde_json::from_str(&text).unwrap();
    }
}
