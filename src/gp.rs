//! GlobalPlatform, read-only: find the issuer security domain, read what it
//! will say with GET DATA, decode CPLC, the key information template, the
//! counters, extended card resources and Card Recognition Data, compute key
//! check values, and build (never send) INSTALL [for load] and LOAD.
//!
//! **Owns.** The `gp info` data: SELECT of the ISD by AID, GET DATA for CPLC,
//! card data, key information, IIN, CIN, the sequence and confirmation counters
//! and extended card resources, the decoders, the machine-readable APDU trace,
//! [`aes_kcv`] / [`des_kcv`] / [`kcv_matches`], and the byte builders
//! [`install_for_load`], [`load_commands`] and [`dap_block`].
//!
//! `gp ara` ([`ara`]) and `gp status` ([`status`]) add SELECT of the ARA-M and GET
//! STATUS (INS F2), both unauthenticated; a refusal is data.
//!
//! **Does not own, and never sends.** INITIALIZE UPDATE, EXTERNAL AUTHENTICATE,
//! STORE DATA, INSTALL, LOAD, DELETE, PUT KEY, SET STATUS, MANAGE CHANNEL (that
//! one is [`session::open_channel`], used by nothing here). The only
//! instructions [`info`], [`ara`] and [`status`] send are SELECT, GET DATA and GET STATUS (plus the GET RESPONSE
//! that [`session::send`] adds for a `61 xx`). A `91 xx` is deliberately NOT
//! followed (no FETCH), and a refusal is recorded once, never retried.
//! The INSTALL / LOAD builders return [`Command`]s and nothing calls
//! `session::send` with them: sending, DAP signing, PUT KEY and DELETE belong
//! to issue #115, and validating a KCV against a card needs keys for that card.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "gp";

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use serde_json::{json, Value};

use crate::apdu::{Command, CorrectedLength, Header, Le, CLA_GET_RESPONSE_ISO};
use crate::session::{self, PendingFollowUp, Policy};
use crate::transport::CardSession;

/// Issuer security domain AIDs, tried in this order: GP default, then the
/// alternative some UICCs answer to.
pub const ISD_AIDS: [&[u8]; 2] = [
    &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00],
    &[0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00],
];

/// GET DATA objects read: name and the two tag bytes (P1 P2).
const OBJECTS: [(&str, [u8; 2]); 8] = [
    ("cplc", [0x9F, 0x7F]),
    ("card_data", [0x00, 0x66]),
    ("key_information", [0x00, 0xE0]),
    ("iin", [0x00, 0x42]),
    ("cin", [0x00, 0x45]),
    ("sequence_counter", [0x00, 0xC1]),
    ("confirmation_counter", [0x00, 0xC2]),
    ("extended_card_resources", [0xFF, 0x21]),
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

/// Key check value of a 2-key (16 byte) or 3-key (24 byte) Triple DES key: the
/// first 3 bytes of the 3DES-ECB encryption of 8 zero bytes (the GlobalPlatform
/// key check value for DES keys; GlobalPlatformPro prints 8BAF47 for its default
/// key, recomputed here with `openssl enc -des-ede`).
pub fn des_kcv(key: &[u8]) -> Result<[u8; 3], KeyLength> {
    macro_rules! enc {
        ($cipher:ty) => {{
            let mut block = [0u8; 8].into();
            <$cipher>::new_from_slice(key)
                .unwrap()
                .encrypt_block(&mut block);
            <[u8; 8]>::from(block)
        }};
    }
    let block = match key.len() {
        16 => enc!(des::TdesEde2),
        24 => enc!(des::TdesEde3),
        n => return Err(KeyLength(n)),
    };
    Ok([block[0], block[1], block[2]])
}

/// Whether `expected` (the 3 bytes a card or key file states) is the KCV of
/// `key`, as AES when `aes` is set and as 3DES otherwise (a 16 byte key is
/// both, so the caller says which). Host-side only: no card is involved, and a
/// KCV is public, so the compare need not be constant time.
pub fn kcv_matches(aes: bool, key: &[u8], expected: &[u8]) -> Result<bool, KeyLength> {
    let kcv = if aes { aes_kcv(key)? } else { des_kcv(key)? };
    Ok(kcv[..] == *expected)
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

/// Decodes a BER OID value into its arcs (first byte is `40 * a + b`, the rest
/// base-128). `None` if empty, truncated, or an arc overflows `u64`.
fn oid_arcs(bytes: &[u8]) -> Option<Vec<u64>> {
    let (first, rest) = bytes.split_first()?;
    let mut arcs = vec![u64::from(first / 40), u64::from(first % 40)];
    let mut acc: u64 = 0;
    let mut open = false;
    for b in rest {
        acc = acc.checked_mul(128)?.checked_add(u64::from(b & 0x7F))?;
        open = b & 0x80 != 0;
        if !open {
            arcs.push(acc);
            acc = 0;
        }
    }
    (!open).then_some(arcs)
}

fn dotted(arcs: &[u64]) -> String {
    arcs.iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// The GlobalPlatform OID arcs, `1.2.840.114283`.
const GP_OID: [u64; 4] = [1, 2, 840, 114_283];

/// The OID (tag 06) inside a Card Recognition Data tag, as arcs.
fn inner_oid(value: &[u8]) -> Option<Vec<u64>> {
    let tlvs = parse_tlvs(value)?;
    let (_, oid) = tlvs.into_iter().find(|(t, _)| *t == 0x06)?;
    oid_arcs(oid)
}

/// Decodes Card Recognition Data (`66 { 73 { ... } }`, GP Card Spec v2.3.1
/// Annex H): the GP version (tag 60), and every supported SCP with its option
/// `i` (tag 64, OID `1.2.840.114283.4.<scp>.<i>`). The other OIDs (card
/// identification scheme 63, card configuration 65, chip details 66) are listed
/// as dotted strings, undecoded. A bare `73` is accepted too.
pub fn decode_card_recognition(data: &[u8]) -> Result<Value, String> {
    let outer = parse_tlvs(data).ok_or("malformed TLV")?;
    let inner = match outer.iter().find(|(t, _)| *t == 0x66) {
        Some((_, v)) => parse_tlvs(v).ok_or("malformed TLV inside 66")?,
        None => outer,
    };
    let (_, body) = inner
        .iter()
        .find(|(t, _)| *t == 0x73)
        .ok_or("no 73 recognition template")?;
    let fields = parse_tlvs(body).ok_or("malformed TLV inside 73")?;
    let mut out = json!({ "recognition_data_present": true, "scp": [], "other_oids": {} });
    for (tag, value) in fields {
        match tag {
            0x06 => {
                let arcs = oid_arcs(value).ok_or("bad OID")?;
                out["gp_oid"] = json!(dotted(&arcs));
                out["is_globalplatform"] = json!(arcs.starts_with(&GP_OID));
            }
            0x60 => {
                let arcs = inner_oid(value).ok_or("bad card management OID")?;
                out["card_management_oid"] = json!(dotted(&arcs));
                // 1.2.840.114283.2.<major>.<minor>[.<patch>]
                if arcs.starts_with(&GP_OID) && arcs.get(4) == Some(&2) && arcs.len() > 6 {
                    let v: Vec<String> = arcs[5..].iter().map(u64::to_string).collect();
                    out["gp_version"] = json!(v.join("."));
                }
            }
            0x64 => {
                let arcs = inner_oid(value).ok_or("bad secure channel OID")?;
                let mut item = json!({ "oid": dotted(&arcs) });
                // 1.2.840.114283.4.<scp>.<i>
                if arcs.starts_with(&GP_OID) && arcs.get(4) == Some(&4) && arcs.len() == 7 {
                    item["scp"] = json!(arcs[5]);
                    item["i"] = json!(format!("{:02X}", arcs[6]));
                }
                out["scp"].as_array_mut().unwrap().push(item);
            }
            0x63 | 0x65 | 0x66 => {
                let arcs = inner_oid(value).ok_or("bad OID")?;
                out["other_oids"][format!("{tag:02X}")] = json!(dotted(&arcs));
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Big-endian value of at most 8 bytes.
fn be_value(bytes: &[u8]) -> Option<u64> {
    (bytes.len() <= 8).then(|| bytes.iter().fold(0, |a, b| (a << 8) | u64::from(*b)))
}

/// Decodes a GET DATA counter (`C1` sequence counter or `C2` confirmation
/// counter, GET DATA tags in the GP Card Spec) into `{ "value": n }`. The tag
/// header may be present or stripped.
pub fn decode_counter(tag: u8, data: &[u8]) -> Result<Value, String> {
    let value = match parse_tlvs(data) {
        Some(t) => t
            .into_iter()
            .find(|(x, _)| *x == u16::from(tag))
            .map(|(_, v)| v),
        None => None,
    }
    .unwrap_or(data);
    be_value(value)
        .map(|v| json!({ "value": v }))
        .ok_or_else(|| "counter is longer than 8 bytes".into())
}

/// Decodes Extended Card Resources Information (`FF21 { 81, 82, 83 }`): number
/// of installed applications, free non-volatile memory, free volatile memory.
pub fn decode_extended_resources(data: &[u8]) -> Result<Value, String> {
    let outer = parse_tlvs(data).ok_or("malformed TLV")?;
    let (_, inner) = outer
        .iter()
        .find(|(t, _)| *t == 0xFF21)
        .ok_or("no FF21 template")?;
    let mut map = serde_json::Map::new();
    for (tag, name) in [
        (0x81, "installed_applications"),
        (0x82, "free_non_volatile_memory"),
        (0x83, "free_volatile_memory"),
    ] {
        let value = parse_tlvs(inner)
            .ok_or("malformed TLV inside FF21")?
            .into_iter()
            .find(|(t, _)| *t == tag)
            .and_then(|(_, v)| be_value(v));
        map.insert(name.into(), json!(value));
    }
    Ok(Value::Object(map))
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
                    "card_data" => Some(
                        decode_card_recognition(ex.data())
                            .or_else(|_| Ok(json!({ "recognition_data_present": false }))),
                    ),
                    "sequence_counter" => Some(decode_counter(0xC1, ex.data())),
                    "confirmation_counter" => Some(decode_counter(0xC2, ex.data())),
                    "extended_card_resources" => Some(decode_extended_resources(ex.data())),
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

/// The ARA-M (Access Rule Application Master) AID, from the architecture
/// chapter of GlobalPlatform Secure Element Access Control v1.1 (GPD_SPE_013,
/// 2024 public review).
pub const ARA_M_AID: [u8; 9] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C, 0x00];

/// Status words that mean "a secure channel is needed", not "broken". GP's own
/// codes for this are 6985 (conditions of use not satisfied) and 6A88; 6982 is
/// kept as the ISO 7816-4 "security status not satisfied" meaning.
const AUTH_REQUIRED: [&str; 2] = ["6982", "6985"];

/// Sends `build(le)` and, on `6C xx`, the same command once with the Le the
/// card named. Nothing else is retried. Records every APDU in `steps`.
fn read_once<S: CardSession + ?Sized>(
    session: &mut S,
    steps: &mut Vec<Value>,
    label: &str,
    build: impl Fn(Le) -> Command,
) -> Result<session::Exchange, session::Error> {
    // The ARA-M and the ISD are GP applets: a 61 xx is answered with the ISO
    // class (00) GET RESPONSE, not the GSM class (A0) that Policy defaults to.
    let policy = Policy {
        proactive_command: PendingFollowUp::Ignore,
        get_response_class: CLA_GET_RESPONSE_ISO,
        ..Policy::default()
    };
    let mut ex = session::send(session, &build(Le::Short(0)), &policy)?;
    if let Some(CorrectedLength::Accepts(le)) = ex.status().and_then(|s| s.corrected_length()) {
        for s in ex.steps() {
            steps.push(json!({"step": label, "command": hex_of(s.command()), "response": hex_of(s.response())}));
        }
        ex = session::send(session, &build(Le::Short(le)), &policy)?;
    }
    for s in ex.steps() {
        steps.push(
            json!({"step": label, "command": hex_of(s.command()), "response": hex_of(s.response())}),
        );
    }
    Ok(ex)
}

fn sw_hex(ex: &session::Exchange) -> Option<String> {
    ex.status().map(|s| hex::encode_upper(s.to_bytes()))
}

fn select_by_aid(aid: &[u8]) -> impl Fn(Le) -> Command + '_ {
    move |le| Command::case4(Header::new(0x00, 0xA4, 0x04, 0x00), aid, le)
}

fn tlv_get<'a>(l: &[(u16, &'a [u8])], t: u16) -> Option<&'a [u8]> {
    l.iter().find(|(x, _)| *x == t).map(|(_, v)| *v)
}

fn byte_rule(name: &str, v: &[u8]) -> Result<Value, String> {
    match v {
        [0] => Ok(json!("never")),
        [1] => Ok(json!("always")),
        _ => Err(format!("{name} is {} bytes, expected 1", v.len())),
    }
}

/// Decodes the ARA-M GET DATA [all] answer (`FF40 { E2 { E1 { 4F|C0, C1 [, CA] },
/// E3 { D0, D1, DB } } ... }`). FF40 is section 4.1 (Table 4-2) and the rule
/// encoding is chapter 6 (Tables 6-3 to 6-9) of GlobalPlatform Secure Element
/// Access Control v1.1 (GPD_SPE_013, 2024 public review). CA (PKG-REF-DO) and
/// DB (PERM-AR-DO) are AOSP SecureElement extensions, not in the GP text. One object per REF-AR-DO with the applet (`aid`: hex,
/// `"all"` for an empty 4F, `"default_selected"` for C0), the device app hash
/// (`"any"` when empty), and the APDU, NFC and permission access rules.
/// `grants_all_apps_all_access` is set for a rule naming all applets and any
/// device app with APDU access always. A bare run of `E2` is accepted too.
pub fn decode_ara_rules(data: &[u8]) -> Result<Value, String> {
    let outer = parse_tlvs(data).ok_or("malformed TLV")?;
    let refs = match outer.iter().find(|(t, _)| *t == 0xFF40) {
        Some((_, v)) => parse_tlvs(v).ok_or("malformed TLV inside FF40")?,
        None => outer,
    };
    let mut rules = Vec::new();
    for (tag, body) in refs {
        if tag != 0xE2 {
            continue; // e.g. DF20 refresh tag
        }
        let parts = parse_tlvs(body).ok_or("malformed TLV inside E2")?;
        let find = |t| parts.iter().find(|(x, _)| *x == t).map(|(_, v)| *v);
        let ref_do = parse_tlvs(find(0xE1).ok_or("REF-AR-DO without E1")?)
            .ok_or("malformed TLV inside E1")?;
        let ar_do = parse_tlvs(find(0xE3).ok_or("REF-AR-DO without E3")?)
            .ok_or("malformed TLV inside E3")?;
        let get = tlv_get;
        let aid = match (get(&ref_do, 0x4F), get(&ref_do, 0xC0)) {
            (Some([]), _) => json!("all"),
            (Some(a), _) => json!(hex::encode_upper(a)),
            (None, Some(_)) => json!("default_selected"),
            _ => return Err("E1 has neither 4F nor C0".into()),
        };
        let device = match get(&ref_do, 0xC1).ok_or("E1 without C1 device app hash")? {
            [] => json!("any"),
            h @ &[_, ..] if h.len() == 20 || h.len() == 32 => json!(hex::encode_upper(h)),
            h => {
                return Err(format!(
                    "device app hash is {} bytes, expected 0, 20 or 32",
                    h.len()
                ))
            }
        };
        let mut rule = json!({ "aid": aid, "device_app": device });
        if let Some(p) = get(&ref_do, 0xCA) {
            rule["package"] = json!(String::from_utf8_lossy(p));
        }
        let mut apdu_always = false;
        if let Some(v) = get(&ar_do, 0xD0) {
            if v.is_empty() {
                rule["apdu"] = json!("never"); // AOSP: an empty APDU-AR-DO denies
            } else if let [b @ (0 | 1)] = v {
                apdu_always = *b == 1;
                rule["apdu"] = byte_rule("D0", v)?;
            } else if v.len() % 8 == 0 {
                rule["apdu"] = json!({ "filters": v.chunks(8).map(|c| json!({
                    "header": hex::encode_upper(&c[..4]), "mask": hex::encode_upper(&c[4..])
                })).collect::<Vec<_>>() });
            } else {
                return Err(format!(
                    "APDU-AR-DO is {} bytes, expected 1 or a multiple of 8",
                    v.len()
                ));
            }
        }
        if let Some(v) = get(&ar_do, 0xD1) {
            rule["nfc"] = byte_rule("D1", v)?;
        }
        if let Some(v) = get(&ar_do, 0xDB) {
            if v.len() != 8 {
                return Err(format!("PERM-AR-DO is {} bytes, expected 8", v.len()));
            }
            rule["permissions"] = hex_of(v);
        }
        rule["grants_all_apps_all_access"] =
            json!(rule["aid"] == "all" && rule["device_app"] == "any" && apdu_always);
        rules.push(rule);
    }
    Ok(Value::Array(rules))
}

/// Longest ARA-M rule list read across GET DATA [Next] calls, and the most calls.
const ARA_MAX_BYTES: usize = 64 * 1024;
const ARA_MAX_NEXT: usize = 255;

/// For a response starting `FF40 <BER length>`: (header bytes, declared length).
fn ff40_header(data: &[u8]) -> Option<(usize, usize)> {
    let rest = data.strip_prefix(&[0xFF, 0x40])?;
    match *rest.first()? {
        n @ 0..=0x7F => Some((3, usize::from(n))),
        0x81 => Some((4, usize::from(*rest.get(1)?))),
        0x82 => Some((
            5,
            usize::from(u16::from_be_bytes([*rest.get(1)?, *rest.get(2)?])),
        )),
        _ => None,
    }
}

/// `gp ara`: SELECT the ARA-M by AID and GET DATA [all] (`80 CA FF 40`), then
/// decode the rules. Read-only; a refusal (`6982`) is reported as
/// `requires_authentication`, not an error.
///
/// # Errors
///
/// Only transport and encoding failures.
pub fn ara<S: CardSession + ?Sized>(
    session: &mut S,
    trace: bool,
) -> Result<Report, session::Error> {
    let mut steps = Vec::new();
    let sel = read_once(session, &mut steps, "select", select_by_aid(&ARA_M_AID))?;
    let found = sel.is_success();
    let mut data = json!({
        "card_touched": true,
        "ara_m": { "aid": hex::encode_upper(ARA_M_AID), "status": sw_hex(&sel) },
        "rules": Value::Null,
    });
    if found {
        let ex = read_once(session, &mut steps, "get_data_all", |le| {
            Command::case2(Header::new(0x80, 0xCA, 0xFF, 0x40), le)
        })?;
        let status = sw_hex(&ex);
        data["get_data_status"] = json!(status);
        data["requires_authentication"] = json!(status
            .as_deref()
            .is_some_and(|s| AUTH_REQUIRED.contains(&s)));
        if ex.is_success() {
            let mut all = ex.data().to_vec();
            // FF40's length is the whole list; the card may deliver it over
            // several GET DATA [Next] (80 CA FF 60), raw bytes with no header.
            let mut short = None;
            if let Some((head, want)) = ff40_header(&all) {
                let want = head + want;
                let mut calls = 0;
                while all.len() < want {
                    if calls == ARA_MAX_NEXT || all.len() >= ARA_MAX_BYTES {
                        short = Some("read bound reached".to_string());
                        break;
                    }
                    calls += 1;
                    let next = read_once(session, &mut steps, "get_data_next", |le| {
                        Command::case2(Header::new(0x80, 0xCA, 0xFF, 0x60), le)
                    })?;
                    if !next.is_success() {
                        let sw = sw_hex(&next).unwrap_or_default();
                        data["get_data_next_status"] = json!(sw);
                        data["requires_authentication"] = json!(AUTH_REQUIRED.contains(&&*sw));
                        short = Some(format!("GET DATA [Next] answered {sw}"));
                        break;
                    }
                    if next.data().is_empty() {
                        short = Some("GET DATA [Next] returned no data".into());
                        break;
                    }
                    all.extend_from_slice(next.data());
                }
                if short.is_none() && all.len() < want {
                    short = Some("incomplete".into());
                }
                if let Some(why) = short.as_ref() {
                    data["truncated"] = json!(true);
                    data["decode_error"] = json!(format!(
                        "truncated: got {} of {want} bytes ({why})",
                        all.len()
                    ));
                }
            }
            data["raw"] = hex_of(&all);
            if short.is_none() {
                match decode_ara_rules(&all) {
                    Ok(v) => data["rules"] = v,
                    Err(e) => data["decode_error"] = json!(e),
                }
            }
        }
    }
    if trace {
        data["trace"] = Value::Array(steps);
    }
    Ok(Report {
        isd_found: found,
        data,
    })
}

/// GET STATUS scopes: P1, name.
const STATUS_SCOPES: [(u8, &str); 4] = [
    (0x80, "isd"),
    (0x40, "applications"),
    (0x20, "load_files"),
    (0x10, "load_files_and_modules"),
];

/// Pages of `63 10` ("more data") followed per scope before saying so.
const STATUS_MAX_PAGES: usize = 16;

fn lifecycle_name(scope: &str, v: u8) -> &'static str {
    match (scope, v) {
        ("isd", 0x01) => "OP_READY",
        ("isd", 0x07) => "INITIALIZED",
        ("isd", 0x0F) => "SECURED",
        ("isd", 0x7F) => "CARD_LOCKED",
        ("isd", 0xFF) => "TERMINATED",
        ("applications", 0x03) => "INSTALLED",
        ("applications", 0x83) => "LOCKED",
        ("applications", v) if v & 0x87 == 0x07 => "SELECTABLE",
        (s, 0x01) if s.starts_with("load_files") => "LOADED",
        _ => "unknown",
    }
}

/// Privilege names per (byte, bit), GlobalPlatform Card Spec v2.3.1 table 11-7.
const PRIVILEGES: [(usize, u8, &str); 15] = [
    (0, 0x80, "security_domain"),
    (0, 0x40, "dap_verification"),
    (0, 0x20, "delegated_management"),
    (0, 0x10, "card_lock"),
    (0, 0x08, "card_terminate"),
    (0, 0x04, "card_reset"),
    (0, 0x02, "cvm_management"),
    (0, 0x01, "mandated_dap_verification"),
    (1, 0x80, "trusted_path"),
    (1, 0x40, "authorized_management"),
    (1, 0x20, "token_verification"),
    (1, 0x10, "global_delete"),
    (1, 0x08, "global_lock"),
    (1, 0x04, "global_registry"),
    (1, 0x02, "final_application"),
];

/// Decodes GET STATUS TLV data (`E3 { 4F aid, 9F70 lifecycle, C5 privileges,
/// CC associated SD, CE version, 84 module AIDs }` repeated, GP Card Spec
/// v2.3.1 section 11.4.2.1) into one object per registry entry.
pub fn decode_registry(scope: &str, data: &[u8]) -> Result<Value, String> {
    let mut out = Vec::new();
    for (tag, body) in parse_tlvs(data).ok_or("malformed TLV")? {
        if tag != 0xE3 {
            return Err(format!("unexpected tag {tag:02X}, expected E3"));
        }
        let parts = parse_tlvs(body).ok_or("malformed TLV inside E3")?;
        let one = |t| parts.iter().find(|(x, _)| *x == t).map(|(_, v)| *v);
        let mut e = json!({ "aid": hex_of(one(0x4F).ok_or("E3 without 4F AID")?) });
        if let Some(l) = one(0x9F70) {
            let [v] = l else {
                return Err("lifecycle is not one byte".into());
            };
            e["lifecycle"] = json!(format!("{v:02X}"));
            e["lifecycle_name"] = json!(lifecycle_name(scope, *v));
        }
        if let Some(p) = one(0xC5) {
            if p.len() != 3 {
                return Err(format!("privileges are {} bytes, expected 3", p.len()));
            }
            e["privileges"] = hex_of(p);
            e["privilege_names"] = json!(PRIVILEGES
                .iter()
                .filter(|(i, m, _)| p[*i] & m != 0)
                .map(|(_, _, n)| *n)
                .collect::<Vec<_>>());
        }
        if let Some(v) = one(0xCC) {
            e["associated_security_domain"] = hex_of(v);
        }
        if let Some(v) = one(0xCE) {
            e["version"] = hex_of(v);
        }
        let modules: Vec<Value> = parts
            .iter()
            .filter(|(t, _)| *t == 0x84)
            .map(|(_, v)| hex_of(v))
            .collect();
        if !modules.is_empty() {
            e["modules"] = Value::Array(modules);
        }
        out.push(e);
    }
    Ok(Value::Array(out))
}

/// `gp status`: SELECT the ISD, GET DATA tag 66 (Card Recognition Data), then
/// GET STATUS (`80 F2 <scope> 02`, TLV format) for the ISD, applications,
/// executable load files and load files with modules. Read-only and
/// unauthenticated: a card that wants a secure channel answers `6982`/`6985`
/// and the scope is reported as `requires_authentication`. `63 10` is followed
/// with GET STATUS "next" up to [`STATUS_MAX_PAGES`] pages.
///
/// # Errors
///
/// Only transport and encoding failures.
pub fn status<S: CardSession + ?Sized>(
    session: &mut S,
    trace: bool,
) -> Result<Report, session::Error> {
    let mut steps = Vec::new();
    let mut attempts = Vec::new();
    let mut selected = None;
    for aid in ISD_AIDS {
        let ex = read_once(session, &mut steps, "select", select_by_aid(aid))?;
        attempts.push(json!({ "aid": hex::encode_upper(aid), "status": sw_hex(&ex) }));
        if ex.is_success() {
            selected = Some(hex::encode_upper(aid));
            break;
        }
    }
    let mut data = json!({ "card_touched": true, "isd": selected, "isd_attempts": attempts });
    if selected.is_some() {
        let ex = read_once(session, &mut steps, "card_data", |le| {
            Command::case2(Header::new(0x80, 0xCA, 0x00, 0x66), le)
        })?;
        let mut crd = json!({ "status": sw_hex(&ex) });
        if ex.is_success() {
            crd["data"] = hex_of(ex.data());
            match decode_card_recognition(ex.data()) {
                Ok(v) => {
                    // SCP01/SCP02 are the old, weak secure channels.
                    let weak: Vec<u64> = v["scp"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|s| s["scp"].as_u64())
                        .filter(|n| *n < 3)
                        .collect();
                    crd["weak_scp"] = json!(weak);
                    crd["decoded"] = v;
                }
                Err(e) => crd["decode_error"] = json!(e),
            }
        }
        data["card_recognition"] = crd;
        let mut scopes = Vec::new();
        for (p1, name) in STATUS_SCOPES {
            let mut collected = Vec::new();
            let mut p2 = 0x02;
            let mut pages = 0;
            let (last, truncated) = loop {
                let ex = read_once(session, &mut steps, name, |le| {
                    Command::case4(Header::new(0x80, 0xF2, p1, p2), vec![0x4F, 0x00], le)
                })?;
                let sw = sw_hex(&ex);
                if ex.is_success() || sw.as_deref() == Some("6310") {
                    collected.extend_from_slice(ex.data());
                }
                pages += 1;
                if sw.as_deref() != Some("6310") {
                    break (sw, false);
                }
                if pages == STATUS_MAX_PAGES {
                    break (sw, true);
                }
                p2 = 0x03;
            };
            let mut item = json!({
                "scope": name,
                "p1": format!("{p1:02X}"),
                "status": last,
                "requires_authentication":
                    last.as_deref().is_some_and(|s| AUTH_REQUIRED.contains(&s)),
                "entries": [],
            });
            if truncated {
                item["truncated"] = json!(true);
            }
            if last.as_deref() == Some("9000") || truncated {
                match decode_registry(name, &collected) {
                    Ok(v) => item["entries"] = v,
                    Err(e) => item["decode_error"] = json!(e),
                }
            }
            scopes.push(item);
        }
        data["registry"] = Value::Array(scopes);
    }
    if trace {
        data["trace"] = Value::Array(steps);
    }
    Ok(Report {
        isd_found: selected.is_some(),
        data,
    })
}

/// Plain-text rendering of a `gp ara` / `gp status` `data`, one fact per line.
/// Card bytes only reach it as hex or as the package name, which goes through
/// [`crate::contract::sanitize`] (JSON output is escaped by the serialiser).
pub fn render_text(data: &Value) -> String {
    let s = |v: &Value| crate::contract::sanitize(v.as_str().unwrap_or("-"));
    let mut out = Vec::new();
    if let Some(rules) = data["rules"].as_array() {
        out.push(format!("ARA-M: {} rule(s)", rules.len()));
        for r in rules {
            let mut line = format!(
                "  applet {} device-app {}",
                s(&r["aid"]),
                s(&r["device_app"])
            );
            for k in ["apdu", "nfc", "permissions", "package"] {
                if let Some(v) = r.get(k) {
                    let v = v.as_str().map_or_else(|| v.to_string(), str::to_string);
                    line += &format!(" {k} {}", crate::contract::sanitize(&v));
                }
            }
            if r["grants_all_apps_all_access"] == true {
                line += "  [GRANTS ALL APPS ALL ACCESS]";
            }
            out.push(line);
        }
    } else if data.get("ara_m").is_some() {
        out.push(format!(
            "ARA-M: not read (select {})",
            s(&data["ara_m"]["status"])
        ));
    }
    if data["requires_authentication"] == true {
        out.push("ARA-M: requires authentication".into());
    }
    if let Some(e) = data.get("decode_error") {
        out.push(format!("decode error: {}", s(e)));
    }
    if let Some(c) = data.get("card_recognition") {
        out.push(format!("Card Recognition Data: status {}", s(&c["status"])));
        if let Some(w) = c["weak_scp"].as_array().filter(|w| !w.is_empty()) {
            out.push(format!("  weak secure channel offered: SCP0{}", w[0]));
        }
    }
    for scope in data["registry"].as_array().into_iter().flatten() {
        let n = scope["entries"].as_array().map_or(0, Vec::len);
        let note = if scope["requires_authentication"] == true {
            " (requires authentication)"
        } else {
            ""
        };
        out.push(format!(
            "{}: status {}, {n} entr(ies){note}",
            s(&scope["scope"]),
            s(&scope["status"])
        ));
        for e in scope["entries"].as_array().into_iter().flatten() {
            out.push(format!("  {} {}", s(&e["aid"]), s(&e["lifecycle_name"])));
        }
    }
    out.join("\n")
}

/// Why an INSTALL or LOAD command could not be built.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// An AID is outside 5..=16 bytes.
    #[error("{field} AID is {len} bytes, an AID is 5 to 16")]
    Aid {
        /// Which AID.
        field: &'static str,
        /// Its length.
        len: usize,
    },
    /// A length-prefixed field is over 255 bytes.
    #[error("{field} is {len} bytes, at most 255 fit a one byte length")]
    Field {
        /// Which field.
        field: &'static str,
        /// Its length.
        len: usize,
    },
    /// The INSTALL data field is over 255 bytes.
    #[error("INSTALL data is {0} bytes, at most 255 fit a short Lc")]
    InstallTooLong(usize),
    /// A load token with no load file data block hash.
    #[error("a load token needs the load file data block hash")]
    TokenWithoutHash,
    /// LOAD block size outside 1..=255.
    #[error("LOAD block size {0} is outside 1..=255")]
    Chunk(usize),
    /// More LOAD blocks than P2's 0..=255.
    #[error("{0} LOAD blocks, the block number P2 stops at 256")]
    TooManyBlocks(usize),
}

/// Default LOAD block size: pySim's, the old GlobalPlatformPro default, leaves
/// room for a secure channel's MAC and padding under the 255 byte Lc.
pub const DEFAULT_LOAD_BLOCK: usize = 240;

fn aid_ok(field: &'static str, aid: &[u8], may_be_empty: bool) -> Result<(), BuildError> {
    if (may_be_empty && aid.is_empty()) || (5..=16).contains(&aid.len()) {
        Ok(())
    } else {
        Err(BuildError::Aid {
            field,
            len: aid.len(),
        })
    }
}

fn lv(out: &mut Vec<u8>, field: &'static str, bytes: &[u8]) -> Result<(), BuildError> {
    let len = u8::try_from(bytes.len()).map_err(|_| BuildError::Field {
        field,
        len: bytes.len(),
    })?;
    out.push(len);
    out.extend_from_slice(bytes);
    Ok(())
}

/// Builds, and does not send, INSTALL [for load]: `80 E6 02 00 Lc <data> 00`
/// with data = `LV(load file AID) LV(security domain AID) LV(load file data
/// block hash) LV(load parameters) LV(load token)`. Empty fields stay as a
/// zero length byte, so an empty security domain AID selects the card's
/// default. `load_parameters` is already-encoded TLV (for example `C9 ..`),
/// passed through. Layout: GP Card Spec v2.3.1 section 11.5.2.3, as
/// implemented by pySim `do_install_for_load`
/// (osmocom/pysim, `pySim/global_platform/__init__.py`).
pub fn install_for_load(
    load_file_aid: &[u8],
    security_domain_aid: &[u8],
    load_file_hash: &[u8],
    load_parameters: &[u8],
    load_token: &[u8],
) -> Result<Command, BuildError> {
    aid_ok("load file", load_file_aid, false)?;
    aid_ok("security domain", security_domain_aid, true)?;
    if !load_token.is_empty() && load_file_hash.is_empty() {
        return Err(BuildError::TokenWithoutHash);
    }
    let mut data = Vec::new();
    lv(&mut data, "load file AID", load_file_aid)?;
    lv(&mut data, "security domain AID", security_domain_aid)?;
    lv(&mut data, "load file data block hash", load_file_hash)?;
    lv(&mut data, "load parameters", load_parameters)?;
    lv(&mut data, "load token", load_token)?;
    if data.len() > 0xFF {
        return Err(BuildError::InstallTooLong(data.len()));
    }
    Ok(Command::case4(
        Header::new(0x80, 0xE6, 0x02, 0x00),
        data,
        Le::Short(0),
    ))
}

/// BER length: one byte below 128, then `81 xx`, `82 xxxx`, `83 xxxxxx`.
fn ber_len(len: usize) -> Vec<u8> {
    match len {
        0..=0x7F => vec![len as u8],
        0x80..=0xFF => vec![0x81, len as u8],
        0x100..=0xFFFF => vec![0x82, (len >> 8) as u8, len as u8],
        _ => vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8],
    }
}

/// The structure of a DAP block, `E2 { 4F <security domain AID>, C3
/// <signature> }`, to put in front of the load file data block. This only
/// frames bytes the caller already has: computing the signature (DAP signing)
/// is out of scope and belongs to issue #115. GP Card Spec v2.3.1 section
/// 11.6.2.3.
pub fn dap_block(security_domain_aid: &[u8], signature: &[u8]) -> Result<Vec<u8>, BuildError> {
    aid_ok("DAP security domain", security_domain_aid, false)?;
    let mut body = vec![0x4F];
    body.extend(ber_len(security_domain_aid.len()));
    body.extend_from_slice(security_domain_aid);
    body.push(0xC3);
    body.extend(ber_len(signature.len()));
    body.extend_from_slice(signature);
    let mut out = vec![0xE2];
    out.extend(ber_len(body.len()));
    out.extend(body);
    Ok(out)
}

/// Builds, and does not send, the LOAD commands for `load_file`: the Load File
/// Data Block `[dap blocks] C4 <BER length> <load file>` cut into `block_size`
/// pieces, each `80 E8 <00, or 80 on the last> <block number> Lc <piece> 00`
/// (GP Card Spec v2.3.1 section 11.6.2; same cutting as pySim `load`).
/// `dap_blocks` are whole `E2` TLVs, see [`dap_block`].
pub fn load_commands(
    load_file: &[u8],
    dap_blocks: &[Vec<u8>],
    block_size: usize,
) -> Result<Vec<Command>, BuildError> {
    if !(1..=0xFF).contains(&block_size) {
        return Err(BuildError::Chunk(block_size));
    }
    let mut data: Vec<u8> = dap_blocks.concat();
    data.push(0xC4);
    data.extend(ber_len(load_file.len()));
    data.extend_from_slice(load_file);
    let pieces: Vec<&[u8]> = data.chunks(block_size).collect();
    if pieces.len() > 256 {
        return Err(BuildError::TooManyBlocks(pieces.len()));
    }
    let last = pieces.len() - 1;
    Ok(pieces
        .iter()
        .enumerate()
        .map(|(n, piece)| {
            let p1 = if n == last { 0x80 } else { 0x00 };
            Command::case4(
                Header::new(0x80, 0xE8, p1, n as u8),
                piece.to_vec(),
                Le::Short(0),
            )
        })
        .collect())
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
    fn des_kcv_known_answer_and_compare() {
        // GlobalPlatformPro's default key; 8BAF47 recomputed independently with
        // `openssl enc -des-ede` (16 byte key) and `-des-ede3` (K1 K2 K1).
        let key = hex::decode("404142434445464748494A4B4C4D4E4F").unwrap();
        assert_eq!(des_kcv(&key).unwrap(), [0x8B, 0xAF, 0x47]);
        let key3 = [&key[..], &key[..8]].concat();
        assert_eq!(des_kcv(&key3).unwrap(), [0x8B, 0xAF, 0x47]);
        assert_eq!(des_kcv(&key[..8]), Err(KeyLength(8)));
        assert_eq!(kcv_matches(false, &key, &[0x8B, 0xAF, 0x47]), Ok(true));
        assert_eq!(kcv_matches(true, &key, &[0x50, 0x4A, 0x77]), Ok(true));
        assert_eq!(kcv_matches(true, &key, &[0x8B, 0xAF, 0x47]), Ok(false));
        assert_eq!(kcv_matches(true, &key[..3], &[0, 0, 0]), Err(KeyLength(3)));
    }

    #[test]
    fn install_for_load_is_byte_exact() {
        // Layout of pySim do_install_for_load: 80 E6 02 00 Lc, LV(load file
        // AID) LV(SD AID) LV(hash) LV(params) LV(token), 00. Assembled by hand.
        let cmd = install_for_load(
            &hex::decode("A0000000620001").unwrap(),
            &hex::decode("A000000151000000").unwrap(),
            &[],
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(
            hex::encode_upper(cmd.encode().unwrap()),
            "80E6020014".to_string() + "07A0000000620001" + "08A000000151000000" + "000000" + "00"
        );
        // hash, parameters and token each get their own length byte
        let cmd = install_for_load(
            &[0xA0, 0, 0, 0, 1],
            &[],
            &[0x11; 20],
            &[0xC9, 0x00],
            &[0x22; 3],
        )
        .unwrap();
        let bytes = cmd.encode().unwrap();
        // Lc = 6 + 1 + 21 + 3 + 4 = 35
        assert_eq!(&bytes[..6], &[0x80, 0xE6, 0x02, 0x00, 35, 0x05]);
        assert_eq!(bytes[bytes.len() - 1], 0x00);
        assert_eq!(bytes.len(), 5 + 35 + 1);
    }

    #[test]
    fn install_for_load_refuses_bad_input() {
        let aid = [0xA0, 0, 0, 0, 1];
        assert!(matches!(
            install_for_load(&aid[..4], &[], &[], &[], &[]),
            Err(BuildError::Aid { .. })
        ));
        assert!(matches!(
            install_for_load(&aid, &[1; 17], &[], &[], &[]),
            Err(BuildError::Aid { .. })
        ));
        assert_eq!(
            install_for_load(&aid, &[], &[], &[], &[1]),
            Err(BuildError::TokenWithoutHash)
        );
        assert!(matches!(
            install_for_load(&aid, &[], &[0; 256], &[], &[]),
            Err(BuildError::Field { .. })
        ));
        // 6 + 1 + 101 + 101 + 101
        assert_eq!(
            install_for_load(&aid, &[], &[0; 100], &[0; 100], &[0; 100]),
            Err(BuildError::InstallTooLong(310))
        );
    }

    #[test]
    fn load_single_block_is_byte_exact() {
        let cmds = load_commands(&[1, 2, 3, 4, 5], &[], DEFAULT_LOAD_BLOCK).unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(
            hex::encode_upper(cmds[0].encode().unwrap()),
            "80E88000".to_string() + "07" + "C405" + "0102030405" + "00"
        );
    }

    #[test]
    fn load_is_cut_into_numbered_blocks_with_a_last_flag() {
        let file = vec![0xAB; 300];
        let cmds = load_commands(&file, &[], DEFAULT_LOAD_BLOCK).unwrap();
        // C4 82 012C + 300 bytes = 304 bytes -> 240 + 64
        assert_eq!(cmds.len(), 2);
        let a = cmds[0].encode().unwrap();
        let b = cmds[1].encode().unwrap();
        assert_eq!(
            &a[..9],
            &[0x80, 0xE8, 0x00, 0x00, 240, 0xC4, 0x82, 0x01, 0x2C]
        );
        assert_eq!(&b[..5], &[0x80, 0xE8, 0x80, 0x01, 64]);
        // the pieces rejoin to the data block
        let joined: Vec<u8> = [&a[5..a.len() - 1], &b[5..b.len() - 1]].concat();
        assert_eq!(joined[..4], [0xC4, 0x82, 0x01, 0x2C]);
        assert_eq!(joined[4..], file[..]);
        assert_eq!(load_commands(&file, &[], 0), Err(BuildError::Chunk(0)));
        assert_eq!(
            load_commands(&[0; 300], &[], 1).unwrap_err(),
            BuildError::TooManyBlocks(304)
        );
    }

    #[test]
    fn dap_block_goes_in_front_of_the_c4_block() {
        let sd = [0xA0, 0, 0, 0, 3, 0, 0];
        let dap = dap_block(&sd, &[0xEE; 4]).unwrap();
        assert_eq!(
            hex::encode_upper(&dap),
            "E2".to_string() + "0F" + "4F07A0000000030000" + "C304EEEEEEEE"
        );
        let cmds = load_commands(&[9], std::slice::from_ref(&dap), DEFAULT_LOAD_BLOCK).unwrap();
        let bytes = cmds[0].encode().unwrap();
        assert_eq!(&bytes[5..5 + dap.len()], &dap[..]);
        assert_eq!(&bytes[5 + dap.len()..bytes.len() - 1], &[0xC4, 0x01, 0x09]);
    }

    #[test]
    fn card_recognition_data_decodes_versions_and_scps() {
        // 66 { 73 { 06 GP, 60 { 06 .. }, 63, 64 x2, 65, 66 } } : GP 2.3.1,
        // SCP02 i=15 and SCP03 i=70 (the shape of GP Card Spec Annex H).
        let gp = "2A864886FC6B";
        let oid = |arcs: &str| format!("06{:02X}{}", arcs.len() / 2, arcs);
        let wrap = |tag: &str, inner: String| format!("{tag}{:02X}{inner}", inner.len() / 2);
        let body = oid(&format!("{gp}01"))
            + &wrap("60", oid(&format!("{gp}02020301")))
            + &wrap("63", oid(&format!("{gp}0301")))
            + &wrap("64", oid(&format!("{gp}040215")))
            + &wrap("64", oid(&format!("{gp}040370")))
            + &wrap("65", oid(&format!("{gp}0501")))
            + &wrap("66", oid(&format!("{gp}0601")));
        let data = hex::decode(wrap("66", wrap("73", body))).unwrap();
        let v = decode_card_recognition(&data).unwrap();
        assert_eq!(v["recognition_data_present"], true);
        assert_eq!(v["is_globalplatform"], true);
        assert_eq!(v["gp_oid"], "1.2.840.114283.1");
        assert_eq!(v["gp_version"], "2.3.1");
        assert_eq!(v["scp"][0]["scp"], 2);
        assert_eq!(v["scp"][0]["i"], "15");
        assert_eq!(v["scp"][1]["scp"], 3);
        assert_eq!(v["scp"][1]["i"], "70");
        assert_eq!(v["other_oids"]["63"], "1.2.840.114283.3.1");
        assert!(decode_card_recognition(&[0x66, 0x00]).is_err());
        assert!(decode_card_recognition(&[0x66, 0x05]).is_err());
    }

    #[test]
    fn counters_and_extended_resources_decode() {
        assert_eq!(
            decode_counter(0xC1, &[0xC1, 0x02, 0x00, 0x2A]).unwrap()["value"],
            42
        );
        assert_eq!(decode_counter(0xC2, &[0x01, 0x00]).unwrap()["value"], 256);
        assert!(decode_counter(0xC2, &[0; 9]).is_err());
        // FF21 { 81 02 0003, 82 04 00010000, 83 02 0400 }
        let data = hex::decode("FF210E8102000382040001000083020400").unwrap();
        let v = decode_extended_resources(&data).unwrap();
        assert_eq!(v["installed_applications"], 3);
        assert_eq!(v["free_non_volatile_memory"], 65536);
        assert_eq!(v["free_volatile_memory"], 1024);
    }

    #[test]
    fn info_reads_the_extra_objects_read_only() {
        let c1 = "C10200059000";
        let ffr = "FF2103810107".to_string() + "9000";
        let mut card = Card::new(&[(SEL1, "9000"), ("80CA00C100", c1), ("80CAFF2100", &ffr)]);
        let report = info(&mut card, false).unwrap();
        let g = &report.data["get_data"];
        assert_eq!(g[5]["name"], "sequence_counter");
        assert_eq!(g[5]["decoded"]["value"], 5);
        assert_eq!(g[6]["status"], "6D00");
        assert_eq!(g[7]["decoded"]["installed_applications"], 7);
        for sent in &card.sent {
            assert!(
                ["A4", "CA", "C0"].contains(&&sent[2..4]),
                "unexpected {sent}"
            );
        }
    }

    fn tlv(tag: &str, inner: &str) -> String {
        let n = inner.len() / 2;
        let len = if n < 0x80 {
            format!("{n:02X}")
        } else {
            format!("81{n:02X}")
        };
        format!("{tag}{len}{inner}")
    }

    const ARA_SEL: &str = "00A4040009A00000015141434C0000";
    const ARA_GET: &str = "80CAFF4000";

    fn ara_rules_hex() -> String {
        let wild = tlv(
            "E2",
            &(tlv("E1", &(tlv("4F", "") + &tlv("C1", "")))
                + &tlv("E3", &(tlv("D0", "01") + &tlv("D1", "01")))),
        );
        let narrow = tlv(
            "E2",
            &(tlv(
                "E1",
                &(tlv("4F", "A000000062")
                    + &tlv("C1", &"AB".repeat(20))
                    + &tlv("CA", "636F6D2E78")),
            ) + &tlv(
                "E3",
                &(tlv("D0", "FFFFFF00FFFFFF00")
                    + &tlv("D1", "00")
                    + &tlv("DB", "0000000000000001")),
            )),
        );
        tlv("FF40", &(wild + &narrow + &tlv("DF20", "0000000000000001")))
    }

    #[test]
    fn ara_rules_decode_and_flag_the_wildcard() {
        let v = decode_ara_rules(&hex::decode(ara_rules_hex()).unwrap()).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
        assert_eq!(v[0]["aid"], "all");
        assert_eq!(v[0]["device_app"], "any");
        assert_eq!(v[0]["apdu"], "always");
        assert_eq!(v[0]["nfc"], "always");
        assert_eq!(v[0]["grants_all_apps_all_access"], true);
        assert_eq!(v[1]["aid"], "A000000062");
        assert_eq!(v[1]["device_app"], "AB".repeat(20));
        assert_eq!(v[1]["package"], "com.x");
        assert_eq!(v[1]["apdu"]["filters"][0]["header"], "FFFFFF00");
        assert_eq!(v[1]["apdu"]["filters"][0]["mask"], "FFFFFF00");
        assert_eq!(v[1]["nfc"], "never");
        assert_eq!(v[1]["permissions"], "0000000000000001");
        assert_eq!(v[1]["grants_all_apps_all_access"], false);
        // empty list and a bare run of E2 are fine
        assert_eq!(decode_ara_rules(&[0xFF, 0x40, 0x00]).unwrap(), json!([]));
    }

    #[test]
    fn malformed_ara_data_is_an_error_not_a_panic() {
        for bad in [
            "FF4005E2",                                                         // truncated
            "FF40",                                                             // no length
            &tlv("FF40", &tlv("E2", &tlv("E1", &tlv("4F", "A000000062"))))[..], // no C1, no E3
            &tlv(
                "FF40",
                &tlv(
                    "E2",
                    &(tlv("E1", &(tlv("4F", "") + &tlv("C1", "AA"))) + &tlv("E3", "")),
                ),
            ), // 1-byte hash
            &tlv(
                "FF40",
                &tlv(
                    "E2",
                    &(tlv("E1", &(tlv("4F", "") + &tlv("C1", "")))
                        + &tlv("E3", &tlv("D0", "0102030405"))),
                ),
            ),
            &tlv(
                "FF40",
                &tlv(
                    "E2",
                    &(tlv("E1", &(tlv("4F", "") + &tlv("C1", ""))) + &tlv("E3", &tlv("DB", "00"))),
                ),
            ),
        ] {
            assert!(
                decode_ara_rules(&hex::decode(bad).unwrap()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn ara_reads_rules_with_select_and_get_data_only() {
        let resp = ara_rules_hex() + "9000";
        let mut card = Card::new(&[(ARA_SEL, "9000"), (ARA_GET, &resp)]);
        let report = ara(&mut card, true).unwrap();
        assert!(report.isd_found);
        assert_eq!(report.data["rules"][0]["grants_all_apps_all_access"], true);
        assert_eq!(report.data["requires_authentication"], false);
        assert_eq!(report.data["trace"].as_array().unwrap().len(), 2);
        assert_eq!(card.sent, [ARA_SEL, ARA_GET]);
        let text = render_text(&report.data);
        assert!(text.contains("2 rule(s)") && text.contains("GRANTS ALL APPS ALL ACCESS"));
    }

    #[test]
    fn ara_refusals_are_data() {
        let mut card = Card::new(&[(ARA_SEL, "9000"), (ARA_GET, "6982")]);
        let r = ara(&mut card, false).unwrap();
        assert_eq!(r.data["requires_authentication"], true);
        assert!(r.data["rules"].is_null());
        assert!(render_text(&r.data).contains("requires authentication"));

        let mut card = Card::new(&[(ARA_SEL, "9000"), (ARA_GET, "6A88")]);
        let r = ara(&mut card, false).unwrap();
        assert_eq!(r.data["get_data_status"], "6A88");
        assert_eq!(r.data["requires_authentication"], false);

        let mut card = Card::new(&[(ARA_SEL, "6A82")]);
        let r = ara(&mut card, false).unwrap();
        assert!(!r.isd_found);
        assert_eq!(card.sent, [ARA_SEL]);

        // a complete FF40 whose content is malformed is "malformed", not truncated
        let mut card = Card::new(&[(ARA_SEL, "9000"), (ARA_GET, "FF4003E201FF9000")]);
        let r = ara(&mut card, false).unwrap();
        assert!(r.data["decode_error"].is_string());
        assert!(r.data.get("truncated").is_none());
    }

    const ARA_NEXT: &str = "80CAFF6000";

    /// A card that answers each command from a queue of responses (key
    /// "00C0" matches any GET RESPONSE in ISO class); empty queue is `6D00`.
    struct SeqCard {
        reader: ReaderName,
        table: HashMap<String, std::collections::VecDeque<Vec<u8>>>,
        sent: Vec<String>,
    }

    impl SeqCard {
        fn new(rows: &[(&str, Vec<String>)]) -> Self {
            Self {
                reader: ReaderName::new("scripted").unwrap(),
                table: rows
                    .iter()
                    .map(|(c, rs)| {
                        (
                            c.to_string(),
                            rs.iter().map(|r| hex::decode(r).unwrap()).collect(),
                        )
                    })
                    .collect(),
                sent: Vec::new(),
            }
        }
    }

    impl CardSession for SeqCard {
        fn reader(&self) -> &ReaderName {
            &self.reader
        }
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, TransportError> {
            let key = hex::encode_upper(command);
            self.sent.push(key.clone());
            let slot = if self.table.contains_key(&key) {
                key
            } else {
                key[..4].to_string()
            };
            Ok(self
                .table
                .get_mut(&slot)
                .and_then(|q| q.pop_front())
                .unwrap_or(vec![0x6D, 0x00]))
        }
        fn disconnect(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    #[test]
    fn ara_rules_split_over_get_data_next() {
        let full = ara_rules_hex();
        let n = full.len() / 2;
        for cuts in [vec![30, n], vec![30, 60, n]] {
            let mut parts = Vec::new();
            let mut at = 0;
            for c in &cuts {
                parts.push(full[at * 2..c * 2].to_string() + "9000");
                at = *c;
            }
            let mut card = SeqCard::new(&[
                (ARA_SEL, vec!["9000".into()]),
                (ARA_GET, vec![parts[0].clone()]),
                (ARA_NEXT, parts[1..].to_vec()),
            ]);
            let r = ara(&mut card, false).unwrap();
            assert!(r.data.get("decode_error").is_none(), "{:?}", r.data);
            assert_eq!(r.data["rules"].as_array().unwrap().len(), 2);
            assert_eq!(
                card.sent.iter().filter(|s| *s == ARA_NEXT).count(),
                parts.len() - 1
            );
        }
    }

    #[test]
    fn ara_early_stop_is_truncated_and_next_refusal_is_clean() {
        let full = ara_rules_hex();
        let first = &full[..60];
        let mut card = SeqCard::new(&[
            (ARA_SEL, vec!["9000".into()]),
            (ARA_GET, vec![first.to_string() + "9000"]),
            (ARA_NEXT, vec!["9000".into()]),
        ]);
        let r = ara(&mut card, false).unwrap();
        assert_eq!(r.data["truncated"], true);
        assert!(r.data["decode_error"]
            .as_str()
            .unwrap()
            .starts_with("truncated"));
        assert!(r.data["rules"].is_null());

        let mut card = SeqCard::new(&[
            (ARA_SEL, vec!["9000".into()]),
            (ARA_GET, vec![first.to_string() + "9000"]),
            (ARA_NEXT, vec!["6985".into()]),
        ]);
        let r = ara(&mut card, false).unwrap();
        assert_eq!(r.data["get_data_next_status"], "6985");
        assert_eq!(r.data["requires_authentication"], true);
        assert_eq!(r.data["truncated"], true);
    }

    #[test]
    fn ara_61xx_is_followed_with_the_iso_class_get_response() {
        let full = ara_rules_hex();
        let n = full.len() / 2;
        let mut card = SeqCard::new(&[
            (ARA_SEL, vec!["9000".into()]),
            (ARA_GET, vec![format!("61{n:02X}")]),
            ("00C0", vec![full + "9000"]),
        ]);
        let r = ara(&mut card, false).unwrap();
        assert_eq!(r.data["rules"].as_array().unwrap().len(), 2, "{:?}", r.data);
        assert!(card.sent.iter().any(|s| s.starts_with("00C0")));
        assert!(!card.sent.iter().any(|s| s.starts_with("A0C0")));
    }

    #[test]
    fn empty_apdu_ar_do_denies() {
        let rule = tlv(
            "E2",
            &(tlv("E1", &(tlv("4F", "") + &tlv("C1", ""))) + &tlv("E3", &tlv("D0", ""))),
        );
        let v = decode_ara_rules(&hex::decode(tlv("FF40", &rule)).unwrap()).unwrap();
        assert_eq!(v[0]["apdu"], "never");
        assert_eq!(v[0]["grants_all_apps_all_access"], false);
    }

    #[test]
    fn ara_text_is_sanitized() {
        let data = json!({"rules": [{"aid": "all", "device_app": "any", "package": "a\u{1b}[31m\u{202e}b"}]});
        let text = render_text(&data);
        assert!(!text.contains('\u{1b}') && !text.contains('\u{202e}'));
    }

    fn status_get(p1: &str, p2: &str) -> String {
        format!("80F2{p1}{p2}024F0000")
    }

    fn recognition_hex(scps: &[&str]) -> String {
        let gp = "2A864886FC6B";
        let oid = |arcs: &str| format!("06{:02X}{}", arcs.len() / 2, arcs);
        let mut body = oid(&format!("{gp}01")) + &tlv("60", &oid(&format!("{gp}02020301")));
        for s in scps {
            body += &tlv("64", &oid(&format!("{gp}04{s}")));
        }
        tlv("66", &tlv("73", &body))
    }

    #[test]
    fn status_lists_the_registry_and_reports_auth_cleanly() {
        let isd = tlv(
            "E3",
            &(tlv("4F", "A000000151000000") + &tlv("9F70", "0F") + &tlv("C5", "9E0000")),
        );
        let app1 = tlv(
            "E3",
            &(tlv("4F", "A0000000620001") + &tlv("9F70", "07") + &tlv("C5", "000000")),
        );
        let app2 = tlv(
            "E3",
            &(tlv("4F", "A0000000620002") + &tlv("9F70", "83") + &tlv("C5", "800000")),
        );
        let crd = recognition_hex(&["0215", "0370"]) + "9000";
        let rows = [
            (SEL1, "9000".to_string()),
            ("80CA006600", crd),
            (&status_get("80", "02")[..], isd + "9000"),
            (&status_get("40", "02")[..], app1 + "6310"),
            (&status_get("40", "03")[..], app2 + "9000"),
            (&status_get("20", "02")[..], "6A88".into()),
            (&status_get("10", "02")[..], "6982".into()),
        ];
        let rows: Vec<(&str, &str)> = rows.iter().map(|(a, b)| (*a, b.as_str())).collect();
        let mut card = Card::new(&rows);
        let r = status(&mut card, false).unwrap();
        assert!(r.isd_found);
        assert_eq!(r.data["card_recognition"]["weak_scp"], json!([2]));
        let reg = &r.data["registry"];
        assert_eq!(reg[0]["entries"][0]["lifecycle_name"], "SECURED");
        assert_eq!(
            reg[0]["entries"][0]["privilege_names"][0],
            "security_domain"
        );
        assert_eq!(reg[1]["entries"].as_array().unwrap().len(), 2);
        assert_eq!(reg[1]["entries"][1]["lifecycle_name"], "LOCKED");
        assert_eq!(reg[2]["status"], "6A88");
        assert_eq!(reg[2]["requires_authentication"], false);
        assert_eq!(reg[3]["requires_authentication"], true);
        assert!(reg[3]["entries"].as_array().unwrap().is_empty());
        let text = render_text(&r.data);
        assert!(text.contains("requires authentication") && text.contains("SCP02"));
        for sent in &card.sent {
            assert!(
                ["A4", "CA", "C0", "F2"].contains(&&sent[2..4]),
                "unexpected {sent}"
            );
        }
    }

    #[test]
    fn status_without_an_isd_sends_nothing_more_and_bad_tlv_is_data() {
        let mut card = Card::new(&[(SEL1, "6A82"), (SEL2, "6A82")]);
        let r = status(&mut card, false).unwrap();
        assert!(!r.isd_found);
        assert_eq!(card.sent.len(), 2);

        let mut card = Card::new(&[(SEL1, "9000")]);
        let r = status(&mut card, false).unwrap();
        assert_eq!(r.data["registry"][0]["status"], "6D00");
        let mut card = Card::new(&[(SEL1, "9000"), (&status_get("80", "02"), "E3054F9000")]);
        let r = status(&mut card, false).unwrap();
        assert!(r.data["registry"][0]["decode_error"].is_string());
        assert!(decode_registry("isd", &[0xE3, 0x02, 0x9F, 0x70]).is_err());
        assert!(decode_registry("isd", &[0x4F, 0x00]).is_err());
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
