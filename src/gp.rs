//! GlobalPlatform: find the issuer security domain, read what it will say with
//! GET DATA, decode CPLC, the key information template, the counters, extended
//! card resources and Card Recognition Data, compute key check values, list the
//! registry, and (behind `--yes`, over SCP03) delete, load and install.
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
//! **Authenticated reads (issues #112, #19).** `gp status` can open one SCP03
//! secure channel to the ISD with user-supplied keys ([`Keys`], [`Auth`]) and
//! list the registry over it; [`select`] is `gp select --aid`. The channel is the
//! one in [`crate::scp03`] (C-MAC only); nothing here builds a second one.
//!
//! **Lockout safety.** A failed EXTERNAL AUTHENTICATE counts toward locking the
//! ISD for good, so a run makes at most ONE attempt and never retries or tries a
//! second key. Before EXTERNAL AUTHENTICATE the card cryptogram from INITIALIZE
//! UPDATE is checked locally (Amendment D 6.2.2: the off-card entity verifies the
//! card cryptogram); on a mismatch the run stops with `keys-do-not-match` and
//! EXTERNAL AUTHENTICATE is never sent. Keys are read from a file or an
//! environment variable by the caller, never the command line, and appear in no
//! output: [`Keys`] has a redacting `Debug`, parse errors never quote input, and
//! the trace holds wire bytes only (cryptograms and MACs, no key or session key).
//! This is the one exception to the full-visibility rule in AGENTS.md.
//!
//! **Card writes (issues #133, #19).** `gp delete` ([`delete`]) and `gp install`
//! ([`install`]) send DELETE, INSTALL and LOAD over the same C-MAC SCP03 channel,
//! and `gp channel open|close` ([`channel_open`], [`channel_close`]) send MANAGE
//! CHANNEL. Every `gp` command can run on a chosen logical channel
//! ([`OnChannel`], `--channel`). **Binding safety rules (owner decision
//! 2026-10-10, same spirit as the eUICC writes):** (1) a write is a dry run
//! unless `--yes`, and `--yes` needs keys: the dry run prints the target and the
//! exact plain APDUs and sends nothing; (2) the keys are the read path's: ONE
//! authentication attempt, local card-cryptogram pre-check, no loop, read from a
//! file or environment variable, never printed; (3) before sending, GET STATUS
//! over the channel must show the AID (delete) or show no clash (install), else
//! the run refuses with nothing sent; the ISD is never deleted; a registry that
//! cannot be read in full refuses; (4) each command is sent once, in order, and
//! the run stops at the first refusal; (5) after a `90 00` the registry is read
//! again and must show the intended result (`verify-failed` otherwise); (6) not
//! exposed over MCP. Without keys a dry run is fully offline (no reader).
//!
//! **PUT KEY and DAP (issue #115).** `gp put-key` ([`put_key`]) adds or replaces
//! an SCP03 AES-128 key set (ENC, MAC, DEK) in the ISD over the same channel: PUT
//! KEY, GP Card Spec v2.3.1 11.8, with every key encrypted under the current
//! static DEK (Amendment D v1.1.2 6.2.8) and a KCV (B.6) for each. The dry run
//! states that replacing the card's own SCP03 keys with values the operator
//! does not hold permanently locks administrative access, and the command
//! refuses to touch the key version it authenticated with unless
//! `--replace-current-keyset` is given. The new keys come only from a file or
//! environment variable, appear in no output (the plan and the trace withhold
//! the encrypted key blocks too; KCVs are shown) and the card's returned KCVs
//! and the key information are read back. `gp install --dap-key-*` signs the
//! Load File Data Block Hash with a symmetric AES DAP key ([`dap_signature`]:
//! AES-CMAC, C.3 and B.2.2) and puts the DAP block in front of the load file.
//!
//! **Does not own, and never sends.** STORE DATA, SET STATUS, INSTALL
//! [for extradition / registry update / personalization], DELETE [key], PUT KEY
//! for anything but an SCP03 AES-128 key set (RSA/ECC/DES keys, a lone DAP
//! verification key), any token, and DAP signatures other than the AES scheme
//! (DES, RSA and ECC DAP keys are not implemented). [`info`], [`ara`], [`status`] and
//! [`select`] send only SELECT, GET DATA and GET STATUS, plus, only when keys are
//! supplied, one INITIALIZE UPDATE and at most one EXTERNAL AUTHENTICATE (and the
//! GET RESPONSE that [`session::send`] adds for a `61 xx`). A `91 xx` is
//! deliberately NOT followed (no FETCH), and a refusal is recorded once, never
//! retried.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "gp";

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use serde_json::{json, Value};

use crate::apdu::{class_on_channel, Command, CorrectedLength, Header, Le, CLA_GET_RESPONSE_ISO};
use crate::scp03;
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

/// The policy of every GP read: the ARA-M and the ISD are GP applets, so a `61 xx`
/// is answered with the ISO class (00) GET RESPONSE, not the GSM class (A0) that
/// [`Policy`] defaults to, and a pending proactive command is ignored.
fn read_policy() -> Policy {
    Policy {
        proactive_command: PendingFollowUp::Ignore,
        get_response_class: CLA_GET_RESPONSE_ISO,
        ..Policy::default()
    }
}

fn push_steps(steps: &mut Vec<Value>, label: &str, ex: &session::Exchange) {
    for s in ex.steps() {
        // PUT KEY carries the new keys encrypted under the DEK: wire bytes, but
        // key material all the same, so the trace keeps the header only.
        let command = match (label, s.command()) {
            (PUT_KEY_STEP, c) if c.len() > 5 => Value::String(format!(
                "{}<{} data bytes withheld>",
                hex::encode_upper(&c[..5]),
                c.len() - 5
            )),
            (_, c) => hex_of(c),
        };
        steps.push(json!({"step": label, "command": command, "response": hex_of(s.response())}));
    }
}

/// Sends `build(le)` and, on `6C xx`, the same command once with the Le the
/// card named. Nothing else is retried. Records every APDU in `steps`.
fn read_once<S: CardSession + ?Sized>(
    session: &mut S,
    steps: &mut Vec<Value>,
    label: &str,
    build: impl Fn(Le) -> Command,
) -> Result<session::Exchange, session::Error> {
    let policy = read_policy();
    let mut ex = session::send(session, &build(Le::Short(0)), &policy)?;
    if let Some(CorrectedLength::Accepts(le)) = ex.status().and_then(|s| s.corrected_length()) {
        push_steps(steps, label, &ex);
        ex = session::send(session, &build(Le::Short(le)), &policy)?;
    }
    push_steps(steps, label, &ex);
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

// ---------------------------------------------------------------------------
// Keys and the one SCP03 authentication attempt
// ---------------------------------------------------------------------------

/// Where the key text comes from. Never the command line (shell history).
#[derive(Debug, Clone, Copy)]
pub enum KeySource<'a> {
    /// A file, read up to [`KEY_TEXT_MAX`] bytes.
    File(&'a std::path::Path),
    /// An environment variable.
    Env(&'a str),
}

/// Largest key text read. Three keys with KCVs are about 120 bytes.
pub const KEY_TEXT_MAX: u64 = 4096;

/// Why keys could not be loaded. Messages name the source and the key's
/// position (1 = ENC, 2 = MAC, 3 = DEK) and never quote the key text.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// The file or variable could not be read.
    #[error("cannot read the keys from {0}")]
    Unreadable(String),
    /// More than [`KEY_TEXT_MAX`] bytes.
    #[error("the key text is longer than {KEY_TEXT_MAX} bytes")]
    TooLong,
    /// Not one to three keys.
    #[error("expected 1 to 3 keys (ENC [MAC [DEK]]), found {0}")]
    Count(usize),
    /// A token is not 32 hex digits, optionally `/` and 6 hex digits of KCV.
    #[error("key {0} is not 32 hex digits (AES-128), optionally followed by /KCV of 6 hex digits")]
    Format(usize),
    /// A DAP key that is not 16, 24 or 32 bytes of hex.
    #[error("the DAP key is not 32, 48 or 64 hex digits (AES-128, -192 or -256), optionally followed by /KCV of 6 hex digits")]
    DapFormat,
    /// The stated KCV is not the KCV of the key.
    #[error(
        "key {index}: its key check value is {computed} but {stated} was stated, so the key or \
         the KCV is mistyped; nothing was sent to the card"
    )]
    Kcv {
        /// 1 = ENC, 2 = MAC, 3 = DEK.
        index: usize,
        /// The KCV of the key as given (a KCV is public, 24 bits).
        computed: String,
        /// The KCV the text stated.
        stated: String,
    },
}

/// The static AES-128 keys of an SCP03 key set. The DEK is kept (one key means
/// ENC = MAC = DEK, as GlobalPlatformPro's `--key`): PUT KEY encrypts the new
/// keys under it, and as the new key set the text must name all three keys.
///
/// `Debug` is redacted. Not `Clone`, not `Serialize`.
pub struct Keys {
    enc: [u8; 16],
    mac: [u8; 16],
    dek: Option<[u8; 16]>,
    count: usize,
    stated: [bool; 2],
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keys { .. }")
    }
}

impl Keys {
    /// Parses `ENC [MAC [DEK]]`, separated by whitespace or commas; `#` lines are
    /// skipped. One key means ENC = MAC (GlobalPlatformPro's `--key`). A token
    /// may be `KEY/KCV` (KCV: first 3 bytes of AES-ECB of 16 bytes of 0x01,
    /// Amendment D 4.1.2); a stated KCV that is wrong is an error, which catches
    /// a typo before the card is touched.
    ///
    /// # Errors
    ///
    /// [`KeyError`], whose text never contains the input.
    pub fn parse(text: &str) -> Result<Self, KeyError> {
        let tokens: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .flat_map(|l| l.split(|c: char| c.is_whitespace() || c == ','))
            .filter(|t| !t.is_empty())
            .collect();
        if tokens.is_empty() || tokens.len() > 3 {
            return Err(KeyError::Count(tokens.len()));
        }
        let mut keys = Vec::new();
        let mut stated = [false; 2];
        for (i, token) in tokens.iter().enumerate() {
            let n = i + 1;
            let (key_hex, kcv_hex) = match token.split_once('/') {
                Some((k, c)) => (k, Some(c)),
                None => (*token, None),
            };
            let key = hex::decode(key_hex)
                .ok()
                .and_then(|v| <[u8; 16]>::try_from(v).ok())
                .ok_or(KeyError::Format(n))?;
            if let Some(kcv_hex) = kcv_hex {
                let want = hex::decode(kcv_hex)
                    .ok()
                    .and_then(|v| <[u8; 3]>::try_from(v).ok())
                    .ok_or(KeyError::Format(n))?;
                let got = aes_kcv(&key).expect("16-byte key");
                if got != want {
                    return Err(KeyError::Kcv {
                        index: n,
                        computed: hex::encode_upper(got),
                        stated: hex::encode_upper(want),
                    });
                }
                if n <= 2 {
                    stated[i] = true;
                }
            }
            keys.push(key);
        }
        if tokens.len() == 1 {
            stated[1] = stated[0];
        }
        Ok(Self {
            enc: keys[0],
            mac: keys.get(1).copied().unwrap_or(keys[0]),
            dek: keys
                .get(2)
                .copied()
                .or((keys.len() == 1).then_some(keys[0])),
            count: keys.len(),
            stated,
        })
    }

    /// Reads and parses the key text from `source`.
    ///
    /// # Errors
    ///
    /// [`KeyError`].
    pub fn load(source: KeySource<'_>) -> Result<Self, KeyError> {
        Self::parse(&read_key_text(source)?)
    }

    /// Whether a DEK is known: the third key, or the single key.
    pub fn has_dek(&self) -> bool {
        self.dek.is_some()
    }

    /// Whether the text named ENC, MAC and DEK as three keys, which is what a
    /// new key set for PUT KEY has to be.
    pub fn is_key_set(&self) -> bool {
        self.count == 3
    }
}

/// Reads the key text of `source`, capped at [`KEY_TEXT_MAX`].
fn read_key_text(source: KeySource<'_>) -> Result<String, KeyError> {
    use std::io::Read;
    let text = match source {
        KeySource::Env(name) => std::env::var(name)
            .map_err(|_| KeyError::Unreadable(format!("environment variable {name}")))?,
        KeySource::File(path) => {
            let mut text = String::new();
            std::fs::File::open(path)
                .and_then(|f| f.take(KEY_TEXT_MAX + 1).read_to_string(&mut text))
                .map_err(|_| KeyError::Unreadable(format!("file {}", path.display())))?;
            text
        }
    };
    if text.len() as u64 > KEY_TEXT_MAX {
        return Err(KeyError::TooLong);
    }
    Ok(text)
}

/// A symmetric AES DAP key (16, 24 or 32 bytes): the Security Domain's DAP
/// verification key, used to sign the Load File Data Block Hash. Text form is
/// one key, hex, optionally `KEY/KCV` (a wrong KCV is an error before the card
/// is touched). `Debug` is redacted; the bytes appear in no output.
#[derive(Clone, PartialEq, Eq)]
pub struct DapKey(Vec<u8>);

impl std::fmt::Debug for DapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DapKey { .. }")
    }
}

impl DapKey {
    /// Parses one key from `text` (`#` lines skipped).
    ///
    /// # Errors
    ///
    /// [`KeyError`], whose text never contains the input.
    pub fn parse(text: &str) -> Result<Self, KeyError> {
        let tokens: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .flat_map(|l| l.split(|c: char| c.is_whitespace() || c == ','))
            .filter(|t| !t.is_empty())
            .collect();
        let [token] = tokens.as_slice() else {
            return Err(KeyError::Count(tokens.len()));
        };
        let (key_hex, kcv_hex) = match token.split_once('/') {
            Some((k, c)) => (k, Some(c)),
            None => (*token, None),
        };
        let key = hex::decode(key_hex)
            .ok()
            .filter(|k| matches!(k.len(), 16 | 24 | 32))
            .ok_or(KeyError::DapFormat)?;
        if let Some(kcv_hex) = kcv_hex {
            let want = hex::decode(kcv_hex)
                .ok()
                .and_then(|v| <[u8; 3]>::try_from(v).ok())
                .ok_or(KeyError::DapFormat)?;
            let got = aes_kcv(&key).expect("16, 24 or 32 bytes");
            if got != want {
                return Err(KeyError::Kcv {
                    index: 1,
                    computed: hex::encode_upper(got),
                    stated: hex::encode_upper(want),
                });
            }
        }
        Ok(Self(key))
    }

    /// Reads and parses the key from `source`.
    ///
    /// # Errors
    ///
    /// [`KeyError`].
    pub fn load(source: KeySource<'_>) -> Result<Self, KeyError> {
        Self::parse(&read_key_text(source)?)
    }

    /// The key check value (public, 24 bits).
    pub fn kcv(&self) -> [u8; 3] {
        aes_kcv(&self.0).expect("16, 24 or 32 bytes")
    }
}

/// What `gp status` needs to authenticate once.
pub struct Auth<'a> {
    /// The static keys.
    pub keys: &'a Keys,
    /// Key version number for INITIALIZE UPDATE P1; 0 lets the card choose.
    pub key_version: u8,
    /// The 8 random bytes of the host challenge. Fresh per run.
    pub host_challenge: [u8; scp03::CHALLENGE_LEN],
    /// The logical channel the secure channel is opened on (0 is the basic
    /// channel). The MAC covers the class byte, which carries it; pair it with
    /// [`OnChannel`] on the session.
    pub logical_channel: u8,
}

/// Why the run stopped before a secure channel existed.
struct Stop {
    kind: &'static str,
    message: String,
    key_version: Option<u8>,
}

struct Established {
    channel: scp03::Channel,
    iur: scp03::InitializeUpdateResponse,
}

/// The ONE authentication attempt: INITIALIZE UPDATE, the local check of the
/// card cryptogram, then EXTERNAL AUTHENTICATE (security level C-MAC, `01`).
///
/// Commands and cryptograms follow GlobalPlatform Card Specification Amendment D
/// (SCP03) v1.2: INITIALIZE UPDATE `80 50 <kvn> 00 08 <host challenge> 00`
/// (7.1.1.2), the 3-byte key information, challenge and cryptogram response
/// (7.1.1.6, Table 7-3), the card cryptogram under S-MAC with derivation
/// constant 00 (6.2.2.2), the host cryptogram with constant 01 (6.2.2.3),
/// EXTERNAL AUTHENTICATE `84 82 <level> 00 10 <host cryptogram> <C-MAC>` with a
/// zero MAC chaining value (7.1.2, 6.2.3). Cross-checked against pySim
/// `pySim/global_platform/scp.py` (`SCP03.parse_init_update_resp`,
/// `gen_ext_auth_apdu`) and GlobalPlatformPro `SCP03Wrapper`. Not done: for a
/// pseudo-random card challenge (`i` bit 0x10) the challenge is not recomputed
/// from the sequence counter (6.2.2.1); the cryptogram check covers the keys.
fn authenticate<S: CardSession + ?Sized>(
    session: &mut S,
    steps: &mut Vec<Value>,
    auth: &Auth<'_>,
) -> Result<Result<Established, Stop>, session::Error> {
    let policy = read_policy();
    let stop = |kind, message, key_version| {
        Ok(Err(Stop {
            kind,
            message,
            key_version,
        }))
    };
    let sw = |ex: &session::Exchange| sw_hex(ex).unwrap_or_else(|| "none".into());

    let init = scp03::initialize_update(auth.key_version, &auth.host_challenge);
    let ex = session::send(session, &init, &policy)?;
    push_steps(steps, "initialize_update", &ex);
    if !ex.is_normal_processing() {
        return stop(
            "initialize-update-refused",
            format!(
                "INITIALIZE UPDATE answered {}; nothing else was sent",
                sw(&ex)
            ),
            None,
        );
    }
    // SCP02 answers 28 bytes with 02 at offset 11; name it rather than "bad length".
    if let Some(&scp) = ex.data().get(11).filter(|b| **b != 0x03) {
        return stop(
            "not-scp03",
            format!("the card answered with SCP {scp:02X}; only SCP03 is implemented"),
            None,
        );
    }
    let iur = match scp03::InitializeUpdateResponse::parse(ex.data()) {
        Ok(iur) => iur,
        Err(e) => return stop("initialize-update-unreadable", e.to_string(), None),
    };
    let kvn = Some(iur.key_version);
    let session_keys = scp03::derive_session_keys(
        &auth.keys.enc,
        &auth.keys.mac,
        &auth.host_challenge,
        &iur.card_challenge,
    );
    if !scp03::verify_card_cryptogram(
        &session_keys,
        &auth.host_challenge,
        &iur.card_challenge,
        &iur.card_cryptogram,
    ) {
        return stop(
            "keys-do-not-match",
            "keys do not match this card: the card cryptogram does not verify with the supplied \
             keys. EXTERNAL AUTHENTICATE was not sent, so no authentication attempt was counted"
                .into(),
            kvn,
        );
    }
    let host_cryptogram = scp03::cryptogram(
        &session_keys.mac,
        scp03::Side::Host,
        &auth.host_challenge,
        &iur.card_challenge,
    );
    let mut channel = scp03::Channel::new(&session_keys).on_logical_channel(auth.logical_channel);
    let external =
        match scp03::external_authenticate(&mut channel, scp03::LEVEL_C_MAC, &host_cryptogram) {
            Ok(command) => command,
            Err(e) => return stop("external-authenticate-unbuildable", e.to_string(), kvn),
        };
    let ex = session::send(session, &external, &policy)?;
    push_steps(steps, "external_authenticate", &ex);
    if !ex.is_normal_processing() {
        return stop(
            "external-authenticate-refused",
            format!(
                "EXTERNAL AUTHENTICATE answered {}. It was not retried; the card counts this as \
                 one failed authentication",
                sw(&ex)
            ),
            kvn,
        );
    }
    Ok(Ok(Established { channel, iur }))
}

/// Sends `plain` MAC'd on `channel` (once, in send order: the chaining value
/// advances per command sent). No `6C` correction, because a re-send would need a
/// new MAC and the card's chain state after a `6C` is not specified.
fn send_secure<S: CardSession + ?Sized>(
    session: &mut S,
    steps: &mut Vec<Value>,
    channel: &mut scp03::Channel,
    label: &str,
    plain: &Command,
) -> Result<session::Exchange, session::Error> {
    // GET STATUS data is the 2-byte search criterion, so data plus MAC always fits.
    let wrapped = channel
        .wrap(plain)
        .expect("2 data bytes plus the C-MAC fit a short APDU");
    let ex = session::send(session, &wrapped, &read_policy())?;
    push_steps(steps, label, &ex);
    Ok(ex)
}

/// The `secure_channel` block of an established channel. Holds the key check
/// values of the supplied keys (public, 24 bits each) and never a key.
fn channel_report(auth: &Auth<'_>, est: &Established, card_keys: Option<&Value>) -> Value {
    let kvn = est.iur.key_version;
    // The card's own entry for this key version: GET DATA E0 has id, version,
    // type and length only; no KCV (GP 2.3.1 11.3.3.1; GlobalPlatformPro
    // `GPKeyInfo.parseTemplate` reads no KCV either).
    let card = card_keys.and_then(Value::as_array).and_then(|keys| {
        keys.iter()
            .find(|k| k["key_version"].as_u64() == Some(u64::from(kvn)))
    });
    let key_info = match card {
        Some(k) => json!({
            "found": true,
            "card_key_type": k["key_type_name"],
            "card_key_length": k["key_length"],
            "matches_supplied": k["key_type"] == "88" && k["key_length"] == 16,
        }),
        None => json!({ "found": false }),
    };
    let kcv = |key: &[u8; 16], stated: bool| {
        json!({
            "kcv": hex::encode_upper(aes_kcv(key).expect("16-byte key")),
            "stated_kcv": if stated { "match" } else { "not-stated" },
        })
    };
    json!({
        "protocol": "SCP03",
        "established": true,
        "security_level": "C-MAC (01)",
        "key_version": kvn,
        "i_parameter": format!("{:02X}", est.iur.i_parameter),
        "card_cryptogram_verified": true,
        "enc_key_exercised": false,
        "enc_key": kcv(&auth.keys.enc, auth.keys.stated[0]),
        "mac_key": kcv(&auth.keys.mac, auth.keys.stated[1]),
        "card_key_info": key_info,
        "kcv_on_card": "not exposed: GET DATA key information carries id, version, type and length only",
    })
}

/// Findings over a `gp status` `data`, as `{id, severity, message[, aid]}`.
/// They are entries in `data.registry_findings`, not doctor/1 findings: `gp`
/// keeps the lpac envelope.
///
/// - `gp/weak-secure-channel` (medium): Card Recognition Data advertises SCP01 or SCP02.
/// - `gp/isd-lifecycle` (medium before SECURED, low when locked or terminated).
/// - `gp/app-locked` (low): an application in the LOCKED state.
/// - `gp/app-excess-privilege` (medium): an application that is not a security
///   domain holds Card Lock, Card Terminate, Card Reset, Global Delete, Global
///   Lock or Global Registry (privilege bits as in [`PRIVILEGES`]).
pub fn registry_findings(data: &Value) -> Vec<Value> {
    const RISKY: [&str; 6] = [
        "card_lock",
        "card_terminate",
        "card_reset",
        "global_delete",
        "global_lock",
        "global_registry",
    ];
    let mut out = Vec::new();
    let mut add = |id: &str, severity: &str, message: String, aid: Option<&Value>| {
        let mut f = json!({ "id": id, "severity": severity, "message": message });
        if let Some(aid) = aid {
            f["aid"] = aid.clone();
        }
        out.push(f);
    };
    for n in data["card_recognition"]["weak_scp"]
        .as_array()
        .into_iter()
        .flatten()
    {
        add(
            "gp/weak-secure-channel",
            "medium",
            format!("the card offers SCP0{n}, an old secure channel protocol; prefer SCP03"),
            None,
        );
    }
    for scope in data["registry"].as_array().into_iter().flatten() {
        let name = scope["scope"].as_str().unwrap_or("");
        for e in scope["entries"].as_array().into_iter().flatten() {
            let aid = &e["aid"];
            let life = e["lifecycle_name"].as_str().unwrap_or("unknown");
            let privs: Vec<&str> = e["privilege_names"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            if name == "isd" && life != "SECURED" && life != "unknown" {
                let (sev, tail) = match life {
                    "CARD_LOCKED" | "TERMINATED" => ("low", ""),
                    _ => ("medium", ": the card is not in the SECURED state"),
                };
                add(
                    "gp/isd-lifecycle",
                    sev,
                    format!("the ISD is {life}{tail}"),
                    Some(aid),
                );
            }
            if name == "applications" {
                if life == "LOCKED" {
                    add(
                        "gp/app-locked",
                        "low",
                        "an application is LOCKED".into(),
                        Some(aid),
                    );
                }
                if !privs.contains(&"security_domain") {
                    let held: Vec<&str> = RISKY
                        .iter()
                        .copied()
                        .filter(|r| privs.contains(r))
                        .collect();
                    if !held.is_empty() {
                        add(
                            "gp/app-excess-privilege",
                            "medium",
                            format!(
                                "a non-security-domain application holds {}",
                                held.join(", ")
                            ),
                            Some(aid),
                        );
                    }
                }
            }
        }
    }
    out
}

/// GET STATUS for the four scopes of [`STATUS_SCOPES`], over `channel` when it
/// is `Some` (MAC'd, in send order) and plain otherwise; `63 10` is followed
/// up to [`STATUS_MAX_PAGES`] pages. A refusal is data in the scope's object.
fn read_registry<S: CardSession + ?Sized>(
    session: &mut S,
    steps: &mut Vec<Value>,
    mut channel: Option<&mut scp03::Channel>,
) -> Result<Vec<Value>, session::Error> {
    let mut scopes = Vec::new();
    for (p1, name) in STATUS_SCOPES {
        let mut collected = Vec::new();
        let mut p2 = 0x02;
        let mut pages = 0;
        let (last, truncated) = loop {
            let build = |le| Command::case4(Header::new(0x80, 0xF2, p1, p2), vec![0x4F, 0x00], le);
            let ex = match channel.as_deref_mut() {
                Some(ch) => send_secure(session, steps, ch, name, &build(Le::Short(0)))?,
                None => read_once(session, steps, name, build)?,
            };
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
    Ok(scopes)
}

/// `gp status` without keys; see [`status_with`].
///
/// # Errors
///
/// Only transport and encoding failures.
pub fn status<S: CardSession + ?Sized>(
    session: &mut S,
    trace: bool,
) -> Result<Report, session::Error> {
    status_with(session, trace, None)
}

/// `gp status` over a secure channel opened with `auth`; see [`status_with`].
///
/// # Errors
///
/// Only transport and encoding failures. A failed authentication is data:
/// `data.error` and `data.secure_channel`.
pub fn status_authenticated<S: CardSession + ?Sized>(
    session: &mut S,
    trace: bool,
    auth: &Auth<'_>,
) -> Result<Report, session::Error> {
    status_with(session, trace, Some(auth))
}

/// `gp select --aid`: SELECT an arbitrary GlobalPlatform application (or any
/// application) by AID and report the status word and the FCI. `isd_found` is
/// whether it answered `90 00`. Changes the card's current selection only.
///
/// # Errors
///
/// Only transport and encoding failures.
pub fn select<S: CardSession + ?Sized>(
    session: &mut S,
    aid: &[u8],
    trace: bool,
) -> Result<Report, session::Error> {
    let mut steps = Vec::new();
    let ex = read_once(session, &mut steps, "select", select_by_aid(aid))?;
    let mut data = json!({
        "card_touched": true,
        "selected": { "aid": hex::encode_upper(aid), "status": sw_hex(&ex) },
    });
    if ex.is_success() {
        data["selected"]["fci"] = hex_of(ex.data());
        // FCI is `6F { 84 DF name, A5 proprietary ... }` (ISO/IEC 7816-4 SELECT).
        if let Some((_, name)) = parse_tlvs(ex.data())
            .and_then(|t| t.into_iter().find(|(tag, _)| *tag == 0x6F))
            .and_then(|(_, body)| parse_tlvs(body))
            .and_then(|t| t.into_iter().find(|(tag, _)| *tag == 0x84))
        {
            data["selected"]["df_name"] = hex_of(name);
        }
    }
    if trace {
        data["trace"] = Value::Array(steps);
    }
    Ok(Report {
        isd_found: ex.is_success(),
        data,
    })
}

/// `gp status`: SELECT the ISD, GET DATA tag 66 (Card Recognition Data), then
/// GET STATUS (`80 F2 <scope> 02`, TLV format) for the ISD, applications,
/// executable load files and load files with modules. Without `auth` it is
/// read-only and unauthenticated: a card that wants a secure channel answers
/// `6982`/`6985` and the scope is reported as `requires_authentication`. With
/// `auth` it also reads the key information (GET DATA E0), makes the one
/// authentication attempt of [`authenticate`] and sends GET STATUS MAC'd on the
/// channel; a failed authentication returns early with `data.error` set and no
/// registry. `63 10` is followed with GET STATUS "next" up to
/// [`STATUS_MAX_PAGES`] pages.
fn status_with<S: CardSession + ?Sized>(
    session: &mut S,
    trace: bool,
    auth: Option<&Auth<'_>>,
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
    let mut channel = None;
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
        if let Some(auth) = auth {
            // Plain reads first: after EXTERNAL AUTHENTICATE every command must be MAC'd.
            let ex = read_once(session, &mut steps, "key_information", |le| {
                Command::case2(Header::new(0x80, 0xCA, 0x00, 0xE0), le)
            })?;
            let card_keys = if ex.is_success() {
                decode_key_information(ex.data()).ok()
            } else {
                None
            };
            match authenticate(session, &mut steps, auth)? {
                Ok(est) => {
                    data["secure_channel"] = channel_report(auth, &est, card_keys.as_ref());
                    channel = Some(est.channel);
                }
                Err(stop) => {
                    data["secure_channel"] = json!({
                        "protocol": "SCP03",
                        "established": false,
                        "stopped": stop.kind,
                        "key_version": stop.key_version,
                    });
                    data["error"] = json!({ "kind": stop.kind, "message": stop.message });
                    if trace {
                        data["trace"] = Value::Array(steps);
                    }
                    return Ok(Report {
                        isd_found: true,
                        data,
                    });
                }
            }
        }
        let scopes = read_registry(session, &mut steps, channel.as_mut())?;
        data["registry"] = Value::Array(scopes);
        data["registry_findings"] = Value::Array(registry_findings(&data));
    }
    if trace {
        data["trace"] = Value::Array(steps);
    }
    Ok(Report {
        isd_found: selected.is_some(),
        data,
    })
}

/// Plain-text rendering of a `gp ara` / `gp status` / `gp select` `data`, one fact per line.
/// Card bytes only reach it as hex or as the package name, which goes through
/// [`crate::contract::sanitize`] (JSON output is escaped by the serialiser).
pub fn render_text(data: &Value) -> String {
    let s = |v: &Value| crate::contract::sanitize(v.as_str().unwrap_or("-"));
    let mut out = Vec::new();
    if let Some(sel) = data.get("selected") {
        out.push(format!(
            "SELECT {}: status {}",
            s(&sel["aid"]),
            s(&sel["status"])
        ));
        for (key, label) in [("df_name", "DF name"), ("fci", "FCI")] {
            if sel.get(key).is_some() {
                out.push(format!("  {label}: {}", s(&sel[key])));
            }
        }
    }
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
    if let Some(c) = data
        .get("secure_channel")
        .filter(|c| c["established"] == true)
    {
        out.push(format!(
            "Secure channel: SCP03 {}, key version {:02X}, card cryptogram verified; ENC KCV {}, MAC KCV {}",
            s(&c["security_level"]),
            c["key_version"].as_u64().unwrap_or(0),
            s(&c["enc_key"]["kcv"]),
            s(&c["mac_key"]["kcv"]),
        ));
        if c["card_key_info"]["matches_supplied"] == false {
            out.push(format!(
                "  card key type {} length {} differs from the supplied AES-128 key",
                s(&c["card_key_info"]["card_key_type"]),
                c["card_key_info"]["card_key_length"]
            ));
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
            let mut line = format!("  {} {}", s(&e["aid"]), s(&e["lifecycle_name"]));
            let privs: Vec<&str> = e["privilege_names"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            if !privs.is_empty() {
                line += &format!(" [{}]", privs.join(", "));
            }
            out.push(line);
        }
    }
    for f in data["registry_findings"].as_array().into_iter().flatten() {
        out.push(format!(
            "finding {} ({}): {}",
            s(&f["id"]),
            s(&f["severity"]),
            s(&f["message"])
        ));
    }
    if let Some(c) = data.get("channel") {
        out.push(format!(
            "Logical channel {}: {} (status {})",
            s(&c["action"]),
            c["number"],
            s(&c["status"])
        ));
    }
    if let Some(op) = data.get("operation") {
        render_write(&mut out, op, data);
    }
    out.join("\n")
}

/// The `delete` / `install` part of [`render_text`].
fn render_write(out: &mut Vec<String>, op: &Value, data: &Value) {
    let s = |v: &Value| crate::contract::sanitize(v.as_str().unwrap_or("-"));
    let state = match (data["dry_run"] == true, data["sent"] == true) {
        (true, _) => "DRY RUN, nothing was written; add --yes to send",
        (false, true) => "SENT",
        (false, false) => "refused, nothing was sent",
    };
    out.push(format!("{}: {state}", s(op).to_uppercase()));
    if let Some(w) = data["warning"].as_str() {
        out.push(format!("  WARNING: {}", crate::contract::sanitize(w)));
    }
    if let Some(t) = data["target"].as_object() {
        for (k, v) in t {
            let v = v.as_str().map_or_else(|| v.to_string(), str::to_string);
            out.push(format!("  {k}: {}", crate::contract::sanitize(&v)));
        }
    }
    if let Some(note) = data["note"].as_str() {
        out.push(format!("  {}", crate::contract::sanitize(note)));
    }
    for a in data["plan"]["apdus"].as_array().into_iter().flatten() {
        if a["apdu"].is_null() {
            out.push(format!(
                "  APDU {}: {} ({})",
                s(&a["step"]),
                s(&a["header"]),
                s(&a["data"])
            ));
        } else {
            out.push(format!("  APDU {}: {}", s(&a["step"]), s(&a["apdu"])));
        }
    }
    if let Some(note) = data["plan"]["note"].as_str() {
        out.push(format!("  ({})", crate::contract::sanitize(note)));
    }
    for r in data["result"]["steps"].as_array().into_iter().flatten() {
        out.push(format!(
            "  sent {}: status {}",
            s(&r["step"]),
            s(&r["status"])
        ));
    }
    if data["result"]["verified"] == true {
        out.push("  verified: the registry shows the intended result".into());
    }
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
    /// Privileges are not 1 or 3 bytes.
    #[error("privileges are {0} bytes, GlobalPlatform defines 1 or 3")]
    Privileges(usize),
    /// A privilege this tool will not grant.
    #[error("{0}")]
    PrivilegeRefused(&'static str),
    /// The Install Parameters field does not hold the mandatory C9 tag.
    #[error("install parameters must be TLV that holds the mandatory C9 tag (C900 for none)")]
    InstallParameters,
    /// A PUT KEY parameter outside what GP Card Spec v2.3.1 11.8.2.1 to 11.8.2.3 allow.
    #[error("{0}")]
    PutKey(&'static str),
    /// The supplied authentication keys have no DEK to encrypt the new keys with.
    #[error("PUT KEY encrypts the new keys under the current DEK, and the supplied keys have none: give ENC MAC DEK (or one key for all three)")]
    DekMissing,
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
/// frames bytes the caller already has; [`dap_signature`] computes the
/// signature. GP Card Spec v2.3.1 section 11.6.2.3, Table 11-58; the same
/// framing as GlobalPlatformPro `GPSession.loadCapFile`.
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

// ---------------------------------------------------------------------------
// Logical channels (issue #19)
// ---------------------------------------------------------------------------

/// A session whose every command is addressed to logical channel `channel`:
/// the class byte of each command sent through it is rewritten with
/// [`class_on_channel`] (GP Card Spec v2.3.1 11.1.4), GET RESPONSE follow-ups
/// included, so a `61 xx` on the channel is collected on the channel. A command
/// that already carries the channel (a MAC'd one: [`scp03::Channel::on_logical_channel`]
/// puts it there before the MAC is computed) comes out unchanged. A class byte
/// that has no channel coding (the GSM `A0`) is sent as is.
///
/// The wire bytes in [`session::Exchange`] are those handed to the session, so a
/// trace taken through this wrapper is corrected afterwards with
/// [`retarget_channel`].
pub struct OnChannel<'a, S: CardSession + ?Sized> {
    inner: &'a mut S,
    channel: u8,
}

impl<'a, S: CardSession + ?Sized> OnChannel<'a, S> {
    /// Wraps `inner`; channel 0 changes nothing.
    pub fn new(inner: &'a mut S, channel: u8) -> Self {
        Self { inner, channel }
    }
}

impl<S: CardSession + ?Sized> CardSession for OnChannel<'_, S> {
    fn reader(&self) -> &crate::transport::ReaderName {
        self.inner.reader()
    }

    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, crate::transport::Error> {
        let mut bytes = command.to_vec();
        if let Some(n) = bytes
            .first()
            .and_then(|c| class_on_channel(*c, self.channel))
        {
            bytes[0] = n;
        }
        self.inner.transmit(&bytes)
    }

    fn disconnect(&mut self) -> Result<(), crate::transport::Error> {
        self.inner.disconnect()
    }
}

/// Rewrites the class byte of every `data.trace[].command` and
/// `data.plan.apdus[].apdu` for logical channel `channel`, so the output shows
/// what [`OnChannel`] put on the wire.
pub fn retarget_channel(data: &mut Value, channel: u8) {
    let fix = |v: &mut Value| {
        if let Some(mut b) = v.as_str().and_then(|h| hex::decode(h).ok()) {
            if let Some(n) = b.first().and_then(|c| class_on_channel(*c, channel)) {
                b[0] = n;
                *v = hex_of(&b);
            }
        }
    };
    for t in data
        .get_mut("trace")
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        fix(&mut t["command"]);
    }
    for t in data
        .pointer_mut("/plan/apdus")
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        fix(&mut t["apdu"]);
    }
}

/// What a status word means for the commands this module sends, as
/// `(kind, meaning)`: the general error conditions of GP Card Spec v2.3.1 Table
/// 11-10 and the DELETE (11-26), INSTALL (11-55), LOAD (11-60) and MANAGE
/// CHANNEL (11-62, 11-63) tables. Every word has its own kind; a word those
/// tables do not list is `unlisted-status`.
fn status_word(sw: Option<&str>) -> (&'static str, &'static str) {
    match sw {
        Some("6200") => ("channel-already-closed", "logical channel already closed"),
        Some("6400") => ("no-specific-diagnosis", "no specific diagnosis"),
        Some("6581") => ("memory-failure", "memory failure"),
        Some("6700") => ("wrong-length", "wrong length in Lc"),
        Some("6881") => (
            "channel-not-active",
            "logical channel not supported or is not active",
        ),
        Some("6882") => (
            "secure-messaging-not-supported",
            "secure messaging not supported",
        ),
        Some("6982") => (
            "security-status-not-satisfied",
            "security status not satisfied",
        ),
        Some("6985") => (
            "conditions-of-use-not-satisfied",
            "conditions of use not satisfied",
        ),
        Some("6A80") => (
            "incorrect-command-data",
            "incorrect values or parameters in the command data",
        ),
        Some("6A81") => (
            "function-not-supported",
            "function not supported, for example the card is CARD_LOCKED",
        ),
        Some("6A82") => ("application-not-found", "application not found"),
        Some("6A84") => ("not-enough-memory-space", "not enough memory space"),
        Some("6A86") => ("incorrect-p1-p2", "incorrect P1 P2"),
        Some("6A88") => ("referenced-data-not-found", "referenced data not found"),
        Some("6D00") => ("invalid-instruction", "invalid instruction"),
        Some("6E00") => ("invalid-class", "invalid class"),
        _ => (
            "unlisted-status",
            "a status word the GlobalPlatform tables for this command do not list",
        ),
    }
}

/// The `data.error` of a command the card refused.
fn refused(what: &str, ex: &session::Exchange) -> Value {
    let sw = sw_hex(ex);
    let (kind, meaning) = status_word(sw.as_deref());
    json!({
        "kind": kind,
        "status": sw,
        "meaning": meaning,
        "message": format!("{what} answered {}: {meaning}", sw.as_deref().unwrap_or("none")),
    })
}

/// `gp channel open`: MANAGE CHANNEL open (`00 70 00 00 01`, ISO/IEC 7816-4
/// 11.1.2; GP Card Spec v2.3.1 11.7). The card picks the number and returns it.
/// The channel stays open on the card until `gp channel close` or a power cycle,
/// and the next `gp` run can address it with `--channel`. `isd_found` is true
/// when a channel was opened.
///
/// # Errors
///
/// Only transport and encoding failures; a refusal is `data.error`.
pub fn channel_open<S: CardSession + ?Sized>(
    session: &mut S,
    trace: bool,
) -> Result<Report, session::Error> {
    let (channel, ex) = session::open_channel(session)?;
    let mut steps = Vec::new();
    push_steps(&mut steps, "manage_channel_open", &ex);
    let mut data = json!({
        "card_touched": true,
        "channel": { "action": "open", "number": channel, "status": sw_hex(&ex) },
    });
    if channel.is_none() {
        data["error"] = if ex.is_success() {
            json!({
                "kind": "channel-number-unreadable",
                "message": "MANAGE CHANNEL answered 9000 without a channel number in 1 to 19",
            })
        } else {
            refused("MANAGE CHANNEL open", &ex)
        };
    }
    if trace {
        data["trace"] = Value::Array(steps);
    }
    Ok(Report {
        isd_found: channel.is_some(),
        data,
    })
}

/// `gp channel close --channel N`: MANAGE CHANNEL close (`00 70 80 <N>`, sent on
/// the basic channel). `isd_found` is true when the card answered `90 00`.
///
/// # Errors
///
/// Only transport and encoding failures; a refusal is `data.error`.
pub fn channel_close<S: CardSession + ?Sized>(
    session: &mut S,
    channel: u8,
    trace: bool,
) -> Result<Report, session::Error> {
    let mut steps = Vec::new();
    let Some(ex) = session::close_channel(session, channel)? else {
        return Ok(Report {
            isd_found: false,
            data: json!({
                "card_touched": false,
                "channel": { "action": "close", "number": channel },
                "error": { "kind": "bad-channel", "message": "the channel to close must be 1 to 19" },
            }),
        });
    };
    push_steps(&mut steps, "manage_channel_close", &ex);
    let mut data = json!({
        "card_touched": true,
        "channel": { "action": "close", "number": channel, "status": sw_hex(&ex) },
    });
    if !ex.is_success() {
        data["error"] = refused("MANAGE CHANNEL close", &ex);
    }
    if trace {
        data["trace"] = Value::Array(steps);
    }
    Ok(Report {
        isd_found: ex.is_success(),
        data,
    })
}

// ---------------------------------------------------------------------------
// Card writes: DELETE and INSTALL/LOAD over the SCP03 channel (issues #133, #19)
// ---------------------------------------------------------------------------

/// Builds, and does not send, DELETE [card content]: `80 E4 00 <P2> Lc 4F <len>
/// <AID> 00`. P2 is `80` to delete the object and its related objects (an
/// Executable Load File and its Applications), `00` for the object alone. GP
/// Card Spec v2.3.1 section 11.2.2 (Tables 11-20 to 11-23); the data field and P2
/// are pySim `do_delete_card_content` (`4F` TLV, `0x80` for related objects) and
/// GlobalPlatformPro `GPSession.deleteAID` (`4F <len> <aid>`, P2 `80` for
/// dependencies). No token (`B6`, `9E`): delegated management is not supported.
pub fn delete_command(aid: &[u8], related: bool) -> Result<Command, BuildError> {
    aid_ok("DELETE target", aid, false)?;
    let mut data = vec![0x4F];
    lv(&mut data, "DELETE target", aid)?;
    Ok(Command::case4(
        Header::new(0x80, 0xE4, 0x00, if related { 0x80 } else { 0x00 }),
        data,
        Le::Short(0),
    ))
}

/// Builds, and does not send, INSTALL [for install] (`make_selectable` false,
/// P1 `04`) or INSTALL [for install and make selectable] (P1 `0C`): `80 E6 <P1>
/// 00 Lc <data> 00` with data = `LV(load file AID) LV(module AID) LV(application
/// AID) LV(privileges) BERLV(install parameters) BERLV(install token)`, the token
/// always empty. GP Card Spec v2.3.1 Table 11-41 (P1: b3 install, b4 make
/// selectable) and Table 11-43; layout as pySim `do_install_for_install` and
/// GlobalPlatformPro `GPSession.buildInstallData`. `privileges` is 1 or 3 bytes
/// (11.1.2), `install_parameters` the whole Install Parameters field, which must
/// hold the mandatory `C9` tag (Table 11-49).
pub fn install_for_install(
    load_file_aid: &[u8],
    module_aid: &[u8],
    application_aid: &[u8],
    privileges: &[u8],
    install_parameters: &[u8],
    make_selectable: bool,
) -> Result<Command, BuildError> {
    aid_ok("load file", load_file_aid, true)?;
    aid_ok("module", module_aid, true)?;
    aid_ok("application", application_aid, false)?;
    if !matches!(privileges.len(), 1 | 3) {
        return Err(BuildError::Privileges(privileges.len()));
    }
    if !parse_tlvs(install_parameters).is_some_and(|t| t.iter().any(|(tag, _)| *tag == 0xC9)) {
        return Err(BuildError::InstallParameters);
    }
    let mut data = Vec::new();
    lv(&mut data, "load file AID", load_file_aid)?;
    lv(&mut data, "module AID", module_aid)?;
    lv(&mut data, "application AID", application_aid)?;
    lv(&mut data, "privileges", privileges)?;
    data.extend(ber_len(install_parameters.len()));
    data.extend_from_slice(install_parameters);
    data.push(0x00); // no install token
    if data.len() > 0xFF {
        return Err(BuildError::InstallTooLong(data.len()));
    }
    let p1 = if make_selectable { 0x0C } else { 0x04 };
    Ok(Command::case4(
        Header::new(0x80, 0xE6, p1, 0x00),
        data,
        Le::Short(0),
    ))
}

/// What `gp delete` removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteRequest {
    /// The application or Executable Load File AID.
    pub aid: Vec<u8>,
    /// Also delete the related objects (DELETE P2 `80`).
    pub related: bool,
}

/// What `gp install` loads and installs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRequest {
    /// The load file (the CAP's components, [`crate::cap::Cap::load_file`]).
    pub load_file: Vec<u8>,
    /// The Executable Load File AID (the package AID).
    pub load_file_aid: Vec<u8>,
    /// The Executable Module AID (the applet class).
    pub module_aid: Vec<u8>,
    /// The Application (instance) AID.
    pub app_aid: Vec<u8>,
    /// Privileges, 1 or 3 bytes. Card Lock and Card Terminate are refused.
    pub privileges: Vec<u8>,
    /// The Install Parameters field, with its `C9` tag; `C9 00` for none.
    pub params: Vec<u8>,
    /// Sign the Load File Data Block Hash and send a DAP block, if set.
    pub dap: Option<DapRequest>,
}

/// Which hash is the Load File Data Block Hash when a DAP block is sent (GP Card
/// Spec v2.3.1 C.2 and Table C-3). SHA-1 is not offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lfdbh {
    /// SHA-256 (Table C-3: the minimum for an AES-128 scheme).
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl Lfdbh {
    /// The name shown in output.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// The digest of the Load File Data Block, without tag `C4` and its length
    /// (C.2).
    pub fn digest(self, load_file: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        match self {
            Self::Sha256 => sha2::Sha256::digest(load_file).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(load_file).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(load_file).to_vec(),
        }
    }
}

/// A DAP block for `gp install`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DapRequest {
    /// The Security Domain's DAP verification key.
    pub key: DapKey,
    /// The Security Domain that verifies the DAP (the `4F` of the block); the
    /// authenticated ISD when `None`.
    pub security_domain: Option<Vec<u8>>,
    /// The Load File Data Block Hash algorithm.
    pub hash: Lfdbh,
}

/// The Load File Data Block Signature of an AES DAP key: AES-CMAC of the Load
/// File Data Block Hash, 16 bytes. GP Card Spec v2.3.1 C.3 ("If the signing key
/// is an AES key, the Load File Data Block Signature is generated according to
/// section B.2.2") and B.2.2 (CMAC, NIST SP 800-38B, 16 byte result).
pub fn dap_signature(key: &DapKey, lfdbh: &[u8]) -> [u8; 16] {
    use cmac::{Cmac, Mac};
    macro_rules! mac {
        ($cipher:ty) => {{
            let mut m = <Cmac<$cipher> as KeyInit>::new_from_slice(&key.0)
                .expect("DapKey holds 16, 24 or 32 bytes");
            m.update(lfdbh);
            m.finalize().into_bytes().into()
        }};
    }
    match key.0.len() {
        16 => mac!(aes::Aes128),
        24 => mac!(aes::Aes192),
        _ => mac!(aes::Aes256),
    }
}

/// One APDU of a write, as built (before secure messaging).
struct Planned {
    step: &'static str,
    command: Command,
}

fn delete_plan_steps(req: &DeleteRequest) -> Result<Vec<Planned>, BuildError> {
    Ok(vec![Planned {
        step: "delete",
        command: delete_command(&req.aid, req.related)?,
    }])
}

/// INSTALL [for load], the LOAD blocks, INSTALL [for install and make
/// selectable]: the GP Card Spec v2.3.1 11.5 and 11.6 sequence, which is also
/// pySim `do_install_cap` and GlobalPlatformPro `GPSession.loadCapFile` followed
/// by `installAndMakeSelectable`. `sd_aid` is the security domain the load file
/// goes into (the one that was authenticated).
fn install_plan_steps(req: &InstallRequest, sd_aid: &[u8]) -> Result<Vec<Planned>, BuildError> {
    if req.privileges.first().is_some_and(|b| b & 0x18 != 0) {
        return Err(BuildError::PrivilegeRefused(
            "Card Lock and Card Terminate are not granted by gp install",
        ));
    }
    // With a DAP the Load File Data Block Hash is mandatory (11.5.2.3.1) and is
    // what the DAP signs; the block precedes the C4 block in the Load File (11.6.2.3).
    let (lfdbh, dap_blocks) = match &req.dap {
        Some(d) => {
            let hash = d.hash.digest(&req.load_file);
            let signature = dap_signature(&d.key, &hash);
            let block = dap_block(d.security_domain.as_deref().unwrap_or(sd_aid), &signature)?;
            (hash, vec![block])
        }
        None => (Vec::new(), Vec::new()),
    };
    let mut plan = vec![Planned {
        step: "install_for_load",
        command: install_for_load(&req.load_file_aid, sd_aid, &lfdbh, &[], &[])?,
    }];
    for command in load_commands(&req.load_file, &dap_blocks, DEFAULT_LOAD_BLOCK)? {
        plan.push(Planned {
            step: "load",
            command,
        });
    }
    plan.push(Planned {
        step: "install_for_install",
        command: install_for_install(
            &req.load_file_aid,
            &req.module_aid,
            &req.app_aid,
            &req.privileges,
            &req.params,
            true,
        )?,
    });
    // Wrapping adds an 8-byte C-MAC to the data; the Lc must still fit.
    for p in &plan {
        if p.command.data().len() + scp03::MAC_LEN > 0xFF {
            return Err(BuildError::InstallTooLong(p.command.data().len()));
        }
    }
    Ok(plan)
}

fn plan_json(plan: &[Planned]) -> Value {
    Value::Array(
        plan.iter()
            .map(|p| {
                let wire = p.command.encode().expect("a built command encodes");
                if p.step == PUT_KEY_STEP {
                    // The data is the new keys encrypted under the DEK: withheld.
                    return json!({
                        "step": p.step,
                        "apdu": null,
                        "header": hex::encode_upper(&wire[..4]),
                        "data": format!("{} bytes withheld: the new key version and the new keys encrypted under the DEK", wire.len() - 6),
                    });
                }
                json!({ "step": p.step, "apdu": hex_of(&wire) })
            })
            .collect(),
    )
}

/// The `data` of a write that was not sent because no keys were given: the
/// plan, built offline, and nothing else. The card is not contacted.
fn offline_dry_run(operation: &str, target: Value, plan: &[Planned], note: &str) -> Value {
    json!({
        "card_touched": false,
        "operation": operation,
        "dry_run": true,
        "sent": false,
        "target": target,
        "plan": {
            "apdus": plan_json(plan),
            "note": "each APDU is sent with the class byte set for secure messaging and an 8-byte C-MAC appended (SCP03, C-MAC); shown here before that",
        },
        "note": note,
    })
}

/// `gp delete` without keys: the offline dry run. Sends nothing and does not
/// touch a card.
///
/// # Errors
///
/// [`BuildError`] for an AID that is not 5 to 16 bytes.
pub fn delete_dry_run(req: &DeleteRequest) -> Result<Value, BuildError> {
    let plan = delete_plan_steps(req)?;
    Ok(offline_dry_run(
        "delete",
        json!({ "aid": hex_of(&req.aid), "related": req.related }),
        &plan,
        "no keys were given, so the card was not contacted and the registry was not checked; add --keys-file or --keys-env to check that the AID is present, and --yes to send",
    ))
}

/// `gp install` without keys: the offline dry run, with the default ISD AID as
/// the security domain. Sends nothing and does not touch a card.
///
/// # Errors
///
/// [`BuildError`] for an AID, privileges, parameters or load file that cannot be
/// built into commands.
pub fn install_dry_run(req: &InstallRequest) -> Result<Value, BuildError> {
    let plan = install_plan_steps(req, ISD_AIDS[0])?;
    let mut data = offline_dry_run(
        "install",
        install_target(req),
        &plan,
        "no keys were given, so the card was not contacted and the registry was not checked; the security domain is assumed to be the default ISD AID; add --keys-file or --keys-env to check the registry, and --yes to send",
    );
    data["target"]["security_domain"] = hex_of(ISD_AIDS[0]);
    Ok(data)
}

fn install_target(req: &InstallRequest) -> Value {
    let mut target = json!({
        "load_file_aid": hex_of(&req.load_file_aid),
        "module_aid": hex_of(&req.module_aid),
        "app_aid": hex_of(&req.app_aid),
        "privileges": hex_of(&req.privileges),
        "install_parameters": hex_of(&req.params),
        "load_file_bytes": req.load_file.len(),
    });
    if let Some(d) = &req.dap {
        target["dap"] = json!({
            "scheme": "AES-CMAC over the Load File Data Block Hash (C.3, B.2.2)",
            "hash": d.hash.name(),
            "load_file_data_block_hash": hex_of(&d.hash.digest(&req.load_file)),
            "security_domain": d.security_domain.as_deref().map_or_else(
                || json!("the authenticated security domain"), hex_of),
            "key_kcv": hex::encode_upper(d.key.kcv()),
        });
    }
    target
}

/// The entry for `aid_hex` in a [`read_registry`] result, with its scope name.
fn registry_entry<'a>(registry: &'a [Value], aid_hex: &str) -> Option<(&'a str, &'a Value)> {
    registry.iter().find_map(|scope| {
        scope["entries"]
            .as_array()?
            .iter()
            .find(|e| e["aid"] == aid_hex)
            .map(|e| (scope["scope"].as_str().unwrap_or(""), e))
    })
}

/// Whether every scope was read in full: `90 00` and decoded, or `6A 88` (no
/// entries). Anything else (a refusal, a decode error, a truncated list) means
/// "not in the registry" cannot be concluded from it.
fn registry_complete(registry: &[Value]) -> bool {
    registry.iter().all(|s| {
        s.get("decode_error").is_none()
            && s.get("truncated").is_none()
            && matches!(s["status"].as_str(), Some("9000" | "6A88"))
    })
}

/// `dap_verification` or `mandated_dap_verification`, whichever the registry
/// entry shows (Table 11-7), or `None`.
fn dap_privilege(entry: &Value) -> Option<&'static str> {
    let names = entry["privilege_names"].as_array()?;
    ["mandated_dap_verification", "dap_verification"]
        .into_iter()
        .find(|p| names.iter().any(|n| n == p))
}

/// The registry entries that can verify a DAP, `{aid, privilege}`. Informational
/// in `data.pre_read`: a card that mandates a DAP (GP 11.6.2.3: a DAP block
/// shall be present when a Security Domain with Mandated DAP Verification
/// exists) refuses a load without one, and this shows which AID to name with
/// `--dap-sd`.
fn dap_security_domains(registry: &[Value]) -> Value {
    Value::Array(
        registry
            .iter()
            .flat_map(|s| s["entries"].as_array().into_iter().flatten())
            .filter_map(|e| dap_privilege(e).map(|p| json!({ "aid": e["aid"], "privilege": p })))
            .collect(),
    )
}

/// A selected and authenticated ISD, with the registry read over the channel.
struct Prepared {
    channel: scp03::Channel,
    isd: Vec<u8>,
    registry: Vec<Value>,
    steps: Vec<Value>,
    data: Value,
    /// The key information template read before authenticating, if it decoded.
    card_keys: Option<Value>,
    /// The key version the channel was authenticated with (from INITIALIZE UPDATE).
    current_kvn: u8,
}

/// SELECT the ISD, the ONE authentication attempt of [`authenticate`], then
/// GET STATUS over the channel. `Err(report)` is a run that stopped before any
/// write could be considered: no ISD, or a refused/failed authentication.
fn prepare_write<S: CardSession + ?Sized>(
    session: &mut S,
    trace: bool,
    auth: &Auth<'_>,
) -> Result<Result<Prepared, Report>, session::Error> {
    let mut steps = Vec::new();
    let mut attempts = Vec::new();
    let mut selected = None;
    for aid in ISD_AIDS {
        let ex = read_once(session, &mut steps, "select", select_by_aid(aid))?;
        attempts.push(json!({ "aid": hex_of(aid), "status": sw_hex(&ex) }));
        if ex.is_success() {
            selected = Some(aid);
            break;
        }
    }
    let mut data = json!({
        "card_touched": true,
        "isd": selected.map(hex_of),
        "isd_attempts": attempts,
        "logical_channel": auth.logical_channel,
    });
    let stopped = |mut data: Value, steps: Vec<Value>, found: bool| {
        if trace {
            data["trace"] = Value::Array(steps);
        }
        Ok(Err(Report {
            isd_found: found,
            data,
        }))
    };
    let Some(isd) = selected else {
        return stopped(data, steps, false);
    };
    // Plain read first: after EXTERNAL AUTHENTICATE every command must be MAC'd.
    let ex = read_once(session, &mut steps, "key_information", |le| {
        Command::case2(Header::new(0x80, 0xCA, 0x00, 0xE0), le)
    })?;
    let card_keys = if ex.is_success() {
        decode_key_information(ex.data()).ok()
    } else {
        None
    };
    let (mut channel, current_kvn) = match authenticate(session, &mut steps, auth)? {
        Ok(est) => {
            data["secure_channel"] = channel_report(auth, &est, card_keys.as_ref());
            (est.channel, est.iur.key_version)
        }
        Err(stop) => {
            data["secure_channel"] = json!({
                "protocol": "SCP03",
                "established": false,
                "stopped": stop.kind,
                "key_version": stop.key_version,
            });
            data["error"] = json!({ "kind": stop.kind, "message": stop.message });
            return stopped(data, steps, true);
        }
    };
    let registry = read_registry(session, &mut steps, Some(&mut channel))?;
    Ok(Ok(Prepared {
        channel,
        isd: isd.to_vec(),
        registry,
        steps,
        data,
        card_keys,
        current_kvn,
    }))
}

/// The shared flow of `gp delete` and `gp install` with keys: authenticate once,
/// read the registry, let `check` refuse (nothing sent), stop at a dry run
/// unless `yes`, otherwise send each planned command MAC'd and in order, stop at
/// the first refusal (no retry, no skipping ahead), then re-read the registry
/// and let `verify` confirm the result.
///
/// `check` returns the `data.pre_read` object or the refusal `(kind, message)`;
/// `verify` says whether the registry now shows the intended result.
#[allow(clippy::too_many_arguments)]
fn write<S, P, C, V>(
    session: &mut S,
    trace: bool,
    auth: &Auth<'_>,
    yes: bool,
    operation: &'static str,
    target: Value,
    plan: P,
    check: C,
    verify: V,
) -> Result<Report, session::Error>
where
    S: CardSession + ?Sized,
    P: FnOnce(&[u8]) -> Result<Vec<Planned>, BuildError>,
    C: FnOnce(&[Value]) -> Result<Value, (&'static str, String)>,
    V: FnOnce(&[Value]) -> bool,
{
    let Prepared {
        mut channel,
        isd,
        registry,
        mut steps,
        mut data,
        ..
    } = match prepare_write(session, trace, auth)? {
        Ok(p) => p,
        Err(report) => return Ok(report),
    };
    data["operation"] = json!(operation);
    data["target"] = target;
    data["dry_run"] = json!(!yes);
    data["sent"] = json!(false);
    let finish = |mut data: Value, steps: Vec<Value>| {
        if trace {
            data["trace"] = Value::Array(steps);
        }
        Ok(Report {
            isd_found: true,
            data,
        })
    };
    let plan = match plan(&isd) {
        Ok(plan) => plan,
        Err(e) => {
            data["error"] = json!({ "kind": "unbuildable", "message": e.to_string() });
            return finish(data, steps);
        }
    };
    data["plan"] = json!({ "apdus": plan_json(&plan) });
    match check(&registry) {
        Ok(pre_read) => data["pre_read"] = pre_read,
        Err((kind, message)) => {
            data["error"] = json!({ "kind": kind, "message": message });
            return finish(data, steps);
        }
    }
    if !yes {
        data["note"] = json!(
            "dry run: the registry was read over the secure channel, nothing was written; add --yes to send the plan"
        );
        return finish(data, steps);
    }
    let mut results = Vec::new();
    for p in &plan {
        let wrapped = match channel.wrap(&p.command) {
            Ok(w) => w,
            Err(e) => {
                data["error"] = json!({ "kind": "unbuildable", "message": e.to_string() });
                break;
            }
        };
        let ex = session::send(session, &wrapped, &read_policy())?;
        push_steps(&mut steps, p.step, &ex);
        data["sent"] = json!(true);
        results.push(json!({ "step": p.step, "status": sw_hex(&ex) }));
        if !ex.is_success() {
            let mut err = refused(&format!("{} ({})", operation.to_uppercase(), p.step), &ex);
            err["step"] = json!(p.step);
            err["completed_steps"] = json!(results.len() - 1);
            err["advice"] = json!(
                "nothing was retried; read the registry with gp status to see what the card now holds"
            );
            data["error"] = err;
            break;
        }
    }
    data["result"] = json!({ "steps": results });
    if data.get("error").is_none() {
        let after = read_registry(session, &mut steps, Some(&mut channel))?;
        let ok = registry_complete(&after) && verify(&after);
        data["result"]["verified"] = json!(ok);
        if !ok {
            data["error"] = json!({
                "kind": "verify-failed",
                "message": "the card answered 9000 to every command but the registry does not show the intended result",
            });
        }
    }
    finish(data, steps)
}

/// `gp delete --aid` over SCP03: authenticate once, GET STATUS, refuse when the
/// AID is not in the registry (`aid-not-present`), is the ISD (`refusing-isd`)
/// or the registry cannot be read in full (`registry-unreadable`), all with
/// nothing sent; a dry run unless `yes`; otherwise DELETE MAC'd, every status
/// word reported with its own kind ([`status_word`]), and a re-read that must no
/// longer list the AID (`verify-failed`).
///
/// # Errors
///
/// Only transport and encoding failures; refusals are `data.error`.
pub fn delete<S: CardSession + ?Sized>(
    session: &mut S,
    trace: bool,
    req: &DeleteRequest,
    auth: &Auth<'_>,
    yes: bool,
) -> Result<Report, session::Error> {
    let aid_hex = hex::encode_upper(&req.aid);
    let target = json!({ "aid": aid_hex, "related": req.related });
    write(
        session,
        trace,
        auth,
        yes,
        "delete",
        target,
        |_| delete_plan_steps(req),
        |registry| {
            if !registry_complete(registry) {
                return Err((
                    "registry-unreadable",
                    "the registry could not be read in full, so the AID cannot be confirmed present; nothing was sent".into(),
                ));
            }
            match registry_entry(registry, &aid_hex) {
                None => Err((
                    "aid-not-present",
                    format!("{aid_hex} is not in the card registry; nothing was sent"),
                )),
                Some(("isd", _)) => Err((
                    "refusing-isd",
                    format!("{aid_hex} is the issuer security domain; deleting it is refused and nothing was sent"),
                )),
                Some((scope, e)) => Ok(json!({
                    "present": true,
                    "scope": scope,
                    "lifecycle": e["lifecycle_name"],
                    "privileges": e["privilege_names"],
                })),
            }
        },
        |after| registry_entry(after, &aid_hex).is_none(),
    )
}

/// `gp install` over SCP03: authenticate once, GET STATUS, refuse when the load
/// file or application AID is already in the registry (`package-already-loaded`,
/// `app-already-installed`) or the registry cannot be read in full; a dry run
/// unless `yes`; otherwise INSTALL [for load], the LOAD blocks and INSTALL [for
/// install and make selectable], MAC'd and in order, stopping at the first
/// refusal, then a re-read that must list the load file and a SELECTABLE
/// application (`verify-failed`).
///
/// # Errors
///
/// Only transport and encoding failures; refusals are `data.error`.
pub fn install<S: CardSession + ?Sized>(
    session: &mut S,
    trace: bool,
    req: &InstallRequest,
    auth: &Auth<'_>,
    yes: bool,
) -> Result<Report, session::Error> {
    let load_hex = hex::encode_upper(&req.load_file_aid);
    let app_hex = hex::encode_upper(&req.app_aid);
    write(
        session,
        trace,
        auth,
        yes,
        "install",
        install_target(req),
        |sd| install_plan_steps(req, sd),
        |registry| {
            if !registry_complete(registry) {
                return Err((
                    "registry-unreadable",
                    "the registry could not be read in full, so a clash cannot be ruled out; nothing was sent".into(),
                ));
            }
            if registry_entry(registry, &load_hex).is_some() {
                return Err((
                    "package-already-loaded",
                    format!("{load_hex} is already in the registry; delete it first with gp delete; nothing was sent"),
                ));
            }
            if registry_entry(registry, &app_hex).is_some() {
                return Err((
                    "app-already-installed",
                    format!("{app_hex} is already in the registry; delete it first with gp delete; nothing was sent"),
                ));
            }
            // A DAP block from a Security Domain that cannot verify one would be
            // refused by the card only after INSTALL [for load] went through.
            if let Some(d) = &req.dap {
                let sd = match &d.security_domain {
                    Some(aid) => registry_entry(registry, &hex::encode_upper(aid)).map(|(_, e)| e),
                    None => registry
                        .iter()
                        .find(|s| s["scope"] == "isd")
                        .and_then(|s| s["entries"].get(0)),
                };
                match sd {
                    None => {
                        return Err((
                            "dap-sd-not-present",
                            "the security domain named for the DAP is not in the registry; nothing was sent".into(),
                        ))
                    }
                    Some(e) if dap_privilege(e).is_none() => {
                        return Err((
                            "dap-sd-without-dap-privilege",
                            "the security domain named for the DAP has neither the DAP Verification nor the Mandated DAP Verification privilege, so it cannot verify one; nothing was sent".into(),
                        ))
                    }
                    Some(_) => {}
                }
            }
            Ok(json!({
                "load_file_present": false,
                "app_present": false,
                "dap_security_domains": dap_security_domains(registry),
            }))
        },
        |after| {
            matches!(registry_entry(after, &load_hex), Some((s, _)) if s.starts_with("load_files"))
                && registry_entry(after, &app_hex).is_some_and(|(s, e)| {
                    s == "applications" && e["lifecycle_name"] == "SELECTABLE"
                })
        },
    )
}

// ---------------------------------------------------------------------------
// PUT KEY (issue #115)
// ---------------------------------------------------------------------------

/// The step label of PUT KEY in plans, traces and results. [`push_steps`] and
/// [`plan_json`] withhold the data of a step with this label.
const PUT_KEY_STEP: &str = "put_key";

/// Said in every PUT KEY output, dry run or not.
pub const PUT_KEY_WARNING: &str = "replacing the card's own SCP03 keys with values you do not hold, or have mistyped, permanently locks administrative access to this security domain: there is no recovery and no retry. Check the key check values shown against your records before adding --yes";

/// What `gp put-key` writes: a complete SCP03 AES-128 key set (ENC, MAC, DEK)
/// under the key identifiers `key_id`, `key_id + 1` and `key_id + 2`.
#[derive(Debug)]
pub struct PutKeyRequest {
    /// The Key Version Number of the new keys (data field, `01` to `7F`).
    pub new_version: u8,
    /// P1: `00` adds a new key set; non-zero replaces the key set with that
    /// version (`01` to `7F`). GP Card Spec v2.3.1 11.8.2.1.
    pub replace_version: u8,
    /// P2: the Key Identifier of the first key (`00` to `7D`; the others follow
    /// at +1 and +2, 11.8.2.2).
    pub key_id: u8,
    /// The new key set; all three keys must have been given ([`Keys::is_key_set`]).
    pub new_keys: Keys,
    /// Allow touching the key version the session authenticated with.
    pub replace_current: bool,
}

/// Checks the parameters against GP Card Spec v2.3.1 11.8.2.1 to 11.8.2.3.
fn put_key_params(req: &PutKeyRequest) -> Result<[[u8; 16]; 3], BuildError> {
    if !(1..=0x7F).contains(&req.new_version) {
        return Err(BuildError::PutKey(
            "the new key version number is coded from 01 to 7F (11.8.2.3)",
        ));
    }
    if req.replace_version > 0x7F {
        return Err(BuildError::PutKey(
            "the replaced key version number is 00 (add) or 01 to 7F (11.8.2.1)",
        ));
    }
    if req.key_id > 0x7D {
        return Err(BuildError::PutKey(
            "the first key identifier is 00 to 7D so that the second and third key identifiers stay within 7F (11.8.2.2)",
        ));
    }
    match (req.new_keys.is_key_set(), req.new_keys.dek) {
        (true, Some(dek)) => Ok([req.new_keys.enc, req.new_keys.mac, dek]),
        _ => Err(BuildError::PutKey(
            "a new key set is three keys, ENC MAC DEK",
        )),
    }
}

/// AES-ECB of one block. For a 16 byte key this is also AES-CBC with a zero ICV,
/// the encryption Amendment D v1.1.2 6.2.8 prescribes, because it is one block.
fn dek_encrypt(dek: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let mut block = (*key).into();
    aes::Aes128::new_from_slice(dek)
        .expect("16-byte key")
        .encrypt_block(&mut block);
    block.into()
}

/// Builds, and does not send, PUT KEY for a new SCP03 key set: `80 D8 <P1> <P2
/// | 80> Lc <KVN> (88 10 <key encrypted under the DEK> 03 <KCV>) x3 00`.
///
/// GP Card Spec v2.3.1 11.8 (Table 11-64 command, 11.8.2.1/11.8.2.2 P1/P2, Table
/// 11-67 data field: the new Key Version Number then one key data field per
/// key), Table 11-68 Basic Format (key type `88` AES from 11.1.8, BER length of
/// the Key Component Block, one byte KCV length, KCV), 11.8.2.3.2 Table 11-71
/// (a key whose length is a multiple of the block size needs no padding and no
/// length prefix, so the block is the 16 encrypted bytes), B.6 (KCV: first 3
/// bytes of AES of 16 bytes of `01`). The keys are encrypted with the current
/// static Key-DEK, AES-CBC with a zero ICV (Amendment D v1.1.2 6.2.8, "no
/// padding is required" for 16 byte AES keys). Byte-for-byte what pySim's
/// `ADF_SD.AddlShellCommands.build_put_key_data` produces for `aes` keys;
/// GlobalPlatformPro `GPSession.putKeys` writes the same key with the Table
/// 11-70 length prefix (`88 11 10 ...`), which 11.8.2.3.3 also lets a card
/// accept. P2 has b8 set (multiple keys), as both do.
///
/// # Errors
///
/// [`BuildError`] for a parameter outside what the specification allows.
pub fn put_key_command(req: &PutKeyRequest, current_dek: &[u8; 16]) -> Result<Command, BuildError> {
    let keys = put_key_params(req)?;
    let mut data = vec![req.new_version];
    for key in &keys {
        data.extend([0x88, 0x10]);
        data.extend(dek_encrypt(current_dek, key));
        data.push(0x03);
        data.extend(aes_kcv(key).expect("16-byte key"));
    }
    Ok(Command::case4(
        Header::new(0x80, 0xD8, req.replace_version, 0x80 | req.key_id),
        data,
        Le::Short(0),
    ))
}

/// The Key Version Number then the three KCVs, which is what the card returns
/// (11.8.3.1: "the Key Version Number followed by the key check value(s) not
/// preceded by a length").
fn put_key_expected_response(req: &PutKeyRequest, keys: &[[u8; 16]; 3]) -> Vec<u8> {
    let mut out = vec![req.new_version];
    for k in keys {
        out.extend(aes_kcv(k).expect("16-byte key"));
    }
    out
}

fn put_key_target(req: &PutKeyRequest, keys: &[[u8; 16]; 3]) -> Value {
    let kcv = |k: &[u8; 16]| json!({ "kcv": hex::encode_upper(aes_kcv(k).expect("16-byte key")) });
    json!({
        "new_key_version": format!("{:02X}", req.new_version),
        "replace_key_version": format!("{:02X}", req.replace_version),
        "key_id": format!("{:02X}", req.key_id),
        "key_type": "AES-128 (88), SCP03 key set ENC, MAC, DEK",
        "new_keys": { "enc": kcv(&keys[0]), "mac": kcv(&keys[1]), "dek": kcv(&keys[2]) },
        "replace_current_keyset": req.replace_current,
    })
}

/// `gp put-key` without authentication keys: validates the request and shows
/// the target and the warning. The APDU cannot be built offline (the new keys
/// are encrypted under the current DEK), so the plan lists none. Sends nothing
/// and does not touch a card.
///
/// # Errors
///
/// [`BuildError`] for a parameter outside what the specification allows.
pub fn put_key_dry_run(req: &PutKeyRequest) -> Result<Value, BuildError> {
    let keys = put_key_params(req)?;
    let mut data = offline_dry_run(
        "put-key",
        put_key_target(req, &keys),
        &[],
        "no keys were given, so the card was not contacted, whether this replaces the keys in use was not checked and no APDU was built (it needs the current DEK); add --keys-file or --keys-env to check against the card, and --yes to send",
    );
    data["plan"]["note"] = json!("the PUT KEY APDU holds the new keys encrypted under the current DEK; it is built, and shown with its data withheld, only once the keys are given");
    data["warning"] = json!(PUT_KEY_WARNING);
    Ok(data)
}

/// What the card's key information says about the request, or the refusal
/// `(kind, message)`. Nothing has been sent when this refuses.
fn put_key_checks(
    req: &PutKeyRequest,
    current_kvn: u8,
    card_keys: Option<&Value>,
) -> Result<Value, (&'static str, String)> {
    let touches = req.new_version == current_kvn
        || (req.replace_version != 0 && req.replace_version == current_kvn);
    if touches && !req.replace_current {
        return Err((
            "refusing-current-keyset",
            format!(
                "this session authenticated with key version {current_kvn:02X}, and the request would replace or overwrite it. Replacing the keys in use with values you do not hold locks administrative access for good. Nothing was sent; if you mean it, add --replace-current-keyset"
            ),
        ));
    }
    let Some(list) = card_keys.and_then(Value::as_array) else {
        return Err((
            "key-information-unreadable",
            "the card's key information (GET DATA E0) could not be read, so the key versions it holds are unknown; nothing was sent".into(),
        ));
    };
    let has = |v: u8| {
        list.iter()
            .any(|k| k["key_version"].as_u64() == Some(u64::from(v)))
    };
    if req.replace_version != 0 && !has(req.replace_version) {
        return Err((
            "replace-target-absent",
            format!(
                "--replace-key-version {:02X} names a key version the card does not hold; nothing was sent",
                req.replace_version
            ),
        ));
    }
    if has(req.new_version) && req.new_version != req.replace_version {
        return Err((
            "key-version-exists",
            format!(
                "key version {:02X} is already on the card; replace it explicitly with --replace-key-version {:02X} (or choose another new version); nothing was sent",
                req.new_version, req.new_version
            ),
        ));
    }
    Ok(json!({
        "authenticated_key_version": current_kvn,
        "key_versions_on_card": list.iter().filter_map(|k| k["key_version"].as_u64()).collect::<Vec<_>>(),
        "touches_authenticated_keyset": touches,
    }))
}

/// `gp put-key` over SCP03: authenticate once, read the registry as every write
/// does, refuse (nothing sent) a request that would overwrite the key set in use
/// without `replace_current` (`refusing-current-keyset`), name a key version the
/// card lacks (`replace-target-absent`) or collide with one it holds
/// (`key-version-exists`), or when the key information is unreadable; a dry run
/// unless `yes`; otherwise PUT KEY once, MAC'd, every status word reported under
/// its own kind. After `90 00` the KVN and KCVs the card returned must equal the
/// ones computed (`card-kcv-mismatch`), and GET DATA E0 over the channel must
/// list the three new keys (`verify-failed`).
///
/// # Errors
///
/// Only transport and encoding failures; refusals are `data.error`.
pub fn put_key<S: CardSession + ?Sized>(
    session: &mut S,
    trace: bool,
    req: &PutKeyRequest,
    auth: &Auth<'_>,
    yes: bool,
) -> Result<Report, session::Error> {
    let Prepared {
        mut channel,
        mut steps,
        mut data,
        card_keys,
        current_kvn,
        ..
    } = match prepare_write(session, trace, auth)? {
        Ok(p) => p,
        Err(report) => return Ok(report),
    };
    let finish = |mut data: Value, steps: Vec<Value>| {
        if trace {
            data["trace"] = Value::Array(steps);
        }
        Ok(Report {
            isd_found: true,
            data,
        })
    };
    data["operation"] = json!("put-key");
    data["dry_run"] = json!(!yes);
    data["sent"] = json!(false);
    data["warning"] = json!(PUT_KEY_WARNING);
    let keys = match put_key_params(req) {
        Ok(keys) => keys,
        Err(e) => {
            data["error"] = json!({ "kind": "unbuildable", "message": e.to_string() });
            return finish(data, steps);
        }
    };
    data["target"] = put_key_target(req, &keys);
    let command = match auth
        .keys
        .dek
        .ok_or(BuildError::DekMissing)
        .and_then(|dek| put_key_command(req, &dek))
    {
        Ok(c) => c,
        Err(e) => {
            data["error"] = json!({ "kind": "unbuildable", "message": e.to_string() });
            return finish(data, steps);
        }
    };
    let plan = [Planned {
        step: PUT_KEY_STEP,
        command,
    }];
    data["plan"] = json!({ "apdus": plan_json(&plan) });
    match put_key_checks(req, current_kvn, card_keys.as_ref()) {
        Ok(pre_read) => data["pre_read"] = pre_read,
        Err((kind, message)) => {
            data["error"] = json!({ "kind": kind, "message": message });
            return finish(data, steps);
        }
    }
    if !yes {
        data["note"] = json!(
            "dry run: the key information was checked over the secure channel, nothing was written; add --yes to send the plan"
        );
        return finish(data, steps);
    }
    let wrapped = match channel.wrap(&plan[0].command) {
        Ok(w) => w,
        Err(e) => {
            data["error"] = json!({ "kind": "unbuildable", "message": e.to_string() });
            return finish(data, steps);
        }
    };
    let ex = session::send(session, &wrapped, &read_policy())?;
    push_steps(&mut steps, PUT_KEY_STEP, &ex);
    data["sent"] = json!(true);
    data["result"] = json!({ "steps": [{ "step": PUT_KEY_STEP, "status": sw_hex(&ex) }] });
    if !ex.is_success() {
        let mut err = refused("PUT KEY", &ex);
        err["step"] = json!(PUT_KEY_STEP);
        err["advice"] = json!(
            "nothing was retried; the card's key sets are unchanged unless it said otherwise, check with gp status"
        );
        data["error"] = err;
        return finish(data, steps);
    }
    let expected = put_key_expected_response(req, &keys);
    let returned = ex.data();
    data["result"]["card_kcv_check"] = json!(if returned.is_empty() {
        "the card returned no key check values"
    } else if returned == expected.as_slice() {
        "match"
    } else {
        "MISMATCH"
    });
    if !returned.is_empty() && returned != expected.as_slice() {
        data["error"] = json!({
            "kind": "card-kcv-mismatch",
            "message": "the card answered 9000 but the key version and key check values it returned are not the ones computed for the new keys: it may hold different keys than intended. Do not rely on the new key set; check with gp status",
        });
        return finish(data, steps);
    }
    // Read back the key information over the channel (MAC'd, once).
    let read = Command::case2(Header::new(0x80, 0xCA, 0x00, 0xE0), Le::Short(0));
    let ex = send_secure(
        session,
        &mut steps,
        &mut channel,
        "key_information_after",
        &read,
    )?;
    let listed = ex
        .is_success()
        .then(|| decode_key_information(ex.data()).ok())
        .flatten();
    let verified = listed
        .as_ref()
        .and_then(Value::as_array)
        .is_some_and(|list| {
            (0..3u8).all(|i| {
                list.iter().any(|k| {
                    k["key_id"].as_u64() == Some(u64::from(req.key_id + i))
                        && k["key_version"].as_u64() == Some(u64::from(req.new_version))
                        && k["key_type"] == "88"
                        && k["key_length"] == 16
                })
            })
        });
    data["result"]["verified"] = json!(verified);
    if !verified {
        data["error"] = json!({
            "kind": "verify-failed",
            "message": format!(
                "the card answered 9000 to PUT KEY but its key information (read back with status {}) does not list the three new AES-128 keys at the requested version and identifiers",
                sw_hex(&ex).as_deref().unwrap_or("none")
            ),
        });
    }
    finish(data, steps)
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

    // ---- authenticated reads --------------------------------------------
    //
    // Test vectors: pySim tests/unittests/test_globalplatform.py class
    // SCP03_Test_AES128_11 (osmocom/pysim, keyset 000102.. / 101112..), repeated
    // in scp03.rs for the primitives. The flow below runs at security level 01,
    // whose wire bytes are not in pySim; they were computed with an independent
    // Python model (AES-CMAC from `cryptography`, written from Amendment D 4.1.5
    // and 6.2.4) that first reproduced every pySim vector byte for byte,
    // including the wrapped `80 F2 80 02 02 4F 00 00` GET STATUS.

    const ENC_HEX: &str = "000102030405060708090A0B0C0D0E0F";
    const MAC_HEX: &str = "101112131415161718191A1B1C1D1E1F";
    const HOST_CHALLENGE: [u8; 8] = [0xB1, 0x3E, 0x5F, 0x93, 0x8F, 0xC1, 0x08, 0xC4];
    const INIT_UPDATE: &str = "8050300008B13E5F938FC108C400";
    const INIT_UPDATE_RESP: &str =
        "000000000000000000003003703EB51047495B249F66C484C1D2EF1948000002";
    const EXT_AUTH_01: &str = "84820100107D5F5826A993EBC8CEDC6DBB0146E4A0";
    const GS_ISD: &str = "84F280020A4F004B3EF773D6AD4FFA00";
    const GS_APPS: &str = "84F240020A4F0006CD27885DC7CBDD00";
    const GS_APPS_NEXT: &str = "84F240030A4F0080F9BC578DEC364D00";
    const GS_LF: &str = "84F220020A4F00900999D121148E2400";
    const GS_LFM: &str = "84F210020A4F00C93E4C6C7772071000";
    const KEY_INFO_AES: &str = "E006C00401308810";

    fn keys() -> Keys {
        Keys::parse(&format!("{ENC_HEX} {MAC_HEX}")).unwrap()
    }

    fn auth(keys: &Keys) -> Auth<'_> {
        Auth {
            keys,
            key_version: 0x30,
            host_challenge: HOST_CHALLENGE,
            logical_channel: 0,
        }
    }

    fn sent_ins(card: &Card, ins: &str) -> usize {
        card.sent.iter().filter(|c| &c[2..4] == ins).count()
    }

    /// A card that accepts the vector's keys and answers the registry.
    fn secure_card(ext_auth_answer: &str) -> Card {
        let isd = tlv(
            "E3",
            &(tlv("4F", "A000000151000000") + &tlv("9F70", "0F") + &tlv("C5", "9E0000")),
        );
        let app1 = tlv(
            "E3",
            &(tlv("4F", "A0000000620001") + &tlv("9F70", "07") + &tlv("C5", "180000")),
        );
        let app2 = tlv(
            "E3",
            &(tlv("4F", "A0000000620002") + &tlv("9F70", "83") + &tlv("C5", "800000")),
        );
        let lfm = tlv(
            "E3",
            &(tlv("4F", "A0000000620003") + &tlv("9F70", "01") + &tlv("84", "A000000062000301")),
        );
        let crd = recognition_hex(&["0215", "0370"]) + "9000";
        let rows = [
            (SEL1, "9000".to_string()),
            ("80CA006600", crd),
            ("80CA00E000", format!("{KEY_INFO_AES}9000")),
            (INIT_UPDATE, format!("{INIT_UPDATE_RESP}9000")),
            (EXT_AUTH_01, ext_auth_answer.to_string()),
            (GS_ISD, isd + "9000"),
            (GS_APPS, app1 + "6310"),
            (GS_APPS_NEXT, app2 + "9000"),
            (GS_LF, "6A88".into()),
            (GS_LFM, lfm + "9000"),
        ];
        let rows: Vec<(&str, &str)> = rows.iter().map(|(a, b)| (*a, b.as_str())).collect();
        Card::new(&rows)
    }

    /// Everything a run could print, for the "no keys anywhere" checks.
    fn everything(report: &Report, keys: &Keys) -> String {
        format!(
            "{}\n{}\n{keys:?}\n{:?}",
            serde_json::to_string(&report.data).unwrap(),
            render_text(&report.data),
            report.data
        )
        .to_lowercase()
    }

    fn assert_no_key_material(out: &str) {
        let session = scp03::derive_session_keys(
            &<[u8; 16]>::try_from(hex::decode(ENC_HEX).unwrap()).unwrap(),
            &<[u8; 16]>::try_from(hex::decode(MAC_HEX).unwrap()).unwrap(),
            &HOST_CHALLENGE,
            &[0x3E, 0xB5, 0x10, 0x47, 0x49, 0x5B, 0x24, 0x9F],
        );
        for secret in [
            hex::decode(ENC_HEX).unwrap(),
            hex::decode(MAC_HEX).unwrap(),
            session.enc.to_vec(),
            session.mac.to_vec(),
            session.rmac.to_vec(),
        ] {
            assert!(
                !out.contains(&hex::encode(&secret)),
                "key material in output"
            );
        }
    }

    #[test]
    fn authenticated_status_lists_the_registry_over_the_channel() {
        let keys = keys();
        let mut card = secure_card("9000");
        let r = status_authenticated(&mut card, true, &auth(&keys)).unwrap();
        assert!(r.isd_found);
        assert!(r.data.get("error").is_none());
        // Exactly one attempt: one INITIALIZE UPDATE, one EXTERNAL AUTHENTICATE.
        assert_eq!(sent_ins(&card, "50"), 1);
        assert_eq!(sent_ins(&card, "82"), 1);
        // Order: plain reads, the handshake, then only MAC'd GET STATUS.
        let wire: Vec<&str> = card.sent.iter().map(String::as_str).collect();
        assert_eq!(
            wire,
            [
                SEL1,
                "80CA006600",
                "80CA00E000",
                INIT_UPDATE,
                EXT_AUTH_01,
                GS_ISD,
                GS_APPS,
                GS_APPS_NEXT,
                GS_LF,
                GS_LFM
            ]
        );
        let ch = &r.data["secure_channel"];
        assert_eq!(ch["established"], true);
        assert_eq!(ch["key_version"], 0x30);
        assert_eq!(ch["card_cryptogram_verified"], true);
        assert_eq!(ch["enc_key"]["kcv"], "C35280");
        assert_eq!(ch["mac_key"]["kcv"], "013808");
        assert_eq!(ch["enc_key"]["stated_kcv"], "not-stated");
        assert_eq!(ch["card_key_info"]["matches_supplied"], true);
        let reg = &r.data["registry"];
        assert_eq!(reg[0]["entries"][0]["lifecycle_name"], "SECURED");
        assert_eq!(reg[1]["entries"].as_array().unwrap().len(), 2);
        assert_eq!(reg[2]["status"], "6A88");
        assert_eq!(reg[3]["entries"][0]["modules"][0], "A000000062000301");
        let ids: Vec<&str> = r.data["registry_findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            [
                "gp/weak-secure-channel",
                "gp/app-excess-privilege",
                "gp/app-locked"
            ]
        );
        assert_no_key_material(&everything(&r, &keys));
        assert!(render_text(&r.data).contains("Secure channel: SCP03"));
    }

    #[test]
    fn wrong_keys_stop_before_external_authenticate() {
        // Same card, but the host holds a different MAC key.
        let wrong = Keys::parse(&format!("{ENC_HEX} {}", "FF".repeat(16))).unwrap();
        let mut card = secure_card("9000");
        let r = status_authenticated(&mut card, true, &auth(&wrong)).unwrap();
        assert_eq!(r.data["error"]["kind"], "keys-do-not-match");
        assert!(r.data["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("keys do not match this card"));
        assert_eq!(r.data["secure_channel"]["established"], false);
        assert_eq!(sent_ins(&card, "50"), 1);
        assert_eq!(
            sent_ins(&card, "82"),
            0,
            "EXTERNAL AUTHENTICATE must not be sent"
        );
        assert_eq!(sent_ins(&card, "F2"), 0);
        assert!(r.data.get("registry").is_none());
        let out = everything(&r, &wrong);
        assert!(!out.contains(&"ff".repeat(16)));
    }

    #[test]
    fn a_refused_external_authenticate_is_never_retried() {
        let keys = keys();
        let mut card = secure_card("6300");
        let r = status_authenticated(&mut card, false, &auth(&keys)).unwrap();
        assert_eq!(r.data["error"]["kind"], "external-authenticate-refused");
        assert!(r.data["error"]["message"]
            .as_str()
            .unwrap()
            .contains("6300"));
        assert_eq!(sent_ins(&card, "50"), 1);
        assert_eq!(sent_ins(&card, "82"), 1);
        assert_eq!(sent_ins(&card, "F2"), 0);
    }

    #[test]
    fn an_initialize_update_refusal_or_scp02_card_sends_no_external_authenticate() {
        let keys = keys();
        for (answer, kind) in [
            ("6A88".to_string(), "initialize-update-refused"),
            // SCP02 INITIALIZE UPDATE response: 28 bytes, 02 at offset 11.
            (
                format!("{}0201{}9000", "00".repeat(11), "00".repeat(14)),
                "not-scp03",
            ),
        ] {
            let mut card = Card::new(&[(SEL1, "9000"), (INIT_UPDATE, &answer)]);
            let r = status_authenticated(&mut card, false, &auth(&keys)).unwrap();
            assert_eq!(r.data["error"]["kind"], kind);
            assert_eq!(sent_ins(&card, "82"), 0);
            assert_eq!(sent_ins(&card, "50"), 1);
        }
    }

    #[test]
    fn key_info_of_another_type_is_reported_not_trusted() {
        let keys = keys();
        let mut card = secure_card("9000");
        // The card says key version 30 is a 3DES key (type 80, 16 bytes).
        card.table.insert(
            "80CA00E000".into(),
            hex::decode("E006C0040130801090 00".replace(' ', "")).unwrap(),
        );
        let r = status_authenticated(&mut card, false, &auth(&keys)).unwrap();
        assert_eq!(
            r.data["secure_channel"]["card_key_info"]["matches_supplied"],
            false
        );
        assert!(render_text(&r.data).contains("differs from the supplied"));
    }

    #[test]
    fn keys_parse_with_kcv_checks_and_never_quote_input() {
        // Key check values: pySim SCP03_KCV_Test (AES-128 keyset 000102.. and 101112..).
        let k = Keys::parse(&format!(
            "{ENC_HEX}/C35280\n# comment\n{MAC_HEX}/013808 {}",
            "20".repeat(16)
        ))
        .unwrap();
        assert_eq!(k.stated, [true, true]);
        assert_eq!(aes_kcv(&k.enc).unwrap(), [0xC3, 0x52, 0x80]);
        assert_eq!(aes_kcv(&k.mac).unwrap(), [0x01, 0x38, 0x08]);
        // one key is both
        let one = Keys::parse(ENC_HEX).unwrap();
        assert_eq!(one.enc, one.mac);
        // a wrong KCV is a mismatch error naming the position, before any card
        let err = Keys::parse(&format!("{ENC_HEX}/000000")).unwrap_err();
        assert_eq!(
            err,
            KeyError::Kcv {
                index: 1,
                computed: "C35280".into(),
                stated: "000000".into()
            }
        );
        // format errors say which key, never what was typed
        let secret = "ZZ0102030405060708090A0B0C0D0E0F";
        for bad in [secret, "0001", &format!("{ENC_HEX}/12"), ""] {
            let msg = Keys::parse(bad).unwrap_err().to_string();
            assert!(!msg.contains(secret) && !msg.contains(ENC_HEX), "{msg}");
        }
        assert_eq!(
            Keys::parse(&format!("{ENC_HEX} {ENC_HEX} {ENC_HEX} {ENC_HEX}")).unwrap_err(),
            KeyError::Count(4)
        );
        assert_eq!(format!("{k:?}"), "Keys { .. }");
    }

    #[test]
    fn keys_load_from_a_file_or_an_environment_variable() {
        let dir = std::env::temp_dir().join(format!("sim-doctor-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("keys.txt");
        std::fs::write(&file, format!("{ENC_HEX} {MAC_HEX}\n")).unwrap();
        assert!(Keys::load(KeySource::File(&file)).is_ok());
        std::fs::write(&file, "x".repeat(5000)).unwrap();
        assert_eq!(
            Keys::load(KeySource::File(&file)).unwrap_err(),
            KeyError::TooLong
        );
        std::fs::remove_dir_all(&dir).unwrap();
        let missing = Keys::load(KeySource::File(&dir.join("nope"))).unwrap_err();
        assert!(matches!(missing, KeyError::Unreadable(_)));
        let var = "SIM_DOCTOR_TEST_GP_KEYS_UNSET";
        assert!(matches!(
            Keys::load(KeySource::Env(var)).unwrap_err(),
            KeyError::Unreadable(m) if m.contains(var)
        ));
    }

    #[test]
    fn select_by_aid_reports_status_and_fci() {
        let fci = tlv(
            "6F",
            &(tlv("84", "A0000000620001") + &tlv("A5", "9F6501FF")),
        );
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x00, 0x01];
        let mut card = Card::new(&[("00A4040007A000000062000100", &(fci.clone() + "9000"))]);
        let r = select(&mut card, &aid, true).unwrap();
        assert!(r.isd_found);
        assert_eq!(r.data["selected"]["df_name"], "A0000000620001");
        assert_eq!(r.data["selected"]["fci"], fci);
        assert!(render_text(&r.data).contains("DF name: A0000000620001"));
        let mut card = Card::new(&[("00A4040007A000000062000100", "6A82")]);
        let r = select(&mut card, &aid, false).unwrap();
        assert!(!r.isd_found);
        assert_eq!(r.data["selected"]["status"], "6A82");
    }

    #[test]
    fn registry_findings_flag_lifecycle_and_privileges() {
        let data = json!({
            "card_recognition": {"weak_scp": [2]},
            "registry": [
                {"scope": "isd", "entries": [{"aid": "A1", "lifecycle_name": "INITIALIZED"}]},
                {"scope": "applications", "entries": [
                    {"aid": "A2", "lifecycle_name": "SELECTABLE", "privilege_names": ["global_delete"]},
                    {"aid": "A3", "lifecycle_name": "SELECTABLE", "privilege_names": ["security_domain", "global_delete"]},
                    {"aid": "A4", "lifecycle_name": "LOCKED"},
                ]},
            ]
        });
        let f = registry_findings(&data);
        let ids: Vec<&str> = f.iter().map(|f| f["id"].as_str().unwrap()).collect();
        assert_eq!(
            ids,
            [
                "gp/weak-secure-channel",
                "gp/isd-lifecycle",
                "gp/app-excess-privilege",
                "gp/app-locked"
            ]
        );
        assert_eq!(f[2]["aid"], "A2");
        assert!(registry_findings(&json!({})).is_empty());
    }

    // ---- writes: DELETE, INSTALL/LOAD, logical channels --------------------
    //
    // Plain command layouts: GP Card Spec v2.3.1 11.2 (DELETE), 11.5 (INSTALL),
    // 11.6 (LOAD), cross-checked against pySim and GlobalPlatformPro (cited on
    // the builders). The MAC'd bytes below come from the same independent Python
    // model as the read vectors above (it reproduces pySim's SCP03_Test_AES128_11
    // and the GET STATUS vectors byte for byte), chained after the very same
    // INITIALIZE UPDATE / EXTERNAL AUTHENTICATE and the five-command registry
    // pre-read. Nothing here was produced by the code under test.

    const KI: &str = "80CA00E000";
    const DELETE_APP1: &str = "84E40000114F07A0000000620001AE095C6F89B477F800";
    const DEL_POST_ISD: &str = "84F280020A4F009AA63C6B15B45D7000";
    const DEL_POST_APPS: &str = "84F240020A4F0027A651FE9BD8CF8E00";
    const DEL_POST_LF: &str = "84F220020A4F00EFCA34D2635D070C00";
    const DEL_POST_LFM: &str = "84F210020A4F00FA9E6D0D68AEE61700";
    const INSTALL_FOR_LOAD: &str =
        "84E602001C07A000000077010008A0000001510000000000000E7BF208CAAB827400";
    const LOAD_0: &str = "84E80000F8C481FA030A11181F262D343B424950575E656C737A81888F969DA4ABB2B9C0C7CED5DCE3EAF1F8FF060D141B222930373E454C535A61686F767D848B9299A0A7AEB5BCC3CAD1D8DFE6EDF4FB020910171E252C333A41484F565D646B727980878E959CA3AAB1B8BFC6CDD4DBE2E9F0F7FE050C131A21282F363D444B525960676E757C838A91989FA6ADB4BBC2C9D0D7DEE5ECF3FA01080F161D242B323940474E555C636A71787F868D949BA2A9B0B7BEC5CCD3DAE1E8EFF6FD040B121920272E353C434A51585F666D747B828990979EA5ACB3BAC1C8CFD6DDE4EBF2F900070E151C232A31383F464D545B62697077AFA9721E44F29E3B00";
    const LOAD_1: &str = "84E88001157E858C939AA1A8AFB6BDC4CBD28657FB78BA12619C00";
    const INSTALL_FOR_INSTALL: &str = "84E60C002A07A000000077010008A00000007701000108A0000000770100020300000002C900005FE64A1219C2C3E500";
    const INS_POST_ISD: &str = "84F280020A4F0034AFE5CFD7F89B6000";
    const INS_POST_APPS: &str = "84F240020A4F00A4429FBD5B5FFFC500";
    const INS_POST_LF: &str = "84F220020A4F00D6C90B1F60A7CB4D00";
    const INS_POST_LFM: &str = "84F210020A4F004FC58CE93CC6226A00";
    const CH1_EXT_AUTH: &str = "85820100107D5F5826A993EBC88C90BAFF6826B43F";
    const CH1_GS_ISD: &str = "85F280020A4F00977C0A2EB91236D800";
    const CH1_GS_APPS: &str = "85F240020A4F00C4F51A0396EE9F1E00";
    const CH1_GS_APPS_NEXT: &str = "85F240030A4F00EA3F666F13FAEDAA00";
    const CH1_GS_LF: &str = "85F220020A4F00D5DE997CD9F3F38F00";
    const CH1_GS_LFM: &str = "85F210020A4F0051004E46989F5E2B00";
    const PLAIN_DELETE: &str = "80E40000094F07A000000062000100";
    const PLAIN_IFL: &str = "80E602001407A000000077010008A00000015100000000000000";
    const PLAIN_IFI: &str =
        "80E60C002207A000000077010008A00000007701000108A0000000770100020300000002C9000000";

    const PKG: &str = "A0000000770100";
    const MODULE: &str = "A000000077010001";
    const APP: &str = "A000000077010002";
    const APP1: &str = "A0000000620001";
    const APP2: &str = "A0000000620002";

    fn load_file_250() -> Vec<u8> {
        (0..250u32).map(|i| ((i * 7 + 3) & 0xFF) as u8).collect()
    }

    fn install_request() -> InstallRequest {
        InstallRequest {
            load_file: load_file_250(),
            load_file_aid: hex::decode(PKG).unwrap(),
            module_aid: hex::decode(MODULE).unwrap(),
            app_aid: hex::decode(APP).unwrap(),
            privileges: vec![0, 0, 0],
            params: vec![0xC9, 0x00],
            dap: None,
        }
    }

    fn delete_request(aid: &str) -> DeleteRequest {
        DeleteRequest {
            aid: hex::decode(aid).unwrap(),
            related: false,
        }
    }

    fn entry(aid: &str, life: &str, privs: &str) -> String {
        tlv(
            "E3",
            &(tlv("4F", aid) + &tlv("9F70", life) + &tlv("C5", privs)),
        )
    }

    fn isd_entry() -> String {
        entry("A000000151000000", "0F", "9E0000")
    }

    fn set(card: &mut Card, command: &str, response: &str) {
        card.table
            .insert(command.into(), hex::decode(response).unwrap());
    }

    /// The post-write registry of the delete vectors: app 2 only.
    fn card_after_delete() -> Card {
        let mut card = secure_card("9000");
        set(&mut card, DEL_POST_ISD, &(isd_entry() + "9000"));
        set(
            &mut card,
            DEL_POST_APPS,
            &(entry(APP2, "83", "800000") + "9000"),
        );
        set(&mut card, DEL_POST_LF, "6A88");
        let lfm = tlv(
            "E3",
            &(tlv("4F", "A0000000620003") + &tlv("9F70", "01") + &tlv("84", "A000000062000301")),
        );
        set(&mut card, DEL_POST_LFM, &(lfm + "9000"));
        card
    }

    fn wire(card: &Card) -> Vec<&str> {
        card.sent.iter().map(String::as_str).collect()
    }

    fn pre_read_wire() -> Vec<&'static str> {
        vec![
            SEL1,
            KI,
            INIT_UPDATE,
            EXT_AUTH_01,
            GS_ISD,
            GS_APPS,
            GS_APPS_NEXT,
            GS_LF,
            GS_LFM,
        ]
    }

    #[test]
    fn delete_and_install_for_install_bytes() {
        // DELETE 80 E4 00 00 Lc 4F len AID 00 (11.2.2; pySim do_delete_card_content).
        let d = delete_command(&hex::decode(APP1).unwrap(), false).unwrap();
        assert_eq!(hex::encode_upper(d.encode().unwrap()), PLAIN_DELETE);
        // related objects: P2 80 (Table 11-22).
        let d = delete_command(&hex::decode(PKG).unwrap(), true).unwrap();
        assert_eq!(d.encode().unwrap()[..4], [0x80, 0xE4, 0x00, 0x80]);
        assert!(matches!(
            delete_command(&[1, 2, 3], false),
            Err(BuildError::Aid { .. })
        ));
        // INSTALL [for install and make selectable] P1 0C, [for install] P1 04.
        let req = install_request();
        let build = |sel, privs: &[u8], params: &[u8]| {
            install_for_install(
                &req.load_file_aid,
                &req.module_aid,
                &req.app_aid,
                privs,
                params,
                sel,
            )
        };
        assert_eq!(
            hex::encode_upper(build(true, &[0; 3], &[0xC9, 0]).unwrap().encode().unwrap()),
            PLAIN_IFI
        );
        assert_eq!(
            build(false, &[0], &[0xC9, 0]).unwrap().encode().unwrap()[2],
            0x04
        );
        assert_eq!(
            build(true, &[0; 2], &[0xC9, 0]),
            Err(BuildError::Privileges(2))
        );
        // C9 is mandatory (Table 11-49); non-TLV is refused too.
        assert_eq!(
            build(true, &[0; 3], &[0xEF, 0]),
            Err(BuildError::InstallParameters)
        );
        assert_eq!(
            build(true, &[0; 3], &[0xC9]),
            Err(BuildError::InstallParameters)
        );
        // the three-step plan, in order
        let plan = install_plan_steps(&req, &hex::decode("A000000151000000").unwrap()).unwrap();
        let steps: Vec<&str> = plan.iter().map(|p| p.step).collect();
        assert_eq!(
            steps,
            ["install_for_load", "load", "load", "install_for_install"]
        );
        let plain: Vec<String> = plan
            .iter()
            .map(|p| hex::encode_upper(p.command.encode().unwrap()))
            .collect();
        assert_eq!(plain[0], PLAIN_IFL);
        assert!(plain[1].starts_with("80E80000F0C481FA"));
        assert!(plain[2].starts_with("80E880010D"));
        assert_eq!(plain[3], PLAIN_IFI);
        // Card Lock / Card Terminate are not granted.
        for bad in [0x10u8, 0x08] {
            let mut r = install_request();
            r.privileges = vec![bad, 0, 0];
            assert!(matches!(
                install_plan_steps(&r, &[0xA0, 0, 0, 1, 0x51]),
                Err(BuildError::PrivilegeRefused(_))
            ));
        }
    }

    #[test]
    fn delete_dry_run_sends_no_delete() {
        let keys = keys();
        let mut card = secure_card("9000");
        let r = delete(&mut card, true, &delete_request(APP1), &auth(&keys), false).unwrap();
        assert!(r.data.get("error").is_none(), "{:?}", r.data);
        assert_eq!(r.data["dry_run"], true);
        assert_eq!(r.data["sent"], false);
        assert_eq!(r.data["target"]["aid"], APP1);
        assert_eq!(r.data["pre_read"]["present"], true);
        assert_eq!(r.data["plan"]["apdus"][0]["apdu"], PLAIN_DELETE);
        assert_eq!(sent_ins(&card, "E4"), 0);
        assert_eq!(
            wire(&card),
            [pre_read_wire(), vec![GS_LFM]].concat()[..9].to_vec()
        );
        let text = render_text(&r.data);
        assert!(text.contains("DRY RUN") && text.contains(APP1), "{text}");
        assert_no_key_material(&everything(&r, &keys));
    }

    #[test]
    fn delete_yes_sends_the_exact_bytes_then_verifies() {
        let keys = keys();
        let mut card = card_after_delete();
        set(&mut card, DELETE_APP1, "9000");
        let r = delete(&mut card, true, &delete_request(APP1), &auth(&keys), true).unwrap();
        assert!(r.data.get("error").is_none(), "{:?}", r.data);
        assert_eq!(
            wire(&card),
            [
                pre_read_wire(),
                vec![
                    DELETE_APP1,
                    DEL_POST_ISD,
                    DEL_POST_APPS,
                    DEL_POST_LF,
                    DEL_POST_LFM
                ]
            ]
            .concat()
        );
        assert_eq!(sent_ins(&card, "50"), 1);
        assert_eq!(sent_ins(&card, "82"), 1);
        assert_eq!(sent_ins(&card, "E4"), 1);
        assert_eq!(r.data["sent"], true);
        assert_eq!(r.data["result"]["steps"][0]["status"], "9000");
        assert_eq!(r.data["result"]["verified"], true);
        assert!(render_text(&r.data).contains("sent delete: status 9000"));
        assert_no_key_material(&everything(&r, &keys));
    }

    #[test]
    fn delete_refuses_what_is_not_there_or_not_safe_and_sends_nothing() {
        let keys = keys();
        // not on the card
        let mut card = secure_card("9000");
        let r = delete(
            &mut card,
            false,
            &delete_request("A0000000620009"),
            &auth(&keys),
            true,
        )
        .unwrap();
        assert_eq!(r.data["error"]["kind"], "aid-not-present");
        assert_eq!(sent_ins(&card, "E4"), 0);
        assert_eq!(r.data["sent"], false);
        // the ISD itself
        let mut card = secure_card("9000");
        let r = delete(
            &mut card,
            false,
            &delete_request("A000000151000000"),
            &auth(&keys),
            true,
        )
        .unwrap();
        assert_eq!(r.data["error"]["kind"], "refusing-isd");
        assert_eq!(sent_ins(&card, "E4"), 0);
        // a registry that could not be read cannot prove presence
        let mut card = secure_card("9000");
        set(&mut card, GS_ISD, "6982");
        let r = delete(&mut card, false, &delete_request(APP1), &auth(&keys), true).unwrap();
        assert_eq!(r.data["error"]["kind"], "registry-unreadable");
        assert_eq!(sent_ins(&card, "E4"), 0);
        // wrong keys: authentication stops, no DELETE, one INITIALIZE UPDATE only
        let wrong = Keys::parse(&format!("{ENC_HEX} {}", "FF".repeat(16))).unwrap();
        let mut card = secure_card("9000");
        let r = delete(&mut card, false, &delete_request(APP1), &auth(&wrong), true).unwrap();
        assert_eq!(r.data["error"]["kind"], "keys-do-not-match");
        assert_eq!(
            (
                sent_ins(&card, "50"),
                sent_ins(&card, "82"),
                sent_ins(&card, "E4")
            ),
            (1, 0, 0)
        );
    }

    #[test]
    fn every_delete_status_word_has_its_own_kind_and_is_not_retried() {
        let keys = keys();
        let cases = [
            ("6A88", "referenced-data-not-found"),
            ("6A82", "application-not-found"),
            ("6A80", "incorrect-command-data"),
            ("6581", "memory-failure"),
            ("6985", "conditions-of-use-not-satisfied"),
            ("6982", "security-status-not-satisfied"),
            ("6700", "wrong-length"),
            ("6A86", "incorrect-p1-p2"),
            ("6D00", "invalid-instruction"),
            ("6E00", "invalid-class"),
            ("6400", "no-specific-diagnosis"),
            ("6881", "channel-not-active"),
            ("6B00", "unlisted-status"),
        ];
        let mut kinds = std::collections::HashSet::new();
        for (sw, kind) in cases {
            let mut card = secure_card("9000");
            set(&mut card, DELETE_APP1, sw);
            let r = delete(&mut card, false, &delete_request(APP1), &auth(&keys), true).unwrap();
            assert_eq!(r.data["error"]["kind"], kind, "{sw}");
            assert_eq!(r.data["error"]["status"], sw);
            assert!(r.data["error"]["message"].as_str().unwrap().contains(sw));
            assert_eq!(sent_ins(&card, "E4"), 1, "{sw} must not be retried");
            // nothing after the refused DELETE: no verification read
            assert_eq!(card.sent.last().unwrap(), DELETE_APP1);
            kinds.insert(kind);
        }
        assert_eq!(kinds.len(), cases.len());
    }

    #[test]
    fn delete_that_the_registry_does_not_confirm_is_verify_failed() {
        let keys = keys();
        // the card says 9000 but the post-read still lists the app
        let mut card = secure_card("9000");
        set(&mut card, DELETE_APP1, "9000");
        let r = delete(&mut card, false, &delete_request(APP1), &auth(&keys), true).unwrap();
        assert_eq!(r.data["error"]["kind"], "verify-failed");
        assert_eq!(r.data["result"]["verified"], false);
    }

    fn card_for_install(after: bool) -> Card {
        let mut card = secure_card("9000");
        for (c, r) in [
            (INSTALL_FOR_LOAD, "9000"),
            (LOAD_0, "9000"),
            (LOAD_1, "9000"),
            (INSTALL_FOR_INSTALL, "9000"),
        ] {
            set(&mut card, c, r);
        }
        if after {
            set(&mut card, INS_POST_ISD, &(isd_entry() + "9000"));
            let apps = entry(APP1, "07", "180000") + &entry(APP, "07", "000000");
            set(&mut card, INS_POST_APPS, &(apps + "9000"));
            set(
                &mut card,
                INS_POST_LF,
                &(tlv("E3", &(tlv("4F", PKG) + &tlv("9F70", "01"))) + "9000"),
            );
            let lfm = tlv(
                "E3",
                &(tlv("4F", PKG) + &tlv("9F70", "01") + &tlv("84", MODULE)),
            );
            set(&mut card, INS_POST_LFM, &(lfm + "9000"));
        }
        card
    }

    #[test]
    fn install_dry_run_sends_nothing() {
        let keys = keys();
        let mut card = card_for_install(false);
        let r = install(&mut card, false, &install_request(), &auth(&keys), false).unwrap();
        assert!(r.data.get("error").is_none(), "{:?}", r.data);
        assert_eq!(r.data["dry_run"], true);
        assert_eq!(r.data["sent"], false);
        for ins in ["E6", "E8"] {
            assert_eq!(sent_ins(&card, ins), 0);
        }
        let apdus = r.data["plan"]["apdus"].as_array().unwrap();
        assert_eq!(apdus.len(), 4);
        assert_eq!(apdus[0]["apdu"], PLAIN_IFL);
        assert_eq!(apdus[3]["apdu"], PLAIN_IFI);
        assert_eq!(r.data["target"]["load_file_aid"], PKG);
        assert_no_key_material(&everything(&r, &keys));
    }

    #[test]
    fn install_yes_sends_load_then_install_in_order_and_verifies() {
        let keys = keys();
        let mut card = card_for_install(true);
        let r = install(&mut card, true, &install_request(), &auth(&keys), true).unwrap();
        assert!(r.data.get("error").is_none(), "{:?}", r.data);
        assert_eq!(
            wire(&card),
            [
                pre_read_wire(),
                vec![
                    INSTALL_FOR_LOAD,
                    LOAD_0,
                    LOAD_1,
                    INSTALL_FOR_INSTALL,
                    INS_POST_ISD,
                    INS_POST_APPS,
                    INS_POST_LF,
                    INS_POST_LFM
                ]
            ]
            .concat()
        );
        let steps: Vec<&str> = r.data["result"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["step"].as_str().unwrap())
            .collect();
        assert_eq!(
            steps,
            ["install_for_load", "load", "load", "install_for_install"]
        );
        assert_eq!(r.data["result"]["verified"], true);
        assert_no_key_material(&everything(&r, &keys));
    }

    #[test]
    fn install_stops_at_the_first_refusal() {
        let keys = keys();
        let mut card = card_for_install(true);
        set(&mut card, LOAD_0, "6A84");
        let r = install(&mut card, false, &install_request(), &auth(&keys), true).unwrap();
        assert_eq!(r.data["error"]["kind"], "not-enough-memory-space");
        assert_eq!(r.data["error"]["step"], "load");
        assert_eq!(r.data["error"]["completed_steps"], 1);
        assert_eq!(
            sent_ins(&card, "E8"),
            1,
            "LOAD block 1 must not follow a refused block 0"
        );
        assert_eq!(
            sent_ins(&card, "E6"),
            1,
            "INSTALL [for install] must not follow"
        );
        assert_eq!(r.data["sent"], true);
    }

    #[test]
    fn install_refuses_clashes_before_sending_anything() {
        let keys = keys();
        let mut req = install_request();
        req.app_aid = hex::decode(APP1).unwrap(); // already installed on the fixture
        let mut card = secure_card("9000");
        let r = install(&mut card, false, &req, &auth(&keys), true).unwrap();
        assert_eq!(r.data["error"]["kind"], "app-already-installed");
        let mut req = install_request();
        req.load_file_aid = hex::decode("A0000000620003").unwrap(); // a load file on the fixture
        let mut card = secure_card("9000");
        let r = install(&mut card, false, &req, &auth(&keys), true).unwrap();
        assert_eq!(r.data["error"]["kind"], "package-already-loaded");
        assert_eq!(sent_ins(&card, "E6") + sent_ins(&card, "E8"), 0);
    }

    #[test]
    fn offline_dry_runs_touch_no_card_and_show_the_apdus() {
        let d = delete_dry_run(&delete_request(APP1)).unwrap();
        assert_eq!(d["card_touched"], false);
        assert_eq!(d["dry_run"], true);
        assert_eq!(d["plan"]["apdus"][0]["apdu"], PLAIN_DELETE);
        let i = install_dry_run(&install_request()).unwrap();
        assert_eq!(i["card_touched"], false);
        assert_eq!(i["plan"]["apdus"][0]["apdu"], PLAIN_IFL);
        assert_eq!(i["target"]["security_domain"], "A000000151000000");
        let text = render_text(&i);
        assert!(text.contains("DRY RUN") && text.contains(PKG), "{text}");
        assert!(delete_dry_run(&delete_request("A000000062")).is_ok());
        assert!(delete_dry_run(&DeleteRequest {
            aid: vec![1],
            related: false
        })
        .is_err());
    }

    #[test]
    fn logical_channel_open_and_close_replay() {
        // MANAGE CHANNEL open 00 70 00 00 01 -> channel number then 90 00;
        // close 00 70 80 <ch> (ISO/IEC 7816-4 11.1.2; GP Card Spec 11.7).
        let mut card = Card::new(&[("0070000001", "019000")]);
        let r = channel_open(&mut card, true).unwrap();
        assert!(r.isd_found);
        assert_eq!(r.data["channel"]["number"], 1);
        assert_eq!(r.data["channel"]["status"], "9000");
        assert_eq!(r.data["trace"][0]["command"], "0070000001");
        assert!(render_text(&r.data).contains("Logical channel open: 1"));
        // refusals, each with its own kind
        for (sw, kind) in [
            ("6A81", "function-not-supported"),
            ("6881", "channel-not-active"),
            ("6882", "secure-messaging-not-supported"),
        ] {
            let mut card = Card::new(&[("0070000001", sw)]);
            let r = channel_open(&mut card, false).unwrap();
            assert!(!r.isd_found);
            assert_eq!(r.data["error"]["kind"], kind);
        }
        let mut card = Card::new(&[("0070000001", "9000")]);
        assert_eq!(
            channel_open(&mut card, false).unwrap().data["error"]["kind"],
            "channel-number-unreadable"
        );
        // close
        let mut card = Card::new(&[("00708001", "9000"), ("00708003", "6200")]);
        assert!(channel_close(&mut card, 1, false).unwrap().isd_found);
        let r = channel_close(&mut card, 3, false).unwrap();
        assert_eq!(r.data["error"]["kind"], "channel-already-closed");
        // the basic channel cannot be closed: nothing is sent
        let r = channel_close(&mut card, 0, false).unwrap();
        assert_eq!(r.data["error"]["kind"], "bad-channel");
        assert_eq!(card.sent, ["00708001", "00708003"]);
    }

    #[test]
    fn commands_run_on_a_chosen_channel_and_the_mac_covers_it() {
        // The whole flow on channel 1: plain commands get CLA 01/81, the secure
        // channel's commands CLA 85 with the MAC computed over that class byte
        // (vectors from the independent model; a MAC over CLA 84 would not match).
        let keys = keys();
        let mut a = auth(&keys);
        a.logical_channel = 1;
        let mut card = secure_card("9000");
        // re-key the fixture's wire commands for channel 1
        let mut table = std::collections::HashMap::new();
        for (c, r) in std::mem::take(&mut card.table) {
            let c = match c.as_str() {
                x if x == SEL1 => "01A4040008A00000015100000000".to_string(),
                x if x == KI => "81CA00E000".to_string(),
                x if x == INIT_UPDATE => "8150300008B13E5F938FC108C400".to_string(),
                x if x == EXT_AUTH_01 => CH1_EXT_AUTH.to_string(),
                x if x == GS_ISD => CH1_GS_ISD.to_string(),
                x if x == GS_APPS => CH1_GS_APPS.to_string(),
                x if x == GS_APPS_NEXT => CH1_GS_APPS_NEXT.to_string(),
                x if x == GS_LF => CH1_GS_LF.to_string(),
                x if x == GS_LFM => CH1_GS_LFM.to_string(),
                _ => c,
            };
            table.insert(c, r);
        }
        card.table = table;
        let mut on = OnChannel::new(&mut card, 1);
        let mut r = delete(&mut on, true, &delete_request(APP1), &a, false).unwrap();
        assert!(r.data.get("error").is_none(), "{:?}", r.data);
        assert_eq!(r.data["pre_read"]["present"], true);
        retarget_channel(&mut r.data, 1);
        // the trace, corrected, is exactly what the card was sent
        let traced: Vec<&str> = r.data["trace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["command"].as_str().unwrap())
            .collect();
        assert_eq!(traced, wire(&card));
        assert_eq!(traced[0], "01A4040008A00000015100000000");
        assert_eq!(traced[3], CH1_EXT_AUTH);
        // a class with no channel coding passes through
        let mut card = Card::new(&[("A0C0000000", "9000")]);
        OnChannel::new(&mut card, 2)
            .transmit(&[0xA0, 0xC0, 0, 0, 0])
            .unwrap();
        assert_eq!(card.sent, ["A0C0000000"]);
    }

    #[test]
    fn write_output_never_holds_key_material() {
        let keys = keys();
        let mut card = card_after_delete();
        set(&mut card, DELETE_APP1, "9000");
        let r = delete(&mut card, true, &delete_request(APP1), &auth(&keys), true).unwrap();
        let out = everything(&r, &keys);
        assert_no_key_material(&out);
        assert!(!out.contains(&hex::encode(keys.enc)) && !out.contains(&hex::encode(keys.mac)));
        // the ENC key is never exercised by a C-MAC-only write
        assert_eq!(r.data["secure_channel"]["enc_key_exercised"], false);
    }

    // ---- PUT KEY and DAP (issue #115) ------------------------------------
    //
    // Every wire vector below was produced by pySim itself, not by this crate:
    // `pySim.global_platform.scp.SCP03` (the very SCP03_Test_AES128_11 handshake
    // used above, with the DEK 202122..2F of its KEYSET_AES128) wrapped the
    // commands, and `ADF_SD.AddlShellCommands.build_put_key_data` built the PUT KEY
    // data field with `aes` keys. The GET STATUS pre-read bytes it produces are
    // the GS_* constants above, which also pins the chain. The DAP signature was
    // computed twice, with python `cryptography` AES-CMAC and with
    // `openssl mac -cipher AES-128-CBC CMAC`.

    const DEK_HEX: &str = "202122232425262728292A2B2C2D2E2F";
    const NEW_ENC: &str = "404142434445464748494A4B4C4D4E4F";
    const NEW_MAC: &str = "505152535455565758595A5B5C5D5E5F";
    const NEW_DEK: &str = "606162636465666768696A6B6C6D6E6F";
    const NEW_KCVS: [&str; 3] = ["504A77", "F2A8DF", "D7D0E4"];
    // The encrypted key blocks of the PUT KEY data (AES-CBC, zero ICV, key DEK).
    const NEW_ENC_CT: &str = "859469C07743C7E45B318D151D3D87E9";
    const NEW_MAC_CT: &str = "B05159C3643927E54547E8A14721D1EB";
    const NEW_DEK_CT: &str = "2602F2F0A58CFBD1CD1A16CFD98BEE32";
    const PLAIN_PUT_ADD: &str = "80D8008143318810859469C07743C7E45B318D151D3D87E903504A778810B05159C3643927E54547E8A14721D1EB03F2A8DF88102602F2F0A58CFBD1CD1A16CFD98BEE3203D7D0E400";
    const PUT_ADD: &str = "84D800814B318810859469C07743C7E45B318D151D3D87E903504A778810B05159C3643927E54547E8A14721D1EB03F2A8DF88102602F2F0A58CFBD1CD1A16CFD98BEE3203D7D0E44893A527EF64D12600";
    const KI_AFTER_ADD: &str = "84CA00E008C750F0D28C7839F800";
    const PUT_REPLACE: &str = "84D830814B308810859469C07743C7E45B318D151D3D87E903504A778810B05159C3643927E54547E8A14721D1EB03F2A8DF88102602F2F0A58CFBD1CD1A16CFD98BEE3203D7D0E41BC7095719BB1A1D00";
    const KI_AFTER_REPLACE: &str = "84CA00E008234A7E0FD26799B800";

    fn current_keys() -> Keys {
        Keys::parse(&format!("{ENC_HEX} {MAC_HEX} {DEK_HEX}")).unwrap()
    }

    fn put_request(new_version: u8, replace_version: u8, replace_current: bool) -> PutKeyRequest {
        PutKeyRequest {
            new_version,
            replace_version,
            key_id: 1,
            new_keys: Keys::parse(&format!("{NEW_ENC} {NEW_MAC} {NEW_DEK}")).unwrap(),
            replace_current,
        }
    }

    /// GET DATA E0 listing key sets `versions`, three AES-128 keys each.
    fn key_info(versions: &[u8]) -> String {
        let mut inner = String::new();
        for v in versions {
            for id in 1..=3 {
                inner += &format!("C004{id:02X}{v:02X}8810");
            }
        }
        tlv("E0", &inner) + "9000"
    }

    fn card_for_put_key(after: &[u8]) -> Card {
        let mut card = secure_card("9000");
        set(&mut card, PUT_ADD, &format!("31{}9000", NEW_KCVS.concat()));
        set(
            &mut card,
            PUT_REPLACE,
            &format!("30{}9000", NEW_KCVS.concat()),
        );
        set(&mut card, KI_AFTER_ADD, &key_info(after));
        set(&mut card, KI_AFTER_REPLACE, &key_info(after));
        card
    }

    fn assert_no_put_key_secrets(out: &str) {
        for secret in [
            ENC_HEX, MAC_HEX, DEK_HEX, NEW_ENC, NEW_MAC, NEW_DEK, NEW_ENC_CT, NEW_MAC_CT,
            NEW_DEK_CT,
        ] {
            assert!(
                !out.contains(&secret.to_lowercase()),
                "key material {} in the output",
                &secret[..4]
            );
        }
        // the ciphertext is withheld in the middle of the data too
        assert!(!out.contains(&PLAIN_PUT_ADD[10..60].to_lowercase()));
    }

    fn put_everything(r: &Report) -> String {
        format!(
            "{}\n{}\n{:?}",
            serde_json::to_string(&r.data).unwrap(),
            render_text(&r.data),
            r.data
        )
        .to_lowercase()
    }

    #[test]
    fn put_key_command_is_byte_exact_with_pysim() {
        let dek = <[u8; 16]>::try_from(hex::decode(DEK_HEX).unwrap()).unwrap();
        let c = put_key_command(&put_request(0x31, 0, false), &dek).unwrap();
        assert_eq!(hex::encode_upper(c.encode().unwrap()), PLAIN_PUT_ADD);
        let c = put_key_command(&put_request(0x30, 0x30, true), &dek).unwrap();
        assert_eq!(c.encode().unwrap()[..5], [0x80, 0xD8, 0x30, 0x81, 0x43]);
        // KCVs: first 3 bytes of AES of 16 x 01 (B.6)
        for (k, kcv) in [NEW_ENC, NEW_MAC, NEW_DEK].iter().zip(NEW_KCVS) {
            let k = hex::decode(k).unwrap();
            assert_eq!(hex::encode_upper(aes_kcv(&k).unwrap()), kcv);
        }
        // parameter ranges (11.8.2.1 to 11.8.2.3)
        for bad in [
            put_request(0, 0, false),
            put_request(0x80, 0, false),
            put_request(0x31, 0x80, false),
        ] {
            assert!(matches!(
                put_key_command(&bad, &dek),
                Err(BuildError::PutKey(_))
            ));
        }
        let mut r = put_request(0x31, 0, false);
        r.key_id = 0x7E;
        assert!(put_key_command(&r, &dek).is_err());
        // a new key set is three keys
        let mut r = put_request(0x31, 0, false);
        r.new_keys = Keys::parse(&format!("{NEW_ENC} {NEW_MAC}")).unwrap();
        assert!(put_key_command(&r, &dek).is_err());
        r.new_keys = Keys::parse(NEW_ENC).unwrap();
        assert!(put_key_command(&r, &dek).is_err());
    }

    #[test]
    fn new_key_kcv_is_checked_and_a_wrong_one_is_refused() {
        let ok = Keys::parse(&format!(
            "{NEW_ENC}/{} {NEW_MAC}/{} {NEW_DEK}/{}",
            NEW_KCVS[0], NEW_KCVS[1], NEW_KCVS[2]
        ));
        assert!(ok.unwrap().is_key_set());
        let bad = Keys::parse(&format!("{NEW_ENC}/000000 {NEW_MAC} {NEW_DEK}"));
        match bad {
            Err(KeyError::Kcv {
                index: 1,
                computed,
                stated,
            }) => {
                assert_eq!((computed.as_str(), stated.as_str()), ("504A77", "000000"));
            }
            other => panic!("{other:?}"),
        }
        // the third key's KCV is checked as well
        assert!(matches!(
            Keys::parse(&format!("{NEW_ENC} {NEW_MAC} {NEW_DEK}/504A77")),
            Err(KeyError::Kcv { index: 3, .. })
        ));
    }

    #[test]
    fn put_key_offline_dry_run_warns_shows_kcvs_and_no_keys() {
        let r = put_key_dry_run(&put_request(0x31, 0, false)).unwrap();
        assert_eq!(r["card_touched"], false);
        assert_eq!(r["dry_run"], true);
        assert_eq!(r["sent"], false);
        assert_eq!(r["target"]["new_keys"]["enc"]["kcv"], NEW_KCVS[0]);
        assert_eq!(r["target"]["new_keys"]["dek"]["kcv"], NEW_KCVS[2]);
        assert_eq!(r["plan"]["apdus"].as_array().unwrap().len(), 0);
        let warning = r["warning"].as_str().unwrap();
        assert!(warning.contains("permanently locks administrative access"));
        let text = render_text(&r);
        assert!(
            text.contains("WARNING") && text.contains("DRY RUN"),
            "{text}"
        );
        assert_no_put_key_secrets(&format!("{r}\n{text}").to_lowercase());
    }

    #[test]
    fn put_key_dry_run_with_keys_sends_no_put_key_and_withholds_the_data() {
        let keys = current_keys();
        let mut card = card_for_put_key(&[0x30, 0x31]);
        let r = put_key(
            &mut card,
            true,
            &put_request(0x31, 0, false),
            &auth(&keys),
            false,
        )
        .unwrap();
        assert!(r.data.get("error").is_none(), "{:?}", r.data);
        assert_eq!(sent_ins(&card, "D8"), 0);
        assert_eq!(wire(&card), pre_read_wire());
        assert_eq!(r.data["dry_run"], true);
        assert_eq!(r.data["pre_read"]["authenticated_key_version"], 0x30);
        assert_eq!(r.data["pre_read"]["touches_authenticated_keyset"], false);
        let apdu = &r.data["plan"]["apdus"][0];
        assert_eq!(apdu["header"], "80D80081");
        assert!(apdu["apdu"].is_null());
        assert!(apdu["data"]
            .as_str()
            .unwrap()
            .starts_with("67 bytes withheld"));
        assert!(r.data["warning"]
            .as_str()
            .unwrap()
            .contains("locks administrative access"));
        let out = put_everything(&r);
        assert_no_put_key_secrets(&out);
        assert!(out.contains("dry run"));
    }

    #[test]
    fn put_key_yes_sends_the_exact_bytes_then_checks_the_card_and_hides_everything() {
        let keys = current_keys();
        // the card ends up with the old set 30 and the new set 31
        let mut card = card_for_put_key(&[0x30, 0x31]);
        let r = put_key(
            &mut card,
            true,
            &put_request(0x31, 0, false),
            &auth(&keys),
            true,
        )
        .unwrap();
        assert!(r.data.get("error").is_none(), "{:?}", r.data);
        assert_eq!(
            wire(&card),
            [pre_read_wire(), vec![PUT_ADD, KI_AFTER_ADD]].concat()
        );
        assert_eq!(r.data["sent"], true);
        assert_eq!(r.data["result"]["card_kcv_check"], "match");
        assert_eq!(r.data["result"]["verified"], true);
        assert_eq!(sent_ins(&card, "50"), 1);
        assert_eq!(sent_ins(&card, "82"), 1);
        // the trace keeps the PUT KEY header and drops its data
        let trace = r.data["trace"].as_array().unwrap();
        let step = trace.iter().find(|s| s["step"] == "put_key").unwrap();
        assert_eq!(step["command"], "84D800814B<76 data bytes withheld>");
        assert_eq!(step["response"], format!("31{}9000", NEW_KCVS.concat()));
        assert_no_put_key_secrets(&put_everything(&r));
        assert_no_key_material(&everything(&r, &keys));
    }

    #[test]
    fn put_key_refuses_the_current_keyset_unless_told_to() {
        let keys = current_keys();
        // replacing 30 with 30, and adding a set that reuses the number 30
        for (new, replace) in [(0x30, 0x30), (0x30, 0x00), (0x31, 0x30)] {
            let mut card = card_for_put_key(&[0x30]);
            let r = put_key(
                &mut card,
                true,
                &put_request(new, replace, false),
                &auth(&keys),
                true,
            )
            .unwrap();
            assert_eq!(
                r.data["error"]["kind"], "refusing-current-keyset",
                "{new:02X} {replace:02X}"
            );
            assert_eq!(r.data["sent"], false);
            assert_eq!(sent_ins(&card, "D8"), 0);
            assert!(r.data["error"]["message"]
                .as_str()
                .unwrap()
                .contains("--replace-current-keyset"));
            assert_no_put_key_secrets(&put_everything(&r));
        }
        // a request that does not touch it needs no flag, and the flag allows one that does
        let mut card = card_for_put_key(&[0x30, 0x31]);
        let r = put_key(
            &mut card,
            true,
            &put_request(0x30, 0x30, true),
            &auth(&keys),
            true,
        )
        .unwrap();
        assert!(r.data.get("error").is_none(), "{:?}", r.data);
        assert_eq!(
            wire(&card),
            [pre_read_wire(), vec![PUT_REPLACE, KI_AFTER_REPLACE]].concat()
        );
        assert_eq!(r.data["pre_read"]["touches_authenticated_keyset"], true);
        assert_eq!(r.data["result"]["verified"], true);
    }

    #[test]
    fn put_key_replace_of_the_current_set_verifies_when_the_card_lists_it() {
        let keys = current_keys();
        let mut card = card_for_put_key(&[0x30]);
        let r = put_key(
            &mut card,
            false,
            &put_request(0x30, 0x30, true),
            &auth(&keys),
            true,
        )
        .unwrap();
        assert!(r.data.get("error").is_none(), "{:?}", r.data);
        assert_eq!(r.data["result"]["verified"], true);
    }

    #[test]
    fn put_key_checks_the_card_key_versions_before_sending() {
        let keys = current_keys();
        let cases = [
            // add a version that is already there
            (
                put_request(0x31, 0, false),
                "key-version-exists",
                &[0x30, 0x31][..],
            ),
            // replace one that is not
            (
                put_request(0x31, 0x32, false),
                "replace-target-absent",
                &[0x30][..],
            ),
            // replace 31 with a number that is taken
            (
                put_request(0x32, 0x31, false),
                "key-version-exists",
                &[0x30, 0x31, 0x32][..],
            ),
        ];
        for (req, kind, versions) in cases {
            let mut card = card_for_put_key(versions);
            set(&mut card, KI, &key_info(versions));
            let r = put_key(&mut card, true, &req, &auth(&keys), true).unwrap();
            assert_eq!(r.data["error"]["kind"], kind);
            assert_eq!(sent_ins(&card, "D8"), 0);
            assert_eq!(r.data["sent"], false);
        }
        // unreadable key information
        let mut card = card_for_put_key(&[0x30]);
        set(&mut card, KI, "6A88");
        let r = put_key(
            &mut card,
            true,
            &put_request(0x31, 0, false),
            &auth(&keys),
            true,
        )
        .unwrap();
        assert_eq!(r.data["error"]["kind"], "key-information-unreadable");
        assert_eq!(sent_ins(&card, "D8"), 0);
    }

    #[test]
    fn put_key_without_a_dek_in_the_authentication_keys_is_unbuildable() {
        let keys = keys(); // ENC MAC only
        let mut card = card_for_put_key(&[0x30]);
        let r = put_key(
            &mut card,
            true,
            &put_request(0x31, 0, false),
            &auth(&keys),
            true,
        )
        .unwrap();
        assert_eq!(r.data["error"]["kind"], "unbuildable");
        assert_eq!(sent_ins(&card, "D8"), 0);
        // one key means ENC = MAC = DEK
        assert!(Keys::parse(ENC_HEX).unwrap().has_dek());
        assert!(!keys.has_dek());
    }

    #[test]
    fn put_key_status_words_each_have_a_kind_and_nothing_is_retried() {
        let keys = current_keys();
        for (sw, kind) in [
            ("6982", "security-status-not-satisfied"),
            ("6A80", "incorrect-command-data"),
            ("6A84", "not-enough-memory-space"),
            ("6A88", "referenced-data-not-found"),
            ("6581", "memory-failure"),
        ] {
            let mut card = card_for_put_key(&[0x30, 0x31]);
            set(&mut card, PUT_ADD, sw);
            let r = put_key(
                &mut card,
                true,
                &put_request(0x31, 0, false),
                &auth(&keys),
                true,
            )
            .unwrap();
            assert_eq!(r.data["error"]["kind"], kind, "{sw}");
            assert_eq!(sent_ins(&card, "D8"), 1, "{sw}: no retry");
            assert_eq!(r.data["sent"], true);
            assert_no_put_key_secrets(&put_everything(&r));
        }
    }

    #[test]
    fn put_key_flags_key_check_values_the_card_did_not_echo() {
        let keys = current_keys();
        let mut card = card_for_put_key(&[0x30, 0x31]);
        set(&mut card, PUT_ADD, &format!("31{}9000", "00".repeat(9)));
        let r = put_key(
            &mut card,
            true,
            &put_request(0x31, 0, false),
            &auth(&keys),
            true,
        )
        .unwrap();
        assert_eq!(r.data["error"]["kind"], "card-kcv-mismatch");
        assert_eq!(r.data["result"]["card_kcv_check"], "MISMATCH");
        // a card that returns no data is noted, not blamed, and the read-back decides
        let mut card = card_for_put_key(&[0x30, 0x31]);
        set(&mut card, PUT_ADD, "9000");
        let r = put_key(
            &mut card,
            true,
            &put_request(0x31, 0, false),
            &auth(&keys),
            true,
        )
        .unwrap();
        assert!(r.data.get("error").is_none(), "{:?}", r.data);
        assert_eq!(
            r.data["result"]["card_kcv_check"],
            "the card returned no key check values"
        );
        // and a read-back that does not list the keys is verify-failed
        let mut card = card_for_put_key(&[0x30]);
        let r = put_key(
            &mut card,
            true,
            &put_request(0x31, 0, false),
            &auth(&keys),
            true,
        )
        .unwrap();
        assert_eq!(r.data["error"]["kind"], "verify-failed");
    }

    // ---- DAP ----------------------------------------------------------

    const DAP_KEY_HEX: &str = "707172737475767778797A7B7C7D7E7F";
    const DAP_KCV: &str = "DCC3AC";
    const DAP_LFDBH: &str = "0F18A2E0DEE3487F7033FF88871236DF0AA4AE20FC2435320920284672E5DD56";
    const DAP_SIG: &str = "6C51D10DDB1990D9DD682AF93DD09F79";
    const DAP_BLOCK: &str = "E21C4F08A000000151000000C3106C51D10DDB1990D9DD682AF93DD09F79";
    const DAP_IFL: &str = "84E602003C07A000000077010008A000000151000000200F18A2E0DEE3487F7033FF88871236DF0AA4AE20FC2435320920284672E5DD5600000C31A1A9E546378D00";
    const DAP_LOAD_0_PREFIX: &str =
        "84E80000F8E21C4F08A000000151000000C3106C51D10DDB1990D9DD682AF93DD09F79C481FA030A1118";
    const DAP_LOAD_0: &str = "84E80000F8E21C4F08A000000151000000C3106C51D10DDB1990D9DD682AF93DD09F79C481FA030A11181F262D343B424950575E656C737A81888F969DA4ABB2B9C0C7CED5DCE3EAF1F8FF060D141B222930373E454C535A61686F767D848B9299A0A7AEB5BCC3CAD1D8DFE6EDF4FB020910171E252C333A41484F565D646B727980878E959CA3AAB1B8BFC6CDD4DBE2E9F0F7FE050C131A21282F363D444B525960676E757C838A91989FA6ADB4BBC2C9D0D7DEE5ECF3FA01080F161D242B323940474E555C636A71787F868D949BA2A9B0B7BEC5CCD3DAE1E8EFF6FD040B121920272E353C434A51585F666D747B828990979EA56304F0F850D25EF100";
    const DAP_LOAD_1: &str = "84E8800133ACB3BAC1C8CFD6DDE4EBF2F900070E151C232A31383F464D545B626970777E858C939AA1A8AFB6BDC4CBD2257B813B0E99947700";
    const DAP_IFI: &str = "84E60C002A07A000000077010008A00000007701000108A0000000770100020300000002C900006840A943E9471AC800";
    const DAP_POST_ISD: &str = "84F280020A4F00E2B90CE8EA2A620800";
    const DAP_POST_APPS: &str = "84F240020A4F004185D89803F426E000";
    const DAP_POST_LF: &str = "84F220020A4F0061765B3D8A56A30500";
    const DAP_POST_LFM: &str = "84F210020A4F001DC7ED2DB83A618B00";

    fn dap_key() -> DapKey {
        DapKey::parse(&format!("{DAP_KEY_HEX}/{DAP_KCV}")).unwrap()
    }

    fn dap_request(sd: Option<&str>) -> InstallRequest {
        InstallRequest {
            dap: Some(DapRequest {
                key: dap_key(),
                security_domain: sd.map(|s| hex::decode(s).unwrap()),
                hash: Lfdbh::Sha256,
            }),
            ..install_request()
        }
    }

    /// A card whose ISD has the DAP Verification privilege (C5 DE0000).
    fn card_for_dap_install() -> Card {
        let mut card = secure_card("9000");
        let isd = entry("A000000151000000", "0F", "DE0000");
        set(&mut card, GS_ISD, &(isd.clone() + "9000"));
        for (c, r) in [
            (DAP_IFL, "9000"),
            (DAP_LOAD_0, "9000"),
            (DAP_LOAD_1, "9000"),
            (DAP_IFI, "9000"),
        ] {
            set(&mut card, c, r);
        }
        set(&mut card, DAP_POST_ISD, &(isd + "9000"));
        let apps = entry(APP1, "07", "180000") + &entry(APP, "07", "000000");
        set(&mut card, DAP_POST_APPS, &(apps + "9000"));
        set(
            &mut card,
            DAP_POST_LF,
            &(tlv("E3", &(tlv("4F", PKG) + &tlv("9F70", "01"))) + "9000"),
        );
        let lfm = tlv(
            "E3",
            &(tlv("4F", PKG) + &tlv("9F70", "01") + &tlv("84", MODULE)),
        );
        set(&mut card, DAP_POST_LFM, &(lfm + "9000"));
        card
    }

    #[test]
    fn dap_signature_is_aes_cmac_of_the_load_file_data_block_hash() {
        let load = load_file_250();
        let hash = Lfdbh::Sha256.digest(&load);
        assert_eq!(hex::encode_upper(&hash), DAP_LFDBH);
        // C.3 -> B.2.2: CMAC, 16 bytes; reproduced with python cryptography and openssl
        assert_eq!(hex::encode_upper(dap_signature(&dap_key(), &hash)), DAP_SIG);
        assert_eq!(hex::encode_upper(dap_key().kcv()), DAP_KCV);
        // the block frames it with the Security Domain AID (Table 11-58)
        let block = dap_block(
            &hex::decode("A000000151000000").unwrap(),
            &hex::decode(DAP_SIG).unwrap(),
        )
        .unwrap();
        assert_eq!(hex::encode_upper(block), DAP_BLOCK);
        // 192 and 256 bit AES keys are accepted; other lengths and wrong KCVs are not
        assert!(DapKey::parse(&"11".repeat(24)).is_ok());
        assert!(DapKey::parse(&"11".repeat(32)).is_ok());
        assert_eq!(
            DapKey::parse(&"11".repeat(8)).unwrap_err(),
            KeyError::DapFormat
        );
        assert_eq!(DapKey::parse("zz").unwrap_err(), KeyError::DapFormat);
        assert!(matches!(
            DapKey::parse(&format!("{DAP_KEY_HEX}/000000")),
            Err(KeyError::Kcv { .. })
        ));
        assert_eq!(DapKey::parse("").unwrap_err(), KeyError::Count(0));
        assert_eq!(format!("{:?}", dap_key()), "DapKey { .. }");
    }

    #[test]
    fn dap_plan_matches_the_pysim_wrapped_vectors() {
        let plan = install_plan_steps(
            &dap_request(None),
            &hex::decode("A000000151000000").unwrap(),
        )
        .unwrap();
        let plain: Vec<String> = plan
            .iter()
            .map(|p| hex::encode_upper(p.command.encode().unwrap()))
            .collect();
        // INSTALL [for load] carries the hash (11.5.2.3.1, mandatory with a DAP)
        assert_eq!(
            plain[0],
            format!("80E602003407A000000077010008A00000015100000020{DAP_LFDBH}000000")
        );
        // the DAP block comes first in the first LOAD block, then C4
        assert!(
            plain[1].starts_with(&format!("80E80000F0{DAP_BLOCK}C481FA")),
            "{}",
            plain[1]
        );
        assert_eq!(plan.iter().filter(|p| p.step == "load").count(), 2);
        assert!(DAP_LOAD_0.starts_with(DAP_LOAD_0_PREFIX));
    }

    #[test]
    fn install_with_a_dap_sends_the_pysim_vectors_in_order_and_verifies() {
        let keys = keys();
        let mut card = card_for_dap_install();
        let r = install(&mut card, true, &dap_request(None), &auth(&keys), true).unwrap();
        assert!(r.data.get("error").is_none(), "{:?}", r.data);
        assert_eq!(
            wire(&card),
            [
                pre_read_wire(),
                vec![
                    DAP_IFL,
                    DAP_LOAD_0,
                    DAP_LOAD_1,
                    DAP_IFI,
                    DAP_POST_ISD,
                    DAP_POST_APPS,
                    DAP_POST_LF,
                    DAP_POST_LFM
                ]
            ]
            .concat()
        );
        assert_eq!(r.data["result"]["verified"], true);
        assert_eq!(r.data["target"]["dap"]["hash"], "sha256");
        assert_eq!(
            r.data["target"]["dap"]["load_file_data_block_hash"],
            DAP_LFDBH
        );
        assert_eq!(r.data["target"]["dap"]["key_kcv"], DAP_KCV);
        // the DAP key itself is nowhere in the output (its KCV and the signature are)
        let shown = everything(&r, &keys);
        assert!(
            !shown.contains(&DAP_KEY_HEX.to_lowercase()),
            "DAP key in output"
        );
        assert!(shown.contains(&DAP_SIG.to_lowercase()));
    }

    #[test]
    fn a_dap_from_a_security_domain_that_cannot_verify_one_is_refused_before_sending() {
        let keys = keys();
        // the ISD of the default fixture has no DAP privilege (9E0000)
        let mut card = secure_card("9000");
        let r = install(&mut card, true, &dap_request(None), &auth(&keys), true).unwrap();
        assert_eq!(r.data["error"]["kind"], "dap-sd-without-dap-privilege");
        assert_eq!(sent_ins(&card, "E6"), 0);
        assert_eq!(r.data["sent"], false);
        // a Security Domain that is not in the registry
        let mut card = card_for_dap_install();
        let r = install(
            &mut card,
            true,
            &dap_request(Some("A0000000629999")),
            &auth(&keys),
            true,
        )
        .unwrap();
        assert_eq!(r.data["error"]["kind"], "dap-sd-not-present");
        assert_eq!(sent_ins(&card, "E6"), 0);
        // a registry that lists DAP-capable domains says so without a DAP request
        let mut card = card_for_dap_install();
        let r = install(&mut card, false, &install_request(), &auth(&keys), false).unwrap();
        assert_eq!(
            r.data["pre_read"]["dap_security_domains"][0]["privilege"],
            "dap_verification"
        );
    }

    #[test]
    fn dap_dry_run_without_keys_is_offline_and_shows_no_dap_key() {
        let d = install_dry_run(&dap_request(None)).unwrap();
        assert_eq!(d["card_touched"], false);
        assert_eq!(
            d["plan"]["apdus"][0]["apdu"].as_str().unwrap().len() / 2,
            5 + 0x34 + 1
        );
        assert_eq!(d["target"]["dap"]["key_kcv"], DAP_KCV);
        let out = format!("{d}\n{}", render_text(&d)).to_lowercase();
        assert!(!out.contains(&DAP_KEY_HEX.to_lowercase()));
        assert!(out.contains(&DAP_LFDBH.to_lowercase()));
    }
}
