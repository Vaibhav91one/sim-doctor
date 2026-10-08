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
//! **Does not own, and never sends.** INITIALIZE UPDATE, EXTERNAL AUTHENTICATE,
//! STORE DATA, INSTALL, LOAD, DELETE, PUT KEY, SET STATUS, MANAGE CHANNEL (that
//! one is [`session::open_channel`], used by nothing here). The only
//! instructions [`info`] sends are SELECT and GET DATA (plus the GET RESPONSE
//! that [`session::send`] adds for a `61 xx`). A `91 xx` is deliberately NOT
//! followed (no FETCH), and a refusal is recorded once, never retried.
//! The INSTALL / LOAD builders return [`Command`]s and nothing calls
//! `session::send` with them: sending, DAP signing, PUT KEY and DELETE belong
//! to issue #115, and validating a KCV against a card needs keys for that card.

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
