//! Field decoders shared by the EF table (`names.rs`): the building blocks TS 31.102 / 51.011 files are
//! made of. Each takes the bytes of one record (or of a transparent file) and returns JSON; none panics
//! on short or hostile input.

use serde_json::{json, Value};

use crate::cardsh::hex_upper;
use crate::ef::{self, Ef};

/// The GSM 7-bit default alphabet (3GPP TS 23.038), one character per octet as SIM files store it.
/// Octets above 0x7F and the escape table are shown as `?`; the extension table is not used by SIM
/// alpha fields in practice.
const GSM7: &str = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\u{1b}ÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";

/// An alpha identifier or text field: GSM 7-bit, or UCS2 when the first octet is 80, 81 or 82
/// (TS 51.011 annex B). Trailing `FF` padding is dropped.
pub fn alpha(bytes: &[u8]) -> String {
    let end = bytes.iter().rposition(|b| *b != 0xFF).map_or(0, |p| p + 1);
    let b = &bytes[..end];
    match b.first() {
        Some(0x80) => ucs2(
            b[1..]
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])),
        ),
        Some(0x81) if b.len() >= 3 => {
            let (n, base) = (usize::from(b[1]).min(b.len() - 3), u16::from(b[2]) << 7);
            ucs2(b[3..3 + n].iter().map(|c| {
                if c & 0x80 != 0 {
                    base + u16::from(c & 0x7F)
                } else {
                    u16::from(*c)
                }
            }))
        }
        Some(0x82) if b.len() >= 4 => {
            let (n, base) = (
                usize::from(b[1]).min(b.len() - 4),
                u16::from_be_bytes([b[2], b[3]]),
            );
            ucs2(b[4..4 + n].iter().map(|c| {
                if c & 0x80 != 0 {
                    base + u16::from(c & 0x7F)
                } else {
                    u16::from(*c)
                }
            }))
        }
        _ => {
            let table: Vec<char> = GSM7.chars().collect();
            b.iter()
                .map(|c| {
                    table
                        .get(usize::from(*c))
                        .copied()
                        .filter(|_| *c < 0x80)
                        .unwrap_or('?')
                })
                .collect()
        }
    }
}

fn ucs2(units: impl Iterator<Item = u16>) -> String {
    char::decode_utf16(units)
        .map(|r| r.unwrap_or('?'))
        .collect()
}

/// Swapped-nibble BCD digits (`0-9`, `*`, `#`, `a b c` for A-C) up to the `F` filler.
pub fn bcd(bytes: &[u8]) -> String {
    let mut out = String::new();
    'octets: for b in bytes {
        for n in [b & 0x0F, b >> 4] {
            match n {
                0..=9 => out.push(char::from(b'0' + n)),
                0xA => out.push('*'),
                0xB => out.push('#'),
                0xC => out.push('p'),
                0xD => out.push('w'),
                0xE => out.push('e'),
                _ => break 'octets,
            }
        }
    }
    out
}

/// A dialling number: length octet (bytes of TON/NPI + digits), TON/NPI, digits (TS 51.011 10.5.1).
pub fn dialling(bytes: &[u8]) -> Value {
    match bytes {
        [len, ton, rest @ ..] if *len != 0xFF && *len > 0 => {
            let digits = &rest[..rest.len().min(usize::from(*len).saturating_sub(1))];
            let number = bcd(digits);
            let number = if ton & 0x70 == 0x10 {
                format!("+{number}")
            } else {
                number
            };
            json!({ "ton_npi": format!("{ton:02X}"), "number": number })
        }
        _ => Value::Null,
    }
}

/// Big-endian unsigned integer of up to 8 octets.
pub fn uint(bytes: &[u8]) -> Value {
    if bytes.len() > 8 {
        return json!(hex_upper(bytes));
    }
    json!(bytes.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b)))
}

/// The 1-based numbers of the set bits, service-table style (bit 1 of octet 1 is service 1).
pub fn bitmap(bytes: &[u8]) -> Vec<u32> {
    bytes
        .iter()
        .enumerate()
        .flat_map(|(i, b)| {
            (0..8)
                .filter(move |k| b >> k & 1 == 1)
                .map(move |k| (i * 8 + k + 1) as u32)
        })
        .collect()
}

/// A 3-octet PLMN (TS 24.008 10.5.1.13), `None` when unused (`FFFFFF`).
pub fn plmn(b: &[u8]) -> Option<String> {
    let [a, b2, c] = <[u8; 3]>::try_from(b.get(..3)?).ok()?;
    if [a, b2, c] == [0xFF; 3] {
        return None;
    }
    let (mcc, mnc3) = (format!("{}{}{}", a & 0x0F, a >> 4, b2 & 0x0F), b2 >> 4);
    let mnc = format!(
        "{}{}{}",
        c & 0x0F,
        c >> 4,
        if mnc3 == 0xF {
            String::new()
        } else {
            mnc3.to_string()
        }
    );
    Some(format!("{mcc}{mnc}"))
}

/// A BER-TLV object tree. Constructed objects (tag bit 6) recurse up to `depth`.
pub fn tlv(bytes: &[u8], depth: u8) -> Value {
    let mut stream = crate::tlv::Stream::new(bytes);
    let mut out = Vec::new();
    loop {
        match stream.next_atom() {
            Ok(Some(atom)) => {
                let tag = atom.tag().to_string();
                let value = atom.value();
                if atom.is_constructed() && depth > 0 {
                    out.push(json!({ "tag": tag, "children": tlv(value, depth - 1) }));
                } else {
                    out.push(json!({ "tag": tag, "value": hex_upper(value) }));
                }
            }
            Ok(None) => break,
            Err(e) => {
                out.push(json!({ "error": e.to_string() }));
                break;
            }
        }
    }
    Value::Array(out)
}

fn lower(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn per_record(records: &[Vec<u8>], f: impl Fn(&[u8]) -> Value) -> Value {
    json!({ "records": records.iter().enumerate().map(|(i, r)| {
        let mut v = f(r);
        if let Some(o) = v.as_object_mut() {
            o.insert("record".into(), json!(i + 1));
            o.insert("empty".into(), json!(!r.is_empty() && r.iter().all(|b| *b == 0xFF)));
        }
        v
    }).collect::<Vec<_>>() })
}

/// The `ef` decoder a kind and file name stand for, when `crate::ef` already has one.
fn ef_for(kind: &str, name: &str) -> Option<Ef> {
    let n = name.to_ascii_uppercase();
    Some(match (kind, n.as_str()) {
        ("iccid", _) => Ef::Iccid,
        ("imsi", "EF.IMSI") => Ef::Imsi,
        ("ad", _) => Ef::Ad,
        ("spn", "EF.SPN") => Ef::Spn,
        ("acc", _) => Ef::Acc,
        ("loci", "EF.LOCI" | "EF.LOCIGPRS") => Ef::Loci,
        ("loci", "EF.PSLOCI") => Ef::Psloci,
        ("loci", "EF.EPSLOCI") => Ef::Epsloci,
        ("plmn-list", "EF.FPLMN") => Ef::Fplmn,
        ("plmn-act", "EF.OPLMNWACT") => Ef::OplmnWact,
        ("plmn-act", "EF.HPLMNWACT") => Ef::HplmnWact,
        ("suci", _) => Ef::SuciCalcInfo,
        ("routing-ind", _) => Ef::RoutingIndicator,
        ("impi", _) => Ef::Impi,
        ("impu", _) => Ef::Impu,
        ("pcscf", _) => Ef::Pcscf,
        _ => return None,
    })
}

/// How a service-table EF is named: the UST and EST have the names `crate::ef` carries.
fn service_table(name: &str) -> Option<ef::Table> {
    match name.to_ascii_uppercase().as_str() {
        "EF.UST" => Some(ef::Table::Ust),
        "EF.EST" => Some(ef::Table::Est),
        _ => None,
    }
}

/// Decodes the content of one standard EF. `kind` is the table's decoder name, `name` the file name
/// and `records` the content (one element for a transparent file). The result is the typed fields;
/// a file that does not parse comes back as `{"error", "hex"}` and never as an empty success.
pub fn decode_ef(kind: &str, name: &str, records: &[Vec<u8>]) -> Value {
    let first = records.first().map_or(&[][..], Vec::as_slice);
    let raw = || json!({ "hex": lower(first) });
    let fail = |why: &str| json!({ "error": why, "hex": records.iter().map(|r| lower(r)).collect::<Vec<_>>().join(" ") });
    if let Some(e) = ef_for(kind, name) {
        return match ef::decode(e, records, None) {
            Ok(d) => d.fields(),
            Err(m) => fail(&m.to_string()),
        };
    }
    match kind {
        "services" => {
            let table = service_table(name);
            let on = bitmap(first);
            let named: Vec<Value> = on
                .iter()
                .map(|n| json!({ "service": n, "name": table.and_then(|t| ef::service_name(t, *n as u16)) }))
                .collect();
            json!({ "enabled": on, "services": named })
        }
        "uint" => json!({ "value": uint(first), "hex": lower(first) }),
        "plmn-list" => {
            json!({ "plmns": first.chunks_exact(3).filter_map(plmn).collect::<Vec<_>>() })
        }
        "plmn-act" => match ef::decode_plmn_list(first, 5) {
            Ok(list) => json!({ "plmns": list.iter().map(|e| json!({
                "plmn": format!("{}{}", e.plmn.mcc, e.plmn.mnc),
                "act": e.act_names(),
            })).collect::<Vec<_>>() }),
            Err(m) => fail(&m.to_string()),
        },
        "adn" => per_record(records, |r| {
            let n = r.len().saturating_sub(14);
            let (alpha_b, num) = r.split_at(n.min(r.len()));
            // ext identifier and capability id are the last two octets; dialling number is the 12 before.
            let d = num.get(..12).map_or(Value::Null, dialling);
            json!({ "alpha": alpha(alpha_b), "number": d.get("number"), "ton_npi": d.get("ton_npi"),
                    "capability": num.get(12).map(|b| format!("{b:02X}")), "ext": num.get(13).map(|b| format!("{b:02X}")) })
        }),
        "sms" => per_record(records, |r| {
            let status = r.first().copied().unwrap_or(0);
            json!({ "status": match status & 7 { 0 => "free", 1 => "received-read", 3 => "received-unread", 5 => "sent", 7 => "to-be-sent", _ => "reserved" },
                    "pdu": lower(r.get(1..).unwrap_or(&[])) })
        }),
        "smsp" => per_record(records, |r| {
            let n = r.len().saturating_sub(28);
            let p = &r[n.min(r.len())..];
            let ind = p.first().copied().unwrap_or(0xFF);
            let addr = |b: Option<&[u8]>| b.map_or(Value::Null, dialling);
            json!({ "alpha": alpha(&r[..n.min(r.len())]), "indicators": format!("{ind:02X}"),
                    "destination": if ind & 1 == 0 { addr(p.get(1..13)) } else { Value::Null },
                    "service_centre": if ind & 2 == 0 { addr(p.get(13..25)) } else { Value::Null },
                    "pid": p.get(25).map(|b| format!("{b:02X}")), "dcs": p.get(26).map(|b| format!("{b:02X}")),
                    "validity": p.get(27).map(|b| format!("{b:02X}")) })
        }),
        "smss" => {
            json!({ "last_tp_mr": first.first(), "memory_capacity_exceeded": first.get(1).map(|b| b & 1 == 0) })
        }
        "alpha-list" => {
            json!({ "languages": first.chunks_exact(2).filter(|c| c[0] != 0xFF).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>() })
        }
        "spn" => {
            json!({ "display_condition": first.first().map(|b| format!("{b:02X}")), "name": alpha(first.get(1..).unwrap_or(&[])) })
        }
        "ecc" => per_record(records, |r| {
            let n = bcd(r.get(..3).unwrap_or(&[]));
            json!({ "number": n, "alpha": alpha(r.get(3..r.len().saturating_sub(1)).unwrap_or(&[])), "category": r.last().map(|b| format!("{b:02X}")) })
        }),
        "cbmi" => {
            json!({ "ids": first.chunks_exact(2).filter(|c| c[..] != [0xFF, 0xFF]).map(|c| u16::from_be_bytes([c[0], c[1]])).collect::<Vec<_>>() })
        }
        "opl" => per_record(
            records,
            |r| json!({ "plmn": r.get(..3).and_then(plmn), "lac_min": r.get(3..5).map(lower), "lac_max": r.get(5..7).map(lower), "pnn_record": r.get(7) }),
        ),
        "uri" => {
            let t = tlv(first, 0);
            json!({ "value": t[0]["value"].as_str().and_then(|h| hex::decode(h).ok()).map(|b| String::from_utf8_lossy(&b).into_owned()), "tlv": t })
        }
        "acl" => json!({ "count": first.first(), "tlv": tlv(first.get(1..).unwrap_or(&[]), 0) }),
        "tlv" => {
            if records.len() > 1 {
                per_record(records, |r| json!({ "tlv": tlv(r, 4) }))
            } else {
                json!({ "tlv": tlv(first, 4) })
            }
        }
        _ if records.len() > 1 => per_record(records, |r| json!({ "hex": lower(r) })),
        _ => raw(),
    }
}

/// Whether [`decode_ef`] gives a kind more than the hex of its content.
pub fn is_structured(kind: &str) -> bool {
    kind != "hex"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha_reads_gsm7_and_ucs2() {
        assert_eq!(alpha(&[b'A', b'n', b'n', 0xFF, 0xFF]), "Ann");
        assert_eq!(alpha(&[0x00, 0x02]), "@$");
        assert_eq!(alpha(&[0x80, 0x00, 0x48, 0x00, 0x69, 0xFF]), "Hi");
        assert_eq!(alpha(&[0x81, 0x02, 0x08, b'A', 0x81]), "A\u{0401}");
        assert_eq!(alpha(&[0xFF, 0xFF]), "");
    }

    #[test]
    fn digits_numbers_and_plmns() {
        assert_eq!(bcd(&[0x21, 0x43, 0xF5]), "12345");
        assert_eq!(bcd(&[0xA1, 0xB2, 0xFF]), "1*2#");
        let n = dialling(&[0x07, 0x91, 0x10, 0x32, 0x54, 0x76, 0x98, 0xFF]);
        assert_eq!(n["number"], "+0123456789");
        assert_eq!(dialling(&[0xFF, 0xFF]), Value::Null);
        assert_eq!(plmn(&[0x00, 0xF1, 0x10]).as_deref(), Some("00101"));
        assert_eq!(plmn(&[0x62, 0xF2, 0x10]).as_deref(), Some("26201"));
        assert_eq!(plmn(&[0xFF, 0xFF, 0xFF]), None);
        assert_eq!(uint(&[0x01, 0x00]), 256);
        assert_eq!(bitmap(&[0b0000_0101, 0b1000_0000]), vec![1, 3, 16]);
    }

    #[test]
    fn tlv_trees_nest() {
        let v = tlv(&[0xA0, 0x03, 0x80, 0x01, 0x05, 0x81, 0x00], 3);
        assert_eq!(v[0]["children"][0]["value"], "05");
        assert_eq!(v[1]["value"], "");
        assert!(tlv(&[0x80, 0x05, 0x01], 3)[0]["error"].is_string());
    }

    fn d(kind: &str, name: &str, recs: &[&[u8]]) -> Value {
        decode_ef(
            kind,
            name,
            &recs.iter().map(|r| r.to_vec()).collect::<Vec<_>>(),
        )
    }

    #[test]
    fn every_kind_in_the_table_has_a_decoder_and_the_table_is_sound() {
        use crate::cardsh::names;
        let known = [
            "hex",
            "tlv",
            "uint",
            "adn",
            "plmn-act",
            "cbmi",
            "loci",
            "plmn-list",
            "services",
            "ad",
            "sms",
            "smsp",
            "smss",
            "alpha-list",
            "imsi",
            "spn",
            "acc",
            "ecc",
            "opl",
            "suci",
            "iccid",
            "acl",
            "impi",
            "uri",
            "impu",
            "pcscf",
            "routing-ind",
        ];
        let mut seen = std::collections::HashSet::new();
        for e in names::all() {
            assert!(
                known.contains(&e.kind),
                "{} has the unknown kind {}",
                e.name,
                e.kind
            );
            assert!(
                seen.insert((e.scope, e.name, e.fid)),
                "{} {} twice",
                e.scope,
                e.name
            );
            assert!(matches!(e.structure, 'T' | 'L' | 'C' | 'B'));
            // No kind falls through to a bare "hex" by accident: a non-hex kind decodes to something typed.
            if e.kind != "hex" {
                let out = decode_ef(e.kind, e.name, &[vec![0xFF; 14]]);
                assert!(
                    out.get("hex").is_none() || out.get("error").is_some() || e.kind == "uint",
                    "{} {out}",
                    e.name
                );
            }
        }
        let distinct: std::collections::HashSet<_> =
            names::all().map(|e| e.name.to_ascii_lowercase()).collect();
        assert!(
            names::all().count() >= 280 && distinct.len() >= 200,
            "{} {}",
            names::all().count(),
            distinct.len()
        );
        // Identifiers the specifications fix (spot checks beyond the pySim cross-check).
        for (scope, name, fid) in [
            ("ADF.USIM", "EF.IMSI", 0x6F07),
            ("ADF.USIM", "EF.UST", 0x6F38),
            ("ADF.USIM", "EF.FPLMN", 0x6F7B),
            ("ADF.USIM", "EF.EPSLOCI", 0x6FE3),
            ("ADF.USIM", "EF.EHPLMN", 0x6FD9),
            ("ADF.ISIM", "EF.IMPI", 0x6F02),
            ("ADF.ISIM", "EF.IST", 0x6F07),
            ("DF.5GS", "EF.SUCI_Calc_Info", 0x4F07),
            ("DF.TELECOM", "EF.MSISDN", 0x6F40),
            ("DF.GSM", "EF.SST", 0x6F38),
            ("MF", "EF.ICCID", 0x2FE2),
        ] {
            assert!(
                names::all().any(|e| e.scope == scope
                    && e.name == name
                    && e.fid.to_bytes() == fid_bytes(fid)),
                "{scope} {name} {fid:04X}"
            );
        }
    }

    fn fid_bytes(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }

    #[test]
    fn records_and_lists_decode() {
        let adn = d(
            "adn",
            "EF.ADN",
            &[&[
                b'B', b'o', b'b', 0x05, 0x91, 0x21, 0x43, 0xF5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF,
            ]],
        );
        assert_eq!(adn["records"][0]["alpha"], "Bob");
        assert_eq!(adn["records"][0]["number"], "+12345");
        let sms = d("sms", "EF.SMS", &[&[0x03, 0x07, 0x91], &[0x00, 0xFF]]);
        assert_eq!(sms["records"][0]["status"], "received-unread");
        assert_eq!(sms["records"][1]["status"], "free");
        let opl = d(
            "opl",
            "EF.OPL",
            &[&[0x62, 0xF2, 0x10, 0x00, 0x01, 0xFF, 0xFE, 0x01]],
        );
        assert_eq!(opl["records"][0]["plmn"], "26201");
        assert_eq!(opl["records"][0]["pnn_record"], 1);
        let ecc = d(
            "ecc",
            "EF.ECC",
            &[&[0x11, 0xF2, 0xFF, b'S', b'O', b'S', 0x01]],
        );
        assert_eq!(ecc["records"][0]["number"], "112");
        assert_eq!(ecc["records"][0]["alpha"], "SOS");
        let plmn = d(
            "plmn-list",
            "EF.PLMNsel",
            &[&[0x62, 0xF2, 0x10, 0xFF, 0xFF, 0xFF]],
        );
        assert_eq!(plmn["plmns"], json!(["26201"]));
        let act = d(
            "plmn-act",
            "EF.PLMNwAcT",
            &[&[0x62, 0xF2, 0x10, 0x80, 0x80]],
        );
        assert_eq!(act["plmns"][0]["act"], json!(["UTRAN", "GSM"]));
        assert_eq!(
            d("cbmi", "EF.CBMI", &[&[0x00, 0x32, 0xFF, 0xFF]])["ids"],
            json!([50])
        );
        assert_eq!(
            d("alpha-list", "EF.LI", &[b"deen"])["languages"],
            json!(["de", "en"])
        );
        assert_eq!(d("uint", "EF.ACMmax", &[&[0x00, 0x01, 0x00]])["value"], 256);
        let smsp = d(
            "smsp",
            "EF.SMSP",
            &[&[
                b'X', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF,
            ]],
        );
        assert_eq!(smsp["records"][0]["alpha"], "X");
        let acl = d("acl", "EF.ACL", &[&[0x01, 0xDD, 0x03, b'a', b'b', b'c']]);
        assert_eq!(acl["count"], 1);
        let ust = d("services", "EF.UST", &[&[0b0000_0010, 0, 0, 0b0000_1000]]);
        assert_eq!(ust["enabled"], json!([2, 28]));
        assert_eq!(ust["services"][1]["name"], "Data download via SMS-PP");
        // A file that does not parse is an error with the bytes, never an empty success.
        let bad = d("imsi", "EF.IMSI", &[&[0x08, 0x09]]);
        assert!(bad["error"].is_string() && bad["hex"] == "0809", "{bad}");
        // A BER-TLV file nests.
        let tl = d("tlv", "EF.PNN", &[&[0x43, 0x03, 0x80, 0x01, 0x41]]);
        assert_eq!(tl["tlv"][0]["tag"], "43");
    }
}
