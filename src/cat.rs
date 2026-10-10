//! The Card Application Toolkit decoder: a proactive command (FETCH response), an ENVELOPE, a TERMINAL
//! RESPONSE or a bare run of comprehension TLVs turned into named fields. Offline, sends nothing.
//!
//! **Owns.** Parsing BER-TLV / comprehension-TLV objects (TS 102 223 clause 8, TS 31.111), naming the 44
//! types of proactive command and the 14 envelope tags, the 90 information elements, the general result
//! codes and the device identities, and decoding the fields of the elements a security review reads (command
//! details with the qualifier spelled out, device identities, result, alpha identifier, text string, address,
//! item, URL, bearer description, channel data, location information, IMEI, event list ...).
//!
//! **Does not own.** Executing any of it: nothing here answers a card. A `TERMINAL RESPONSE` is decoded the
//! same way as a command and never built.
//!
//! The tables (`tables.rs`) follow pySim's `cat.py` (osmocom/pysim, GPL: tags read, code written here); the field
//! layouts follow ETSI TS 102 223 clause 8. An element without a field decoder is shown as its hex, named,
//! with `"decoded": false`, never dropped. Two elements share a tag where ECAT and later additions reused a
//! number; both names are listed as `alternatives`.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "cat";

mod tables;

use serde_json::{json, Value};

pub use tables::{COMMANDS, DEVICES, ENVELOPES, IES, RESULTS};

/// One comprehension TLV (or BER-TLV) object as found on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// The tag octets as read (one, or `7F` and two more).
    pub tag: u16,
    /// Length of the value.
    pub value: Vec<u8>,
    /// Whether the comprehension-required bit (b8) was set.
    pub required: bool,
}

/// Why a buffer is not a well-formed object list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Nothing to decode.
    #[error("empty input")]
    Empty,
    /// The length field or the value runs past the buffer.
    #[error("object at offset {offset} is truncated: {need} more octets are needed")]
    Truncated {
        /// Where the object starts.
        offset: usize,
        /// How many octets are missing.
        need: usize,
    },
}

fn read_len(b: &[u8], at: usize) -> Result<(usize, usize), Error> {
    let truncated = |need| Error::Truncated { offset: at, need };
    match b.get(at) {
        None => Err(truncated(1)),
        Some(&n) if n < 0x80 => Ok((usize::from(n), 1)),
        Some(0x81) => b
            .get(at + 1)
            .map(|&n| (usize::from(n), 2))
            .ok_or_else(|| truncated(1)),
        Some(0x82) => match b.get(at + 1..at + 3) {
            Some(&[a, c]) => Ok((usize::from(u16::from_be_bytes([a, c])), 3)),
            _ => Err(truncated(2)),
        },
        Some(_) => Err(truncated(0)),
    }
}

/// Splits `bytes` into objects. A `00` or `FF` octet where a tag should be is padding and ends the list.
///
/// # Errors
///
/// [`Error::Truncated`] when an object runs past the buffer.
pub fn objects(bytes: &[u8]) -> Result<Vec<Object>, Error> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if matches!(bytes[at], 0x00 | 0xFF) {
            break;
        }
        let start = at;
        let (tag, tag_len) = if bytes[at] == 0x7F && bytes.len() >= at + 3 {
            (
                u16::from_be_bytes([bytes[at + 1], bytes[at + 2]]) | 0x8000,
                3,
            )
        } else {
            (u16::from(bytes[at]), 1)
        };
        at += tag_len;
        let (len, n) = read_len(bytes, at).map_err(|e| match e {
            Error::Truncated { need, .. } => Error::Truncated {
                offset: start,
                need,
            },
            other => other,
        })?;
        at += n;
        let value = bytes.get(at..at + len).ok_or_else(|| Error::Truncated {
            offset: start,
            need: at + len - bytes.len(),
        })?;
        at += len;
        out.push(Object {
            tag,
            value: value.to_vec(),
            required: tag < 0x100 && tag & 0x80 != 0,
        });
    }
    Ok(out)
}

fn lookup<T: Copy>(table: &[(u8, T)], code: u8) -> Option<T> {
    table.iter().find(|(c, _)| *c == code).map(|(_, v)| *v)
}

/// The name of a type of proactive command.
pub fn command_name(code: u8) -> Option<&'static str> {
    lookup(COMMANDS, code)
}

fn hex(b: &[u8]) -> String {
    hex::encode_upper(b)
}

/// All the names information element tag `tag` (b8 cleared) goes by.
pub fn ie_names(tag: u8) -> Vec<&'static str> {
    IES.iter()
        .filter(|(t, ..)| *t == tag)
        .map(|(_, n, _)| *n)
        .collect()
}

// ---- field decoders --------------------------------------------------------------------------------

const GSM7: &str = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\u{1b}ÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";

fn gsm7_char(c: u8) -> char {
    GSM7.chars().nth(usize::from(c & 0x7F)).unwrap_or('?')
}

fn unpack7(b: &[u8]) -> String {
    let (mut out, mut acc, mut bits) = (String::new(), 0u32, 0);
    for &byte in b {
        acc |= u32::from(byte) << bits;
        bits += 8;
        while bits >= 7 {
            out.push(gsm7_char((acc & 0x7F) as u8));
            acc >>= 7;
            bits -= 7;
        }
    }
    // A trailing group of fewer than 7 bits is padding.
    out
}

fn ucs2(b: &[u8]) -> String {
    char::decode_utf16(b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])))
        .map(|r| r.unwrap_or('?'))
        .collect()
}

/// A text string with its data coding scheme octet (TS 23.038 groups 0 and 1 are enough here).
pub fn text_with_dcs(dcs: u8, b: &[u8]) -> (String, &'static str) {
    match dcs & 0x0C {
        0x00 if dcs & 0xF0 == 0xF0 && dcs & 0x04 != 0 => {
            (String::from_utf8_lossy(b).into_owned(), "8-bit data")
        }
        0x00 => (unpack7(b), "GSM 7-bit packed"),
        0x04 => (String::from_utf8_lossy(b).into_owned(), "8-bit data"),
        0x08 => (ucs2(b), "UCS2"),
        _ => (hex(b), "reserved"),
    }
}

/// Alpha identifier, item text: GSM 7-bit one octet per character, or UCS2 with the 80/81/82 marker.
pub fn alpha(b: &[u8]) -> String {
    match b.first() {
        Some(0x80) => ucs2(&b[1..]),
        Some(0x81) | Some(0x82) => format!("(UCS2 with base pointer) {}", hex(b)),
        _ => b.iter().map(|c| gsm7_char(*c)).collect(),
    }
}

fn bcd(b: &[u8]) -> String {
    let mut out = String::new();
    'o: for x in b {
        for n in [x & 0x0F, x >> 4] {
            match n {
                0..=9 => out.push(char::from(b'0' + n)),
                0xA => out.push('*'),
                0xB => out.push('#'),
                0xC => out.push('p'),
                0xD => out.push('w'),
                0xE => out.push('e'),
                _ => break 'o,
            }
        }
    }
    out
}

fn plmn(b: &[u8]) -> Option<String> {
    let [a, c, d] = <[u8; 3]>::try_from(b.get(..3)?).ok()?;
    let mnc3 = if c >> 4 == 0xF {
        String::new()
    } else {
        (c >> 4).to_string()
    };
    Some(format!(
        "{}{}{}-{}{}{mnc3}",
        a & 0x0F,
        a >> 4,
        c & 0x0F,
        d & 0x0F,
        d >> 4
    ))
}

fn named(table: &[(u8, &'static str)], code: u8) -> Value {
    json!({ "code": format!("{code:02X}"), "name": lookup(table, code) })
}

fn qualifier_text(cmd: u8, q: u8) -> Vec<String> {
    let bits = |names: &[(u8, &str)]| -> Vec<String> {
        names
            .iter()
            .filter(|(m, _)| q & m != 0)
            .map(|(_, n)| (*n).to_owned())
            .collect()
    };
    let one = |names: &[(u8, &str)]| -> Vec<String> {
        vec![names
            .iter()
            .find(|(v, _)| *v == q)
            .map_or_else(|| format!("reserved ({q:02X})"), |(_, n)| (*n).to_owned())]
    };
    match cmd {
        0x01 => one(&[
            (0, "NAA initialization and full file change notification"),
            (1, "file change notification"),
            (2, "NAA initialization and file change notification"),
            (3, "NAA initialization"),
            (4, "UICC reset"),
            (5, "NAA application reset"),
            (6, "NAA session reset"),
            (7, "steering of roaming"),
        ]),
        0x10 => one(&[
            (
                0,
                "set up call, but only if not currently busy on another call",
            ),
            (
                1,
                "set up call, but only if not currently busy on another call, with redial",
            ),
            (2, "set up call, putting all other calls (if any) on hold"),
            (
                3,
                "set up call, putting all other calls (if any) on hold, with redial",
            ),
            (4, "set up call, disconnecting all other calls (if any)"),
            (
                5,
                "set up call, disconnecting all other calls (if any), with redial",
            ),
        ]),
        0x13 => bits(&[(0x01, "SMS packing by the terminal required")]),
        0x15 => one(&[
            (0, "launch browser, if not already launched"),
            (
                2,
                "use the existing browser (the browser shall not use the active session)",
            ),
            (
                3,
                "close the existing browser session and launch new browser session",
            ),
        ]),
        0x21 => bits(&[
            (0x01, "high priority"),
            (0x80, "wait for user to clear message"),
        ]),
        0x22 => bits(&[
            (0x01, "alphabet set (not digits only)"),
            (0x02, "UCS2 alphabet"),
            (0x04, "Yes/No answer"),
            (0x08, "immediate digit response"),
            (0x80, "help information available"),
        ]),
        0x23 => bits(&[
            (0x01, "alphabet set (not digits only)"),
            (0x02, "UCS2 alphabet"),
            (0x04, "do not echo the user's input"),
            (0x08, "packing required"),
            (0x80, "help information available"),
        ]),
        0x24 => bits(&[
            (0x01, "presentation type is specified"),
            (0x02, "navigation options (move backward)"),
            (0x04, "soft-key choice"),
            (0x80, "help information available"),
        ]),
        0x25 => bits(&[(0x01, "soft-key"), (0x80, "help information available")]),
        0x26 => one(&[
            (
                0x00,
                "location information (MCC, MNC, LAC/TAC, cell identity)",
            ),
            (0x01, "IMEI"),
            (0x02, "network measurement results"),
            (0x03, "date, time and time zone"),
            (0x04, "language setting"),
            (0x05, "timing advance"),
            (0x06, "access technology"),
            (0x07, "ESN"),
            (0x08, "IMEISV"),
            (0x09, "search mode"),
            (0x0A, "charge state of the battery"),
            (0x0B, "MEID"),
            (0x0D, "WSID of the current WLAN connection"),
            (0x0E, "broadcast network information"),
            (0x0F, "multiple access technologies"),
            (
                0x10,
                "location information for multiple access technologies",
            ),
            (
                0x11,
                "network measurement results for multiple access technologies",
            ),
        ]),
        0x27 => one(&[
            (0, "start the timer"),
            (1, "deactivate the timer"),
            (2, "get the current value of the timer"),
        ]),
        0x40 => bits(&[
            (0x01, "immediate link establishment"),
            (0x02, "automatic reconnection"),
            (0x04, "background mode"),
        ]),
        0x20 | 0x28 | 0x43 | 0x42 | 0x14 | 0x16 => {
            if q == 0 {
                vec![]
            } else {
                bits(&[
                    (0x01, "bit 1"),
                    (0x02, "bit 2"),
                    (0x04, "bit 3"),
                    (0x08, "bit 4"),
                    (0x10, "bit 5"),
                    (0x20, "bit 6"),
                    (0x40, "bit 7"),
                    (0x80, "bit 8"),
                ])
            }
        }
        _ => vec![],
    }
}

fn command_details(v: &[u8]) -> Value {
    match v {
        [number, kind, qualifier, ..] => {
            let quals = qualifier_text(*kind, *qualifier);
            json!({
                "number": number,
                "type": format!("{kind:02X}"),
                "type_name": command_name(*kind),
                "qualifier": format!("{qualifier:02X}"),
                "qualifier_meaning": quals,
            })
        }
        _ => json!({ "error": "command details are three octets" }),
    }
}

/// Decodes the value of information element `tag` (b8 cleared). `None` when this module has no field
/// layout for it (the caller then shows the hex).
fn fields(tag: u8, v: &[u8]) -> Option<Value> {
    Some(match tag {
        0x01 => command_details(v),
        0x02 => match v {
            [s, d] => json!({ "source": named(DEVICES, *s), "destination": named(DEVICES, *d) }),
            _ => return None,
        },
        0x03 => {
            let (&g, extra) = v.split_first()?;
            json!({ "general_result": named(RESULTS, g), "additional_information": hex(extra),
                    "success": g < 0x10, "terminal_problem": (0x20..0x30).contains(&g), "error": g >= 0x30 })
        }
        0x04 => match v {
            [unit, n] => {
                json!({ "unit": match unit { 0 => "minutes", 1 => "seconds", 2 => "tenths of a second", _ => "reserved" }, "interval": n })
            }
            _ => return None,
        },
        0x05 => json!({ "text": alpha(v) }),
        0x06 | 0x09 => {
            let (&ton, num) = v.split_first()?;
            let number = bcd(num);
            json!({ "ton_npi": format!("{ton:02X}"), "international": ton & 0x70 == 0x10, "number": number })
        }
        0x0A | 0x0D | 0x17 => {
            let (&dcs, text) = v.split_first()?;
            let (t, coding) = text_with_dcs(dcs, text);
            json!({ "dcs": format!("{dcs:02X}"), "coding": coding, "text": t })
        }
        0x0E => json!({ "tone": v.first().map(|t| match t {
            0x01 => "dial tone", 0x02 => "called subscriber busy", 0x03 => "congestion", 0x04 => "radio path acknowledge",
            0x05 => "radio path not available / call dropped", 0x06 => "error / special information", 0x07 => "call waiting tone",
            0x08 => "ringing tone", 0x10 => "general beep", 0x11 => "positive acknowledgement tone", 0x12 => "negative acknowledgement or error tone",
            0x13 => "ringing tone as selected by the user", 0x14 => "SMS alert tone selected by the user", 0x15 => "critical alert tone", 0x20 => "vibrate only",
            0x30 => "happy tone", 0x31 => "sad tone", 0x32 => "urgent action tone", 0x33 => "question tone", 0x34 => "message received tone",
            _ => "reserved" }), "code": v.first().map(|t| format!("{t:02X}")) }),
        0x0F => {
            let (&id, text) = v.split_first()?;
            json!({ "id": id, "text": alpha(text) })
        }
        0x10 => json!({ "item_id": v.first() }),
        0x11 => match v {
            [min, max] => json!({ "minimum": min, "maximum": max }),
            _ => return None,
        },
        0x13 => {
            let p = plmn(v)?;
            let rest = &v[3..];
            json!({ "plmn": p, "area_code": hex(rest.get(..2)?), "cell_id": hex(rest.get(2..).unwrap_or(&[])) })
        }
        0x14 | 0x62 => json!({ "digits": bcd(v) }),
        0x19 => json!({ "events": v.iter().map(|e| match e {
            0x00 => "MT call", 0x01 => "call connected", 0x02 => "call disconnected", 0x03 => "location status", 0x04 => "user activity",
            0x05 => "idle screen available", 0x06 => "card reader status", 0x07 => "language selection", 0x08 => "browser termination",
            0x09 => "data available", 0x0A => "channel status", 0x0B => "access technology change", 0x0C => "display parameters changed",
            0x0D => "local connection", 0x0E => "network search mode change", 0x0F => "browsing status", 0x10 => "frames information change",
            0x11 => "I-WLAN access status", 0x12 => "network rejection", 0x13 => "HCI connectivity event", 0x14 => "access technology change (multiple)",
            0x15 => "CSG cell selection", 0x16 => "contactless state request", 0x17 => "IMS registration", 0x18 => "IMS incoming data", 0x19 => "profile container",
            0x1A => "void", 0x1B => "secured profile container", 0x1C => "poll interval negotiation", 0x1D => "data connection status change",
            0x1E => "CAG cell selection", 0x1F => "slice(s) change", _ => "reserved" }).collect::<Vec<_>>() }),
        0x1A => json!({ "cause": hex(v) }),
        0x1B => {
            json!({ "status": v.first().map(|s| match s { 0 => "normal service", 1 => "limited service", 2 => "no service", _ => "reserved" }) })
        }
        0x1E => match v {
            [q, id] => json!({ "self_explanatory": q & 1 == 0, "icon_id": id }),
            _ => return None,
        },
        0x24 => json!({ "timer_id": v.first() }),
        0x25 => json!({ "hhmmss": bcd(v) }),
        0x2D => json!({ "language": String::from_utf8_lossy(v) }),
        0x2C => json!({ "dtmf": bcd(v) }),
        0x28 => json!({ "command": String::from_utf8_lossy(v) }),
        0x31 => json!({ "url": String::from_utf8_lossy(v) }),
        0x32 => {
            json!({ "bearers": v.iter().map(|b| match b { 0 => "SMS", 1 => "CSD", 2 => "USSD", 3 => "GPRS", _ => "reserved" }).collect::<Vec<_>>() })
        }
        0x35 => {
            let (&t, rest) = v.split_first()?;
            json!({ "bearer_type": match t { 1 => "CSD", 2 => "GPRS / UTRAN / E-UTRAN / NG-RAN packet service", 3 => "default bearer for requested transport layer",
                0x0B => "I-WLAN", 0x0C => "E-UTRAN / mapped UTRAN packet service", 0x0D => "NG-RAN", _ => "unknown" }, "type": format!("{t:02X}"), "parameters": hex(rest) })
        }
        0x36 => json!({ "length": v.len(), "data": hex(v) }),
        0x37 | 0x39 => match v {
            [a, b] => json!({ "value": u16::from_be_bytes([*a, *b]) }),
            [a] => json!({ "value": a }),
            _ => return None,
        },
        0x38 => match v {
            [id, status] => {
                json!({ "channel": id & 0x07, "link_established": id & 0x80 != 0, "status": format!("{status:02X}") })
            }
            _ => return None,
        },
        0x3C => match v {
            [proto, a, b] => {
                json!({ "protocol": match proto { 1 => "UDP, UICC in client mode, remote connection", 2 => "TCP, UICC in client mode, remote connection",
                3 => "TCP, UICC in server mode", 4 => "UDP, UICC in client mode, local connection", 5 => "TCP, UICC in client mode, local connection",
                6 => "direct communication channel", _ => "reserved" }, "port": u16::from_be_bytes([*a, *b]) })
            }
            _ => return None,
        },
        0x3E => {
            let (&t, addr) = v.split_first()?;
            match (t, addr) {
                (0x21, [a, b, c, d]) => {
                    json!({ "type": "IPv4", "address": format!("{a}.{b}.{c}.{d}") })
                }
                (0x57, a) if a.len() == 16 => {
                    json!({ "type": "IPv6", "address": a.chunks(2).map(|c| format!("{:02x}{:02x}", c[0], c[1])).collect::<Vec<_>>().join(":") })
                }
                _ => json!({ "type": format!("{t:02X}"), "address": hex(addr) }),
            }
        }
        0x47 => {
            let mut labels = Vec::new();
            let mut at = 0;
            while at < v.len() {
                let n = usize::from(v[at]);
                labels.push(String::from_utf8_lossy(v.get(at + 1..at + 1 + n)?).into_owned());
                at += 1 + n;
            }
            json!({ "apn": labels.join(".") })
        }
        0x2F => json!({ "aid": hex(v) }),
        0x63 => {
            json!({ "battery": v.first().map(|s| match s { 0 => "very low", 1 => "low", 2 => "average", 3 => "good", 4 => "full", _ => "reserved" }) })
        }
        _ => return None,
    })
}

/// One decoded information element.
fn ie_json(o: &Object) -> Value {
    let tag = (o.tag & 0x7F) as u8;
    let names = ie_names(tag);
    let decoded = if o.tag < 0x100 {
        fields(tag, &o.value)
    } else {
        None
    };
    let mut out = json!({
        "tag": format!("{:02X}", o.tag),
        "comprehension_required": o.required,
        "name": names.first(),
        "length": o.value.len(),
        "hex": hex(&o.value),
        "decoded": decoded.is_some(),
    });
    if names.len() > 1 {
        out["alternatives"] = json!(names[1..]);
    }
    if let Some(f) = decoded {
        out["fields"] = f;
    }
    out
}

/// The result of [`decode`].
#[derive(Debug, Clone)]
pub struct Decoded {
    /// `proactive-command`, `envelope`, `terminal-response` or `comprehension-tlvs`.
    pub kind: &'static str,
    /// The outer tag octet, when there is one (`D0`..`DF`).
    pub outer_tag: Option<u8>,
    /// The type of command (proactive command, terminal response) or the envelope's name.
    pub name: Option<String>,
    /// The JSON view.
    pub json: Value,
}

/// Decodes `bytes`. A leading `D0` is a proactive command, `D1`..`DF` an envelope; anything else is read as
/// a run of comprehension TLVs (a TERMINAL RESPONSE starts with Command details `81 03`).
///
/// # Errors
///
/// [`Error`] when the outer object or one of the elements is truncated.
pub fn decode(bytes: &[u8]) -> Result<Decoded, Error> {
    if bytes.is_empty() {
        return Err(Error::Empty);
    }
    let (kind, outer_tag, inner): (&'static str, Option<u8>, Vec<u8>) =
        if (0xD0..=0xDF).contains(&bytes[0]) {
            let outer = objects(bytes)?;
            let first = outer.first().ok_or(Error::Empty)?;
            (
                if bytes[0] == 0xD0 {
                    "proactive-command"
                } else {
                    "envelope"
                },
                Some(bytes[0]),
                first.value.clone(),
            )
        } else {
            ("comprehension-tlvs", None, bytes.to_vec())
        };
    let list = objects(&inner)?;
    let details =
        list.iter()
            .find(|o| o.tag & 0x7F == 0x01)
            .and_then(|o| match o.value.as_slice() {
                [_, kind, ..] => Some(*kind),
                _ => None,
            });
    let has_result = list.iter().any(|o| o.tag & 0x7F == 0x03);
    let kind = if kind == "comprehension-tlvs" && has_result && details.is_some() {
        "terminal-response"
    } else {
        kind
    };
    let name = match (kind, outer_tag, details) {
        ("envelope", Some(t), _) => lookup(ENVELOPES, t).map(str::to_owned),
        (_, _, Some(c)) => command_name(c).map(str::to_owned),
        _ => None,
    };
    let consumed: usize = list.iter().map(|o| 1 + 1 + o.value.len()).sum();
    let json = json!({
        "kind": kind,
        "outer_tag": outer_tag.map(|t| format!("{t:02X}")),
        "name": name,
        "elements": list.iter().map(ie_json).collect::<Vec<_>>(),
        "undecoded_elements": list.iter().filter(|o| o.tag >= 0x100 || fields((o.tag & 0x7F) as u8, &o.value).is_none()).count(),
        "trailing_octets": inner.len().saturating_sub(consumed.min(inner.len())).min(inner.len()),
    });
    Ok(Decoded {
        kind,
        outer_tag,
        name,
        json,
    })
}

/// The human rendering of a decoded value (the `json` of [`decode`]).
pub fn render(d: &Decoded) -> String {
    let mut out = format!(
        "{}{}\n",
        d.kind,
        d.name.as_ref().map_or(String::new(), |n| format!(": {n}"))
    );
    if let Some(list) = d.json["elements"].as_array() {
        for e in list {
            let tag = e["tag"].as_str().unwrap_or("");
            let name = e["name"].as_str().unwrap_or("unknown element");
            let detail = match e.get("fields") {
                Some(f) => compact(f),
                None => e["hex"].as_str().unwrap_or("").to_owned(),
            };
            out.push_str(&format!("  {tag} {name}: {detail}\n"));
        }
    }
    out
}

fn compact(v: &Value) -> String {
    match v {
        Value::Object(m) => m
            .iter()
            .map(|(k, v)| format!("{k}={}", compact(v)))
            .collect::<Vec<_>>()
            .join(", "),
        Value::Array(a) => format!("[{}]", a.iter().map(compact).collect::<Vec<_>>().join(", ")),
        Value::String(s) => s.clone(),
        Value::Null => "-".to_owned(),
        other => other.to_string(),
    }
}

/// The hex text a person types or pipes: pairs, spaces and `0x` ignored.
///
/// # Errors
///
/// A sentence when it is not hex.
pub fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let t: String = text
        .split_whitespace()
        .map(|w| w.trim_start_matches("0x"))
        .collect();
    hex::decode(&t).map_err(|_| "the input is not hex".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(h: &str) -> Value {
        decode(&parse_hex(h).unwrap()).unwrap().json
    }

    /// `D0` and the right length around the elements in `inner`.
    fn pc(inner: &str) -> String {
        let n = parse_hex(inner).unwrap().len();
        format!("D0 {n:02X} {inner}")
    }

    // DISPLAY TEXT from TS 31.124 / 102 384: D0 12 | 81 03 01 21 80 | 82 02 81 02 | 8D 07 04 "Hello"
    const DISPLAY_TEXT: &str = "D0 0F 81 03 01 21 80 82 02 81 02 8D 04 04 48 49 21";

    #[test]
    fn display_text_is_named_with_its_qualifier_and_text() {
        let v = d(DISPLAY_TEXT);
        assert_eq!(v["kind"], "proactive-command");
        assert_eq!(v["name"], "DISPLAY TEXT");
        let cd = &v["elements"][0]["fields"];
        assert_eq!(cd["type_name"], "DISPLAY TEXT");
        assert_eq!(
            cd["qualifier_meaning"],
            json!(["wait for user to clear message"])
        );
        assert_eq!(v["elements"][1]["fields"]["source"]["name"], "uicc");
        assert_eq!(v["elements"][1]["fields"]["destination"]["name"], "display");
        assert_eq!(v["elements"][2]["fields"]["text"], "HI!");
        assert_eq!(v["elements"][2]["fields"]["coding"], "8-bit data");
        assert_eq!(v["undecoded_elements"], 0);
    }

    #[test]
    fn terminal_response_and_result_codes() {
        let v = d("81 03 01 21 80 82 02 82 81 83 01 00");
        assert_eq!(v["kind"], "terminal-response");
        assert_eq!(
            v["elements"][2]["fields"]["general_result"]["name"],
            "performed successfully"
        );
        assert_eq!(v["elements"][2]["fields"]["success"], true);
        let v = d("81 03 01 21 80 82 02 82 81 83 02 32 01");
        assert_eq!(v["elements"][2]["fields"]["error"], true);
        assert_eq!(v["elements"][2]["fields"]["additional_information"], "01");
    }

    #[test]
    fn every_command_type_and_envelope_has_a_name_and_the_counts_are_what_pysim_defines() {
        assert_eq!(COMMANDS.len(), 44);
        assert_eq!(ENVELOPES.len(), 14);
        assert_eq!(IES.len(), 90);
        for (code, name) in COMMANDS {
            let v = d(&pc(&format!("81 03 01 {code:02X} 00 82 02 81 82")));
            assert_eq!(v["name"], *name, "{code:02X}");
        }
        for (tag, name) in ENVELOPES {
            let v = d(&format!("{tag:02X} 04 82 02 81 82"));
            assert_eq!(v["kind"], "envelope");
            assert_eq!(v["name"], *name);
        }
        // Every information element is named by its tag, with a comprehension-required bit or without.
        for (tag, name, _) in IES {
            assert!(ie_names(*tag).contains(name));
        }
        assert_eq!(ie_names(0x34).len(), 2, "shared tags list both names");
    }

    #[test]
    fn elements_decode_their_fields() {
        // SET UP CALL with an address and an alpha identifier; SELECT ITEM; LAUNCH BROWSER with an URL; OPEN CHANNEL.
        let v = d(&pc(
            "81 03 01 10 02 82 02 81 83 85 04 43 61 6C 6C 86 07 91 21 43 65 87 09 F1",
        ));
        assert_eq!(v["name"], "SET UP CALL");
        assert_eq!(
            v["elements"][0]["fields"]["qualifier_meaning"][0],
            "set up call, putting all other calls (if any) on hold"
        );
        let addr = v["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["tag"] == "86")
            .unwrap();
        assert_eq!(addr["fields"]["number"], "12345678901");
        assert_eq!(addr["fields"]["international"], true);
        let url = d(&pc("81 03 01 15 00 82 02 81 82 B1 05 68 74 74 70 3A"));
        assert_eq!(url["elements"][2]["fields"]["url"], "http:");
        let apn = d(&pc(
            "81 03 01 40 01 82 02 81 82 C7 08 03 77 77 77 03 63 6F 6D 00",
        ));
        assert_eq!(apn["elements"][2]["name"], "Network Access Name");
        assert_eq!(apn["elements"][2]["fields"]["apn"], "www.com");
        let ev = d(&pc("81 03 01 05 00 82 02 81 82 99 03 05 07 0A"));
        assert_eq!(
            ev["elements"][2]["fields"]["events"],
            json!([
                "idle screen available",
                "language selection",
                "channel status"
            ])
        );
        let loc = d(&pc("81 03 01 26 00 82 02 81 82 93 07 00 F1 10 00 01 00 02"));
        assert_eq!(loc["elements"][2]["fields"]["plmn"], "001-01");
        // PROVIDE LOCAL INFORMATION qualifiers and a command with named bit flags.
        assert_eq!(
            d(&pc("81 03 01 26 03 82 02 81 82"))["elements"][0]["fields"]["qualifier_meaning"][0],
            "date, time and time zone"
        );
        let sel = d(&pc("81 03 01 24 81 82 02 81 82"));
        assert_eq!(
            sel["elements"][0]["fields"]["qualifier_meaning"],
            json!([
                "presentation type is specified",
                "help information available"
            ])
        );
    }

    #[test]
    fn unknown_elements_are_kept_as_hex_and_malformed_input_is_an_error() {
        let v = d(&pc("81 03 01 21 00 FE 03 AA BB CC"));
        assert_eq!(v["elements"][1]["decoded"], false);
        assert_eq!(v["elements"][1]["hex"], "AABBCC");
        assert_eq!(v["undecoded_elements"], 1);
        assert!(decode(&[]).is_err());
        assert!(matches!(
            decode(&[0xD0, 0x05, 0x81]),
            Err(Error::Truncated { .. })
        ));
        assert!(matches!(
            decode(&parse_hex("D0 03 81 03 01").unwrap()),
            Err(Error::Truncated { .. })
        ));
        assert!(parse_hex("zz").is_err());
        // The long length forms.
        let mut long = vec![0xD0, 0x81, 0x84, 0x81, 0x03, 0x01, 0x21, 0x00];
        long.extend([0xFE, 0x81, 0x7C]);
        long.extend(vec![0u8; 0x7C]);
        assert_eq!(decode(&long).unwrap().json["elements"][1]["length"], 0x7C);
    }

    #[test]
    fn text_codings() {
        // "hello" GSM 7-bit packed: E8 32 9B FD 06
        assert_eq!(
            text_with_dcs(0x00, &[0xE8, 0x32, 0x9B, 0xFD, 0x06]).0,
            "hello"
        );
        assert_eq!(text_with_dcs(0x08, &[0x00, 0x48, 0x00, 0x69]).0, "Hi");
        assert_eq!(alpha(&[0x80, 0x00, 0x41]), "A");
        assert_eq!(alpha(b"Call"), "Call");
    }

    #[test]
    fn render_names_each_element() {
        let text = render(&decode(&parse_hex(DISPLAY_TEXT).unwrap()).unwrap());
        assert!(
            text.starts_with("proactive-command: DISPLAY TEXT"),
            "{text}"
        );
        assert!(text.contains("Command Details"), "{text}");
        assert!(text.contains("text=HI!"), "{text}");
    }
}
