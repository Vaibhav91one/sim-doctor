//! Offline APDU trace decoder: command/response hex in, named exchanges out,
//! with the currently selected file tracked. Sends nothing, needs no card.
//!
//! **Owns.** Parsing a trace (stdin hex pairs, or our own `--trace` JSON) and
//! naming each command. The command set follows pySim's `pySim/apdu`
//! (osmocom/pysim@3c437d4: ISO 7816-4, TS 102 221, TS 31.102) plus
//! GlobalPlatform; the code is written here, not copied. Status words reuse
//! [`crate::apdu::StatusWord`].
//!
//! **Not done.** pcap/GSMTAP input (follow-up of issue #109). The selected
//! file is tracked from SELECT parameters only; whether a FID is a DF or an EF
//! is guessed from its first octet (3F/7F/5F are DFs), because the FCP is not
//! read.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "trace";

use serde_json::{json, Value};

use crate::apdu::{Command, StatusWord};

/// One parsed exchange: optional label, command bytes, response bytes.
pub type Pair = (Option<String>, Vec<u8>, Vec<u8>);

/// One decoded command/response pair.
#[derive(Debug, Clone)]
pub struct Decoded {
    /// Optional label carried by our own trace JSON (`select`, `cplc`, ...).
    pub step: Option<String>,
    /// Command hex, upper case.
    pub command: String,
    /// Response hex, upper case; empty when the trace ended on a command.
    pub response: String,
    /// Instruction name, e.g. `SELECT`.
    pub name: String,
    /// Parameter and data summary.
    pub detail: String,
    /// Status word hex, when the response had one.
    pub status: Option<String>,
    /// What the status word means.
    pub meaning: String,
    /// The selected file after this exchange.
    pub selected: String,
}

impl Decoded {
    /// The machine-readable form (additive `data.exchanges[]` entries).
    pub fn to_json(&self, index: usize) -> Value {
        json!({
            "index": index,
            "step": self.step,
            "command": self.command,
            "response": self.response,
            "name": self.name,
            "detail": self.detail,
            "status": self.status,
            "status_meaning": self.meaning,
            "selected": self.selected,
        })
    }
}

/// Reads a trace: JSON (array of `{step,command,response}`, `{trace:[..]}` or a
/// full `gp info --json --trace` envelope), otherwise hex lines alternating
/// command, response. `#` starts a comment; spaces inside hex are ignored.
///
/// # Errors
///
/// A sentence naming the first thing that is not hex or not a trace.
pub fn parse(input: &str) -> Result<Vec<Pair>, String> {
    let text = input.trim_start();
    if text.starts_with('{') || text.starts_with('[') {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("trace JSON: {e}"))?;
        let steps = [
            &v,
            &v["trace"],
            &v["data"]["trace"],
            &v["payload"]["data"]["trace"],
        ]
        .into_iter()
        .find_map(Value::as_array)
        .ok_or("trace JSON has no trace array (expected [..], trace, or data.trace)")?;
        return steps
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let field = |k: &str| {
                    hex::decode(s[k].as_str().unwrap_or("").replace(' ', ""))
                        .map_err(|e| format!("trace[{i}].{k}: {e}"))
                };
                Ok((
                    s["step"].as_str().map(str::to_owned),
                    field("command")?,
                    field("response")?,
                ))
            })
            .collect();
    }
    let mut lines = Vec::new();
    for (n, line) in input.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("");
        let compact: String = line.split_whitespace().collect();
        if compact.is_empty() {
            continue;
        }
        lines.push(hex::decode(&compact).map_err(|e| format!("line {}: {e}", n + 1))?);
    }
    Ok(lines
        .chunks(2)
        .map(|p| (None, p[0].clone(), p.get(1).cloned().unwrap_or_default()))
        .collect())
}

/// Decodes a parsed trace, carrying the selected file across exchanges.
pub fn decode(pairs: &[Pair]) -> Vec<Decoded> {
    let mut sel = Selected::default();
    pairs
        .iter()
        .map(|(step, cmd, rsp)| decode_one(&mut sel, step.clone(), cmd, rsp))
        .collect()
}

#[derive(Default)]
struct Selected {
    path: Vec<String>,
    last_is_ef: bool,
}

impl Selected {
    fn show(&self) -> String {
        if self.path.is_empty() {
            "(none)".into()
        } else {
            self.path.join("/")
        }
    }

    fn select_fid(&mut self, fid: u16) {
        let s = format!("{fid:04X}");
        match fid >> 8 {
            0x3F => {
                self.path = vec![s];
                self.last_is_ef = false;
            }
            hi @ (0x7F | 0x5F) => {
                if hi == 0x7F {
                    self.path.truncate(1);
                } else if self.last_is_ef {
                    self.path.pop();
                }
                if self.path.is_empty() {
                    self.path.push("3F00".into());
                }
                self.path.push(s);
                self.last_is_ef = false;
            }
            _ => {
                if self.last_is_ef {
                    self.path.pop();
                }
                self.path.push(s);
                self.last_is_ef = true;
            }
        }
    }
}

fn hex_short(b: &[u8]) -> String {
    if b.len() > 24 {
        format!(
            "{}...(+{} bytes)",
            hex::encode_upper(&b[..24]),
            b.len() - 24
        )
    } else {
        hex::encode_upper(b)
    }
}

/// Instructions whose data field is a secret: PIN/PUK (20/24/26/28/2C), PUT KEY
/// (D8) and EXTERNAL AUTHENTICATE (82, a cryptogram). AUTHENTICATE (88) carries
/// RAND/AUTN in the command (not secret) but CK/IK in the response (secret).
fn secret_command(cmd: &[u8]) -> bool {
    cmd.len() > 4 && matches!(cmd[1], 0x20 | 0x24 | 0x26 | 0x28 | 0x2C | 0xD8 | 0x82)
}

fn redact_command(cmd: &[u8]) -> String {
    if secret_command(cmd) {
        format!(
            "{} <{} bytes redacted>",
            hex::encode_upper(&cmd[..4]),
            cmd.len() - 4
        )
    } else {
        hex::encode_upper(cmd)
    }
}

fn redact_response(cmd: &[u8], rsp: &[u8]) -> String {
    let secret = secret_command(cmd) || cmd.get(1) == Some(&0x88);
    if secret && rsp.len() > 2 {
        let n = rsp.len() - 2;
        format!("<{n} bytes redacted> {}", hex::encode_upper(&rsp[n..]))
    } else {
        hex::encode_upper(rsp)
    }
}

fn decode_one(sel: &mut Selected, step: Option<String>, cmd: &[u8], rsp: &[u8]) -> Decoded {
    let status =
        (rsp.len() >= 2).then(|| StatusWord::from_bytes([rsp[rsp.len() - 2], rsp[rsp.len() - 1]]));
    let body = &rsp[..rsp.len().saturating_sub(2)];
    let (name, detail) = match Command::decode(cmd) {
        Ok(c) => {
            let h = c.header();
            let head = [h.class(), h.instruction(), h.parameter_1(), h.parameter_2()];
            describe(sel, head, c.body().data(), body, status)
        }
        Err(e) => ("UNKNOWN".into(), format!("not a command APDU: {e}")),
    };
    Decoded {
        step,
        command: redact_command(cmd),
        response: redact_response(cmd, rsp),
        name,
        detail,
        status: status.map(|s| s.to_string()),
        meaning: status.map_or_else(|| "no status word".into(), sw_meaning),
        selected: sel.show(),
    }
}

/// What a status word means: specific values first, then the shared
/// [`StatusWord`] classification.
pub fn sw_meaning(sw: StatusWord) -> String {
    let (a, b) = (sw.sw1(), sw.sw2());
    let known = match (a, b) {
        (0x90, 0x00) => "success",
        (0x62, 0x83) => "selected file invalidated",
        (0x63, 0xC0..=0xCF) => return format!("verification failed, {} tries left", b & 0x0F),
        (0x67, 0x00) => "wrong length",
        (0x69, 0x82) => "security status not satisfied",
        (0x69, 0x83) => "authentication method blocked",
        (0x69, 0x84) => "referenced data invalidated",
        (0x69, 0x85) => "conditions of use not satisfied",
        (0x6A, 0x82) => "file or application not found",
        (0x6A, 0x83) => "record not found",
        (0x6A, 0x86) => "incorrect P1-P2",
        (0x6B, 0x00) => "wrong parameters P1-P2",
        (0x6D, 0x00) => "instruction not supported",
        (0x6E, 0x00) => "class not supported",
        (0x6F, 0x00) => "no precise diagnosis",
        (0x94, 0x00) => "no EF selected",
        (0x94, 0x04) => "file ID not found",
        (0x98, 0x04) => "access condition not fulfilled / auth failed",
        (0x98, 0x40) => "PIN blocked",
        (0x61 | 0x9F, n) => {
            let n = if n == 0 { 256 } else { u16::from(n) };
            return format!("{n} response bytes available (GET RESPONSE)");
        }
        (0x6C, n) => return format!("wrong Le, card wants {n:02X}"),
        (0x91, n) => return format!("success, proactive command pending, {n} bytes (FETCH)"),
        _ => "",
    };
    if known.is_empty() {
        format!("{:?} status", sw.class())
    } else {
        known.into()
    }
}

fn be16(d: &[u8]) -> Option<u16> {
    (d.len() == 2).then(|| u16::from_be_bytes([d[0], d[1]]))
}

/// PIN key reference (TS 102 221 clause 9.5.1, as used by VERIFY and friends).
fn key_ref(p2: u8) -> String {
    match p2 {
        0x01..=0x08 => format!("PIN appl {p2}"),
        0x0A..=0x0E => format!("ADM {}", p2 - 9),
        0x8A..=0x8E => format!("ADM {}", p2 - 0x84),
        0x11 => "universal PIN".into(),
        0x81..=0x88 => format!("2nd PIN appl {}", p2 - 0x80),
        _ => format!("key ref {p2:02X}"),
    }
}

/// Length-prefixed fields from the front of `d`, named in order, as hex.
fn lv_fields(d: &[u8], names: &[&str]) -> String {
    let mut rest = d;
    let mut out = Vec::new();
    for n in names {
        let Some((&l, tail)) = rest.split_first() else {
            break;
        };
        let l = usize::from(l);
        if tail.len() < l {
            break;
        }
        out.push(format!("{n}={}", hex::encode_upper(&tail[..l])));
        rest = &tail[l..];
    }
    out.join(" ")
}

fn proactive_type(t: u8) -> &'static str {
    match t {
        0x01 => "REFRESH",
        0x05 => "SET UP EVENT LIST",
        0x10 => "SET UP CALL",
        0x11 => "SEND SS",
        0x12 => "SEND USSD",
        0x13 => "SEND SHORT MESSAGE",
        0x14 => "SEND DTMF",
        0x15 => "LAUNCH BROWSER",
        0x20 => "PLAY TONE",
        0x21 => "DISPLAY TEXT",
        0x22 => "GET INKEY",
        0x23 => "GET INPUT",
        0x24 => "SELECT ITEM",
        0x25 => "SET UP MENU",
        0x26 => "PROVIDE LOCAL INFORMATION",
        0x27 => "TIMER MANAGEMENT",
        0x28 => "SET UP IDLE MODE TEXT",
        0x30 => "RUN AT COMMAND",
        0x40 => "OPEN CHANNEL",
        0x41 => "CLOSE CHANNEL",
        0x42 => "RECEIVE DATA",
        0x43 => "SEND DATA",
        0x44 => "GET CHANNEL STATUS",
        _ => "unknown proactive command",
    }
}

/// Command type from the command-details TLV (tag 01 or 81, length 3) at the
/// front of a proactive command (`D0 ..`) or a terminal response.
fn command_details_type(d: &[u8]) -> Option<u8> {
    let d = match d {
        [0xD0, 0x81, _, rest @ ..] | [0xD0, _, rest @ ..] => rest,
        _ => d,
    };
    match d {
        [0x01 | 0x81, 0x03, _, t, ..] => Some(*t),
        _ => None,
    }
}

fn describe(
    sel: &mut Selected,
    h: [u8; 4],
    data: &[u8],
    rsp: &[u8],
    sw: Option<StatusWord>,
) -> (String, String) {
    let [cla, ins, p1, p2] = h;
    let ok = sw.is_some_and(|s| s.is_normal_processing());
    // GET STATUS shares INS F2 with UICC STATUS; P1 tells them apart.
    // GP only at CLA 80/84; CLA 00 E2/E4/82 are ISO (APPEND RECORD, DELETE FILE, EXTERNAL AUTHENTICATE).
    let gp = matches!(cla, 0x80 | 0x84)
        && (matches!(ins, 0xE6 | 0xE8 | 0xD8 | 0xE2 | 0xE4 | 0xF0 | 0x50 | 0x82)
            || (ins == 0xF2 && matches!(p1, 0x80 | 0x40 | 0x20 | 0x10)));
    let n = |s: &str, d: String| (s.to_owned(), d);
    if gp {
        return match ins {
            0xE6 => {
                let (mode, fields): (&str, &[&str]) = match p1 & 0x7F {
                    0x02 => ("for load", &["load_file", "security_domain"]),
                    0x04 => ("for install", &["load_file", "module", "application"]),
                    0x08 => (
                        "for make selectable",
                        &["load_file", "module", "application"],
                    ),
                    0x0C => (
                        "for install and make selectable",
                        &["load_file", "module", "application"],
                    ),
                    0x10 => ("for personalization", &[]),
                    0x20 => ("for registry update", &[]),
                    0x40 => ("for extradition", &["security_domain"]),
                    _ => ("(unknown P1)", &[]),
                };
                n(
                    "GP INSTALL",
                    format!("{mode} {}", lv_fields(data, fields)).trim().into(),
                )
            }
            0xE8 => n(
                "GP LOAD",
                format!(
                    "block {p2}{}, {} bytes",
                    if p1 & 0x80 != 0 { "" } else { " (last)" },
                    data.len()
                ),
            ),
            0xD8 => n(
                "GP PUT KEY",
                format!(
                    "key set version {p1:02X}, key id {p2:02X}, {} bytes (redacted)",
                    data.len()
                ),
            ),
            0xF2 => n(
                "GP GET STATUS",
                match p1 {
                    0x80 => "issuer security domain",
                    0x40 => "applications and SDs",
                    0x20 => "executable load files",
                    _ => "executable load files and modules",
                }
                .into(),
            ),
            0xE2 => n(
                "GP STORE DATA",
                format!("P1={p1:02X} block {p2}, {} bytes", data.len()),
            ),
            0xE4 => n("GP DELETE", hex_short(data)),
            0xF0 => n(
                "GP SET STATUS",
                format!("P1={p1:02X} P2={p2:02X} {}", hex_short(data)),
            ),
            0x50 => n(
                "GP INITIALIZE UPDATE",
                format!("host challenge {}", hex_short(data)),
            ),
            _ => n(
                "GP EXTERNAL AUTHENTICATE",
                format!("security level {p1:02X}, {} bytes", data.len()),
            ),
        };
    }
    match ins {
        0xA4 => {
            let mode = match p1 {
                0x00 => "by file id",
                0x01 => "child DF",
                0x02 => "EF under current DF",
                0x03 => "parent DF",
                0x04 => "by DF name",
                0x08 => "path from MF",
                0x09 => "path from current DF",
                _ => "(P1 unknown)",
            };
            let target = match p1 {
                0x00..=0x02 if data.is_empty() => "MF".to_owned(),
                0x04 => format!("AID {}", hex::encode_upper(data)),
                _ => hex::encode_upper(data),
            };
            if ok {
                match p1 {
                    0x00 if data.is_empty() => sel.select_fid(0x3F00),
                    0x00..=0x02 => {
                        if let Some(fid) = be16(data) {
                            sel.select_fid(fid);
                        }
                    }
                    0x03 => {
                        sel.path.pop();
                        sel.last_is_ef = false;
                    }
                    0x04 => {
                        sel.path = vec![format!("ADF {}", hex::encode_upper(data))];
                        sel.last_is_ef = false;
                    }
                    0x08 | 0x09 => {
                        if p1 == 0x08 {
                            sel.path = vec!["3F00".into()];
                            sel.last_is_ef = false;
                        }
                        for fid in data.chunks_exact(2) {
                            sel.select_fid(u16::from_be_bytes([fid[0], fid[1]]));
                        }
                    }
                    _ => {}
                }
            }
            n("SELECT", format!("{mode} {target}"))
        }
        0xB0 | 0xD6 => {
            let name = if ins == 0xB0 {
                "READ BINARY"
            } else {
                "UPDATE BINARY"
            };
            let d = if p1 & 0x80 != 0 {
                format!("SFI {:02X}, offset {p2}", p1 & 0x1F)
            } else {
                format!("offset {}", u16::from_be_bytes([p1, p2]))
            };
            n(
                name,
                if ins == 0xD6 {
                    format!("{d}, {} bytes", data.len())
                } else {
                    d
                },
            )
        }
        0xB2 | 0xDC => {
            let name = if ins == 0xB2 {
                "READ RECORD"
            } else {
                "UPDATE RECORD"
            };
            let mode = match p2 & 0x07 {
                2 => "next",
                3 => "previous",
                4 => "absolute/current",
                _ => "first/last",
            };
            let sfi = if p2 >> 3 == 0 {
                "current EF".to_owned()
            } else {
                format!("SFI {:02X}", p2 >> 3)
            };
            n(name, format!("record {p1} ({mode}), {sfi}"))
        }
        0x20 | 0x24 | 0x26 | 0x28 | 0x2C => {
            let name = match ins {
                0x20 => "VERIFY PIN",
                0x24 => "CHANGE PIN",
                0x26 => "DISABLE PIN",
                0x28 => "ENABLE PIN",
                _ => "UNBLOCK PIN",
            };
            // PIN and PUK octets are secrets: length only, never the value.
            let d = if data.is_empty() {
                "status query".into()
            } else {
                format!("{} bytes (redacted)", data.len())
            };
            n(name, format!("{}, {d}", key_ref(p2)))
        }
        0x88 => n(
            "AUTHENTICATE",
            format!(
                "{} context, {}",
                match p2 {
                    0x00 => "GSM",
                    0x80 => "UMTS",
                    _ => "other",
                },
                hex_short(data)
            ),
        ),
        0xC0 => n("GET RESPONSE", format!("{} bytes received", rsp.len())),
        0xF2 => n(
            "STATUS",
            format!(
                "{}, {}",
                match p1 {
                    0x00 => "no indication",
                    0x01 => "application initialized",
                    0x02 => "application terminated",
                    _ => "P1 unknown",
                },
                match p2 {
                    0x00 => "return FCP",
                    0x01 => "return DF name",
                    0x0C => "no data",
                    _ => "P2 unknown",
                }
            ),
        ),
        0xCA | 0xCB => {
            let tag = match (p1, p2) {
                (0x9F, 0x7F) => " (CPLC)",
                (0x00, 0x66) => " (card data)",
                (0x00, 0xE0) => " (key information)",
                (0x00, 0x42) => " (IIN)",
                (0x00, 0x45) => " (CIN)",
                _ => "",
            };
            n("GET DATA", format!("tag {p1:02X}{p2:02X}{tag}"))
        }
        0xDA | 0xDB => n(
            "PUT DATA",
            format!("tag {p1:02X}{p2:02X}, {} bytes", data.len()),
        ),
        0xC2 => {
            let kind = match data.first() {
                Some(0xD1) => "SMS-PP download",
                Some(0xD2) => "cell broadcast download",
                Some(0xD3) => "menu selection",
                Some(0xD4) => "call control",
                Some(0xD5) => "MO SMS control",
                Some(0xD6) => "event download",
                Some(0xD7) => "timer expiration",
                Some(0xD9) => "USSD download",
                _ => "unknown envelope",
            };
            n("ENVELOPE", format!("{kind}, {} bytes", data.len()))
        }
        0x12 => n(
            "FETCH",
            command_details_type(rsp).map_or_else(
                || format!("{} bytes", rsp.len()),
                |t| proactive_type(t).to_owned(),
            ),
        ),
        0x14 => {
            let t = command_details_type(data).map_or("unknown", proactive_type);
            n("TERMINAL RESPONSE", format!("to {t}"))
        }
        0x10 => n("TERMINAL PROFILE", format!("{} bytes", data.len())),
        0x70 => n(
            "MANAGE CHANNEL",
            format!("{} channel {p2}", if p1 == 0 { "open" } else { "close" }),
        ),
        0xE2 => n("APPEND RECORD", hex_short(data)),
        0xE4 => n("DELETE FILE", hex_short(data)),
        0x82 => n(
            "EXTERNAL AUTHENTICATE",
            format!("{} bytes (redacted)", data.len()),
        ),
        0x04 => n("DEACTIVATE FILE", String::new()),
        0x44 => n("ACTIVATE FILE", String::new()),
        0xA2 => n("SEARCH RECORD", hex_short(data)),
        0x32 => n("INCREASE", hex_short(data)),
        _ => n(
            "UNKNOWN",
            format!("CLA {cla:02X} INS {ins:02X} P1 {p1:02X} P2 {p2:02X}"),
        ),
    }
}

/// The human table: two lines per exchange.
pub fn render(rows: &[Decoded]) -> String {
    let mut out = String::new();
    for (i, r) in rows.iter().enumerate() {
        out.push_str(&format!(
            "{:>3}  {:<22} {}\n     -> {} {}   [{}]\n",
            i + 1,
            r.name,
            r.detail,
            r.status.as_deref().unwrap_or("----"),
            r.meaning,
            r.selected,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &str) -> Vec<Decoded> {
        decode(&parse(input).unwrap())
    }

    #[test]
    fn select_get_response_read_binary_track_the_file() {
        let rows = run("
            A0A40000023F00   # SELECT MF
            9F16
            A0C0000016
            000000000000000000000000000000000000000000009000
            A0A40000026F07
            9F0F
            A0B0000009
            0102030405060708099000
            A0A40000026F99
            9404
        ");
        assert_eq!(rows[0].name, "SELECT");
        assert_eq!(rows[0].selected, "3F00");
        assert!(rows[0].meaning.contains("response bytes"));
        assert_eq!(rows[1].name, "GET RESPONSE");
        assert_eq!(rows[2].selected, "3F00/6F07");
        assert_eq!(rows[3].name, "READ BINARY");
        assert_eq!(rows[3].detail, "offset 0");
        assert_eq!(rows[3].meaning, "success");
        // A refused SELECT leaves the selection alone.
        assert_eq!(rows[4].selected, "3F00/6F07");
        assert_eq!(rows[4].meaning, "file ID not found");
    }

    #[test]
    fn pin_values_are_redacted_and_retries_decoded() {
        let rows = run("002000010831323334FFFFFFFF\n63C2");
        assert_eq!(rows[0].name, "VERIFY PIN");
        assert!(rows[0].detail.contains("redacted"));
        assert!(!rows[0].detail.contains("31323334"));
        assert_eq!(rows[0].meaning, "verification failed, 2 tries left");
    }

    #[test]
    fn gp_install_and_load() {
        let rows = run("
            80E602000705AABBCCDDEE00
            9000
            80E80000 05 C403010203
            9000
        ");
        assert_eq!(rows[0].name, "GP INSTALL");
        assert!(rows[0].detail.starts_with("for load load_file=AABBCCDDEE"));
        assert_eq!(rows[1].name, "GP LOAD");
        assert_eq!(rows[1].detail, "block 0 (last), 5 bytes");
    }

    #[test]
    fn our_gp_trace_json_decodes() {
        let json = r#"{"data":{"trace":[
            {"step":"select","command":"00A4040008A000000151000000","response":"6A82"}]}}"#;
        let rows = run(json);
        assert_eq!(rows[0].step.as_deref(), Some("select"));
        assert_eq!(rows[0].detail, "by DF name AID A000000151000000");
        assert_eq!(rows[0].meaning, "file or application not found");
        assert_eq!(rows[0].selected, "(none)");
    }

    #[test]
    fn fetch_and_terminal_response_are_named() {
        let rows = run("
            801200000D
            D00B8103012100820281029100
            8014000009 810301210082028281
            9000
        ");
        assert_eq!(rows[0].detail, "DISPLAY TEXT");
        assert_eq!(rows[1].name, "TERMINAL RESPONSE");
        assert_eq!(rows[1].detail, "to DISPLAY TEXT");
    }

    #[test]
    fn bad_hex_is_an_error() {
        assert!(parse("zz").is_err());
        assert!(parse("A0A\n9000").is_err()); // odd-length hex
    }

    #[test]
    fn secrets_never_reach_json() {
        let rows = run("
            002000010831323334FFFFFFFF
            9000
            80D80000 04 CAFEBABE
            9000
            0082000008 DEADBEEF01020304
            9000
            008800 0010 AABBCCDDEEFF00112233445566778899
            DB08 C1C2C3C4C5C6C7C8 9000
        ");
        let out: String = rows
            .iter()
            .enumerate()
            .map(|(i, r)| r.to_json(i + 1).to_string())
            .collect();
        for secret in ["31323334", "CAFEBABE", "DEADBEEF", "C1C2C3C4"] {
            assert!(!out.contains(secret), "{secret} leaked: {out}");
        }
        assert!(out.contains("bytes redacted>"));
        assert!(out.contains("AABBCCDD")); // RAND is not a secret
    }

    #[test]
    fn iso_cla_00_is_not_labelled_gp() {
        let rows = run("00E2000002AABB\n9000\n00E4000002AABB\n9000\n0082000002AABB\n9000");
        assert_eq!(rows[0].name, "APPEND RECORD");
        assert_eq!(rows[1].name, "DELETE FILE");
        assert_eq!(rows[2].name, "EXTERNAL AUTHENTICATE");
    }

    #[test]
    fn truncated_apdu_is_an_unknown_row_and_does_not_desync() {
        let rows = run("00A4\n6700\n00A40000023F00\n9000");
        assert_eq!(rows[0].name, "UNKNOWN");
        assert_eq!(rows[1].selected, "3F00");
    }
}
