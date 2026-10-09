//! pcap / pcapng reader for `sim-doctor trace`: pulls GSMTAP SIM APDUs out of
//! a capture and returns them as the decoder's usual command/response pairs.
//!
//! Hand-written subset, no pcap crate: classic pcap and pcapng (SHB, IDB, EPB,
//! SPB) over Ethernet, BSD loopback, raw IP, Linux cooked v1/v2, then IPv4
//! (unfragmented) and UDP to port 4729. IPv6 and other link types are skipped.
//!
//! Sources (primary, checked 2026-10-10):
//! - GSMTAP header, `GSMTAP_TYPE_SIM` (0x04) and `GSMTAP_SIM_*` sub-types:
//!   osmocom/libosmocore `include/osmocom/core/gsmtap.h`.
//! - Pairing: osmocom/pysim `pySim/apdu_source/gsmtap.py` handles only the
//!   `apdu` sub-type (a complete APDU in ONE packet: "CLA INS P1 P2 P3 DATA SW",
//!   see `ApduCommand.from_bytes` in `pySim/apdu/__init__.py`), treats `atr` as
//!   a card reset and ignores PPS. The TPDU sub-types (header, body, SW in
//!   separate packets) are rejected by pySim-trace and skipped here too.
//! - pcap: libpcap `pcap-savefile(5)`; pcapng: IETF draft-ietf-opsawg-pcapng.

use super::Pair;

const GSMTAP_PORT: u16 = 4729;
const GSMTAP_VERSION: u8 = 2;
const GSMTAP_TYPE_SIM: u8 = 0x04;
const GSMTAP_SIM_APDU: u8 = 0x00;
const GSMTAP_HDR_MIN: usize = 16;

/// True when `bytes` start with a classic pcap or pcapng magic number.
pub fn is_capture(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..4),
        Some(
            [0xD4, 0xC3, 0xB2, 0xA1]
                | [0xA1, 0xB2, 0xC3, 0xD4]
                | [0x4D, 0x3C, 0xB2, 0xA1]
                | [0xA1, 0xB2, 0x3C, 0x4D]
                | [0x0A, 0x0D, 0x0D, 0x0A]
        )
    )
}

/// Reads a pcap or pcapng capture into command/response pairs.
///
/// # Errors
///
/// A sentence for a truncated or malformed file, or a capture with no GSMTAP
/// SIM APDU in it. Never panics.
pub fn parse(bytes: &[u8]) -> Result<Vec<Pair>, String> {
    let mut apdus = Vec::new();
    if bytes.get(..4) == Some(&[0x0A, 0x0D, 0x0D, 0x0A]) {
        pcapng(bytes, &mut apdus)?;
    } else {
        classic(bytes, &mut apdus)?;
    }
    if apdus.is_empty() {
        return Err("the capture holds no GSMTAP SIM APDU packets (UDP port 4729, GSMTAP type SIM, sub-type APDU)".into());
    }
    Ok(apdus.iter().filter_map(|a| split_apdu(a)).collect())
}

#[derive(Clone, Copy)]
struct Order(bool); // true = little endian

impl Order {
    fn u16(self, b: &[u8]) -> Option<u16> {
        let a: [u8; 2] = b.get(..2)?.try_into().ok()?;
        Some(if self.0 {
            u16::from_le_bytes(a)
        } else {
            u16::from_be_bytes(a)
        })
    }
    fn u32(self, b: &[u8]) -> Option<u32> {
        let a: [u8; 4] = b.get(..4)?.try_into().ok()?;
        Some(if self.0 {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }
}

const TRUNCATED: &str = "the capture is truncated or malformed";

fn classic(b: &[u8], out: &mut Vec<Vec<u8>>) -> Result<(), String> {
    let le = match b.get(..4) {
        Some([0xD4, 0xC3, 0xB2, 0xA1] | [0x4D, 0x3C, 0xB2, 0xA1]) => true,
        Some([0xA1, 0xB2, 0xC3, 0xD4] | [0xA1, 0xB2, 0x3C, 0x4D]) => false,
        _ => return Err("not a pcap file".into()),
    };
    let o = Order(le);
    let link = o.u32(b.get(20..).ok_or(TRUNCATED)?).ok_or(TRUNCATED)?;
    let mut pos = 24;
    while pos < b.len() {
        let hdr = b.get(pos..pos + 16).ok_or(TRUNCATED)?;
        let incl = o.u32(&hdr[8..]).ok_or(TRUNCATED)? as usize;
        let data = b
            .get(pos + 16..pos.saturating_add(16).saturating_add(incl))
            .ok_or(TRUNCATED)?;
        if let Some(apdu) = gsmtap_apdu(link, data) {
            out.push(apdu);
        }
        pos += 16 + incl;
    }
    Ok(())
}

fn pcapng(b: &[u8], out: &mut Vec<Vec<u8>>) -> Result<(), String> {
    let mut o = Order(true);
    let mut links: Vec<u32> = Vec::new();
    let mut pos = 0;
    while pos < b.len() {
        let head = b.get(pos..pos + 8).ok_or(TRUNCATED)?;
        // A section header carries the byte order of its own section.
        if head[..4] == [0x0A, 0x0D, 0x0D, 0x0A] {
            o = match b.get(pos + 8..pos + 12).ok_or(TRUNCATED)? {
                [0x4D, 0x3C, 0x2B, 0x1A] => Order(true),
                [0x1A, 0x2B, 0x3C, 0x4D] => Order(false),
                _ => return Err("pcapng section header has a bad byte-order magic".into()),
            };
            links.clear();
        }
        let kind = o.u32(head).ok_or(TRUNCATED)?;
        let total = o.u32(&head[4..]).ok_or(TRUNCATED)? as usize;
        if total < 12 || total % 4 != 0 {
            return Err("pcapng block has an invalid length".into());
        }
        let body = b.get(pos + 8..pos + total - 4).ok_or(TRUNCATED)?;
        match kind {
            1 => links.push(u32::from(o.u16(body).ok_or(TRUNCATED)?)),
            6 => {
                let iface = o.u32(body).ok_or(TRUNCATED)? as usize;
                let cap = o.u32(body.get(12..).ok_or(TRUNCATED)?).ok_or(TRUNCATED)? as usize;
                let data = body.get(20..).and_then(|d| d.get(..cap)).ok_or(TRUNCATED)?;
                if let Some(apdu) = links.get(iface).and_then(|&l| gsmtap_apdu(l, data)) {
                    out.push(apdu);
                }
            }
            3 => {
                let orig = o.u32(body).ok_or(TRUNCATED)? as usize;
                let data = body.get(4..).ok_or(TRUNCATED)?;
                let data = &data[..orig.min(data.len())];
                if let Some(apdu) = links.first().and_then(|&l| gsmtap_apdu(l, data)) {
                    out.push(apdu);
                }
            }
            _ => {}
        }
        pos += total;
    }
    Ok(())
}

/// The APDU bytes of one captured frame, or None when it is not GSMTAP SIM APDU.
fn gsmtap_apdu(link: u32, frame: &[u8]) -> Option<Vec<u8>> {
    let ip = match link {
        1 => {
            let ethertype = frame.get(12..14)?;
            (ethertype == [0x08, 0x00]).then_some(())?;
            frame.get(14..)?
        }
        0 => frame.get(4..)?,    // BSD loopback: 4-byte address family
        101 | 12 => frame,       // raw IP
        113 => frame.get(16..)?, // Linux cooked v1
        276 => frame.get(20..)?, // Linux cooked v2
        _ => return None,
    };
    let ihl = usize::from(ip.first()? & 0x0F) * 4;
    if ip[0] >> 4 != 4 || ihl < 20 || *ip.get(9)? != 17 {
        return None;
    }
    let frag = u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]);
    if frag & 0x3FFF != 0 {
        return None; // fragmented; GSMTAP SIM APDUs are tiny
    }
    let udp = ip.get(ihl..)?;
    if u16::from_be_bytes([*udp.get(2)?, *udp.get(3)?]) != GSMTAP_PORT {
        return None;
    }
    let g = udp.get(8..)?;
    let hdr_len = usize::from(*g.get(1)?) * 4;
    if g.len() < GSMTAP_HDR_MIN
        || g[0] != GSMTAP_VERSION
        || hdr_len < GSMTAP_HDR_MIN
        || g[2] != GSMTAP_TYPE_SIM
        || g[12] != GSMTAP_SIM_APDU
    {
        return None;
    }
    Some(g.get(hdr_len..)?.to_vec())
}

/// INS values whose DATA field belongs to the command (cases 3 and 4). pySim
/// knows this per command class; for the rest the data is response data.
const CMD_DATA_INS: &[u8] = &[
    0x10, 0x14, 0x20, 0x24, 0x26, 0x28, 0x2C, 0x82, 0x88, 0x89, 0xA4, 0xC2, 0xD6, 0xDA, 0xDC, 0xD8,
    0xE2, 0xE4, 0xE6, 0xE8, 0xF0, 0xF2,
];

/// Splits "CLA INS P1 P2 P3 DATA SW" into command and response bytes.
fn split_apdu(a: &[u8]) -> Option<Pair> {
    if a.len() < 7 {
        return None; // header + SW at least
    }
    let cmd_len = if CMD_DATA_INS.contains(&a[1]) {
        (5 + usize::from(a[4])).min(a.len() - 2)
    } else {
        5
    };
    Some((None, a[..cmd_len].to_vec(), a[cmd_len..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GSMTAP v2 header, type SIM, given sub-type, then the payload.
    fn gsmtap(sub: u8, payload: &[u8]) -> Vec<u8> {
        let mut g = vec![
            2,
            4,
            GSMTAP_TYPE_SIM,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            sub,
            0,
            0,
            0,
        ];
        g.extend_from_slice(payload);
        g
    }

    /// Ethernet + IPv4 + UDP around `payload`.
    fn frame(port: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0; 12];
        f.extend_from_slice(&[0x08, 0x00]);
        let total = (20 + 8 + payload.len()) as u16;
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1]);
        f.extend_from_slice(&[0x12, 0x34]);
        f.extend_from_slice(&port.to_be_bytes());
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    fn frames() -> Vec<Vec<u8>> {
        vec![
            frame(4729, &gsmtap(1, &[0x3B, 0x9F])), // ATR: skipped
            frame(
                4729,
                &gsmtap(0, &[0xA0, 0xA4, 0, 0, 2, 0x3F, 0x00, 0x9F, 0x16]),
            ),
            frame(
                5000,
                &gsmtap(0, &[0xA0, 0xA4, 0, 0, 2, 0x7F, 0x20, 0x90, 0x00]),
            ), // wrong port
            frame(
                4729,
                &gsmtap(0, &[0xA0, 0xB0, 0, 0, 2, 0xAA, 0xBB, 0x90, 0x00]),
            ),
        ]
    }

    fn classic_file(le: bool) -> Vec<u8> {
        let w32 = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
        let mut f = w32(0xA1B2C3D4).to_vec();
        if le {
            f = vec![0xD4, 0xC3, 0xB2, 0xA1];
        }
        f.extend_from_slice(&[0; 4 + 4 + 4]);
        f.extend_from_slice(&w32(65535));
        f.extend_from_slice(&w32(1));
        for fr in frames() {
            f.extend_from_slice(&[0; 8]);
            f.extend_from_slice(&w32(fr.len() as u32));
            f.extend_from_slice(&w32(fr.len() as u32));
            f.extend_from_slice(&fr);
        }
        f
    }

    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        let pad = (4 - body.len() % 4) % 4;
        let total = (12 + body.len() + pad) as u32;
        let mut b = kind.to_le_bytes().to_vec();
        b.extend_from_slice(&total.to_le_bytes());
        b.extend_from_slice(body);
        b.extend_from_slice(&vec![0; pad]);
        b.extend_from_slice(&total.to_le_bytes());
        b
    }

    fn pcapng_file() -> Vec<u8> {
        let mut shb = vec![0x4D, 0x3C, 0x2B, 0x1A, 1, 0, 0, 0];
        shb.extend_from_slice(&u64::MAX.to_le_bytes());
        let mut f = block(0x0A0D0D0A, &shb);
        f.extend(block(1, &[1, 0, 0, 0, 0xFF, 0xFF, 0, 0]));
        for fr in frames() {
            let mut epb = vec![0; 4 + 8];
            epb.extend_from_slice(&(fr.len() as u32).to_le_bytes());
            epb.extend_from_slice(&(fr.len() as u32).to_le_bytes());
            epb.extend_from_slice(&fr);
            f.extend(block(6, &epb));
        }
        // one simple packet block, too
        let fr = frame(
            4729,
            &gsmtap(0, &[0xA0, 0xF2, 0x80, 0x00, 0x00, 0x6A, 0x82]),
        );
        let mut spb = (fr.len() as u32).to_le_bytes().to_vec();
        spb.extend_from_slice(&fr);
        f.extend(block(3, &spb));
        f
    }

    fn hex(p: &Pair) -> (String, String) {
        (hex::encode_upper(&p.1), hex::encode_upper(&p.2))
    }

    #[test]
    fn classic_pcap_both_byte_orders() {
        for le in [true, false] {
            let pairs = parse(&classic_file(le)).unwrap();
            assert_eq!(pairs.len(), 2, "ATR and wrong-port packets are skipped");
            assert_eq!(hex(&pairs[0]), ("A0A40000023F00".into(), "9F16".into()));
            assert_eq!(hex(&pairs[1]), ("A0B0000002".into(), "AABB9000".into()));
        }
    }

    #[test]
    fn capture_feeds_the_decoder_unchanged() {
        let rows = crate::trace::decode(&crate::trace::parse_bytes(&classic_file(true)).unwrap());
        assert_eq!(rows[0].name, "SELECT");
        assert_eq!(rows[1].name, "READ BINARY");
        assert_eq!(rows[1].selected, "3F00");
    }

    #[test]
    fn pcapng_epb_and_spb() {
        let pairs = parse(&pcapng_file()).unwrap();
        assert_eq!(pairs.len(), 3);
        assert_eq!(hex(&pairs[1]), ("A0B0000002".into(), "AABB9000".into()));
        assert_eq!(hex(&pairs[2]), ("A0F2800000".into(), "6A82".into()));
    }

    #[test]
    fn capture_without_gsmtap_sim_apdu_is_an_error() {
        let only_atr = vec![frame(4729, &gsmtap(1, &[0x3B]))];
        let mut f = classic_file(true)[..24].to_vec();
        for fr in only_atr {
            f.extend_from_slice(&[0; 8]);
            f.extend_from_slice(&(fr.len() as u32).to_le_bytes());
            f.extend_from_slice(&(fr.len() as u32).to_le_bytes());
            f.extend_from_slice(&fr);
        }
        assert!(parse(&f).unwrap_err().contains("no GSMTAP SIM APDU"));
    }

    #[test]
    fn truncated_and_garbage_input_never_panics() {
        for file in [classic_file(true), classic_file(false), pcapng_file()] {
            for n in 0..file.len() {
                let _ = parse(&file[..n]);
            }
            // flip every byte once
            for i in 0..file.len() {
                let mut m = file.clone();
                m[i] ^= 0xFF;
                let _ = parse(&m);
            }
        }
        // xorshift garbage behind each magic
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        for magic in [
            &[0xD4u8, 0xC3, 0xB2, 0xA1][..],
            &[0x0A, 0x0D, 0x0D, 0x0A],
            &[0xA1, 0xB2, 0xC3, 0xD4],
        ] {
            for len in 0..200 {
                let mut g = magic.to_vec();
                for _ in 0..len {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    g.push(x as u8);
                }
                let _ = parse(&g);
            }
        }
        assert!(parse(&[0xD4, 0xC3, 0xB2, 0xA1, 1]).is_err());
        assert!(parse(&pcapng_file()[..40]).is_err());
    }
}
