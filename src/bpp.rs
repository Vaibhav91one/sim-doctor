//! Bound Profile Package builder (SGP.22 v2.5 section 2.5.4). Library only:
//! nothing here sends a byte.
//!
//! **Owns.** Putting the caller's plaintext blocks in BPP order, protecting
//! them with ONE [`Channel`] (one MAC chain, one encryption counter), cutting
//! them into segments, and wrapping them in the `BF36` / `A0`-`A3` structure
//! ([`Bpp::segments`]).
//!
//! **Does not own.** The ASN.1 of the blocks (`BF23` InitialiseSecureChannelRequest,
//! ConfigureISDP, StoreMetadata, ReplaceSessionKeys), the crypto
//! ([`crate::scp03t`]), or STORE DATA chunking and I/O (`LoadBoundProfilePackage`,
//! 5.7.6, 255 bytes per APDU).
//!
//! # Spec map (SGP.22 v2.5)
//!
//! - 2.5.4: order is `BF23` in clear, `A0` firstSequenceOf87 (ConfigureISDP,
//!   encrypted and MACed, 2.5.4.2), `A1` sequenceOf88 (StoreMetadata, MAC only,
//!   "i.e. not encrypted", 2.5.4.3), optional `A2` secondSequenceOf87
//!   (ReplaceSessionKeys, 2.5.4.4), `A3` sequenceOf86 (the PPP). "The encryption
//!   counter for ICV calculation is incremented each time a TLV with tag '86',
//!   '87' or '88' is received": one counter, and, via SGP.02 4.1.3.3, one MAC
//!   chain, across all of them.
//! - 2.5.3: segments are at most 1020 bytes including tag, length and MAC; 1008
//!   are payload (1 tag + 3 length + 8 MAC); with the mandatory `80` padding an
//!   encrypted segment carries 1007 bytes. A MAC-only `88` has no padding, so it
//!   carries all 1008. The 1007 is the data BEFORE padding.
//! - 2.5.3: after ReplaceSessionKeys the `86` segments use the new keys, an
//!   explicit initial chaining value and a counter reset to 1; without it the
//!   chain simply continues.
//! - 2.5.5: the segment list for LoadBoundProfilePackage.
//!
//! The wrapping TLVs can exceed 65535 bytes, which [`crate::tlv::Length`]
//! cannot hold, so [`ber_length`] is local.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "bpp";

use crate::scp03t::{self, Channel, Protection};

/// Payload bytes in one encrypted segment (`87`, `86`): 1008 less the minimum
/// one byte of padding (2.5.3).
pub const MAX_ENCRYPTED_PAYLOAD: usize = 1007;
/// Payload bytes in one MAC-only segment (`88`): 1020 - 1 tag - 3 length - 8 MAC.
pub const MAX_MAC_ONLY_PAYLOAD: usize = 1008;

const TAG_86: u8 = 0x86;
const TAG_87: u8 = 0x87;
const TAG_88: u8 = 0x88;

/// What went wrong assembling a BPP.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A mandatory block (named) is empty.
    #[error("{0} is empty")]
    Empty(&'static str),
    /// The secure channel refused a segment.
    #[error(transparent)]
    Channel(#[from] scp03t::Error),
}

/// The plaintext blocks of a BPP.
pub struct Input<'a> {
    /// The `BF23` InitialiseSecureChannelRequest TLV, sent in clear (2.5.4.1).
    pub initialise_secure_channel: &'a [u8],
    /// The ConfigureISDP TLV (5.5.2), sent as `87`.
    pub configure_isdp: &'a [u8],
    /// The StoreMetadata TLV (5.5.3), sent as `88`.
    pub store_metadata: &'a [u8],
    /// Optional ReplaceSessionKeys TLV (5.5.4), sent as `87`, plus the channel
    /// built from the new keys (see [`Channel::with_keys`]) that then protects
    /// the `86` segments.
    pub replace_session_keys: Option<(&'a [u8], Channel)>,
    /// The Protected Profile Package payload, cut into `86` segments.
    pub profile_package: &'a [u8],
}

/// A built Bound Profile Package, every protected TLV in wire order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bpp {
    /// `BF23`, in clear.
    pub initialise_secure_channel: Vec<u8>,
    /// The `87` TLVs of `A0`.
    pub first_sequence_of_87: Vec<Vec<u8>>,
    /// The `88` TLVs of `A1`.
    pub sequence_of_88: Vec<Vec<u8>>,
    /// The `87` TLVs of `A2`; empty means `A2` is absent.
    pub second_sequence_of_87: Vec<Vec<u8>>,
    /// The `86` TLVs of `A3`.
    pub sequence_of_86: Vec<Vec<u8>>,
}

/// Builds a BPP, protecting every block with `channel` in BPP order. `channel`
/// must be fresh from [`Channel::new`].
///
/// # Errors
///
/// [`Error::Empty`] for an empty mandatory block; [`Error::Channel`] if the
/// secure channel refuses a segment.
pub fn build(channel: &mut Channel, input: Input<'_>) -> Result<Bpp, Error> {
    for (name, block) in [
        (
            "initialiseSecureChannelRequest",
            input.initialise_secure_channel,
        ),
        ("ConfigureISDP", input.configure_isdp),
        ("StoreMetadata", input.store_metadata),
        ("profile package", input.profile_package),
    ] {
        if block.is_empty() {
            return Err(Error::Empty(name));
        }
    }
    let first = protect_all(
        channel,
        TAG_87,
        input.configure_isdp,
        Protection::EncryptAndMac,
    )?;
    let sequence_of_88 = protect_all(channel, TAG_88, input.store_metadata, Protection::MacOnly)?;
    let (second, mut ppp_channel) = match input.replace_session_keys {
        Some((data, new)) => (
            protect_all(channel, TAG_87, data, Protection::EncryptAndMac)?,
            Some(new),
        ),
        None => (Vec::new(), None),
    };
    let sequence_of_86 = protect_all(
        ppp_channel.as_mut().unwrap_or(channel),
        TAG_86,
        input.profile_package,
        Protection::EncryptAndMac,
    )?;
    Ok(Bpp {
        initialise_secure_channel: input.initialise_secure_channel.to_vec(),
        first_sequence_of_87: first,
        sequence_of_88,
        second_sequence_of_87: second,
        sequence_of_86,
    })
}

fn protect_all(
    channel: &mut Channel,
    tag: u8,
    data: &[u8],
    protection: Protection,
) -> Result<Vec<Vec<u8>>, Error> {
    let max = match protection {
        Protection::EncryptAndMac => MAX_ENCRYPTED_PAYLOAD,
        Protection::MacOnly => MAX_MAC_ONLY_PAYLOAD,
    };
    data.chunks(max)
        .map(|chunk| channel.protect(tag, chunk, protection).map_err(Error::from))
        .collect()
}

/// BER definite length for any size (short form below 128, else the minimal
/// long form).
pub fn ber_length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let bytes = n.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    let mut out = vec![0x80 | (bytes.len() - skip) as u8];
    out.extend_from_slice(&bytes[skip..]);
    out
}

fn header(tag: &[u8], content_len: usize) -> Vec<u8> {
    let mut out = tag.to_vec();
    out.extend(ber_length(content_len));
    out
}

impl Bpp {
    /// The whole `BF36` BoundProfilePackage as one byte string.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.segments().concat()
    }

    /// The segments of 2.5.5, in order, ready for LoadBoundProfilePackage: each
    /// one is sent as its own run of STORE DATA blocks. Segment boundaries:
    /// `BF36` header + `BF23`; `A0` header + first `87`; (further `87`s alone);
    /// `A1` header; each `88`; `A2` header + first `87` and further `87`s, only
    /// when present; `A3` header; each `86`.
    ///
    /// 2.5.5 names the first `87` of a sequence only; the rest of a sequence
    /// is cut one TLV per segment as well (an interpretation, the clause is
    /// silent).
    pub fn segments(&self) -> Vec<Vec<u8>> {
        fn total(tlvs: &[Vec<u8>]) -> usize {
            tlvs.iter().map(Vec::len).sum()
        }
        let (a0, a1, a2, a3) = (
            total(&self.first_sequence_of_87),
            total(&self.sequence_of_88),
            total(&self.second_sequence_of_87),
            total(&self.sequence_of_86),
        );
        let a2_present = !self.second_sequence_of_87.is_empty();
        let head = |tag: u8, len: usize| header(&[tag], len);
        let mut inner = self.initialise_secure_channel.len()
            + head(0xA0, a0).len()
            + a0
            + head(0xA1, a1).len()
            + a1
            + head(0xA3, a3).len()
            + a3;
        if a2_present {
            inner += head(0xA2, a2).len() + a2;
        }

        let mut out = vec![[
            header(&[0xBF, 0x36], inner),
            self.initialise_secure_channel.clone(),
        ]
        .concat()];
        let mut group = |head: Vec<u8>, tlvs: &[Vec<u8>], joins_first: bool| {
            let mut iter = tlvs.iter();
            match (joins_first, iter.next()) {
                (true, Some(first)) => out.push([head, first.clone()].concat()),
                (_, first) => {
                    out.push(head);
                    out.extend(first.cloned());
                }
            }
            out.extend(iter.cloned());
        };
        group(head(0xA0, a0), &self.first_sequence_of_87, true);
        group(head(0xA1, a1), &self.sequence_of_88, false);
        if a2_present {
            group(head(0xA2, a2), &self.second_sequence_of_87, true);
        }
        group(head(0xA3, a3), &self.sequence_of_86, false);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scp03::{cmac, BLOCK};
    use crate::scp03t::{derive_keys, Eid, HostId, SessionKeys};
    use aes::cipher::{
        block_padding::NoPadding, BlockCipherEncrypt, BlockModeDecrypt, KeyInit, KeyIvInit,
    };
    use aes::Aes128;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }

    // Same session as the osmocom/pysim known answers in scp03t.rs.
    fn keys() -> SessionKeys {
        derive_keys(
            &h("c9a993dd4879a8f7161f2085410edd4f9652f1df37be097ba96ba2ca6be528fe")
                .try_into()
                .unwrap(),
            &HostId::new(&[0x80; 8]).unwrap(),
            &Eid(h("89049032123451234512345678901235").try_into().unwrap()),
        )
    }

    fn input<'a>(isdp: &'a [u8], meta: &'a [u8], ppp: &'a [u8]) -> Input<'a> {
        Input {
            initialise_secure_channel: &[0xBF, 0x23, 0x01, 0x00],
            configure_isdp: isdp,
            store_metadata: meta,
            replace_session_keys: None,
            profile_package: ppp,
        }
    }

    /// (tag, length bytes, body, wire MAC) of a protected TLV.
    fn parts(tlv: &[u8]) -> (u8, Vec<u8>, Vec<u8>, Vec<u8>) {
        let (len, used) = crate::tlv::Length::decode(&tlv[1..]).unwrap();
        let end = 1 + used;
        assert_eq!(tlv.len(), end + len.value() as usize);
        (
            tlv[0],
            tlv[1..end].to_vec(),
            tlv[end..tlv.len() - 8].to_vec(),
            tlv[tlv.len() - 8..].to_vec(),
        )
    }

    fn decrypt(k: &SessionKeys, counter: u128, body: &[u8]) -> Vec<u8> {
        let mut iv = counter.to_be_bytes().into();
        Aes128::new(&k.enc.into()).encrypt_block(&mut iv);
        let mut buf = body.to_vec();
        cbc::Decryptor::<Aes128>::new(&k.enc.into(), &iv)
            .decrypt_padded::<NoPadding>(&mut buf)
            .unwrap();
        buf
    }

    // (a) One chain. Walks 87, 88, 86 and recomputes each MAC from the PREVIOUS
    // TLV's full CMAC. With a per-tag chain the 88 would be MACed from the
    // initial value and the assertions in the loop would fail.
    #[test]
    fn one_mac_chain_and_one_counter_across_87_88_86() {
        let k = keys();
        let bpp = build(&mut Channel::new(&k), input(&[1; 5], &[2; 40], &[3; 100])).unwrap();
        let tlvs = [
            &bpp.first_sequence_of_87[0],
            &bpp.sequence_of_88[0],
            &bpp.sequence_of_86[0],
        ];
        let mut chain: [u8; BLOCK] = k.icv;
        for (i, tlv) in tlvs.iter().enumerate() {
            let (tag, len, body, mac) = parts(tlv);
            let full = cmac(&k.mac, &[&chain, &[tag], &len, &body]);
            assert_eq!(mac, full[..8], "TLV {i} chains on the previous full CMAC");
            if i > 0 {
                let fresh = cmac(&k.mac, &[&k.icv, &[tag], &len, &body]);
                assert_ne!(
                    mac,
                    fresh[..8],
                    "TLV {i} must not restart from the initial chain"
                );
            }
            chain = full;
        }
        // The counter is shared too: the 86 is the third TLV, so counter 3. The
        // 88 advanced it although it is not encrypted.
        let (_, _, body, _) = parts(tlvs[2]);
        assert_eq!(&decrypt(&k, 3, &body)[..100], &[3; 100]);
        assert_ne!(&decrypt(&k, 1, &body)[..100], &[3; 100]);
    }

    // (b) Segment limits at the boundary: exactly at, one over.
    #[test]
    fn segment_sizes_at_and_over_the_limits() {
        let k = keys();
        for (len, count) in [(1007, 1), (1008, 2), (2014, 2), (2015, 3)] {
            let bpp = build(&mut Channel::new(&k), input(&[1], &[2], &vec![9; len])).unwrap();
            assert_eq!(bpp.sequence_of_86.len(), count, "86 payload {len}");
            assert!(bpp.sequence_of_86.iter().all(|t| t.len() <= 1020));
            assert_eq!(bpp.sequence_of_86[0].len(), 1020);
        }
        // 87 is limited like 86.
        let bpp = build(&mut Channel::new(&k), input(&[1; 1008], &[2], &[3])).unwrap();
        assert_eq!(bpp.first_sequence_of_87.len(), 2);
        assert_eq!(bpp.first_sequence_of_87[0].len(), 1020);
        // 88 is MAC only and carries 1008 bytes, one more than an encrypted one.
        for (len, count) in [(1008, 1), (1009, 2)] {
            let bpp = build(&mut Channel::new(&k), input(&[1], &vec![2; len], &[3])).unwrap();
            assert_eq!(bpp.sequence_of_88.len(), count, "88 payload {len}");
            assert_eq!(bpp.sequence_of_88[0].len(), 1020);
        }
        // The pieces put back together are the input.
        let ppp: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let bpp = build(&mut Channel::new(&k), input(&[1], &[2], &ppp)).unwrap();
        let joined: Vec<u8> = bpp
            .sequence_of_86
            .iter()
            .enumerate()
            .flat_map(|(i, t)| {
                let (_, _, body, _) = parts(t);
                let plain = decrypt(&k, 3 + i as u128, &body);
                let pad = plain.iter().rposition(|b| *b == 0x80).unwrap();
                plain[..pad].to_vec()
            })
            .collect();
        assert_eq!(joined, ppp);
    }

    // (c) 88 is plaintext, the others are not.
    #[test]
    fn tag_88_is_never_encrypted() {
        let k = keys();
        let meta = b"StoreMetadata plaintext marker 0123456789".to_vec();
        let isdp = b"ConfigureISDP plaintext marker 0123456789".to_vec();
        let bpp = build(&mut Channel::new(&k), input(&isdp, &meta, &isdp)).unwrap();
        let t88 = &bpp.sequence_of_88[0];
        assert_eq!(t88[0], 0x88);
        assert!(t88.windows(meta.len()).any(|w| w == meta));
        assert_eq!(t88.len(), 1 + 1 + meta.len() + 8, "no padding on a 88");
        assert!(!bpp.first_sequence_of_87[0]
            .windows(8)
            .any(|w| w == &isdp[..8]));
        assert!(!bpp.sequence_of_86[0].windows(8).any(|w| w == &isdp[..8]));
    }

    // (d) Padding: 80 then zeros, 1 to 16 bytes, so never all zero and a full
    // block when the data is already aligned.
    #[test]
    fn padding_is_one_to_sixteen_bytes_and_starts_with_80() {
        let k = keys();
        for len in 1..=48usize {
            let bpp = build(&mut Channel::new(&k), input(&vec![5; len], &[2], &[3])).unwrap();
            let (_, _, body, _) = parts(&bpp.first_sequence_of_87[0]);
            let plain = decrypt(&k, 1, &body);
            let pad = &plain[len..];
            assert_eq!(&plain[..len], &vec![5; len][..]);
            assert!(
                (1..=16).contains(&pad.len()),
                "len {len}: pad {}",
                pad.len()
            );
            assert_eq!(pad[0], 0x80);
            assert!(pad[1..].iter().all(|b| *b == 0));
            assert_eq!(plain.len() % 16, 0);
        }
    }

    #[test]
    fn replace_session_keys_group_is_87_and_resets_the_86_channel() {
        let k = keys();
        let new = Channel::with_keys([1; 16], [2; 16], [3; 16]);
        let mut inp = input(&[1], &[2], &[3]);
        inp.replace_session_keys = Some((&[9, 9], new.clone()));
        let bpp = build(&mut Channel::new(&k), inp).unwrap();
        assert_eq!(bpp.second_sequence_of_87.len(), 1);
        assert_eq!(bpp.second_sequence_of_87[0][0], 0x87);
        // The 86 comes from the new channel as if it were the first TLV on it.
        let want = new
            .clone()
            .protect(0x86, &[3], Protection::EncryptAndMac)
            .unwrap();
        assert_eq!(bpp.sequence_of_86[0], want);
    }

    #[test]
    fn empty_blocks_are_refused() {
        let k = keys();
        assert_eq!(
            build(&mut Channel::new(&k), input(&[1], &[], &[3])),
            Err(Error::Empty("StoreMetadata"))
        );
    }

    #[test]
    fn ber_length_forms() {
        assert_eq!(ber_length(0x7f), [0x7f]);
        assert_eq!(ber_length(0x80), [0x81, 0x80]);
        assert_eq!(ber_length(0x100), [0x82, 1, 0]);
        assert_eq!(ber_length(70_000), [0x83, 1, 0x11, 0x70]);
    }

    // 2.5.5 segmentation, and the segments joined are one well-formed BF36.
    #[test]
    fn segments_follow_2_5_5_and_concatenate_to_a_well_formed_bf36() {
        let k = keys();
        let mut inp = input(&[1], &[2; 1500], &[3; 2500]);
        inp.replace_session_keys = Some((&[9], Channel::with_keys([1; 16], [2; 16], [3; 16])));
        let bpp = build(&mut Channel::new(&k), inp).unwrap();
        let segs = bpp.segments();
        // BF36+BF23 | A0+87 | A1 | 88 | 88 | A2+87 | A3 | 86 x3
        assert_eq!(segs.len(), 1 + 1 + 1 + 2 + 1 + 1 + 3);
        assert_eq!(&segs[0][..2], &[0xBF, 0x36]);
        assert_eq!(&segs[0][segs[0].len() - 4..], &[0xBF, 0x23, 0x01, 0x00]);
        assert_eq!(segs[2][0], 0xA1);
        assert_eq!(segs[3], bpp.sequence_of_88[0]);
        assert_eq!(segs[5][0], 0xA2);
        assert_eq!(segs[6][0], 0xA3);
        let whole = bpp.to_bytes();
        let (len, n) = crate::tlv::Length::decode(&whole[2..]).unwrap();
        assert_eq!(2 + n + len.value() as usize, whole.len());

        // Without ReplaceSessionKeys there is no A2.
        let plain = build(&mut Channel::new(&k), input(&[1], &[2], &[3])).unwrap();
        assert_eq!(plain.segments().len(), 6);
        assert!(plain.segments().iter().all(|s| s[0] != 0xA2));
    }

    // (e) Known answer, osmocom/pysim tests/unittests/test_esim_bsp.py class
    // BSP_Test_mode51 at commit a3962b2076d157e075262c51e6c4d0a48ba12465 (hex
    // dumps of a third-party SM-DP+): 87, 88, 87 (ReplaceSessionKeys), then two
    // full 86 segments under the replaced keys. The PPP is the two plaintext
    // segments joined, exactly 2 x 1007 bytes, so the builder must cut it at
    // the same place.
    #[test]
    fn known_answer_full_sequence_from_a_third_party_sm_dp() {
        let k = keys();
        let rsk = h("bf26368010000102030405060708090a0b0c0d0e0f8110010102030405060708090a0b0c0d0e0f8210020102030405060708090a0b0c0d0e0f");
        let ppp = [h(SEGMENT0), h(SEGMENT1)].concat();
        let new = Channel::with_keys(
            h("01010203 04050607 08090a0b 0c0d0e0f").try_into().unwrap(),
            h("02010203 04050607 08090a0b 0c0d0e0f").try_into().unwrap(),
            h("00010203 04050607 08090a0b 0c0d0e0f").try_into().unwrap(),
        );
        let meta = h("bf252d5a0a98001032547698103214910947534d415f54455354921147534d415f544553545f50524f46494c45950100");
        let bpp = build(
            &mut Channel::new(&k),
            Input {
                initialise_secure_channel: &[0xBF, 0x23, 0x01, 0x00],
                configure_isdp: &h("bf2400"),
                store_metadata: &meta,
                replace_session_keys: Some((&rsk, new)),
                profile_package: &ppp,
            },
        )
        .unwrap();
        assert_eq!(
            bpp.first_sequence_of_87,
            [h("8718f6fe031e4b9cfe87c8e1e62f3fde85c49412d7722a6a2d89")]
        );
        assert_eq!(bpp.sequence_of_88, [h("8838bf252d5a0a98001032547698103214910947534d415f54455354921147534d415f544553545f50524f46494c459501008a62cc9adbb5ccbc")]);
        assert_eq!(bpp.second_sequence_of_87, [h("8748a14c800a001992351cd46ad2945654674369701d82b7b46567652bc8fbed234939fc57fba748015525fd6c651e9d3d1330652d42a0cfad950e912122af4ec5362d3c0bc535729c40")]);
        assert_eq!(bpp.sequence_of_86, [h(OUT0), h(OUT1)]);
    }

    const SEGMENT0: &str = "a048800102810101821a53494d616c6c69616e63652053616d706c652050726f66696c65830a89000123456789012341a506810084008b00a610060667810f010201060667810f010204b08201f8a0058000810101810667810f010201a207a105c60301020aa305a1038b010fa40c830a98001032547698103214a527a109820442210026800198831a61184f10a0000000871002ff33ff01890000010050045553494da682019ea10a8204422100258002022b831b8001019000800102a406830101950108800158a40683010a95010882010a8316800101a40683010195010880015aa40683010a95010882010f830b80015ba40683010a95010882011a830a800101900080015a970082011b8316800103a406830101950108800158a40683010a95010882010f8316800111a40683010195010880014aa40683010a95010882010f8321800103a406830101950108800158a40683010a950108840132a4068301019501088201048321800101a406830101950108800102a406830181950108800158a40683010a950108820104831b800101900080011aa406830101950108800140a40683010a95010882010a8310800101900080015aa40683010a95010882011583158001019000800118a40683010a95010880014297008201108310800101a40683010195010880015a97008201158316800113a406830101950108800148a40683010a95010882010f830b80015ea40683010a95010882011a83258001019000800102a010a406830101950108a406830102950108800158a40683010a950108a33fa0058000810102a13630118001018108303030303030303082020099300d800102810831323334353637383012800200818108313233343536373882020088a241a0058000810103a138a0363010800101810831323334ffffffff8201013010800102810830303030ffffffff820102301080010a810835363738ffffffff830101a182029ea0058000810104a18202933082028f62228202782183027ff18410a0000000871002ff33ff0189000001008b010ac60301810a62118202412183026f078b01028001098801388109082943019134876765621482044221002583026f068b010a8801b8c7022f06621a8202412183026f088b0105800121880140a507c00180c10207ff621a8202412183026f098b0105800121880148a507c00180c10207ff62168202412183026f318b0102800101880190a503c1010a62118202412183026f388b010280010e880120810d0a2e178ce73204000000000000621982044221001a83026f3b8b0108800202088800a504c10200ff62198204422100b083026f3c8b0105800206e08800a504c10200ff621282044221002683026f428b0105800126";
    const SEGMENT1: &str = "880062158202412183026f438b01058001028800a503c0018062128202412183026f468b036f060a8001118800810c0253494d616c6c69616e636562118202412183026f568b0108800101880128810100621b8202412183026f5b8b0105800106880178a508c00180c203f0000062168202412183026f5c8b0102800103880180a503c0018062168202412183026f738b010580010e880160a503c00180020107810700f1100000ff0162118202412183026f788b01028001028801308102004062118202412183026f7b8b010580010c88016862168202412183026f7e8b010580010b880158a503c0018002010781040000ff0162168202412183026fad8b010a800104880118a503c10100020103810102621382044221000483026fb78b010a800104880108810419f1ff0162158202412183026fc48b01058001808800a503c0018062168202412183026fe38b01058001128801f0a503c0018002010f810300000162168202412183026fe48b01058001508801c0a503c00180a225a0058000810105a11ca01a301880020081810831323334ffffffff82020081830101840122a43aa0058000810106a131a12f8001018101018210000102030405060708090a0b0c0d0e0f83100102030405060708090a0b0c0d0e0f008603010203a681bba0058000810107a1444f07a00000015153504f08a0000001515350414f08a000000151000000820382dc0083010fc90a810280008201f08701f0ea11800f0100000100000002011203b2010000a26c3022950138820101830101301730158001808610112233445566778899aabbccddeeff103022950134820102830101301730158001808610112233445566778899aabbccddeeff1030229501c8820103830101301730158001808610112233445566778899aabbccddeeff10a681c0a0058000810108a1494f07a00000015153504f08a0000001515350414f10a00000055910100102736456616c7565820380800083010fc907810280008201f0ea11800f01000001000000020112036c756500a26c30229501388201018301013017301580018086108811223344556677881122334455667730229501348201028301013017301580018086108811223344556677881122334455667730229501c882010383010130173015800180861088112233445566778811223344556677a8820263a0058000810109a18202184f08a000000559101001c482020a01002edecaffed020204000108a0000005591010011b636f6d2f67736d612f65756963632f746573742f6170706c657431020021002e0021000f003b002a00210066000a000e0000008a040f00000000000004010004003b04030107a0000000620101000110a0000000090005ffffffff";
    const OUT0: &str = "868203f80fd36b066b43e53906b33263c4141d18036fcac7bde47faed79e76514d39f1f405d9785ff04badf379a96bcf4685eb861239da34eeb213d0cd1e0d85e96e36097a52f600907e08b6f01232eb3792a00cc6b3288cc832c7f30357edfe0818d1f39ad8d55b5bd5d9c65917d0d16ee7e1421a44453714d66209bf441425bf6d153a85ba7e7406d58a4c46fb930bb14eefd6a853434619805429cbbb003bd5a56e7bceaf4666eb352ad46f47ea572c6ad311683803db3bec4d783583858f2ecfbaec3ed780fb3e3a645b1bf5cfd1047e5862c4a8877382dabd6aef6fa72ec6378ce7b21502d3267514b29bd589703ee7bd5b1e6d868b6b7c55006bc32406a924f44bfdb6c801d490450a54633bbd66bb0ece8b3a9be09433c537f3e3b2b8e45833365a94479b1895e9ba13387fca116565c267b6bc1274c82510b21ac9fa77574412351468fd1eac8928c9494e5eb8a909d9372476c62e8a2b556b557a79cdb47503ba5d9fd86d1962c23b3289f37df9a05668957df34c37806359af1d8dfecedf9bbf4888be9753f2b449ce4e5cde510572f9be4fb506f329a848c4583ac9ac710e53d512ad504f2e3769c2911c34f84ad0622c5428446d1e9c59bb6b2029f231b05ef45d3ec60fceff121ba684a023037b753f855e1067b8ad02783c04eb81ba47fcec0947bbc9661d90c6f00c0f4e6f9c22e0b25905379f8b265b436a4a74253a64c5734f956d134cf5b6c0671125b20b735f405fee1fc1941ed141734fa6856e898dc655fb91b045b3797d14b97a68ed3480ec137565d6c4d007f95ee705d452d0344ce9e9bbd0712f399ef8604f3f472b403ea64f00c969fd30a012cb8be049c54556994117fc5f6043930107774910be5f47c780427de063a56d45400a814c86dfcc2465262baf273a6ca89e77bb8c73efe2d22d975516b80c648404b10d3f329776a21251bedf445ade24b656e8635f0d7fe39772d942d9432766efb5152c6e990123c52744f1c402962a381ff2aaddaa1bd522a9b65a229f9adcd4099475b3f9ba45161ee35206365181e1d69d263d8d27444a7c3a2d7ddbb398ac5affea28cb0373057dad7741e52adb95822fee5157ce3c0ad978c5231a219ca0726d50eeb0c69d579094a54820194aeef13a365d85c52257f51cb65c567e0cdf1ce38b80eaa4d131ab7086e303c5728cf41a25df954d60ac12400d2a2990e67dbeff866736937beb8fce526be1dd5dc5d77d00b8783b34691a3e9bda7e697eec4cfa70b25914795af23ec6d258530f71402b9230947dc99f9140b16a54ba1291f54ef736de6711c1ae074b627dfc2fc5d5250f812b7ecd1d0f5020a3acf20ad5759cd9e761ce21882977f7db66aaba2d8f5190f6f23996af14b670ccac066c93af06a41f19d9ee712ce13fbe73b99e55401b208b991c8ced12d34c";
    const OUT1: &str = "868203f8648e034ae0dc4ce022ee1e60b130dda95e13b21b0da3de7677677f47900c1beb3637b8aa35f3a9e096c0285ffe3e931983df900b36b7e6bc4b9af14b0ee3d49637eb2d4cff314b5d00789a751dfd9554651fb2b7c66ad4e22a794d5b88cb71ccf4c05d53abeba8bd3b0c8209346f014cbdee62be4878e3fea09a96007135a6c584aa843c48972842bdbece1c439723021b3f0d535d557995beedbd2b56f416148df90cb1a4d2fa26288801d56a2cbb0a404f2fd9a73042d7a3486bfb7256c1d274aae5b7ec24e8eba28b7dce69edc44189b24186b98397b4a74831f8ab46e8e46a2ed3077d4924f5d3f6e4c1de5ddffd194e7f0f97d94ea2801d1364835c9871bae6539e3e1355c5970711d845864f04d9c1dccac0d4068dcf4664e9976509fe43fec6beb3ddc96839aba6d89bb1593c5b6ebbc32fff39c4a5bb3e5c9df6a1abc05818dbd5149733381e69521066e1bbd648eb19b00602767e90beaeb3b3b92679940a603c0500e37892d7b4fa44355c3deec8af207f89d04f83cd88603e9cb9c96f74643816e87af85a8a9d0283cdf535d1fbaefb930fd4a0dba2ae30ee9d2d9e2a31827a012a6380af42ac87f3bfd7079ddd8fa27d2299fb4d5879e9a17a5062e13cab4f7bed22ed54932fa53d630bca8592f957a7ed148e9d4f28075c2565a550694b876091a1181ba512e70fde4f28ae6968a18d721396c0fee9cd7744dee90bf85f5adddb3417b3ede9ea3cfd5eae2d820b17600ce3b95f6df38a5bc39302c5155c3f241ddfc7cee527af7f6a67868a577c39e76e26c4ed5d6aca031a97c280da27ae8de20e57a1dbab40a31e96e054f9a6f50578fd00156e37b70eead71af3258075c1ba84282aea462553504a868443b301ed99dcd5f414b720ef67cf5c4d16f1f7b9df741c2343246dcb717f3fa62b633539bdcc0082d161499caad8d097be78133dafd19777559f77c6d7a8f61323ff660613aa47cee26a4f7515204eee3c7eaa00eb55529b0ddae3436ec679fc591fe2063de94db00b5d0f041beeb80a91f108f7cf4b3b1344b0fbb437630ee437b4c7744c54009a59a9099681f3a3fa386f294c0eb4562581202a369772833efdc6e840695352de3864671e7fb0fd081ec162a2a62ea5b8a9da837f3920b4196fbe2ec912ade440537ae4a07dfc115c9c030539f278e0801bda4f15298ba50e329b18992af8b899686ec97175509d4a217d2eba8feef5f5732fc7be86370f7723896b784bd45517af86a7521e952b6be924d91a5190e3c2c65ce8924df43ddb25c529dde324a722a156df459f4b38bb062975fad9fadd27f6425e422b1abd9a7259f0bd712a486e1aa25ca848cf65c5fb888bf61ae136b68cf55cb643c198537cd83df0dbb842c5f4982ca3088cc2d8e867c3049a84b515ec39b0b774a8482099327006acff";
}
