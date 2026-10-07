//! SCP03t, the secure channel of the SGP.22 Bound Profile Package: key
//! agreement, key derivation, and the MAC and AES-CBC protection of TLV
//! segments. Library only: nothing here sends a byte.
//!
//! **Owns.** ECDH on P-256 ([`shared_secret`]), the X9.63 KDF ([`x963_kdf`]),
//! the SharedInfo layout ([`shared_info`]), the split of the derived key data
//! into ICV / S-ENC / S-MAC ([`derive_keys`]), and the protection of one TLV
//! segment ([`Channel::protect`]).
//!
//! **Does not own.** BPP assembly, segmentation of a profile package, the
//! ES8+ ASN.1 messages, or any card or network I/O. SCP03t is forbidden on
//! the live operator SIM (it is a plain USIM, not an eUICC), so everything
//! here is checked by known-answer vectors only.
//!
//! # Spec map (SGP.22 v2.5 unless stated)
//!
//! - Annex G: ECDH shared secret, SharedInfo, X9.63 KDF with SHA-256, and the
//!   split `1..L` initial MAC chaining value, `L+1..2L` S-ENC, `2L+1..3L`
//!   S-MAC, with `L = 16`.
//! - 5.5.1 (`InitialiseSecureChannel`): `ControlRefTemplate` carries key type
//!   (AES = `0x88`), key length (`0x10`) and the Host ID (`hostId`, 1 to 16
//!   bytes). The EID is a separate value.
//! - 2.5.3 and 2.5.4: padding is `0x80` then zeros, segments are at most 1020
//!   bytes including tag, length and MAC, and the encryption counter for the
//!   ICV is incremented for every tag `0x86`, `0x87` or `0x88` TLV, MAC-only
//!   ones included.
//! - The MAC input, the ICV rule and `Lcc = L + padding + L_MAC` are *not*
//!   spelled out in SGP.22: it points to SGP.02 section 4.1.3.3 (checked
//!   against SGP.02 v4.2.1, figure 46) and, through it, GP Card Spec
//!   Amendment D section 6.2.4 (C-MAC, not fetched) for the CMAC itself. The
//!   ICV block rule (counter, big-endian, encrypted with S-ENC) is pinned by
//!   the third-party known-answer test in this module's tests rather than by a
//!   clause I read.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "scp03t";

use crate::scp03::{cmac, BLOCK, MAC_LEN};
use crate::tlv::Length;
use aes::cipher::{
    block_padding::NoPadding, BlockCipherEncrypt, BlockModeEncrypt, KeyInit, KeyIvInit,
};
use aes::Aes128;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

/// Key type AES, `ControlRefTemplate.keyType` (5.5.1).
pub const KEY_TYPE_AES: u8 = 0x88;
/// Key length in bytes, `ControlRefTemplate.keyLen`, and the `L` of Annex G.
pub const KEY_LEN: usize = 16;
/// Length of an EID.
pub const EID_LEN: usize = 16;
/// Longest Host ID (`OctetTo16`, 5.5.1).
pub const HOST_ID_MAX: usize = 16;
/// Largest TLV segment, tag and length and MAC included (2.5.3).
pub const MAX_SEGMENT: usize = 1020;

/// What went wrong deriving keys or protecting a segment.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The Host ID is empty or longer than 16 bytes.
    #[error("Host ID is {0} bytes, expected 1 to 16")]
    HostIdLength(usize),
    /// The private scalar is zero or not below the group order.
    #[error("invalid P-256 private key")]
    PrivateKey,
    /// The peer's public key is not a point on P-256.
    #[error("invalid P-256 public key")]
    PublicKey,
    /// The protected segment would exceed 1020 bytes.
    #[error("segment would be {0} bytes, over the {MAX_SEGMENT} byte limit")]
    SegmentTooLong(usize),
}

/// The Host ID of `InitialiseSecureChannel`: a different value, and a
/// different type, from the [`Eid`] (AGENTS.md 5.7). Passing one where the
/// other belongs is a compile error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostId(Vec<u8>);

impl HostId {
    /// A Host ID of 1 to 16 bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > HOST_ID_MAX {
            return Err(Error::HostIdLength(bytes.len()));
        }
        Ok(Self(bytes.to_vec()))
    }
}

/// The 16-byte EID of the target eUICC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eid(pub [u8; EID_LEN]);

/// ECDH on P-256 (Annex G, GP Card Spec Amendment F 3.1.1 limited to
/// one-time keys): the shared secret `ShS` is the x coordinate of
/// `own_sk * peer_pk`, 32 bytes big-endian.
///
/// `peer_pk_sec1` is the SEC1 point, e.g. the `0x04 || X || Y` of `smdpOtpk`.
pub fn shared_secret(own_sk: &[u8; 32], peer_pk_sec1: &[u8]) -> Result<[u8; 32], Error> {
    let sk = SecretKey::from_slice(own_sk).map_err(|_| Error::PrivateKey)?;
    let pk = PublicKey::from_sec1_bytes(peer_pk_sec1).map_err(|_| Error::PublicKey)?;
    let point = (pk.to_projective() * *sk.to_nonzero_scalar()).to_affine();
    Ok(point.x().into())
}

/// The X9.63 key derivation function with SHA-256 (BSI TR-03111, as Annex G
/// requires): the output is `SHA-256(Z || counter_be32 || info)` for counter
/// 1, 2, ... concatenated and truncated to `out.len()`.
pub fn x963_kdf(z: &[u8], info: &[u8], out: &mut [u8]) {
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let counter = u32::try_from(i + 1).expect("output far below 2^32 blocks");
        let block = Sha256::new()
            .chain_update(z)
            .chain_update(counter.to_be_bytes())
            .chain_update(info)
            .finalize();
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}

/// SharedInfo (Annex G): `keyType(1) || keyLen(1) || HostID-LV || EID-LV`,
/// where an LV is a BER length followed by the value. The Host ID comes first
/// and is its own field; the EID is never substituted for it.
pub fn shared_info(key_type: u8, key_len: u8, host_id: &HostId, eid: &Eid) -> Vec<u8> {
    let mut out = vec![key_type, key_len];
    for value in [host_id.0.as_slice(), eid.0.as_slice()] {
        out.extend(Length::new(value.len() as u16).encode());
        out.extend_from_slice(value);
    }
    out
}

/// The keys one `InitialiseSecureChannel` produces.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// Initial MAC chaining value (`KeyData` bytes `1..L`).
    pub icv: [u8; BLOCK],
    /// S-ENC (`L+1..2L`).
    pub enc: [u8; BLOCK],
    /// S-MAC (`2L+1..3L`).
    pub mac: [u8; BLOCK],
}

// Key material must not reach logs or panic messages through `{:?}`.
impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKeys { .. }")
    }
}

/// Derives the session keys from the shared secret (Annex G): X9.63 over
/// [`shared_info`] with key type AES and key length 16, three blocks of
/// `L = 16` bytes.
pub fn derive_keys(shs: &[u8; 32], host_id: &HostId, eid: &Eid) -> SessionKeys {
    let info = shared_info(KEY_TYPE_AES, KEY_LEN as u8, host_id, eid);
    let mut data = [0u8; 3 * BLOCK];
    x963_kdf(shs, &info, &mut data);
    SessionKeys {
        icv: data[..BLOCK].try_into().expect("16 bytes"),
        enc: data[BLOCK..2 * BLOCK].try_into().expect("16 bytes"),
        mac: data[2 * BLOCK..].try_into().expect("16 bytes"),
    }
}

/// How one segment is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// AES-128-CBC with S-ENC, then C-MAC: tags `0x86` and `0x87`.
    EncryptAndMac,
    /// C-MAC only: tag `0x88` (StoreMetadata, 2.5.4.3). The ICV counter still
    /// advances.
    MacOnly,
}

/// The sending side of an SCP03t channel: S-ENC, S-MAC, the MAC chaining value
/// and the encryption counter.
#[derive(Clone)]
pub struct Channel {
    s_enc: [u8; BLOCK],
    s_mac: [u8; BLOCK],
    chain: [u8; BLOCK],
    counter: u128,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Channel { .. }")
    }
}

impl Channel {
    /// A channel with the initial MAC chaining value from [`derive_keys`] and
    /// the encryption counter at 1 (the 16-byte value `00..01`, 2.5.3).
    pub fn new(keys: &SessionKeys) -> Self {
        Self::with_keys(keys.enc, keys.mac, keys.icv)
    }

    /// A channel from explicit keys, e.g. the Profile Protection Keys of
    /// `ReplaceSessionKeys` (5.5.4). Counter and chain are the caller's
    /// `initial_mac_chaining_value`; the counter restarts at 1 (2.5.3).
    pub fn with_keys(s_enc: [u8; BLOCK], s_mac: [u8; BLOCK], chain: [u8; BLOCK]) -> Self {
        Self {
            s_enc,
            s_mac,
            chain,
            counter: 1,
        }
    }

    /// Protects one segment and returns the TLV `tag || BER(Lcc) || body ||
    /// C-MAC`, advancing the MAC chain and the counter.
    ///
    /// - Encryption pads with `0x80` then zeros to a multiple of 16 (always at
    ///   least one byte, 2.5.3), and uses AES-128-CBC with S-ENC and
    ///   `ICV = AES-ECB(S-ENC, counter as 16 bytes big-endian)`.
    /// - `Lcc` is the body length plus 8 (SGP.02 4.1.3.3: `L + padding + L_MAC`).
    /// - The CMAC input is `chain || tag || Lcc || body` (SGP.02 4.1.3.3) under
    ///   S-MAC. The **full 16 bytes** become the next chain value; only the
    ///   **8 most significant bytes** go on the wire.
    ///
    /// # Errors
    ///
    /// [`Error::SegmentTooLong`] when the TLV would exceed 1020 bytes. The
    /// channel is left unchanged in that case.
    pub fn protect(
        &mut self,
        tag: u8,
        data: &[u8],
        protection: Protection,
    ) -> Result<Vec<u8>, Error> {
        let body = match protection {
            Protection::MacOnly => data.to_vec(),
            Protection::EncryptAndMac => {
                let mut padded = data.to_vec();
                padded.push(0x80);
                padded.resize(padded.len().next_multiple_of(BLOCK), 0);
                padded
            }
        };
        let lcc = body.len() + MAC_LEN;
        let length = Length::new(u16::try_from(lcc).unwrap_or(u16::MAX)).encode();
        let total = 1 + length.len() + lcc;
        if total > MAX_SEGMENT {
            return Err(Error::SegmentTooLong(total));
        }

        let body = match protection {
            Protection::MacOnly => body,
            Protection::EncryptAndMac => {
                let mut icv_block = self.counter.to_be_bytes().into();
                Aes128::new(&self.s_enc.into()).encrypt_block(&mut icv_block);
                let mut buf = body;
                let len = buf.len();
                cbc::Encryptor::<Aes128>::new(&self.s_enc.into(), &icv_block)
                    .encrypt_padded::<NoPadding>(&mut buf, len)
                    .expect("body is a whole number of blocks");
                buf
            }
        };
        let full = cmac(&self.s_mac, &[&self.chain, &[tag], &length, &body]);
        self.chain = full;
        self.counter = self.counter.wrapping_add(1);

        let mut out = vec![tag];
        out.extend(length);
        out.extend(body);
        out.extend_from_slice(&full[..MAC_LEN]);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }

    fn h16(s: &str) -> [u8; 16] {
        h(s).try_into().unwrap()
    }

    // RFC 5903 section 8.1 (256-bit random ECP group), IANA group 19:
    // initiator private key i, responder public key g^r, shared secret x(g^ir).
    #[test]
    fn ecdh_rfc5903_section_8_1() {
        let i: [u8; 32] =
            h("C88F01F5 10D9AC3F 70A292DA A2316DE5 44E9AAB8 AFE84049 C62A9C57 862D1433")
                .try_into()
                .unwrap();
        let mut grx_gry = vec![0x04];
        grx_gry.extend(h(
            "D12DFB52 89C8D4F8 1208B702 70398C34 2296970A 0BCCB74C 736FC755 4494BF63",
        ));
        grx_gry.extend(h(
            "56FBF3CA 366CC23E 8157854C 13C58D6A AC23F046 ADA30F83 53E74F33 039872AB",
        ));
        assert_eq!(
            shared_secret(&i, &grx_gry).unwrap().to_vec(),
            h("D6840F6B 42F6EDAF D13116E0 E1256520 2FEF8E9E CE7DCE03 812464D0 4B9442DE")
        );
        // A point that is not on the curve is refused.
        let mut off_curve = grx_gry.clone();
        off_curve[64] ^= 1;
        assert_eq!(shared_secret(&i, &off_curve), Err(Error::PublicKey));
        assert_eq!(shared_secret(&[0; 32], &grx_gry), Err(Error::PrivateKey));
    }

    // ANS X9.63-2001 KDF, SHA-256, |Z| = 192 bits, |SharedInfo| = 128 bits,
    // key data 1024 bits, COUNT = 0. Source: NIST CAVS 12.0 "ANS X9.63-2001"
    // vectors as vendored by pyca/cryptography,
    // vectors/cryptography_vectors/KDF/ansx963_2001.txt, last changed in
    // commit e69da95e57f9ceb2bbe04edaf2369bce2c496851 (file read at main
    // 63feda2ab07382f742b0c65c5b50b64b31d5f030).
    // Four output blocks, so the counter really counts.
    #[test]
    fn x963_kdf_cavs_sha256() {
        let z = h("22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d");
        let info = h("75eef81aa3041e33b80971203d2c0c52");
        let want = h(
            "c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e\
             52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485\
             500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269\
             142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21",
        );
        let mut out = [0u8; 128];
        x963_kdf(&z, &info, &mut out);
        assert_eq!(out.to_vec(), want);
        // A length that is not a block multiple is a prefix, not a re-hash.
        let mut short = [0u8; 48];
        x963_kdf(&z, &info, &mut short);
        assert_eq!(short.to_vec(), want[..48]);
    }

    // Known answers for the key split and the session. Source: osmocom/pysim,
    // tests/unittests/test_esim_bsp.py class BSP_Test_mode51 at commit
    // a3962b2076d157e075262c51e6c4d0a48ba12465 (the file's last change; its
    // implementation, pySim/esim/bsp.py, last changed at
    // 5d2e2ee259b19e836a056bf8c8e7c9d33032f77f). The test's own comment says it
    // was "created using hex-dumps from a log/trace of a 3rd party SM-DP+", so
    // it is an independent implementation, not pySim agreeing with itself.
    // pySim calls this protocol BSP; SGP.22 v2.x called it SCP03t.
    const SHS: &str = "c9a993dd4879a8f7161f2085410edd4f9652f1df37be097ba96ba2ca6be528fe";
    const EID: &str = "89049032123451234512345678901235";
    const ICV: &str = "406d507b448a699e7a36a38494debbde";
    const S_ENC: &str = "472f5bfadd97f21d34f3ce9b51b92751";
    const S_MAC: &str = "9ec07f5b36a13e12a991d66e294e6242";

    fn host_id() -> HostId {
        HostId::new(&[0x80; 8]).unwrap()
    }

    fn eid() -> Eid {
        Eid(h16(EID))
    }

    fn keys() -> SessionKeys {
        derive_keys(&h(SHS).try_into().unwrap(), &host_id(), &eid())
    }

    #[test]
    fn key_split_gives_the_documented_icv_enc_mac_triple() {
        let k = keys();
        assert_eq!(k.icv, h16(ICV));
        assert_eq!(k.enc, h16(S_ENC));
        assert_eq!(k.mac, h16(S_MAC));
    }

    #[test]
    fn shared_info_layout_is_type_len_hostid_lv_eid_lv() {
        let info = shared_info(KEY_TYPE_AES, 16, &host_id(), &eid());
        let mut want = vec![0x88, 0x10, 0x08];
        want.extend([0x80; 8]);
        want.push(0x10);
        want.extend(h(EID));
        assert_eq!(info, want);
    }

    // HostID is its own field (5.5.1 hostId), not the EID. The two inputs
    // below have different lengths and values, so swapping them changes the
    // SharedInfo and every derived key; using the EID as the Host ID is a
    // different value of the same type only if the API let it, which it does
    // not (HostId and Eid are separate types).
    #[test]
    fn host_id_is_its_own_field_and_not_the_eid() {
        let k = keys();
        let host = host_id();
        assert_ne!(host.0, eid().0.to_vec());

        // What the wrong implementation computes: the EID in the Host ID slot.
        let eid_as_host = HostId::new(&eid().0).unwrap();
        let wrong = derive_keys(&h(SHS).try_into().unwrap(), &eid_as_host, &eid());
        assert_ne!(wrong.icv, k.icv);
        assert_ne!(wrong.enc, k.enc);
        assert_ne!(wrong.mac, k.mac);

        // Swapped order: EID bytes first, Host ID second.
        let a = shared_info(KEY_TYPE_AES, 16, &host_id(), &eid());
        let swapped = HostId::new(&eid().0).unwrap();
        let b = shared_info(KEY_TYPE_AES, 16, &swapped, &Eid([0x80; 16]));
        assert_ne!(a, b);
        // The first LV in SharedInfo is the Host ID's 8 bytes, not 16.
        assert_eq!(a[2], 8);
    }

    #[test]
    fn host_id_length_is_checked() {
        assert_eq!(HostId::new(&[]), Err(Error::HostIdLength(0)));
        assert_eq!(HostId::new(&[1; 17]), Err(Error::HostIdLength(17)));
        assert!(HostId::new(&[1; 16]).is_ok());
    }

    // Same source and commit as above: the first three protected TLVs of the
    // trace on one chain: ConfigureISDP (87, encrypted), StoreMetadata (88,
    // MAC only) and a second 87. The third only matches if the 88 advanced
    // both the MAC chain and the ICV counter.
    #[test]
    fn session_known_answers_from_a_third_party_sm_dp() {
        let mut ch = Channel::new(&keys());
        let t1 = ch
            .protect(0x87, &h("bf2400"), Protection::EncryptAndMac)
            .unwrap();
        assert_eq!(
            t1,
            h("8718f6fe031e4b9cfe87c8e1e62f3fde85c49412d7722a6a2d89")
        );

        let meta = h("bf252d5a0a98001032547698103214910947534d415f54455354921147534d415f544553545f50524f46494c45950100");
        let t2 = ch.protect(0x88, &meta, Protection::MacOnly).unwrap();
        assert_eq!(
            t2,
            h("8838bf252d5a0a98001032547698103214910947534d415f54455354921147534d415f544553545f50524f46494c459501008a62cc9adbb5ccbc")
        );

        let t3 = ch
            .protect(
                0x87,
                &h("bf26368010000102030405060708090a0b0c0d0e0f8110010102030405060708090a0b0c0d0e0f8210020102030405060708090a0b0c0d0e0f"),
                Protection::EncryptAndMac,
            )
            .unwrap();
        assert_eq!(
            t3,
            h("8748a14c800a001992351cd46ad2945654674369701d82b7b46567652bc8fbed234939fc57fba748015525fd6c651e9d3d1330652d42a0cfad950e912122af4ec5362d3c0bc535729c40")
        );
    }

    // The wire MAC is the 8 MOST significant bytes of the 16-byte CMAC, and
    // the chain is the whole 16. Recomputed from the CMAC directly, so the test
    // fails if the wire MAC were 16 bytes or the 8 least significant ones.
    #[test]
    fn wire_mac_is_the_8_msb_of_the_cmac_and_the_chain_is_all_16() {
        let k = keys();
        let mut ch = Channel::new(&k);
        let tlv = ch.protect(0x88, &[1, 2, 3], Protection::MacOnly).unwrap();
        // 88 | Lcc = 3 + 8 | data | MAC
        assert_eq!(tlv.len(), 1 + 1 + 3 + 8);
        let full = cmac(&k.mac, &[&k.icv, &[0x88, 0x0b], &[1, 2, 3]]);
        assert_eq!(&tlv[5..], &full[..8]);
        assert_ne!(&tlv[5..], &full[8..]);
        assert_eq!(ch.chain, full);

        // The next segment is chained on the full 16 bytes.
        let next = ch.protect(0x88, &[4], Protection::MacOnly).unwrap();
        let full2 = cmac(&k.mac, &[&full, &[0x88, 0x09], &[4]]);
        assert_eq!(&next[3..], &full2[..8]);
    }

    #[test]
    fn padding_is_always_added_and_lcc_counts_it_and_the_mac() {
        let mut ch = Channel::new(&keys());
        // 16 bytes of data still gets a full padding block: 32 + 8.
        let tlv = ch
            .protect(0x86, &[7; 16], Protection::EncryptAndMac)
            .unwrap();
        assert_eq!(tlv[1], 40);
        assert_eq!(tlv.len(), 2 + 40);
    }

    #[test]
    fn segment_limit_is_1020_bytes_with_a_three_byte_length() {
        let mut ch = Channel::new(&keys());
        // 1007 bytes pad to 1008, + 8 MAC = 1016 = Lcc, so 1 + 3 + 1016 = 1020.
        let ok = ch
            .protect(0x86, &[0; 1007], Protection::EncryptAndMac)
            .unwrap();
        assert_eq!(ok.len(), 1020);
        assert_eq!(&ok[1..4], &[0x82, 0x03, 0xF8]);
        // One more byte pads to 1024 and no longer fits; the channel is untouched.
        let before = ch.chain;
        assert_eq!(
            ch.protect(0x86, &[0; 1008], Protection::EncryptAndMac),
            Err(Error::SegmentTooLong(1 + 3 + 1024 + 8))
        );
        assert_eq!(ch.chain, before);
    }
}
