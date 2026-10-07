//! GlobalPlatform Secure Channel Protocol 03 (SCP03): the pure crypto core, the
//! two handshake APDU builders, and the `auth/scp03-missing-mac` rule.
//!
//! **Owns.** Session key derivation (GP Card Spec Amendment D v1.1.2, section
//! 4.1.5: NIST SP 800-108 counter-mode KDF with AES-CMAC as the PRF), host and
//! card cryptograms, the C-MAC with its MAC chaining value, the INITIALIZE
//! UPDATE and EXTERNAL AUTHENTICATE command builders, the INITIALIZE UPDATE
//! response parser (which records the key version number, i.e. the keyset
//! identifier), and the evaluation of the missing-MAC rule over a *recorded*
//! exchange.
//!
//! **Does not own.** A transport. Nothing here sends a byte to a card, and no
//! CLI path runs SCP03: INITIALIZE UPDATE (`80 50`) and EXTERNAL AUTHENTICATE
//! (`84 82`) are forbidden on the live operator SIM, and a wrong EXTERNAL
//! AUTHENTICATE counts toward a card's retry limit. A future live path must be
//! opt-in (an explicit flag) and is not part of this module.
//!
//! **Scope.** AES-128 keys, 8-byte challenges and 8-byte cryptograms/MACs
//! (the "i" = 0x00/0x10 profiles). C-MAC only: C-DECRYPTION and R-MAC/R-ENC
//! are not implemented, though S-ENC and S-RMAC are derived. SCP02 and SCP11
//! are not implemented (tracked as a follow-up to issue #22).

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "scp03";

use crate::apdu::{Command, Header, Le, StatusWord};
use crate::rules;
use aes::Aes128;
use cmac::{Cmac, KeyInit, Mac};

/// Length of an AES-128 key, a MAC chaining value and a full CMAC output.
pub const BLOCK: usize = 16;
/// Length of a host or card challenge.
pub const CHALLENGE_LEN: usize = 8;
/// Length of a cryptogram and of a transmitted C-MAC.
pub const MAC_LEN: usize = 8;

/// INS of INITIALIZE UPDATE (CLA 80).
pub const INS_INITIALIZE_UPDATE: u8 = 0x50;
/// INS of EXTERNAL AUTHENTICATE (CLA 84).
pub const INS_EXTERNAL_AUTHENTICATE: u8 = 0x82;
/// Security level bit: command MAC.
pub const LEVEL_C_MAC: u8 = 0x01;
/// Security level bits: command MAC and command decryption (not implemented).
pub const LEVEL_C_MAC_C_DECRYPTION: u8 = 0x03;

/// Data derivation constants, Amendment D table 4-1.
const DDC_CARD_CRYPTOGRAM: u8 = 0x00;
const DDC_HOST_CRYPTOGRAM: u8 = 0x01;
const DDC_S_ENC: u8 = 0x04;
const DDC_S_MAC: u8 = 0x06;
const DDC_S_RMAC: u8 = 0x07;

/// What went wrong building or parsing an SCP03 value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// INITIALIZE UPDATE response of an unsupported length.
    #[error("INITIALIZE UPDATE response is {0} bytes, expected 29 or 32 (before the status word)")]
    ResponseLength(usize),
    /// The response's key information does not announce SCP03.
    #[error("key information announces SCP {0:02X}, not 03")]
    NotScp03(u8),
    /// The command data plus the MAC would not fit a short Lc.
    #[error("command data is {0} bytes; with the 8-byte C-MAC it exceeds a short APDU")]
    TooLong(usize),
}

/// AES-CMAC (NIST SP 800-38B), full 16-byte output.
fn cmac(key: &[u8; BLOCK], parts: &[&[u8]]) -> [u8; BLOCK] {
    // The key is exactly 16 bytes, so new_from_slice cannot fail.
    let mut mac = <Cmac<Aes128> as KeyInit>::new_from_slice(key).expect("16-byte AES-128 key");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// One block of the SP 800-108 counter-mode KDF as Amendment D uses it:
/// `CMAC(key, 0^11 || constant || 0x00 || L(2) || counter(1) || context)`.
///
/// Only counter 1 is needed: every output is at most 128 bits.
fn kdf(key: &[u8; BLOCK], constant: u8, l_bits: u16, context: &[u8]) -> [u8; BLOCK] {
    let mut label = [0u8; 16];
    label[11] = constant;
    label[13..15].copy_from_slice(&l_bits.to_be_bytes());
    label[15] = 0x01;
    cmac(key, &[&label, context])
}

/// The three session keys of one SCP03 session.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// S-ENC (derived; unused while C-DECRYPTION is not implemented).
    pub enc: [u8; BLOCK],
    /// S-MAC, keys the C-MAC and both cryptograms.
    pub mac: [u8; BLOCK],
    /// S-RMAC (derived; unused while R-MAC is not implemented).
    pub rmac: [u8; BLOCK],
}

// Key material must not reach logs or panic messages through `{:?}`.
impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKeys { .. }")
    }
}

fn context(host: &[u8; CHALLENGE_LEN], card: &[u8; CHALLENGE_LEN]) -> [u8; 2 * CHALLENGE_LEN] {
    let mut out = [0u8; 2 * CHALLENGE_LEN];
    out[..CHALLENGE_LEN].copy_from_slice(host);
    out[CHALLENGE_LEN..].copy_from_slice(card);
    out
}

/// Derives S-ENC, S-MAC and S-RMAC from the static keys and both challenges.
pub fn derive_session_keys(
    static_enc: &[u8; BLOCK],
    static_mac: &[u8; BLOCK],
    host: &[u8; CHALLENGE_LEN],
    card: &[u8; CHALLENGE_LEN],
) -> SessionKeys {
    let ctx = context(host, card);
    SessionKeys {
        enc: kdf(static_enc, DDC_S_ENC, 128, &ctx),
        mac: kdf(static_mac, DDC_S_MAC, 128, &ctx),
        rmac: kdf(static_mac, DDC_S_RMAC, 128, &ctx),
    }
}

/// Which side's cryptogram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Proves the card knows the keys.
    Card,
    /// Proves the host knows the keys.
    Host,
}

/// The 8-byte authentication cryptogram of one side, keyed with S-MAC.
pub fn cryptogram(
    s_mac: &[u8; BLOCK],
    side: Side,
    host: &[u8; CHALLENGE_LEN],
    card: &[u8; CHALLENGE_LEN],
) -> [u8; MAC_LEN] {
    let constant = match side {
        Side::Card => DDC_CARD_CRYPTOGRAM,
        Side::Host => DDC_HOST_CRYPTOGRAM,
    };
    let full = kdf(s_mac, constant, 64, &context(host, card));
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&full[..MAC_LEN]);
    out
}

/// Compares two byte strings without an early exit.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether the card's cryptogram proves it holds the keys behind `keys`.
pub fn verify_card_cryptogram(
    keys: &SessionKeys,
    host: &[u8; CHALLENGE_LEN],
    card: &[u8; CHALLENGE_LEN],
    received: &[u8],
) -> bool {
    ct_eq(&cryptogram(&keys.mac, Side::Card, host, card), received)
}

/// A secure channel's command-MAC state: S-MAC and the MAC chaining value.
///
/// The chaining value starts at zero and becomes the **full 16-byte** CMAC of
/// every command wrapped, in order, so wrapping must happen once per command
/// actually sent and in send order.
#[derive(Debug, Clone)]
pub struct Channel {
    s_mac: [u8; BLOCK],
    chain: [u8; BLOCK],
}

impl Channel {
    /// A fresh channel with a zero chaining value.
    pub fn new(keys: &SessionKeys) -> Self {
        Self {
            s_mac: keys.mac,
            chain: [0; BLOCK],
        }
    }

    /// Adds the C-MAC to `command`: sets the secure messaging bit (0x04) in
    /// CLA, appends the 8-byte MAC to the data and advances the chain.
    ///
    /// MAC input (Amendment D 6.2.4): `chain || CLA' INS P1 P2 Lc' || data`,
    /// where `CLA'` has the bit set and `Lc'` counts the MAC.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] when data plus MAC exceeds 255 bytes.
    pub fn wrap(&mut self, command: &Command) -> Result<Command, Error> {
        let data = command.data();
        let lc = u8::try_from(data.len() + MAC_LEN).map_err(|_| Error::TooLong(data.len()))?;
        let h = command.header();
        let header = Header::new(
            h.class() | 0x04,
            h.instruction(),
            h.parameter_1(),
            h.parameter_2(),
        );
        let full = cmac(&self.s_mac, &[&self.chain, &header.to_bytes(), &[lc], data]);
        self.chain = full;
        let mut body = data.to_vec();
        body.extend_from_slice(&full[..MAC_LEN]);
        Ok(match command.le() {
            Some(le) => Command::case4(header, body, le),
            None => Command::case3(header, body),
        })
    }
}

/// INITIALIZE UPDATE (`80 50 <key version> 00 08 <host challenge> 00`).
///
/// `key_version` is the key version number (the keyset identifier); 0 asks the
/// card for its default keyset.
pub fn initialize_update(key_version: u8, host: &[u8; CHALLENGE_LEN]) -> Command {
    Command::case4(
        Header::new(0x80, INS_INITIALIZE_UPDATE, key_version, 0x00),
        host.to_vec(),
        Le::Short(0),
    )
}

/// EXTERNAL AUTHENTICATE (`84 82 <level> 00 10 <host cryptogram> <C-MAC>`),
/// MAC'd through `channel`, which must be fresh (zero chaining value).
///
/// # Errors
///
/// Never in practice; mirrors [`Channel::wrap`].
pub fn external_authenticate(
    channel: &mut Channel,
    security_level: u8,
    host_cryptogram: &[u8; MAC_LEN],
) -> Result<Command, Error> {
    // The wrap adds the secure-messaging bit, so build the plain 80 82 form.
    channel.wrap(&Command::case3(
        Header::new(0x80, INS_EXTERNAL_AUTHENTICATE, security_level, 0x00),
        host_cryptogram.to_vec(),
    ))
}

/// A parsed INITIALIZE UPDATE response (status word already stripped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitializeUpdateResponse {
    /// Key diversification data (10 bytes).
    pub diversification: [u8; 10],
    /// Key version number: the keyset identifier the card selected.
    pub key_version: u8,
    /// The "i" parameter of the SCP.
    pub i_parameter: u8,
    /// The card challenge.
    pub card_challenge: [u8; CHALLENGE_LEN],
    /// The card cryptogram.
    pub card_cryptogram: [u8; MAC_LEN],
    /// Sequence counter, present only for pseudo-random challenges (i bit 0x10).
    pub sequence_counter: Option<[u8; 3]>,
}

impl InitializeUpdateResponse {
    /// Parses `10 diversification || kvn || 03 || i || 8 challenge || 8
    /// cryptogram [|| 3 sequence counter]`.
    ///
    /// # Errors
    ///
    /// [`Error::ResponseLength`] or [`Error::NotScp03`].
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 29 && bytes.len() != 32 {
            return Err(Error::ResponseLength(bytes.len()));
        }
        if bytes[11] != 0x03 {
            return Err(Error::NotScp03(bytes[11]));
        }
        // Lengths were checked above, so these conversions cannot fail.
        Ok(Self {
            diversification: bytes[..10].try_into().expect("10 bytes"),
            key_version: bytes[10],
            i_parameter: bytes[12],
            card_challenge: bytes[13..21].try_into().expect("8 bytes"),
            card_cryptogram: bytes[21..29].try_into().expect("8 bytes"),
            sequence_counter: bytes.get(29..32).map(|s| s.try_into().expect("3 bytes")),
        })
    }
}

// ---------------------------------------------------------------------------
// auth/scp03-missing-mac
// ---------------------------------------------------------------------------

/// The ID of the missing-MAC rule, as AGENTS.md section 3 spells it.
pub const MISSING_MAC_RULE: &str = "auth/scp03-missing-mac";

/// Which command a recorded exchange sent without a valid C-MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// EXTERNAL AUTHENTICATE whose data carried no (or a wrong) C-MAC.
    ExternalAuthenticateWithoutMac,
    /// A command sent on an established C-MAC channel with no C-MAC appended.
    CommandWithoutMac,
}

impl ProbeKind {
    fn label(self) -> &'static str {
        match self {
            Self::ExternalAuthenticateWithoutMac => "EXTERNAL AUTHENTICATE without C-MAC",
            Self::CommandWithoutMac => "command without C-MAC on a C-MAC channel",
        }
    }
}

/// One recorded exchange: a command that should have been refused for lack of
/// a MAC, and what the card answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// What was sent.
    pub kind: ProbeKind,
    /// What the card answered.
    pub status: StatusWord,
}

/// The recorded SCP03 exchanges a scan was handed.
///
/// **Recorded, not live.** Nothing in this crate produces one from a card;
/// tests build it from mock exchanges. The scan carries `None` today, so the
/// rule is registered but reports no evidence (see [`had_evidence`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Audit {
    /// The probes, in the order they were recorded.
    pub probes: Vec<Probe>,
}

/// The rule's declaration.
pub fn missing_mac_spec() -> rules::RuleSpec {
    rules::RuleSpec::new(
        rules::RuleId::new(MISSING_MAC_RULE).expect("a validated constant"),
        rules::Severity::High,
        "the card accepted an SCP03 command that carried no valid C-MAC",
    )
    .with_remediation(
        "require C-MAC (security level 01 or higher) on EXTERNAL AUTHENTICATE and on every \
         command after it, and configure the security domain to refuse a command without one",
    )
}

/// Raises one finding per probe the card answered `90 00`.
///
/// Strictly `90 00`: a `61 xx` or `91 xx` is not proof the command was acted
/// on, and claiming it was would manufacture a finding.
pub fn missing_mac(audit: &Audit) -> Vec<rules::Finding> {
    audit
        .probes
        .iter()
        .filter(|probe| probe.status.is_success())
        .map(|probe| {
            rules::Finding::new(
                rules::RuleId::new(MISSING_MAC_RULE).expect("a validated constant"),
                rules::Severity::High,
                format!(
                    "{} was accepted with {}: the card does not enforce the C-MAC",
                    probe.kind.label(),
                    probe
                        .status
                        .to_bytes()
                        .map(|b| format!("{b:02X}"))
                        .join(" "),
                ),
                rules::Location::apdu(probe.kind.label()),
                rules::Evidence::text(format!("status={}", hex::encode(probe.status.to_bytes()))),
            )
        })
        .collect()
}

/// Whether there was any recorded exchange to decide from.
pub fn had_evidence(audit: &Audit) -> bool {
    !audit.probes.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    // NIST SP 800-38B, Appendix D.1 (AES-128), examples 1 and 2, via the
    // `cmac` crate: pins the PRF the KDF is built on.
    #[test]
    fn cmac_nist_sp_800_38b() {
        let key = h::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        assert_eq!(cmac(&key, &[]), h::<16>("bb1d6929e95937287fa37d129b756746"));
        assert_eq!(
            cmac(&key, &[&h::<16>("6bc1bee22e409f96e93d7e117393172a")]),
            h::<16>("070a16b46b4d4144f79bdd9dd04a287c")
        );
    }

    // Known answers: session keys and both cryptograms.
    //
    // Source: OpenPhysical/Gp4Net, scripts/scp03_test_vectors.json at commit
    // 55a974b9affe77eb3ad1b07ac8dfdc4a3aaa34c5
    // (https://github.com/OpenPhysical/Gp4Net/blob/55a974b9affe77eb3ad1b07ac8dfdc4a3aaa34c5/scripts/scp03_test_vectors.json),
    // generated there by a Python implementation of GP Amendment D / SP 800-108.
    // All keys are obvious test patterns. Columns: enc, mac, host challenge,
    // card challenge, S-ENC, S-MAC, S-RMAC, card cryptogram, host cryptogram.
    #[allow(clippy::type_complexity)]
    const VECTORS: &[[&str; 9]] = &[
        [
            "000102030405060708090A0B0C0D0E0F",
            "101112131415161718191A1B1C1D1E1F",
            "0001020304050607",
            "08090A0B0C0D0E0F",
            "3619112820D79FF81146E6862151F521",
            "E2B6C0D5DC55B27602375D7A983A2B3C",
            "35210536E8D79B6574FC6F8B6049630D",
            "6E3E560916763FAA",
            "C44D56DED351F5A4",
        ],
        [
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "0000000000000000",
            "0000000000000000",
            "D119A7CCA75F050B4F306C8E1E5CC554",
            "78C41DD9D3CCFA9814C3B128FB0BB166",
            "B7698E3A4E8C6AE05E8D8C9A533CA83E",
            "D2119C5615BCA32C",
            "A6C824ACA566F3FD",
        ],
        [
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFF",
            "33DE3D6267494625C13A8E2B382372C5",
            "D14E9907C8EA69F19EEE0BB1D678BE52",
            "F4F51A2E049B61F3C24AC5733BAC07E9",
            "93A22E96300255BC",
            "18117A53AF7F8382",
        ],
        [
            "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF",
            "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
            "0123456789ABCDEF",
            "FEDCBA9876543210",
            "4FE5C3B41D1241A27F1B41F16EC8962B",
            "CA632CE8EB08EFC57B8606A06559A9C6",
            "48D57C3EC8EFCBB6631EC72330FB6428",
            "1EF309E33483B925",
            "0385E37C1B125747",
        ],
        [
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "55555555555555555555555555555555",
            "5555555555555555",
            "AAAAAAAAAAAAAAAA",
            "F1919F3ACF4A5E0CCD5BA7BE22FFFF41",
            "E47B29F6A71006EBAE6F2908CBD6F6C3",
            "F28B86FCC30CE9030ECC9771AA050242",
            "B53C0785454B72FF",
            "627BADF61D353860",
        ],
    ];

    #[test]
    fn kdf_and_cryptograms_match_known_answers() {
        for v in VECTORS {
            let (host, card) = (h::<8>(v[2]), h::<8>(v[3]));
            let keys = derive_session_keys(&h(v[0]), &h(v[1]), &host, &card);
            assert_eq!(keys.enc, h::<16>(v[4]), "S-ENC {}", v[0]);
            assert_eq!(keys.mac, h::<16>(v[5]), "S-MAC {}", v[0]);
            assert_eq!(keys.rmac, h::<16>(v[6]), "S-RMAC {}", v[0]);
            assert_eq!(
                cryptogram(&keys.mac, Side::Card, &host, &card),
                h::<8>(v[7])
            );
            assert_eq!(
                cryptogram(&keys.mac, Side::Host, &host, &card),
                h::<8>(v[8])
            );
            assert!(verify_card_cryptogram(&keys, &host, &card, &h::<8>(v[7])));
            assert!(!verify_card_cryptogram(&keys, &host, &card, &h::<8>(v[8])));
        }
    }

    #[test]
    fn initialize_update_bytes() {
        let cmd = initialize_update(0x30, &h("0001020304050607"));
        assert_eq!(
            hex::encode(cmd.encode().unwrap()),
            "8050300008000102030405060700"
        );
    }

    // No external vector exists for the C-MAC wrapping (the Gp4Net file has
    // none), so this recomputes the Amendment D 6.2.4 input by hand and checks
    // the chain advances with the FULL 16-byte MAC.
    #[test]
    fn c_mac_wrap_and_chain() {
        let keys = derive_session_keys(
            &h("000102030405060708090A0B0C0D0E0F"),
            &h("101112131415161718191A1B1C1D1E1F"),
            &h("0001020304050607"),
            &h("08090A0B0C0D0E0F"),
        );
        let host_cryptogram = h::<8>("C44D56DED351F5A4");
        let mut ch = Channel::new(&keys);
        let ea = external_authenticate(&mut ch, LEVEL_C_MAC, &host_cryptogram).unwrap();

        let mut input = vec![0u8; 16];
        input.extend_from_slice(&[0x84, 0x82, 0x01, 0x00, 0x10]);
        input.extend_from_slice(&host_cryptogram);
        let full = cmac(&keys.mac, &[&input]);
        let wire = ea.encode().unwrap();
        assert_eq!(&wire[..5], &[0x84, 0x82, 0x01, 0x00, 0x10]);
        assert_eq!(&wire[5..13], &host_cryptogram);
        assert_eq!(&wire[13..], &full[..8]);

        // Second command chains on the full first MAC.
        let next = Command::case3(Header::new(0x80, 0xCA, 0x00, 0x66), vec![0xAA]);
        let wrapped = ch.wrap(&next).unwrap();
        let mut input = full.to_vec();
        input.extend_from_slice(&[0x84, 0xCA, 0x00, 0x66, 0x09, 0xAA]);
        let second = cmac(&keys.mac, &[&input]);
        let wire = wrapped.encode().unwrap();
        assert_eq!(&wire[wire.len() - 8..], &second[..8]);
        assert_ne!(&full[..8], &second[..8]);
    }

    #[test]
    fn wrap_rejects_oversize_data() {
        let keys = derive_session_keys(&[0; 16], &[0; 16], &[0; 8], &[0; 8]);
        let big = Command::case3(Header::new(0x80, 0xE2, 0, 0), vec![1u8; 248]);
        assert_eq!(Channel::new(&keys).wrap(&big), Err(Error::TooLong(248)));
    }

    #[test]
    fn parse_initialize_update_response() {
        let mut r = Vec::new();
        r.extend_from_slice(&[0x11; 10]);
        r.extend_from_slice(&[0x30, 0x03, 0x00]);
        r.extend_from_slice(&[0x22; 8]);
        r.extend_from_slice(&[0x33; 8]);
        let p = InitializeUpdateResponse::parse(&r).unwrap();
        assert_eq!(p.key_version, 0x30);
        assert_eq!(p.card_challenge, [0x22; 8]);
        assert_eq!(p.card_cryptogram, [0x33; 8]);
        assert_eq!(p.sequence_counter, None);
        r.extend_from_slice(&[0, 0, 7]);
        assert_eq!(
            InitializeUpdateResponse::parse(&r)
                .unwrap()
                .sequence_counter,
            Some([0, 0, 7])
        );
        assert_eq!(
            InitializeUpdateResponse::parse(&r[..28]),
            Err(Error::ResponseLength(28))
        );
        r[11] = 0x02;
        assert_eq!(InitializeUpdateResponse::parse(&r), Err(Error::NotScp03(2)));
    }

    #[test]
    fn rule_fires_only_on_a_90_00_probe() {
        let audit = Audit {
            probes: vec![
                Probe {
                    kind: ProbeKind::ExternalAuthenticateWithoutMac,
                    status: StatusWord::new(0x69, 0x82),
                },
                Probe {
                    kind: ProbeKind::CommandWithoutMac,
                    status: StatusWord::new(0x90, 0x00),
                },
            ],
        };
        assert!(had_evidence(&audit));
        let found = missing_mac(&audit);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule().as_str(), MISSING_MAC_RULE);
        assert_eq!(found[0].severity(), rules::Severity::High);
        assert!(missing_mac(&Audit::default()).is_empty());
        assert!(!had_evidence(&Audit::default()));
        assert_eq!(missing_mac_spec().id().as_str(), MISSING_MAC_RULE);
    }
}
