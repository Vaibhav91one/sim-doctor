//! SGP.26 test PKI vs `sim_doctor::sign` (issue #73, follow-up to #21).
//!
//! # Why the certificates are not committed
//!
//! GSMA publishes the SGP.26 test certificates and states no licence allowing
//! redistribution, and AGENTS.md keeps PKI material out of git (`.gitignore`
//! blocks `*.pem`, `*.der`, `*.crt`). So the repo carries only a pointer: the
//! URL, the SHA-256 of the zip and the member names below. The test fetches the
//! zip at run time into a temp dir, checks the hash, and deletes everything.
//!
//! # Running it (`#[ignore]`d, so plain `cargo test` never touches the network)
//!
//! ```text
//! cargo test --test sgp26_fixtures -- --ignored --nocapture
//! ```
//!
//! Needs the system tools `unzip` and, unless `SGP26_ZIP` is set, `curl`. No
//! crate was added: shelling out keeps the dependency tree unchanged.
//!
//! GSMA's host sits behind a Cloudflare challenge: plain `curl` was served a
//! 403 when this was written (2026-10-08). If so, download the zip in a browser
//! and run with `SGP26_ZIP=/path/to/SGP.26_v3.0.1-Certificates_06_06_2024.zip`;
//! the hash check applies to that file too.
//!
//! # Expiry
//!
//! Dates read from the v3.0.1 zip (Variant O, NIST P-256) on 2026-10-08, not
//! the often-quoted 30 March 2030 (that belongs to older certificate sets):
//! CI 2059-06-04, EUM 2058-05-27, eUICC year 7500, DPauth/DPpb 2027-06-05.
//! The DP-TLS certificates expired on 2025-07-07, so they are listed but not
//! used. This test never checks validity dates, only signatures, so expiry
//! cannot make it fail; the nearest real deadline is 2027-06-05.
//!
//! # What is proved
//!
//! Every certificate's signature, an ECDSA-with-SHA256 signature in DER, is
//! converted to `r || s` and checked with `sign::verify` under its issuer's
//! public key, for the chain CI -> EUM -> eUICC and CI -> DPauth / DPpb. Each
//! private key from the zip then signs with `sign::sign` and the signature
//! must verify under the public key in its own certificate.
//! This is test PKI material, not a conformance harness.

use sim_doctor::der::Der;
use sim_doctor::sign::{sign, verify, SIGNATURE_LEN};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Pointer manifest: everything needed to re-fetch the fixtures, nothing else.
const URL: &str = "https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2024/01/SGP.26_v3.0.1-Certificates_06_06_2024.zip";
const SHA256: &str = "82621fd816042e04c389ca54f9554025f9215d60bcc5379ddfb7b78d0068322f";
const ROOT: &str = "SGP.26_v3.0.1-2024_Files_v6/Valid Test Cases/Variant O";
/// (role, certificate member, private-key member, issuer role). Paths are under
/// `ROOT`. CI is self-signed.
const MEMBERS: [(&str, &str, &str, &str); 5] = [
    (
        "CI",
        "CI/CERT_CI_SIG_NIST.der",
        "CI/SK_CI_SIG_NIST.pem",
        "CI",
    ),
    (
        "EUM",
        "EUM/CERT_EUM_SIG_NIST.der",
        "EUM/SK_EUM_SIG_NIST.pem",
        "CI",
    ),
    (
        "eUICC",
        "eUICC/CERT_EUICC_SIG_NIST.der",
        "eUICC/SK_EUICC_SIG_NIST.pem",
        "EUM",
    ),
    (
        "DPauth",
        "SM-DP+/SM_DPauth/CERT_S_SM_DPauth_VARO_SIG_NIST.der",
        "SM-DP+/SM_DPauth/SK_S_SM_DPauth_VARO_SIG_NIST.pem",
        "CI",
    ),
    (
        "DPpb",
        "SM-DP+/SM_DPpb/CERT_S_SM_DPpb_VARO_SIG_NIST.der",
        "SM-DP+/SM_DPpb/SK_S_SM_DPpb_SIG_NIST.pem",
        "CI",
    ),
];

fn run(cmd: &mut Command) {
    let st = cmd.status().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(st.success(), "{cmd:?} failed: {st}");
}

fn sha256_hex(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(std::fs::read(path).unwrap()))
}

/// Minimal PEM body decoder (standard base64), enough for the EC key files.
fn pem_body(pem: &str) -> Vec<u8> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    let block = pem
        .split("-----BEGIN EC PRIVATE KEY-----")
        .nth(1)
        .expect("EC PRIVATE KEY block");
    for c in block.split("-----END").next().unwrap().bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue, // '=', newlines
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// DER INTEGER value -> 32 big-endian bytes (drop the sign pad, left-pad).
fn int32(v: &[u8]) -> [u8; 32] {
    let v = if v.len() > 32 { &v[v.len() - 32..] } else { v };
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(v);
    out
}

struct Cert {
    tbs: Vec<u8>,
    sig: [u8; SIGNATURE_LEN],
    pubkey: Vec<u8>,
}

fn parse_cert(der: &[u8]) -> Cert {
    let cert = Der::decode(der).unwrap().children().unwrap();
    let tbs = cert[0];
    let sig_bits = cert[2].value(); // BIT STRING: 0 unused bits, then DER SEQ{r,s}
    let rs = Der::decode(&sig_bits[1..]).unwrap().children().unwrap();
    let mut sig = [0u8; SIGNATURE_LEN];
    sig[..32].copy_from_slice(&int32(rs[0].value()));
    sig[32..].copy_from_slice(&int32(rs[1].value()));
    // TBS: [0] version, serial, sigAlg, issuer, validity, subject, SPKI, ...
    let spki = tbs.children().unwrap()[6].children().unwrap();
    Cert {
        tbs: tbs.encode(),
        sig,
        pubkey: spki[1].value()[1..].to_vec(),
    }
}

fn scalar(pem: &str) -> [u8; 32] {
    // ECPrivateKey ::= SEQ { version, privateKey OCTET STRING, ... }
    let der = pem_body(pem);
    let top = Der::decode_first(&der).unwrap().0.children().unwrap();
    top[1].value().try_into().unwrap()
}

#[test]
#[ignore = "downloads the GSMA SGP.26 zip; run with --ignored (see module docs)"]
fn sgp26_fixtures_from_gsma() {
    let tmp = std::env::temp_dir().join(format!("sim-doctor-sgp26-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let result = std::panic::catch_unwind(|| check(&tmp));
    let _ = std::fs::remove_dir_all(&tmp); // leave nothing behind, pass or fail
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

fn check(tmp: &Path) {
    let zip: PathBuf = match std::env::var_os("SGP26_ZIP") {
        Some(p) => p.into(),
        None => {
            let z = tmp.join("sgp26.zip");
            run(Command::new("curl").args(["-fsSL", "-o"]).arg(&z).arg(URL));
            z
        }
    };
    assert_eq!(
        sha256_hex(&zip),
        SHA256,
        "zip hash mismatch: GSMA changed the file or the download is not the zip"
    );

    let out = tmp.join("x");
    run(Command::new("unzip")
        .arg("-q")
        .arg(&zip)
        .arg("-d")
        .arg(&out));
    let base = out.join(ROOT);

    let mut certs = std::collections::HashMap::new();
    for (role, cert, key, _) in MEMBERS {
        let c = parse_cert(&std::fs::read(base.join(cert)).unwrap());
        // Private key signs; the public key in its own certificate verifies.
        let sk = scalar(&std::fs::read_to_string(base.join(key)).unwrap());
        let sig = sign(&sk, b"sim-doctor sgp26").unwrap();
        assert!(
            verify(&c.pubkey, b"sim-doctor sgp26", &sig),
            "{role}: own key/cert mismatch"
        );
        assert!(
            !verify(&c.pubkey, b"sim-doctor sgp27", &sig),
            "{role}: verify accepted a wrong message"
        );
        certs.insert(role, c);
    }
    for (role, _, _, issuer) in MEMBERS {
        let c = &certs[role];
        assert!(
            verify(&certs[issuer].pubkey, &c.tbs, &c.sig),
            "{role}: signature does not verify under {issuer}"
        );
    }
}
