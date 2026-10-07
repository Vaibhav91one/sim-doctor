//! RFC 6979 deterministic ECDSA over P-256 with SHA-256 (issue #21).
//!
//! The signature is plain `r || s`, 64 bytes, **not** DER (SGP.22 2.6.7.2 ->
//! GPCS v2.2 Amendment E 3.1.3). A DER signature here is a real bug: it starts
//! with the SEQUENCE tag `0x30` and has a variable length.
//!
//! # SGP.26 test PKI fixtures: pending
//!
//! The SGP.26 test certificates (public home: `waigel/euicc-rsp`,
//! `testdata/sgp26/`) are NOT vendored. AGENTS.md ("Never commit card secrets")
//! states PKI material stays out of git and `.gitignore` blocks `*.pem`,
//! `*.der`, `*.crt`; no licence for redistributing the files has been verified,
//! and certificate bytes are never invented. The "SGP.26 vectors validate"
//! acceptance item therefore waits on a decision to carry them. Note the real
//! test certs expire 30 March 2030: a future failure mode, not a today problem.
//! This is test PKI material, not a conformance harness.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

/// Length of an `r || s` P-256 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Sign `message` (hashed with SHA-256) with the 32-byte big-endian private
/// scalar. Deterministic per RFC 6979. Errors if the scalar is not a valid key.
pub fn sign(
    private_key: &[u8; 32],
    message: &[u8],
) -> Result<[u8; SIGNATURE_LEN], p256::ecdsa::Error> {
    let key = SigningKey::from_slice(private_key)?;
    let sig: Signature = key.try_sign(message)?;
    Ok(sig.to_bytes().into())
}

/// Verify an `r || s` signature against a SEC1-encoded public key.
pub fn verify(public_key_sec1: &[u8], message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
    let Ok(key) = VerifyingKey::from_sec1_bytes(public_key_sec1) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6979 appendix A.2.5, ECDSA P-256, SHA-256.
    const X: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    const UX: &str = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    const UY: &str = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    // (message, r, s)
    const VECTORS: [(&[u8], &str, &str); 2] = [
        (
            b"sample",
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
            "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
        ),
        (
            b"test",
            "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
            "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
        ),
    ];

    fn key() -> [u8; 32] {
        hex::decode(X).unwrap().try_into().unwrap()
    }

    fn pubkey() -> Vec<u8> {
        hex::decode(format!("04{UX}{UY}")).unwrap()
    }

    #[test]
    fn rfc6979_a25_vectors_match_byte_for_byte() {
        for (msg, r, s) in VECTORS {
            let want = hex::decode(format!("{r}{s}")).unwrap();
            let got = sign(&key(), msg).unwrap();
            assert_eq!(got.to_vec(), want, "{:?}", msg);
            assert!(verify(&pubkey(), msg, &got));
        }
    }

    #[test]
    fn deterministic_64_bytes_and_not_der() {
        for (msg, _, _) in VECTORS {
            let a = sign(&key(), msg).unwrap();
            let b = sign(&key(), msg).unwrap();
            assert_eq!(a, b);
            assert_eq!(a.len(), 64);
            // r||s of these vectors starts 0xEF / 0xF1, never the DER SEQUENCE tag.
            assert_ne!(a[0], 0x30);
        }
    }

    #[test]
    fn verify_rejects_flipped_bit() {
        let (msg, _, _) = VECTORS[0];
        let mut sig = sign(&key(), msg).unwrap();
        sig[10] ^= 1;
        assert!(!verify(&pubkey(), msg, &sig));
        let good = sign(&key(), msg).unwrap();
        assert!(!verify(&pubkey(), b"sampld", &good));
    }
}
