//! Milenage (3GPP TS 35.205/35.206) f1, f1*, f2, f3, f4, f5 and f5* in one call.
//!
//! **Owns.** A thin wrapper over the `milenage` crate that turns its stateful
//! per-function API into one value, so a caller gets every output of an AKA
//! run for one `(K, OP/OPc, RAND, SQN, AMF)` and cannot read a stale one.
//!
//! **Does not own.** Any algorithm: the crypto is the `milenage` crate's. Does
//! not talk to a card either. Milenage is the USIM AUTHENTICATE (INS 88)
//! algorithm; `scan`, `fuzz` and `trace` never send it. The card shell's
//! `authenticate` does, on request (`--yes`), and uses [`autn`] and
//! [`open_auts`] to build the challenge and read a resynchronisation answer.
//! The functions are tested by known-answer vectors.
//!
//! Note for readers of issue #22: GlobalPlatform SCP03 does not use Milenage
//! (it is AES-CMAC based, see [`crate::scp03`]). The two are separate here.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "aka";

use milenage::Milenage;

/// How the operator constant is supplied.
#[derive(Clone, Copy)]
pub enum Operator {
    /// OP, from which OPc is derived.
    Op([u8; 16]),
    /// OPc directly.
    Opc([u8; 16]),
}

/// Every Milenage output for one RAND.
#[derive(Clone, PartialEq, Eq)]
pub struct Output {
    /// OPc actually used.
    pub opc: [u8; 16],
    /// f1: network authentication code MAC-A.
    pub mac_a: [u8; 8],
    /// f1*: resynchronisation code MAC-S.
    pub mac_s: [u8; 8],
    /// f2: response RES.
    pub res: [u8; 8],
    /// f3: confidentiality key CK.
    pub ck: [u8; 16],
    /// f4: integrity key IK.
    pub ik: [u8; 16],
    /// f5: anonymity key AK.
    pub ak: [u8; 6],
    /// f5*: resynchronisation anonymity key AK.
    pub ak_star: [u8; 6],
}

// Key material must not reach logs through `{:?}`.
impl std::fmt::Debug for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("aka::Output { .. }")
    }
}

/// Runs f1, f1*, f2, f3, f4, f5 and f5* for one challenge.
pub fn compute(
    k: [u8; 16],
    operator: Operator,
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
) -> Output {
    let mut m = match operator {
        Operator::Op(op) => Milenage::new_with_op(k, op),
        Operator::Opc(opc) => Milenage::new_with_opc(k, opc),
    };
    let mac_a = m.f1(rand, sqn, amf);
    let mac_s = m.f1star(rand, sqn, amf);
    let (res, ck, ik, ak) = m.f2345(rand);
    let ak_star = m.f5star(rand);
    Output {
        opc: *m.opc(),
        mac_a,
        mac_s,
        res,
        ck,
        ik,
        ak,
        ak_star,
    }
}

/// The network authentication token a USIM expects: `AUTN = (SQN xor AK) || AMF || MAC-A`
/// (3GPP TS 33.102 clause 6.3.2).
pub fn autn(out: &Output, sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 16] {
    let mut autn = [0u8; 16];
    for i in 0..6 {
        autn[i] = sqn[i] ^ out.ak[i];
    }
    autn[6..8].copy_from_slice(amf);
    autn[8..].copy_from_slice(&out.mac_a);
    autn
}

/// Opens the `AUTS` of a synchronisation failure (`AUTS = (SQNms xor AK*) || MAC-S`, TS 33.102 clause
/// 6.3.3; MAC-S is f1* with AMF `0000`). Returns the card's `SQNms` and whether MAC-S checks out, i.e.
/// whether the token really came from the card that holds these keys.
pub fn open_auts(
    k: [u8; 16],
    operator: Operator,
    rand: &[u8; 16],
    auts: &[u8; 14],
) -> ([u8; 6], bool) {
    let first = compute(k, operator, rand, &[0; 6], &[0; 2]);
    let mut sqn_ms = [0u8; 6];
    for i in 0..6 {
        sqn_ms[i] = auts[i] ^ first.ak_star[i];
    }
    let check = compute(k, operator, rand, &sqn_ms, &[0; 2]);
    (sqn_ms, check.mac_s == auts[6..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    // 3GPP TS 35.208 "Design conformance test data", Test Set 1 (section 4).
    // Values are those in the milenage-0.3.1 crate's own test_set1_* tests,
    // which cite the same table; they were not re-read from the 3GPP PDF here.
    const K: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
    const OP: &str = "cdc202d5123e20f62b6d676ac72cb318";
    const RAND: &str = "23553cbe9637a89d218ae64dae47bf35";
    const SQN: &str = "ff9bb4d0b607";
    const AMF: &str = "b9b9";

    #[test]
    fn ts_35_208_test_set_1_with_op() {
        let o = compute(h(K), Operator::Op(h(OP)), &h(RAND), &h(SQN), &h(AMF));
        assert_eq!(o.opc, h::<16>("cd63cb71954a9f4e48a5994e37a02baf"));
        assert_eq!(o.mac_a, h::<8>("4a9ffac354dfafb3"));
        assert_eq!(o.mac_s, h::<8>("01cfaf9ec4e871e9"));
        assert_eq!(o.res, h::<8>("a54211d5e3ba50bf"));
        assert_eq!(o.ck, h::<16>("b40ba9a3c58b2a05bbf0d987b21bf8cb"));
        assert_eq!(o.ik, h::<16>("f769bcd751044604127672711c6d3441"));
        assert_eq!(o.ak, h::<6>("aa689c648370"));
        assert_eq!(o.ak_star, h::<6>("451e8beca43b"));
    }

    #[test]
    fn autn_is_sqn_xor_ak_amf_mac_a() {
        // TS 35.208 test set 1: SQN ff9bb4d0b607 xor AK aa689c648370 = 55f328b43577.
        let o = compute(h(K), Operator::Op(h(OP)), &h(RAND), &h(SQN), &h(AMF));
        assert_eq!(
            autn(&o, &h(SQN), &h(AMF)),
            h::<16>("55f328b43577b9b94a9ffac354dfafb3")
        );
    }

    #[test]
    fn auts_round_trips_and_a_foreign_one_fails_its_mac() {
        let op = Operator::Op(h(OP));
        let o = compute(h(K), op, &h(RAND), &h(SQN), &[0, 0]);
        let mut auts = [0u8; 14];
        for (a, (s, k)) in auts.iter_mut().zip(h::<6>(SQN).iter().zip(o.ak_star)) {
            *a = s ^ k;
        }
        auts[6..].copy_from_slice(&o.mac_s);
        assert_eq!(open_auts(h(K), op, &h(RAND), &auts), (h(SQN), true));
        auts[13] ^= 1;
        assert!(!open_auts(h(K), op, &h(RAND), &auts).1);
    }

    #[test]
    fn opc_and_op_agree() {
        let a = compute(h(K), Operator::Op(h(OP)), &h(RAND), &h(SQN), &h(AMF));
        let b = compute(
            h(K),
            Operator::Opc(h("cd63cb71954a9f4e48a5994e37a02baf")),
            &h(RAND),
            &h(SQN),
            &h(AMF),
        );
        assert_eq!(a, b);
    }
}
