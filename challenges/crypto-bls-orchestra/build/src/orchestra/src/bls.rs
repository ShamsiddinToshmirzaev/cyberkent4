// BLS12-381 primitives for C15 (minimal-pubkey-size: pk in G1, sig in G2).
// Built on the zkcrypto bls12_381 crate. All decode paths enforce the prime-order
// subgroup (from_compressed) and reject the identity — the challenge's only
// intended second bug is at the application/weight layer, never a point trick.
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar,
};
use group::Curve;
use sha2::{Digest, Sha256};

pub const APP_PREFIX: &[u8] = b"setlist-approval-v1|";

pub fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(char::from_digit((x >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((x & 0xf) as u32, 16).unwrap());
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let hv = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut o = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        o.push((hv(b[i])? << 4) | hv(b[i + 1])?);
        i += 2;
    }
    Some(o)
}

pub fn hash_to_g2(dst: &[u8], msg: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([msg], dst)
}

pub fn approval_msg(title: &str) -> Vec<u8> {
    let mut v = APP_PREFIX.to_vec();
    v.extend_from_slice(title.as_bytes());
    v
}

pub fn g1_gen() -> G1Projective {
    G1Projective::generator()
}

/// Decode a compressed G1 point (48 bytes hex): subgroup-checked, identity rejected.
pub fn decode_g1(h: &str) -> Option<G1Affine> {
    let b = hex_decode(h)?;
    if b.len() != 48 {
        return None;
    }
    let mut a = [0u8; 48];
    a.copy_from_slice(&b);
    let p: Option<G1Affine> = G1Affine::from_compressed(&a).into();
    let p = p?;
    if bool::from(p.is_identity()) {
        return None;
    }
    Some(p)
}

/// Decode a compressed G2 point (96 bytes hex): subgroup-checked, identity rejected.
pub fn decode_g2(h: &str) -> Option<G2Affine> {
    let b = hex_decode(h)?;
    if b.len() != 96 {
        return None;
    }
    let mut a = [0u8; 96];
    a.copy_from_slice(&b);
    let p: Option<G2Affine> = G2Affine::from_compressed(&a).into();
    let p = p?;
    if bool::from(p.is_identity()) {
        return None;
    }
    Some(p)
}

pub fn encode_g1(p: &G1Affine) -> String {
    hex_encode(&p.to_compressed())
}
pub fn encode_g2(p: &G2Affine) -> String {
    hex_encode(&p.to_compressed())
}

/// Aggregate verify e(apk, H(dst,msg)) == e(G1, asig), one Miller loop + final exp.
/// Caller must have already rejected identity apk/asig.
pub fn verify_agg(apk: &G1Affine, dst: &[u8], msg: &[u8], asig: &G2Affine) -> bool {
    let h = G2Prepared::from(hash_to_g2(dst, msg).to_affine());
    let sp = G2Prepared::from(*asig);
    let neg_g1 = -G1Affine::generator();
    multi_miller_loop(&[(apk, &h), (&neg_g1, &sp)]).final_exponentiation() == Gt::identity()
}

/// Proof of possession: pop = sk * H_pop(pk); verify e(pk, H_pop(pk)) == e(G1, pop).
pub fn verify_pop(pk: &G1Affine, pop_dst: &[u8], pop: &G2Affine) -> bool {
    verify_agg(pk, pop_dst, &pk.to_compressed(), pop)
}

/// Deterministic key derivation from (seed, idx) — server-side setup only; the
/// secret is used to compute the public key and then discarded.
pub fn scalar_from_seed(seed: u64, idx: u64) -> Scalar {
    let mut h = Sha256::new();
    h.update(b"C15-keygen|");
    h.update(seed.to_le_bytes());
    h.update(idx.to_le_bytes());
    let d1 = h.finalize();
    let mut h2 = Sha256::new();
    h2.update(b"C15-keygen2|");
    h2.update(d1);
    let d2 = h2.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&d1);
    wide[32..].copy_from_slice(&d2);
    Scalar::from_bytes_wide(&wide)
}

pub fn pk_of(sk: &Scalar) -> G1Affine {
    (g1_gen() * sk).to_affine()
}

pub fn sum_g1(points: &[G1Affine]) -> G1Projective {
    points.iter().map(G1Projective::from).sum()
}
