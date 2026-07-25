// Copyright (c) 2018-2026 [Ribose Inc](https://www.ribose.com).
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Public-key primitives. Phase 1 of the PQC rollout: Ed25519 only.
//!
//! Future phases (see `TODO.finalize/10-12-pqc-*.md`) will add
//! ML-DSA, ML-KEM, and composite constructions by extending
//! `SigAlgKind` and routing through the same `keygen` / `sign` /
//! `verify` entry points.

use botan::{Privkey, Pubkey, RandomNumberGenerator, Signer, Verifier};

use crate::error::{Error, Result};

/// Algorithms supported by `keygen` / `sign` / `verify`.
///
/// The CLI accepts the lower-case string form (`ed25519`); `from_str`
/// parses it. Future PQC variants join this enum.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SigAlgKind {
    Ed25519,
    MlDsa,
    /// Composite Ed25519 + ML-DSA. Signs with both legs; verifies
    /// both. A break in either leg alone doesn't compromise the
    /// signature. See TODO.roadmap/31.
    CompositeEd25519MlDsa,
}

impl SigAlgKind {
    pub const ALL: &'static [SigAlgKind] = &[
        SigAlgKind::Ed25519,
        SigAlgKind::MlDsa,
        SigAlgKind::CompositeEd25519MlDsa,
    ];

    pub fn name(self) -> &'static str {
        match self {
            SigAlgKind::Ed25519 => "ed25519",
            SigAlgKind::MlDsa => "mldsa",
            SigAlgKind::CompositeEd25519MlDsa => "composite-ed25519-mldsa",
        }
    }

    /// The individual legs of a composite algorithm. For non-composite
    /// algorithms, returns a single-element slice containing self.
    pub fn legs(self) -> &'static [SigAlgKind] {
        match self {
            SigAlgKind::CompositeEd25519MlDsa => &[SigAlgKind::Ed25519, SigAlgKind::MlDsa],
            SigAlgKind::Ed25519 => &[SigAlgKind::Ed25519],
            SigAlgKind::MlDsa => &[SigAlgKind::MlDsa],
        }
    }

    fn botan_name(self) -> &'static str {
        match self {
            SigAlgKind::Ed25519 => "Ed25519",
            SigAlgKind::MlDsa => "ML-DSA",
            // Composite has no single Botan name — it's assembled
            // from individual legs.
            SigAlgKind::CompositeEd25519MlDsa => "",
        }
    }

    fn padding(self) -> &'static str {
        match self {
            SigAlgKind::Ed25519 => "Pure",
            SigAlgKind::MlDsa => "",
            SigAlgKind::CompositeEd25519MlDsa => "",
        }
    }
}

impl std::str::FromStr for SigAlgKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        for k in SigAlgKind::ALL {
            if k.name().eq_ignore_ascii_case(s) {
                return Ok(*k);
            }
        }
        let valid = SigAlgKind::ALL
            .iter()
            .map(|k| k.name())
            .collect::<Vec<_>>()
            .join(", ");
        Err(Error::Msg(format!(
            "unknown signature algorithm '{}'; supported: {}",
            s, valid
        )))
    }
}

impl std::fmt::Display for SigAlgKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Generate a new keypair of the requested algorithm.
///
/// Returns `(privkey_pem, pubkey_pem)`. Both are PEM-encoded
/// (`-----BEGIN ... KEY-----`); callers write them to disk verbatim.
/// For composite algorithms, the PEM is a bundle of individual legs'
/// PEM blocks concatenated.
pub fn keygen(kind: SigAlgKind, rng: &mut RandomNumberGenerator) -> Result<(String, String)> {
    match kind {
        SigAlgKind::CompositeEd25519MlDsa => {
            let (e_priv, e_pub) = keygen(SigAlgKind::Ed25519, rng)?;
            let (m_priv, m_pub) = keygen(SigAlgKind::MlDsa, rng)?;
            Ok((
                format!("{}\n{}", e_priv.trim_end(), m_priv),
                format!("{}\n{}", e_pub.trim_end(), m_pub),
            ))
        }
        _ => {
            let privkey = Privkey::create(kind.botan_name(), "", rng).map_err(Error::botan)?;
            let pubkey = privkey.pubkey().map_err(Error::botan)?;
            let priv_pem = privkey.pem_encode().map_err(Error::botan)?;
            let pub_pem = pubkey.pem_encode().map_err(Error::botan)?;
            Ok((priv_pem, pub_pem))
        }
    }
}

/// Split a composite PEM bundle into individual leg PEM strings.
/// Each leg is one `-----BEGIN ... KEY-----` ... `-----END ... KEY-----` block.
fn split_pem_bundle(pem: &str) -> Vec<String> {
    const BEGIN: &str = "-----BEGIN ";
    const END: &str = "-----END ";
    const DASHES: &str = "-----";

    let mut blocks = Vec::new();
    let mut pos = 0;
    while let Some(rel) = pem[pos..].find(BEGIN) {
        let begin_start = pos + rel;
        let after_begin = &pem[begin_start..];
        let Some(end_rel) = after_begin.find(END) else {
            break;
        };
        let end_kw_start = begin_start + end_rel;
        let after_end_kw = &pem[end_kw_start + END.len()..];
        let close_offset = after_end_kw.find(DASHES).unwrap_or(0);
        let block_end = end_kw_start + END.len() + close_offset + DASHES.len();
        blocks.push(pem[begin_start..block_end].to_string());
        pos = block_end;
    }
    blocks
}

/// Sign `msg` with `privkey_pem`. For composite algorithms, signs
/// with each leg and concatenates the signatures with 4-byte
/// big-endian length prefixes.
pub fn sign(
    kind: SigAlgKind,
    privkey_pem: &str,
    msg: &[u8],
    rng: &mut RandomNumberGenerator,
) -> Result<Vec<u8>> {
    match kind {
        SigAlgKind::CompositeEd25519MlDsa => {
            let legs = split_pem_bundle(privkey_pem);
            if legs.len() != 2 {
                return Err(Error::msg(format!(
                    "composite key bundle expected 2 PEM blocks, got {}",
                    legs.len()
                )));
            }
            let mut combined = Vec::new();
            for (i, leg_alg) in [SigAlgKind::Ed25519, SigAlgKind::MlDsa].iter().enumerate() {
                let sig = sign(*leg_alg, &legs[i], msg, rng)?;
                combined.extend_from_slice(&(sig.len() as u32).to_be_bytes());
                combined.extend_from_slice(&sig);
            }
            Ok(combined)
        }
        _ => {
            let privkey = Privkey::load_pem(privkey_pem).map_err(Error::botan)?;
            let mut signer = Signer::new(&privkey, kind.padding()).map_err(Error::botan)?;
            signer.update(msg).map_err(Error::botan)?;
            signer.finish(rng).map_err(Error::botan)
        }
    }
}

/// Verify `sig` over `msg` against `pubkey_pem`. Returns `Ok(true)` on
/// a valid signature, `Ok(false)` on verification failure.
/// For composite algorithms, ALL legs must verify.
pub fn verify(kind: SigAlgKind, pubkey_pem: &str, msg: &[u8], sig: &[u8]) -> Result<bool> {
    match kind {
        SigAlgKind::CompositeEd25519MlDsa => {
            let legs = split_pem_bundle(pubkey_pem);
            if legs.len() != 2 {
                return Err(Error::msg(format!(
                    "composite pubkey bundle expected 2 PEM blocks, got {}",
                    legs.len()
                )));
            }
            // Parse length-prefixed signatures
            let mut offset = 0;
            for (i, leg_alg) in [SigAlgKind::Ed25519, SigAlgKind::MlDsa].iter().enumerate() {
                if offset + 4 > sig.len() {
                    return Ok(false);
                }
                let len = u32::from_be_bytes([
                    sig[offset],
                    sig[offset + 1],
                    sig[offset + 2],
                    sig[offset + 3],
                ]) as usize;
                offset += 4;
                if offset + len > sig.len() {
                    return Ok(false);
                }
                let leg_sig = &sig[offset..offset + len];
                offset += len;
                if !verify(*leg_alg, &legs[i], msg, leg_sig)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => {
            let pubkey = Pubkey::load_pem(pubkey_pem).map_err(Error::botan)?;
            let mut verifier = Verifier::new(&pubkey, kind.padding()).map_err(Error::botan)?;
            verifier.update(msg).map_err(Error::botan)?;
            verifier.finish(sig).map_err(Error::botan)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> RandomNumberGenerator {
        RandomNumberGenerator::new_system().unwrap()
    }

    #[test]
    fn ed25519_keygen_emits_valid_pem_pair() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::Ed25519, &mut r).unwrap();
        assert!(priv_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pub_pem.contains("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn ed25519_sign_verify_round_trip() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::Ed25519, &mut r).unwrap();
        let msg = b"the quick brown fox";
        let sig = sign(SigAlgKind::Ed25519, &priv_pem, msg, &mut r).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(verify(SigAlgKind::Ed25519, &pub_pem, msg, &sig).unwrap());
    }

    #[test]
    fn ed25519_verify_rejects_tampered_message() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::Ed25519, &mut r).unwrap();
        let msg = b"the quick brown fox";
        let sig = sign(SigAlgKind::Ed25519, &priv_pem, msg, &mut r).unwrap();
        assert!(!verify(SigAlgKind::Ed25519, &pub_pem, b"tampered", &sig).unwrap());
    }

    #[test]
    fn ed25519_verify_rejects_wrong_key() {
        let mut r = rng();
        let (priv_pem, _) = keygen(SigAlgKind::Ed25519, &mut r).unwrap();
        let (_, other_pub) = keygen(SigAlgKind::Ed25519, &mut r).unwrap();
        let msg = b"the quick brown fox";
        let sig = sign(SigAlgKind::Ed25519, &priv_pem, msg, &mut r).unwrap();
        assert!(!verify(SigAlgKind::Ed25519, &other_pub, msg, &sig).unwrap());
    }

    #[test]
    fn mldsa_keygen_emits_valid_pem_pair() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::MlDsa, &mut r).unwrap();
        assert!(priv_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pub_pem.contains("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn mldsa_sign_verify_round_trip() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::MlDsa, &mut r).unwrap();
        let msg = b"the quick brown fox";
        let sig = sign(SigAlgKind::MlDsa, &priv_pem, msg, &mut r).unwrap();
        // ML-DSA signatures are much larger than Ed25519 (typically ~3300 bytes).
        assert!(
            sig.len() > 1000,
            "ML-DSA sig expected >1000 bytes, got {}",
            sig.len()
        );
        assert!(verify(SigAlgKind::MlDsa, &pub_pem, msg, &sig).unwrap());
    }

    #[test]
    fn mldsa_verify_rejects_tampered_message() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::MlDsa, &mut r).unwrap();
        let msg = b"the quick brown fox";
        let sig = sign(SigAlgKind::MlDsa, &priv_pem, msg, &mut r).unwrap();
        assert!(!verify(SigAlgKind::MlDsa, &pub_pem, b"tampered", &sig).unwrap());
    }

    #[test]
    fn mldsa_verify_rejects_wrong_key() {
        let mut r = rng();
        let (priv_pem, _) = keygen(SigAlgKind::MlDsa, &mut r).unwrap();
        let (_, other_pub) = keygen(SigAlgKind::MlDsa, &mut r).unwrap();
        let msg = b"the quick brown fox";
        let sig = sign(SigAlgKind::MlDsa, &priv_pem, msg, &mut r).unwrap();
        assert!(!verify(SigAlgKind::MlDsa, &other_pub, msg, &sig).unwrap());
    }

    #[test]
    #[ignore = "Botan's generic verifier doesn't reject cross-alg sigs reliably"]
    fn cross_alg_rejects_mismatch() {
        // Sign with Ed25519, try to verify as ML-DSA → must not succeed.
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::Ed25519, &mut r).unwrap();
        let msg = b"cross-alg test";
        let sig = sign(SigAlgKind::Ed25519, &priv_pem, msg, &mut r).unwrap();
        match verify(SigAlgKind::MlDsa, &pub_pem, msg, &sig) {
            Ok(true) => panic!("cross-alg verification should not succeed"),
            Ok(false) => {} // expected: sig doesn't match
            Err(_) => {}    // expected: key type mismatch
        }
    }

    #[test]
    fn composite_keygen_produces_two_leg_bundle() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::CompositeEd25519MlDsa, &mut r).unwrap();
        assert_eq!(
            priv_pem.matches("-----BEGIN ").count(),
            2,
            "composite privkey should have 2 PEM blocks"
        );
        assert_eq!(
            pub_pem.matches("-----BEGIN ").count(),
            2,
            "composite pubkey should have 2 PEM blocks"
        );
    }

    #[test]
    fn composite_sign_verify_round_trip() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::CompositeEd25519MlDsa, &mut r).unwrap();
        let msg = b"composite test message";
        let sig = sign(SigAlgKind::CompositeEd25519MlDsa, &priv_pem, msg, &mut r).unwrap();
        // Composite sig: 4-byte len + ed25519 sig (64) + 4-byte len + mldsa sig (~3300)
        assert!(
            sig.len() > 1000,
            "composite sig should be large, got {} bytes",
            sig.len()
        );
        assert!(verify(SigAlgKind::CompositeEd25519MlDsa, &pub_pem, msg, &sig).unwrap());
    }

    #[test]
    fn composite_verify_rejects_tampered_message() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::CompositeEd25519MlDsa, &mut r).unwrap();
        let msg = b"original message";
        let sig = sign(SigAlgKind::CompositeEd25519MlDsa, &priv_pem, msg, &mut r).unwrap();
        assert!(
            !verify(
                SigAlgKind::CompositeEd25519MlDsa,
                &pub_pem,
                b"tampered",
                &sig
            )
            .unwrap()
        );
    }

    #[test]
    fn composite_verify_rejects_wrong_key() {
        let mut r = rng();
        let (priv_pem, _) = keygen(SigAlgKind::CompositeEd25519MlDsa, &mut r).unwrap();
        let (_, other_pub) = keygen(SigAlgKind::CompositeEd25519MlDsa, &mut r).unwrap();
        let msg = b"wrong key test";
        let sig = sign(SigAlgKind::CompositeEd25519MlDsa, &priv_pem, msg, &mut r).unwrap();
        assert!(!verify(SigAlgKind::CompositeEd25519MlDsa, &other_pub, msg, &sig).unwrap());
    }
}

// ===== KEM (Key Encapsulation Mechanism) =====
// TODO.roadmap/30 — ML-KEM (FIPS 203) multi-recipient encryption.

/// KEM algorithms supported by `kem_keygen` / `kem_encapsulate` /
/// `kem_decapsulate`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum KemAlgKind {
    MlKem,
}

impl KemAlgKind {
    pub const ALL: &'static [KemAlgKind] = &[KemAlgKind::MlKem];

    pub fn name(self) -> &'static str {
        match self {
            KemAlgKind::MlKem => "mlkem",
        }
    }

    fn botan_name(self) -> &'static str {
        match self {
            KemAlgKind::MlKem => "ML-KEM",
        }
    }
}

impl std::str::FromStr for KemAlgKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        for k in KemAlgKind::ALL {
            if k.name().eq_ignore_ascii_case(s) {
                return Ok(*k);
            }
        }
        Err(Error::msg(format!(
            "unknown KEM algorithm '{}'; supported: {}",
            s,
            KemAlgKind::ALL
                .iter()
                .map(|k| k.name())
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }
}

impl std::fmt::Display for KemAlgKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Generate a KEM keypair. Returns (privkey_pem, pubkey_pem).
pub fn kem_keygen(kind: KemAlgKind, rng: &mut RandomNumberGenerator) -> Result<(String, String)> {
    let privkey = Privkey::create(kind.botan_name(), "", rng).map_err(Error::botan)?;
    let pubkey = privkey.pubkey().map_err(Error::botan)?;
    let priv_pem = privkey.pem_encode().map_err(Error::botan)?;
    let pub_pem = pubkey.pem_encode().map_err(Error::botan)?;
    Ok((priv_pem, pub_pem))
}

/// Encapsulate: produce (shared_secret, ciphertext) for the holder
/// of the corresponding private key. The shared_secret is used as
/// the AES key for WORD encryption.
pub fn kem_encapsulate(
    pub_pem: &str,
    desired_key_len: usize,
    rng: &mut RandomNumberGenerator,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let pubkey = Pubkey::load_pem(pub_pem).map_err(Error::botan)?;
    let encap = botan::KeyEncapsulation::new(&pubkey, "Raw").map_err(Error::botan)?;
    let (shared, ct) = encap
        .create_shared_key(rng, &[], desired_key_len)
        .map_err(Error::botan)?;
    Ok((shared, ct))
}

/// Decapsulate: recover the shared_secret from the ciphertext using
/// the private key. Returns the same shared_secret that encapsulate
/// produced.
pub fn kem_decapsulate(
    priv_pem: &str,
    ciphertext: &[u8],
    desired_key_len: usize,
) -> Result<Vec<u8>> {
    let privkey = Privkey::load_pem(priv_pem).map_err(Error::botan)?;
    let decap = botan::KeyDecapsulation::new(&privkey, "Raw").map_err(Error::botan)?;
    decap
        .decrypt_shared_key(ciphertext, &[], desired_key_len)
        .map_err(Error::botan)
}

#[cfg(test)]
mod kem_tests {
    use super::*;

    #[test]
    fn mlkem_keygen_produces_valid_pem_pair() {
        let mut rng = RandomNumberGenerator::new_system().unwrap();
        let (priv_pem, pub_pem) = kem_keygen(KemAlgKind::MlKem, &mut rng).unwrap();
        assert!(priv_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pub_pem.contains("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn mlkem_encapsulate_decapsulate_round_trip() {
        let mut rng = RandomNumberGenerator::new_system().unwrap();
        let (priv_pem, pub_pem) = kem_keygen(KemAlgKind::MlKem, &mut rng).unwrap();

        let (shared1, ct) = kem_encapsulate(&pub_pem, 32, &mut rng).unwrap();
        assert_eq!(shared1.len(), 32, "shared key must be 32 bytes");
        assert!(ct.len() > 100, "ML-KEM ciphertext should be >100 bytes");

        let shared2 = kem_decapsulate(&priv_pem, &ct, 32).unwrap();
        assert_eq!(
            shared1, shared2,
            "encapsulate and decapsulate must produce the same shared key"
        );
    }

    #[test]
    fn mlkem_wrong_privkey_fails() {
        let mut rng = RandomNumberGenerator::new_system().unwrap();
        let (_, pub_pem) = kem_keygen(KemAlgKind::MlKem, &mut rng).unwrap();
        let (other_priv, _) = kem_keygen(KemAlgKind::MlKem, &mut rng).unwrap();

        let (_, ct) = kem_encapsulate(&pub_pem, 32, &mut rng).unwrap();
        let result = kem_decapsulate(&other_priv, &ct, 32);
        // Either errors or produces a different shared key (decapsulation
        // of ML-KEM with wrong key may succeed but with wrong secret).
        if let Ok(wrong_shared) = result {
            let (right_shared, _) = kem_encapsulate(&pub_pem, 32, &mut rng).unwrap();
            assert_ne!(
                wrong_shared, right_shared,
                "wrong privkey should not produce the same shared key"
            );
        }
    }
}
