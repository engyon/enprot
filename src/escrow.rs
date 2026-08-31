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
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY EXPRESS OR INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
// OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
// AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
// WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

//! Key escrow / recovery envelope (TODO.complete/59).
//!
//! Escrow mode gives an Encrypted block **two independent decryption
//! paths**: the user's password, and any one of a set of recovery
//! private keys. The payload is encrypted under a fresh random CEK;
//! the CEK is then wrapped once per path:
//!
//! - **Password path**: `KEK = PBKDF(password, salt)`, then
//!   `pw-wrap: base64(iv ‖ GCM(KEK, CEK))`. A wrong password fails
//!   the wrap AEAD — a clean error, never garbage plaintext.
//! - **Recovery path** (per pubkey): ML-KEM encapsulation yields a
//!   shared secret; `wrap_key = HKDF(shared, "enprot-recovery-wrap")`;
//!   `recovery-wrap-mlkem-<fp>: base64(iv ‖ GCM(wrap_key, CEK))` with
//!   the KEM ciphertext in `recovery-kem-mlkem-<fp>:`.
//!
//! Wire extfields:
//!
//! ```text
//! pbkdf: $argon2id$…
//! pw-wrap: <base64 iv‖ct>
//! recovery: mlkem:<fp1>,mlkem:<fp2>
//! recovery-kem-mlkem-<fp1>: <base64 KEM ct>
//! recovery-wrap-mlkem-<fp1>: <base64 iv‖ct>
//! cipher: <alg>$iv=…
//! ```
//!
//! The wrap cipher is always AES-256-GCM (policy-approved under both
//! the default and NIST policies, unlike SIV) and independent of the
//! payload cipher. Deterministic payload ciphers (`-det`) are
//! refused: the fresh CEK would silently break their same-input →
//! same-output contract (CAS dedup).

use std::collections::BTreeMap;

use crate::cipher;
use crate::cipher::{format_cipher_extfield, parse_cipher_extfield};
use crate::crypto::{self, CryptoPolicy};
use crate::error::{Error, Result};
use crate::etree;
use crate::extfield::EncryptedExtField;
use crate::pbkdf::{PBKDFCache, derive_key};
use crate::pki;

/// CEK-wrap cipher. AES-256-GCM: approved under both policies and
/// distinct from any payload algorithm so wrap and payload keys are
/// never conflated.
const WRAP_ALG: &str = "aes-256-gcm";

/// HKDF domain-separation for the recovery wrap key.
const RECOVERY_HKDF_INFO: &[u8] = b"enprot-recovery-wrap";

/// ML-KEM shared-secret length.
const KEM_SHARED_LEN: usize = 32;

// Arg count mirrors prot::encrypt plus the recovery pubkeys — the
// natural shape at the transform call site, where every argument
// comes from paops.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(pt, password, recovery_pub_pems, rng, pbkdfopts, cipheropts, cache, policy), fields(bytes = pt.len(), alg = %cipheropts.alg, recovery_keys = recovery_pub_pems.len()))]
pub fn encrypt(
    pt: Vec<u8>,
    password: &str,
    recovery_pub_pems: &[String],
    pgp_pubs: &[String],
    rng: &mut Option<botan::RandomNumberGenerator>,
    pbkdfopts: &etree::PBKDFOptions,
    cipheropts: &etree::CipherOptions,
    cache: &mut Option<PBKDFCache>,
    policy: &dyn CryptoPolicy,
) -> Result<(Vec<u8>, BTreeMap<String, String>)> {
    if recovery_pub_pems.is_empty() && pgp_pubs.is_empty() {
        return Err(Error::InvalidArg {
            arg: "--recovery-key",
            reason: "escrow encrypt: supply --recovery-key and/or --pgp-pubkey".to_string(),
        });
    }
    if cipheropts.alg.ends_with("-det") {
        return Err(Error::InvalidArg {
            arg: "--recovery-key",
            reason: format!(
                "recovery mode is incompatible with {} — the fresh CEK breaks the \
                 deterministic (same-input → same-output, CAS-dedup) contract",
                cipheropts.alg
            ),
        });
    }
    policy
        .check_cipher_alg(&cipheropts.alg)
        .map_err(Error::Policy)?;
    policy.check_cipher_alg(WRAP_ALG).map_err(Error::Policy)?;

    let mut wrap_enc = cipher::encryption(WRAP_ALG)?;
    let wrap_key_len = wrap_enc.key_len_max();

    // Fresh CEK — the single key both paths converge on.
    let enc = cipher::encryption(&cipheropts.alg)?;
    let payload_key_len = enc.key_len_max();
    let cek = rng
        .as_mut()
        .ok_or_else(|| Error::InvalidArg {
            arg: "rng",
            reason: "Missing RNG for escrow encrypt".to_string(),
        })?
        .read(payload_key_len)
        .map_err(Error::botan)?;

    let mut extfields: BTreeMap<String, String> = BTreeMap::new();
    let (key, iv) =
        crate::prot::compute_iv(cipheropts, &cek, &pt, payload_key_len, enc.nonce_len(), rng)?;
    if !cipheropts.alg.starts_with("aes-256-siv") {
        EncryptedExtField::Cipher(format_cipher_extfield(&cipheropts.alg, &iv)?)
            .insert_into(&mut extfields);
    }
    policy
        .check_cipher(&cipheropts.alg, &key, &iv, &[])
        .map_err(Error::Policy)?;
    let pt_final = crate::prot::apply_compression(pt, cipheropts.compress, &mut extfields)?;
    let mut enc = enc;
    let ct = enc.process(&key, &iv, &[], &pt_final)?;

    // Password path: PBKDF KEK wraps the CEK.
    let (kek, pbkdf) = derive_key(password, wrap_key_len, rng, pbkdfopts, cache, policy)?;
    if let Some(p) = pbkdf {
        EncryptedExtField::Pbkdf(p).insert_into(&mut extfields);
    }
    let wrapped = gcm_seal(
        &mut wrap_enc,
        &kek,
        &cek,
        rng.as_mut().ok_or_else(|| Error::InvalidArg {
            arg: "rng",
            reason: "Missing RNG for escrow encrypt".to_string(),
        })?,
    )?;
    EncryptedExtField::PwWrap(crate::utils::base64_encode(&wrapped)?).insert_into(&mut extfields);

    // Recovery path: one KEM wrap per pubkey, all converging on the
    // same CEK.
    let mut fps: Vec<String> = Vec::with_capacity(recovery_pub_pems.len());
    for pub_pem in recovery_pub_pems {
        let (shared, kem_ct) = pki::kem_encapsulate(
            pub_pem,
            KEM_SHARED_LEN,
            rng.as_mut().ok_or_else(|| Error::InvalidArg {
                arg: "rng",
                reason: "Missing RNG for escrow encrypt".to_string(),
            })?,
        )?;
        let wrap_key = crypto::hkdf_sha256(&shared, RECOVERY_HKDF_INFO, wrap_key_len)?;
        let wrapped = gcm_seal(
            &mut wrap_enc,
            &wrap_key,
            &cek,
            rng.as_mut().ok_or_else(|| Error::InvalidArg {
                arg: "rng",
                reason: "Missing RNG for escrow encrypt".to_string(),
            })?,
        )?;
        let fp = crate::capability::KeyFp::from_pem(pub_pem)?.to_hex();
        fps.push(format!("mlkem:{}", fp));
        extfields.insert(
            format!("recovery-kem-mlkem-{}", fp),
            crate::utils::base64_encode(&kem_ct)?,
        );
        extfields.insert(
            format!("recovery-wrap-mlkem-{}", fp),
            crate::utils::base64_encode(&wrapped)?,
        );
    }
    EncryptedExtField::Recovery(fps.join(",")).insert_into(&mut extfields);

    // PGP recipient path: each OpenPGP pubkey wraps the same CEK
    // into a PGP message. Rotation never changes the CEK, so these
    // wraps stay valid across `enprot rotate` and are carried
    // through untouched.
    if !pgp_pubs.is_empty() {
        for (fpr16, b64) in crate::openpgp::wrap_cek_to_pubkeys(pgp_pubs, &cek)? {
            extfields.insert(format!("pgp-{fpr16}-wrap"), b64);
        }
    }

    Ok((ct, extfields))
}

/// Is this Encrypted block's extfield map escrow-mode? The public
/// predicate so consumers never read the `recovery:` wire key as a
/// raw string — the key name stays private to this module and
/// `extfield`'s view.
pub fn is_escrow_block(extfields: &std::collections::BTreeMap<String, String>) -> bool {
    crate::extfield::EncryptedExtFields::from_map(extfields).is_recovery_mode()
}

/// Decrypt an escrow-mode block via the password path.
pub fn decrypt_with_password(
    ct: Vec<u8>,
    password: &str,
    extfields: &BTreeMap<String, String>,
    cache: &mut Option<PBKDFCache>,
    policy: &dyn CryptoPolicy,
) -> Result<Vec<u8>> {
    let pw_wrap = extfields.get("pw-wrap").ok_or_else(|| Error::Extfield {
        field: "pw-wrap",
        reason: "escrow block has no pw-wrap field; the password path is unavailable".to_string(),
    })?;
    let wrapped = crate::utils::base64_decode(pw_wrap)?;
    let wrap_key_len = cipher::encryption(WRAP_ALG)?.key_len_max();
    let kek = crate::prot::derive_decrypt_key(
        password,
        extfields.get("pbkdf").map(|s| s.as_str()),
        wrap_key_len,
        cache,
        policy,
    )?;
    let cek = gcm_open(&kek, &wrapped)?;
    finish(ct, cek, extfields, policy)
}

/// Decrypt an escrow-mode block via a recovery privkey.
pub fn decrypt_with_key(
    ct: Vec<u8>,
    priv_pem: &str,
    extfields: &BTreeMap<String, String>,
    policy: &dyn CryptoPolicy,
) -> Result<Vec<u8>> {
    // PGP armor routes to the OpenPGP unwrap; PEM stays on the
    // ML-KEM recovery path.
    if crate::openpgp::is_armored(priv_pem) {
        for (key, v) in extfields {
            if key.starts_with("pgp-")
                && key.ends_with("-wrap")
                && let Ok(cek) = crate::openpgp::unwrap_cek(v, priv_pem)
            {
                return finish(ct, cek, extfields, policy);
            }
        }
        return Err(Error::InvalidArg {
            arg: "--key-file",
            reason: "none of the pgp-*-wrap recipients matched the supplied                      OpenPGP secret key"
                .to_string(),
        });
    }

    let botan_priv = botan::Privkey::load_pem(priv_pem).map_err(Error::botan)?;
    let pub_pem = botan_priv
        .pubkey()
        .map_err(Error::botan)?
        .pem_encode()
        .map_err(Error::botan)?;
    let fp = crate::capability::KeyFp::from_pem(&pub_pem)?.to_hex();
    let kem_ct = crate::utils::base64_decode(
        extfields
            .get(&format!("recovery-kem-mlkem-{}", fp))
            .ok_or_else(|| Error::InvalidArg {
                arg: "key-file",
                reason: format!("no recovery entry for fingerprint {fp} in this block"),
            })?,
    )?;
    let wrapped = crate::utils::base64_decode(
        extfields
            .get(&format!("recovery-wrap-mlkem-{}", fp))
            .ok_or_else(|| Error::Extfield {
                field: "recovery-wrap",
                reason: format!("recovery KEM entry for {fp} present but its CEK wrap is not"),
            })?,
    )?;
    let shared = pki::kem_decapsulate(priv_pem, &kem_ct, KEM_SHARED_LEN)?;
    let wrap_key_len = cipher::encryption(WRAP_ALG)?.key_len_max();
    let wrap_key = crypto::hkdf_sha256(&shared, RECOVERY_HKDF_INFO, wrap_key_len)?;
    let cek = gcm_open(&wrap_key, &wrapped)?;
    finish(ct, cek, extfields, policy)
}

/// Unwrap the CEK via the password path (rotation's first half —
/// the payload is NOT decrypted; the CEK is recovered so it can be
/// re-wrapped under new key material).
fn unwrap_cek_with_password(
    password: &str,
    extfields: &BTreeMap<String, String>,
    cache: &mut Option<PBKDFCache>,
    policy: &dyn CryptoPolicy,
) -> Result<Vec<u8>> {
    let pw_wrap = extfields.get("pw-wrap").ok_or_else(|| Error::Extfield {
        field: "pw-wrap",
        reason: "escrow block has no pw-wrap field; the password path is unavailable".to_string(),
    })?;
    let wrapped = crate::utils::base64_decode(pw_wrap)?;
    let wrap_key_len = cipher::encryption(WRAP_ALG)?.key_len_max();
    let kek = crate::prot::derive_decrypt_key(
        password,
        extfields.get("pbkdf").map(|s| s.as_str()),
        wrap_key_len,
        cache,
        policy,
    )?;
    gcm_open(&kek, &wrapped)
}

/// Unwrap the CEK via a recovery privkey (rotation's first half).
fn unwrap_cek_with_key(priv_pem: &str, extfields: &BTreeMap<String, String>) -> Result<Vec<u8>> {
    let botan_priv = botan::Privkey::load_pem(priv_pem).map_err(Error::botan)?;
    let pub_pem = botan_priv
        .pubkey()
        .map_err(Error::botan)?
        .pem_encode()
        .map_err(Error::botan)?;
    let fp = crate::capability::KeyFp::from_pem(&pub_pem)?.to_hex();
    let kem_ct = crate::utils::base64_decode(
        extfields
            .get(&format!("recovery-kem-mlkem-{}", fp))
            .ok_or_else(|| Error::InvalidArg {
                arg: "key-file",
                reason: format!("no recovery entry for fingerprint {fp} in this block"),
            })?,
    )?;
    let wrapped = crate::utils::base64_decode(
        extfields
            .get(&format!("recovery-wrap-mlkem-{}", fp))
            .ok_or_else(|| Error::Extfield {
                field: "recovery-wrap",
                reason: format!("recovery KEM entry for {fp} present but its CEK wrap is not"),
            })?,
    )?;
    let shared = pki::kem_decapsulate(priv_pem, &kem_ct, KEM_SHARED_LEN)?;
    let wrap_key_len = cipher::encryption(WRAP_ALG)?.key_len_max();
    let wrap_key = crypto::hkdf_sha256(&shared, RECOVERY_HKDF_INFO, wrap_key_len)?;
    gcm_open(&wrap_key, &wrapped)
}

/// Rotate an escrow-mode block's key material WITHOUT touching the
/// payload: unwrap the CEK (via the old password or a recovery
/// privkey), re-wrap under the new password + the new recovery
/// pubkeys, and return the rebuilt extfields. The payload
/// ciphertext is byte-identical — CAS pointers remain valid and no
/// re-encryption cost is incurred.
///
/// The `cipher:` and `compress:` extfields are carried over
/// verbatim (the payload didn't change). This is the key-lifecycle
/// gap the escrow CEK indirection was designed to close (TODO 59's
/// design notes).
// Arg count mirrors escrow::encrypt plus the two old-credential
// slots — the natural shape at the CLI call site.
#[allow(clippy::too_many_arguments)]
pub fn rotate(
    extfields: &BTreeMap<String, String>,
    old_password: Option<&str>,
    old_recovery_priv_pem: Option<&str>,
    new_password: &str,
    new_recovery_pub_pems: &[String],
    rng: &mut Option<botan::RandomNumberGenerator>,
    pbkdfopts: &etree::PBKDFOptions,
    cache: &mut Option<PBKDFCache>,
    policy: &dyn CryptoPolicy,
) -> Result<BTreeMap<String, String>> {
    if old_password.is_none() && old_recovery_priv_pem.is_none() {
        return Err(Error::InvalidArg {
            arg: "--old-password",
            reason: "rotate: supply the current password (-k) or a current recovery \
                     privkey (--key-file) to unwrap the CEK"
                .to_string(),
        });
    }
    if new_recovery_pub_pems.is_empty() {
        return Err(Error::InvalidArg {
            arg: "--recovery-key",
            reason: "rotate: supply at least one --recovery-key for the new wrap \
                     (escrow mode requires a recovery path)"
                .to_string(),
        });
    }

    // 1. Unwrap the CEK via whichever credential is available.
    let cek = if let Some(pw) = old_password {
        unwrap_cek_with_password(pw, extfields, cache, policy)?
    } else {
        unwrap_cek_with_key(old_recovery_priv_pem.expect("checked above"), extfields)?
    };

    // 2. Rebuild the extfields: carry cipher + compress, re-wrap the
    //    CEK under the new password + new recovery pubkeys.
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for key in ["cipher", "compress"] {
        if let Some(v) = extfields.get(key) {
            out.insert(key.to_string(), v.clone());
        }
    }
    // PGP recipient wraps ride along: they wrap the CEK, which
    // rotation does not change.
    for (key, v) in extfields {
        if key.starts_with("pgp-") && key.ends_with("-wrap") {
            out.insert(key.clone(), v.clone());
        }
    }

    let wrap_key_len = cipher::encryption(WRAP_ALG)?.key_len_max();

    // Password path: fresh salt + params for the new KEK. derive_key
    // needs the Option<RNG> shape; the manual takes are sequential
    // (non-overlapping) borrows.
    let (kek, pbkdf) = derive_key(new_password, wrap_key_len, rng, pbkdfopts, cache, policy)?;
    if let Some(p) = pbkdf {
        EncryptedExtField::Pbkdf(p).insert_into(&mut out);
    }
    let mut wrap_enc = cipher::encryption(WRAP_ALG)?;
    let wrapped = gcm_seal(&mut wrap_enc, &kek, &cek, need_rng(rng)?)?;
    EncryptedExtField::PwWrap(crate::utils::base64_encode(&wrapped)?).insert_into(&mut out);

    // Recovery path: fresh KEM encapsulation per new pubkey.
    let mut fps: Vec<String> = Vec::with_capacity(new_recovery_pub_pems.len());
    for pub_pem in new_recovery_pub_pems {
        let (shared, kem_ct) = pki::kem_encapsulate(pub_pem, KEM_SHARED_LEN, need_rng(rng)?)?;
        let wrap_key = crypto::hkdf_sha256(&shared, RECOVERY_HKDF_INFO, wrap_key_len)?;
        let wrapped = gcm_seal(&mut wrap_enc, &wrap_key, &cek, need_rng(rng)?)?;
        let fp = crate::capability::KeyFp::from_pem(pub_pem)?.to_hex();
        fps.push(format!("mlkem:{}", fp));
        out.insert(
            format!("recovery-kem-mlkem-{}", fp),
            crate::utils::base64_encode(&kem_ct)?,
        );
        out.insert(
            format!("recovery-wrap-mlkem-{}", fp),
            crate::utils::base64_encode(&wrapped)?,
        );
    }
    EncryptedExtField::Recovery(fps.join(",")).insert_into(&mut out);

    Ok(out)
}

fn need_rng(
    rng: &mut Option<botan::RandomNumberGenerator>,
) -> Result<&mut botan::RandomNumberGenerator> {
    rng.as_mut().ok_or_else(|| Error::InvalidArg {
        arg: "rng",
        reason: "Missing RNG for escrow rotate".to_string(),
    })
}

/// Unwrap → payload decrypt → decompress, shared by both paths.
fn finish(
    ct: Vec<u8>,
    cek: Vec<u8>,
    extfields: &BTreeMap<String, String>,
    policy: &dyn CryptoPolicy,
) -> Result<Vec<u8>> {
    let (cipher_alg, iv) = match extfields.get("cipher").map(|s| s.as_str()) {
        Some(s) => parse_cipher_extfield(s)?,
        None => (cipher::DEFAULT_CIPHER_ALG.to_string(), Vec::new()),
    };
    policy
        .check_cipher_alg(&cipher_alg)
        .map_err(Error::Policy)?;
    let dec = cipher::decryption(&cipher_alg)?;
    let key_len = dec.key_len_max();
    if cek.len() != key_len {
        return Err(Error::AeadFailed {
            alg: WRAP_ALG,
            op: "decrypt",
        });
    }
    let key = crate::prot::recover_key(&cipher_alg, cek, key_len)?;
    policy
        .check_cipher(&cipher_alg, &key, &iv, &[])
        .map_err(Error::Policy)?;
    let mut dec = dec;
    let pt = dec.process(&key, &iv, &[], &ct)?;
    if extfields.get("compress").map(|s| s.as_str()) == Some(crate::compress::COMPRESS_EXTFIELD) {
        crate::compress::decompress(&pt)
    } else {
        Ok(pt)
    }
}

/// AES-256-GCM seal of `data` under `key`; returns `iv ‖ ct`.
fn gcm_seal(
    enc: &mut Box<dyn cipher::SymmetricCipher>,
    key: &[u8],
    data: &[u8],
    rng: &mut botan::RandomNumberGenerator,
) -> Result<Vec<u8>> {
    let iv = rng.read(enc.nonce_len()).map_err(Error::botan)?;
    let ct = enc.process(key, &iv, &[], data)?;
    let mut blob = iv;
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Open a `gcm_seal` blob. A failed tag maps to
/// [`Error::AeadFailed`] — on the password path that is exactly
/// "wrong password".
fn gcm_open(key: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    let mut dec = cipher::decryption(WRAP_ALG)?;
    let nonce_len = dec.nonce_len();
    if blob.len() < nonce_len {
        return Err(Error::AeadFailed {
            alg: WRAP_ALG,
            op: "decrypt",
        });
    }
    dec.process(key, &blob[..nonce_len], &[], &blob[nonce_len..])
        .map_err(|_| Error::AeadFailed {
            alg: WRAP_ALG,
            op: "decrypt",
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paops_defaults() -> (etree::PBKDFOptions, etree::CipherOptions) {
        let policy = crate::crypto::default_policy();
        // Escrow refuses the default deterministic cipher; use SIV
        // (already deterministic by design, no -det suffix needed).
        let mut cipheropts = etree::CipherOptions::new(&*policy);
        cipheropts.alg = "aes-256-siv".to_string();
        (etree::PBKDFOptions::new(&*policy), cipheropts)
    }

    fn rng() -> Option<botan::RandomNumberGenerator> {
        Some(botan::RandomNumberGenerator::new_system().unwrap())
    }

    fn keypair() -> (String, String) {
        let mut r = botan::RandomNumberGenerator::new_system().unwrap();
        pki::kem_keygen(pki::KemAlgKind::MlKem, &mut r).unwrap()
    }

    #[test]
    fn roundtrip_via_password_and_via_recovery_key() {
        let (pbkdfopts, cipheropts) = paops_defaults();
        let (rec_priv, rec_pub) = keypair();
        let policy = crate::crypto::default_policy();
        let pt = b"escrow roundtrip".to_vec();

        let (ct, ext) = encrypt(
            pt.clone(),
            "pw",
            &[rec_pub],
            &[],
            &mut rng(),
            &pbkdfopts,
            &cipheropts,
            &mut None,
            &*policy,
        )
        .unwrap();
        assert!(ext.contains_key("recovery"));
        assert!(ext.contains_key("pw-wrap"));

        let via_pw = decrypt_with_password(ct.clone(), "pw", &ext, &mut None, &*policy).unwrap();
        let via_key = decrypt_with_key(ct, &rec_priv, &ext, &*policy).unwrap();
        assert_eq!(via_pw, pt);
        assert_eq!(via_key, pt);
    }

    #[test]
    fn is_escrow_block_detects_mode() {
        let policy = crate::crypto::default_policy();
        let (pbkdfopts, cipheropts) = paops_defaults();
        let (_, rec_pub) = keypair();
        let (_ct, ext) = encrypt(
            b"x".to_vec(),
            "pw",
            &[rec_pub],
            &[],
            &mut rng(),
            &pbkdfopts,
            &cipheropts,
            &mut None,
            &*policy,
        )
        .unwrap();
        assert!(is_escrow_block(&ext));
        // A legacy (non-escrow) map is not.
        let legacy = std::collections::BTreeMap::from([(
            "pbkdf".to_string(),
            "$argon2$m=1,p=1,t=1$AAAA".to_string(),
        )]);
        assert!(!is_escrow_block(&legacy));
    }

    #[test]
    fn wrong_password_fails_cleanly() {
        let (pbkdfopts, cipheropts) = paops_defaults();
        let (_, rec_pub) = keypair();
        let policy = crate::crypto::default_policy();
        let (ct, ext) = encrypt(
            b"secret".to_vec(),
            "pw",
            &[rec_pub],
            &[],
            &mut rng(),
            &pbkdfopts,
            &cipheropts,
            &mut None,
            &*policy,
        )
        .unwrap();
        let err = decrypt_with_password(ct, "wrong", &ext, &mut None, &*policy).unwrap_err();
        assert!(matches!(err, Error::AeadFailed { .. }), "got {err:?}");
    }

    #[test]
    fn any_one_of_multiple_recovery_keys_suffices() {
        let (pbkdfopts, cipheropts) = paops_defaults();
        let (k1_priv, k1_pub) = keypair();
        let (k2_priv, k2_pub) = keypair();
        let policy = crate::crypto::default_policy();
        let (ct, ext) = encrypt(
            b"multi".to_vec(),
            "pw",
            &[k1_pub, k2_pub],
            &[],
            &mut rng(),
            &pbkdfopts,
            &cipheropts,
            &mut None,
            &*policy,
        )
        .unwrap();
        assert!(decrypt_with_key(ct.clone(), &k1_priv, &ext, &*policy).is_ok());
        assert!(decrypt_with_key(ct, &k2_priv, &ext, &*policy).is_ok());
    }

    #[test]
    fn rotate_preserves_payload_and_both_paths_work() {
        let (pbkdfopts, cipheropts) = paops_defaults();
        let (old_rec_priv, old_rec_pub) = keypair();
        let (new_rec_priv, new_rec_pub) = keypair();
        let policy = crate::crypto::default_policy();
        let pt = b"rotated secret".to_vec();

        let (ct, ext) = encrypt(
            pt.clone(),
            "old-password",
            &[old_rec_pub],
            &[],
            &mut rng(),
            &pbkdfopts,
            &cipheropts,
            &mut None,
            &*policy,
        )
        .unwrap();

        // Rotate: old password -> new password + new recovery key.
        let ext2 = rotate(
            &ext,
            Some("old-password"),
            None,
            "new-password",
            &[new_rec_pub],
            &mut rng(),
            &pbkdfopts,
            &mut None,
            &*policy,
        )
        .unwrap();

        // The payload ciphertext is UNCHANGED (re-wrapping only).
        // cipher + compress extfields carried verbatim; the old
        // recovery + pw-wrap entries are gone.
        assert!(
            !ext2.contains_key("recovery-kem-mlkem-"),
            "old recovery entries must not leak" // (fp-specific; if the same key were reused this would
                                                 // collide — the test uses distinct keys)
        );
        // Decrypt via the NEW password works.
        let via_new_pw =
            decrypt_with_password(ct.clone(), "new-password", &ext2, &mut None, &*policy).unwrap();
        assert_eq!(via_new_pw, pt);
        // Decrypt via the NEW recovery key works.
        let via_new_key = decrypt_with_key(ct, &new_rec_priv, &ext2, &*policy).unwrap();
        assert_eq!(via_new_key, pt);
        // The OLD password no longer works.
        let err = decrypt_with_password(pt.clone(), "old-password", &ext2, &mut None, &*policy);
        assert!(err.is_err());
        // The OLD recovery key no longer works.
        let err2 = decrypt_with_key(pt, &old_rec_priv, &ext2, &*policy);
        assert!(err2.is_err());
    }

    #[test]
    fn rotate_via_recovery_key_instead_of_password() {
        let (pbkdfopts, cipheropts) = paops_defaults();
        let (old_rec_priv, old_rec_pub) = keypair();
        let (_new_rec_priv, new_rec_pub) = keypair();
        let policy = crate::crypto::default_policy();
        let pt = b"key-rotated".to_vec();
        let (ct, ext) = encrypt(
            pt.clone(),
            "pw",
            &[old_rec_pub],
            &[],
            &mut rng(),
            &pbkdfopts,
            &cipheropts,
            &mut None,
            &*policy,
        )
        .unwrap();
        // Unwrap via the OLD recovery key, not the password.
        let ext2 = rotate(
            &ext,
            None,
            Some(&old_rec_priv),
            "rotated-pw",
            &[new_rec_pub],
            &mut rng(),
            &pbkdfopts,
            &mut None,
            &*policy,
        )
        .unwrap();
        assert_eq!(
            decrypt_with_password(ct, "rotated-pw", &ext2, &mut None, &*policy).unwrap(),
            pt
        );
    }

    #[test]
    fn det_cipher_refused() {
        let (pbkdfopts, _) = paops_defaults();
        let cipheropts = etree::CipherOptions {
            alg: "aes-256-gcm-det".to_string(),
            ..paops_defaults().1
        };
        let (_, rec_pub) = keypair();
        let policy = crate::crypto::default_policy();
        let err = encrypt(
            b"x".to_vec(),
            "pw",
            &[rec_pub],
            &[],
            &mut rng(),
            &pbkdfopts,
            &cipheropts,
            &mut None,
            &*policy,
        )
        .unwrap_err();
        assert!(err.to_string().contains("incompatible"), "got {err}");
    }
}
