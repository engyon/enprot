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

use botan::CipherDirection;
use phf::phf_map;

use crate::error::{Error, Result};

/// Map enprot cipher names to Botan cipher names. Only algorithms Botan
/// actually implements appear here. `aes-256-gcm-siv` (RFC 8452) is not
/// implemented by Botan; it routes through the RustCrypto `aes-gcm-siv`
/// crate via `AesGcmSivCipher`.
pub static BOTAN_CIPHER_ALG_MAP: phf::Map<&'static str, &'static str> = phf_map! {
    "aes-256-siv" => "AES-256/SIV",
    "aes-256-gcm" => "AES-256/GCM",
};

pub trait SymmetricCipher {
    fn alg(&self) -> &str;
    fn nonce_len(&self) -> usize;
    fn key_len_max(&self) -> usize;
    fn process(&mut self, key: &[u8], iv: &[u8], ad: &[u8], data: &[u8]) -> Result<Vec<u8>>;
}

struct BotanCipher {
    alg: String,
    nonce_len: usize,
    key_len_max: usize,
    obj: botan::Cipher,
}

impl BotanCipher {
    fn create(alg: &str, direction: CipherDirection) -> Result<Self> {
        let botan_alg =
            BOTAN_CIPHER_ALG_MAP
                .get(alg)
                .copied()
                .ok_or_else(|| Error::CipherUnknown {
                    alg: alg.to_string(),
                })?;
        let obj = botan::Cipher::new(botan_alg, direction).map_err(Error::botan)?;
        let keyspec = obj.key_spec().map_err(Error::botan)?;
        Ok(BotanCipher {
            alg: alg.to_string(),
            nonce_len: obj.default_nonce_length(),
            key_len_max: keyspec.maximum_keylength(),
            obj,
        })
    }
}

impl SymmetricCipher for BotanCipher {
    fn alg(&self) -> &str {
        &self.alg
    }
    fn nonce_len(&self) -> usize {
        self.nonce_len
    }
    fn key_len_max(&self) -> usize {
        self.key_len_max
    }
    fn process(&mut self, key: &[u8], iv: &[u8], ad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        tracing::trace!(cipher = %self.alg(), key_len = key.len(), "botan cipher process");
        self.obj.set_key(key).map_err(Error::botan)?;
        self.obj.set_associated_data(ad).map_err(Error::botan)?;
        self.obj.process(iv, data).map_err(Error::botan)
    }
}

/// Backend for AES-GCM-SIV (RFC 8452). Botan does not implement this AEAD,
/// so we route through RustCrypto's `aes-gcm-siv` crate. Construction is
/// per-call (the cipher takes the key inline) so there is no key/AD state
/// to retain between calls.
struct AesGcmSivCipher {
    direction: CipherDirection,
}

impl AesGcmSivCipher {
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;

    fn new(direction: CipherDirection) -> Self {
        Self { direction }
    }
}

impl SymmetricCipher for AesGcmSivCipher {
    fn alg(&self) -> &str {
        "aes-256-gcm-siv"
    }
    fn nonce_len(&self) -> usize {
        Self::NONCE_LEN
    }
    fn key_len_max(&self) -> usize {
        Self::KEY_LEN
    }
    fn process(&mut self, key: &[u8], iv: &[u8], ad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        tracing::trace!(cipher = %self.alg(), key_len = key.len(), "aes-gcm-siv cipher process");
        use aes_gcm_siv::Aes256GcmSiv;
        use aes_gcm_siv::aead::{Aead, KeyInit, Payload};

        let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| Error::InvalidArg {
            arg: "key",
            reason: "AES-256-GCM-SIV key must be 32 bytes".to_string(),
        })?;
        let nonce = aes_gcm_siv::aead::generic_array::GenericArray::from_slice(iv);
        let payload = Payload { msg: data, aad: ad };
        match self.direction {
            CipherDirection::Encrypt => {
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| Error::AeadFailed {
                        alg: "aes-256-gcm-siv",
                        op: "encrypt",
                    })
            }
            CipherDirection::Decrypt => {
                cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| Error::AeadFailed {
                        alg: "aes-256-gcm-siv",
                        op: "decrypt",
                    })
            }
        }
    }
}

pub fn encryption(alg: &str) -> Result<Box<dyn SymmetricCipher>> {
    let base = alg.trim_end_matches("-det");
    match base {
        "aes-256-gcm-siv" => Ok(Box::new(AesGcmSivCipher::new(CipherDirection::Encrypt))),
        _ => Ok(Box::new(BotanCipher::create(
            base,
            CipherDirection::Encrypt,
        )?)),
    }
}

pub fn decryption(alg: &str) -> Result<Box<dyn SymmetricCipher>> {
    let base = alg.trim_end_matches("-det");
    match base {
        "aes-256-gcm-siv" => Ok(Box::new(AesGcmSivCipher::new(CipherDirection::Decrypt))),
        _ => Ok(Box::new(BotanCipher::create(
            base,
            CipherDirection::Decrypt,
        )?)),
    }
}

/// Default cipher assumed when no `cipher:` extfield is present on a
/// `ENCRYPTED` block. Older enprot blobs encrypted under the default
/// policy have no cipher: field; we treat them as AES-256-SIV.
pub const DEFAULT_CIPHER_ALG: &str = "aes-256-siv";

/// Serialize a cipher spec into the wire format used by the `cipher:`
/// extended field on `ENCRYPTED` blocks: `<alg>$iv=<base64-iv>` (or just
/// `<alg>` when the cipher takes no IV, e.g. AES-SIV).
pub fn format_cipher_extfield(alg: &str, iv: &[u8]) -> Result<String> {
    if iv.is_empty() {
        Ok(alg.to_string())
    } else {
        Ok(format!("{}$iv={}", alg, crate::utils::base64_encode(iv)?))
    }
}

/// Parse the wire format produced by `format_cipher_extfield`. Returns
/// the cipher algorithm name and the IV bytes (empty if the cipher
/// takes no IV).
pub fn parse_cipher_extfield(value: &str) -> Result<(String, Vec<u8>)> {
    let mut it = value.split('$');
    let alg = it
        .next()
        .ok_or_else(|| Error::Extfield {
            field: "cipher",
            reason: "empty extfield value".to_string(),
        })?
        .to_string();
    let mut fields = std::collections::BTreeMap::new();
    for part in it {
        let mut kv = part.splitn(2, '=');
        let k = kv.next().ok_or_else(|| Error::Extfield {
            field: "cipher",
            reason: "missing field key in $-segment".to_string(),
        })?;
        let v = kv.collect::<String>();
        fields.insert(k, v);
    }
    let iv = match fields.get("iv") {
        Some(b64) => crate::utils::base64_decode(b64)?,
        None => Vec::new(),
    };
    Ok((alg, iv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn botan_unrecognized_alg_rejected() {
        assert!(encryption("aes-128-gcm").is_err());
    }

    #[test]
    fn aes_256_gcm_kat() {
        let key = hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
            .unwrap();
        let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let pt = hex::decode(concat!(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        ))
        .unwrap();

        let enc = encryption("aes-256-gcm").unwrap();
        assert_eq!(enc.alg(), "aes-256-gcm");
        assert_eq!(enc.nonce_len(), 12);
        assert_eq!(enc.key_len_max(), 32);
        assert_eq!(enc.key_len_max(), 32);
        let mut enc = enc;
        let ct = enc.process(&key, &iv, &[], &pt).unwrap();
        assert_eq!(
            ct,
            hex::decode(concat!(
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3d",
                "a7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c"
            ))
            .unwrap()
        );

        let mut dec = decryption("aes-256-gcm").unwrap();
        assert_eq!(dec.process(&key, &iv, &[], &ct).unwrap(), pt);
    }

    #[test]
    fn aes_256_gcm_siv_kat() {
        let key = hex::decode("0100000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
        let iv = hex::decode("030000000000000000000000").unwrap();
        let pt = hex::decode(concat!(
            "0100000000000000000000000000000002000000000000000000000000000000",
            "0300000000000000000000000000000004000000000000000000000000000000"
        ))
        .unwrap();

        let enc = encryption("aes-256-gcm-siv").unwrap();
        assert_eq!(enc.alg(), "aes-256-gcm-siv");
        assert_eq!(enc.nonce_len(), 12);
        assert_eq!(enc.key_len_max(), 32);
        assert_eq!(enc.key_len_max(), 32);
        let mut enc = enc;
        let ct = enc.process(&key, &iv, &[], &pt).unwrap();
        assert_eq!(
            ct,
            hex::decode(concat!(
                "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7e1049eb080883891",
                "a4db8caaa1f99dd004d80487540735234e3744512c6f90ce112864c269fc0d9d88c61fa47e39aa08"
            ))
            .unwrap()
        );

        let mut dec = decryption("aes-256-gcm-siv").unwrap();
        assert_eq!(dec.process(&key, &iv, &[], &ct).unwrap(), pt);
    }
}
