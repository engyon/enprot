// Copyright (c) 2019-2020 [Ribose Inc](https://www.ribose.com).
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

use aes::Aes256;
use aes_gcm_siv::aead;
use aes_gcm_siv::aead::generic_array::typenum::{U16, U8};
use aes_gcm_siv::aead::generic_array::GenericArray;
use aes_gcm_siv::aead::{Aead, NewAead};
use aes_gcm_siv::AesGcmSiv;
use block_cipher_trait::generic_array::typenum::Unsigned;
use block_cipher_trait::BlockCipher;
use botan::CipherDirection;
use phf::phf_map;
use std::marker::PhantomData;

use crypto;

pub static BOTAN_CIPHER_ALG_MAP: phf::Map<&'static str, &'static str> = phf_map! {
    "aes-256-siv" => "AES-256/SIV",
    "aes-256-gcm" => "AES-256/GCM",
};

pub trait SymmetricCipher {
    fn alg(&self) -> &str;
    fn nonce_len(&self) -> usize;
    fn key_len_min(&self) -> usize;
    fn key_len_max(&self) -> usize;
    fn _process(
        &self,
        key: &[u8],
        iv: &[u8],
        ad: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, &'static str>;

    fn process(
        &self,
        key: &[u8],
        iv: &[u8],
        ad: &[u8],
        data: &[u8],
        policy: &Box<dyn crypto::CryptoPolicy>,
    ) -> Result<Vec<u8>, &'static str> {
        policy.check_cipher(self.alg(), key, iv, ad)?;
        self._process(key, iv, ad, data)
    }
}

fn to_botan_cipher(alg: &str) -> Result<&'static str, &'static str> {
    Ok(BOTAN_CIPHER_ALG_MAP
        .get::<str>(alg)
        .ok_or("Unrecognized cipher")?)
}

struct BotanCipher {
    alg: String,
    nonce_len: usize,
    key_len_min: usize,
    key_len_max: usize,
    obj: botan::Cipher,
}

impl BotanCipher {
    fn create(alg: &str, direction: CipherDirection) -> Result<Self, &'static str> {
        let obj = botan::Cipher::new(to_botan_cipher(alg)?, direction)
            .map_err(|_| "Botan error creating cipher")?;
        let keyspec = obj
            .key_spec()
            .map_err(|_| "Botan error retrieving key spec")?;
        Ok(BotanCipher {
            alg: alg.to_string(),
            nonce_len: obj.default_nonce_length(),
            key_len_min: keyspec.minimum_keylength(),
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

    fn key_len_min(&self) -> usize {
        self.key_len_min
    }

    fn key_len_max(&self) -> usize {
        self.key_len_max
    }

    fn _process(
        &self,
        key: &[u8],
        iv: &[u8],
        ad: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        self.obj
            .set_key(key)
            .map_err(|_| "Botan error setting cipher key")?;
        self.obj
            .set_associated_data(ad)
            .map_err(|_| "Botan error setting AD")?;
        self.obj
            .process(iv, data)
            .map_err(|_| "Botan error processing cipher data")
    }
}

struct AESGCMSIVCipher<C>
where
    C: BlockCipher<BlockSize = U16, ParBlocks = U8>,
{
    alg: String,
    nonce_len: usize,
    key_len_min: usize,
    key_len_max: usize,
    direction: CipherDirection,
    phantom: PhantomData<C>,
}

impl<C> AESGCMSIVCipher<C>
where
    C: BlockCipher<BlockSize = U16, ParBlocks = U8>,
{
    fn create(direction: CipherDirection) -> Result<Self, &'static str> {
        Ok(AESGCMSIVCipher {
            alg: format!("aes-{}-gcm-siv", C::KeySize::to_usize() * 8),
            nonce_len: <AesGcmSiv<C> as Aead>::NonceSize::to_usize(),
            key_len_min: C::KeySize::to_usize(),
            key_len_max: C::KeySize::to_usize(),
            direction,
            phantom: PhantomData,
        })
    }
}

impl<C> SymmetricCipher for AESGCMSIVCipher<C>
where
    C: BlockCipher<BlockSize = U16, ParBlocks = U8>,
{
    fn alg(&self) -> &str {
        &self.alg
    }

    fn nonce_len(&self) -> usize {
        self.nonce_len
    }

    fn key_len_min(&self) -> usize {
        self.key_len_min
    }

    fn key_len_max(&self) -> usize {
        self.key_len_max
    }

    fn _process(
        &self,
        key: &[u8],
        iv: &[u8],
        ad: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let obj = AesGcmSiv::<C>::new(GenericArray::clone_from_slice(key));
        match self.direction {
            CipherDirection::Encrypt => obj
                .encrypt(
                    GenericArray::from_slice(iv),
                    aead::Payload { msg: data, aad: ad },
                )
                .map_err(|_| "Failed to encrypt"),
            CipherDirection::Decrypt => obj
                .decrypt(
                    GenericArray::from_slice(iv),
                    aead::Payload { msg: data, aad: ad },
                )
                .map_err(|_| "Failed to decrypt"),
        }
    }
}

fn create(alg: &str, direction: CipherDirection) -> Result<Box<dyn SymmetricCipher>, &'static str> {
    match alg {
        "aes-256-gcm-siv" => Ok(Box::new(AESGCMSIVCipher::<Aes256>::create(direction)?)),
        _ => Ok(Box::new(BotanCipher::create(alg, direction)?)),
    }
}

pub fn encryption(alg: &str) -> Result<Box<dyn SymmetricCipher>, &'static str> {
    create(alg, CipherDirection::Encrypt)
}

pub fn decryption(alg: &str) -> Result<Box<dyn SymmetricCipher>, &'static str> {
    create(alg, CipherDirection::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn cipher_create_invalid() {
        create("aes-128-gcm", CipherDirection::Encrypt).unwrap();
    }

    #[test]
    fn aes_256_gcm() {
        let policy: Box<dyn crypto::CryptoPolicy> = Box::new(crypto::CryptoPolicyDefault {});
        let key: &[u8] =
            &hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
                .unwrap();
        let iv: &[u8] = &hex::decode("cafebabefacedbaddecaf888").unwrap();
        let pt: &[u8] = &hex::decode(concat!(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        ))
        .unwrap();
        let ct;
        {
            let enc = encryption("aes-256-gcm").unwrap();
            assert_eq!(enc.alg(), "aes-256-gcm");
            assert_eq!(enc.nonce_len(), 12);
            assert_eq!(enc.key_len_min(), 32);
            assert_eq!(enc.key_len_max(), 32);

            ct = enc.process(&key, &iv, &[], &pt, &policy).unwrap();
            assert_eq!(
                ct,
                hex::decode(
                    concat!(
                        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3d",
                        "a7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c"
                        )).unwrap()
            );
        }

        let dec = decryption("aes-256-gcm").unwrap();
        assert_eq!(dec.alg(), "aes-256-gcm");
        assert_eq!(dec.nonce_len(), 12);
        assert_eq!(dec.key_len_min(), 32);
        assert_eq!(dec.key_len_max(), 32);
        assert_eq!(dec.process(&key, &iv, &[], &ct, &policy).unwrap(), pt);
    }

    #[test]
    fn aes_256_gcm_siv() {
        let policy: Box<dyn crypto::CryptoPolicy> = Box::new(crypto::CryptoPolicyDefault {});
        let key: &[u8] =
            &hex::decode("0100000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let iv: &[u8] = &hex::decode("030000000000000000000000").unwrap();
        let pt: &[u8] = &hex::decode(concat!(
            "0100000000000000000000000000000002000000000000000000000000000000",
            "0300000000000000000000000000000004000000000000000000000000000000"
        ))
        .unwrap();
        let ct;
        {
            let enc = encryption("aes-256-gcm-siv").unwrap();
            assert_eq!(enc.alg(), "aes-256-gcm-siv");
            assert_eq!(enc.nonce_len(), 12);
            assert_eq!(enc.key_len_min(), 32);
            assert_eq!(enc.key_len_max(), 32);

            ct = enc.process(&key, &iv, &[], &pt, &policy).unwrap();
            assert_eq!(
                ct,
                hex::decode(
                    concat!(
                        "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7e1049eb080883891",
                        "a4db8caaa1f99dd004d80487540735234e3744512c6f90ce112864c269fc0d9d88c61fa47e39aa08"
                        )).unwrap()
            );
        }

        let dec = decryption("aes-256-gcm-siv").unwrap();
        assert_eq!(dec.alg(), "aes-256-gcm-siv");
        assert_eq!(dec.nonce_len(), 12);
        assert_eq!(dec.key_len_min(), 32);
        assert_eq!(dec.key_len_max(), 32);
        assert_eq!(dec.process(&key, &iv, &[], &ct, &policy).unwrap(), pt);
    }
}
