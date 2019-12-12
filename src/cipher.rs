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
