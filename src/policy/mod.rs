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

use std::collections::BTreeMap;

pub mod default;
pub mod nist;

/// Cryptographic policy: gates every cipher/pbkdf/hash call and
/// supplies defaults.
///
/// The `Send + Sync` bounds are required so that [`crate::etree::ParseOps`]
/// can move across thread boundaries — needed for the rayon-based
/// parallel multi-file processing planned in
/// `TODO.complete/04-parallel-multi-file`. Existing implementations
/// (`DefaultPolicy`, `NistPolicy`) are already `Send + Sync` in
/// practice because they hold only plain data; this trait declaration
/// just makes the requirement compile-time explicit so future impls
/// can't accidentally break it.
pub trait CryptoPolicy: Send + Sync {
    fn check_hash(&self, alg: &str) -> Result<(), String>;

    fn check_pbkdf(
        &self,
        alg: &str,
        key_len: usize,
        password: &str,
        salt: &[u8],
        params: &BTreeMap<String, usize>,
    ) -> Result<(), String>;

    /// Validate that the cipher algorithm is permitted by this policy,
    /// independent of any key/IV. Called before backend cipher creation so
    /// policy rejection happens even when the backend does not implement
    /// the requested algorithm.
    ///
    /// The deterministic variants (`aes-256-gcm-det`, `aes-256-gcm-siv-det`)
    /// use the same underlying backend cipher as their non-det counterparts,
    /// so policy checks against the base name.
    fn check_cipher_alg(&self, alg: &str) -> Result<(), String> {
        self.check_cipher_alg_impl(alg.trim_end_matches("-det"))
    }

    /// Implementation backing `check_cipher_alg` after any `-det` suffix
    /// has been stripped. Concrete policies implement this.
    fn check_cipher_alg_impl(&self, alg: &str) -> Result<(), String>;

    fn check_cipher(&self, alg: &str, key: &[u8], iv: &[u8], ad: &[u8]) -> Result<(), String>;

    fn default_pbkdf_alg(&self) -> String;
    fn default_pbkdf_salt_length(&self) -> usize;
    fn default_pbkdf_millis(&self) -> u32;
    fn default_cipher_alg(&self) -> String;
}

/// Compile-time assertion that the known policy implementations are
/// `Send + Sync`. If a future change breaks the bounds, this function
/// stops compiling.
#[doc(hidden)]
fn _assert_policy_send_sync() {
    fn _assert<T: Send + Sync>() {}
    _assert::<crate::policy::default::CryptoPolicyDefault>();
    _assert::<crate::policy::nist::CryptoPolicyNIST>();
    // The trait object itself must also be `Send + Sync` so that
    // `Box<dyn CryptoPolicy>` is usable from worker threads.
    fn _assert_dyn_send_sync(_: Box<dyn CryptoPolicy>) {}
    _assert::<Box<dyn CryptoPolicy>>();
}
