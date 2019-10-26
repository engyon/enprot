// Copyright (c) 2019 [Ribose Inc](https://www.ribose.com).
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

// pbkdf
pub const DEFAULT_PBKDF_ALG: &str = "argon2";
pub const DEFAULT_PBKDF_SALT_LEN: usize = 16;
pub const DEFAULT_PBKDF_MSEC: u32 = 100;
pub const DEFAULT_PBKDF2_HASH_ALG: &str = "sha256";

// parsing separators
pub const DEFAULT_LEFT_SEP: &str = "// <(";
pub const DEFAULT_RIGHT_SEP: &str = ")>";

// valid value lists
pub const VALID_PBKDF_ALGS: &[&str] = &["argon2", "scrypt", "pbkdf2", "legacy"];
pub const VALID_PBKDF2_HASH_ALGS: &[&str] = &["sha256", "sha512"];

pub const AES256_KEY_LENGTH: usize = 64;
