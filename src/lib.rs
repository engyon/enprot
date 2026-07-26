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

//! Engyon Protected Text (EPT) confidentiality processor.
//!
//! Enprot parses text/source files whose host-language comments contain
//! `BEGIN`/`END`/`STORED`/`ENCRYPTED`/`DATA` directives and applies four
//! idempotent transformations on the named segments: store, fetch, encrypt,
//! decrypt. The pipeline is `parse` → `transform` → `tree_write`, run once
//! per input file.
//!
//! Most callers want [`app_main`], which is the CLI entry point. The
//! `crypto` and `utils` modules are re-exported for integration tests.

pub mod capability;
mod cappolicy;
mod cas;
mod cipher;
mod config;
mod consts;
pub mod crypto;
mod error;
pub mod etree;
pub mod kemenc;
pub mod ledger;
pub mod merge;
pub mod merkle;
pub mod output;
mod password;
mod pbkdf;
pub mod pki;
mod policy;
pub mod prot;
pub mod provenance;
pub mod provider;
pub mod resolve;
pub mod scm;
pub mod utils;

pub use error::{Error, Result};

/// CLI dispatch layer — all clap-dependent types and the
/// `app_main` entry point live here. Gated behind the `cli`
/// feature so downstream Rust consumers can use enprot as a
/// library without pulling in clap.
///
/// When the feature is enabled (the default), all CLI types are
/// re-exported at the crate root for backwards compatibility:
/// `enprot::app_main`, `enprot::CommonArgs`, etc.
#[cfg(feature = "cli")]
pub mod cli;

#[cfg(feature = "cli")]
#[allow(unused_imports)]
pub use cli::*;
