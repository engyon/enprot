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

//! `enprot sbom` — Software Bill of Materials for the binary itself
//! (TODO.complete/62). Thin CLI wrapper over [`crate::sbom`]; the
//! document models and determinism guarantees live there.

use std::io::Write;
use std::path::PathBuf;

use clap::Args;

use crate::error::Result;
use crate::sbom;

/// Output format for `enprot sbom`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum SbomFormat {
    /// SPDX 2.3 JSON (the SPDX-blessed exchange format).
    #[default]
    SpdxJson,
    /// CycloneDX 1.5 JSON.
    CyclonedxJson,
}

/// `sbom` subcommand: emit an SBOM for this binary.
#[derive(Args, Debug)]
pub struct SbomSubcmd {
    /// SBOM output format. The field name differs from the flag
    /// because the global `--format` (text/json switch for
    /// inspection subcommands) already owns the `format` arg id.
    #[arg(long = "sbom-format", value_enum, default_value_t)]
    pub sbom_format: SbomFormat,

    /// Write to FILE instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

pub fn run(a: SbomSubcmd) -> Result<()> {
    if !sbom::has_embedded_deps() {
        eprintln!(
            "Warning: this binary was built without a Cargo.lock; the \
             SBOM lists only enprot and the linked C libraries."
        );
    }
    let doc = match a.sbom_format {
        SbomFormat::SpdxJson => sbom::spdx_json()?,
        SbomFormat::CyclonedxJson => sbom::cyclonedx_json()?,
    };
    match a.output {
        Some(path) => std::fs::write(path, doc).map_err(crate::Error::from),
        None => {
            let mut out = std::io::stdout().lock();
            writeln!(out, "{doc}")?;
            Ok(())
        }
    }
}
