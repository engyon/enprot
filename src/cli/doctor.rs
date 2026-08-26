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

//! `enprot doctor` — one-command environment diagnostics.
//!
//! Every audience needs this at some point: a bug report without
//! the linked-library versions is unactionable; a compliance audit
//! needs to know what policy is actually in effect; an onboarding
//! sanity check catches "wrong Botan" before it becomes a mystery
//! decryption failure.
//!
//! Checks (each reports ok/warn/fail + detail):
//! 1. enprot version + feature flags compiled in
//! 2. linked Botan version (FIPS module status if detectable)
//! 3. librnp availability + version (OpenPGP path)
//! 4. resolved crypto policy (from --policy/--fips/env)
//! 5. CAS backend resolution + writability probe
//! 6. locale
//! 7. git filter configuration (if inside a git repo with
//!    .gitattributes referencing enprot)
//!
//! Exit code: 0 = all ok (warnings permitted), 1 = any failure.

use std::path::Path;

use crate::error::Result;
use crate::output::OutputFormat;

use super::CommonArgs;

pub(super) fn run(common: &CommonArgs, _format: OutputFormat) -> Result<()> {
    let mut failures = 0;

    // 1. enprot version + features
    println!("enprot: {}", env!("CARGO_PKG_VERSION"));
    let features: Vec<&str> = vec![
        #[cfg(feature = "cli")]
        "cli",
        #[cfg(feature = "cas-s3")]
        "cas-s3",
        #[cfg(feature = "cas-ipfs")]
        "cas-ipfs",
        #[cfg(feature = "cas-rekor")]
        "cas-rekor",
        #[cfg(feature = "async-pipeline")]
        "async-pipeline",
        #[cfg(feature = "pure-rust-crypto")]
        "pure-rust-crypto",
        #[cfg(feature = "telemetry")]
        "telemetry",
        #[cfg(feature = "vendored-rnp")]
        "vendored-rnp",
    ];
    if features.is_empty() {
        println!("  features: (none — library-only build)");
    } else {
        println!("  features: {}", features.join(", "));
    }

    // 2. Botan
    match botan::Version::current() {
        Ok(v) => {
            println!("Botan: {}.{}.{} ({})", v.major, v.minor, v.patch, v.string);
        }
        Err(e) => {
            println!("Botan: FAIL — {e}");
            failures += 1;
        }
    }

    // 3. librnp (OpenPGP)
    let rnp_ver = rnp_rs_probe();
    match rnp_ver {
        Ok(v) => println!("librnp: {v}"),
        Err(e) => {
            println!("librnp: warn — {e}");
            println!("  (OpenPGP sign/verify unavailable; WORD encryption unaffected)");
        }
    }

    // 4. Policy
    let policy_name = common.policy.clone().unwrap_or_else(|| {
        if common.fips {
            "nist (forced by --fips)".to_string()
        } else {
            "default".to_string()
        }
    });
    println!("policy: {policy_name}");
    if common.fips {
        println!("  FIPS mode: engaged (--fips)");
    }

    // 5. CAS
    let casdir = common
        .casdir
        .clone()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| {
            if Path::new("cas").is_dir() {
                "cas/ (auto-detected)".to_string()
            } else {
                ". (cwd, no cas/ dir)".to_string()
            }
        });
    println!("CAS: {casdir}");
    let probe_path = common
        .casdir
        .clone()
        .unwrap_or_else(|| Path::new("cas").to_path_buf());
    let probe = std::fs::metadata(&probe_path);
    match probe {
        Ok(m) if m.is_dir() => {
            // Writability probe: create + delete a temp file.
            let test = probe_path.join(".enprot-doctor-probe");
            match std::fs::write(&test, b"probe") {
                Ok(()) => {
                    let _ = std::fs::remove_file(&test);
                    println!("  writability: ok");
                }
                Err(e) => {
                    println!("  writability: FAIL — {e}");
                    failures += 1;
                }
            }
        }
        Ok(_) => {
            println!("  warn: {probe_path:?} exists but is not a directory");
        }
        Err(_) => {
            // No CAS dir yet — that's fine for read-only flows.
            println!("  (directory not present; created on first store)");
        }
    }

    // 6. Locale
    let locale = std::env::var("ENPROT_LOCALE").unwrap_or_else(|_| "en (default)".to_string());
    println!("locale: {locale}");

    // 7. git filter wiring
    if Path::new(".git").is_dir() {
        match std::fs::read_to_string(".gitattributes") {
            Ok(attr) if attr.contains("enprot") => {
                println!("git filter: ok (.gitattributes references enprot)");
            }
            _ => println!("git filter: not configured (add to .gitattributes for smudge/clean)"),
        }
    }

    if failures > 0 {
        println!(
            "\n{} failure(s) — see above. Warnings do not affect the exit code.",
            failures
        );
        std::process::exit(1);
    }
    println!("\nall critical checks passed");
    Ok(())
}

/// Probe librnp's version without taking the full OpenPGP init path.
/// Isolated so a failure here is a warning, not a hard failure.
fn rnp_rs_probe() -> std::result::Result<String, String> {
    let ver = rnp::version_string();
    if ver.is_empty() {
        return Err("librnp returned an empty version string".to_string());
    }
    Ok(ver)
}
