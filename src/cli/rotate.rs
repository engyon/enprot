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

//! `enprot rotate` — re-wrap escrow-mode blocks' key material under
//! a new password and/or new recovery keys, WITHOUT re-encrypting
//! the payload. The escrow CEK indirection (TODO.complete/59) makes
//! this possible: unwrap the CEK once, re-wrap under the new key
//! material, payload ciphertext stays byte-identical (CAS pointers
//! remain valid).
//!
//! Works per-WORD across whole files: every `ENCRYPTED` block with a
//! `recovery:` extfield is rotated; blocks without one are left
//! untouched (they're not escrow-mode).

use clap::Args;
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::etree::{self, ParseOps, TextNode, TextTree};

use super::{CommonArgs, apply_common, resolve_policy};

/// `rotate` subcommand (TODO 59's rotation gap): re-wrap escrow
/// blocks' CEK under new key material. Payload unchanged.
#[derive(Args)]
pub struct RotateSubcmd {
    /// Current recovery privkey (PEM) — the alternative unwrap
    /// credential when the password isn't available.
    #[arg(long = "key-file", value_name = "PRIV.pem")]
    pub key_file: Option<PathBuf>,

    /// The NEW password to wrap under.
    #[arg(long, value_name = "PASSWORD")]
    pub new_password: String,

    /// Recovery pubkey (PEM) for the new wrap. Repeatable; at
    /// least one required.
    #[arg(long = "recovery-key", value_name = "PUB.pem")]
    pub recovery_key: Vec<PathBuf>,

    /// Input file(s), each rotated in place.
    #[arg(value_name = "FILE")]
    pub files: Vec<String>,
}

pub(super) fn run(common: CommonArgs, a: RotateSubcmd) -> Result<()> {
    if a.files.is_empty() {
        return Err(Error::InvalidArg {
            arg: "FILE",
            reason: "rotate needs at least one FILE".to_string(),
        });
    }
    if let Some(f) = a.files.iter().find(|f| f.as_str() == "-") {
        return Err(Error::InvalidArg {
            arg: "FILE",
            reason: format!(
                "stdin ('{f}') not supported: the rewrite must be written back in place"
            ),
        });
    }
    // The word-password flag carries the OLD password (unwrap) and
    // --new-password carries the new one.
    if common.password.is_empty() && a.key_file.is_none() {
        return Err(Error::InvalidArg {
            arg: "-k",
            reason: "rotate: supply the current WORD password (-k WORD=PASSWORD) \\
                     or a current recovery privkey (--key-file)"
                .to_string(),
        });
    }

    let policy = resolve_policy(&common)?;
    let mut paops = ParseOps::new(policy)?;
    apply_common(&common, &mut paops);

    // Old password (per-WORD via the common -k flag).
    let old_passwords: BTreeMap<String, String> = common.password.iter().cloned().collect();

    // Recovery privkey (if rotating via key instead of password).
    let old_priv = a.key_file.as_ref().map(fs::read_to_string).transpose()?;

    // New recovery pubkeys.
    let new_pubs: Vec<String> = a
        .recovery_key
        .iter()
        .map(fs::read_to_string)
        .collect::<std::result::Result<_, _>>()?;
    if new_pubs.is_empty() {
        return Err(Error::InvalidArg {
            arg: "--recovery-key",
            reason: "rotate needs at least one --recovery-key for the new wrap".to_string(),
        });
    }

    for path in &a.files {
        rotate_one_file(
            path,
            &old_passwords,
            old_priv.as_deref(),
            &a.new_password,
            &new_pubs,
            &mut paops,
        )?;
    }
    Ok(())
}

fn rotate_one_file(
    path: &str,
    old_passwords: &BTreeMap<String, String>,
    old_priv: Option<&str>,
    new_password: &str,
    new_pubs: &[String],
    paops: &mut ParseOps,
) -> Result<()> {
    paops.runtime.fname = path.into();
    let reader = File::open(path)
        .map_err(|e| Error::Io(std::io::Error::other(format!("Failed to open {path}: {e}"))))?;
    let mut tree = etree::parse(BufReader::new(reader), paops)?;

    let count = rotate_tree(
        &mut tree,
        old_passwords,
        old_priv,
        new_password,
        new_pubs,
        paops,
    )?;
    if count == 0 {
        println!("{path}: no escrow-mode blocks found; nothing to rotate");
        return Ok(());
    }

    let mut out = File::create(path)?;
    etree::tree_write(&mut out, &tree, paops)?;
    println!("{path}: rotated {count} escrow block(s)");
    Ok(())
}

fn rotate_tree(
    tree: &mut TextTree,
    old_passwords: &BTreeMap<String, String>,
    old_priv: Option<&str>,
    new_password: &str,
    new_pubs: &[String],
    paops: &mut ParseOps,
) -> Result<usize> {
    let mut count = 0;
    let mut bad: Option<Error> = None;
    // Per-kind logic only — the descent contract lives in the
    // visitor (architecture review round 7). The Prune on every
    // Encrypted records that its Data/Stored child is payload
    // transport, never rotated; errors surface after the walk,
    // matching the original's fail-the-whole-file semantics
    // (rewrite_nested precedent).
    etree::visitor::visit_mut(tree, &mut |node| {
        let TextNode::Encrypted {
            keyw, extfields, ..
        } = node
        else {
            return etree::visitor::Control::Continue;
        };
        // Only escrow-mode blocks carry a recovery: field.
        if !crate::escrow::is_escrow_block(extfields) {
            return etree::visitor::Control::Prune;
        }
        let old_pw = old_passwords.get(keyw).map(|s| s.as_str());
        match crate::escrow::rotate(
            extfields,
            old_pw,
            old_priv,
            new_password,
            new_pubs,
            &mut paops.crypto.rng,
            &paops.crypto.pbkdfopts,
            &mut paops.crypto.pbkdf_cache,
            &*paops.crypto.policy,
        ) {
            Ok(new_ext) => {
                *extfields = new_ext;
                count += 1;
            }
            Err(e) => {
                bad.get_or_insert(e);
            }
        }
        etree::visitor::Control::Prune
    });
    if let Some(e) = bad {
        return Err(e);
    }
    Ok(count)
}
