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

//! Apply the four transform sets (store / fetch / encrypt / decrypt) to
//! a parsed `TextTree`. `transform` is the entry point; it dispatches
//! per node kind to `transform_begin_end`, `transform_encrypted`, and
//! `transform_stored`. `Plain` and `Data` nodes are passed through
//! unchanged.

use crate::cas;
use crate::error::{Error, Result};
use crate::etree::TextNode;
use crate::etree::TextTree;
use crate::password;
use crate::prot;

#[tracing::instrument(skip(text_in, paops))]
pub fn transform(text_in: &TextTree, paops: &mut crate::etree::ParseOps) -> Result<TextTree> {
    if paops.max_depth != 0 && paops.runtime.level > paops.max_depth {
        return Err(Error::InvalidArg {
            arg: "max_depth",
            reason: "Maximum recursion depth exceeded".to_string(),
        });
    }
    let mut out = Vec::with_capacity(text_in.len());
    for node in text_in {
        let new_node = match node {
            TextNode::Plain(_) | TextNode::Data(_) => node.clone(),
            // Chain anchors, INCLUDE references, and CONFLICT markers
            // are metadata, not content — pass through unchanged.
            TextNode::Chain { .. } | TextNode::Include { .. } | TextNode::Conflict { .. } => {
                node.clone()
            }
            // IMMUTABLE/MUTED/KEY/CERT/UNKEY/UNCERT are integrity and
            // key-binding directives, not confidentiality transforms.
            // They pass through unchanged. Future `store`/`fetch` for
            // IMMUTABLE↔MUTED sanitization will be separate transform
            // modes.
            TextNode::Immutable { .. }
            | TextNode::Muted { .. }
            | TextNode::Key { .. }
            | TextNode::Unkey { .. }
            | TextNode::Cert { .. }
            | TextNode::Uncert { .. } => node.clone(),
            TextNode::BeginEnd { keyw, txt } => transform_begin_end(keyw, txt, paops)?,
            TextNode::Encrypted {
                keyw,
                txt,
                extfields,
            } => transform_encrypted(keyw, txt, extfields, paops)?,
            TextNode::Stored { keyw, cas } => transform_stored(keyw, cas, paops)?,
        };
        out.push(new_node);
    }
    Ok(out)
}

/// Transform a `BeginEnd` segment. Takes the variant's fields
/// directly (not the whole `TextNode`) so the type system enforces
/// the variant — no runtime check or `unreachable!`.
fn transform_begin_end(
    keyw: &str,
    txt: &TextTree,
    paops: &mut crate::etree::ParseOps,
) -> Result<TextNode> {
    if paops.transforms.encrypt.contains(keyw) {
        paops.runtime.level += 1;
        let block = transform(txt, paops)?;
        paops.runtime.level -= 1;

        let pt = crate::etree::tree_to_blob(&block, paops)?;

        let (ct, extfields) = if !paops.crypto.recipient_pubs.is_empty() {
            // KEM mode (TODO.roadmap/60): encrypt to recipient pubkeys
            // via ML-KEM instead of password-based PBKDF.
            let rng = paops.crypto.rng.as_mut().ok_or(Error::InvalidArg {
                arg: "rng",
                reason: "Missing RNG for KEM encrypt".to_string(),
            })?;
            crate::kemenc::encrypt(
                pt,
                &paops.crypto.recipient_pubs,
                &paops.crypto.cipheropts.alg,
                rng,
            )?
        } else {
            // Password mode (default).
            let pass = ensure_password(keyw, paops, true)?;
            prot::encrypt(
                pt,
                &pass,
                &mut paops.crypto.rng,
                &paops.crypto.pbkdfopts,
                &paops.crypto.cipheropts,
                &mut paops.crypto.pbkdf_cache,
                &*paops.crypto.policy,
            )?
        };

        let inner = if paops.transforms.store.contains(keyw) || cas_default_applies(paops) {
            let hexhash = cas::save(ct, paops)?;
            vec![TextNode::Stored {
                keyw: "ct".to_string(),
                cas: hexhash,
            }]
        } else {
            vec![TextNode::Data(ct)]
        };
        return Ok(TextNode::Encrypted {
            keyw: keyw.to_string(),
            txt: inner,
            extfields,
        });
    }

    if paops.transforms.store.contains(keyw) {
        paops.runtime.level += 1;
        let block = transform(txt, paops)?;
        paops.runtime.level -= 1;

        let blob = crate::etree::tree_to_blob(&block, paops)?;
        let hexhash = cas::save(blob, paops)?;
        return Ok(TextNode::Stored {
            keyw: keyw.to_string(),
            cas: hexhash,
        });
    };

    paops.runtime.level += 1;
    let block = transform(txt, paops)?;
    paops.runtime.level -= 1;
    Ok(TextNode::BeginEnd {
        keyw: keyw.to_string(),
        txt: block,
    })
}

/// Transform an `Encrypted` segment. Takes the variant's fields
/// directly; see `transform_begin_end` for rationale.
fn transform_encrypted(
    keyw: &str,
    txt: &TextTree,
    extfields: &std::collections::BTreeMap<String, String>,
    paops: &mut crate::etree::ParseOps,
) -> Result<TextNode> {
    if paops.transforms.decrypt.contains(keyw) {
        let ct = extract_ciphertext(txt, keyw, paops)?;

        let ef = crate::extfield::EncryptedExtFields::from_map(extfields);
        let pt = if ef.is_kem_mode() {
            let priv_pem = paops
                .crypto
                .recipient_privkeys
                .get(keyw)
                .or_else(|| paops.crypto.recipient_privkeys.values().next())
                .ok_or_else(|| Error::InvalidArg {
                    arg: "key-file",
                    reason: format!(
                        "KEM-mode block for WORD {keyw} but no --key-file privkey supplied"
                    ),
                })?;
            crate::kemenc::decrypt(&ct, priv_pem, extfields)?
        } else {
            let pass = ensure_password(keyw, paops, false)?;
            match prot::decrypt(
                ct,
                &pass,
                ef.pbkdf(),
                ef.cipher(),
                ef.compress(),
                &mut paops.crypto.pbkdf_cache,
                &*paops.crypto.policy,
            ) {
                Ok(ct) => ct.to_vec(),
                Err(e) => {
                    eprintln!("Error decrypting {}: {}.", keyw, e);
                    return Err(e);
                }
            }
        };

        let mut block = crate::etree::blob_to_tree(pt, "decrypted".to_string(), paops)?;
        paops.runtime.level += 1;
        block = transform(&block, paops)?;
        paops.runtime.level -= 1;
        return Ok(TextNode::BeginEnd {
            keyw: keyw.to_string(),
            txt: block,
        });
    }

    if paops.transforms.store.contains(keyw) {
        let hexhash = to_cas_pointer(txt, keyw, paops)?;
        return Ok(TextNode::Encrypted {
            keyw: keyw.to_string(),
            txt: vec![TextNode::Stored {
                keyw: "ct".to_string(),
                cas: hexhash,
            }],
            extfields: std::collections::BTreeMap::new(),
        });
    }

    if paops.transforms.fetch.contains(keyw) {
        let ct = extract_ciphertext(txt, keyw, paops)?;
        return Ok(TextNode::Encrypted {
            keyw: keyw.to_string(),
            txt: vec![TextNode::Data(ct)],
            extfields: std::collections::BTreeMap::new(),
        });
    }

    Ok(TextNode::Encrypted {
        keyw: keyw.to_string(),
        txt: txt.clone(),
        extfields: extfields.clone(),
    })
}

/// Extract ciphertext bytes from the first child of an Encrypted
/// block. Loads from CAS if the child is a Stored pointer.
fn extract_ciphertext(
    txt: &TextTree,
    keyw: &str,
    paops: &mut crate::etree::ParseOps,
) -> Result<Vec<u8>> {
    let first = txt.first().ok_or_else(|| Error::BlockShape {
        word: keyw.to_string(),
        reason: "ENCRYPTED block has no children".to_string(),
    })?;
    match first {
        TextNode::Data(data) => Ok(data.clone()),
        TextNode::Stored { cas, .. } => cas::load(cas, paops),
        _ => Err(Error::BlockShape {
            word: keyw.to_string(),
            reason: "ENCRYPTED block has no DATA or STORED child".to_string(),
        }),
    }
}

/// Convert the first child of an Encrypted block to a CAS pointer.
/// Saves to CAS if the child is inline Data; returns the existing
/// hash if already Stored.
fn to_cas_pointer(
    txt: &TextTree,
    keyw: &str,
    paops: &mut crate::etree::ParseOps,
) -> Result<String> {
    let first = txt.first().ok_or_else(|| Error::BlockShape {
        word: keyw.to_string(),
        reason: "ENCRYPTED block has no children".to_string(),
    })?;
    match first {
        TextNode::Data(data) => cas::save(data.clone(), paops),
        TextNode::Stored { cas, .. } => Ok(cas.clone()),
        _ => Err(Error::BlockShape {
            word: keyw.to_string(),
            reason: "ENCRYPTED block has no DATA or STORED child".to_string(),
        }),
    }
}

/// Transform a `Stored` pointer. Takes the variant's fields directly.
fn transform_stored(keyw: &str, cas: &str, paops: &mut crate::etree::ParseOps) -> Result<TextNode> {
    if paops.transforms.fetch.contains(keyw) {
        let blob = cas::load(cas, paops)?;
        let mut block = crate::etree::blob_to_tree(blob, cas.to_string(), paops)?;
        paops.runtime.level += 1;
        block = transform(&block, paops)?;
        paops.runtime.level -= 1;
        return Ok(TextNode::BeginEnd {
            keyw: keyw.to_string(),
            txt: block,
        });
    }

    Ok(TextNode::Stored {
        keyw: keyw.to_string(),
        cas: cas.to_string(),
    })
}

fn ensure_password(keyw: &str, paops: &mut crate::etree::ParseOps, repeat: bool) -> Result<String> {
    if let Some(p) = paops.passwords.get(keyw) {
        return Ok(p.clone());
    }
    let p = password::get_password(keyw, repeat)?;
    paops.passwords.insert(keyw.to_string(), p.clone());
    Ok(p)
}

/// True when CAS-referenced output should be produced for newly
/// encrypted blocks. Per TODO.roadmap/42: the default is STORED ct
/// unless the caller opted into inline mode (via `--inline`) or no
/// CAS dir was supplied (stdin pipeline carve-out).
fn cas_default_applies(paops: &crate::etree::ParseOps) -> bool {
    !paops.io.inline_data
}

/// Transform spec (TODO.complete/49): the non-crypto branches of the
/// state machine — passthrough directives, the Encrypted store/fetch
/// moves, the Stored fetch restore, and the BlockShape error paths.
/// The crypto arms (encrypt/decrypt round-trips) are covered by the
/// e2e tests in `etree::tests` and `tests/cli`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::etree::{ParseOps, TextNode};
    use std::collections::BTreeMap;

    fn paops_with_cas() -> (ParseOps, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut p = ParseOps::new(crate::crypto::default_policy()).unwrap();
        p.io.casdir = dir.path().to_path_buf();
        (p, dir)
    }

    fn encrypted_with(child: TextNode) -> TextNode {
        TextNode::Encrypted {
            keyw: "W".into(),
            txt: vec![child],
            extfields: BTreeMap::new(),
        }
    }

    #[test]
    fn integrity_and_binding_directives_pass_through() {
        let (mut p, _d) = paops_with_cas();
        let tree = vec![
            TextNode::Immutable {
                name: "L".into(),
                hashalg: "sha384".into(),
                hash: "AB".into(),
                txt: vec![TextNode::Plain("text".into())],
            },
            TextNode::Muted {
                name: "L".into(),
                hashalg: "sha384".into(),
                hash: "AB".into(),
            },
            TextNode::Key {
                name: "k".into(),
                hashalg: "sha256".into(),
                hash: "11".into(),
            },
            TextNode::Unkey { name: "k".into() },
            TextNode::Cert {
                name: "c".into(),
                hashalg: "sha256".into(),
                hash: "22".into(),
            },
            TextNode::Uncert { name: "c".into() },
        ];
        let out = transform(&tree, &mut p).unwrap();
        assert_eq!(out, tree, "no transform set: every node passes through");
    }

    #[test]
    fn begin_end_without_transform_passes_through() {
        let (mut p, _d) = paops_with_cas();
        let tree = vec![TextNode::BeginEnd {
            keyw: "W".into(),
            txt: vec![TextNode::Plain("body".into())],
        }];
        let out = transform(&tree, &mut p).unwrap();
        assert_eq!(out, tree);
    }

    #[test]
    fn encrypted_store_moves_inline_data_to_cas() {
        let (mut p, _d) = paops_with_cas();
        p.transforms.store.insert("W".into());
        let tree = vec![encrypted_with(TextNode::Data(vec![1, 2, 3]))];
        let out = transform(&tree, &mut p).unwrap();
        match &out[0] {
            TextNode::Encrypted { txt, .. } => match &txt[0] {
                TextNode::Stored { keyw, cas } => {
                    assert_eq!(keyw, "ct");
                    assert_eq!(cas.len(), 64, "CAS id is a SHA3-256 hex hash");
                }
                other => panic!("expected Stored child, got {other:?}"),
            },
            other => panic!("expected Encrypted, got {other:?}"),
        }
    }

    #[test]
    fn encrypted_store_keeps_existing_pointer() {
        // Already stored → the hash is returned as-is, no re-save.
        let (mut p, _d) = paops_with_cas();
        p.transforms.store.insert("W".into());
        let hash = "a".repeat(64);
        let tree = vec![encrypted_with(TextNode::Stored {
            keyw: "ct".into(),
            cas: hash.clone(),
        })];
        let out = transform(&tree, &mut p).unwrap();
        match &out[0] {
            TextNode::Encrypted { txt, .. } => match &txt[0] {
                TextNode::Stored { cas, .. } => assert_eq!(cas, &hash),
                other => panic!("expected Stored child, got {other:?}"),
            },
            other => panic!("expected Encrypted, got {other:?}"),
        }
    }

    #[test]
    fn encrypted_fetch_inlines_stored_ciphertext() {
        // Round-trip with the store test: save a blob, fetch it back.
        let (mut p, _d) = paops_with_cas();
        let blob = vec![9, 8, 7];
        let hash = crate::cas::save(blob.clone(), &mut p).unwrap();
        p.transforms.fetch.insert("W".into());
        let tree = vec![encrypted_with(TextNode::Stored {
            keyw: "ct".into(),
            cas: hash,
        })];
        let out = transform(&tree, &mut p).unwrap();
        match &out[0] {
            TextNode::Encrypted { txt, extfields, .. } => {
                assert!(extfields.is_empty(), "fetch drops extfields");
                match &txt[0] {
                    TextNode::Data(d) => assert_eq!(d, &blob, "CAS content inlined"),
                    other => panic!("expected Data child, got {other:?}"),
                }
            }
            other => panic!("expected Encrypted, got {other:?}"),
        }
    }

    #[test]
    fn encrypted_without_transform_passes_through() {
        let (mut p, _d) = paops_with_cas();
        let tree = vec![encrypted_with(TextNode::Data(vec![5]))];
        let out = transform(&tree, &mut p).unwrap();
        assert_eq!(out, tree);
    }

    #[test]
    fn stored_fetch_restores_begin_end_block() {
        // Store a valid EPT body in CAS, then fetch via a Stored node.
        let (mut p, _d) = paops_with_cas();
        let body = b"restored line\n".to_vec();
        let hash = crate::cas::save(body, &mut p).unwrap();
        p.transforms.fetch.insert("W".into());
        let tree = vec![TextNode::Stored {
            keyw: "W".into(),
            cas: hash,
        }];
        let out = transform(&tree, &mut p).unwrap();
        match &out[0] {
            TextNode::BeginEnd { keyw, txt } => {
                assert_eq!(keyw, "W");
                assert!(matches!(&txt[0], TextNode::Plain(s) if s.contains("restored")));
            }
            other => panic!("expected BeginEnd, got {other:?}"),
        }
    }

    #[test]
    fn stored_without_fetch_passes_through() {
        let (mut p, _d) = paops_with_cas();
        let tree = vec![TextNode::Stored {
            keyw: "W".into(),
            cas: "f".repeat(64),
        }];
        let out = transform(&tree, &mut p).unwrap();
        assert_eq!(out, tree);
    }

    #[test]
    fn empty_encrypted_block_is_a_shape_error() {
        // decrypt / fetch / store on a childless Encrypted block must
        // produce a typed BlockShape error, never a panic.
        for mode in ["decrypt", "fetch", "store"] {
            let (mut p, _d) = paops_with_cas();
            match mode {
                "decrypt" => {
                    p.transforms.decrypt.insert("W".into());
                    p.passwords.insert("W".into(), "pw".into());
                }
                "fetch" => {
                    p.transforms.fetch.insert("W".into());
                }
                _ => {
                    p.transforms.store.insert("W".into());
                }
            }
            let tree = vec![TextNode::Encrypted {
                keyw: "W".into(),
                txt: vec![],
                extfields: BTreeMap::new(),
            }];
            let err = transform(&tree, &mut p).unwrap_err();
            assert!(
                matches!(err, crate::error::Error::BlockShape { .. }),
                "{mode}: expected BlockShape, got {err}"
            );
        }
    }

    #[test]
    fn non_payload_child_is_a_shape_error() {
        // A Plain child inside Encrypted is not a payload carrier.
        for mode in ["decrypt", "store"] {
            let (mut p, _d) = paops_with_cas();
            match mode {
                "decrypt" => {
                    p.transforms.decrypt.insert("W".into());
                    p.passwords.insert("W".into(), "pw".into());
                }
                _ => {
                    p.transforms.store.insert("W".into());
                }
            }
            let tree = vec![encrypted_with(TextNode::Plain("text".into()))];
            let err = transform(&tree, &mut p).unwrap_err();
            assert!(
                matches!(err, crate::error::Error::BlockShape { .. }),
                "{mode}: expected BlockShape, got {err}"
            );
        }
    }
}
