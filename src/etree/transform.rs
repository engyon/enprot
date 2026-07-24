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

pub fn transform(text_in: &TextTree, paops: &mut crate::etree::ParseOps) -> Result<TextTree> {
    if paops.max_depth != 0 && paops.level > paops.max_depth {
        return Err(Error::Msg("Maximum recursion depth!".into()));
    }
    let mut out = Vec::with_capacity(text_in.len());
    for node in text_in {
        let new_node = match node {
            TextNode::Plain(_) | TextNode::Data(_) => node.clone(),
            TextNode::BeginEnd { .. } => transform_begin_end(node, paops)?,
            TextNode::Encrypted { .. } => transform_encrypted(node, paops)?,
            TextNode::Stored { .. } => transform_stored(node, paops)?,
        };
        out.push(new_node);
    }
    Ok(out)
}

fn transform_begin_end(node: &TextNode, paops: &mut crate::etree::ParseOps) -> Result<TextNode> {
    let (keyw, txt) = match node {
        TextNode::BeginEnd { keyw, txt } => (keyw.clone(), txt.clone()),
        _ => unreachable!(),
    };

    if paops.transforms.encrypt.contains(&keyw) {
        paops.level += 1;
        let block = transform(&txt, paops)?;
        paops.level -= 1;

        let pt = crate::etree::tree_to_blob(&block, paops)?;
        let pass = ensure_password(&keyw, paops, true);
        let (ct, extfields) = prot::encrypt(
            pt,
            &pass,
            &mut paops.crypto.rng,
            &paops.crypto.pbkdfopts,
            &paops.crypto.cipheropts,
            &mut paops.crypto.pbkdf_cache,
            &*paops.crypto.policy,
        )?;

        let inner = if paops.transforms.store.contains(&keyw) {
            let hexhash = cas::save(ct, paops)?;
            vec![TextNode::Stored {
                keyw: "ct".to_string(),
                cas: hexhash,
            }]
        } else {
            vec![TextNode::Data(ct)]
        };
        return Ok(TextNode::Encrypted {
            keyw,
            txt: inner,
            extfields,
        });
    }

    if paops.transforms.store.contains(&keyw) {
        paops.level += 1;
        let block = transform(&txt, paops)?;
        paops.level -= 1;

        let blob = crate::etree::tree_to_blob(&block, paops)?;
        let hexhash = cas::save(blob, paops)?;
        return Ok(TextNode::Stored { keyw, cas: hexhash });
    };

    paops.level += 1;
    let block = transform(&txt, paops)?;
    paops.level -= 1;
    Ok(TextNode::BeginEnd { keyw, txt: block })
}

fn transform_encrypted(node: &TextNode, paops: &mut crate::etree::ParseOps) -> Result<TextNode> {
    let (keyw, txt, extfields) = match node {
        TextNode::Encrypted {
            keyw,
            txt,
            extfields,
        } => (keyw.clone(), txt.clone(), extfields.clone()),
        _ => unreachable!(),
    };

    if paops.transforms.decrypt.contains(&keyw) {
        let ct = match &txt[0] {
            TextNode::Data(data) => data.clone(),
            TextNode::Stored { cas: hexhash, .. } => cas::load(hexhash, paops)?,
            _ => return Err(Error::Msg("No data in ENCRYPTED.".into())),
        };

        let pass = ensure_password(&keyw, paops, false);
        let pt = match prot::decrypt(
            ct,
            &pass,
            &extfields.get("pbkdf"),
            &extfields.get("cipher"),
            &mut paops.crypto.pbkdf_cache,
            &*paops.crypto.policy,
        ) {
            Ok(ct) => ct.to_vec(),
            Err(e) => {
                eprintln!("Error decrypting {}: {}.", keyw, e);
                return Err(e);
            }
        };

        let mut block = crate::etree::blob_to_tree(pt, "decrypted".to_string(), paops)?;
        paops.level += 1;
        block = transform(&block, paops)?;
        paops.level -= 1;
        return Ok(TextNode::BeginEnd { keyw, txt: block });
    }

    if paops.transforms.store.contains(&keyw) {
        let hexhash = match &txt[0] {
            TextNode::Data(data) => cas::save(data.clone(), paops)?,
            TextNode::Stored { cas: hexhash, .. } => hexhash.clone(),
            _ => return Err(Error::Msg("No data in ENCRYPTED.".into())),
        };
        return Ok(TextNode::Encrypted {
            keyw,
            txt: vec![TextNode::Stored {
                keyw: "ct".to_string(),
                cas: hexhash,
            }],
            extfields: std::collections::BTreeMap::new(),
        });
    }

    if paops.transforms.fetch.contains(&keyw) {
        let ct = match &txt[0] {
            TextNode::Data(data) => data.clone(),
            TextNode::Stored { cas: hexhash, .. } => cas::load(hexhash, paops)?,
            _ => return Err(Error::Msg("No data in ENCRYPTED.".into())),
        };
        return Ok(TextNode::Encrypted {
            keyw,
            txt: vec![TextNode::Data(ct)],
            extfields: std::collections::BTreeMap::new(),
        });
    }

    Ok(node.clone())
}

fn transform_stored(node: &TextNode, paops: &mut crate::etree::ParseOps) -> Result<TextNode> {
    let (keyw, cas) = match node {
        TextNode::Stored { keyw, cas } => (keyw.clone(), cas.clone()),
        _ => unreachable!(),
    };

    if paops.transforms.fetch.contains(&keyw) {
        let blob = cas::load(&cas, paops)?;
        let mut block = crate::etree::blob_to_tree(blob, cas.clone(), paops)?;
        paops.level += 1;
        block = transform(&block, paops)?;
        paops.level -= 1;
        return Ok(TextNode::BeginEnd { keyw, txt: block });
    }

    Ok(node.clone())
}

fn ensure_password(keyw: &str, paops: &mut crate::etree::ParseOps, repeat: bool) -> String {
    if let Some(p) = paops.passwords.get(keyw) {
        return p.clone();
    }
    let p = password::get_password(keyw, repeat);
    paops.passwords.insert(keyw.to_string(), p.clone());
    p
}
