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

//! In-memory round-trip helpers: serialize a tree to bytes (for the CAS
//! pipeline or for tests that want to re-parse the post-transform output)
//! and re-parse a blob into a tree.

use std::io::Cursor;

use crate::error::Result;
use crate::etree::ParseOps;
use crate::etree::TextTree;
use crate::etree::parse;
use crate::etree::tree_write;

pub fn tree_to_blob(text: &TextTree, paops: &mut ParseOps) -> Result<Vec<u8>> {
    let mut blob = Vec::new();
    tree_write(&mut blob, text, paops)?;
    Ok(blob)
}

pub fn blob_to_tree(data: Vec<u8>, path: String, paops: &mut ParseOps) -> Result<TextTree> {
    paops.runtime.fname = path;
    parse(Cursor::new(data), paops)
}
