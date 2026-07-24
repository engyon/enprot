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

//! Inverse of `parse`: emit EPT markup from a `TextTree`. IO errors
//! propagate (audit A8); a write failure no longer panics.

use std::io::Write;

use crate::error::Result;
use crate::etree::ParseOps;
use crate::etree::TextNode;
use crate::etree::TextTree;
use crate::utils;

const DATA_BYTES_PER_LINE: usize = 48;

pub fn tree_write<W: Write>(outw: &mut W, text: &TextTree, paops: &mut ParseOps) -> Result<()> {
    for elem in text {
        match elem {
            TextNode::Plain(line) => writeln!(outw, "{}", line)?,
            TextNode::BeginEnd { keyw, txt } => {
                writeln!(
                    outw,
                    "{} BEGIN {} {}",
                    paops.separators.left, keyw, paops.separators.right
                )?;
                paops.level += 1;
                tree_write(outw, txt, paops)?;
                paops.level -= 1;
                writeln!(
                    outw,
                    "{} END {} {}",
                    paops.separators.left, keyw, paops.separators.right
                )?;
            }
            TextNode::Encrypted {
                keyw,
                txt,
                extfields,
            } => {
                write!(outw, "{} ENCRYPTED {}", paops.separators.left, keyw)?;
                if let TextNode::Stored { keyw: _, cas } = &txt[0] {
                    write!(outw, " {}", cas)?;
                    for (key, value) in extfields.iter() {
                        write!(outw, " {}:{}", key, value)?;
                    }
                    writeln!(outw, " {}", paops.separators.right)?;
                } else {
                    for (key, value) in extfields.iter() {
                        write!(outw, " {}:{}", key, value)?;
                    }
                    writeln!(outw, " {}", paops.separators.right)?;
                    paops.level += 1;
                    tree_write(outw, txt, paops)?;
                    paops.level -= 1;
                    writeln!(
                        outw,
                        "{} END {} {}",
                        paops.separators.left, keyw, paops.separators.right
                    )?;
                }
            }
            TextNode::Stored { keyw, cas } => {
                writeln!(
                    outw,
                    "{} STORED {} {} {}",
                    paops.separators.left, keyw, cas, paops.separators.right
                )?;
            }
            TextNode::Data(data) => {
                for chunk in data.chunks(DATA_BYTES_PER_LINE) {
                    writeln!(
                        outw,
                        "{} DATA {} {}",
                        paops.separators.left,
                        utils::base64_encode(chunk)?,
                        paops.separators.right
                    )?;
                }
            }
        }
    }
    Ok(())
}
