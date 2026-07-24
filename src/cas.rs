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

//	content addressed storage

use std::fs::File;
use std::io::prelude::*;

use crate::crypto;
use crate::error::{Error, Result};
use crate::etree::ParseOps;

pub fn load(hexhash: &str, paops: &mut ParseOps) -> Result<Vec<u8>> {
    hex::decode(hexhash).map_err(|_| Error::Cas(format!("Not a valid hex token: {}", hexhash)))?;

    let mut path = paops.casdir.clone();
    path.push(hexhash);

    let mut file_in = File::open(&path)
        .map_err(|e| Error::Cas(format!("Failed to open {}: {}", path.display(), e)))?;

    let mut blob = Vec::new();
    let bytes = file_in
        .read_to_end(&mut blob)
        .map_err(|e| Error::Cas(format!("Error reading {}: {}", path.display(), e)))?;
    if paops.verbose {
        eprintln!("cas::load(): {} bytes from {}", bytes, path.display());
    }

    let verify = crypto::hexdigest("sha3-256", &blob, &*paops.policy)?;
    // Non-constant-time string comparison is fine here: the hash is derived
    // from the file contents (CAS semantic), not from a secret. A timing
    // leak would only reveal how many leading hex chars of a public hash
    // match — no secret material is exposed.
    if hexhash != verify {
        return Err(Error::Cas(format!(
            "CONTENT HASH MISMATCH!\ninput = {}\ncheck = {}",
            hexhash, verify
        )));
    }

    Ok(blob)
}

pub fn save(blob: Vec<u8>, paops: &mut ParseOps) -> Result<String> {
    let hexhash = crypto::hexdigest("sha3-256", &blob, &*paops.policy)?;
    let mut path = paops.casdir.clone();
    path.push(&hexhash);

    if path.is_file() {
        if paops.verbose {
            eprintln!("cas::save(): {} already exists. Exiting.", path.display());
        }
        return Ok(hexhash);
    }

    let mut file_out = File::create(&path)
        .map_err(|e| Error::Cas(format!("Failed to open {}: {}", path.display(), e)))?;
    let bytes = file_out.write(&blob).map_err(|e| {
        Error::Cas(format!(
            "Error writing {} bytes to {}: {}",
            blob.len(),
            path.display(),
            e
        ))
    })?;
    if paops.verbose {
        eprintln!("cas::save(): {} bytes to {}", bytes, path.display());
    }

    Ok(hexhash)
}
