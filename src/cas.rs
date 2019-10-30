// Copyright (c) 2018-2019 [Ribose Inc](https://www.ribose.com).
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

extern crate hex;

use etree::ParseOps;
use std::fs::File;
use std::io::prelude::*;

use utils;

pub fn load(hexhash: &str, paops: &mut ParseOps) -> Result<Vec<u8>, &'static str> {
    // check that it is valid
    if let Err(_) = hex::decode(hexhash) {
        eprintln!("Not a valid hex token for CAS: {}", hexhash);
        return Err("CAS hex token invalid");
    };

    let mut path = paops.casdir.clone();
    path.push(&hexhash);

    // open input file
    let mut file_in = match File::open(&path) {
        Ok(file_in) => file_in,
        Err(e) => {
            eprintln!("Failed to open {} for reading: {}", path.display(), e);
            return Err("CAS file error");
        }
    };

    let mut blob = Vec::new();
    match file_in.read_to_end(&mut blob) {
        Ok(bytes) => {
            if paops.verbose {
                println!("cas::load(): {} bytes from {}", bytes, path.display());
            }
        }
        Err(e) => {
            eprintln!("Error reading {}: {}", path.display(), e);
            return Err("CAS read error");
        }
    }

    // verify hash just because
    let verify = utils::hexdigest("SHA-3(256)", &blob)?;

    if hexhash != verify {
        eprintln!(
            "CONTENT HASH MISMATCH!\ninput = {}\ncheck = {}",
            hexhash, verify
        );
        return Err("CAS verification error");
    }

    Ok(blob)
}

pub fn save(blob: Vec<u8>, paops: &mut ParseOps) -> Result<String, &'static str> {
    let hexhash = utils::hexdigest("SHA-3(256)", &blob)?;
    let mut path = paops.casdir.clone();
    path.push(&hexhash);

    // check if it exists
    if path.is_file() {
        if paops.verbose {
            println!("cas:save(): {} already exists. Exiting.", path.display());
        }
        return Ok(hexhash);
    }

    // open output file
    let mut file_out = match File::create(&path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open {} for writing: {}", path.display(), e);
            return Err("CAS create error");
        }
    };

    // write it
    match file_out.write(&blob) {
        Ok(bytes) => {
            if paops.verbose {
                println!("cas:save(): {} bytes to {}", bytes, path.display());
            }
        }
        Err(e) => {
            eprintln!(
                "Error writing {} bytes to {}: {}",
                blob.len(),
                path.display(),
                e
            );
            return Err("CAS write error");
        }
    }

    Ok(hexhash)
}
