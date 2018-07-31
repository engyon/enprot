//	cas.rs
//	2018-07-28	Markku-Juhani O. Saarinen <mjos@iki.fi>

//	content addressed storage

extern crate hex;
extern crate crypto;

use std::io::prelude::*;
use std::fs::File;
use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;
use etree::ParseOps;

pub fn load(hexhash: &str, paops: &mut ParseOps)
	-> Result<Vec<u8>, &'static str>
{
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
			eprintln!("Failed to open {} for reading: {}", 
				path.display(), e);
			return Err("CAS file error");
		},
	};

	let mut blob = Vec::new();
	match file_in.read_to_end(&mut blob) {
		Ok(bytes) => {
			if paops.verbose {
				println!("cas::load(): {} bytes from {}", 
					bytes, path.display());
			}
		},
		Err(e) => {
			eprintln!("Error reading {}: {}", path.display(), e);
			return Err("CAS read error");
		}
	}

	// verify hash just because
	let mut hasher = Sha3::sha3_256();
	hasher.input(&blob);
	let verify = hasher.result_str();

	if hexhash != verify {
		eprintln!("CONTENT HASH MISMATCH!\ninput = {}\ncheck = {}", 	
					hexhash, verify);
		return Err("CAS verification error");
	}

	Ok(blob)
}

pub fn save(blob: Vec<u8>, paops: &mut ParseOps)
	-> Result<String, &'static str>

{
	let mut hasher = Sha3::sha3_256();
	hasher.input(&blob);
	let hexhash = hasher.result_str();
	let mut path = paops.casdir.clone();
	path.push(&hexhash);

	// check if it exists
	if path.is_file() {
		if paops.verbose {
			println!("cas:save(): {} already exists. Exiting.", 
				path.display());
		}
		return Ok(hexhash);
	}

	// open output file
	let mut file_out = match File::create(&path) {
		Ok(file) => file,
		Err(e) => {
			eprintln!("Failed to open {} for writing: {}", 
						path.display(), e);
			return Err("CAS create error");
		},
	};

	// write it
	match file_out.write(&blob) {
		Ok(bytes) => {
			if paops.verbose {
				println!("cas:save(): {} bytes to {}", 
						bytes, path.display());
			}
		},
		Err(e) => {
			eprintln!("Error writing {} bytes to {}: {}", 
				blob.len(), path.display(), e);
			return Err("CAS write error");
		},
	}

	Ok(hexhash)
}

