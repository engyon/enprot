//	prot.rs
//	2018-07-30	Markku-Juhani O. Saarinen <mjos@iki.fi>

extern crate rpassword;
extern crate miscreant;
extern crate crypto;

use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;
use self::miscreant::siv::Aes256Siv;

// Get a key -- currently a password prompt

pub fn get_key(name: &str, rep: bool) -> String 
{
	let prompt = "Password for ".to_string() + name + ": ";
	let mut pass = rpassword::prompt_password_stdout(&prompt).unwrap();
	if rep {
		let prompt = "Repeat password for ".to_string() + name + ": ";
		let pass2 = rpassword::prompt_password_stdout(&prompt).unwrap();
		if pass != pass2 {
			eprintln!("Password mismatch. Try again.");
			pass = get_key(name, rep);
		}
	}
	pass
}

// Encrypt

pub fn encrypt(pt: Vec<u8>, key: Vec<u8>) -> Vec<u8>
{
	let no_ad = vec![vec![]];
	let mut sivkey = [0; 64];
	let mut khash = Sha3::sha3_512();
	khash.input(&key);
	khash.result(&mut sivkey);

	Aes256Siv::new(&sivkey).seal(&no_ad, &pt)
}

// Decrypt

pub fn decrypt(ct: Vec<u8>, key: Vec<u8>) -> Option<Vec<u8>>
{
	let no_ad = vec![vec![]];
	let mut sivkey = [0; 64];
	let mut khash = Sha3::sha3_512();
	khash.input(&key);
	khash.result(&mut sivkey);

	// The miscreant error type is really uninformative (good!)
	match Aes256Siv::new(&sivkey).open(&no_ad, &ct) {
		Ok(pt) => Some(pt),
		Err(_) => None
	}
}

