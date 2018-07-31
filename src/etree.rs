// 	etree.rs
//	2018-07-26	Markku-Juhani O. Saarinen <mjos@iki.fi>

extern crate base64;

use std::io::prelude::*;
use std::io::{Cursor,Write};
use std::collections::HashSet;
use std::collections::HashMap;
use std::path::{PathBuf,Path};

use cas;
use prot;

// parse operationsm

pub struct ParseOps {
	pub left_sep: String,					// left separator
	pub right_sep: String,					// right separator
	pub store: HashSet<String>,				// keywords to store
	pub fetch: HashSet<String>,				// keywords to fetch
	pub encrypt: HashSet<String>,			// keywords to encrypt
	pub decrypt: HashSet<String>,			// keywords to decrypt
	pub keys: HashMap<String, Vec<u8>>,		// secret keys 
	pub fname: String,						// file name being parsed
	pub	casdir: PathBuf,					// directory for cas objects
	pub verbose: bool,						// verbose output to stdout
	level: isize,							// current recursion level
}

impl ParseOps {
	pub fn new() -> ParseOps {
		ParseOps { 
			left_sep: "// <(".to_string(),
			right_sep: ")>".to_string(),
			store: HashSet::new(),
			fetch: HashSet::new(),
			encrypt: HashSet::new(),
			decrypt: HashSet::new(),
			keys: HashMap::new(),
			fname: "".to_string(),
			casdir: Path::new("").to_path_buf(),
			level: 0,
			verbose: false,
		}
	}
}

const MAX_DEPTH: isize = 100;			// at least bail out of infinite loop
const DATA_BYTES_PER_LINE: usize = 48;	// that's 64 characters

// the actual tree

type TextTree = Vec<TextNode>;

#[derive(Clone,PartialEq, Eq)]
pub enum TextNode {
	Plain(String),
	Data(Vec<u8>),
	Stored { keyw: String, cas: String },
	Encrypted { keyw: String, txt: TextTree },
	BeginEnd { keyw: String, txt: TextTree },
}

pub fn parse<R>(buf_in: R, paops: &mut ParseOps) 
	-> Result<TextTree, &'static str>
	where R: BufRead
{
	if paops.level > MAX_DEPTH {
		panic!("Maximum recursion depth!");
	}

	let mut text = Vec::new();			// the vector of TextNodes
	let mut lineno = 0;					// line number in source
	let mut pstack = Vec::new();		// stack

	for line_in in buf_in.lines() {

		let line = line_in.expect("read error");
		lineno += 1;

		if !line.trim_left().starts_with(&paops.left_sep) {

			// combine with previous
			if let Some(TextNode::Plain(last)) = text.last_mut() {
				last.push('\n');
				*last += &line;
				continue;
			} 

			text.push(TextNode::Plain(line.clone()));
			continue;
		}

		// we have a command
		let mut trimmed = line.trim().replacen(&paops.left_sep, "", 1);

		// create a vector out of it
		if !trimmed.ends_with(&paops.right_sep) {
			eprintln!("Parse: Right separator '{}' missing.\n\
						{}:{}:{}", paops.right_sep, paops.fname, lineno, line);
			return Err("Parse error");
		}

		let i = trimmed.len() - paops.right_sep.len();
		trimmed.truncate(i);
		let cmd: Vec<&str> = trimmed.split_whitespace().collect();
	
		// parse data
		if cmd[0] == "DATA" {
			for i in 1..cmd.len() {
				let mut data = match base64::decode(cmd[i]) {
					Ok(data) => data,
					Err(e) => {
						eprintln!("Parse: Error decoding base64.\n\
							Parse: '{}': {}\n\
							{}:{}:{}", cmd[i], e, paops.fname, lineno, line); 
						return Err("Parse error");
					},
				};

				// combine with previous
				if let Some(TextNode::Data(last)) = text.last_mut() {
				    last.append(&mut data);
					continue;
				} 
				text.push(TextNode::Data(data));
			}
			continue;
		}

		// parse begin
		if cmd[0] == "BEGIN" {
			if cmd.len() != 2 {
				eprintln!("Parse: BEGIN needs a single keyword.\n\
						{}:{}:{}", paops.fname, lineno, line); 
				return Err("Parse error");
			}
			paops.level += 1;
			pstack.push(TextNode::BeginEnd{ 
				keyw: cmd[1].to_owned(), txt: text });
			text = Vec::new();
			continue;
		}

		// parse begin
		if cmd[0] == "ENCRYPTED" {
			match cmd.len() { 
				2 => {	// immediate data
					paops.level += 1;
					pstack.push(TextNode::Encrypted{ 
						keyw: cmd[1].to_owned(), txt: text });
					text = Vec::new();
					continue;
				},
				3 => {	// CAS parameter
					let node = vec![TextNode::Stored { 
						keyw: "ct".to_string(), cas: cmd[2].to_string() }];
					text.push(TextNode::Encrypted { 
						keyw: cmd[1].to_string(), txt: node });
					continue;
				},
				_ => {
					eprintln!("Parse: ENCRYPTED has wrong number of \
						parameters.\n{}:{}:{}", paops.fname, lineno, line); 
					return Err("Parse error");
				}
			}
		}

		// parse end
		if cmd[0] == "END" {
			if cmd.len() > 2 {
				eprintln!("Parse: Unknown padding in END.\n{}:{}:{}",
							paops.fname, lineno, line);
				return Err("Parse error");
			}
			match pstack.pop() {
				Some(TextNode::BeginEnd{ keyw, txt }) => {

					// keyword mismatch ?
					if cmd.len() >= 2 && keyw != cmd[1] {
						eprintln!("Parse: END mismatch (expected '{}').\n\
							{}:{}:{}", keyw, paops.fname, lineno, line);
						return Err("Parse error");
					}

					let node = TextNode::BeginEnd { 
									keyw: keyw, txt: text };
					text = txt;
					text.push(node);
					paops.level -= 1;
				},
				Some(TextNode::Encrypted{ keyw, txt }) => {
					// keyword mismatch ?
					if keyw != cmd[1] {
						eprintln!("Parse: END mismatch (expected '{}').\n\
							{}:{}:{}", keyw, paops.fname, lineno, line);
						return Err("Parse error");
					}
					// check that the contents are right type
					if text.len() != 1 {
						eprintln!("Parse: {} elements in encrypted {} \
							(must be a single DATA or STORED).\n{}:{}:{}", 
							text.len(), keyw, paops.fname, lineno, line);
						return Err("Parse error");
					}
					match text[0] {
						TextNode::Data(_) | TextNode::Stored{..} => {
							let node = TextNode::Encrypted { 
								keyw: keyw, txt: text };
							text = txt;
							text.push(node);
							paops.level -= 1;						
						},
						_ => {
							eprintln!("Parse: not DATA or STORED \
								element in encrypted {}.\n{}:{}:{}", 
									keyw, paops.fname, lineno, line);
							return Err("Parse error");		
						},
					}
				},
				_ => {
					eprintln!("Parse: END without a start clause.\n{}:{}:{}", 
						paops.fname, lineno, line);
					return Err("Parse error");
				},
			}

			continue;
		}

		// stored
		if cmd[0] == "STORED" {
			if cmd.len() != 3 {
				eprintln!("Parse: STORED needs two parameters.\n{}:{}:{}",
							paops.fname, lineno, line);
				return Err("Parse error");
			}
			text.push(TextNode::Stored{ 
				keyw: cmd[1].to_owned(), cas: cmd[2].to_owned() });
			continue;
		}

		eprintln!("Parse: Unknown section '{}' at\n{}:{}:{}", 
					cmd[0], paops.fname, lineno, line);
		return Err("Parse errorn");
	}

	if pstack.len() > 0 {
		loop {
			match pstack.pop() {
				Some(TextNode::BeginEnd{ keyw, txt: _ }) => {
					eprintln!("Parse: BEGIN {} without END.", keyw);
				},
				Some(TextNode::Encrypted{ keyw, txt: _ }) => {
					eprintln!("Parse: ENCRYPTED {} without END.", keyw);
				},
				_ => return Err("Unexpected end"),
			}
		}
	}

	Ok(text)
}



// recursive unparser

pub fn tree_write<W: Write>(outw: &mut W, text: &TextTree, paops: &mut ParseOps) 
{
	for elem in text {
		match elem {

			// Plain chunk of text
			TextNode::Plain(line) => {
				writeln!(outw, "{}", line).unwrap();
			},

			// BEGIN-END block
			TextNode::BeginEnd{ keyw, txt } => {
				writeln!(outw, "{} BEGIN {} {}", 
					paops.left_sep, keyw, paops.right_sep).unwrap();
				paops.level += 1;
				tree_write(outw, txt, paops);
				paops.level -= 1;
				writeln!(outw, "{} END {} {}", 
					paops.left_sep, keyw, paops.right_sep).unwrap();
			},

			// ENCRYPTED block
			TextNode::Encrypted{ keyw, txt } => {
				if let TextNode::Stored { keyw: _, ref cas } = txt[0] {
					writeln!(outw, "{} ENCRYPTED {} {} {}", 
						paops.left_sep, keyw, cas, paops.right_sep).unwrap();
				} else {
					writeln!(outw, "{} ENCRYPTED {} {}", 
						paops.left_sep, keyw, paops.right_sep).unwrap();
					paops.level += 1;
					tree_write(outw, txt, paops);
					paops.level -= 1;
					writeln!(outw, "{} END {} {}", 
						paops.left_sep, keyw, paops.right_sep).unwrap();
				}
			},

			// STORED
			TextNode::Stored { keyw, cas } => {
				writeln!(outw, "{} STORED {} {} {}", 
					paops.left_sep, keyw, cas, paops.right_sep).unwrap();
			},
			// DATA
			TextNode::Data(data) => {
				for line in data.chunks(DATA_BYTES_PER_LINE) {
					writeln!(outw, "{} DATA {} {}", paops.left_sep, 
						base64::encode(line), paops.right_sep).unwrap();
				}
			},
		}
	}
}

// perform ops

pub fn transform(text_in: TextTree, mut paops: &mut ParseOps) 
	-> Result<TextTree, &'static str>
{
	let mut text_out = Vec::new();

	if paops.level > MAX_DEPTH {
		panic!("Maximum recursion depth!");
	}

	for elem in text_in {
		match elem {

			// BEGIN-END
			TextNode::BeginEnd { ref keyw, ref txt } => {

				// encrypt it ?
				if paops.encrypt.contains(keyw) {
	
					// get blob
					let pt = tree_to_blob(&txt, paops);

					// get key
					let (newkey, key) = match paops.keys.get(keyw) {
						Some(key) => (false, key.to_vec()),
						None => (true, 
							prot::get_key(&keyw, true).as_bytes().to_vec()),
					};
					if newkey {
						paops.keys.insert(keyw.clone().to_string(), 
											key.clone());
					}

					// encrypt
					let ct = prot::encrypt(pt, key);

					// also store it (store at CAS) ?
					let node = if paops.store.contains(keyw) {
						let hexhash = cas::save(ct, paops)?;
						vec![TextNode::Stored {
							keyw: "ct".to_string(), cas: hexhash }]
					} else {
						vec![TextNode::Data(ct)]
					};
					text_out.push(TextNode::Encrypted {	
						keyw: keyw.to_string(), txt: node });
					continue;
				}

				// just store it without encryption ?
				if paops.store.contains(keyw) {
					let blob = tree_to_blob(&txt, paops);
					let hexhash = cas::save(blob, paops)?;
					text_out.push(TextNode::Stored { 
						keyw: keyw.to_string(), cas: hexhash } );
					continue;
				};

				// just recursion
				paops.level += 1;
				let block = transform(txt.to_vec(), paops)?;
				paops.level -= 1;

				text_out.push(TextNode::BeginEnd { 
					keyw: keyw.to_string(), txt: block });
				continue;
			},

			// ENCRYPTED
			TextNode::Encrypted { ref keyw, ref txt } => {

				// decrypt it
				if paops.decrypt.contains(keyw) {

					// get ciphertext
					let ct = match txt[0] {
						TextNode::Data(ref data) => 
							data.to_vec(),
						TextNode::Stored { keyw: _, cas: ref hexhash } =>
							cas::load(&hexhash, paops)?,
						_ => panic!("No data in ENCRYPTED."),
					};

					// get key
					let (newkey, key) = match paops.keys.get(keyw) {
						Some(key) => (false, key.to_vec()),
						None => (true, 
							prot::get_key(keyw, false).as_bytes().to_vec()),
					};
					if newkey {
						paops.keys.insert(keyw.clone().to_string(), 
											key.clone());
					}

					// decrypt
					let pt = match prot::decrypt(ct, key) {
						Some(ct) => ct.to_vec(),
						_ => {
							eprintln!("Bad key for {}.", &keyw);
							return Err("Decryption failure");
						}
					};

					// parse to tree
					let subtree = blob_to_tree(pt, 
									"decrypted".to_string(), &mut paops)?;
					text_out.push(TextNode::BeginEnd { 
						keyw: keyw.to_string(), txt: subtree });
					continue;

				} else {

					// store (store) ciphertext
					if paops.store.contains(keyw) {

						let hexhash = match txt[0] {
							TextNode::Data(ref data) => 
								cas::save(data.to_vec(), paops)?,
							TextNode::Stored { keyw:_, cas: ref hexhash } =>
								hexhash.to_string(),
							_ => panic!("No data in ENCRYPTED."),
						};
						let node = vec![TextNode::Stored { 
							keyw: "ct".to_string(), cas: hexhash }];
						text_out.push(TextNode::Encrypted { 
							keyw: keyw.to_string(), txt: node });
						continue;					
					}

					// fetch (include) ciphertext
					if paops.fetch.contains(keyw) {

						let ct = match txt[0] {
							TextNode::Data(ref data) => 
								data.to_vec(),
							TextNode::Stored { keyw: _, cas: ref hexhash } =>
								cas::load(&hexhash, paops)?,
							_ => panic!("No data in ENCRYPTED."),
						};
						let node = vec![TextNode::Data(ct)];

						text_out.push(TextNode::Encrypted { 
							keyw: keyw.to_string(), 
							txt: node });
						continue;
					};

				}

				text_out.push(elem.clone());
			},

			// STORED
			TextNode::Stored { ref keyw, ref cas } => {
			
				// fetch it ?
				if paops.fetch.contains(keyw) {
					let blob = cas::load(&cas, paops)?;
					let subtree = blob_to_tree(blob, cas.to_string(), paops)?;
					text_out.push(TextNode::BeginEnd{ 
						keyw: keyw.to_string(), txt: subtree });
					continue;
				}

				text_out.push(elem.clone());
			},

			// don't care, just copy
			_ => text_out.push(elem.clone()),
		}
	}
	Ok(text_out)
}

// convenience functions

fn blob_to_tree(data: Vec<u8>, path: String, mut paops: &mut ParseOps) 
	-> Result<TextTree, &'static str>
{
	paops.fname = path.clone();
	let tree = parse(Cursor::new(data), &mut paops)?;
	Ok(tree)
}

fn tree_to_blob(text: &TextTree, mut paops: &mut ParseOps) -> Vec<u8>
{
	let mut blob = Vec::new();
	tree_write(&mut blob, text, &mut paops);
	blob
}


