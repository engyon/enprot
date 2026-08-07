//! `enprot clean` / `smudge` / `textconv` subcommands — git filter drivers.

use std::io::{Read, Write};

use crate::error::{Error, Result};
use crate::etree::{self, ParseOps};
use crate::{crypto, prot};

use super::{CommonArgs, SmudgeCleanSubcmd};

/// Direction of the smudge/clean filter. Clean encrypts (plaintext
/// in, ciphertext out); Smudge decrypts (ciphertext in, plaintext
/// out). Textconv is the same as Smudge — git just calls it from a
/// different context (diff rendering vs. checkout).
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Mode {
    Clean,
    Smudge,
}

/// Entry point for the three filter-driver subcommands. Pipes stdin
/// through the encrypt (Clean) or decrypt (Smudge/Textconv) pipeline
/// and writes the result to stdout. The input is treated as opaque
/// bytes — Clean bypasses the tree pipeline entirely and emits a
/// single self-describing Encrypted block; Smudge parses the EPT
/// markup to locate the Encrypted block to decrypt.
pub fn run(mode: Mode, a: SmudgeCleanSubcmd, common: CommonArgs) -> Result<()> {
    let password = lookup_word_password(&common, &a.word)?;

    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let policy = Box::new(crypto::CryptoPolicyDefault {}) as Box<dyn crypto::CryptoPolicy>;
    let mut paops = ParseOps::new(policy)?;
    paops.passwords.insert(a.word.clone(), password);

    match mode {
        Mode::Clean => {
            paops.crypto.cipheropts.alg = a
                .cipher
                .clone()
                .unwrap_or_else(|| "aes-256-gcm-siv-det".to_string());
            if let Some(p) = a.pbkdf.as_ref() {
                paops.crypto.pbkdfopts.alg = p.clone();
            }
            let (ct, extfields) = prot::encrypt(
                input,
                paops.passwords.get(&a.word).unwrap(),
                &mut paops.crypto.rng,
                &paops.crypto.pbkdfopts,
                &paops.crypto.cipheropts,
                &mut paops.crypto.pbkdf_cache,
                &*paops.crypto.policy,
            )?;
            let tree: etree::TextTree = vec![etree::TextNode::Encrypted {
                keyw: a.word.clone(),
                txt: vec![etree::TextNode::Data(ct)],
                extfields,
            }];
            etree::tree_write(&mut out, &tree, &mut paops)?;
        }
        Mode::Smudge => {
            paops.runtime.fname = "<smudge-stdin>".into();
            let cursor = std::io::Cursor::new(input);
            let tree = etree::parse(cursor, &mut paops)?;
            let (ct, pbkdf, cipher) =
                extract_first_encrypted(&tree, &a.word).ok_or_else(|| Error::BlockShape {
                    word: a.word.clone(),
                    reason: "no ENCRYPTED block for this WORD in input".to_string(),
                })?;
            let pt = prot::decrypt(
                ct,
                paops.passwords.get(&a.word).unwrap(),
                &pbkdf.as_ref(),
                &cipher.as_ref(),
                &mut paops.crypto.pbkdf_cache,
                &*paops.crypto.policy,
            )?;
            out.write_all(&pt)?;
        }
    }
    out.flush()?;
    Ok(())
}

/// Walk a parsed tree and return the first Encrypted block's
/// ciphertext payload (Data or Stored) plus its extfields for the
/// named WORD. Returns (ct, pbkdf, cipher) — the values decrypt needs.
fn extract_first_encrypted(
    tree: &etree::TextTree,
    word: &str,
) -> Option<(Vec<u8>, Option<String>, Option<String>)> {
    for node in tree {
        match node {
            etree::TextNode::Encrypted {
                keyw,
                txt,
                extfields,
            } if keyw == word => {
                if let Some(first) = txt.first() {
                    let payload = match first {
                        etree::TextNode::Data(d) => Some(d.clone()),
                        _ => None,
                    };
                    if let Some(ct) = payload {
                        let pbkdf = extfields.get("pbkdf").cloned();
                        let cipher = extfields.get("cipher").cloned();
                        return Some((ct, pbkdf, cipher));
                    }
                }
            }
            etree::TextNode::BeginEnd { txt, .. } => {
                if let Some(found) = extract_first_encrypted(txt, word) {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

/// Pull the WORD password from `-k` or `ENPROPT_KEY=WORD=password`.
/// Git filters can't prompt interactively, so the env-var fallback
/// is required for non-interactive use.
fn lookup_word_password(common: &CommonArgs, word: &str) -> Result<String> {
    for (w, p) in &common.password {
        if w == word {
            return Ok(p.clone());
        }
    }
    if let Ok(env_val) = std::env::var("ENPROPT_KEY")
        && let Some((w, p)) = env_val.split_once('=')
        && w == word
        && !p.is_empty()
    {
        return Ok(p.to_string());
    }
    Err(Error::InvalidArg {
        arg: "password",
        reason: format!("no password supplied for WORD {word}"),
    })
}
