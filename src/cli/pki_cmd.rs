//! `enprot keygen` / `sign` / `verify-sig` / `fingerprint` — PKI commands.
//!
//! All four commands operate on PEM-encoded Ed25519 (or other) keys
//! via `crate::pki`. They're grouped here because they share helpers
//! (`read_file_or_stdin`, `write_key_or_stdout`, `append_sig_ext`)
//! and the same dispatch shape (each takes its `*Subcmd` directly).

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::capability;
use crate::error::{Error, Result};
use crate::pki;

use super::CommonArgs;
use clap::Args;

pub fn keygen(_common: CommonArgs, a: KeygenSubcmd) -> Result<()> {
    let kind: pki::SigAlgKind = a.alg.parse()?;
    let mut rng = botan::RandomNumberGenerator::new_system().map_err(Error::botan)?;
    let (priv_pem, pub_pem) = pki::keygen(kind, &mut rng)?;
    write_key_or_stdout(a.out_priv.as_deref(), priv_pem.as_bytes())?;
    write_key_or_stdout(a.out_pub.as_deref(), pub_pem.as_bytes())?;
    Ok(())
}

pub fn sign(_common: CommonArgs, a: SignSubcmd) -> Result<()> {
    if a.key.is_empty() {
        return Err(Error::InvalidArg {
            arg: "key-file",
            reason: "sign: at least one --key-file is required".to_string(),
        });
    }
    let kind: pki::SigAlgKind = a.alg.parse()?;
    let msg = read_file_or_stdin(a.input.as_deref())?;
    let mut rng = botan::RandomNumberGenerator::new_system().map_err(Error::botan)?;

    let out_path = match (&a.out, &a.input) {
        (Some(p), _) => p.clone(),
        (None, Some(input)) => append_sig_ext(input),
        (None, None) => PathBuf::from("-"),
    };

    if a.key.len() == 1 {
        // Backwards-compat single-sig path: raw signature bytes.
        let priv_pem = fs::read_to_string(&a.key[0])?;
        let sig = pki::sign(kind, &priv_pem, &msg, &mut rng)?;
        if out_path == Path::new("-") {
            std::io::stdout().write_all(&sig)?;
        } else {
            fs::write(&out_path, &sig)?;
        }
        return Ok(());
    }

    // Multi-sig bundle path (TODO.roadmap/59). Each signer signs
    // the same payload; the bundle carries (alg, fp, sig) per
    // signer.
    let mut entries = Vec::with_capacity(a.key.len());
    for key_path in &a.key {
        let priv_pem = fs::read_to_string(key_path)?;
        let botan_priv = botan::Privkey::load_pem(&priv_pem).map_err(Error::botan)?;
        let botan_pub = botan_priv.pubkey().map_err(Error::botan)?;
        let pub_pem = botan_pub.pem_encode().map_err(Error::botan)?;
        let fp = capability::KeyFp::from_pem(&pub_pem)?;
        let sig = pki::sign(kind, &priv_pem, &msg, &mut rng)?;
        entries.push(pki::SigEntry {
            alg: kind,
            fp: fp.to_hex(),
            sig,
        });
    }
    let bundle = pki::SigBundle { entries };
    let body = bundle.serialize();
    if out_path == Path::new("-") {
        std::io::stdout().write_all(body.as_bytes())?;
    } else {
        fs::write(&out_path, body.as_bytes())?;
    }
    Ok(())
}

pub fn verify_sig(_common: CommonArgs, a: VerifySigSubcmd) -> Result<()> {
    if a.key.is_empty() {
        return Err(Error::InvalidArg {
            arg: "key-file",
            reason: "verify-sig: at least one --key-file is required".to_string(),
        });
    }
    let kind: pki::SigAlgKind = a.alg.parse()?;
    let sig_bytes = match (&a.sig, &a.input) {
        (Some(p), _) => fs::read(p)?,
        (None, Some(input)) => fs::read(append_sig_ext(input))?,
        (None, None) => {
            return Err(Error::InvalidArg {
                arg: "sig",
                reason: "verify-sig: no signature file or input file given".to_string(),
            });
        }
    };
    let msg = read_file_or_stdin(a.input.as_deref())?;

    if a.key.len() == 1 {
        // Backwards-compat single-sig path.
        let pub_pem = fs::read_to_string(&a.key[0])?;
        let ok = pki::verify(kind, &pub_pem, &msg, &sig_bytes)?;
        return if ok {
            Ok(())
        } else {
            Err(Error::SignatureVerify {
                key_id: "verify-sig".to_string(),
            })
        };
    }

    // Multi-sig bundle path. Parse the bundle and verify each
    // entry against the supplied pubkeys (matched by fingerprint).
    let body = String::from_utf8(sig_bytes).map_err(|e| Error::InvalidArg {
        arg: "sig",
        reason: format!("signature bundle is not UTF-8: {e}"),
    })?;
    let bundle = pki::SigBundle::parse(&body)?;
    if bundle.entries.len() != a.key.len() {
        return Err(Error::InvalidArg {
            arg: "sig",
            reason: format!(
                "verify-sig: {} signatures in bundle but {} pubkeys supplied",
                bundle.entries.len(),
                a.key.len()
            ),
        });
    }
    // Build fp → pem lookup from the supplied pubkeys.
    let mut by_fp: HashMap<String, String> = HashMap::new();
    for key_path in &a.key {
        let pem = fs::read_to_string(key_path)?;
        let fp = capability::KeyFp::from_pem(&pem)?;
        by_fp.insert(fp.to_hex(), pem);
    }
    for entry in &bundle.entries {
        let pem = by_fp.get(&entry.fp).ok_or_else(|| Error::SignatureVerify {
            key_id: format!("no pubkey for fp {}", entry.fp),
        })?;
        let ok = pki::verify(entry.alg, pem, &msg, &entry.sig)?;
        if !ok {
            return Err(Error::SignatureVerify {
                key_id: format!("fp {}", entry.fp),
            });
        }
    }
    Ok(())
}

/// `foo.txt` → `foo.txt.sig`, `foo` → `foo.sig`. Idempotent if the
/// `.sig` extension is already present.
fn append_sig_ext(input: &Path) -> PathBuf {
    let mut p = input.to_path_buf();
    if p.extension().and_then(|e| e.to_str()) == Some("sig") {
        return p;
    }
    match p.extension() {
        Some(e) => {
            let mut new_ext = e.to_os_string();
            new_ext.push(".sig");
            p.set_extension(new_ext);
        }
        None => {
            p.set_extension("sig");
        }
    }
    p
}

pub fn fingerprint(a: FingerprintSubcmd) -> Result<()> {
    let pem = fs::read_to_string(&a.key)?;
    let fp = capability::KeyFp::from_pem(&pem)?;
    println!("{}", fp);
    Ok(())
}

fn read_file_or_stdin(path: Option<&Path>) -> Result<Vec<u8>> {
    match path {
        Some(p) if p != Path::new("-") => Ok(fs::read(p)?),
        _ => {
            use std::io::Read;
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn write_key_or_stdout(path: Option<&Path>, data: &[u8]) -> Result<()> {
    match path {
        Some(p) if p != Path::new("-") => {
            fs::write(p, data)?;
            // Private keys should be owner-read-only on Unix.
            // We can't tell from the data whether this is a priv
            // or pub key, so set 0600 unconditionally — pubkeys
            // don't need to be world-readable (the caller usually
            // distributes them via other channels).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
            }
        }
        _ => {
            std::io::stdout().write_all(data)?;
        }
    }
    Ok(())
}

/// `keygen` subcommand: emit a fresh keypair.
#[derive(Args)]
pub struct KeygenSubcmd {
    /// Signature algorithm.
    #[arg(value_parser = clap::builder::PossibleValuesParser::new(
        pki::SigAlgKind::ALL.iter().map(|k| k.name()).collect::<Vec<_>>()
    ))]
    pub alg: String,

    /// Write private key to PATH (PEM). Default: stdout.
    #[arg(long = "out-priv", value_name = "PATH")]
    pub out_priv: Option<PathBuf>,

    /// Write public key to PATH (PEM). Default: stdout.
    #[arg(long = "out-pub", value_name = "PATH")]
    pub out_pub: Option<PathBuf>,
}

/// `sign` subcommand: produce a detached signature. When
/// `--key-file` is supplied multiple times (TODO.roadmap/59),
/// produces a multi-signature bundle file; single `--key-file`
/// produces raw signature bytes (backwards compat).
#[derive(Args)]
pub struct SignSubcmd {
    /// Signature algorithm (must match the key type).
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(
        pki::SigAlgKind::ALL.iter().map(|k| k.name()).collect::<Vec<_>>()
    ))]
    pub alg: String,

    /// Private key (PEM) to sign with. Repeatable for multi-sig
    /// bundles. Named `--key-file` because the global `-k/--key`
    /// already means a symmetric WORD=PASSWORD pair.
    #[arg(long = "key-file", value_name = "PRIV.pem")]
    pub key: Vec<PathBuf>,

    /// Input file (omit to read stdin).
    #[arg(value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// Write signature to PATH. Default: `<FILE>.sig`, or stdout when
    /// reading from stdin.
    #[arg(short = 'o', long = "out", value_name = "PATH")]
    pub out: Option<PathBuf>,
}

/// `verify-sig` subcommand: verify a detached signature. When
/// `--key-file` is supplied multiple times (TODO.roadmap/59), the
/// signature file is treated as a multi-sig bundle and every entry
/// must verify against its corresponding pubkey.
#[derive(Args)]
pub struct VerifySigSubcmd {
    /// Signature algorithm (must match the key type).
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(
        pki::SigAlgKind::ALL.iter().map(|k| k.name()).collect::<Vec<_>>()
    ))]
    pub alg: String,

    /// Public key (PEM) to verify against. Repeatable for multi-sig
    /// bundles.
    #[arg(long = "key-file", value_name = "PUB.pem")]
    pub key: Vec<PathBuf>,

    /// Signature file. Default: `<FILE>.sig`. Required when reading
    /// the message from stdin.
    #[arg(long = "sig-file", value_name = "SIG")]
    pub sig: Option<PathBuf>,

    /// Input file (omit to read stdin).
    #[arg(value_name = "FILE")]
    pub input: Option<PathBuf>,
}

/// `fingerprint` subcommand: print the SHA3-256 fingerprint of a
/// PEM-encoded pubkey. Used to populate `trust_roots` lists in
/// policy files (TODO.finalize/26) and to compare two keys for
/// equality without parsing the full PEM.
#[derive(Args)]
pub struct FingerprintSubcmd {
    /// Public key (PEM) to fingerprint.
    #[arg(value_name = "PUB.pem")]
    pub key: PathBuf,
}
