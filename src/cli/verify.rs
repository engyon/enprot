//! `enprot verify` subcommand — structural integrity check.
//!
//! Distinct from `verify-chain` (which checks cryptographic chain
//! anchor signatures against trust roots): this checks that parsed
//! EPT files have resolvable CAS pointers, well-formed cipher/pbkdf
//! extfields, and that IMMUTABLE/MUTED content hashes match their
//! declared values.

use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::error::{Error, Result};
use crate::etree::{self, ParseOps};
use crate::{cas, cipher, crypto, pbkdf};

use super::pipeline::pair_inputs_to_outputs;
use super::{CommonArgs, OutputArgs, common::apply_common, common::resolve_policy};

/// `verify` entry point: parse each input file, walk the tree, and
/// report any structural issue (missing CAS blob, malformed extfield,
/// IMMUTABLE/MUTED hash mismatch). Returns Err if any issue found.
pub fn run(common: CommonArgs, output: OutputArgs) -> Result<()> {
    let policy = resolve_policy(&common)?;
    let mut paops = ParseOps::new(policy)?;
    apply_common(&common, &mut paops);

    let files = pair_inputs_to_outputs(
        &output.files,
        &output.output,
        &output.prefix,
        output.output_dir.as_deref(),
    );

    let mut issues = 0usize;
    for (path_in, _) in &files {
        if paops.io.verbose {
            eprintln!("Verifying {}", path_in);
        }

        let reader: Box<dyn BufRead> = if path_in == "-" {
            Box::new(BufReader::new(std::io::stdin()))
        } else {
            Box::new(BufReader::new(File::open(path_in).map_err(|e| {
                Error::Io(std::io::Error::other(format!(
                    "Failed to open {path_in}: {e}"
                )))
            })?))
        };
        paops.runtime.fname = path_in.clone();

        let tree = match etree::parse(reader, &mut paops) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("FAIL {}: parse error: {}", path_in, e);
                issues += 1;
                continue;
            }
        };

        for node in &tree {
            let node_issues = verify_node(node, &mut paops);
            issues += node_issues;
        }

        if issues == 0 {
            eprintln!("OK   {}", path_in);
        }
    }

    if issues > 0 {
        return Err(Error::VerifyFailed { issues });
    }
    Ok(())
}

/// Recursively verify a tree node. Returns the number of issues found.
fn verify_node(node: &etree::TextNode, paops: &mut ParseOps) -> usize {
    match node {
        etree::TextNode::Stored { keyw, cas } => match cas::load(cas, paops) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("FAIL: CAS pointer '{}' for WORD '{}': {}", cas, keyw, e);
                1
            }
        },
        etree::TextNode::Encrypted { txt, extfields, .. } => {
            let mut n = 0;
            for child in txt {
                n += verify_node(child, paops);
            }
            if let Some(cipher_str) = extfields.get("cipher")
                && let Err(e) = cipher::parse_cipher_extfield(cipher_str)
            {
                eprintln!("FAIL: cipher extfield '{}': {}", cipher_str, e);
                n += 1;
            }
            if let Some(phc_str) = extfields.get("pbkdf")
                && let Err(e) = pbkdf::parse_phc(phc_str)
            {
                eprintln!("FAIL: pbkdf extfield '{}': {}", phc_str, e);
                n += 1;
            }
            n
        }
        etree::TextNode::BeginEnd { txt, .. } => {
            let mut n = 0;
            for child in txt {
                n += verify_node(child, paops);
            }
            n
        }
        etree::TextNode::Immutable {
            name,
            hashalg,
            hash,
            txt,
        } => {
            // RSD spec: verify that the declared hash matches the
            // actual content hash.
            let mut n = 0;
            let blob = crate::etree::tree_to_blob(txt, paops);
            match blob {
                Ok(b) => {
                    let policy: &dyn crypto::CryptoPolicy = &*paops.crypto.policy;
                    match crate::crypto::hexdigest(hashalg, &b, policy) {
                        Ok(computed) if computed == *hash => {
                            // Hash matches — pass
                        }
                        Ok(computed) => {
                            eprintln!(
                                "FAIL: IMMUTABLE {} hash mismatch (declared={}, computed={})",
                                name, hash, computed
                            );
                            n += 1;
                        }
                        Err(e) => {
                            eprintln!(
                                "FAIL: IMMUTABLE {} hash algorithm '{}': {}",
                                name, hashalg, e
                            );
                            n += 1;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("FAIL: IMMUTABLE {} internal serialization: {}", name, e);
                    n += 1;
                }
            }
            for child in txt {
                n += verify_node(child, paops);
            }
            n
        }
        etree::TextNode::Muted {
            name,
            hashalg,
            hash,
        } => {
            // MUTED is the sanitized form — content lives in CAS.
            // Verify the CAS blob exists and its hash matches.
            match cas::load(hash, paops) {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!(
                        "FAIL: MUTED {} CAS blob ({}={}): {}",
                        name, hashalg, hash, e
                    );
                    1
                }
            }
        }
        _ => 0,
    }
}
