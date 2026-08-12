//! `enprot verify-chain` subcommand — cryptographic chain verification.
//!
//! Distinct from [`crate::cli::verify`]: this checks cryptographic
//! chain anchor signatures against trust roots, validates payload
//! hashes (tamper detection), and enforces monotonic timestamps.
//! Also used by `provenance_cmd::run_scm` (ScmCommand::Verify path).

use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::error::{Error, Result};
use crate::etree::{self, ParseOps};
use crate::ledger;
use crate::{capability, cappolicy, output};

use super::{CommonArgs, VerifyChainSubcmd, apply_common, resolve_policy};

/// `verify-chain` entry point: for each input file, walk the CHAIN
/// anchor DAG and validate every signature against the named signer's
/// pubkey (from `--trust-root`), check parent references resolve,
/// enforce monotonic timestamps if the policy requires it, and verify
/// each anchor's `payload:` hash matches the file state before that
/// anchor. Returns Err if any file fails.
pub(super) fn run(common: CommonArgs, a: VerifyChainSubcmd) -> Result<()> {
    // Load trust roots into a fingerprint → PEM map.
    let mut trust: HashMap<String, String> = HashMap::new();
    for pem_path in &a.trust_roots {
        let pem = fs::read_to_string(pem_path)?;
        let fp = capability::KeyFp::from_pem(&pem)?;
        trust.insert(fp.to_hex(), pem);
    }

    let cap_policy = common
        .policy_file
        .as_ref()
        .map(|p| cappolicy::CapPolicy::load_file(p))
        .transpose()?;

    let policy = resolve_policy(&common)?;
    let mut paops = ParseOps::new(policy)?;
    apply_common(&common, &mut paops);

    let mut json_reports: Vec<output::VerifyChainFileReport> = Vec::new();
    let mut any_failure = false;
    for path_in in &a.files {
        let result = verify_chain_one_file(path_in, &mut paops, &trust, cap_policy.as_ref());
        match common.format {
            output::OutputFormat::Text => match &result {
                Ok(()) => println!("OK    {}", path_in),
                Err(e) => {
                    any_failure = true;
                    eprintln!("FAIL  {}: {}", path_in, e);
                }
            },
            output::OutputFormat::Json => {
                let report = verify_chain_report_from_result(path_in, &result, &mut paops);
                if !report.ok {
                    any_failure = true;
                }
                json_reports.push(report);
            }
        }
    }

    if matches!(common.format, output::OutputFormat::Json) {
        let payload = output::VerifyChainOutput {
            ok: !any_failure,
            files: json_reports,
        };
        println!("{}", output::to_json(&payload)?);
    }

    if any_failure {
        Err(Error::SignatureVerify {
            key_id: "one or more files failed chain verification".to_string(),
        })
    } else {
        Ok(())
    }
}

/// Build a JSON-friendly per-file report from a verify result. Even on
/// failure, we want to surface the structured errors (and as much of
/// the DAG as we parsed before the failure) rather than a bare string.
fn verify_chain_report_from_result(
    path_in: &str,
    result: &Result<()>,
    paops: &mut ParseOps,
) -> output::VerifyChainFileReport {
    let (ok, message) = match result {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e.to_string())),
    };

    // Re-parse to collect the DAG info. On success this matches what
    // verify_chain_one_file already did; on failure, we re-parse here
    // because the error path returns early without exposing the DAG.
    let reader: Box<dyn BufRead> = if path_in == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        match File::open(path_in) {
            Ok(f) => Box::new(BufReader::new(f)),
            Err(_) => {
                return output::VerifyChainFileReport {
                    path: path_in.to_string(),
                    ok: false,
                    anchors_total: 0,
                    signers: Vec::new(),
                    forks: Vec::new(),
                    errors: vec![output::VerifyError {
                        anchor: None,
                        message: message.unwrap_or_else(|| "unknown error".into()),
                    }],
                };
            }
        }
    };
    paops.runtime.fname = path_in.into();
    let tree = match etree::parse(reader, paops) {
        Ok(t) => t,
        Err(e) => {
            return output::VerifyChainFileReport {
                path: path_in.to_string(),
                ok: false,
                anchors_total: 0,
                signers: Vec::new(),
                forks: Vec::new(),
                errors: vec![output::VerifyError {
                    anchor: None,
                    message: e.to_string(),
                }],
            };
        }
    };

    let mut dag = ledger::AnchorDag::new();
    if let Err(e) = collect_chain_anchors(&tree, &mut dag) {
        return output::VerifyChainFileReport {
            path: path_in.to_string(),
            ok: false,
            anchors_total: 0,
            signers: Vec::new(),
            forks: Vec::new(),
            errors: vec![output::VerifyError {
                anchor: None,
                message: e.to_string(),
            }],
        };
    }

    let tips = dag.tips();
    let signers: Vec<String> = dag
        .iter()
        .map(|(_, s)| s.anchor.signer.to_string())
        .collect();
    let forks: Vec<output::ForkPoint> = tips
        .into_iter()
        .map(|id| {
            let parents = dag
                .get(&id)
                .map(|s| s.anchor.parents.iter().map(|p| p.to_string()).collect())
                .unwrap_or_default();
            output::ForkPoint {
                anchor: id.to_string(),
                parents,
            }
        })
        .collect();

    let errors = match message {
        Some(m) => vec![output::VerifyError {
            anchor: None,
            message: m,
        }],
        None => Vec::new(),
    };

    output::VerifyChainFileReport {
        path: path_in.to_string(),
        ok,
        anchors_total: dag.len(),
        signers,
        forks,
        errors,
    }
}

fn verify_chain_one_file(
    path_in: &str,
    paops: &mut ParseOps,
    trust: &HashMap<String, String>,
    cap_policy: Option<&cappolicy::CapPolicy>,
) -> Result<()> {
    paops.runtime.fname = path_in.into();
    let reader: Box<dyn BufRead> = if path_in == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(File::open(path_in).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "Failed to open {path_in}: {e}"
            )))
        })?))
    };
    let tree = etree::parse(reader, paops)?;

    // Signature + DAG verification.
    let mut dag = ledger::AnchorDag::new();
    collect_chain_anchors(&tree, &mut dag)?;
    let report = dag.verify_signatures(|fp_hex| trust.get(fp_hex).cloned());

    let mut errors: Vec<String> = Vec::new();
    for r in &report.reports {
        if !r.ok
            && let Some(ref e) = r.error
        {
            errors.push(format!("{}: {}", r.id, e));
        }
        if let Some(p) = cap_policy
            && let Some(signed) = dag.get(&r.id)
            && !p.trust_root_allows(&signed.anchor.signer)
        {
            errors.push(format!(
                "{}: signer {} not in policy trust_roots",
                r.id, signed.anchor.signer
            ));
        }
    }

    if let Some(p) = cap_policy
        && p.chain.require_monotonic_timestamps
    {
        errors.extend(check_monotonic_timestamps(&dag));
    }

    // Content integrity: recompute payload_hash for each CHAIN block
    // over the file state BEFORE that block (tree prefix), and compare
    // with the recorded `payload:` field. Mismatch means content was
    // tampered after the anchor was created.
    let payload_errors = verify_payload_hashes(&tree, paops)?;
    errors.extend(payload_errors);

    if !errors.is_empty() {
        return Err(Error::SignatureVerify {
            key_id: format!(
                "{} anchor(s) failed verification: {}",
                errors.len(),
                errors.join("; ")
            ),
        });
    }
    Ok(())
}

/// For each CHAIN block at position i, recompute SHA3-256 over
/// tree[0..i] (all nodes before this CHAIN) and compare with the
/// recorded `payload:` field. Mismatch means the file was tampered
/// after the anchor was created.
///
/// Returns a list of human-readable error strings (empty = all
/// payloads match).
fn verify_payload_hashes(tree: &etree::TextTree, paops: &mut ParseOps) -> Result<Vec<String>> {
    let policy = crate::crypto::CryptoPolicyDefault {};
    let mut errors = Vec::new();
    let mut prefix: etree::TextTree = Vec::new();

    for node in tree {
        if let etree::TextNode::Chain { extfields } = node {
            // Recompute payload over everything we've seen so far
            // (i.e., all nodes BEFORE this CHAIN).
            let blob = etree::tree_to_blob(&prefix, paops)?;
            let recomputed = crate::crypto::hexdigest("sha3-256", &blob, &policy)?;

            let recorded = extfields.get("payload").map(|s| s.as_str()).unwrap_or("");
            if recomputed != recorded {
                errors.push(format!(
                    "payload mismatch: anchor payload={} but file content hashes to {}",
                    recorded, recomputed
                ));
            }
            // The CHAIN node itself becomes part of the prefix for
            // the NEXT anchor (so tampering an anchor also breaks
            // subsequent anchors).
        }
        prefix.push(node.clone());
    }
    Ok(errors)
}

/// Walks the DAG in insertion order and reports any anchor whose
/// timestamp is strictly less than the maximum timestamp of its
/// parents. Anchors without a timestamp are skipped (treated as
/// not-monotonic-data). Empty timestamps on every anchor → no errors.
fn check_monotonic_timestamps(dag: &ledger::AnchorDag) -> Vec<String> {
    let mut errors = Vec::new();
    for (id, signed) in dag.iter() {
        let Some(child_ts) = signed.anchor.timestamp.as_ref() else {
            continue;
        };
        for parent_id in &signed.anchor.parents {
            let Some(parent) = dag.get(parent_id) else {
                continue;
            };
            let Some(parent_ts) = parent.anchor.timestamp.as_ref() else {
                continue;
            };
            if child_ts < parent_ts {
                errors.push(format!(
                    "{}: timestamp {} older than parent {} ({})",
                    id, child_ts, parent_id, parent_ts
                ));
            }
        }
    }
    errors
}

/// Walk a parsed tree and push every `TextNode::Chain` into the DAG.
/// Recurses into `BeginEnd` and `Encrypted` children; CHAIN blocks
/// typically live at the top level but can appear inside any block.
pub(super) fn collect_chain_anchors(
    tree: &etree::TextTree,
    dag: &mut ledger::AnchorDag,
) -> Result<()> {
    for node in tree {
        match node {
            etree::TextNode::Chain { extfields } => {
                let signed = ledger::SignedAnchor::from_extfields(extfields)?;
                dag.push(signed).map_err(Error::from)?;
            }
            etree::TextNode::BeginEnd { txt, .. } | etree::TextNode::Encrypted { txt, .. } => {
                collect_chain_anchors(txt, dag)?;
            }
            _ => {}
        }
    }
    Ok(())
}
