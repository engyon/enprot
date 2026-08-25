//! Core transform pipeline — `encrypt` / `decrypt` / `store` / `fetch` /
//! `encrypt-store` / `passthrough`.
//!
//! This module owns the orchestration that turns a typed [`RunConfig`]
//! into actual file transformations. `app_main`'s dispatch arms for
//! the six core ops each build a `RunConfig` and call [`run`]. The
//! parallel-processing path (`--jobs > 1`) builds one `ParseOps` per
//! scoped thread via [`RunConfig::build_paops`].

use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use crate::error::{Error, Result};
use crate::etree::{self, ParseOps};
use crate::{capability, cappolicy};

use super::{
    CommonArgs, EncryptOpts, Operation, OutputArgs, build_anchor_config, make_policy,
    resolve_policy_name, resolve_separators, validate, walk_for_chains,
};

/// Typed configuration for the four core transform operations
/// (`encrypt`, `decrypt`, `store`, `fetch`, `encrypt-store`,
/// `passthrough`). Grouping these previously-separate parameters
/// into a struct gives the FFI, library consumers, and tests a
/// single dispatch surface that doesn't depend on clap.
///
/// Model-driven: the configuration IS the model. `app_main` parses
/// argv into `RunConfig`; `run()` consumes `RunConfig`. The FFI
/// can build a `RunConfig` directly from JSON, bypassing clap
/// entirely.
#[derive(Clone, Debug)]
pub struct RunConfig {
    pub common: CommonArgs,
    pub output: OutputArgs,
    /// `None` means Passthrough (no transform).
    pub op: Option<(EncryptOpts, Operation)>,
    pub recipient_pubs: Vec<String>,
    pub recipient_privs: Vec<String>,
}

impl RunConfig {
    /// Build a fresh `ParseOps` from this configuration. Each call
    /// produces an independent instance with its own RNG, PBKDF cache,
    /// and mutable state. Safe to call from multiple threads — no
    /// shared mutable state between instances.
    ///
    /// `policy_name` must be pre-resolved (FIPS detection, explicit
    /// policy, defaults) by the caller. This method does NOT redo
    /// that resolution.
    pub(super) fn build_paops(&self, policy_name: &str) -> Result<ParseOps> {
        let policy = make_policy(policy_name);
        let mut paops = if let Some(defaults) = self.common.defaults.as_deref() {
            let mut p = ParseOps::new(make_policy(defaults))?;
            p.crypto.policy = policy;
            p
        } else {
            ParseOps::new(policy)?
        };

        if let Some(dir) = self.common.casdir.clone() {
            paops.io.set_local_casdir(dir);
        } else if Path::new("cas").is_dir() {
            paops.io.set_local_casdir(Path::new("cas").to_path_buf());
        } else {
            paops.io.set_local_casdir(Path::new(".").to_path_buf());
        }

        paops.io.verbose = self.common.verbose && !self.common.quiet;
        paops.io.inline_data = self.common.inline || self.common.casdir.is_none();
        paops.io.streaming = self.common.streaming;
        paops.max_depth = self.common.max_depth;
        let (left, right) = resolve_separators(&self.common);
        paops.separators.left = left;
        paops.separators.right = right;
        paops.passwords.extend(self.common.password.clone());
        paops.crypto.recipient_pubs = self.recipient_pubs.clone();
        for (i, w) in self.output.word.iter().enumerate() {
            if let Some(priv_pem) = self
                .recipient_privs
                .get(i)
                .or_else(|| self.recipient_privs.first())
            {
                paops
                    .crypto
                    .recipient_privkeys
                    .insert(w.clone(), priv_pem.clone());
            }
        }
        if self.common.pbkdf_disable_cache {
            paops.crypto.pbkdf_cache = None;
        }

        if let Some((enc_opts, op_kind)) = self.op.as_ref() {
            for w in &self.output.word {
                match op_kind {
                    Operation::Encrypt => {
                        paops.transforms.encrypt.insert(w.clone());
                    }
                    Operation::Decrypt => {
                        paops.transforms.decrypt.insert(w.clone());
                    }
                    Operation::Store => {
                        paops.transforms.store.insert(w.clone());
                    }
                    Operation::Fetch => {
                        paops.transforms.fetch.insert(w.clone());
                    }
                    Operation::EncryptStore => {
                        paops.transforms.encrypt.insert(w.clone());
                        paops.transforms.store.insert(w.clone());
                    }
                }
            }

            if matches!(op_kind, Operation::Encrypt | Operation::EncryptStore) {
                if let Some(alg) = enc_opts.pbkdf.as_deref() {
                    paops.crypto.pbkdfopts.alg = alg.to_string();
                }
                if let Some(saltlen) = enc_opts.pbkdf_salt_len {
                    paops.crypto.pbkdfopts.saltlen = saltlen;
                }
                if let Some(msec) = enc_opts.pbkdf_msec {
                    paops.crypto.pbkdfopts.msec = Some(msec);
                }
                if let Some(raw) = enc_opts.pbkdf_params.as_deref() {
                    paops.crypto.pbkdfopts.msec = None;
                    let params: std::collections::BTreeMap<String, usize> = raw
                        .split(',')
                        .map(|kv| {
                            let (k, v) = kv.split_once('=').unwrap_or(("", "0"));
                            (k.to_string(), v.parse().unwrap_or(0))
                        })
                        .collect();
                    paops.crypto.pbkdfopts.params = Some(params);
                }
                if let Some(salt_hex) = enc_opts.pbkdf_salt.as_deref() {
                    paops.crypto.pbkdfopts.salt = Some(hex::decode(salt_hex).map_err(Error::from)?);
                }
                if let Some(c) = enc_opts.cipher.as_deref() {
                    paops.crypto.cipheropts.alg = c.to_string();
                }
                if let Some(iv_hex) = enc_opts.cipher_iv.as_deref() {
                    paops.crypto.cipheropts.iv = Some(hex::decode(iv_hex).map_err(Error::from)?);
                }
                paops.crypto.cipheropts.compress = enc_opts.compress;
            }
        }

        paops.anchor = build_anchor_config(
            self.common.anchor,
            self.common.signer.as_deref(),
            self.op.as_ref().map(|(_, k)| *k),
            &self.output.word,
        )?;

        Ok(paops)
    }
}

pub fn run(cfg: RunConfig) -> Result<()> {
    let cfg_parallel = cfg.clone();
    let RunConfig {
        common,
        output,
        op,
        recipient_pubs,
        recipient_privs,
    } = cfg;
    // Resolve policy via the shared `resolve_policy_name` helper —
    // single source of truth for the FIPS+policy conflict check
    // (DRY). The upfront `validate_common` gate catches the user-set
    // --fips case for CLI callers; this remains defense-in-depth for
    // the /proc/sys/crypto/fips_enabled runtime auto-engage path and
    // for library callers that bypass validate_common.
    let policy_name = resolve_policy_name(&common)?;
    let policy = make_policy(&policy_name);
    // Per-subcommand semantic rules (TODO.complete/33 phase 2): output
    // wiring and encrypt knobs against the resolved policy. Same gate
    // as validate_common — all issues at once, before any file is
    // processed.
    let mut issues = validate::collect_output(&output);
    if let Some((enc_opts, _)) = op.as_ref() {
        issues.extend(validate::collect_encrypt(enc_opts, policy.as_ref()));
    }
    validate::report(&issues)?;
    let mut paops = if let Some(defaults) = common.defaults.as_deref() {
        let mut p = ParseOps::new(make_policy(defaults))?;
        p.crypto.policy = policy;
        p
    } else {
        ParseOps::new(policy)?
    };

    if let Some(dir) = common.casdir.clone() {
        paops.io.set_local_casdir(dir);
    } else if Path::new("cas").is_dir() {
        paops.io.set_local_casdir(Path::new("cas").to_path_buf());
    } else {
        paops.io.set_local_casdir(Path::new(".").to_path_buf());
    }

    paops.io.verbose = common.verbose && !common.quiet;
    paops.io.inline_data = common.inline || common.casdir.is_none();
    paops.max_depth = common.max_depth;
    let (left, right) = resolve_separators(&common);
    paops.separators.left = left;
    paops.separators.right = right;
    paops.passwords.extend(common.password);
    paops.crypto.recipient_pubs = recipient_pubs;
    for (i, w) in output.word.iter().enumerate() {
        if let Some(priv_pem) = recipient_privs.get(i).or_else(|| recipient_privs.first()) {
            paops
                .crypto
                .recipient_privkeys
                .insert(w.clone(), priv_pem.clone());
        }
    }
    if common.pbkdf_disable_cache {
        paops.crypto.pbkdf_cache = None;
    }

    // Apply the operation: populate the transform sets on paops. `op == None`
    // means Passthrough — leave the sets empty.
    if let Some((enc_opts, op_kind)) = op.as_ref() {
        // Capability policy check (TODO.roadmap/46): when encrypting,
        // refuse to write blocks for a WORD whose required capability
        // the caller doesn't hold. Decrypt/store/fetch don't gate on
        // per-WORD capability — they're not capability-changing ops.
        if matches!(op_kind, Operation::Encrypt | Operation::EncryptStore)
            && let Some(p) = common
                .policy_file
                .as_ref()
                .map(|p| cappolicy::CapPolicy::load_file(p))
                .transpose()?
        {
            let held = capability::CapabilitySet::from_paops(&paops);
            for w in &output.word {
                p.check_word_capability(w, &held)?;
            }
        }
        for w in &output.word {
            match op_kind {
                Operation::Encrypt => {
                    paops.transforms.encrypt.insert(w.clone());
                }
                Operation::Decrypt => {
                    paops.transforms.decrypt.insert(w.clone());
                }
                Operation::Store => {
                    paops.transforms.store.insert(w.clone());
                }
                Operation::Fetch => {
                    paops.transforms.fetch.insert(w.clone());
                }
                Operation::EncryptStore => {
                    paops.transforms.encrypt.insert(w.clone());
                    paops.transforms.store.insert(w.clone());
                }
            }
        }

        // PBKDF + cipher options only meaningful for encrypt / encrypt-store.
        if matches!(op_kind, Operation::Encrypt | Operation::EncryptStore) {
            if let Some(alg) = enc_opts.pbkdf.as_deref() {
                paops.crypto.pbkdfopts.alg = alg.to_string();
            }
            if let Some(saltlen) = enc_opts.pbkdf_salt_len {
                paops.crypto.pbkdfopts.saltlen = saltlen;
            }
            if let Some(msec) = enc_opts.pbkdf_msec {
                paops.crypto.pbkdfopts.msec = Some(msec);
            }
            if let Some(raw) = enc_opts.pbkdf_params.as_deref() {
                paops.crypto.pbkdfopts.msec = None;
                let params: std::collections::BTreeMap<String, usize> = raw
                    .split(',')
                    .map(|kv| {
                        let (k, v) = kv.split_once('=').unwrap_or(("", "0"));
                        (k.to_string(), v.parse().unwrap_or(0))
                    })
                    .collect();
                paops.crypto.pbkdfopts.params = Some(params);
            }
            if let Some(salt_hex) = enc_opts.pbkdf_salt.as_deref() {
                paops.crypto.pbkdfopts.salt = Some(hex::decode(salt_hex).map_err(Error::from)?);
            }
            if let Some(c) = enc_opts.cipher.as_deref() {
                paops.crypto.cipheropts.alg = c.to_string();
            }
            if let Some(iv_hex) = enc_opts.cipher_iv.as_deref() {
                paops.crypto.cipheropts.iv = Some(hex::decode(iv_hex).map_err(Error::from)?);
            }
        }
    }

    if paops.io.verbose {
        eprintln!(
            "LEFT_SEP='{}' RIGHT_SEP='{}' casdir = '{}'",
            paops.separators.left,
            paops.separators.right,
            paops.io.casdir.display(),
        );
    }

    let files = pair_inputs_to_outputs(
        &output.files,
        &output.output,
        &output.prefix,
        output.output_dir.as_deref(),
    );

    // Populate the anchor context once. `passthrough` (op == None) is
    // excluded because it performs no transformation and therefore
    // has nothing meaningful to anchor.
    paops.anchor = build_anchor_config(
        common.anchor,
        common.signer.as_deref(),
        op.as_ref().map(|(_, k)| *k),
        &output.word,
    )?;

    // --- File processing ---
    // Metric label for the per-file counters: the subcommand's
    // operation (`encrypt`, `fetch`, …); `passthrough` records none
    // (op == None means no transformation ran).
    let op_label = op.as_ref().map(|(_, k)| k.label()).unwrap_or("passthrough");
    // When --jobs > 1 and we have multiple files, process them in
    // parallel using scoped threads. Each thread builds its own
    // ParseOps from the same RunConfig — no shared mutable state.
    if common.jobs > 1 && files.len() > 1 {
        tracing::info!(
            files = files.len(),
            jobs = common.jobs,
            "processing files in parallel"
        );
        let jobs = common.jobs.min(files.len());
        let chunk_size = files.len().div_ceil(jobs);
        let policy_name_ref = &policy_name;
        let cfg_ref = &cfg_parallel;
        let chunks: Vec<&[(String, String)]> = files.chunks(chunk_size).collect();
        std::thread::scope(|s| {
            let handles: Vec<_> = chunks
                .iter()
                .map(|chunk| {
                    s.spawn(move || -> Result<()> {
                        let mut local_paops = cfg_ref.build_paops(policy_name_ref)?;
                        for (path_in, path_out) in chunk.iter() {
                            process_one_file(path_in, path_out, op_label, &mut local_paops)?;
                        }
                        Ok(())
                    })
                })
                .collect();
            for h in handles {
                h.join()
                    .map_err(|_| Error::Io(std::io::Error::other("worker thread panicked")))??;
            }
            Ok(())
        })
    } else {
        for (i, (path_in, path_out)) in files.iter().enumerate() {
            if files.len() > 1 && !common.quiet {
                eprintln!("[{}/{}] {}", i + 1, files.len(), path_in);
            }
            process_one_file(path_in, path_out, op_label, &mut paops)?;
        }
        Ok(())
    }
}

/// Pair each input with its output, following the rules in
/// `TODO.issues/18-output-directory-mode.md`:
///
/// 1. `--output <FILE>` paired with this input → use it as-is.
/// 2. `--output-dir <DIR>` given → `DIR + "/" + basename(input)`.
/// 3. `--prefix <PREFIX>` where PREFIX ends in `/` or is an existing
///    directory → same as `--output-dir` behaviour.
/// 4. `--prefix <PREFIX>` (other) → PREFIX prepended to input verbatim
///    (the legacy flat-CLI behavior).
/// 5. Input is `-` (stdin) → output is `-` (stdout passthrough).
/// 6. Otherwise → output = input (in-place).
pub(super) fn pair_inputs_to_outputs(
    inputs: &[String],
    outputs: &[String],
    prefix: &str,
    output_dir: Option<&Path>,
) -> Vec<(String, String)> {
    let mut result = Vec::with_capacity(inputs.len());
    let mut out_iter = outputs.iter();
    let prefix_is_dir = !prefix.is_empty() && (prefix.ends_with('/') || Path::new(prefix).is_dir());

    for input in inputs {
        if let Some(output) = out_iter.next() {
            result.push((input.clone(), output.clone()));
            continue;
        }
        let output = if input == "-" {
            "-".to_string()
        } else if let Some(dir) = output_dir {
            join_with_basename(dir, input)
        } else if prefix_is_dir {
            let dir_str = prefix.trim_end_matches('/');
            join_with_basename(Path::new(dir_str), input)
        } else if prefix.is_empty() {
            input.clone()
        } else {
            format!("{}{}", prefix, input)
        };
        result.push((input.clone(), output));
    }
    result
}

fn join_with_basename(dir: &Path, input: &str) -> String {
    let base = Path::new(input)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| input.to_string());
    dir.join(base).to_string_lossy().into_owned()
}

#[tracing::instrument(skip(paops, operation), fields(path = %path_in))]
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
fn process_one_file(
    path_in: &str,
    path_out: &str,
    operation: &'static str,
    paops: &mut ParseOps,
) -> Result<()> {
    tracing::debug!(path_in, path_out, "processing file");

    let reader_in: Box<dyn BufRead> = if path_in == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        match std::fs::File::open(path_in) {
            Ok(f) => Box::new(BufReader::new(f)),
            Err(e) => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "Failed to open {path_in} for reading: {e}"
                ))));
            }
        }
    };

    paops.runtime.fname = if path_in == "-" {
        "<stdin>".to_string()
    } else {
        path_in.to_string()
    };

    // Streaming fast path (TODO.complete/35): bounded memory, output
    // written incrementally. Anchoring and dry-run need the full
    // tree (payload hash / node stats), so they keep the in-memory
    // pipeline regardless of the flag.
    if paops.io.streaming && !paops.anchor.enabled && !paops.io.dry_run {
        if paops.io.verbose {
            eprintln!("Streaming {}", path_in);
        }
        let mut writer_out: Box<dyn Write> = if path_out == "-" {
            Box::new(BufWriter::new(std::io::stdout()))
        } else {
            match std::fs::File::create(path_out) {
                Ok(f) => Box::new(BufWriter::new(f)),
                Err(e) => {
                    return Err(Error::Io(std::io::Error::other(format!(
                        "Failed to open {path_out} for writing: {e}"
                    ))));
                }
            }
        };
        return etree::transform_stream(reader_in, &mut writer_out, paops)
            .map_err(|e| Error::Io(std::io::Error::other(format!("{e} in {path_in}, aborting"))));
    }

    let tree_in = etree::parse(reader_in, paops)
        .map_err(|e| Error::Io(std::io::Error::other(format!("{e} in {path_in}, aborting"))))?;

    if paops.io.verbose {
        eprintln!("Transforming {}", path_in);
    }
    let mut tree_out = etree::transform(&tree_in, paops)
        .map_err(|e| Error::Io(std::io::Error::other(format!("{e} in {path_in}, aborting"))))?;

    // Optionally append a CHAIN block signing the new file state.
    // Must happen BEFORE tree_write so the anchor lands in the output.
    if paops.anchor.enabled {
        let chain_node = build_chain_anchor_node(&tree_out, paops)?;
        tree_out.push(chain_node);
    }

    if paops.io.verbose {
        eprintln!("Writing {}", path_out);
    }

    if paops.io.dry_run {
        eprintln!(
            "dry-run: {} → {} ({} nodes in, {} nodes out, would write)",
            path_in,
            path_out,
            tree_in.len(),
            tree_out.len()
        );
        return Ok(());
    }

    let mut writer_out: Box<dyn Write> = if path_out == "-" {
        Box::new(BufWriter::new(std::io::stdout()))
    } else {
        match std::fs::File::create(path_out) {
            Ok(f) => Box::new(BufWriter::new(f)),
            Err(e) => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "Failed to open {path_out} for writing: {e}"
                ))));
            }
        }
    };

    etree::tree_write(&mut writer_out, &tree_out, paops).map_err(|e| {
        Error::Io(std::io::Error::other(format!(
            "Write to {path_out} failed: {e}"
        )))
    })?;
    #[cfg(feature = "telemetry")]
    {
        let bytes = std::fs::metadata(path_in).map(|m| m.len()).unwrap_or(0);
        crate::telemetry::metrics::record_file_processed(operation);
        crate::telemetry::metrics::record_bytes_processed(operation, bytes);
    }
    Ok(())
}

/// Build a [`TextNode::Chain`] node that signs the post-transform
/// `tree_out` state. The payload hash commits to the file content
/// EXCLUDING any chain anchors — that way the anchor isn't
/// self-referential and the hash is stable across re-anchoring.
///
/// parents: hashes of every CHAIN block already present in tree_out,
/// in file order. This makes the new anchor a linear descendant of
/// the most-recent prior anchor (TODO.finalize/17 DAG semantics;
/// multiple-parents / merge anchors are a future extension).
fn build_chain_anchor_node(
    tree_out: &etree::TextTree,
    paops: &mut ParseOps,
) -> Result<etree::TextNode> {
    use crate::ledger::{Anchor, PayloadHash, SignerId};
    use crate::pki::SigAlgKind;
    use std::collections::BTreeMap;

    let priv_pem = paops
        .anchor
        .signer_priv_pem
        .clone()
        .ok_or_else(|| Error::InvalidArg {
            arg: "anchor",
            reason: "anchor config missing signer_priv_pem".to_string(),
        })?;

    // Derive pubkey from privkey; compute fingerprint.
    let botan_priv = botan::Privkey::load_pem(&priv_pem).map_err(Error::botan)?;
    let botan_pub = botan_priv.pubkey().map_err(Error::botan)?;
    let pub_pem = botan_pub.pem_encode().map_err(Error::botan)?;
    let fp = capability::KeyFp::from_pem(&pub_pem)?;

    // payload_hash: SHA3-256 over the ENTIRE post-transform tree
    // (including any prior CHAIN blocks). This gives end-to-end
    // tamper detection: changing any earlier content invalidates
    // every subsequent anchor's payload. The new anchor itself
    // isn't in `tree_out` yet, so there's no self-reference.
    let blob = etree::tree_to_blob(tree_out, paops)?;
    let policy = crate::crypto::CryptoPolicyDefault {};
    let payload_hex = crate::crypto::hexdigest("sha3-256", &blob, &policy)?;
    let mut payload_arr = [0u8; 32];
    payload_arr.copy_from_slice(&hex::decode(payload_hex)?);
    let payload_hash = PayloadHash(payload_arr);

    // parents: latest existing CHAIN anchor only (linear chain).
    let parents = latest_existing_anchors(tree_out, paops)?;

    // mutations: e.g., "encrypt+Agent_007,GEHEIM". URL-encoded space.
    let words_joined = paops.anchor.words.join(",");
    let mutations = if words_joined.is_empty() {
        paops.anchor.operation.clone()
    } else {
        format!("{}+{}", paops.anchor.operation, words_joined)
    };

    let signer = SignerId::new(SigAlgKind::Ed25519, fp);
    let anchor = Anchor::builder(signer, payload_hash)
        .with_parents(parents)
        .with_mutations(mutations)
        .build();
    let signed = anchor.sign(&priv_pem, &pub_pem, SigAlgKind::Ed25519)?;
    let extfields: BTreeMap<String, String> = signed.to_extfields();
    Ok(etree::TextNode::Chain { extfields })
}

/// Return at most one parent: the [`AnchorHash`] of the LAST
/// [`TextNode::Chain`] in document order, or `None` if the tree has
/// no anchors. Linear-chain semantic — new anchors build on the tip.
fn latest_existing_anchors(
    tree: &etree::TextTree,
    _paops: &ParseOps,
) -> Result<Vec<crate::ledger::AnchorHash>> {
    let mut all = Vec::new();
    walk_for_chains(tree, &mut all)?;
    Ok(all.pop().into_iter().collect())
}
