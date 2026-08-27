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

//! CommonArgs resolution — the single seam between the parsed CLI
//! and the pipeline's [`ParseOps`] (architecture review round 2,
//! candidate 1 phase A).
//!
//! Everything here answers one question: <em>given what the user
//! passed (flags + TOML config + environment), what policy,
//! separators, passwords, and anchor config does the transform
//! run under?</em> Previously these helpers lived in `cli/mod.rs`
//! beside the Command enum; now they have their own module and
//! their own test surface.

use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto;
use crate::error::{Error, Result};
use crate::etree::{self, ParseOps};

use super::{CommonArgs, Operation, config, consts, validate};

pub(super) fn make_policy(name: &str) -> Box<dyn crypto::CryptoPolicy> {
    // Invariant: callers route `name` through clap's `VALID_POLICIES`
    // value_parser, so only "default" or "nist" reach here. Returning
    // an `Err` would be incorrect — this function is infallible by
    // contract; an unknown name indicates a programming error in the
    // caller, not user input.
    match name {
        "default" => Box::new(crypto::CryptoPolicyDefault {}),
        "nist" => Box::new(crypto::CryptoPolicyNIST {}),
        other => panic!(
            "make_policy: unknown policy '{}' (callers must validate via VALID_POLICIES)",
            other
        ),
    }
}

/// Load layered TOML config and fill in `Option<T>` fields on `common`
/// where the user did not pass an explicit CLI flag. Built-in defaults
/// Load the layered TOML config and merge it into `common`, then
/// invoke the closure with the resolved `CommonArgs`. Used by the
/// `app_main` dispatch for subcommands that need config (the bypass
/// subcommands call their handlers directly, without this wrapper).
pub(super) fn with_config<F>(common: CommonArgs, f: F) -> Result<()>
where
    F: FnOnce(CommonArgs) -> Result<()>,
{
    let common = apply_config(common)?;
    validate_common(&common)?;
    f(common)
}

/// Semantic validation of the fully-resolved common args. Runs after
/// config merge so TOML-supplied values (e.g. `auto_anchor = true`)
/// are considered. Delegates to [`validate::collect`] + [`validate::report`]
/// so every semantic rule lives in one MECE location and adding a new
/// rule is a single variant + branch (OCP), not a new ad-hoc branch here.
fn validate_common(common: &CommonArgs) -> Result<()> {
    let issues = validate::collect(common);
    validate::report(&issues)
}

/// (clap `default_value_t`) are treated as "not explicitly set" — they
/// defer to config when present.
pub(super) fn apply_config(mut common: CommonArgs) -> Result<CommonArgs> {
    let cfg = config::Config::load(&PathBuf::from("."))?;
    if common.casdir.is_none() {
        common.casdir = cfg.casdir.clone();
    }
    if common.policy.is_none() {
        common.policy = cfg.policy.clone();
    }
    if common.defaults.is_none() {
        common.defaults = cfg.defaults.clone();
    }
    if common.lang.is_none() {
        common.lang = cfg.lang.clone();
    }
    // Locale resolution (TODO.complete/71): $ENPROT_LOCALE wins over
    // the config field; English otherwise. Resolved once, lazily, on
    // first message render.
    let _ = crate::i18n::resolve_locale(cfg.locale.as_deref());
    if common.signer.is_none() {
        common.signer = cfg.chain.signer.as_ref().map(PathBuf::from);
    }
    if cfg.chain.auto_anchor == Some(true) {
        common.anchor = true;
    }
    if cfg.fips == Some(true) {
        common.fips = true;
    }
    Ok(common)
}

pub(super) fn build_anchor_config(
    anchor_flag: bool,
    signer_path: Option<&Path>,
    op_kind: Option<Operation>,
    words: &[String],
) -> Result<etree::AnchorConfig> {
    if !anchor_flag {
        return Ok(etree::AnchorConfig::disabled());
    }
    let signer_path = signer_path.ok_or_else(|| Error::InvalidArg {
        arg: "anchor",
        reason: "--anchor requires --signer <PRIV.pem>".to_string(),
    })?;
    let priv_pem = fs::read_to_string(signer_path)?;
    let op = op_kind
        .map(|k| k.label())
        .unwrap_or("passthrough")
        .to_string();
    Ok(etree::AnchorConfig {
        enabled: true,
        operation: op,
        words: words.to_vec(),
        signer_priv_pem: Some(priv_pem),
    })
}

pub(super) fn walk_for_chains(
    tree: &etree::TextTree,
    out: &mut Vec<crate::ledger::AnchorHash>,
) -> Result<()> {
    etree::visitor::visit(tree, &mut |node| {
        if let etree::TextNode::Chain { extfields } = node
            && let Ok(signed) = crate::ledger::SignedAnchor::from_extfields(extfields)
            && let Ok(h) = signed.id()
        {
            out.push(h);
        }
        etree::visitor::Control::Continue
    });
    Ok(())
}

/// Resolve the policy NAME from CommonArgs, applying the FIPS
/// override (FIPS forces NIST). Shared by `resolve_policy` (which
/// wraps it to produce a `Box<dyn CryptoPolicy>`) and by
/// `pipeline::run`'s parallel path (which needs the name to feed
/// `RunConfig::build_paops(&str)` per worker thread).
///
/// Single source of truth for the FIPS+policy conflict check (DRY):
/// the upfront `validate_common` gate catches the user-set `--fips`
/// case for CLI callers; this function remains the defense-in-depth
/// for the `/proc/sys/crypto/fips_enabled` runtime auto-engage path
/// and for library callers that bypass `validate_common`.
pub(super) fn resolve_policy_name(common: &CommonArgs) -> Result<String> {
    let explicit_policy = common.policy.clone();
    let mut policy_name = explicit_policy
        .clone()
        .unwrap_or_else(|| consts::DEFAULT_POLICY.to_string());
    let fips = common.fips
        || (cfg!(unix)
            && match fs::read_to_string("/proc/sys/crypto/fips_enabled") {
                Ok(s) => s.starts_with('1'),
                Err(_) => false,
            });
    if fips {
        if let Some(p) = explicit_policy.as_deref()
            && p != "nist"
        {
            return Err(Error::InvalidArg {
                arg: "--policy",
                reason: format!("--fips forces --policy=nist but --policy={p} was set"),
            });
        }
        policy_name = "nist".to_string();
    }
    Ok(policy_name)
}

/// Resolve the crypto policy from CommonArgs (shared by `run` and `verify_files`).
pub(super) fn resolve_policy(common: &CommonArgs) -> Result<Box<dyn crypto::CryptoPolicy>> {
    Ok(make_policy(&resolve_policy_name(common)?))
}

/// Resolve the final left/right separator strings from CLI args.
///
/// `--lang` provides a preset; explicit `-l`/`-r` flags override
/// the preset's value. The override is detected by comparing against
/// `consts::DEFAULT_*` — if the user didn't change the default, the
/// preset is used; if they did, the explicit value wins.
///
/// Single source of truth: `run()` and `apply_common()` both call
/// this. Before this helper existed, the logic was duplicated in
/// both, risking drift (TODO.finalize/32).
pub(super) fn resolve_separators(common: &CommonArgs) -> (String, String) {
    if let Some(ref lang) = common.lang
        && let Some((left, right)) = consts::lang_separators(lang)
    {
        let l = if common.left_separator == consts::DEFAULT_LEFT_SEP {
            left.to_string()
        } else {
            common.left_separator.clone()
        };
        let r = if common.right_separator == consts::DEFAULT_RIGHT_SEP {
            right.to_string()
        } else {
            common.right_separator.clone()
        };
        return (l, r);
    }
    (
        common.left_separator.clone(),
        common.right_separator.clone(),
    )
}

/// Apply common args to ParseOps (shared by `run` and `verify_files`).
pub(super) fn apply_common(common: &CommonArgs, paops: &mut ParseOps) {
    if let Some(dir) = common.casdir.clone() {
        paops.io.set_local_casdir(dir);
    } else if Path::new("cas").is_dir() {
        paops.io.set_local_casdir(Path::new("cas").to_path_buf());
    } else {
        paops.io.set_local_casdir(Path::new(".").to_path_buf());
    }
    paops.io.verbose = common.verbose && !common.quiet;
    paops.io.inline_data = common.inline || common.casdir.is_none();
    paops.io.dry_run = common.dry_run;
    paops.max_depth = common.max_depth;
    let (left, right) = resolve_separators(common);
    paops.separators.left = left;
    paops.separators.right = right;
    paops.passwords.extend(common.password.clone());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> CommonArgs {
        CommonArgs::for_filter(None)
    }

    #[test]
    fn policy_resolution_prefers_explicit_over_fips_default() {
        // Explicit --policy wins the name; --fips only forces nist
        // when no explicit policy was given.
        let mut c = args();
        c.fips = true;
        c.policy = Some("nist".to_string());
        assert_eq!(resolve_policy_name(&c).unwrap(), "nist");

        let mut c = args();
        c.fips = true;
        assert_eq!(resolve_policy_name(&c).unwrap(), "nist");
    }

    #[test]
    fn policy_resolution_defaults_without_flags() {
        let c = args();
        assert_eq!(resolve_policy_name(&c).unwrap(), "default");
    }

    #[test]
    fn separators_fall_back_to_defaults_without_lang() {
        let c = args();
        let (left, right) = resolve_separators(&c);
        assert_eq!((left.as_str(), right.as_str()), ("// <(", ")>"));
    }

    #[test]
    fn make_policy_knows_both_policies() {
        let _ = make_policy("default");
        let _ = make_policy("nist");
    }

    #[test]
    #[should_panic(expected = "unknown policy")]
    fn make_policy_panics_on_programming_error() {
        let _ = make_policy("klingon");
    }
}
