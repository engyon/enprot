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

//! Semantic validation of resolved CLI configuration (TODO.complete/33).
//!
//! Clap handles *syntactic* validation (required args present, types
//! parse, value-parser rules honored). This module handles *semantic*
//! validation: relationships between flags that no individual flag's
//! parser can express (`--fips` + `--policy default`, `--signer`
//! without `--anchor`, etc.).
//!
//! Runs once after [`super::apply_config`] so TOML-supplied values
//! (`auto_anchor`, `fips = true`, …) participate in the check.
//!
//! Design (MECE + OCP):
//! - Each rule is one [`ConfigIssue`] variant. Adding a rule = adding
//!   a variant + a `collect` branch. No existing variant changes.
//! - [`collect`] gathers *all* issues, errors and warnings together,
//!   so the user sees every problem in one report rather than
//!   fixing them one at a time across reruns.
//! - [`report`] prints warnings to stderr and folds errors into a
//!   single [`crate::Error::InvalidArg`] whose `reason` lists every
//!   error. Warnings never block; errors always do.

use crate::cli::{CommonArgs, EncryptOpts, OutputArgs};
use crate::crypto::CryptoPolicy;
use crate::error::{Error, Result};

/// One semantic issue with a resolved configuration. Variants are
/// typed so callers (CLI, FFI, structured-logging hooks) can
/// pattern-match instead of regex-scraping prose.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigIssue {
    /// `--fips` was set but `--policy` was explicitly set to a
    /// non-NIST policy. FIPS implies NIST; the two flags contradict.
    FipsPolicyConflict { explicit: String },

    /// `--signer` was provided but neither `--anchor` nor
    /// `--audit-log` is set. The signer key would be loaded and then
    /// discarded. Warning only — some workflows pre-set `--signer`
    /// for later use; `--audit-log` legitimately consumes the signer
    /// for audit-record signatures.
    SignerWithoutAnchor,

    /// `--jobs` was set to zero. There is no useful interpretation.
    JobsZero,

    /// `--jobs` exceeds the number of detected CPUs. Scheduling
    /// overhead may dominate the parallelism benefit. Warning.
    JobsExceedsCpus { requested: usize, available: usize },

    /// `--output-dir` was set but at least one input is `-` (stdin).
    /// Stdin always writes to stdout; the directory is silently
    /// ignored for that input. Warning — the operation itself is
    /// well-defined, the flag just doesn't apply.
    OutputDirWithStdin,

    /// `--pbkdf-msec` was set below the active policy's floor
    /// ([`CryptoPolicy::min_pbkdf_millis`]). A derivation budget
    /// that weak defeats the policy's compliance posture.
    PbkdfMsecBelowFloor { requested: u32, floor: u32 },

    /// `--recovery-key` was combined with a deterministic cipher
    /// (`-det`). Escrow mode encrypts under a fresh random CEK, so
    /// the same-input → same-output (CAS dedup) contract cannot
    /// hold. Error.
    RecoveryWithDet { alg: String },
}

impl ConfigIssue {
    /// True when this issue should block execution.
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            ConfigIssue::FipsPolicyConflict { .. }
                | ConfigIssue::JobsZero
                | ConfigIssue::PbkdfMsecBelowFloor { .. }
                | ConfigIssue::RecoveryWithDet { .. }
        )
    }

    /// Human-readable description, localized (TODO.complete/71):
    /// English default, `$ENPROT_LOCALE` / config `locale` selects
    /// ja / zh-CN / de / fr.
    pub fn describe(&self) -> String {
        crate::i18n::tr(&self.msg_key())
    }

    fn msg_key(&self) -> crate::i18n::MsgKey {
        use crate::i18n::MsgKey;
        match self {
            ConfigIssue::FipsPolicyConflict { explicit } => MsgKey::FipsPolicyConflict {
                explicit: explicit.clone(),
            },
            ConfigIssue::SignerWithoutAnchor => MsgKey::SignerWithoutAnchor,
            ConfigIssue::JobsZero => MsgKey::JobsZero,
            ConfigIssue::JobsExceedsCpus {
                requested,
                available,
            } => MsgKey::JobsExceedsCpus {
                requested: *requested,
                available: *available,
            },
            ConfigIssue::OutputDirWithStdin => MsgKey::OutputDirWithStdin,
            ConfigIssue::PbkdfMsecBelowFloor { requested, floor } => MsgKey::PbkdfMsecBelowFloor {
                requested: *requested,
                floor: *floor,
            },
            ConfigIssue::RecoveryWithDet { alg } => MsgKey::RecoveryWithDet { alg: alg.clone() },
        }
    }

    /// Flag/parameter name, for [`Error::InvalidArg`]`{ arg, .. }`.
    fn arg(&self) -> &'static str {
        match self {
            ConfigIssue::FipsPolicyConflict { .. } => "--policy",
            ConfigIssue::SignerWithoutAnchor => "--signer",
            ConfigIssue::JobsZero | ConfigIssue::JobsExceedsCpus { .. } => "--jobs",
            ConfigIssue::OutputDirWithStdin => "--output-dir",
            ConfigIssue::PbkdfMsecBelowFloor { .. } => "--pbkdf-msec",
            ConfigIssue::RecoveryWithDet { .. } => "--recovery-key",
        }
    }
}

/// Collect every semantic issue with the resolved configuration.
/// Returns both errors and warnings; the caller decides what to do
/// with each via [`report`].
pub fn collect(common: &CommonArgs) -> Vec<ConfigIssue> {
    let mut issues = Vec::new();

    if common.fips
        && let Some(p) = common.policy.as_deref()
        && p != "nist"
    {
        issues.push(ConfigIssue::FipsPolicyConflict {
            explicit: p.to_string(),
        });
    }

    if common.signer.is_some() && !common.anchor && common.audit_log.is_none() {
        issues.push(ConfigIssue::SignerWithoutAnchor);
    }

    if common.jobs == 0 {
        issues.push(ConfigIssue::JobsZero);
    } else if let Some(available) = available_cpus()
        && common.jobs > available
    {
        issues.push(ConfigIssue::JobsExceedsCpus {
            requested: common.jobs,
            available,
        });
    }

    issues
}

/// Collect output-wiring issues: relationships between
/// [`OutputArgs`] fields that no single flag's parser can express.
/// Per-subcommand counterpart of [`collect`], called from
/// `pipeline::run` where the `OutputArgs` live.
pub fn collect_output(output: &OutputArgs) -> Vec<ConfigIssue> {
    let mut issues = Vec::new();

    if output.output_dir.is_some() && output.files.iter().any(|f| f == "-") {
        issues.push(ConfigIssue::OutputDirWithStdin);
    }

    issues
}

/// Collect encrypt-knob issues against the resolved policy. Only the
/// two encrypt-bearing subcommands pass real `EncryptOpts`; the
/// others pass `EncryptOpts::default()` (all `None`), which
/// collects nothing.
///
/// Manual-params mode (`--pbkdf-params`) is exempt from the msec
/// floor: it overrides the timed budget entirely and its iteration
/// count is gated by [`CryptoPolicy::check_pbkdf`] at derive time.
pub fn collect_encrypt(enc: &EncryptOpts, policy: &dyn CryptoPolicy) -> Vec<ConfigIssue> {
    let mut issues = Vec::new();

    let floor = policy.min_pbkdf_millis();
    if floor > 0
        && enc.pbkdf_params.is_none()
        && let Some(requested) = enc.pbkdf_msec
        && requested < floor
    {
        issues.push(ConfigIssue::PbkdfMsecBelowFloor { requested, floor });
    }

    if !enc.recovery_key.is_empty() {
        // The explicit --cipher flag, or the policy's default.
        let alg = enc
            .cipher
            .clone()
            .unwrap_or_else(|| policy.default_cipher_alg());
        if alg.ends_with("-det") {
            issues.push(ConfigIssue::RecoveryWithDet { alg });
        }
    }

    issues
}

/// Surface a list of collected issues: warnings go to stderr,
/// errors fold into one [`Error::InvalidArg`] whose `reason` lists
/// every error, one per line. Returns `Ok(())` when only warnings
/// (or no issues at all) were collected.
pub fn report(issues: &[ConfigIssue]) -> Result<()> {
    for issue in issues {
        if !issue.is_error() {
            eprintln!("{}", issue.describe());
        }
    }

    let errors: Vec<&ConfigIssue> = issues.iter().filter(|i| i.is_error()).collect();
    if errors.is_empty() {
        return Ok(());
    }

    // Use the first error's flag as the InvalidArg tag; the reason
    // body enumerates every error so the user sees them all at once.
    let arg = errors[0].arg();
    let reason = errors
        .iter()
        .map(|e| e.describe())
        .collect::<Vec<_>>()
        .join("\n  ");
    Err(Error::InvalidArg { arg, reason })
}

/// Detect the number of available CPUs. Wrapped so the [`collect`]
/// call site reads cleanly; falls back to `None` on the rare
/// platforms that refuse to answer (treated as "don't warn").
fn available_cpus() -> Option<usize> {
    std::thread::available_parallelism().ok().map(|n| n.get())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn base_args() -> CommonArgs {
        CommonArgs::for_filter(None)
    }

    #[test]
    fn clean_config_collects_no_issues() {
        let c = base_args();
        assert!(collect(&c).is_empty());
    }

    #[test]
    fn fips_with_explicit_default_policy_errors() {
        let mut c = base_args();
        c.fips = true;
        c.policy = Some("default".to_string());
        let issues = collect(&c);
        assert_eq!(
            issues,
            vec![ConfigIssue::FipsPolicyConflict {
                explicit: "default".to_string()
            }]
        );
        assert!(issues[0].is_error());
    }

    #[test]
    fn fips_with_explicit_nist_policy_ok() {
        let mut c = base_args();
        c.fips = true;
        c.policy = Some("nist".to_string());
        assert!(collect(&c).is_empty());
    }

    #[test]
    fn fips_with_no_explicit_policy_ok() {
        let mut c = base_args();
        c.fips = true;
        assert!(
            collect(&c).is_empty(),
            "fips alone is fine; policy defaults to nist later"
        );
    }

    #[test]
    fn signer_without_anchor_warns() {
        let mut c = base_args();
        c.signer = Some(Path::new("k.pem").to_path_buf());
        let issues = collect(&c);
        assert_eq!(issues, vec![ConfigIssue::SignerWithoutAnchor]);
        assert!(!issues[0].is_error());
        // Warning-only report should succeed.
        assert!(report(&issues).is_ok());
    }

    #[test]
    fn signer_with_anchor_ok() {
        let mut c = base_args();
        c.signer = Some(Path::new("k.pem").to_path_buf());
        c.anchor = true;
        assert!(collect(&c).is_empty());
    }

    #[test]
    fn jobs_zero_errors() {
        let mut c = base_args();
        c.jobs = 0;
        let issues = collect(&c);
        assert_eq!(issues, vec![ConfigIssue::JobsZero]);
        assert!(issues[0].is_error());
        let err = report(&issues).unwrap_err();
        match err {
            Error::InvalidArg { arg, reason } => {
                assert_eq!(arg, "--jobs");
                assert!(reason.contains("at least 1"), "got: {reason}");
            }
            _ => panic!("expected InvalidArg, got {err:?}"),
        }
    }

    #[test]
    fn multiple_errors_listed_in_one_message() {
        let mut c = base_args();
        c.fips = true;
        c.policy = Some("default".to_string());
        c.jobs = 0;
        let issues = collect(&c);
        assert_eq!(issues.len(), 2, "both errors collected, not just the first");
        let err = report(&issues).unwrap_err();
        match err {
            Error::InvalidArg { reason, .. } => {
                assert!(reason.contains("--policy"), "missing policy in: {reason}");
                assert!(reason.contains("--jobs"), "missing jobs in: {reason}");
            }
            _ => panic!("expected InvalidArg, got {err:?}"),
        }
    }

    #[test]
    fn jobs_above_available_warns() {
        let mut c = base_args();
        // No portable way to force num_cpus low, but a very large
        // value is effectively guaranteed to exceed
        // available_parallelism on any realistic CI runner.
        c.jobs = 65535;
        let issues = collect(&c);
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, ConfigIssue::JobsExceedsCpus { .. })),
            "expected JobsExceedsCpus warning, got {issues:?}"
        );
        // Warning-only path: report should succeed.
        assert!(report(&issues).is_ok());
    }

    #[test]
    fn describe_prefixes_match_severity() {
        assert!(ConfigIssue::JobsZero.describe().starts_with("error:"));
        assert!(
            ConfigIssue::SignerWithoutAnchor
                .describe()
                .starts_with("warning:")
        );
        assert!(
            ConfigIssue::JobsExceedsCpus {
                requested: 99,
                available: 1
            }
            .describe()
            .starts_with("warning:")
        );
        assert!(
            ConfigIssue::OutputDirWithStdin
                .describe()
                .starts_with("warning:")
        );
        assert!(
            ConfigIssue::PbkdfMsecBelowFloor {
                requested: 10,
                floor: 100
            }
            .describe()
            .starts_with("error:")
        );
    }

    fn base_output(files: &[&str]) -> OutputArgs {
        OutputArgs {
            word: Vec::new(),
            output: Vec::new(),
            prefix: String::new(),
            output_dir: None,
            files: files.iter().map(|f| f.to_string()).collect(),
        }
    }

    #[test]
    fn output_dir_with_stdin_warns() {
        let mut o = base_output(&["-"]);
        o.output_dir = Some(Path::new("out").to_path_buf());
        assert_eq!(collect_output(&o), vec![ConfigIssue::OutputDirWithStdin]);
    }

    #[test]
    fn output_dir_with_mixed_stdin_warns() {
        // A single stdin input among real files still can't use the dir.
        let mut o = base_output(&["a.ept", "-", "b.ept"]);
        o.output_dir = Some(Path::new("out").to_path_buf());
        assert_eq!(collect_output(&o), vec![ConfigIssue::OutputDirWithStdin]);
    }

    #[test]
    fn output_dir_with_files_only_is_clean() {
        let mut o = base_output(&["a.ept", "b.ept"]);
        o.output_dir = Some(Path::new("out").to_path_buf());
        assert!(collect_output(&o).is_empty());
    }

    #[test]
    fn stdin_without_output_dir_is_clean() {
        assert!(collect_output(&base_output(&["-"])).is_empty());
    }

    #[test]
    fn nist_rejects_msec_below_floor() {
        let enc = EncryptOpts {
            pbkdf_msec: Some(10),
            ..EncryptOpts::default()
        };
        let nist = crate::policy::nist::CryptoPolicyNIST {};
        let issues = collect_encrypt(&enc, &nist);
        assert_eq!(
            issues,
            vec![ConfigIssue::PbkdfMsecBelowFloor {
                requested: 10,
                floor: nist.min_pbkdf_millis()
            }]
        );
        assert!(issues[0].is_error());
    }

    #[test]
    fn nist_accepts_msec_at_floor() {
        let nist = crate::policy::nist::CryptoPolicyNIST {};
        let enc = EncryptOpts {
            pbkdf_msec: Some(nist.min_pbkdf_millis()),
            ..EncryptOpts::default()
        };
        assert!(collect_encrypt(&enc, &nist).is_empty());
    }

    #[test]
    fn default_policy_has_no_floor() {
        // Tests deliberately use tiny msec budgets for speed under
        // the default policy; it must not grow an opinion.
        let default = crate::policy::default::CryptoPolicyDefault {};
        assert_eq!(default.min_pbkdf_millis(), 0);
        let enc = EncryptOpts {
            pbkdf_msec: Some(1),
            ..EncryptOpts::default()
        };
        assert!(collect_encrypt(&enc, &default).is_empty());
    }

    #[test]
    fn manual_params_exempt_from_msec_floor() {
        // --pbkdf-params overrides the timed budget; its iteration
        // count is gated by check_pbkdf at derive time instead.
        let nist = crate::policy::nist::CryptoPolicyNIST {};
        let enc = EncryptOpts {
            pbkdf_msec: Some(1),
            pbkdf_params: Some("i=1000,r=8,p=1".to_string()),
            ..EncryptOpts::default()
        };
        assert!(collect_encrypt(&enc, &nist).is_empty());
    }

    #[test]
    fn recovery_key_with_det_cipher_errors() {
        let enc = EncryptOpts {
            cipher: Some("aes-256-gcm-det".to_string()),
            recovery_key: vec![Path::new("r.pem").to_path_buf()],
            ..EncryptOpts::default()
        };
        let default = crate::policy::default::CryptoPolicyDefault {};
        let issues = collect_encrypt(&enc, &default);
        assert!(matches!(issues[0], ConfigIssue::RecoveryWithDet { .. }));
        assert!(issues[0].is_error());
    }

    #[test]
    fn recovery_key_with_explicit_non_det_cipher_ok() {
        let enc = EncryptOpts {
            cipher: Some("aes-256-siv".to_string()),
            recovery_key: vec![Path::new("r.pem").to_path_buf()],
            ..EncryptOpts::default()
        };
        let default = crate::policy::default::CryptoPolicyDefault {};
        assert!(collect_encrypt(&enc, &default).is_empty());
    }

    #[test]
    fn recovery_key_with_default_policy_cipher_errors() {
        // The default policy's cipher is aes-256-gcm-siv-det; escrow
        // must refuse out of the box, not deep inside the transform.
        let enc = EncryptOpts {
            recovery_key: vec![Path::new("r.pem").to_path_buf()],
            ..EncryptOpts::default()
        };
        let default = crate::policy::default::CryptoPolicyDefault {};
        let issues = collect_encrypt(&enc, &default);
        assert!(matches!(issues[0], ConfigIssue::RecoveryWithDet { .. }));
    }

    #[test]
    fn recovery_key_under_nist_default_cipher_ok() {
        // The NIST default (aes-256-gcm) is not det; escrow works
        // out of the box under --fips.
        let enc = EncryptOpts {
            recovery_key: vec![Path::new("r.pem").to_path_buf()],
            ..EncryptOpts::default()
        };
        let nist = crate::policy::nist::CryptoPolicyNIST {};
        assert!(collect_encrypt(&enc, &nist).is_empty());
    }

    #[test]
    fn unset_msec_never_flags() {
        let nist = crate::policy::nist::CryptoPolicyNIST {};
        assert!(
            collect_encrypt(&EncryptOpts::default(), &nist).is_empty(),
            "no explicit --pbkdf-msec means the policy default applies"
        );
    }
}
