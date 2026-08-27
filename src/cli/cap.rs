//! `enprot cap` subcommand — capability policy queries.
//!
//! Implements TODO.complete/25-capability-cli-surface.
//!
//! Two actions:
//!
//! - `enprot cap list` — reads a policy file and lists all declared
//!   WORDs + their required capabilities + trust roots.
//! - `enprot cap check --word SECRET --op encrypt` — builds a
//!   capability set from the current flags (passwords, CAS dir)
//!   and checks whether the policy allows the requested operation.
//!
//! Both support `--format json` for machine consumption.
//!
//! Future work tracked in the TODO: `cap why` (decision provenance),
//! `cap diff` (compare two capability sets), `cap revoke`.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

use crate::capability::{Capability, CapabilitySet};
use crate::cappolicy::CapPolicy;
use crate::cli::CommonArgs;
use crate::error::Result;
use crate::output;

/// `enprot cap` subcommand wrapper.
#[derive(Args, Debug, Clone)]
pub struct CapArgs {
    #[command(subcommand)]
    pub command: CapSubcmd,
}

/// `enprot cap` subcommand actions.
#[derive(Subcommand, Debug, Clone)]
pub enum CapSubcmd {
    /// List all WORDs declared in the policy file.
    List(CapListArgs),

    /// Check whether the current caller can perform an operation on a WORD.
    ///
    /// Builds a capability set from the current flags (passwords, CAS
    /// dir) and evaluates it against the policy's declared requirements
    /// for the WORD. Exit code 0 = allowed, 1 = denied.
    Check(CapCheckArgs),
}

#[derive(Args, Debug, Clone)]
pub struct CapListArgs {
    /// Policy file path. Defaults to `.enprot/policy.toml` if it
    /// exists, else no policy is loaded (empty list).
    #[arg(long, value_name = "PATH")]
    pub policy_file: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct CapCheckArgs {
    /// WORD to check.
    #[arg(long)]
    pub word: String,

    /// Operation to evaluate.
    #[arg(long, value_enum)]
    pub op: CapOp,

    /// Policy file path. Defaults to `.enprot/policy.toml`.
    #[arg(long, value_name = "PATH")]
    pub policy_file: Option<PathBuf>,
}

/// Operations the capability model gates.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum CapOp {
    /// Encrypt requires Decryptor capability for the WORD.
    Encrypt,
    /// Decrypt requires Decryptor capability for the WORD.
    Decrypt,
    /// Store requires Reader capability.
    Store,
    /// Fetch requires Reader capability.
    Fetch,
    /// Verify requires Verifier capability.
    Verify,
}

/// Entry point for `enprot cap`.
pub fn run(args: CapArgs, common: &CommonArgs) -> Result<()> {
    match args.command {
        CapSubcmd::List(a) => run_list(a, common),
        CapSubcmd::Check(a) => run_check(a, common),
    }
}

/// Resolve the policy file path: explicit `--policy-file` from args,
/// falling back to `common.policy_file`, then `.enprot/policy.toml`.
fn resolve_policy_path(args_path: Option<PathBuf>, common: &CommonArgs) -> Option<PathBuf> {
    args_path
        .or_else(|| common.policy_file.clone())
        .or_else(|| {
            let default = PathBuf::from(".enprot/policy.toml");
            if default.exists() {
                Some(default)
            } else {
                None
            }
        })
}

fn load_policy(path: Option<PathBuf>) -> Result<Option<CapPolicy>> {
    match path {
        Some(p) => Ok(Some(CapPolicy::load_file(&p)?)),
        None => Ok(None),
    }
}

fn run_list(args: CapListArgs, common: &CommonArgs) -> Result<()> {
    let path = resolve_policy_path(args.policy_file, common);
    let policy = load_policy(path.as_ref().cloned())?;

    match common.format {
        output::OutputFormat::Text => match &policy {
            None => {
                println!("No policy file found. Run `enprot init` to create one.");
            }
            Some(p) => {
                if p.words.is_empty() {
                    println!("Policy has no WORD declarations.");
                } else {
                    println!("WORDs declared in {}:", path.unwrap().display());
                    for w in &p.words {
                        println!("  {:<20} required: {}", w.name, w.required_capability);
                        if !w.accepted_recipients.is_empty() {
                            println!("    recipients: {}", w.accepted_recipients.join(", "));
                        }
                    }
                }
                if !p.chain.trust_roots.is_empty() {
                    println!("\nTrust roots:");
                    for r in &p.chain.trust_roots {
                        println!("  {r}");
                    }
                }
                if p.chain.require_monotonic_timestamps {
                    println!("\nTimestamp monotonicity: required");
                }
            }
        },
        output::OutputFormat::Json => {
            let words: Vec<serde_json::Value> = policy
                .as_ref()
                .map(|p| {
                    p.words
                        .iter()
                        .map(|w| {
                            serde_json::json!({
                                "word": w.name,
                                "required_capability": w.required_capability,
                                "accepted_recipients": w.accepted_recipients,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            let payload = serde_json::json!({
                "words": words,
                "trust_roots": policy.as_ref().map(|p| &p.chain.trust_roots).cloned().unwrap_or_default(),
                "require_monotonic_timestamps": policy.as_ref().map(|p| p.chain.require_monotonic_timestamps).unwrap_or(false),
            });
            println!("{}", output::to_json(&payload)?);
        }
    }
    Ok(())
}

fn run_check(args: CapCheckArgs, common: &CommonArgs) -> Result<()> {
    let path = resolve_policy_path(args.policy_file, common);
    let policy = load_policy(path)?;

    // Build the caller's capability set from the current flags.
    let policy_engine = crate::crypto::default_policy();
    let mut paops = crate::etree::ParseOps::new(policy_engine)?;
    super::common::apply_common(common, &mut paops);
    let caps = CapabilitySet::from_paops(&paops);

    // Determine the required capability for the requested operation.
    let required = required_capability(&args.op, &args.word);
    let held = caps.contains(&required);

    // If a policy file is loaded, also check its explicit declarations.
    let policy_ok = if let Some(ref p) = policy {
        p.check_word_capability(&args.word, &caps).is_ok()
    } else {
        true // No policy file = no additional gate.
    };

    let allowed = held && policy_ok;

    match common.format {
        output::OutputFormat::Text => {
            let verdict = if allowed { "ALLOW" } else { "DENY" };
            println!("{verdict} op={:?} word={}", args.op, args.word);
            println!("  required: {required}");
            println!("  held:     {held}");
            if let Some(ref p) = policy {
                println!("  policy:   {}", if policy_ok { "pass" } else { "fail" });
                let _ = p; // suppress unused warning in some builds
            }
        }
        output::OutputFormat::Json => {
            // Reuse the envelope with a small payload.
            let payload = serde_json::json!({
                "op": format!("{:?}", args.op).to_lowercase(),
                "word": args.word,
                "allowed": allowed,
                "required": format!("{required}"),
                "held": held,
                "policy_ok": policy_ok,
            });
            println!("{}", output::to_json(&payload)?);
        }
    }

    if !allowed {
        std::process::exit(1);
    }
    Ok(())
}

/// Map an operation + WORD to the capability it requires.
fn required_capability(op: &CapOp, word: &str) -> Capability {
    match op {
        CapOp::Encrypt | CapOp::Decrypt => {
            Capability::Decryptor(crate::capability::WordId::new(word))
        }
        CapOp::Store | CapOp::Fetch => Capability::Reader,
        CapOp::Verify => Capability::Viewer,
    }
}
