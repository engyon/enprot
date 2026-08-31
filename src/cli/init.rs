//! `enprot init` subcommand — bootstrap a new enprot-aware directory.
//!
//! Extracted from `cli/mod.rs` (TODO.complete/07-cli-rs-decomposition).
//! Follows the per-subcommand-module pattern.

use std::path::PathBuf;

use crate::config;
use crate::error::{Error, Result};
use clap::Args;

/// Entry point for `enprot init`.
///
/// Writes a default `.enprot.toml` (or the user-level config if
/// `--global`), optionally writes `.gitattributes` to route `.ept`
/// files through enprot's git filters, and creates the CAS directory
/// if absent.
pub fn run(a: InitSubcmd) -> Result<()> {
    let target = if a.global {
        config::user_config_path().ok_or_else(|| Error::InvalidArg {
            arg: "--global",
            reason: "could not resolve user config path (is $HOME set?)".to_string(),
        })?
    } else {
        PathBuf::from(".enprot.toml")
    };
    if target.exists() && !a.force {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; pass --force to overwrite",
                target.display()
            ),
        )));
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&target, config::Config::template())?;
    println!("wrote {}", target.display());

    if a.git {
        init_gitattributes()?;
        configure_git_filters(&a.git_word)?;
    }
    // Create the CAS directory if it doesn't exist — most commands
    // assume it's there; creating it at init time saves the user
    // a separate mkdir.
    let cas_path = PathBuf::from("cas");
    if !cas_path.exists() {
        std::fs::create_dir(&cas_path)?;
        eprintln!("created {}", cas_path.display());
    }
    Ok(())
}

/// Append-safe `.gitattributes` entry routing `*.ept` through
/// enprot's filter/diff/merge machinery.
fn init_gitattributes() -> Result<()> {
    let path = PathBuf::from(".gitattributes");
    let line = "*.ept filter=enprot diff=enprot merge=enprot\n";
    if path.exists() {
        let existing = std::fs::read_to_string(&path)?;
        if existing.contains("filter=enprot") {
            println!("{} already routes enprot; left as is", path.display());
        } else {
            std::fs::write(&path, format!("{existing}\n{line}"))?;
            println!("appended enprot entry to {}", path.display());
        }
    } else {
        std::fs::write(
            &path,
            format!("# Route *.ept through enprot's clean/smudge filters.\n{line}"),
        )?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

/// Configure the git filter/diff/merge trio surgically via
/// `git config` (never file rewriting — unrelated entries are safe).
/// Credentials are deliberately NOT baked here: `required = false`
/// keeps checkouts working without them, and the printed hint shows
/// where to add a `-k WORD=PASSWORD` once the user chooses how to
/// store it.
fn configure_git_filters(words: &[String]) -> Result<()> {
    if !PathBuf::from(".git").exists() {
        println!("not a git repository; skipped .git/config (attributes still written)");
        return Ok(());
    }
    let word_flags: String = words
        .iter()
        .map(|w| format!(" -w {w}"))
        .collect::<Vec<_>>()
        .join("");
    let entries = [
        ("filter.enprot.clean", format!("enprot clean{word_flags}")),
        ("filter.enprot.smudge", format!("enprot smudge{word_flags}")),
        ("filter.enprot.required", "false".to_string()),
        (
            "diff.enprot.textconv",
            format!("enprot textconv{word_flags}"),
        ),
        (
            "merge.enprot.driver",
            "enprot merge-driver %O %A %B %P".to_string(),
        ),
        ("merge.enprot.name", "enprot WORD-aware merge".to_string()),
    ];
    for (key, value) in entries {
        let status = std::process::Command::new("git")
            .args(["config", key, &value])
            .status()
            .map_err(|e| Error::Io(std::io::Error::other(format!("git config {key}: {e}"))))?;
        if !status.success() {
            return Err(Error::InvalidArg {
                arg: "--git",
                reason: format!("git config {key} failed"),
            });
        }
        println!("git config {key} = {value}");
    }
    println!(
        "\nFilters degrade gracefully without credentials (required=false). \
         To decrypt on checkout, add `-k WORD=PASSWORD` to \
         filter.enprot.smudge (or a credential helper of your choosing)."
    );
    Ok(())
}

/// `init` subcommand: scaffold a commented TOML config the user can
/// edit in place. With `--git`, also writes a `.gitattributes` file
/// that wires `enprot` into git's `clean` / `smudge` / `textconv`
/// filter chain.
#[derive(Args)]
pub struct InitSubcmd {
    /// Write to `~/.config/enprot/config.toml` instead of `./.enprot.toml`.
    #[arg(long)]
    pub global: bool,

    /// Overwrite an existing file. Off by default to prevent stomping
    /// hand-edited config.
    #[arg(long)]
    pub force: bool,

    /// Turnkey git wiring: `.gitattributes` entry (append-safe) plus
    /// the filter/diff/merge trio in `.git/config`, set surgically
    /// via `git config` so unrelated entries are never touched.
    /// Credentials are not baked in — `filter.enprot.required=false`
    /// keeps checkouts working without them.
    #[arg(long)]
    pub git: bool,

    /// WORDs to bake into the filter commands (`enprot init --git
    /// --word ALPHA --word BETA`). Without any, the bare commands are
    /// configured and every WORD is handled when credentials are
    /// supplied.
    #[arg(long = "git-word", value_name = "WORD")]
    pub git_word: Vec<String>,
}
