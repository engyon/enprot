//! `enprot init` subcommand — bootstrap a new enprot-aware directory.
//!
//! Extracted from `cli/mod.rs` as Phase 1 of TODO.complete/07. Shows
//! the per-subcommand-module decomposition pattern that the rest of
//! the file will follow: one `cli/<subcommand>.rs` per top-level
//! subcommand, exposing a single `pub fn run(args) -> Result<()>`
//! entry point. The module owns its own helpers; `mod.rs` keeps the
//! dispatch table.

use std::path::PathBuf;

use crate::cli::InitSubcmd;
use crate::config;
use crate::error::{Error, Result};

/// Entry point for `enprot init`.
///
/// Writes a default `.enprot.toml` (or the user-level config if
/// `--global`), optionally writes `.gitattributes` to route `.ept`
/// files through enprot's git filters, and creates the CAS directory
/// if absent.
pub fn run(a: InitSubcmd) -> Result<()> {
    let target = if a.global {
        config::user_config_path()
            .ok_or_else(|| Error::msg("could not resolve user config path (is $HOME set?)"))?
    } else {
        PathBuf::from(".enprot.toml")
    };
    if target.exists() && !a.force {
        return Err(Error::msg(format!(
            "{} already exists; pass --force to overwrite",
            target.display()
        )));
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&target, config::Config::template())?;
    println!("wrote {}", target.display());

    if a.git {
        init_gitattributes()?;
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

/// Write `.gitattributes` so *.ept files route through enprot's
/// filter/diff/merge machinery. Prints the `.git/config` snippet to
/// stdout — we don't write to `.git/config` directly to avoid
/// clobbering unrelated entries.
fn init_gitattributes() -> Result<()> {
    let path = PathBuf::from(".gitattributes");
    let snippet = "# Route *.ept through enprot's clean/smudge filters.\n\
                   *.ept filter=enprot diff=enprot merge=enprot\n";
    if path.exists() {
        return Err(Error::msg(format!(
            "{} already exists; merge this snippet in manually:\n{}",
            path.display(),
            snippet
        )));
    }
    std::fs::write(&path, snippet)?;
    println!("wrote {}", path.display());
    println!(
        "\nAdd the following to .git/config (or run `git config -f .git/config ...`):\n\
               [filter \"enprot\"]\n\
               \x20   clean = enprot clean -w WORD -k WORD=PASSWORD\n\
               \x20   smudge = enprot smudge -w WORD -k WORD=PASSWORD\n\
               [diff \"enprot\"]\n\
               \x20   textconv = enprot textconv -w WORD -k WORD=PASSWORD\n\
               [merge \"enprot\"]\n\
               \x20   driver = enprot merge-driver %O %A %B %P\n"
    );
    Ok(())
}
