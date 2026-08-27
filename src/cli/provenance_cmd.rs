//! `enprot manifest` / `attest` / `scm` subcommands — provenance workflow.
//!
//! These three commands form a cohesive provenance/SCM group:
//! `manifest` walks a directory tree and emits an EPT manifest,
//! `attest` appends a signed chain anchor to a manifest, and `scm`
//! dispatches to manifest-management operations (init/add/deps/attest/
//! verify/diff). They share the same deps (`crate::provenance`,
//! `crate::scm`) and `run_scm` delegates to `run_attest` and the
//! verify-chain path.

use std::fs::{self, File};
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::etree::{self, ParseOps};
use crate::{crypto, provenance, scm};

use super::verify_chain;
use super::{CommonArgs, ScmCommand, VerifyChainSubcmd};
use clap::Args;

/// `manifest` entry point: walk a directory tree and emit an EPT
/// manifest referencing each file via STORED directives. Defaults
/// `casdir` to `cas/` if present, else the current directory.
pub fn run_manifest(a: ManifestSubcmd) -> Result<()> {
    let casdir = a
        .casdir
        .clone()
        .or_else(|| {
            if Path::new("cas").is_dir() {
                Some(PathBuf::from("cas"))
            } else {
                Some(PathBuf::from("."))
            }
        })
        .unwrap();
    if !casdir.is_dir() {
        std::fs::create_dir_all(&casdir)?;
    }

    eprintln!("manifest: walking {}...", a.dir.display());
    let tree = provenance::build_manifest(&a.dir, &casdir)?;
    eprintln!(
        "manifest: {} entries",
        tree.iter()
            .filter(|n| matches!(n, etree::TextNode::Include { .. }))
            .count()
    );
    let policy = crypto::default_policy();
    let mut paops = ParseOps::new(policy)?;
    paops.runtime.fname = a
        .output
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<stdout>".into());

    match a.output.as_ref() {
        Some(path) => {
            let f = File::create(path)?;
            etree::tree_write(&mut BufWriter::new(f), &tree, &mut paops)?;
            eprintln!("manifest: wrote {}", path.display());
        }
        None => {
            let stdout = std::io::stdout();
            etree::tree_write(&mut stdout.lock(), &tree, &mut paops)?;
        }
    }
    Ok(())
}

/// `attest` entry point: append a signed chain anchor to a manifest.
pub fn run_attest(a: AttestSubcmd) -> Result<()> {
    let priv_pem = fs::read_to_string(&a.signer)?;
    let body = fs::read_to_string(&a.file)?;
    let policy = Box::new(crypto::CryptoPolicyDefault {}) as Box<dyn crypto::CryptoPolicy>;
    let mut paops = ParseOps::new(policy)?;
    paops.runtime.fname = a.file.display().to_string();
    let cursor = std::io::Cursor::new(body.into_bytes());
    let tree = etree::parse(cursor, &mut paops)?;

    // Default casdir to `.` so attest doesn't fail when the manifest
    // has no CAS-referenced content (the chain anchor just needs to
    // hash the file state).
    if paops.io.casdir.as_os_str().is_empty() {
        paops.io.set_local_casdir(PathBuf::from("."));
    }

    let attested = provenance::attest(&tree, &priv_pem, &paops.io.casdir, Vec::new())?;
    let f = File::create(&a.file)?;
    etree::tree_write(&mut BufWriter::new(f), &attested, &mut paops)?;
    eprintln!("attest: signed {}", a.file.display());
    Ok(())
}

/// `scm` entry point: dispatch to the appropriate sub-operation.
/// Re-uses provenance::attest for signing so the wire format is
/// identical to TODO.roadmap/51.
pub fn run_scm(a: ScmSubcmd) -> Result<()> {
    let casdir = a.casdir.clone().unwrap_or_else(|| {
        if Path::new("cas").is_dir() {
            PathBuf::from("cas")
        } else {
            PathBuf::from(".")
        }
    });
    if !casdir.is_dir() {
        std::fs::create_dir_all(&casdir)?;
    }
    match a.command {
        ScmCommand::Init { manifest } => {
            scm::init_manifest(&manifest)?;
            println!("scm init: wrote {}", manifest.display());
            Ok(())
        }
        ScmCommand::Add { manifest, path } => {
            let n = scm::add_to_manifest(&manifest, &path, &casdir)?;
            println!("scm add: appended {} entries to {}", n, manifest.display());
            Ok(())
        }
        ScmCommand::Deps {
            manifest,
            cargo_toml,
        } => {
            let n = scm::add_cargo_deps(&manifest, &cargo_toml, &casdir)?;
            println!("scm deps: appended {} entries to {}", n, manifest.display());
            Ok(())
        }
        ScmCommand::Attest { signer, manifest } => {
            run_attest(AttestSubcmd {
                signer,
                file: manifest.clone(),
            })?;
            println!("scm attest: signed {}", manifest.display());
            Ok(())
        }
        ScmCommand::Verify {
            trust_root,
            manifest,
        } => {
            // Delegate to the existing verify-chain implementation so
            // customers get identical semantics to `enprot verify-
            // chain --trust-root X FILE`. CommonArgs is constructed
            // with the filter-context defaults via the helper.
            verify_chain::run(
                CommonArgs::for_filter(Some(casdir.clone())),
                VerifyChainSubcmd {
                    trust_roots: vec![trust_root],
                    files: vec![manifest.to_string_lossy().into_owned()],
                },
            )
        }
        ScmCommand::Diff { old, new } => {
            let d = scm::diff_manifests(&old, &new)?;
            print!("{d}");
            Ok(())
        }
    }
}

/// `manifest` subcommand (TODO.roadmap/51): build a provenance
/// manifest for a project tree. Walks the directory, stores each
/// file in CAS, emits an EPT file with one INCLUDE per source file.
#[derive(Args)]
pub struct ManifestSubcmd {
    /// Project root to walk.
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,

    /// CAS directory (default: `./cas` if it exists, else `.`).
    #[arg(short = 'c', long, value_name = "DIR")]
    pub casdir: Option<PathBuf>,

    /// Output manifest path (default: stdout).
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// `attest` subcommand (TODO.roadmap/51): append a signed chain
/// anchor to a manifest, signing the file's current state.
#[derive(Args)]
pub struct AttestSubcmd {
    /// Builder's private key (PEM).
    #[arg(long, value_name = "PRIV.pem")]
    pub signer: PathBuf,

    /// Manifest file. Modified in-place.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// `scm` subcommand (TODO.roadmap/52). The subcommand selects the
/// operation; common args (CAS dir, signer, etc.) are flat fields.
/// Re-uses `provenance::attest` and the existing `verify-chain` so
/// the wire format is identical to TODO.roadmap/51.
#[derive(Args)]
pub struct ScmSubcmd {
    #[command(subcommand)]
    pub command: ScmCommand,

    /// CAS directory. Default: `./cas` if it exists, else `.`.
    #[arg(short = 'c', long, global = true)]
    pub casdir: Option<PathBuf>,
}
