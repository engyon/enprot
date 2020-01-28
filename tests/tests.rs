#![allow(dead_code)]

extern crate assert_cmd;
extern crate cpu_time;
extern crate predicates;
extern crate tempfile;

use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use tempfile::TempDir;

mod cli;

struct Fixture {
    path: PathBuf,
    source: PathBuf,
    _tempdir: TempDir,
}

impl Fixture {
    fn blank(fname: &str) -> Self {
        let src_dir = &env::var("CARGO_MANIFEST_DIR").unwrap();
        let source = PathBuf::from(&src_dir).join(&fname);

        let tempdir = tempfile::tempdir().unwrap();
        let path = PathBuf::from(&tempdir.path()).join(Path::new(fname).file_name().unwrap());

        Fixture {
            path,
            source,
            _tempdir: tempdir,
        }
    }

    fn copy(fname: &str) -> Self {
        let fixture = Fixture::blank(fname);
        fs::copy(&fixture.source, &fixture.path).unwrap();
        fixture
    }
}

pub fn digest(alg: &str, data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let policy: Box<dyn enprot::crypto::CryptoPolicy> =
        Box::new(enprot::crypto::CryptoPolicyDefault {});
    enprot::crypto::digest(alg, data, &policy)
}

pub fn hexdigest(alg: &str, data: &[u8]) -> Result<String, &'static str> {
    let policy: Box<dyn enprot::crypto::CryptoPolicy> =
        Box::new(enprot::crypto::CryptoPolicyDefault {});
    enprot::crypto::hexdigest(alg, data, &policy)
}
