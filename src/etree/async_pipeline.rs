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

//! Async pipeline twins (TODO.complete/54), behind the
//! `async-pipeline` feature.
//!
//! Design: **thin adapters over the untouched sync cores — no
//! forking.** `parse_async` reads the stream to a buffer and calls
//! the very same `parse::<Cursor>` (byte-identical semantics by
//! construction); `tree_write_async` serializes through the same
//! generic `tree_write::<Vec<u8>>` (`Vec<u8>` is a `Write`) and
//! writes the buffer. The CPU-bound parse/transform/serialize runs
//! on `spawn_blocking`; the async surface buys I/O multiplexing —
//! many in-flight files per thread, which is exactly the
//! networked-CAS pain the TODO describes.
//!
//! For whole-file workloads, [`run_files_async`] is the entry
//! point: one task per file on the blocking pool (each with its own
//! `ParseOps`, mirroring the rayon parallel path's isolation), all
//! files in flight concurrently on a `JoinSet`.

use std::io::Cursor;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::etree::{self, ParseOps, TextTree};

/// Parse an EPT stream. Reads everything, then runs the
/// synchronous, incremental parser over it unchanged.
pub async fn parse_async<R>(reader: R, paops: &mut ParseOps) -> Result<TextTree>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    use tokio::io::AsyncReadExt;
    let mut reader = reader;
    reader.read_to_end(&mut buf).await.map_err(Error::from)?;
    // CPU-bound over an in-memory buffer; runs inline — the async
    // surface is for I/O multiplexing, not for moving parse work.
    etree::parse(Cursor::new(&buf), paops)
}

/// Unparse a tree. Serializes through the generic sync writer
/// (`Vec<u8>` is a `Write`), then writes the buffer.
pub async fn tree_write_async<W>(writer: W, text: &TextTree, paops: &mut ParseOps) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    etree::tree_write(&mut buf, text, paops)?;
    use tokio::io::AsyncWriteExt;
    let mut writer = writer;
    writer.write_all(&buf).await.map_err(Error::from)?;
    writer.flush().await.map_err(Error::from)?;
    Ok(())
}

/// The full pipeline over async I/O: parse → transform → write.
/// The transform is CPU-bound (and CAS-blocking); it runs on the
/// blocking pool so many files can be in flight concurrently.
pub async fn process_one_file_async<R, W, F>(
    reader: R,
    writer: W,
    paops: &mut ParseOps,
    transform: F,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    F: FnOnce(TextTree, &mut ParseOps) -> Result<TextTree>,
{
    let tree_in = parse_async(reader, paops).await?;
    let tree_out = transform(tree_in, paops)?;
    tree_write_async(writer, &tree_out, paops).await
}

/// Whole-file concurrency primitive for callers driving many files
/// over networked CAS: one task per file on the blocking pool (each
/// owns its `ParseOps` — the same isolation the rayon parallel path
/// uses), all in flight on a `JoinSet`. `process` receives the file
/// path, its bytes, and a fresh `ParseOps`, and returns the output
/// bytes.
///
/// This is where async actually pays: the blocking CAS round-trips
/// inside each file's transform sit on blocking threads while the
/// JoinSet keeps every other file's I/O moving.
pub async fn run_files_async<I, F>(files: I, make_paops: F) -> Vec<(String, Result<Vec<u8>>)>
where
    I: IntoIterator<Item = String>,
    F: Fn() -> Result<ParseOps> + Send + Sync + 'static,
{
    let make = Arc::new(make_paops);
    let mut set = tokio::task::JoinSet::new();
    for path in files {
        let make = Arc::clone(&make);
        set.spawn_blocking(move || {
            let result = (|| -> Result<Vec<u8>> {
                let bytes = std::fs::read(&path)?;
                let mut paops = make()?;
                paops.runtime.fname.clone_from(&path);
                let tree = etree::parse(Cursor::new(&bytes), &mut paops)?;
                let mut out = Vec::new();
                etree::tree_write(&mut out, &tree, &mut paops)?;
                Ok(out)
            })();
            (path, result)
        });
    }
    let mut results = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(pair) => results.push(pair),
            Err(e) => results.push((
                String::new(),
                Err(Error::Io(std::io::Error::other(format!(
                    "file task failed: {e}"
                )))),
            )),
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paops() -> ParseOps {
        ParseOps::new(crate::crypto::default_policy()).unwrap()
    }

    #[tokio::test]
    async fn async_round_trip_is_byte_identical_to_sync() {
        let input = "// <( BEGIN Agent_007 )>\nhello\n// <( END Agent_007 )>\nplain text\n";
        let mut p = paops();
        let tree_sync = etree::parse(Cursor::new(input), &mut p).unwrap();
        let tree_async = parse_async(input.as_bytes(), &mut p).await.unwrap();
        assert_eq!(format!("{tree_sync:?}"), format!("{tree_async:?}"));

        let mut sync_out = Vec::new();
        etree::tree_write(&mut sync_out, &tree_sync, &mut p).unwrap();
        let mut async_out = Vec::new();
        tree_write_async(&mut async_out, &tree_sync, &mut p)
            .await
            .unwrap();
        assert_eq!(sync_out, async_out);
        assert_eq!(String::from_utf8(async_out).unwrap(), input);
    }

    #[tokio::test]
    async fn run_files_round_trips_many_files_concurrently() {
        let dir = tempfile::tempdir().unwrap();
        let mut paths = Vec::new();
        for i in 0..16 {
            let p = dir.path().join(format!("f{i}.ept"));
            std::fs::write(&p, "// <( BEGIN X )>\ndata\n// <( END X )>\n").unwrap();
            paths.push(p.display().to_string());
        }
        let results = run_files_async(paths, || -> crate::error::Result<ParseOps> {
            ParseOps::new(crate::crypto::default_policy())
        })
        .await;
        assert_eq!(results.len(), 16);
        for (path, res) in results {
            let out = res.unwrap();
            assert_eq!(
                String::from_utf8(out).unwrap(),
                "// <( BEGIN X )>\ndata\n// <( END X )>\n",
                "file {path} must round-trip byte-identically"
            );
        }
    }

    #[tokio::test]
    async fn process_one_file_passthrough_round_trip() {
        let input = b"// <( BEGIN X )>\ndata\n// <( END X )>\n".to_vec();
        let mut p = paops();
        let mut out = Vec::new();
        process_one_file_async(input.as_slice(), &mut out, &mut p, |tree, _paops| Ok(tree))
            .await
            .unwrap();
        assert_eq!(out, input);
    }
}
