# 61 — Concurrent CAS access (file locking)

**Priority**: P1
**Status**: specified

## Problem

Two `enprot store` processes running simultaneously against the same
`--casdir` can corrupt each other's writes. The CAS save path is:

```rust
fn save(&self, blob: &[u8], policy: &dyn CryptoPolicy) -> Result<String> {
    let hexhash = crypto::hexdigest("sha3-256", blob, policy)?;
    let path = self.path_for(&hexhash);
    if path.is_file() { return Ok(hexhash); }  // check
    File::create(&path)?;                        // create
    file.write_all(blob)?;                       // write
    Ok(hexhash)
}
```

The check-then-create pattern is a TOCTOU race. Process A checks
(hash doesn't exist), Process B checks (same), A creates, B creates
(truncating A's write mid-flight). The resulting file may have
garbage content from interleaved writes.

This is unlikely in single-user workflows but common in CI
pipelines and parallel multi-file processing (`--jobs > 1`).

## Goals

- CAS writes are atomic: a reader never sees a partially-written
  blob.
- CAS writes are idempotent under concurrency: two concurrent saves
  of the same blob produce one file, not two.
- The locking mechanism is portable (Linux, macOS, Windows).
- No deadlocks under any interleaving.

## Design

### Atomic write via temp file + rename

The standard pattern for atomic file writes:

1. Write to a temp file in the same directory: `<hash>.tmp.<pid>`.
2. `fsync()` the temp file.
3. `rename(temp, <hash>)` — atomic on POSIX, atomic on Windows
   NTFS (since Windows Server 2016 / Windows 10).

On POSIX, `rename` atomically replaces the destination. On Windows,
`MoveFileEx` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`
achieves the same.

```rust
fn save(&self, blob: &[u8], policy: &dyn CryptoPolicy) -> Result<String> {
    let hexhash = crypto::hexdigest("sha3-256", blob, policy)?;
    let path = self.path_for(&hexhash);

    if path.is_file() {
        return Ok(hexhash);  // already exists; idempotent
    }

    // Write to temp file in the SAME directory (rename must be
    // atomic, which requires same filesystem).
    let temp_path = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut f = File::create(&temp_path)?;
        f.write_all(blob)?;
        f.sync_all()?;  // fsync to survive crash
    }

    // Atomically replace (POSIX) or fail if exists (Windows).
    // On POSIX: rename(temp, path) — replaces if path exists.
    // On Windows: MoveFileEx(temp, path, REPLACE_EXISTING).
    std::fs::rename(&temp_path, &path)
        .or_else(|_| {
            // rename failed — path might have been created by another
            // process in the meantime. Check if it exists with the
            // correct content; if so, clean up temp and succeed.
            if path.is_file() {
                std::fs::remove_file(&temp_path)?;
                Ok(())
            } else {
                Err(Error::Io(std::io::Error::last_os_error()))
            }
        })?;

    Ok(hexhash)
}
```

### Advisory file locking (optional)

For CAS backends where temp-file-rename isn't enough (e.g., network
filesystems where rename isn't atomic), use `flock` (POSIX) or
`LockFileEx` (Windows) as an advisory lock around the entire save
operation.

```rust
use fs2::FileExt;

fn save(&self, blob: &[u8], policy: &dyn CryptoPolicy) -> Result<String> {
    let hexhash = crypto::hexdigest("sha3-256", blob, policy)?;
    let path = self.path_for(&hexhash);
    let lock_path = path.with_extension("lock");

    let lock = File::create(&lock_path)?;
    lock.lock_exclusive()?;

    // ... write atomically as above ...

    lock.unlock()?;
    Ok(hexhash)
}
```

This serializes concurrent saves but is correct on all platforms.

### Cleanup of stale temp files

If a process crashes between creating the temp file and the rename,
the temp file stays. A startup cleanup pass removes files matching
`*.tmp.*` that are older than 1 hour (stale threshold).

## Implementation plan

1. Replace `File::create` → write-to-temp → rename in `LocalCas::save`.
2. Add `fs2` as a dep for file locking (or use `fcntl`/`flock` directly).
3. Add stale-temp cleanup on `LocalCas::new`.
4. Test with two threads racing on the same blob (property test).
5. Test with two processes racing (integration test).

## Test plan

- [ ] Two threads saving the same blob produce exactly one file.
- [ ] Two threads saving different blobs don't corrupt each other.
- [ ] A crash mid-write leaves a temp file, not a partial blob.
- [ ] Stale temp files are cleaned up on next startup.
- [ ] Works on Linux, macOS, and Windows.

## Out of scope

- Network filesystem locking (NFS/SMB) — use a network CAS backend
  (#27) instead.
- Mandatory locking (Linux `mand` mount option) — advisory is enough.
- Lock-free CAS via content-addressed directories (sharding by hash
  prefix to reduce contention).
