//! S3-backed content-addressed storage (TODO.complete/27).
//!
//! `s3://bucket/optional/prefix` maps SHA3-256-named blobs onto
//! object keys, delegating SigV4 signing, the credential chain
//! (env vars → shared config → instance profile), and retries to
//! [`object_store`] — signing code is never hand-rolled here.
//!
//! The pipeline is synchronous, so the backend owns a dedicated
//! tokio runtime behind a mutex: `CasStore` methods `block_on` the
//! async object_store calls. Concurrent callers serialize on that
//! lock — acceptable at blob granularity (CAS ops are per-segment,
//! not per byte), and it keeps the runtime single-instance and
//! panic-free (`block_on` from multiple unsynchronized threads is
//! UB-adjacent on a shared runtime).
//!
//! The `CasStore` contract — save is idempotent, load MUST verify
//! the hash — is preserved: S3 PUT of identical content under the
//! same key is naturally idempotent, and every GET is re-hashed
//! with SHA3-256 and compared before the bytes are returned.

use std::sync::Mutex;

use object_store::path::Path;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use url::Url;

use crate::crypto;
use crate::error::{Error, Result};

use super::CasStore;

#[derive(Debug)]
pub struct S3Cas {
    store: Box<dyn ObjectStore>,
    prefix: Path,
    /// The sync→async bridge. Current-thread runtime; all calls go
    /// through the mutex so only one `block_on` is in flight.
    rt: Mutex<tokio::runtime::Runtime>,
}

impl S3Cas {
    /// Build from an `s3://bucket/key-prefix` spec. Credentials and
    /// region come from the standard chain (`AWS_*` env vars, shared
    /// config, IAM role); a custom endpoint (MinIO, LocalStack,
    /// R2…) is honored via `AWS_ENDPOINT_URL`/`AWS_ENDPOINT_URL_S3`
    /// exactly as object_store documents.
    pub fn from_spec(spec: &str) -> Result<Self> {
        let url = Url::parse(spec).map_err(|e| Error::InvalidArg {
            arg: "--casdir",
            reason: format!("malformed S3 CAS spec '{spec}': {e}"),
        })?;
        if url.scheme() != "s3" {
            return Err(Error::InvalidArg {
                arg: "--casdir",
                reason: format!("S3Cas cannot serve scheme '{}'", url.scheme()),
            });
        }
        // AmazonS3Builder::from_env() is what loads the credential
        // chain (AWS_ACCESS_KEY_ID/…, AWS_ENDPOINT_URL,
        // AWS_ALLOW_HTTP); parse_url alone builds a store with no
        // credentials, whose requests then fall through to the EC2
        // IMDS endpoint — wrong everywhere except a real EC2 host.
        let store = object_store::aws::AmazonS3Builder::from_env()
            .with_url(url.clone())
            .build()
            .map_err(|e| Error::InvalidArg {
                arg: "--casdir",
                reason: format!("cannot open S3 CAS '{spec}': {e}"),
            })?;
        let store: Box<dyn ObjectStore> = Box::new(store);
        let prefix = Path::from(url.path().trim_start_matches('/'));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::InvalidArg {
                arg: "--casdir",
                reason: format!("cannot start the object-store runtime: {e}"),
            })?;
        Ok(Self {
            store,
            prefix,
            rt: Mutex::new(rt),
        })
    }

    fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        self.rt
            .lock()
            .expect("object-store runtime mutex poisoned")
            .block_on(fut)
    }

    fn key(&self, hash: &str) -> Path {
        self.prefix.clone().join(hash)
    }

    fn store_error(op: &'static str, e: object_store::Error) -> Error {
        Error::CasBackend {
            backend: "s3",
            op,
            detail: e.to_string(),
        }
    }
}

fn hash_of(blob: &[u8], policy: &dyn crypto::CryptoPolicy) -> Result<String> {
    // Through the crate's own wrapper so policy hooks and the Botan
    // provider stay in play — same path LocalCas uses.
    crypto::hexdigest("sha3-256", blob, policy)
}

impl CasStore for S3Cas {
    fn save(&self, blob: &[u8], policy: &dyn crypto::CryptoPolicy) -> Result<String> {
        let hash = hash_of(blob, policy)?;
        let key = self.key(&hash);
        let payload = PutPayload::from_bytes(blob.to_vec().into());
        let res = self.block_on(self.store.put(&key, payload));
        res.map_err(|e| Self::store_error("put", e))?;
        Ok(hash)
    }

    fn load(&self, hash: &str, policy: &dyn crypto::CryptoPolicy) -> Result<Vec<u8>> {
        super::validate_cas_hash(hash)?;
        let key = self.key(hash);
        let res = self.block_on(self.store.get(&key));
        let result = res.map_err(|e| match e {
            object_store::Error::NotFound { .. } => Error::CasNotFound { hash: hash.into() },
            other => Self::store_error("get", other),
        })?;
        let bytes = self
            .block_on(result.bytes())
            .map_err(|e| Self::store_error("get (read body)", e))?;
        let actual = hash_of(&bytes, policy)?;
        if actual != hash {
            return Err(Error::CasHashMismatch {
                expected: hash.into(),
                actual,
            });
        }
        Ok(bytes.to_vec())
    }

    fn contains(&self, hash: &str, _policy: &dyn crypto::CryptoPolicy) -> Result<bool> {
        super::validate_cas_hash(hash)?;
        let key = self.key(hash);
        match self.block_on(self.store.head(&key)) {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(Self::store_error("head", e)),
        }
    }

    fn list(&self) -> Result<Vec<String>> {
        let mut hashes = Vec::new();
        let mut stream = self.store.list(Some(&self.prefix));
        // list() returns a stream; drive it to completion here.
        use futures::StreamExt;
        loop {
            let next = self.block_on(stream.next());
            match next {
                Some(Ok(meta)) => {
                    let name = meta.location.filename().unwrap_or_default().to_string();
                    if name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                        hashes.push(name);
                    }
                }
                Some(Err(e)) => return Err(Self::store_error("list", e)),
                None => break,
            }
        }
        hashes.sort();
        Ok(hashes)
    }

    fn delete(&self, hash: &str) -> Result<()> {
        super::validate_cas_hash(hash)?;
        let key = self.key(hash);
        self.block_on(self.store.delete(&key))
            .map_err(|e| Self::store_error("delete", e))
    }
}
