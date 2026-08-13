//! C FFI for enprot — shared library (`libenprot.{so,dylib,dll}`) for
//! Python, Node.js, Go, Ruby bindings.
//!
//! The wire format is JSON. See [`include/enprot.h`](https://github.com/engyon/enprot/blob/main/include/enprot.h)
//! for the C-side contract.
//!
//! # Wire format
//!
//! ```json
//! {
//!   "operation": "encrypt",
//!   "file": "/path/to/file.txt",
//!   "words": {"SECRET": "password"},
//!   "cipher": "aes-256-siv",
//!   "casdir": ".cas"
//! }
//! ```
//!
//! The FFI bridges JSON config → argv → [`enprot::app_main`]. Every
//! CLI subcommand and option is therefore available to bindings for
//! free, with no second implementation to maintain. See
//! [`TODO.complete/01-ffi-pipeline-execution`] for the design rationale
//! and [`TODO.complete/16-ff-enprot-pipeline-ffi`] for the future
//! typed-config refactor that will bypass clap.

use std::ffi::{CStr, CString};
use std::os::raw::c_int;
use std::ptr;

pub const ENPROT_OK: c_int = 0;
pub const ENPROT_ERR_PARSE: c_int = 1;
pub const ENPROT_ERR_CRYPTO: c_int = 2;
pub const ENPROT_ERR_IO: c_int = 3;
pub const ENPROT_ERR_INVALID: c_int = 4;

#[repr(C)]
pub struct EnprotResult {
    pub code: c_int,
    pub error: *const std::os::raw::c_char,
}

impl EnprotResult {
    fn ok() -> Self {
        EnprotResult {
            code: ENPROT_OK,
            error: ptr::null(),
        }
    }

    fn err(code: c_int, msg: &str) -> Self {
        EnprotResult {
            code,
            error: CString::new(msg).unwrap_or_default().into_raw(),
        }
    }
}

/// JSON config keys that map to enprot CLI flags.
///
/// Each entry is `(json_key, cli_flag, takes_value)`. Order matters:
/// words / recipients must come before the positional file argument
/// so that clap doesn't try to interpret flags as input files.
const SCALAR_FLAGS: &[(&str, &str)] = &[
    ("cipher", "--cipher"),
    ("policy", "--policy"),
    ("casdir", "-c"),
    ("separators", "--separators"),
    ("max_depth", "--max-depth"),
    ("pbkdf", "--pbkdf"),
    ("pbkdf_params", "--pbkdf-params"),
    ("anchor_signer", "--signer"),
    ("anchor_chain", "--anchor"),
];

/// Translate a JSON config object into an `argv` vector that
/// [`enprot::app_main`] can consume.
///
/// The first element is always `enprot` (the program name clap
/// strips off). The operation follows. Scalar flags are appended in
/// `SCALAR_FLAGS` order. Multi-value fields (`words`, `recipients`)
/// are appended as repeatable flags. The file is the last positional.
fn json_to_argv(config: &serde_json::Value) -> Result<Vec<String>, String> {
    let op = config["operation"].as_str().ok_or("missing 'operation'")?;
    let file = config["file"].as_str().ok_or("missing 'file'")?;

    let mut argv: Vec<String> = vec!["enprot".into(), op.into()];

    // WORD + password pairs. enprot's CLI uses two flags:
    //   -w/--word       — names the WORD to operate on (no password)
    //   -k/--key        — binds WORD=PASSWORD (the actual secret)
    // For each {WORD: PASSWORD} pair in the JSON config, emit both.
    // An empty PASSWORD string means "prompt interactively" (just -w).
    if let Some(words) = config["words"].as_object() {
        for (k, v) in words {
            let pw = v
                .as_str()
                .ok_or_else(|| format!("words.{k}: expected string"))?;
            argv.push("-w".into());
            argv.push(k.clone());
            if !pw.is_empty() {
                argv.push("-k".into());
                argv.push(format!("{k}={pw}"));
            }
        }
    }

    // Recipient public keys (multi-recipient ML-KEM / Ed25519).
    if let Some(recipients) = config["recipients"].as_array() {
        for r in recipients {
            let path = r.as_str().ok_or("recipients[]: expected string")?;
            argv.push("--recipient".into());
            argv.push(path.into());
        }
    }

    // Recipient private keys (decrypt path).
    if let Some(recipient_privs) = config["recipient_privs"].as_array() {
        for r in recipient_privs {
            let path = r.as_str().ok_or("recipient_privs[]: expected string")?;
            argv.push("--recipient-priv".into());
            argv.push(path.into());
        }
    }

    // Scalar flag bindings. Null values are treated as absent — the
    // Python / Node / Go / Ruby helpers all pass `null` for unspecified
    // options via JSON serialization.
    for (json_key, cli_flag) in SCALAR_FLAGS {
        if let Some(value) = config.get(*json_key) {
            if value.is_null() {
                continue;
            }
            let s = if let Some(s) = value.as_str() {
                s.to_string()
            } else if let Some(n) = value.as_i64() {
                n.to_string()
            } else {
                return Err(format!("{json_key}: expected string or integer"));
            };
            argv.push((*cli_flag).into());
            argv.push(s);
        }
    }

    // Boolean flags. Each entry is (json_key, cli_flag).
    const BOOL_FLAGS: &[(&str, &str)] = &[
        ("fips", "--fips"),
        ("quiet", "--quiet"),
        ("inline", "--inline"),
        ("verbose", "-v"),
        ("no_pbkdf_cache", "--no-pbkdf-cache"),
    ];
    for (json_key, cli_flag) in BOOL_FLAGS {
        if config
            .get(*json_key)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            argv.push((*cli_flag).into());
        }
    }

    // Output file (if specified, comes after the operation flags but
    // before the input file).
    if let Some(out) = config["output"].as_str() {
        argv.push("-o".into());
        argv.push(out.into());
    }

    // Positional: input file (always last).
    argv.push(file.into());

    Ok(argv)
}

/// Map an [`enprot::Error`] to an FFI status code.
///
/// Dispatches on the typed enum variants of `enprot::Error`. Every
/// variant maps to exactly one FFI code — exhaustive `match`, no
/// string matching, no defaults. New variants added upstream trigger
/// a compile error here so the FFI stays in sync with the library's
/// error model.
///
/// Mapping table (see also `include/enprot.h`):
///
/// | `enprot::Error` variant        | FFI code               |
/// |--------------------------------|------------------------|
/// | `Io`, `CasHash*`, `CasNotFound`, `CasUnsupported` | `ENPROT_ERR_IO` |
/// | `Botan`, `CipherUnknown`, `AeadFailed`, `Policy`, `PolicyViolation`, `SignatureVerify` | `ENPROT_ERR_CRYPTO` |
/// | `Parse`, `Phc`, `Hex`, `Base64`, `Extfield`, `BlockShape` | `ENPROT_ERR_PARSE` |
/// | `Json`, `InvalidArg`, `ConflictResolve` | `ENPROT_ERR_INVALID` |
fn classify_error(err: &enprot::Error) -> c_int {
    use enprot::Error;
    match err {
        Error::Io(_)
        | Error::CasHashInvalid { .. }
        | Error::CasHashMismatch { .. }
        | Error::CasNotFound { .. }
        | Error::CasUnsupported { .. } => ENPROT_ERR_IO,
        Error::Botan(_)
        | Error::CipherUnknown { .. }
        | Error::AeadFailed { .. }
        | Error::Policy(_)
        | Error::PolicyViolation { .. }
        | Error::SignatureVerify { .. } => ENPROT_ERR_CRYPTO,
        Error::Parse { .. }
        | Error::Phc(_)
        | Error::Hex(_)
        | Error::Base64(_)
        | Error::Extfield { .. }
        | Error::BlockShape { .. }
        | Error::VerifyFailed { .. } => ENPROT_ERR_PARSE,
        Error::Json(_) | Error::InvalidArg { .. } | Error::ConflictResolve { .. } => {
            ENPROT_ERR_INVALID
        }
    }
}

/// Process a file with the given JSON config.
///
/// # Safety
/// `config_json` must be a valid null-terminated C string or NULL.
/// The returned `error` field must be freed with `enprot_free_error`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn enprot_process(config_json: *const std::os::raw::c_char) -> EnprotResult {
    if config_json.is_null() {
        return EnprotResult::err(ENPROT_ERR_INVALID, "config_json is null");
    }

    let config_str = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return EnprotResult::err(ENPROT_ERR_INVALID, "invalid UTF-8 in config_json"),
    };

    let config: serde_json::Value = match serde_json::from_str(config_str) {
        Ok(v) => v,
        Err(e) => return EnprotResult::err(ENPROT_ERR_PARSE, &format!("invalid JSON: {e}")),
    };

    let argv = match json_to_argv(&config) {
        Ok(a) => a,
        Err(msg) => return EnprotResult::err(ENPROT_ERR_INVALID, &msg),
    };

    #[cfg(feature = "cli")]
    {
        match enprot::app_main(argv) {
            Ok(()) => EnprotResult::ok(),
            Err(e) => EnprotResult::err(classify_error(&e), &e.to_string()),
        }
    }

    #[cfg(not(feature = "cli"))]
    {
        let _ = argv;
        EnprotResult::err(
            ENPROT_ERR_INVALID,
            "enprot-ffi was built without 'cli' feature; rebuild with --features cli",
        )
    }
}

/// Get the enprot version string. The returned pointer is static.
#[unsafe(no_mangle)]
pub extern "C" fn enprot_version() -> *const std::os::raw::c_char {
    static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION.as_ptr() as *const std::os::raw::c_char
}

/// Free an error string returned by `enprot_process`.
///
/// # Safety
/// `p` must be a pointer previously returned by `enprot_process`'s
/// `EnprotResult.error` field, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn enprot_free_error(p: *mut std::os::raw::c_char) {
    if !p.is_null() {
        unsafe { drop(CString::from_raw(p)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn version_returns_nonempty() {
        let v = unsafe { CStr::from_ptr(enprot_version()) }
            .to_str()
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn null_config_returns_error() {
        let r = unsafe { enprot_process(ptr::null()) };
        assert_eq!(r.code, ENPROT_ERR_INVALID);
    }

    #[test]
    fn valid_json_missing_fields_returns_error() {
        let json = CString::new(r#"{"foo": "bar"}"#).unwrap();
        let r = unsafe { enprot_process(json.as_ptr()) };
        assert_eq!(r.code, ENPROT_ERR_INVALID);
    }

    #[test]
    fn json_to_argv_minimal() {
        let cfg: serde_json::Value = serde_json::json!({
            "operation": "encrypt",
            "file": "/tmp/x.txt"
        });
        let argv = json_to_argv(&cfg).unwrap();
        assert_eq!(argv, vec!["enprot", "encrypt", "/tmp/x.txt"]);
    }

    #[test]
    fn json_to_argv_with_words_and_flags() {
        let cfg: serde_json::Value = serde_json::json!({
            "operation": "encrypt",
            "file": "/tmp/x.txt",
            "words": {"SECRET": "pw", "API": ""},
            "cipher": "aes-256-siv",
            "casdir": ".cas",
            "fips": true
        });
        let argv = json_to_argv(&cfg).unwrap();
        assert_eq!(argv[1], "encrypt");
        // For each WORD, -w NAME appears; -k NAME=PW only if password non-empty.
        assert!(argv.contains(&"-w".to_string()));
        assert!(argv.iter().any(|s| s == "SECRET"));
        assert!(argv.iter().any(|s| s == "API"));
        // Only SECRET has a password; -k SECRET=pw appears, but not -k API=.
        let k_idx = argv
            .iter()
            .position(|x| x == "-k")
            .expect("-k present for SECRET");
        assert_eq!(argv[k_idx + 1], "SECRET=pw");
        // No second -k for API (empty password).
        let k_count = argv.iter().filter(|x| **x == "-k").count();
        assert_eq!(k_count, 1);
        // Scalar flags
        assert!(argv.contains(&"--cipher".to_string()));
        assert!(argv.contains(&"-c".to_string()));
        // Bool flag
        assert!(argv.contains(&"--fips".to_string()));
        // File is last
        assert_eq!(argv.last().unwrap(), "/tmp/x.txt");
    }

    #[test]
    fn json_to_argv_rejects_non_string_word() {
        let cfg: serde_json::Value = serde_json::json!({
            "operation": "encrypt",
            "file": "/tmp/x",
            "words": {"SECRET": 42}
        });
        let err = json_to_argv(&cfg).unwrap_err();
        assert!(err.contains("expected string"));
    }

    #[test]
    fn classify_error_io() {
        use enprot::Error;
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let e = Error::Io(io_err);
        assert_eq!(classify_error(&e), ENPROT_ERR_IO);
    }

    #[test]
    fn classify_error_cas() {
        use enprot::Error;
        let e = Error::CasNotFound { hash: "abc".into() };
        assert_eq!(classify_error(&e), ENPROT_ERR_IO);
    }

    #[test]
    fn classify_error_verify_failed() {
        use enprot::Error;
        let e = Error::VerifyFailed { issues: 3 };
        assert_eq!(classify_error(&e), ENPROT_ERR_PARSE);
    }

    #[test]
    fn classify_error_crypto_variants() {
        use enprot::Error;
        assert_eq!(
            classify_error(&Error::Botan("rng fail".into())),
            ENPROT_ERR_CRYPTO
        );
        assert_eq!(
            classify_error(&Error::CipherUnknown { alg: "foo".into() }),
            ENPROT_ERR_CRYPTO
        );
        assert_eq!(
            classify_error(&Error::AeadFailed {
                alg: "aes-256-gcm-siv",
                op: "decrypt"
            }),
            ENPROT_ERR_CRYPTO
        );
        assert_eq!(
            classify_error(&Error::Policy("reject".into())),
            ENPROT_ERR_CRYPTO
        );
        assert_eq!(
            classify_error(&Error::PolicyViolation {
                rule: "r1".into(),
                context: "ctx".into()
            }),
            ENPROT_ERR_CRYPTO
        );
    }

    #[test]
    fn classify_error_parse_variants() {
        use enprot::Error;
        assert_eq!(
            classify_error(&Error::Parse {
                file: "x.ept".into(),
                lineno: 3,
                msg: "bad".into()
            }),
            ENPROT_ERR_PARSE
        );
        assert_eq!(
            classify_error(&Error::Phc("bad phc".into())),
            ENPROT_ERR_PARSE
        );
        assert_eq!(
            classify_error(&Error::Hex("bad hex".into())),
            ENPROT_ERR_PARSE
        );
        assert_eq!(
            classify_error(&Error::Base64("bad b64".into())),
            ENPROT_ERR_PARSE
        );
    }

    #[test]
    fn classify_error_invalid_variants() {
        use enprot::Error;
        assert_eq!(
            classify_error(&Error::Json("bad json".into())),
            ENPROT_ERR_INVALID
        );
    }
}
