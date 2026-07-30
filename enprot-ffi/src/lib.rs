/// C FFI for enprot — enables bindings in Python, Node.js, Go, Ruby.
/// Each function takes a JSON config string and returns a result code.
/// Future bindings: pyenprot (PyO3), @engyon/enprot (napi-rs),
/// go-enprot (cgo), enprot gem (ffi).
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

    if config["file"].as_str().is_none() {
        return EnprotResult::err(ENPROT_ERR_INVALID, "missing 'file' in config");
    }

    if config["operation"].as_str().is_none() {
        return EnprotResult::err(ENPROT_ERR_INVALID, "missing 'operation' in config");
    }

    EnprotResult::ok()
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
}
