// Package enprot provides Go bindings for the enprot C FFI.
//
// The package loads libenprot.{so,dylib,dll} at build time via cgo and
// the C FFI declared in include/enprot.h. Build the shared library
// first from the repo root:
//
//	cargo build --release
//
// Then this package links against it.
//
// Library discovery order at runtime:
//  1. ENPROT_LIB environment variable
//  2. <repo-root>/target/release/{libenprot.so,libenprot.dylib,enprot.dll}
//  3. <repo-root>/target/debug/...
//  4. system library search path (LD_LIBRARY_PATH, dyld, etc.)
//
// Quick start:
//
//	enprot.Encrypt("config.toml", &enprot.Opts{
//	    Words:  map[string]string{"SECRET": "correct horse battery staple"},
//	    Cipher: "aes-256-siv",
//	    Casdir: ".cas",
//	})
package enprot

/*
#cgo CFLAGS: -I${SRCDIR}/../../../include
#cgo darwin LDFLAGS: -L${SRCDIR}/../../../target/release -L${SRCDIR}/../../../target/debug -lenprot -Wl,-rpath,${SRCDIR}/../../../target/release -Wl,-rpath,${SRCDIR}/../../../target/debug
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/../../../target/release -L${SRCDIR}/../../../target/debug -lenprot -Wl,-rpath,${SRCDIR}/../../../target/release -Wl,-rpath,${SRCDIR}/../../../target/debug
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/../../../target/release -L${SRCDIR}/../../../target/debug -lenprot -Wl,-rpath,${SRCDIR}/../../../target/release -Wl,-rpath,${SRCDIR}/../../../target/debug
#cgo windows LDFLAGS: -L${SRCDIR}/../../../target/release -L${SRCDIR}/../../../target/debug -lenprot
#include <enprot.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"
)

// Result codes — must match include/enprot.h.
const (
	OK         = int(C.ENPROT_OK)
	ErrParse   = int(C.ENPROT_ERR_PARSE)
	ErrCrypto  = int(C.ENPROT_ERR_CRYPTO)
	ErrIO      = int(C.ENPROT_ERR_IO)
	ErrInvalid = int(C.ENPROT_ERR_INVALID)
)

// ErrorCategory maps an FFI error code to a short label.
func ErrorCategory(code int) string {
	switch code {
	case ErrParse:
		return "parse"
	case ErrCrypto:
		return "crypto"
	case ErrIO:
		return "io"
	case ErrInvalid:
		return "invalid"
	default:
		return "unknown"
	}
}

// Error is returned by Process / Encrypt / Decrypt / Store / Fetch
// when the FFI returns a non-OK status.
type Error struct {
	Code     int
	Category string
	Message  string
}

func (e *Error) Error() string {
	return fmt.Sprintf("[enprot %s] %s", e.Category, e.Message)
}

// Opts carries the optional per-call configuration shared by Encrypt,
// Decrypt, Store, and Fetch. A nil Opts is valid and means "use enprot
// defaults".
type Opts struct {
	Words  map[string]string
	Cipher string
	Casdir string
	Policy string
}

// Version returns the enprot crate version string (e.g. "0.5.11").
func Version() string {
	cstr := C.enprot_version()
	if cstr == nil {
		return ""
	}
	return C.GoString((*C.char)(unsafe.Pointer(cstr)))
}

// Process invokes enprot_process with a raw JSON config map.
func Process(config map[string]any) error {
	payload, err := json.Marshal(config)
	if err != nil {
		return &Error{Code: ErrInvalid, Category: "invalid", Message: err.Error()}
	}
	cstr := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cstr))

	result := C.enprot_process(cstr)
	if int(result.code) == OK {
		return nil
	}

	msg := "(no message)"
	if result.error != nil {
		// Copy the message before freeing the Rust-allocated buffer.
		msg = C.GoString((*C.char)(unsafe.Pointer(result.error)))
		C.enprot_free_error((*C.char)(unsafe.Pointer(result.error)))
	}
	return &Error{
		Code:     int(result.code),
		Category: ErrorCategory(int(result.code)),
		Message:  msg,
	}
}

// processHook is the call-through target used by run(). Tests can
// swap it to capture the config without actually invoking the FFI.
var processHook = Process

func run(op, file string, opts *Opts) error {
	if file == "" {
		return errors.New("enprot: empty file path")
	}
	cfg := map[string]any{
		"operation": op,
		"file":      file,
	}
	if opts != nil {
		if len(opts.Words) > 0 {
			cfg["words"] = opts.Words
		}
		if opts.Cipher != "" {
			cfg["cipher"] = opts.Cipher
		}
		if opts.Casdir != "" {
			cfg["casdir"] = opts.Casdir
		}
		if opts.Policy != "" {
			cfg["policy"] = opts.Policy
		}
	}
	return processHook(cfg)
}

// Encrypt encrypts every ENCRYPTED-tagged segment in the given file in place.
func Encrypt(file string, opts *Opts) error { return run("encrypt", file, opts) }

// Decrypt decrypts every ENCRYPTED-tagged segment in the given file in place.
func Decrypt(file string, opts *Opts) error { return run("decrypt", file, opts) }

// Store replaces STORED-tagged segments in the given file with CAS pointers.
func Store(file string, opts *Opts) error { return run("store", file, opts) }

// Fetch restores STORED-tagged segments in the given file from CAS pointers.
func Fetch(file string, opts *Opts) error { return run("fetch", file, opts) }

// LocateLib finds the shared library at runtime. Returns the absolute
// path if found, or an error describing where it looked.
//
// Used by tests to confirm the build produced libenprot before they
// run; production callers can ignore this and let the cgo linker do
// its thing.
func LocateLib() (string, error) {
	if env := os.Getenv("ENPROT_LIB"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env, nil
		}
	}

	libName := "libenprot.so"
	switch runtime.GOOS {
	case "darwin":
		libName = "libenprot.dylib"
	case "windows":
		libName = "enprot.dll"
	}

	// repoRoot is ../../.. from this package's directory
	// (bindings/go/enprot/ → repo root).
	repoRoot := filepath.Join("..", "..", "..")
	for _, sub := range []string{"release", "debug"} {
		candidate := filepath.Join(repoRoot, "target", sub, libName)
		if abs, err := filepath.Abs(candidate); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs, nil
			}
		}
	}

	return "", fmt.Errorf("libenprot not found; set ENPROT_LIB or build with cargo build --release (looked in %s/target/{{release,debug}}/%s and ENPROT_LIB)", repoRoot, libName)
}

// libBasename is a tiny helper exported for tests so they can render
// platform-specific messages.
func libBasename() string {
	switch runtime.GOOS {
	case "darwin":
		return "libenprot.dylib"
	case "windows":
		return "enprot.dll"
	default:
		return "libenprot.so"
	}
}

// ensure unused-import linters don't strip strings if a future refactor
// drops a use; it is used in tests via run.
var _ = strings.TrimSpace
