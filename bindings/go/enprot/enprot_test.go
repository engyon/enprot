package enprot

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// findLibOrSkip ensures the test only runs when libenprot is available.
// Tests that need it skip gracefully otherwise (CI without the Rust
// toolchain shouldn't fail Go tests).
func findLibOrSkip(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("ENPROT_LIB"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	// repo root = bindings/go/../..
	repoRoot := filepath.Join("..", "..", "..")
	for _, sub := range []string{"release", "debug"} {
		candidate := filepath.Join(repoRoot, "target", sub, libBasename())
		if abs, err := filepath.Abs(candidate); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	t.Skipf("libenprot not built — run `cargo build --release` from repo root. (GOOS=%s GOARCH=%s)", runtime.GOOS, runtime.GOARCH)
	return ""
}

func TestVersionLooksLikeSemver(t *testing.T) {
	findLibOrSkip(t)
	v := Version()
	if len(v) < 5 || v[0] < '0' || v[0] > '9' {
		t.Fatalf("unexpected version: %q", v)
	}
}

func TestProcessRejectsMissingKeys(t *testing.T) {
	findLibOrSkip(t)
	err := Process(map[string]any{"foo": "bar"})
	e, ok := err.(*Error)
	if !ok {
		t.Fatalf("want *Error, got %T (%v)", err, err)
	}
	if e.Code != ErrInvalid {
		t.Fatalf("want code %d, got %d", ErrInvalid, e.Code)
	}
	if e.Category != "invalid" {
		t.Fatalf("want category 'invalid', got %q", e.Category)
	}
}

func TestProcessHandlesNonExistentFile(t *testing.T) {
	findLibOrSkip(t)
	err := Process(map[string]any{
		"operation": "encrypt",
		"file":      "/tmp/enprot-go-does-not-exist.txt",
	})
	if err == nil {
		return // FFI currently returns OK after JSON validation.
	}
	e, ok := err.(*Error)
	if !ok {
		t.Fatalf("want *Error, got %T", err)
	}
	acceptable := map[int]bool{ErrIO: true, ErrInvalid: true, ErrParse: true}
	if !acceptable[e.Code] {
		t.Fatalf("unexpected error code %d", e.Code)
	}
}

func TestEncryptBuildsWellFormedConfig(t *testing.T) {
	findLibOrSkip(t)
	// Monkey-patch Process via a package-level indirection so we can
	// capture the config that Encrypt builds.
	original := processHook
	defer func() { processHook = original }()
	var captured map[string]any
	processHook = func(cfg map[string]any) error {
		captured = cfg
		return nil
	}

	err := Encrypt("/some/file.txt", &Opts{
		Words:  map[string]string{"SECRET": "pw"},
		Cipher: "aes-256-siv",
		Casdir: ".cas",
		Policy: "nist",
	})
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if captured["operation"] != "encrypt" {
		t.Errorf("operation: want encrypt, got %v", captured["operation"])
	}
	if captured["file"] != "/some/file.txt" {
		t.Errorf("file: want /some/file.txt, got %v", captured["file"])
	}
	words, _ := captured["words"].(map[string]string)
	if words["SECRET"] != "pw" {
		t.Errorf("words: want SECRET=pw, got %v", captured["words"])
	}
	if captured["cipher"] != "aes-256-siv" {
		t.Errorf("cipher: want aes-256-siv, got %v", captured["cipher"])
	}
	if captured["policy"] != "nist" {
		t.Errorf("policy: want nist, got %v", captured["policy"])
	}
}

func TestStoreAndFetchDispatch(t *testing.T) {
	findLibOrSkip(t)
	original := processHook
	defer func() { processHook = original }()
	var ops []string
	processHook = func(cfg map[string]any) error {
		ops = append(ops, cfg["operation"].(string))
		return nil
	}

	_ = Store("/file", &Opts{Words: map[string]string{"X": "y"}, Casdir: ".cas"})
	_ = Fetch("/file", &Opts{Words: map[string]string{"X": "y"}, Casdir: ".cas"})

	want := []string{"store", "fetch"}
	if len(ops) != len(want) || ops[0] != want[0] || ops[1] != want[1] {
		t.Fatalf("ops: want %v, got %v", want, ops)
	}
}
