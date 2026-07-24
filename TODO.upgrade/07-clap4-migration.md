# 07 — clap 2 → 4 derive migration

## Goal

Migrate the CLI from clap 2.33's `App` builder API to clap 4's `Parser`
derive. Cleaner code, eliminates the giant `Arg::with_name(...)` chain, makes
the schema declarative.

## Files

- `Cargo.toml` — `clap = { version = "4.5", features = ["derive", "wrap_help"] }`
- `src/lib.rs` — full rewrite of the `app_main` argument-construction section
- `src/consts.rs` — promote the `possible_values` slices to typed enums where
  useful

## Approach

Define a `Cli` struct with `#[derive(Parser)]`:

```rust
use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(name = "enprot", version, about = "Engyon Protected Text")]
#[command(derive_display_order = true)]
pub struct Cli {
    #[arg(short = 'v', long)]           pub verbose: bool,
    #[arg(short = 'q', long)]           pub quiet: bool,
    #[arg(long, default_value_t = consts::DEFAULT_MAX_DEPTH)]
    pub max_depth: usize,

    #[arg(short = 'l', long, default_value = consts::DEFAULT_LEFT_SEP)]
    pub left_separator: String,
    #[arg(short = 'r', long, default_value = consts::DEFAULT_RIGHT_SEP)]
    pub right_separator: String,

    #[arg(short = 's', long, value_name = "WORD",
          value_delimiter = ',')]
    pub store: Vec<String>,
    #[arg(short = 'f', long, value_name = "WORD",
          value_delimiter = ',')]
    pub fetch: Vec<String>,
    #[arg(short = 'e', long, value_name = "WORD",
          value_delimiter = ',')]
    pub encrypt: Vec<String>,
    #[arg(short = 'E', long = "encrypt-store", value_name = "WORD",
          value_delimiter = ',')]
    pub encrypt_store: Vec<String>,
    #[arg(short = 'd', long, value_name = "WORD",
          value_delimiter = ',')]
    pub decrypt: Vec<String>,

    #[arg(short = 'k', long = "key", value_name = "WORD=PASSWORD",
          value_delimiter = ',')]
    pub password: Vec<String>,

    #[arg(long, value_enum, default_value_t = Policy::Default)]
    pub policy: Policy,
    #[arg(long, value_enum)]
    pub defaults: Option<Policy>,
    #[arg(long)]                       pub fips: bool,

    #[arg(long, value_enum)]
    pub pbkdf: Option<PbkdfAlg>,
    #[arg(long, value_name = "MSEC")]
    pub pbkdf_msec: Option<u32>,
    #[arg(long, value_name = "BYTES")]
    pub pbkdf_salt_len: Option<usize>,
    #[arg(long, value_name = "PARAMS", hide = true)]
    pub pbkdf_params: Option<String>,
    #[arg(long, value_name = "HEX", hide = true)]
    pub pbkdf_salt: Option<String>,
    #[arg(long = "pbkdf-disable-cache")]
    pub pbkdf_disable_cache: bool,

    #[arg(long, value_enum)]
    pub cipher: Option<CipherAlg>,
    #[arg(long, value_name = "ALG", hide = true)]
    pub cipher_iv: Option<String>,

    #[arg(short = 'c', long)]
    pub casdir: Option<PathBuf>,
    #[arg(short = 'p', long, default_value = "",
          allow_hyphen_values = true)]
    pub prefix: String,
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Vec<String>,

    #[arg(value_name = "FILE", default_value = "-")]
    pub input: Vec<String>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Policy { Default, Nist }

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum PbkdfAlg { Argon2, Scrypt, Pbkdf2Sha256, Pbkdf2Sha512, Legacy }

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum CipherAlg { Aes256Siv, Aes256Gcm, Aes256GcmSiv }
```

### Things the derive doesn't express — keep post-parse logic

- The `WORD=PASSWORD` validator: clap 4 lets us put `value_parser` on the
  field. Easiest is to parse after the fact (the existing macro
  `csep_arg!` becomes a single `flat_map(split('=')`) — or even simpler with
  `value_delimiter = ','`, clap splits on comma for us, leaving `["word=pass",
  "word2=pass2"]` to split on `=`).
- FIPS auto-detection from `/proc/sys/crypto/fips_enabled`.
- `casdir` default: `./cas` if it exists, else `.`. clap default_value can't
  look at the FS; keep the post-parse resolution.
- `-o` / input pairing: keep the existing post-parse loop.
- `policy`/`defaults`/`fips` interaction (fips forces nist; defaults loads
  another policy's defaults without enforcing it).

### Validators that move to typed enums

- `--policy default|nist` → `Policy` enum.
- `--pbkdf` → `PbkdfAlg` enum.
- `--cipher` → `CipherAlg` enum.

This is OCP-friendly: adding a new policy/pbkdf/cipher = adding a new enum
variant and a single match arm in the relevant dispatch. Currently adding a
cipher means editing three places (`consts::VALID_CIPHER_ALGS`,
`cipher::BOTAN_CIPHER_ALG_MAP`, and `cipher::create()`).

### Behavior to preserve

- `--version`, `--help`, `--quiet` all behave identically.
- Comma-separated values for `-s`, `-f`, `-e`, `-E`, `-d`, `-k`.
- Hidden flags `--pbkdf-params`, `--pbkdf-salt`, `--cipher-iv` stay hidden.

## Verification

```
cargo check
cargo run -- --help        # visually compare to old help text
cargo run -- sample/test.ept -v   # same verbose output
cargo test --test integration     # all CLI tests
```

## Rollback

Revert `Cargo.toml` and `src/lib.rs`. The CLI tests are the main check.
