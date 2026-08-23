# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.60](https://github.com/engyon/enprot/compare/enprot-v0.5.59...enprot-v0.5.60) - 2026-08-23

### Other

- *(site)* publish the reference docs + 0.5.x reality
- *(deploy)* remove the emptied extras/ dir — the upload-set guard caught it
- *(deploy)* completions as a tarball — gh release upload aborts on directories
- *(deploy)* completions as a tarball — gh release upload aborts on directories
- *(deploy)* publish the extras artifact — releases shipped binaries only

## [0.5.59](https://github.com/engyon/enprot/compare/enprot-v0.5.58...enprot-v0.5.59) - 2026-08-22

### Fixed

- *(audit)* whoami 2 removed the fallible module

### Other

- bump actions/cache from 4 to 6
- bump clap_mangen from 0.3.2 to 0.3.3
- bump whoami from 1.6.1 to 2.1.3
- bump docker/metadata-action from 5 to 6
- bump taiki-e/install-action from 2.85.11 to 2.86.3

## [0.5.58](https://github.com/engyon/enprot/compare/enprot-v0.5.57...enprot-v0.5.58) - 2026-08-21

### Other

- *(deploy)* strip -Wl,--fix-cortex-a53-843419 too — the compound form reached zig
- *(deploy)* drop --fix-cortex-a53-843419 before zig links

## [0.5.57](https://github.com/engyon/enprot/compare/enprot-v0.5.56...enprot-v0.5.57) - 2026-08-20

### Added

- *(tests)* cross-version compatibility harness (TODO.complete/60)
- *(build)* vendor Botan on unix cross builds too — vendored-rnp enables botan/vendored

### Fixed

- *(build)* botan/vendored belongs to the cross builds, not the feature

### Other

- canonical Cargo.lock (drop pruned optional botan-src) + bench-compare checks out -f
- *(deploy)* last botan-src lock entry for the tarball repack; verify aarch64 by ELF arch
- *(deploy)* one less Botan on windows-gnu + 240-min bootstrap window
- *(build)* comment above 'if !' — the inline comment broke the shell line
- *(xver)* forward-compat skips loudly when the latest release has no linux asset
- drop the azure apt mirror in release/ohos workflows — same stall as tests
- merge main: bench-suite + CI hardening
- *(build)* source the pre-script before the generic rustflags append
- LD_LIBRARY_PATH for the /usr/local prefix — librnp.so.0 unfindable at runtime
- export RNP_INCLUDE_DIR/RNP_LIB_DIR from install.sh
- *(deploy)* cache the C stacks — 2h legs to ~30 min on warm runs
- *(deploy)* link-self-contained=no for the zig-linked musl targets
- *(deploy)* 180 min for archive legs — three Botan builds per leg exceed 90
- *(deploy)* link the musl binaries with zig — the C objects are libc++
- *(deploy)* tool-ar also emits libbotan-3.a for the mingw Botan archive
- *(build)* clang on the musl host side — clang-only flags must parse there too
- *(build)* emit BOTH the tool-* env handles and the bare-name shadows
- *(deploy)* explicit BOTAN_CONFIGURE_CC — old botan-src cannot classify the wrappers
- *(deploy)* amalgamate Botan on windows-gnu too — it also outlived the job timeout
- *(deploy)* amalgamate the zig-built Botan — one TU instead of ~400
- *(deploy)* msvc EXE_PATH missed the target subdir
- *(deploy)* 90 min for archive legs — 45 killed the zig builds mid-flight
- *(msvc)* comment above the backtick-continued cmake invocation
- *(msvc)* define BOTAN_DLL empty when compiling librnp against static Botan
- *(build)* the shadow compilers must be named gcc/g++/cc/c++, not tool-gcc
- *(deploy)* build Botan 3.12 on the msvc leg — match the vendored botan-src
- *(deploy)* fold the msvc PDB suppression into RUSTFLAGS env
- *(build)* shadow gcc/g++/cc/c++ with OUT_DIR dispatchers in the images
- *(deploy)* published crate layout is botan-src-<ver>/, not package/
- *(deploy)* plain CC for CMake deps, HOST_CC shields cc-crate host builds
- *(deploy)* -mevex512 for the zig-built Botan (x86_64-musl)
- *(deploy)* fetch the botan-src crate from static.crates.io
- drop the azure apt mirror — it stalls below apt's HTTP timeout
- gitignore the windows-gnu patched-Botan tarball artifacts
- *(deploy)* posix-absolute Botan install root for the windows-gnu configure
- *(build)* wrappers.sh repo-relative too — same $0 trap as musl-common
- *(deploy)* OUT_DIR-branching toolchain wrappers for every cross leg
- *(deploy)* portable SHA-2 for aarch64-musl — zig can't lower sha512h2
- *(deploy)* no PDB at all for the msvc release build — LNK1201
- *(deploy)* disable Botan's getentropy module on windows-gnu
- *(build)* pin zig's global cache to /tmp — 'AccessDenied' inside cross containers
- apt network timeouts + retries — the azure mirror stalls silently on runners
- *(deploy)* scoped compiler env — never blanket CC/CXX in cross builds
- *(build)* source musl-common.sh repo-relative — $0 is the runner's temp wrapper on Actions
- *(bench)* 60 min for Benchmarks vs main — the full suite compiles twice
- *(deploy)* job-level if cannot use env context — express the publish gate in raw contexts
- *(deploy)* zig toolchain for the musl legs + branch test-build dispatch
- *(deploy)* clean target before the cross build (hermetic releases)

## [0.5.56](https://github.com/engyon/enprot/compare/enprot-v0.5.55...enprot-v0.5.56) - 2026-08-19

### Other

- *(deploy)* dump container env + mingw toolchain paths on failure
- *(deploy)* explicit CC/CXX passthrough in Cross.toml + container dump

## [0.5.55](https://github.com/engyon/enprot/compare/enprot-v0.5.54...enprot-v0.5.55) - 2026-08-19

### Other

- *(deploy)* surface the real error when cross -vv swallows it

## [0.5.54](https://github.com/engyon/enprot/compare/enprot-v0.5.53...enprot-v0.5.54) - 2026-08-18

### Other

- *(deploy)* CC/CXX for windows-gnu — botan configure autodetected the host

## [0.5.53](https://github.com/engyon/enprot/compare/enprot-v0.5.52...enprot-v0.5.53) - 2026-08-18

### Other

- *(deploy)* windows-gnu needs cross-rs :main — the 0.2.5 tag predates the 24.04 rebase

## [0.5.52](https://github.com/engyon/enprot/compare/enprot-v0.5.51...enprot-v0.5.52) - 2026-08-18

### Fixed

- *(release)* grant actions:write — deploy dispatch got HTTP 403

## [0.5.51](https://github.com/engyon/enprot/compare/enprot-v0.5.50...enprot-v0.5.51) - 2026-08-18

### Fixed

- *(release)* dispatch deploy by tag age, not points-at-HEAD

## [0.5.50](https://github.com/engyon/enprot/compare/enprot-v0.5.49...enprot-v0.5.50) - 2026-08-18

### Added

- *(streaming)* --streaming transform+write, O(largest-block) memory (TODO #35)

### Fixed

- *(deploy)* resolve rebase markers — keep gh upload step + pattern download
- *(deploy)* per-target artifacts — parallel uploads to one name collided
- *(deploy)* cross-build TOML duplicates, runner-broken release step, timeout

### Other

- *(release)* dispatch deploy for released tags — releases were empty

## [0.5.49](https://github.com/engyon/enprot/compare/enprot-v0.5.48...enprot-v0.5.49) - 2026-08-17

### Other

- *(security)* audited timing-sensitivity classification (TODO #52)
- *(extfield)* value-exact accessor specs — close mutation gap

## [0.5.48](https://github.com/engyon/enprot/compare/enprot-v0.5.47...enprot-v0.5.48) - 2026-08-17

### Added

- *(audit)* operational audit trail (TODO #63)

### Other

- *(mutants)* set install.sh env vars; make survivors non-gating

## [0.5.47](https://github.com/engyon/enprot/compare/enprot-v0.5.46...enprot-v0.5.47) - 2026-08-16

### Fixed

- *(snapshots)* normalize JSON-escaped tempdir paths (Windows)
- *(build)* link librnp transitive C libs on OHOS (closes #351)

### Other

- *(snapshots)* insta harness + 5 stable-output CLI snapshots (TODO #44)

## [0.5.46](https://github.com/engyon/enprot/compare/enprot-v0.5.45...enprot-v0.5.46) - 2026-08-16

### Added

- *(sbom)* 'enprot sbom' — SPDX 2.3 + CycloneDX 1.5 (TODO #62)

### Fixed

- *(sbom)* hand-parse Cargo.lock in build.rs — no build-dependency

### Other

- bisect experiment — disable lockfile embed directives
- *(reproducibility)* build-twice-compare workflow for musl (TODO #45)

## [0.5.45](https://github.com/engyon/enprot/compare/enprot-v0.5.44...enprot-v0.5.45) - 2026-08-15

### Added

- *(cappolicy)* rule engine — policy rules as data, not methods (TODO #34)

### Other

- *(tests)* native Linux aarch64 leg (TODO #46)
- gitignore cargo-mutants scratch output
- *(mutation)* cargo-mutants harness + cappolicy at 100% viable coverage (TODO #43)

## [0.5.44](https://github.com/engyon/enprot/compare/enprot-v0.5.43...enprot-v0.5.44) - 2026-08-14

### Other

- *(provider,resolve)* AnySigner bridge + print_tree specs
- *(etree)* wire-format spec for parse + transform state machine
- *(etree)* wire-format spec for tree_write + CI coverage gate (TODO #49)

## [0.5.43](https://github.com/engyon/enprot/compare/enprot-v0.5.42...enprot-v0.5.43) - 2026-08-14

### Fixed

- *(cipher)* adapt to aes-gcm-siv 0.12 / aead 0.6 API

### Other

- bump aes-gcm-siv from 0.11.1 to 0.12.0 in the rustcrypto group
- bump docker/setup-qemu-action from 3 to 4
- bump clap_complete from 4.6.8 to 4.6.9
- bump clap_mangen from 0.3.0 to 0.3.2
- bump taiki-e/install-action from 2.85.8 to 2.85.11
- bump thiserror from 2.0.19 to 2.0.20 in the tracing-logging group
- bump docker/login-action from 3 to 4
- bump clap from 4.6.5 to 4.6.6 in the clap group
- bump actions/upload-artifact from 4 to 7
- bump docker/setup-buildx-action from 3 to 4

## [0.5.42](https://github.com/engyon/enprot/compare/enprot-v0.5.41...enprot-v0.5.42) - 2026-08-14

### Added

- *(cli)* typed ConfigIssue validation gate (TODO #33 phase 1)

### Other

- *(cli)* DRY — single source for FIPS+policy conflict check
- *(cli)* integration tests for typed ConfigIssue gate
- *(bench)* end-to-end encrypt pipeline bench (TODO #41)
- *(cli)* align defense-in-depth FIPS message with upfront validation
- *(reproducibility)* SOURCE_DATE_EPOCH + reproducible-builds.md (TODO #45 phase 1)

## [0.5.41](https://github.com/engyon/enprot/compare/enprot-v0.5.40...enprot-v0.5.41) - 2026-08-13

### Fixed

- *(security)* update nanoid to 3.3.18 — fixes high-severity CVE

### Other

- integration tests for 'enprot cas stats'

## [0.5.40](https://github.com/engyon/enprot/compare/enprot-v0.5.39...enprot-v0.5.40) - 2026-08-13

### Added

- *(cas)* implement 'enprot cas stats' — blob count, size range

## [0.5.39](https://github.com/engyon/enprot/compare/enprot-v0.5.38...enprot-v0.5.39) - 2026-08-13

### Other

- add CAS + compression benchmarks (TODO #41)

## [0.5.38](https://github.com/engyon/enprot/compare/enprot-v0.5.37...enprot-v0.5.38) - 2026-08-13

### Other

- *(error)* replace Cas(String) with VerifyFailed — last catch-all eliminated

## [0.5.37](https://github.com/engyon/enprot/compare/enprot-v0.5.36...enprot-v0.5.37) - 2026-08-13

### Other

- validate --jobs 0 is rejected with error

## [0.5.36](https://github.com/engyon/enprot/compare/enprot-v0.5.35...enprot-v0.5.36) - 2026-08-12

### Added

- *(cli)* validate --jobs >= 1 — hard error on zero (TODO #33)

## [0.5.35](https://github.com/engyon/enprot/compare/enprot-v0.5.34...enprot-v0.5.35) - 2026-08-12

### Other

- *(provider)* extract SignFuture type alias — remove type_complexity suppressions

## [0.5.34](https://github.com/engyon/enprot/compare/enprot-v0.5.33...enprot-v0.5.34) - 2026-08-12

### Other

- *(error)* eliminate Error::Msg entirely — DagError mapped to structured variants

## [0.5.33](https://github.com/engyon/enprot/compare/enprot-v0.5.32...enprot-v0.5.33) - 2026-08-12

### Other

- compression round-trip integration tests — encrypt+compress -> decrypt

## [0.5.32](https://github.com/engyon/enprot/compare/enprot-v0.5.31...enprot-v0.5.32) - 2026-08-11

### Other

- update CLAUDE.md with CAS subsystem, extfield, compression, errors

## [0.5.31](https://github.com/engyon/enprot/compare/enprot-v0.5.30...enprot-v0.5.31) - 2026-08-11

### Other

- *(error)* remove dead Cipher(String) and Pbkdf(String) variants

## [0.5.30](https://github.com/engyon/enprot/compare/enprot-v0.5.29...enprot-v0.5.30) - 2026-08-11

### Other

- *(extfield)* complete typed view migration — eliminate last raw string key

## [0.5.29](https://github.com/engyon/enprot/compare/enprot-v0.5.28...enprot-v0.5.29) - 2026-08-10

### Added

- *(cli)* progress reporting for multi-file operations (TODO #72)

## [0.5.28](https://github.com/engyon/enprot/compare/enprot-v0.5.27...enprot-v0.5.28) - 2026-08-09

### Fixed

- *(ci)* docs deploy non-blocking — continue-on-error when Pages not enabled

## [0.5.27](https://github.com/engyon/enprot/compare/enprot-v0.5.26...enprot-v0.5.27) - 2026-08-09

### Other

- CAS operations spec — verify, gc, list CLI reference

## [0.5.26](https://github.com/engyon/enprot/compare/enprot-v0.5.25...enprot-v0.5.26) - 2026-08-09

### Fixed

- *(docker)* add libclang-dev for bindgen (rnp-rs FFI generation)

## [0.5.25](https://github.com/engyon/enprot/compare/enprot-v0.5.24...enprot-v0.5.25) - 2026-08-09

### Fixed

- *(docker)* correct Botan configure.py flag — --build-targets not --with-build-targets
- *(docker)* add xz-utils + fix PKG_CONFIG_PATH warning
- *(docker)* build Botan 3 from source in Docker image

### Other

- *(docker)* add .dockerignore — exclude target/, .git/, node_modules/

## [0.5.24](https://github.com/engyon/enprot/compare/enprot-v0.5.23...enprot-v0.5.24) - 2026-08-09

### Other

- *(prot)* idiomatic decrypt signature — Option<&str> instead of &Option<&String>

## [0.5.23](https://github.com/engyon/enprot/compare/enprot-v0.5.22...enprot-v0.5.23) - 2026-08-09

### Added

- *(cas)* implement 'enprot cas list' — enumerate CAS blobs

## [0.5.22](https://github.com/engyon/enprot/compare/enprot-v0.5.21...enprot-v0.5.22) - 2026-08-09

### Other

- *(error)* eliminate Error::Pbkdf(String) — ZERO remaining
- *(extfield)* eliminate raw string keys in prot.rs — DRY migration

## [0.5.21](https://github.com/engyon/enprot/compare/enprot-v0.5.20...enprot-v0.5.21) - 2026-08-09

### Other

- *(transform)* DRY extract ciphertext helpers — eliminate 3x duplication
- bump actions/setup-python from 5 to 7
- bump taiki-e/install-action from 2.85.3 to 2.85.8

## [0.5.20](https://github.com/engyon/enprot/compare/enprot-v0.5.19...enprot-v0.5.20) - 2026-08-08

### Other

- *(error)* eliminate Error::Cipher(String) entirely — ZERO remaining

## [0.5.19](https://github.com/engyon/enprot/compare/enprot-v0.5.18...enprot-v0.5.19) - 2026-08-08

### Other

- *(prot)* decompose decrypt into focused helpers

## [0.5.18](https://github.com/engyon/enprot/compare/enprot-v0.5.17...enprot-v0.5.18) - 2026-08-08

### Other

- *(prot)* decompose encrypt into focused helpers

## [0.5.17](https://github.com/engyon/enprot/compare/enprot-v0.5.16...enprot-v0.5.17) - 2026-08-08

### Other

- *(fuzz)* add CAS hash validation + separator fuzz targets (TODO #36)

## [0.5.16](https://github.com/engyon/enprot/compare/enprot-v0.5.15...enprot-v0.5.16) - 2026-08-08

### Added

- *(cli)* color output for diagnostic commands (TODO #73)

### Fixed

- *(typos)* rephrase CHANGELOG entry to avoid spell-check failure

## [0.5.15](https://github.com/engyon/enprot/compare/enprot-v0.5.14...enprot-v0.5.15) - 2026-08-08

### Added

- *(compress)* optional zlib compression before encryption (TODO #68)
- *(cas)* CasStore trait completeness + atomic writes (#61, #74)

### Fixed

- *(typos)* fix misspelled CHANGELOG reference that broke spell check

## [0.5.14](https://github.com/engyon/enprot/compare/enprot-v0.5.13...enprot-v0.5.14) - 2026-08-08

### Added

- *(cas)* implement 'enprot cas gc' — CAS garbage collection (TODO #66)
- *(cas)* implement 'enprot cas verify' — CAS integrity check (TODO #67)
- implement --dry-run mode + reach 25-fixture conformance target
- kemenc.rs typed errors + 3 conformance fixtures + TODOs #58-65
- pki.rs typed errors + CODE_OF_CONDUCT + CONTRIBUTING expansion + TODOs #50-57 + 3 conformance fixtures
- *(tracing)* instrument crypto + CAS + ledger + PKI hot paths
- *(error)* add 5 typed variants + migrate signature/extfield/block sites
- *(parallel)* implement --jobs flag for parallel multi-file processing
- eliminate all stubs — streaming parser, sigstore sign/verify, memory CAS
- *(lsp+wasm)* minimal LSP server + WASM feature flag
- *(streaming+cas)* ParseEvent scaffold + CAS backend dispatch
- *(observability)* add tracing crate + instrument key functions
- *(cli)* add 'enprot cap' subcommand — capability policy queries
- *(grammar+sigstore)* pest EPT grammar + Sigstore module scaffold
- *(cli)* group run() parameters into RunConfig (typed dispatch)
- *(distro)* deb/rpm + NixOS module + Chocolatey + Snap fix + Marketplace publish
- *(ffi)* classify errors via typed match (no string matching)
- *(policy)* require Send + Sync on CryptoPolicy trait
- *(cli)* add --format json to `enprot inspect`
- *(ffi)* actually run the pipeline — JSON config → argv → app_main

### Fixed

- *(typo)* fixed misspelled CHANGELOG reference in TODO #30
- *(deploy)* match release-plz per-crate tag pattern (enprot-v0.5.X)

### Other

- eliminate all #[allow(dead_code)] — TODO #10
- bump actions/checkout from 4 to 7
- fix .gitignore CAS blob pattern + untrack TODO.complete/
- bump postcss from 8.5.22 to 8.5.26 in /docs ([#257](https://github.com/engyon/enprot/pull/257))
- bump js-yaml from 4.3.0 to 4.3.1 in /docs ([#256](https://github.com/engyon/enprot/pull/256))
- bump fast-uri from 3.1.4 to 3.1.5 in /docs ([#233](https://github.com/engyon/enprot/pull/233))
- bump rnp-rs from 0.1.10 to 0.1.11 ([#250](https://github.com/engyon/enprot/pull/250))
- bump toml from 1.1.3+spec-1.1.0 to 1.1.4+spec-1.1.0 ([#249](https://github.com/engyon/enprot/pull/249))
- bump clap from 4.6.4 to 4.6.5 in the clap group ([#248](https://github.com/engyon/enprot/pull/248))
- bump actions/setup-node from 4 to 7 ([#244](https://github.com/engyon/enprot/pull/244))
- *(error)* migrate ALL extracted cli/ Error::msg sites — ZERO remaining
- complete Display test coverage + CAS round-trip property + 4 conformance fixtures
- *(error)* migrate ALL remaining small-module Error::msg sites + TODOs #66-73
- *(todo)* sync README with PR #251 (docs execution + #43-49)
- *(error)* migrate small-module Error::msg sites (continue #26)
- *(todo)* update README with #33-42 + latest shipped items
- *(error)* finish typed-error migration in ledger/anchor.rs
- *(rsd)* add 5 conformance fixtures + 10 architectural TODOs
- *(proptest)* add encrypt/decrypt/encrypt-store property tests
- *(cli)* extract core transform pipeline into pipeline module
- *(cli)* extract snapshot/pin/audit-log into chain_head_cmd module
- *(cli)* extract keygen/sign/verify-sig/fingerprint into pki_cmd module
- *(cli)* extract verify-chain into verify_chain module
- *(cli)* extract verify_files into verify module
- *(cli)* extract list_files into list module
- *(cli)* extract manifest/attest/scm into provenance_cmd module
- *(cli)* extract clean/smudge/textconv into smudge module
- *(cli)* extract inspect subcommand into inspect module
- *(ohos)* add QEMU emulation for dockerharmony (image is aarch64-only)
- *(ohos)* set BINDGEN_EXTRA_CLANG_ARGS so rnp-rs bindgen uses OHOS sysroot
- *(ohos)* manual install for sexpp (cmake install expects bin/sexpp)
- *(ohos)* build only sexpp library target, not tests
- *(ohos)* cross-compile librnp + deps via ci/build-rnp-ohos.sh
- *(windows)* build enprot + enprot-ffi sequentially to avoid PDB collision
- *(windows)* use Defender exclusion path instead of disabling realtime
- *(windows)* disable Defender realtime monitoring to fix LNK1201
- *(ohos)* revert vendored-rnp experiment
- *(windows)* use -C debuginfo=1 to fix LNK1201 PDB race
- *(windows)* use -C split-debuginfo=unpacked to fully fix LNK1201
- *(windows)* set /DEBUG:FASTLINK via RUSTFLAGS env to bypass cargo override
- *(schemas)* fix typos-checker failure on example typo
- fix Windows LNK1201 PDB race + OHOS rnp-rs header panic
- *(cli)* extract merge-driver/resolve/conflicts into merge_cmd module
- eliminate all stale 'scaffold'/'stub'/'not yet' language from source
- *(rsd)* conformance suite — 5 key fixtures
- *(parse)* migrate max-depth error to typed Error::Parse variant
- *(cli)* split cli.rs into cli/ module dir; extract init
- downgrade unreachable pub to pub(crate) in private modules
- *(todo)* update README statuses — 11 done, 4 partial, 10 specified
- *(proptest)* add store/fetch + CAS invariants
- remove build-cache hash files accidentally committed
- *(specs)* EPT wire-format, CHAIN anchor, extfield JSON Schemas (v1)
- remove build-cache hash files accidentally committed
- *(todo)* comprehensive TODO.complete/ — 25 prioritized specs

## [0.5.13](https://github.com/engyon/enprot/compare/enprot-v0.5.12...enprot-v0.5.13) - 2026-07-31

### Other

- bump actions/deploy-pages from 4 to 5

## [0.5.12](https://github.com/engyon/enprot/compare/enprot-v0.5.11...enprot-v0.5.12) - 2026-07-31

### Added

- *(bindings+distro)* Go + Ruby bindings, AUR package, Nix flake
- *(editor)* VS Code extension skeleton for EPT
- *(bindings)* Node.js bindings + quickstart cookbook + SOPS importer
- *(bindings)* pyenprot + GitHub Action + pre-commit hook
- *(ffi)* split libenprot into a separate workspace member
- Docker image, Homebrew formula, C FFI API, GHCR workflow

### Fixed

- *(deploy)* idempotent [target.$TARGET] block in .cargo/config.toml

### Other

- bump clap_mangen from 0.2.33 to 0.3.0
- bump actions/cache from 4 to 6
- bump docker/build-push-action from 6 to 7
- bump taiki-e/install-action from 2 to 2.85.3
- bump actions/upload-pages-artifact from 3 to 5
- bump clap_complete from 4.6.7 to 4.6.8
- *(bindings)* quote job name to avoid YAML reserved-char error
- *(bindings)* set BOTAN_VERSION for windows install.ps1
- *(bindings)* set PREFIX before install.ps1 on windows

## [0.5.11](https://github.com/engyon/enprot/compare/v0.5.10...v0.5.11) - 2026-07-30

### Added

- full Windows CI via vendored-rnp + vendored botan

### Fixed

- *(ci)* vendored-rnp for Unix, keep install.ps1 for Windows
- *(deploy)* replace deprecated macos-13 with macos-15-intel

### Other

- *(deploy)* add Windows binary verification step

## [0.5.10](https://github.com/engyon/enprot/compare/v0.5.9...v0.5.10) - 2026-07-29

### Added

- vendored-rnp for Docker cross-compile + rnp-src workaround

### Other

- upgrade rnp-rs 0.1.7 → 0.1.10; add vendored-rnp feature

## [0.5.9](https://github.com/engyon/enprot/compare/v0.5.8...v0.5.9) - 2026-07-29

### Fixed

- *(deploy)* relax macOS post-build check + set DYLD_LIBRARY_PATH

## [0.5.8](https://github.com/engyon/enprot/compare/v0.5.7...v0.5.8) - 2026-07-29

### Fixed

- *(deploy)* set PKG_CONFIG_PATH for macOS deploy builds
- *(deploy)* use macos-13 (x86_64) runner for x86_64-apple-darwin

### Other

- EPT wire format + ExtField schema specs; deploy concurrency

## [0.5.7](https://github.com/engyon/enprot/compare/v0.5.6...v0.5.7) - 2026-07-29

### Fixed

- *(deploy)* fail-fast: false so native builds survive Docker failures

## [0.5.6](https://github.com/engyon/enprot/compare/v0.5.5...v0.5.6) - 2026-07-29

### Fixed

- *(deploy)* use pwsh shell for Windows + publish partial releases

## [0.5.5](https://github.com/engyon/enprot/compare/v0.5.4...v0.5.5) - 2026-07-29

### Fixed

- *(deploy)* correct Windows PREFIX path construction

## [0.5.4](https://github.com/engyon/enprot/compare/v0.5.3...v0.5.4) - 2026-07-29

### Fixed

- *(deploy)* correct Docker FROM tag + snap version variable + snap deps

## [0.5.3](https://github.com/engyon/enprot/compare/v0.5.2...v0.5.3) - 2026-07-29

### Other

- use prebuilt static musl binary instead of building from source

## [0.5.2](https://github.com/engyon/enprot/compare/v0.5.1...v0.5.2) - 2026-07-29

### Other

- switch base from core22 to core24
- append to .cargo/config.toml instead of overwriting .cargo/config
- *(deploy)* run sed BEFORE snapcore/action-build step in snap job
- *(deploy)* pass BOTAN_VERSION + PREFIX to generate-extras install.sh

## [0.5.1](https://github.com/engyon/enprot/compare/v0.5.0...v0.5.1) - 2026-07-29

### Fixed

- *(deploy)* accept v-prefixed tags from release-plz

### Other

- update CLAUDE.md release section to reflect release-plz flow
- *(deploy)* add workflow_dispatch + unified DEPLOY_TAG for both triggers
- derive CMAKE_SYSTEM_PROCESSOR from TARGET triple in cross-deps script
- Release pipeline gap analysis: fix deploy CI, add LICENSE, aarch64, docs
- document DYLD_LIBRARY_PATH requirement for macOS test runs
- document Windows MSVC support in README installation section
- update CLAUDE.md with Windows MSVC build pipeline
- build zlib static so the test binary has no zlib1.dll dep
- set RUSTFLAGS so botan-sys resolves botan-3.lib globally
- split botan dep per target (drop pkg-config on MSVC)
- use build.rs for link directives (not cargo rustflags which breaks deps)
- use rustflags for linking (cargo config doesn't support rustc-link-lib key)
- fix .cargo/config format (flat target section, not per-lib subtables)
- link all deps (json-c, sexpp, bzip2, zlib) in cargo config
- clear Error stream + global LASTEXITCODE after tolerated cmake install
- reset LASTEXITCODE after tolerated cmake install error
- tolerate cmake install error (rnp.exe not built is OK)
- manually copy rnp headers + lib instead of cmake install
- use full cmake install (component names don't match rnp's)
- use tronkko/dirent for real POSIX dir API on MSVC
- put getopt.h stub in PREFIX/include so compiler finds it
- provide stub getopt.lib for cmake find_library
- GitHub mirrors for deps, stub POSIX headers, build only librnp target
- provide dirent.h + getopt.h from rnp src/common for MSVC
- also build zlib from source for librnp find_package(ZLIB REQUIRED)
- build bzip2 from source for librnp CMake find_package
- Windows install: provide bzip2 dev for librnp CMake find_package
- Windows install: disable bzip2/zlib compression in librnp build
- Restore Windows CI: build botan + json-c + librnp from source

## [0.5.0](https://github.com/engyon/enprot/compare/v0.4.2...v0.5.0) - 2026-07-28

### Other

- Restore deny.toml; fix .gitignore to only match 64-char CAS hashes
- Fix provenance CAS: use set_local_casdir after trait refactor
- Restore deny.toml
- Fix clippy: use .. instead of name: _ in KEY/CERT match patterns
- strategic positioning + RSD spec directive documentation
- Remove stray CAS test blobs + add to .gitignore
- Add IMMUTABLE/MUTED hash verification to enprot verify
- Restore deny.toml (accidentally deleted)
- Implement RSD spec directives: IMMUTABLE/MUTABLE/MUTED + KEY/CERT/UNKEY/UNCERT
- Implementation batch: 7 TODOs landed as code + 4 as docs

## [0.4.2](https://github.com/engyon/enprot/compare/v0.4.1...v0.4.2) - 2026-07-27

### Other

- Bump rnp-rs 0.1.6 -> 0.1.7
- Cross-ref upstream OHOS-blocker issues in TODO.finalize/51
- Document OHOS + rnp-rs blocker (librnp cross-compile pending)
- Update Confium integration tracker to reflect released v0.3.0 crates
- Fix clippy::collapsible_if across cli.rs, config.rs, policy/nist.rs
- Drop Windows from CI matrix (librnp unavailable); tracked in TODO 52
- Bump MSRV 1.85 -> 1.88 (rnp-rs uses let-chains)
- force /usr/local on macOS (SIP blocks /usr)
- Disable ENABLE_PQC/ENABLE_CRYPTO_REFRESH in librnp build
- Fix botan module names (auto_seeding_rng etc. don't exist)
- Expand ci/botan-modules with everything librnp needs
- Fix librnp build: init submodules, build botan first
- Build librnp from source in CI (rnp-rs 0.1.6 needs newest FFI)
- install librnp-dev / rnp for rnp-rs build
- Add OpenPGP signature support via rnp-rs 0.1.6 (required dep)
- Simplify OHOS smoke test: hash + RNG only (no botan_aead_*)
- Fix OHOS smoke test: use botan/ffi.h (C FFI) instead of C++ headers
- Fix OHOS linker: -lc++ -lc++abi instead of -lstdc++
- Fix OHOS linker: drop PKG_CONFIG_SYSROOT_DIR, add -L for botan lib
- Fix OHOS pkg-config: use absolute paths + BOTAN_STATIC=1
- Fix build-botan-ohos.sh: resolve botan-modules via absolute path
- Fix NDK clang++ binary name: hyphens, not underscores
- Fix function ordering in setup-ohos-ndk.sh
- Fix OHOS NDK setup: archive format + sysroot path
- Fix OHOS Rust target name + criterion --baseline flag
- Add OHOS (OpenHarmony) cross-compile target
- Architecture audit: 4 new TODOs (47-50) written and completed
- Mark TODO.finalize/36-46 as done; small DRY cleanup
- Fix three CI failures: clippy, typos, Windows paths

## [0.4.0] - 2026-07-24

### Breaking Changes

- **CLI is now subcommand-style**: `enprot encrypt -w WORD file.ept` instead of `enprot -e WORD file.ept`. The flat-flag form is gone. (#22)
- **`-k` no longer splits on commas**: one `WORD=PASSWORD` per flag; use multiple `-k` for multiple pairs. (#19)
- **Rust edition 2024** (minimum Rust 1.85).

### Added

- **Subcommand CLI**: `encrypt`, `decrypt`, `store`, `fetch`, `encrypt-store`, `passthrough`, `verify`, `list`, `completions`. (#22)
- **Deterministic AES-GCM**: `aes-256-gcm-det` and `aes-256-gcm-siv-det` variants derive the nonce from plaintext via HKDF + HMAC, enabling CAS deduplication for encrypted segments. (#39)
- **`--output-dir <DIR>` flag** and `-p DIR/` directory mode for multi-file output. (#18)
- **`--lang <LANG>` flag**: separator presets for `raw`, `c`, `python`, `html`, `latex`. 
- **`enprot verify` subcommand**: check markup structure, CAS pointers, and extfield format without decrypting.
- **`enprot list` subcommand**: list all WORD segments in a file with type and crypto metadata.
- **`enprot completions <SHELL>`**: generate bash/zsh/fish/PowerShell completion scripts.
- **`enprot keygen`, `sign`, `verify-sig`**: Ed25519 detached signatures (PQC Phase 1). Foundation for ML-DSA / ML-KEM / composites tracked in `TODO.finalize/10-12`.
- **Typed `Error` enum** (`src/error.rs`) with `thiserror`. `app_main` returns `Result<()>`. (#23)
- **Property-based tests** via `proptest`: round-trip + determinism checks for the `-det` variants. (A10)
- **`ParseOps` decomposition**: `Separators`, `Transforms`, `CryptoConfig` inner structs. (A1)
- **`etree/` module split**: `mod.rs`, `parse.rs`, `transform.rs`, `write.rs`, `blob.rs`. (A3)
- **Password module** (`src/password.rs`): TTY-aware reading extracted from `prot.rs`. (A4)
- **NIST policy `AlgKind` enum**: replaces stringly-typed `kind` parameter. (A5)
- **`cipher::format/parse_cipher_extfield`**: single source of truth for the cipher wire format. (A2)
- **`--pbkdf legacy` deprecation warning**: stderr message on encrypt.
- **Pre-commit hook** (`.githooks/pre-commit`): fmt + clippy + typos.
- **`deny.toml`**: cargo-deny config for license + advisory checking.
- **`typos.toml`**: spell-checker config with enprot vocabulary.
- **`SECURITY.md`**: vulnerability reporting policy.
- **`CONTRIBUTING.md`**: development setup and PR process.
- **Dependabot config**: weekly cargo + github-actions dep bumps.
- **Release profile** with LTO + codegen-units=1 + strip.

### Changed

- **Botan 2.13 → Botan 3** (CI builds against 3.7.0; Homebrew 3.12.0). The `botan` crate is at 0.11 with `botan3` + `pkg-config` features.
- **Dropped `block-cipher-trait`** (deprecated). AES-GCM-SIV stays via RustCrypto `aes-gcm-siv` 0.11 (Botan doesn't implement RFC 8452).
- **Dropped `phc` 0.2** (unmaintained). Replaced with a 30-line PHC parser/serializer in `pbkdf.rs` that accepts padded base64 salts.
- **`clap` 2.33 → 4.5** with `Parser` derive.
- **`rpassword` 2 → 7**. TTY-detecting password reader.
- **`phf` 0.8 → 0.14**, `hex` 0.3 → 0.4, `num` dropped.
- **`assert_cmd` 0.11 → 2**, `predicates` 1 → 3, `tempfile` 3.1 → 3.
- **CI**: `actions/checkout@v7`, `dtolnay/rust-toolchain`, `snapcore/action-build/publish`, concurrency cancellation, typos job, cargo-deny + cargo-audit job.
- **Snap**: `core20` → `core22`, `libbotan-2-dev` → `libbotan-3-dev`.
- **Windows static builds**: botan-3 library suffix.

### Fixed

- **#50**: Windows stdin password reading now works via rpassword 7's TTY-aware path.
- **#23**: All `Result<T, &'static str>` replaced with typed `Error` enum. `panic!` calls on max recursion depth replaced with `Err` returns.
- **AES-SIV key length**: Botan 3 reports 64-byte keys for `AES-256/SIV` (RFC 5297 double-key); PBKDF derives `key_len_max()` bytes.
- **Windows CI link failure**: `--library-suffix=-3` is redundant on Botan 3.x (the major version already adds `-3`); dropping it lets the static library name match the cargo link directive (`botan-3.lib`).

## [0.3.1] - 2020-10-05

- Initial public release.
