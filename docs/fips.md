<!-- Copyright (c) 2018-2026 [Ribose Inc](https://www.ribose.com). -->
<!--
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
-->

# FIPS-mode builds

This document captures what it would take to ship an enprot binary whose
crypto stack is constrained to a FIPS-validated module. Issue #48 is
long-standing; this file is the design note that closes the issue.

## Current state

enprot's `--fips` flag selects the `nist` policy and enforces it at the
Rust level: only FIPS-approved algorithm names (sha3-{256,512},
pbkdf2-{sha256,sha512}, aes-256-gcm) are accepted, with salt length,
iteration count, and IV-width checks. The crypto operations themselves
run in the linked Botan library, which is built with its full default
algorithm set.

So the existing `--fips` mode is "policy-enforced FIPS-compliant
behaviour running on a non-FIPS-validated library". That is **not** a
FIPS 140-validated binary. To produce one, the underlying library
itself must be a validated module, and only its FIPS-approved
primitives may be called.

## What a real FIPS build needs

Three things, each non-trivial:

1. **OpenSSL 3.x FIPS provider**, built from source via
   `./Configure enable-fips && make && make install_sw install_ssldirs`
   followed by `openssl fipsinstall`. The provider is then loadable by
   any OpenSSL consumer via the default provider registry.

2. **Botan 3 built against the OpenSSL FIPS provider**. As of Botan
   3.12 the build-time flag is `--enable-modules=fips` together with
   `--with-openssl` (so Botan's OpenSSL bindings delegate to the FIPS
   provider). The Botan docs note that this is "wrapping OpenSSL FIPS",
   not a separate Botan FIPS validation. The combined module inherits
   OpenSSL 3.x's FIPS 140-2 certificate (#4282) for the primitives
   Botan calls.

3. **Static linking of the whole stack** into the enprot binary so the
   FIPS context is self-contained. That mirrors the existing
   `ci/build-static/` matrix and adds OpenSSL FIPS to the per-target
   build steps.

Even with all three, the resulting binary is "FIPS-capable" — claiming
actual compliance requires platform-specific certification paperwork
outside the scope of this repo.

## Why this issue is closed without a binary

The work above is real engineering, but its value depends on a
certification effort this project isn't currently pursuing. What we can
do (and have done):

- The `nist` policy already rejects every algorithm that wouldn't be
  FIPS-permitted, including in the deterministic AES-GCM variants
  introduced in PR #64 (`aes-256-gcm-det`, `aes-256-gcm-siv-det`).
- `--fips` is documented as a policy-mode flag, not a compliance claim.
- This document explains the path so anyone pursuing actual
  certification has a starting point.

If you want to drive the FIPS build to completion:

1. Add a `ci/build-fips.sh` modeled on `ci/build-static.sh` that builds
   OpenSSL with `enable-fips`, then Botan with `--with-openssl` and the
   `fips` module, then statically links enprot.
2. Add a `.github/workflows/fips.yml` that runs the script and uploads
   the resulting binary.
3. Update `ci/botan-modules` to include `openssl` and `fips` when the
   `FIPS=1` env var is set.
4. Document the resulting binary's FIPS claims precisely — what
   certificate is inherited, what's excluded, and where the security
   boundary is.

## References

- OpenSSL FIPS module 3.x: https://www.openssl.org/source/
- Botan FIPS support notes: https://botan.randombit.net/handbook/fips.html
- NIST FIPS 140-3: https://csrc.nist.gov/projects/cryptographic-module-validation-program
