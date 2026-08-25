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

# Post-quantum key migration

enprot's chain anchors are self-describing: every `CHAIN` block carries
`signer:<alg>:<fingerprint>`, so a verifier knows which algorithm and key
to use *per anchor*. That is what makes migration incremental — a file
never has a global "PQ mode" flag to flip. This guide walks through
moving from classical (Ed25519) to post-quantum (ML-DSA, FIPS 204)
signatures with `enprot migrate-keys`.

## When to migrate

| Phase | Ed25519 anchors | Composite anchors | ML-DSA-only anchors |
|---|---|---|---|
| Now (0.5.x) | Active | Active | Active |
| Harvest-now-decrypt-later becomes signing-relevant | Deprecated | Active | Active |
| Post-quantum era | Removed | Deprecated | Active |

There is no date-driven deadline inside enprot; the trigger is your own
assessment of when adversaries might begin forging classical
signatures. Until then, the **composite** algorithm
(`composite-ed25519-mldsa`) is the recommended resting state: it
verifies under both the classical and the PQ leg, so both old and new
verifiers accept it.

## Generating post-quantum keys

```sh
enprot keygen mldsa --out-priv mldsa_priv.pem --out-pub mldsa_pub.pem
enprot keygen composite-ed25519-mldsa \
    --out-priv comp_priv.pem --out-pub comp_pub.pem
```

## Migrating a file

```sh
enprot migrate-keys \
    --from ed25519 \
    --to composite-ed25519-mldsa \
    --old-key old_pub.pem \
    --new-key comp_priv.pem \
    FILE [FILE...]
```

- `--old-key` is the old signer's **public** key — every matching
  anchor is verified against it *before anything is rewritten*. One
  tampered anchor aborts the file, leaving it byte-identical.
- `--new-key` is the new signer's **private** key.
- Each file is migrated in place. Stdin is not supported.

What changes and what doesn't:

- `signer:` becomes the new algorithm + fingerprint.
- `payload:` is preserved for anchors whose predecessors were not
  migrated, and recomputed over the rewritten bytes for anchors that
  follow a migrated ancestor (an anchor's payload commits to the exact
  bytes before it, and re-signing an ancestor legitimately changes
  those bytes).
- Parent references are rewired to the re-signed anchors' new hashes,
  so the DAG stays closed: `enprot verify-chain --trust-root
  new_pub.pem FILE` passes end to end.

## The hybrid period

During transition, a repository can hold a mix:

- Files whose anchors are still Ed25519.
- Files whose anchors were migrated to composite or ML-DSA.
- Old anchors and new anchors coexisting inside one file (migration is
  per-anchor).

`verify-chain` accepts every anchor against its own algorithm — pass
all current trust roots:

```sh
enprot verify-chain --trust-root old_pub.pem \
                    --trust-root comp_pub.pem \
                    FILE...
```

An old Ed25519-only verifier that does not know ML-DSA fails
gracefully on migrated anchors (an explicit "no pubkey registered"
error), never a crash.

## Limitations

- **Multi-sig anchors** (with co-signatures) are refused: re-signing
  changes the bytes every co-signer committed to, and their keys are
  not available to the migrating party. Migrate them by collecting
  fresh co-signatures.
- **Descendants by other signers**: if an anchor references a migrated
  parent but is signed by a different key, migration refuses —
  rewriting its parents would invalidate its signature. Run
  `migrate-keys` again with that signer's keys first, or migrate both
  signers in one pass per file.
- **Cross-file parent references**: an anchor's `parents:` may point
  at an anchor in another file. Those hashes cannot be remapped from
  here; migrate the referenced file first and re-anchor if needed.

## Reversibility

Migration is reversible by running it in the opposite direction
(`--from composite-ed25519-mldsa --to ed25519 --old-key comp_pub.pem
--new-key old_priv.pem`). The re-signed file verifies against the
original trust root again.

## Checklist

1. `enprot keygen composite-ed25519-mldsa` for each signer.
2. Distribute the new pubkeys; add them to `verify-chain
   --trust-root` lists and capability policy files (fingerprint =
   SHA3-256 over the PEM, via `enprot fingerprint`).
3. Run `enprot verify-chain` on the repository before migrating
   (everything must already verify).
4. `migrate-keys` file by file (or in bulk); commit per logical unit
   so review stays readable.
5. Re-run `verify-chain` with both old and new trust roots.
6. Keep the old keys until every copy of the old anchors is migrated
   or retired; then archive them.

## See also

- [FIPS mode](fips.md) — the policy layer that gates algorithms.
- `docs/threat-model.md` — the PQ adversary classification.
- `enprot keygen --help`, `enprot migrate-keys --help`.
