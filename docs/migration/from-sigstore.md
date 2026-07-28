# Composition with sigstore (cosign, Rekor, Fulcio)

sigstore and enprot are complementary, not competitive. sigstore
signs **artifacts** (binaries, container images, release tarballs);
enprot signs **documents** (text files with embedded EPT markup).
They don't overlap; they cover different layers of the trust stack.

## When to use which

| Task | Tool |
|---|---|
| Sign a release binary | sigstore (cosign) |
| Sign a container image | sigstore (cosign) |
| Sign a source document | enprot (chain anchors) |
| Sign a multi-party approval (3-of-5) | enprot + Confium |
| Verify artifact at install time | sigstore (cosign verify) |
| Verify document provenance | enprot (verify-chain) |
| Transparency log anchoring | sigstore (Rekor) — or enprot + Confium transparency |

## Typical composition: source + binary both signed

```sh
# 1. Sign the source document with enprot (document-level)
enprot manifest . --output build.ept -c cas/
enprot attest --signer builder-priv.pem build.ept

# 2. Build the artifact
cargo build --release
tar czf app.tar.gz target/release/app

# 3. Sign the built artifact with cosign (artifact-level)
cosign sign-blob --key cosign.key app.tar.gz

# 4. (Optional) Anchor both signatures in Rekor
cosign attach signature app.tar.gz
rekor-cli upload --artifact app.tar.gz ...
```

The downstream verifier does both checks:

```sh
# Verify the source provenance
enprot verify-chain --trust-root builder-pub.pem build.ept

# Verify the binary signature
cosign verify-blob --key cosign.pub app.tar.gz
```

## What you can't do with sigstore that enprot does

- Embed signatures **inside** text files (sigstore uses sidecar
  `.sig` files or OCI image annotations).
- Sign **regions** of a file independently (sigstore signs the
  whole blob).
- Track **multi-step edit history** with chain anchors (sigstore
  signs snapshots; doesn't link them).
- **Merge** two signed branches without losing either signature
  (sigstore signatures are over final artifacts).

## What you can't do with enprot that sigstore does

- **Public-key identity** via OIDC (sigstore's Fulcio issues
  short-lived certs tied to GitHub / Google identity). enprot's
  identity is key-fingerprint-based.
- **Public transparency log** via Rekor (anyone can monitor for
  misuse). enprot + Confium has its own transparency crate but
  isn't a public CT-style log.
- **Native container image signing** (cosign's bread and butter).
  enprot could sign an OCI manifest but the tooling isn't there.

## Migration path (none needed)

You don't migrate between them. You adopt both:

- enprot for source documents, configuration, classified text,
  supply-chain manifests
- sigstore for built artifacts, container images, package releases

If you currently use sigstore for everything and want enprot's
document-level features, adopt enprot **alongside** sigstore.
The two never conflict; they operate on different layers.

## See also

- [Migration from git-crypt](from-git-crypt.md)
- [Migration from sops](from-sops.md)
- [Migration from age](from-age.md)
- [Supply chain attestation cookbook](../cookbooks/supply-chain.md)
