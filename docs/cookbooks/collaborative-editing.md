# Collaborative editing with cryptographic provenance

Demonstrates enprot's core value: multiple authors editing the same
file, each signing their contributions, with merge-friendly conflict
handling. No Confium needed — local PEM keys suffice.

## Setup

Each contributor generates an Ed25519 keypair:

```sh
git clone https://example.com/team/design.ept
cd design.ept
enprot init
enprot keygen ed25519 --out-priv $USER-priv.pem --out-pub $USER-pub.pem
```

Commit the pubkeys so verifiers can resolve fingerprints later:

```sh
mkdir -p keys && mv $USER-pub.pem keys/
git add .enprot.toml keys/$USER-pub.pem
git commit -m "Add $USER pubkey"
```

## Alice signs a contribution

Alice encrypts a section and signs the resulting chain anchor:

```sh
enprot encrypt -w Draft -k Draft=password design.ept
enprot encrypt --anchor --signer alice-priv.pem -w Draft design.ept
git commit -am "Alice: encrypted Draft + signed anchor"
git push
```

The anchor records: timestamp, payload hash, signer fingerprint,
and the Ed25519 signature. Verifiers don't need to decrypt to
validate the signature — the anchor is over the *ciphertext*
representation of the file, not the plaintext.

## Bob signs a different change to the same region

```sh
git pull alice/branch
# (Bob edits design.ept locally — modifies content under Draft)
enprot encrypt --anchor --signer bob-priv.pem -w Draft design.ept
git commit -am "Bob: re-encrypted Draft + signed"
git push
```

## Merge with conflict

The two branches both touched the same chain anchor. A plain `git
merge` would produce `<` / `=` / `>` markers that aren't valid
host-language syntax. enprot's merge driver produces `CONFLICT`
blocks instead:

```
// <( CONFLICT Draft )>
// <( OURS )>
<encrypted block from bob>
// <( THEIRS )>
<encrypted block from alice>
// <( END Draft )>
```

Install the merge driver once per repo:

```sh
enprot init --git
```

Now `git merge` automatically uses enprot's conflict markers.

## Resolving conflicts

`enprot resolve` accepts per-WORD overrides:

```sh
# Resolve Draft in favor of "ours"; resolve Marketing in favor of "theirs"
enprot resolve --word Draft:ours --word Marketing:theirs design.ept
```

Or one mode for all conflicts:

```sh
enprot resolve --mode ours design.ept
```

After resolve, re-sign to record the merge decision:

```sh
enprot encrypt --anchor --signer bob-priv.pem -w Draft design.ept
git commit -am "Resolved Draft conflict; re-signed"
```

## Verifying provenance

Anyone with both pubkeys can verify the full history without
decrypting:

```sh
enprot verify-chain --trust-root keys/alice-pub.pem \
                    --trust-root keys/bob-pub.pem \
                    design.ept
```

The chain DAG is tamper-evident — removing, reordering, or
substituting any anchor breaks verification.

## Publishing the chain head

For external verifiers that only want "this is the latest state":

```sh
enprot snapshot design.ept
# Prints: 7a3c9f4b… (the current head hash)
```

Publish that hash out-of-band (release notes, signing party, etc).
Verifiers check:

```sh
enprot pin 7a3c9f4b… design.ept
```

## What this demonstrates

- Multi-signer chain anchors work locally without Confium.
- WORD-region merge produces valid host-language source (CONFLICT
  blocks live inside comments).
- Verification doesn't need to decrypt — chain anchors carry their
  own proof.
- Pinning gives reproducible verification at any downstream point.

## Next: scaling to distributed trust

When the team grows beyond ~5 people or needs hardware key custody,
swap local PEM signing for Confium threshold sessions:

```sh
enprot encrypt --anchor \
    --signer confium://release-approvers-session \
    -w Draft design.ept
```

See [Classified documents cookbook](classified-documents.md) for
the threshold + attribute-based access pattern.
