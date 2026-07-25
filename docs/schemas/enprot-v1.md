# JSON output schema — `enprot/v1`

`enprot --format json` is supported on the inspection subcommands
(`capabilities`, `list`, `verify-chain`). Every payload is wrapped in a
versioned envelope:

```json
{ "$schema": "enprot/v1", ...payload }
```

The schema tag lets consumers pin a version independent of the enprot
release. Additive changes (new optional fields) keep `enprot/v1`; a
breaking shape change will bump to `enprot/v2`.

## `capabilities`

```json
{
  "$schema": "enprot/v1",
  "capabilities": [
    { "tier": "viewer" },
    { "tier": "reader" },
    { "tier": "decryptor", "word": "Agent_007" },
    { "tier": "signer",    "key_fp": "9f3a7b…" },
    { "tier": "verifier",  "key_fp": "1c8d2e…" }
  ]
}
```

`tier` is one of `viewer`, `reader`, `decryptor`, `signer`, `verifier`.
`word` is present only on `decryptor`; `key_fp` is present only on
`signer`/`verifier`.

## `list`

```json
{
  "$schema": "enprot/v1",
  "files": [
    {
      "path": "input.ept",
      "nodes": [
        {
          "type": "begin-end",
          "word": "Agent_007",
          "depth": 0,
          "children": [
            { "type": "encrypted", "word": "Agent_007", "depth": 1,
              "cipher": "aes-256-siv", "pbkdf": "argon2" }
          ]
        },
        { "type": "stored",  "word": "Agent_007", "depth": 0, "cas": "abc123…" },
        { "type": "chain",   "word": "", "depth": 0,
          "signer": "ed25519:9f3a7b…", "payload": "575d69…" },
        { "type": "include", "word": "575d69f5…", "depth": 0 }
      ]
    }
  ]
}
```

`type` is one of `begin-end`, `encrypted`, `stored`, `chain`, `include`.
Optional fields (`cipher`, `pbkdf`, `cas`, `signer`, `payload`,
`children`) are omitted when empty. `Plain` and `Data` nodes never
appear in `list` output.

## `verify-chain`

```json
{
  "$schema": "enprot/v1",
  "ok": true,
  "files": [
    {
      "path": "input.ept",
      "ok": true,
      "anchors_total": 3,
      "signers": ["ed25519:9f3a7b…"],
      "forks": [
        { "anchor": "abc123…", "parents": ["000000…"] }
      ],
      "errors": [
        { "anchor": "abc123…", "message": "no pubkey registered for signer fingerprint …" }
      ]
    }
  ]
}
```

Top-level `ok` is the AND of every file's `ok`. `forks` lists anchor
IDs that have no children (DAG tips); multiple tips mean a fork.
`errors` is empty on success.
