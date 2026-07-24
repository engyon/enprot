# 03 — Snap: core22 + Botan 3

## Goal

Bring `snap/snapcraft.yaml` in line with current snapd and Botan 3 packaging.

## Files

- `snap/snapcraft.yaml`

## Approach

| Field | Before | After | Reason |
|-------|--------|-------|--------|
| `base` | `core20` | `core22` | core20 EOL; core22 is the current LTS base |
| `build-packages` | `libbotan-2-dev` | `libbotan-3-dev` | Botan 3 |
| `stage-packages` | `botan` | `libbotan-3-1` | runtime shared lib on Debian/Ubuntu |

`libbotan-3-1` is the runtime package name in Debian/Ubuntu for Botan 3.x.
The metapackage `botan` may pull a different version depending on suite, so
pin the explicit library package.

The `plugin: rust` snap part uses `snapcraft-rust` and will build the crate
against the host's `libbotan-3-dev`. No source change needed beyond the
package swap.

## Verification

- `snapcraft --use-lxd` locally if LXD is available.
- Otherwise, validate the YAML parses and the deploy workflow runs in CI.

## Rollback

Revert the YAML.
