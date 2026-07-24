# Git smudge/clean filters (deferred)

`enprot smudge` and `enprot clean` for `.gitattributes` integration.
Depends on #05 (config file) for non-interactive key source.
Needs deterministic AEAD (already implemented) so clean→smudge is
idempotent and git diffs are minimal.
