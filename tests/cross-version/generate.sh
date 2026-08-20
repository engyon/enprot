#!/bin/sh
# Generate cross-version fixtures with a specific enprot binary
# (TODO.complete/60). Usage:
#
#   tests/cross-version/generate.sh <enprot-binary> <version> <out-dir>
#
# The output is committed: every fixture is self-contained (inline
# DATA, or a cas/ dir for STORED) so the current build can decrypt
# it without any other state. Re-run for each release and commit
# the new directory.
set -eu

bin=$1 version=$2 out=$3

word=TEST
password=cross-version-fixture

mkdir -p "$out"
cd "$out"

cat > plaintext.txt <<'EOF'
The quick brown fox jumps over the lazy dog.
Cross-version fixture plaintext — enprot must decrypt this
regardless of the version that produced the ciphertext.
EOF

sha3=$(python3 -c 'import hashlib,sys; print(hashlib.sha3_256(open(sys.argv[1],"rb").read()).hexdigest())' plaintext.txt)

# Self-contained encrypted fixtures (inline DATA blocks).
"$bin" encrypt --inline -w "$word" -k "${word}=${password}" \
  -o encrypt_default.ept plaintext.txt
"$bin" encrypt --inline --cipher aes-256-gcm -w "$word" -k "${word}=${password}" \
  -o encrypt_aes256gcm.ept plaintext.txt
"$bin" encrypt --inline --cipher aes-256-gcm-siv-det -w "$word" -k "${word}=${password}" \
  -o encrypt_aes256gcmsiv_det.ept plaintext.txt
"$bin" encrypt --inline --compress -w "$word" -k "${word}=${password}" \
  -o encrypt_compress.ept plaintext.txt

# CAS-referenced STORED fixture: the cas/ dir ships with it.
mkdir -p cas
"$bin" store -w "$word" -c cas -o store_basic.ept plaintext.txt

cat > meta.toml <<EOF
version = "$version"
word = "$word"
password = "$password"
plaintext_sha3_256 = "$sha3"
EOF

rm plaintext.txt
echo "generated $out ($version, sha3 $sha3)"
