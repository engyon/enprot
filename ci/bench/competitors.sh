#!/bin/sh
# Competitive benchmark harness: enprot vs SOPS vs git-crypt.
# Run by .github/workflows/benchmark-comparison.yml (weekly + manual);
# the workflow installs the competitors and builds enprot. Emits
# results.json + results.md in $OUT_DIR (default: ./bench-results).
#
# Axes (the ones that matter for committed-ciphertext workflows):
#   throughput — encrypt/decrypt of a corpus at three sizes
#   diff noise — how many ciphertext lines change for a one-line
#                plaintext edit (the review/diff cost of the format)
#   merge      — can two parties editing DIFFERENT secrets in one
#                file merge cleanly (git merge-file, 3-way)
set -eu
OUT_DIR="${OUT_DIR:-./bench-results}"
ENPROT="${ENPROT:-enprot}"
SOPS="${SOPS:-sops}"
AGE_KEYGEN="${AGE_KEYGEN:-age-keygen}"
GIT_CRYPT="${GIT_CRYPT:-git-crypt}"
mkdir -p "$OUT_DIR"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

now_ms() { date +%s%3N; }

# --- corpus ---------------------------------------------------------
# A source-ish file with S secret segments ("words") interleaved with
# plain text; sizes approximate a config module, a document, a bundle.
make_corpus() {
    dir=$1; size=$2; words=$3
    mkdir -p "$dir"
    for w in $(seq 1 "$words"); do
        printf 'plain context for segment %s\n' "$w" >> "$dir/file.txt"
        if [ "$TOOL" = enprot ]; then
            printf '// <( BEGIN W%s )>\nsecret payload %s %s\n// <( END W%s )>\n' \
                "$w" "$(head -c 512 /dev/zero | tr "\0" "a")" "$w" "$w" >> "$dir/file.txt"
        else
            # sops/git-crypt see raw text; secrets are plain lines
            i=0; while [ $i -lt $((size / words / 64)) ]; do
                printf 'secret_payload_%s_line_%s\n' "$w" "$i" >> "$dir/file.txt"
                i=$((i + 1))
            done
        fi
        printf 'trailing plain %s\n' "$w" >> "$dir/file.txt"
    done
}

# --- per-tool setup --------------------------------------------------
setup_enprot() { :; }
encrypt_enprot() { "$ENPROT" encrypt -w W1 -k W1=pw --cipher aes-256-gcm-det "$1/file.txt"; }
decrypt_enprot() { "$ENPROT" decrypt -w W1 -k W1=pw "$1/file.txt"; }

setup_sops() {
    # age-keygen: the SECRET key goes to -o; the matching public key
    # prints with -y. The env var is how sops finds the identity at
    # decrypt time — without it sops falls back to
    # ~/.config/sops/age/keys.txt and the run dies there.
    # Idempotent: bench() invokes setup once per corpus size.
    [ -f "$WORK/age.key" ] || "$AGE_KEYGEN" -o "$WORK/age.key"
    "$AGE_KEYGEN" -y "$WORK/age.key" > "$WORK/recipients.txt"
    export SOPS_AGE_KEY_FILE="$WORK/age.key"
}
encrypt_sops() {
    # --age takes the recipient STRING (not a file); the secret key
    # reaches decrypt via SOPS_AGE_KEY_FILE, set in setup_sops.
    (cd "$1" && "$SOPS" encrypt --age "$(cat "$WORK/recipients.txt")" \
        --encrypted-regex 'secret_payload' file.txt > file.enc && mv file.enc file.txt)
}
decrypt_sops() {
    (cd "$1" && "$SOPS" decrypt file.txt > file.dec && mv file.dec file.txt)
}

setup_gitcrypt() {
    # A fresh repo per invocation: git-crypt lock/unlock cycles do not
    # compose on a shared working tree (second lock on a locked repo
    # errors).
    GC="$WORK/gc-$(basename "$1")"
    export GC
    mkdir -p "$GC" && (cd "$GC" && git init -q && "$GIT_CRYPT" init && \
        "$GIT_CRYPT" export-key "$WORK/gc-key" && echo "*.txt filter=git-crypt diff=git-crypt" > .gitattributes)
}
encrypt_gitcrypt() {
    (cd "$GC" && cp "$1/file.txt" . && git add file.txt && \
        git -c user.email=b@b -c user.name=b commit -qm x && "$GIT_CRYPT" lock)
    cp "$GC/file.txt" "$1/file.txt"
}
decrypt_gitcrypt() {
    cp "$1/file.txt" "$GC/file.txt"
    (cd "$GC" && "$GIT_CRYPT" unlock "$WORK/gc-key")
    cp "$GC/file.txt" "$1/file.txt"
}

# --- measurement -----------------------------------------------------
bench() { # tool size_bytes words label
    TOOL=$1; size=$2; words=$3
    d="$WORK/$TOOL-$size"
    rm -rf "$d"; mkdir -p "$d"
    TOOL=$TOOL make_corpus "$d" "$size" "$words" >/dev/null
    cp -r "$d" "$d-plain"
    "setup_$TOOL" 2>>"$OUT_DIR/errors.log"
    t0=$(now_ms); "encrypt_$TOOL" "$d" 2>>"$OUT_DIR/errors.log"; t1=$(now_ms)
    enc_bytes=$(wc -c < "$d/file.txt" | tr -d ' ')
    plain_bytes=$(wc -c < "$d-plain/file.txt" | tr -d ' ')
    t2=$(now_ms); "decrypt_$TOOL" "$d" 2>>"$OUT_DIR/errors.log"; t3=$(now_ms)
    echo "{\"tool\":\"$TOOL\",\"bytes\":$plain_bytes,\"words\":$words,\"encrypt_ms\":$((t1-t0)),\"decrypt_ms\":$((t3-t2)),\"overhead_pct\":$(( (enc_bytes * 100 / plain_bytes) - 100 ))}"
}

diffnoise() { # tool — ciphertext lines changed for a one-line plaintext edit
    TOOL=$1; d="$WORK/noise-$TOOL"
    rm -rf "$d"; mkdir -p "$d"
    TOOL=$TOOL make_corpus "$d" 8192 3 >/dev/null
    "encrypt_$TOOL" "$d" >/dev/null 2>&1
    cp "$d/file.txt" "$WORK/noise-before"
    sed -i 's/secret payload 2 /secret payload 2 X/' "$d-plain/file.txt" 2>/dev/null || true
    # re-encrypt from plain: tools differ in-place; redo cycle
    rm -rf "$d"; mkdir -p "$d"; TOOL=$TOOL make_corpus "$d" 8192 3 >/dev/null
    sed -i 's/secret payload 2 /secret payload 2 X/' "$d/file.txt"
    sed -i 's/trailing plain 2/trailing plain 2/' "$d/file.txt"
    "encrypt_$TOOL" "$d" >/dev/null 2>&1
    changed=$(diff "$WORK/noise-before" "$d/file.txt" | grep -c '^<' || true)
    echo "{\"tool\":\"$TOOL\",\"metric\":\"diff_noise\",\"changed_lines\":$changed}"
}

merge3() { # tool — two parties edit DIFFERENT secrets; clean merge?
    TOOL=$1; d="$WORK/merge-$TOOL"; rm -rf "$d"; mkdir -p "$d"
    TOOL=$TOOL make_corpus "$d" 8192 4 >/dev/null
    "encrypt_$TOOL" "$d" >/dev/null 2>&1 || true
    cp "$d/file.txt" "$WORK/base"
    sed 's/secret payload 1 /A edited 1 /' "$WORK/base" > "$WORK/ours"
    sed 's/secret payload 3 /B edited 3 /' "$WORK/base" > "$WORK/theirs"
    if git merge-file -p "$WORK/ours" "$WORK/base" "$WORK/theirs" > "$WORK/merged" 2>/dev/null; then
        result=clean
    else
        result=conflict
    fi
    echo "{\"tool\":\"$TOOL\",\"metric\":\"merge3\",\"different_secrets\":\"$result\"}"
}

# --- run -------------------------------------------------------------
{
  bench enprot 16384 8
  bench enprot 262144 32
  bench enprot 4194304 64
  bench sops 16384 8
  bench sops 262144 32
  bench sops 4194304 64
  bench gitcrypt 16384 8
  bench gitcrypt 262144 32
  bench gitcrypt 4194304 64
  diffnoise enprot; diffnoise sops; diffnoise gitcrypt
  merge3 enprot; merge3 sops; merge3 gitcrypt
} | tee "$OUT_DIR/results.jsonl"

echo "wrote $OUT_DIR/results.jsonl ($(wc -l < "$OUT_DIR/results.jsonl") rows)"
