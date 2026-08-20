#!/bin/sh
# Verify cross-version fixtures with a given enprot binary
# (TODO.complete/60). Usage:
#
#   tests/cross-version/run.sh <enprot-binary>
#
# Walks every v*/ directory and, per meta.toml, decrypts (or
# fetches) each fixture, checking the recovered plaintext's
# SHA3-256. enprot transforms files IN PLACE, so each fixture is
# copied to a tempdir first — the committed tree is never
# touched and the script is idempotent. Exits non-zero on the
# first mismatch, naming the version and fixture — the CI log
# then says exactly which compatibility promise broke.
#
# macOS note: system /bin/sh strips DYLD_*, so pass a WRAPPER
# script that sets DYLD_LIBRARY_PATH and execs the real binary;
# on Linux the release binary is self-contained.
set -eu

bin=$1
here=$(cd "$(dirname "$0")" && pwd)
fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# hash a file with sha3-256 (python3: present on CI runners and dev macs)
sha3() {
  python3 -c 'import hashlib,sys; print(hashlib.sha3_256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"
}

toml_get() { sed -n "s/^$1 *= *\"\(.*\)\"$/\1/p" "$2"; }

for dir in "$here"/v*/; do
  version=$(basename "$dir")
  meta="$dir/meta.toml"
  [ -f "$meta" ] || continue
  word=$(toml_get word "$meta")
  password=$(toml_get password "$meta")
  want=$(toml_get plaintext_sha3_256 "$meta")

  for fixture in "$dir"*.ept; do
    [ -e "$fixture" ] || continue
    name=$(basename "$fixture")
    case $name in
      encrypt_*) op=decrypt ;;
      store_*)   op=fetch ;;
      *)         echo "SKIP $version/$name (unknown op)"; continue ;;
    esac

    work="$tmp/$name"
    cp "$fixture" "$work"
    # STORED fixtures reference the CAS via relative hash — point
    # -c at the fixture's own cas/ dir. inline fixtures ignore it.
    if "$bin" "$op" -w "$word" -k "${word}=${password}" \
         -c "$dir/cas" "$work" 2>"$tmp/err"; then
      got=$(sha3 "$work")
    else
      echo "FAIL $version/$name: $op exited $? — $(head -1 "$tmp/err")"
      fail=1
      continue
    fi

    if [ "$got" != "$want" ]; then
      echo "FAIL $version/$name: sha3 $got != $want"
      fail=1
    else
      echo "OK   $version/$name ($op)"
    fi
  done
done

exit $fail
