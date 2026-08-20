# check
file "$EXE_PATH" | grep 'statically linked'

# Cross-arch: the aarch64 binary cannot execute on the x86_64
# runner ("Exec format error") — verify the ELF arch + linkage
# statically instead.
file "$EXE_PATH" | grep -q 'ARM aarch64' || {
  echo "not an aarch64 binary: $(file "$EXE_PATH")"; exit 1; }

