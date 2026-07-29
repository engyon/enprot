# Verify the binary runs. Set DYLD_LIBRARY_PATH so the dynamic linker
# can find librnp/botan at runtime (same requirement as `cargo test`
# locally with Homebrew librnp — see CLAUDE.md).
export DYLD_LIBRARY_PATH="${PREFIX}/lib:${DYLD_LIBRARY_PATH:-}"

"$EXE_PATH" --version | grep "$PROJECT_NAME $RELEASE_TAG"

# List dynamic dependencies for diagnostic purposes. We don't enforce
# a strict set — the macOS binary dynamically links against librnp
# and botan (the Homebrew/source-built versions). Static linking on
# macOS is a future enhancement.
otool -L "$EXE_PATH" || true
