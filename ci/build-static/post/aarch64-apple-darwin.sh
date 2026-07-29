# check
brew install ripgrep
otool -L "$EXE_PATH" | rg -PU "^$EXE_PATH:
\t/usr/lib/libc\+\+.1.dylib \(compatibility version \d+\.\d+\.\d+, current version \d+\.\d+\.\d+\)
\t/usr/lib/libSystem.B.dylib \(compatibility version \d+\.\d+\.\d+, current version \d+\.\d+\.\d+\)
\t/usr/lib/libresolv.9.dylib \(compatibility version \d+\.\d+\.\d+, current version \d+\.\d+\.\d+\)$"

"$EXE_PATH" --version | grep "$PROJECT_NAME $RELEASE_TAG"

