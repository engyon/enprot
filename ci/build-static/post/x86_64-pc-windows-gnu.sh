# TODO: maybe check DLL dependencies here
file "$EXE_PATH"

docker run --rm -v "$PWD:/project" -w "/project" "$img" wine "$EXE_PATH" --version | grep "$PROJECT_NAME $RELEASE_TAG"

