# check
file "$EXE_PATH" | grep 'statically linked'

"$EXE_PATH" --version | grep "$PROJECT_NAME $RELEASE_TAG"

