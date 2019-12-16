if [[ $TARGET == *"windows"* ]]; then
  ext="zip"
  cmd="zip -r"
else
  ext="tar.gz"
  cmd="tar czf"
fi

name="$PROJECT_NAME-$RELEASE_TAG-$TARGET"
mkdir -p "staging/$name"
files=("$EXE_PATH" README.adoc)
for file in "${files[@]}"; do
  cp "$file" "staging/$name"
done
mkdir -p archives
outname="$PWD/archives/$name.$ext"
pushd staging
$cmd "$outname" "$name"
popd

