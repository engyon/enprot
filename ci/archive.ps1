$name = "$Env:PROJECT_NAME-$Env:RELEASE_TAG-$Env:TARGET"
New-Item -ItemType Directory -Force -Path $(Join-Path 'staging' "$name")

ForEach ($file in "$Env:EXE_PATH",'README.adoc') {
  Copy-Item -LiteralPath "$file" -Destination $(Join-Path 'staging' "$name")
}
New-Item -ItemType Directory -Force -Path 'archives'
$outname = Join-Path "$PWD" $(Join-Path 'archives' "$name.zip")
Push-Location -LiteralPath 'staging'
& 7z a "$outname" "$name"
Pop-Location

