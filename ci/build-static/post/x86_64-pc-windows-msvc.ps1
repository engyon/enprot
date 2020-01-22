# TODO: maybe check DLL dependencies here

$result = & "$Env:EXE_PATH" --version | Select-String "$Env:PROJECT_NAME $Env:RELEASE_TAG"
if (-not $result) { exit 1 }

