param(
    [string]$BuildDirectory = "",
    [string]$QtBin = "C:/Qt/6.11.0/mingw_64/bin"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($BuildDirectory)) {
    $projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "../..")).Path
    $BuildDirectory = Join-Path $projectRoot "out/qt-release"
}

$executable = Join-Path $BuildDirectory "bin/VM protect unpack.exe"
$deployTool = Join-Path $QtBin "windeployqt.exe"

if (!(Test-Path -LiteralPath $executable)) {
    throw "Build the application first: $executable"
}

if (!(Test-Path -LiteralPath $deployTool)) {
    throw "Qt deployment tool missing: $deployTool"
}

& $deployTool --release --no-translations --no-opengl-sw --no-system-d3d-compiler $executable
if ($LASTEXITCODE -ne 0) {
    throw "Qt deployment failed with exit code $LASTEXITCODE"
}

Write-Output "Runnable application: $executable"
