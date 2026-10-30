param(
    [string]$Config = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not $Config) {
    $Config = Join-Path $root "config.json"
}
Push-Location $root
try {
    python -m l4wall run --config $Config
} finally {
    Pop-Location
}
exit $LASTEXITCODE

