param(
    [string]$Repo = 'TaroHarado/carapace'
)

$ErrorActionPreference = 'Stop'

$api = "https://api.github.com/repos/$Repo/releases/latest"
$release = Invoke-RestMethod -Uri $api -Method Get

$asset = $release.assets | Where-Object { $_.name -match 'x86_64-pc-windows-msvc\.zip$' } | Select-Object -First 1
if (-not $asset) {
    throw "Could not find Windows release asset in latest release."
}

$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path $env:TEMP 'carapace-release-smoke'
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Path $work | Out-Null

$zip = Join-Path $work $asset.name
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip
Expand-Archive -LiteralPath $zip -DestinationPath $work -Force

$bin = Join-Path $work 'cape.exe'
if (!(Test-Path $bin)) {
    throw "Extracted archive does not contain cape.exe"
}

Write-Host "downloaded $($asset.name)"
& "$root\scripts\smoke-release.ps1" -BinaryPath $bin
& "$root\scripts\smoke-local.ps1" -BinaryPath $bin -Port 8592
