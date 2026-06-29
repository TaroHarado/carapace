param(
    [string]$BinaryPath = ".\target\release\cape.exe",
    [int]$Port = 8484,
    [string]$OutDir = ".\captures"
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$bin = (Resolve-Path $BinaryPath).Path
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

$browsers = @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe",
    "$env:LocalAppData\Google\Chrome\Application\chrome.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $browsers) {
    throw "No Chrome/Edge binary found for headless capture."
}

$browser = $browsers
$stdout = Join-Path $env:TEMP 'saferouter-capture.out.log'
$stderr = Join-Path $env:TEMP 'saferouter-capture.err.log'
$proc = Start-Process -FilePath $bin -ArgumentList @('web', '--listen', "127.0.0.1:$Port", '--site', 'site') -PassThru -WindowStyle Hidden -WorkingDirectory $root -RedirectStandardOutput $stdout -RedirectStandardError $stderr

try {
    for ($i = 0; $i -lt 50; $i++) {
        try {
            Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/health" -Method Get | Out-Null
            break
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }

    $shotDesktop = Join-Path $OutDir 'saferouter-1440.png'
    $shotMobile  = Join-Path $OutDir 'saferouter-390.png'

    Start-Process -FilePath $browser -ArgumentList @('--headless=new', '--disable-gpu', '--window-size=1440,1100', "--screenshot=$shotDesktop", "http://127.0.0.1:$Port") -Wait | Out-Null
    Start-Process -FilePath $browser -ArgumentList @('--headless=new', '--disable-gpu', '--window-size=390,1200', "--screenshot=$shotMobile", "http://127.0.0.1:$Port") -Wait | Out-Null

    Write-Host "wrote $shotDesktop"
    Write-Host "wrote $shotMobile"
}
finally {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force
    }
}
