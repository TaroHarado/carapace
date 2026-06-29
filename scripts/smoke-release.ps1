param(
    [string]$BinaryPath = ".\\cape.exe"
)

$ErrorActionPreference = 'Stop'

function Invoke-Step($label, [scriptblock]$action) {
    & $action
    if ($LASTEXITCODE -ne 0) {
        throw "$label failed with exit code $LASTEXITCODE"
    }
    Write-Host "${label}: ok"
}

Write-Host "== cape smoke (windows) =="
Invoke-Step 'help' { & $BinaryPath --help | Out-Null }
Invoke-Step 'audit' { & $BinaryPath audit | Out-Null }
Invoke-Step 'registry' { & $BinaryPath registry list | Out-Null }
Invoke-Step 'score' { & $BinaryPath score --help | Out-Null }

Write-Host "smoke: ok"
