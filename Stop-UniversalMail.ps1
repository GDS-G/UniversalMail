#requires -Version 5.1
[CmdletBinding()]param()
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    & docker compose --env-file .env -p universalmail -f compose.yaml stop
    if ($LASTEXITCODE -ne 0) { throw 'Docker stop failed.' }
    Write-Host 'Containers stopped. Configuration and data volume were preserved.'
} finally { Pop-Location }
