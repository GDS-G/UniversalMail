$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
foreach ($name in @('Start-UniversalMail.ps1', 'Stop-UniversalMail.ps1')) {
    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root $name), [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count) { throw ($errors | Out-String) }
}
$script:calls = @()
function global:docker {
    $script:calls += ,@($args)
    $global:LASTEXITCODE = 0
    if ($args[0] -eq 'context') { 'npipe:////./pipe/dockerDesktopLinuxEngine'; return }
    if ($args[0] -eq 'info') { 'linux'; return }
    if ($args[0] -eq 'compose' -and $args[1] -eq 'version') { '2.30.0'; return }
    throw 'Read-only preflight unexpectedly tried to modify Docker.'
}
try {
    & (Join-Path $root 'Start-UniversalMail.ps1') -CheckOnly
    if ($script:calls.Count -ne 3) { throw 'Preflight did not check context, engine and Compose exactly once.' }
    if (Test-Path (Join-Path $root '.env')) { throw 'CheckOnly created configuration.' }
    Write-Host 'PowerShell parsing and read-only preflight passed.'
} finally { Remove-Item Function:\docker }
