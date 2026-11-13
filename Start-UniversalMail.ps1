#requires -Version 5.1
<#
.SYNOPSIS
Build and start UniversalMail on this Windows computer using Docker Desktop.
.DESCRIPTION
Checks for a local Linux Docker engine, generates keys only on first run, starts
loopback-only containers, verifies readiness and opens the guided setup page.
Does not install Docker, alter Windows execution policy, open firewall ports,
connect mailboxes, or modify an existing .env. Use -CheckOnly for a read-only check.
#>
[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)][int]$Port = 8000,
    [switch]$CheckOnly,
    [switch]$CopyKey,
    [switch]$NoBrowser
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Image = 'universalmail:0.5.0'

function Invoke-DockerChecked {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Docker command failed. Read its output above; no successful setup is being claimed.' }
}

function Protect-Configuration {
    param([string]$Path)
    if ($env:OS -ne 'Windows_NT') { return }
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')))
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', 'Allow')))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

Push-Location $Root
try {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'Docker was not found. Install Docker Desktop for Windows, enable its Linux/WSL 2 engine, start it, then run this script again. See docs/LOCAL_SETUP.md.'
    }
    if ($Root.Contains(',')) { throw 'Move the project to a folder without a comma; Docker bind-mount syntax cannot safely use this path.' }
    if ($env:DOCKER_HOST -and $env:DOCKER_HOST -notmatch '^(unix|npipe)://') {
        throw 'DOCKER_HOST targets a remote engine. This launcher only changes the computer on which it is run.'
    }
    $endpoint = (& docker context inspect --format '{{.Endpoints.docker.Host}}' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $endpoint -notmatch '^(unix|npipe)://') {
        throw 'Select a local Docker Desktop context first. Remote Docker contexts are not used by this launcher.'
    }
    $engine = (& docker info --format '{{.OSType}}' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop is not ready. Start it and wait for the engine to report running, then rerun.' }
    if ($engine -ne 'linux') { throw 'Switch Docker Desktop to Linux containers. Windows-container mode is not supported.' }
    $version = (& docker compose version --short | Out-String).Trim().TrimStart('v')
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '^(\d+)\.(\d+)') { throw 'Docker Compose v2.24 or newer is required.' }
    if (([int]$Matches[1] -lt 2) -or (([int]$Matches[1] -eq 2) -and ([int]$Matches[2] -lt 24))) { throw 'Upgrade Docker Compose to v2.24 or newer.' }
    Write-Host 'Compatible local Linux Docker engine and Compose found.'
    if ($CheckOnly) { Write-Host 'Read-only check complete. No configuration or containers were changed.'; return }
    # Prevent shell-environment precedence from silently replacing the generated keys.
    $conflicts = @(Get-ChildItem Env: | Where-Object { $_.Name -match '^(UNIVERSALMAIL_|GOOGLE_CLIENT_|MICROSOFT_CLIENT_|MICROSOFT_TENANT$)' })
    if ($conflicts.Count -gt 0) { throw 'Deployment variables already exist in this PowerShell process. Open a clean PowerShell session or use the documented manual Compose setup; values will not be overwritten.' }
    if (-not (Test-Path -LiteralPath (Join-Path $Root '.env'))) {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        try { $listener.Start() } catch { throw "Port $Port is occupied. Rerun with -Port and an unused port." } finally { $listener.Stop() }
    }
    Write-Host 'Building the backend image from this checkout...'
    Invoke-DockerChecked -Arguments @('build', '-t', $Image, '.')
    Invoke-DockerChecked -Arguments @('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--mount', "type=bind,source=$Root,target=/workspace", '--entrypoint', 'python', $Image, '/app/scripts/configure.py', '--directory', '/workspace', '--mode', 'local', '--port', "$Port")
    $envPath = Join-Path $Root '.env'
    Protect-Configuration -Path $envPath
    Invoke-DockerChecked -Arguments @('compose', '--env-file', '.env', '-p', 'universalmail', '-f', 'compose.yaml', 'up', '-d', '--wait', '--wait-timeout', '120')
    $health = Invoke-RestMethod -Uri "http://localhost:$Port/health" -TimeoutSec 10
    if ($health.service -ne 'universalmail' -or $health.status -ne 'ok' -or $health.version -ne '0.5.0') { throw 'The expected backend version did not pass the health check.' }
    if ($CopyKey) {
        $line = Get-Content -LiteralPath $envPath | Where-Object { $_ -match '^UNIVERSALMAIL_API_KEY=' } | Select-Object -First 1
        if (-not $line) { throw 'No administration key found in .env.' }
        $adminKey = $line.Substring($line.IndexOf('=') + 1).Trim().Trim([char[]]@([char]34, [char]39))
        Set-Clipboard -Value $adminKey
        $adminKey = $null
        Write-Host 'Administration key copied to your clipboard. Paste it into the setup page.'
    } else {
        Write-Host 'Use UNIVERSALMAIL_API_KEY from your private .env file to unlock setup, or rerun with -CopyKey.'
    }
    Write-Host "Backend verified at http://localhost:$Port/setup. No mailbox is connected by this script."
    Write-Host 'The installed ChatGPT plugin is not connected yet.'
    if (-not $NoBrowser) { Start-Process "http://localhost:$Port/setup" }
} finally {
    Pop-Location
}
