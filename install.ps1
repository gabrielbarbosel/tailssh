<#
.SYNOPSIS
    tailssh installer (Windows) — fetch the static binary and join the mesh.
    Requires Tailscale. Run in an elevated PowerShell.
.EXAMPLE
    irm https://raw.githubusercontent.com/gabrielbarbosel/tailssh/main/install.ps1 | iex
#>
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$repo = 'gabrielbarbosel/tailssh'

function Say($m) { Write-Host "[tailssh] $m" -ForegroundColor Cyan }

# Elevation guard (in case #Requires is bypassed, e.g. via iex).
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This installer must be run in an elevated PowerShell (Run as Administrator).'
}

if (-not (Get-Command tailscale -ErrorAction SilentlyContinue) -and
    -not (Test-Path "$env:ProgramFiles\Tailscale\tailscale.exe")) {
    throw 'Tailscale is required first: https://tailscale.com/download'
}

# PROCESSOR_ARCHITEW6432 is set when a 32-bit process runs on a 64-bit host;
# it reflects the true machine architecture, so prefer it when present.
$procArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($procArch) {
    'ARM64' { $arch = 'arm64' }
    'AMD64' { $arch = 'amd64' }
    default { throw "Unsupported processor architecture: $procArch (only amd64 and arm64 are supported)." }
}
$bin = "tailssh-windows-$arch.exe"
$url = "https://github.com/$repo/releases/latest/download/$bin"

$dir = "$env:ProgramFiles\tailssh"
$dest = "$dir\tailssh.exe"
New-Item -ItemType Directory -Force $dir | Out-Null

# Stop any running instance first: Windows locks a running .exe, so an in-place
# upgrade fails to overwrite it otherwise. The `up --yes` below re-arms the daemon.
Get-ScheduledTask -TaskName 'tailssh' -ErrorAction SilentlyContinue | Stop-ScheduledTask -ErrorAction SilentlyContinue
Get-Process -Name 'tailssh' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

Say "downloading $bin..."
# Force TLS 1.2 so Invoke-WebRequest works on PowerShell 5.1 hosts (default may be SSL3/TLS1.0).
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
# Download beside the target then move into place, so a failed download never leaves
# a half-written binary at $dest.
$tmp = "$dest.new"
Invoke-WebRequest -Uri $url -OutFile $tmp
Move-Item -Force -Path $tmp -Destination $dest

# Put tailssh on the machine PATH (idempotent).
# Write the registry value directly with -Type ExpandString: the .NET
# SetEnvironmentVariable API rewrites Path as REG_SZ, which flattens any
# %VAR% references already in the system PATH and corrupts it.
$envKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$machinePath = (Get-ItemProperty -Path $envKey -Name 'Path').Path
if ($machinePath -notlike "*$dir*") {
    $newPath = $machinePath.TrimEnd(';') + ';' + $dir
    Set-ItemProperty -Path $envKey -Name 'Path' -Value $newPath -Type ExpandString
    Say 'added tailssh to system PATH (restart your shell to pick it up)'
}
Say "installed -> $dest"

Say 'setting up this device (up --yes)...'
& $dest up --yes
