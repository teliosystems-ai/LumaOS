[CmdletBinding()]
param(
    [string] $Distribution = "Ubuntu-24.04",
    [switch] $Upgrade
)

$ErrorActionPreference = "Stop"
$ProjectDirectory = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "WSL2 is not available. Install it explicitly with: wsl --install -d Ubuntu-24.04"
}

$Distributions = @(& wsl.exe --list --quiet | ForEach-Object { $_.Trim().Replace([char]0, "") })
if ($Distributions -notcontains $Distribution) {
    throw "WSL distribution '$Distribution' is not installed. Install it explicitly with: wsl --install -d Ubuntu-24.04"
}

$InstallArguments = @("bash", "./scripts/install-user.sh")
if ($Upgrade) {
    $InstallArguments += "--upgrade"
}

Write-Host "Installing Luma OS inside WSL distribution '$Distribution' without elevation..."
& wsl.exe --distribution $Distribution --cd $ProjectDirectory -- @InstallArguments
if ($LASTEXITCODE -ne 0) {
    throw "The WSL user install failed with exit code $LASTEXITCODE."
}

Write-Host "Install complete. Launch with .\packaging\wsl\launch.ps1"
