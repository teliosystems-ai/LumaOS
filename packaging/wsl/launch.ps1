[CmdletBinding(PositionalBinding = $false)]
param(
    [string] $Distribution = "Ubuntu-24.04",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $LumaArguments
)

$ErrorActionPreference = "Stop"
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "WSL2 is not available."
}

& wsl.exe --distribution $Distribution -- sh -lc 'test -x "$HOME/.local/bin/luma-os"'
if ($LASTEXITCODE -ne 0) {
    throw "Luma OS is not installed in '$Distribution'. Run .\packaging\wsl\install.ps1 first."
}

& wsl.exe --distribution $Distribution -- bash -lc 'exec "$HOME/.local/bin/luma-os" "$@"' luma-os @LumaArguments
exit $LASTEXITCODE
