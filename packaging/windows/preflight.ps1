[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z]$')][string] $StorageDrive = 'D',
    [ValidatePattern('^LumaOS-[A-Za-z0-9-]{1,48}$')][string] $DistributionName = 'LumaOS-Dev',
    [ValidateRange(1,1024)][int] $GuestMemoryGiB = 12
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Luma.Preflight.psm1') -Force
$observation = Get-LumaWindowsObservation -StorageDrive $StorageDrive
Test-LumaWindowsPreflight -Observation $observation -DistributionName $DistributionName `
    -GuestMemoryGiB $GuestMemoryGiB | ConvertTo-Json -Depth 12
