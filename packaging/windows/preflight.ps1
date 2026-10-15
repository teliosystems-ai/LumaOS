[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z]$')][string] $StorageDrive = 'D',
    [ValidatePattern('^LumaOS-[A-Za-z0-9-]{1,48}$')][string] $DistributionName = 'LumaOS-Dev',
    [ValidateRange(1,1024)][int] $GuestMemoryGiB = 12,
    [string] $StoragePlanPath,
    [string] $ReleasePolicyPath
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Luma.Preflight.psm1') -Force
$observation = Get-LumaWindowsObservation -StorageDrive $StorageDrive
$storagePlan = if ($PSBoundParameters.ContainsKey('StoragePlanPath')) { Read-LumaPlanningJson $StoragePlanPath } else { $null }
$releasePolicy = if ($PSBoundParameters.ContainsKey('ReleasePolicyPath')) { Read-LumaPlanningJson $ReleasePolicyPath } else { $null }
Test-LumaWindowsPreflight -Observation $observation -DistributionName $DistributionName `
    -GuestMemoryGiB $GuestMemoryGiB -StoragePlan $storagePlan -ReleasePolicy $releasePolicy | ConvertTo-Json -Depth 12
