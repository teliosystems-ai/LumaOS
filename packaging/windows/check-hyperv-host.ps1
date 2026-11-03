[CmdletBinding()]
param(
    [ValidatePattern('\A[A-Za-z]\z')][string] $StorageDrive = 'D',
    [ValidatePattern('\A[A-Za-z]\z')][string] $ImageDrive = 'D',
    [ValidatePattern('\ALumaOS-[A-Za-z0-9-]{1,48}\z')][string] $Name = 'LumaOS-Desktop-Lab',
    [ValidateRange(8,64)][int] $GuestMemoryGiB = 8,
    [ValidateRange(1,32)][int] $CpuCount = 4,
    [ValidateRange(64,2048)][int] $InstalledDiskGiB = 128,
    [ValidateRange(2,32)][int] $WindowsHeadroomGiB = 4,
    [ValidateRange(1,16)][int] $StartMarginGiB = 2,
    [ValidateRange(1,64)][int] $MediaGiB = 16
)
# Read-only Profile V host prerequisite check. It queries CIM, the registry,
# processes, services and drives, and changes nothing: no feature, service,
# WSL, firmware or Hyper-V state. Elevation is optional; without it some
# answers degrade to "unknown" or a non-privileged fallback.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Luma.HyperV.psm1') -Force
$observation = Get-LumaHyperVHostObservation -StorageDrive $StorageDrive -ImageDrive $ImageDrive
Test-LumaHyperVHost -Observation $observation -Name $Name -GuestMemoryGiB $GuestMemoryGiB -CpuCount $CpuCount `
    -InstalledDiskGiB $InstalledDiskGiB -WindowsHeadroomGiB $WindowsHeadroomGiB -StartMarginGiB $StartMarginGiB `
    -MediaBytes ([long]$MediaGiB * 1GB) | ConvertTo-Json -Depth 8
