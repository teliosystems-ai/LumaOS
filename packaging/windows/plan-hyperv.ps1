[CmdletBinding()]
param([Parameter(Mandatory)][string] $ManifestPath,[Parameter(Mandatory)][string] $ManifestSha256,
    [Parameter(Mandatory)][string] $RawSha256,[Parameter(Mandatory)][string] $VhdxPath,
    [Parameter(Mandatory)][string] $VhdxSha256,[ValidatePattern('\A[A-Za-z]\z')][string] $StorageDrive='D',
    [ValidatePattern('\ALumaOS-[A-Za-z0-9-]{1,48}\z')][string] $Name='LumaOS-Desktop-Lab',
    [ValidateRange(4,64)][int] $GuestMemoryGiB=8,[ValidateRange(1,32)][int] $CpuCount=4,
    [ValidateRange(64,2048)][int] $InstalledDiskGiB=128,
    [string] $ObservationPath,[string] $ObservationSha256)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Luma.HyperV.psm1') -Force
if ($PSBoundParameters.ContainsKey('ObservationPath') -ne $PSBoundParameters.ContainsKey('ObservationSha256')) {
    throw 'Captured planning requires both observation path and independent SHA256; no fallback is supported.'
}
$captured=$PSBoundParameters.ContainsKey('ObservationPath')
$manifest=Read-LumaHyperVManifest -Path $ManifestPath -Sha256 $ManifestSha256
$null=Test-LumaHyperVMedia -Manifest $manifest -ExpectedRawSha256 $RawSha256 -ExpectedVhdxSha256 $VhdxSha256
$media=[Luma.Windows.HyperVImageLease]::Acquire($VhdxPath,$VhdxSha256,[long]$manifest.output_bytes)
try {
    $observation=if ($captured) {
        Read-LumaHyperVCapturedObservation -Path $ObservationPath -Sha256 $ObservationSha256
    } else { Get-LumaHyperVObservation -StorageDrive $StorageDrive }
    $plan=Test-LumaHyperVPlan -Observation $observation -Manifest $manifest -ExpectedRawSha256 $RawSha256 `
        -ExpectedVhdxSha256 $VhdxSha256 -Name $Name -GuestMemoryGiB $GuestMemoryGiB -CpuCount $CpuCount -InstalledDiskGiB $InstalledDiskGiB
    $media.Check()
    $plan | Add-Member -NotePropertyName actual_vhdx_held_and_hashed -NotePropertyValue $true
    $plan | Add-Member -NotePropertyName observation_source -NotePropertyValue $(if ($captured) {'pinned-captured-data'} else {'local-read-only-query'})
    $plan | Add-Member -NotePropertyName observation_fresh -NotePropertyValue (-not $captured)
    $plan | ConvertTo-Json -Depth 10
} finally { $media.Dispose() }
