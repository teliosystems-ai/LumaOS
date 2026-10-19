[CmdletBinding()]
param([Parameter(Mandatory)][string] $ManifestPath,[Parameter(Mandatory)][string] $ManifestSha256,
    [Parameter(Mandatory)][string] $RawSha256,[Parameter(Mandatory)][string] $VhdxPath,
    [Parameter(Mandatory)][string] $VhdxSha256,[ValidatePattern('\A[A-Za-z]\z')][string] $StorageDrive='D',
    [ValidatePattern('\ALumaOS-[A-Za-z0-9-]{1,48}\z')][string] $Name='LumaOS-Desktop-Lab',
    [ValidateRange(4,64)][int] $GuestMemoryGiB=8,[ValidateRange(1,32)][int] $CpuCount=4,
    [ValidateRange(64,2048)][int] $InstalledDiskGiB=128,
    [string] $ObservationPath,[string] $ObservationSha256,
    [string] $ExportReceiptPath,[string] $ExportReceiptSha256)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Luma.HyperV.psm1') -Force
if ($PSBoundParameters.ContainsKey('ObservationPath') -ne $PSBoundParameters.ContainsKey('ObservationSha256')) {
    throw 'Captured planning requires both observation path and independent SHA256; no fallback is supported.'
}
$captured=$PSBoundParameters.ContainsKey('ObservationPath')
if ($PSBoundParameters.ContainsKey('ExportReceiptPath') -ne $PSBoundParameters.ContainsKey('ExportReceiptSha256')) {
    throw 'Export receipt review requires both path and independent SHA256; it never substitutes for media verification.'
}
$exported=$PSBoundParameters.ContainsKey('ExportReceiptPath')
$manifest=Read-LumaHyperVManifest -Path $ManifestPath -Sha256 $ManifestSha256
$null=Test-LumaHyperVMedia -Manifest $manifest -ExpectedRawSha256 $RawSha256 -ExpectedVhdxSha256 $VhdxSha256
if ($exported) {
    $receipt=Read-LumaHyperVExportReceipt -Path $ExportReceiptPath -Sha256 $ExportReceiptSha256
    $null=Test-LumaHyperVExportReceipt -Receipt $receipt -Manifest $manifest -ManifestSha256 $ManifestSha256 `
        -ManifestPath $ManifestPath -VhdxPath $VhdxPath -ExpectedRawSha256 $RawSha256 -ExpectedVhdxSha256 $VhdxSha256
}
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
    $plan | Add-Member -NotePropertyName export_receipt_join_verified -NotePropertyValue $exported
    $plan | Add-Member -NotePropertyName export_receipt_confers_authority -NotePropertyValue $false
    $plan | ConvertTo-Json -Depth 10
} finally { $media.Dispose() }
