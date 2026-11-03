[CmdletBinding(DefaultParameterSetName='Manifest')]
param(
    # Manifest set: the existing local VHDX conversion plan (plan only).
    [Parameter(Mandatory,ParameterSetName='Manifest')][string] $ManifestPath,
    [Parameter(Mandatory,ParameterSetName='Manifest')][string] $ManifestSha256,
    [Parameter(Mandatory,ParameterSetName='Manifest')][string] $RawSha256,
    [Parameter(Mandatory,ParameterSetName='Manifest')][string] $VhdxPath,
    [Parameter(Mandatory,ParameterSetName='Manifest')][string] $VhdxSha256,
    [Parameter(ParameterSetName='Manifest')][string] $ExportReceiptPath,
    [Parameter(ParameterSetName='Manifest')][string] $ExportReceiptSha256,
    # Download set: a downloaded .iso or .vhdx checked against SHA256SUMS,
    # planned by default and applied only with -Apply.
    [Parameter(Mandatory,ParameterSetName='Download')][string] $Sha256SumsPath,
    [Parameter(Mandatory,ParameterSetName='Download')][string] $Sha256SumsSha256,
    [Parameter(Mandatory,ParameterSetName='Download')][string] $ImagePath,
    [Parameter(ParameterSetName='Download')]
    [ValidateSet('MicrosoftUEFICertificateAuthority','OpenSourceShieldedVM','MicrosoftWindows')]
    [string] $SecureBootTemplate='MicrosoftUEFICertificateAuthority',
    [Parameter(ParameterSetName='Download')][AllowEmptyString()][string] $SwitchName='',
    [Parameter(ParameterSetName='Download')][string[]] $EnableIntegrationService=@(),
    [Parameter(ParameterSetName='Download')][ValidateRange(2,32)][int] $WindowsHeadroomGiB=4,
    [Parameter(ParameterSetName='Download')][ValidateRange(1,16)][int] $StartMarginGiB=2,
    [Parameter(ParameterSetName='Download')][string] $VmRoot,
    [Parameter(ParameterSetName='Download')][switch] $Apply,
    # Shared.
    [ValidatePattern('\A[A-Za-z]\z')][string] $StorageDrive='D',
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

if ($PSCmdlet.ParameterSetName -ceq 'Download') {
    if ($Apply -and $captured) { throw 'Apply refuses a captured observation; it needs a fresh local read-only query.' }
    $sums=Read-LumaHyperVSha256Sums -Path $Sha256SumsPath -Sha256 $Sha256SumsSha256
    $opened=Open-LumaHyperVListedMedia -Sums $sums -SumsSha256 $Sha256SumsSha256 -ImagePath $ImagePath
    try {
        $observation=if ($captured) {
            Read-LumaHyperVHostObservation -Path $ObservationPath -Sha256 $ObservationSha256
        } else {
            Get-LumaHyperVHostObservation -StorageDrive $StorageDrive -ImageDrive ([IO.Path]::GetPathRoot($ImagePath).Substring(0,1))
        }
        $planArguments=@{ Observation=$observation; Media=$opened.record; Name=$Name; GuestMemoryGiB=$GuestMemoryGiB
            CpuCount=$CpuCount; InstalledDiskGiB=$InstalledDiskGiB; StorageDrive=$StorageDrive
            SecureBootTemplate=$SecureBootTemplate; SwitchName=$SwitchName; EnableIntegrationService=$EnableIntegrationService
            WindowsHeadroomGiB=$WindowsHeadroomGiB; StartMarginGiB=$StartMarginGiB
            ObservationSource=$(if ($captured) {'pinned-captured-data'} else {'local-read-only-query'}) }
        if ($PSBoundParameters.ContainsKey('VmRoot')) { $planArguments['VmRoot']=$VmRoot }
        $plan=Test-LumaHyperVDeployment @planArguments
        $opened.lease.Check()
        # The Hyper-V module is looked up only for an admitted -Apply; a plan
        # needs none, and a blocked plan is refused before any lookup.
        $commands=if ($Apply -and $plan.apply_admitted) { Get-LumaHyperVCommandTable } else { @{} }
        $result=Invoke-LumaHyperVDeployment -Plan $plan -MediaLease $opened.lease -Commands $commands -Apply:$Apply
        $plan | Add-Member -NotePropertyName apply_requested -NotePropertyValue ([bool]$Apply)
        $plan | Add-Member -NotePropertyName apply_result -NotePropertyValue $result
        $plan | ConvertTo-Json -Depth 12
    } finally { $opened.lease.Dispose() }
    return
}

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
