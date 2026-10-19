Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Luma.Preflight.psm1') -ErrorAction Stop

function Initialize-LumaHyperVTypes {
    $platform='Luma.Windows.PlatformInputLease' -as [type]
    $image='Luma.Windows.HyperVImageLease' -as [type]
    if (($null -eq $platform) -xor ($null -eq $image)) {
        throw 'Partial Hyper-V type loading is refused; use a fresh PowerShell process.'
    }
    if ($null -eq $platform) {
        # Add-Type -Path normally creates an in-memory assembly with an empty
        # Location. Compile the dependent sources together, not against that
        # nonexistent path, and never redefine a partly loaded type family.
        Add-Type -Path @((Join-Path $PSScriptRoot 'PlatformSignature.cs'),
            (Join-Path $PSScriptRoot 'HyperVImage.cs')) -ErrorAction Stop
    }
}

function Assert-HyperVClosed {
    param($Record, [string[]] $Fields)
    if ($Record -isnot [pscustomobject]) { throw 'Hyper-V record must be a closed object.' }
    $keys=@($Record.PSObject.Properties.Name)
    if ($keys.Count -ne $Fields.Count) { throw 'Hyper-V record has omitted or unsupported fields.' }
    foreach ($field in $Fields) {
        if (@($keys | Where-Object { $_ -ceq $field }).Count -ne 1) { throw 'Hyper-V field spelling differs.' }
    }
}

function Assert-HyperVInteger {
    param($Value,[long] $Minimum,[long] $Maximum)
    if ($null -eq $Value -or $Value.GetType() -notin @([int],[long],[uint32],[uint64]) -or
        $Value -lt $Minimum -or $Value -gt $Maximum) { throw 'Hyper-V integral value exceeds the closed bound.' }
}

function Test-LumaHyperVMedia {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Manifest, [Parameter(Mandatory)][string] $ExpectedRawSha256,
        [Parameter(Mandatory)][string] $ExpectedVhdxSha256)
    foreach ($pin in @($ExpectedRawSha256,$ExpectedVhdxSha256)) {
        if ($pin -cnotmatch '\A[a-f0-9]{64}\z') { throw 'Independent canonical raw/VHDX SHA256 pins required.' }
    }
    Assert-HyperVClosed $Manifest @('schema_version','purpose','architecture','profile','media_kind',
        'vm_generation','source_raw_bytes','source_raw_sha256','converter_sha256','output_name','output_bytes',
        'output_sha256','geometry','raw_preserved','raw_vhdx_guest_bytes_compared','installed_desktop',
        'vm_created','vm_started','boot_qualified','production_qualified','secure_boot_trust_established',
        'vtpm_commissioned','host_settings_changed','physical_disk_opened','gate_closing')
    Assert-HyperVInteger $Manifest.schema_version 1 1
    Assert-HyperVInteger $Manifest.vm_generation 2 2
    Assert-HyperVInteger $Manifest.source_raw_bytes 16190013440 16190013440
    Assert-HyperVInteger $Manifest.output_bytes 1048576 16324231168
    foreach ($field in @('purpose','architecture','profile','media_kind','source_raw_sha256',
        'converter_sha256','output_name','output_sha256')) {
        if ($Manifest.$field -isnot [string]) { throw 'Hyper-V identity/hash fields must be actual strings.' }
    }
    if ($Manifest.purpose -cne 'luma-hyperv-live-installer-v1' -or $Manifest.architecture -cne 'amd64' -or
        $Manifest.profile -cne 'V' -or $Manifest.media_kind -cne 'live-installer-disk' -or
        $Manifest.source_raw_sha256 -cne $ExpectedRawSha256 -or $Manifest.output_sha256 -cne $ExpectedVhdxSha256 -or
        $Manifest.converter_sha256 -isnot [string] -or $Manifest.converter_sha256 -cnotmatch '\A[a-f0-9]{64}\z' -or
        $Manifest.output_name -cne 'luma-hyperv-live-installer.vhdx') { throw 'Unsupported or substituted Hyper-V installer media.' }
    foreach ($field in @('raw_preserved','raw_vhdx_guest_bytes_compared')) {
        if ($Manifest.$field -isnot [bool] -or -not $Manifest.$field) { throw 'Raw input preservation/byte comparison is required.' }
    }
    foreach ($field in @('installed_desktop','vm_created','vm_started','boot_qualified','production_qualified',
        'secure_boot_trust_established','vtpm_commissioned','host_settings_changed','physical_disk_opened','gate_closing')) {
        if ($Manifest.$field -isnot [bool] -or $Manifest.$field) { throw 'Media data must not claim deployment or authority qualification.' }
    }
    Assert-HyperVClosed $Manifest.geometry @('virtual_bytes','block_bytes','logical_sector_bytes',
        'physical_sector_bytes','dynamic','parent_present')
    foreach ($tuple in @(@('virtual_bytes',16190013440L),@('block_bytes',2097152L),
        @('logical_sector_bytes',512L),@('physical_sector_bytes',512L))) {
        Assert-HyperVInteger $Manifest.geometry.($tuple[0]) $tuple[1] $tuple[1]
    }
    if ($Manifest.geometry.dynamic -isnot [bool] -or -not $Manifest.geometry.dynamic -or
        $Manifest.geometry.parent_present -isnot [bool] -or $Manifest.geometry.parent_present) {
        throw 'Standalone dynamic VHDX required; differencing/backing images are refused.'
    }
    return $Manifest
}

function Test-LumaHyperVPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Observation,[Parameter(Mandatory)] $Manifest,
        [Parameter(Mandatory)][string] $ExpectedRawSha256,[Parameter(Mandatory)][string] $ExpectedVhdxSha256,
        [ValidatePattern('\ALumaOS-[A-Za-z0-9-]{1,48}\z')][string] $Name='LumaOS-Desktop-Lab',
        [ValidateRange(4,64)][int] $GuestMemoryGiB=8,[ValidateRange(1,32)][int] $CpuCount=4,
        [ValidateRange(64,2048)][int] $InstalledDiskGiB=128)
    $media=Test-LumaHyperVMedia $Manifest $ExpectedRawSha256 $ExpectedVhdxSha256
    Assert-HyperVClosed $Observation @('os_build','os_architecture','edition','hypervisor_present',
        'hyperv_module_available','vmms_running','host_available_bytes','host_logical_processors',
        'storage_free_bytes','storage_format','existing_vm_names','observation_only')
    Assert-HyperVInteger $Observation.os_build 0 1000000
    Assert-HyperVInteger $Observation.host_available_bytes 0 ([long]::MaxValue)
    Assert-HyperVInteger $Observation.host_logical_processors 1 4096
    Assert-HyperVInteger $Observation.storage_free_bytes 0 ([long]::MaxValue)
    foreach ($field in @('hypervisor_present','hyperv_module_available','vmms_running','observation_only')) {
        if ($Observation.$field -isnot [bool]) { throw 'Hyper-V observation flags must be actual booleans.' }
    }
    if (-not $Observation.observation_only -or $Observation.os_architecture -isnot [string] -or
        $Observation.edition -isnot [string] -or $Observation.storage_format -isnot [string] -or
        $null -eq $Observation.existing_vm_names -or $Observation.existing_vm_names -is [string] -or
        @($Observation.existing_vm_names).Count -gt 1024) { throw 'Malformed or oversized Hyper-V observation.' }
    foreach ($existing in @($Observation.existing_vm_names)) {
        if ($existing -isnot [string] -or $existing.Length -gt 128) { throw 'Invalid VM inventory observation.' }
    }
    $blockers=New-Object 'System.Collections.Generic.List[string]'
    if ($Observation.os_build -lt 22621 -or $Observation.os_architecture -cne 'AMD64' -or
        $Observation.edition -notin @('Professional','Enterprise','Education','ProfessionalWorkstation')) {
        $blockers.Add('A supported Windows11 x64 Hyper-V host edition/build must be qualified.')
    }
    if (-not $Observation.hypervisor_present -or -not $Observation.hyperv_module_available -or
        -not $Observation.vmms_running) { $blockers.Add('Hyper-V/module/VMMS is unavailable; no feature or host setting is changed.') }
    $reserve=8L*1GB; $guest=[long]$GuestMemoryGiB*1GB
    if ($Observation.host_available_bytes -lt $guest+$reserve) { $blockers.Add('Observed free RAM cannot cover fixed guest RAM plus8GiB Windows headroom.') }
    if ($Observation.host_logical_processors-$CpuCount -lt 2) { $blockers.Add('Requested vCPUs leave fewer than2 host logical processors.') }
    $disk=[long]$InstalledDiskGiB*1GB
    $required=$disk+[long]$media.output_bytes+2L*1GB
    if ($Observation.storage_free_bytes -lt $required) { $blockers.Add('Observed storage cannot cover the full target disk, media and2GiB metadata reserve.') }
    if ($Observation.storage_format -cne 'NTFS') { $blockers.Add('VM private storage must be separately protected NTFS; public/exFAT export storage is staging only.') }
    if (@($Observation.existing_vm_names | Where-Object { $_ -ieq $Name }).Count -ne 0) { $blockers.Add('Exact proposed VM name collides with an existing VM; replacement is forbidden.') }
    $blockers.Add('Current lab certificate has no established Hyper-V firmware trust; SecureBoot will not be silently disabled.')
    $blockers.Add('Fresh per-VM vTPM/key-protector custody and guest Admin/C/R/U commissioning require explicit reviewed execution.')
    $blockers.Add('The VHDX is live installation media, not an installed encrypted A/B desktop; target-disk installation and recovery remain required.')
    return [pscustomobject]@{
        schema_version=1; profile='V'; stage='read-only-deployment-plan'; vm_name=$Name; generation=2
        media_kind='live-installer-disk'; installed_desktop=$false; fixed_memory_bytes=$guest
        host_ram_headroom_bytes=$reserve; logical_processors=$CpuCount; target_disk_bytes=$disk
        observed_storage_required_bytes=$required; dynamic_memory=$false; network_attached=$false
        host_folder_sharing=$false; clipboard_sharing=$false; device_passthrough=$false
        enhanced_session_enabled=$false; automatic_start='Nothing'; automatic_checkpoints=$false
        secure_boot_required=$true; secure_boot_trust_established=$false; unique_clone_identity_required=$true
        startup_admitted=$false; deployment_admitted=$false; vm_created=$false; vm_started=$false
        resources_reserved=$false; host_settings_changed=$false; production_qualified=$false; gate_closing=$false
        blockers=@($blockers); media=$media; observation=$Observation
    }
}

function Get-LumaHyperVObservation {
    [CmdletBinding()]
    param([ValidatePattern('\A[A-Za-z]\z')][string] $StorageDrive='D')
    if ($env:OS -cne 'Windows_NT') { throw 'Native Windows read-only observations required.' }
    $system=Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $edition=(Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction Stop).EditionID
    $drive=New-Object IO.DriveInfo ($StorageDrive+':\')
    if (-not $drive.IsReady -or $drive.DriveType -notin @([IO.DriveType]::Fixed,[IO.DriveType]::Removable)) { throw 'Existing local storage required.' }
    $available=$null -ne (Get-Module -ListAvailable -Name Hyper-V | Select-Object -First 1)
    $vmms=Get-Service -Name vmms -ErrorAction SilentlyContinue
    $running=$null -ne $vmms -and $vmms.Status -eq 'Running'
    $names=@()
    if ($available -and $running) { $names=@(Get-VM -ErrorAction Stop | Select-Object -ExpandProperty Name) }
    return [pscustomobject]@{ os_build=[long]$os.BuildNumber; os_architecture=$env:PROCESSOR_ARCHITECTURE
        edition=[string]$edition; hypervisor_present=[bool]$system.HypervisorPresent
        hyperv_module_available=[bool]$available; vmms_running=[bool]$running
        host_available_bytes=[long]$os.FreePhysicalMemory*1024L
        host_logical_processors=[long]$system.NumberOfLogicalProcessors
        storage_free_bytes=[long]$drive.AvailableFreeSpace; storage_format=[string]$drive.DriveFormat
        existing_vm_names=$names; observation_only=$true }
}

function Read-LumaHyperVPinnedJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path,[Parameter(Mandatory)][string] $Sha256)
    if ($Sha256 -cnotmatch '\A[a-f0-9]{64}\z') { throw 'Independent planning-input SHA256 required.' }
    Initialize-LumaHyperVTypes
    $lease=[Luma.Windows.PlatformInputLease]::Acquire($Path)
    try {
        [byte[]]$bytes=$lease.Capture(1,65536)
        if ([Luma.Windows.PlatformSignature]::Hash($bytes) -cne $Sha256) { throw 'Planning-input independent pin differs.' }
        # Existing strict duplicate/container parser reads the same held, non-
        # write/delete-shared identity; this manifest is data, not authority.
        $record=Read-LumaPlanningJson -LiteralPath $Path
        $lease.Check()
        return $record
    } finally { $lease.Dispose() }
}

function Read-LumaHyperVManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path,[Parameter(Mandatory)][string] $Sha256)
    return Read-LumaHyperVPinnedJson -Path $Path -Sha256 $Sha256
}

function Test-LumaHyperVExportReceipt {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Receipt,[Parameter(Mandatory)] $Manifest,
        [Parameter(Mandatory)][string] $ManifestSha256,[Parameter(Mandatory)][string] $ManifestPath,
        [Parameter(Mandatory)][string] $VhdxPath,[Parameter(Mandatory)][string] $ExpectedRawSha256,
        [Parameter(Mandatory)][string] $ExpectedVhdxSha256)
    $null=Test-LumaHyperVMedia $Manifest $ExpectedRawSha256 $ExpectedVhdxSha256
    if ($ManifestSha256 -cnotmatch '\A[a-f0-9]{64}\z') { throw 'Independent original conversion pin required.' }
    Assert-HyperVClosed $Receipt @('schema_version','purpose','output_name','output_bytes','output_sha256',
        'conversion_name','conversion_sha256','source_raw_sha256','source_conversion_preserved',
        'full_destination_readback','public_staging_untrusted','installed_desktop','vm_created','vm_started',
        'boot_qualified','production_qualified','gate_closing')
    Assert-HyperVInteger $Receipt.schema_version 1 1
    Assert-HyperVInteger $Receipt.output_bytes $Manifest.output_bytes $Manifest.output_bytes
    foreach ($field in @('purpose','output_name','output_sha256','conversion_name','conversion_sha256','source_raw_sha256')) {
        if ($Receipt.$field -isnot [string]) { throw 'Export receipt identities must be actual strings.' }
    }
    $name=[IO.Path]::GetFileName($VhdxPath)
    if ($Receipt.purpose -cne 'luma-hyperv-public-export-v1' -or
        $Receipt.output_name -cne $name -or $Receipt.conversion_name -cne ($name+'.conversion.json') -or
        [IO.Path]::GetFileName($ManifestPath) -cne $Receipt.conversion_name -or
        $Receipt.output_sha256 -cne $ExpectedVhdxSha256 -or $Receipt.conversion_sha256 -cne $ManifestSha256 -or
        $Receipt.source_raw_sha256 -cne $ExpectedRawSha256) { throw 'Export receipt and independently pinned selected media differ.' }
    foreach ($field in @('source_conversion_preserved','full_destination_readback','public_staging_untrusted')) {
        if ($Receipt.$field -isnot [bool] -or -not $Receipt.$field) { throw 'Export receipt must retain data-only/untrusted staging scope.' }
    }
    foreach ($field in @('installed_desktop','vm_created','vm_started','boot_qualified','production_qualified','gate_closing')) {
        if ($Receipt.$field -isnot [bool] -or $Receipt.$field) { throw 'Export receipt must not claim deployment or qualification.' }
    }
    return $Receipt
}

function Read-LumaHyperVExportReceipt {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path,[Parameter(Mandatory)][string] $Sha256)
    return Read-LumaHyperVPinnedJson -Path $Path -Sha256 $Sha256
}

function Read-LumaHyperVCapturedObservation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path,[Parameter(Mandatory)][string] $Sha256)
    # Captured observations are caller-selected DATA, never fresh host admission.
    return Read-LumaHyperVPinnedJson -Path $Path -Sha256 $Sha256
}

Export-ModuleMember -Function Test-LumaHyperVMedia,Test-LumaHyperVPlan,Get-LumaHyperVObservation,
    Read-LumaHyperVManifest,Read-LumaHyperVCapturedObservation,Read-LumaHyperVExportReceipt,Test-LumaHyperVExportReceipt
