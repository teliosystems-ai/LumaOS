Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Luma.Preflight.psm1') -ErrorAction Stop

function Initialize-LumaHyperVTypes {
    $platform='Luma.Windows.PlatformInputLease' -as [type]
    $image='Luma.Windows.HyperVImageLease' -as [type]
    $media='Luma.Windows.HyperVMediaLease' -as [type]
    if ((($null -eq $platform) -xor ($null -eq $image)) -or (($null -eq $platform) -xor ($null -eq $media))) {
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

# ---------------------------------------------------------------------------
# Profile V deployment from downloaded media: read-only host check, plan, and
# an explicit apply path that runs only with -Apply on a capable host.
# ---------------------------------------------------------------------------

$script:HyperVEditions=@('Professional','ProfessionalN','Enterprise','EnterpriseN','Education','EducationN',
    'ProfessionalWorkstation','ProfessionalWorkstationN')
$script:HyperVTemplates=@('MicrosoftUEFICertificateAuthority','OpenSourceShieldedVM')
# English Hyper-V service names. Default is all disabled, which needs no
# names; an opt-in on a localized host is refused rather than guessed.
$script:HyperVIntegrationServices=@('Guest Service Interface','Heartbeat','Key-Value Pair Exchange','Shutdown',
    'Time Synchronization','VSS')
$script:HyperVCommandNames=@('Get-VM','Get-VMSwitch','New-VM','Set-VM','Set-VMMemory','Set-VMProcessor',
    'Get-VMNetworkAdapter','Remove-VMNetworkAdapter','Add-VMNetworkAdapter','Get-VMIntegrationService',
    'Enable-VMIntegrationService','Disable-VMIntegrationService','New-VHD','Add-VMHardDiskDrive','Get-VMHardDiskDrive',
    'Add-VMDvdDrive','Get-VMDvdDrive','Set-VMFirmware','Get-VMFirmware','Set-VMKeyProtector','Enable-VMTPM',
    'Get-VMSecurity','Get-VMMemory','Get-VMProcessor')
$script:HostObservationFields=@('schema_version','observation_only','observed_at_utc','elevated',
    'hyperv_administrators_member','os_build','os_architecture','os_caption','edition','hyperv_feature_state',
    'virtual_machine_platform_state','hypervisor_present','firmware_virtualization','slat','hyperv_module_available',
    'vmms_running','hyperv_inventory','existing_vm_names','switches','total_memory_bytes','available_memory_bytes',
    'logical_processors','wsl_running','wsl_vm_working_set_bytes','wsl_distributions','wsl_memory_limit_bytes',
    'wsl_memory_limit_source','storage','image_storage','tpm_present','tpm_source')
$script:DriveFields=@('drive','ready','drive_type','format','free_bytes','total_bytes')

function ConvertFrom-LumaWslSize {
    param([string] $Text)
    if ($Text -notmatch '\A\s*(?<n>[0-9]{1,9})\s*(?<u>[KMGT]?)B?\s*\z') { return $null }
    $scale=switch ($Matches.u.ToUpperInvariant()) { 'K' {1KB} 'M' {1MB} 'G' {1GB} 'T' {1TB} default {1L} }
    return [long]$Matches.n*[long]$scale
}

function Read-LumaWslMemoryLimit {
    param([Parameter(Mandatory)][long] $TotalBytes)
    # Read-only parse of the per-user WSL2 limit. WSL2's documented default is
    # half of host memory when .wslconfig sets no memory value.
    $default=[pscustomobject]@{ bytes=[long]($TotalBytes/2); source='wsl-default-50-percent' }
    $path=Join-Path $env:USERPROFILE '.wslconfig'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $default }
    if ((Get-Item -LiteralPath $path -Force).Length -gt 65536) { return [pscustomobject]@{ bytes=0L; source='wslconfig-unparsed' } }
    $section=''
    foreach ($line in [IO.File]::ReadAllLines($path)) {
        $text=$line.Trim()
        if ($text -match '\A\[(?<name>[^\]]+)\]') { $section=$Matches.name.Trim().ToLowerInvariant(); continue }
        if ($section -cne 'wsl2' -or $text -match '\A[#;]') { continue }
        if ($text -match '\Amemory\s*=\s*(?<value>[^#;]*)') {
            $bytes=ConvertFrom-LumaWslSize $Matches.value
            if ($null -eq $bytes -or $bytes -le 0) { return [pscustomobject]@{ bytes=0L; source='wslconfig-unparsed' } }
            return [pscustomobject]@{ bytes=[long]$bytes; source='wslconfig' }
        }
    }
    return $default
}

function Get-LumaHyperVDrive {
    param([Parameter(Mandatory)][string] $Letter)
    $drive=New-Object IO.DriveInfo ($Letter+':\')
    $ready=$false
    try { $ready=[bool]$drive.IsReady } catch { $ready=$false }
    return [pscustomobject]@{ drive=$Letter.ToUpperInvariant(); ready=$ready; drive_type=[string]$drive.DriveType
        format=$(if ($ready) { [string]$drive.DriveFormat } else { '' })
        free_bytes=$(if ($ready) { [long]$drive.AvailableFreeSpace } else { 0L })
        total_bytes=$(if ($ready) { [long]$drive.TotalSize } else { 0L }) }
}

function Get-LumaHyperVHostObservation {
    [CmdletBinding()]
    param([ValidatePattern('\A[A-Za-z]\z')][string] $StorageDrive='D',
        [ValidatePattern('\A[A-Za-z]\z')][string] $ImageDrive='D')
    # Read-only. Every query here is a CIM/registry/process/file read; it never
    # enables a feature, starts a service, or calls a state-changing cmdlet.
    if ($env:OS -cne 'Windows_NT') { throw 'Native Windows read-only observations required.' }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal $identity
    $elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $hyperVAdmin=$principal.IsInRole((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-578'))
    $system=Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $processors=@(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
    $edition=(Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction Stop).EditionID
    $features=@{}
    foreach ($feature in @('Microsoft-Hyper-V-All','VirtualMachinePlatform')) {
        # Win32_OptionalFeature answers without elevation; Get-WindowsOptionalFeature does not.
        try {
            $found=@(Get-CimInstance -ClassName Win32_OptionalFeature -Filter ("Name='"+$feature+"'") -ErrorAction Stop)
            $features[$feature]=if ($found.Count -eq 0) { 'Absent' } else {
                switch ([int]$found[0].InstallState) { 1 {'Enabled'} 2 {'Disabled'} 3 {'Absent'} default {'Unknown'} } }
        } catch { $features[$feature]='Unknown' }
    }
    $hypervisor=[bool]$system.HypervisorPresent
    # Win32_Processor hides SLAT (and sometimes VT) once a hypervisor runs; a
    # running Windows hypervisor itself implies both on a Windows 11 host.
    $firmware=if (@($processors | Where-Object { $_.VirtualizationFirmwareEnabled -eq $true }).Count -gt 0) { 'yes' }
        elseif ($hypervisor) { 'implied-by-running-hypervisor' }
        elseif (@($processors | Where-Object { $_.VirtualizationFirmwareEnabled -eq $false }).Count -gt 0) { 'no' } else { 'unknown' }
    $slat=if ($hypervisor) { 'implied-by-running-hypervisor' }
        elseif (@($processors | Where-Object { $_.SecondLevelAddressTranslationExtensions -eq $true }).Count -gt 0) { 'yes' }
        elseif (@($processors | Where-Object { $_.SecondLevelAddressTranslationExtensions -eq $false }).Count -gt 0) { 'no' } else { 'unknown' }
    $module=$null -ne (Get-Module -ListAvailable -Name Hyper-V | Select-Object -First 1)
    $vmms=Get-Service -Name vmms -ErrorAction SilentlyContinue
    $vmmsRunning=$null -ne $vmms -and $vmms.Status -eq 'Running'
    $inventory='not-queried'; $names=@(); $switches=@()
    if ($module -and $vmmsRunning) {
        try {
            $names=@(Hyper-V\Get-VM -ErrorAction Stop | ForEach-Object { [string]$_.Name })
            $switches=@(Hyper-V\Get-VMSwitch -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ name=[string]$_.Name; type=[string]$_.SwitchType } })
            $inventory='read'
        } catch { $inventory='unreadable'; $names=@(); $switches=@() }
    }
    $total=[long]$system.TotalPhysicalMemory
    $wslProcess=@(Get-Process -Name vmmemWSL -ErrorAction SilentlyContinue)
    $workingSet=0L; foreach ($process in $wslProcess) { $workingSet+=[long]$process.WorkingSet64 }
    $distributions=@()
    $preflight=@(Get-Module -Name Luma.Preflight -All) | Select-Object -First 1
    if ($null -ne $preflight) {
        # wsl.exe --list --verbose reports states; it does not start a distro.
        $list=& $preflight { Invoke-LumaWslObservation list }
        $parsed=ConvertFrom-LumaWslList -Text $list.text -ExitCode $list.exit_code
        $distributions=@($parsed.distributions | ForEach-Object { [pscustomobject]@{ name=[string]$_.name; state=[string]$_.state } })
    }
    $wslRunning=$wslProcess.Count -gt 0 -or @($distributions | Where-Object { $_.state -ceq 'Running' }).Count -gt 0
    $limit=Read-LumaWslMemoryLimit -TotalBytes $total
    $tpm='unknown'; $tpmSource='none'
    try {
        $chip=Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop | Select-Object -First 1
        $tpm=if ($null -ne $chip) { 'yes' } else { 'no' }; $tpmSource='Win32_Tpm'
    } catch {
        # Win32_Tpm needs elevation; the PnP device list does not.
        try {
            $device=@(Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPClass='SecurityDevices'" -ErrorAction Stop |
                Where-Object { [string]$_.PNPDeviceID -like 'ACPI\MSFT0101*' })
            $tpm=if ($device.Count -gt 0) { 'yes' } else { 'no-device-observed' }; $tpmSource='pnp-security-device'
        } catch { $tpm='unknown'; $tpmSource='unreadable' }
    }
    return [pscustomobject][ordered]@{ schema_version=1; observation_only=$true
        observed_at_utc=[DateTime]::UtcNow.ToString('o'); elevated=[bool]$elevated
        hyperv_administrators_member=[bool]$hyperVAdmin; os_build=[long]$os.BuildNumber
        os_architecture=[string]$env:PROCESSOR_ARCHITECTURE; os_caption=[string]$os.Caption; edition=[string]$edition
        hyperv_feature_state=[string]$features['Microsoft-Hyper-V-All']
        virtual_machine_platform_state=[string]$features['VirtualMachinePlatform']
        hypervisor_present=$hypervisor; firmware_virtualization=$firmware; slat=$slat
        hyperv_module_available=[bool]$module; vmms_running=[bool]$vmmsRunning; hyperv_inventory=$inventory
        existing_vm_names=$names; switches=$switches; total_memory_bytes=$total
        available_memory_bytes=[long]$os.FreePhysicalMemory*1024L
        logical_processors=[long]$system.NumberOfLogicalProcessors; wsl_running=[bool]$wslRunning
        wsl_vm_working_set_bytes=$workingSet; wsl_distributions=$distributions
        wsl_memory_limit_bytes=[long]$limit.bytes; wsl_memory_limit_source=[string]$limit.source
        storage=(Get-LumaHyperVDrive $StorageDrive); image_storage=(Get-LumaHyperVDrive $ImageDrive)
        tpm_present=$tpm; tpm_source=$tpmSource }
}

function Assert-LumaHyperVHostObservation {
    param($Observation)
    Assert-HyperVClosed $Observation $script:HostObservationFields
    Assert-HyperVInteger $Observation.schema_version 1 1
    foreach ($field in @('os_build','total_memory_bytes','available_memory_bytes','wsl_vm_working_set_bytes',
        'wsl_memory_limit_bytes')) { Assert-HyperVInteger $Observation.$field 0 ([long]::MaxValue) }
    Assert-HyperVInteger $Observation.logical_processors 1 4096
    foreach ($field in @('observation_only','elevated','hyperv_administrators_member','hypervisor_present',
        'hyperv_module_available','vmms_running','wsl_running')) {
        if ($Observation.$field -isnot [bool]) { throw 'Hyper-V host observation flags must be actual booleans.' }
    }
    # PowerShell 7 ConvertFrom-Json turns ISO timestamps into DateTime.
    if ($Observation.observed_at_utc -isnot [string] -and $Observation.observed_at_utc -isnot [datetime]) {
        throw 'Hyper-V host observation time is malformed.'
    }
    foreach ($field in @('os_architecture','os_caption','edition','hyperv_feature_state',
        'virtual_machine_platform_state','firmware_virtualization','slat','hyperv_inventory','wsl_memory_limit_source',
        'tpm_present','tpm_source')) {
        if ($Observation.$field -isnot [string] -or $Observation.$field.Length -gt 256) { throw 'Hyper-V host observation text field is malformed.' }
    }
    if (-not $Observation.observation_only) { throw 'Host observation must be read-only data.' }
    foreach ($field in @('existing_vm_names','switches','wsl_distributions')) {
        if ($null -eq $Observation.$field -or $Observation.$field -is [string] -or @($Observation.$field).Count -gt 1024) {
            throw 'Hyper-V host inventory is malformed or oversized.'
        }
    }
    foreach ($name in @($Observation.existing_vm_names)) { if ($name -isnot [string] -or $name.Length -gt 128) { throw 'Invalid VM inventory observation.' } }
    foreach ($switch in @($Observation.switches)) {
        Assert-HyperVClosed $switch @('name','type')
        if ($switch.name -isnot [string] -or $switch.type -isnot [string]) { throw 'Invalid switch observation.' }
    }
    foreach ($distribution in @($Observation.wsl_distributions)) {
        Assert-HyperVClosed $distribution @('name','state')
        if ($distribution.name -isnot [string] -or $distribution.state -isnot [string]) { throw 'Invalid WSL observation.' }
    }
    foreach ($drive in @($Observation.storage,$Observation.image_storage)) {
        Assert-HyperVClosed $drive $script:DriveFields
        if ($drive.drive -isnot [string] -or $drive.drive -cnotmatch '\A[A-Z]\z' -or $drive.ready -isnot [bool] -or
            $drive.drive_type -isnot [string] -or $drive.format -isnot [string]) { throw 'Invalid drive observation.' }
        Assert-HyperVInteger $drive.free_bytes 0 ([long]::MaxValue)
        Assert-HyperVInteger $drive.total_bytes 0 ([long]::MaxValue)
    }
}

function Read-LumaHyperVHostObservation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path,[Parameter(Mandatory)][string] $Sha256)
    # Caller-selected captured DATA: it can be planned against, never applied.
    $record=Read-LumaHyperVPinnedJson -Path $Path -Sha256 $Sha256
    Assert-LumaHyperVHostObservation $record
    return $record
}

function New-LumaHyperVCheck {
    param([string] $Id,[ValidateSet('pass','fail','unknown','info')][string] $Status,[string] $Observed,
        [string] $Required,[string] $Remedy='')
    return [pscustomobject][ordered]@{ id=$Id; status=$Status; observed=$Observed; required=$Required; remedy=$Remedy }
}

function Format-LumaGiB { param([long] $Bytes) return ('{0:N2} GiB' -f ($Bytes/1GB)) }

function Test-LumaHyperVHost {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Observation,
        [ValidatePattern('\ALumaOS-[A-Za-z0-9-]{1,48}\z')][string] $Name='LumaOS-Desktop-Lab',
        [ValidateRange(1,64)][int] $GuestMemoryGiB=8,[ValidateRange(1,32)][int] $CpuCount=4,
        [ValidateRange(64,2048)][int] $InstalledDiskGiB=128,[ValidateRange(2,32)][int] $WindowsHeadroomGiB=4,
        [ValidateRange(1,16)][int] $StartMarginGiB=2,[ValidateRange(1048576L,68719476736L)][long] $MediaBytes=17179869184L,
        [switch] $MediaDownloaded)
    # Pure evaluation of read-only data. It changes nothing on the host.
    Assert-LumaHyperVHostObservation $Observation
    $o=$Observation; $checks=New-Object 'System.Collections.Generic.List[object]'
    $homeEdition=$o.edition -like 'Core*'
    $checks.Add((New-LumaHyperVCheck 'edition' $(if ($o.edition -in $script:HyperVEditions) {'pass'} else {'fail'}) `
        ($o.edition+' ('+$o.os_caption+')') 'Windows 11 Pro, Enterprise or Education; Home cannot host Hyper-V' `
        $(if ($homeEdition) {'Owner: upgrade Windows 11 Home to Pro with a paid Pro licence (Settings > System > Activation > Change product key or Microsoft Store upgrade), then reboot.'} else {'Owner: use a Pro, Enterprise or Education host.'})))
    $checks.Add((New-LumaHyperVCheck 'os_build' $(if ($o.os_build -ge 22621 -and $o.os_architecture -ceq 'AMD64') {'pass'} else {'fail'}) `
        ('build '+$o.os_build+' '+$o.os_architecture) 'Windows 11 x64 build 22621 or later' 'Owner: update Windows on an x64 host.'))
    $featureStatus=switch ($o.hyperv_feature_state) { 'Enabled' {'pass'} 'Disabled' {'fail'} 'Absent' {'fail'} default {'unknown'} }
    $checks.Add((New-LumaHyperVCheck 'hyperv_feature' $featureStatus ('Microsoft-Hyper-V-All '+$o.hyperv_feature_state) 'Enabled' `
        $(if ($o.hyperv_feature_state -ceq 'Absent') {'The edition does not offer Hyper-V; upgrade the edition first, then enable Microsoft-Hyper-V-All and reboot.'} else {'Owner, elevated: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All, then reboot.'})))
    $checks.Add((New-LumaHyperVCheck 'firmware_virtualization' $(switch ($o.firmware_virtualization) { 'yes' {'pass'} 'implied-by-running-hypervisor' {'pass'} 'no' {'fail'} default {'unknown'} }) `
        $o.firmware_virtualization 'AMD-V/VT-x enabled in UEFI setup' 'Owner: enable SVM (AMD) or VT-x (Intel) in the UEFI setup.'))
    $checks.Add((New-LumaHyperVCheck 'slat' $(switch ($o.slat) { 'yes' {'pass'} 'implied-by-running-hypervisor' {'pass'} 'no' {'fail'} default {'unknown'} }) `
        $o.slat 'Second Level Address Translation (AMD RVI/NPT, Intel EPT)' 'A CPU with SLAT is required.'))
    $checks.Add((New-LumaHyperVCheck 'hypervisor_running' $(if ($o.hypervisor_present) {'pass'} else {'fail'}) `
        ([string]$o.hypervisor_present) 'Windows hypervisor running' 'Reboot after enabling Hyper-V; check that firmware virtualization is on.'))
    $checks.Add((New-LumaHyperVCheck 'hyperv_management' $(if ($o.hyperv_module_available -and $o.vmms_running) {'pass'} else {'fail'}) `
        ('module='+$o.hyperv_module_available+' vmms='+$o.vmms_running) 'Hyper-V PowerShell module present and VMMS running' `
        'Comes with Microsoft-Hyper-V-All after the reboot; no service is started by this checker.'))
    $guest=[long]$GuestMemoryGiB*1GB; $headroom=[long]$WindowsHeadroomGiB*1GB; $margin=[long]$StartMarginGiB*1GB
    $checks.Add((New-LumaHyperVCheck 'guest_memory_floor' $(if ($GuestMemoryGiB -ge 8) {'pass'} else {'fail'}) `
        (Format-LumaGiB $guest) 'at least 8 GiB fixed; live payload staging needs more than 6732 MiB' 'Use -GuestMemoryGiB 8 or more.'))
    $checks.Add((New-LumaHyperVCheck 'memory_total' $(if ($o.total_memory_bytes -ge $guest+$headroom) {'pass'} else {'fail'}) `
        (Format-LumaGiB $o.total_memory_bytes) ((Format-LumaGiB ($guest+$headroom))+' = fixed guest + '+$WindowsHeadroomGiB+' GiB Windows headroom') `
        'The host needs more RAM, or a smaller guest is not supported for live installation.'))
    $checks.Add((New-LumaHyperVCheck 'memory_available' $(if ($o.available_memory_bytes -ge $guest+$margin) {'pass'} else {'fail'}) `
        (Format-LumaGiB $o.available_memory_bytes) ((Format-LumaGiB ($guest+$margin))+' available when the VM starts') `
        'Owner, at test time: close large applications and shut WSL down (wsl --shutdown) before starting the VM.'))
    $wslNeed=$guest+$headroom+[long]$o.wsl_memory_limit_bytes
    $wslStatus=if (-not $o.wsl_running) { 'pass' } elseif ($o.wsl_memory_limit_bytes -le 0) { 'unknown' }
        elseif ($o.total_memory_bytes -ge $wslNeed) { 'pass' } else { 'fail' }
    $checks.Add((New-LumaHyperVCheck 'wsl_coexistence' $wslStatus `
        ('running='+$o.wsl_running+' limit='+(Format-LumaGiB $o.wsl_memory_limit_bytes)+' ('+$o.wsl_memory_limit_source+') vmmemWSL='+(Format-LumaGiB $o.wsl_vm_working_set_bytes)) `
        ('WSL stopped, or total RAM >= '+(Format-LumaGiB $wslNeed)+' (guest + headroom + WSL limit)') `
        'Owner, at test time: wsl --shutdown, and keep WSL builds off while the VM runs. This checker never stops WSL.'))
    $checks.Add((New-LumaHyperVCheck 'logical_processors' $(if ($o.logical_processors-$CpuCount -ge 2) {'pass'} else {'fail'}) `
        ([string]$o.logical_processors) ([string]($CpuCount+2)+' (vCPUs + 2 for the host)') 'Lower -CpuCount.'))
    $disk=[long]$InstalledDiskGiB*1GB; $download=if ($MediaDownloaded) { 0L } else { $MediaBytes+1GB }
    $sameDrive=$o.storage.drive -ceq $o.image_storage.drive
    $vmNeed=$disk+$MediaBytes+2GB+$(if ($sameDrive) { $download } else { 0L })
    $s=$o.storage
    $storageStatus=if (-not $s.ready) { 'fail' } elseif ($s.format -cne 'NTFS' -or $s.free_bytes -lt $vmNeed) { 'fail' } else { 'pass' }
    $checks.Add((New-LumaHyperVCheck 'vm_storage' $storageStatus `
        ($s.drive+': '+$s.format+' free '+(Format-LumaGiB $s.free_bytes)+' of '+(Format-LumaGiB $s.total_bytes)) `
        ('NTFS with '+(Format-LumaGiB $vmNeed)+' free: '+$InstalledDiskGiB+' GiB target VHDX + media copy + 2 GiB'+$(if ($sameDrive -and -not $MediaDownloaded) {' + the download'} else {''})) `
        $(if ($s.format -cne 'NTFS') {'Owner: provide an NTFS volume for the VM (for example a new NTFS partition, or reformat after backing up). exFAT/FAT cannot hold the VM.'} else {'Owner: free space or choose another NTFS drive with -StorageDrive.'})))
    $i=$o.image_storage
    $imageStatus=if ($MediaDownloaded) { 'info' } elseif (-not $i.ready) { 'fail' } elseif ($i.free_bytes -ge $download) { 'pass' } else { 'fail' }
    $checks.Add((New-LumaHyperVCheck 'image_storage' $imageStatus `
        ($i.drive+': '+$i.format+' free '+(Format-LumaGiB $i.free_bytes)) `
        $(if ($MediaDownloaded) {'image already present'} else {(Format-LumaGiB $download)+' for the download'}) 'Owner: free space on the download drive.'))
    $nameStatus=if ($o.hyperv_inventory -cne 'read') { if ($o.hyperv_module_available -and $o.vmms_running) {'unknown'} else {'info'} }
        elseif (@($o.existing_vm_names | Where-Object { $_ -ieq $Name }).Count -ne 0) { 'fail' } else { 'pass' }
    $checks.Add((New-LumaHyperVCheck 'vm_name' $nameStatus ('inventory '+$o.hyperv_inventory) ('no existing VM named '+$Name) `
        'Choose another -Name; this tool never replaces a VM. Unreadable inventory needs an elevated prompt or Hyper-V Administrators membership.'))
    $checks.Add((New-LumaHyperVCheck 'apply_permission' $(if ($o.elevated -or $o.hyperv_administrators_member) {'pass'} else {'info'}) `
        ('elevated='+$o.elevated+' hyperv_administrators='+$o.hyperv_administrators_member) 'Apply only: an elevated prompt or Hyper-V Administrators membership' `
        'This check is read-only and needs neither; run -Apply from an elevated prompt.'))
    $checks.Add((New-LumaHyperVCheck 'host_tpm' 'info' ($o.tpm_present+' via '+$o.tpm_source) 'not required: a Hyper-V vTPM with a local key protector does not use the host TPM' ''))
    $checks.Add((New-LumaHyperVCheck 'virtual_machine_platform' 'info' $o.virtual_machine_platform_state 'not required by Hyper-V; used by WSL2' ''))
    [object[]]$all=$checks.ToArray()
    [object[]]$failed=@($all | Where-Object { $_.status -in @('fail','unknown') })
    [object[]]$blocking=@($failed | ForEach-Object { [string]$_.id })
    [object[]]$changes=@($failed | Where-Object { $_.remedy.Length -gt 0 } | ForEach-Object { [string]($_.id+': '+$_.remedy) })
    # Windows PowerShell 5.1 cannot compile @($typedList) inside a hashtable
    # literal ("Argument types do not match"), so arrays are built first.
    return [pscustomobject][ordered]@{ schema_version=1; profile='V'; stage='hyperv-host-check'
        host_capable=($failed.Count -eq 0); blocking_checks=$blocking; required_host_changes=$changes; checks=$all
        sizing=[pscustomobject][ordered]@{ guest_fixed_memory_bytes=$guest; windows_headroom_bytes=$headroom
            start_margin_bytes=$margin; required_total_memory_bytes=$guest+$headroom
            required_total_memory_with_wsl_bytes=$wslNeed; required_available_memory_bytes=$guest+$margin
            target_disk_bytes=$disk; media_bytes=$MediaBytes; media_bytes_estimated=(-not $MediaDownloaded)
            vm_storage_required_bytes=$vmNeed; image_storage_required_bytes=$download; vcpus=$CpuCount }
        observation=$Observation; observation_only=$true; host_settings_changed=$false; vm_created=$false
        state_changing_hyperv_cmdlets_invoked=$false; production_qualified=$false; gate_closing=$false }
}

function ConvertFrom-LumaSha256Sums {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]] $Bytes)
    # Mirrors native/image/vm_workspace.py and assemble.py: one
    # "<64 lowercase hex><two spaces><plain name>\n" line per file, ASCII only.
    if ($Bytes.Length -lt 68 -or $Bytes.Length -gt 65536) { throw 'SHA256SUMS must hold at least one entry and at most 64KiB.' }
    $text=[Text.Encoding]::GetEncoding(28591).GetString($Bytes)
    if ($text -cnotmatch '\A(?:[0-9a-f]{64}  [A-Za-z0-9][A-Za-z0-9._-]{0,127}\n)+\z') {
        throw 'SHA256SUMS lines must be <64 lowercase hex><two spaces><plain file name> with LF endings.'
    }
    $entries=New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in $text.Substring(0,$text.Length-1).Split([char]10)) {
        $name=$line.Substring(66)
        # Windows names are case-insensitive, so case-only twins are duplicates.
        if ($entries.ContainsKey($name)) { throw 'SHA256SUMS lists a file name twice.' }
        $entries.Add($name,$line.Substring(0,64))
    }
    return $entries
}

function Read-LumaHyperVSha256Sums {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path,[Parameter(Mandatory)][string] $Sha256)
    if ($Sha256 -cnotmatch '\A[a-f0-9]{64}\z') {
        throw 'An independent SHA256SUMS pin is required: a SHA256SUMS from the download location proves integrity, not origin.'
    }
    Initialize-LumaHyperVTypes
    $lease=[Luma.Windows.PlatformInputLease]::Acquire($Path)
    try {
        [byte[]]$bytes=$lease.Capture(1,65536)
        if ([Luma.Windows.PlatformSignature]::Hash($bytes) -cne $Sha256) { throw 'SHA256SUMS independent pin differs.' }
        $entries=ConvertFrom-LumaSha256Sums -Bytes $bytes
        $lease.Check()
        return $entries
    } finally { $lease.Dispose() }
}

function Open-LumaHyperVListedMedia {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Sums,[Parameter(Mandatory)][string] $SumsSha256,[Parameter(Mandatory)][string] $ImagePath)
    # Returns the held, hashed lease and its data record. Caller disposes.
    $name=[IO.Path]::GetFileName($ImagePath)
    if ($Sums -isnot [System.Collections.Generic.Dictionary[string,string]] -or -not $Sums.ContainsKey($name)) {
        throw ('The selected image '+$name+' is not listed in SHA256SUMS.')
    }
    $expected=$Sums[$name]
    Initialize-LumaHyperVTypes
    $lease=[Luma.Windows.HyperVMediaLease]::Acquire($ImagePath,$expected)
    $record=[pscustomobject][ordered]@{ name=$name; kind=$lease.Kind; bytes=[long]$lease.Bytes; sha256=$lease.Sha256
        sha256sums_sha256=$SumsSha256; listed_in_sha256sums=$true; held_and_hashed=$true; origin_authenticated=$false }
    return [pscustomobject]@{ lease=$lease; record=$record }
}

function Test-LumaHyperVDeployment {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Observation,[Parameter(Mandatory)] $Media,
        [ValidatePattern('\ALumaOS-[A-Za-z0-9-]{1,48}\z')][string] $Name='LumaOS-Desktop-Lab',
        [ValidateRange(4,64)][int] $GuestMemoryGiB=8,[ValidateRange(1,32)][int] $CpuCount=4,
        [ValidateRange(64,2048)][int] $InstalledDiskGiB=128,[ValidatePattern('\A[A-Za-z]\z')][string] $StorageDrive='D',
        [string] $VmRoot,
        [ValidateSet('MicrosoftUEFICertificateAuthority','OpenSourceShieldedVM','MicrosoftWindows')][string] $SecureBootTemplate='MicrosoftUEFICertificateAuthority',
        [AllowEmptyString()][string] $SwitchName='',[string[]] $EnableIntegrationService=@(),
        [ValidateRange(2,32)][int] $WindowsHeadroomGiB=4,[ValidateRange(1,16)][int] $StartMarginGiB=2,
        [ValidateSet('local-read-only-query','pinned-captured-data')][string] $ObservationSource='local-read-only-query')
    Assert-HyperVClosed $Media @('name','kind','bytes','sha256','sha256sums_sha256','listed_in_sha256sums',
        'held_and_hashed','origin_authenticated')
    Assert-HyperVInteger $Media.bytes 1048576 68719476736
    if ($Media.name -isnot [string] -or $Media.name -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z' -or
        $Media.kind -notin @('iso','vhdx') -or -not $Media.name.EndsWith('.'+$Media.kind,[StringComparison]::Ordinal) -or
        $Media.sha256 -cnotmatch '\A[a-f0-9]{64}\z' -or $Media.sha256sums_sha256 -cnotmatch '\A[a-f0-9]{64}\z' -or
        $Media.listed_in_sha256sums -isnot [bool] -or -not $Media.listed_in_sha256sums -or
        $Media.held_and_hashed -isnot [bool] -or -not $Media.held_and_hashed -or
        $Media.origin_authenticated -isnot [bool] -or $Media.origin_authenticated) { throw 'Media must be a held, hashed and SHA256SUMS-listed .iso or .vhdx record.' }
    if (-not $PSBoundParameters.ContainsKey('VmRoot')) { $VmRoot=$StorageDrive.ToUpperInvariant()+':\LumaOS-VMs' }
    if ($VmRoot.Length -gt 150 -or $VmRoot -cnotmatch '\A[A-Za-z]:(?:\\[A-Za-z0-9][A-Za-z0-9_.-]{0,63})+\z' -or
        $VmRoot -match '\\\.\.?(?:\\|\z)' -or -not $VmRoot.StartsWith($StorageDrive+':',[StringComparison]::OrdinalIgnoreCase)) {
        throw 'VM root must be a plain absolute folder on the selected storage drive.'
    }
    $hostReport=Test-LumaHyperVHost -Observation $Observation -Name $Name -GuestMemoryGiB $GuestMemoryGiB -CpuCount $CpuCount `
        -InstalledDiskGiB $InstalledDiskGiB -WindowsHeadroomGiB $WindowsHeadroomGiB -StartMarginGiB $StartMarginGiB `
        -MediaBytes ([long]$Media.bytes) -MediaDownloaded
    if ($Observation.storage.drive -cne $StorageDrive.ToUpperInvariant()) { throw 'Observation storage drive differs from the planned drive.' }
    $blockers=New-Object 'System.Collections.Generic.List[string]'
    foreach ($id in @($hostReport.blocking_checks)) { $blockers.Add('host check '+$id+' is not passing.') }
    if ($SecureBootTemplate -notin $script:HyperVTemplates) {
        $blockers.Add('The MicrosoftWindows template admits only Windows-signed loaders; use MicrosoftUEFICertificateAuthority or OpenSourceShieldedVM. Secure Boot stays on in every case.')
    }
    $switchType=''
    if ($SwitchName.Length -gt 0) {
        $match=@($Observation.switches | Where-Object { $_.name -ceq $SwitchName })
        if ($match.Count -ne 1) { $blockers.Add('The opted-in switch is not observed exactly once; no switch is created.') }
        else {
            $switchType=$match[0].type
            if ($switchType -notin @('Internal','Private')) { $blockers.Add('Only an Internal or Private switch may be attached; External switches are refused.') }
        }
    }
    $services=@($EnableIntegrationService | Sort-Object -Unique)
    foreach ($service in $services) {
        if ($service -cnotin $script:HyperVIntegrationServices) { $blockers.Add('Unknown integration service opt-in: '+$service) }
    }
    if ($ObservationSource -cne 'local-read-only-query') { $blockers.Add('A captured observation plans only; it never admits apply.') }
    $vmDirectory=$VmRoot+'\'+$Name
    $mediaCopy=$vmDirectory+'\Media\'+$Media.name; $targetVhdx=$vmDirectory+'\Disks\'+$Name+'-target.vhdx'
    if ($mediaCopy.Length -gt 240 -or $targetVhdx.Length -gt 240) { $blockers.Add('VM file paths exceed 240 characters; use a shorter -VmRoot or -Name.') }
    $gaps=@(
        [pscustomobject]@{ id='secure-boot-trust'; blocks_apply=$false
            detail='The live loader and UKIs are signed only with the LumaOS lab key, which is not in any Hyper-V template db. Expect the firmware to refuse the image; Secure Boot stays on.' },
        [pscustomobject]@{ id='vtpm-custody'; blocks_apply=$false
            detail='A local key protector (host UntrustedGuardian) is not independently commissioned vTPM custody; the host administrator can unwrap the vTPM state.' },
        [pscustomobject]@{ id='hyperv-guest-drivers'; blocks_apply=$false
            detail='The initrd driver list does not name hv_vmbus, hv_storvsc or hyperv_keyboard; boot from Hyper-V synthetic SCSI and keyboard input in the initrd are unverified.' },
        [pscustomobject]@{ id='live-media-not-installed-desktop'; blocks_apply=$false
            detail='The downloaded image is live installation media; installation to the target VHDX and recovery remain manual tests.' })
    return [pscustomobject][ordered]@{ schema_version=1; profile='V'; stage='hyperv-deployment-plan'; vm_name=$Name
        generation=2; vm_root=$VmRoot; vm_directory=$vmDirectory
        media_copy_path=$mediaCopy; target_vhdx_path=$targetVhdx
        media=$Media; fixed_memory_bytes=[long]$GuestMemoryGiB*1GB; dynamic_memory=$false; processor_count=$CpuCount
        target_disk_bytes=[long]$InstalledDiskGiB*1GB; target_disk_dynamic=$true
        first_boot_device=$(if ($Media.kind -ceq 'iso') {'dvd'} else {'media-disk'})
        secure_boot_enabled=$true; secure_boot_template=$SecureBootTemplate; secure_boot_trust_established=$false
        vtpm_enabled=$true; key_protector='local'; vtpm_independently_commissioned=$false
        network_attached=($SwitchName.Length -gt 0); switch_name=$SwitchName; switch_type=$switchType
        integration_services_enabled=$services; host_file_copy=('Guest Service Interface' -cin $services)
        host_folder_sharing=$false; clipboard_sharing=$false; enhanced_session_enabled=$false; device_passthrough=$false
        checkpoint_type='Disabled'; automatic_checkpoints=$false; automatic_start='Nothing'; automatic_stop='ShutDown'
        start_after_apply=$false; observation_source=$ObservationSource
        apply_admitted=($blockers.Count -eq 0); blockers=@($blockers); known_gaps=$gaps; host=$hostReport
        vm_created=$false; vm_started=$false; host_settings_changed=$false; production_qualified=$false; gate_closing=$false }
}

function Get-LumaHyperVCommandTable {
    [CmdletBinding()]
    param()
    # Module-qualified lookup so another module's Get-VM cannot be selected.
    $table=@{}
    foreach ($name in $script:HyperVCommandNames) {
        $command=Get-Command -Name $name -Module Hyper-V -CommandType Cmdlet -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $command) { throw ('The Hyper-V PowerShell module does not provide '+$name+'; Hyper-V must be enabled by the owner first.') }
        $table[$name]=$command
    }
    return $table
}

function Invoke-LumaHyperVDeployment {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Plan,$MediaLease,[hashtable] $Commands=@{},[switch] $Apply)
    if (-not $Apply) {
        return [pscustomobject][ordered]@{ applied=$false; hyperv_calls=0; vm_created=$false; vm_started=$false
            host_settings_changed=$false; reason='Plan only: -Apply was not given, so nothing on the host changed.' }
    }
    if ($Plan.stage -cne 'hyperv-deployment-plan' -or -not $Plan.apply_admitted -or @($Plan.blockers).Count -ne 0) {
        throw ('Apply refused: the plan has blockers: '+(@($Plan.blockers) -join ' | '))
    }
    if ($Plan.observation_source -cne 'local-read-only-query') { throw 'Apply refused: a captured observation never admits apply.' }
    $o=$Plan.host.observation
    if (-not ($o.elevated -or $o.hyperv_administrators_member)) { throw 'Apply refused: run from an elevated prompt or as a Hyper-V Administrators member.' }
    if ($Plan.fixed_memory_bytes -lt 8GB -or $Plan.dynamic_memory -or -not $Plan.secure_boot_enabled -or
        $Plan.secure_boot_template -notin $script:HyperVTemplates) { throw 'Apply refused: fixed memory of at least 8GiB and Secure Boot with a supported template are required.' }
    if ($null -eq $MediaLease -or $MediaLease -isnot [Luma.Windows.HyperVMediaLease] -or
        $MediaLease.Sha256 -cne $Plan.media.sha256 -or $MediaLease.Bytes -ne $Plan.media.bytes) { throw 'Apply refused: the held media lease differs from the plan.' }
    foreach ($name in $script:HyperVCommandNames) {
        if (-not $Commands.ContainsKey($name) -or $null -eq $Commands[$name]) { throw ('Apply refused: command table lacks '+$name+'.') }
    }
    $C=$Commands; $n=$Plan.vm_name
    # Fresh re-checks of mutable host state immediately before the first change.
    if (@(& $C['Get-VM'] -Name $n -ErrorAction SilentlyContinue).Count -ne 0) { throw 'Apply refused: a VM with this name exists; replacement is forbidden.' }
    if (Test-Path -LiteralPath $Plan.vm_directory) { throw 'Apply refused: the VM directory exists; replacement is forbidden.' }
    if ($Plan.network_attached) {
        $switch=@(& $C['Get-VMSwitch'] -Name $Plan.switch_name -ErrorAction SilentlyContinue)
        if ($switch.Count -ne 1 -or [string]$switch[0].SwitchType -notin @('Internal','Private')) { throw 'Apply refused: the opted-in switch is no longer a single Internal or Private switch.' }
    }
    $created=New-Object 'System.Collections.Generic.List[string]'; $step='directories'
    try {
        if (-not (Test-Path -LiteralPath $Plan.vm_root)) { $null=[IO.Directory]::CreateDirectory($Plan.vm_root); $created.Add('directory '+$Plan.vm_root) }
        foreach ($directory in @($Plan.vm_directory,($Plan.vm_directory+'\Media'),($Plan.vm_directory+'\Disks'))) {
            $null=[IO.Directory]::CreateDirectory($directory); $created.Add('directory '+$directory)
        }
        $step='copy-and-verify-media'
        $copySha=$MediaLease.CopyTo($Plan.media_copy_path); $created.Add('file '+$Plan.media_copy_path)
        if ($copySha -cne $Plan.media.sha256) { throw 'Media copy SHA256 differs.' }
        $step='new-vhd'
        $null=& $C['New-VHD'] -Path $Plan.target_vhdx_path -SizeBytes $Plan.target_disk_bytes -Dynamic
        $created.Add('file '+$Plan.target_vhdx_path)
        $step='new-vm'
        $null=& $C['New-VM'] -Name $n -Generation 2 -MemoryStartupBytes $Plan.fixed_memory_bytes -NoVHD -Path $Plan.vm_root
        $created.Add('vm '+$n)
        $step='vm-settings'
        & $C['Set-VM'] -Name $n -CheckpointType Disabled -AutomaticCheckpointsEnabled $false -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
        & $C['Set-VMMemory'] -VMName $n -DynamicMemoryEnabled $false -StartupBytes $Plan.fixed_memory_bytes
        & $C['Set-VMProcessor'] -VMName $n -Count $Plan.processor_count
        $step='network'
        foreach ($adapter in @(& $C['Get-VMNetworkAdapter'] -VMName $n)) { & $C['Remove-VMNetworkAdapter'] -VMNetworkAdapter $adapter }
        if ($Plan.network_attached) { & $C['Add-VMNetworkAdapter'] -VMName $n -SwitchName $Plan.switch_name }
        $step='integration-services'
        $wanted=@($Plan.integration_services_enabled); $seen=@()
        foreach ($service in @(& $C['Get-VMIntegrationService'] -VMName $n)) {
            if ([string]$service.Name -cin $wanted) { & $C['Enable-VMIntegrationService'] -VMIntegrationService $service; $seen+=[string]$service.Name }
            else { & $C['Disable-VMIntegrationService'] -VMIntegrationService $service }
        }
        foreach ($service in $wanted) { if ($service -cnotin $seen) { throw ('Integration service '+$service+' was not found (localized host?).') } }
        $step='disks'
        & $C['Add-VMHardDiskDrive'] -VMName $n -Path $Plan.target_vhdx_path
        if ($Plan.media.kind -ceq 'iso') { & $C['Add-VMDvdDrive'] -VMName $n -Path $Plan.media_copy_path }
        else { & $C['Add-VMHardDiskDrive'] -VMName $n -Path $Plan.media_copy_path }
        $step='firmware'
        # @() around the whole if: an if-expression unrolls a one-item array,
        # and strict mode in Windows PowerShell 5.1 has no .Count on a scalar.
        $boot=@(if ($Plan.media.kind -ceq 'iso') { & $C['Get-VMDvdDrive'] -VMName $n }
            else { & $C['Get-VMHardDiskDrive'] -VMName $n | Where-Object { [string]$_.Path -ieq $Plan.media_copy_path } })
        if ($boot.Count -ne 1) { throw 'The installation media device is not attached exactly once.' }
        & $C['Set-VMFirmware'] -VMName $n -EnableSecureBoot On -SecureBootTemplate $Plan.secure_boot_template -FirstBootDevice $boot[0]
        $step='vtpm'
        & $C['Set-VMKeyProtector'] -VMName $n -NewLocalKeyProtector
        & $C['Enable-VMTPM'] -VMName $n
        $step='read-back'
        $vm=@(& $C['Get-VM'] -Name $n)
        $memory=@(& $C['Get-VMMemory'] -VMName $n); $cpu=@(& $C['Get-VMProcessor'] -VMName $n)
        $firmware=@(& $C['Get-VMFirmware'] -VMName $n); $security=@(& $C['Get-VMSecurity'] -VMName $n)
        $adapters=@(& $C['Get-VMNetworkAdapter'] -VMName $n)
        $enabled=@(& $C['Get-VMIntegrationService'] -VMName $n | Where-Object { $_.Enabled } | ForEach-Object { [string]$_.Name } | Sort-Object)
        $disks=@(& $C['Get-VMHardDiskDrive'] -VMName $n | ForEach-Object { [string]$_.Path })
        $dvds=@(& $C['Get-VMDvdDrive'] -VMName $n | ForEach-Object { [string]$_.Path })
        $readBack=[pscustomobject][ordered]@{ generation=[int]$vm[0].Generation; state=[string]$vm[0].State
            checkpoint_type=[string]$vm[0].CheckpointType; automatic_checkpoints=[bool]$vm[0].AutomaticCheckpointsEnabled
            automatic_start=[string]$vm[0].AutomaticStartAction; automatic_stop=[string]$vm[0].AutomaticStopAction
            vm_path=[string]$vm[0].Path; dynamic_memory=[bool]$memory[0].DynamicMemoryEnabled
            startup_bytes=[long]$memory[0].Startup; processor_count=[int]$cpu[0].Count
            secure_boot=[string]$firmware[0].SecureBoot; secure_boot_template=[string]$firmware[0].SecureBootTemplate
            tpm_enabled=[bool]$security[0].TpmEnabled; network_adapters=$adapters.Count
            switch_names=@($adapters | ForEach-Object { [string]$_.SwitchName }); integration_services_enabled=$enabled
            hard_disks=$disks; dvd_drives=$dvds }
        $expectedDisks=if ($Plan.media.kind -ceq 'iso') { 1 } else { 2 }
        $wrong=@()
        if ($vm.Count -ne 1 -or $readBack.generation -ne 2 -or $readBack.state -cne 'Off') { $wrong+='vm' }
        if (-not $readBack.vm_path.StartsWith($Plan.vm_root,[StringComparison]::OrdinalIgnoreCase)) { $wrong+='vm_path' }
        if ($readBack.checkpoint_type -cne 'Disabled' -or $readBack.automatic_checkpoints) { $wrong+='checkpoints' }
        if ($readBack.automatic_start -cne 'Nothing' -or $readBack.automatic_stop -cne 'ShutDown') { $wrong+='automatic_actions' }
        if ($readBack.dynamic_memory -or $readBack.startup_bytes -ne $Plan.fixed_memory_bytes) { $wrong+='memory' }
        if ($readBack.processor_count -ne $Plan.processor_count) { $wrong+='processor' }
        if ($readBack.secure_boot -cne 'On' -or $readBack.secure_boot_template -cne $Plan.secure_boot_template) { $wrong+='secure_boot' }
        if (-not $readBack.tpm_enabled) { $wrong+='vtpm' }
        if ($readBack.network_adapters -ne $(if ($Plan.network_attached) {1} else {0}) -or
            ($Plan.network_attached -and $readBack.switch_names[0] -cne $Plan.switch_name)) { $wrong+='network' }
        if ((@($Plan.integration_services_enabled | Sort-Object) -join '|') -cne ($enabled -join '|')) { $wrong+='integration_services' }
        if ($disks.Count -ne $expectedDisks -or $dvds.Count -ne $(if ($Plan.media.kind -ceq 'iso') {1} else {0})) { $wrong+='storage' }
        if ($wrong.Count -ne 0) { throw ('Read-back differs from the plan: '+($wrong -join ', ')) }
    } catch {
        $message=$_.Exception.Message
        throw ("Hyper-V apply stopped at step '"+$step+"': "+$message+' Created and left in place for owner review (nothing was deleted): '+
            $(if ($created.Count -eq 0) {'nothing'} else {$created -join '; '})+
            ". Owner cleanup after review, elevated: Remove-VM -Name '"+$n+"' -Force; Remove-Item -LiteralPath '"+$Plan.vm_directory+"' -Recurse.")
    }
    return [pscustomobject][ordered]@{ applied=$true; vm_created=$true; vm_started=$false; start_requested=$false
        host_settings_changed=$true; created=@($created); media_copy_sha256=$copySha; read_back=$readBack
        host_side_effects=@('New VM configuration, target VHDX and media copy under '+$Plan.vm_directory,
            'Set-VMKeyProtector -NewLocalKeyProtector creates or reuses the local UntrustedGuardian certificates in the host store "Shielded VM Local Certificates".')
        secure_boot_trust_established=$false; vtpm_independently_commissioned=$false; production_qualified=$false; gate_closing=$false }
}

Export-ModuleMember -Function Test-LumaHyperVMedia,Test-LumaHyperVPlan,Get-LumaHyperVObservation,
    Read-LumaHyperVManifest,Read-LumaHyperVCapturedObservation,Read-LumaHyperVExportReceipt,Test-LumaHyperVExportReceipt,
    Get-LumaHyperVHostObservation,Read-LumaHyperVHostObservation,Test-LumaHyperVHost,ConvertFrom-LumaSha256Sums,Read-LumaHyperVSha256Sums,
    Open-LumaHyperVListedMedia,Test-LumaHyperVDeployment,Get-LumaHyperVCommandTable,Invoke-LumaHyperVDeployment
