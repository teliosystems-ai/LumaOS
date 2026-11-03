[CmdletBinding()]
param([Parameter(Mandatory)][string] $WorkRoot)
# Profile V downloaded-media deployment tests. Every Hyper-V cmdlet here is a
# scriptblock mock that records its call; no real Hyper-V cmdlet, feature,
# service or WSL state is touched. The only live host access is the read-only
# observation inside the fresh public planner child, which is never -Apply.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:OS -cne 'Windows_NT' -or $WorkRoot -notmatch '\AD:\\LumaOS-builds(?:\\[A-Za-z0-9_. -]+)*\z') {
    throw 'Native Windows tests require existing D:\LumaOS-builds scratch.'
}
$parent=Get-Item -LiteralPath $WorkRoot -Force
if ($parent -isnot [IO.DirectoryInfo]) { throw 'Existing D scratch directory required.' }
$walk=$parent
while ($null -ne $walk) {
    if (($walk.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'No scratch reparse ancestors.' }
    $walk=$walk.Parent
}
$scratch=Join-Path $parent.FullName ('hyperv-deploy-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $scratch -ErrorAction Stop
$oldTemp=$env:TEMP; $oldTmp=$env:TMP
$script:Assertions=0
function Check([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }; $script:Assertions++
}
function Refuses([scriptblock]$Operation,[string]$Like,[string]$Message) {
    $text=$null
    try { $null=& $Operation } catch { $text=$_.Exception.Message }
    Check ($null -ne $text -and $text -like $Like) ($Message+' (got: '+$text+')')
}
function Copy-Data($Object) { return ($Object | ConvertTo-Json -Depth 12 | ConvertFrom-Json) }
function Hash-Data([byte[]]$Bytes) {
    $hasher=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $hasher.Dispose() }
}
function Ascii([string]$Text) { return [Text.Encoding]::ASCII.GetBytes($Text) }

# ---- Hyper-V cmdlet mocks with fake VM state --------------------------------
$script:Calls=New-Object 'System.Collections.Generic.List[object]'
$script:Fake=@{}
$script:Common=@('Verbose','Debug','ErrorAction','WarningAction','InformationAction','ErrorVariable','WarningVariable',
    'InformationVariable','OutVariable','OutBuffer','PipelineVariable','ProgressAction')
function Log([string]$Name,$Bound) {
    $copy=@{}
    foreach ($key in @($Bound.Keys)) { if ($key -notin $script:Common) { $copy[$key]=$Bound[$key] } }
    $script:Calls.Add([pscustomobject]@{ name=$Name; args=$copy })
}
function Reset-Fake {
    $script:Calls.Clear()
    $script:Fake=@{ existing=$false; vm=$null; switches=@([pscustomobject]@{ Name='LumaLab'; SwitchType='Internal' },
            [pscustomobject]@{ Name='Uplink'; SwitchType='External' })
        adapters=@(); services=@(); disks=@(); dvds=@(); fail=''; dynamicAfterSet=$false; vhds=@() }
}
function Fail-If([string]$Name) { if ($script:Fake.fail -ceq $Name) { throw ('mock '+$Name+' failed') } }
function CallNames { return @($script:Calls.ToArray() | ForEach-Object { $_.name }) }
function CallsOf([string]$Name) { return @($script:Calls.ToArray() | Where-Object { $_.name -ceq $Name }) }
$mocks=@{
    'Get-VM'={ [CmdletBinding()] param([string]$Name) Log 'Get-VM' $PSBoundParameters
        if ($script:Fake.existing) { return [pscustomobject]@{ Name=$Name } }
        $v=$script:Fake.vm
        if ($null -ne $v -and $v.Name -ieq $Name) {
            return [pscustomobject]@{ Name=$v.Name; Generation=$v.Generation; State='Off'; CheckpointType=$v.CheckpointType
                AutomaticCheckpointsEnabled=$v.AutomaticCheckpointsEnabled; AutomaticStartAction=$v.AutomaticStartAction
                AutomaticStopAction=$v.AutomaticStopAction; Path=$v.Path } } }
    'Get-VMSwitch'={ [CmdletBinding()] param([string]$Name) Log 'Get-VMSwitch' $PSBoundParameters
        return @($script:Fake.switches | Where-Object { $_.Name -ceq $Name }) }
    'New-VM'={ [CmdletBinding()] param([string]$Name,[int]$Generation,[long]$MemoryStartupBytes,[switch]$NoVHD,[string]$Path)
        Log 'New-VM' $PSBoundParameters; Fail-If 'New-VM'
        # Hyper-V defaults that the apply path must override.
        $script:Fake.vm=@{ Name=$Name; Generation=$Generation; Path=(Join-Path $Path $Name); CheckpointType='Production'
            AutomaticCheckpointsEnabled=$true; AutomaticStartAction='StartIfRunning'; AutomaticStopAction='Save'
            Dynamic=$true; Startup=$MemoryStartupBytes; Count=1; SecureBoot='On'; Template='MicrosoftWindows'
            Tpm=$false; KeyProtector=$false; FirstBoot=$null }
        $script:Fake.adapters=@([pscustomobject]@{ Id='a1'; Name='Network Adapter'; SwitchName='' })
        $script:Fake.services=@(foreach ($s in @('Guest Service Interface','Heartbeat','Key-Value Pair Exchange','Shutdown',
            'Time Synchronization','VSS')) { [pscustomobject]@{ Name=$s; Enabled=($s -cne 'Guest Service Interface') } })
        return [pscustomobject]@{ Name=$Name } }
    'Set-VM'={ [CmdletBinding()] param([string]$Name,[string]$CheckpointType,[bool]$AutomaticCheckpointsEnabled,
        [string]$AutomaticStartAction,[string]$AutomaticStopAction) Log 'Set-VM' $PSBoundParameters; Fail-If 'Set-VM'
        $v=$script:Fake.vm; $v.CheckpointType=$CheckpointType; $v.AutomaticCheckpointsEnabled=$AutomaticCheckpointsEnabled
        $v.AutomaticStartAction=$AutomaticStartAction; $v.AutomaticStopAction=$AutomaticStopAction }
    'Set-VMMemory'={ [CmdletBinding()] param([string]$VMName,[bool]$DynamicMemoryEnabled,[long]$StartupBytes)
        Log 'Set-VMMemory' $PSBoundParameters
        $script:Fake.vm.Dynamic=($DynamicMemoryEnabled -or $script:Fake.dynamicAfterSet); $script:Fake.vm.Startup=$StartupBytes }
    'Set-VMProcessor'={ [CmdletBinding()] param([string]$VMName,[int]$Count) Log 'Set-VMProcessor' $PSBoundParameters
        $script:Fake.vm.Count=$Count }
    'Get-VMNetworkAdapter'={ [CmdletBinding()] param([string]$VMName) Log 'Get-VMNetworkAdapter' $PSBoundParameters
        return @($script:Fake.adapters) }
    'Remove-VMNetworkAdapter'={ [CmdletBinding()] param($VMNetworkAdapter) Log 'Remove-VMNetworkAdapter' $PSBoundParameters
        $script:Fake.adapters=@($script:Fake.adapters | Where-Object { $_.Id -cne $VMNetworkAdapter.Id }) }
    'Add-VMNetworkAdapter'={ [CmdletBinding()] param([string]$VMName,[string]$SwitchName) Log 'Add-VMNetworkAdapter' $PSBoundParameters
        $script:Fake.adapters=@($script:Fake.adapters)+@([pscustomobject]@{ Id='a2'; Name='Network Adapter'; SwitchName=$SwitchName }) }
    'Get-VMIntegrationService'={ [CmdletBinding()] param([string]$VMName) Log 'Get-VMIntegrationService' $PSBoundParameters
        return @($script:Fake.services) }
    'Enable-VMIntegrationService'={ [CmdletBinding()] param($VMIntegrationService) Log 'Enable-VMIntegrationService' $PSBoundParameters
        $VMIntegrationService.Enabled=$true }
    'Disable-VMIntegrationService'={ [CmdletBinding()] param($VMIntegrationService) Log 'Disable-VMIntegrationService' $PSBoundParameters
        $VMIntegrationService.Enabled=$false }
    'New-VHD'={ [CmdletBinding()] param([string]$Path,[long]$SizeBytes,[switch]$Dynamic) Log 'New-VHD' $PSBoundParameters
        $script:Fake.vhds=@($script:Fake.vhds)+@($Path) }
    'Add-VMHardDiskDrive'={ [CmdletBinding()] param([string]$VMName,[string]$Path) Log 'Add-VMHardDiskDrive' $PSBoundParameters
        $script:Fake.disks=@($script:Fake.disks)+@([pscustomobject]@{ Path=$Path }) }
    'Get-VMHardDiskDrive'={ [CmdletBinding()] param([string]$VMName) Log 'Get-VMHardDiskDrive' $PSBoundParameters
        return @($script:Fake.disks) }
    'Add-VMDvdDrive'={ [CmdletBinding()] param([string]$VMName,[string]$Path) Log 'Add-VMDvdDrive' $PSBoundParameters
        $script:Fake.dvds=@($script:Fake.dvds)+@([pscustomobject]@{ Path=$Path }) }
    'Get-VMDvdDrive'={ [CmdletBinding()] param([string]$VMName) Log 'Get-VMDvdDrive' $PSBoundParameters
        return @($script:Fake.dvds) }
    'Set-VMFirmware'={ [CmdletBinding()] param([string]$VMName,[string]$EnableSecureBoot,[string]$SecureBootTemplate,$FirstBootDevice)
        Log 'Set-VMFirmware' $PSBoundParameters; Fail-If 'Set-VMFirmware'
        $script:Fake.vm.SecureBoot=$EnableSecureBoot; $script:Fake.vm.Template=$SecureBootTemplate; $script:Fake.vm.FirstBoot=$FirstBootDevice }
    'Get-VMFirmware'={ [CmdletBinding()] param([string]$VMName) Log 'Get-VMFirmware' $PSBoundParameters
        return [pscustomobject]@{ SecureBoot=$script:Fake.vm.SecureBoot; SecureBootTemplate=$script:Fake.vm.Template } }
    'Set-VMKeyProtector'={ [CmdletBinding()] param([string]$VMName,[switch]$NewLocalKeyProtector) Log 'Set-VMKeyProtector' $PSBoundParameters
        $script:Fake.vm.KeyProtector=[bool]$NewLocalKeyProtector }
    'Enable-VMTPM'={ [CmdletBinding()] param([string]$VMName) Log 'Enable-VMTPM' $PSBoundParameters
        if (-not $script:Fake.vm.KeyProtector) { throw 'Enable-VMTPM needs a key protector first.' }
        $script:Fake.vm.Tpm=$true }
    'Get-VMSecurity'={ [CmdletBinding()] param([string]$VMName) Log 'Get-VMSecurity' $PSBoundParameters
        return [pscustomobject]@{ TpmEnabled=$script:Fake.vm.Tpm } }
    'Get-VMMemory'={ [CmdletBinding()] param([string]$VMName) Log 'Get-VMMemory' $PSBoundParameters
        return [pscustomobject]@{ DynamicMemoryEnabled=$script:Fake.vm.Dynamic; Startup=$script:Fake.vm.Startup } }
    'Get-VMProcessor'={ [CmdletBinding()] param([string]$VMName) Log 'Get-VMProcessor' $PSBoundParameters
        return [pscustomobject]@{ Count=$script:Fake.vm.Count } }
}
$stateChanging=@('New-VM','Set-VM','Set-VMMemory','Set-VMProcessor','Remove-VMNetworkAdapter','Add-VMNetworkAdapter',
    'Enable-VMIntegrationService','Disable-VMIntegrationService','New-VHD','Add-VMHardDiskDrive','Add-VMDvdDrive',
    'Set-VMFirmware','Set-VMKeyProtector','Enable-VMTPM')

try {
    $env:TEMP=$scratch; $env:TMP=$scratch
    Import-Module (Join-Path $PSScriptRoot 'Luma.HyperV.psm1') -Force
    Check ($null -eq ('Luma.Windows.PlatformInputLease' -as [type]) -and $null -eq ('Luma.Windows.HyperVImageLease' -as [type]) -and
        $null -eq ('Luma.Windows.HyperVMediaLease' -as [type])) 'Run the deployment tests in a fresh process.'
    Check ($mocks.Count -eq 24) 'Every Hyper-V command in the apply table needs a mock.'

    # ---- Downloaded media fixtures and SHA256SUMS ---------------------------
    # Content markers only (ISO9660 "CD001", VHDX "vhdxfile"); not bootable.
    [byte[]]$iso=New-Object byte[] 1048576
    [Array]::Copy((Ascii 'CD001'),0,$iso,32769,5)
    [byte[]]$vhdx=New-Object byte[] 1048576
    [Array]::Copy((Ascii 'vhdxfile'),0,$vhdx,0,8)
    $download=Join-Path $scratch 'download'
    $null=New-Item -ItemType Directory -Path $download
    $isoPath=Join-Path $download 'luma-live-fixture.iso'; [IO.File]::WriteAllBytes($isoPath,$iso)
    $vhdxPath=Join-Path $download 'luma-live-fixture.vhdx'; [IO.File]::WriteAllBytes($vhdxPath,$vhdx)
    $isoHash=Hash-Data $iso; $vhdxHash=Hash-Data $vhdx
    [byte[]]$sumsBytes=Ascii ($isoHash+'  luma-live-fixture.iso'+"`n"+$vhdxHash+'  luma-live-fixture.vhdx'+"`n")
    $sumsPath=Join-Path $download 'SHA256SUMS'; [IO.File]::WriteAllBytes($sumsPath,$sumsBytes)
    $sumsPin=Hash-Data $sumsBytes

    $parsed=ConvertFrom-LumaSha256Sums -Bytes $sumsBytes
    Check ($parsed.Count -eq 2 -and $parsed['luma-live-fixture.iso'] -ceq $isoHash) 'SHA256SUMS parser differs.'
    $line=$isoHash+'  a.iso'
    foreach ($row in @(@('crlf',($line+"`r`n")),@('no-final-newline',$line),@('one-space',($isoHash+' a.iso'+"`n")),
        @('binary-marker',($isoHash+' *a.iso'+"`n")),@('uppercase-hex',($isoHash.ToUpperInvariant()+'  a.iso'+"`n")),
        @('short-hex',($isoHash.Substring(1)+'  a.iso'+"`n")),@('path',($isoHash+'  dir/a.iso'+"`n")),
        @('backslash-path',($isoHash+'  dir\a.iso'+"`n")),@('dot-name',($isoHash+'  ..'+"`n")),
        @('blank-line',($line+"`n`n")),@('duplicate',($line+"`n"+$line+"`n")),
        @('case-duplicate',($line+"`n"+$vhdxHash+'  A.iso'+"`n")))) {
        Refuses { ConvertFrom-LumaSha256Sums -Bytes (Ascii $row[1]) } '*' ('Malformed SHA256SUMS accepted: '+$row[0])
    }
    [byte[]]$latin=Ascii ($isoHash+'  a.iso'+"`n"); $latin[66]=0xE9
    Refuses { ConvertFrom-LumaSha256Sums -Bytes $latin } '*' 'Non-ASCII SHA256SUMS name accepted.'
    Refuses { ConvertFrom-LumaSha256Sums -Bytes (Ascii (($line+"`n")*1000)) } '*64KiB*' 'Oversized SHA256SUMS accepted.'

    $sums=Read-LumaHyperVSha256Sums -Path $sumsPath -Sha256 $sumsPin
    Check ($null -ne ('Luma.Windows.HyperVMediaLease' -as [type])) 'Public SHA256SUMS reader did not load the type family together.'
    Check ($sums.Count -eq 2) 'Held SHA256SUMS reader differs.'
    Refuses { Read-LumaHyperVSha256Sums -Path $sumsPath -Sha256 ('0'*64) } '*independent pin differs*' 'Substituted SHA256SUMS accepted.'
    Refuses { Read-LumaHyperVSha256Sums -Path $sumsPath -Sha256 'pin' } '*integrity, not origin*' 'SHA256SUMS accepted without an independent pin.'

    $opened=Open-LumaHyperVListedMedia -Sums $sums -SumsSha256 $sumsPin -ImagePath $isoPath
    $isoLease=$opened.lease; $isoRecord=$opened.record
    $openedVhdx=Open-LumaHyperVListedMedia -Sums $sums -SumsSha256 $sumsPin -ImagePath $vhdxPath
    $vhdxLease=$openedVhdx.lease; $vhdxRecord=$openedVhdx.record
    try {
        Check ($isoRecord.kind -ceq 'iso' -and $isoRecord.sha256 -ceq $isoHash -and $isoRecord.bytes -eq 1048576 -and
            $isoRecord.held_and_hashed -and $isoRecord.listed_in_sha256sums -and -not $isoRecord.origin_authenticated) 'ISO media record differs.'
        Check ($vhdxRecord.kind -ceq 'vhdx' -and $vhdxRecord.sha256 -ceq $vhdxHash) 'VHDX media record differs.'
        Refuses { [IO.File]::Open($isoPath,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read).Dispose() } '*' 'Held media allowed a writer.'
        Refuses { [IO.File]::Move($isoPath,(Join-Path $download 'moved.iso')) } '*' 'Held media allowed a rename.'

        # ---- Checksum mismatch and media refusals ---------------------------
        $wrong=Join-Path $scratch 'wrong'; $null=New-Item -ItemType Directory -Path $wrong
        $wrongIso=Join-Path $wrong 'luma-live-fixture.iso'; [IO.File]::WriteAllBytes($wrongIso,$iso)
        [byte[]]$wrongSums=Ascii (('e'*64)+'  luma-live-fixture.iso'+"`n")
        $wrongSumsPath=Join-Path $wrong 'SHA256SUMS'; [IO.File]::WriteAllBytes($wrongSumsPath,$wrongSums)
        $wrongTable=Read-LumaHyperVSha256Sums -Path $wrongSumsPath -Sha256 (Hash-Data $wrongSums)
        Refuses { (Open-LumaHyperVListedMedia -Sums $wrongTable -SumsSha256 (Hash-Data $wrongSums) -ImagePath $wrongIso).lease.Dispose() } `
            '*differs from its SHA256SUMS entry*' 'Checksum mismatch accepted.'
        $unlisted=Join-Path $wrong 'other.iso'; [IO.File]::WriteAllBytes($unlisted,$iso)
        Refuses { (Open-LumaHyperVListedMedia -Sums $sums -SumsSha256 $sumsPin -ImagePath $unlisted).lease.Dispose() } '*not listed*' 'Unlisted image accepted.'
        $noMagic=Join-Path $wrong 'plain.iso'; [byte[]]$plain=New-Object byte[] 1048576; [IO.File]::WriteAllBytes($noMagic,$plain)
        Refuses { [Luma.Windows.HyperVMediaLease]::Acquire($noMagic,(Hash-Data $plain)).Dispose() } '*does not match its iso*' 'ISO without CD001 accepted.'
        $raw=Join-Path $wrong 'disk.img'; [IO.File]::WriteAllBytes($raw,$iso)
        Refuses { [Luma.Windows.HyperVMediaLease]::Acquire($raw,$isoHash).Dispose() } '*.iso or .vhdx*' 'Raw .img accepted as Hyper-V media.'
        $upper=Join-Path $wrong 'upper.ISO'; [IO.File]::WriteAllBytes($upper,$iso)
        Refuses { [Luma.Windows.HyperVMediaLease]::Acquire($upper,$isoHash).Dispose() } '*lowercase*' 'Uppercase extension accepted.'
        $small=Join-Path $wrong 'small.vhdx'; [byte[]]$tiny=Ascii 'vhdxfile'; [IO.File]::WriteAllBytes($small,$tiny)
        Refuses { [Luma.Windows.HyperVMediaLease]::Acquire($small,(Hash-Data $tiny)).Dispose() } '*1MiB-64GiB*' 'Undersized media accepted.'

        # ---- Host prerequisite evaluation -----------------------------------
        $capable=[pscustomobject][ordered]@{ schema_version=1; observation_only=$true; observed_at_utc='2026-11-03T00:00:00Z'
            elevated=$true; hyperv_administrators_member=$false; os_build=26200L; os_architecture='AMD64'
            os_caption='Microsoft Windows 11 Pro'; edition='Professional'; hyperv_feature_state='Enabled'
            virtual_machine_platform_state='Enabled'; hypervisor_present=$true; firmware_virtualization='yes'; slat='yes'
            hyperv_module_available=$true; vmms_running=$true; hyperv_inventory='read'; existing_vm_names=@('Other-VM')
            switches=@([pscustomobject]@{ name='LumaLab'; type='Internal' },[pscustomobject]@{ name='Uplink'; type='External' })
            total_memory_bytes=32L*1GB; available_memory_bytes=20L*1GB; logical_processors=16L; wsl_running=$false
            wsl_vm_working_set_bytes=0L; wsl_distributions=@(); wsl_memory_limit_bytes=16L*1GB
            wsl_memory_limit_source='wsl-default-50-percent'
            storage=[pscustomobject][ordered]@{ drive='D'; ready=$true; drive_type='Fixed'; format='NTFS'; free_bytes=500L*1GB; total_bytes=1000L*1GB }
            image_storage=[pscustomobject][ordered]@{ drive='D'; ready=$true; drive_type='Fixed'; format='NTFS'; free_bytes=500L*1GB; total_bytes=1000L*1GB }
            tpm_present='yes'; tpm_source='Win32_Tpm' }
        $report=Test-LumaHyperVHost -Observation $capable
        Check ($report.host_capable -and @($report.blocking_checks).Count -eq 0) ('Capable host refused: '+(@($report.blocking_checks) -join ','))
        foreach ($name in @('host_settings_changed','vm_created','state_changing_hyperv_cmdlets_invoked','production_qualified','gate_closing')) {
            Check ($report.$name -is [bool] -and -not $report.$name) ('Host check claimed: '+$name)
        }
        Check ($report.sizing.required_total_memory_bytes -eq 12L*1GB -and $report.sizing.required_available_memory_bytes -eq 10L*1GB) 'Memory sizing differs.'
        Check ((Copy-Data $report).host_capable) 'Host report does not survive JSON.'
        $rows=@(
            @('edition','Core','edition'),@('edition','CoreSingleLanguage','edition'),@('edition','Professional ','edition'),
            @('hyperv_feature_state','Disabled','hyperv_feature'),@('hyperv_feature_state','Absent','hyperv_feature'),
            @('hyperv_feature_state','Unknown','hyperv_feature'),@('hypervisor_present',$false,'hypervisor_running'),
            @('hyperv_module_available',$false,'hyperv_management'),@('vmms_running',$false,'hyperv_management'),
            @('firmware_virtualization','no','firmware_virtualization'),@('slat','no','slat'),
            @('total_memory_bytes',(12L*1GB-1),'memory_total'),@('available_memory_bytes',(10L*1GB-1),'memory_available'),
            @('logical_processors',5L,'logical_processors'),@('os_build',19045L,'os_build'),
            @('existing_vm_names',@('lumaos-desktop-lab'),'vm_name'),@('hyperv_inventory','unreadable','vm_name'))
        foreach ($row in $rows) {
            $bad=Copy-Data $capable; $bad.($row[0])=$row[1]
            $result=Test-LumaHyperVHost -Observation $bad
            Check (-not $result.host_capable -and $row[2] -cin @($result.blocking_checks)) ('Missing host refusal: '+$row[0]+'='+$row[1])
        }
        $bad=Copy-Data $capable; $bad.storage.format='exFAT'
        Check ('vm_storage' -cin @((Test-LumaHyperVHost -Observation $bad).blocking_checks)) 'exFAT VM storage accepted.'
        $bad=Copy-Data $capable; $bad.storage.free_bytes=100L*1GB
        Check ('vm_storage' -cin @((Test-LumaHyperVHost -Observation $bad -MediaBytes (16L*1GB)).blocking_checks)) 'Insufficient VM storage accepted.'
        Check ('guest_memory_floor' -cin @((Test-LumaHyperVHost -Observation $capable -GuestMemoryGiB 6).blocking_checks)) 'Guest below 8GiB accepted.'
        # WSL coexistence: running WSL with a 12GiB limit needs 24GiB total.
        $bad=Copy-Data $capable; $bad.wsl_running=$true; $bad.wsl_memory_limit_bytes=12L*1GB; $bad.total_memory_bytes=24L*1GB-1
        Check ('wsl_coexistence' -cin @((Test-LumaHyperVHost -Observation $bad).blocking_checks)) 'Running WSL overcommit accepted.'
        $bad.total_memory_bytes=24L*1GB
        Check ('wsl_coexistence' -cnotin @((Test-LumaHyperVHost -Observation $bad).blocking_checks)) 'Sufficient WSL coexistence refused.'
        $bad.wsl_memory_limit_bytes=0L
        Check ('wsl_coexistence' -cin @((Test-LumaHyperVHost -Observation $bad).blocking_checks)) 'Unparsed WSL limit accepted.'
        # This laptop as observed on 2026-11-03 (Home, 16GB, WSL 12GB, exFAT D).
        $laptop=Copy-Data $capable
        $laptop.edition='CoreSingleLanguage'; $laptop.os_caption='Microsoft Windows 11 Home Single Language'
        $laptop.hyperv_feature_state='Absent'; $laptop.hyperv_module_available=$false; $laptop.vmms_running=$false
        $laptop.hyperv_inventory='not-queried'; $laptop.existing_vm_names=@(); $laptop.switches=@(); $laptop.elevated=$false
        $laptop.total_memory_bytes=16989728768L; $laptop.available_memory_bytes=4482854912L; $laptop.wsl_running=$true
        $laptop.wsl_memory_limit_bytes=12L*1GB; $laptop.wsl_memory_limit_source='wslconfig'; $laptop.storage.format='exFAT'
        $laptop.image_storage.format='exFAT'; $laptop.slat='implied-by-running-hypervisor'
        $result=Test-LumaHyperVHost -Observation $laptop
        Check (-not $result.host_capable -and ((@($result.blocking_checks) -join ',') -ceq
            'edition,hyperv_feature,hyperv_management,memory_available,wsl_coexistence,vm_storage')) ('Laptop blockers differ: '+(@($result.blocking_checks) -join ','))
        # The same 16GB laptop after Pro, Hyper-V, WSL shut down and an NTFS volume.
        $ready=Copy-Data $laptop; $ready.edition='Professional'; $ready.hyperv_feature_state='Enabled'
        $ready.hyperv_module_available=$true; $ready.vmms_running=$true; $ready.hyperv_inventory='read'; $ready.wsl_running=$false
        $ready.available_memory_bytes=11L*1GB; $ready.storage.format='NTFS'
        Check (Test-LumaHyperVHost -Observation $ready).host_capable '16GB host with WSL stopped should fit one 8GiB VM.'
        $bad=Copy-Data $capable; $bad | Add-Member -NotePropertyName extra -NotePropertyValue 1
        Refuses { Test-LumaHyperVHost -Observation $bad } '*unsupported fields*' 'Unknown observation field accepted.'
        $bad=Copy-Data $capable; $bad.observation_only=$false
        Refuses { Test-LumaHyperVHost -Observation $bad } '*read-only*' 'Non-observation host data accepted.'
        $bad=Copy-Data $capable; $bad.total_memory_bytes='34359738368'
        Refuses { Test-LumaHyperVHost -Observation $bad } '*closed bound*' 'String memory size accepted.'

        # ---- Deployment plan ------------------------------------------------
        $vmRoot=Join-Path $scratch 'vms'
        $plan=Test-LumaHyperVDeployment -Observation $capable -Media $isoRecord -VmRoot $vmRoot
        Check ($plan.apply_admitted -and @($plan.blockers).Count -eq 0) ('Capable plan blocked: '+(@($plan.blockers) -join ' | '))
        Check ($plan.generation -eq 2 -and $plan.fixed_memory_bytes -eq 8L*1GB -and $plan.processor_count -eq 4 -and
            $plan.target_disk_bytes -eq 128L*1GB) 'Plan shape differs.'
        Check ($plan.secure_boot_enabled -and $plan.secure_boot_template -ceq 'MicrosoftUEFICertificateAuthority' -and
            $plan.vtpm_enabled -and $plan.key_protector -ceq 'local') 'Secure Boot or vTPM missing from plan.'
        Check ($plan.checkpoint_type -ceq 'Disabled' -and $plan.automatic_start -ceq 'Nothing' -and $plan.first_boot_device -ceq 'dvd') 'Plan lifecycle differs.'
        foreach ($name in @('dynamic_memory','network_attached','host_file_copy','host_folder_sharing','clipboard_sharing',
            'enhanced_session_enabled','device_passthrough','automatic_checkpoints','start_after_apply',
            'secure_boot_trust_established','vtpm_independently_commissioned','vm_created','vm_started',
            'host_settings_changed','production_qualified','gate_closing')) {
            Check ($plan.$name -is [bool] -and -not $plan.$name) ('Unexpected plan activation/claim: '+$name)
        }
        Check (@($plan.integration_services_enabled).Count -eq 0) 'Integration services must default to off.'
        Check (((@($plan.known_gaps) | ForEach-Object { $_.id }) -join ',') -ceq
            'secure-boot-trust,vtpm-custody,hyperv-guest-drivers,live-media-not-installed-desktop') 'Known gaps must stay explicit.'
        Check ($plan.vm_directory -ceq ($vmRoot+'\LumaOS-Desktop-Lab') -and
            $plan.media_copy_path -ceq ($vmRoot+'\LumaOS-Desktop-Lab\Media\luma-live-fixture.iso') -and
            $plan.target_vhdx_path -ceq ($vmRoot+'\LumaOS-Desktop-Lab\Disks\LumaOS-Desktop-Lab-target.vhdx')) 'Plan paths differ.'
        Check ((Test-LumaHyperVDeployment -Observation $capable -Media $isoRecord).vm_root -ceq 'D:\LumaOS-VMs') 'Default VM root differs.'
        $blockedRows=@(
            @{ Observation=$laptop; Like='host check edition*' },
            @{ GuestMemoryGiB=6; Like='host check guest_memory_floor*' },
            @{ SecureBootTemplate='MicrosoftWindows'; Like='*MicrosoftWindows template*' },
            @{ SwitchName='Uplink'; Like='*External switches are refused*' },
            @{ SwitchName='Missing'; Like='*not observed exactly once*' },
            @{ EnableIntegrationService=@('Bogus'); Like='Unknown integration service*' },
            @{ ObservationSource='pinned-captured-data'; Like='*captured observation*' },
            @{ Name='LumaOS-'+('x'*48); VmRoot=('D:\'+('r'*63)+'\'+('s'*63)); Like='*240 characters*' })
        foreach ($row in $blockedRows) {
            $arguments=@{ Observation=$capable; Media=$isoRecord; VmRoot=$vmRoot }
            foreach ($key in @($row.Keys)) { if ($key -cne 'Like') { $arguments[$key]=$row[$key] } }
            $actual=Test-LumaHyperVDeployment @arguments
            Check (-not $actual.apply_admitted -and @($actual.blockers | Where-Object { $_ -like $row.Like }).Count -ge 1) ('Missing plan blocker: '+$row.Like)
        }
        $bad=Copy-Data $capable; $bad.hyperv_feature_state='Absent'
        Check (-not (Test-LumaHyperVDeployment -Observation $bad -Media $isoRecord -VmRoot $vmRoot).apply_admitted) 'Plan admitted without Hyper-V.'
        $bad=Copy-Data $capable; $bad.total_memory_bytes=11L*1GB
        Check (-not (Test-LumaHyperVDeployment -Observation $bad -Media $isoRecord -VmRoot $vmRoot).apply_admitted) 'Plan admitted without memory headroom.'
        $networked=Test-LumaHyperVDeployment -Observation $capable -Media $isoRecord -VmRoot $vmRoot -SwitchName 'LumaLab' `
            -EnableIntegrationService @('Heartbeat','Shutdown')
        Check ($networked.apply_admitted -and $networked.network_attached -and $networked.switch_type -ceq 'Internal' -and
            (@($networked.integration_services_enabled) -join ',') -ceq 'Heartbeat,Shutdown' -and -not $networked.host_file_copy) 'Opt-in plan differs.'
        foreach ($row in @(@('origin_authenticated',$true),@('listed_in_sha256sums',$false),@('held_and_hashed',$false),
            @('kind','vhdx'),@('bytes',1024),@('sha256',('A'*64)),@('name','../x.iso'),@('bytes',$true))) {
            $bad=Copy-Data $isoRecord; $bad.($row[0])=$row[1]
            Refuses { Test-LumaHyperVDeployment -Observation $capable -Media $bad -VmRoot $vmRoot } '*' ('Bad media record accepted: '+$row[0])
        }
        foreach ($root in @('C:\LumaOS-VMs','D:\','D:\a\..\b','LumaOS-VMs','\\server\share\vms','D:\a b')) {
            Refuses { Test-LumaHyperVDeployment -Observation $capable -Media $isoRecord -VmRoot $root } '*VM root*' ('Bad VM root accepted: '+$root)
        }

        # ---- No state change without -Apply ---------------------------------
        Reset-Fake
        $none=Invoke-LumaHyperVDeployment -Plan $plan -MediaLease $isoLease -Commands $mocks
        Check (-not $none.applied -and $none.hyperv_calls -eq 0 -and $script:Calls.Count -eq 0) 'Plan-only run invoked Hyper-V.'
        Check (-not (Test-Path -LiteralPath $vmRoot)) 'Plan-only run created VM folders.'

        # ---- Apply refusals before any state change -------------------------
        $blocked=Test-LumaHyperVDeployment -Observation $laptop -Media $isoRecord -VmRoot $vmRoot
        Reset-Fake
        Refuses { Invoke-LumaHyperVDeployment -Plan $blocked -MediaLease $isoLease -Commands $mocks -Apply } '*plan has blockers*' 'Blocked plan applied.'
        Check ($script:Calls.Count -eq 0) 'Blocked apply called Hyper-V.'
        $captured=Test-LumaHyperVDeployment -Observation $capable -Media $isoRecord -VmRoot $vmRoot -ObservationSource pinned-captured-data
        Refuses { Invoke-LumaHyperVDeployment -Plan $captured -MediaLease $isoLease -Commands $mocks -Apply } '*Apply refused*' 'Captured observation applied.'
        $unprivileged=Copy-Data $capable; $unprivileged.elevated=$false
        $unprivilegedPlan=Test-LumaHyperVDeployment -Observation $unprivileged -Media $isoRecord -VmRoot $vmRoot
        Check $unprivilegedPlan.apply_admitted 'Permission is an apply-time refusal, not a plan blocker.'
        Refuses { Invoke-LumaHyperVDeployment -Plan $unprivilegedPlan -MediaLease $isoLease -Commands $mocks -Apply } '*elevated prompt*' 'Unprivileged apply accepted.'
        $partialTable=@{}; foreach ($key in $mocks.Keys) { if ($key -cne 'Enable-VMTPM') { $partialTable[$key]=$mocks[$key] } }
        Refuses { Invoke-LumaHyperVDeployment -Plan $plan -MediaLease $isoLease -Commands $partialTable -Apply } '*lacks Enable-VMTPM*' 'Incomplete command table accepted.'
        Refuses { Invoke-LumaHyperVDeployment -Plan $plan -MediaLease $vhdxLease -Commands $mocks -Apply } '*held media lease differs*' 'Different media lease accepted.'
        Refuses { Invoke-LumaHyperVDeployment -Plan $plan -Commands $mocks -Apply } '*held media lease differs*' 'Missing media lease accepted.'
        Check ($script:Calls.Count -eq 0 -and -not (Test-Path -LiteralPath $vmRoot)) 'Refused apply changed state.'
        Reset-Fake; $script:Fake.existing=$true
        Refuses { Invoke-LumaHyperVDeployment -Plan $plan -MediaLease $isoLease -Commands $mocks -Apply } '*replacement is forbidden*' 'Existing VM replaced.'
        Check (((CallNames) -join ',') -ceq 'Get-VM') 'Existing-VM refusal made more than the read-only lookup.'
        Reset-Fake
        $collision=Join-Path $scratch 'vms-collision'
        $null=New-Item -ItemType Directory -Path (Join-Path $collision 'LumaOS-Desktop-Lab') -Force
        $collisionPlan=Test-LumaHyperVDeployment -Observation $capable -Media $isoRecord -VmRoot $collision
        Refuses { Invoke-LumaHyperVDeployment -Plan $collisionPlan -MediaLease $isoLease -Commands $mocks -Apply } '*directory exists*' 'Existing VM folder reused.'
        Check (@(CallNames | Where-Object { $_ -cin $stateChanging }).Count -eq 0) 'Folder refusal changed Hyper-V state.'
        Reset-Fake; $script:Fake.switches=@([pscustomobject]@{ Name='LumaLab'; SwitchType='External' })
        $switchPlan=Test-LumaHyperVDeployment -Observation $capable -Media $isoRecord -VmRoot (Join-Path $scratch 'vms-switch') -SwitchName 'LumaLab'
        Refuses { Invoke-LumaHyperVDeployment -Plan $switchPlan -MediaLease $isoLease -Commands $mocks -Apply } '*Internal or Private*' 'Changed switch accepted.'
        Check (@(CallNames | Where-Object { $_ -cin $stateChanging }).Count -eq 0) 'Switch refusal changed Hyper-V state.'

        # ---- Mocked apply: ISO, no network, nothing shared --------------------
        Reset-Fake
        $applied=Invoke-LumaHyperVDeployment -Plan $plan -MediaLease $isoLease -Commands $mocks -Apply
        $names=CallNames
        $expected='Get-VM,New-VHD,New-VM,Set-VM,Set-VMMemory,Set-VMProcessor,Get-VMNetworkAdapter,Remove-VMNetworkAdapter,'+
            'Get-VMIntegrationService,Disable-VMIntegrationService,Disable-VMIntegrationService,Disable-VMIntegrationService,'+
            'Disable-VMIntegrationService,Disable-VMIntegrationService,Disable-VMIntegrationService,Add-VMHardDiskDrive,'+
            'Add-VMDvdDrive,Get-VMDvdDrive,Set-VMFirmware,Set-VMKeyProtector,Enable-VMTPM,Get-VM,Get-VMMemory,'+
            'Get-VMProcessor,Get-VMFirmware,Get-VMSecurity,Get-VMNetworkAdapter,Get-VMIntegrationService,'+
            'Get-VMHardDiskDrive,Get-VMDvdDrive'
        Check (($names -join ',') -ceq $expected) ('Apply call order differs: '+($names -join ','))
        Check ($names -notcontains 'Start-VM' -and $applied.applied -and -not $applied.vm_started -and -not $applied.start_requested) 'Apply must never start the VM.'
        $newVm=(CallsOf 'New-VM')[0].args
        Check ($newVm.Generation -eq 2 -and $newVm.NoVHD -and $newVm.Path -ceq $vmRoot -and $newVm.MemoryStartupBytes -eq 8L*1GB) 'New-VM arguments differ.'
        $setVm=(CallsOf 'Set-VM')[0].args
        Check ($setVm.CheckpointType -ceq 'Disabled' -and $setVm.AutomaticCheckpointsEnabled -eq $false -and
            $setVm.AutomaticStartAction -ceq 'Nothing' -and $setVm.AutomaticStopAction -ceq 'ShutDown') 'Set-VM arguments differ.'
        $memory=(CallsOf 'Set-VMMemory')[0].args
        Check ($memory.DynamicMemoryEnabled -eq $false -and $memory.StartupBytes -eq 8L*1GB) 'Fixed memory not applied.'
        Check ((CallsOf 'Set-VMProcessor')[0].args['Count'] -eq 4) 'vCPU count not applied.'
        $firmware=(CallsOf 'Set-VMFirmware')[0].args
        Check ($firmware.EnableSecureBoot -ceq 'On' -and $firmware.SecureBootTemplate -ceq 'MicrosoftUEFICertificateAuthority' -and
            $firmware.FirstBootDevice.Path -ceq $plan.media_copy_path) 'Secure Boot or first boot device differs.'
        Check ((CallsOf 'Set-VMKeyProtector')[0].args.NewLocalKeyProtector) 'Local key protector not requested.'
        Check ((CallsOf 'New-VHD')[0].args.SizeBytes -eq 128L*1GB -and (CallsOf 'New-VHD')[0].args.Path -ceq $plan.target_vhdx_path) 'Target VHDX differs.'
        Check ((CallsOf 'Add-VMDvdDrive')[0].args.Path -ceq $plan.media_copy_path) 'DVD must attach the verified copy as a file.'
        $rb=$applied.read_back
        Check ($rb.secure_boot -ceq 'On' -and $rb.tpm_enabled -and -not $rb.dynamic_memory -and $rb.network_adapters -eq 0 -and
            @($rb.integration_services_enabled).Count -eq 0 -and $rb.checkpoint_type -ceq 'Disabled') 'Read-back differs.'
        Check ($applied.media_copy_sha256 -ceq $isoHash -and
            (Get-FileHash -LiteralPath $plan.media_copy_path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $isoHash) 'Media copy is not the verified bytes.'
        Check (-not $applied.secure_boot_trust_established -and -not $applied.vtpm_independently_commissioned -and
            -not $applied.production_qualified) 'Apply overclaimed trust.'
        Check (@($applied.host_side_effects | Where-Object { $_ -like '*UntrustedGuardian*' }).Count -eq 1) 'Key protector host side effect not reported.'

        # ---- Mocked apply: VHDX media, internal switch, opt-in services -------
        Reset-Fake
        $vhdxPlan=Test-LumaHyperVDeployment -Observation $capable -Media $vhdxRecord -VmRoot (Join-Path $scratch 'vms-vhdx') `
            -SwitchName 'LumaLab' -EnableIntegrationService @('Heartbeat') -SecureBootTemplate OpenSourceShieldedVM
        $appliedVhdx=Invoke-LumaHyperVDeployment -Plan $vhdxPlan -MediaLease $vhdxLease -Commands $mocks -Apply
        Check (@(CallsOf 'Add-VMDvdDrive').Count -eq 0 -and @(CallsOf 'Add-VMHardDiskDrive').Count -eq 2) 'VHDX media must attach as a second disk.'
        Check ((CallsOf 'Set-VMFirmware')[0].args.FirstBootDevice.Path -ceq $vhdxPlan.media_copy_path) 'VHDX media must be the first boot device.'
        Check ((CallsOf 'Add-VMNetworkAdapter')[0].args.SwitchName -ceq 'LumaLab' -and $appliedVhdx.read_back.network_adapters -eq 1) 'Internal switch opt-in differs.'
        Check (((@(CallsOf 'Enable-VMIntegrationService') | ForEach-Object { $_.args.VMIntegrationService.Name }) -join ',') -ceq 'Heartbeat' -and
            (@($appliedVhdx.read_back.integration_services_enabled) -join ',') -ceq 'Heartbeat') 'Integration service opt-in differs.'
        Check ($appliedVhdx.read_back.secure_boot_template -ceq 'OpenSourceShieldedVM') 'Template differs.'

        # ---- Failure mid-way leaves everything for owner review --------------
        Reset-Fake; $script:Fake.fail='Set-VMFirmware'
        $failPlan=Test-LumaHyperVDeployment -Observation $capable -Media $isoRecord -VmRoot (Join-Path $scratch 'vms-fail')
        Refuses { Invoke-LumaHyperVDeployment -Plan $failPlan -MediaLease $isoLease -Commands $mocks -Apply } `
            "*stopped at step 'firmware'*nothing was deleted*vm LumaOS-Desktop-Lab*Remove-VM -Name 'LumaOS-Desktop-Lab'*" 'Failure report differs.'
        Check ((Test-Path -LiteralPath $failPlan.media_copy_path) -and @(CallsOf 'Enable-VMTPM').Count -eq 0) 'Failure must stop and keep created items.'
        Reset-Fake; $script:Fake.dynamicAfterSet=$true
        $driftPlan=Test-LumaHyperVDeployment -Observation $capable -Media $isoRecord -VmRoot (Join-Path $scratch 'vms-drift')
        Refuses { Invoke-LumaHyperVDeployment -Plan $driftPlan -MediaLease $isoLease -Commands $mocks -Apply } '*Read-back differs from the plan: memory*' 'Read-back drift accepted.'
    } finally { $isoLease.Dispose(); $vhdxLease.Dispose() }

    # ---- Fresh public planner children ----------------------------------------
    $shell=if ($PSVersionTable.PSEdition -ceq 'Core') { Join-Path $PSHOME 'pwsh.exe' } else { Join-Path $PSHOME 'powershell.exe' }
    function Invoke-Child([string[]]$Arguments) {
        $ErrorActionPreference='Continue'
        $output=@(& $shell -NoLogo -NoProfile -ExecutionPolicy RemoteSigned @Arguments 2>&1 | ForEach-Object { [string]$_ })
        # Windows PowerShell wraps a child's error record at console width, so
        # message matching uses whitespace-collapsed text.
        return [pscustomobject]@{ exit=$LASTEXITCODE; text=($output -join "`n"); flat=(($output -join ' ') -replace '\s+',' ') }
    }
    $planner=Join-Path $PSScriptRoot 'plan-hyperv.ps1'
    $childRoot=Join-Path $scratch 'vms-child'
    # Plan only against this host's live read-only observation. Never -Apply.
    $live=Invoke-Child @('-File',$planner,'-Sha256SumsPath',$sumsPath,'-Sha256SumsSha256',$sumsPin,'-ImagePath',$isoPath,'-VmRoot',$childRoot)
    Check ($live.exit -eq 0) ('Live plan-only child failed: '+$live.text)
    $livePlan=$live.text | ConvertFrom-Json
    Check (-not $livePlan.apply_requested -and -not $livePlan.apply_result.applied -and $livePlan.apply_result.hyperv_calls -eq 0 -and
        $livePlan.observation_source -ceq 'local-read-only-query' -and $livePlan.media.sha256 -ceq $isoHash -and
        -not $livePlan.media.origin_authenticated) 'Live plan-only child differs.'
    Check (-not (Test-Path -LiteralPath $childRoot)) 'Plan-only child created VM folders.'
    $liveAdmitted=[bool]$livePlan.apply_admitted
    $liveBlockers=@($livePlan.host.blocking_checks)
    # Captured observation: plans, never applies.
    $observationPath=Join-Path $scratch 'captured-host.json'
    [byte[]]$observationBytes=[Text.Encoding]::UTF8.GetBytes(($capable | ConvertTo-Json -Depth 8 -Compress))
    [IO.File]::WriteAllBytes($observationPath,$observationBytes)
    $observationPin=Hash-Data $observationBytes
    $read=Read-LumaHyperVHostObservation -Path $observationPath -Sha256 $observationPin
    Check ((Test-LumaHyperVHost -Observation $read).host_capable) 'Captured host observation does not round-trip.'
    $capturedChild=Invoke-Child @('-File',$planner,'-Sha256SumsPath',$sumsPath,'-Sha256SumsSha256',$sumsPin,'-ImagePath',$isoPath,
        '-VmRoot',$childRoot,'-ObservationPath',$observationPath,'-ObservationSha256',$observationPin)
    Check ($capturedChild.exit -eq 0) ('Captured plan child failed: '+$capturedChild.text)
    $capturedPlan=$capturedChild.text | ConvertFrom-Json
    Check ($capturedPlan.observation_source -ceq 'pinned-captured-data' -and -not $capturedPlan.apply_admitted -and
        -not $capturedPlan.apply_result.applied) 'Captured plan child admitted apply.'
    $capturedApply=Invoke-Child @('-File',$planner,'-Sha256SumsPath',$sumsPath,'-Sha256SumsSha256',$sumsPin,'-ImagePath',$isoPath,
        '-VmRoot',$childRoot,'-ObservationPath',$observationPath,'-ObservationSha256',$observationPin,'-Apply')
    Check ($capturedApply.exit -ne 0 -and $capturedApply.flat -like '*Apply refuses a captured observation*') 'Captured -Apply was not refused.'
    $mismatch=Invoke-Child @('-File',$planner,'-Sha256SumsPath',$wrongSumsPath,'-Sha256SumsSha256',(Hash-Data $wrongSums),
        '-ImagePath',$wrongIso,'-VmRoot',$childRoot,'-ObservationPath',$observationPath,'-ObservationSha256',$observationPin)
    Check ($mismatch.exit -ne 0 -and $mismatch.flat -like '*differs from its SHA256SUMS entry*') 'Child accepted a checksum mismatch.'
    $unpinned=Invoke-Child @('-File',$planner,'-Sha256SumsPath',$sumsPath,'-Sha256SumsSha256',('0'*64),'-ImagePath',$isoPath,
        '-VmRoot',$childRoot,'-ObservationPath',$observationPath,'-ObservationSha256',$observationPin)
    Check ($unpinned.exit -ne 0 -and $unpinned.flat -like '*independent pin differs*') 'Child accepted a substituted SHA256SUMS.'
    Check (-not (Test-Path -LiteralPath $childRoot)) 'Refused children created VM folders.'
    function Quote-Script([string]$Value) { return "'"+$Value.Replace("'","''")+"'" }
    $prefixes=@(('Add-Type -Path '+(Quote-Script (Join-Path $PSScriptRoot 'PlatformSignature.cs'))),
        ('Add-Type -Path '+(Quote-Script (Join-Path $PSScriptRoot 'PlatformSignature.cs'))+
            '; Add-Type -WarningAction SilentlyContinue -TypeDefinition ''namespace Luma.Windows { public sealed class HyperVImageLease {} }'''))
    foreach ($prefix in $prefixes) {
        $partial='$ErrorActionPreference=''Stop''; '+$prefix+'; Import-Module '+(Quote-Script (Join-Path $PSScriptRoot 'Luma.HyperV.psm1'))+
            '; try { $null=Read-LumaHyperVSha256Sums '+(Quote-Script $sumsPath)+' '+(Quote-Script $sumsPin)+
            '; exit 17 } catch { if ($_.Exception.Message -like ''Partial Hyper-V type loading is refused*'') { ''partial-family-refused''; exit 0 }; throw }'
        $child=Invoke-Child @('-Command',$partial)
        Check ($child.exit -eq 0 -and $child.text -ceq 'partial-family-refused') ('Partial type family was not refused: '+$child.text)
    }

    $result=[ordered]@{ schema_version=1; assertions_passed=$script:Assertions; skips=0; scratch=$scratch
        powershell_edition=[string]$PSVersionTable.PSEdition; powershell_version=$PSVersionTable.PSVersion.ToString()
        mocked_hyperv_cmdlets=$true; real_hyperv_cmdlets_invoked=$false; live_apply_attempted=$false
        live_plan_only_child=$true; live_host_apply_admitted=$liveAdmitted; live_host_blocking_checks=$liveBlockers
        fixture_media_bootable=$false; vm_created=$false; host_settings_changed=$false; production_qualified=$false; gate_closing=$false }
    $record=Join-Path $scratch 'verification.json'
    [byte[]]$resultBytes=[Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 8))
    $stream=[IO.File]::Open($record,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($resultBytes,0,$resultBytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $result['evidence_path']=$record
    $result['evidence_sha256']=(Get-FileHash -LiteralPath $record -Algorithm SHA256).Hash.ToLowerInvariant()
    $result | ConvertTo-Json -Depth 8
} catch {
    throw ($_.Exception.Message+'; stack: '+$_.ScriptStackTrace)
} finally { $env:TEMP=$oldTemp; $env:TMP=$oldTmp }
