[CmdletBinding()]
param([Parameter(Mandatory)][string] $WorkRoot)
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
$scratch=Join-Path $parent.FullName ('hyperv-plan-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $scratch -ErrorAction Stop
$oldTemp=$env:TEMP; $oldTmp=$env:TMP
$script:Assertions=0
function Check([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }; $script:Assertions++
}
function Refuses([scriptblock]$Operation,[string]$Message) {
    $failed=$false;try { $null=& $Operation } catch { $failed=$true };Check $failed $Message
}
function Copy-Data($Object) { return ($Object | ConvertTo-Json -Depth 12 | ConvertFrom-Json) }
function Hash-Data([byte[]]$Bytes) {
    $hasher=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $hasher.Dispose() }
}
try {
    $env:TEMP=$scratch; $env:TMP=$scratch
    Import-Module (Join-Path $PSScriptRoot 'Luma.HyperV.psm1') -Force
    Check ($null -eq ('Luma.Windows.PlatformInputLease' -as [type]) -and
        $null -eq ('Luma.Windows.HyperVImageLease' -as [type])) 'Run the public loader regression in a fresh process.'
    $raw='a'*64; $vhdx='b'*64
    $manifest=[pscustomobject]@{schema_version=1;purpose='luma-hyperv-live-installer-v1';architecture='amd64'
        profile='V';media_kind='live-installer-disk';vm_generation=2;source_raw_bytes=16190013440L
        source_raw_sha256=$raw;converter_sha256=('c'*64);output_name='luma-hyperv-live-installer.vhdx'
        output_bytes=16777216L;output_sha256=$vhdx
        geometry=[pscustomobject]@{virtual_bytes=16190013440L;block_bytes=2097152L
            logical_sector_bytes=512;physical_sector_bytes=512;dynamic=$true;parent_present=$false}
        raw_preserved=$true;raw_vhdx_guest_bytes_compared=$true;installed_desktop=$false;vm_created=$false
        vm_started=$false;boot_qualified=$false;production_qualified=$false;secure_boot_trust_established=$false
        vtpm_commissioned=$false;host_settings_changed=$false;physical_disk_opened=$false;gate_closing=$false}
    [byte[]]$encoded=[Text.Encoding]::UTF8.GetBytes(($manifest | ConvertTo-Json -Depth 10 -Compress))
    $manifestPath=Join-Path $scratch 'manifest.json'
    [IO.File]::WriteAllBytes($manifestPath,$encoded)
    $manifestPin=Hash-Data $encoded
    $loaded=Read-LumaHyperVManifest $manifestPath $manifestPin
    Check ($null -ne ('Luma.Windows.PlatformInputLease' -as [type]) -and
        $null -ne ('Luma.Windows.HyperVImageLease' -as [type])) 'Public manifest loader did not initialize both dependent types together.'
    Check ($loaded.source_raw_sha256 -ceq $raw) 'Actual public held manifest parser differs.'
    $again=Read-LumaHyperVManifest $manifestPath $manifestPin
    Check ($again.source_raw_sha256 -ceq $raw) 'Repeated public loading must not redefine types.'
    $observation=[pscustomobject]@{os_build=26100;os_architecture='AMD64';edition='Professional'
        hypervisor_present=$true;hyperv_module_available=$true;vmms_running=$true
        host_available_bytes=32L*1GB;host_logical_processors=12;storage_free_bytes=512L*1GB
        storage_format='NTFS';existing_vm_names=@();observation_only=$true}
    $plan=Test-LumaHyperVPlan $observation $manifest $raw $vhdx
    Check ($plan.blockers.Count -eq 3) 'Trust/vTPM/installed-desktop gaps must remain explicit.'
    foreach ($name in @('vm_created','vm_started','startup_admitted','deployment_admitted','dynamic_memory',
        'network_attached','host_folder_sharing','clipboard_sharing','device_passthrough','enhanced_session_enabled',
        'automatic_checkpoints','resources_reserved','host_settings_changed','production_qualified','gate_closing')) {
        Check ($plan.$name -is [bool] -and -not $plan.$name) ('Unexpected activation/claim: '+$name)
    }
    Check ($plan.secure_boot_required -and $plan.unique_clone_identity_required) 'Guest trust and unique identities required.'
    Check ($plan.automatic_start -ceq 'Nothing') 'VM must never auto-start.'
    Check ($plan.fixed_memory_bytes -eq 8L*1GB -and $plan.host_ram_headroom_bytes -eq 8L*1GB) 'Fixed RAM/headroom differs.'
    foreach ($row in @(@('host_available_bytes',(8L*1GB)),@('host_logical_processors',2),
        @('storage_free_bytes',1GB),@('storage_format','exFAT'),@('edition','Core'),
        @('hypervisor_present',$false),@('hyperv_module_available',$false),@('vmms_running',$false),
        @('existing_vm_names',@('lumaos-desktop-lab')))) {
        $bad=Copy-Data $observation;$bad.($row[0])=$row[1]
        $actual=Test-LumaHyperVPlan $bad $manifest $raw $vhdx
        Check ($actual.blockers.Count -gt 3 -and -not $actual.deployment_admitted) ('Missing blocker: '+$row[0])
    }
    foreach ($field in @('installed_desktop','boot_qualified','secure_boot_trust_established','gate_closing')) {
        $bad=Copy-Data $manifest;$bad.$field=$true
        Refuses { Test-LumaHyperVMedia $bad $raw $vhdx } ('False media qualification accepted: '+$field)
    }
    $bad=Copy-Data $manifest;$bad.geometry.parent_present=$true
    Refuses { Test-LumaHyperVMedia $bad $raw $vhdx } 'Parent image accepted.'
    $bad=Copy-Data $manifest;$bad.output_bytes=$true
    Refuses { Test-LumaHyperVMedia $bad $raw $vhdx } 'Boolean byte count accepted.'
    $bad=Copy-Data $manifest;$bad | Add-Member -NotePropertyName extra -NotePropertyValue 1
    Refuses { Test-LumaHyperVMedia $bad $raw $vhdx } 'Unknown schema field accepted.'
    Refuses { Test-LumaHyperVMedia $manifest ('d'*64) $vhdx } 'Substituted independent raw pin accepted.'
    Refuses { Test-LumaHyperVMedia $manifest $raw ('d'*64) } 'Substituted independent VHDX pin accepted.'
    # This fixture tests held-file/hash handling ONLY. It is not asserted to be
    # real VHDX metadata; actual QEMU conversion/format tests are the Linux lane.
    [byte[]]$bytes=New-Object byte[] 1048576
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('vhdxfile'),$bytes,8)
    $path=Join-Path $scratch 'held-data-fixture.vhdx'
    [IO.File]::WriteAllBytes($path,$bytes)
    $hash=Hash-Data $bytes
    $lease=[Luma.Windows.HyperVImageLease]::Acquire($path,$hash,$bytes.Length)
    try {
        $lease.Check();Check ($lease.Sha256 -ceq $hash -and $lease.Bytes -eq $bytes.Length) 'Actual held hash/length differs.'
        Refuses { [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read).Dispose() } 'Held input allowed a new writer.'
        Refuses { [IO.File]::Move($path,(Join-Path $scratch 'moved.vhdx')) } 'Held input allowed rename.'
    } finally { $lease.Dispose() }
    Refuses { [Luma.Windows.HyperVImageLease]::Acquire($path,('0'*64),$bytes.Length).Dispose() } 'Wrong actual data SHA accepted.'
    Refuses { [Luma.Windows.HyperVImageLease]::Acquire($path,$hash,$bytes.Length+1).Dispose() } 'Wrong exact data length accepted.'
    Refuses { [Luma.Windows.HyperVImageLease]::Acquire($path,$hash,0).Dispose() } 'Zero bound accepted.'
    Refuses { Read-LumaHyperVManifest $manifestPath ('0'*64) } 'Wrong manifest SHA accepted.'
    $duplicate=Join-Path $scratch 'duplicate.json'
    [byte[]]$duplicateBytes=[Text.Encoding]::UTF8.GetBytes('{"schema_version":1,"schema_version":1}')
    [IO.File]::WriteAllBytes($duplicate,$duplicateBytes)
    Refuses { Read-LumaHyperVManifest $duplicate ([Luma.Windows.PlatformSignature]::Hash($duplicateBytes)) } 'Duplicate JSON fields accepted.'
    # The PUBLIC script's fresh process must exercise the same shared loader,
    # not the test's previously initialized types. Pinned captured observation
    # mode is legitimate offline planning and invokes no host/Hyper-V observer.
    $publicManifest=Copy-Data $manifest
    $publicManifest.output_bytes=$bytes.Length
    $publicManifest.output_sha256=$hash
    $publicManifestPath=$path+'.conversion.json'
    [byte[]]$publicManifestBytes=[Text.Encoding]::UTF8.GetBytes(($publicManifest | ConvertTo-Json -Depth 10 -Compress))
    [IO.File]::WriteAllBytes($publicManifestPath,$publicManifestBytes)
    $publicManifestPin=Hash-Data $publicManifestBytes
    $receipt=[pscustomobject]@{schema_version=1;purpose='luma-hyperv-public-export-v1'
        output_name=[IO.Path]::GetFileName($path);output_bytes=$bytes.Length;output_sha256=$hash
        conversion_name=[IO.Path]::GetFileName($publicManifestPath);conversion_sha256=$publicManifestPin
        source_raw_sha256=$raw;source_conversion_preserved=$true;full_destination_readback=$true
        public_staging_untrusted=$true;installed_desktop=$false;vm_created=$false;vm_started=$false
        boot_qualified=$false;production_qualified=$false;gate_closing=$false}
    $validated=Test-LumaHyperVExportReceipt $receipt $publicManifest $publicManifestPin $publicManifestPath $path $raw $hash
    Check ($validated.public_staging_untrusted -and -not $validated.production_qualified) 'Receipt became trust authority.'
    foreach ($row in @(@('output_name','other.vhdx'),@('output_bytes',1048577),@('output_sha256',('0'*64)),
        @('conversion_name','other.json'),@('conversion_sha256',('0'*64)),@('source_raw_sha256',('0'*64)),
        @('source_conversion_preserved',$false),@('full_destination_readback',$false),
        @('public_staging_untrusted',$false),@('installed_desktop',$true),@('vm_created',$true),
        @('vm_started',$true),@('boot_qualified',$true),@('production_qualified',$true),@('gate_closing',$true),
        @('schema_version',$true),@('output_bytes',$true),@('full_destination_readback',1))) {
        $bad=Copy-Data $receipt;$bad.($row[0])=$row[1]
        Refuses { Test-LumaHyperVExportReceipt $bad $publicManifest $publicManifestPin $publicManifestPath $path $raw $hash } ('Receipt mismatch accepted: '+$row[0])
    }
    $bad=Copy-Data $receipt;$bad | Add-Member -NotePropertyName extra -NotePropertyValue 1
    Refuses { Test-LumaHyperVExportReceipt $bad $publicManifest $publicManifestPin $publicManifestPath $path $raw $hash } 'Unknown export receipt field accepted.'
    $receiptPath=$path+'.export.json'
    [byte[]]$receiptBytes=[Text.Encoding]::UTF8.GetBytes(($receipt | ConvertTo-Json -Depth 5 -Compress))
    [IO.File]::WriteAllBytes($receiptPath,$receiptBytes)
    $receiptPin=Hash-Data $receiptBytes
    $readReceipt=Read-LumaHyperVExportReceipt $receiptPath $receiptPin
    Check ($readReceipt.conversion_sha256 -ceq $publicManifestPin) 'Actual held export receipt parser differs.'
    Refuses { Read-LumaHyperVExportReceipt $receiptPath ('0'*64) } 'Wrong independent export receipt pin accepted.'
    $observationPath=Join-Path $scratch 'captured-observation.json'
    [byte[]]$observationBytes=[Text.Encoding]::UTF8.GetBytes(($observation | ConvertTo-Json -Depth 8 -Compress))
    [IO.File]::WriteAllBytes($observationPath,$observationBytes)
    $shell=Join-Path $PSHOME 'powershell.exe'
    $publicOutput=@(& $shell -NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File (Join-Path $PSScriptRoot 'plan-hyperv.ps1') `
        -ManifestPath $publicManifestPath -ManifestSha256 $publicManifestPin -RawSha256 $raw `
        -VhdxPath $path -VhdxSha256 $hash -ObservationPath $observationPath -ObservationSha256 (Hash-Data $observationBytes) `
        -ExportReceiptPath $receiptPath -ExportReceiptSha256 $receiptPin)
    Check ($LASTEXITCODE -eq 0) 'Actual fresh public planner process failed.'
    $publicResult=($publicOutput -join "`n") | ConvertFrom-Json
    Check ($publicResult.observation_source -ceq 'pinned-captured-data' -and -not $publicResult.observation_fresh) 'Captured data was misrepresented as a fresh host observation.'
    Check ($publicResult.actual_vhdx_held_and_hashed -and -not $publicResult.vm_created -and
        -not $publicResult.vm_started -and -not $publicResult.deployment_admitted) 'Public planner claimed deployment or skipped the held media check.'
    Check ($publicResult.export_receipt_join_verified -and -not $publicResult.export_receipt_confers_authority) 'Fresh public planner omitted the export join or conferred authority.'
    # A process with only one old type family loaded must refuse explicitly,
    # rather than compile duplicate types or an empty Assembly.Location.
    function Quote-Script([string]$Value) { return "'"+$Value.Replace("'","''")+"'" }
    $partial='$ErrorActionPreference=''Stop''; Add-Type -Path '+(Quote-Script (Join-Path $PSScriptRoot 'PlatformSignature.cs'))+
        '; Import-Module '+(Quote-Script (Join-Path $PSScriptRoot 'Luma.HyperV.psm1'))+
        '; try { $null=Read-LumaHyperVManifest '+(Quote-Script $manifestPath)+' '+(Quote-Script $manifestPin)+
        '; exit 17 } catch { if ($_.Exception.Message -like ''Partial Hyper-V type loading is refused*'') { ''partial-family-refused''; exit 0 }; throw }'
    $partialOutput=@(& $shell -NoLogo -NoProfile -ExecutionPolicy RemoteSigned -Command $partial)
    Check ($LASTEXITCODE -eq 0 -and ($partialOutput -join '') -ceq 'partial-family-refused') 'Partial existing type family was not refused.'
    $report=[ordered]@{schema_version=1;assertions_passed=$script:Assertions;skips=0;scratch=$scratch
        actual_windows_held_data_hash_test=$true;actual_vhdx_format_test=$false;fresh_public_planner_child_test=$true
        partial_type_family_refused=$true;host_observer_invoked=$false
        hyperv_cmdlets_invoked=$false;vm_created=$false;host_settings_changed=$false;production_qualified=$false;gate_closing=$false}
    $record=Join-Path $scratch 'verification.json'
    [byte[]]$reportBytes=[Text.Encoding]::UTF8.GetBytes(($report | ConvertTo-Json -Depth 8))
    $stream=[IO.File]::Open($record,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($reportBytes,0,$reportBytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
    $report['evidence_path']=$record
    $report['evidence_sha256']=(Get-FileHash -LiteralPath $record -Algorithm SHA256).Hash.ToLowerInvariant()
    $report | ConvertTo-Json -Depth 8
} catch {
    throw ($_.Exception.Message+'; stack: '+$_.ScriptStackTrace)
} finally { $env:TEMP=$oldTemp;$env:TMP=$oldTmp }
