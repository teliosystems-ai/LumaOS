Set-StrictMode -Version Latest

if (-not ('Luma.Windows.WindowsHostProtection' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'WindowsHostProtection.cs') -ReferencedAssemblies @('System.dll','System.Core.dll','System.Security.dll','System.Management.dll')
}

function Get-LumaHostProtectionObservation {
    [CmdletBinding()]
    param()
    $path=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    $observed=[Luma.Windows.WindowsHostProtection]::Observe($path)
    $volume=$observed.Volume
    $management=$observed.Management
    [pscustomobject]@{
        host_encryption=[pscustomobject]@{schema_version=1;scope='fixed-private-custody-and-product-volume';volume=$volume.Volume;volume_serial=$volume.Serial
            status=$volume.Status;error_code=$volume.ErrorCode;protection_status=$volume.Protection;conversion_status=$volume.Conversion
            encryption_method=$volume.EncryptionMethod;lock_status=$volume.Lock;protection_observed=$volume.Protected}
        enterprise_policy=[pscustomobject]@{schema_version=1;scope='current-token-and-machine';status=$management.Status
            domain_join=$management.DomainJoin;aad_join=$management.AadJoin;mdm_registered=$management.MdmRegistered
            wsl_policy_configured=$management.WslPolicyConfigured;wsl_explicitly_denied=$management.WslExplicitlyDenied
            known_local_checks_passed=$management.KnownLocalChecksPassed;enterprise_authorization=$false}
    }
}

function Assert-LumaClosedRecord {
    param($Value, [string[]] $Fields, [string] $Name)
    if ($null -eq $Value -or ($Value -isnot [pscustomobject] -and
        $Value -isnot [System.Collections.IDictionary])) { throw "$Name must be an object." }
    $keys = if ($Value -is [System.Collections.IDictionary]) { @($Value.Keys) } else { @($Value.PSObject.Properties.Name) }
    if ($keys.Count -ne $Fields.Count) { throw "$Name has omitted or unsupported fields." }
    foreach ($field in $Fields) {
        if (@($keys | Where-Object { $_ -ceq $field }).Count -ne 1) {
            throw "$Name has omitted or unsupported fields."
        }
    }
}

function ConvertTo-LumaUnsignedBytes {
    param($Value, [string] $Name)
    if ($null -eq $Value -or $Value.GetType() -notin @([byte], [sbyte], [int16], [uint16],
        [int32], [uint32], [int64], [uint64]) -or $Value -lt 0) {
        throw "$Name must be a nonnegative integral byte count."
    }
    return [uint64]$Value
}

function Read-LumaPlanningJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $LiteralPath)
    $file = Get-Item -LiteralPath $LiteralPath -ErrorAction Stop
    if ($file -isnot [System.IO.FileInfo] -or $file.Length -gt 65536) {
        throw 'Planning input must be a JSON file of at most 65536 bytes.'
    }
    $stream = [System.IO.File]::Open($file.FullName, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $buffer = New-Object byte[] 65537
        $count = 0
        while ($count -lt $buffer.Length) {
            $read = $stream.Read($buffer, $count, $buffer.Length - $count)
            if ($read -eq 0) { break }
            $count += $read
        }
        if ($count -gt 65536) { throw 'Planning JSON exceeds the input bound.' }
        $encoding = New-Object System.Text.UTF8Encoding ($false, $true)
        $text = $encoding.GetString($buffer, 0, $count).TrimStart([char]0xFEFF)
    } finally { $stream.Dispose() }
    # ConvertFrom-Json may silently collapse repeated keys on Windows PowerShell.
    # Bound all container nesting and inspect complete string tokens before parsing.
    $objects = New-Object 'System.Collections.Generic.Stack[System.Collections.Generic.HashSet[string]]'
    $containers = New-Object 'System.Collections.Generic.Stack[string]'
    foreach ($token in [regex]::Matches($text, '"(?<raw>(?:[^"\\]|\\.)*)"|(?<open>[\{\[])|(?<close>[\}\]])')) {
        if ($token.Groups['open'].Success) {
            if ($containers.Count -ge 16) { throw 'Planning JSON nesting exceeds the input bound.' }
            $containers.Push($token.Value)
            if ($token.Value -ceq '{') {
                $objects.Push((New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)))
            }
        } elseif ($token.Groups['close'].Success) {
            if ($containers.Count -eq 0) { throw 'Invalid planning JSON container nesting.' }
            $expected = if ($token.Value -ceq '}') { '{' } else { '[' }
            if ($containers.Pop() -cne $expected) { throw 'Invalid planning JSON container nesting.' }
            if ($token.Value -ceq '}') { $null = $objects.Pop() }
        } else {
            $following = $text.Substring($token.Index + $token.Length).TrimStart()
            if ($following.StartsWith(':')) {
                $key = $token.Groups['raw'].Value
                if ($containers.Count -eq 0 -or $containers.Peek() -cne '{' -or
                    $objects.Count -eq 0 -or $key.Contains('\') -or -not $objects.Peek().Add($key)) {
                    throw 'Duplicate, escaped or misplaced planning JSON property.'
                }
            }
        }
    }
    if ($objects.Count -ne 0 -or $containers.Count -ne 0) { throw 'Invalid planning JSON container nesting.' }
    return ConvertFrom-Json -InputObject $text -ErrorAction Stop
}

function Test-LumaCanonicalRuntimeVersion {
    param($Value)
    if ($Value -isnot [string] -or $Value -notmatch '^(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){3}$') {
        return $false
    }
    foreach ($part in $Value.Split('.')) { if ([int]$part -gt 65535) { return $false } }
    return $true
}

function Test-LumaStoragePlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Observation, $Plan)
    if ($null -eq $Plan) {
        return [pscustomobject]@{ status='not-provided'; capacity_observation_passed=$false; allocation_reserved=$false }
    }
    $components = @('active_image_bytes', 'candidate_image_bytes', 'model_pack_bytes',
        'state_migration_bytes', 'user_quota_bytes', 'backup_staging_bytes', 'recovery_reserve_bytes')
    Assert-LumaClosedRecord $Plan (@('schema_version', 'storage_drive') + $components) 'Storage plan'
    if ((ConvertTo-LumaUnsignedBytes $Plan.schema_version 'Storage schema') -ne 1) {
        throw 'Unsupported storage planning schema.'
    }
    if ($Plan.storage_drive -isnot [string] -or $Plan.storage_drive -cnotmatch '^[A-Z]$' -or
        $Observation.storage_drive -isnot [string] -or $Plan.storage_drive -cne $Observation.storage_drive) {
        throw 'Storage plan must name the exact observed uppercase drive letter.'
    }
    $total = [uint64]0
    $calculated = [ordered]@{}
    foreach ($component in $components) {
        $bytes = ConvertTo-LumaUnsignedBytes $Plan.$component $component
        if ($bytes -gt ([uint64]::MaxValue - $total)) { throw 'Storage planning sum exceeds UInt64 capacity.' }
        $total += $bytes
        $calculated[$component] = $bytes
    }
    if ($calculated.candidate_image_bytes -eq 0 -or $calculated.user_quota_bytes -eq 0 -or
        $calculated.recovery_reserve_bytes -eq 0) {
        throw 'Candidate image, user quota and recovery reserve must each be positive.'
    }
    $free = ConvertTo-LumaUnsignedBytes $Observation.storage_free_bytes 'Observed storage free bytes'
    $enough = $free -ge $total
    [pscustomobject]@{ status=$(if ($enough) { 'capacity-observed' } else { 'insufficient-capacity' })
        capacity_observation_passed=$enough; allocation_reserved=$false; storage_drive=$Plan.storage_drive
        required_free_bytes=$total; observed_free_bytes=$free
        shortfall_bytes=$(if ($enough) { [uint64]0 } else { $total - $free }); components=[pscustomobject]$calculated }
}

function Test-LumaReleasePolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Observation, $Policy)
    if ($null -eq $Policy) {
        return [pscustomobject]@{ status='not-provided'; tuple_matches_input=$false; policy_authenticated=$false; production_qualified=$false }
    }
    Assert-LumaClosedRecord $Policy @('schema_version', 'review_reference', 'tuples') 'Release comparison policy'
    if ((ConvertTo-LumaUnsignedBytes $Policy.schema_version 'Release schema') -ne 1) {
        throw 'Unsupported release comparison schema.'
    }
    if ($Policy.review_reference -isnot [string] -or $Policy.review_reference -notmatch '^[\x21-\x7e]{1,256}$' -or
        $Policy.tuples -isnot [array] -or $Policy.tuples.Count -lt 1 -or $Policy.tuples.Count -gt 128) {
        throw 'Release comparison requires a bounded review reference and 1 to 128 explicit tuples.'
    }
    $observedVersion = $null
    if ($Observation.wsl_runtime.status -eq 'observed' -and $Observation.wsl_runtime.exit_code -eq 0 -and
        $Observation.wsl_runtime.text -is [string] -and $Observation.wsl_runtime.text.Length -le 65536) {
        $firstLine = @($Observation.wsl_runtime.text -split '\r?\n' | Where-Object { $_.Trim().Length -gt 0 } | Select-Object -First 1)
        if ($firstLine.Count -eq 1 -and $firstLine[0] -match '^(?:WSL\s+(?:version|versione)|WSL-Version|Version\s+WSL)\s*:\s*(?<version>[0-9]{1,5}(?:\.[0-9]{1,5}){3})\s*$') {
            $parsedVersion = $Matches.version
            if (Test-LumaCanonicalRuntimeVersion $parsedVersion) { $observedVersion = $parsedVersion }
        }
    }
    $observedBuild = ConvertTo-LumaUnsignedBytes $Observation.windows_build 'Observed Windows build'
    if ($Observation.windows_edition -isnot [string]) { throw 'Observed Windows edition must be a string.' }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $matchesInput = $false
    foreach ($tuple in $Policy.tuples) {
        Assert-LumaClosedRecord $tuple @('windows_edition', 'windows_build', 'wsl_runtime_version') 'Release tuple'
        $build = ConvertTo-LumaUnsignedBytes $tuple.windows_build 'Tuple Windows build'
        if ($build -lt 22000 -or $build -gt [int]::MaxValue -or $tuple.windows_edition -isnot [string] -or
            $tuple.windows_edition -cnotmatch '^[A-Za-z][A-Za-z0-9]{0,63}$' -or
            -not (Test-LumaCanonicalRuntimeVersion $tuple.wsl_runtime_version)) {
            throw 'Release tuples require exact Windows 11 build, edition identifier and four-part WSL runtime version.'
        }
        $identity = '{0}|{1}|{2}' -f $tuple.windows_edition, $build, $tuple.wsl_runtime_version
        if (-not $seen.Add($identity)) { throw 'Duplicate release comparison tuple.' }
        if ($Observation.windows_edition -ceq $tuple.windows_edition -and $observedBuild -eq $build -and
            $null -ne $observedVersion -and $observedVersion -ceq $tuple.wsl_runtime_version) { $matchesInput = $true }
    }
    [pscustomobject]@{ status=$(if ($matchesInput) { 'matches-reviewed-input' } else { 'unsupported-or-unobserved-tuple' })
        tuple_matches_input=$matchesInput; review_reference=$Policy.review_reference
        observed_windows_edition=$Observation.windows_edition; observed_windows_build=$observedBuild
        observed_wsl_runtime_version=$observedVersion; policy_authenticated=$false; production_qualified=$false }
}

function ConvertFrom-LumaWslList {
    [CmdletBinding()]
    param([AllowEmptyString()][string] $Text, [int] $ExitCode)
    $unknown = [pscustomobject]@{ status = 'unknown'; distributions = @() }
    if ($ExitCode -ne 0 -or $Text.Length -gt 65536) { return $unknown }
    $lines = @($Text.Replace([string][char]0, '').TrimStart([char]0xFEFF) -split '\r?\n' |
        Where-Object { $_.Trim().Length -gt 0 })
    if ($lines.Count -lt 2 -or $lines.Count -gt 256) { return $unknown }
    if ($lines[0] -match '(?:\s|^)[12]\s*$' -or $lines[0].Contains('*')) { return $unknown }
    $result = @()
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    for ($index = 1; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -notmatch '^\s*(?<default>\*)?\s*(?<name>\S(?:.*?\S)?)\s{2,}(?<state>\S.*?)\s{2,}(?<version>[12])\s*$') {
            return $unknown
        }
        $name = $Matches.name
        if ($name.Length -gt 128 -or $name -match '[\x00-\x1f\x7f]' -or -not $names.Add($name)) {
            return $unknown
        }
        $result += [pscustomobject]@{ name = $name; version = [int]$Matches.version
            default = ($Matches['default'] -eq '*'); state = $Matches.state.Trim() }
    }
    if (@($result | Where-Object { $_.default }).Count -gt 1) { return $unknown }
    [pscustomobject]@{ status = 'observed'; distributions = @($result) }
}

function Invoke-LumaWslObservation {
    param([ValidateSet('version', 'list')][string] $Operation)
    $executable = Join-Path ([Environment]::SystemDirectory) 'wsl.exe'
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        return [pscustomobject]@{ exit_code = -1; text = ''; status = 'unavailable' }
    }
    $process = New-Object System.Diagnostics.Process
    $stdout = New-Object byte[] 65537
    $stderr = New-Object byte[] 65537
    $started = $false
    try {
        $process.StartInfo.FileName = $executable
        $process.StartInfo.Arguments = if ($Operation -eq 'list') { '--list --verbose' } else { '--version' }
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        $null = $process.Start()
        $started = $true
        $outCount = 0; $errCount = 0; $outDone = $false; $errDone = $false
        $outTask = $process.StandardOutput.BaseStream.ReadAsync($stdout, 0, $stdout.Length)
        $errTask = $process.StandardError.BaseStream.ReadAsync($stderr, 0, $stderr.Length)
        $clock = [Diagnostics.Stopwatch]::StartNew()
        while (-not ($outDone -and $errDone -and $process.HasExited)) {
            if ($clock.ElapsedMilliseconds -ge 5000) {
                return [pscustomobject]@{ exit_code = -1; text = ''; status = 'timed-out' }
            }
            if (-not $outDone -and $outTask.IsCompleted) {
                $read = $outTask.Result
                $outCount += $read
                if ($outCount -gt 65536) {
                    return [pscustomobject]@{ exit_code = -1; text = ''; status = 'invalid-output' }
                }
                $outDone = ($read -eq 0)
                if (-not $outDone) {
                    $outTask = $process.StandardOutput.BaseStream.ReadAsync($stdout, $outCount, $stdout.Length-$outCount)
                }
            }
            if (-not $errDone -and $errTask.IsCompleted) {
                $read = $errTask.Result
                $errCount += $read
                if ($errCount -gt 65536) {
                    return [pscustomobject]@{ exit_code = -1; text = ''; status = 'invalid-output' }
                }
                $errDone = ($read -eq 0)
                if (-not $errDone) {
                    $errTask = $process.StandardError.BaseStream.ReadAsync($stderr, $errCount, $stderr.Length-$errCount)
                }
            }
            if (-not ($outDone -and $errDone -and $process.HasExited)) { Start-Sleep -Milliseconds 10 }
        }
        $encoding = New-Object System.Text.UTF8Encoding ($false, $true)
        if ($outCount -ge 2 -and (($stdout[0] -eq 255 -and $stdout[1] -eq 254) -or $stdout[1] -eq 0)) {
            $encoding = New-Object System.Text.UnicodeEncoding ($false, $false, $true)
        }
        [pscustomobject]@{ exit_code = $process.ExitCode
            text = $encoding.GetString($stdout, 0, $outCount).TrimStart([char]0xFEFF); status = 'observed' }
    } catch {
        [pscustomobject]@{ exit_code = -1; text = ''; status = 'unavailable' }
    } finally {
        if ($started -and -not $process.HasExited) { $process.Kill(); $null = $process.WaitForExit(2000) }
        $process.Dispose()
    }
}

function Get-LumaWindowsObservation {
    [CmdletBinding()]
    param([ValidatePattern('^[A-Za-z]$')][string] $StorageDrive = 'D')
    if ($env:OS -ne 'Windows_NT') { throw 'Windows observation requires native Windows.' }
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $processors = @(Get-CimInstance Win32_Processor -ErrorAction Stop)
    $edition = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
        -Name EditionID -ErrorAction Stop
    $version = Invoke-LumaWslObservation version
    $list = Invoke-LumaWslObservation list
    $distributions = ConvertFrom-LumaWslList -Text $list.text -ExitCode $list.exit_code
    $drive = Get-PSDrive -Name $StorageDrive -PSProvider FileSystem -ErrorAction Stop
    $protection = Get-LumaHostProtectionObservation
    [pscustomobject]@{
        schema_version = 1
        observed_at_utc = [DateTime]::UtcNow.ToString('o')
        windows_caption = [string]$os.Caption
        windows_edition = [string]$edition.EditionID
        windows_version = [string]$os.Version
        windows_build = [int]$os.BuildNumber
        windows_product_type = [int]$os.ProductType
        processor_architectures = @($processors | ForEach-Object { [int]$_.Architecture } | Sort-Object -Unique)
        virtualization_firmware = @($processors | ForEach-Object { $_.VirtualizationFirmwareEnabled })
        hypervisor_present = [bool]$system.HypervisorPresent
        total_memory_bytes = [uint64]$os.TotalVisibleMemorySize * 1024
        available_memory_bytes = [uint64]$os.FreePhysicalMemory * 1024
        storage_drive = $StorageDrive.ToUpperInvariant()
        storage_free_bytes = [uint64]$drive.Free
        wsl_runtime = $version
        wsl = $distributions
        host_encryption = $protection.host_encryption
        enterprise_policy = $protection.enterprise_policy
        nested_virtualization = 'not-qualified'
        confinement = 'not-qualified'
        accelerator = 'not-qualified'
    }
}

function Test-LumaWindowsPreflight {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Observation,
        [ValidatePattern('^LumaOS-[A-Za-z0-9-]{1,48}$')][string] $DistributionName = 'LumaOS-Dev',
        [ValidateRange(1,1024)][int] $GuestMemoryGiB = 12,
        $StoragePlan = $null, $ReleasePolicy = $null)
    if ($Observation.schema_version -ne 1) { throw 'Unsupported Windows observation schema.' }
    $blockers = New-Object 'System.Collections.Generic.List[string]'
    if ($Observation.windows_product_type -ne 1 -or $Observation.windows_build -lt 22000 -or
        $Observation.windows_version -notmatch '^10\.0\.\d+(\.\d+)?$') {
        $blockers.Add('Windows 11 workstation baseline not observed.')
    }
    $architectures = @($Observation.processor_architectures)
    if ($architectures.Count -ne 1 -or $architectures[0] -ne 9) {
        $blockers.Add('AMD64 processor architecture not observed.')
    }
    if (-not $Observation.hypervisor_present -and
        @($Observation.virtualization_firmware | Where-Object { $_ -eq $true }).Count -eq 0) {
        $blockers.Add('Virtualization availability not observed.')
    }
    if ($Observation.wsl.status -ne 'observed' -or $Observation.wsl_runtime.status -ne 'observed' -or
        $Observation.wsl_runtime.exit_code -ne 0 -or [string]::IsNullOrWhiteSpace($Observation.wsl_runtime.text)) {
        $blockers.Add('WSL runtime/distribution inventory unavailable; no installation inferred.')
    }
    if (@($Observation.wsl.distributions | Where-Object { $_.version -eq 2 }).Count -eq 0) {
        $blockers.Add('No WSL2 development distribution observed; WSL1 is not sufficient.')
    }
    if (@($Observation.wsl.distributions | Where-Object { $_.name -ieq $DistributionName }).Count -gt 0) {
        $blockers.Add('Requested product distribution name already exists; replacement is forbidden.')
    }
    $reserve = [uint64]8 * 1GB
    $requested = [uint64]$GuestMemoryGiB * 1GB
    if ($Observation.available_memory_bytes -gt $Observation.total_memory_bytes -or
        $Observation.available_memory_bytes -lt ($reserve + $requested)) {
        $blockers.Add('Observed available memory does not cover the proposed guest plus 8-GiB host reserve.')
    }
    $storage = Test-LumaStoragePlan -Observation $Observation -Plan $StoragePlan
    $release = Test-LumaReleasePolicy -Observation $Observation -Policy $ReleasePolicy
    $planningBlockers = New-Object 'System.Collections.Generic.List[string]'
    if (-not ($Observation.PSObject.Properties.Name -ccontains 'host_encryption') -or
        $null -eq $Observation.host_encryption -or $Observation.host_encryption.status -cne 'protected' -or
        $Observation.host_encryption.protection_observed -isnot [bool] -or -not $Observation.host_encryption.protection_observed) {
        $planningBlockers.Add('Actual fixed private custody/product volume must have observed active full encryption; suspended, absent, locked, unsupported or unknown protection refuses admission.')
    }
    if (-not ($Observation.PSObject.Properties.Name -ccontains 'enterprise_policy') -or
        $null -eq $Observation.enterprise_policy -or $Observation.enterprise_policy.status -cne 'no-management-signals-observed' -or
        $Observation.enterprise_policy.known_local_checks_passed -isnot [bool] -or -not $Observation.enterprise_policy.known_local_checks_passed) {
        $planningBlockers.Add('Known local Windows policy checks must pass; managed, configured, denied or unknown signals require separate authenticated enterprise authorization, not an observation flag.')
    }
    if (-not $storage.capacity_observation_passed) {
        $planningBlockers.Add('An explicit complete storage budget must fit the observed selected-drive free capacity.')
    }
    if (-not $release.tuple_matches_input) {
        $planningBlockers.Add('Observed Windows edition/build and WSL runtime must match an explicit reviewed comparison tuple.')
    }
    [pscustomobject]@{
        schema_version = 1; profile = 'W'; proposed_distribution = $DistributionName
        development_observations_passed = ($blockers.Count -eq 0)
        blockers = @($blockers.ToArray())
        planning_observations_passed = ($blockers.Count -eq 0 -and $planningBlockers.Count -eq 0)
        planning_blockers = @($planningBlockers.ToArray()); storage_planning = $storage; release_comparison = $release
        guest_memory_requested_bytes = $requested; host_reserve_bytes = $reserve
        guest_memory_reserved = $false; global_wsl_settings_changed = $false
        existing_distributions_changed = $false; product_installation_admitted = $false
        executable_skills_enabled = $false; production_qualified = $false; gate_closing = $false
        pending_qualification = @('Authenticated production release policy and actual per-tuple qualification',
            'Fresh storage recheck and exclusive allocation at installation',
            'Installed encryption/policy transition qualification and authenticated enterprise authorization when applicable', 'Effective guest limits and other WSL workloads',
            'Authenticated bridge and Windows ACL broker', 'Enforcing worker confinement',
            'Actual compact inference', 'Hyper-V Gen2 desktop and recovery proof')
        observation = $Observation
    }
}

Export-ModuleMember -Function ConvertFrom-LumaWslList, Get-LumaWindowsObservation, Test-LumaWindowsPreflight,
    Test-LumaStoragePlan, Test-LumaReleasePolicy, Read-LumaPlanningJson, Get-LumaHostProtectionObservation
