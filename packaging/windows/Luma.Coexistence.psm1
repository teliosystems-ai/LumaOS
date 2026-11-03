Set-StrictMode -Version Latest

# Read-only W009 coexistence planning. Nothing in this module edits the global
# WSL configuration, stops or starts a distribution, or reserves memory.
$script:Preflight = Import-Module (Join-Path $PSScriptRoot 'Luma.Preflight.psm1') -PassThru -ErrorAction Stop

# Mirrors HostedInferenceContract in HostedAuthorityInference.cs; the test joins both.
$script:LowWaterReserveBytes = [uint64]1073741824
$script:InferenceStartBytes = [uint64]5905580032
$script:ConfigBound = 65536
$script:GiB = [uint64]1073741824
$script:MiB = [uint64]1048576

function Assert-LumaCoexistenceRecord {
    param($Value, [string[]] $Fields, [string] $Name)
    & $script:Preflight { param($v, $f, $n) Assert-LumaClosedRecord $v $f $n } $Value $Fields $Name
}

function ConvertTo-LumaCoexistenceCount {
    param($Value, [string] $Name)
    & $script:Preflight { param($v, $n) ConvertTo-LumaUnsignedBytes $v $n } $Value $Name
}

function ConvertTo-LumaSizeBytes {
    param([string] $Text, [switch] $AllowBareZero)
    if ($AllowBareZero -and $Text -ceq '0') { return [uint64]0 }
    if ($Text -cnotmatch '^(?<n>[0-9]{1,15})(?<u>MB|GB)$') { return $null }
    $unit = if ($Matches.u -ceq 'GB') { [decimal]$script:GiB } else { [decimal]$script:MiB }
    $value = [decimal]$Matches.n * $unit
    if ($value -gt [decimal][uint64]::MaxValue) { return $null }
    return [uint64]$value
}

function ConvertFrom-LumaWslConfig {
    [CmdletBinding()]
    param([AllowNull()][byte[]] $Bytes)
    if ($null -eq $Bytes) {
        return [pscustomobject]@{ status='absent'; reason='no-user-configuration-file'; sha256=$null; length=[uint64]0
            memory_bytes=$null; memory_text=$null; swap_bytes=$null; swap_text=$null; processors=$null }
    }
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try { $digest = -join ($hasher.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $hasher.Dispose() }
    $unknown = { param([string] $Reason)
        [pscustomobject]@{ status='unknown'; reason=$Reason; sha256=$digest; length=[uint64]$Bytes.Length
            memory_bytes=$null; memory_text=$null; swap_bytes=$null; swap_text=$null; processors=$null } }
    if ($Bytes.Length -gt $script:ConfigBound) { return & $unknown 'oversized' }
    $offset = 0
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { $offset = 3 }
    try {
        $text = (New-Object System.Text.UTF8Encoding ($false, $true)).GetString($Bytes, $offset, $Bytes.Length - $offset)
    } catch { return & $unknown 'not-strict-utf8' }
    if ($text -match '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\uFEFF\uFFFE]') { return & $unknown 'control-character' }
    $section = $null
    $values = @{}
    foreach ($line in ($text -split '\r?\n')) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith('#')) { continue }
        if ($trimmed -match '^\[(?<name>[A-Za-z0-9_.-]{1,64})\]$') {
            if ($Matches.name -ine 'wsl2') { $section = $Matches.name; continue }
            if ($Matches.name -cne 'wsl2') { return & $unknown 'noncanonical-wsl2-section' }
            $section = 'wsl2'; continue
        }
        if ($trimmed -notmatch '^(?<key>[A-Za-z][A-Za-z0-9_.]{0,63})\s*=\s*(?<value>.*)$') { return & $unknown 'unparsed-line' }
        if ($section -cne 'wsl2') { continue }
        $key = $Matches.key
        $value = $Matches.value
        if (@('memory', 'swap', 'processors') -inotcontains $key) { continue }
        if (@('memory', 'swap', 'processors') -cnotcontains $key) { return & $unknown 'noncanonical-resource-key' }
        if ($values.ContainsKey($key)) { return & $unknown 'duplicate-resource-key' }
        $values[$key] = $value
    }
    $memory = $null; $swap = $null; $processors = $null
    if ($values.ContainsKey('memory')) {
        $memory = ConvertTo-LumaSizeBytes $values.memory
        if ($null -eq $memory -or $memory -eq 0) { return & $unknown 'unsupported-memory-value' }
    }
    if ($values.ContainsKey('swap')) {
        $swap = ConvertTo-LumaSizeBytes $values.swap -AllowBareZero
        if ($null -eq $swap) { return & $unknown 'unsupported-swap-value' }
    }
    if ($values.ContainsKey('processors')) {
        if ($values.processors -cnotmatch '^[1-9][0-9]{0,3}$') { return & $unknown 'unsupported-processors-value' }
        $processors = [int]$values.processors
    }
    [pscustomobject]@{ status='observed'; reason='parsed'; sha256=$digest; length=[uint64]$Bytes.Length
        memory_bytes=$memory; memory_text=$(if ($values.ContainsKey('memory')) { $values.memory } else { $null })
        swap_bytes=$swap; swap_text=$(if ($values.ContainsKey('swap')) { $values.swap } else { $null }); processors=$processors }
}

function Read-LumaWslConfigBytes {
    $path = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)) '.wslconfig'
    if (-not (Test-Path -LiteralPath $path)) { return [pscustomobject]@{ present=$false; bytes=$null; readable=$true } }
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item -isnot [System.IO.FileInfo] -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        return [pscustomobject]@{ present=$true; bytes=$null; readable=$false }
    }
    $stream = [System.IO.File]::Open($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $buffer = New-Object byte[] ($script:ConfigBound + 1)
        $count = 0
        while ($count -lt $buffer.Length) {
            $read = $stream.Read($buffer, $count, $buffer.Length - $count)
            if ($read -eq 0) { break }
            $count += $read
        }
    } finally { $stream.Dispose() }
    $bytes = New-Object byte[] $count
    [Array]::Copy($buffer, $bytes, $count)
    [pscustomobject]@{ present=$true; bytes=$bytes; readable=$true }
}

function Get-LumaObservedWslConfig {
    $file = Read-LumaWslConfigBytes
    if (-not $file.readable) {
        return [pscustomobject]@{ status='unknown'; reason='not-a-regular-file'; sha256=$null; length=[uint64]0
            memory_bytes=$null; memory_text=$null; swap_bytes=$null; swap_text=$null; processors=$null }
    }
    if (-not $file.present) { return ConvertFrom-LumaWslConfig -Bytes $null }
    ConvertFrom-LumaWslConfig -Bytes $file.bytes
}

function Get-LumaWslVmSample {
    # vmmemWSL is the shared per-user WSL2 utility VM; other vmmem processes are
    # non-WSL virtual machines and therefore count as Windows-side use.
    $processes = @([System.Diagnostics.Process]::GetProcessesByName('vmmemWSL'))
    try {
        if ($processes.Count -eq 0) {
            return [pscustomobject]@{ status='not-running'; working_set_bytes=[uint64]0; private_bytes=[uint64]0 }
        }
        if ($processes.Count -gt 1) {
            return [pscustomobject]@{ status='ambiguous'; working_set_bytes=[uint64]0; private_bytes=[uint64]0 }
        }
        try {
            $workingSet = [uint64]$processes[0].WorkingSet64
            $private = [uint64]$processes[0].PrivateMemorySize64
        } catch {
            return [pscustomobject]@{ status='unavailable'; working_set_bytes=[uint64]0; private_bytes=[uint64]0 }
        }
        [pscustomobject]@{ status='running'; working_set_bytes=$workingSet; private_bytes=$private }
    } finally { foreach ($process in $processes) { $process.Dispose() } }
}

function Get-LumaWslCoexistenceObservation {
    [CmdletBinding()]
    param([ValidateRange(1,120)][int] $Samples = 10, [ValidateRange(250,60000)][int] $IntervalMilliseconds = 1000)
    if ($env:OS -ne 'Windows_NT') { throw 'Coexistence observation requires native Windows.' }
    $configBefore = Get-LumaObservedWslConfig
    $list = & $script:Preflight { Invoke-LumaWslObservation list }
    $inventory = ConvertFrom-LumaWslList -Text $list.text -ExitCode $list.exit_code
    $total = $null
    $records = New-Object 'System.Collections.Generic.List[object]'
    $clock = [Diagnostics.Stopwatch]::StartNew()
    for ($index = 0; $index -lt $Samples; $index++) {
        if ($index -gt 0) { Start-Sleep -Milliseconds $IntervalMilliseconds }
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $vm = Get-LumaWslVmSample
        $sampleTotal = [uint64]$os.TotalVisibleMemorySize * 1024
        if ($null -eq $total) { $total = $sampleTotal }
        elseif ($sampleTotal -ne $total) { throw 'Total visible memory changed during sampling.' }
        $records.Add([pscustomobject]@{ elapsed_milliseconds=[uint64]$clock.ElapsedMilliseconds
            available_memory_bytes=[uint64]$os.FreePhysicalMemory * 1024; wsl_vm=$vm })
    }
    $configAfter = Get-LumaObservedWslConfig
    [pscustomobject]@{
        schema_version = 1
        observed_at_utc = [DateTime]::UtcNow.ToString('o')
        total_memory_bytes = $total
        samples = @($records.ToArray())
        wsl_config = $configBefore
        wsl_config_unchanged = ($configBefore.status -ceq $configAfter.status -and $configBefore.sha256 -ceq $configAfter.sha256)
        wsl = $inventory
    }
}

function Test-LumaWslCoexistenceObservationShape {
    param($Observation)
    Assert-LumaCoexistenceRecord $Observation @('schema_version', 'observed_at_utc', 'total_memory_bytes', 'samples',
        'wsl_config', 'wsl_config_unchanged', 'wsl') 'Coexistence observation'
    if ((ConvertTo-LumaCoexistenceCount $Observation.schema_version 'Coexistence schema') -ne 1) {
        throw 'Unsupported coexistence observation schema.'
    }
    if ($Observation.observed_at_utc -isnot [string] -or $Observation.wsl_config_unchanged -isnot [bool]) {
        throw 'Coexistence observation time and configuration stability must be typed.'
    }
    $total = ConvertTo-LumaCoexistenceCount $Observation.total_memory_bytes 'Total memory'
    if ($total -eq 0) { throw 'Total memory must be positive.' }
    if ($Observation.samples -isnot [array] -or $Observation.samples.Count -lt 1 -or $Observation.samples.Count -gt 3600) {
        throw 'Coexistence observation requires 1 to 3600 samples.'
    }
    foreach ($sample in $Observation.samples) {
        Assert-LumaCoexistenceRecord $sample @('elapsed_milliseconds', 'available_memory_bytes', 'wsl_vm') 'Memory sample'
        $null = ConvertTo-LumaCoexistenceCount $sample.elapsed_milliseconds 'Sample time'
        if ((ConvertTo-LumaCoexistenceCount $sample.available_memory_bytes 'Available memory') -gt $total) {
            throw 'Available memory exceeds total memory.'
        }
        Assert-LumaCoexistenceRecord $sample.wsl_vm @('status', 'working_set_bytes', 'private_bytes') 'WSL VM sample'
        $workingSet = ConvertTo-LumaCoexistenceCount $sample.wsl_vm.working_set_bytes 'VM working set'
        $private = ConvertTo-LumaCoexistenceCount $sample.wsl_vm.private_bytes 'VM private bytes'
        if (@('running', 'not-running', 'ambiguous', 'unavailable') -cnotcontains $sample.wsl_vm.status) {
            throw 'Unsupported WSL VM sample status.'
        }
        if ($sample.wsl_vm.status -cne 'running' -and ($workingSet -ne 0 -or $private -ne 0)) {
            throw 'Only a running WSL VM sample may carry memory figures.'
        }
    }
    $config = $Observation.wsl_config
    Assert-LumaCoexistenceRecord $config @('status', 'reason', 'sha256', 'length', 'memory_bytes', 'memory_text',
        'swap_bytes', 'swap_text', 'processors') 'WSL configuration observation'
    if (@('absent', 'observed', 'unknown') -cnotcontains $config.status) { throw 'Unsupported WSL configuration status.' }
    if ($config.status -cne 'observed' -and ($null -ne $config.memory_bytes -or $null -ne $config.swap_bytes)) {
        throw 'Only an observed WSL configuration may carry resource values.'
    }
    if ($null -ne $config.memory_bytes -and (ConvertTo-LumaCoexistenceCount $config.memory_bytes 'Configured memory') -eq 0) {
        throw 'Configured memory must be positive.'
    }
    if ($null -ne $config.swap_bytes) { $null = ConvertTo-LumaCoexistenceCount $config.swap_bytes 'Configured swap' }
    Assert-LumaCoexistenceRecord $Observation.wsl @('status', 'distributions') 'WSL inventory'
    if (@('observed', 'unknown') -cnotcontains $Observation.wsl.status -or $Observation.wsl.distributions -isnot [array]) {
        throw 'Unsupported WSL inventory status or distribution list.'
    }
    foreach ($distribution in $Observation.wsl.distributions) {
        Assert-LumaCoexistenceRecord $distribution @('name', 'version', 'default', 'state') 'WSL distribution'
        if ($distribution.name -isnot [string] -or $distribution.state -isnot [string] -or $distribution.default -isnot [bool] -or
            @(1, 2) -notcontains (ConvertTo-LumaCoexistenceCount $distribution.version 'WSL version')) {
            throw 'WSL distribution records must carry a name, state, default flag and version 1 or 2.'
        }
    }
    return $total
}

function Get-LumaProposedSize {
    param([uint64] $Minimum, [uint64] $Maximum, [ValidateSet('lower', 'raise')][string] $Direction)
    foreach ($unit in @($script:GiB, $script:MiB)) {
        if ($Direction -eq 'lower') { $candidate = [uint64]([decimal]::Floor([decimal]$Maximum / [decimal]$unit) * [decimal]$unit) }
        else { $candidate = [uint64]([decimal]::Ceiling([decimal]$Minimum / [decimal]$unit) * [decimal]$unit) }
        if ($candidate -ge $Minimum -and $candidate -le $Maximum -and $candidate -gt 0) {
            $suffix = if ($unit -eq $script:GiB) { 'GB' } else { 'MB' }
            return [pscustomobject]@{ bytes=$candidate; text=('{0}{1}' -f ([decimal]$candidate / [decimal]$unit), $suffix) }
        }
    }
    return $null
}

function Test-LumaWslCoexistence {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Observation,
        [ValidatePattern('^(LumaOS-[A-Za-z0-9-]{1,48}|LumaHosted-[0-9a-f]{64}-(0|[1-9][0-9]{0,19})-[0-9a-f]{32})$')][string] $ProductDistribution = 'LumaOS-Dev')
    $total = Test-LumaWslCoexistenceObservationShape $Observation
    $config = $Observation.wsl_config
    $observationBlockers = New-Object 'System.Collections.Generic.List[string]'
    $capacityBlockers = New-Object 'System.Collections.Generic.List[string]'
    if ($config.status -ceq 'unknown') {
        $observationBlockers.Add("Global WSL configuration could not be interpreted exactly ($($config.reason)); review it manually. No change is proposed.")
    }
    if (-not $Observation.wsl_config_unchanged) {
        $observationBlockers.Add('Global WSL configuration changed during sampling; repeat the observation.')
    }
    if ($Observation.wsl.status -cne 'observed') {
        $observationBlockers.Add('WSL distribution inventory unavailable; other WSL workloads and affected distributions are unknown.')
    }
    $peakWindows = [uint64]0
    $peakOther = [uint64]0
    $vmObservedRunning = $false
    $vmStatusBlocked = $false
    $inconsistent = $false
    foreach ($sample in $Observation.samples) {
        $available = [uint64]$sample.available_memory_bytes
        $inUse = $total - $available
        $vm = $sample.wsl_vm
        if (@('ambiguous', 'unavailable') -ccontains $vm.status) { $vmStatusBlocked = $true; continue }
        $workingSet = [uint64]$vm.working_set_bytes
        if ($vm.status -ceq 'running') { $vmObservedRunning = $true }
        if ($workingSet -gt $inUse) { $inconsistent = $true; continue }
        $windows = $inUse - $workingSet
        if ($windows -gt $peakWindows) { $peakWindows = $windows }
        $resident = [uint64][Math]::Max([decimal]$workingSet, [decimal][uint64]$vm.private_bytes)
        if ($resident -gt $peakOther) { $peakOther = $resident }
    }
    if ($vmStatusBlocked) {
        $observationBlockers.Add('More than one WSL VM memory process, or unreadable VM memory, was observed; per-user attribution needs the manual two-user procedure.')
    }
    if ($inconsistent) {
        $observationBlockers.Add('A WSL VM resident figure exceeded observed Windows in-use memory; repeat the observation.')
    }
    $distributions = @()
    if ($Observation.wsl.status -ceq 'observed') { $distributions = @($Observation.wsl.distributions) }
    $wsl2 = @($distributions | Where-Object { $_.version -eq 2 })
    $others = @($wsl2 | Where-Object { $_.name -ine $ProductDistribution })
    if (-not $vmObservedRunning -and $others.Count -gt 0) {
        $observationBlockers.Add('Other WSL2 distributions are registered but the shared WSL VM was not running during sampling; measure again with their normal workload running.')
    }
    $limit = $null
    $limitBasis = 'unknown'
    if ($config.status -cne 'unknown') {
        if ($null -eq $config.memory_bytes) {
            $limit = [uint64][decimal]::Floor([decimal]$total / [decimal]2); $limitBasis = 'wsl-default-half-of-physical'
        } elseif ([uint64]$config.memory_bytes -gt $total) {
            $limit = $total; $limitBasis = 'configured-capped-at-physical'
        } else {
            $limit = [uint64]$config.memory_bytes; $limitBasis = 'configured'
        }
    }
    $requiredReserve = $peakWindows + $script:LowWaterReserveBytes
    $maximum = $null
    if ($requiredReserve -lt $total) { $maximum = $total - $requiredReserve }
    $minimum = $peakOther + $script:InferenceStartBytes
    $feasible = ($null -ne $maximum -and $minimum -le $maximum)
    $currentFits = ($feasible -and $null -ne $limit -and $limit -ge $minimum -and $limit -le $maximum)
    if ($null -ne $limit) {
        if ($null -eq $maximum -or $limit -gt $maximum) {
            $capacityBlockers.Add('The effective WSL VM limit leaves less than the measured Windows foreground reserve if the shared VM reaches its limit.')
        }
        if ($limit -lt $minimum) {
            $capacityBlockers.Add('The effective WSL VM limit does not cover other WSL resident use plus the compact inference start budget; swap is not counted.')
        }
    }
    if (-not $feasible) {
        $capacityBlockers.Add('No WSL VM limit satisfies both the measured Windows foreground reserve and other WSL use plus compact inference start on this host; no change is proposed.')
    }
    $affected = @($wsl2 | ForEach-Object { [pscustomobject]@{ name=$_.name; state=$_.state; product=($_.name -ieq $ProductDistribution) } })
    $proposal = $null
    if ($observationBlockers.Count -eq 0 -and $feasible -and -not $currentFits -and $null -ne $limit) {
        $direction = if ($limit -gt $maximum) { 'lower' } else { 'raise' }
        $size = Get-LumaProposedSize -Minimum $minimum -Maximum $maximum -Direction $direction
        if ($null -eq $size) {
            $capacityBlockers.Add('The feasible WSL VM limit window contains no whole-MiB value; no change is proposed.')
        } else {
            $proposal = [pscustomobject]@{
                setting = '[wsl2] memory'; current_value_text = $config.memory_text; proposed_value_text = $size.text
                proposed_bytes = $size.bytes; direction = $direction
                creates_global_configuration = ($config.status -ceq 'absent')
                other_settings_unchanged = $true; affected_distributions = $affected
                requires_wsl_restart = $true; requires_reviewed_maintenance_action = $true; applied = $false
                maintenance_action = 'Owner-reviewed maintenance only: back up the user .wslconfig, change only the [wsl2] memory value, then stop every listed distribution at a planned time. This tool never edits the file or stops WSL.'
            }
        }
    }
    $status = if ($observationBlockers.Count -gt 0) { 'blocked-observation' }
        elseif ($currentFits) { 'current-limit-fits' }
        elseif ($null -ne $proposal) { 'change-proposed' }
        else { 'no-feasible-limit' }
    [pscustomobject]@{
        schema_version = 1; profile = 'W'; requirement = 'W009'; product_distribution = $ProductDistribution
        status = $status; coexistence_observations_passed = ($status -ceq 'current-limit-fits')
        blockers = @($observationBlockers.ToArray() + $capacityBlockers.ToArray())
        effective_vm_limit_bytes = $limit; effective_vm_limit_basis = $limitBasis
        configured_swap_bytes = $config.swap_bytes; swap_counted_as_model_capacity = $false
        windows_foreground = [pscustomobject]@{ sample_count = $Observation.samples.Count; peak_in_use_bytes = $peakWindows
            low_water_reserve_bytes = $script:LowWaterReserveBytes; required_reserve_bytes = $requiredReserve }
        other_wsl_workloads = [pscustomobject]@{ vm_observed_running = $vmObservedRunning; peak_resident_bytes = $peakOther
            other_wsl2_distributions = @($others | ForEach-Object { $_.name }) }
        inference_start_bytes = $script:InferenceStartBytes
        feasible_vm_limit = $(if ($feasible) { [pscustomobject]@{ minimum_bytes = $minimum; maximum_bytes = $maximum } } else { $null })
        proposed_change = $proposal; affected_distributions = $affected
        wsl_shutdown_issued = $false; global_wsl_settings_changed = $false; existing_distributions_changed = $false
        automatic_memory_change = $false; memory_reserved = $false; product_installation_admitted = $false
        production_qualified = $false; gate_closing = $false
        pending_qualification = @('Guest-observed effective memory limit inside the installed product distribution',
            'Installed per-service cgroup limits for product workers',
            'Windows foreground responsiveness under the declared workload (QW04) and combined saturation (V04)',
            'Joining the measured reserve to dispatch-time hosted inference admission',
            'Other Windows users and their separate WSL VMs (two-user coexistence)',
            'The installed LocalSystem service WSL VM, its inventory and the configuration WSL applies to it')
        observation = $Observation
    }
}

Export-ModuleMember -Function ConvertFrom-LumaWslConfig, Get-LumaWslCoexistenceObservation, Test-LumaWslCoexistence
