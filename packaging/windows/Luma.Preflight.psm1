Set-StrictMode -Version Latest

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
    $version = Invoke-LumaWslObservation version
    $list = Invoke-LumaWslObservation list
    $distributions = ConvertFrom-LumaWslList -Text $list.text -ExitCode $list.exit_code
    $drive = Get-PSDrive -Name $StorageDrive -PSProvider FileSystem -ErrorAction Stop
    [pscustomobject]@{
        schema_version = 1
        observed_at_utc = [DateTime]::UtcNow.ToString('o')
        windows_caption = [string]$os.Caption
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
        host_encryption = 'not-qualified'
        enterprise_policy = 'not-qualified'
        nested_virtualization = 'not-qualified'
        confinement = 'not-qualified'
        accelerator = 'not-qualified'
    }
}

function Test-LumaWindowsPreflight {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Observation,
        [ValidatePattern('^LumaOS-[A-Za-z0-9-]{1,48}$')][string] $DistributionName = 'LumaOS-Dev',
        [ValidateRange(1,1024)][int] $GuestMemoryGiB = 12)
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
    [pscustomobject]@{
        schema_version = 1; profile = 'W'; proposed_distribution = $DistributionName
        development_observations_passed = ($blockers.Count -eq 0)
        blockers = @($blockers.ToArray())
        guest_memory_requested_bytes = $requested; host_reserve_bytes = $reserve
        guest_memory_reserved = $false; global_wsl_settings_changed = $false
        existing_distributions_changed = $false; product_installation_admitted = $false
        executable_skills_enabled = $false; production_qualified = $false; gate_closing = $false
        pending_qualification = @('Supported exact Windows/WSL release policy',
            'Calculated active/candidate/model/state/backup/recovery storage',
            'Host encryption and managed-device policy', 'Effective guest limits and other WSL workloads',
            'Authenticated bridge and Windows ACL broker', 'Enforcing worker confinement',
            'Actual compact inference', 'Hyper-V Gen2 desktop and recovery proof')
        observation = $Observation
    }
}

Export-ModuleMember -Function ConvertFrom-LumaWslList, Get-LumaWindowsObservation, Test-LumaWindowsPreflight
