$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Luma.Preflight.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Luma.Coexistence.psm1') -Force
$script:Assertions = 0
$GiB = [uint64]1073741824
$MiB = [uint64]1048576
function Assert-Luma($Condition, [string]$Message) {
    $script:Assertions++
    if (-not $Condition) { throw $Message }
}
function Assert-LumaThrows([scriptblock] $Action, [string] $Message) {
    $threw = $false
    try { $null = & $Action } catch { $threw = $true }
    Assert-Luma $threw $Message
}
function ConvertTo-Bytes([string] $Text) { return ,([Text.Encoding]::UTF8.GetBytes($Text)) }
function New-RawSample([uint64] $Available, [uint64] $WorkingSet = 0, [uint64] $Private = 0, [string] $Status = '') {
    if (-not $Status) { $Status = if ($WorkingSet -gt 0 -or $Private -gt 0) { 'running' } else { 'not-running' } }
    [pscustomobject]@{ elapsed_milliseconds=[uint64]0; available_memory_bytes=$Available
        wsl_vm=[pscustomobject]@{ status=$Status; working_set_bytes=$WorkingSet; private_bytes=$Private } }
}
function New-Sample([decimal] $Available, [decimal] $WorkingSet = 0, [decimal] $Private = -1, [string] $Status = '') {
    if ($Private -lt 0) { $Private = $WorkingSet }
    New-RawSample ([uint64]($Available * $GiB)) ([uint64]($WorkingSet * $GiB)) ([uint64]($Private * $GiB)) $Status
}
$DefaultInventory = "  NAME            STATE           VERSION`n* Ubuntu          Running         2`n  docker-desktop  Running         2`n  Legacy          Stopped         1"
function New-Coexistence {
    param([decimal] $Total = 32, [object[]] $Samples = @((New-Sample 20 4)), $Config = "[wsl2]`nmemory=16GB`n",
        [string] $Inventory = $DefaultInventory)
    $bytes = if ($null -eq $Config) { $null } else { ConvertTo-Bytes $Config }
    [pscustomobject]@{ schema_version=1; observed_at_utc='2026-11-03T00:00:00.0000000Z'
        total_memory_bytes=[uint64]($Total * $GiB); samples=@($Samples)
        wsl_config=(ConvertFrom-LumaWslConfig -Bytes $bytes); wsl_config_unchanged=$true
        wsl=(ConvertFrom-LumaWslList $Inventory 0) }
}
function Assert-NoAuthority($Result, [string] $Case) {
    Assert-Luma (-not $Result.wsl_shutdown_issued -and -not $Result.global_wsl_settings_changed -and
        -not $Result.existing_distributions_changed -and -not $Result.automatic_memory_change -and
        -not $Result.memory_reserved -and -not $Result.product_installation_admitted -and
        -not $Result.production_qualified -and -not $Result.gate_closing -and
        -not $Result.swap_counted_as_model_capacity) "Coexistence result conferred authority or changed WSL: $Case."
    if ($null -ne $Result.proposed_change) {
        Assert-Luma (-not $Result.proposed_change.applied -and $Result.proposed_change.requires_reviewed_maintenance_action -and
            $Result.proposed_change.requires_wsl_restart -and $Result.proposed_change.other_settings_unchanged) "Proposal was not review-only: $Case."
    }
}

# Exact .wslconfig interpretation; anything ambiguous is unknown rather than defaulted.
$ownerText = "# Owner note.`r`n# Previously absent.`r`n[wsl2]`r`nmemory=12GB`r`nswap=2GB`r`n"
$owner = ConvertFrom-LumaWslConfig -Bytes (ConvertTo-Bytes $ownerText)
Assert-Luma ($owner.status -ceq 'observed' -and $owner.memory_bytes -eq 12 * $GiB -and $owner.swap_bytes -eq 2 * $GiB -and
    $null -eq $owner.processors -and $owner.memory_text -ceq '12GB') 'Owner configuration was not parsed exactly.'
$hasher = [Security.Cryptography.SHA256]::Create()
$expectedDigest = -join ($hasher.ComputeHash((ConvertTo-Bytes $ownerText)) | ForEach-Object { $_.ToString('x2') }); $hasher.Dispose()
Assert-Luma ($owner.sha256 -ceq $expectedDigest -and $owner.length -eq (ConvertTo-Bytes $ownerText).Length) 'Configuration digest was not bound to the bytes.'
$small = ConvertFrom-LumaWslConfig -Bytes (ConvertTo-Bytes "[wsl2]`r`nmemory = 512MB`r`nprocessors = 4`r`nswap=0`r`n")
Assert-Luma ($small.status -ceq 'observed' -and $small.memory_bytes -eq 512 * $MiB -and $small.swap_bytes -eq 0 -and
    $small.processors -eq 4) 'MB, bare-zero swap and processor values were not parsed.'
$bom = ConvertFrom-LumaWslConfig -Bytes ([byte[]](@(0xEF, 0xBB, 0xBF) + (ConvertTo-Bytes "[wsl2]`nmemory=8GB`n")))
Assert-Luma ($bom.status -ceq 'observed' -and $bom.memory_bytes -eq 8 * $GiB) 'UTF-8 byte-order mark was not accepted.'
$elsewhere = ConvertFrom-LumaWslConfig -Bytes (ConvertTo-Bytes "[experimental]`nautoMemoryReclaim=gradual`nMemory=99`n[general]`nmemory=4GB`n[wsl2]`nkernelCommandLine = a;b # c`nnetworkingMode=mirrored`n")
Assert-Luma ($elsewhere.status -ceq 'observed' -and $null -eq $elsewhere.memory_bytes -and $null -eq $elsewhere.swap_bytes) 'Keys outside [wsl2] memory/swap/processors changed the limit.'
$absent = ConvertFrom-LumaWslConfig -Bytes $null
Assert-Luma ($absent.status -ceq 'absent' -and $null -eq $absent.memory_bytes -and $null -eq $absent.sha256) 'Absent configuration was not distinguished.'
$unknownCases = [ordered]@{
    'unit-less memory' = "[wsl2]`nmemory=12`n"; 'lowercase unit' = "[wsl2]`nmemory=12gb`n"; 'fraction' = "[wsl2]`nmemory=1.5GB`n"
    'spaced unit' = "[wsl2]`nmemory=12 GB`n"; 'quoted' = "[wsl2]`nmemory=`"12GB`"`n"; 'inline comment' = "[wsl2]`nmemory=12GB # note`n"
    'zero memory' = "[wsl2]`nmemory=0GB`n"; 'negative' = "[wsl2]`nmemory=-1GB`n"; 'terabyte' = "[wsl2]`nmemory=1TB`n"
    'overflow' = "[wsl2]`nmemory=999999999999999GB`n"; 'noncanonical key' = "[wsl2]`nMemory=12GB`n"
    'noncanonical section' = "[WSL2]`nmemory=12GB`n"; 'duplicate' = "[wsl2]`nmemory=12GB`n[wsl2]`nmemory=4GB`n"
    'bare swap' = "[wsl2]`nswap=2`n"; 'zero processors' = "[wsl2]`nprocessors=0`n"; 'unparsed' = "[wsl2]`nmemory=12GB`ngarbage`n"
    'semicolon comment' = "; note`n[wsl2]`nmemory=12GB`n"; 'section comment' = "[wsl2] # c`nmemory=12GB`n"
    'control character' = "[wsl2]`nmemory=12GB`n# $([char]1)`n"
}
foreach ($case in $unknownCases.Keys) {
    $parsed = ConvertFrom-LumaWslConfig -Bytes (ConvertTo-Bytes $unknownCases[$case])
    Assert-Luma ($parsed.status -ceq 'unknown' -and $null -eq $parsed.memory_bytes -and $null -ne $parsed.sha256) "Ambiguous configuration admitted: $case."
}
foreach ($bytes in @([byte[]](0x5B, 0xC3, 0x28, 0x5D), [byte[]](@(0xFF, 0xFE) + [Text.Encoding]::Unicode.GetBytes("[wsl2]`nmemory=8GB`n")),
    [byte[]](@(0x23) * 65537))) {
    Assert-Luma ((ConvertFrom-LumaWslConfig -Bytes $bytes).status -ceq 'unknown') 'Non-UTF-8 or oversized configuration admitted.'
}

# Planning arithmetic: the measured reserve and other WSL use bound the shared VM limit.
$base = New-Coexistence
$before = $base | ConvertTo-Json -Depth 10 -Compress
$result = Test-LumaWslCoexistence $base
Assert-Luma (($base | ConvertTo-Json -Depth 10 -Compress) -ceq $before) 'Coexistence planning changed its input.'
Assert-Luma ($result.status -ceq 'current-limit-fits' -and $result.coexistence_observations_passed -and $result.blockers.Count -eq 0 -and
    $null -eq $result.proposed_change) 'A fitting limit was refused or changed.'
Assert-Luma ($result.effective_vm_limit_bytes -eq 16 * $GiB -and $result.effective_vm_limit_basis -ceq 'configured') 'Configured limit lost.'
Assert-Luma ($result.windows_foreground.peak_in_use_bytes -eq 8 * $GiB -and $result.windows_foreground.required_reserve_bytes -eq 9 * $GiB -and
    $result.other_wsl_workloads.peak_resident_bytes -eq 4 * $GiB -and $result.other_wsl_workloads.vm_observed_running) 'Measured reserve or other WSL use lost.'
Assert-Luma ($result.feasible_vm_limit.maximum_bytes -eq 23 * $GiB -and
    $result.feasible_vm_limit.minimum_bytes -eq 4 * $GiB + 5905580032) 'Feasible VM window miscalculated.'
Assert-Luma ((@($result.affected_distributions | ForEach-Object { $_.name }) -join ',') -ceq 'Ubuntu,docker-desktop') 'Affected WSL2 distributions not reported exactly.'
Assert-Luma ((@($result.other_wsl_workloads.other_wsl2_distributions) -join ',') -ceq 'Ubuntu,docker-desktop') 'Other WSL2 distributions not reported.'
Assert-NoAuthority $result 'fits'

$lower = Test-LumaWslCoexistence (New-Coexistence -Config "[wsl2]`nmemory=28GB`nswap=2GB`n")
Assert-Luma ($lower.status -ceq 'change-proposed' -and -not $lower.coexistence_observations_passed) 'An oversized VM limit was admitted.'
Assert-Luma ($lower.proposed_change.direction -ceq 'lower' -and $lower.proposed_change.proposed_value_text -ceq '23GB' -and
    $lower.proposed_change.proposed_bytes -eq 23 * $GiB -and $lower.proposed_change.current_value_text -ceq '28GB' -and
    -not $lower.proposed_change.creates_global_configuration) 'Reserve-preserving lower limit not proposed exactly.'
Assert-Luma (@($lower.proposed_change.affected_distributions).Count -eq 2 -and @($lower.blockers | Where-Object { $_ -match 'foreground reserve' }).Count -eq 1) 'Affected distributions or reserve blocker missing.'
Assert-NoAuthority $lower 'lower'

$raise = Test-LumaWslCoexistence (New-Coexistence -Config "[wsl2]`nmemory=8GB`n")
Assert-Luma ($raise.status -ceq 'change-proposed' -and $raise.proposed_change.direction -ceq 'raise' -and
    $raise.proposed_change.proposed_value_text -ceq '10GB' -and $raise.effective_vm_limit_bytes -eq 8 * $GiB) 'Insufficient VM limit not shown as a review-only raise.'
Assert-Luma (@($raise.blockers | Where-Object { $_ -match 'swap is not counted' }).Count -eq 1) 'Capacity blocker missing.'
Assert-NoAuthority $raise 'raise'

$swapped = Test-LumaWslCoexistence (New-Coexistence -Config "[wsl2]`nmemory=8GB`nswap=64GB`n")
$swapless = Test-LumaWslCoexistence (New-Coexistence -Config "[wsl2]`nmemory=8GB`nswap=0`n")
Assert-Luma ($swapped.status -ceq 'change-proposed' -and $swapped.configured_swap_bytes -eq 64 * $GiB -and $swapless.configured_swap_bytes -eq 0 -and
    $swapped.proposed_change.proposed_bytes -eq $swapless.proposed_change.proposed_bytes -and
    $swapped.feasible_vm_limit.minimum_bytes -eq $swapless.feasible_vm_limit.minimum_bytes) 'Swap was counted as resident model capacity.'
Assert-NoAuthority $swapped 'swap'

$default = Test-LumaWslCoexistence (New-Coexistence -Config $null)
Assert-Luma ($default.status -ceq 'current-limit-fits' -and $default.effective_vm_limit_bytes -eq 16 * $GiB -and
    $default.effective_vm_limit_basis -ceq 'wsl-default-half-of-physical') 'Absent configuration default not derived.'
$defaultLower = Test-LumaWslCoexistence (New-Coexistence -Config $null -Samples @((New-Sample 8 4)))
Assert-Luma ($defaultLower.status -ceq 'change-proposed' -and $defaultLower.proposed_change.creates_global_configuration -and
    $null -eq $defaultLower.proposed_change.current_value_text -and $defaultLower.proposed_change.proposed_value_text -ceq '11GB') 'Absent configuration change not shown as a new global file.'
Assert-NoAuthority $defaultLower 'default-lower'
$capped = Test-LumaWslCoexistence (New-Coexistence -Config "[wsl2]`nmemory=64GB`n")
Assert-Luma ($capped.effective_vm_limit_bytes -eq 32 * $GiB -and $capped.effective_vm_limit_basis -ceq 'configured-capped-at-physical' -and
    $capped.proposed_change.proposed_value_text -ceq '23GB') 'Limit above physical memory not capped.'

$empty = Test-LumaWslCoexistence (New-Coexistence -Total 16 -Samples @((New-Sample 1 6 8)) -Config "[wsl2]`nmemory=12GB`nswap=2GB`n")
Assert-Luma ($empty.status -ceq 'no-feasible-limit' -and $null -eq $empty.feasible_vm_limit -and $null -eq $empty.proposed_change -and
    @($empty.blockers | Where-Object { $_ -match '^No WSL VM limit' }).Count -eq 1) 'An infeasible host received a proposal.'
Assert-NoAuthority $empty 'empty'

$peak = Test-LumaWslCoexistence (New-Coexistence -Samples @((New-Sample 20 4), (New-Sample 15 4), (New-Sample 22 4)) -Config "[wsl2]`nmemory=20GB`n")
Assert-Luma ($peak.windows_foreground.peak_in_use_bytes -eq 13 * $GiB -and $peak.proposed_change.proposed_value_text -ceq '18GB' -and
    $peak.windows_foreground.sample_count -eq 3) 'Peak Windows use across samples not applied.'
$otherPeak = Test-LumaWslCoexistence (New-Coexistence -Samples @((New-Sample 20 4), (New-Sample 18 6), (New-Sample 20 4)) -Config "[wsl2]`nmemory=10GB`n")
Assert-Luma ($otherPeak.other_wsl_workloads.peak_resident_bytes -eq 6 * $GiB -and $otherPeak.proposed_change.proposed_value_text -ceq '12GB') 'Peak other WSL use across samples not applied.'
$private = Test-LumaWslCoexistence (New-Coexistence -Samples @((New-Sample 20 4 6)) -Config "[wsl2]`nmemory=10GB`n")
Assert-Luma ($private.other_wsl_workloads.peak_resident_bytes -eq 6 * $GiB -and $private.windows_foreground.peak_in_use_bytes -eq 8 * $GiB -and
    $private.proposed_change.proposed_value_text -ceq '12GB') 'Committed VM memory was not treated as other WSL use.'

$narrow = @((New-Sample 6.75 4.75))
$mibLower = Test-LumaWslCoexistence (New-Coexistence -Samples $narrow -Config "[wsl2]`nmemory=12GB`n")
$mibRaise = Test-LumaWslCoexistence (New-Coexistence -Samples $narrow -Config "[wsl2]`nmemory=4GB`n")
Assert-Luma ($mibLower.proposed_change.proposed_value_text -ceq '10752MB' -and $mibRaise.proposed_change.proposed_value_text -ceq '10496MB') 'Sub-GiB window did not fall back to whole MiB.'
$tight = Test-LumaWslCoexistence (New-Coexistence -Samples @((New-RawSample (13 * $GiB / 2 + 100) ($GiB + 1) ($GiB + 1))) -Config "[wsl2]`nmemory=4GB`n")
Assert-Luma ($tight.status -ceq 'no-feasible-limit' -and $null -ne $tight.feasible_vm_limit -and $null -eq $tight.proposed_change -and
    @($tight.blockers | Where-Object { $_ -match 'whole-MiB' }).Count -eq 1) 'A window without a representable value received a proposal.'

# Observation gaps fail closed and never produce a proposal.
$stopped = Test-LumaWslCoexistence (New-Coexistence -Samples @((New-Sample 20 0)) -Config "[wsl2]`nmemory=8GB`n")
Assert-Luma ($stopped.status -ceq 'blocked-observation' -and $null -eq $stopped.proposed_change -and
    @($stopped.blockers | Where-Object { $_ -match 'not running during sampling' }).Count -eq 1) 'Unmeasured other WSL workloads admitted.'
$productOnly = Test-LumaWslCoexistence (New-Coexistence -Samples @((New-Sample 20 0)) `
    -Inventory "  NAME            STATE           VERSION`n* LumaOS-Dev      Stopped         2`n  Legacy          Stopped         1")
Assert-Luma ($productOnly.status -ceq 'current-limit-fits' -and @($productOnly.affected_distributions).Count -eq 1 -and
    $productOnly.affected_distributions[0].product -and @($productOnly.other_wsl_workloads.other_wsl2_distributions).Count -eq 0) 'Product-only inventory misclassified.'
# The installed hosted authority names its slot LumaHosted-INSTALLATION-SEQUENCE-PACKAGE.
$hostedName = 'LumaHosted-' + ('a' * 64) + '-7-' + ('b' * 32)
$hosted = Test-LumaWslCoexistence (New-Coexistence -Samples @((New-Sample 20 4)) -Config "[wsl2]`nmemory=16GB`n" `
    -Inventory "  NAME  STATE  VERSION`n* Ubuntu  Running  2`n  $hostedName  Running  2") -ProductDistribution $hostedName
Assert-Luma ($hosted.status -ceq 'current-limit-fits' -and $hosted.product_distribution -ceq $hostedName -and
    (@($hosted.other_wsl_workloads.other_wsl2_distributions) -join ',') -ceq 'Ubuntu' -and
    @($hosted.affected_distributions | Where-Object { $_.product }).Count -eq 1) 'Installed hosted product distribution misclassified.'
foreach ($badName in @(('LumaHosted-' + ('a' * 63) + '-7-' + ('b' * 32)), ('LumaHosted-' + ('a' * 64) + '-07-' + ('b' * 32)),
        ('LumaHosted-' + ('g' * 64) + '-7-' + ('b' * 32)), ('LumaHosted-' + ('a' * 64) + '-7-' + ('b' * 32) + '-x'))) {
    Assert-LumaThrows { Test-LumaWslCoexistence (New-Coexistence) -ProductDistribution $badName } "Malformed hosted distribution name accepted: $badName."
}
foreach ($status in @('ambiguous', 'unavailable')) {
    $gap = Test-LumaWslCoexistence (New-Coexistence -Samples @((New-Sample 20 4), (New-Sample 20 0 0 $status)) -Config "[wsl2]`nmemory=8GB`n")
    Assert-Luma ($gap.status -ceq 'blocked-observation' -and $null -eq $gap.proposed_change -and
        @($gap.blockers | Where-Object { $_ -match 'two-user' }).Count -eq 1) "Unattributed WSL VM memory admitted: $status."
    Assert-NoAuthority $gap $status
}
$unknownConfig = Test-LumaWslCoexistence (New-Coexistence -Config "[wsl2]`nmemory=12`n")
Assert-Luma ($unknownConfig.status -ceq 'blocked-observation' -and $null -eq $unknownConfig.effective_vm_limit_bytes -and
    $unknownConfig.effective_vm_limit_basis -ceq 'unknown' -and $null -eq $unknownConfig.proposed_change) 'Unknown configuration was defaulted.'
$changed = New-Coexistence -Config "[wsl2]`nmemory=8GB`n"; $changed.wsl_config_unchanged = $false
$changedResult = Test-LumaWslCoexistence $changed
Assert-Luma ($changedResult.status -ceq 'blocked-observation' -and $null -eq $changedResult.proposed_change) 'Configuration changed during sampling was accepted.'
$noInventory = New-Coexistence; $noInventory.wsl = ConvertFrom-LumaWslList '' 1
$noInventoryResult = Test-LumaWslCoexistence $noInventory
Assert-Luma ($noInventoryResult.status -ceq 'blocked-observation' -and @($noInventoryResult.affected_distributions).Count -eq 0) 'Unknown inventory was accepted.'
$inconsistent = Test-LumaWslCoexistence (New-Coexistence -Samples @((New-Sample 20 13)))
Assert-Luma ($inconsistent.status -ceq 'blocked-observation' -and -not $inconsistent.coexistence_observations_passed) 'Inconsistent VM sample accepted.'

# Closed, typed observation records.
$malformed = [ordered]@{
    'schema' = { param($o) $o.schema_version = 2 }
    'extra field' = { param($o) $o | Add-Member authority 'trusted' }
    'available above total' = { param($o) $o.samples[0].available_memory_bytes = [uint64](33 * $GiB) }
    'negative' = { param($o) $o.samples[0].available_memory_bytes = -1 }
    'string count' = { param($o) $o.total_memory_bytes = '34359738368' }
    'boolean count' = { param($o) $o.samples[0].wsl_vm.working_set_bytes = $true }
    'double count' = { param($o) $o.samples[0].available_memory_bytes = [double]1 }
    'zero total' = { param($o) $o.total_memory_bytes = 0; $o.samples[0].available_memory_bytes = 0; $o.samples[0].wsl_vm = [pscustomobject]@{ status='not-running'; working_set_bytes=[uint64]0; private_bytes=[uint64]0 } }
    'no samples' = { param($o) $o.samples = @() }
    'too many samples' = { param($o) $o.samples = @(1..3601 | ForEach-Object { New-Sample 20 4 }) }
    'scalar sample' = { param($o) $o.samples = $o.samples[0] }
    'sample field' = { param($o) $o.samples[0] | Add-Member note 'x' }
    'vm status' = { param($o) $o.samples[0].wsl_vm.status = 'paused' }
    'stopped with memory' = { param($o) $o.samples[0].wsl_vm.status = 'not-running' }
    'config status' = { param($o) $o.wsl_config.status = 'trusted' }
    'unknown config value' = { param($o) $o.wsl_config.status = 'unknown' }
    'stability type' = { param($o) $o.wsl_config_unchanged = 'true' }
    'inventory status' = { param($o) $o.wsl.status = 'assumed' }
    'distribution version' = { param($o) $o.wsl.distributions[0].version = 3 }
    'distribution field' = { param($o) $o.wsl.distributions[0] | Add-Member owner 'x' }
}
foreach ($case in $malformed.Keys) {
    $bad = New-Coexistence
    & $malformed[$case] $bad
    Assert-LumaThrows { Test-LumaWslCoexistence $bad } "Malformed observation accepted: $case."
}
$missing = New-Coexistence; $missing.PSObject.Properties.Remove('samples')
Assert-LumaThrows { Test-LumaWslCoexistence $missing } 'Observation without samples accepted.'
Assert-LumaThrows { Test-LumaWslCoexistence (New-Coexistence) -ProductDistribution 'Ubuntu' } 'Non-product distribution name accepted.'

# The planning constants are joined to the hosted inference contract, and the
# module cannot change WSL or host state.
$contract = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'HostedAuthorityInference.cs') -Raw
Assert-Luma ($contract -match 'public const ulong MemoryBytes=(?<memory>[0-9]+);' -and
    [uint64]$Matches.memory + $result.windows_foreground.low_water_reserve_bytes -eq $result.inference_start_bytes) 'Inference start budget diverged from the hosted contract.'
Assert-Luma ($contract -match 'public const ulong HostMemoryReserveBytes=(?<reserve>[0-9]+)UL;' -and
    [uint64]$Matches.reserve -eq $result.windows_foreground.low_water_reserve_bytes) 'Low-water reserve diverged from the hosted contract.'
foreach ($file in @('Luma.Coexistence.psm1', 'coexistence.ps1')) {
    $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot $file) -Raw
    Assert-Luma ($text -notmatch '(?i)--(shutdown|terminate|unregister|import|set-default|set-version|install|mount)|wsl\.exe|wslconfig\.exe|Set-Content|Add-Content|Out-File|WriteAll|Remove-Item|New-Item|Move-Item|Copy-Item|Rename-Item|Set-ItemProperty|Stop-Process|Start-Process|Restart-Service|Stop-Service|FileAccess\]::(ReadWrite|Write)|FileMode\]::(Create|Truncate|Append|OpenOrCreate)') "Mutating command present in $file."
}
Write-Output "Passed $script:Assertions PowerShell coexistence assertions; no host changes."
