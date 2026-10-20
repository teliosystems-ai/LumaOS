$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Luma.Preflight.psm1') -Force
$script:Assertions = 0
function Assert-Luma($Condition, [string]$Message) {
    $script:Assertions++
    if (-not $Condition) { throw $Message }
}
function Assert-LumaThrows([scriptblock] $Action, [string] $Message) {
    $threw = $false
    try { $null = & $Action } catch { $threw = $true }
    Assert-Luma $threw $Message
}
function New-Observation {
    [pscustomobject]@{ schema_version=1; windows_build=26100; windows_version='10.0.26100'
        windows_product_type=1; windows_edition='Professional'; processor_architectures=@(9); virtualization_firmware=@($true)
        hypervisor_present=$true; available_memory_bytes=32GB; total_memory_bytes=64GB
        storage_drive='D'; storage_free_bytes=[uint64]32GB
        host_encryption=[pscustomobject]@{status='protected';protection_observed=$true}
        enterprise_policy=[pscustomobject]@{status='no-management-signals-observed';known_local_checks_passed=$true}
        wsl_runtime=[pscustomobject]@{ status='observed'; exit_code=0; text='WSL version: 2.6.0.0' }
        wsl=(ConvertFrom-LumaWslList "  NAME            STATE           VERSION`n* Ubuntu          Running         2" 0) }
}
function New-StoragePlan {
    [pscustomobject]@{ schema_version=1; storage_drive='D'; active_image_bytes=1GB
        candidate_image_bytes=2GB; model_pack_bytes=3GB; state_migration_bytes=1GB
        user_quota_bytes=4GB; backup_staging_bytes=2GB; recovery_reserve_bytes=1GB }
}
function New-ReleasePolicy {
    [pscustomobject]@{ schema_version=1; review_reference='test-fixture-only-not-production'
        tuples=@([pscustomobject]@{ windows_edition='Professional'; windows_build=26100; wsl_runtime_version='2.6.0.0' }) }
}
$parsed = ConvertFrom-LumaWslList "  NAME            STATE           VERSION`n* Ubuntu          Running         2`n  Debian          Stopped         1" 0
Assert-Luma ($parsed.status -eq 'observed' -and $parsed.distributions.Count -eq 2) 'Valid inventory not parsed.'
Assert-Luma ($parsed.distributions[0].default -and $parsed.distributions[1].version -eq 1) 'WSL mode/default lost.'
$localized = ConvertFrom-LumaWslList "  NAME            STATUS          VERSION`n* Ubuntu          Wird ausgeführt  2" 0
Assert-Luma ($localized.status -eq 'observed') 'Localized state was incorrectly interpreted.'
foreach ($inputText in @('', 'No distributions installed.',
    "NAME STATE VERSION`n  Ubuntu   Running   3",
    "NAME STATE VERSION`n* Ubuntu   Running   2`n* Debian   Running   2",
    "NAME STATE VERSION`n  Ubuntu   Running   2`n  ubuntu   Stopped   2",
    "NAME STATE VERSION`n  Ubuntu   Running   2`nnot a row",
    "* LumaOS-Dev   Running   2`n  Ubuntu   Running   2")) {
    Assert-Luma ((ConvertFrom-LumaWslList $inputText 0).status -eq 'unknown') 'Ambiguous inventory admitted.'
}
Assert-Luma ((ConvertFrom-LumaWslList ('x' * 65537) 0).status -eq 'unknown') 'Unbounded inventory admitted.'
Assert-Luma ((ConvertFrom-LumaWslList "NAME STATE VERSION`n  Ubuntu   Running   2" 1).status -eq 'unknown') 'Command failure ignored.'
$base = New-Observation
$before = $base | ConvertTo-Json -Depth 8 -Compress
$result = Test-LumaWindowsPreflight $base
Assert-Luma $result.development_observations_passed 'Valid development observations refused.'
Assert-Luma (-not $result.product_installation_admitted -and -not $result.executable_skills_enabled `
    -and -not $result.gate_closing -and -not $result.production_qualified) 'Observation conferred product authority.'
Assert-Luma (($base | ConvertTo-Json -Depth 8 -Compress) -eq $before) 'Preflight changed its input.'
Assert-Luma (-not $result.planning_observations_passed -and $result.planning_blockers.Count -eq 2) 'Missing planning input admitted.'
foreach ($change in @('build', 'server', 'arm', 'virtualization', 'wsl1', 'inventory', 'runtime', 'memory', 'collision')) {
    $bad = New-Observation
    switch ($change) {
        build { $bad.windows_build = 19045 }
        server { $bad.windows_product_type = 3 }
        arm { $bad.processor_architectures = @(12) }
        virtualization { $bad.hypervisor_present=$false; $bad.virtualization_firmware=@($false) }
        wsl1 { $bad.wsl.distributions[0].version=1 }
        inventory { $bad.wsl.status='unknown' }
        runtime { $bad.wsl_runtime.exit_code=1 }
        memory { $bad.available_memory_bytes=19GB }
        collision { $bad.wsl.distributions[0].name='lumaos-dev' }
    }
    Assert-Luma (-not (Test-LumaWindowsPreflight $bad).development_observations_passed) "Failed to reject $change."
}
$boundary = New-Observation
$boundary.available_memory_bytes=20GB
Assert-Luma (Test-LumaWindowsPreflight $boundary).development_observations_passed 'Exact planning boundary refused.'
$boundary.available_memory_bytes=20GB-1
Assert-Luma (-not (Test-LumaWindowsPreflight $boundary).development_observations_passed) 'Memory reserve boundary ignored.'

$plan = New-StoragePlan
$policy = New-ReleasePolicy
$base = New-Observation
$before = @($base, $plan, $policy) | ConvertTo-Json -Depth 12 -Compress
$complete = Test-LumaWindowsPreflight $base -StoragePlan $plan -ReleasePolicy $policy
foreach ($status in @('fully-decrypted','suspended-or-protection-off','conversion-incomplete','locked','query-access-denied','provider-unavailable','query-timed-out','unknown')) {
    $unsafe=New-Observation;$unsafe.host_encryption.status=$status;$unsafe.host_encryption.protection_observed=$false
    Assert-Luma (-not (Test-LumaWindowsPreflight $unsafe -StoragePlan $plan -ReleasePolicy $policy).planning_observations_passed) "Unsafe encryption status admitted: $status"
}
foreach ($status in @('enterprise-review-required','wsl-policy-denied','unknown','non-user-token-context')) {
    $unsafe=New-Observation;$unsafe.enterprise_policy.status=$status;$unsafe.enterprise_policy.known_local_checks_passed=$false
    Assert-Luma (-not (Test-LumaWindowsPreflight $unsafe -StoragePlan $plan -ReleasePolicy $policy).planning_observations_passed) "Unsafe policy status admitted: $status"
}
Assert-Luma $complete.planning_observations_passed 'Exact complete planning input refused.'
Assert-Luma ($complete.storage_planning.required_free_bytes -eq 14GB) 'Seven-component storage sum incorrect.'
Assert-Luma (-not $complete.storage_planning.allocation_reserved -and -not $complete.release_comparison.policy_authenticated `
    -and -not $complete.release_comparison.production_qualified -and -not $complete.product_installation_admitted) 'Planning conferred authority.'
Assert-Luma ((@($base, $plan, $policy) | ConvertTo-Json -Depth 12 -Compress) -ceq $before) 'Planning mutated inputs.'
$base.storage_free_bytes=14GB
Assert-Luma (Test-LumaStoragePlan $base $plan).capacity_observation_passed 'Exact storage boundary refused.'
$base.storage_free_bytes=14GB-1
$short = Test-LumaStoragePlan $base $plan
Assert-Luma (-not $short.capacity_observation_passed -and $short.shortfall_bytes -eq 1) 'Storage boundary ignored.'
Assert-Luma (-not (Test-LumaWindowsPreflight $base -StoragePlan $plan -ReleasePolicy $policy).planning_observations_passed) 'Insufficient storage planning admitted.'
$small = New-StoragePlan
foreach ($field in @('active_image_bytes', 'candidate_image_bytes', 'model_pack_bytes', 'state_migration_bytes',
    'user_quota_bytes', 'backup_staging_bytes', 'recovery_reserve_bytes')) { $small.$field=[uint64]1 }
$base.storage_free_bytes=7
Assert-Luma (Test-LumaStoragePlan $base $small).capacity_observation_passed 'Arbitrary storage floor introduced.'
foreach ($field in @('active_image_bytes', 'candidate_image_bytes', 'model_pack_bytes', 'state_migration_bytes',
    'user_quota_bytes', 'backup_staging_bytes', 'recovery_reserve_bytes')) {
    foreach ($invalid in @(-1, $true, '1', [double]1, [decimal]1, $null, @{}, @(1,2))) {
        $bad = New-StoragePlan
        $bad.$field=$invalid
        Assert-LumaThrows { Test-LumaStoragePlan (New-Observation) $bad } "Invalid storage type accepted for $field."
    }
    $bad = New-StoragePlan
    $bad.PSObject.Properties.Remove($field)
    Assert-LumaThrows { Test-LumaStoragePlan (New-Observation) $bad } "Omitted storage component accepted: $field."
}
$bad = New-StoragePlan
$bad | Add-Member unexpected_bytes 1
Assert-LumaThrows { Test-LumaStoragePlan (New-Observation) $bad } 'Unknown storage field accepted.'
foreach ($zeroField in @('candidate_image_bytes', 'user_quota_bytes', 'recovery_reserve_bytes')) {
    $bad = New-StoragePlan; $bad.$zeroField=0
    Assert-LumaThrows { Test-LumaStoragePlan (New-Observation) $bad } "Missing positive reservation accepted: $zeroField."
}
$bad=New-StoragePlan; $bad.active_image_bytes=[uint64]::MaxValue
Assert-LumaThrows { Test-LumaStoragePlan (New-Observation) $bad } 'Overflowing storage total accepted.'
$maximum=New-StoragePlan
foreach ($field in @('active_image_bytes', 'candidate_image_bytes', 'model_pack_bytes', 'state_migration_bytes',
    'backup_staging_bytes')) { $maximum.$field=[uint64]0 }
$maximum.candidate_image_bytes=[uint64]1; $maximum.user_quota_bytes=[uint64]1
$maximum.recovery_reserve_bytes=[uint64]::MaxValue - [uint64]2
$maximumObservation=New-Observation; $maximumObservation.storage_free_bytes=[uint64]::MaxValue
Assert-Luma ((Test-LumaStoragePlan $maximumObservation $maximum).required_free_bytes -eq [uint64]::MaxValue) 'UInt64 storage boundary lost precision.'
foreach ($badDrive in @('C', 'd', 'D:', '../D', $true)) {
    $bad=New-StoragePlan; $bad.storage_drive=$badDrive
    Assert-LumaThrows { Test-LumaStoragePlan (New-Observation) $bad } 'Mismatched or invalid storage drive accepted.'
}
foreach ($badSchema in @($true, '1', [double]1, 2)) {
    $bad=New-StoragePlan; $bad.schema_version=$badSchema
    Assert-LumaThrows { Test-LumaStoragePlan (New-Observation) $bad } 'Invalid storage schema accepted.'
}
foreach ($free in @(-1, $true, '99999999999999999999', [double]1, $null)) {
    $badObservation=New-Observation; $badObservation.storage_free_bytes=$free
    Assert-LumaThrows { Test-LumaStoragePlan $badObservation (New-StoragePlan) } 'Invalid observed free capacity accepted.'
}
foreach ($change in @('edition', 'build', 'runtime', 'unknown-runtime', 'failure-runtime', 'kernel-only')) {
    $badObservation=New-Observation
    switch ($change) {
        edition { $badObservation.windows_edition='Core' }
        build { $badObservation.windows_build=26101 }
        runtime { $badObservation.wsl_runtime.text='WSL version: 2.6.0.1' }
        unknown-runtime { $badObservation.wsl_runtime.status='unknown' }
        failure-runtime { $badObservation.wsl_runtime.exit_code=1 }
        kernel-only { $badObservation.wsl_runtime.text='Kernel version: 2.6.0.0' }
    }
    Assert-Luma (-not (Test-LumaReleasePolicy $badObservation (New-ReleasePolicy)).tuple_matches_input) "Unreviewed release matched: $change."
}
$german=New-Observation; $german.wsl_runtime.text="WSL-Version: 2.6.0.0`nKernelversion: 6.6.0"
Assert-Luma (Test-LumaReleasePolicy $german (New-ReleasePolicy)).tuple_matches_input 'German WSL runtime header not recognized.'
foreach ($badSchema in @($true, '1', [double]1, 2)) {
    $bad=New-ReleasePolicy; $bad.schema_version=$badSchema
    Assert-LumaThrows { Test-LumaReleasePolicy (New-Observation) $bad } 'Invalid release schema accepted.'
}
foreach ($badBuild in @(-1, $true, '26100', [double]26100, [uint64]::MaxValue, 19045)) {
    $bad=New-ReleasePolicy; $bad.tuples[0].windows_build=$badBuild
    Assert-LumaThrows { Test-LumaReleasePolicy (New-Observation) $bad } 'Invalid release build accepted.'
}
foreach ($badVersion in @('2.6', '2.6.*.*', '>=2.6.0.0', '02.6.0.0', '2.65536.0.0', $true, 2)) {
    $bad=New-ReleasePolicy; $bad.tuples[0].wsl_runtime_version=$badVersion
    Assert-LumaThrows { Test-LumaReleasePolicy (New-Observation) $bad } 'Nonexact WSL version accepted.'
}
$bad=New-ReleasePolicy; $bad.tuples+= $bad.tuples[0]
Assert-LumaThrows { Test-LumaReleasePolicy (New-Observation) $bad } 'Duplicate tuple accepted.'
$bad=New-ReleasePolicy; $bad.tuples[0] | Add-Member authority 'trusted'
Assert-LumaThrows { Test-LumaReleasePolicy (New-Observation) $bad } 'Unknown release tuple field accepted.'
$bad=New-ReleasePolicy; $bad | Add-Member production_qualified $true
Assert-LumaThrows { Test-LumaReleasePolicy (New-Observation) $bad } 'Authority field accepted in policy.'
$bad=New-ReleasePolicy; $bad.tuples=@()
Assert-LumaThrows { Test-LumaReleasePolicy (New-Observation) $bad } 'Empty release policy accepted.'
$bad=New-ReleasePolicy; $bad.tuples=$bad.tuples[0]
Assert-LumaThrows { Test-LumaReleasePolicy (New-Observation) $bad } 'Scalar release tuples accepted.'
$bad=New-ReleasePolicy; $bad.review_reference="review`nforged"
Assert-LumaThrows { Test-LumaReleasePolicy (New-Observation) $bad } 'Control character review reference accepted.'
$jsonPlan=Read-LumaPlanningJson (Join-Path $PSScriptRoot 'test-data/storage-plan.json')
Assert-Luma (Test-LumaStoragePlan (New-Observation) $jsonPlan).capacity_observation_passed 'Bounded JSON plan failed.'
foreach ($fixture in @('duplicate-property.json', 'duplicate-tuple-property.json', 'escaped-property.json', 'invalid.json', 'deep-array.json')) {
    Assert-LumaThrows { Read-LumaPlanningJson (Join-Path $PSScriptRoot "test-data/$fixture") } "Unsafe JSON accepted: $fixture."
}
Write-Output "Passed $script:Assertions PowerShell preflight assertions; no host changes."
