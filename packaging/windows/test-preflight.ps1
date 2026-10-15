$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Luma.Preflight.psm1') -Force
$script:Assertions = 0
function Assert-Luma($Condition, [string]$Message) {
    $script:Assertions++
    if (-not $Condition) { throw $Message }
}
function New-Observation {
    [pscustomobject]@{ schema_version=1; windows_build=26100; windows_version='10.0.26100'
        windows_product_type=1; processor_architectures=@(9); virtualization_firmware=@($true)
        hypervisor_present=$true; available_memory_bytes=32GB; total_memory_bytes=64GB
        wsl_runtime=[pscustomobject]@{ status='observed'; exit_code=0; text='WSL version: 2.6.0.0' }
        wsl=(ConvertFrom-LumaWslList "  NAME            STATE           VERSION`n* Ubuntu          Running         2" 0) }
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
Write-Output "Passed $script:Assertions PowerShell preflight assertions; no host changes."
