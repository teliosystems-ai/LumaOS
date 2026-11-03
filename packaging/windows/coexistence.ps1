[CmdletBinding()]
param(
    [ValidatePattern('^(LumaOS-[A-Za-z0-9-]{1,48}|LumaHosted-[0-9a-f]{64}-(0|[1-9][0-9]{0,19})-[0-9a-f]{32})$')][string] $ProductDistribution = 'LumaOS-Dev',
    [ValidateRange(1,120)][int] $Samples = 10,
    [ValidateRange(250,60000)][int] $IntervalMilliseconds = 1000
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Luma.Coexistence.psm1') -Force
$observation = Get-LumaWslCoexistenceObservation -Samples $Samples -IntervalMilliseconds $IntervalMilliseconds
Test-LumaWslCoexistence -Observation $observation -ProductDistribution $ProductDistribution | ConvertTo-Json -Depth 12
