[CmdletBinding()]
param([Parameter(Mandatory)][string] $PackageDirectory)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Luma.Package.psm1') -Force
Test-LumaWslPackage -PackageDirectory $PackageDirectory | ConvertTo-Json -Depth 6
