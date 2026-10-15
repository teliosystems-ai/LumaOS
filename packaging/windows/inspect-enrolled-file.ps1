[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $EnrollmentPath,
    [Parameter(Mandatory)][string] $CompilerWorkRoot,
    [switch] $ReviewOnly,
    [string] $Confirmation
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Luma.Ingestion.psm1') -Force
Initialize-LumaIngestionRuntime -CompilerWorkRoot $CompilerWorkRoot
$enrollment = Read-LumaIngestionEnrollmentInput -LiteralPath $EnrollmentPath
if ($ReviewOnly) {
    if ($PSBoundParameters.ContainsKey('Confirmation')) { throw 'Review-only data preparation cannot consume a read confirmation.' }
    Get-LumaIngestionReview -Enrollment $enrollment | ConvertTo-Json -Depth 4
} else {
    if ([string]::IsNullOrEmpty($Confirmation)) { throw 'Reading requires explicit exact review confirmation.' }
    Read-LumaEnrolledFile -Enrollment $enrollment -Confirmation $Confirmation | ConvertTo-Json -Depth 4
}
