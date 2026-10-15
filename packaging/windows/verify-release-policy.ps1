[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PackageDirectory,
    [Parameter(Mandatory)][string] $SignaturePath,
    [Parameter(Mandatory)][string] $AnchorPath,
    [Parameter(Mandatory)][string] $AnchorSha256,
    [Parameter(Mandatory)][string] $OpenSslPath,
    [Parameter(Mandatory)][string] $OpenSslSha256,
    [Parameter(Mandatory)][string] $WorkRoot,
    [Parameter(Mandatory)][string] $AuthorityPath,
    [Parameter(Mandatory)][string] $AuthoritySha256,
    [Parameter(Mandatory)][string] $PolicyPath,
    [Parameter(Mandatory)][string] $PolicySignaturePath,
    [Parameter(Mandatory)][string] $TimeAttestationPath,
    [Parameter(Mandatory)][string] $TimeSignaturePath,
    [Parameter(Mandatory)][string] $ChallengeNonce,
    [Parameter(Mandatory)][string] $MinimumSequence,
    [Parameter(Mandatory)][string] $ExpectedPreviousPolicySha256,
    [ValidateSet('lab', 'production')][string] $Environment = 'lab',
    [Parameter(Mandatory)][string] $CompilerWorkRoot
)
$ErrorActionPreference = 'Stop'
$originalTemp = $env:TEMP; $originalTmp = $env:TMP
try {
    if ($MinimumSequence -cnotmatch '\A[1-9][0-9]{0,15}\z') {
        throw 'Minimum sequence requires canonical positive decimal text, at most 9007199254740991.'
    }
    $sequence = [long]::Parse($MinimumSequence, [Globalization.CultureInfo]::InvariantCulture)
    if ($sequence -gt 9007199254740991L) {
        throw 'Minimum sequence requires canonical positive decimal text, at most 9007199254740991.'
    }
    if ($CompilerWorkRoot -notmatch '^[A-Za-z]:\\' -or $CompilerWorkRoot.Contains('/') -or
        $CompilerWorkRoot -match '(^|\\)\.{1,2}(\\|$)') { throw 'Compiler work root requires an absolute local canonical path.' }
    $work = Get-Item -LiteralPath $CompilerWorkRoot -Force -ErrorAction Stop
    if ($work -isnot [IO.DirectoryInfo]) { throw 'Compiler work root must be an existing directory.' }
    $ancestor = $work
    while ($null -ne $ancestor) {
        if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Compiler work root must not traverse reparse points.' }
        $ancestor = $ancestor.Parent
    }
    $env:TEMP = $work.FullName; $env:TMP = $work.FullName
    Import-Module (Join-Path $PSScriptRoot 'Luma.Trust.psm1') -Force
    $arguments = @{}
    foreach ($name in $PSBoundParameters.Keys) {
        if ($name -cne 'CompilerWorkRoot') { $arguments[$name] = $PSBoundParameters[$name] }
    }
    $arguments.MinimumSequence = $sequence
    Test-LumaWslLabReleasePolicy @arguments | ConvertTo-Json -Depth 6
} finally { $env:TEMP = $originalTemp; $env:TMP = $originalTmp }
