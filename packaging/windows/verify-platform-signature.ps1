[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PublicKeyPath,
    [Parameter(Mandatory)][string] $PublicKeySha256,
    [Parameter(Mandatory)][string] $StatementPath,
    [Parameter(Mandatory)][string] $StatementSha256,
    [Parameter(Mandatory)][string] $PayloadPath,
    [Parameter(Mandatory)][string] $PayloadSha256,
    [Parameter(Mandatory)][string] $SignaturePath,
    [Parameter(Mandatory)][string] $ExpectedNonce,
    [Parameter(Mandatory)][string] $ExpectedSequence,
    [Parameter(Mandatory)][string] $CompilerWorkRoot
)
$ErrorActionPreference = 'Stop'
$priorTemp = $env:TEMP; $priorTmp = $env:TMP
try {
    if ($CompilerWorkRoot -notmatch '\A[A-Za-z]:\\' -or $CompilerWorkRoot.Contains('/') -or
        $CompilerWorkRoot -match '(^|\\)\.{1,2}(\\|$)') { throw 'Compiler work root must be a canonical absolute local directory.' }
    $work = Get-Item -LiteralPath $CompilerWorkRoot -Force -ErrorAction Stop
    if ($work -isnot [IO.DirectoryInfo]) { throw 'Compiler work root must exist as a real directory.' }
    $ancestor = $work
    while ($null -ne $ancestor) {
        if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Compiler work root may not traverse a reparse point.' }
        $ancestor = $ancestor.Parent
    }
    $env:TEMP = $work.FullName; $env:TMP = $work.FullName
    Import-Module (Join-Path $PSScriptRoot 'Luma.PlatformSignature.psm1') -Force
    $arguments = @{}
    foreach ($name in $PSBoundParameters.Keys) {
        if ($name -cne 'CompilerWorkRoot') { $arguments[$name] = $PSBoundParameters[$name] }
    }
    Test-LumaWindowsPlatformStatement @arguments | ConvertTo-Json -Depth 5
} finally { $env:TEMP=$priorTemp; $env:TMP=$priorTmp }
