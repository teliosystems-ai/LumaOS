[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PackageDirectory,
    [Parameter(Mandatory)][string] $SignaturePath,
    [Parameter(Mandatory)][string] $AnchorPath,
    [Parameter(Mandatory)][string] $AnchorSha256,
    [Parameter(Mandatory)][string] $OpenSslPath,
    [Parameter(Mandatory)][string] $OpenSslSha256,
    [Parameter(Mandatory)][string] $WorkRoot,
    [string] $CompilerWorkRoot
)
$ErrorActionPreference = 'Stop'
$originalTemp = $env:TEMP; $originalTmp = $env:TMP
try {
    $compilerRoot = if ([string]::IsNullOrEmpty($CompilerWorkRoot)) { $WorkRoot } else { $CompilerWorkRoot }
    $work = Get-Item -LiteralPath $compilerRoot -Force -ErrorAction Stop
    if ($work -isnot [IO.DirectoryInfo] -or $compilerRoot -notmatch '^[A-Za-z]:\\' -or
        ($work.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Compiler scratch requires an existing local directory.' }
    $ancestor=$work
    while ($null -ne $ancestor) {
        if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Compiler scratch cannot traverse a reparse point.' }
        $ancestor=$ancestor.Parent
    }
    $env:TEMP = $work.FullName; $env:TMP = $work.FullName
    Import-Module (Join-Path $PSScriptRoot 'Luma.Package.psm1') -Force
    $arguments=@{}; foreach($name in $PSBoundParameters.Keys) {
        if ($name -cne 'CompilerWorkRoot') { $arguments[$name]=$PSBoundParameters[$name] }
    }
    Test-LumaWslPackageSignature @arguments | ConvertTo-Json -Depth 6
} finally { $env:TEMP=$originalTemp; $env:TMP=$originalTmp }
