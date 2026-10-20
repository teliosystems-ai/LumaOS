[CmdletBinding()]
param([Parameter(Mandatory)][string] $BuildRoot,[switch] $LibraryOnly)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:OS -cne 'Windows_NT' -or -not [Environment]::Is64BitProcess) { throw 'Hosted authority requires actual native x64 Windows.' }
if ($BuildRoot -notmatch '\A[A-Za-z]:\\' -or $BuildRoot.Contains('/') -or $BuildRoot -match '(^|\\)\.{1,2}(\\|$)') { throw 'Build root must be canonical local storage.' }
$parent=Get-Item -LiteralPath $BuildRoot -Force
if ($parent -isnot [IO.DirectoryInfo]) { throw 'Build root must already exist.' }
for ($check=$parent;$null -ne $check;$check=$check.Parent) {
    if (($check.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Build storage may not traverse links.' }
}
$runtime=[Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
$compiler=Join-Path $runtime 'csc.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'Fixed installed .NET Framework compiler unavailable.' }
$output=Join-Path $parent.FullName ('luma-hosted-build-'+[Guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($output)
function Compile-Hosted([string[]] $Inputs,[string] $Output,[string[]] $References,[string] $Target,[bool] $Checked=$false) {
    $arguments=@('/nologo','/warn:4','/warnaserror+','/optimize+','/platform:x64',('/target:'+$Target),('/out:'+$Output))
    $arguments+=$(if ($Checked) {'/checked+'} else {'/checked-'})
    foreach ($reference in $References) { $arguments+=('/reference:'+$reference) }
    $arguments+=$Inputs
    $messages=& $compiler @arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Actual hosted compilation failed: '+($messages -join [Environment]::NewLine)) }
}
$signature=Join-Path $output 'Luma.PlatformSignature.dll'
$custody=Join-Path $output 'Luma.PlatformCustody.dll'
$package=Join-Path $output 'Luma.PackageInspector.dll'
Compile-Hosted @((Join-Path $PSScriptRoot 'PlatformSignature.cs')) $signature @('System.dll','System.Core.dll','System.Security.dll') 'library'
Compile-Hosted @((Join-Path $PSScriptRoot 'PlatformCustody.cs')) $custody @('System.dll','System.Core.dll','System.Security.dll') 'library'
Compile-Hosted @((Join-Path $PSScriptRoot 'PackageInspector.cs')) $package @('System.dll','System.Core.dll') 'library'
$names=@('HostedAuthorityProtocol.cs','HostedAuthorityCustody.cs','HostedAuthorityCapacity.cs','HostedAuthorityStorage.cs','HostedAuthorityRelease.cs','HostedAuthorityTransport.cs','HostedAuthorityDeployment.cs','HostedAuthorityService.cs','HostedAuthorityTime.cs','HostedAuthorityLifecycle.cs','HostedAuthorityImport.cs','HostedAuthorityRecovery.cs','HostedAuthorityTrust.cs','HostedAuthorityRuntime.cs','HostedAuthorityRuntimeService.cs','HostedAuthorityInstalledInput.cs','HostedAuthorityRead.cs','HostedAuthorityEnrollment.cs','HostedAuthorityCompute.cs','HostedAuthorityInference.cs','HostedAuthorityIngestion.cs')
$inputs=@($names | ForEach-Object {Join-Path $PSScriptRoot $_})
foreach ($sourceInput in $inputs) { if (-not (Test-Path -LiteralPath $sourceInput -PathType Leaf)) { throw ('Hosted build source missing: '+$sourceInput) } }
$target=if ($LibraryOnly) {'library'} else {'exe'}
$binary=Join-Path $output $(if ($LibraryOnly) {'Luma.HostedAuthority.Library.dll'} else {'Luma.HostedAuthority.exe'})
Compile-Hosted $inputs $binary @('System.dll','System.Core.dll','System.Security.dll','System.ServiceProcess.dll',$signature,$custody,$package) $target $true
[string[]]$files=@($signature,$custody,$package,$binary)
[Array]::Sort($files,[StringComparer]::Ordinal)
$pins=@($files | ForEach-Object {[ordered]@{name=[IO.Path]::GetFileName($_);bytes=(Get-Item -LiteralPath $_).Length;sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()}})
$canonical="luma-windows-hosted-runtime-bundle-v1`n"
foreach ($pin in $pins) { $canonical+=$pin.name+"`t"+$pin.bytes.ToString([Globalization.CultureInfo]::InvariantCulture)+"`t"+$pin.sha256+"`n" }
$bundleBytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($canonical)
$bundlePath=Join-Path $output 'runtime-bundle.txt'
[IO.File]::WriteAllBytes($bundlePath,$bundleBytes)
$bundleHash=(Get-FileHash -LiteralPath $bundlePath -Algorithm SHA256).Hash.ToLowerInvariant()
[pscustomobject][ordered]@{schema_version=1;status='compiled';work_directory=$output;binary=$binary;library_only=[bool]$LibraryOnly;
    components=$pins;bundle_sha256=$bundleHash;bundle_manifest=$bundlePath;service_installed=$false;hardware_custody_invoked=$false;distribution_imported=$false;production_qualified=$false;gate_closing=$false}
