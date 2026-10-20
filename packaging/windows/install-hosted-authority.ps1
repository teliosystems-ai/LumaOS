[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PackageDirectory,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string] $ReviewedBundleSha256,
    [switch] $Install
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:OS -cne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {throw 'Actual native x64 Windows is required.'}
if ($PackageDirectory -notmatch '\A[A-Za-z]:\\' -or $PackageDirectory.Contains('/') -or [IO.Path]::GetFullPath($PackageDirectory) -cne $PackageDirectory.TrimEnd('\')) {throw 'Package directory must be an exact canonical local path.'}
$package=Get-Item -LiteralPath $PackageDirectory -Force
if ($package -isnot [IO.DirectoryInfo]) {throw 'Package source must be a directory.'}
$names=@('Luma.HostedAuthority.exe','Luma.PackageInspector.dll','Luma.PlatformCustody.dll','Luma.PlatformSignature.dll')
$pins=[Collections.Generic.List[IDisposable]]::new()
$sources=[Collections.Generic.Dictionary[string,IO.FileStream]]::new([StringComparer]::Ordinal)
$records=[Collections.Generic.List[object]]::new()
# This installer helper has no service, TPM, WSL, command or key interface.
# It pins only source handles before hashing or copying any executable bytes.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
public static class LumaHostedInstallSource {
    [StructLayout(LayoutKind.Sequential)] private struct Information {
        public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;
        public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Information information);
    public static SafeFileHandle Pin(string path,bool directory) {
        SafeFileHandle handle=CreateFile(path,directory?0x20081U:0x80020080U,directory?3U:1U,IntPtr.Zero,3,0x00300000U|(directory?0x02000000U:0x08000000U),IntPtr.Zero);
        try {
            Information observed;if(handle.IsInvalid || !GetFileInformationByHandle(handle,out observed)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if(((observed.Attributes&0x10)!=0)!=directory || (observed.Attributes&(0x400|0x1000|0x40000|0x400000))!=0 || (!directory && observed.Links!=1))
                throw new IOException("Installer source is linked, offline, recalled or not the required type.");return handle;
        } catch {handle.Dispose();throw;}
    }
}
'@
try {
    $ancestors=[Collections.Generic.List[string]]::new()
    for ($current=$package;$null -ne $current;$current=$current.Parent) {$ancestors.Insert(0,$current.FullName)}
    foreach ($ancestor in $ancestors) {$pins.Add([LumaHostedInstallSource]::Pin($ancestor,$true))}
    foreach ($name in $names) {
        $handle=[LumaHostedInstallSource]::Pin((Join-Path $package.FullName $name),$false)
        $stream=[IO.FileStream]::new($handle,[IO.FileAccess]::Read,32768,$false)
        $sources.Add($name,$stream)
        if ($stream.Length -lt 64 -or $stream.Length -gt 134217728) {throw 'Native bundle component exceeds fixed bounds.'}
        $hasher=[Security.Cryptography.SHA256]::Create()
        try {$hash=[BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-','').ToLowerInvariant()} finally {$hasher.Dispose()}
        $records.Add([pscustomobject]@{name=$name;bytes=$stream.Length;sha256=$hash})
    }
    $canonical="luma-windows-hosted-runtime-bundle-v1`n"
    foreach ($record in $records) {$canonical+=$record.name+"`t"+$record.bytes.ToString([Globalization.CultureInfo]::InvariantCulture)+"`t"+$record.sha256+"`n"}
    $hasher=[Security.Cryptography.SHA256]::Create()
    try {$actual=[BitConverter]::ToString($hasher.ComputeHash([Text.UTF8Encoding]::new($false,$true).GetBytes($canonical))).Replace('-','').ToLowerInvariant()} finally {$hasher.Dispose()}
    if ($actual -cne $ReviewedBundleSha256) {throw 'Exact independently reviewed executable/DLL bundle differs. Nothing is installed.'}
    $destination=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'LumaOS-HostedAuthority'
    if (-not $Install) {
        [pscustomobject][ordered]@{schema_version=1;status='review-only';bundle_sha256=$actual;fixed_destination=$destination;
            service_name='LumaHostedAuthority';components=@($records);service_installed=$false;service_started=$false;hardware_custody_invoked=$false;
            distribution_imported=$false;production_qualified=$false;gate_closing=$false}
        return
    }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'Actual enabled Windows Admin is required for explicit service installation.'};$installerSid=$identity.User.Value} finally {$identity.Dispose()}
    # Load only the exact held EXE whose complete bundle passed the independent
    # review above. Loading does not invoke its entrypoint or install a service.
    $reviewedExecutable=Join-Path $package.FullName 'Luma.HostedAuthority.exe'
    $reviewedAssembly=[Reflection.Assembly]::LoadFrom($reviewedExecutable)
    if (-not [String]::Equals($reviewedAssembly.Location,$reviewedExecutable,[StringComparison]::OrdinalIgnoreCase)) {throw 'Host admission observer did not originate in the exact reviewed executable.'}
    $protectionType=$reviewedAssembly.GetType('Luma.Windows.WindowsHostProtection',$true)
    $observe=$protectionType.GetMethod('Observe',[type[]]@([string]))
    $custodyPath=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    $protectionVolume=$null;$protectionSerial=[uint32]0
    function Assert-InstallHostProtection {
        $snapshot=$observe.Invoke($null,[object[]]@($custodyPath))
        $snapshot.Volume.RequireProtected();$snapshot.Management.RequireLocalChecks($installerSid)
        if ($null -ne $protectionVolume -and ($snapshot.Volume.Volume -ine $protectionVolume -or $snapshot.Volume.Serial -ne $protectionSerial)) {throw 'Private custody backing volume changed during installation admission.'}
        return $snapshot
    }
    $firstProtection=Assert-InstallHostProtection
    $protectionVolume=$firstProtection.Volume.Volume;$protectionSerial=$firstProtection.Volume.Serial
    if (Test-Path -LiteralPath $destination) {throw 'Existing runtime is never overwritten or adopted; a separately reviewed runtime migration is required.'}
    if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LumaHostedAuthority') {throw 'Fixed service already exists; never replace an unrelated or existing registration.'}
    $programFiles=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($destination)) -Force
    for ($current=$programFiles;$null -ne $current;$current=$current.Parent) {$pins.Add([LumaHostedInstallSource]::Pin($current.FullName,$true))}
    $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($destination))
    if ($drive.DriveFormat -cne 'NTFS') {throw 'Installed runtime requires native NTFS ACL enforcement.'}
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)',[Security.AccessControl.AccessControlSections]'Owner,Group,Access')
    $null=Assert-InstallHostProtection
    $null=[IO.Directory]::CreateDirectory($destination,$acl)
    foreach ($name in $names) {
        $null=Assert-InstallHostProtection
        $source=$sources[$name];$source.Position=0
        $target=[IO.FileStream]::new((Join-Path $destination $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,32768,[IO.FileOptions]::WriteThrough)
        try {$source.CopyTo($target,32768);$target.Flush($true)} finally {$target.Dispose()}
        $fileAcl=[Security.AccessControl.FileSecurity]::new()
        $fileAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)',[Security.AccessControl.AccessControlSections]'Owner,Group,Access')
        [IO.File]::SetAccessControl((Join-Path $destination $name),$fileAcl)
        $expected=@($records | Where-Object {$_.name -ceq $name})[0]
        if ((Get-FileHash -LiteralPath (Join-Path $destination $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected.sha256) {throw 'Installed runtime component differs; service was not created.'}
        $null=Assert-InstallHostProtection
    }
    $sc=Join-Path ([Environment]::SystemDirectory) 'sc.exe'
    $image='"'+(Join-Path $destination 'Luma.HostedAuthority.exe')+'" service'
    $null=Assert-InstallHostProtection
    $messages=& $sc create LumaHostedAuthority 'type=' own 'start=' demand 'error=' normal 'obj=' LocalSystem 'binPath=' $image 2>&1
    if ($LASTEXITCODE -ne 0) {throw ('SCM create refused; installed files preserved for inspection: '+($messages -join ' '))}
    $messages=& $sc sidtype LumaHostedAuthority unrestricted 2>&1
    if ($LASTEXITCODE -ne 0) {throw ('Service SID setup refused; service is not started: '+($messages -join ' '))}
    $registered=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LumaHostedAuthority'
    if ($registered.ImagePath -cne $image -or $registered.Type -ne 16 -or $registered.ObjectName -cne 'LocalSystem' -or $registered.ServiceSidType -ne 1) {throw 'Actual SCM registration differs; service is not started.'}
    $null=Assert-InstallHostProtection
    [pscustomobject][ordered]@{schema_version=1;status='service-installed-not-started';bundle_sha256=$actual;fixed_destination=$destination;
        service_name='LumaHostedAuthority';service_installed=$true;service_started=$false;hardware_custody_invoked=$false;
        distribution_imported=$false;production_qualified=$false;gate_closing=$false;
        next_action='Explicitly start LumaHostedAuthority, then use its original interactive Admin commission/review commands. No keys, NV objects or distributions were provisioned by installation.'}
} finally {
    foreach ($source in $sources.Values) {$source.Dispose()}
    for ($index=$pins.Count-1;$index -ge 0;$index--) {$pins[$index].Dispose()}
}
