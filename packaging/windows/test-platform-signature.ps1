[CmdletBinding()]
param([Parameter(Mandatory)][string] $WorkRoot, [string] $SecurityWorkRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -cne 'Windows_NT') { throw 'Actual BCrypt tests require native Windows.' }
if ($WorkRoot -notmatch '\A[A-Za-z]:\\' -or $WorkRoot.Contains('/') -or $WorkRoot -match '(^|\\)\.{1,2}(\\|$)') {
    throw 'Test work root requires a canonical absolute local directory.'
}
$parent = Get-Item -LiteralPath $WorkRoot -Force -ErrorAction Stop
if ($parent -isnot [IO.DirectoryInfo]) { throw 'Test work root must already exist.' }
$ancestor=$parent
while ($null -ne $ancestor) {
    if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Test work root may not traverse reparse points.' }
    $ancestor=$ancestor.Parent
}
$priorTemp=$env:TEMP; $priorTmp=$env:TMP
$root=$null; $key=$null; $other=$null; $securityFixture=$null; $junction=$null
$ntfsTested=$false
$script:Assertions=0
function Assert-Platform([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
    $script:Assertions++
}
function Assert-PlatformThrows([scriptblock] $Operation, [string] $Message) {
    $refused=$false
    try { $null=& $Operation } catch { $refused=$true }
    Assert-Platform $refused $Message
}
try {
    $env:TEMP=$parent.FullName; $env:TMP=$parent.FullName
    Import-Module (Join-Path $PSScriptRoot 'Luma.PlatformSignature.psm1') -Force
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
public sealed class LumaPlatformEphemeralTestKey : IDisposable {
    private IntPtr algorithm, key;
    [DllImport("bcrypt.dll",CharSet=CharSet.Unicode)] private static extern int BCryptOpenAlgorithmProvider(out IntPtr a,string n,string p,uint f);
    [DllImport("bcrypt.dll")] private static extern int BCryptGenerateKeyPair(IntPtr a,out IntPtr k,uint b,uint f);
    [DllImport("bcrypt.dll")] private static extern int BCryptFinalizeKeyPair(IntPtr k,uint f);
    [DllImport("bcrypt.dll",CharSet=CharSet.Unicode)] private static extern int BCryptExportKey(IntPtr k,IntPtr e,string t,byte[] b,uint s,out uint r,uint f);
    [DllImport("bcrypt.dll")] private static extern int BCryptSignHash(IntPtr k,IntPtr p,byte[] h,uint n,byte[] s,uint z,out uint r,uint f);
    [DllImport("bcrypt.dll")] private static extern int BCryptDestroyKey(IntPtr k);
    [DllImport("bcrypt.dll")] private static extern int BCryptCloseAlgorithmProvider(IntPtr a,uint f);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool CreateHardLink(string path,string existing,IntPtr security);
    private static void Check(int value) { if(value!=0) throw new CryptographicException("Ephemeral BCrypt fixture failed: "+((uint)value).ToString("x8")); }
    public LumaPlatformEphemeralTestKey() {
        try { Check(BCryptOpenAlgorithmProvider(out algorithm,"ECDSA_P256","Microsoft Primitive Provider",0));
            Check(BCryptGenerateKeyPair(algorithm,out key,256,0)); Check(BCryptFinalizeKeyPair(key,0)); }
        catch { Dispose(); throw; }
    }
    public byte[] PublicBlob() {
        if(key==IntPtr.Zero) throw new ObjectDisposedException("fixture");
        byte[] result=new byte[72]; uint written;
        Check(BCryptExportKey(key,IntPtr.Zero,"ECCPUBLICBLOB",result,72,out written,0));
        if(written!=72) throw new CryptographicException("Unexpected fixture public format"); return result;
    }
    public byte[] Sign(byte[] input) {
        if(key==IntPtr.Zero) throw new ObjectDisposedException("fixture");
        byte[] hash; using(SHA256 digest=SHA256.Create()) hash=digest.ComputeHash(input);
        byte[] result=new byte[64]; uint written;
        Check(BCryptSignHash(key,IntPtr.Zero,hash,32,result,64,out written,0));
        if(written!=64) throw new CryptographicException("Unexpected fixture signature format"); return result;
    }
    public void Dispose() { if(key!=IntPtr.Zero){BCryptDestroyKey(key);key=IntPtr.Zero;}
        if(algorithm!=IntPtr.Zero){BCryptCloseAlgorithmProvider(algorithm,0);algorithm=IntPtr.Zero;} }
    public static void HardLink(string path,string existing) {
        if(!CreateHardLink(path,existing,IntPtr.Zero)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }
}
'@ -ErrorAction Stop
    $root=Join-Path $parent.FullName ('luma-platform-signature-'+[Guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($root)
    $key=New-Object LumaPlatformEphemeralTestKey
    $other=New-Object LumaPlatformEphemeralTestKey
    [byte[]] $blob=$key.PublicBlob()
    [byte[]] $fixtureInput=[Text.Encoding]::UTF8.GetBytes('real ephemeral P256 BCrypt fixture')
    [byte[]] $signature=$key.Sign($fixtureInput)
    Assert-Platform ([Luma.Windows.PlatformSignature]::Verify($blob,$fixtureInput,$signature)) 'Actual BCrypt signature failed.'
    Assert-Platform (-not [Luma.Windows.PlatformSignature]::Verify($other.PublicBlob(),$fixtureInput,$signature)) 'Wrong actual public key admitted.'
    Assert-Platform (-not [Luma.Windows.PlatformSignature]::Verify($blob,[Text.Encoding]::UTF8.GetBytes('changed'),$signature)) 'Changed preimage admitted.'
    foreach ($size in @(0,63,65,70)) {
        Assert-PlatformThrows { [Luma.Windows.PlatformSignature]::Verify($blob,$fixtureInput,(New-Object byte[] $size)) } 'Non-P1363 size admitted.'
    }
    Assert-Platform (-not [Luma.Windows.PlatformSignature]::Verify($blob,$fixtureInput,(New-Object byte[] 64))) 'Zero signature scalar admitted.'
    [byte[]] $range=$signature.Clone()
    [byte[]] $order=[Luma.Windows.PlatformSignature]::Hex('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',32)
    [Array]::Copy($order,0,$range,0,32)
    Assert-Platform (-not [Luma.Windows.PlatformSignature]::Verify($blob,$fixtureInput,$range)) 'Out-of-range r scalar admitted.'
    $range=$signature.Clone()
    [Array]::Copy($order,0,$range,32,32)
    Assert-Platform (-not [Luma.Windows.PlatformSignature]::Verify($blob,$fixtureInput,$range)) 'Out-of-range s scalar admitted.'
    foreach ($size in @(0,65,71,73,104)) {
        Assert-PlatformThrows { [Luma.Windows.PlatformSignature]::Verify((New-Object byte[] $size),$fixtureInput,$signature) } 'Wrong public-key blob size admitted.'
    }
    [byte[]] $foreign=$blob.Clone(); $foreign[2]=0x4b
    Assert-PlatformThrows { [Luma.Windows.PlatformSignature]::Verify($foreign,$fixtureInput,$signature) } 'ECDH magic admitted as ECDSA.'
    [byte[]] $invalidPoint=New-Object byte[] 72
    [Array]::Copy($blob,0,$invalidPoint,0,8)
    Assert-PlatformThrows { [Luma.Windows.PlatformSignature]::Verify($invalidPoint,$fixtureInput,$signature) } 'Invalid curve point imported.'
    Assert-PlatformThrows { [Luma.Windows.PlatformSignature]::Verify($blob,(New-Object byte[] 8193),$signature) } 'Oversize primitive preimage admitted.'

    $utf8=New-Object Text.UTF8Encoding ($false,$true)
    $nonce='1'*64
    $paths=@{ Key=(Join-Path $root 'key.json'); Statement=(Join-Path $root 'statement.json');
              Payload=(Join-Path $root 'payload.bin'); Signature=(Join-Path $root 'signature.bin') }
    $keyRecord=[ordered]@{schema_version=2;environment='lab';purpose='luma-windows-platform-public-key-v2';
        algorithm='ecdsa-p256-sha256-p1363';architecture='amd64';profile='W';key_format='cng-eccpublicblob-p256';
        public_key_blob_hex=([BitConverter]::ToString($blob).Replace('-','').ToLowerInvariant())}
    function Write-PlatformFixture {
        param([byte[]] $Payload=$fixtureInput, [string] $KeyText='', [string] $StatementText='')
        if ($KeyText.Length -eq 0) { $KeyText=$keyRecord | ConvertTo-Json -Compress }
        [byte[]] $keyBytes=$utf8.GetBytes($KeyText)
        $publicHash=[Luma.Windows.PlatformSignature]::Hash($keyBytes)
        $payloadHash=[Luma.Windows.PlatformSignature]::Hash($Payload)
        $statementRecord=[ordered]@{schema_version=2;environment='lab';purpose='luma-windows-platform-statement-v2';
            algorithm='ecdsa-p256-sha256-p1363';architecture='amd64';profile='W';public_key_sha256=$publicHash;
            payload_sha256=$payloadHash;nonce=$nonce;sequence='1'}
        if ($StatementText.Length -eq 0) { $StatementText=$statementRecord | ConvertTo-Json -Compress }
        [byte[]] $statementBytes=$utf8.GetBytes($StatementText)
        [IO.File]::WriteAllBytes($paths.Key,$keyBytes)
        [IO.File]::WriteAllBytes($paths.Statement,$statementBytes)
        [IO.File]::WriteAllBytes($paths.Payload,$Payload)
        [IO.File]::WriteAllBytes($paths.Signature,$key.Sign([Luma.Windows.PlatformSignature]::SigningInput($statementBytes)))
        return @{PublicKeyPath=$paths.Key;PublicKeySha256=$publicHash;StatementPath=$paths.Statement;
            StatementSha256=[Luma.Windows.PlatformSignature]::Hash($statementBytes);PayloadPath=$paths.Payload;
            PayloadSha256=$payloadHash;SignaturePath=$paths.Signature;ExpectedNonce=$nonce;ExpectedSequence='1'}
    }
    $arguments=Write-PlatformFixture
    $valid=Test-LumaWindowsPlatformStatement @arguments
    Assert-Platform $valid.cryptographic_signature_valid 'Valid canonical v2 statement refused.'
    Assert-Platform $valid.exact_selected_binding 'Exact statement binding was not checked.'
    foreach ($field in @('external_crypto_process_used','persistent_key_created','physical_tpm_used','key_custody_authenticated',
        'host_os_dependencies_qualified','protected_utc_established','attestation_freshness_established',
        'current_revocation_state_established','durable_rollback_protection_established','product_installation_admitted',
        'distribution_imported','host_settings_changed','hard_deadline_enforced','cloud_provider_qualified','production_qualified','gate_closing')) {
        Assert-Platform (-not $valid.$field) ('Unqualified authority flag asserted: '+$field)
    }
    foreach ($change in @(
        @{Name='PublicKeySha256';Value=('0'*64)}, @{Name='StatementSha256';Value=('0'*64)},
        @{Name='PayloadSha256';Value=('0'*64)}, @{Name='ExpectedNonce';Value=('2'*64)},
        @{Name='ExpectedNonce';Value=('0'*64)}, @{Name='ExpectedNonce';Value=('A'*64)},
        @{Name='ExpectedSequence';Value='01'}, @{Name='ExpectedSequence';Value='1e0'},
        @{Name='ExpectedSequence';Value='0'}, @{Name='ExpectedSequence';Value='9007199254740992'})) {
        $bad=$arguments.Clone(); $bad[$change.Name]=$change.Value
        Assert-PlatformThrows { Test-LumaWindowsPlatformStatement @bad } ('Invalid independent selection admitted: '+$change.Name)
    }
    $baseKey=$utf8.GetString([IO.File]::ReadAllBytes($paths.Key))
    foreach ($text in @(
        $baseKey.Replace('"schema_version":2','"schema_version":1'),
        $baseKey.Replace('"lab"','"production"'),
        $baseKey.Replace('ecdsa-p256-sha256-p1363','ed25519'),
        $baseKey.Replace('cng-eccpublicblob-p256','sec1-uncompressed'),
        $baseKey.Replace('luma-windows-platform-public-key-v2','luma-wsl-package-v1'),
        $baseKey.Replace('4543533120000000','45434b3120000000'),
        $baseKey.Replace('"schema_version":2','"schema_version":2,"schema_version":2'),
        $baseKey.Replace('"schema_version":2','"schema_\u0076ersion":2'),
        (' '+$baseKey), ($baseKey+"`n"))) {
        $bad=Write-PlatformFixture -KeyText $text
        Assert-PlatformThrows { Test-LumaWindowsPlatformStatement @bad } 'Noncanonical, foreign or ambiguous key record admitted.'
    }
    $arguments=Write-PlatformFixture
    $baseStatement=$utf8.GetString([IO.File]::ReadAllBytes($paths.Statement))
    foreach ($text in @(
        $baseStatement.Replace('"schema_version":2','"schema_version":1'),
        $baseStatement.Replace('"lab"','"production"'),
        $baseStatement.Replace('ecdsa-p256-sha256-p1363','ed25519'),
        $baseStatement.Replace('"amd64"','"arm64"'), $baseStatement.Replace('"W"','"N"'),
        $baseStatement.Replace('luma-windows-platform-statement-v2','luma-windows-bridge-message-v2'),
        $baseStatement.Replace('"sequence":"1"','"sequence":1'),
        $baseStatement.Replace('"sequence":"1"','"sequence":"2"'),
        $baseStatement.Replace('"sequence":"1"','"sequence":"01"'),
        $baseStatement.Replace('"sequence":"1"','"sequence":"1","extra":true'),
        $baseStatement.Replace('"schema_version":2','"schema_version":2,"schema_version":2'),
        $baseStatement.Replace('"schema_version":2','"schema_\u0076ersion":2'),
        (' '+$baseStatement), ($baseStatement+"`n"))) {
        $bad=Write-PlatformFixture -StatementText $text
        Assert-PlatformThrows { Test-LumaWindowsPlatformStatement @bad } 'Signed foreign, ambiguous or noncanonical statement admitted.'
    }
    $arguments=Write-PlatformFixture
    [byte[]] $canonical=[IO.File]::ReadAllBytes($paths.Statement)
    [IO.File]::WriteAllBytes($paths.Signature,$other.Sign([Luma.Windows.PlatformSignature]::SigningInput($canonical)))
    Assert-PlatformThrows { Test-LumaWindowsPlatformStatement @arguments } 'Other ephemeral signer admitted.'
    [IO.File]::WriteAllBytes($paths.Signature,$key.Sign($canonical))
    Assert-PlatformThrows { Test-LumaWindowsPlatformStatement @arguments } 'Missing domain prefix admitted.'
    foreach ($size in @(0,63,65)) {
        [IO.File]::WriteAllBytes($paths.Signature,(New-Object byte[] $size))
        Assert-PlatformThrows { Test-LumaWindowsPlatformStatement @arguments } 'Signature file size admitted.'
    }
    $arguments=Write-PlatformFixture -Payload (New-Object byte[] 65536)
    Assert-Platform (Test-LumaWindowsPlatformStatement @arguments).cryptographic_signature_valid 'Exact maximum payload refused.'
    [IO.File]::WriteAllBytes($paths.Payload,(New-Object byte[] 65537))
    Assert-PlatformThrows { Test-LumaWindowsPlatformStatement @arguments } 'Oversize payload read admitted.'
    $arguments=Write-PlatformFixture
    [IO.File]::WriteAllBytes($paths.Statement,[byte[]]@(0xff,0xfe,0xfd))
    $arguments.StatementSha256=[Luma.Windows.PlatformSignature]::Hash([byte[]]@(0xff,0xfe,0xfd))
    Assert-PlatformThrows { Test-LumaWindowsPlatformStatement @arguments } 'Invalid UTF8 record admitted.'
    $arguments=Write-PlatformFixture
    $lease=[Luma.Windows.PlatformInputLease]::Acquire($paths.Payload)
    try {
        Assert-Platform ($lease.Capture(1,65536).Length -eq $fixtureInput.Length) 'Held capture changed content size.'
        Assert-PlatformThrows { $handle=[IO.File]::Open($paths.Payload,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite); $handle.Dispose() } 'Writer opened held public input.'
        Assert-PlatformThrows { [IO.File]::Move($paths.Payload,(Join-Path $root 'moved.bin')) } 'Held input renamed.'
        Assert-PlatformThrows { [IO.Directory]::Move($root,($root+'-moved')) } 'Held ancestor renamed.'
        $lease.Check()
    } finally { $lease.Dispose() }
    Assert-PlatformThrows { $lease.Check() } 'Disposed input lease remained usable.'
    foreach ($path in @('relative.json','\\server\share\key.json','\\.\C:\key.json',
        ($paths.Key+':stream'),(Join-Path $root '..\key.json'),(Join-Path $root 'CON'),(Join-Path $root 'key.json.'))) {
        Assert-PlatformThrows { [Luma.Windows.PlatformInputLease]::Acquire($path) } 'Ambiguous public input path admitted.'
    }
    if ($PSBoundParameters.ContainsKey('SecurityWorkRoot')) {
        if ($SecurityWorkRoot -notmatch '\A[A-Za-z]:\\' -or $SecurityWorkRoot.Contains('/') -or
            $SecurityWorkRoot -match '(^|\\)\.{1,2}(\\|$)') { throw 'NTFS safety fixtures require an explicit canonical local root.' }
        $securityBase=Get-Item -LiteralPath $SecurityWorkRoot -Force -ErrorAction Stop
        if ($securityBase -isnot [IO.DirectoryInfo]) { throw 'NTFS safety fixture root must exist.' }
        $ancestor=$securityBase
        while ($null -ne $ancestor) {
            if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'NTFS safety fixture ancestors may not be reparse points.' }
            $ancestor=$ancestor.Parent
        }
        $drive=New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($securityBase.FullName))
        if ($drive.DriveFormat -cne 'NTFS') { throw 'Explicit safety fixtures require actual NTFS.' }
        $securityFixture=Join-Path $securityBase.FullName ('luma-platform-signature-security-'+[Guid]::NewGuid().ToString('N'))
        $inside=Join-Path $securityFixture 'inner'
        $null=[IO.Directory]::CreateDirectory($inside)
        $source=Join-Path $inside 'public.bin'
        [IO.File]::WriteAllBytes($source,[byte[]]@(1,2,3,4))
        $hardlink=Join-Path $inside 'alias.bin'
        [LumaPlatformEphemeralTestKey]::HardLink($hardlink,$source)
        try {
            Assert-PlatformThrows { [Luma.Windows.PlatformInputLease]::Acquire($source) } 'Hardlinked original public file admitted.'
            Assert-PlatformThrows { [Luma.Windows.PlatformInputLease]::Acquire($hardlink) } 'Hardlink alias public file admitted.'
        } finally { [IO.File]::Delete($hardlink) }
        $junction=Join-Path $securityFixture 'jump'
        $null=New-Item -ItemType Junction -Path $junction -Target $inside -ErrorAction Stop
        Assert-PlatformThrows { [Luma.Windows.PlatformInputLease]::Acquire((Join-Path $junction 'public.bin')) } 'Reparse ancestor followed.'
        Assert-PlatformThrows { [Luma.Windows.PlatformInputLease]::Acquire($junction) } 'Reparse final member followed.'
        [IO.Directory]::Delete($junction); $junction=$null
        $lease=[Luma.Windows.PlatformInputLease]::Acquire($source)
        try {
            Assert-Platform ($lease.Capture(4,4).Length -eq 4) 'Actual NTFS held public capture failed.'
            Assert-PlatformThrows { [IO.Directory]::Move($inside,(Join-Path $securityFixture 'renamed')) } 'Actual NTFS held ancestor renamed.'
            $lease.Check()
        } finally { $lease.Dispose() }
        $ntfsTested=$true
    }
    $arguments=Write-PlatformFixture
    $wrapper=Join-Path $PSScriptRoot 'verify-platform-signature.ps1'
    $cliArguments=@('-NoProfile','-ExecutionPolicy','RemoteSigned','-File',$wrapper,'-CompilerWorkRoot',$parent.FullName)
    foreach ($name in $arguments.Keys) {
        $cliArguments+=('-'+$name)
        $cliArguments+=([string]$arguments[$name])
    }
    $cli=& (Join-Path $PSHOME 'powershell.exe') @cliArguments
    Assert-Platform ($LASTEXITCODE -eq 0) 'Actual child verifier CLI failed.'
    $parsed=($cli -join "`n") | ConvertFrom-Json
    Assert-Platform $parsed.cryptographic_signature_valid 'Actual child CLI did not verify signature.'
    [pscustomobject]@{schema_version=2;status='passed';assertions=$script:Assertions;skipped=0;
        actual_bcrypt_sign_verify=$true;ephemeral_software_keys_only=$true;child_cli_tested=$true;
        ntfs_reparse_hardlink_fixture_tested=$ntfsTested;cloud_provider_qualified=$false;
        external_crypto_process_used=$false;persistent_key_created=$false;physical_tpm_used=$false;
        host_settings_changed=$false;production_qualified=$false;gate_closing=$false} | ConvertTo-Json -Depth 4
} finally {
    if ($null -ne $other) { $other.Dispose() }
    if ($null -ne $key) { $key.Dispose() }
    if ($null -ne $junction -and [IO.Directory]::Exists($junction)) { [IO.Directory]::Delete($junction) }
    if ($null -ne $securityFixture -and [IO.Directory]::Exists($securityFixture)) {
        $resolved=[IO.Path]::GetFullPath($securityFixture)
        $prefix=$securityBase.FullName.TrimEnd('\')+'\'
        if (-not $resolved.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($resolved) -notmatch '\Aluma-platform-signature-security-[0-9a-f]{32}\z') {
            throw 'Refusing NTFS cleanup outside the exact owned fixture.'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop
    }
    if ($null -ne $root -and [IO.Directory]::Exists($root)) {
        $resolved=[IO.Path]::GetFullPath($root)
        $prefix=$parent.FullName.TrimEnd('\')+'\'
        if (-not $resolved.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($resolved) -notmatch '\Aluma-platform-signature-[0-9a-f]{32}\z') {
            throw 'Refusing test cleanup outside the exact owned fixture.'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop
    }
    $env:TEMP=$priorTemp; $env:TMP=$priorTmp
}
