[CmdletBinding()]
param([Parameter(Mandatory)][string] $WorkRoot,[switch] $InspectExactEmptySoftwareKey,
    [switch] $RemoveExactEmptySoftwareFixture,[string] $ExpectedPublicBlobSha256)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:OS -cne 'Windows_NT') { throw 'Custody codec/software-key tests require native Windows.' }
if ($InspectExactEmptySoftwareKey -and $RemoveExactEmptySoftwareFixture) { throw 'Select inspection or fixture cleanup, never both.' }
if ($PSBoundParameters.ContainsKey('ExpectedPublicBlobSha256') -and -not $RemoveExactEmptySoftwareFixture) { throw 'Expected key pin is only accepted with explicit fixture cleanup.' }
if ($RemoveExactEmptySoftwareFixture -and $ExpectedPublicBlobSha256 -cne 'c988f5e7898e379a63ac60e59c031c6a0ea00368f178069ef09b2273ef947b55') {
    throw 'Fixture cleanup requires the independently observed exact public-key SHA256.'
}
if ($WorkRoot -notmatch '\A[A-Za-z]:\\' -or $WorkRoot.Contains('/') -or $WorkRoot -match '(^|\\)\.{1,2}(\\|$)') {
    throw 'Compiler work root must be a canonical existing local directory.'
}
$work=Get-Item -LiteralPath $WorkRoot -Force -ErrorAction Stop
if ($work -isnot [IO.DirectoryInfo]) { throw 'Compiler work root must exist.' }
$ancestor=$work
while ($null -ne $ancestor) {
    if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Compiler work root may not traverse reparse points.' }
    $ancestor=$ancestor.Parent
}
$priorTemp=$env:TEMP; $priorTmp=$env:TMP
$ephemeral=$null; $signer=$null
$script:Assertions=0
function Assert-Custody([bool] $Condition,[string] $Message) {
    if (-not $Condition) { throw $Message }
    $script:Assertions++
}
function Assert-CustodyThrows([scriptblock] $Operation,[string] $Message) {
    $refused=$false
    try { $null=& $Operation } catch { $refused=$true }
    Assert-Custody $refused $Message
}
function Custody-Bytes([string] $Hex) {
    return ,([Luma.Windows.PlatformCustodyProtocol]::Hex($Hex,($Hex.Length/2)))
}
function Custody-NvReply($Configuration) {
    [byte[]] $public=[Luma.Windows.PlatformCustodyProtocol]::ExpectedNvPublic($Configuration.Domain,$Configuration.PolicyHex)
    return ,(Custody-Bytes ('80010000005e00000000002e'+[Luma.Windows.PlatformCustodyProtocol]::Encode($public)+'0022'+$Configuration.NvNameHex))
}
function Custody-HeadReply($Configuration) {
    return ,(Custody-Bytes ('80020000003500000000000000220020'+$Configuration.ExpectedHeadHex+'0000010000'))
}
try {
    $env:TEMP=$work.FullName; $env:TMP=$work.FullName
    if ($InspectExactEmptySoftwareKey -or $RemoveExactEmptySoftwareFixture) {
        # Separate explicit fixture maintenance. Inspection cannot mutate; cleanup
        # only deletes the independently observed, exact-pinned empty-name key.
        if (-not ('Luma.Windows.Tests.EmptySoftwareKeyDiagnostic' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
namespace Luma.Windows.Tests {
    public sealed class EmptySoftwareKeyObservation {
        public string Provider { get { return "Microsoft Software Key Storage Provider"; } }
        public bool CurrentUserOnly { get { return true; } }
        public bool KeyFound { get; internal set; }
        public bool MatchingFixtureDeleted { get; internal set; }
        public string Status { get; internal set; }
        public string Algorithm { get; internal set; }
        public int NameLength { get; internal set; }
        public string PublicBlobSha256 { get; internal set; }
    }
    public static class EmptySoftwareKeyDiagnostic {
        [DllImport("ncrypt.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
        static extern int NCryptOpenStorageProvider(out IntPtr provider, string name, int flags);
        [DllImport("ncrypt.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
        static extern int NCryptOpenKey(IntPtr provider, out IntPtr key, string name, int legacy, int flags);
        [DllImport("ncrypt.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
        static extern int NCryptGetProperty(IntPtr key, string property, byte[] output, int length, out int required, int flags);
        [DllImport("ncrypt.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
        static extern int NCryptExportKey(IntPtr key, IntPtr exportKey, string type, IntPtr parameters, byte[] output, int length, out int required, int flags);
        [DllImport("ncrypt.dll", ExactSpelling=true)]
        static extern int NCryptFreeObject(IntPtr value);
        [DllImport("ncrypt.dll", ExactSpelling=true)]
        static extern int NCryptDeleteKey(IntPtr key, int flags);
        static void Check(int status) {
            if (status != 0) throw new CryptographicException(status);
        }
        static string StringProperty(IntPtr key, string property) {
            int required;
            Check(NCryptGetProperty(key, property, null, 0, out required, 0x40));
            if (required < 2 || required > 512 || (required & 1) != 0)
                throw new CryptographicException("Unexpected bounded public property size.");
            byte[] bytes = new byte[required];
            int actual;
            Check(NCryptGetProperty(key, property, bytes, bytes.Length, out actual, 0x40));
            if (actual != bytes.Length || bytes[actual-1] != 0 || bytes[actual-2] != 0)
                throw new CryptographicException("Unexpected public property framing.");
            string result = new UnicodeEncoding(false, false, true).GetString(bytes, 0, bytes.Length-2);
            if (result.IndexOf('\0') >= 0) throw new CryptographicException("Unexpected embedded public-property terminator.");
            return result;
        }
        public static EmptySoftwareKeyObservation Inspect() {
            return Observe(false, null);
        }
        public static EmptySoftwareKeyObservation RemoveMatchingFixture(string expectedPublicBlobSha256) {
            if (!String.Equals(expectedPublicBlobSha256,
                "c988f5e7898e379a63ac60e59c031c6a0ea00368f178069ef09b2273ef947b55", StringComparison.Ordinal))
                throw new CryptographicException("Cleanup requires the independently observed exact fixture pin.");
            return Observe(true, expectedPublicBlobSha256);
        }
        static EmptySoftwareKeyObservation Observe(bool remove, string expectedPublicBlobSha256) {
            IntPtr provider = IntPtr.Zero, key = IntPtr.Zero;
            try {
                Check(NCryptOpenStorageProvider(out provider, "Microsoft Software Key Storage Provider", 0));
                // Real managed non-null empty string: exactly one name, never enumeration.
                int status = NCryptOpenKey(provider, out key, String.Empty, 0, 0x40);
                EmptySoftwareKeyObservation result = new EmptySoftwareKeyObservation();
                result.Status = "0x" + unchecked((uint)status).ToString("x8");
                if (!remove && (unchecked((uint)status) == 0x80090016U || unchecked((uint)status) == 0x80090011U))
                    return result;
                Check(status);
                result.KeyFound = true;
                result.NameLength = StringProperty(key, "Name").Length;
                result.Algorithm = StringProperty(key, "Algorithm Name");
                int required;
                Check(NCryptExportKey(key, IntPtr.Zero, "ECCPUBLICBLOB", IntPtr.Zero, null, 0, out required, 0x40));
                if (required != 72) throw new CryptographicException("Unexpected public P256 blob size; ownership unresolved.");
                byte[] blob = new byte[72];
                Check(NCryptExportKey(key, IntPtr.Zero, "ECCPUBLICBLOB", IntPtr.Zero, blob, blob.Length, out required, 0x40));
                if (required != 72 || BitConverter.ToUInt32(blob,0) != 0x31534345U || BitConverter.ToUInt32(blob,4) != 32U)
                    throw new CryptographicException("Unexpected public P256 blob; ownership unresolved.");
                using (SHA256 hash = SHA256.Create()) {
                    result.PublicBlobSha256 = BitConverter.ToString(hash.ComputeHash(blob)).Replace("-", "").ToLowerInvariant();
                }
                if (remove) {
                    if (result.NameLength != 0 || !String.Equals(result.Algorithm, "ECDSA_P256", StringComparison.Ordinal) ||
                        !String.Equals(result.PublicBlobSha256, expectedPublicBlobSha256, StringComparison.Ordinal))
                        throw new CryptographicException("Exact fixture name, algorithm or public-key pin mismatch; nothing deleted.");
                    Check(NCryptDeleteKey(key, 0x40));
                    // Successful NCryptDeleteKey consumes the handle. On failure
                    // Check throws and finally releases the still-owned handle.
                    key = IntPtr.Zero;
                    result.MatchingFixtureDeleted = true;
                }
                return result;
            }
            finally {
                if (key != IntPtr.Zero) NCryptFreeObject(key);
                if (provider != IntPtr.Zero) NCryptFreeObject(provider);
            }
        }
    }
}
'@ -ErrorAction Stop
        }
        if ($RemoveExactEmptySoftwareFixture) {
            [Luma.Windows.Tests.EmptySoftwareKeyDiagnostic]::RemoveMatchingFixture($ExpectedPublicBlobSha256)
        } else {
            [Luma.Windows.Tests.EmptySoftwareKeyDiagnostic]::Inspect()
        }
        return
    }
    Import-Module (Join-Path $PSScriptRoot 'Luma.PlatformSignature.psm1') -Force
    if (-not ('Luma.Windows.PlatformCustodyProtocol' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'PlatformCustody.cs') -ErrorAction Stop
    }
    if (-not ('Luma.Windows.Tests.CustodySoftwareFixture' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Security.Cryptography;
namespace Luma.Windows.Tests {
    public static class CustodySoftwareFixture {
        public static CngKey CreateEphemeral() {
            CngKeyCreationParameters parameters = new CngKeyCreationParameters();
            parameters.Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
            parameters.KeyUsage = CngKeyUsages.Signing;
            // Pass an actual managed null, not a PowerShell null converted to string.Empty.
            CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, (string)null, parameters);
            try {
                if (!key.IsEphemeral || key.KeyName != null || key.IsMachineKey ||
                    key.Provider != CngProvider.MicrosoftSoftwareKeyStorageProvider) {
                    throw new CryptographicException("Software fixture must be unnamed and ephemeral.");
                }
                return key;
            }
            catch {
                key.Dispose();
                throw;
            }
        }
    }
}
'@ -ErrorAction Stop
    }
    # Explicit ephemeral SOFTWARE provider only. Never call OpenCommissioned,
    # the physical Platform Crypto Provider, TBS, service or provisioning APIs.
    $ephemeral=[Luma.Windows.Tests.CustodySoftwareFixture]::CreateEphemeral()
    Assert-Custody $ephemeral.IsEphemeral 'Fixture key unexpectedly persisted.'
    Assert-Custody ($null -eq $ephemeral.KeyName) 'Fixture unexpectedly has a persisted name.'
    Assert-Custody ($ephemeral.Provider.Provider -ceq 'Microsoft Software Key Storage Provider') 'Fixture did not select exact software provider.'
    $signer=New-Object Security.Cryptography.ECDsaCng -ArgumentList $ephemeral
    $signer.HashAlgorithm=[Security.Cryptography.CngAlgorithm]::Sha256
    [byte[]] $blob=$ephemeral.Export([Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
    $blobHex=[Luma.Windows.PlatformCustodyProtocol]::Encode($blob)
    $keyHash=[Luma.Windows.PlatformCustodyProtocol]::Hash($blob)
    $installation='1'*64; $policy='3'*64; $head='4'*64; $nonce='5'*64
    $domain='host-deployment'
    $nvName=[Luma.Windows.PlatformCustodyProtocol]::ExpectedNvName($domain,$policy)
    $configuration=[Luma.Windows.PlatformCustodyConfiguration]::Commissioned($domain,$installation,$blobHex,$keyHash,$policy,$nvName,$head)
    $contentName=[Luma.Windows.PlatformCustodyProtocol]::ExpectedNvName('content-authority',$policy)
    $content=[Luma.Windows.PlatformCustodyConfiguration]::Commissioned('content-authority',$installation,$blobHex,$keyHash,$policy,$contentName,$head)
    Assert-Custody ($configuration.NvIndex -eq 0x01804c57) 'Host index is not the fixed W namespace.'
    Assert-Custody ($content.NvIndex -eq 0x01804c58) 'Content index is not the fixed X namespace.'
    Assert-Custody ($configuration.NvIndex -ne $content.NvIndex) 'Windows custody domains share an index.'
    foreach ($reserved in @(0x01804c41,0x01804c52,0x01804c43)) {
        Assert-Custody ($configuration.NvIndex -ne $reserved -and $content.NvIndex -ne $reserved) 'Windows custody collides with a native namespace.'
    }
    Assert-Custody ($configuration.KeyName -ceq ('LumaOS.HostedAuthority.v1.host.'+$installation+'.signing')) 'Host key name was caller-selected or ambiguous.'
    Assert-Custody ($content.KeyName -ceq ('LumaOS.HostedAuthority.v1.content.'+$installation+'.signing')) 'Content key name is not independently scoped.'
    [byte[]] $copy=$configuration.PublicBlob
    $copy[0]=0
    Assert-Custody ($configuration.PublicBlob[0] -eq 0x45) 'Caller mutated the commissioned public-key buffer.'
    $cases=@(
        @{Domain='native-admin';Installation=$installation;Blob=$blobHex;Hash=$keyHash;Policy=$policy;Name=$nvName;Head=$head},
        @{Domain=$domain;Installation=('0'*64);Blob=$blobHex;Hash=$keyHash;Policy=$policy;Name=$nvName;Head=$head},
        @{Domain=$domain;Installation=$installation;Blob=$blobHex;Hash=('0'*64);Policy=$policy;Name=$nvName;Head=$head},
        @{Domain=$domain;Installation=$installation;Blob=$blobHex;Hash=$keyHash;Policy=('0'*64);Name=$nvName;Head=$head},
        @{Domain=$domain;Installation=$installation;Blob=$blobHex;Hash=$keyHash;Policy=$policy;Name=$contentName;Head=$head},
        @{Domain=$domain;Installation=$installation;Blob=$blobHex;Hash=$keyHash;Policy=$policy;Name=$nvName;Head=('0'*64)},
        @{Domain=$domain;Installation=$installation;Blob=$blobHex.ToUpperInvariant();Hash=$keyHash;Policy=$policy;Name=$nvName;Head=$head},
        @{Domain=$domain;Installation=$installation;Blob=('0'*144);Hash=$keyHash;Policy=$policy;Name=$nvName;Head=$head}
    )
    foreach ($case in $cases) {
        Assert-CustodyThrows { [Luma.Windows.PlatformCustodyConfiguration]::Commissioned($case.Domain,$case.Installation,$case.Blob,$case.Hash,$case.Policy,$case.Name,$case.Head) } 'Invalid commissioned selection admitted.'
    }
    Assert-Custody ([Luma.Windows.PlatformCustodyProtocol]::Encode([Luma.Windows.PlatformCustodyProtocol]::FamilyRequest()) -ceq '8001000000160000017a000000060000010000000001') 'Family request wire bytes differ.'
    Assert-Custody ([Luma.Windows.PlatformCustodyProtocol]::Encode([Luma.Windows.PlatformCustodyProtocol]::IndexRequest($domain)) -ceq '8001000000160000017a0000000101804c5700000001') 'Index capability request wire bytes differ.'
    Assert-Custody ([Luma.Windows.PlatformCustodyProtocol]::Encode([Luma.Windows.PlatformCustodyProtocol]::NvPublicRequest($domain)) -ceq '80010000000e0000016901804c57') 'NV-public request wire bytes differ.'
    Assert-Custody ([Luma.Windows.PlatformCustodyProtocol]::Encode([Luma.Windows.PlatformCustodyProtocol]::HeadRequest($domain)) -ceq '8002000000230000014e01804c5701804c570000000940000009000001000000200000') 'Empty password NV-read request wire bytes differ.'
    foreach ($request in @([Luma.Windows.PlatformCustodyProtocol]::FamilyRequest(),[Luma.Windows.PlatformCustodyProtocol]::IndexRequest($domain),
        [Luma.Windows.PlatformCustodyProtocol]::NvPublicRequest($domain),[Luma.Windows.PlatformCustodyProtocol]::HeadRequest($domain))) {
        Assert-Custody ([Luma.Windows.PlatformCustodyProtocol]::IsReadOnlyCommand($domain,$request)) 'An exact read command was not recognized.'
        [byte[]] $changed=$request.Clone(); $changed[9]=0x36
        Assert-Custody (-not [Luma.Windows.PlatformCustodyProtocol]::IsReadOnlyCommand($domain,$changed)) 'Mutation command admitted by read-only transport.'
    }
    Assert-Custody (-not [Luma.Windows.PlatformCustodyProtocol]::IsReadOnlyCommand($domain,[Luma.Windows.PlatformCustodyProtocol]::HeadRequest('content-authority'))) 'Another authority index was admitted.'
    [byte[]] $family=Custody-Bytes '80010000001b0000000001000000060000000100000100322e3000'
    [Luma.Windows.PlatformCustodyProtocol]::CheckFamily($family)
    [byte[]] $index=Custody-Bytes '8001000000170000000000000000010000000101804c57'
    [Luma.Windows.PlatformCustodyProtocol]::CheckIndex($domain,$index)
    $script:Assertions+=2
    [byte[]] $nvPublic=Custody-NvReply $configuration
    [Luma.Windows.PlatformCustodyProtocol]::CheckNvPublic($configuration,$nvPublic)
    [byte[]] $headReply=Custody-HeadReply $configuration
    Assert-Custody ([Luma.Windows.PlatformCustodyProtocol]::Encode([Luma.Windows.PlatformCustodyProtocol]::CheckHead($configuration,$headReply)) -ceq $head) 'Exact current head response refused.'
    $script:Assertions++
    foreach ($position in @(0,5,9,10,14,18,22,26)) {
        [byte[]] $changed=$family.Clone(); $changed[$position]=$changed[$position] -bxor 0xff
        Assert-CustodyThrows { [Luma.Windows.PlatformCustodyProtocol]::CheckFamily($changed) } 'Malformed or foreign family capability admitted.'
    }
    foreach ($position in @(0,5,9,10,14,18,22)) {
        [byte[]] $changed=$index.Clone(); $changed[$position]=$changed[$position] -bxor 0xff
        Assert-CustodyThrows { [Luma.Windows.PlatformCustodyProtocol]::CheckIndex($domain,$changed) } 'Malformed or missing index capability admitted.'
    }
    foreach ($position in @(0,5,9,11,15,17,18,21,23,55,57,59,93)) {
        [byte[]] $changed=$nvPublic.Clone(); $changed[$position]=$changed[$position] -bxor 1
        Assert-CustodyThrows { [Luma.Windows.PlatformCustodyProtocol]::CheckNvPublic($configuration,$changed) } 'Changed NV policy, Name, attributes, index or size admitted.'
    }
    foreach ($position in @(0,5,9,13,15,47,49,50,52)) {
        [byte[]] $changed=$headReply.Clone(); $changed[$position]=$changed[$position] -bxor 1
        Assert-CustodyThrows { [Luma.Windows.PlatformCustodyProtocol]::CheckHead($configuration,$changed) } 'Changed head, response framing or password-session acknowledgment admitted.'
    }
    foreach ($response in @((New-Object byte[] 9),(New-Object byte[] 513),(Custody-Bytes '80010000000a0000018b'))) {
        Assert-CustodyThrows { [Luma.Windows.PlatformCustodyProtocol]::CheckHead($configuration,$response) } 'Truncated, oversized or TPM-error response admitted.'
    }
    [byte[]] $trailing=New-Object byte[] 54
    [Array]::Copy($headReply,0,$trailing,0,$headReply.Length); $trailing[5]=54
    Assert-CustodyThrows { [Luma.Windows.PlatformCustodyProtocol]::CheckHead($configuration,$trailing) } 'Trailing response data admitted.'
    [byte[]] $inspection=[Luma.Windows.PlatformCustodyProtocol]::InspectionInput($configuration,$nonce)
    [byte[]] $signature=$signer.SignData($inspection)
    Assert-Custody ([Luma.Windows.PlatformSignature]::Verify($blob,$inspection,$signature)) 'Actual ephemeral P256 signature over inspection protocol failed.'
    Assert-Custody (-not [Luma.Windows.PlatformSignature]::Verify($blob,[Luma.Windows.PlatformCustodyProtocol]::InspectionInput($content,$nonce),$signature)) 'Inspection proof crossed authority domains.'
    Assert-Custody (-not [Luma.Windows.PlatformSignature]::Verify($blob,[Luma.Windows.PlatformCustodyProtocol]::InspectionInput($configuration,('6'*64)),$signature)) 'Inspection nonce substitution admitted.'
    Assert-CustodyThrows { [Luma.Windows.PlatformCustodyProtocol]::InspectionInput($configuration,('0'*64)) } 'Zero inspection nonce admitted.'
    [Luma.Windows.PlatformCustodyProtocol]::CheckKeyPolicy(1,'ECDSA_P256',256,32,2,0,$configuration.KeyName,$configuration.KeyName)
    $script:Assertions++
    foreach ($change in @(@{Name='Implementation';Value=2},@{Name='Implementation';Value=3},@{Name='Algorithm';Value='ECDH_P256'},
        @{Name='Length';Value=384},@{Name='Type';Value=0},@{Name='Usage';Value=0x00ffffff},@{Name='Export';Value=1},
        @{Name='Actual';Value='caller-key'})) {
        $values=@{Implementation=1;Algorithm='ECDSA_P256';Length=256;Type=32;Usage=2;Export=0;Actual=$configuration.KeyName}
        $values[$change.Name]=$change.Value
        Assert-CustodyThrows { [Luma.Windows.PlatformCustodyProtocol]::CheckKeyPolicy($values.Implementation,$values.Algorithm,
            $values.Length,$values.Type,$values.Usage,$values.Export,$values.Actual,$configuration.KeyName) } 'Unsafe commissioned key properties admitted.'
    }
    $serviceSid='S-1-5-80-1-2-3-4-5'
    function Custody-Descriptor([string] $Sddl) {
        $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor $Sddl
        [byte[]] $bytes=New-Object byte[] $descriptor.BinaryLength
        $descriptor.GetBinaryForm($bytes,0)
        return ,$bytes
    }
    [Luma.Windows.PlatformCustodyProtocol]::CheckKeySecurity((Custody-Descriptor ('O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;'+$serviceSid+')')),$serviceSid)
    $script:Assertions++
    foreach ($sddl in @('O:SYG:SY',('O:SYG:SYD:(A;;GA;;;SY)(A;;GA;;;'+$serviceSid+')'),
        ('O:BAG:SYD:P(A;;GA;;;SY)(A;;GA;;;'+$serviceSid+')'),
        ('O:SYG:SYD:P(A;;GR;;;SY)(A;;GA;;;'+$serviceSid+')'),
        ('O:SYG:SYD:P(A;OI;GA;;;SY)(A;;GA;;;'+$serviceSid+')'),
        ('O:SYG:SYD:P(D;;GA;;;SY)(A;;GA;;;'+$serviceSid+')'),
        ('O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;'+$serviceSid+')(A;;GA;;;BA)'),
        'O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;SY)')) {
        [byte[]] $descriptor=Custody-Descriptor $sddl
        Assert-CustodyThrows { [Luma.Windows.PlatformCustodyProtocol]::CheckKeySecurity($descriptor,$serviceSid) } 'Unsafe key security descriptor admitted.'
    }
    $source=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'PlatformCustody.cs') -Raw
    foreach ($forbidden in @('NCryptCreatePersistedKey','NCryptDeleteKey','NCryptSetProperty','RegistryKey','TPM2_Clear')) {
        Assert-Custody (-not $source.Contains($forbidden)) ('Unexpected provisioning or host-mutation API: '+$forbidden)
    }
    [pscustomobject]@{schema_version=1;status='passed';assertions=$script:Assertions;skipped=0;
        actual_ephemeral_software_p256=$true;strict_tpm_wire_vectors_tested=$true;
        live_platform_provider_exercised=$false;live_tbs_exercised=$false;physical_tpm_used=$false;
        persistent_key_created=$false;service_installed=$false;registry_changed=$false;
        provisioning_authority_established=$false;durable_rollback_protection_established=$false;
        hosted_authority_enrollment_complete=$false;product_installation_admitted=$false;
        host_settings_changed=$false;production_qualified=$false;gate_closing=$false} | ConvertTo-Json -Depth 4
} finally {
    if ($null -ne $signer) { $signer.Dispose() }
    if ($null -ne $ephemeral) { $ephemeral.Dispose() }
    $env:TEMP=$priorTemp; $env:TMP=$priorTmp
}
