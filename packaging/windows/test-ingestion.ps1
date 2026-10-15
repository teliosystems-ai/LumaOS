[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $CompilerWorkRoot,
    [Parameter(Mandatory)][string] $SecurityWorkRoot
)
$ErrorActionPreference = 'Stop'
$script:Assertions = 0
function Assert-Ingestion($Condition, [string] $Message) {
    $script:Assertions++
    if (-not $Condition) { throw $Message }
}
function Assert-IngestionThrows([scriptblock] $Action, [string] $Message) {
    $threw = $false
    try { $null = & $Action } catch {
        $leaf = $_.Exception.GetBaseException()
        if ($_.FullyQualifiedErrorId -match 'PropertyNotFound|MethodNotFound|TypeNotFound|CommandNotFound|UnexpectedToken' -or
            $leaf -is [NullReferenceException] -or $leaf -is [IndexOutOfRangeException] -or
            $leaf -is [OutOfMemoryException] -or $leaf -is [AccessViolationException] -or
            $leaf -is [InvalidCastException] -or $leaf -is [EntryPointNotFoundException] -or
            $leaf -is [DllNotFoundException] -or $leaf -is [TypeInitializationException]) {
            throw "Unexpected implementation error masked as refusal: $_"
        }
        $threw = $true
    }
    Assert-Ingestion $threw $Message
}
function Restore-OwnedFixtureAcl([string] $Path, [Security.AccessControl.FileSecurity] $Snapshot) {
    # SetAccessControl writes only modified sections; an untouched GetAccessControl
    # snapshot is not a reliable restore. Mark exactly the captured DACL dirty.
    $restore = New-Object Security.AccessControl.FileSecurity
    $restore.SetSecurityDescriptorBinaryForm($Snapshot.GetSecurityDescriptorBinaryForm(), [Security.AccessControl.AccessControlSections]::Access)
    [IO.File]::SetAccessControl($Path, $restore)
}
function Assert-WorkRoot([string] $Path) {
    if ($Path -notmatch '\A[A-Za-z]:\\' -or $Path.Contains('/') -or $Path.Substring(2).Contains(':') -or
        $Path -match '(^|\\)\.{1,2}(\\|$)') { throw 'Fixture work roots must be exact absolute local paths.' }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item -isnot [IO.DirectoryInfo]) { throw 'Fixture work root must already exist.' }
    $ancestor = $item
    while ($null -ne $ancestor) {
        if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Fixture work root cannot traverse reparse points.' }
        $ancestor = $ancestor.Parent
    }
    return $item.FullName.TrimEnd('\')
}
$compilerBase = Assert-WorkRoot $CompilerWorkRoot
$securityBase = Assert-WorkRoot $SecurityWorkRoot
$securityDrive = New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($securityBase))
if ($securityDrive.DriveFormat -cne 'NTFS') { throw 'ACL/identity fixtures require real NTFS; exFAT is not equivalent.' }
$fixtureName = 'luma-ingestion-fixture-' + [guid]::NewGuid().ToString('N')
$fixture = Join-Path $securityBase $fixtureName
$compilerName = 'luma-ingestion-compiler-' + [guid]::NewGuid().ToString('N')
$compiler = Join-Path $compilerBase $compilerName
$null = New-Item -ItemType Directory -Path $fixture -ErrorAction Stop
$null = New-Item -ItemType Directory -Path $compiler -ErrorAction Stop
$previousTemp = $env:TEMP; $previousTmp = $env:TMP
$junction = $null; $denied = $null; $previousAcl = $null
try {
    $env:TEMP = $compiler; $env:TMP = $compiler
    Import-Module (Join-Path $PSScriptRoot 'Luma.Ingestion.psm1') -Force
    Initialize-LumaIngestionRuntime -CompilerWorkRoot $compiler
    # Positive tests require the actual ordinary interactive caller. Elevated
    # execution is a fixture failure, not a skipped or simulated positive pass.
    $sid = [Luma.Windows.ScopedIngestion]::CurrentSid()
    Assert-Ingestion ($sid.StartsWith('S-1-5-') -and $sid -ne 'S-1-5-18') 'Expected an actual ordinary interactive SID.'
    if (-not ('Luma.Windows.IngestionFixture' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Luma.Windows {
  public static class IngestionFixture {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateHardLink(string path, string existing, IntPtr security);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool DeviceIoControl(SafeFileHandle file, uint code, IntPtr input, uint inputLength,
      IntPtr output, uint outputLength, out uint returned, IntPtr overlapped);
    public static void HardLink(string path, string existing) {
      if (!CreateHardLink(path, existing, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    public static void Sparse(SafeFileHandle file) {
      uint returned;
      if (!DeviceIoControl(file, 0x000900c4, IntPtr.Zero, 0, IntPtr.Zero, 0, out returned, IntPtr.Zero))
        throw new Win32Exception(Marshal.GetLastWin32Error());
    }
  }
  public sealed class LiveIngestionFixture : IDisposable {
    object token, lease;
    MethodInfo check;
    Stopwatch clock;
    FileStream stream;
    Type leaseType;
    public LiveIngestionFixture(string root, string relative) {
      try {
        Type implementation = null;
        foreach (Assembly assembly in AppDomain.CurrentDomain.GetAssemblies()) {
          implementation = assembly.GetType("Luma.Windows.ScopedIngestion", false);
          if (implementation != null) break;
        }
        if (implementation == null) throw new InvalidOperationException("Actual source reader is unavailable.");
        Type tokenType = implementation.GetNestedType("Token", BindingFlags.NonPublic);
        leaseType = implementation.GetNestedType("Lease", BindingFlags.NonPublic);
        MethodInfo pin = implementation.GetMethod("Pin", BindingFlags.NonPublic | BindingFlags.Static);
        if (tokenType == null || leaseType == null || pin == null) throw new InvalidOperationException("Actual private source gates are unavailable.");
        check = leaseType.GetMethod("Check", BindingFlags.Public | BindingFlags.Instance);
        if (check == null) throw new InvalidOperationException("Actual live source check is unavailable.");
        token = Activator.CreateInstance(tokenType, true);
        clock = Stopwatch.StartNew();
        lease = pin.Invoke(null, new object[] { root, relative, token, clock });
        Check();
      } catch { Dispose(); throw; }
    }
    public void Check() {
      try { check.Invoke(lease, new object[] { token, clock }); }
      catch (TargetInvocationException error) { throw error.InnerException; }
    }
    public byte[] Read(int length) {
      Check();
      PropertyInfo property = leaseType.GetProperty("File", BindingFlags.Public | BindingFlags.Instance);
      if (property == null) throw new InvalidOperationException("Actual pinned source handle is unavailable.");
      SafeFileHandle file = (SafeFileHandle)property.GetValue(lease, null);
      stream = new FileStream(file, FileAccess.Read, 4096, true);
      byte[] bytes = new byte[length];
      int read = stream.Read(bytes, 0, bytes.Length);
      if (read != length) throw new IOException("Actual pinned fixture handle returned incomplete bytes.");
      Check();
      return bytes;
    }
    public void Dispose() {
      if (stream != null) stream.Dispose();
      if (lease != null) ((IDisposable)lease).Dispose();
      if (token != null) ((IDisposable)token).Dispose();
    }
  }
}
'@ -ErrorAction Stop
    }
    function Hash-Bytes([byte[]] $Bytes) {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
    }
    function New-Enrollment([string] $Relative, [byte[]] $Bytes, [int] $Maximum = 32768) {
        return [pscustomobject][ordered]@{
            schema_version = 1; enrollment_id = [guid]::NewGuid().ToString('N'); windows_sid = $sid
            root = $fixture; relative_path = $Relative; max_bytes = $Maximum; expected_sha256 = (Hash-Bytes $Bytes)
        }
    }
    function Copy-Enrollment($Value) { return ConvertFrom-Json ($Value | ConvertTo-Json -Compress) }
    function Inspect($Enrollment) {
        $review = Get-LumaIngestionReview -Enrollment $Enrollment
        return Read-LumaEnrolledFile -Enrollment $Enrollment -Confirmation $review.confirmation
    }

    [byte[]] $payload = @(0, 255, 10, 13, 127, 128, 65)
    $payloadPath = Join-Path $fixture 'payload.bin'
    [IO.File]::WriteAllBytes($payloadPath, $payload)
    $enrollment = New-Enrollment 'payload.bin' $payload
    $review = Get-LumaIngestionReview -Enrollment $enrollment
    Assert-Ingestion (-not $review.source_accessed -and -not $review.input_authenticated -and -not $review.grant_issued) 'Review must remain inert input preparation.'
    $result = Read-LumaEnrolledFile -Enrollment $enrollment -Confirmation $review.confirmation
    Assert-Ingestion ($result.content_hex -ceq '00ff0a0d7f8041' -and $result.bytes -eq $payload.Length) 'Actual scoped read must return the exact verified bytes.'
    Assert-Ingestion ($result.sha256 -ceq $enrollment.expected_sha256 -and $result.windows_sid -ceq $sid) 'Actual source hash and SID must be exact.'
    Assert-Ingestion ($result.read_only -and -not $result.product_grants -and -not $result.authenticated_linux_bridge -and -not $result.production_qualified -and -not $result.gate_closing) 'An unsigned local read must not claim managed/Linux or production authority.'
    Assert-Ingestion (-not $result.confidentiality_established -and -not $result.hard_deadline_enforced -and $result.partial_delivery_possible) 'Shared-source privacy, hard deadlines and atomic stdout delivery must not be invented.'
    Assert-Ingestion ($result.open_no_recall_requested -and -not $result.cloud_provider_qualified) 'No-recall intent is not untested cloud-provider qualification.'
    Assert-Ingestion (([Luma.Windows.ScopedIngestion]::OpenNoRecall -band 0x00100000) -ne 0 -and
        ([Luma.Windows.ScopedIngestion]::OpenReparsePoint -band 0x00200000) -ne 0) 'Both metadata and data opens must request no-recall/reparse-point semantics.'
    Assert-Ingestion ($result.file_id -cmatch '\A[a-f0-9]{16}\z' -and $result.review_sha256 -ceq $review.review_sha256) 'Actual handle identity and exact review binding are required.'
    Assert-Ingestion ((Hash-Bytes ([IO.File]::ReadAllBytes($payloadPath))) -ceq $enrollment.expected_sha256) 'Inspection must not alter source bytes.'

    $inertMissing = Copy-Enrollment $enrollment; $inertMissing.relative_path = 'not-present.bin'
    Assert-Ingestion (-not (Get-LumaIngestionReview $inertMissing).source_accessed) 'Review must not enumerate or open the enrolled source.'
    Assert-IngestionThrows { Inspect $inertMissing } 'Missing exact file must refuse.'
    Assert-IngestionThrows { Read-LumaEnrolledFile $enrollment 'yes' } 'A generic confirmation cannot authorize a scope.'
    $changed = Copy-Enrollment $enrollment; $changed.max_bytes = 6
    Assert-IngestionThrows { Read-LumaEnrolledFile $changed $review.confirmation } 'Review confirmation must bind the exact byte limit.'
    Assert-IngestionThrows { Inspect $changed } 'Source length beyond reviewed limit must refuse before returning content.'
    $wrongHash = Copy-Enrollment $enrollment; $wrongHash.expected_sha256 = ('a' * 64)
    Assert-IngestionThrows { Inspect $wrongHash } 'Expected SHA256 mismatch must refuse rather than returning observed bytes.'
    $wrongSid = Copy-Enrollment $enrollment; $wrongSid.windows_sid = 'S-1-5-21-1-2-3-1001'
    Assert-IngestionThrows { Inspect $wrongSid } 'Caller SID substitution must refuse.'

    $emptyPath = Join-Path $fixture 'empty.bin'; [IO.File]::WriteAllBytes($emptyPath, [byte[]]@())
    $empty = Inspect (New-Enrollment 'empty.bin' ([byte[]]@()) 1)
    Assert-Ingestion ($empty.bytes -eq 0 -and $empty.content_hex -ceq '') 'An explicitly hash-bound empty file must round-trip.'
    [byte[]] $block = New-Object byte[] 32768
    for ($index = 0; $index -lt $block.Length; $index++) { $block[$index] = [byte]($index % 251) }
    [IO.File]::WriteAllBytes((Join-Path $fixture 'block.bin'), $block)
    $bounded = Inspect (New-Enrollment 'block.bin' $block)
    Assert-Ingestion ($bounded.bytes -eq 32768 -and $bounded.content_hex.Length -eq 65536) 'The actual bounded block reader must return complete validated content.'

    $reader = New-Object IO.FileStream ($payloadPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { Assert-Ingestion ((Inspect $enrollment).content_hex -ceq $result.content_hex) 'Compatible ordinary readers may coexist.' }
    finally { $reader.Dispose() }
    $writer = New-Object IO.FileStream ($payloadPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try { Assert-IngestionThrows { Inspect $enrollment } 'An outstanding writable handle must prevent acquiring the read-only source lease.' }
    finally { $writer.Dispose() }

    $hardlink = Join-Path $fixture 'hardlink.bin'
    [Luma.Windows.IngestionFixture]::HardLink($hardlink, $payloadPath)
    try {
        Assert-IngestionThrows { Inspect $enrollment } 'The original name of a multiply linked file must refuse.'
        Assert-IngestionThrows { Inspect (New-Enrollment 'hardlink.bin' $payload) } 'A hard-link alias must refuse.'
    } finally { [IO.File]::Delete($hardlink) }
    Assert-Ingestion ((Inspect $enrollment).content_hex -ceq $result.content_hex) 'Removing only the disposable alias restores a single-link source.'

    $offlinePath = Join-Path $fixture 'offline.bin'; [IO.File]::WriteAllBytes($offlinePath, $payload)
    $ordinaryAttributes = [IO.File]::GetAttributes($offlinePath)
    [IO.File]::SetAttributes($offlinePath, ($ordinaryAttributes -bor [IO.FileAttributes]::Offline))
    try { Assert-IngestionThrows { Inspect (New-Enrollment 'offline.bin' $payload) } 'An actual NTFS offline-marked source must refuse before data access.' }
    finally { [IO.File]::SetAttributes($offlinePath, $ordinaryAttributes) }

    $denied = Join-Path $fixture 'denied.bin'; [IO.File]::WriteAllBytes($denied, $payload)
    $previousAcl = [IO.File]::GetAccessControl($denied)
    $restrictedAcl = [IO.File]::GetAccessControl($denied)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule ((New-Object Security.Principal.SecurityIdentifier $sid), [Security.AccessControl.FileSystemRights]::ReadData, [Security.AccessControl.AccessControlType]::Deny)
    $restrictedAcl.AddAccessRule($rule)
    [IO.File]::SetAccessControl($denied, $restrictedAcl)
    try { Assert-IngestionThrows { Inspect (New-Enrollment 'denied.bin' $payload) } 'The actual ordinary-caller read-deny ACL must be enforced.' }
    finally { Restore-OwnedFixtureAcl $denied $previousAcl; $previousAcl = $null }

    # Exercise a real already-open lease, not merely another pathname open.
    # Reflection is confined to this fixture; no production hook or authority
    # constructor is exported. Windows does not retroactively revoke the access
    # mask on an existing handle, so the live AccessCheck must reject explicitly.
    $midPath = Join-Path $fixture 'midlease.bin'; [IO.File]::WriteAllBytes($midPath, $payload)
    $midPreviousAcl = [IO.File]::GetAccessControl($midPath)
    $liveFixture = $null
    try {
        $liveFixture = New-Object Luma.Windows.LiveIngestionFixture ($fixture, 'midlease.bin')
        $liveFixture.Check()
        Assert-Ingestion ($null -ne $liveFixture) 'The actual ordinary-caller lease must validate before revocation.'
        $midDeny = [IO.File]::GetAccessControl($midPath)
        $midRule = New-Object Security.AccessControl.FileSystemAccessRule ((New-Object Security.Principal.SecurityIdentifier $sid), [Security.AccessControl.FileSystemRights]::ReadData, [Security.AccessControl.AccessControlType]::Deny)
        $midDeny.AddAccessRule($midRule)
        [IO.File]::SetAccessControl($midPath, $midDeny)
        $aclRefused = $false
        try { $liveFixture.Check() }
        catch {
            $leaf = $_.Exception.GetBaseException()
            if ($leaf -isnot [UnauthorizedAccessException] -or $leaf.Message -cne 'The current ordinary-caller ACL denies this exact read.') {
                throw "A non-ACL error cannot stand in for actual mid-lease authorization refusal: $_"
            }
            $aclRefused = $true
        }
        Assert-Ingestion $aclRefused 'A read-deny ACL applied after acquisition must revoke the actual existing lease at use.'
        Restore-OwnedFixtureAcl $midPath $midPreviousAcl
        $liveFixture.Check()
        Assert-Ingestion ($null -ne $liveFixture) 'Restoring only the owned fixture ACL must restore the genuine live check.'
        $observed = $liveFixture.Read($payload.Length)
        Assert-Ingestion ($observed.Length -eq $payload.Length -and (Hash-Bytes $observed) -ceq (Hash-Bytes $payload)) 'The same pinned handle must read the exact fixture again only after the actual ACL check succeeds.'
    } finally {
        try { Restore-OwnedFixtureAcl $midPath $midPreviousAcl }
        finally {
            if ($null -ne $liveFixture) { $liveFixture.Dispose() }
        }
    }

    $inside = Join-Path $fixture 'inner'; $null = New-Item -ItemType Directory -Path $inside
    [IO.File]::WriteAllBytes((Join-Path $inside 'payload.bin'), $payload)
    $nested = Inspect (New-Enrollment 'inner\payload.bin' $payload)
    Assert-Ingestion ($nested.content_hex -ceq $result.content_hex) 'An explicit non-reparse nested path must work without enumeration.'
    $junction = Join-Path $fixture 'jump'
    $null = New-Item -ItemType Junction -Path $junction -Target $inside -ErrorAction Stop
    Assert-IngestionThrows { Inspect (New-Enrollment 'jump\payload.bin' $payload) } 'A junction ancestor must refuse without following or hydrating it.'
    $rootJunction = Copy-Enrollment $enrollment; $rootJunction.root = $junction
    Assert-IngestionThrows { Inspect $rootJunction } 'A junction enrollment root must refuse.'
    [IO.Directory]::Delete($junction); $junction = $null
    Assert-IngestionThrows { Inspect (New-Enrollment 'inner' $payload) } 'Directories cannot substitute for the exact file.'

    $oversize = Join-Path $fixture 'oversize.bin'
    $sparse = New-Object IO.FileStream ($oversize, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { [Luma.Windows.IngestionFixture]::Sparse($sparse.SafeFileHandle); $sparse.SetLength(1048577) }
    finally { $sparse.Dispose() }
    $tooLarge = New-Enrollment 'oversize.bin' $payload 1048576
    Assert-IngestionThrows { Inspect $tooLarge } 'A sparse file over one MiB must refuse without reading its payload.'

    foreach ($relative in @('..\payload.bin', '.\payload.bin', 'inner\..\payload.bin', '\payload.bin', 'C:\payload.bin',
        'payload.bin:secret', 'payload.bin::$DATA', 'payload.bin ', 'payload.bin.', 'inner//payload.bin', 'inner\\payload.bin',
        'payload*.bin', 'NUL.txt', 'COM1', 'LPT9.log', ('COM' + [char]0xb9), 'CLOCK$', ('x' + [char]10 + 'y'), ('x' * 241))) {
        $bad = Copy-Enrollment $enrollment; $bad.relative_path = $relative
        Assert-IngestionThrows { Get-LumaIngestionReview $bad } ('Unsafe relative source must refuse: ' + $relative)
    }
    foreach ($root in @('C:\', '\\server\share\root', '\\?\C:\root', '\\.\C:\root', 'C:\root\..\other', 'C:/root', 'C:\root:stream', 'C:\root\')) {
        $bad = Copy-Enrollment $enrollment; $bad.root = $root
        Assert-IngestionThrows { Get-LumaIngestionReview $bad } ('Unsafe root must refuse: ' + $root)
    }
    foreach ($maximum in @($true, '32768', 3.5, 0, -1, 1048577)) {
        $bad = Copy-Enrollment $enrollment; $bad.max_bytes = $maximum
        Assert-IngestionThrows { Get-LumaIngestionReview $bad } 'Noninteger or out-of-range byte limits must refuse.'
    }
    $rootDepth = $fixture.Substring(3).Split('\').Length
    $tooDeep = Copy-Enrollment $enrollment
    $tooDeep.relative_path = ((@('a') * (32 - $rootDepth)) -join '\') + '\payload.bin'
    Assert-IngestionThrows { Get-LumaIngestionReview $tooDeep } 'Combined root and relative depth must refuse before any scoped handles are opened.'
    $bad = Copy-Enrollment $enrollment; $bad | Add-Member ignored_authority $true
    Assert-IngestionThrows { Get-LumaIngestionReview $bad } 'Unknown caller-authority fields must refuse.'
    $json = $enrollment | ConvertTo-Json -Compress
    $parsed = ConvertFrom-LumaIngestionJson $json
    Assert-Ingestion ((Get-LumaIngestionReview $parsed).review_sha256 -ceq $review.review_sha256) 'Strict transport parsing must preserve the exact review binding.'
    foreach ($invalid in @('{"schema_version":1,"schema_version":1}', '{"schema_version":1,"SCHEMA_VERSION":1}',
        '{"schema\u005fversion":1}', '{"nested":{"value":1}}', '[{"schema_version":1}]', '{}{}', (' ' * 8193))) {
        Assert-IngestionThrows { ConvertFrom-LumaIngestionJson $invalid } 'Duplicate, escaped, nested, multiple-record or oversized JSON must refuse.'
    }
    $controlPath = Join-Path $fixture 'enrollment.json'
    [IO.File]::WriteAllText($controlPath, $json, (New-Object Text.UTF8Encoding $false))
    $captured = Read-LumaIngestionEnrollmentInput -LiteralPath $controlPath
    Assert-Ingestion ((Get-LumaIngestionReview $captured).review_sha256 -ceq $review.review_sha256) 'Actual control input must use the same bounded handle-safe capture.'
    $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $entry = Join-Path $PSScriptRoot 'inspect-enrolled-file.ps1'
    $reviewOutput = & $powershell -NoProfile -ExecutionPolicy RemoteSigned -File $entry -EnrollmentPath $controlPath -CompilerWorkRoot $compiler -ReviewOnly
    Assert-Ingestion ($LASTEXITCODE -eq 0) 'The actual read-only review CLI must succeed as the ordinary caller.'
    $cliReview = ConvertFrom-Json ($reviewOutput -join [Environment]::NewLine)
    Assert-Ingestion ($cliReview.confirmation -ceq $review.confirmation -and -not $cliReview.source_accessed) 'The actual review CLI must preserve the exact inert confirmation.'
    $readOutput = & $powershell -NoProfile -ExecutionPolicy RemoteSigned -File $entry -EnrollmentPath $controlPath -CompilerWorkRoot $compiler -Confirmation $review.confirmation
    Assert-Ingestion ($LASTEXITCODE -eq 0) 'The actual read CLI must enforce the ordinary-caller token and return verified data.'
    $cliRead = ConvertFrom-Json ($readOutput -join [Environment]::NewLine)
    Assert-Ingestion ($cliRead.content_hex -ceq $result.content_hex -and -not $cliRead.authenticated_linux_bridge -and -not $cliRead.gate_closing) 'The actual CLI payload must remain exact data, not product/Linux authority.'
    $controlWriter = New-Object IO.FileStream ($controlPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    try { Assert-IngestionThrows { Read-LumaIngestionEnrollmentInput $controlPath } 'Writable control input cannot be captured as a stable enrollment.' }
    finally { $controlWriter.Dispose() }
    $controlLink = Join-Path $fixture 'enrollment-link.json'
    [Luma.Windows.IngestionFixture]::HardLink($controlLink, $controlPath)
    try { Assert-IngestionThrows { Read-LumaIngestionEnrollmentInput $controlLink } 'Control-file hard-link aliases must refuse.' }
    finally { [IO.File]::Delete($controlLink) }

    [pscustomobject][ordered]@{
        schema_version = 1; result = 'passed'; assertions = $script:Assertions; skipped = 0
        actual_windows_sid = $sid; ntfs_security_fixture = $true; ordinary_caller_acl_read = $true
        authenticated_linux_bridge = $false; product_grants = $false; production_qualified = $false; gate_closing = $false
        compiler_work_root = $compilerBase; security_work_root = $securityBase
    } | ConvertTo-Json -Depth 3
} finally {
    $env:TEMP = $previousTemp; $env:TMP = $previousTmp
    if ($null -ne $previousAcl -and $null -ne $denied -and [IO.File]::Exists($denied)) { Restore-OwnedFixtureAcl $denied $previousAcl }
    if ($null -ne $junction -and [IO.Directory]::Exists($junction)) { [IO.Directory]::Delete($junction) }
    foreach ($entry in @(@($fixture, $securityBase, $fixtureName), @($compiler, $compilerBase, $compilerName))) {
        $target = [IO.Path]::GetFullPath([string]$entry[0])
        $expected = [IO.Path]::GetFullPath((Join-Path ([string]$entry[1]) ([string]$entry[2])))
        if ($target -cne $expected -or -not $target.StartsWith(([string]$entry[1] + '\'), [StringComparison]::OrdinalIgnoreCase) -or
            ([string]$entry[2]) -cnotmatch '\Aluma-ingestion-(fixture|compiler)-[a-f0-9]{32}\z') { throw 'Refusing cleanup outside the exact disposable fixture targets.' }
        if ([IO.Directory]::Exists($target)) { Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop }
    }
}
