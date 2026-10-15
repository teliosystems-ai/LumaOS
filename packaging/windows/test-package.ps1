[CmdletBinding()]
param([string] $WorkRoot = [System.IO.Path]::GetTempPath(),
    [string] $OpenSslPath = 'C:\Program Files\Git\usr\bin\openssl.exe',
    [string] $SecurityWorkRoot)
$ErrorActionPreference = 'Stop'
$script:Assertions = 0
function Assert-Package($Condition, [string] $Message) {
    $script:Assertions++
    if (-not $Condition) { throw $Message }
}
function Assert-PackageThrows([scriptblock] $Action, [string] $Message) {
    $threw = $false
    try { $null = & $Action } catch {
        $leaf = $_.Exception.GetBaseException()
        if ($_.FullyQualifiedErrorId -match 'PropertyNotFound|MethodNotFound|TypeNotFound|CommandNotFound|UnexpectedToken' -or
            $leaf -is [System.NullReferenceException] -or $leaf -is [System.IndexOutOfRangeException] -or
            $leaf -is [System.OutOfMemoryException] -or $leaf -is [System.AccessViolationException] -or
            $leaf -is [System.InvalidCastException]) { throw "Unexpected implementation error masked as refusal: $_" }
        $threw = $true
    }
    Assert-Package $threw $Message
}
if ($WorkRoot -notmatch '^[A-Za-z]:\\' -or $WorkRoot -match '(^|[\\/])\.{1,2}([\\/]|$)') {
    throw 'Test work root must be an explicit absolute local path without traversal.'
}
$base = Get-Item -LiteralPath $WorkRoot -Force -ErrorAction Stop
if ($base -isnot [System.IO.DirectoryInfo] -or ($base.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Test work root must be an existing real directory.'
}
$temporary = Join-Path $base.FullName ('luma-package-fixture-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temporary -ErrorAction Stop
$originalTemp = $env:TEMP; $originalTmp = $env:TMP
$securityParentLease=$null
try {
    # Add-Type/csc scratch files remain inside the disposable caller-selected drive.
    $env:TEMP = $temporary; $env:TMP = $temporary
    Import-Module (Join-Path $PSScriptRoot 'Luma.Package.psm1') -Force
    function New-Entry([string] $Path, [byte[]] $Content, [string] $Type='0', [int] $Mode=420) {
        [pscustomobject]@{ Path=$Path; Content=$Content; Type=$Type; Mode=$Mode }
    }
    function Bytes([string] $Text) { return [System.Text.Encoding]::UTF8.GetBytes($Text) }
    function Put-Field([byte[]] $Header, [int] $Offset, [string] $Text) {
        $encoded = [System.Text.Encoding]::ASCII.GetBytes($Text)
        [Array]::Copy($encoded, 0, $Header, $Offset, $encoded.Length)
    }
    function Set-Checksum([byte[]] $Header) {
        for ($index=148; $index -lt 156; $index++) { $Header[$index]=32 }
        $sum=0
        foreach ($value in $Header) { $sum += [int]$value }
        Put-Field $Header 148 ([Convert]::ToString($sum, 8).PadLeft(6, '0') + [char]0 + ' ')
    }
    function New-Archive([object[]] $Entries) {
        $stream = New-Object System.IO.MemoryStream
        try {
            foreach ($entry in $Entries) {
                $header = New-Object byte[] 512
                Put-Field $header 0 $entry.Path
                Put-Field $header 100 ([Convert]::ToString($entry.Mode, 8).PadLeft(7, '0'))
                Put-Field $header 108 '0000000'; Put-Field $header 116 '0000000'
                Put-Field $header 124 ([Convert]::ToString($entry.Content.Length, 8).PadLeft(11, '0'))
                Put-Field $header 136 '00000000000'
                $header[156] = [byte][char]$entry.Type
                Put-Field $header 257 'ustar'; Put-Field $header 263 '00'
                Set-Checksum $header
                $stream.Write($header, 0, 512)
                $stream.Write($entry.Content, 0, $entry.Content.Length)
                $padding = New-Object byte[] ((512 - $entry.Content.Length % 512) % 512)
                $stream.Write($padding, 0, $padding.Length)
            }
            $end = New-Object byte[] 1024
            $stream.Write($end, 0, $end.Length)
            return $stream.ToArray()
        } finally { $stream.Dispose() }
    }
    function New-FixtureEntries {
        $elf = New-Object byte[] 64
        $elf[0]=127; $elf[1]=69; $elf[2]=76; $elf[3]=70; $elf[4]=2; $elf[5]=1; $elf[6]=1
        $elf[16]=3; $elf[18]=62; $elf[20]=1; $elf[52]=64; $elf[56]=1
        $identity='{"schema_version":1,"release_id":"luma-wsl-dev-fixture","architecture":"amd64","profile":"W"}'
        @((New-Entry 'etc/' @() '5' 493), (New-Entry 'usr/' @() '5' 493),
          (New-Entry 'usr/bin/' @() '5' 493), (New-Entry 'usr/lib/' @() '5' 493),
          (New-Entry 'usr/lib/luma/' @() '5' 493),
          (New-Entry 'etc/os-release' (Bytes "ID=ubuntu`nVERSION_ID=`"24.04`"`n")),
          (New-Entry 'etc/wsl.conf' (Bytes "[boot]`nsystemd=true`n[automount]`nenabled=false`n[interop]`nenabled=false`nappendWindowsPath=false`n")),
          (New-Entry 'usr/lib/luma/platform.json' (Bytes $identity)),
          (New-Entry 'usr/bin/luma-platform' $elf '0' 493))
    }
    function New-Manifest([object[]] $Entries, [byte[]] $Archive) {
        $files=@()
        [long]$contentBytes=0
        foreach ($entry in $Entries) {
            $contentBytes += $entry.Content.Length
            if ($entry.Type -ceq '0' -and $entry.Path -cin @('etc/os-release', 'etc/wsl.conf',
                'usr/lib/luma/platform.json', 'usr/bin/luma-platform')) {
                $files += [pscustomobject]@{ path=$entry.Path; bytes=$entry.Content.Length
                    sha256=[Luma.Windows.PackageInspector]::Sha256($entry.Content); executable=(($entry.Mode -band 73) -ne 0) }
            }
        }
        [pscustomobject]@{ schema_version=1; package_type='luma-wsl-rootfs-ustar-v1'
            release_id='luma-wsl-dev-fixture'; architecture='amd64'; profile='W'
            rootfs=[pscustomobject]@{ path='rootfs.tar'; bytes=$Archive.Length; sha256=[Luma.Windows.PackageInspector]::Sha256($Archive)
                member_count=$Entries.Count; content_bytes=$contentBytes }; required_files=@($files) }
    }
    function Write-Fixture([object[]] $Entries, [byte[]] $Archive=$null, $Manifest=$null) {
        $directory = Join-Path $temporary ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $directory
        if ($null -eq $Archive) { $Archive=New-Archive $Entries }
        if ($null -eq $Manifest) { $Manifest=New-Manifest $Entries $Archive }
        [System.IO.File]::WriteAllBytes((Join-Path $directory 'rootfs.tar'), $Archive)
        [System.IO.File]::WriteAllText((Join-Path $directory 'manifest.json'), ($Manifest | ConvertTo-Json -Depth 8 -Compress),
            (New-Object System.Text.UTF8Encoding ($false)))
        return $directory
    }
    function Invoke-PackageCli([string] $Directory) {
        $process = New-Object System.Diagnostics.Process
        try {
            $process.StartInfo.FileName = Join-Path $PSHOME 'powershell.exe'
            $process.StartInfo.Arguments = '-NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File "{0}" -PackageDirectory "{1}"' -f `
                (Join-Path $PSScriptRoot 'validate-package.ps1'), $Directory
            $process.StartInfo.UseShellExecute=$false; $process.StartInfo.CreateNoWindow=$true
            $process.StartInfo.RedirectStandardOutput=$true; $process.StartInfo.RedirectStandardError=$true
            $null=$process.Start()
            $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(30000)) {
                $process.Kill(); $null=$process.WaitForExit(5000)
                throw 'Package CLI fixture timed out.'
            }
            if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000) -or
                $stdout.Result.Length -gt 65536 -or $stderr.Result.Length -gt 65536) { throw 'Package CLI fixture exceeded output bounds.' }
            [pscustomobject]@{ exit_code=$process.ExitCode; stdout=$stdout.Result; stderr=$stderr.Result }
        } finally { $process.Dispose() }
    }
    $entries = New-FixtureEntries
    $archive = New-Archive $entries
    $manifest = New-Manifest $entries $archive
    $valid = Write-Fixture $entries $archive $manifest
    $before = Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $valid 'rootfs.tar'),(Join-Path $valid 'manifest.json') | ConvertTo-Json -Compress
    $report = Test-LumaWslPackage $valid
    Assert-Package ($report.content_valid -and $report.structure_valid -and $report.archive_member_count -eq 9) 'Valid normalized fixture refused.'
    Assert-Package ($report.rootfs_bytes -eq $archive.Length -and $report.required_file_count -eq 4) 'Measured content metadata differs.'
    foreach ($flag in @('package_authenticated', 'signer_verified', 'runtime_qualified', 'product_installation_admitted',
        'distribution_imported', 'host_settings_changed', 'production_qualified', 'gate_closing')) {
        Assert-Package (-not $report.$flag) "Content validation conferred authority: $flag."
    }
    $after = Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $valid 'rootfs.tar'),(Join-Path $valid 'manifest.json') | ConvertTo-Json -Compress
    Assert-Package ($before -ceq $after) 'Validation changed package bytes.'
    Assert-Package (@(Get-ChildItem -LiteralPath $valid -Force).Count -eq 2) 'Validation extracted or added package files.'
    $cli = Invoke-PackageCli $valid
    Assert-Package ($cli.exit_code -eq 0 -and $cli.stderr.Length -eq 0) 'Actual package CLI refused valid fixture.'
    $cliReport = ConvertFrom-Json $cli.stdout
    Assert-Package ($cliReport.content_valid -and -not $cliReport.package_authenticated -and
        -not $cliReport.product_installation_admitted) 'Actual CLI conferred authority.'
    foreach ($change in @('schema', 'profile', 'architecture', 'type', 'raw-name', 'archive-hash', 'size', 'count', 'content-size',
        'unknown-field', 'missing-field', 'bool-size', 'string-size', 'negative-size', 'float-size', 'overflow-size',
        'file-hash', 'file-size', 'file-path', 'file-executable', 'duplicate-file', 'missing-required', 'scalar-files', 'authority')) {
        $bad = New-Manifest $entries $archive
        switch ($change) {
            schema { $bad.schema_version=2 }
            profile { $bad.profile='N' }
            architecture { $bad.architecture='arm64' }
            type { $bad.package_type='native-raw-image' }
            raw-name { $bad.rootfs.path='candidate.img' }
            archive-hash { $bad.rootfs.sha256='0' * 64 }
            size { $bad.rootfs.bytes += 512 }
            count { $bad.rootfs.member_count++ }
            content-size { $bad.rootfs.content_bytes++ }
            unknown-field { $bad.rootfs | Add-Member unexpected 1 }
            missing-field { $bad.PSObject.Properties.Remove('profile') }
            bool-size { $bad.rootfs.bytes=$true }
            string-size { $bad.rootfs.bytes=[string]$bad.rootfs.bytes }
            negative-size { $bad.rootfs.bytes=-1 }
            float-size { $bad.rootfs.bytes=[double]$bad.rootfs.bytes + 0.5 }
            overflow-size { $bad.rootfs.bytes=[uint64]::MaxValue }
            file-hash { $bad.required_files[0].sha256='0' * 64 }
            file-size { $bad.required_files[0].bytes++ }
            file-path { $bad.required_files[0].path='../etc/os-release' }
            file-executable { $bad.required_files[0].executable='false' }
            duplicate-file { $bad.required_files += $bad.required_files[0] }
            missing-required { $bad.required_files=@($bad.required_files | Select-Object -Skip 1) }
            scalar-files { $bad.required_files=$bad.required_files[0] }
            authority { $bad | Add-Member package_authenticated $true }
        }
        $directory = Write-Fixture $entries $archive $bad
        Assert-PackageThrows { Test-LumaWslPackage $directory } "Invalid manifest admitted: $change."
    }
    foreach ($suffix in @("`n", "`r", "`r`n")) {
        $badEntries = New-FixtureEntries
        $identity = [pscustomobject]@{ schema_version=1; release_id=('luma-wsl-dev-fixture' + $suffix)
            architecture='amd64'; profile='W' }
        $badEntries[7].Content = Bytes ($identity | ConvertTo-Json -Compress)
        $badArchive = New-Archive $badEntries
        $badManifest = New-Manifest $badEntries $badArchive
        $badManifest.release_id = $identity.release_id
        $directory = Write-Fixture $badEntries $badArchive $badManifest
        Assert-PackageThrows { Test-LumaWslPackage $directory } 'Newline-suffixed release identity admitted.'
    }
    foreach ($path in @('../outside', '/absolute', 'etc/../outside', 'etc//empty', 'etc/./dot', 'etc\windows', 'C:/drive',
        'etc/file:stream', 'etc/trailing.', 'etc/NUL', 'etc/CON.txt', 'etc/space name', 'etc/%2e%2e', ('etc/a' + [char]0 + 'b'))) {
        $badEntries = @(New-FixtureEntries) + @(New-Entry $path (Bytes 'x'))
        $directory = Write-Fixture $badEntries
        Assert-PackageThrows { Test-LumaWslPackage $directory } "Unsafe archive path admitted: $path."
    }
    foreach ($type in @('1','2','3','4','6','x','g','L','K','S')) {
        $badEntries = @(New-FixtureEntries) + @(New-Entry 'etc/unsafe' @() $type)
        $directory = Write-Fixture $badEntries
        Assert-PackageThrows { Test-LumaWslPackage $directory } "Link/extension/special archive type admitted: $type."
    }
    foreach ($change in @('duplicate', 'case-alias', 'parent-case-alias', 'missing-parent', 'file-parent', 'setuid', 'writable',
        'directory-payload', 'checksum', 'padding', 'truncated', 'single-end', 'trailing-data', 'raw-image', 'compressed',
        'foreign-elf', 'foreign-marker', 'unknown-marker', 'os-release', 'lowercase-os-release', 'mixedcase-os-release',
        'wsl-config', 'wsl-default-root', 'link-metadata', 'hidden-name')) {
        $badEntries = New-FixtureEntries
        switch ($change) {
            duplicate { $badEntries += $badEntries[5] }
            case-alias { $badEntries += New-Entry 'etc/OS-RELEASE' (Bytes 'other') }
            parent-case-alias { $badEntries += New-Entry 'ETC/child' (Bytes 'other') }
            missing-parent { $badEntries += New-Entry 'missing/child' (Bytes 'other') }
            file-parent { $badEntries += New-Entry 'etc/os-release/child' (Bytes 'other') }
            setuid { $badEntries[8].Mode=2541 }
            writable { $badEntries[8].Mode=511 }
            directory-payload { $badEntries[0].Content=Bytes 'bad' }
            foreign-elf { $badEntries[8].Content[18]=183 }
            foreign-marker { $badEntries[7].Content=Bytes '{"schema_version":1,"release_id":"luma-wsl-dev-foreign","architecture":"amd64","profile":"W"}' }
            unknown-marker { $badEntries[7].Content=Bytes '{"schema_version":1,"release_id":"luma-wsl-dev-fixture","architecture":"amd64","profile":"W","trusted":true}' }
            os-release { $badEntries[5].Content=Bytes "ID=ubuntu`nVERSION_ID=22.04`n" }
            lowercase-os-release { $badEntries[5].Content=Bytes "id=ubuntu`nversion_id=24.04`n" }
            mixedcase-os-release { $badEntries[5].Content=Bytes "Id=ubuntu`nVERSION_id=24.04`n" }
            wsl-config { $badEntries[6].Content=Bytes "[interop]`nenabled=true`n" }
            wsl-default-root { $badEntries[6].Content=Bytes "[boot]`nsystemd=true`n[automount]`nenabled=false`n[interop]`nenabled=false`nappendWindowsPath=false`n[user]`ndefault=root`n" }
        }
        $badArchive=New-Archive $badEntries
        switch ($change) {
            checksum { $badArchive[0]=120 }
            padding { $badArchive[5*512 + 512 + $badEntries[5].Content.Length]=1 }
            truncated { $badArchive=$badArchive[0..($badArchive.Length - 514)] }
            single-end { $badArchive=$badArchive[0..($badArchive.Length - 513)] }
            trailing-data { $badArchive += New-Object byte[] 512; $badArchive[$badArchive.Length-1]=1 }
            raw-image { $badArchive=New-Object byte[] 2048; $badArchive[510]=85; $badArchive[511]=170 }
            compressed { $badArchive=New-Object byte[] 2048; $badArchive[0]=40; $badArchive[1]=181; $badArchive[2]=47; $badArchive[3]=253 }
            link-metadata { $badArchive[157]=120; $first=$badArchive[0..511]; Set-Checksum $first; [Array]::Copy($first,0,$badArchive,0,512) }
            hidden-name { $badArchive[6]=120; $first=$badArchive[0..511]; Set-Checksum $first; [Array]::Copy($first,0,$badArchive,0,512) }
        }
        $directory = Write-Fixture $badEntries $badArchive
        Assert-PackageThrows { Test-LumaWslPackage $directory } "Unsafe archive/content admitted: $change."
    }
    foreach ($json in @('{"schema_version":1,"schema_version":1}', '{"schema_\u0076ersion":1}',
        '{"rootfs":{"bytes":1,"bytes":2}}', ('{"x":' + ('[' * 17) + '0' + (']' * 17) + '}'), '{"schema_version":')) {
        $directory = Write-Fixture $entries
        [IO.File]::WriteAllText((Join-Path $directory 'manifest.json'), $json, (New-Object Text.UTF8Encoding ($false)))
        Assert-PackageThrows { Test-LumaWslPackage $directory } 'Ambiguous or malformed package JSON admitted.'
    }
    $directory = Write-Fixture $entries
    [IO.File]::WriteAllText((Join-Path $directory 'manifest.json'), (' ' * 65537))
    Assert-PackageThrows { Test-LumaWslPackage $directory } 'Oversize manifest admitted.'
    $directory = Write-Fixture $entries
    [IO.File]::WriteAllBytes((Join-Path $directory 'manifest.json'), [byte[]]@(255,254,0,1))
    Assert-PackageThrows { Test-LumaWslPackage $directory } 'Non-UTF8 manifest admitted.'
    $directory = Write-Fixture $entries
    [IO.File]::WriteAllBytes((Join-Path $directory 'release.sig'), [byte[]]@(0))
    Assert-PackageThrows { Test-LumaWslPackage $directory } 'Unknown signature file implicitly authenticated.'
    $cli = Invoke-PackageCli $directory
    Assert-Package ($cli.exit_code -eq 1 -and $cli.stdout.Length -eq 0 -and $cli.stderr.Contains('Content package must contain exactly')) `
        'Invalid package CLI did not return an explicit refusal; crashes and silent errors are not accepted.'
    # Read an existing Windows compatibility junction; create no C-drive fixture.
    $junction = Join-Path ([IO.Path]::GetPathRoot($env:WINDIR)) 'Users\All Users'
    $probe = Get-Item -LiteralPath $junction -Force -ErrorAction Stop
    Assert-Package (($probe.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) 'Expected Windows compatibility junction was not observed.'
    $refusal = $null
    try { $null = Test-LumaWslPackage $junction } catch { $refusal=$_.Exception.Message }
    Assert-Package ($null -ne $refusal -and $refusal.Contains('Reparse points, symlinks and junctions are forbidden')) `
        'Actual observed junction was not explicitly refused before package access.'
    foreach ($invalidPath in @('rootfs.tar', '\\server\share\package', 'Registry::HKEY_LOCAL_MACHINE',
        (Join-Path $valid '..\outside'))) {
        Assert-PackageThrows { Test-LumaWslPackage $invalidPath } 'Nonlocal/relative/traversing package path admitted.'
    }
    # Actual Ed25519 key generation/signing occurs only in this disposable lab fixture.
    # No checked-in or production private key is read or created.
    $openssl = Get-Item -LiteralPath $OpenSslPath -Force -ErrorAction Stop
    $opensslPin = (Get-FileHash -LiteralPath $openssl.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $key = Join-Path $temporary 'lab.key'
    $der = Join-Path $temporary 'lab.der'
    & $openssl.FullName genpkey -algorithm ED25519 -out $key
    if ($LASTEXITCODE -ne 0) { throw 'Actual lab Ed25519 generation failed.' }
    & $openssl.FullName pkey -in $key -pubout -outform DER -out $der
    if ($LASTEXITCODE -ne 0) { throw 'Actual lab Ed25519 public extraction failed.' }
    $publicHex = [BitConverter]::ToString([IO.File]::ReadAllBytes($der)).Replace('-', '').ToLowerInvariant()
    $otherKey=Join-Path $temporary 'other-lab.key'; $otherDer=Join-Path $temporary 'other-lab.der'
    & $openssl.FullName genpkey -algorithm ED25519 -out $otherKey
    if ($LASTEXITCODE -ne 0) { throw 'Actual alternate lab key generation failed.' }
    & $openssl.FullName pkey -in $otherKey -pubout -outform DER -out $otherDer
    if ($LASTEXITCODE -ne 0) { throw 'Actual alternate lab public extraction failed.' }
    $otherPublicHex=[BitConverter]::ToString([IO.File]::ReadAllBytes($otherDer)).Replace('-', '').ToLowerInvariant()
    $anchor = [pscustomobject]@{schema_version=1; environment='lab'; purpose='luma-wsl-package-v1'
        public_key_spki_hex=$publicHex; not_before_ms=1700000000000L; expires_ms=1700086400000L}
    $anchorPath = Join-Path $temporary 'public-anchor.json'
    function Write-TestAnchor {
        [IO.File]::WriteAllText($anchorPath, ($anchor | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding ($false)))
        (Get-FileHash -LiteralPath $anchorPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $anchorPin = Write-TestAnchor
    $signedPackage = Write-Fixture (New-FixtureEntries)
    $manifestPath = Join-Path $signedPackage 'manifest.json'
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $message = Join-Path $temporary 'lab-message.bin'
    $signaturePath = Join-Path $temporary 'package.sig'
    function Write-TestSignature([string] $Prefix="luma-wsl-package-v1`nlab`namd64`nW`n") {
        [IO.File]::WriteAllBytes($message, ([byte[]]((Bytes $Prefix) + [IO.File]::ReadAllBytes($manifestPath))))
        & $openssl.FullName pkeyutl -sign -rawin -inkey $key -in $message -out $signaturePath
        if ($LASTEXITCODE -ne 0) { throw 'Actual lab Ed25519 signing failed.' }
    }
    Write-TestSignature
    $signatureBytes = [IO.File]::ReadAllBytes($signaturePath)
    $verify = @{PackageDirectory=$signedPackage; SignaturePath=$signaturePath; AnchorPath=$anchorPath
        AnchorSha256=$anchorPin; OpenSslPath=$openssl.FullName; OpenSslSha256=$opensslPin; WorkRoot=$temporary}
    $unsupportedRefusal=$null
    $storageReport=$null
    try { $storageReport=Test-LumaWslPackageSignature @verify } catch { $unsupportedRefusal=$_.Exception.GetBaseException().Message }
    if ($null -ne $unsupportedRefusal) {
        Assert-Package ($unsupportedRefusal -ceq 'Signature scratch volume does not support persistent ACLs.') `
            'Actual storage refusal was not the expected persistent-ACL capability refusal.'
    } else {
        Assert-Package $storageReport.cryptographic_signature_valid 'ACL-capable storage failed actual cryptographic verification.'
    }
    if ([string]::IsNullOrEmpty($SecurityWorkRoot)) {
        Write-Output "Passed $script:Assertions content/storage-capability assertions only. Full signature suite requires explicit -SecurityWorkRoot in repository .luma; it was not executed."
        return
    }
    $allowedSecurityRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\.luma'))
    if (-not [string]::Equals([IO.Path]::GetFullPath($SecurityWorkRoot),$allowedSecurityRoot,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Security metadata fixture is restricted to this repository .luma directory.'
    }
    $securityParentLease=[Luma.Windows.PackageDirectoryLease]::Acquire($allowedSecurityRoot)
    $verify.WorkRoot=$allowedSecurityRoot
    $signed = Test-LumaWslPackageSignature @verify
    $leaseParent=Join-Path $allowedSecurityRoot ('luma-pinned-fixture-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $leaseParent
    $chain=[Luma.Windows.PackageDirectoryLease]::Acquire($leaseParent)
    $private=$null
    try {
        Assert-PackageThrows { [IO.Directory]::Move($leaseParent,($leaseParent+'-renamed')) } 'Pinned input ancestor could be renamed.'
        Assert-PackageThrows { [IO.Directory]::Delete($leaseParent,$false) } 'Pinned input ancestor could be deleted.'
        $private=$chain.CreateScratch()
        $private.VerifyPrivateScratch()
        $privatePath=$private.DirectoryPath
        $acl=Get-Acl -LiteralPath $privatePath
        Assert-Package ($acl.AreAccessRulesProtected -and $acl.Access.Count -eq 2 -and
            $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) `
            'Atomically created scratch owner/protected DACL differs.'
        Assert-PackageThrows { [IO.Directory]::Move($privatePath,($privatePath+'-renamed')) } 'Pinned scratch could be replaced by rename.'
        Assert-PackageThrows { [IO.Directory]::Delete($privatePath,$false) } 'Pinned scratch could be replaced by deletion.'
        $unexpected=Join-Path $privatePath 'unexpected.bin'
        [IO.File]::WriteAllText($unexpected,'retain unknown file')
        Assert-PackageThrows { $private.RemoveScratch() } 'Cleanup recursively deleted unrecognized scratch content.'
        Assert-Package ([IO.File]::ReadAllText($unexpected) -ceq 'retain unknown file') 'Unknown scratch content was changed during cleanup refusal.'
        [IO.File]::Delete($unexpected)
        $private.RemoveScratch(); $private.Dispose(); $private=$null
        Assert-Package (-not [IO.Directory]::Exists($privatePath)) 'Handle-based scratch cleanup did not remove the exact created directory.'
    } finally {
        if ($null -ne $private) { $private.Dispose() }
        $chain.Dispose()
    }
    [IO.Directory]::Delete($leaseParent,$false)
    $outside=Join-Path $temporary 'outside-target'
    $null=New-Item -ItemType Directory -Path $outside
    $marker=Join-Path $outside 'unchanged.txt'; [IO.File]::WriteAllText($marker,'no outside mutation')
    $outsideAcl=(Get-Acl -LiteralPath $outside).Sddl
    $reparse=Join-Path $allowedSecurityRoot ('luma-junction-fixture-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Junction -Path $reparse -Target $outside -ErrorAction Stop
    try {
        Assert-PackageThrows { [Luma.Windows.PackageDirectoryLease]::Acquire($reparse) } 'Lease followed a final junction.'
        Assert-PackageThrows { [Luma.Windows.PackageDirectoryLease]::Acquire((Join-Path $reparse 'subdirectory')) } 'Lease followed an ancestor junction.'
        Assert-Package ((Get-Acl -LiteralPath $outside).Sddl -ceq $outsideAcl -and
            [IO.File]::ReadAllText($marker) -ceq 'no outside mutation') 'Refused reparse path changed the outside target or its ACL.'
    } finally { [IO.Directory]::Delete($reparse,$false) }
    Assert-Package ($signed.cryptographic_signature_valid -and $signed.independent_input_pins_match -and
        $signed.content_valid -and $signed.environment -ceq 'lab') 'Genuine lab package signature was not verified.'
    Assert-Package ($signed.verifier_version_observed.StartsWith('OpenSSL 3.')) 'Actual verifier version was not recorded.'
    Assert-Package ($signed.anchor_not_before_ms -eq 1700000000000L -and
        $signed.anchor_expires_ms -eq 1700086400000L) 'Signed inspection consulted wall time or lost finite anchor bounds.'
    foreach ($flag in @('anchor_custody_authenticated', 'verifier_dependencies_authenticated', 'protected_utc_established',
        'anchor_currently_valid', 'revocation_state_authenticated', 'package_authenticated', 'product_installation_admitted',
        'distribution_imported', 'runtime_qualified', 'host_settings_changed', 'production_qualified', 'gate_closing')) {
        Assert-Package (-not $signed.$flag) "Signature primitive conferred unestablished authority: $flag."
    }
    $badWork=$verify.Clone(); $badWork.WorkRoot=$signedPackage.ToUpperInvariant()
    Assert-PackageThrows { Test-LumaWslPackageSignature @badWork } 'Case alias allowed signature scratch inside candidate package.'
    foreach ($change in @('anchor-pin', 'verifier-pin', 'signature-size', 'signature-bit', 'manifest-whitespace',
        'purpose-preimage', 'environment-preimage', 'architecture-preimage', 'profile-preimage', 'native-release-preimage')) {
        $arguments = $verify.Clone()
        switch ($change) {
            anchor-pin { $arguments.AnchorSha256='0'*64 }
            verifier-pin { $arguments.OpenSslSha256='0'*64 }
            signature-size { [IO.File]::WriteAllBytes($signaturePath, [byte[]]@(1,2)) }
            signature-bit { $badSignature=[byte[]]$signatureBytes.Clone(); $badSignature[0]=$badSignature[0] -bxor 1
                [IO.File]::WriteAllBytes($signaturePath,$badSignature) }
            manifest-whitespace { [IO.File]::WriteAllBytes($manifestPath, ([byte[]]($manifestBytes + (Bytes "`n")))) }
            purpose-preimage { Write-TestSignature "luma-model-catalog-v1`nlab`namd64`nW`n" }
            environment-preimage { Write-TestSignature "luma-wsl-package-v1`nproduction`namd64`nW`n" }
            architecture-preimage { Write-TestSignature "luma-wsl-package-v1`nlab`narm64`nW`n" }
            profile-preimage { Write-TestSignature "luma-wsl-package-v1`nlab`namd64`nN`n" }
            native-release-preimage { Write-TestSignature '' }
        }
        Assert-PackageThrows { Test-LumaWslPackageSignature @arguments } "Cryptographic substitution admitted: $change."
        [IO.File]::WriteAllBytes($manifestPath,$manifestBytes)
        [IO.File]::WriteAllBytes($signaturePath,$signatureBytes)
    }
    foreach ($change in @('purpose','environment','spki','zero-key','foreign-key','expiry','lifetime','start','unknown','duplicate')) {
        $savedAnchor=$anchor | ConvertTo-Json -Compress
        switch ($change) {
            purpose { $anchor.purpose='os-release' }
            environment { $anchor.environment='production' }
            spki { $anchor.public_key_spki_hex='00'+$publicHex.Substring(2) }
            zero-key { $anchor.public_key_spki_hex=$publicHex.Substring(0,24)+('0'*64) }
            foreign-key { $anchor.public_key_spki_hex=$otherPublicHex }
            expiry { $anchor.expires_ms=$anchor.not_before_ms }
            lifetime { $anchor.expires_ms=$anchor.not_before_ms+31622400001L }
            start { $anchor.not_before_ms=0 }
            unknown { $anchor | Add-Member -NotePropertyName trusted -NotePropertyValue $true }
        }
        $arguments=$verify.Clone(); $arguments.AnchorSha256=Write-TestAnchor
        if ($change -ceq 'duplicate') {
            [IO.File]::WriteAllText($anchorPath, ($savedAnchor.TrimEnd('}')+',"purpose":"luma-wsl-package-v1"}'),
                (New-Object Text.UTF8Encoding ($false)))
            $arguments.AnchorSha256=(Get-FileHash -LiteralPath $anchorPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        Assert-PackageThrows { Test-LumaWslPackageSignature @arguments } "Malformed/substituted anchor admitted: $change."
        $anchor=$savedAnchor | ConvertFrom-Json
        $null=Write-TestAnchor
    }
    # Execute the actual public CLI, not just the module entry point.
    $process = New-Object Diagnostics.Process
    try {
        $process.StartInfo.FileName=Join-Path $PSHOME 'powershell.exe'
        $process.StartInfo.Arguments=('-NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File "{0}" -PackageDirectory "{1}" '+
            '-SignaturePath "{2}" -AnchorPath "{3}" -AnchorSha256 {4} -OpenSslPath "{5}" -OpenSslSha256 {6} -WorkRoot "{7}" -CompilerWorkRoot "{8}"') -f
            (Join-Path $PSScriptRoot 'verify-package-signature.ps1'),$signedPackage,$signaturePath,$anchorPath,$anchorPin,
            $openssl.FullName,$opensslPin,$verify.WorkRoot,$temporary
        $process.StartInfo.UseShellExecute=$false; $process.StartInfo.CreateNoWindow=$true
        $process.StartInfo.RedirectStandardOutput=$true; $process.StartInfo.RedirectStandardError=$true
        $null=$process.Start()
        $out=$process.StandardOutput.ReadToEndAsync(); $err=$process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) { $process.Kill(); $null=$process.WaitForExit(2000); throw 'Signature CLI fixture timed out.' }
        if (-not $out.Wait(5000) -or -not $err.Wait(5000)) { throw 'Signature CLI output fixture timed out.' }
        Assert-Package ($process.ExitCode -eq 0 -and $err.Result.Length -eq 0 -and $out.Result.Length -lt 65536) 'Actual signature CLI failed.'
        $cliSignature=$out.Result | ConvertFrom-Json
        Assert-Package ($cliSignature.cryptographic_signature_valid -and -not $cliSignature.product_installation_admitted) 'Actual CLI changed signature authority boundary.'
    } finally { $process.Dispose() }
    [IO.File]::WriteAllBytes($signaturePath, (New-Object byte[] 64))
    $process = New-Object Diagnostics.Process
    try {
        $process.StartInfo.FileName=Join-Path $PSHOME 'powershell.exe'
        $process.StartInfo.Arguments=('-NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File "{0}" -PackageDirectory "{1}" '+
            '-SignaturePath "{2}" -AnchorPath "{3}" -AnchorSha256 {4} -OpenSslPath "{5}" -OpenSslSha256 {6} -WorkRoot "{7}" -CompilerWorkRoot "{8}"') -f
            (Join-Path $PSScriptRoot 'verify-package-signature.ps1'),$signedPackage,$signaturePath,$anchorPath,$anchorPin,
            $openssl.FullName,$opensslPin,$verify.WorkRoot,$temporary
        $process.StartInfo.UseShellExecute=$false; $process.StartInfo.CreateNoWindow=$true
        $process.StartInfo.RedirectStandardOutput=$true; $process.StartInfo.RedirectStandardError=$true
        $null=$process.Start()
        $out=$process.StandardOutput.ReadToEndAsync(); $err=$process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) { $process.Kill(); $null=$process.WaitForExit(2000); throw 'Refusal CLI fixture timed out.' }
        if (-not $out.Wait(5000) -or -not $err.Wait(5000)) { throw 'Refusal CLI output fixture timed out.' }
        Assert-Package ($process.ExitCode -eq 1 -and $out.Result.Length -eq 0 -and
            ($err.Result -replace '\s+', ' ').Contains('Detached package signature verification refused.')) `
            ('Actual invalid signature CLI failed without the expected explicit cryptographic refusal: ' + $err.Result)
    } finally { $process.Dispose() }
    # Exercise the real bounded process reader, not mocks or a claimed timeout flag.
    $toolFixture=Join-Path $temporary 'reader-fixture.exe'
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Threading;
public static class LumaVerifierReaderFixture {
    public static void Main(string[] args) {
        string name=System.IO.Path.GetFileName(Process.GetCurrentProcess().MainModule.FileName);
        if (name.StartsWith("slow")) { Thread.Sleep(10000); return; }
        if (name.StartsWith("large")) { Console.Write(new string('x', 70000)); return; }
        Console.WriteLine("OpenSSL 2.0 unsupported verifier");
    }
}
'@ -OutputAssembly $toolFixture -OutputType ConsoleApplication -ErrorAction Stop
    foreach ($mode in @('slow', 'large', 'invalid-version')) {
        $executable=Join-Path $temporary ($mode+'.exe')
        Copy-Item -LiteralPath $toolFixture -Destination $executable -ErrorAction Stop
        $clock=[Diagnostics.Stopwatch]::StartNew()
        Assert-PackageThrows { [Luma.Windows.PackageSignature]::Run($executable,$temporary,$true) } `
            "Actual subprocess verifier reader failed to refuse $mode."
        Assert-Package ($clock.ElapsedMilliseconds -lt 8000) 'Verifier subprocess exceeded bounded cleanup deadline.'
    }
    Write-Output "Passed $script:Assertions Windows package assertions; no archive extraction or distribution import."
} finally {
    $env:TEMP=$originalTemp; $env:TMP=$originalTmp
    if ($null -ne $securityParentLease) { $securityParentLease.Dispose() }
    $resolved = [System.IO.Path]::GetFullPath($temporary)
    $expectedParent = [System.IO.Path]::GetFullPath($base.FullName).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($expectedParent, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notmatch '^luma-package-fixture-[a-f0-9]{32}$') {
        throw 'Refusing cleanup outside the exact generated fixture directory.'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop
}
