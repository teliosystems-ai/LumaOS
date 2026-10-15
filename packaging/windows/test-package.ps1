[CmdletBinding()]
param([string] $WorkRoot = [System.IO.Path]::GetTempPath())
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
    Write-Output "Passed $script:Assertions Windows package assertions; no archive extraction or distribution import."
} finally {
    $env:TEMP=$originalTemp; $env:TMP=$originalTmp
    $resolved = [System.IO.Path]::GetFullPath($temporary)
    $expectedParent = [System.IO.Path]::GetFullPath($base.FullName).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($expectedParent, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notmatch '^luma-package-fixture-[a-f0-9]{32}$') {
        throw 'Refusing cleanup outside the exact generated fixture directory.'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop
}
