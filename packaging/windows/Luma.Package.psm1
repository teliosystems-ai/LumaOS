Set-StrictMode -Version Latest

if (-not ('Luma.Windows.PackageInspector' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'PackageInspector.cs') -ErrorAction Stop
}

function Assert-LumaPackageRecord {
    param($Value, [string[]] $Fields, [string] $Name)
    if ($null -eq $Value -or ($Value -isnot [pscustomobject] -and
        $Value -isnot [System.Collections.IDictionary])) { throw "$Name must be a record." }
    $keys = if ($Value -is [System.Collections.IDictionary]) { @($Value.Keys) } else { @($Value.PSObject.Properties.Name) }
    if ($keys.Count -ne $Fields.Count) { throw "$Name contains omitted or unsupported fields." }
    foreach ($field in $Fields) {
        if (@($keys | Where-Object { $_ -ceq $field }).Count -ne 1) { throw "$Name field spelling is not canonical." }
    }
}

function ConvertTo-LumaPackageInteger {
    param($Value, [long] $Maximum, [string] $Name)
    if ($null -eq $Value -or $Value.GetType() -notin @([byte], [sbyte], [int16], [uint16],
        [int32], [uint32], [int64], [uint64]) -or $Value -lt 0 -or $Value -gt $Maximum) {
        throw "$Name must be a nonnegative bounded integer."
    }
    return [long]$Value
}

function ConvertFrom-LumaPackageJson {
    param([Parameter(Mandatory)][string] $Text)
    if ($Text.Length -eq 0 -or $Text.Length -gt 65536) { throw 'Package JSON exceeds the fixed bound.' }
    $objects = New-Object 'System.Collections.Generic.Stack[System.Collections.Generic.HashSet[string]]'
    $containers = New-Object 'System.Collections.Generic.Stack[string]'
    foreach ($token in [regex]::Matches($Text, '"(?<raw>(?:[^"\\]|\\.)*)"|(?<open>[\{\[])|(?<close>[\}\]])')) {
        if ($token.Groups['open'].Success) {
            if ($containers.Count -ge 16) { throw 'Package JSON exceeds the fixed nesting bound.' }
            $containers.Push($token.Value)
            if ($token.Value -ceq '{') {
                $objects.Push((New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)))
            }
        } elseif ($token.Groups['close'].Success) {
            if ($containers.Count -eq 0) { throw 'Package JSON has invalid container nesting.' }
            $expected = if ($token.Value -ceq '}') { '{' } else { '[' }
            if ($containers.Pop() -cne $expected) { throw 'Package JSON has invalid container nesting.' }
            if ($token.Value -ceq '}') { $null = $objects.Pop() }
        } elseif ($Text.Substring($token.Index + $token.Length).TrimStart().StartsWith(':')) {
            $key = $token.Groups['raw'].Value
            if ($containers.Count -eq 0 -or $containers.Peek() -cne '{' -or $key.Contains('\') -or
                -not $objects.Peek().Add($key)) { throw 'Package JSON has duplicate, escaped or misplaced fields.' }
        }
    }
    if ($containers.Count -ne 0) { throw 'Package JSON has unterminated containers.' }
    return ConvertFrom-Json -InputObject $Text -ErrorAction Stop
}

function Assert-LumaPackageHostPath {
    param([Parameter(Mandatory)][string] $LiteralPath, [bool] $Directory)
    if ($LiteralPath -notmatch '^[A-Za-z]:\\' -or $LiteralPath -match '(^|[\\/])\.{1,2}([\\/]|$)' -or
        $LiteralPath.Contains('/') -or $LiteralPath.Contains('::')) {
        throw 'Package inputs require absolute local Windows paths without traversal or provider syntax.'
    }
    $drive = New-Object System.IO.DriveInfo ([System.IO.Path]::GetPathRoot($LiteralPath))
    if ($drive.DriveType -notin @([System.IO.DriveType]::Fixed, [System.IO.DriveType]::Removable)) {
        throw 'Network, unknown and nonlocal package storage are forbidden.'
    }
    $item = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
    if (($Directory -and $item -isnot [System.IO.DirectoryInfo]) -or
        (-not $Directory -and $item -isnot [System.IO.FileInfo])) { throw 'Package path has the wrong filesystem type.' }
    $current = $item
    while ($null -ne $current) {
        if (($current.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Reparse points, symlinks and junctions are forbidden in package paths.'
        }
        $current = if ($current -is [System.IO.FileInfo]) { $current.Directory } else { $current.Parent }
    }
    return $item
}

function Test-LumaWslPackage {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $PackageDirectory)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows package inspection requires native Windows.' }
    $root = Assert-LumaPackageHostPath $PackageDirectory $true
    $children = @(Get-ChildItem -LiteralPath $root.FullName -Force -ErrorAction Stop)
    if ($children.Count -ne 2 -or @($children | Where-Object { $_.Name -ceq 'manifest.json' }).Count -ne 1 -or
        @($children | Where-Object { $_.Name -ceq 'rootfs.tar' }).Count -ne 1) {
        throw 'Content package must contain exactly manifest.json and rootfs.tar; native image bundles are not WSL packages.'
    }
    $manifestFile = Assert-LumaPackageHostPath (Join-Path $root.FullName 'manifest.json') $false
    $archiveFile = Assert-LumaPackageHostPath (Join-Path $root.FullName 'rootfs.tar') $false
    $manifestBytes = [Luma.Windows.PackageInspector]::ReadManifest($manifestFile.FullName)
    $encoding = New-Object System.Text.UTF8Encoding ($false, $true)
    $manifest = ConvertFrom-LumaPackageJson ($encoding.GetString($manifestBytes))
    Assert-LumaPackageRecord $manifest @('schema_version', 'package_type', 'release_id', 'architecture', 'profile', 'rootfs', 'required_files') 'Package manifest'
    if ((ConvertTo-LumaPackageInteger $manifest.schema_version 1 'Manifest schema') -ne 1 -or
        $manifest.package_type -isnot [string] -or $manifest.package_type -cne 'luma-wsl-rootfs-ustar-v1' -or
        $manifest.architecture -isnot [string] -or $manifest.architecture -cne 'amd64' -or
        $manifest.profile -isnot [string] -or $manifest.profile -cne 'W' -or
        $manifest.release_id -isnot [string] -or $manifest.release_id -cnotmatch '\Aluma-wsl-dev-[A-Za-z0-9][A-Za-z0-9.-]{0,63}\z') {
        throw 'Unsupported package schema/type/release/architecture/profile identity.'
    }
    Assert-LumaPackageRecord $manifest.rootfs @('path', 'bytes', 'sha256', 'member_count', 'content_bytes') 'Rootfs descriptor'
    if ($manifest.rootfs.path -isnot [string] -or $manifest.rootfs.path -cne 'rootfs.tar' -or
        $manifest.rootfs.sha256 -isnot [string] -or $manifest.rootfs.sha256 -cnotmatch '\A[a-f0-9]{64}\z') {
        throw 'Rootfs must be the exact local rootfs.tar with canonical SHA256.'
    }
    $archiveBytes = ConvertTo-LumaPackageInteger $manifest.rootfs.bytes ([Luma.Windows.PackageInspector]::MaximumArchiveBytes) 'Archive bytes'
    $contentBytes = ConvertTo-LumaPackageInteger $manifest.rootfs.content_bytes ([Luma.Windows.PackageInspector]::MaximumArchiveBytes) 'Content bytes'
    $memberCount = ConvertTo-LumaPackageInteger $manifest.rootfs.member_count ([Luma.Windows.PackageInspector]::MaximumMembers) 'Member count'
    if ($memberCount -eq 0 -or $manifest.required_files -isnot [array] -or
        $manifest.required_files.Count -lt 4 -or $manifest.required_files.Count -gt 64) {
        throw 'Manifest requires bounded member count and 4 to 64 required regular files.'
    }
    $files = New-Object 'System.Collections.Generic.List[Luma.Windows.RequiredFile]'
    $paths = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $manifest.required_files) {
        Assert-LumaPackageRecord $file @('path', 'bytes', 'sha256', 'executable') 'Required file'
        if ($file.path -isnot [string] -or $file.sha256 -isnot [string] -or
            $file.sha256 -cnotmatch '\A[a-f0-9]{64}\z' -or $file.executable -isnot [bool]) {
            throw 'Required file path/hash/executable types are invalid.'
        }
        $null = [Luma.Windows.PackageInspector]::ValidatePath($file.path)
        if (-not $paths.Add($file.path)) { throw 'Duplicate or case-aliased required file.' }
        $expected = New-Object Luma.Windows.RequiredFile
        $expected.Path = $file.path
        $expected.Bytes = ConvertTo-LumaPackageInteger $file.bytes ([Luma.Windows.PackageInspector]::MaximumArchiveBytes) 'Required file bytes'
        $expected.Sha256 = $file.sha256
        $expected.Executable = $file.executable
        $files.Add($expected)
    }
    foreach ($mandatory in @('etc/os-release', 'etc/wsl.conf', 'usr/lib/luma/platform.json', 'usr/bin/luma-platform')) {
        $selected = @($files | Where-Object { $_.Path -ceq $mandatory })
        if ($selected.Count -ne 1) { throw "Missing exact mandatory package member: $mandatory." }
        $maximum = if ($mandatory -ceq 'usr/bin/luma-platform') { 64MB } elseif ($mandatory -ceq 'usr/lib/luma/platform.json') { 4096 } else { 16384 }
        if ($selected[0].Bytes -eq 0 -or $selected[0].Bytes -gt $maximum -or
            $selected[0].Executable -ne ($mandatory -ceq 'usr/bin/luma-platform')) {
            throw 'Mandatory member size or executable state is invalid.'
        }
    }
    $content = [Luma.Windows.PackageInspector]::Validate($archiveFile.FullName, $archiveBytes, $contentBytes,
        [int]$memberCount, $manifest.rootfs.sha256, $files.ToArray())
    $identity = ConvertFrom-LumaPackageJson $content.PlatformIdentity
    Assert-LumaPackageRecord $identity @('schema_version', 'release_id', 'architecture', 'profile') 'Embedded platform identity'
    if ((ConvertTo-LumaPackageInteger $identity.schema_version 1 'Platform schema') -ne 1 -or
        $identity.release_id -isnot [string] -or $identity.release_id -cne $manifest.release_id -or
        $identity.architecture -isnot [string] -or $identity.architecture -cne 'amd64' -or
        $identity.profile -isnot [string] -or $identity.profile -cne 'W') { throw 'Embedded platform identity differs from package manifest.' }
    $osKeys = @{}
    foreach ($line in ($content.OsRelease -split '\r?\n')) {
        if ($line -cmatch '^(?<key>ID|VERSION_ID)=(?:"(?<quoted>[A-Za-z0-9.]+)"|(?<plain>[A-Za-z0-9.]+))$') {
            if ($osKeys.ContainsKey($Matches.key)) { throw 'Duplicate OS release identity.' }
            $osKeys[$Matches.key] = if ($Matches.ContainsKey('quoted')) { $Matches['quoted'] } else { $Matches['plain'] }
        } elseif ($line -cmatch '^(?:ID|VERSION_ID)=') { throw 'Unsupported OS release identity encoding.' }
    }
    if ($osKeys.Count -ne 2 -or $osKeys['ID'] -cne 'ubuntu' -or $osKeys['VERSION_ID'] -cne '24.04') {
        throw 'WSL rootfs must declare Ubuntu 24.04 userland.'
    }
    $requiredWsl = "[boot]`nsystemd=true`n[automount]`nenabled=false`n[interop]`nenabled=false`nappendWindowsPath=false`n"
    if ($content.WslConfiguration -cne $requiredWsl) { throw 'WSL configuration is not the exact confined development baseline.' }
    [pscustomobject]@{
        schema_version=1; status='content-validated-not-authenticated'; package_type=$manifest.package_type
        release_id=$manifest.release_id; architecture='amd64'; profile='W'
        manifest_sha256=[Luma.Windows.PackageInspector]::Sha256($manifestBytes)
        rootfs_sha256=$content.ArchiveSha256; rootfs_bytes=$content.ArchiveBytes
        archive_member_count=$content.MemberCount; content_bytes=$content.ContentBytes
        required_file_count=$files.Count; structure_valid=$true; content_valid=$true
        package_authenticated=$false; signer_verified=$false; runtime_qualified=$false
        product_installation_admitted=$false; distribution_imported=$false
        host_settings_changed=$false; production_qualified=$false; gate_closing=$false
    }
}

Export-ModuleMember -Function Test-LumaWslPackage
