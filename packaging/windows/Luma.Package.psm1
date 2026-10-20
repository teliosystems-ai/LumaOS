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

function Get-LumaValidatedHostedInferencePresence {
    param([bool] $InferenceIdentity, [bool] $WorkspaceIdentity, $Configuration)
    # Call only after ValidateHostedProfile has joined both full descriptors to
    # publisher-required bytes. This classifies that validated composition; it
    # does not authenticate a package or grant an inference session.
    $profile = $Configuration.ContainsKey('usr/share/luma-os/hosted-inference.json')
    $runtime = $Configuration.ContainsKey('usr/share/luma-os/hosted-inference-runtime.json')
    if ($profile -ne $runtime -or ($InferenceIdentity -and -not $profile)) {
        throw 'Validated inference composition requires both complete descriptors.'
    }
    if ($profile -and -not ($InferenceIdentity -or $WorkspaceIdentity)) {
        throw 'Inference descriptors require a closed inference or workspace identity.'
    }
    return $profile -and ($InferenceIdentity -or $WorkspaceIdentity)
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
        $manifest.required_files.Count -lt 4 -or $manifest.required_files.Count -gt 128) {
        throw 'Manifest requires bounded member count and 4 to 128 required regular files; only closed inference/workspace identities admit more than 64.'
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
    $platformSchema = ConvertTo-LumaPackageInteger $identity.schema_version 3 'Platform schema'
    $hostedWorkspace = $platformSchema -eq 3
    $hostedCompute = $platformSchema -eq 2 -or $hostedWorkspace
    $hostedInference = $false
    $identityFields = @('schema_version', 'release_id', 'architecture', 'profile')
    if ($hostedCompute) { $identityFields += 'runtime_profile' }
    Assert-LumaPackageRecord $identity $identityFields 'Embedded platform identity'
    if ($hostedCompute) { $hostedInference = $identity.runtime_profile -is [string] -and $identity.runtime_profile -ceq 'luma-windows-hosted-inference-v1' }
    if ($platformSchema -lt 1 -or $identity.release_id -isnot [string] -or $identity.release_id -cne $manifest.release_id -or
        $identity.architecture -isnot [string] -or $identity.architecture -cne 'amd64' -or
        $identity.profile -isnot [string] -or $identity.profile -cne 'W') { throw 'Embedded platform identity differs from package manifest.' }
    if ($hostedWorkspace -and ($identity.runtime_profile -isnot [string] -or $identity.runtime_profile -cne 'luma-windows-hosted-workspace-v1')) {throw 'Schema3 admits only the distinct closed workspace profile.'}
    if ($hostedCompute -and -not $hostedWorkspace -and ($identity.runtime_profile -isnot [string] -or $identity.runtime_profile -cnotin @('luma-windows-hosted-compute-v1','luma-windows-hosted-inference-v1'))) {
        throw 'Unsupported hosted compute profile.'
    }
    if ($files.Count -gt 64 -and -not $hostedInference -and -not $hostedWorkspace) { throw 'Only closed separately inspected inference/workspace profiles permit 65 to 128 required files.' }
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
    if ($hostedCompute) {
        $requiredWsl += "[user]`ndefault=nobody`n"
        $configuration = @{
            'etc/passwd'="root:x:0:0:Locked guest root:/root:/bin/bash`nnobody:x:65534:65534:Inert compute:/nonexistent:/bin/false`n"
            'etc/group'="root:x:0:`nnogroup:x:65534:`n"
            'etc/shadow'="root:!:0:0:99999:7:::`nnobody:!:0:0:99999:7:::`n"
            'etc/gshadow'="root:!::`nnogroup:!::`n"
        }
        $confinementUnit = @'
[Unit]
Description=Luma hosted inert compute confinement
DefaultDependencies=no
After=systemd-remount-fs.service
Before=multi-user.target
ConditionSecurity=apparmor

[Service]
Type=oneshot
ExecStart=/usr/sbin/apparmor_parser --add --skip-cache /etc/apparmor.d/luma-hosted-compute
RemainAfterExit=yes
TimeoutStartSec=15
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_MAC_ADMIN
AmbientCapabilities=
ProtectHome=yes
PrivateTmp=yes
ProtectSystem=strict
RestrictAddressFamilies=AF_UNIX

[Install]
WantedBy=multi-user.target
'@
        $confinementUnit = ($confinementUnit -replace "`r`n", "`n") + "`n"
        $configuration['etc/systemd/system/luma-hosted-confinement.service']=$confinementUnit
        $configuration['etc/systemd/system/multi-user.target.wants/luma-hosted-confinement.service']=$confinementUnit
        foreach ($path in $configuration.Keys) {
            if (-not $paths.Contains($path) -or -not $content.HostedConfiguration.ContainsKey($path) -or
                $content.HostedConfiguration[$path] -cne $configuration[$path]) { throw 'Hosted guest fixed account or confinement configuration differs.' }
        }
        foreach ($path in @('usr/bin/systemd-run','usr/bin/systemctl','usr/sbin/apparmor_parser','usr/libexec/luma-os/luma-platform')) {
            $selected=@($files | Where-Object {$_.Path -ceq $path})
            if ($selected.Count -ne 1 -or -not $selected[0].Executable -or $selected[0].Bytes -lt 64 -or $selected[0].Bytes -gt 64MB) {
                throw 'Hosted guest fixed executable is missing or exceeds bounds.'
            }
        }
        $first=@($files | Where-Object {$_.Path -ceq 'usr/bin/luma-platform'})[0]
        $alias=@($files | Where-Object {$_.Path -ceq 'usr/libexec/luma-os/luma-platform'})[0]
        if ($first.Bytes -ne $alias.Bytes -or $first.Sha256 -cne $alias.Sha256) { throw 'Hosted platform alias differs from exact compiled binary.' }
        $policy='etc/apparmor.d/luma-hosted-compute'
        if (-not $paths.Contains($policy) -or -not $content.HostedConfiguration.ContainsKey($policy) -or
            $content.HostedConfiguration[$policy] -cmatch '(?m)^[ \t]*(?:#[ \t]*)?include(?:[ \t]|$)' -or
            -not $content.HostedConfiguration[$policy].Contains('profile luma-hosted-compute ') -or
            -not $content.HostedConfiguration[$policy].Contains('deny network,')) { throw 'Hosted policy is missing or not completely preprocessed.' }
        [Luma.Windows.PackageInspector]::ValidateHostedProfile($content, $files.ToArray())
        $hostedInference = Get-LumaValidatedHostedInferencePresence $hostedInference $hostedWorkspace $content.HostedConfiguration
    }
    if ($content.WslConfiguration -cne $requiredWsl) { throw 'WSL configuration is not the exact confined development baseline.' }
    [pscustomobject]@{
        schema_version=1; status='content-validated-not-authenticated'; package_type=$manifest.package_type
        release_id=$manifest.release_id; architecture='amd64'; profile='W'
        hosted_compute_profile=$hostedCompute
        hosted_inference_profile=$hostedInference
        hosted_workspace_profile=$hostedWorkspace
        manifest_sha256=[Luma.Windows.PackageInspector]::Sha256($manifestBytes)
        rootfs_sha256=$content.ArchiveSha256; rootfs_bytes=$content.ArchiveBytes
        archive_member_count=$content.MemberCount; content_bytes=$content.ContentBytes
        required_file_count=$files.Count; structure_valid=$true; content_valid=$true
        package_authenticated=$false; signer_verified=$false; runtime_qualified=$false
        product_installation_admitted=$false; distribution_imported=$false
        host_settings_changed=$false; production_qualified=$false; gate_closing=$false
    }
}

function Test-LumaWslPackageSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $PackageDirectory,
        [Parameter(Mandatory)][string] $SignaturePath,
        [Parameter(Mandatory)][string] $AnchorPath,
        [Parameter(Mandatory)][string] $AnchorSha256,
        [Parameter(Mandatory)][string] $OpenSslPath,
        [Parameter(Mandatory)][string] $OpenSslSha256,
        [Parameter(Mandatory)][string] $WorkRoot
    )
    if ($env:OS -ne 'Windows_NT') { throw 'Windows signature inspection requires native Windows.' }
    foreach ($pin in @($AnchorSha256, $OpenSslSha256)) {
        if ($pin -cnotmatch '\A[a-f0-9]{64}\z') { throw 'Independent input pins require canonical lowercase SHA256.' }
    }
    if (-not ('Luma.Windows.PackageSignature' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'PackageSignature.cs') -ErrorAction Stop
    }
    $root = Assert-LumaPackageHostPath $PackageDirectory $true
    $workBase = Assert-LumaPackageHostPath $WorkRoot $true
    $rootPrefix = $root.FullName.TrimEnd('\') + '\'
    if ([string]::Equals($workBase.FullName, $root.FullName, [StringComparison]::OrdinalIgnoreCase) -or
        $workBase.FullName.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Signature scratch must be separate from the candidate package.'
    }
    $paths = @($AnchorPath, $OpenSslPath, $SignaturePath,
        (Join-Path $root.FullName 'manifest.json'), (Join-Path $root.FullName 'rootfs.tar'))
    $leases = New-Object 'System.Collections.Generic.List[System.IO.FileStream]'
    $directoryLeases = New-Object 'System.Collections.Generic.List[System.IDisposable]'
    $scratchLease = $null
    try {
        $workLease = [Luma.Windows.PackageDirectoryLease]::Acquire($workBase.FullName)
        $directoryLeases.Add($workLease)
        foreach ($path in $paths) {
            $file = Assert-LumaPackageHostPath $path $false
            if ($path -cin @($AnchorPath, $OpenSslPath, $SignaturePath) -and
                $file.FullName.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Signature, independent anchor and verifier must be outside the candidate package.'
            }
            $directoryLeases.Add([Luma.Windows.PackageDirectoryLease]::Acquire($file.Directory.FullName))
            $leases.Add([IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read))
        }
        if ($leases[0].Length -eq 0 -or $leases[0].Length -gt 65536 -or
            $leases[1].Length -eq 0 -or $leases[1].Length -gt 64MB -or
            $leases[2].Length -ne 64 -or [IO.Path]::GetExtension($OpenSslPath) -cne '.exe') {
            throw 'Anchor, verifier or detached Ed25519 signature has an invalid type or size.'
        }
        if ((Get-FileHash -LiteralPath $AnchorPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $AnchorSha256 -or
            (Get-FileHash -LiteralPath $OpenSslPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $OpenSslSha256) {
            throw 'Independent anchor or verifier SHA256 pin mismatch.'
        }
        $anchorBytes = [Luma.Windows.PackageInspector]::ReadManifest($AnchorPath)
        $anchor = ConvertFrom-LumaPackageJson ((New-Object Text.UTF8Encoding ($false, $true)).GetString($anchorBytes))
        Assert-LumaPackageRecord $anchor @('schema_version', 'environment', 'purpose', 'public_key_spki_hex',
            'not_before_ms', 'expires_ms') 'Package public anchor'
        if ((ConvertTo-LumaPackageInteger $anchor.schema_version 1 'Anchor schema') -ne 1 -or
            $anchor.environment -isnot [string] -or $anchor.environment -cne 'lab' -or
            $anchor.purpose -isnot [string] -or $anchor.purpose -cne 'luma-wsl-package-v1' -or
            $anchor.public_key_spki_hex -isnot [string] -or
            $anchor.public_key_spki_hex -cnotmatch '\A302a300506032b6570032100[a-f0-9]{64}\z') {
            throw 'Anchor requires exact lab development package purpose and canonical Ed25519 SPKI.'
        }
        $start = ConvertTo-LumaPackageInteger $anchor.not_before_ms 4102444800000 'Anchor not-before'
        $end = ConvertTo-LumaPackageInteger $anchor.expires_ms 4102444800000 'Anchor expiry'
        if ($start -eq 0 -or $end -le $start -or $end - $start -gt 31622400000) {
            throw 'Anchor validity must be positive, finite and at most 366 days.'
        }
        $public = [Luma.Windows.PackageSignature]::DecodeHex($anchor.public_key_spki_hex, 44)
        if ($anchor.public_key_spki_hex.Substring(24) -ceq ('0' * 64)) { throw 'Zero Ed25519 public key is forbidden.' }
        $content = Test-LumaWslPackage $root.FullName
        $manifest = [Luma.Windows.PackageInspector]::ReadManifest((Join-Path $root.FullName 'manifest.json'))
        if ([Luma.Windows.PackageInspector]::Sha256($manifest) -cne $content.manifest_sha256) {
            throw 'Exact manifest bytes changed across content and signature checks.'
        }
        $signature = [Luma.Windows.PackageInspector]::ReadManifest($SignaturePath)
        $scratchLease = $workLease.CreateScratch()
        $scratch = $scratchLease.DirectoryPath
        [IO.File]::WriteAllBytes((Join-Path $scratch 'anchor.der'), $public)
        [IO.File]::WriteAllBytes((Join-Path $scratch 'signature.bin'), $signature)
        [IO.File]::WriteAllBytes((Join-Path $scratch 'input.bin'),
            [Luma.Windows.PackageSignature]::SigningInput($manifest, $anchor.environment))
        [IO.File]::WriteAllBytes((Join-Path $scratch 'empty.cnf'), [byte[]]@())
        $version = [Luma.Windows.PackageSignature]::Run($OpenSslPath, $scratch, $true)
        $null = [Luma.Windows.PackageSignature]::Run($OpenSslPath, $scratch, $false)
        if ((Get-FileHash -LiteralPath $AnchorPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $AnchorSha256 -or
            (Get-FileHash -LiteralPath $OpenSslPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $OpenSslSha256) {
            throw 'Independent anchor or verifier changed during cryptographic inspection.'
        }
        [pscustomobject]@{
            schema_version=1; status='cryptographically-valid-lab-inputs-not-installation-authority'
            release_id=$content.release_id; architecture=$content.architecture; profile=$content.profile
            manifest_sha256=$content.manifest_sha256; rootfs_sha256=$content.rootfs_sha256
            anchor_input_sha256=$AnchorSha256; public_key_spki_sha256=[Luma.Windows.PackageInspector]::Sha256($public)
            signature_sha256=[Luma.Windows.PackageInspector]::Sha256($signature)
            signature_purpose=$anchor.purpose; environment=$anchor.environment
            anchor_not_before_ms=$start; anchor_expires_ms=$end
            verifier_sha256=$OpenSslSha256; verifier_version_observed=$version
            structure_valid=$true; content_valid=$true; cryptographic_signature_valid=$true
            independent_input_pins_match=$true; anchor_custody_authenticated=$false
            verifier_dependencies_authenticated=$false; protected_utc_established=$false
            anchor_currently_valid=$false; revocation_state_authenticated=$false
            package_authenticated=$false; product_installation_admitted=$false
            distribution_imported=$false; runtime_qualified=$false; host_settings_changed=$false
            production_qualified=$false; gate_closing=$false
        }
    } finally {
        foreach ($lease in $leases) { $lease.Dispose() }
        try {
            if ($null -ne $scratchLease) { $scratchLease.RemoveScratch() }
        } finally {
            if ($null -ne $scratchLease) { $scratchLease.Dispose() }
            foreach ($directoryLease in $directoryLeases) { $directoryLease.Dispose() }
        }
    }
}

Export-ModuleMember -Function Test-LumaWslPackage, Test-LumaWslPackageSignature
