Set-StrictMode -Version Latest

$script:PackageModule = Import-Module (Join-Path $PSScriptRoot 'Luma.Package.psm1') -PassThru -Force

function Invoke-LumaTrustPackageHelper {
    param([string] $Name, [object[]] $Arguments)
    & $script:PackageModule { param($FunctionName, $Values) & $FunctionName @Values } $Name $Arguments
}

function Assert-LumaTrustRecord {
    param($Value, [string[]] $Fields, [string] $Name)
    Invoke-LumaTrustPackageHelper 'Assert-LumaPackageRecord' @($Value, $Fields, $Name)
}

function Get-LumaTrustInteger {
    param($Value, [long] $Maximum, [string] $Name)
    Invoke-LumaTrustPackageHelper 'ConvertTo-LumaPackageInteger' @($Value, $Maximum, $Name)
}

function Assert-LumaTrustHash {
    param($Value)
    if ($Value -isnot [string] -or $Value -cnotmatch '\A[0-9a-f]{64}\z') {
        throw 'Trust identities require canonical lowercase SHA256.'
    }
}

function Get-LumaTrustPublicKey {
    param($Value)
    if ($Value -isnot [string] -or $Value -cnotmatch '\A302a300506032b6570032100[0-9a-f]{64}\z' -or
        $Value.Substring(24) -ceq ('0' * 64)) { throw 'Trust authority requires a nonzero canonical Ed25519 SPKI.' }
    return ,([Luma.Windows.PackageSignature]::DecodeHex($Value, 44))
}

function Assert-LumaTrustRevocations {
    param($Value)
    if ($Value -isnot [Array] -or $Value.Count -gt 64) { throw 'Revocations require a bounded array.' }
    $previous = ''
    foreach ($item in $Value) {
        Assert-LumaTrustHash $item
        if ([string]::CompareOrdinal($previous, $item) -ge 0) { throw 'Revocations must be sorted and unique.' }
        $previous = $item
    }
}

function Test-LumaWslLabReleasePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $PackageDirectory,
        [Parameter(Mandatory)][string] $SignaturePath,
        [Parameter(Mandatory)][string] $AnchorPath,
        [Parameter(Mandatory)][string] $AnchorSha256,
        [Parameter(Mandatory)][string] $OpenSslPath,
        [Parameter(Mandatory)][string] $OpenSslSha256,
        [Parameter(Mandatory)][string] $WorkRoot,
        [Parameter(Mandatory)][string] $AuthorityPath,
        [Parameter(Mandatory)][string] $AuthoritySha256,
        [Parameter(Mandatory)][string] $PolicyPath,
        [Parameter(Mandatory)][string] $PolicySignaturePath,
        [Parameter(Mandatory)][string] $TimeAttestationPath,
        [Parameter(Mandatory)][string] $TimeSignaturePath,
        [Parameter(Mandatory)][string] $ChallengeNonce,
        [Parameter(Mandatory)][object] $MinimumSequence,
        [Parameter(Mandatory)][string] $ExpectedPreviousPolicySha256,
        [ValidateSet('lab', 'production')][string] $Environment = 'lab'
    )
    if ($Environment -cne 'lab') {
        throw 'Production admission requires deployed custody, protected UTC and durable rollback protection; this lab verifier cannot grant it.'
    }
    if ($env:OS -ne 'Windows_NT') { throw 'Release policy inspection requires native Windows.' }
    Assert-LumaTrustHash $AuthoritySha256
    Assert-LumaTrustHash $ExpectedPreviousPolicySha256
    if ($ChallengeNonce -cnotmatch '\A[0-9a-f]{64}\z' -or $ChallengeNonce -ceq ('0' * 64)) {
        throw 'A nonzero independent 32-byte challenge is required.'
    }
    $minimum = Get-LumaTrustInteger $MinimumSequence 9007199254740991 'Minimum policy sequence'
    if ($minimum -lt 1) { throw 'Minimum policy sequence must be positive.' }
    if (-not ('Luma.Windows.PackageSignature' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'PackageSignature.cs') -ErrorAction Stop
    }
    if (-not ('Luma.Windows.TrustInputLease' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'TrustInputs.cs') -ErrorAction Stop
    }
    $candidate = Invoke-LumaTrustPackageHelper 'Assert-LumaPackageHostPath' @($PackageDirectory, $true)
    $work = Invoke-LumaTrustPackageHelper 'Assert-LumaPackageHostPath' @($WorkRoot, $true)
    $prefix = $candidate.FullName.TrimEnd('\') + '\'
    if ([string]::Equals($work.FullName, $candidate.FullName, [StringComparison]::OrdinalIgnoreCase) -or
        $work.FullName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Trust scratch must be independent of the candidate package.'
    }
    $directories = New-Object 'System.Collections.Generic.List[System.IDisposable]'
    $streams = New-Object 'System.Collections.Generic.List[System.IDisposable]'
    $trustInputs = New-Object 'System.Collections.Generic.List[Luma.Windows.TrustInputLease]'
    $scratch = $null
    try {
        $workLease = [Luma.Windows.PackageDirectoryLease]::Acquire($work.FullName)
        $directories.Add($workLease)
        $paths = @($AuthorityPath, $PolicyPath, $PolicySignaturePath, $TimeAttestationPath, $TimeSignaturePath,
            $AnchorPath, $OpenSslPath, $SignaturePath,
            (Join-Path $candidate.FullName 'manifest.json'), (Join-Path $candidate.FullName 'rootfs.tar'))
        for ($pathIndex = 0; $pathIndex -lt $paths.Count; $pathIndex++) {
            $path = $paths[$pathIndex]
            $file = Invoke-LumaTrustPackageHelper 'Assert-LumaPackageHostPath' @($path, $false)
            if ($path -cin @($AuthorityPath, $PolicyPath, $PolicySignaturePath, $TimeAttestationPath, $TimeSignaturePath) -and
                $file.FullName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Independent trust inputs cannot be embedded inside the candidate package.'
            }
            $directories.Add([Luma.Windows.PackageDirectoryLease]::Acquire($file.Directory.FullName))
            if ($pathIndex -lt 5) {
                $inputLease = [Luma.Windows.TrustInputLease]::Acquire($file.FullName)
                $streams.Add($inputLease); $trustInputs.Add($inputLease)
            } else {
                $streams.Add([IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read))
            }
        }
        $captures = New-Object 'System.Collections.Generic.List[byte[]]'
        for ($index = 0; $index -lt 5; $index++) {
            $captures.Add($trustInputs[$index].Capture(65536, ($index -in @(2, 4))))
        }
        if ([Luma.Windows.PackageInspector]::Sha256($captures[0]) -cne $AuthoritySha256) {
            throw 'Independent lab authority pin mismatch.'
        }
        $encoding = New-Object Text.UTF8Encoding ($false, $true)
        $authority = Invoke-LumaTrustPackageHelper 'ConvertFrom-LumaPackageJson' @($encoding.GetString($captures[0]))
        Assert-LumaTrustRecord $authority @('schema_version', 'environment', 'purpose', 'public_key_spki_hex',
            'not_before_ms', 'expires_ms') 'Lab trust authority'
        if ((Get-LumaTrustInteger $authority.schema_version 1 'Authority schema') -ne 1 -or
            $authority.environment -isnot [string] -or $authority.environment -cne 'lab' -or
            $authority.purpose -isnot [string] -or $authority.purpose -cne 'luma-wsl-trust-policy-v1') {
            throw 'Trust authority is not an exact lab release-policy authority.'
        }
        $public = Get-LumaTrustPublicKey $authority.public_key_spki_hex
        $authorityStart = Get-LumaTrustInteger $authority.not_before_ms 4102444800000 'Authority start'
        $authorityEnd = Get-LumaTrustInteger $authority.expires_ms 4102444800000 'Authority expiry'
        if ($authorityStart -eq 0 -or $authorityEnd -le $authorityStart -or
            $authorityEnd - $authorityStart -gt 31622400000) { throw 'Authority lifetime is invalid.' }
        $policyHash = [Luma.Windows.PackageInspector]::Sha256($captures[1])
        $policy = Invoke-LumaTrustPackageHelper 'ConvertFrom-LumaPackageJson' @($encoding.GetString($captures[1]))
        Assert-LumaTrustRecord $policy @('schema_version', 'environment', 'purpose', 'sequence', 'previous_policy_sha256',
            'not_before_ms', 'expires_ms', 'package_anchor_sha256', 'verifier_sha256', 'clock_public_key_spki_hex',
            'authorized_release', 'revoked_anchor_sha256s', 'revoked_manifest_sha256s', 'revoked_rootfs_sha256s') 'Release policy'
        if ((Get-LumaTrustInteger $policy.schema_version 1 'Policy schema') -ne 1 -or
            $policy.environment -isnot [string] -or $policy.environment -cne 'lab' -or
            $policy.purpose -isnot [string] -or $policy.purpose -cne 'luma-wsl-release-policy-v1') {
            throw 'Release policy has an unsupported purpose or environment.'
        }
        $sequence = Get-LumaTrustInteger $policy.sequence 9007199254740991 'Policy sequence'
        Assert-LumaTrustHash $policy.previous_policy_sha256
        if ($sequence -lt $minimum -or $policy.previous_policy_sha256 -cne $ExpectedPreviousPolicySha256 -or
            ($sequence -eq 1 -and $policy.previous_policy_sha256 -cne ('0' * 64)) -or
            ($sequence -gt 1 -and $policy.previous_policy_sha256 -ceq ('0' * 64))) {
            throw 'Policy sequence floor or exact predecessor binding refused.'
        }
        $start = Get-LumaTrustInteger $policy.not_before_ms 4102444800000 'Policy start'
        $end = Get-LumaTrustInteger $policy.expires_ms 4102444800000 'Policy expiry'
        if ($start -lt $authorityStart -or $end -gt $authorityEnd -or $end -le $start -or
            $end - $start -gt 604800000) { throw 'Policy finite lifetime is outside authority bounds or exceeds seven days.' }
        foreach ($field in @('package_anchor_sha256', 'verifier_sha256')) { Assert-LumaTrustHash $policy.$field }
        $clock = Get-LumaTrustPublicKey $policy.clock_public_key_spki_hex
        if ($policy.clock_public_key_spki_hex -ceq $authority.public_key_spki_hex) {
            throw 'Clock attestation and release-policy signing keys must be independent.'
        }
        foreach ($field in @('revoked_anchor_sha256s', 'revoked_manifest_sha256s', 'revoked_rootfs_sha256s')) {
            Assert-LumaTrustRevocations $policy.$field
        }
        Assert-LumaTrustRecord $policy.authorized_release @('release_id', 'manifest_sha256', 'rootfs_sha256') 'Authorized release'
        Assert-LumaTrustHash $policy.authorized_release.manifest_sha256
        Assert-LumaTrustHash $policy.authorized_release.rootfs_sha256
        if ($policy.authorized_release.release_id -isnot [string] -or
            $policy.authorized_release.release_id -cnotmatch '\Aluma-wsl-dev-[A-Za-z0-9][A-Za-z0-9.-]{0,63}\z') {
            throw 'Authorized release identity is invalid.'
        }
        $time = Invoke-LumaTrustPackageHelper 'ConvertFrom-LumaPackageJson' @($encoding.GetString($captures[3]))
        Assert-LumaTrustRecord $time @('schema_version', 'environment', 'purpose', 'policy_sha256', 'manifest_sha256',
            'challenge_nonce', 'policy_sequence', 'lower_ms', 'upper_ms') 'Time attestation'
        if ((Get-LumaTrustInteger $time.schema_version 1 'Time schema') -ne 1 -or
            $time.environment -isnot [string] -or $time.environment -cne 'lab' -or
            $time.purpose -isnot [string] -or $time.purpose -cne 'luma-wsl-clock-interval-v1' -or
            $time.policy_sha256 -isnot [string] -or $time.policy_sha256 -cne $policyHash -or
            $time.manifest_sha256 -isnot [string] -or $time.manifest_sha256 -cne $policy.authorized_release.manifest_sha256 -or
            $time.challenge_nonce -isnot [string] -or $time.challenge_nonce -cne $ChallengeNonce -or
            (Get-LumaTrustInteger $time.policy_sequence 9007199254740991 'Time policy sequence') -ne $sequence) {
            throw 'Clock attestation purpose, nonce or exact release/policy binding refused.'
        }
        $lower = Get-LumaTrustInteger $time.lower_ms 4102444800000 'Clock lower bound'
        $upper = Get-LumaTrustInteger $time.upper_ms 4102444800000 'Clock upper bound'
        if ($lower -lt $start -or $upper -ge $end -or $upper -lt $lower -or $upper - $lower -gt 60000) {
            throw 'Entire clock interval must be inside the policy half-open lifetime with at most 60-second uncertainty.'
        }
        $packageArguments = @{}
        foreach ($name in @('PackageDirectory', 'SignaturePath', 'AnchorPath', 'AnchorSha256', 'OpenSslPath', 'OpenSslSha256', 'WorkRoot')) {
            $packageArguments[$name] = $PSBoundParameters[$name]
        }
        $package = Test-LumaWslPackageSignature @packageArguments
        if ($package.anchor_input_sha256 -cne $policy.package_anchor_sha256 -or
            $package.verifier_sha256 -cne $policy.verifier_sha256 -or
            $package.release_id -cne $policy.authorized_release.release_id -or
            $package.manifest_sha256 -cne $policy.authorized_release.manifest_sha256 -or
            $package.rootfs_sha256 -cne $policy.authorized_release.rootfs_sha256 -or
            $lower -lt $package.anchor_not_before_ms -or $upper -ge $package.anchor_expires_ms) {
            throw 'Signed policy does not authorize this exact package, verifier, anchor and entire clock interval.'
        }
        if ($policy.revoked_anchor_sha256s -ccontains $package.anchor_input_sha256 -or
            $policy.revoked_manifest_sha256s -ccontains $package.manifest_sha256 -or
            $policy.revoked_rootfs_sha256s -ccontains $package.rootfs_sha256) { throw 'Exact package or signing anchor is revoked.' }
        if ($authority.public_key_spki_hex -ceq $policy.clock_public_key_spki_hex -or
            [Luma.Windows.PackageInspector]::Sha256($public) -ceq $package.public_key_spki_sha256 -or
            [Luma.Windows.PackageInspector]::Sha256($clock) -ceq $package.public_key_spki_sha256) {
            throw 'Release, policy and clock signing keys must be mutually independent.'
        }
        $scratch = $workLease.CreateScratch()
        $directory = $scratch.DirectoryPath
        [IO.File]::WriteAllBytes((Join-Path $directory 'empty.cnf'), [byte[]]@())
        foreach ($verification in @(
            @{ Public=$public; Signature=$captures[2]; Input=$captures[1]; Purpose='luma-wsl-release-policy-v1' },
            @{ Public=$clock; Signature=$captures[4]; Input=$captures[3]; Purpose='luma-wsl-clock-interval-v1' })) {
            [IO.File]::WriteAllBytes((Join-Path $directory 'anchor.der'), $verification.Public)
            [IO.File]::WriteAllBytes((Join-Path $directory 'signature.bin'), $verification.Signature)
            $preimage = [Text.Encoding]::ASCII.GetBytes($verification.Purpose + "`nlab`namd64`nW`n") + $verification.Input
            [IO.File]::WriteAllBytes((Join-Path $directory 'input.bin'), $preimage)
            $null = [Luma.Windows.PackageSignature]::Run($OpenSslPath, $directory, $false)
        }
        foreach ($inputLease in $trustInputs) { $inputLease.Check() }
        [pscustomobject]@{
            schema_version=1; status='signed-lab-policy-valid-at-attested-interval-not-installation-authority'
            environment='lab'; release_id=$package.release_id; manifest_sha256=$package.manifest_sha256
            rootfs_sha256=$package.rootfs_sha256; package_anchor_sha256=$package.anchor_input_sha256
            authority_sha256=$AuthoritySha256; policy_sha256=$policyHash; policy_sequence=$sequence
            previous_policy_sha256=$policy.previous_policy_sha256; minimum_sequence=$minimum
            time_attestation_sha256=[Luma.Windows.PackageInspector]::Sha256($captures[3])
            challenge_nonce=$ChallengeNonce; attested_lower_ms=$lower; attested_upper_ms=$upper
            verifier_sha256=$package.verifier_sha256; verifier_version_observed=$package.verifier_version_observed
            package_signature_valid=$true; policy_signature_valid=$true; time_signature_valid=$true
            exact_release_policy_match=$true; revoked_by_signed_policy=$false; valid_at_attested_interval=$true
            supplied_sequence_floor_satisfied=$true; exact_predecessor_match=$true
            independent_input_pins_match=$true; anchor_custody_authenticated=$false
            verifier_dependencies_authenticated=$false; protected_utc_established=$false
            attestation_freshness_established=$false; durable_rollback_protection_established=$false
            current_revocation_state_established=$false; anchor_currently_valid=$false
            product_installation_admitted=$false; distribution_imported=$false; host_settings_changed=$false
            production_qualified=$false; gate_closing=$false
        }
    } finally {
        try { if ($null -ne $scratch) { $scratch.RemoveScratch() } } finally {
            if ($null -ne $scratch) { $scratch.Dispose() }
            for ($index = $streams.Count - 1; $index -ge 0; $index--) { $streams[$index].Dispose() }
            for ($index = $directories.Count - 1; $index -ge 0; $index--) { $directories[$index].Dispose() }
        }
    }
}

Export-ModuleMember -Function Test-LumaWslLabReleasePolicy
