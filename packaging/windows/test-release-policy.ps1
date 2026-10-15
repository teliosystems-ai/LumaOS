[CmdletBinding()]
param(
    [string] $WorkRoot = 'D:\LumaOS-builds',
    [string] $SecurityWorkRoot = 'C:\Users\hakim\LumaOS\.luma',
    [string] $OpenSslPath = 'C:\Program Files\Git\usr\bin\openssl.exe'
)
$ErrorActionPreference = 'Stop'
$script:Assertions = 0
function Assert-Trust($Condition, [string] $Message) {
    $script:Assertions++
    if (-not $Condition) { throw $Message }
}
function Assert-TrustThrows([scriptblock] $Action, [string] $Message) {
    $threw = $false
    try { $null = & $Action } catch {
        $leaf = $_.Exception.GetBaseException()
        if ($_.FullyQualifiedErrorId -match 'PropertyNotFound|MethodNotFound|TypeNotFound|CommandNotFound|UnexpectedToken' -or
            $leaf -is [NullReferenceException] -or $leaf -is [IndexOutOfRangeException] -or
            $leaf -is [InvalidCastException] -or $leaf -is [OutOfMemoryException]) { throw "Implementation error masked as refusal: $_" }
        $threw = $true
    }
    Assert-Trust $threw $Message
}
foreach ($path in @($WorkRoot, $SecurityWorkRoot)) {
    if ($path -notmatch '^[A-Za-z]:\\' -or $path.Contains('/') -or $path -match '(^|\\)\.{1,2}(\\|$)') {
        throw 'Fixture roots require explicit local canonical paths.'
    }
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item -isnot [IO.DirectoryInfo]) { throw 'Fixture root must be an existing directory.' }
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Fixture root cannot traverse reparse points.' }
        $item = $item.Parent
    }
}
$temporary = Join-Path $WorkRoot ('luma-trust-fixture-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temporary -ErrorAction Stop
$originalTemp = $env:TEMP; $originalTmp = $env:TMP
$securityFixture = $null
try {
    $env:TEMP = $temporary; $env:TMP = $temporary
    Import-Module (Join-Path $PSScriptRoot 'Luma.Trust.psm1') -Force
    function Bytes([string] $Text) { return ,([Text.Encoding]::UTF8.GetBytes($Text)) }
    function Hash([string] $Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
    function Write-Json([string] $Path, $Value) {
        [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 12 -Compress), (New-Object Text.UTF8Encoding ($false)))
    }
    function Invoke-Crypto([string[]] $Arguments) {
        $output = & $OpenSslPath @Arguments 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Actual fixture OpenSSL operation failed: $output" }
    }
    function New-Key([string] $Name) {
        $key = Join-Path $temporary ($Name + '.pem')
        $public = Join-Path $temporary ($Name + '.der')
        Invoke-Crypto @('genpkey', '-algorithm', 'ED25519', '-out', $key)
        Invoke-Crypto @('pkey', '-in', $key, '-pubout', '-outform', 'DER', '-out', $public)
        [pscustomobject]@{ Private=$key; Public=([BitConverter]::ToString([IO.File]::ReadAllBytes($public))).Replace('-', '').ToLowerInvariant() }
    }
    function Sign([string] $Path, [string] $Signature, [string] $Purpose, [string] $Private) {
        $inputPath = Join-Path $temporary 'signing-input.bin'
        [IO.File]::WriteAllBytes($inputPath, ((Bytes ($Purpose + "`nlab`namd64`nW`n")) + [IO.File]::ReadAllBytes($Path)))
        Invoke-Crypto @('pkeyutl', '-sign', '-inkey', $Private, '-rawin', '-in', $inputPath, '-out', $Signature)
    }
    function Put-Field([byte[]] $Header, [int] $Offset, [string] $Text) {
        $encoded = [Text.Encoding]::ASCII.GetBytes($Text)
        [Array]::Copy($encoded, 0, $Header, $Offset, $encoded.Length)
    }
    function New-Entry([string] $Path, [byte[]] $Content, [string] $Type='0', [int] $Mode=420) {
        [pscustomobject]@{ Path=$Path; Content=$Content; Type=$Type; Mode=$Mode }
    }
    $elf = New-Object byte[] 64
    $elf[0]=127; $elf[1]=69; $elf[2]=76; $elf[3]=70; $elf[4]=2; $elf[5]=1; $elf[6]=1
    $elf[16]=3; $elf[18]=62; $elf[20]=1; $elf[52]=64; $elf[56]=1
    $identity='{"schema_version":1,"release_id":"luma-wsl-dev-trust-fixture","architecture":"amd64","profile":"W"}'
    $entries = @((New-Entry 'etc/' @() '5' 493), (New-Entry 'usr/' @() '5' 493),
        (New-Entry 'usr/bin/' @() '5' 493), (New-Entry 'usr/lib/' @() '5' 493),
        (New-Entry 'usr/lib/luma/' @() '5' 493),
        (New-Entry 'etc/os-release' (Bytes "ID=ubuntu`nVERSION_ID=`"24.04`"`n")),
        (New-Entry 'etc/wsl.conf' (Bytes "[boot]`nsystemd=true`n[automount]`nenabled=false`n[interop]`nenabled=false`nappendWindowsPath=false`n")),
        (New-Entry 'usr/lib/luma/platform.json' (Bytes $identity)),
        (New-Entry 'usr/bin/luma-platform' $elf '0' 493))
    $memory = New-Object IO.MemoryStream
    try {
        foreach ($entry in $entries) {
            $header = New-Object byte[] 512
            Put-Field $header 0 $entry.Path; Put-Field $header 100 ([Convert]::ToString($entry.Mode,8).PadLeft(7,'0'))
            Put-Field $header 108 '0000000'; Put-Field $header 116 '0000000'
            Put-Field $header 124 ([Convert]::ToString($entry.Content.Length,8).PadLeft(11,'0'))
            Put-Field $header 136 '00000000000'; $header[156]=[byte][char]$entry.Type
            Put-Field $header 257 'ustar'; Put-Field $header 263 '00'
            for ($index=148; $index -lt 156; $index++) { $header[$index]=32 }
            $sum=0; foreach ($value in $header) { $sum += [int]$value }
            Put-Field $header 148 ([Convert]::ToString($sum,8).PadLeft(6,'0') + [char]0 + ' ')
            $memory.Write($header,0,512); $memory.Write($entry.Content,0,$entry.Content.Length)
            $padding=New-Object byte[] ((512-$entry.Content.Length%512)%512); $memory.Write($padding,0,$padding.Length)
        }
        $memory.Write((New-Object byte[] 1024),0,1024)
        $archive=$memory.ToArray()
    } finally { $memory.Dispose() }
    $packageDirectory=Join-Path $temporary 'package'; $null=New-Item -ItemType Directory -Path $packageDirectory
    $archivePath=Join-Path $packageDirectory 'rootfs.tar'; [IO.File]::WriteAllBytes($archivePath,$archive)
    $files=@(); [long]$contentBytes=0
    foreach ($entry in $entries) {
        $contentBytes += $entry.Content.Length
        if ($entry.Type -ceq '0') {
            $files += [pscustomobject]@{ path=$entry.Path; bytes=$entry.Content.Length
                sha256=[Luma.Windows.PackageInspector]::Sha256($entry.Content); executable=(($entry.Mode -band 73) -ne 0) }
        }
    }
    $manifestPath=Join-Path $packageDirectory 'manifest.json'
    $manifest=[ordered]@{ schema_version=1; package_type='luma-wsl-rootfs-ustar-v1'; release_id='luma-wsl-dev-trust-fixture'
        architecture='amd64'; profile='W'; rootfs=[ordered]@{ path='rootfs.tar'; bytes=$archive.Length
            sha256=(Hash $archivePath); member_count=$entries.Count; content_bytes=$contentBytes }; required_files=$files }
    Write-Json $manifestPath $manifest
    $releaseKey=New-Key 'release'; $policyKey=New-Key 'policy'; $clockKey=New-Key 'clock'; $foreignKey=New-Key 'foreign'
    $anchorPath=Join-Path $temporary 'release-anchor.json'; $authorityPath=Join-Path $temporary 'authority.json'
    $anchor=[ordered]@{ schema_version=1; environment='lab'; purpose='luma-wsl-package-v1'; public_key_spki_hex=$releaseKey.Public
        not_before_ms=1700000000000L; expires_ms=1700086400000L }
    Write-Json $anchorPath $anchor
    $authority=[ordered]@{ schema_version=1; environment='lab'; purpose='luma-wsl-trust-policy-v1'; public_key_spki_hex=$policyKey.Public
        not_before_ms=1700000000000L; expires_ms=1700086400000L }
    Write-Json $authorityPath $authority
    $signaturePath=Join-Path $temporary 'release.sig'; Sign $manifestPath $signaturePath 'luma-wsl-package-v1' $releaseKey.Private
    $policyPath=Join-Path $temporary 'policy.json'; $policySignaturePath=Join-Path $temporary 'policy.sig'
    $timePath=Join-Path $temporary 'clock.json'; $timeSignaturePath=Join-Path $temporary 'clock.sig'
    $nonce='12'*32
    $policy=[ordered]@{ schema_version=1; environment='lab'; purpose='luma-wsl-release-policy-v1'; sequence=1
        previous_policy_sha256=('0'*64); not_before_ms=1700000010000L; expires_ms=1700001010000L
        package_anchor_sha256=(Hash $anchorPath); verifier_sha256=(Hash $OpenSslPath); clock_public_key_spki_hex=$clockKey.Public
        authorized_release=[ordered]@{ release_id=$manifest.release_id; manifest_sha256=(Hash $manifestPath); rootfs_sha256=(Hash $archivePath) }
        revoked_anchor_sha256s=@(); revoked_manifest_sha256s=@(); revoked_rootfs_sha256s=@() }
    $time=[ordered]@{ schema_version=1; environment='lab'; purpose='luma-wsl-clock-interval-v1'; policy_sha256=('0'*64)
        manifest_sha256=(Hash $manifestPath); challenge_nonce=$nonce; policy_sequence=1; lower_ms=1700000020000L; upper_ms=1700000021000L }
    function Write-PolicyAndTime {
        Write-Json $policyPath $policy
        $time.policy_sha256=Hash $policyPath
        Write-Json $timePath $time
        Sign $policyPath $policySignaturePath 'luma-wsl-release-policy-v1' $policyKey.Private
        Sign $timePath $timeSignaturePath 'luma-wsl-clock-interval-v1' $clockKey.Private
    }
    Write-PolicyAndTime
    $arguments=@{ PackageDirectory=$packageDirectory; SignaturePath=$signaturePath; AnchorPath=$anchorPath; AnchorSha256=(Hash $anchorPath)
        OpenSslPath=$OpenSslPath; OpenSslSha256=(Hash $OpenSslPath); WorkRoot=$SecurityWorkRoot
        AuthorityPath=$authorityPath; AuthoritySha256=(Hash $authorityPath); PolicyPath=$policyPath; PolicySignaturePath=$policySignaturePath
        TimeAttestationPath=$timePath; TimeSignaturePath=$timeSignaturePath; ChallengeNonce=$nonce; MinimumSequence=1L
        ExpectedPreviousPolicySha256=('0'*64) }
    $result=Test-LumaWslLabReleasePolicy @arguments
    $probePath=Join-Path $temporary 'lease-probe.json'
    [IO.File]::WriteAllBytes($probePath,(Bytes '{"probe":true}'))
    $probe=[Luma.Windows.TrustInputLease]::Acquire($probePath)
    try {
        Assert-Trust (([Text.Encoding]::UTF8.GetString($probe.Capture(65536,$false))) -ceq '{"probe":true}') 'Actual handle capture changed exact bytes.'
        Assert-TrustThrows { [IO.File]::Open($probePath,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read) } 'Held trust input allowed a concurrent writer.'
        Assert-TrustThrows { $probe.Capture(65536,$true) } 'Non-64-byte detached signature admitted by exact handle capture.'
        Assert-TrustThrows { $probe.Capture(4,$false) } 'Held input size exceeded caller bound.'
        Assert-TrustThrows { [IO.File]::SetLastWriteTimeUtc($probePath,([datetime]'2020-01-01T00:00:00Z')) } 'Held input allowed a conflicting metadata writer.'
        $probe.Check()
    } finally { $probe.Dispose() }
    foreach ($alias in @($probePath.Replace('\','/'), (Join-Path $temporary 'sub\..\lease-probe.json'), ($probePath+':stream'))) {
        Assert-TrustThrows { [Luma.Windows.TrustInputLease]::Acquire($alias) } 'Noncanonical/traversal/ADS trust path admitted.'
    }
    $securityFixture=Join-Path $SecurityWorkRoot ('luma-trust-input-fixture-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $securityFixture
    $linkedPath=Join-Path $securityFixture 'source.json'; $aliasPath=Join-Path $securityFixture 'alias.json'
    [IO.File]::WriteAllBytes($linkedPath,(Bytes '{"probe":true}'))
    $null=New-Item -ItemType HardLink -Path $aliasPath -Target $linkedPath
    Assert-TrustThrows { [Luma.Windows.TrustInputLease]::Acquire($linkedPath) } 'Multiply linked NTFS trust input admitted.'
    [IO.File]::Delete($aliasPath)
    $unlinked=[Luma.Windows.TrustInputLease]::Acquire($linkedPath)
    try { Assert-Trust ($unlinked.Capture(65536,$false).Length -eq 14) 'Exact single-link file failed after removal of owned alias.' }
    finally { $unlinked.Dispose() }
    $savedAttributes=[IO.File]::GetAttributes($linkedPath)
    try {
        [IO.File]::SetAttributes($linkedPath,($savedAttributes -bor [IO.FileAttributes]::Offline))
        Assert-TrustThrows { [Luma.Windows.TrustInputLease]::Acquire($linkedPath) } 'Observed offline trust file was not refused before capture.'
    } finally { [IO.File]::SetAttributes($linkedPath,$savedAttributes) }
    Assert-Trust ($result.package_signature_valid -and $result.policy_signature_valid -and $result.time_signature_valid -and
        $result.valid_at_attested_interval -and $result.exact_release_policy_match) 'Genuine independently signed exact lab policy was refused.'
    Assert-Trust ($result.policy_sha256 -ceq (Hash $policyPath) -and $result.time_attestation_sha256 -ceq (Hash $timePath) -and
        $result.attested_lower_ms -eq 1700000020000L -and $result.attested_upper_ms -eq 1700000021000L) 'Exact evidence bindings or signed historical interval were lost.'
    foreach ($flag in @('anchor_custody_authenticated','verifier_dependencies_authenticated','protected_utc_established',
        'attestation_freshness_established','durable_rollback_protection_established','current_revocation_state_established',
        'anchor_currently_valid','product_installation_admitted','distribution_imported','host_settings_changed','production_qualified','gate_closing')) {
        Assert-Trust (-not $result.$flag) "Lab evidence invented authority: $flag."
    }
    $basePolicy=$policy | ConvertTo-Json -Depth 12 -Compress
    $baseTime=$time | ConvertTo-Json -Depth 12 -Compress
    foreach ($change in @('policy-sig-bit','clock-sig-bit','policy-domain','clock-domain','foreign-policy-key','foreign-clock-key',
        'policy-whitespace','clock-whitespace','signature-truncated','policy-as-clock-signature')) {
        switch ($change) {
            policy-sig-bit { $bytes=[IO.File]::ReadAllBytes($policySignaturePath); $bytes[0]=$bytes[0] -bxor 1; [IO.File]::WriteAllBytes($policySignaturePath,$bytes) }
            clock-sig-bit { $bytes=[IO.File]::ReadAllBytes($timeSignaturePath); $bytes[0]=$bytes[0] -bxor 1; [IO.File]::WriteAllBytes($timeSignaturePath,$bytes) }
            policy-domain { Sign $policyPath $policySignaturePath 'luma-wsl-package-v1' $policyKey.Private }
            clock-domain { Sign $timePath $timeSignaturePath 'luma-wsl-release-policy-v1' $clockKey.Private }
            foreign-policy-key { Sign $policyPath $policySignaturePath 'luma-wsl-release-policy-v1' $foreignKey.Private }
            foreign-clock-key { Sign $timePath $timeSignaturePath 'luma-wsl-clock-interval-v1' $foreignKey.Private }
            policy-whitespace { [IO.File]::AppendAllText($policyPath,"`n",(New-Object Text.UTF8Encoding ($false))) }
            clock-whitespace { [IO.File]::AppendAllText($timePath,"`n",(New-Object Text.UTF8Encoding ($false))) }
            signature-truncated { [IO.File]::WriteAllBytes($policySignaturePath,[byte[]]@(1,2)) }
            policy-as-clock-signature { [IO.File]::WriteAllBytes($timeSignaturePath,[IO.File]::ReadAllBytes($policySignaturePath)) }
        }
        Assert-TrustThrows { Test-LumaWslLabReleasePolicy @arguments } "Cryptographic policy/clock substitution admitted: $change."
        Write-PolicyAndTime
    }
    foreach ($change in @('revoked-anchor','revoked-manifest','revoked-rootfs','unsorted-revocations','duplicate-revocations','revocation-type',
        'revocation-count','policy-production','policy-purpose','unknown-field','policy-schema-bool','sequence-float','sequence-rollback',
        'genesis-predecessor','anchor-substitution','verifier-substitution','release-substitution','manifest-substitution','rootfs-substitution',
        'shared-policy-clock-key','shared-release-clock-key','clock-zero-key','policy-expiry','policy-lifetime','policy-before-authority',
        'clock-production','clock-purpose','clock-nonce','clock-release','clock-sequence','clock-before-policy','clock-at-expiry',
        'clock-inverted','clock-uncertainty','clock-type')) {
        switch ($change) {
            revoked-anchor { $policy.revoked_anchor_sha256s=@($policy.package_anchor_sha256) }
            revoked-manifest { $policy.revoked_manifest_sha256s=@($policy.authorized_release.manifest_sha256) }
            revoked-rootfs { $policy.revoked_rootfs_sha256s=@($policy.authorized_release.rootfs_sha256) }
            unsorted-revocations { $policy.revoked_manifest_sha256s=@(('f'*64),('1'*64)) }
            duplicate-revocations { $policy.revoked_manifest_sha256s=@(('1'*64),('1'*64)) }
            revocation-type { $policy.revoked_manifest_sha256s='1'*64 }
            revocation-count { $policy.revoked_manifest_sha256s=@(1..65 | ForEach-Object { $_.ToString('x64') }) }
            policy-production { $policy.environment='production' }
            policy-purpose { $policy.purpose='luma-wsl-package-v1' }
            unknown-field { $policy | Add-Member -NotePropertyName trusted -NotePropertyValue $true }
            policy-schema-bool { $policy.schema_version=$true }
            sequence-float { $policy.sequence=1.25 }
            sequence-rollback { $policy.sequence=0; $time.policy_sequence=0 }
            genesis-predecessor { $policy.previous_policy_sha256='1'*64 }
            anchor-substitution { $policy.package_anchor_sha256='1'*64 }
            verifier-substitution { $policy.verifier_sha256='1'*64 }
            release-substitution { $policy.authorized_release.release_id='luma-wsl-dev-other' }
            manifest-substitution { $policy.authorized_release.manifest_sha256='1'*64; $time.manifest_sha256='1'*64 }
            rootfs-substitution { $policy.authorized_release.rootfs_sha256='1'*64 }
            shared-policy-clock-key { $policy.clock_public_key_spki_hex=$policyKey.Public }
            shared-release-clock-key { $policy.clock_public_key_spki_hex=$releaseKey.Public }
            clock-zero-key { $policy.clock_public_key_spki_hex=$clockKey.Public.Substring(0,24)+('0'*64) }
            policy-expiry { $policy.expires_ms=$policy.not_before_ms }
            policy-lifetime { $policy.expires_ms=$policy.not_before_ms+604800001L }
            policy-before-authority { $policy.not_before_ms=1699999999999L }
            clock-production { $time.environment='production' }
            clock-purpose { $time.purpose='luma-wsl-package-v1' }
            clock-nonce { $time.challenge_nonce='34'*32 }
            clock-release { $time.manifest_sha256='1'*64 }
            clock-sequence { $time.policy_sequence=2 }
            clock-before-policy { $time.lower_ms=$policy.not_before_ms-1 }
            clock-at-expiry { $time.upper_ms=$policy.expires_ms }
            clock-inverted { $time.upper_ms=$time.lower_ms-1 }
            clock-uncertainty { $time.upper_ms=$time.lower_ms+60001 }
            clock-type { $time.lower_ms='1700000020000' }
        }
        Write-PolicyAndTime
        Assert-TrustThrows { Test-LumaWslLabReleasePolicy @arguments } "Signed but invalid policy/interval admitted: $change."
        $policy=$basePolicy | ConvertFrom-Json; $time=$baseTime | ConvertFrom-Json
        Write-PolicyAndTime
    }
    foreach ($change in @('production','authority-pin','zero-nonce','nonce','floor','floor-type','predecessor')) {
        $bad=$arguments.Clone()
        switch ($change) {
            production { $bad.Environment='production' }
            authority-pin { $bad.AuthoritySha256='0'*64 }
            zero-nonce { $bad.ChallengeNonce='0'*64 }
            nonce { $bad.ChallengeNonce='34'*32 }
            floor { $bad.MinimumSequence=2L }
            floor-type { $bad.MinimumSequence='1' }
            predecessor { $bad.ExpectedPreviousPolicySha256='1'*64 }
        }
        Assert-TrustThrows { Test-LumaWslLabReleasePolicy @bad } "Invalid independent admission constraint accepted: $change."
    }
    foreach ($kind in @('policy','clock','authority')) {
        $bad=$arguments.Clone()
        switch ($kind) {
            policy {
                [IO.File]::WriteAllText($policyPath,($basePolicy.TrimEnd('}')+',"purpose":"luma-wsl-release-policy-v1"}'),(New-Object Text.UTF8Encoding ($false)))
                $time.policy_sha256=Hash $policyPath; Write-Json $timePath $time
                Sign $policyPath $policySignaturePath 'luma-wsl-release-policy-v1' $policyKey.Private
                Sign $timePath $timeSignaturePath 'luma-wsl-clock-interval-v1' $clockKey.Private
            }
            clock {
                [IO.File]::WriteAllText($timePath,($baseTime.TrimEnd('}')+',"purpose":"luma-wsl-clock-interval-v1"}'),(New-Object Text.UTF8Encoding ($false)))
                Sign $timePath $timeSignaturePath 'luma-wsl-clock-interval-v1' $clockKey.Private
            }
            authority {
                $json=$authority | ConvertTo-Json -Compress
                [IO.File]::WriteAllText($authorityPath,($json.TrimEnd('}')+',"purpose":"luma-wsl-trust-policy-v1"}'),(New-Object Text.UTF8Encoding ($false)))
                $bad.AuthoritySha256=Hash $authorityPath
            }
        }
        Assert-TrustThrows { Test-LumaWslLabReleasePolicy @bad } "Duplicate signed/pinned $kind fields were silently collapsed."
        Write-Json $authorityPath $authority
        $time=$baseTime | ConvertFrom-Json; Write-PolicyAndTime
    }
    # A genuine next policy must bind both the supplied predecessor and sequence floor.
    $policy.sequence=2; $policy.previous_policy_sha256=Hash $policyPath; $time.policy_sequence=2
    $arguments.MinimumSequence=2L; $arguments.ExpectedPreviousPolicySha256=$policy.previous_policy_sha256
    Write-PolicyAndTime
    $next=Test-LumaWslLabReleasePolicy @arguments
    Assert-Trust ($next.policy_sequence -eq 2 -and $next.exact_predecessor_match -and $next.supplied_sequence_floor_satisfied -and
        -not $next.durable_rollback_protection_established) 'Valid update predecessor/floor was not checked without inventing durable rollback custody.'
    $bad=$arguments.Clone(); $bad.ExpectedPreviousPolicySha256='f'*64
    Assert-TrustThrows { Test-LumaWslLabReleasePolicy @bad } 'Next policy ignored the exact independently supplied predecessor.'
    $command=@('-NoLogo','-NoProfile','-ExecutionPolicy','RemoteSigned','-File',('"'+(Join-Path $PSScriptRoot 'verify-release-policy.ps1')+'"'))
    foreach ($name in $arguments.Keys) { $command += '-'+$name; $command += '"'+[string]$arguments[$name]+'"' }
    $command += '-CompilerWorkRoot'; $command += '"'+$temporary+'"'
    $process=New-Object Diagnostics.Process
    try {
        $process.StartInfo.FileName=Join-Path $PSHOME 'powershell.exe'; $process.StartInfo.Arguments=$command -join ' '
        $process.StartInfo.UseShellExecute=$false; $process.StartInfo.CreateNoWindow=$true
        $process.StartInfo.RedirectStandardOutput=$true; $process.StartInfo.RedirectStandardError=$true
        $null=$process.Start(); $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) { $process.Kill(); $null=$process.WaitForExit(2000); throw 'Actual release-policy CLI fixture timed out.' }
        if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) { throw 'Actual CLI output fixture timed out.' }
        Assert-Trust ($process.ExitCode -eq 0 -and $stderr.Result.Length -eq 0 -and $stdout.Result.Length -lt 65536) `
            ('Actual release-policy CLI failed: '+$stderr.Result)
        $cli=$stdout.Result | ConvertFrom-Json
        Assert-Trust ($cli.policy_signature_valid -and $cli.time_signature_valid -and -not $cli.product_installation_admitted -and
            -not $cli.protected_utc_established) 'Actual CLI changed lab signature authority boundaries.'
    } finally { $process.Dispose() }
    $process=New-Object Diagnostics.Process
    try {
        $process.StartInfo.FileName=Join-Path $PSHOME 'powershell.exe'
        $process.StartInfo.Arguments=($command -join ' ')+' -Environment production'
        $process.StartInfo.UseShellExecute=$false; $process.StartInfo.CreateNoWindow=$true
        $process.StartInfo.RedirectStandardOutput=$true; $process.StartInfo.RedirectStandardError=$true
        $null=$process.Start(); $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) { $process.Kill(); $null=$process.WaitForExit(2000); throw 'Production-refusal CLI fixture timed out.' }
        if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) { throw 'Production-refusal CLI output fixture timed out.' }
        Assert-Trust ($process.ExitCode -eq 1 -and $stdout.Result.Length -eq 0 -and
            ($stderr.Result -replace '\s+',' ').Contains('Production admission requires deployed custody')) `
            'Actual production CLI did not fail closed without admission output.'
    } finally { $process.Dispose() }
    foreach ($noncanonical in @('1.4','1e2','+2',' 2','2 ','02','-2','true','9007199254740992')) {
        $malformed=[string[]]$command.Clone()
        $found=$false
        for ($index=0; $index -lt $malformed.Length-1; $index++) {
            if ($malformed[$index] -ceq '-MinimumSequence') { $malformed[$index+1]='"'+$noncanonical+'"'; $found=$true; break }
        }
        if (-not $found) { throw 'Actual CLI test command is missing its sequence input.' }
        $process=New-Object Diagnostics.Process
        try {
            $process.StartInfo.FileName=Join-Path $PSHOME 'powershell.exe'; $process.StartInfo.Arguments=$malformed -join ' '
            $process.StartInfo.UseShellExecute=$false; $process.StartInfo.CreateNoWindow=$true
            $process.StartInfo.RedirectStandardOutput=$true; $process.StartInfo.RedirectStandardError=$true
            $null=$process.Start(); $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(30000)) { $process.Kill(); $null=$process.WaitForExit(2000); throw 'Sequence-refusal CLI fixture timed out.' }
            if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) { throw 'Sequence-refusal CLI output fixture timed out.' }
            Assert-Trust ($process.ExitCode -eq 1 -and $stdout.Result.Length -eq 0 -and
                ($stderr.Result -replace '\s+',' ').Contains('Minimum sequence requires canonical positive decimal text')) `
                "Actual CLI coerced malformed sequence text: $noncanonical."
        } finally { $process.Dispose() }
    }
    Write-Output "Passed $script:Assertions Windows release-policy assertions; no installation or host mutation."
} finally {
    $env:TEMP=$originalTemp; $env:TMP=$originalTmp
    if ($null -ne $securityFixture) {
        $securityResolved=[IO.Path]::GetFullPath($securityFixture)
        $securityParent=[IO.Path]::GetFullPath($SecurityWorkRoot).TrimEnd('\')+'\'
        if (-not $securityResolved.StartsWith($securityParent,[StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($securityResolved) -notmatch '^luma-trust-input-fixture-[0-9a-f]{32}$') {
            throw 'Refusing cleanup outside the exact owned NTFS fixture.'
        }
        Remove-Item -LiteralPath $securityResolved -Recurse -Force -ErrorAction Stop
    }
    $resolved=[IO.Path]::GetFullPath($temporary)
    $parent=[IO.Path]::GetFullPath($WorkRoot).TrimEnd('\')+'\'
    if (-not $resolved.StartsWith($parent,[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notmatch '^luma-trust-fixture-[0-9a-f]{32}$') {
        throw 'Refusing recursive cleanup outside the exact generated fixture directory.'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop
}
