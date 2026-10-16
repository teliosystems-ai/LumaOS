Set-StrictMode -Version Latest

if (-not ('Luma.Windows.PlatformSignature' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'PlatformSignature.cs') -ErrorAction Stop
}

function Assert-LumaPlatformHash {
    param($Value)
    if ($Value -isnot [string] -or $Value -cnotmatch '\A[0-9a-f]{64}\z') {
        throw 'Independent input pins require exact canonical lowercase SHA256.'
    }
}

function Read-LumaPlatformRecord {
    param([byte[]] $Bytes, [string[]] $Fields)
    $text = (New-Object Text.UTF8Encoding ($false, $true)).GetString($Bytes)
    $containers = New-Object 'System.Collections.Generic.Stack[string]'
    $objects = New-Object 'System.Collections.Generic.Stack[System.Collections.Generic.HashSet[string]]'
    foreach ($token in [regex]::Matches($text, '"(?<raw>(?:[^"\\]|\\.)*)"|(?<open>[\{\[])|(?<close>[\}\]])')) {
        if ($token.Groups['open'].Success) {
            if ($containers.Count -ge 4) { throw 'Platform record nesting exceeds its fixed bound.' }
            $containers.Push($token.Value)
            if ($token.Value -ceq '{') {
                $objects.Push((New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)))
            }
        } elseif ($token.Groups['close'].Success) {
            if ($containers.Count -eq 0) { throw 'Platform record has invalid nesting.' }
            $expected = if ($token.Value -ceq '}') { '{' } else { '[' }
            if ($containers.Pop() -cne $expected) { throw 'Platform record has invalid nesting.' }
            if ($token.Value -ceq '}') { $null = $objects.Pop() }
        } elseif ($text.Substring($token.Index + $token.Length).TrimStart().StartsWith(':')) {
            $key = $token.Groups['raw'].Value
            if ($containers.Count -eq 0 -or $containers.Peek() -cne '{' -or $key.Contains('\') -or
                -not $objects.Peek().Add($key)) { throw 'Platform record has duplicate, escaped or misplaced fields.' }
        }
    }
    if ($containers.Count -ne 0) { throw 'Platform record is unterminated.' }
    $value = ConvertFrom-Json -InputObject $text -ErrorAction Stop
    if ($null -eq $value -or $value -isnot [pscustomobject]) { throw 'Platform input must be a closed object.' }
    $keys = @($value.PSObject.Properties.Name)
    if ($keys.Count -ne $Fields.Count) { throw 'Platform record has missing or unsupported fields.' }
    foreach ($field in $Fields) {
        if (@($keys | Where-Object { $_ -ceq $field }).Count -ne 1) { throw 'Platform field spelling is not canonical.' }
    }
    return $value
}

function Assert-LumaPlatformIdentity {
    param($Record, [string] $Purpose)
    if ($null -eq $Record.schema_version -or $Record.schema_version.GetType() -notin @([int], [long]) -or
        $Record.schema_version -ne 2 -or $Record.environment -isnot [string] -or $Record.environment -cne 'lab' -or
        $Record.purpose -isnot [string] -or $Record.purpose -cne $Purpose -or
        $Record.algorithm -isnot [string] -or $Record.algorithm -cne 'ecdsa-p256-sha256-p1363' -or
        $Record.architecture -isnot [string] -or $Record.architecture -cne 'amd64' -or
        $Record.profile -isnot [string] -or $Record.profile -cne 'W') {
        throw 'Unsupported platform schema, lab purpose, algorithm, architecture or profile.'
    }
}

function Test-LumaWindowsPlatformStatement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $PublicKeyPath,
        [Parameter(Mandatory)][string] $PublicKeySha256,
        [Parameter(Mandatory)][string] $StatementPath,
        [Parameter(Mandatory)][string] $StatementSha256,
        [Parameter(Mandatory)][string] $PayloadPath,
        [Parameter(Mandatory)][string] $PayloadSha256,
        [Parameter(Mandatory)][string] $SignaturePath,
        [Parameter(Mandatory)][string] $ExpectedNonce,
        [Parameter(Mandatory)][string] $ExpectedSequence
    )
    if ($env:OS -cne 'Windows_NT') { throw 'Platform statement verification requires native Windows.' }
    foreach ($pin in @($PublicKeySha256, $StatementSha256, $PayloadSha256, $ExpectedNonce)) { Assert-LumaPlatformHash $pin }
    if ($ExpectedNonce -ceq ('0' * 64) -or $ExpectedSequence -cnotmatch '\A[1-9][0-9]{0,15}\z' -or
        [long]::Parse($ExpectedSequence, [Globalization.CultureInfo]::InvariantCulture) -gt 9007199254740991L) {
        throw 'Independent selection requires a nonzero nonce and canonical positive sequence text.'
    }
    $leases = New-Object 'System.Collections.Generic.List[Luma.Windows.PlatformInputLease]'
    try {
        foreach ($path in @($PublicKeyPath, $StatementPath, $PayloadPath, $SignaturePath)) {
            $leases.Add([Luma.Windows.PlatformInputLease]::Acquire($path))
        }
        [byte[]] $keyBytes = $leases[0].Capture(1, 4096)
        [byte[]] $statementBytes = $leases[1].Capture(1, 4096)
        [byte[]] $payloadBytes = $leases[2].Capture(1, 65536)
        [byte[]] $signature = $leases[3].Capture(64, 64)
        if ([Luma.Windows.PlatformSignature]::Hash($keyBytes) -cne $PublicKeySha256 -or
            [Luma.Windows.PlatformSignature]::Hash($statementBytes) -cne $StatementSha256 -or
            [Luma.Windows.PlatformSignature]::Hash($payloadBytes) -cne $PayloadSha256) {
            throw 'Independently selected platform input pin mismatch.'
        }
        $key = Read-LumaPlatformRecord $keyBytes @('schema_version', 'environment', 'purpose', 'algorithm',
            'architecture', 'profile', 'key_format', 'public_key_blob_hex')
        Assert-LumaPlatformIdentity $key 'luma-windows-platform-public-key-v2'
        if ($key.key_format -isnot [string] -or $key.key_format -cne 'cng-eccpublicblob-p256' -or
            $key.public_key_blob_hex -isnot [string] -or $key.public_key_blob_hex -cnotmatch '\A4543533120000000[0-9a-f]{128}\z') {
            throw 'Platform key must use exact canonical P256 CNG ECCPUBLICBLOB encoding.'
        }
        $canonicalKey = '{"schema_version":2,"environment":"lab","purpose":"luma-windows-platform-public-key-v2","algorithm":"ecdsa-p256-sha256-p1363","architecture":"amd64","profile":"W","key_format":"cng-eccpublicblob-p256","public_key_blob_hex":"' + $key.public_key_blob_hex + '"}'
        if ([Luma.Windows.PlatformSignature]::Hash([Text.Encoding]::UTF8.GetBytes($canonicalKey)) -cne $PublicKeySha256) {
            throw 'Platform public-key record bytes are not the exact canonical serialization.'
        }
        $statement = Read-LumaPlatformRecord $statementBytes @('schema_version', 'environment', 'purpose', 'algorithm',
            'architecture', 'profile', 'public_key_sha256', 'payload_sha256', 'nonce', 'sequence')
        Assert-LumaPlatformIdentity $statement 'luma-windows-platform-statement-v2'
        foreach ($field in @('public_key_sha256', 'payload_sha256', 'nonce')) { Assert-LumaPlatformHash $statement.$field }
        if ($statement.sequence -isnot [string] -or $statement.sequence -cne $ExpectedSequence -or
            $statement.nonce -cne $ExpectedNonce -or $statement.public_key_sha256 -cne $PublicKeySha256 -or
            $statement.payload_sha256 -cne $PayloadSha256) {
            throw 'Platform statement does not bind exact selected key, payload, nonce and sequence.'
        }
        $canonicalStatement = '{"schema_version":2,"environment":"lab","purpose":"luma-windows-platform-statement-v2","algorithm":"ecdsa-p256-sha256-p1363","architecture":"amd64","profile":"W","public_key_sha256":"' + $PublicKeySha256 + '","payload_sha256":"' + $PayloadSha256 + '","nonce":"' + $ExpectedNonce + '","sequence":"' + $ExpectedSequence + '"}'
        if ([Luma.Windows.PlatformSignature]::Hash([Text.Encoding]::UTF8.GetBytes($canonicalStatement)) -cne $StatementSha256) {
            throw 'Platform statement bytes are not the exact canonical serialization.'
        }
        [byte[]] $publicBlob = [Luma.Windows.PlatformSignature]::Hex($key.public_key_blob_hex, 72)
        if (-not [Luma.Windows.PlatformSignature]::Verify($publicBlob,
                [Luma.Windows.PlatformSignature]::SigningInput($statementBytes), $signature)) {
            throw 'Platform ECDSA P256 SHA256 P1363 signature is invalid.'
        }
        foreach ($lease in $leases) { $lease.Check() }
        [pscustomobject]@{
            schema_version=2; status='in-process-lab-platform-signature-valid-not-authority'
            purpose='luma-windows-platform-statement-v2'; environment='lab'; architecture='amd64'; profile='W'
            algorithm='ecdsa-p256-sha256-p1363'; key_format='cng-eccpublicblob-p256'
            public_key_sha256=$PublicKeySha256; statement_sha256=$StatementSha256; payload_sha256=$PayloadSha256
            signature_sha256=[Luma.Windows.PlatformSignature]::Hash($signature)
            nonce=$ExpectedNonce; sequence=$ExpectedSequence; cryptographic_signature_valid=$true
            independent_input_pins_match=$true; exact_selected_binding=$true
            crypto_provider='Microsoft Primitive Provider'; external_crypto_process_used=$false
            persistent_key_created=$false; physical_tpm_used=$false; key_custody_authenticated=$false
            host_os_dependencies_qualified=$false; protected_utc_established=$false
            attestation_freshness_established=$false; current_revocation_state_established=$false
            durable_rollback_protection_established=$false; product_installation_admitted=$false
            distribution_imported=$false; host_settings_changed=$false; hard_deadline_enforced=$false
            cloud_provider_qualified=$false; production_qualified=$false; gate_closing=$false
        }
    } finally {
        for ($index=$leases.Count-1; $index -ge 0; $index--) { $leases[$index].Dispose() }
    }
}

Export-ModuleMember -Function Test-LumaWindowsPlatformStatement
