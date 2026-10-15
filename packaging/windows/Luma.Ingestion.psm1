Set-StrictMode -Version Latest

function Initialize-LumaIngestionRuntime {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $CompilerWorkRoot)
    if ($env:OS -cne 'Windows_NT') { throw 'Scoped Windows ingestion requires native Windows.' }
    if ('Luma.Windows.ScopedIngestion' -as [type]) { return }
    if ($CompilerWorkRoot -notmatch '\A[A-Za-z]:\\' -or $CompilerWorkRoot.Contains('/') -or
        $CompilerWorkRoot -match '(^|\\)\.{1,2}(\\|$)' -or $CompilerWorkRoot.Substring(2).Contains(':')) {
        throw 'Compiler scratch requires an explicit existing local path.'
    }
    $directory = Get-Item -LiteralPath $CompilerWorkRoot -Force -ErrorAction Stop
    if ($directory -isnot [IO.DirectoryInfo]) { throw 'Compiler scratch is not a directory.' }
    $ancestor = $directory
    while ($null -ne $ancestor) {
        if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Compiler scratch cannot traverse reparse points.' }
        $ancestor = $ancestor.Parent
    }
    $drive = New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($directory.FullName))
    if ($drive.DriveType -notin @([IO.DriveType]::Fixed, [IO.DriveType]::Removable)) { throw 'Compiler scratch requires a local drive.' }
    $previousTemp = $env:TEMP; $previousTmp = $env:TMP
    try {
        $env:TEMP = $directory.FullName; $env:TMP = $directory.FullName
        Add-Type -Path (Join-Path $PSScriptRoot 'Ingestion.cs') -ErrorAction Stop
    } finally { $env:TEMP = $previousTemp; $env:TMP = $previousTmp }
}

function ConvertFrom-LumaIngestionJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Text)
    $encoding = New-Object Text.UTF8Encoding ($false, $true)
    if ($Text.Length -eq 0 -or $encoding.GetByteCount($Text) -gt 8192) { throw 'Enrollment JSON exceeds its fixed 8192-byte bound.' }
    $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $depth = 0; $records = 0
    foreach ($token in [regex]::Matches($Text, '"(?<raw>(?:[^"\\]|\\.)*)"|(?<delimiter>[\{\}\[\]])')) {
        if ($token.Groups['delimiter'].Success) {
            if ($token.Value -ceq '{') { $depth++; $records++ }
            elseif ($token.Value -ceq '}') { $depth-- }
            else { throw 'Enrollment must be one flat record without arrays.' }
            if ($depth -lt 0 -or $depth -gt 1 -or $records -gt 1) { throw 'Enrollment nesting is forbidden.' }
        } elseif ($Text.Substring($token.Index + $token.Length).TrimStart().StartsWith(':')) {
            $key = $token.Groups['raw'].Value
            if ($depth -ne 1 -or $key.Contains('\') -or -not $keys.Add($key)) { throw 'Duplicate, escaped or misplaced enrollment fields are forbidden.' }
        }
    }
    if ($depth -ne 0 -or $records -ne 1) { throw 'Enrollment requires one complete flat JSON record.' }
    return ConvertFrom-Json -InputObject $Text -ErrorAction Stop
}

function ConvertTo-LumaIngestionEnrollment {
    param([Parameter(Mandatory)] $Enrollment)
    if ($Enrollment -isnot [pscustomobject] -and $Enrollment -isnot [Collections.IDictionary]) { throw 'Enrollment must be a record.' }
    $fields = @('schema_version', 'enrollment_id', 'windows_sid', 'root', 'relative_path', 'max_bytes', 'expected_sha256')
    $keys = if ($Enrollment -is [Collections.IDictionary]) { @($Enrollment.Keys) } else { @($Enrollment.PSObject.Properties.Name) }
    if ($keys.Count -ne $fields.Count) { throw 'Enrollment has omitted or unsupported fields.' }
    foreach ($field in $fields) {
        if (@($keys | Where-Object { $_ -ceq $field }).Count -ne 1) { throw 'Enrollment field spelling must be exact.' }
    }
    foreach ($field in @('enrollment_id', 'windows_sid', 'root', 'relative_path', 'expected_sha256')) {
        if ($Enrollment.$field -isnot [string]) { throw "Enrollment $field must be a string." }
    }
    foreach ($field in @('schema_version', 'max_bytes')) {
        if ($null -eq $Enrollment.$field -or $Enrollment.$field.GetType() -notin @([byte], [sbyte], [int16], [uint16], [int32], [uint32], [int64], [uint64])) {
            throw "Enrollment $field must be an integer, not a string, boolean or float."
        }
    }
    if ($Enrollment.schema_version -ne 1 -or $Enrollment.max_bytes -lt 1 -or $Enrollment.max_bytes -gt 1048576) { throw 'Enrollment schema or byte limit is unsupported.' }
    $value = New-Object Luma.Windows.IngestionEnrollment
    $value.EnrollmentId = $Enrollment.enrollment_id; $value.WindowsSid = $Enrollment.windows_sid
    $value.Root = $Enrollment.root; $value.RelativePath = $Enrollment.relative_path
    $value.MaximumBytes = [int]$Enrollment.max_bytes; $value.ExpectedSha256 = $Enrollment.expected_sha256
    $null = [Luma.Windows.ScopedIngestion]::Review($value)
    return $value
}

function Get-LumaIngestionReview {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Enrollment)
    $value = ConvertTo-LumaIngestionEnrollment $Enrollment
    $review = [Luma.Windows.ScopedIngestion]::Review($value)
    return [pscustomobject][ordered]@{
        schema_version = 1; enrollment_id = $value.EnrollmentId; windows_sid = $value.WindowsSid
        root = $value.Root; relative_path = $value.RelativePath; max_bytes = $value.MaximumBytes
        expected_sha256 = $value.ExpectedSha256; review_sha256 = $review
        confirmation = ('read-exact-file:' + $review)
        source_accessed = $false; input_authenticated = $false; grant_issued = $false
        authenticated_linux_bridge = $false; production_qualified = $false; gate_closing = $false
    }
}

function Read-LumaEnrolledFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Enrollment, [Parameter(Mandatory)][string] $Confirmation)
    $value = ConvertTo-LumaIngestionEnrollment $Enrollment
    $result = [Luma.Windows.ScopedIngestion]::Inspect($value, $Confirmation)
    return [pscustomobject][ordered]@{
        schema_version = 1; enrollment_id = $result.EnrollmentId; windows_sid = $result.WindowsSid
        review_sha256 = $result.ReviewSha256; root = $result.Root; relative_path = $result.RelativePath
        sha256 = $result.Sha256; bytes = $result.Bytes; volume_serial = $result.VolumeSerial
        file_id = $result.FileId; content_hex = $result.ContentHex; read_only = $result.ReadOnly
        input_authenticated = $result.InputAuthenticated; product_grants = $result.ProductGrants
        authenticated_linux_bridge = $result.AuthenticatedLinuxBridge; confidentiality_established = $result.ConfidentialityEstablished
        production_qualified = $result.ProductionQualified; gate_closing = $result.GateClosing
        partial_delivery_possible = $result.PartialDeliveryPossible
        hard_deadline_enforced = $result.HardDeadlineEnforced; observation_window_ms = 5000
        open_no_recall_requested = $result.OpenNoRecallRequested; cloud_provider_qualified = $result.CloudProviderQualified
    }
}

function Read-LumaIngestionEnrollmentInput {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $LiteralPath)
    $bytes = [Luma.Windows.ScopedIngestion]::CaptureEnrollmentFile($LiteralPath)
    $encoding = New-Object Text.UTF8Encoding ($false, $true)
    return ConvertFrom-LumaIngestionJson ($encoding.GetString($bytes))
}

Export-ModuleMember -Function Initialize-LumaIngestionRuntime, ConvertFrom-LumaIngestionJson, Get-LumaIngestionReview, Read-LumaEnrolledFile, Read-LumaIngestionEnrollmentInput
