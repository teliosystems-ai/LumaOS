[CmdletBinding()]
param([switch] $Apply)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# One-time retirement of the explicitly reviewed superseded Windows work set.
# Keep logs/manifests/source archives at their original evidence paths.
$retirementRoot = 'D:\LumaOS-builds\work'
$retirementNames = @(
    '20260928T124255Z-headless', '20260929T170514Z-headless',
    '20260929T175214Z-headless', '20260929T194815Z-headless',
    '20260929T195529Z-headless', '20260929T221048Z-headless',
    '20260930T073705Z-headless', '20261001T072028Z-desktop',
    '20261001T090338Z-desktop', '20261010T210838Z-desktop',
    '20261011T062224Z-desktop', '20261012T174442Z-desktop',
    '20261012T180018Z-desktop'
)

function Assert-RetirementPath([string] $Path, [string] $ExpectedRoot) {
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not $resolved.StartsWith($ExpectedRoot.TrimEnd('\')+'\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Retirement target escapes the explicitly named work root.'
    }
    $entry = Get-Item -LiteralPath $resolved -Force
    while ($null -ne $entry) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Retirement refuses redirected files and ancestors.'
        }
        $entry = if ($entry -is [IO.DirectoryInfo]) { $entry.Parent } else { $entry.Directory }
    }
    return $resolved
}

$rootInfo = Get-Item -LiteralPath $retirementRoot -Force
if ($rootInfo -isnot [IO.DirectoryInfo] -or $rootInfo.FullName -cne $retirementRoot) {
    throw 'Expected exact existing assembly work directory.'
}
$candidates = New-Object 'System.Collections.Generic.List[object]'
$retainedFiles = 0
foreach ($name in $retirementNames) {
    $target = Join-Path $retirementRoot $name
    if (-not (Test-Path -LiteralPath $target)) { continue }
    $target = Assert-RetirementPath $target $retirementRoot
    $stack = New-Object 'System.Collections.Generic.Stack[System.IO.DirectoryInfo]'
    $stack.Push((Get-Item -LiteralPath $target -Force))
    while ($stack.Count -gt 0) {
        $directory = $stack.Pop()
        $null = Assert-RetirementPath $directory.FullName $retirementRoot
        foreach ($entry in $directory.EnumerateFileSystemInfos()) {
            $path = Assert-RetirementPath $entry.FullName $target
            if ($entry -is [IO.DirectoryInfo]) {
                $stack.Push($entry)
                continue
            }
            $bulk = $entry.Name -cin @('root.ext4', 'payload.ext4', 'root.verity',
                'slot-a.efi', 'slot-b.efi', 'slot-live.efi', 'esp.fat', 'unsigned.fat', 'target.qcow2')
            $image = $entry.Name -cmatch '\Aluma-native-lab-20260927-(?:headless|desktop)-(?:[4-9]|1[0-3])\.img(?:\.zst)?\z'
            if ($bulk -or $image) {
                $candidates.Add([pscustomobject]@{Path=$path;Bytes=$entry.Length;WriteTicks=$entry.LastWriteTimeUtc.Ticks})
            } else { $retainedFiles++ }
        }
    }
}
if ($candidates.Count -gt 512) { throw 'Unexpected retirement inventory size.' }
$leases = New-Object 'System.Collections.Generic.List[System.IO.FileStream]'
try {
    # Refuse before any deletion if an active user holds one of these disks.
    foreach ($candidate in $candidates) {
        $lease = [IO.File]::Open($candidate.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        $leases.Add($lease)
        if ($lease.Length -ne $candidate.Bytes) { throw 'Assembly disk changed during retirement planning.' }
    }
} finally {
    foreach ($lease in $leases) { $lease.Dispose() }
}
$removed = New-Object 'System.Collections.Generic.List[object]'
$candidateBytes = [long]0
foreach ($candidate in $candidates) { $candidateBytes += $candidate.Bytes }
$removedBytes = [long]0
if ($Apply) {
    foreach ($candidate in $candidates) {
        $path = Assert-RetirementPath $candidate.Path $retirementRoot
        $current = Get-Item -LiteralPath $path -Force
        if ($current -isnot [IO.FileInfo] -or $current.Length -ne $candidate.Bytes -or
            $current.LastWriteTimeUtc.Ticks -ne $candidate.WriteTicks) {
            throw 'Assembly disk changed before deletion; remaining files retained.'
        }
        Remove-Item -LiteralPath $path -Force
        $removed.Add($candidate)
        $removedBytes += $candidate.Bytes
    }
}
[pscustomobject]@{
    schema_version=1;mode=$(if ($Apply) {'applied'} else {'read-only-plan'})
    root=$retirementRoot;reviewed_folders=$retirementNames
    candidate_files=$candidates.Count;candidate_bytes=$candidateBytes
    deleted_files=$removed.Count;deleted_bytes=$removedBytes
    retained_evidence_files=$retainedFiles;original_evidence_paths_preserved=$true
    final_sequence_14_touched=$false;native_exports_touched=$false;backing_stores_touched=$false
    recoverability='Deleted intermediates require rebuilding; surviving compressed deliveries remain separate.'
    files=$candidates
} | ConvertTo-Json -Depth 5
