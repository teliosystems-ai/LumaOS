# Read-only preflight for this host-specific builder. Never repair a volume.
$ErrorActionPreference = 'Stop'
$buildVolume = Get-Volume -DriveLetter D
if ($buildVolume.HealthStatus -ne 'Healthy' -or
    @($buildVolume.OperationalStatus).Count -ne 1 -or
    $buildVolume.OperationalStatus -ne 'OK') {
    throw "D: is not ready for builds: $($buildVolume.HealthStatus), $($buildVolume.OperationalStatus). No storage mutation permitted."
}
if ($buildVolume.FileSystem -ne 'NTFS') {
    throw 'This builder requires healthy NTFS storage with sparse-file and ACL support. Do not reformat existing storage automatically.'
}
$buildDisk = Get-Item -LiteralPath 'D:\LumaOS-builds\docker\build-store.ext4'
if ($buildDisk.PSIsContainer -or
    ($buildDisk.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
    -not ($buildDisk.Attributes -band [System.IO.FileAttributes]::SparseFile)) {
    throw 'The build backing file must be a regular NTFS sparse file.'
}
if ($buildVolume.SizeRemaining -lt 80GB) {
    throw 'D: has less than the required 80 GiB physical build headroom.'
}
Write-Output 'D: filesystem, sparse-file and physical-capacity checks passed.'
