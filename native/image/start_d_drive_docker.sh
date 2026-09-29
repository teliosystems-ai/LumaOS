#!/bin/bash
# Operator-only, host-specific WSL builder. Never formats or migrates storage.
set -euo pipefail
test "$(id -u)" = 0
umask 077
disk=/mnt/d/LumaOS-builds/docker/build-store.ext4
store=/mnt/luma-docker-build
endpoint=unix:///run/luma-docker-build/docker.sock
configuration=$(dirname -- "$(realpath -- "$0")")/docker-d-drive.json
# Check Windows physical storage before reading/mounting a large DrvFS file.
# Linux virtual capacity alone does not establish host-drive readiness.
windows_probe=$(wslpath -w "$(dirname -- "$configuration")/check_d_drive.ps1")
powershell.exe -NoProfile -NonInteractive -File "$windows_probe"
test -f "$disk" && test ! -L "$disk"
test "$(realpath -- "$disk")" = "$disk"
test "$(blkid -p -s TYPE -o value -- "$disk")" = ext4
test ! -L "$store"
if ! mountpoint -q "$store"; then
    # Refuse to hide any existing directory contents under the mount.
    if [ -d "$store" ]; then test -z "$(ls -A -- "$store")"; fi
    install -d -m 0700 "$store"
    mount -o loop,nodev,nosuid "$disk" "$store"
fi
test "$(findmnt -n -o FSTYPE --target "$store")" = ext4
device=$(findmnt -n -o SOURCE --target "$store")
test "$(losetup --noheadings --raw --output BACK-FILE "$device")" = "$disk"
mount --make-private "$store"
if systemctl is-active --quiet luma-docker-build.service; then
    test "$(docker --host "$endpoint" info --format '{{.DockerRootDir}}')" = "$store/docker"
    echo 'D: builder already active.'
    exit 0
fi
test ! -e /run/luma-docker-build/docker.sock
install -d -m 0700 /run/luma-docker-build "$store/tmp"
install -m 0600 "$configuration" /run/luma-docker-build/daemon.json
dockerd --validate --config-file=/run/luma-docker-build/daemon.json
systemd-run --unit=luma-docker-build --collect \
    --property=Delegate=yes --property=KillMode=mixed --property=TimeoutStopSec=90 \
    --property='ExecStartPre=/usr/bin/mountpoint -q /mnt/luma-docker-build' \
    --property=StandardOutput=append:/mnt/luma-docker-build/daemon.log \
    --property=StandardError=append:/mnt/luma-docker-build/daemon.log \
    --setenv=DOCKER_TMPDIR="$store/tmp" --setenv=TMPDIR="$store/tmp" \
    /usr/bin/dockerd --config-file=/run/luma-docker-build/daemon.json
for attempt in $(seq 1 30); do
    if docker --host "$endpoint" info >/dev/null 2>&1; then
        test "$(docker --host "$endpoint" info --format '{{.DockerRootDir}}')" = "$store/docker"
        echo 'D: builder ready; existing Docker daemon is unchanged.'
        exit 0
    fi
    sleep 1
done
echo 'Builder did not become ready; inspect the private daemon.log.' >&2
exit 1
