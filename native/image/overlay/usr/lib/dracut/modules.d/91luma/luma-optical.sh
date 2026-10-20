#!/bin/sh
# Runs only from the firmware-authenticated optical UKI's embedded initrd.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
. /lib/dracut-lib.sh
[ "$(getarg luma.media=)" = optical ] && [ "$(getarg luma.mode=)" = live ] &&
    [ "$(getarg luma.slot=)" = live ] || exit 1
hash=$(getarg roothash=)
case "$hash" in *[!0-9a-f]*|'') exit 1 ;; esac
[ "${#hash}" = 64 ] || exit 1
selected=
count=0
for node in /sys/class/block/sr*; do
    [ -e "$node" ] || continue
    name=${node##*/}
    case "$name" in sr[0-9]|sr[0-9][0-9]) ;; *) exit 1 ;; esac
    count=$((count+1))
    [ "$count" -le 16 ] || exit 1
    [ "$(cat "$node/device/type")" = 5 ] && [ "$(cat "$node/ro")" = 1 ] || exit 1
    [ -b "/dev/$name" ] || exit 1
    # No label-only lookup and no silent choice between multiple inserted CDs.
    [ -z "$selected" ] || exit 1
    selected=/dev/$name
done
[ -n "$selected" ] || exit 1
base=/run/initramfs/luma-optical
[ ! -e "$base" ] && [ ! -L "$base" ] || exit 1
mkdir -m 0700 "$base"
mount -t iso9660 -o ro,nodev,nosuid,noexec,norock,nojoliet "$selected" "$base"
[ "$(findmnt -n -o FSTYPE --target "$base")" = iso9660 ] || exit 1
case ",$(findmnt -n -o OPTIONS --target "$base")," in *,ro,*) ;; *) exit 1 ;; esac
for name in root.ext4 root.verity; do
    [ -f "$base/$name" ] && [ ! -L "$base/$name" ] &&
        [ "$(stat -c %h "$base/$name")" = 1 ] || exit 1
done
root_bytes=$(stat -c %s "$base/root.ext4")
hash_bytes=$(stat -c %s "$base/root.verity")
case "$root_bytes" in 4294967296|6442450944) ;; *) exit 1 ;; esac
case "$hash_bytes" in *[!0-9]*|'') exit 1 ;; esac
[ "$hash_bytes" -ge 4096 ] && [ "$hash_bytes" -le 67108864 ] &&
    [ $((hash_bytes%4096)) = 0 ] || exit 1
# The signed root hash, not this unauthenticated CD's label or directory, is
# root authority. The normal verity setup consumes these read-only loop objects.
root_loop=$(losetup --find --show --read-only --sector-size 512 --sizelimit "$root_bytes" "$base/root.ext4")
hash_loop=$(losetup --find --show --read-only --sector-size 512 --sizelimit "$hash_bytes" "$base/root.verity")
for node in "$root_loop" "$hash_loop"; do
    case "$node" in /dev/loop[0-9]*) ;; *) exit 1 ;; esac
    [ "$(blockdev --getro "$node")" = 1 ] || exit 1
    udevadm trigger --action=change "$node"
done
udevadm settle --timeout=10
[ "$(readlink -f /dev/luma-optical-root)" = "$root_loop" ] &&
    [ "$(readlink -f /dev/luma-optical-hash)" = "$hash_loop" ] || exit 1
