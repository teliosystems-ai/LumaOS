#!/bin/sh
. /lib/dracut-lib.sh
mode=$(getarg luma.mode=)
case "$mode" in
    live) /usr/libexec/luma-os/luma-platform init-data live || die "Luma live data initialization failed" ;;
    installed) /usr/libexec/luma-os/luma-platform init-data installed || die "Luma encrypted data unlock failed" ;;
    *) die "Missing Luma boot mode" ;;
esac
# This path mounts /var outside dracut's crypt/root discovery. Explicitly ask
# the packaged restore service to prepare a late-shutdown initrd for teardown.
mkdir -p /run/initramfs && need_shutdown || die "Luma shutdown preparation failed"
