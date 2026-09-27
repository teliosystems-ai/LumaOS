#!/bin/sh
. /lib/dracut-lib.sh
mode=$(getarg luma.mode=)
case "$mode" in
    live) /usr/libexec/luma-os/luma-platform init-data live || die "Luma live data initialization failed" ;;
    installed) /usr/libexec/luma-os/luma-platform init-data installed || die "Luma encrypted data unlock failed" ;;
    *) die "Missing Luma boot mode" ;;
esac
