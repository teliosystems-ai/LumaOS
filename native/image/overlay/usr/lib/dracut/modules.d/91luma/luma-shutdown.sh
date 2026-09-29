#!/bin/sh
. /lib/luma-shutdown-check.sh
luma_shutdown_storage_check /proc/mounts /sys/block || return 1
echo LUMA_SHUTDOWN_STORAGE_CLEAN
