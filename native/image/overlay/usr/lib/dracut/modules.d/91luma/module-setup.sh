#!/bin/bash
check() { return 0; }
depends() { echo 'systemd dm rootfs-block'; }
install() {
    inst_multiple /usr/libexec/luma-os/luma-platform /usr/sbin/cryptsetup \
        /usr/bin/mount /usr/bin/lsblk /usr/bin/cp /usr/bin/udevadm
    inst_hook pre-pivot 90 "$moddir/luma-data.sh"
    inst_simple "$moddir/luma-shutdown-check.sh" /lib/luma-shutdown-check.sh
    inst_hook shutdown 90 "$moddir/luma-shutdown.sh"
}
