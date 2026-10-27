#!/bin/bash
check() { return 0; }
depends() { echo 'systemd dm rootfs-block'; }
install() {
    inst_multiple /usr/libexec/luma-os/luma-platform /usr/sbin/cryptsetup \
        /usr/bin/mount /usr/bin/lsblk /usr/bin/cp /usr/bin/udevadm
    inst_hook pre-pivot 90 "$moddir/luma-data.sh"
    inst_simple "$moddir/luma-shutdown-check.sh" /lib/luma-shutdown-check.sh
    inst_multiple /usr/sbin/losetup /usr/sbin/blockdev /usr/bin/findmnt /usr/bin/stat /usr/bin/readlink /usr/bin/cat
    inst_simple "$moddir/luma-optical.sh" /lib/luma-optical.sh
    inst_simple "$moddir/luma-optical.service" /usr/lib/systemd/system/luma-optical.service
    # One root-overlay rule: the real root re-runs systemd-veritysetup@root
    # after switch-root and must name the same loops. inst_multiple resolves -r.
    inst_multiple /etc/udev/rules.d/99-luma-optical.rules || return 1
    mkdir -p "$initdir/usr/lib/systemd/system/systemd-veritysetup@root.service.requires"
    ln_r /usr/lib/systemd/system/luma-optical.service \
        /usr/lib/systemd/system/systemd-veritysetup@root.service.requires/luma-optical.service
    inst_hook shutdown 90 "$moddir/luma-shutdown.sh"
}
