#!/bin/bash
# Ubuntu systemd 255 names the helper pcrextend; packaged dracut still tests
# for the old pcrphase name. Use the vendor unit and TPM dependency module.
check() {
    require_binaries "$systemdutildir/systemd-pcrextend" || return 1
    return 255
}
depends() { echo 'systemd tpm2-tss'; }
install() {
    inst_multiple "$systemdutildir/systemd-pcrextend" \
        "$systemdsystemunitdir/systemd-pcrphase-initrd.service"
    mkdir -p "$initdir$systemdsystemunitdir/initrd.target.wants"
    ln -sfn ../systemd-pcrphase-initrd.service \
        "$initdir$systemdsystemunitdir/initrd.target.wants/systemd-pcrphase-initrd.service"
}
