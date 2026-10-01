"""Image shutdown assertions shared by disposable-VM acceptance fixtures."""
import re


def verify_secure_boot(vm):
    vm.run('test "$(od -An -tu1 -j4 /sys/firmware/efi/efivars/'
           'SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c | tr -d \' \\n\')" = 1')


def finish_stage(vm, *, require_clean=False, secure_boot=False):
    if secure_boot:
        verify_secure_boot(vm)
    poweroff(vm, require_clean)


def poweroff(vm, require_clean=False):
    if require_clean:
        vm.run('systemctl is-active dracut-shutdown.service && '
               'test -f /run/initramfs/.need_shutdown && '
               'test "$(readlink /boot/initrd.img-$(uname -r))" = luma-initrd')
    vm.run('sync')
    # A previous marker (including one printed by a guest command) must not
    # satisfy this power-off. Inspect only the newly received shutdown bytes.
    serial = vm.work/'serial.log'
    offset = serial.stat().st_size
    vm.send('systemctl poweroff')
    if vm.wait_exit() != 0:
        raise RuntimeError('guest poweroff failed')
    if require_clean:
        with serial.open('rb') as stream:
            stream.seek(offset)
            output = stream.read()
        if not re.search(rb'(?:^|\r?\n)LUMA_SHUTDOWN_STORAGE_CLEAN\r?\n', output):
            raise RuntimeError('shutdown lacked verified filesystem and DM teardown')
