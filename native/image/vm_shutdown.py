"""Image shutdown assertions shared by disposable-VM acceptance fixtures."""
import re


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
