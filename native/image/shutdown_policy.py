"""Connect the packaged dracut late-shutdown path to the verified image root."""
from pathlib import Path
import re
import subprocess


def link_exact(path, target):
    if path.is_symlink():
        if path.readlink() != Path(target):
            raise ValueError('unexpected existing shutdown link')
    elif path.exists():
        raise ValueError('refusing to replace existing shutdown artifact')
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)


def configure(root, version):
    if not re.fullmatch(r'[0-9][A-Za-z0-9.+_-]{0,95}', version):
        raise ValueError('invalid kernel version')
    for relative in ('boot/luma-initrd',
                     'usr/lib/dracut/dracut-initramfs-restore',
                     'usr/lib/dracut/modules.d/98dracut-systemd/dracut-shutdown.service'):
        path = root/relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError('missing packaged shutdown prerequisite: '+relative)
    # The restore helper checks this conventional name before the ESP fallback.
    # Both the alias and target are in the immutable, verity-protected root.
    link_exact(root/('boot/initrd.img-'+version), 'luma-initrd')
    link_exact(root/'etc/systemd/system/multi-user.target.wants/dracut-shutdown.service',
               '/usr/lib/systemd/system/dracut-shutdown.service')


def verify_initrd(initrd):
    listing = subprocess.check_output(['lsinitrd', str(initrd)], text=True)
    paths = {line.split(' -> ', 1)[0].split()[-1].lstrip('./')
             for line in listing.splitlines() if line.split()}
    # Dracut uses merged-/usr paths for executables and hooks in this toolchain.
    required = {'shutdown', 'usr/bin/umount', 'usr/sbin/dmsetup',
                'usr/lib/dracut/hooks/shutdown/25-dm-shutdown.sh',
                'usr/lib/luma-shutdown-check.sh',
                'usr/lib/dracut/hooks/shutdown/90-luma-shutdown.sh'}
    if not required <= paths:
        raise ValueError('initrd lacks late-shutdown teardown: '+str(sorted(required-paths)))
    return {'required_paths':sorted(required), 'boot_tested':False}
