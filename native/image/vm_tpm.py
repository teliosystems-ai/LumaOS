#!/usr/bin/env python3
"""Persistent, locked software TPM fixture for disposable container-only VMs.

Not an external production TPM transport. Never exports private state.
"""
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time


def private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise RuntimeError('software TPM state needs a private owned Linux directory')


def state_directory(run: Path):
    # External NTFS/DrvFS can hold large virtual disks but may not enforce Unix
    # private modes. A dedicated Linux volume can hold the small TPM state.
    root = os.environ.get('LUMA_VM_TPM_ROOT')
    if root is None:
        return run/'tpm'
    root = Path(root)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise RuntimeError('LUMA_VM_TPM_ROOT must be an existing absolute Linux directory')
    info = root.stat()
    if os.name == 'posix' and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
        raise RuntimeError('LUMA_VM_TPM_ROOT must be owned and not writable by other users')
    identity = hashlib.sha256(str(run.resolve()).encode()).hexdigest()
    return root/identity


def validate_state(directory):
    for index, entry in enumerate(directory.iterdir()):
        if index >= 16:
            raise RuntimeError('unexpected software TPM state inventory')
        info = entry.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
            raise RuntimeError(f'unsafe software TPM state member {entry.name}: mode={stat.S_IMODE(info.st_mode):04o}, links={info.st_nlink}')


class SoftwareTPM:
    def __init__(self, directory: Path):
        import fcntl
        self.process = self.lock = self.sockets = None
        if not Path('/.dockerenv').is_file() or Path('/dev/tpm0').exists() or Path('/dev/tpmrm0').exists():
            raise RuntimeError('VM TPM requires a disposable container without host TPM devices')
        # Caller selects its existing run directory. Refuse symlinks/public
        # state rather than following, chmodding or replacing unknown content.
        directory.mkdir(mode=0o700, exist_ok=True)
        private_directory(directory)
        try:
            fd = os.open(directory/'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            self.lock = os.fdopen(fd, 'rb+')
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                raise RuntimeError('unsafe software TPM lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            state = directory/'state'
            state.mkdir(mode=0o700, exist_ok=True)
            private_directory(state)
            validate_state(state)
            self.sockets = tempfile.TemporaryDirectory(prefix='luma-vm-tpm-', dir='/tmp')
            self.control = Path(self.sockets.name)/'control.sock'
            # QEMU initializes and starts the TPM through its emulator backend.
            # Do not clear/startup-clear persistent NV on each harness stage.
            self.process = subprocess.Popen(['swtpm', 'socket', '--tpm2',
                '--tpmstate', f'dir={state},mode=0600', '--ctrl', f'type=unixio,path={self.control}',
                '--flags', 'not-need-init'], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, umask=0o077)
            deadline = time.monotonic() + 10
            while not self.control.exists():
                if self.process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('VM software TPM startup failed')
                time.sleep(.02)
        except BaseException:
            self.close()
            raise

    def qemu_arguments(self):
        return ['-chardev', f'socket,id=luma-tpm,path={self.control}',
                '-tpmdev', 'emulator,id=luma-tpm,chardev=luma-tpm',
                '-device', 'tpm-tis,tpmdev=luma-tpm']

    def close(self):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process = None
        if self.sockets is not None:
            self.sockets.cleanup()
            self.sockets = None
        if self.lock is not None:
            self.lock.close()
            self.lock = None
