"""Offline image policy: retain QEMU, prohibit automatic KVM/KSM preparation."""
import os
from pathlib import Path
import stat

PROFILE = 'luma-qemu-no-autostart-no-ksm-v1'
CONFIG = b'# Luma: no ungoverned global memory sharing or QEMU boot preparation.\nKSM_ENABLED=0\nSLEEP_MILLISECS=200\n'
PACKAGED_CONFIG = b'''# Set to 1 to enable KSM, 0 to disable KSM, and AUTO to use default settings.
# After changing this setting restart the qemu-kvm service.
KSM_ENABLED=AUTO
SLEEP_MILLISECS=200

# Dropped VHOST_NET_ENABLED as this is auto-loaded in recent kernels

# Dropped KVM_HUGEPAGES as systemd provides feasible hugepage moutpoints
'''
VENDOR_UNIT = b'''[Unit]
Description=QEMU KVM preparation - module, ksm, hugepages
DefaultDependencies=no
After=local-fs.target
Before=shutdown.target
Conflicts=shutdown.target
RequiresMountsFor=/usr

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/share/qemu/init/qemu-kvm-init start
ExecReload=/usr/share/qemu/init/qemu-kvm-init start

[Install]
WantedBy=multi-user.target
'''
CONFIG_PATH = 'etc/default/qemu-kvm'
MASK_PATH = 'etc/systemd/system/qemu-kvm.service'
WANTED_PATH = 'etc/systemd/system/multi-user.target.wants/qemu-kvm.service'
VENDOR_PATH = 'usr/lib/systemd/system/qemu-kvm.service'
BINARY_PATH = 'usr/bin/qemu-system-x86_64'
STAGING_PATH = 'etc/default/.qemu-kvm.luma-prepared'
VENDOR_TARGET = '/usr/lib/systemd/system/qemu-kvm.service'


def image_root(root):
    root = Path(root)
    if not root.is_absolute() or root == Path('/') or root.resolve(strict=True) != root:
        raise ValueError('QEMU policy requires a separate canonical image root, never the host root')
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError('QEMU image root is not root protected')
    return root


def path(root, relative):
    selected = root
    for part in Path(relative).parts[:-1]:
        selected /= part
        try:
            metadata = selected.lstat()
        except FileNotFoundError:
            return root/relative
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('QEMU policy parent is an alias or is not root protected')
    return root/relative


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
            metadata.st_mode, metadata.st_nlink, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def regular(root, relative, maximum, mode, *, optional=False, prefix=False):
    selected = path(root, relative)
    try:
        descriptor = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        if optional:
            return None
        raise
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != mode or not 0 < before.st_size <= maximum:
            raise ValueError('unsafe QEMU image member metadata or size')
        data = os.read(descriptor, 64 if prefix else maximum+1)
        if (not prefix and len(data) != before.st_size) or identity(before) != identity(os.fstat(descriptor)) or identity(before) != identity(selected.lstat()):
            raise ValueError('QEMU image member changed during inspection')
        return data
    finally:
        os.close(descriptor)


def link(root, relative, expected):
    selected = path(root, relative)
    try:
        metadata = selected.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1 or os.readlink(selected) != expected:
        raise ValueError('unexpected QEMU policy unit or symlink; preserve it')
    return True


def preflight(root):
    root = image_root(root)
    if regular(root, VENDOR_PATH, 8192, 0o644) != VENDOR_UNIT:
        raise ValueError('QEMU vendor unit differs from the closed packaged unit')
    binary = regular(root, BINARY_PATH, 512*1024*1024, 0o755, prefix=True)
    if len(binary) != 64 or binary[:7] != b'\x7fELF\x02\x01\x01' or int.from_bytes(binary[16:18], 'little') not in (2, 3) or int.from_bytes(binary[18:20], 'little') != 62:
        raise ValueError('QEMU executable must remain a protected x86-64 ELF')
    configuration = regular(root, CONFIG_PATH, 4096, 0o644, optional=True)
    if configuration not in (None, CONFIG, PACKAGED_CONFIG):
        raise ValueError('unexpected existing QEMU defaults; no silent policy overwrite')
    masked = link(root, MASK_PATH, '/dev/null')
    wanted = link(root, WANTED_PATH, VENDOR_TARGET)
    try:
        path(root, STAGING_PATH).lstat()
    except FileNotFoundError:
        pass
    else:
        raise ValueError('retained QEMU policy staging must not be overwritten')
    return root, configuration, masked, wanted


def validate(root):
    root, configuration, masked, wanted = preflight(root)
    if configuration != CONFIG or not masked or wanted:
        raise ValueError('image QEMU autostart/KSM policy is not the exact closed disabled state')
    return dict(schema_version=1, profile=PROFILE, qemu_binary_retained=True,
                vendor_unit_retained=True, autostart_disabled=True, ksm_default_disabled=True,
                service_executed=False, kernel_ksm_state_observed=False,
                kvm_or_native_boot_qualified=False)


def sync_directory(directory):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def configure(root):
    root, configuration, masked, wanted = preflight(root)
    # Validate every existing target before the first mutation. Only these
    # build-owned image members change; no helper, service or sysfs is invoked.
    if configuration != CONFIG:
        temporary = path(root, STAGING_PATH)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(CONFIG)
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            os.fsync(output.fileno())
        if regular(root, STAGING_PATH, 4096, 0o644) != CONFIG:
            raise ValueError('QEMU policy stage changed; retain it')
        os.replace(temporary, path(root, CONFIG_PATH))
        sync_directory((root/CONFIG_PATH).parent)
    if wanted:
        if not link(root, WANTED_PATH, VENDOR_TARGET):
            raise ValueError('packaged QEMU wanted link changed before removal')
        (root/WANTED_PATH).unlink()
        sync_directory((root/WANTED_PATH).parent)
    if not masked:
        os.symlink('/dev/null', path(root, MASK_PATH))
        sync_directory((root/MASK_PATH).parent)
    return validate(root)
