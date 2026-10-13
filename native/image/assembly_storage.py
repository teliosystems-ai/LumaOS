"""Admit large image work only on a writable Linux ext4 filesystem."""
import ctypes
import os
from pathlib import Path
import stat


def require_ext4(path):
    path = Path(path)
    if os.name != 'posix' or not stat.S_ISDIR(path.lstat().st_mode):
        raise ValueError('image artifact work requires a real Linux directory')
    buffer = ctypes.create_string_buffer(256)
    library = ctypes.CDLL(None, use_errno=True)
    if library.statfs(os.fsencode(path), buffer) != 0:
        raise OSError(ctypes.get_errno(), 'artifact filesystem inspection failed')
    if ctypes.c_long.from_buffer(buffer).value != 0xef53:
        raise ValueError('large image work must be ext4-backed, never DrvFS/NTFS or overlay')
    if os.statvfs(path).f_flag & os.ST_RDONLY:
        raise ValueError('image artifact work filesystem is read-only')


def export_headroom(source, destination, names):
    import shutil
    source, destination = Path(source), Path(destination)
    if not destination.is_dir() or destination.is_symlink() or any(destination.iterdir()):
        raise ValueError('artifact export requires an exact fresh empty directory')
    total = 1024**3
    for name in names:
        if not name or Path(name).name != name or name in ('.', '..'):
            raise ValueError('export artifact name escapes its namespace')
        info = (source/name).lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('export source must be a regular file, not a link')
        total += info.st_size
    if shutil.disk_usage(destination).free < total:
        raise ValueError('artifact destination lacks exact compressed-media export headroom')
    return total
