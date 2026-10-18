"""Build pins for the actual unprivileged HTTPS transport, never UTC authority.

Run inside the assembled Ubuntu root, after copying the fixed frontend. The
exact Python/OpenSSL code/tuple is signed as part of the surrounding image.
"""
import json
from pathlib import Path
import ssl
import sys
import office_policy


def canonical_manifest(root):
    import _ssl
    root = Path(root).resolve(strict=True)
    if root != Path('/'):
        raise ValueError('UTC transport manifest requires actual assembled-root Python runtime')
    paths = [str(Path(sys.executable).resolve()), str(Path(ssl.__file__).resolve()),
             str(Path(_ssl.__file__).resolve()), '/usr/lib/x86_64-linux-gnu/libssl.so.3',
             '/usr/lib/x86_64-linux-gnu/libcrypto.so.3', '/usr/libexec/luma-os/utc-windows-front.py']
    files = []
    for name in paths:
        pin, _ = office_policy.read(root, name.lstrip('/'), 64 * 1024**2)
        files.append(pin)
    value = dict(schema_version=1, profile='windows-protected-utc-https-transport-v1',
                 python_version=list(sys.version_info[:3]), openssl_version=ssl.OPENSSL_VERSION,
                 files=files, native_qualified=False)
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
