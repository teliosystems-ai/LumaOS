"""Actual desktop image WebKit tuple and ELF pin; no runtime qualification."""
import json
from pathlib import Path
import re
import office_policy


def canonical_manifest(root):
    root = Path(root).resolve(strict=True)
    _, data = office_policy.read(root, 'var/lib/dpkg/status', 16*1024*1024)
    matches = []
    for stanza in data.decode('utf-8').split('\n\n'):
        fields = {}
        for line in stanza.splitlines():
            if line and not line.startswith((' ', '\t')):
                key, separator, value = line.partition(': ')
                if not separator or key in fields:
                    raise ValueError('ambiguous browser package metadata')
                fields[key] = value
        if fields.get('Package') == 'libwebkit2gtk-4.1-0':
            matches.append(fields)
    if len(matches) != 1 or matches[0].get('Status') != 'install ok installed' or matches[0].get('Architecture') != 'amd64':
        raise ValueError('actual installed WebKitGTK 4.1 package absent/ambiguous')
    version = matches[0].get('Version', '')
    parsed = re.fullmatch(r'(?:[0-9]+:)?(2)\.([0-9]+)\.([0-9]+)[A-Za-z0-9.+:~_-]*', version)
    if not parsed or len(version) > 128:
        raise ValueError('actual WebKit package/runtime tuple refused')
    relative = Path('usr/lib/x86_64-linux-gnu/libwebkit2gtk-4.1.so.0')
    alias = root / relative
    target = str(alias.readlink())
    if not re.fullmatch(r'libwebkit2gtk-4\.1\.so\.0\.[0-9]+\.[0-9]+', target):
        raise ValueError('browser SONAME alias must resolve to exact same-directory versioned library')
    pin, _ = office_policy.read(root, str(relative.parent / target), 256*1024*1024, elf=True)
    value = dict(schema_version=1, profile='webkitgtk-native-document-presentation-v1', api_version='4.1',
                 package_version=version, runtime_version=[int(item) for item in parsed.groups()], library=pin,
                 max_html_bytes=1024*1024, timeout_seconds=15, native_qualified=False)
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
