"""Fresh-image exclusive ordinary-writer mediation, never host configuration.

Only the pinned supported image policies are transformed. Runtime controllers
must still qualify the actual device, daemon, loaded policy and original Admin.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import xml.etree.ElementTree as ET

PROFILE = 'hardware-mediated-writers-v1'
PPD_VERSION = '0.21-1ubuntu3'
PPD_PACKAGE_SHA256 = 'b86cfc96ee86c9ce95bbca1dc0c8366cc79e4ef66970b7e9550f4d484de1e4e5'
PLATFORM_FILES = {
    'usr/lib/systemd/systemd': 'b472aadf808bef87c0eb203056a77cb64bd268b71b756306013a53de68a94173',
    'usr/bin/dbus-daemon': '8c479f1fcddfd6693c736ce541da0955f6752834bdeeef4b928e27f5e974c247',
    'usr/lib/systemd/system/dbus.service': 'bf7ec47644997441174ef6aac992d34cc46b9d2d7b8dc2feba7074d719fdbef1',
    'usr/lib/systemd/system/dbus.socket': '12b7aaec8d1e007047ec12fc85b1cc6db78565dfb896850cd9148dee0455fe7e',
}
LOGIN = 'org.freedesktop.login1'
POWER = ('net.hadess.PowerProfiles', 'org.freedesktop.UPower.PowerProfiles')
ORIGINALS = {
    'usr/share/dbus-1/system.d/org.freedesktop.login1.conf': '234f59974a978a7747cd477f8672db0c6e1191e80f3bee19a82e3503706f513c',
    'usr/share/dbus-1/system.d/net.hadess.PowerProfiles.conf': '1e41a29b7189bb39e3998284af8f0cd9744f7522e6c152c6558447a643a5b60a',
    'usr/share/dbus-1/system.d/org.freedesktop.UPower.PowerProfiles.conf': '919d35bb79d7ad12f3a4ccf496b5d359a10fd96c491191d54db4dbe8417281fc',
}
PPD_FILES = {
    'usr/libexec/power-profiles-daemon': '9d02f65b9314a62847a8460325dcd9009855df050dc423d2941a45e3aac8e43a',
    'usr/lib/systemd/system/power-profiles-daemon.service': '13491aae75bfa99db6f8fd68d98e8a0284936d16a4496b990639b43d384916b3',
    'usr/share/polkit-1/actions/power-profiles-daemon.policy': '6a32d5ce30969fc33a649b238d968421874d045d5588d79b683a94cca00cac2b',
}
TRANSFORMED = {
    'usr/share/dbus-1/system.d/org.freedesktop.login1.conf': 'bdf77601ce0fe683b7eda85f70d92f3fbff4a1b29a5a886524ab199b28de50ff',
    'usr/share/dbus-1/system.d/net.hadess.PowerProfiles.conf': '148a1739081af0a38cb1dfa12e7f3efd5efe478f27a063c49e130023af5d62d4',
    'usr/share/dbus-1/system.d/org.freedesktop.UPower.PowerProfiles.conf': '8373f7c215a400add8235040a36002b33a2494d09ca075352ef68a51630bcf12',
}
POLKIT_NAME = 'etc/polkit-1/rules.d/00-luma-hardware.rules'
POLKIT = '''// Image-owned hardware writer policy; no model or ambient agent approval.
polkit.addRule(function(action, subject) {
    if (action.id === "org.freedesktop.UPower.PowerProfiles.switch-profile" ||
        action.id === "org.freedesktop.UPower.PowerProfiles.hold-profile" ||
        action.id === "net.hadess.PowerProfiles.switch-profile" ||
        action.id === "net.hadess.PowerProfiles.hold-profile") {
        return subject.user === "root" ? polkit.Result.YES : polkit.Result.NO;
    }
});
'''
UDEV_NAME = 'etc/udev/rules.d/99-luma-backlight.rules'
UDEV = '''# Sysfs brightness is not a /dev node: do not grant uaccess or run helpers.
# The controller independently checks actual root-only sysfs permissions.
SUBSYSTEM=="backlight", TAG-="uaccess"
'''
MANIFEST = 'usr/share/luma-os/hardware-writer-policy.json'


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _read(root, relative, maximum=262144):
    name = PurePosixPath(relative)
    if name.is_absolute() or any(part in ('', '.', '..') for part in name.parts):
        raise ValueError('hardware policy requires a canonical image-relative path')
    path = root
    for part in name.parts:
        path = path / part
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('hardware policy input is linked or not protected: ' + relative)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size < 1 or info.st_size > maximum:
        raise ValueError('hardware policy file exceeds its fixed bound: ' + relative)
    return path.read_bytes()


def _xml(raw):
    if b'<!ENTITY' in raw.upper():
        raise ValueError('hardware policy refuses XML entity declarations')
    value = ET.fromstring(raw)
    if value.tag != 'busconfig' or len(list(value.iter())) > 10000:
        raise ValueError('unexpected or unbounded hardware bus configuration')
    return value


def _parent(root, relative, *, create=True):
    path = root / relative
    current = root
    for part in PurePosixPath(relative).parts[:-1]:
        current = current / part
        if not current.exists() and not current.is_symlink():
            if not create:
                raise ValueError('missing protected hardware configuration ancestor')
            current.mkdir()
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('refusing unprotected hardware configuration ancestor')
    return path


def _write(root, relative, data):
    path = _parent(root, relative)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('refusing linked/unprotected hardware image configuration')
    path.write_bytes(data)
    path.chmod(0o644)


def mediate_login(raw):
    """Remove exactly the supported unprivileged SetBrightness exception."""
    if _sha(raw) != ORIGINALS['usr/share/dbus-1/system.d/org.freedesktop.login1.conf']:
        raise ValueError('login1 policy differs from the pinned image version')
    tree = _xml(raw)
    removed = 0
    for policy in tree.findall('policy'):
        if policy.attrib != {'context': 'default'}:
            continue
        for child in list(policy):
            if child.tag == 'allow' and child.attrib == {
                'send_destination': LOGIN, 'send_interface': LOGIN + '.Session',
                'send_member': 'SetBrightness',
            }:
                policy.remove(child)
                removed += 1
    if removed != 1:
        raise ValueError('pinned login1 brightness exception did not match exactly')
    return b'<?xml version="1.0"?>\n' + ET.tostring(tree) + b'\n'


def mediate_power(raw, destination):
    if destination not in POWER or _sha(raw) != ORIGINALS['usr/share/dbus-1/system.d/' + destination + '.conf']:
        raise ValueError('power-profile alias policy differs from pinned package')
    tree = _xml(raw)
    if len(tree.findall('policy')) != 2:
        raise ValueError('unexpected supported power-profile policy shape')
    # Preserve root ownership, replace the ordinary broad method/Properties
    # allows, and give the trusted root controller its explicit write path.
    for child in list(tree):
        tree.remove(child)
    root = ET.SubElement(tree, 'policy', {'user': 'root'})
    ET.SubElement(root, 'allow', {'own': destination})
    ET.SubElement(root, 'allow', {'send_destination': destination})
    ordinary = ET.SubElement(tree, 'policy', {'context': 'default'})
    ET.SubElement(ordinary, 'deny', {'send_destination': destination})
    for interface, members in (
        ('org.freedesktop.DBus.Properties', ('Get', 'GetAll')),
        ('org.freedesktop.DBus.Introspectable', ('Introspect',)),
        ('org.freedesktop.DBus.Peer', ('Ping', 'GetMachineId')),
    ):
        for member in members:
            ET.SubElement(ordinary, 'allow', {'send_destination': destination,
                                            'send_interface': interface, 'send_member': member})
    return b'<?xml version="1.0"?>\n' + ET.tostring(tree) + b'\n'


def _may_write(rule):
    attrs = rule.attrib
    if not any(key.startswith('send_') for key in attrs):
        return False
    if attrs.get('send_type', 'method_call') not in ('method_call', '*'):
        return False
    for destination, interface, members in (
        (LOGIN, LOGIN + '.Session', ('SetBrightness',)),
        *((name, name, ('HoldProfile', 'ReleaseProfile')) for name in POWER),
        *((name, 'org.freedesktop.DBus.Properties', ('Set',)) for name in POWER),
    ):
        selected = attrs.get('send_destination', '*')
        prefix = attrs.get('send_destination_prefix')
        if selected not in ('*', destination) or prefix is not None and not destination.startswith(prefix):
            continue
        # A call may omit its interface. A matching generic allow is unsafe;
        # a different specified interface does not permit this exact call.
        if attrs.get('send_interface', '*') not in ('*', interface):
            continue
        if attrs.get('send_member', '*') in ('*', *members):
            path = attrs.get('send_path')
            if path is not None:
                if destination == LOGIN and not path.startswith('/org/freedesktop/login1/session/'):
                    continue
                if destination in POWER and path not in ('/net/hadess/PowerProfiles', '/org/freedesktop/UPower/PowerProfiles'):
                    continue
            return True
    return False


def _may_own(rule):
    if 'own' in rule.attrib and rule.attrib['own'] in ('*', LOGIN, *POWER):
        return True
    prefix = rule.attrib.get('own_prefix')
    return prefix is not None and any(name.startswith(prefix) for name in (LOGIN, *POWER))


def audit_bus(root):
    """Walk actual recursive includes; do not depend on includedir ordering."""
    inputs = {}
    active = set()
    policies = []

    def visit(relative, depth=0):
        if depth > 12 or relative in active or len(inputs) >= 256:
            raise ValueError('hardware bus include graph loops or exceeds fixed bounds')
        active.add(relative)
        raw = _read(root, relative)
        inputs[relative] = _sha(raw)
        tree = _xml(raw)
        for child in tree:
            if child.tag == 'policy':
                policies.append(child)
            elif child.tag in ('include', 'includedir'):
                if child.attrib.get('if_selinux_enabled') == 'yes':
                    # This image is AppArmor-only; an SELinux include is not
                    # silently reinterpreted as another policy authority.
                    if child.attrib != {'if_selinux_enabled': 'yes', 'selinux_root_relative': 'yes'}:
                        raise ValueError('unknown conditional hardware bus include')
                    continue
                if set(child.attrib) - {'ignore_missing'} or child.attrib.get('ignore_missing', 'no') not in ('yes', 'no'):
                    raise ValueError('unsupported hardware bus include attributes')
                name = child.text or ''
                if not name or name != name.strip() or '..' in PurePosixPath(name).parts:
                    raise ValueError('ambiguous hardware bus include path')
                included = name.lstrip('/') if name.startswith('/') else str(PurePosixPath(relative).parent / name)
                path = root / included
                if not path.exists() and not path.is_symlink():
                    if child.attrib.get('ignore_missing') == 'yes':
                        continue
                    raise ValueError('missing hardware bus include: ' + included)
                if child.tag == 'include':
                    visit(included, depth + 1)
                else:
                    info = path.lstat()
                    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                        raise ValueError('unprotected hardware bus include directory')
                    for entry in sorted(path.glob('*.conf')):
                        visit(entry.relative_to(root).as_posix(), depth + 1)
        active.remove(relative)

    visit('usr/share/dbus-1/system.conf')
    for policy in policies:
        if policy.attrib == {'user': 'root'}:
            continue
        for rule in policy:
            if rule.tag == 'allow' and (_may_write(rule) or _may_own(rule)):
                raise ValueError('merged bus policy can authorize another ordinary hardware writer/owner: ' + repr((policy.attrib, rule.attrib)))
            if policy.attrib.get('context') == 'mandatory' and rule.tag == 'deny' and _may_write(rule):
                raise ValueError('mandatory hardware deny would also block the trusted root controller')
    return inputs


def writer_inputs(root):
    inputs = {}
    total = 0
    for directory, suffix in (
        ('etc/udev/rules.d', '.rules'), ('usr/lib/udev/rules.d', '.rules'),
        ('etc/polkit-1/rules.d', '.rules'), ('usr/share/polkit-1/rules.d', '.rules'),
        ('usr/share/polkit-1/actions', '.policy'),
    ):
        path = root / directory
        if not path.exists():
            continue
        for entry in sorted(path.glob('*' + suffix)):
            if len(inputs) >= 512:
                raise ValueError('hardware ordinary-writer policy inventory exceeds bound')
            name = entry.relative_to(root).as_posix()
            raw = _read(root, name, 524288 if suffix == '.policy' else 262144)
            total += len(raw)
            if total > 8388608:
                raise ValueError('hardware ordinary-writer policy bytes exceed fixed inventory bound')
            if 'udev/' in name and name != UDEV_NAME:
                for line in raw.decode('utf-8').splitlines():
                    if not line.lstrip().startswith('#') and any(word in line.lower() for word in ('backlight', 'brightness')) and any(word in line for word in ('RUN', 'PROGRAM', 'MODE', 'GROUP', 'OWNER', 'uaccess')):
                        raise ValueError('unqualified ordinary backlight writer rule: ' + name)
            inputs[name] = _sha(raw)
    return inputs


def configure(root, edition):
    if edition not in ('desktop', 'headless'):
        raise ValueError('unknown hardware mediation image edition')
    if (root / MANIFEST).exists() or (root / MANIFEST).is_symlink():
        raise ValueError('hardware mediation must compose a new image, not reconfigure a host')
    for relative, expected in ORIGINALS.items():
        raw = _read(root, relative)
        if _sha(raw) != expected:
            raise ValueError('unsupported hardware package policy: ' + relative)
    for relative, expected in PPD_FILES.items():
        if _sha(_read(root, relative)) != expected:
            raise ValueError('unsupported power-profile executable/service tuple: ' + relative)
    for relative, expected in PLATFORM_FILES.items():
        if _sha(_read(root, relative, 1048576)) != expected:
            raise ValueError('unsupported fixed systemd/system-bus platform tuple: ' + relative)
    if stat.S_IMODE((root / 'usr/libexec/power-profiles-daemon').stat().st_mode) != 0o755:
        raise ValueError('power-profile daemon executable mode differs')
    login = next(name for name in ORIGINALS if name.endswith('login1.conf'))
    _write(root, login, mediate_login(_read(root, login)))
    for destination in POWER:
        name = 'usr/share/dbus-1/system.d/' + destination + '.conf'
        _write(root, name, mediate_power(_read(root, name), destination))
    _write(root, POLKIT_NAME, POLKIT.encode())
    _write(root, UDEV_NAME, UDEV.encode())
    wanted = 'etc/systemd/system/multi-user.target.wants/power-profiles-daemon.service'
    destination = _parent(root, wanted)
    if destination.exists() or destination.is_symlink():
        if not destination.is_symlink() or str(destination.readlink()) != '/usr/lib/systemd/system/power-profiles-daemon.service':
            raise ValueError('unexpected existing power-profile boot target')
    else:
        destination.symlink_to('/usr/lib/systemd/system/power-profiles-daemon.service')
    result = {'schema_version': 1, 'profile': PROFILE, 'edition': edition, 'power_profiles_version': PPD_VERSION,
              'power_profiles_package_sha256': PPD_PACKAGE_SHA256,
              'originals': ORIGINALS, 'power_profiles_files': PPD_FILES, 'platform_files': PLATFORM_FILES,
              'multi_user_target_link': wanted, 'bus_inputs': audit_bus(root),
              'ordinary_writer_inputs': writer_inputs(root),
              'root_and_firmware_trusted': True, 'atomic_device_cas': False,
              'installed_qualified': False}
    _write(root, MANIFEST, (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode())
    verify(root)
    return result


def verify(root):
    """Read-only fixed-policy verification, not a signed hardware capability."""
    raw = _read(root, MANIFEST)
    def fields(items):
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError('duplicate hardware writer manifest field')
            result[name] = value
        return result
    manifest = json.loads(raw, object_pairs_hook=fields,
        parse_constant=lambda unused: (_ for _ in ()).throw(ValueError('nonfinite hardware manifest value')))
    expected = {'schema_version', 'profile', 'edition', 'power_profiles_version',
                'power_profiles_package_sha256', 'originals', 'power_profiles_files', 'platform_files',
                'multi_user_target_link', 'bus_inputs', 'ordinary_writer_inputs',
                'root_and_firmware_trusted', 'atomic_device_cas', 'installed_qualified'}
    if (not isinstance(manifest, dict) or set(manifest) != expected
            or type(manifest['schema_version']) is not int or manifest['schema_version'] != 1
            or manifest['profile'] != PROFILE or manifest['edition'] not in ('headless', 'desktop')
            or manifest['power_profiles_version'] != PPD_VERSION
            or manifest['power_profiles_package_sha256'] != PPD_PACKAGE_SHA256
            or manifest['originals'] != ORIGINALS or manifest['power_profiles_files'] != PPD_FILES
            or manifest['platform_files'] != PLATFORM_FILES
            or manifest['root_and_firmware_trusted'] is not True
            or manifest['atomic_device_cas'] is not False or manifest['installed_qualified'] is not False
            or (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode() != raw):
        raise ValueError('hardware writer manifest is not the exact fixed canonical contract')
    for relative, expected_hash in {**TRANSFORMED, **PPD_FILES, **PLATFORM_FILES}.items():
        if _sha(_read(root, relative, 1048576 if relative in PLATFORM_FILES else 262144)) != expected_hash:
            raise ValueError('fixed hardware policy/executable bytes differ: ' + relative)
    if (_read(root, POLKIT_NAME) != POLKIT.encode() or _read(root, UDEV_NAME) != UDEV.encode()
            or stat.S_IMODE((root / 'usr/libexec/power-profiles-daemon').stat().st_mode) != 0o755):
        raise ValueError('fixed ordinary hardware writer mediation differs')
    wanted = 'etc/systemd/system/multi-user.target.wants/power-profiles-daemon.service'
    link = _parent(root, wanted, create=False)
    if (manifest['multi_user_target_link'] != wanted or not link.is_symlink()
            or link.lstat().st_uid != 0
            or str(link.readlink()) != '/usr/lib/systemd/system/power-profiles-daemon.service'):
        raise ValueError('fixed server/desktop power service boot wiring differs')
    current_bus, current_writers = audit_bus(root), writer_inputs(root)
    if manifest['bus_inputs'] != current_bus or manifest['ordinary_writer_inputs'] != current_writers:
        raise ValueError('complete current hardware writer policy closure changed')
    closure = json.dumps({'bus_inputs': current_bus, 'ordinary_writer_inputs': current_writers,
                          'power_profiles_files': PPD_FILES, 'platform_files': PLATFORM_FILES}, sort_keys=True, separators=(',', ':')).encode()
    return {'schema_version': 1, 'profile': PROFILE, 'edition': manifest['edition'],
            'manifest_sha256': _sha(raw), 'closure_sha256': _sha(closure),
            'power_profiles_version': PPD_VERSION, 'verified': True,
            'observation_not_authority': True, 'installed_qualified': False}


if __name__ == '__main__':
    try:
        if sys.argv[1:] != ['--verify'] or not sys.flags.isolated or os.geteuid() != 0:
            raise ValueError('fixed isolated read-only image-policy verification required')
        print(json.dumps(verify(Path('/')), sort_keys=True, separators=(',', ':')))
    except Exception as error:
        print('Hardware writer image-policy verification refused: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
