"""Static boot contract for unit mount namespaces; no booted result is claimed.

systemd fails a unit with 226/NAMESPACE when a path in InaccessiblePaths=,
ReadWritePaths= or ReadOnlyPaths= without a "-" prefix is missing. /run is
empty at every boot, so each such /run path needs a boot-time creator.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
IMAGE = ROOT / 'native/image'
OVERLAY = IMAGE / 'overlay'
SYSTEM = OVERLAY / 'etc/systemd/system'
UNITS = sorted(SYSTEM.glob('*.service')) + sorted((IMAGE / 'utc').glob('*.service'))
NAMESPACE = ('InaccessiblePaths', 'ReadWritePaths', 'ReadOnlyPaths')


def unit_values(path):
    values = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith(('#', ';', '[')) and '=' in line:
            key, value = line.split('=', 1)
            values.setdefault(key, []).append(value)
    return values


def words(values, key):
    return [word for value in values.get(key, []) for word in value.split()]


def tmpfiles_entries():
    entries = {}
    for path in sorted((OVERLAY / 'etc/tmpfiles.d').glob('*.conf')):
        for line in path.read_text().splitlines():
            fields = line.split()
            if fields and fields[0] in ('d', 'f'):
                entries[fields[1]] = (path.name, fields)
    return entries


def required_run_paths(values):
    for key in NAMESPACE:
        for entry in words(values, key):
            path = entry.lstrip('-+')
            if '-' not in entry[:len(entry) - len(path)] and path.startswith('/run/'):
                yield key, path


def runtime_directories(values):
    return {'/run/' + name for name in words(values, 'RuntimeDirectory')}


def within(guard, path):
    return guard == path or guard.startswith(path + '/')


def guaranteed(values, path, created, groups):
    if path in created or path in runtime_directories(values):
        return True
    guards = [guard for guard in values.get('ConditionPathExists', [])
              if not guard.startswith(('!', '|'))]
    if any(within(guard, path) for guard in guards):
        return True
    # One unit's RuntimeDirectory= entries exist together while it runs, so a
    # start condition inside one of them also proves its siblings exist.
    return any(path in group and within(guard, sibling)
               for group in groups for sibling in group for guard in guards)


class RuntimeNamespacePathTests(unittest.TestCase):
    def test_every_required_run_path_has_a_boot_time_creator(self):
        created = tmpfiles_entries()
        groups = [runtime_directories(unit_values(unit)) for unit in UNITS]
        self.assertGreater(len(UNITS), 20)
        missing = [(unit.name, key, path) for unit in UNITS
                   for key, path in required_run_paths(unit_values(unit))
                   if not guaranteed(unit_values(unit), path, created, groups)]
        self.assertEqual(missing, [])

    def test_governance_mount_point_lives_for_the_whole_boot(self):
        lines = (OVERLAY / 'etc/tmpfiles.d/luma-governance.conf').read_text().splitlines()
        self.assertIn('d /run/luma-governance 0711 root root -', lines)
        self.assertEqual([line for line in lines if not line.startswith('#')],
                         ['d /run/luma-governance 0711 root root -'])
        for unit in UNITS:
            self.assertNotIn('luma-governance', words(unit_values(unit), 'RuntimeDirectory'), unit.name)
        admin = unit_values(SYSTEM / 'luma-admin.service')
        self.assertIn('/run/luma-governance', words(admin, 'ReadWritePaths'))
        self.assertIn('systemd-tmpfiles-setup.service', words(admin, 'After'))
        source = (ROOT / 'rust/luma-platform/src/admin_service.rs').read_text().split('#[cfg(test)]')[0]
        self.assertIn('metadata.mode() & 0o777 != 0o711', source)
        self.assertIn('error.kind() == io::ErrorKind::ConnectionRefused', source)
        keeper = unit_values(IMAGE / 'utc/luma-utc-recovery-keeper.service')
        self.assertEqual(keeper['ConditionKernelCommandLine'], ['luma.mode=live'])
        self.assertIn('/run/luma-governance', words(keeper, 'InaccessiblePaths'))

    def test_masked_service_runtime_directories_match_their_owners(self):
        text = (OVERLAY / 'etc/tmpfiles.d/luma-runtime-masks.conf').read_text()
        rows = [line.split() for line in text.splitlines() if line and not line.startswith('#')]
        self.assertEqual([row[1] for row in rows], ['/run/luma-broker', '/run/luma-content-custody'])
        owners = {name: unit_values(SYSTEM / name) for name in ('luma-broker.service', 'luma-content-custody.service')}
        observer = unit_values(SYSTEM / 'luma-content-data-observer.service')
        for kind, path, mode, user, group, age in rows:
            self.assertEqual((kind, age), ('d', '-'))
            self.assertIn(path, words(observer, 'InaccessiblePaths'))
            owner = [values for values in owners.values() if words(values, 'RuntimeDirectory') == [path[5:]]]
            self.assertEqual(len(owner), 1, path)
            owner = owner[0]
            self.assertEqual(owner['RuntimeDirectoryMode'], [mode])
            self.assertEqual((owner['User'], owner['Group']), ([user], [group]))
            # Owners bind without stale-socket recovery, so stop must still
            # remove the directory and every socket in it.
            self.assertEqual(owner['RuntimeDirectoryPreserve'], ['no'])


if __name__ == '__main__':
    unittest.main()
