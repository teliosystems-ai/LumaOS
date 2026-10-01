"""Prevent moving CA bootstrap dependencies from contaminating pinned builds.

These are source-policy checks; a real Docker build is separate evidence.
"""
from pathlib import Path
import re
import unittest


IMAGE = Path(__file__).resolve().parents[1] / 'image'
NAMES = ('Dockerfile.tools', 'Dockerfile.root')


def instructions(name):
    return (IMAGE / name).read_text().replace('\\\n', ' ').splitlines()


class PackageSnapshotTests(unittest.TestCase):
    def test_both_builders_use_same_pinned_base_and_bootstrap(self):
        files = [instructions(name) for name in NAMES]
        bases = [next(line for line in lines if line.startswith('ARG UBUNTU_BASE='))
                 for lines in files]
        self.assertEqual(bases[0], bases[1])
        self.assertRegex(bases[0], r'^ARG UBUNTU_BASE=ubuntu@sha256:[0-9a-f]{64}$')
        bootstraps = [next(line for line in lines if line.startswith('RUN '))
                      for lines in files]
        self.assertEqual(bootstraps[0], bootstraps[1])

    def test_bootstrap_is_release_only_authenticated_and_exact(self):
        for name in NAMES:
            with self.subTest(builder=name):
                bootstrap = next(line for line in instructions(name) if line.startswith('RUN '))
                self.assertIn('deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] '
                              'http://archive.ubuntu.com/ubuntu noble main', bootstrap)
                for pocket in ('noble-updates', 'noble-security', 'noble-backports'):
                    self.assertNotIn(pocket, bootstrap)
                commands = [command.strip() for command in bootstrap.split('&&')]
                apt = [command for command in commands if command.startswith('apt-get ')]
                self.assertEqual(len(apt), 2)
                for command in apt:
                    self.assertIn('-o Dir::Etc::sourcelist=/tmp/luma-bootstrap.list', command)
                    self.assertIn('-o Dir::Etc::sourceparts=-', command)
                self.assertTrue(apt[0].startswith('apt-get update '))
                self.assertIn('-o APT::Update::Error-Mode=any', apt[0])
                self.assertTrue(apt[1].startswith('apt-get install '))
                self.assertIn('ca-certificates=20240203', apt[1])
                self.assertIn('ubuntu-keyring=2023.11.28.1', apt[1])
                self.assertIn('openssl=3.0.13-0ubuntu3', apt[1])
                self.assertEqual(commands[-1], 'rm /tmp/luma-bootstrap.list')

    def test_all_subsequent_package_operations_select_snapshot(self):
        for name in NAMES:
            with self.subTest(builder=name):
                runs = [line for line in instructions(name) if line.startswith('RUN ')]
                count = 0
                for line in runs[1:]:
                    for command in re.findall(r'apt-get\s+(?:update|install)\s+[^;&]+', line):
                        count += 1
                        self.assertIn('--snapshot=${SNAPSHOT}', command)
                self.assertGreaterEqual(count, 4)
                text = (IMAGE / name).read_text().lower()
                for bypass in ('allow-unauthenticated', 'allow-insecure', 'trusted=yes',
                               'verify-peer', 'verify-host', 'allow-downgrades'):
                    self.assertNotIn(bypass, text)


if __name__ == '__main__':
    unittest.main()
