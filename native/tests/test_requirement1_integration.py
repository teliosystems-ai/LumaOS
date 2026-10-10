"""Integrated Requirement #1 source/assembly checks, not native qualification."""
import ast
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
IMAGE = ROOT / 'native/image'
RUST = ROOT / 'rust/luma-platform/src'


def load_assembly():
    spec = importlib.util.spec_from_file_location('r1_image_assembly', IMAGE / 'assemble.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RequirementOneIntegration(unittest.TestCase):
    def test_confined_dispatch_rejects_other_paths_before_terminal_and_effects(self):
        source = (RUST / 'main.rs').read_text()
        guard = source.index('if confined_client\n')
        terminal = source.index('service::granted_gateway::prepare_terminal()?;')
        dispatch = source.index('match args.first().map(String::as_str) {', terminal)
        self.assertLess(guard, terminal)
        self.assertLess(terminal, dispatch)
        allowed = source[guard:terminal]
        for verb in ('granted-infer', 'workflow-governed-advance', 'artifact-governed-export'):
            self.assertIn('"' + verb + '"', allowed)
        for verb in ('admin-service', 'utc-keeper', 'admin-catalog', 'granted-run'):
            self.assertNotIn('"' + verb + '"', allowed)
        legacy = source[terminal:dispatch]
        for verb in ('workflow-invoice-advance', 'artifact-catalog-read', 'invoice-calculate'):
            self.assertIn('"' + verb + '"', legacy)
        self.assertIn('reject_laboratory_effects_after_bootstrap()?', legacy)

    def test_immutable_pin_parent_traversal_and_restart_signal_are_permitted(self):
        profiles = IMAGE / 'overlay/etc/apparmor.d'
        for name in ('luma-admin', 'luma-granted-client'):
            source = (profiles / name).read_text()
            for parent in ('/ r,', '/usr/ r,', '/usr/libexec/luma-os/ r,',
                           '/usr/lib/systemd/ r,', '/usr/lib/systemd/system/ r,',
                           '/etc/ r,', '/etc/apparmor.d/ r,', '/run/ r,'):
                self.assertIn(parent, source, (name, parent))
            self.assertIn('/usr/bin/systemd-creds mrix,', source)
        self.assertIn('signal (send,receive) peer=luma-utc-restart,',
                      (profiles / 'luma-admin').read_text())
        self.assertIn('signal (send,receive) peer=luma-admin,',
                      (profiles / 'luma-utc-restart').read_text())

    def test_input_and_output_are_owned_bounded_and_not_argv_payloads(self):
        launcher = (RUST / 'service/granted_gateway.rs').read_text()
        workflow = (RUST / 'workflow_runs.rs').read_text()
        for check in ('input.json', 'input.csv', 'O_NOFOLLOW', 'create_new(true)',
                      '/run/luma-granted-client/requests', 'terminal.c_oflag &= !libc::ONLCR',
                      'fstatfs', '0x01021994'):
            self.assertIn(check, launcher)
        for check in ('before.nlink() != 1', 'before.mode() & 0o7777 != 0o400',
                      'operator_snapshot(&args[7])?', 'owned launcher snapshot'):
            self.assertIn(check, workflow)
        self.assertIn('SystemCallFilter=@system-service @memlock', launcher)

    def test_assembly_packages_candidate_and_only_enables_seed_gated_units(self):
        """Run the actual packaging function with fake compiler and image links.

        No chroot, ELF execution, daemon, host unit or privileged symlink occurs.
        This checks layout and ordering, not Linux ownership or confinement.
        """
        assembly = load_assembly()
        with tempfile.TemporaryDirectory(prefix='luma-r1-assembly-') as temporary:
            base = Path(temporary)
            image = base / 'image'
            work = base / 'work'
            work.mkdir()
            for directory in ('etc/ssl/certs', 'usr/libexec/luma-os', 'etc/systemd/system'):
                (image / directory).mkdir(parents=True, exist_ok=True)
            (image / 'etc/ssl/certs/ca-certificates.crt').write_bytes(b'candidate CA fixture')
            inputs = base / 'inputs'
            inputs.mkdir()
            (inputs / 'chrony-4.9.tar.gz').write_bytes(b'candidate source fixture')
            (inputs / 'chrony-4.9.provenance.json').write_text('{"signature_verified":false}')
            calls = []
            links = []
            original_copy = shutil.copy2

            def copy(source, destination, **kwargs):
                source = Path(source)
                if source.parent == Path('/inputs'):
                    source = inputs / source.name
                return original_copy(source, destination, **kwargs)

            def run(*args, **kwargs):
                calls.append(tuple(str(arg) for arg in args))
                if args[0] == 'bash':
                    package = Path(args[-1])
                    package.mkdir()
                    for name in ('chronyd', 'COPYING.chrony', 'source-inputs.json',
                                 'build-packages.tsv', 'SHA256SUMS', 'version.txt'):
                        (package / name).write_bytes(('fixture:' + name).encode())
                return ''

            with patch.object(assembly, 'run', side_effect=run), \
                    patch.object(assembly.shutil, 'copy2', side_effect=copy), \
                    patch.object(Path, 'symlink_to', autospec=True,
                                 side_effect=lambda path, target: links.append((path, str(target)))):
                assembly.package_protected_utc(image, ROOT, work)
            target = image / 'usr/share/luma-os/utc'
            self.assertEqual((target / 'source/chrony-4.9.tar.gz').read_bytes(),
                             (inputs / 'chrony-4.9.tar.gz').read_bytes())
            self.assertEqual((image / 'usr/libexec/luma-os/chronyd').read_bytes(), b'fixture:chronyd')
            self.assertEqual((target / 'source/chrony_hook.c').read_bytes(),
                             (IMAGE / 'utc/chrony_hook.c').read_bytes())
            enabled = {path.name for path, _ in links if path.parent.name == 'multi-user.target.wants'}
            self.assertEqual(enabled, {'luma-utc-keeper.service', 'luma-utc-producer.path'})
            masked = {path.name for path, destination in links if destination == '/dev/null'}
            self.assertEqual(masked, {'systemd-timesyncd.service', 'chrony.service', 'ntp.service'})
            self.assertEqual(calls[0][0], 'bash')
            self.assertEqual(Path(calls[-1][1]).name, 'package_runtime.py')
            self.assertNotIn('systemctl', {arg for call in calls for arg in call})

    def test_builder_captures_control_inputs_and_corresponding_source(self):
        source = (IMAGE / 'assemble.py').read_text()
        tree = ast.parse(source)
        self.assertTrue(any(isinstance(node, ast.FunctionDef)
                            and node.name == 'package_protected_utc' for node in tree.body))
        for input_path in ('native/image/overlay', 'luma-utc-restart',
                           'luma-admin-control', 'package_protected_utc(ROOT, REPO, WORK)'):
            self.assertIn(input_path, source)
        driver = (IMAGE / 'build.sh').read_text()
        self.assertIn('prepare_release_input.py', driver)
        self.assertIn('dst=/inputs,readonly', driver)
        self.assertIn('LUMA_BUILD_ROOT', driver)

    def test_catalog_json_cannot_bypass_typed_custody_and_final_commits_are_rechecked(self):
        source = (RUST / 'admin_governance.rs').read_text()
        parser = source.split('fn parse_command(', 1)[1].split('pub fn catalog_command(', 1)[0]
        self.assertIn('Some("admin-catalog") if end == 4', parser)
        self.assertIn('finite_catalog_file', parser)
        delivery = source.split('fn finite_catalog_json(', 1)[1].split('fn parse_command(', 1)[0]
        for variant in ('AssignRole', 'RevokeAssignment', 'IssueGrant', 'RevokeGrant'):
            self.assertIn('Command::' + variant, delivery)
        self.assertNotIn('Command::PrepareAdminAccountRecovery', delivery)
        self.assertIn('input changed while captured', delivery)
        workflow = (RUST / 'workflow_runs.rs').read_text()
        self.assertIn('self.root.sync_all()?;\n        authorize(plan)?;\n        tx.commit()?;', workflow)
        self.assertIn('report: bytes.clone()', workflow)
        production = workflow.split('#[cfg(test)]', 1)[0]
        self.assertNotIn('calculation::report_bytes', production)
        artifact = (RUST / 'artifact_catalog.rs').read_text()
        self.assertIn('hook(Phase::TemporarySynced)?;\n            authorize(receipt)?;\n            self.rename(', artifact)
        self.assertIn('self.root.sync_all()?;\n        authorize(receipt)?;\n        transaction.commit()?;', artifact)
        grants = source.split("impl GrantBoundary<'_>", 1)[1].split('pub(crate) fn with_grant', 1)[0]
        final = grants.split('let final_observation = client.recheck', 1)[1]
        self.assertLess(final.index('password_window('), final.index('self.fenced = false'))
        self.assertIn('original protected password epoch', final)


if __name__ == '__main__':
    unittest.main()
