"""Real Linux file/ELF build tests; no WSL imports or product qualification.

The isolated fixture deliberately copies the test environment's real /bin/true
and its loader/library closure into shell/systemd slots. It proves the builder's
structural checks, not those programs' shell/boot semantics. An actual candidate
must use the reviewed Ubuntu shell/systemd and actual compiled luma-platform.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

IMAGE = Path(__file__).resolve().parents[1] / 'image'
SPEC = importlib.util.spec_from_file_location('windows_package_builder', IMAGE / 'windows_package.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class WindowsPackageBuilderTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='luma-windows-package-')
        self.addCleanup(self.work.cleanup)
        self.base = Path(self.work.name)
        self.root = self.base / 'ubuntu'
        self.root.mkdir(mode=0o755)
        self.platform = self.base / 'luma-platform'
        self.platform.write_bytes(Path('/usr/bin/true').read_bytes())
        self.platform.chmod(0o755)
        self.plan = self.base / 'plan.json'
        self.write_plan()
        self.write('etc/os-release', b'ID=ubuntu\nVERSION_ID="24.04"\n')
        # Real executable and real dependencies, not invented ELF headers.
        executable = self.platform.read_bytes()
        self.write('usr/bin/dash', executable, 0o755)
        self.write('usr/lib/systemd/systemd', executable, 0o755)
        (self.root / 'bin').symlink_to('usr/bin', target_is_directory=True)
        (self.root / 'usr/bin/sh').symlink_to('dash')
        todo = [executable]
        seen = set()
        while todo:
            interp, needed = builder.elf(todo.pop())
            paths = [interp] if interp else []
            for name in needed:
                candidates = [Path('/') / folder / name for folder in builder.LIB_DIRS]
                selected = next((p for p in candidates if p.is_file()), None)
                if selected is None:
                    raise AssertionError('isolated tools image lacks real ELF dependency: ' + name)
                paths.append(str(selected))
            for path in paths:
                if path in seen:
                    continue
                seen.add(path)
                data = Path(path).read_bytes()
                self.write(path.lstrip('/'), data, 0o755)
                todo.append(data)

    def write(self, relative, data, mode=0o644):
        target = self.root / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(mode)
        return target

    def write_plan(self, exclusions=(), normalize=False, **extra):
        value = {'schema_version': 1, 'exclude_paths': list(exclusions),
                 'normalize_privileged_modes': normalize}
        value.update(extra)
        self.plan.write_bytes(builder.canonical(value))

    def build(self, name='candidate'):
        return builder.build(self.root, self.platform, self.plan, self.base / name,
                             'luma-wsl-dev-real-elf-test')

    def test_real_files_archive_matches_manifest_and_is_deterministic(self):
        result = self.build()
        second = self.build('second')
        self.assertEqual(result, second)
        self.assertEqual((self.base / 'candidate/rootfs.tar').read_bytes(),
                         (self.base / 'second/rootfs.tar').read_bytes())
        manifest = json.loads((self.base / 'candidate/manifest.json').read_bytes())
        archive_path = self.base / 'candidate/rootfs.tar'
        self.assertEqual(manifest['rootfs']['bytes'], archive_path.stat().st_size)
        self.assertEqual(manifest['rootfs']['sha256'], hashlib.sha256(archive_path.read_bytes()).hexdigest())
        self.assertEqual(set(p.name for p in (self.base / 'candidate').iterdir()),
                         {'manifest.json', 'rootfs.tar'})
        with tarfile.open(archive_path, 'r:') as archive:
            members = archive.getmembers()
            self.assertEqual(len(members), result['member_count'])
            self.assertEqual(sum(m.size for m in members), manifest['rootfs']['content_bytes'])
            self.assertEqual([m.name for m in members], sorted(m.name for m in members))
            self.assertTrue(all((m.isfile() or m.isdir()) and m.uid == m.gid == m.mtime == 0 for m in members))
            self.assertEqual(archive.extractfile('bin/sh').read(), self.platform.read_bytes())
            self.assertEqual(archive.extractfile('etc/wsl.conf').read(), builder.WSL)
            for expected in manifest['required_files']:
                member = archive.getmember(expected['path'])
                data = archive.extractfile(member).read()
                self.assertEqual(expected['bytes'], len(data))
                self.assertEqual(expected['sha256'], hashlib.sha256(data).hexdigest())
                self.assertEqual(expected['executable'], bool(member.mode & 0o111))
        self.assertFalse(result['package_authenticated'])
        self.assertFalse(result['runtime_qualified'])
        self.assertFalse(result['distribution_imported'])
        self.assertFalse(result['gate_closing'])

    def test_absolute_alias_is_root_anchored_and_relative_parent_stays_inside(self):
        (self.root / 'etc/absolute').symlink_to('/usr/bin/dash')
        (self.root / 'etc/relative').symlink_to('../usr/bin/dash')
        self.build()
        with tarfile.open(self.base / 'candidate/rootfs.tar') as archive:
            for path in ('etc/absolute', 'etc/relative'):
                self.assertEqual(archive.extractfile(path).read(), self.platform.read_bytes())

    def test_link_escape_missing_absolute_target_and_cycles_refuse(self):
        link = self.root / 'etc/host-link'
        for target in ('../../luma-platform', '/proc/self/status', 'host-link'):
            with self.subTest(target=target):
                link.symlink_to(target)
                with self.assertRaises((ValueError, OSError)):
                    self.build()
                self.assertFalse((self.base / 'candidate').exists())
                link.unlink()
        (self.root / 'etc/loop').symlink_to('../etc', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'cycle'):
            self.build()

    def test_explicit_exclusions_not_implicit_drops(self):
        (self.root / 'etc/mtab').symlink_to('/proc/mounts')
        with self.assertRaises(OSError):
            self.build()
        self.write_plan(['etc/mtab'])
        result = self.build()
        self.assertEqual(result['excluded_paths'], ['etc/mtab'])
        with tarfile.open(self.base / 'candidate/rootfs.tar') as archive:
            self.assertNotIn('etc/mtab', archive.getnames())
        self.write_plan(['etc/missing'])
        with self.assertRaises((ValueError, OSError)):
            self.build('missing')

    def test_excluded_mandatory_identity_is_not_replaced_with_invented_data(self):
        self.write_plan(['etc/os-release'])
        with self.assertRaisesRegex(ValueError, 'mandatory'):
            self.build()

    def test_special_files_and_case_aliases_refuse_without_touching_source(self):
        fifo = self.root / 'etc/pipe'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, 'special'):
            self.build()
        fifo.unlink()
        self.write('etc/Case', b'one')
        self.write('etc/case', b'two')
        with self.assertRaisesRegex(ValueError, 'case-aliased'):
            self.build()
        self.assertEqual((self.root / 'etc/Case').read_bytes(), b'one')

    def test_path_grammar_and_ustar_limits_are_unchanged(self):
        for name in ('CON', 'A.', 'bad:name', 'bad name', 'x' * 101):
            with self.subTest(name=name):
                path = self.write('etc/' + name, b'no')
                with self.assertRaises(ValueError):
                    self.build()
                path.unlink()
        builder.archive_path('a' * 100 + '/' + 'b' * 100)
        with self.assertRaises(ValueError):
            builder.archive_path('a' * 156 + '/' + 'b' * 99)

    def test_privileged_modes_require_exact_opt_in_and_never_modify_inputs(self):
        path = self.write('usr/bin/privileged', b'data', 0o4755)
        with self.assertRaisesRegex(ValueError, 'explicit normalization'):
            self.build()
        self.write_plan(normalize=True)
        result = self.build()
        self.assertEqual(result['privileged_modes_removed'], ['bin/privileged', 'usr/bin/privileged'])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o4755)
        with tarfile.open(self.base / 'candidate/rootfs.tar') as archive:
            self.assertEqual(archive.getmember('usr/bin/privileged').mode, 0o755)

    def test_private_modes_preserved_and_unsafe_write_refused(self):
        self.write('etc/private', b'secret', 0o600)
        directory = self.root / 'tmp'
        directory.mkdir()
        directory.chmod(0o1777)
        self.build()
        with tarfile.open(self.base / 'candidate/rootfs.tar') as archive:
            self.assertEqual(archive.getmember('etc/private').mode, 0o600)
            self.assertEqual(archive.getmember('tmp').mode, 0o1777)
        path = self.write('etc/writable', b'no', 0o664)
        self.write_plan(normalize=True)
        with self.assertRaisesRegex(ValueError, 'unsafe writable'):
            self.build('unsafe')
        path.chmod(0o644)

    def test_strict_plan_closed_types_duplicates_and_overlaps(self):
        cases = [b'{"schema_version":1,"schema_version":1}',
                 b'{"schema_version":true,"exclude_paths":[],"normalize_privileged_modes":false}',
                 b'{"schema_version":1,"exclude_paths":["../host"],"normalize_privileged_modes":false}',
                 b'{"schema_version":1,"exclude_paths":["etc","etc/mtab"],"normalize_privileged_modes":false}',
                 b'{"schema_version":1,"exclude_paths":[],"normalize_privileged_modes":false,"extra":0}']
        for data in cases:
            with self.subTest(data=data):
                self.plan.write_bytes(data)
                with self.assertRaises((ValueError, TypeError)):
                    self.build()

    def test_plan_refuses_sparse_oversize_and_special_files_before_reading(self):
        with self.plan.open('wb') as stream:
            stream.truncate(2**30)
        with self.assertRaisesRegex(ValueError, 'source file exceeds bound'):
            builder.plan_input(self.plan)
        self.plan.unlink()
        os.mkfifo(self.plan)
        with self.assertRaisesRegex(ValueError, 'special'):
            builder.plan_input(self.plan)
        self.plan.unlink()
        self.plan.mkdir()
        with self.assertRaisesRegex(ValueError, 'source file exceeds bound'):
            builder.plan_input(self.plan)
        self.assertFalse((self.base / 'candidate').exists())

    def test_real_elf_rejects_header_only_invalid_segments_and_missing_runtime(self):
        original = self.platform.read_bytes()
        for data in (original[:64], b'not an elf', original[:100]):
            with self.subTest(length=len(data)):
                self.platform.write_bytes(data)
                with self.assertRaises(ValueError):
                    self.build()
        self.platform.write_bytes(original)
        (self.root / 'usr/lib/systemd/systemd').unlink()
        with self.assertRaisesRegex(ValueError, 'mandatory'):
            self.build()

    def test_missing_loader_or_needed_library_refuses_before_output(self):
        interp, needed = builder.elf(self.platform.read_bytes())
        self.assertTrue(interp)
        target = self.root / interp.lstrip('/')
        saved = target.read_bytes()
        target.unlink()
        with self.assertRaisesRegex(ValueError, 'missing bounded runtime'):
            self.build()
        target.write_bytes(saved)
        target.chmod(0o755)
        self.assertTrue(needed)
        for folder in builder.LIB_DIRS:
            candidate = self.root / folder / needed[0]
            if candidate.is_file():
                candidate.unlink()
        with self.assertRaisesRegex(ValueError, 'missing ELF dependency'):
            self.build()
        self.assertFalse((self.base / 'candidate').exists())

    def test_ubuntu_identity_duplicate_wrong_version_and_bad_release_refuse(self):
        for value in (b'ID=ubuntu\nVERSION_ID=22.04\n', b'ID=ubuntu\nID=ubuntu\nVERSION_ID=24.04\n'):
            self.write('etc/os-release', value)
            with self.assertRaises(ValueError):
                self.build()
        with self.assertRaises(ValueError):
            builder.build(self.root, self.platform, self.plan, self.base / 'candidate', 'production')

    def test_output_is_new_external_directory_and_parent_symlinks_refuse(self):
        self.build()
        before = (self.base / 'candidate/rootfs.tar').read_bytes()
        with self.assertRaises(FileExistsError):
            self.build()
        self.assertEqual((self.base / 'candidate/rootfs.tar').read_bytes(), before)
        with self.assertRaisesRegex(ValueError, 'outside'):
            builder.build(self.root, self.platform, self.plan, self.root / 'candidate', 'luma-wsl-dev-test')
        (self.base / 'alias').symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(OSError):
            builder.build(self.root, self.platform, self.plan, self.base / 'alias/other', 'luma-wsl-dev-test')

    def test_source_ancestor_symlink_and_member_count_or_file_bounds_refuse(self):
        (self.base / 'alias').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            builder.build(self.base / 'alias', self.platform, self.plan,
                          self.base / 'candidate', 'luma-wsl-dev-test')
        with patch.object(builder, 'MAX_MEMBERS', 2):
            with self.assertRaisesRegex(ValueError, 'member count'):
                self.build()
        with patch.object(builder, 'MAX_FILE', 8):
            with self.assertRaisesRegex(ValueError, 'bounds'):
                self.build()

    def compile_private_dependency(self, path, *, old_rpath=False, library_rpath=None, extra_dependency=False,
                                   direct_sibling=False):
        """Compile real bounded ELF fixtures; never patch a fake ELF header."""
        source = self.base / 'dependency.c'
        if extra_dependency:
            source.write_text('int fixture_leaf(void) { return 17; }\n')
            leaf = self.base / 'libluma-leaf.so'
            subprocess.run(['gcc', '-shared', '-fPIC', '-nostdlib', '-Wl,-soname,libluma-leaf.so',
                            str(source), '-o', str(leaf)], check=True, capture_output=True, timeout=15)
            self.write('usr/lib/x86_64-linux-gnu/systemd/libluma-leaf.so', leaf.read_bytes())
            source.write_text('extern int fixture_leaf(void); int fixture_value(void) { return fixture_leaf(); }\n')
        else:
            source.write_text('int fixture_value(void) { return 17; }\n')
        library = self.base / 'libluma-fixture.so'
        command = ['gcc', '-shared', '-fPIC', '-nostdlib', '-Wl,-soname,libluma-fixture.so',
                   str(source), '-o', str(library)]
        if library_rpath is not None:
            command.extend(['-Wl,-rpath,' + library_rpath])
        if extra_dependency:
            command.extend(['-L' + str(self.base), '-lluma-leaf'])
        subprocess.run(command, check=True, capture_output=True, timeout=15)
        self.write('usr/lib/x86_64-linux-gnu/systemd/libluma-fixture.so', library.read_bytes(), 0o644)
        source.write_text('extern int fixture_value(void); extern int fixture_leaf(void);\n'
                          'void _start(void) { int value = fixture_value()' +
                          (' + fixture_leaf()' if direct_sibling else '') + '; '
                          '__asm__ volatile("syscall" : : "a"(60L), "D"((long)value) : "rcx", "r11", "memory"); '
                          '__builtin_unreachable(); }\n')
        command = ['gcc', '-nostdlib', '-no-pie', '-fno-stack-protector', '-Wl,-e,_start',
                   str(source), '-L' + str(self.base), '-lluma-fixture', '-Wl,-rpath,' + path,
                   '-o', str(self.platform)]
        if old_rpath:
            command.append('-Wl,--disable-new-dtags')
        if extra_dependency:
            command.append('-Wl,-rpath-link,' + str(self.base))
        if direct_sibling:
            command.append('-lluma-leaf')
        subprocess.run(command, check=True, capture_output=True, timeout=15)

    def test_actual_compiled_systemd_style_runpath_closure_accepts_private_library(self):
        self.compile_private_dependency('/usr/lib/x86_64-linux-gnu/systemd')
        _, needed, search = builder.elf(self.platform.read_bytes(), object_path='usr/bin/luma-platform', details=True)
        self.assertEqual(needed, ['libluma-fixture.so'])
        self.assertEqual(search, {'rpath': (), 'runpath': ('usr/lib/x86_64-linux-gnu/systemd',), 'soname': None})
        self.build()
        manifest = json.loads((self.base / 'candidate/manifest.json').read_bytes())
        self.assertIn('usr/lib/x86_64-linux-gnu/systemd/libluma-fixture.so',
                      [record['path'] for record in manifest['required_files']])

    def test_real_elf_rpath_and_origin_expansion_are_bound_to_object_location(self):
        for index, value in enumerate(('$ORIGIN/../lib/x86_64-linux-gnu/systemd',
                                        '${ORIGIN}/../lib/x86_64-linux-gnu/systemd')):
            self.compile_private_dependency(value, old_rpath=True)
            _, _, search = builder.elf(self.platform.read_bytes(), object_path='usr/bin/luma-platform', details=True)
            self.assertEqual(search['rpath'], ('usr/lib/x86_64-linux-gnu/systemd',))
            self.assertIsNone(search['runpath'])
            self.build('origin-' + str(index))

    def test_compiled_empty_relative_escaping_and_nonpolicy_runpaths_refuse(self):
        for path in ('', '.', '/tmp', '/usr/lib/x86_64-linux-gnu/systemd:',
                     ':', '$ORIGIN/../../../lib', '$ORIGIN/../lib/private',
                     '$LIB/systemd', '/usr/lib/../lib/x86_64-linux-gnu/systemd',
                     '/usr/lib/x86_64-linux-gnu/systemd:/usr/lib/x86_64-linux-gnu/systemd'):
            with self.subTest(path=path):
                self.compile_private_dependency(path)
                with self.assertRaises(ValueError):
                    self.build()
                self.assertFalse((self.base / 'candidate').exists())

    def test_private_and_standard_soname_collision_refuses_different_bytes(self):
        self.compile_private_dependency('/usr/lib/x86_64-linux-gnu/systemd')
        self.write('usr/lib/x86_64-linux-gnu/libluma-fixture.so', self.platform.read_bytes(), 0o644)
        with self.assertRaisesRegex(ValueError, 'ambiguous ELF dependency'):
            self.build()

    def test_runpath_is_direct_only_but_old_rpath_is_inherited(self):
        self.compile_private_dependency('/usr/lib/x86_64-linux-gnu/systemd', extra_dependency=True)
        with self.assertRaisesRegex(ValueError, 'missing ELF dependency: libluma-leaf'):
            self.build()
        self.compile_private_dependency('/usr/lib/x86_64-linux-gnu/systemd',
                                        old_rpath=True, extra_dependency=True)
        self.build('old-rpath')
        self.compile_private_dependency('/usr/lib/x86_64-linux-gnu/systemd',
                                        library_rpath='$ORIGIN', extra_dependency=True)
        self.build('own-runpath')

    def test_real_systemd_style_loaded_sibling_soname_is_reused_per_executable(self):
        self.compile_private_dependency('/usr/lib/x86_64-linux-gnu/systemd',
                                        extra_dependency=True, direct_sibling=True)
        interpreter, _ = builder.elf(self.platform.read_bytes(), object_path='usr/bin/luma-platform')
        execution = subprocess.run([interpreter, '--inhibit-cache', '--library-path',
                                    str(self.root / 'usr/lib/x86_64-linux-gnu/systemd'), str(self.platform)],
                                   check=False, capture_output=True, timeout=5,
                                   env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        self.assertEqual(execution.returncode, 34, execution.stderr)
        self.assertEqual(execution.stdout, b'')
        self.assertEqual(execution.stderr, b'')
        self.build('sibling')
        # Another executable cannot borrow the first executable's loader state.
        sibling = self.platform.read_bytes()
        self.compile_private_dependency('/usr/lib/x86_64-linux-gnu/systemd', extra_dependency=True)
        # systemd root is traversed first. A wrongly global map would retain
        # its loaded leaf and incorrectly admit the later platform root.
        (self.root / 'usr/lib/systemd/systemd').write_bytes(sibling)
        with self.assertRaisesRegex(ValueError, 'missing ELF dependency: libluma-leaf'):
            self.build('isolated-loader')

    def test_real_compiled_elf_with_both_rpath_and_runpath_refuses_before_output(self):
        self.compile_private_dependency('/usr/lib/x86_64-linux-gnu/systemd')
        value = bytearray(self.platform.read_bytes())
        phoff = struct.unpack_from('<Q', value, 32)[0]
        count = struct.unpack_from('<H', value, 56)[0]
        runpath, debug_slot = None, None
        for index in range(count):
            header = phoff + index * 56
            if struct.unpack_from('<I', value, header)[0] != 2:
                continue
            offset = struct.unpack_from('<Q', value, header + 8)[0]
            size = struct.unpack_from('<Q', value, header + 32)[0]
            for position in range(offset, offset + size, 16):
                tag, item = struct.unpack_from('<qQ', value, position)
                if tag == 29:
                    runpath = item
                elif tag == 21:
                    debug_slot = position
        self.assertIsNotNone(runpath, 'real compiler fixture must carry RUNPATH')
        self.assertIsNotNone(debug_slot, 'real compiler fixture must have a DT_DEBUG slot')
        # Preserve the genuine ELF layout and strings; replace only this
        # nonessential debugger slot with RPATH using the existing path string.
        struct.pack_into('<qQ', value, debug_slot, 15, runpath)
        # readelf requires a real regular input path, never execute the mutant.
        self.platform.write_bytes(value)
        observed = subprocess.run(['readelf', '-d', str(self.platform)], capture_output=True, timeout=5, check=True)
        self.assertIn(b'(RPATH)', observed.stdout)
        self.assertIn(b'(RUNPATH)', observed.stdout)
        with self.assertRaisesRegex(ValueError, 'mixed ELF RPATH and RUNPATH'):
            builder.elf(bytes(value), object_path='usr/bin/luma-platform')
        with self.assertRaisesRegex(ValueError, 'mixed ELF RPATH and RUNPATH'):
            self.build()
        self.assertFalse((self.base / 'candidate').exists())

    def test_closed_origin_policy_rejects_cwd_unknown_tokens_and_escape(self):
        self.assertEqual(builder.runtime_search_paths('$ORIGIN', 'usr/lib/x86_64-linux-gnu/systemd/library.so'),
                         ('usr/lib/x86_64-linux-gnu/systemd',))
        for path in ('relative', 'lib', '$ORIGIN/../../../../../../lib', '${ORIGINX}/lib',
                     '/lib//x86_64-linux-gnu', '/lib/', '$ORIGIN//../lib',
                     '$ORIGIN/missing/../../lib/x86_64-linux-gnu/systemd',
                     '$ORIGIN/./../lib/x86_64-linux-gnu/systemd'):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    builder.runtime_search_paths(path, 'usr/bin/luma-platform')


if __name__ == '__main__':
    unittest.main()
