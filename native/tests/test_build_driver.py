"""Shell-driver orchestration regression; Docker is stubbed, no image is built."""
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux Bash fixture')
class BuildDriverTests(unittest.TestCase):
    def test_edit_during_assembly_cannot_replace_remaining_driver_commands(self):
        self.exercise_driver('standard')

    def test_installed_profile_automatically_selects_external_build_storage(self):
        self.exercise_driver('auto')

    def exercise_driver(self, profile):
        with tempfile.TemporaryDirectory(prefix='luma-build-driver-') as temporary:
            root = Path(temporary)
            driver = root/'repo/native/image/build.sh'
            driver.parent.mkdir(parents=True)
            shutil.copyfile(Path(__file__).resolve().parents[1]/'image/build.sh', driver)
            installed = root/'profile.sh'
            external = root/'external'
            external.mkdir()
            installed.write_text('export LUMA_BUILD_ROOT='+str(external)+'\n'
                                 'export DOCKER_HOST=unix:///run/luma-build-docker.sock\n')
            # Substitute only this temporary driver's profile path; never read
            # or mutate the host's real installed configuration in a unit test.
            driver.write_text(driver.read_text().replace('/etc/luma-build/environment.sh', str(installed)))
            binaries = root/'bin'
            binaries.mkdir()
            # No Docker daemon, archive, package installation, keys or devices.
            # Only shell control flow is exercised. Assembly pauses so this
            # test can replace its disposable script, never the real checkout.
            scripts = {
                'python3': '''import json, os, pathlib, sys
with (pathlib.Path(os.environ['LUMA_DRIVER_FIXTURE'])/'python-calls.jsonl').open('a') as stream:
    stream.write(json.dumps(sys.argv[1:])+'\\n')
''',
                'docker': '''import json, os, pathlib, sys, time
root = pathlib.Path(os.environ['LUMA_DRIVER_FIXTURE'])
(root/'selected-endpoint').write_text(os.environ['DOCKER_HOST'])
with (root/'docker-calls.jsonl').open('a') as stream:
    stream.write(json.dumps(sys.argv[1:])+'\\n')
if '/repo/native/image/assemble.py' in sys.argv:
    (root/'assembly-entered').touch()
    end = time.monotonic()+15
    while not (root/'continue').exists():
        if time.monotonic() > end: sys.exit(88)
        time.sleep(.02)
''',
            }
            for name, body in scripts.items():
                path = binaries/name
                path.write_text('#!'+sys.executable+'\n'+body)
                path.chmod(0o755)
            environment = {**os.environ, 'PATH':str(binaries)+':/usr/bin:/bin',
                           'LUMA_DRIVER_FIXTURE':str(root), 'LUMA_BUILD_ROOT':'',
                           'LUMA_RUNTIME_ARCHIVE':'', 'LUMA_BUILD_NETWORK':'none',
                           'LUMA_BUILD_PROFILE':profile,
                           'DOCKER_HOST':'unix:///var/run/docker.sock'}
            process = subprocess.Popen(['/bin/bash', str(driver), 'headless', '12'],
                                       env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                end = time.monotonic()+15
                while not (root/'assembly-entered').exists():
                    if process.poll() is not None or time.monotonic() > end:
                        self.fail('stub assembly did not start')
                    time.sleep(.02)
                driver.write_text('#!/bin/bash\nexit 99\n')
                (root/'continue').touch()
                stdout, stderr = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 0, stderr.decode())
                self.assertIn(b'Image output: ', stdout)
                self.assertIn(b'Laboratory private keys remain in Docker volume', stdout)
                output_root = external if profile == 'auto' else root/'repo/dist'
                self.assertEqual(len(list((output_root/'native').iterdir())), 1)
                expected_endpoint = 'unix:///run/luma-build-docker.sock' if profile == 'auto' else 'unix:///var/run/docker.sock'
                self.assertEqual((root/'selected-endpoint').read_text(), expected_endpoint)
                calls = [json.loads(line) for line in (root/'python-calls.jsonl').read_text().splitlines()]
                capture = next(args for args in calls if args[0].endswith('/snapshot.py'))
                source = capture[capture.index('--output')+1]
                prepare = next(args for args in calls if args[0].endswith('/prepare_runtime.py'))
                self.assertEqual(prepare[0], source+'/native/image/prepare_runtime.py')
                docker = [json.loads(line) for line in (root/'docker-calls.jsonl').read_text().splitlines()]
                builds = [args for args in docker if args[0] == 'build']
                self.assertEqual(len(builds), 2)
                for args in builds:
                    self.assertTrue(args[args.index('-f')+1].startswith(source+'/native/image/'))
                for helper in ('assemble.py', 'export.py'):
                    args = next(args for args in docker if '/repo/native/image/'+helper in args)
                    self.assertIn('type=bind,src='+source+',dst=/repo,readonly', args)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=20)


if __name__ == '__main__':
    unittest.main()
