"""Pure adversarial audit of the verifier-only instance-template adapter (v2).

Loads install_instance_template_extraction from the exact verifier file given
as argv[1] and drives it with a fake resume module: no image, filesystem or
debugfs is touched. Proves the four exact paths are the only '@' paths
accepted, every ordinary path is delegated unchanged, and bounded single-link
regular-file observation is still required.
"""
import hashlib
import importlib.util
import json
import sys
from types import SimpleNamespace

path = sys.argv[1]
spec = importlib.util.spec_from_file_location('candidate17_verifier_under_audit', path)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

ALLOWED = (
    '/etc/systemd/system/getty@tty1.service.d/luma-mode.conf',
    '/etc/systemd/system/luma-hardware-daemon-observer@.service',
    '/etc/systemd/system/luma-hardware-query@.service',
    '/etc/systemd/system/serial-getty@ttyS0.service.d/luma-mode.conf',
)
GOOD = 'Inode: 12   Type: regular    Mode:  0644   Flags: 0x80000\nUser:     0   Group:     0   Size: 321\nLinks: 1   Blockcount: 8\n'
MIB = 1024 * 1024
cases, failures = 0, []


def fake(output):
    calls = SimpleNamespace(original=[], run=[])
    def original(image, source, maximum):
        calls.original.append((image, source, maximum))
        return 'delegated'
    def run(*argv):
        calls.run.append(argv)
        return output
    resume = SimpleNamespace(ext4_member_size=original, run=run)
    report = verifier.install_instance_template_extraction(resume)
    return resume, calls, report


def expect(label, condition):
    global cases
    cases += 1
    if not condition:
        failures.append(label)


def refuses(label, output, source, maximum):
    resume, calls, _ = fake(output)
    try:
        resume.ext4_member_size('root.ext4', source, maximum)
    except ValueError:
        expect(label, not calls.original)
        return
    expect(label, False)


resume, calls, report = fake(GOOD)
expect('report-exact-allowlist', report['exact_allowed_paths'] == list(ALLOWED))
expect('report-profile-v2', report['profile'] == 'candidate17-fixed-instance-template-extraction-v2')
expect('report-no-source-or-image-change', report['signed_source_or_image_modified'] is False
       and report['ordinary_paths_delegated_unchanged'] is True and report['verifier_compatibility_only'] is True)

for source in ALLOWED:
    resume, calls, _ = fake(GOOD)
    expect('allowed-size ' + source, resume.ext4_member_size('root.ext4', source, 4096) == 321)
    expect('allowed-not-delegated ' + source, not calls.original)
    expect('allowed-exact-stat ' + source, calls.run == [('debugfs', '-R', 'stat ' + source, 'root.ext4')])
    for maximum in (-1, 16 * MIB + 1, True, 4096.0, None, '4096'):
        refuses(f'bad-maximum {maximum!r} {source}', GOOD, source, maximum)
    refuses('size-above-maximum ' + source, GOOD, source, 320)
    for name, output in (
            ('directory', GOOD.replace('Type: regular', 'Type: directory')),
            ('symlink', GOOD.replace('Type: regular', 'Type: symlink')),
            ('regularfile-suffix', GOOD.replace('Type: regular ', 'Type: regularx ')),
            ('two-links', GOOD.replace('Links: 1', 'Links: 2')),
            ('eleven-links', GOOD.replace('Links: 1 ', 'Links: 11 ')),
            ('no-size', GOOD.replace('Size: 321', 'Bytes: 321')),
            ('size-suffix', GOOD.replace('Size: 321', 'Size: 321x')),
            ('empty', ''),
            ('bytes-output', GOOD.encode()),
            ('none-output', None)):
        refuses(f'observation-{name} {source}', output, source, 4096)

near = []
for source in ALLOWED:
    near += [source + '/', source + '.bak', source.upper(), source.replace('/etc/', '/etc//'),
             source.replace('/etc/', '/etc/./'), source.replace('/etc/systemd/', '/etc/systemd/../'),
             source[1:], ' ' + source, source + ' ', source + '\n', source + '\0', source.replace('@', '@@'),
             source.replace('.service', '.socket'), '/usr/lib' + source[4:]]
near += ['/etc/systemd/system/luma-hardware-query@x.service',
         '/etc/systemd/system/luma-hardware-daemon-observer@1.service',
         '/etc/systemd/system/getty@tty2.service.d/luma-mode.conf',
         '/etc/systemd/system/serial-getty@ttyS1.service.d/luma-mode.conf',
         '/etc/systemd/system/multi-user.target.wants/getty@tty1.service',
         '/etc/systemd/system/luma-hardware-query@.service.d/override.conf',
         '/@', '@', '/etc/shadow@', '/root/@/.ssh/id_rsa']
for source in near:
    refuses('near-miss ' + repr(source), GOOD, source, 4096)
for source in (b'/etc/systemd/system/luma-hardware-query@.service', None, 7, ['/x@']):
    resume, calls, _ = fake(GOOD)
    try:
        resume.ext4_member_size('root.ext4', source, 4096)
        expect('non-str ' + repr(source), False)
    except ValueError:
        expect('non-str ' + repr(source), not calls.original and not calls.run)

for source in ('/usr/share/luma-os/release.pub', '/etc/systemd/system/luma-broker.service',
               '/etc/sudoers.d/luma-original-pam', '/usr/libexec/luma-os/luma-platform', '/x'):
    resume, calls, _ = fake(GOOD)
    expect('ordinary-delegated ' + source, resume.ext4_member_size('img', source, 99) == 'delegated'
           and calls.original == [('img', source, 99)] and not calls.run)

result = dict(audit='candidate17-instance-template-adapter-v2-pure-adversarial', verifier=path,
              verifier_sha256=hashlib.sha256(open(path, 'rb').read()).hexdigest(),
              audit_sha256=hashlib.sha256(open(__file__, 'rb').read()).hexdigest(),
              cases=cases, passed=cases - len(failures), failures=failures,
              image_filesystem_or_debugfs_touched=False)
print(json.dumps(result, indent=2, sort_keys=True))
sys.exit(1 if failures else 0)
