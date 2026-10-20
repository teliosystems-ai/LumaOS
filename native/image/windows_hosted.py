"""Closed compute-only Windows guest composition; never guest authority.

The build-time parser is the pinned tools image's parser. It only preprocesses
policy; no kernel policy is loaded here and no captured guest program is run.
"""
from pathlib import Path
import re
import stat
import subprocess

PROFILE = 'luma-windows-hosted-compute-v1'
BINARIES = ('usr/bin/systemd-run', 'usr/sbin/apparmor_parser')
PLATFORM = 'usr/libexec/luma-os/luma-platform'
POLICY = 'etc/apparmor.d/luma-hosted-compute'
SERVICE = 'etc/systemd/system/luma-hosted-confinement.service'
ENABLED = 'etc/systemd/system/multi-user.target.wants/luma-hosted-confinement.service'
UNIT = b'''[Unit]
Description=Luma hosted inert compute confinement
DefaultDependencies=no
After=systemd-remount-fs.service
Before=multi-user.target
ConditionSecurity=apparmor

[Service]
Type=oneshot
ExecStart=/usr/sbin/apparmor_parser --add --skip-cache /etc/apparmor.d/luma-hosted-compute
RemainAfterExit=yes
TimeoutStartSec=15
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_MAC_ADMIN
AmbientCapabilities=
ProtectHome=yes
PrivateTmp=yes
ProtectSystem=strict
RestrictAddressFamilies=AF_UNIX

[Install]
WantedBy=multi-user.target
'''
GENERATED = {
    'etc/passwd': (b'root:x:0:0:Locked guest root:/root:/bin/bash\nnobody:x:65534:65534:Inert compute:/nonexistent:/bin/false\n', 0o644),
    'etc/group': (b'root:x:0:\nnogroup:x:65534:\n', 0o644),
    'etc/shadow': (b'root:!:0:0:99999:7:::\nnobody:!:0:0:99999:7:::\n', 0o600),
    'etc/gshadow': (b'root:!::\nnogroup:!::\n', 0o600),
    SERVICE: (UNIT, 0o644),
    ENABLED: (UNIT, 0o644),
}


def unresolved_includes(data):
    # The real parser emits harmless `##included ...` audit comments. Only an
    # actual directive (including the bare `include` form) is unresolved.
    return re.search(rb'(?m)^[ \t]*(?:#[ \t]*)?include(?:[ \t]|$)', data) is not None


def preprocess_policy(policy=POLICY):
    if policy not in (POLICY, 'etc/apparmor.d/luma-hosted-inference'):
        raise ValueError('only the fixed compute and inference policies may be preprocessed')
    parser = Path('/usr/sbin/apparmor_parser')
    for path in (parser, *parser.parents):
        metadata = path.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('build policy parser path is not root protected')
    metadata = parser.stat()
    if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
        raise ValueError('build policy parser is not an installed executable')
    source = Path(__file__).with_name('overlay') / policy
    data = source.read_bytes()
    if not 1 <= len(data) <= 16384 or source.is_symlink():
        raise ValueError('closed hosted policy source refused')
    # stdout is capped by a real regular-file size limit, not unbounded capture.
    import resource
    import tempfile
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        def bounds():
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
        completed = subprocess.run([str(parser), '--preprocess', '--skip-cache',
            '--base', '/etc/apparmor.d', str(source)], stdin=subprocess.DEVNULL,
            stdout=output, stderr=errors, timeout=15, check=False,
            env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'}, preexec_fn=bounds)
        if completed.returncode != 0:
            raise ValueError('pinned build parser refused hosted policy preprocessing')
        output.seek(0)
        expanded = output.read(1024 * 1024 + 1)
    if not 1 <= len(expanded) <= 1024 * 1024 or unresolved_includes(expanded):
        raise ValueError('hosted policy preprocessing is incomplete or exceeds bound')
    if source.read_bytes() != data:
        raise ValueError('hosted policy changed during preprocessing')
    return expanded


def validate(data_at, entries, binary):
    for path, (expected, mode) in GENERATED.items():
        selected = entries.get(path)
        if selected is None or selected[0] or selected[1] != mode or data_at(path) != expected:
            raise ValueError('hosted guest fixed account/confinement configuration differs: ' + path)
    if data_at(PLATFORM) != binary or entries[PLATFORM][1] != 0o755:
        raise ValueError('hosted guest platform alias is not the exact compiled ELF')
    policy = data_at(POLICY)
    if (entries[POLICY][1] != 0o644 or len(policy) > 1024 * 1024 or
            unresolved_includes(policy) or b'profile luma-hosted-compute ' not in policy or
            b'deny network,' not in policy):
        raise ValueError('hosted guest policy is not a complete closed preprocessed input')
