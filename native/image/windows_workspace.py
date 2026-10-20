"""Closed, opt-in Windows first-account workspace profile.

This descriptor is deliberately not the compute/inference profile. It permits
one specified account-file transition, not arbitrary mutable account files or
Windows-SID-as-PAM authentication. Construction is data-only; it never creates
an account, imports a distribution, or qualifies the host.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

PROFILE = 'luma-windows-hosted-workspace-v1'
PROFILE_PATH = 'usr/share/luma-os/hosted-workspace.json'
MANIFEST_PATH = 'usr/share/luma-os/hosted-workspace-runtime.json'
BASE = 'usr/share/luma-os/hosted-workspace/accounts'
PLATFORM = 'usr/libexec/luma-os/luma-platform'
AUTH_HELPER = 'usr/libexec/luma-os/luma-workspace-auth-helper'
SHELL = 'bin/bash'
PAM_MODULE = 'usr/lib/x86_64-linux-gnu/security/pam_unix.so'
PAM_PATH = 'etc/pam.d/luma-admin'
NSS_PATH = 'etc/nsswitch.conf'
POLICY = 'etc/apparmor.d/luma-hosted-workspace-bootstrap'
SERVICE = 'etc/systemd/system/luma-hosted-workspace-confinement.service'
ENABLED = 'etc/systemd/system/multi-user.target.wants/luma-hosted-workspace-confinement.service'
PAM = (b'# Local Linux password/account verification, not a product Admin role.\n'
       b'auth required /usr/lib/x86_64-linux-gnu/security/pam_unix.so nodelay\n'
       b'account required /usr/lib/x86_64-linux-gnu/security/pam_unix.so\n')
NSS = b'passwd: files\ngroup: files\nshadow: files\ngshadow: files\nhosts: files\n'
BASELINES = {
    'passwd': (b'root:x:0:0:Locked guest root:/root:/bin/bash\nnobody:x:65534:65534:Inert compute:/nonexistent:/bin/false\n', 0o644),
    'group': (b'root:x:0:\nnogroup:x:65534:\n', 0o644),
    'shadow': (b'root:!:0:0:99999:7:::\nnobody:!:0:0:99999:7:::\n', 0o600),
    'gshadow': (b'root:!::\nnogroup:!::\n', 0o600),
}
PURPOSE_SECONDS = 30
CPU_SECONDS = 25
DRAIN_SECONDS = 5
UNIT = b'''[Unit]
Description=Luma hosted first-account workspace confinement
DefaultDependencies=no
After=systemd-remount-fs.service
Before=multi-user.target
ConditionSecurity=apparmor

[Service]
Type=oneshot
ExecStart=/usr/sbin/apparmor_parser --add --skip-cache /etc/apparmor.d/luma-hosted-workspace-bootstrap
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


def digest(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value) or value == '0'*64:
        raise ValueError('exact nonzero lowercase SHA256 required')
    return value


def login(value):
    if not isinstance(value, str) or not re.fullmatch('[a-z][a-z0-9_-]{0,30}', value) or value in ('root', 'nobody', 'nogroup'):
        raise ValueError('new canonical nonroot account required')
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)+'\n').encode('ascii')


def closed(raw, maximum=32768):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= maximum:
        raise ValueError('workspace JSON exceeds its fixed byte bound')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate workspace field')
            result[key] = value
        return result
    def nonfinite(_value):
        raise ValueError('nonfinite workspace value')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def profile(runtime_sha256):
    return dict(schema_version=3, profile=PROFILE, runtime='luma-windows-manual-workspace-v1',
                runtime_manifest_sha256=digest(runtime_sha256), default_uid=65534, wsl_flags=0,
                account_uid=1000, account_gid=1000, account_generation=1, password_max_age_days=90,
                bootstrap_purpose_seconds=PURPOSE_SECONDS, bootstrap_cpu_seconds=CPU_SECONDS,
                drain_seconds=DRAIN_SECONDS, memory_max_bytes=268435456, memory_swap_max_bytes=0,
                tasks_max=8, cpu_quota_usec=100000, cpu_period_usec=100000,
                account_baselines={name: hashlib.sha256(data).hexdigest() for name, (data, _mode) in BASELINES.items()},
                pam_sha256=hashlib.sha256(PAM).hexdigest(), nss_sha256=hashlib.sha256(NSS).hexdigest())


def validate_profile(raw, runtime_sha256):
    value = closed(raw)
    expected = profile(runtime_sha256)
    # bool is an int in Python; byte-canonical equality also closes that hole.
    if value != expected or encoded(value) != encoded(expected) or raw != encoded(expected):
        raise ValueError('workspace profile is not the exact canonical reviewed profile')
    return value


def request(raw):
    value = closed(raw)
    names = {'schema_version', 'profile', 'nonce', 'installation', 'release_sha256',
             'runtime_manifest_sha256', 'profile_sha256', 'actor_sid_sha256', 'login',
             'uid', 'gid', 'account_generation', 'protected_utc_day', 'utc_proof_sha256'}
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError('workspace request fields differ')
    for name in ('nonce', 'installation', 'release_sha256', 'runtime_manifest_sha256',
                 'profile_sha256', 'actor_sid_sha256', 'utc_proof_sha256'):
        digest(value[name])
    login(value['login'])
    for name, expected in (('schema_version', 1), ('uid', 1000), ('gid', 1000), ('account_generation', 1)):
        if type(value[name]) is not int or value[name] != expected:
            raise ValueError('workspace request changes the one-account generation')
    if value['profile'] != PROFILE or type(value['protected_utc_day']) is not int or not 1 <= value['protected_utc_day'] <= 2932896:
        raise ValueError('workspace protected UTC day/profile differs')
    if raw != encoded(value):
        raise ValueError('workspace request must use canonical sorted ASCII JSON and one LF')
    return value


def runtime_manifest(raw):
    value = closed(raw)
    if not isinstance(value, dict) or set(value) != {'schema_version', 'profile', 'files'} or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['profile'] != PROFILE:
        raise ValueError('workspace runtime manifest identity differs')
    files = value['files']
    if not isinstance(files, list) or not 5 <= len(files) <= 64:
        raise ValueError('workspace runtime closure is outside its bound')
    paths = []
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {'path', 'bytes', 'sha256', 'executable'}:
            raise ValueError('workspace runtime member fields differ')
        path = entry['path']
        if not isinstance(path, str) or not re.fullmatch('[a-zA-Z0-9_+./-]{1,240}', path) or path.startswith('/') or any(part in ('', '.', '..') for part in path.split('/')):
            raise ValueError('workspace runtime member path escapes its root')
        if path not in (PLATFORM, AUTH_HELPER, PAM_MODULE, SHELL) and not (path.startswith(('usr/lib/x86_64-linux-gnu/', 'usr/lib64/', 'lib/x86_64-linux-gnu/', 'lib64/')) and '/security/' not in path and '.so' in path.rsplit('/', 1)[-1]):
            raise ValueError('workspace runtime contains an undeclared executable/module family')
        if type(entry['bytes']) is not int or not 64 <= entry['bytes'] <= 64*1024**2 or type(entry['executable']) is not bool:
            raise ValueError('workspace runtime member length/mode differs')
        if path in (PLATFORM, AUTH_HELPER, SHELL) and not entry['executable']:
            raise ValueError('workspace fixed worker/helper is not executable')
        digest(entry['sha256'])
        paths.append(path)
    if paths != sorted(set(paths)) or not {PLATFORM, AUTH_HELPER, PAM_MODULE, SHELL} <= set(paths):
        raise ValueError('workspace runtime is ambiguous or omits the real PAM/worker closure')
    if raw != encoded(value):
        raise ValueError('workspace runtime manifest is not canonical')
    return value


def required_files(runtime_raw):
    """Exact additional publisher pins, not an approval to trust supplied bytes."""
    manifest = runtime_manifest(runtime_raw)
    return tuple(sorted({PROFILE_PATH, MANIFEST_PATH, PAM_PATH, NSS_PATH, POLICY, SERVICE, ENABLED,
                         *(BASE+'/'+name for name in BASELINES),
                         *(item['path'] for item in manifest['files'])}))


def generated(runtime_raw):
    """Exact data members for a new opt-in package; never alter an old profile."""
    runtime_manifest(runtime_raw)
    return {PROFILE_PATH: (encoded(profile(hashlib.sha256(runtime_raw).hexdigest())), 0o644),
            MANIFEST_PATH: (runtime_raw, 0o644), PAM_PATH: (PAM, 0o644), NSS_PATH: (NSS, 0o644),
            SERVICE: (UNIT, 0o644), ENABLED: (UNIT, 0o644),
            **{BASE+'/'+name: (raw, 0o644) for name, (raw, _mode) in BASELINES.items()}}


def components():
    """Load the existing held-tree/ELF primitives without importing a package CLI."""
    here=Path(__file__).parent
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,here/path)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    return load('luma_workspace_package','windows_package.py'),load('luma_workspace_elf','windows_inference.py'),load('luma_workspace_hosted','windows_hosted.py')


def compose(root,source_root,auth_helper=None):
    """Capture the actual fixed worker/shell/PAM ELF closure into fresh staging.

    The supplied root must already contain the closed compute base. Existing
    differing bytes are never overwritten; a failed stage is retained. No
    guest executable, helper, shell, or PAM module is run by composition.
    """
    if os.geteuid()!=0:
        raise ValueError('workspace composition requires isolated root-owned Linux build')
    root=Path(os.path.abspath(root))
    if root==Path('/') or str(root).startswith('/mnt/c/') or root==Path('/mnt/c'):
        raise ValueError('workspace composition requires a narrow external Linux staging root')
    package,inference,hosted=components()
    target=source=helper_tree=None
    try:
        target=package.Tree(root)
        source=package.Tree(source_root)
        for name,(expected,_mode) in BASELINES.items():
            if target.read('etc/'+name,32768)!=expected:
                raise ValueError('new workspace requires the exact empty-account compute baseline')
        for path in (PROFILE_PATH,MANIFEST_PATH,AUTH_HELPER,BASE,POLICY,SERVICE,ENABLED):
            try:
                with target.opened(path):
                    raise ValueError('workspace opt-in destination already exists: '+path)
            except FileNotFoundError:
                pass
        if auth_helper is not None:
            helper_path=Path(auth_helper).absolute()
            helper_tree=package.Tree(helper_path.parent)
            helper=inference.source_elf(helper_tree,helper_path.name)
        else:
            helper=inference.source_elf(source,'usr/libexec/luma-os/luma-auth-helper')
        data={PLATFORM:inference.source_elf(target,PLATFORM),
              AUTH_HELPER:helper,
              SHELL:inference.source_elf(source,'usr/bin/bash'),
              PAM_MODULE:inference.source_elf(source,PAM_MODULE)}
        queue=list(data)
        checked=set()
        while queue:
            name=queue.pop()
            if name in checked:
                continue
            checked.add(name)
            if len(checked)>64:
                raise ValueError('workspace ELF closure exceeds its fixed member bound')
            interpreter,needed,search=package.elf(data[name][0],require_entry=name in (PLATFORM,AUTH_HELPER,SHELL),object_path=name,details=True)
            folders=tuple(dict.fromkeys((*(search['runpath'] or search['rpath']),*package.LIB_DIRS)))
            dependencies=[interpreter[1:]] if interpreter else []
            for soname in needed:
                candidates=[]
                for folder in folders:
                    candidate=folder+'/'+soname
                    if candidate in data:
                        value=data[candidate][0]
                    else:
                        try:
                            value,_mode=inference.source_elf(source,candidate)
                        except FileNotFoundError:
                            continue
                    candidates.append((candidate,value))
                if not candidates or len({hashlib.sha256(value).digest() for _name,value in candidates})!=1:
                    raise ValueError('workspace ELF dependency is missing/ambiguous: '+soname)
                selected,value=candidates[0]
                metadata=package.elf(value,object_path=selected,details=True)[2]
                if metadata['soname'] not in (None,soname):
                    raise ValueError('workspace ELF dependency SONAME differs')
                if selected not in data:
                    captured,mode=inference.source_elf(source,selected)
                    if captured!=value:
                        raise ValueError('workspace dependency changed during held resolution')
                    data[selected]=(captured,mode)
                dependencies.append(selected)
            for dependency in dependencies:
                if dependency not in data:
                    data[dependency]=inference.source_elf(source,dependency)
                queue.append(dependency)
        records=[]
        for name,(raw,mode) in sorted(data.items()):
            try:
                current=target.read(name,package.MAX_ELF)
            except FileNotFoundError:
                inference.write_new(target,name,raw,mode)
            else:
                if current!=raw:
                    raise ValueError('workspace ELF conflicts with existing staged userland')
            with target.opened(name) as (_fd,info):
                executable=bool(info.st_mode&0o111)
            records.append(dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),executable=executable))
        runtime_raw=encoded(dict(schema_version=1,profile=PROFILE,files=records))
        runtime_manifest(runtime_raw)
        policy=hosted.preprocess_policy(POLICY)
        for name,(raw,mode) in {**generated(runtime_raw),POLICY:(policy,0o644)}.items():
            try:
                current=target.read(name,max(len(raw),32768))
            except FileNotFoundError:
                inference.write_new(target,name,raw,mode)
            else:
                if current!=raw:
                    raise ValueError('workspace configuration conflicts with an existing staged profile')
        return dict(schema_version=1,profile=PROFILE,runtime_manifest_sha256=hashlib.sha256(runtime_raw).hexdigest(),
                    profile_sha256=hashlib.sha256(generated(runtime_raw)[PROFILE_PATH][0]).hexdigest(),
                    runtime_files=len(records),account_created=False,pam_authenticated=False,
                    package_authenticated=False,guest_confinement_qualified=False,production_qualified=False)
    finally:
        for tree in (helper_tree,source,target):
            if tree is not None:
                tree.close()


def validate(data_at,entries,tree):
    """Validate exact initial package bytes; never accept a post-bootstrap tar."""
    package,_inference,hosted=components()
    runtime_raw=data_at(MANIFEST_PATH)
    manifest=runtime_manifest(runtime_raw)
    validate_profile(data_at(PROFILE_PATH),hashlib.sha256(runtime_raw).hexdigest())
    required=set(required_files(runtime_raw))
    for name,(expected,mode) in {**generated(runtime_raw),**{'etc/'+name:(raw,mode) for name,(raw,mode) in BASELINES.items()}}.items():
        if data_at(name)!=expected or name not in entries or entries[name][0] or entries[name][1]!=mode:
            raise ValueError('workspace initial account/PAM/configuration bytes/mode differ')
    for member in manifest['files']:
        name=member['path']
        if name not in entries or entries[name][0] or bool(entries[name][1]&0o111)!=member['executable']:
            raise ValueError('workspace actual runtime inventory/mode differs')
        value=data_at(name)
        if len(value)!=member['bytes'] or hashlib.sha256(value).hexdigest()!=member['sha256']:
            raise ValueError('workspace actual runtime full bytes differ')
        package.elf(value,object_path=name,require_entry=name in (PLATFORM,AUTH_HELPER,SHELL))
    policy=data_at(POLICY)
    if not 1<=len(policy)<=1024**2 or hosted.unresolved_includes(policy) or b'profile luma-hosted-workspace-bootstrap ' not in policy or b'deny network,' not in policy or b'capability chown,' not in policy:
        raise ValueError('workspace enforcing preprocessed confinement differs')
    return required


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',required=True,type=Path)
    parser.add_argument('--source-root',required=True,type=Path)
    parser.add_argument('--auth-helper',type=Path)
    args=parser.parse_args()
    print(encoded(compose(args.root,args.source_root,args.auth_helper)).decode('ascii'),end='')
