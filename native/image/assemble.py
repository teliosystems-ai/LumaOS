#!/usr/bin/env python3
"""Assemble laboratory UEFI media in an isolated container-owned /work volume.

Only regular image files are partitioned. This builder never opens a host disk.
Private laboratory keys stay in the separate /keys volume, outside output/source.
"""
from __future__ import annotations
import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

# Imports run from the captured source tree. Interpreter caches are not product
# inputs and must never appear in its corresponding source archive.
sys.dont_write_bytecode = True

MIB = 1024 * 1024
REPO = Path('/repo')
WORK = Path('/work')
ROOT = WORK / 'root'
OUT = WORK / 'artifacts'
KEYS = Path('/keys')

# The fixed product launcher creates its own confined PAM PTY. A second sudo
# PTY would replace the original kernel terminal owner before source capture.
# This command-scoped default adds no command or privilege authorization.
ORIGINAL_PAM_SUDOERS = '''Cmnd_Alias LUMA_ORIGINAL_PAM = /usr/libexec/luma-os/luma-platform granted-run *
Defaults!LUMA_ORIGINAL_PAM !use_pty
'''


def run(*args: str | Path, **kwargs) -> str:
    result = subprocess.run([str(a) for a in args], check=True, text=True,
                            stdout=subprocess.PIPE, **kwargs)
    return result.stdout


def put(relative: str, data: str, mode: int = 0o644) -> None:
    destination = ROOT / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        destination.unlink()
    destination.write_text(data, encoding='utf-8')
    destination.chmod(mode)


def configure_original_pam_sudoers() -> None:
    put('etc/sudoers.d/luma-original-pam', ORIGINAL_PAM_SUDOERS, 0o440)


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def sparse_copy(source: Path, destination: Path, offset: int = 0) -> None:
    with source.open('rb') as src, destination.open('r+b') as dst:
        dst.seek(offset)
        while block := src.read(MIB):
            if block.count(0) == len(block):
                dst.seek(len(block), 1)
            else:
                dst.write(block)
        dst.flush()
        os.fsync(dst.fileno())


def enable(unit: str, target: str = 'multi-user.target') -> None:
    wanted = ROOT / f'etc/systemd/system/{target}.wants'
    wanted.mkdir(parents=True, exist_ok=True)
    link = wanted / unit
    if not link.exists():
        link.symlink_to('../' + unit)


def stage_payload_member(source: Path, destination: Path) -> None:
    # External artifacts may lack hardlinks or be on a different filesystem.
    try:
        os.link(source, destination)
    except OSError as error:
        if error.errno not in (errno.EXDEV, errno.EOPNOTSUPP, errno.ENOSYS):
            raise
        with destination.open('xb') as stream:
            stream.truncate(source.stat().st_size)
        sparse_copy(source, destination)
        if digest(source) != digest(destination):
            raise RuntimeError('payload staging digest mismatch')


def release_payload_staging(directory: Path, source: Path, names) -> None:
    """Unlink only verified generated aliases after payload image verification."""
    allowed={'root.ext4','root.verity','slot-a.efi','slot-b.efi','bootloader.efi','secureboot.cer',
             'release.json','release.sig','packages.lock','release-trust.json'}
    if (os.geteuid()!=0 or directory != WORK/'payload' or source != OUT
            or not names or not set(names)<=allowed or len(names)!=len(set(names))):
        raise ValueError('payload cleanup requires the exact generated private staging directory')
    dirs=[];files=[]
    def witness(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
                info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    def check_dirs():
        for path,fd,expected in dirs:
            if witness(os.fstat(fd))[:5]!=expected or witness(path.lstat())[:5]!=expected:
                raise ValueError('protected payload staging namespace changed')
    try:
        for path in (directory,source):
            for parent in (path,*path.parents):
                info=parent.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
                    raise ValueError('payload cleanup requires root-owned protected ancestors')
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            dirs.append((path,fd,witness(os.fstat(fd))[:5]))
        check_dirs();target_fd,source_fd=dirs[0][1],dirs[1][1]
        if set(os.listdir(target_fd))!=set(names):
            raise ValueError('payload staging contains an unknown or missing member')
        for name in names:
            pair=[]
            for parent in (source_fd,target_fd):
                fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                info=witness(os.fstat(fd));files.append((name,parent,fd,info));pair.append(files[-1])
                if not stat.S_ISREG(info[2]) or info[3]!=0 or info[2]&0o022:
                    raise ValueError('payload cleanup refuses writable, foreign or special members')
            same=pair[0][3][:2]==pair[1][3][:2]
            expected_links=2 if same else 1
            if any(item[3][5]!=expected_links for item in pair) or pair[0][3][6]!=pair[1][3][6]:
                raise ValueError('payload cleanup refuses unreviewed link aliases or different lengths')
            hashes=[]
            for _,_,fd,_ in pair:
                with os.fdopen(os.dup(fd),'rb') as stream:hashes.append(hashlib.file_digest(stream,'sha256').digest())
            if hashes[0]!=hashes[1]:raise ValueError('payload staging differs from preserved exact source bytes')
        check_dirs()
        if set(os.listdir(target_fd))!=set(names):raise ValueError('payload staging inventory changed before unlink')
        for name,parent,fd,expected in files:
            if witness(os.fstat(fd))!=expected or witness(os.stat(name,dir_fd=parent,follow_symlinks=False))!=expected:
                raise ValueError('payload staged member substituted or changed before unlink')
        # No recursive deletion; OUT originals and verified payload.ext4 remain.
        for name in names:
            check_dirs();os.unlink(name,dir_fd=target_fd)
        for name,parent,fd,expected in files[::2]:
            now=witness(os.fstat(fd));named=witness(os.stat(name,dir_fd=parent,follow_symlinks=False))
            if now!=named or now[:5]!=expected[:5] or now[5]!=1 or now[6:8]!=expected[6:8]:
                raise ValueError('preserved original payload source did not survive staging release')
        check_dirs();os.fsync(target_fd);os.fsync(source_fd);directory.rmdir()
    finally:
        for _,_,fd,_ in reversed(files):os.close(fd)
        for _,fd,_ in reversed(dirs):os.close(fd)


def package_skill_registry(root: Path, keys: Path) -> None:
    """Package one inert lab registry under a trust root distinct from release."""
    skill_key = keys/'skills-lab.key'
    if skill_key.is_symlink():
        raise SystemExit('skill signing key must not be a symbolic link')
    if not skill_key.exists():
        run('openssl','genpkey','-algorithm','ED25519','-out',skill_key)
        skill_key.chmod(0o600)
    key_stat = skill_key.stat()
    if (not stat.S_ISREG(key_stat.st_mode) or key_stat.st_uid != os.geteuid()
            or key_stat.st_mode & 0o077):
        raise SystemExit('skill signing key must be an owned private regular file')
    skills_dir = root/'usr/share/luma-os/skills'
    skills_dir.mkdir(mode=0o755, exist_ok=True)
    skill_pub = skills_dir/'skills.pub'
    run('openssl','pkey','-in',skill_key,'-pubout','-out',skill_pub)
    if skill_pub.read_bytes() == (root/'usr/share/luma-os/release.pub').read_bytes():
        raise SystemExit('skill and release signing keys must be distinct')
    workflow = root/'usr/share/luma-os/workflows/file-to-artifact-v1.json'
    if workflow.is_symlink() or not workflow.is_file():
        raise SystemExit('missing image-owned skill workflow')
    registry = {
        'schema_version':1,'environment':'lab','profile':'file-to-artifact-v1',
        'workflow_sha256':digest(workflow),
        'skills':[
            {'id':'file-read','input_types':[],'output_type':'text'},
            {'id':'deterministic-calculate','input_types':['text'],'output_type':'report'},
            {'id':'artifact-write','input_types':['report'],'output_type':'artifact'},
        ],
    }
    registry_file = skills_dir/'registry.json'
    registry_file.write_text(json.dumps(registry,separators=(',',':'))+'\n',encoding='utf-8')
    registry_file.chmod(0o644)
    run('openssl','pkeyutl','-sign','-rawin','-inkey',skill_key,
        '-in',registry_file,'-out',skills_dir/'registry.sig')
    (skills_dir/'registry.sig').chmod(0o644)


def package_protected_utc(root: Path, source: Path, work: Path) -> None:
    """Build the release candidate; never seed, run or certify a host clock."""
    assets = source/'native/image/utc'
    package = work/'utc-package'
    run('bash', assets/'build_release.sh', '/inputs/chrony-4.9.tar.gz',
        work/'utc-build', package)
    target = root/'usr/share/luma-os/utc'
    target.mkdir(parents=True, exist_ok=True)
    for name in ('chrony.conf', 'approved-policy.json'):
        shutil.copy2(assets/name, target/name)
        (target/name).chmod(0o644)
    shutil.copy2(root/'etc/ssl/certs/ca-certificates.crt', target/'ca-certificates.crt')
    (target/'ca-certificates.crt').chmod(0o644)
    for name in ('COPYING.chrony', 'source-inputs.json', 'build-packages.tsv', 'SHA256SUMS',
                 'version.txt', 'upstream-provenance.json'):
        shutil.copy2(package/name, target/name)
        (target/name).chmod(0o644)
    corresponding = target/'source'
    corresponding.mkdir()
    shutil.copy2(package/'chrony-4.9.tar.gz', corresponding/'chrony-4.9.tar.gz')
    shutil.copy2(package/'chrony-4.9.tar.gz.asc', corresponding/'chrony-4.9.tar.gz.asc')
    shutil.copy2(package/'upstream-provenance.json', corresponding/'chrony-4.9.provenance.json')
    for name in ('prepare_chrony.py', 'prepare_release_input.py', 'verify_release.py',
                 'upstream-signing-key.asc', 'build_release.sh', 'publisher.c', 'publisher.h',
                 'chrony_hook.c', 'chrony_hook.h', 'approved-policy.json',
                 'reviewed-release.json', 'reviewed-source-inputs.json',
                 'test_release_authentication.py', 'test_release_units.py'):
        shutil.copy2(assets/name, corresponding/name)
    for member in corresponding.iterdir():
        member.chmod(0o644)
    executable = root/'usr/libexec/luma-os/chronyd'
    shutil.copy2(package/'chronyd', executable)
    executable.chmod(0o755)
    vendor = root/'usr/lib/systemd/system'
    vendor.mkdir(parents=True, exist_ok=True)
    for unit in ('luma-utc-keeper.service', 'luma-utc-producer.service', 'luma-utc-producer.path',
                 'luma-utc-recovery-keeper.service', 'luma-utc-recovery-producer.service',
                 'luma-utc-recovery-producer.path'):
        shutil.copy2(assets/unit, vendor/unit)
        (vendor/unit).chmod(0o644)
    system = root/'etc/systemd/system'
    for unit in ('systemd-timesyncd.service', 'chrony.service', 'ntp.service'):
        mask = system/unit
        if mask.exists() or mask.is_symlink():
            mask.unlink()
        mask.symlink_to('/dev/null')
    wanted = system/'multi-user.target.wants'
    wanted.mkdir(parents=True, exist_ok=True)
    for unit in ('luma-utc-keeper.service', 'luma-utc-producer.path',
                 'luma-utc-recovery-keeper.service', 'luma-utc-recovery-producer.path'):
        link = wanted/unit
        if link.exists() or link.is_symlink():
            raise SystemExit('unexpected pre-enabled UTC unit: '+unit)
        link.symlink_to('/usr/lib/systemd/system/'+unit)
    run('python3', assets/'package_runtime.py', '--root', root)


def main() -> None:
    global REPO
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--edition', choices=('headless','desktop'), default='headless')
    parser.add_argument('--sequence', type=int, default=1)
    parser.add_argument('--environment', choices=('lab', 'production'), default='lab')
    parser.add_argument('--release-id', help='owner-selected production release identity')
    parser.add_argument('--production-public-inputs', type=Path,
                        help='public-only OS trust, delegated signer, Secure Boot certificate and PCR public key')
    parser.add_argument('--external-artifacts', action='store_true')
    parser.add_argument('--public-trust-inputs', type=Path,
                        help='independently signed public roots and inert skill admissions; never private keys')
    parser.add_argument('--model-public-inputs', type=Path,
                        help='externally signed frozen model roots/trust/catalog, pack metadata and certificates; no weights or private keys')
    args = parser.parse_args()
    if os.uname().machine != 'x86_64' or run('dpkg','--print-architecture').strip() != 'amd64':
        raise SystemExit('native image assembly requires the amd64 toolchain container')
    if ROOT.resolve() != Path('/work/root') or not (ROOT / 'etc/os-release').exists():
        raise SystemExit('a fresh exported Ubuntu root must exist at /work/root')
    if args.external_artifacts:
        if OUT.is_symlink() or not OUT.is_mount() or not OUT.is_dir() or any(OUT.iterdir()):
            raise SystemExit('external artifacts must be a fresh empty mount at /work/artifacts')
    elif OUT.exists():
        raise SystemExit('artifacts directory exists; use a fresh build volume')
    if not 1 <= args.sequence <= 2**63-1:
        raise SystemExit('sequence must be a positive signed 64-bit integer')
    if not args.external_artifacts:OUT.mkdir()
    from assembly_storage import require_ext4
    require_ext4(OUT)
    if args.environment == 'production':
        if args.production_public_inputs is None or args.public_trust_inputs is None or args.model_public_inputs is None:
            raise SystemExit('production assembly requires independently provisioned public OS, skill and model inputs')
        if KEYS.exists():
            raise SystemExit('production assembly must not mount or create a private-key volume')
    elif args.production_public_inputs is not None or args.release_id is not None:
        raise SystemExit('production custody inputs/release override cannot select laboratory signing')
    else:
        KEYS.mkdir(mode=0o700, exist_ok=True)
        if KEYS.is_symlink() or not KEYS.is_dir() or KEYS.stat().st_uid != os.geteuid():
            raise SystemExit('laboratory key volume must be an owned directory, not a link')
    # Docker creates a fresh volume root with 0755; restrict directory access
    # before generating any key. Existing private key files are not repaired.
    if args.environment == 'lab':
        KEYS.chmod(0o700)
    release = (f'luma-native-lab-20260927-{args.edition}-{args.sequence}'
               if args.environment == 'lab' else
               args.release_id or f'luma-native-production-20260927-{args.edition}-{args.sequence}')
    if not 1 <= len(release) <= 64 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_' for c in release):
        raise SystemExit('release identity must be finite ASCII alphanumeric .-_')
    print(f'Assembling {release}', flush=True)
    inputs=[]
    snapshot=WORK/'source'
    snapshot.mkdir()
    for folder in ('rust','native/image','native/desktop','native/utc','src','web','schemas','examples','docs/adr','scripts'):
        for source in sorted((REPO/folder).rglob('*')):
            if source.is_file() and not any(p in ('target','__pycache__') for p in source.relative_to(REPO).parts):
                if source.is_symlink():raise SystemExit('source snapshot refuses symbolic links')
                relative=source.relative_to(REPO)
                frozen=snapshot/relative
                frozen.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(source,frozen)
                frozen.chmod(0o755 if frozen.suffix=='.sh' else 0o644)
                inputs.append({'path':relative.as_posix(),
                               'bytes':frozen.stat().st_size,'sha256':digest(frozen)})
    shutil.copy2(REPO/'LICENSE',snapshot/'LICENSE')
    (snapshot/'LICENSE').chmod(0o644)
    inputs.append({'path':'LICENSE','bytes':(snapshot/'LICENSE').stat().st_size,'sha256':digest(snapshot/'LICENSE')})
    inputs.sort(key=lambda entry:entry['path'])
    # Everything compiled or copied below comes from these captured bytes, not
    # from a mutable workspace that may change while a long build is running.
    REPO=snapshot
    sys.path.insert(0, str(REPO/'native/image'))
    import boot_policy
    import desktop_policy
    import qemu_policy
    import office_policy
    source_lock=json.dumps({'schema_version':1,'files':inputs},sort_keys=True,indent=2)+'\n'
    (OUT/'source-lock.json').write_text(source_lock)
    put('usr/share/luma-os/source-lock.json',source_lock)
    run('tar','--sort=name','--mtime=@0','--owner=0','--group=0','--numeric-owner',
        '-I','zstd -T2 -3','-cf',OUT/'native-source.tar.zst','-C',snapshot,'.')
    # Compiler and Rust dependencies come from the authenticated Ubuntu snapshot.
    run('cargo','build','--offline','--locked','--release','--target-dir','/work/cargo',cwd=REPO/'rust')
    binary = ROOT / 'usr/libexec/luma-os/luma-platform'
    binary.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(WORK/'cargo/release/luma-platform',binary)
    binary.chmod(0o755)
    helpers = list((WORK/'cargo/release/build').glob('luma-platform-*/out/luma-auth-helper'))
    if len(helpers) != 1:
        raise SystemExit('expected one freshly compiled PAM authentication helper')
    auth_helper = binary.parent/'luma-auth-helper'
    shutil.copy2(helpers[0], auth_helper)
    auth_helper.chmod(0o700)  # Never setuid; only the trusted root process calls it.
    supervisors = list((WORK/'cargo/release/build').glob('luma-platform-*/out/luma-utc-restart'))
    if len(supervisors) != 1:
        raise SystemExit('expected one freshly compiled fixed UTC supervisor')
    supervisor = binary.parent/'luma-utc-restart'
    shutil.copy2(supervisors[0], supervisor)
    supervisor.chmod(0o700)
    recovery_supervisors = list((WORK/'cargo/release/build').glob(
        'luma-platform-*/out/luma-utc-recovery-restart'))
    if len(recovery_supervisors) != 1:
        raise SystemExit('expected one freshly compiled fixed recovery UTC supervisor')
    recovery_supervisor = binary.parent/'luma-utc-recovery-restart'
    shutil.copy2(recovery_supervisors[0], recovery_supervisor)
    recovery_supervisor.chmod(0o700)
    crypto_helpers = list((WORK/'cargo/release/build').glob(
        'luma-platform-*/out/luma-backup-crypto'))
    if len(crypto_helpers) != 1:
        raise SystemExit('expected one freshly compiled fixed backup crypto helper')
    crypto_helper = binary.parent/'luma-backup-crypto'
    shutil.copy2(crypto_helpers[0], crypto_helper)
    crypto_helper.chmod(0o755)
    receipt_helpers = list((WORK/'cargo/release/build').glob(
        'luma-platform-*/out/luma-receipt-signer'))
    if len(receipt_helpers) != 1:
        raise SystemExit('expected one freshly compiled fixed content receipt signer')
    receipt_helper = binary.parent/'luma-receipt-signer'
    shutil.copy2(receipt_helpers[0], receipt_helper)
    receipt_helper.chmod(0o755)
    utc_crypto_helpers = list((WORK/'cargo/release/build').glob(
        'luma-platform-*/out/luma-utc-windows-crypto'))
    if len(utc_crypto_helpers) != 1:
        raise SystemExit('expected one freshly compiled fixed Windows UTC crypto helper')
    utc_crypto_helper = binary.parent/'luma-utc-windows-crypto'
    shutil.copy2(utc_crypto_helpers[0], utc_crypto_helper)
    utc_crypto_helper.chmod(0o755)
    utc_front = binary.parent/'utc-windows-front.py'
    shutil.copy2(REPO/'native/utc/windows_front.py', utc_front)
    utc_front.chmod(0o644)
    # Pin the actual assembled interpreter and SSL runtime, not the builder's
    # possibly different Python/OpenSSL version or an unexecuted metadata claim.
    with tempfile.TemporaryDirectory(prefix='luma-utc-policy-', dir=ROOT/'tmp') as temporary:
        policy_directory = Path(temporary)
        for name in ('windows_utc_policy.py', 'office_policy.py'):
            shutil.copy2(REPO/'native/image'/name, policy_directory/name)
            (policy_directory/name).chmod(0o644)
        policy_path = '/'+policy_directory.relative_to(ROOT).as_posix()
        transport_manifest = run('chroot', ROOT, '/usr/bin/python3', '-I', '-S', '-B', '-c',
            f'import sys; sys.path.insert(0,{policy_path!r}); import windows_utc_policy; '
            'sys.stdout.buffer.write(windows_utc_policy.canonical_manifest("/"))')
    put('usr/share/luma-os/utc/windows-transport.json', transport_manifest)
    put('usr/share/luma-os/adapters/office-pdf-v1.json',
        office_policy.canonical_manifest(ROOT).decode('utf-8'))
    (ROOT/'usr/bin/luma-platform').symlink_to('/usr/libexec/luma-os/luma-platform')
    shutil.copytree(REPO/'native/image/overlay',ROOT,dirs_exist_ok=True)
    # WSL Windows-mounted source files often report 0777. Never propagate those
    # host mount permissions into trusted policy directories or service units.
    ROOT.chmod(0o755)
    for source in (REPO/'native/image/overlay').rglob('*'):
        target=ROOT/source.relative_to(REPO/'native/image/overlay')
        target.chmod(0o755 if source.is_dir() or source.suffix=='.sh' or source.parent.name=='system-generators' else 0o644)
    for script in (ROOT/'usr/lib/dracut/modules.d/91luma').glob('*.sh'):
        script.chmod(0o755)
    (ROOT/'usr/bin/luma-admin-control').chmod(0o755)
    (ROOT/'usr/bin/luma-recovery-control').chmod(0o755)
    reference = ROOT/'usr/share/luma-os/reference'
    for name in ('src','web','schemas','examples'):
        shutil.copytree(REPO/name,reference/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    if args.edition == 'desktop':
        import browser_policy
        for name in ('workspace_host.py', 'workspace_auth.py', 'workspace_app.py', 'workspace_capture.py', 'workspace_draft.py', 'workspace_collections.py', 'workspace_speech.py', 'workspace_grounding.py', 'workspace_lifecycle.py', 'workspace_editor.py', 'browser_adapter.py'):
            target = binary.parent/name
            shutil.copy2(REPO/'native/desktop'/name, target)
            target.chmod(0o644)
        # The named AppArmor userns entry attaches ONLY to this fixed ELF, never
        # to Python globally. Fingerprint its actual compiled image bytes below.
        workspace_launcher = binary.parent/'luma-workspace-launch'
        run('gcc', '-std=c17', '-O2', '-Wall', '-Wextra', '-Wpedantic', '-Werror', '-Wformat=2',
            '-Wformat-security', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=3',
            '-fPIE', '-pie', '-Wl,-z,relro,-z,now,-z,noexecstack', '-Wl,--as-needed',
            REPO/'native/image/workspace_launcher.c', '-o', workspace_launcher)
        workspace_launcher.chmod(0o755)
        put('usr/share/luma-os/adapters/browser-presentation-v1.json',
            browser_policy.canonical_manifest(ROOT).decode('utf-8'))
        workspace = ROOT/'usr/share/luma-os/workspace'
        workspace.mkdir(parents=True, exist_ok=True)
        for name in ('native-workspace.html', 'native-workspace.js', 'native-workspace.css'):
            target = workspace/name
            shutil.copy2(REPO/'web'/name, target)
            target.chmod(0o644)
    hardware_query = binary.parent/'hardware-bpf-query'
    run('gcc', '-std=c17', '-O2', '-Wall', '-Wextra', '-Wpedantic', '-Werror', '-Wformat=2',
        '-Wformat-security', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=3',
        '-fPIE', '-pie', '-Wl,-z,relro,-z,now,-z,noexecstack', '-Wl,--as-needed',
        REPO/'native/image/hardware_query/query.c', REPO/'native/image/hardware_query/worker.c',
        '-o', hardware_query)
    hardware_query.chmod(0o755)
    enable('luma-hardware-query.socket', 'sockets.target')
    hardware_observer = binary.parent/'hardware-daemon-observer'
    run('gcc', '-std=c17', '-O2', '-Wall', '-Wextra', '-Wpedantic', '-Werror', '-Wformat=2',
        '-Wformat-security', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=3',
        '-fPIE', '-pie', '-Wl,-z,relro,-z,now,-z,noexecstack', '-Wl,--as-needed',
        REPO/'native/image/hardware_query/daemon.c', '-lcrypto', '-o', hardware_observer)
    hardware_observer.chmod(0o755)
    enable('luma-hardware-daemon-observer.socket', 'sockets.target')
    put('usr/share/luma-os/release-id',release+'\n')
    put('usr/share/luma-os/release-identity.json', json.dumps({
        'schema_version': 1, 'release': release, 'sequence': args.sequence,
        'environment': args.environment, 'architecture': 'amd64', 'ubuntu': '24.04',
        'edition': args.edition}, separators=(',', ':'))+'\n')
    if args.environment == 'production':
        import production_release
        production_release.validate_public_inputs(ROOT, args.production_public_inputs,
            {'schema_version': 1, 'release': release, 'sequence': args.sequence,
             'environment': 'production', 'architecture': 'amd64', 'ubuntu': '24.04',
             'edition': args.edition}, OUT)
    else:
        if not (KEYS/'release.key').exists():
            run('openssl','genpkey','-algorithm','ED25519','-out',KEYS/'release.key')
        run('openssl','pkey','-in',KEYS/'release.key','-pubout','-out',ROOT/'usr/share/luma-os/release.pub')
    for name in ('model-catalog.json','runtime-lock.json'):
        shutil.copy2(REPO/'native/image'/name,ROOT/'usr/share/luma-os'/name)
    if args.environment == 'lab':
        run('openssl','pkeyutl','-sign','-rawin','-inkey',KEYS/'release.key',
            '-in',ROOT/'usr/share/luma-os/model-catalog.json',
            '-out',ROOT/'usr/share/luma-os/model-catalog.sig')
    # Neither laboratory private key enters the source snapshot, image or
    # published artifacts. Production signing custody remains separate.
    if args.environment == 'lab':
        package_skill_registry(ROOT, KEYS)
    public_spec = importlib.util.spec_from_file_location(
        'luma_public_trust', REPO/'native/image/provision_public_trust.py')
    public_trust = importlib.util.module_from_spec(public_spec)
    public_spec.loader.exec_module(public_trust)
    public_inputs = public_trust.provision(ROOT, args.public_trust_inputs)
    if args.environment == 'production' and (public_inputs.get('environment') != 'production'
                                             or not public_inputs.get('skill_registry')):
        raise SystemExit('production image requires the complete externally signed production skill group')
    put('usr/share/luma-os/public-trust-inputs.json',
        json.dumps(public_inputs, sort_keys=True, separators=(',', ':'))+'\n')
    model_spec = importlib.util.spec_from_file_location(
        'luma_model_inputs', REPO/'native/image/provision_model_inputs.py')
    model_inputs = importlib.util.module_from_spec(model_spec)
    model_spec.loader.exec_module(model_inputs)
    model_report = model_inputs.provision(ROOT, args.model_public_inputs)
    if args.environment == 'production':
        from assembly_custody import recheck_public_domains
        if not model_report.get('provided') or model_report.get('environment') != 'production':
            raise SystemExit('production assembly requires independently signed production model metadata')
        profiles = json.loads((ROOT/'usr/share/luma-os/models/catalog.json').read_bytes())['profiles']
        if not any(p.get('kind') == 'model' and p.get('profile_id') in
                   ('qwen3-4b-q4-k-m', 'qwen3-1-7b-q4-k-m') for p in profiles):
            raise SystemExit('production image must package a supported signed native Qwen3 model tuple')
        recheck_public_domains(ROOT, OUT)
    put('usr/share/luma-os/model-public-inputs.json',
        json.dumps(model_report, sort_keys=True, separators=(',', ':'))+'\n')
    if args.environment == 'production':
        pcr_public = (OUT/'production-public/pcr-policy.pub').read_bytes()
        pcr_key = None
        run('openssl','x509','-in',OUT/'production-public/secureboot.pem','-outform','DER','-out',OUT/'secureboot.cer')
    else:
        if not (KEYS/'secureboot.key').exists():
            run('openssl','req','-new','-x509','-newkey','rsa:3072','-nodes','-sha256','-days','365',
                '-subj','/CN=Luma Native Laboratory Only/','-keyout',KEYS/'secureboot.key','-out',KEYS/'secureboot.pem',stderr=subprocess.DEVNULL)
        run('openssl','x509','-in',KEYS/'secureboot.pem','-outform','DER','-out',OUT/'secureboot.cer')
        pcr_key, pcr_public = boot_policy.prepare_lab_key(KEYS)
        for p in KEYS.iterdir():
            p.chmod(0o600)
    pcr_public_path = ROOT/'usr/share/luma-os/admin-pcr-public.pem'
    pcr_public_path.write_bytes(pcr_public)
    pcr_public_path.chmod(0o644)
    # Never inherit a build host's machine identity, credentials, DNS or mounts.
    for name in ('.dockerenv','etc/hostname','etc/resolv.conf','etc/machine-id','var/lib/dbus/machine-id'):
        p = ROOT/name
        if p.is_file() or p.is_symlink():
            p.unlink()
    put('etc/hostname','luma-native\n')
    put('etc/hosts','127.0.0.1 localhost\n127.0.1.1 luma-native\n::1 localhost\n')
    (ROOT/'etc/resolv.conf').symlink_to('/run/systemd/resolve/stub-resolv.conf')
    for name,major,minor in [('null',1,3),('zero',1,5),('random',1,8),('urandom',1,9),('console',5,1)]:
        node = ROOT/'dev'/name
        if not node.exists(): os.mknod(node,0o20666,os.makedev(major,minor))
    run('chroot',ROOT,'groupadd','--gid','990','luma-control')
    run('chroot',ROOT,'useradd','--uid','990','--gid','990','--system','--no-create-home',
        '--home-dir','/var/lib/luma-os/reference','--shell','/usr/sbin/nologin','luma-control')
    for uid,name in ((989,'luma-model'),(988,'luma-fetch'),(987,'luma-utc-producer'),(986,'luma-office'),(985,'luma-utc-front')):
        run('chroot',ROOT,'groupadd','--gid',str(uid),name)
        run('chroot',ROOT,'useradd','--uid',str(uid),'--gid',str(uid),'--system','--no-create-home',
            '--home-dir','/nonexistent','--shell','/usr/sbin/nologin',name)
    package_protected_utc(ROOT, REPO, WORK)
    run('chroot',ROOT,'passwd','--lock','root')
    # Ubuntu's container image may ship a UID 1000 convenience account. Never
    # carry that account into an OS with operator-created first-user identities.
    accounts = (ROOT/'etc/passwd').read_text().splitlines()
    if any(line.startswith('ubuntu:') for line in accounts):
        run('chroot',ROOT,'userdel','ubuntu')
    if any(1000 <= int(line.split(':')[2]) < 65534
           for line in (ROOT/'etc/passwd').read_text().splitlines()):
        raise SystemExit('unexpected pre-existing interactive identity in base image')
    speech_spec = importlib.util.spec_from_file_location(
        'luma_speech_package', REPO/'native/image/speech/package_runtime.py')
    speech_package = importlib.util.module_from_spec(speech_spec)
    speech_spec.loader.exec_module(speech_package)
    speech_package.package(ROOT, WORK)
    put('usr/share/doc/luma-os/speech.md',
        (REPO/'native/image/speech/README.md').read_text())
    put('usr/share/doc/luma-os/hardware-policy.md',
        (REPO/'native/image/HARDWARE_POLICY.md').read_text())
    qemu_policy.configure(ROOT)
    desktop_profile = desktop_policy.configure(ROOT, args.edition, args.environment)
    import hardware_policy
    put('usr/libexec/luma-os/hardware_writer_verify.py',
        (REPO/'native/image/hardware_policy.py').read_text())
    desktop_profile['hardware_writer_mediation'] = hardware_policy.configure(ROOT, args.edition)
    if args.edition == 'desktop':
        import capture_policy
        desktop_profile['input_capture'] = capture_policy.verify(ROOT)
        import speech_policy
        desktop_profile['speech'] = speech_policy.verify(ROOT)
    root_mib, payload_mib = desktop_policy.geometry(args.edition)
    template = ROOT/'usr/share/luma-os/var-template'
    # Fresh build-owned exported filesystem only; no host files are involved.
    for relative in ('var/cache/apt/archives','var/lib/apt/lists','var/log','tmp'):
        directory = ROOT/relative
        for p in directory.iterdir() if directory.is_dir() else ():
            if p.is_dir() and not p.is_symlink(): shutil.rmtree(p)
            else: p.unlink()
    identity = ROOT/'var/lib/luma-os/identity'
    identity.mkdir(parents=True)
    for name in ('passwd','shadow','group','gshadow'):
        source = ROOT/'etc'/name
        shutil.copy2(source,identity/name)
        source.unlink()
        source.symlink_to('../var/lib/luma-os/identity/'+name)
    (identity/'machine-id').write_text('uninitialized\n')
    (ROOT/'etc/machine-id').symlink_to('../var/lib/luma-os/identity/machine-id')
    (ROOT/'var/lib/dbus').mkdir(parents=True,exist_ok=True)
    (ROOT/'var/lib/dbus/machine-id').symlink_to('../luma-os/identity/machine-id')
    (ROOT/'var/lib/luma-os/sudoers').mkdir()
    put('etc/sudoers.d/luma-admin','#includedir /var/lib/luma-os/sudoers\n',0o440)
    configure_original_pam_sudoers()
    for path in ('var/home','var/root','var/lib/luma-os/reference','efi','media/luma'):
        (ROOT/path).mkdir(parents=True,exist_ok=True)
    (ROOT/'var/root').chmod(0o700)
    # Durable admission evidence is not an authority source. Runtime writers
    # refuse a missing namespace rather than silently initializing one.
    (ROOT/'var/lib/luma-os/policy-decisions').mkdir()
    (ROOT/'var/lib/luma-os/policy-decisions').chmod(0o700)
    # Empty public-certificate transport storage is not model authority.
    (ROOT/'var/lib/luma-os/model-qualifications').mkdir()
    (ROOT/'var/lib/luma-os/model-qualifications').chmod(0o700)
    (ROOT/'var/lib/luma-os/workflow-inputs').mkdir()
    (ROOT/'var/lib/luma-os/workflow-inputs').chmod(0o711)
    connections=ROOT/'var/lib/NetworkManager/system-connections'
    connections.mkdir(parents=True,exist_ok=True)
    connections.chmod(0o700)
    os.chown(ROOT/'var/lib/luma-os/reference',990,990)
    put('etc/fstab',
        '/var/home /home none bind 0 0\n'
        '/var/root /root none bind 0 0\n'
        'tmpfs /tmp tmpfs mode=1777,nosuid,nodev 0 0\n')
    put('etc/systemd/journald.conf.d/luma.conf','[Journal]\nStorage=persistent\nSystemMaxUse=128M\nRuntimeMaxUse=64M\n')
    put('etc/systemd/system/systemd-bless-boot.service','[Unit]\nDescription=Disabled automatic blessing; luma-boot-health owns acknowledgement\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')
    put('etc/systemd/system/sleep.target.d/luma.conf',
        '[Unit]\nConflicts=luma-reference.service luma-model.service\n')
    put('etc/systemd/system/hibernate.target','[Unit]\nDescription=Hibernation is unqualified and disabled\nRefuseManualStart=yes\n')
    for unit in ('luma-broker.service','luma-reference.service','luma-model.service','luma-staging-clean.service','luma-peer-observer.service','luma-admin.service','luma-content-custody.service','luma-content-custody.path'):
        enable(unit)
    # Explicitly activate the packaged measured-UKI userspace phase barriers.
    # They do not activate Admin or make a missing TPM a general boot dependency.
    for unit,target in (('systemd-pcrphase-sysinit.service','basic.target'),
                        ('systemd-pcrphase.service','multi-user.target')):
        if not (ROOT/'usr/lib/systemd/system'/unit).is_file():
            raise SystemExit('missing packaged PCR phase unit: '+unit)
        wanted=ROOT/f'etc/systemd/system/{target}.wants'
        wanted.mkdir(parents=True,exist_ok=True)
        (wanted/unit).symlink_to('/usr/lib/systemd/system/'+unit)
    put('etc/issue',f'Luma native Ubuntu {args.environment} image. Native qualification is pending.\nRun luma-platform --help. Installation/recovery bundle: /media/luma\n')
    run('cp','-a',ROOT/'var',template)
    versions = run('chroot',ROOT,'dpkg-query','-W','-f=${Package}=${Version}\n')
    (OUT/'packages.lock').write_text(versions,encoding='utf-8')
    (OUT/'toolchain-packages.lock').write_text(run('dpkg-query','-W','-f=${Package}=${Version}\n'))
    kernel_candidates = sorted((ROOT/'boot').glob('vmlinuz-*-generic'))
    if len(kernel_candidates) != 1:
        raise SystemExit('expected one pinned generic kernel')
    kernel = kernel_candidates[0]
    version = kernel.name.removeprefix('vmlinuz-')
    generated_spec = importlib.util.spec_from_file_location(
        'luma_generated_package', REPO/'native/image/generated/package_runtime.py')
    generated_package = importlib.util.module_from_spec(generated_spec)
    generated_spec.loader.exec_module(generated_package)
    generated_package.package(ROOT, kernel, WORK)
    # Device nodes are created only within the new container-owned rootfs.
    for name,major,minor in [('null',1,3),('zero',1,5),('random',1,8),('urandom',1,9),('console',5,1)]:
        node = ROOT/'dev'/name
        if not node.exists(): os.mknod(node,0o20666,os.makedev(major,minor))
    # Sysroot mode uses the container's proc/sys without mounting host resources
    # into the target and avoids unsupported proc-less chroot generation.
    run('dracut','--sysroot',ROOT,'--force','--no-hostonly','--no-hostonly-cmdline',
        '--add','systemd systemd-initrd systemd-veritysetup crypt luma luma-pcrphase',
        '--add-drivers','virtio_pci virtio_blk virtio_scsi ext4 dm_verity dm_crypt loop iso9660 sr_mod cdrom',
        '--kver',version,ROOT/'boot/luma-initrd')
    initrd = ROOT/'boot/luma-initrd'
    initrd_policy = boot_policy.verify_initrd(initrd)
    import shutdown_policy
    shutdown_policy.configure(ROOT, version)
    initrd_policy['shutdown'] = shutdown_policy.verify_initrd(initrd)
    root_image = OUT/'root.ext4'
    with root_image.open('xb') as f: f.truncate(root_mib*MIB)
    run('mkfs.ext4','-F','-L','luma-root','-d',ROOT,root_image)
    verity = OUT/'root.verity'
    output = run('veritysetup','format',root_image,verity)
    roothash = next(line.split(':',1)[1].strip() for line in output.splitlines() if line.startswith('Root hash:'))
    (OUT/'verity-format.txt').write_text(output)
    run('veritysetup','verify',root_image,verity,roothash)
    os_release = OUT/'uki-os-release'
    os_release.write_text(f'ID=luma\nNAME="Luma Native {"Laboratory" if args.environment == "lab" else "Production"}"\nVERSION_ID={args.sequence}\nPRETTY_NAME="{release}"\n')
    unsigned = OUT/'production-unsigned'
    if args.environment == 'production':
        unsigned.mkdir()
    pcr_records = []
    for slot in ('a','b','live','optical'):
        mode = 'live' if slot in ('live','optical') else 'installed'
        cmdline = boot_policy.command_line(roothash,slot,args.edition)
        custody_args = (['--secureboot-private-key',KEYS/'secureboot.key',
                         '--secureboot-certificate',KEYS/'secureboot.pem',
                         *boot_policy.signing_arguments(slot,pcr_key,pcr_public_path)]
                        if args.environment == 'lab' else
                        ['--pcrpkey',pcr_public_path] if slot in ('a','b') else [])
        run('/usr/lib/systemd/ukify','build','--linux',kernel,'--initrd',initrd,
            '--config','/dev/null',
            '--cmdline',cmdline,'--os-release','@'+str(os_release),'--uname',version,
            *custody_args,
            '--output',(OUT if args.environment == 'lab' else unsigned)/f'slot-{slot}.efi')
        if args.environment == 'lab':
            pcr_records.append(boot_policy.verify_uki(OUT/f'slot-{slot}.efi',slot,pcr_public,KEYS/'secureboot.pem'))
        desktop_policy.verify_boot_target(boot_policy.read_sections((OUT if args.environment == 'lab' else unsigned)/f'slot-{slot}.efi')['.cmdline'],args.edition,mode)
    if args.environment == 'production':
        shutil.copyfile('/usr/lib/systemd/boot/efi/systemd-bootx64.efi',unsigned/'bootloader.efi')
        checkpoint = {'schema_version': 1, 'identity': {'schema_version': 1,
            'release': release, 'sequence': args.sequence, 'environment': 'production',
            'architecture': 'amd64', 'ubuntu': '24.04', 'edition': args.edition},
            'root_hash': roothash, 'kernel': version, 'source_lock_sha256': digest(OUT/'source-lock.json'),
            'initrd_policy': initrd_policy, 'desktop': desktop_profile}
        with (OUT/'production-build.json').open('x') as stream:
            json.dump(checkpoint, stream, sort_keys=True, indent=2); stream.write('\n')
        request = production_release.prepare_pcr(OUT, ROOT)
        print(json.dumps({'status': 'production-custody-pcr-signatures-required',
            'request': request, 'product_rebuilt': True, 'production_signed': False,
            'gate_closing': False}, default=str), flush=True)
        return
    (OUT/'boot-policy.json').write_text(json.dumps({'schema_version':1,'environment':'lab',
        'slots':pcr_records,'initrd':initrd_policy,
        'enrollment_active':False,'gate_closing':False},indent=2)+'\n')
    run('sbsign','--key',KEYS/'secureboot.key','--cert',KEYS/'secureboot.pem',
        '--output',OUT/'bootloader.efi','/usr/lib/systemd/boot/efi/systemd-bootx64.efi')
    names=['root.ext4','root.verity','slot-a.efi','slot-b.efi','bootloader.efi','secureboot.cer']
    manifest={'schema_version':1,'release':release,'sequence':args.sequence,'environment':'lab',
              'architecture':'amd64','ubuntu':'24.04','edition':args.edition,'root_hash':roothash,
              'root_bytes':root_image.stat().st_size,'hash_bytes':verity.stat().st_size,
              'artifacts':[{'name':n,'bytes':(OUT/n).stat().st_size,'sha256':digest(OUT/n)} for n in names]}
    (OUT/'release.json').write_text(json.dumps(manifest,separators=(',',':'))+'\n')
    run('openssl','pkeyutl','-sign','-rawin','-inkey',KEYS/'release.key',
        '-in',OUT/'release.json','-out',OUT/'release.sig')
    seal_media(manifest, desktop_profile, version)


def seal_media(manifest, desktop_profile, version):
    """Seal already signed six-artifact bytes; never creates signing keys."""
    production = manifest['environment'] == 'production'
    if production:
        import production_release
        production_release.verify_complete(OUT)
    release = manifest['release']
    root_image, verity = OUT/'root.ext4', OUT/'root.verity'
    roothash = manifest['root_hash']
    root_mib, payload_mib = __import__('desktop_policy').geometry(manifest['edition'])
    names=['root.ext4','root.verity','slot-a.efi','slot-b.efi','bootloader.efi','secureboot.cer']
    # Optical input hashing requires exclusive regular members. Seal it before
    # stage_payload_member creates the deliberate installed-payload hardlinks.
    import optical_media
    optical = optical_media.create_iso(OUT,OUT,manifest)
    payload_tree=WORK/'payload'; payload_tree.mkdir()
    payload_names=[*names,'release.json','release.sig','packages.lock',
                   *(['release-trust.json'] if production else [])]
    for name in payload_names:
        stage_payload_member(OUT/name,payload_tree/name)
    payload=OUT/'payload.ext4'
    with payload.open('xb') as f:f.truncate(payload_mib*MIB)
    run('mkfs.ext4','-F','-L','luma-payload','-d',payload_tree,payload)
    import resume as image_checks
    with tempfile.TemporaryDirectory(prefix='.payload-readback-',dir=OUT) as temporary:
        image_checks.verify_payload(OUT,Path(temporary),production=production)
    release_payload_staging(payload_tree,OUT,payload_names)
    esp=OUT/'esp.fat'
    with esp.open('xb') as f:f.truncate(1024*MIB)
    run('mkfs.vfat','-F','32','-n','LUMALIVE',esp)
    for directory in ('::/EFI','::/EFI/BOOT','::/EFI/Linux','::/loader'):
        run('mmd','-i',esp,directory)
    run('mcopy','-i',esp,OUT/'bootloader.efi','::/EFI/BOOT/BOOTX64.EFI')
    run('mcopy','-i',esp,OUT/'slot-live.efi','::/EFI/Linux/luma-live.efi')
    run('mcopy','-i',esp,OUT/'secureboot.cer','::/secureboot.cer')
    loader=OUT/'loader.conf'; loader.write_text('default luma-live.efi\ntimeout 3\neditor no\n')
    run('mcopy','-i',esp,loader,'::/loader/loader.conf')
    image=OUT/f'{release}.img'
    sizes=[1024,root_mib,64,payload_mib]
    with image.open('xb') as f:f.truncate((sum(sizes)+16)*MIB)
    argv=['sgdisk','--clear']
    labels=['LUMA-LIVE-ESP','luma-live-root','luma-live-hash','luma-payload']
    start=1
    offsets=[]
    for i,(size,label) in enumerate(zip(sizes,labels),1):
        argv += ['--new',f'{i}:{start*2048}:{(start+size)*2048-1}','--change-name',f'{i}:{label}']
        if i==1:argv += ['--typecode','1:ef00']
        offsets.append(start*MIB);start+=size
    run(*argv,image)
    for source,offset in zip([esp,root_image,verity,payload],offsets):sparse_copy(source,image,offset)
    run('sgdisk','--verify',image)
    image_checks.verify_gpt(image, manifest['edition'])
    partitions, _ = image_checks.layout(manifest['edition'])
    image_checks.verify_ranges(image, [esp,root_image,verity,payload], partitions)
    run('zstd','-T2','-3',image,'-o',str(image)+'.zst')
    run('zstd','-t',str(image)+'.zst')
    selected=[image,Path(str(image)+'.zst'),OUT/optical['image'],OUT/'optical-media.json',OUT/'release.json',OUT/'release.sig',OUT/'secureboot.cer',OUT/'packages.lock',OUT/'source-lock.json',OUT/'toolchain-packages.lock',OUT/'native-source.tar.zst',OUT/'boot-policy.json',
              *([OUT/'release-trust.json'] if production else [])]
    (OUT/'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.name}\n' for p in selected))
    if production:
        production_release.verify_complete(OUT)
    record={'status':'built-not-yet-boot-tested','release':release,'kernel':version,'edition':manifest['edition'],
            'root_hash':roothash,'image':image.name,'image_sha256':digest(image),
            'source_lock_sha256':digest(OUT/'source-lock.json'),
            'desktop':desktop_profile, 'production_signed':production,'gate_closing':False,
            'optical':optical,
            'custody_qualified':False, 'native_qualification_claimed':False}
    (OUT/'build.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2),flush=True)


if __name__=='__main__': main()
