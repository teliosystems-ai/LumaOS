#!/usr/bin/env python3
"""Assemble laboratory UEFI media in an isolated container-owned /work volume.

Only regular image files are partitioned. This builder never opens a host disk.
Private laboratory keys stay in the separate /keys volume, outside output/source.
"""
from __future__ import annotations
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

MIB = 1024 * 1024
REPO = Path('/repo')
WORK = Path('/work')
ROOT = WORK / 'root'
OUT = WORK / 'artifacts'
KEYS = Path('/keys')


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


def main() -> None:
    global REPO
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--edition', choices=('headless','desktop'), default='headless')
    parser.add_argument('--sequence', type=int, default=1)
    parser.add_argument('--external-artifacts', action='store_true')
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
    KEYS.mkdir(mode=0o700, exist_ok=True)
    release = f'luma-native-lab-20260927-{args.edition}-{args.sequence}'
    print(f'Assembling {release}', flush=True)
    inputs=[]
    snapshot=WORK/'source'
    snapshot.mkdir()
    for folder in ('rust','native/image','src','web','schemas','examples'):
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
    reference = ROOT/'usr/share/luma-os/reference'
    for name in ('src','web','schemas','examples'):
        shutil.copytree(REPO/name,reference/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    put('usr/share/luma-os/release-id',release+'\n')
    if not (KEYS/'release.key').exists():
        run('openssl','genpkey','-algorithm','ED25519','-out',KEYS/'release.key')
    run('openssl','pkey','-in',KEYS/'release.key','-pubout','-out',ROOT/'usr/share/luma-os/release.pub')
    for name in ('model-catalog.json','runtime-lock.json'):
        shutil.copy2(REPO/'native/image'/name,ROOT/'usr/share/luma-os'/name)
    run('openssl','pkeyutl','-sign','-rawin','-inkey',KEYS/'release.key',
        '-in',ROOT/'usr/share/luma-os/model-catalog.json',
        '-out',ROOT/'usr/share/luma-os/model-catalog.sig')
    if not (KEYS/'secureboot.key').exists():
        run('openssl','req','-new','-x509','-newkey','rsa:3072','-nodes','-sha256','-days','365',
            '-subj','/CN=Luma Native Laboratory Only/','-keyout',KEYS/'secureboot.key','-out',KEYS/'secureboot.pem',stderr=subprocess.DEVNULL)
    run('openssl','x509','-in',KEYS/'secureboot.pem','-outform','DER','-out',OUT/'secureboot.cer')
    for p in KEYS.iterdir():
        p.chmod(0o600)
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
    for uid,name in ((989,'luma-model'),(988,'luma-fetch')):
        run('chroot',ROOT,'groupadd','--gid',str(uid),name)
        run('chroot',ROOT,'useradd','--uid',str(uid),'--gid',str(uid),'--system','--no-create-home',
            '--home-dir','/nonexistent','--shell','/usr/sbin/nologin',name)
    run('chroot',ROOT,'passwd','--lock','root')
    # Ubuntu's container image may ship a UID 1000 convenience account. Never
    # carry that account into an OS with operator-created first-user identities.
    accounts = (ROOT/'etc/passwd').read_text().splitlines()
    if any(line.startswith('ubuntu:') for line in accounts):
        run('chroot',ROOT,'userdel','ubuntu')
    if any(1000 <= int(line.split(':')[2]) < 65534
           for line in (ROOT/'etc/passwd').read_text().splitlines()):
        raise SystemExit('unexpected pre-existing interactive identity in base image')
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
    for path in ('var/home','var/root','var/lib/luma-os/reference','efi','media/luma'):
        (ROOT/path).mkdir(parents=True,exist_ok=True)
    (ROOT/'var/root').chmod(0o700)
    connections=ROOT/'var/lib/NetworkManager/system-connections'
    connections.mkdir(parents=True,exist_ok=True)
    connections.chmod(0o700)
    os.chown(ROOT/'var/lib/luma-os/reference',990,990)
    put('etc/fstab',
        '/var/home /home none bind 0 0\n'
        '/var/root /root none bind 0 0\n'
        'tmpfs /tmp tmpfs mode=1777,nosuid,nodev 0 0\n'
        'PARTLABEL=luma-payload /media/luma ext4 ro,nodev,nosuid,noexec,nofail,x-systemd.device-timeout=3s 0 0\n')
    put('etc/systemd/journald.conf.d/luma.conf','[Journal]\nStorage=persistent\nSystemMaxUse=128M\nRuntimeMaxUse=64M\n')
    put('etc/systemd/system/systemd-bless-boot.service','[Unit]\nDescription=Disabled automatic blessing; luma-boot-health owns acknowledgement\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')
    put('etc/systemd/system/sleep.target.d/luma.conf','[Unit]\nConflicts=luma-reference.service\n')
    put('etc/systemd/system/hibernate.target','[Unit]\nDescription=Hibernation is unqualified and disabled\nRefuseManualStart=yes\n')
    for unit in ('luma-broker.service','luma-reference.service','luma-model.service','luma-staging-clean.service'):
        enable(unit)
    put('etc/issue','Luma native Ubuntu laboratory image. Native qualification is pending.\nRun luma-platform --help. Installation/recovery bundle: /media/luma\n')
    run('cp','-a',ROOT/'var',template)
    versions = run('chroot',ROOT,'dpkg-query','-W','-f=${Package}=${Version}\n')
    (OUT/'packages.lock').write_text(versions,encoding='utf-8')
    (OUT/'toolchain-packages.lock').write_text(run('dpkg-query','-W','-f=${Package}=${Version}\n'))
    kernel_candidates = sorted((ROOT/'boot').glob('vmlinuz-*-generic'))
    if len(kernel_candidates) != 1:
        raise SystemExit('expected one pinned generic kernel')
    kernel = kernel_candidates[0]
    version = kernel.name.removeprefix('vmlinuz-')
    # Device nodes are created only within the new container-owned rootfs.
    for name,major,minor in [('null',1,3),('zero',1,5),('random',1,8),('urandom',1,9),('console',5,1)]:
        node = ROOT/'dev'/name
        if not node.exists(): os.mknod(node,0o20666,os.makedev(major,minor))
    # Sysroot mode uses the container's proc/sys without mounting host resources
    # into the target and avoids unsupported proc-less chroot generation.
    run('dracut','--sysroot',ROOT,'--force','--no-hostonly','--no-hostonly-cmdline',
        '--add','systemd systemd-initrd systemd-veritysetup crypt luma',
        '--add-drivers','virtio_pci virtio_blk virtio_scsi ext4 dm_verity dm_crypt',
        '--kver',version,ROOT/'boot/luma-initrd')
    initrd = ROOT/'boot/luma-initrd'
    root_image = OUT/'root.ext4'
    with root_image.open('xb') as f: f.truncate(4*1024*MIB)
    run('mkfs.ext4','-F','-L','luma-root','-d',ROOT,root_image)
    verity = OUT/'root.verity'
    output = run('veritysetup','format',root_image,verity)
    roothash = next(line.split(':',1)[1].strip() for line in output.splitlines() if line.startswith('Root hash:'))
    (OUT/'verity-format.txt').write_text(output)
    run('veritysetup','verify',root_image,verity,roothash)
    os_release = OUT/'uki-os-release'
    os_release.write_text(f'ID=luma\nNAME="Luma Native Laboratory"\nVERSION_ID={args.sequence}\nPRETTY_NAME="{release}"\n')
    for slot in ('a','b','live'):
        mode = 'live' if slot=='live' else 'installed'
        data = 'luma-live-root' if slot=='live' else f'luma-root-{slot}'
        hash_label = 'luma-live-hash' if slot=='live' else f'luma-hash-{slot}'
        cmdline = (f'root=/dev/mapper/root ro roothash={roothash} '
                   'systemd.verity_root_options=panic-on-corruption '
                   f'systemd.verity_root_data=/dev/disk/by-partlabel/{data} '
                   f'systemd.verity_root_hash=/dev/disk/by-partlabel/{hash_label} '
                   f'luma.mode={mode} luma.slot={slot} '
                   'console=tty0 console=ttyS0,115200n8 apparmor=1 security=apparmor '
                   'systemd.show_status=yes rd.shell=0 panic=10')
        run('/usr/lib/systemd/ukify','build','--linux',kernel,'--initrd',initrd,
            '--cmdline',cmdline,'--os-release','@'+str(os_release),'--uname',version,
            '--secureboot-private-key',KEYS/'secureboot.key',
            '--secureboot-certificate',KEYS/'secureboot.pem','--output',OUT/f'slot-{slot}.efi')
        run('sbverify','--cert',KEYS/'secureboot.pem',OUT/f'slot-{slot}.efi')
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
    payload_tree=WORK/'payload'; payload_tree.mkdir()
    for name in [*names,'release.json','release.sig','packages.lock']:
        stage_payload_member(OUT/name,payload_tree/name)
    payload=OUT/'payload.ext4'
    with payload.open('xb') as f:f.truncate(6*1024*MIB)
    run('mkfs.ext4','-F','-L','luma-payload','-d',payload_tree,payload)
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
    sizes=[1024,4096,64,6144]
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
    run('zstd','-T2','-3',image,'-o',str(image)+'.zst')
    selected=[image,Path(str(image)+'.zst'),OUT/'release.json',OUT/'release.sig',OUT/'secureboot.cer',OUT/'packages.lock',OUT/'source-lock.json',OUT/'toolchain-packages.lock',OUT/'native-source.tar.zst']
    (OUT/'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.name}\n' for p in selected))
    record={'status':'built-not-yet-boot-tested','release':release,'kernel':version,'edition':args.edition,
            'root_hash':roothash,'image':image.name,'image_sha256':digest(image),
            'source_lock_sha256':digest(OUT/'source-lock.json'),
            'production_signed':False,'gate_closing':False}
    (OUT/'build.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2),flush=True)


if __name__=='__main__': main()
