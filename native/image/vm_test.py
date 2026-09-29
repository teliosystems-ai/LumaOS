#!/usr/bin/env python3
"""Native integration on fresh virtual disks; never accepts host block devices.

All VM credentials below are PUBLIC disposable test fixtures, not image defaults.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from vm_tpm import SoftwareTPM, state_directory

USER_PASSWORD='VM-only-user-passphrase-2026'
ADMIN_PASSWORD='VM-only-admin-passphrase-2026'
DATA_PASSWORD='VM-only-data-passphrase-2026'
RECOVERY_PASSWORD='VM-only-independent-recovery-2026'
TARGET='/dev/disk/by-id/virtio-LUMA-VM-TARGET'
TEST_SOURCES={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(Path(__file__).parent.glob('*.py'))}


class VM:
    def __init__(self,image: Path,work: Path,target: Path,live: bool,timeout: int,secure_boot: bool=False,acceleration: str='auto',attach_media: bool | None=None,media_format: str='raw',memory_mib: int=4096,network: bool=False):
        self.work=work;work.mkdir()
        # External filesystems hold disks/logs, not Unix socket endpoints.
        self.socket_directory=tempfile.TemporaryDirectory(prefix='luma-vm-',dir='/tmp')
        self.socket_dir=Path(self.socket_directory.name)
        # Preserve virtual NVRAM across the complete installation/boot sequence.
        variables=work.parent/'firmware.fd'
        fresh_variables=not variables.exists()
        if fresh_variables:shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd',variables)
        self.secure_boot=secure_boot
        if secure_boot and fresh_variables:
            subprocess.run(['openssl','x509','-inform','DER','-in',str(image.parent/'secureboot.cer'),
                            '-out',str(work/'public-cert.pem')],check=True)
            owner='d89f6f4e-6249-4fc4-ad4e-4d10f21e83ef'
            cert=str(work/'public-cert.pem')
            subprocess.run(['virt-fw-vars','--inplace',str(variables),
                            '--set-pk',owner,cert,'--add-kek',owner,cert,
                            '--add-db',owner,cert,'--sb'],check=True)
        firmware='/usr/share/OVMF/OVMF_CODE_4M'+('.secboot' if secure_boot else '')+'.fd'
        self.acceleration=acceleration if acceleration!='auto' else ('kvm' if os.access('/dev/kvm',os.R_OK|os.W_OK) else 'tcg')
        if memory_mib not in (4096,6144):raise ValueError('unsupported test memory fixture')
        command=['qemu-system-x86_64','-machine',f'q35,accel={self.acceleration}','-m',str(memory_mib),'-smp','2',
            '-cpu','host' if self.acceleration=='kvm' else 'max',
            '-drive',f'if=pflash,format=raw,readonly=on,file={firmware}',
            '-drive',f'if=pflash,format=raw,file={variables}',
            '-drive',f'if=none,id=target,format=qcow2,discard=unmap,detect-zeroes=unmap,file={target}',
            '-device',f'virtio-blk-pci,drive=target,serial=LUMA-VM-TARGET,bootindex={2 if live else 1}',
            '-nic','user,model=virtio-net-pci' if network else 'none','-display','none','-monitor','none',
            '-serial',f'unix:{self.socket_dir}/console.sock,server=on,wait=off',
            '-qmp',f'unix:{self.socket_dir}/qmp.sock,server=on,wait=off','-no-reboot']
        if media_format not in ('raw','qcow2'):raise ValueError('unsupported media format')
        if attach_media if attach_media is not None else live:
            command+=['-drive',f'if=none,id=media,format={media_format},readonly=on,file={image}',
                      '-device',f'virtio-blk-pci,drive=media,serial=LUMA-LIVE,bootindex={1 if live else 2}']
        self.tpm=self.process=self.errors=self.log=self.console=None
        try:
            self.tpm=SoftwareTPM(state_directory(work.parent))
            command+=self.tpm.qemu_arguments()
            self.errors=(work/'qemu.log').open('wb')
            self.process=subprocess.Popen(command,stdout=self.errors,stderr=self.errors)
            self.log=(work/'serial.log').open('wb');self.buffer=b'';self.counter=0
            self.deadline=time.monotonic()+timeout
            self.console=socket.socket(socket.AF_UNIX)
            while not (self.socket_dir/'console.sock').exists():
                if self.process.poll() is not None:raise RuntimeError((work/'qemu.log').read_text())
                if time.monotonic()>self.deadline:raise TimeoutError('QEMU startup')
                time.sleep(.1)
            self.console.connect(str(self.socket_dir/'console.sock'))
        except BaseException:
            self.close()
            raise

    def expect(self,pattern: bytes,timeout: int=300) -> bytes:
        end=min(self.deadline,time.monotonic()+timeout)
        while time.monotonic()<end:
            match=re.search(pattern,self.buffer)
            if match:
                result=self.buffer[:match.end()];self.buffer=self.buffer[match.end():]
                return result
            if self.process.poll() is not None:break
            readable,_,_=select.select([self.console],[],[],1)
            if not readable:continue
            chunk=self.console.recv(65536)
            if not chunk:break
            self.log.write(chunk);self.log.flush();self.buffer=(self.buffer+chunk)[-2_000_000:]
        raise RuntimeError(f'Expected {pattern!r}; inspect {self.work}/serial.log')

    def send(self,line: str) -> None:self.console.sendall(line.encode()+b'\n')

    def action(self,success: bytes,timeout: int=300) -> bytes:
        result=self.expect(success+rb'|luma-platform: [^\r\n]+[\r\n]',timeout)
        if b'luma-platform: ' in result:
            detail=result.split(b'luma-platform: ')[-1].decode(errors='replace').strip()
            raise RuntimeError(f'Native operation failed: {detail}; inspect {self.work}/serial.log')
        return result

    def run(self,command: str,expected: int=0,timeout: int=300) -> bytes:
        self.counter+=1;marker=f'__LUMA_RC_{self.counter}'
        self.send(command+f'; printf "\\n{marker}=%s__\\n" "$?"')
        result=self.expect(rb'\r?\n'+marker.encode()+rb'=\d+__\r?\n',timeout)
        actual=int(re.search(marker.encode()+rb'=(\d+)__',result).group(1))
        if actual!=expected:raise RuntimeError(f'Guest command exit {actual}, expected {expected}: {command}; see {self.work}/serial.log')
        return result

    def close(self) -> None:
        if self.process is not None:
            self.process.terminate()
            try:self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait()
            self.process=None
        for name in ('console','log','errors'):
            resource=getattr(self,name,None)
            if resource is not None:resource.close();setattr(self,name,None)
        if self.tpm is not None:self.tpm.close();self.tpm=None
        self.socket_directory.cleanup()

    def wait_exit(self,timeout: int=180) -> int:
        # Keep consuming the serial socket during shutdown: a full console
        # socket can block the guest, and dropping it loses failure evidence.
        end=min(self.deadline,time.monotonic()+timeout)
        while time.monotonic()<end:
            readable,_,_=select.select([self.console],[],[],1)
            if readable:
                chunk=self.console.recv(65536)
                if chunk:
                    self.log.write(chunk);self.log.flush();self.buffer=(self.buffer+chunk)[-2_000_000:]
                elif self.process.poll() is not None:
                    return self.process.returncode
            if self.process.poll() is not None:
                return self.process.returncode
        raise RuntimeError(f'Guest did not exit within {timeout}s; inspect {self.work}/serial.log')


def live_ready(vm: VM) -> None:
    vm.expect(rb'root@[^\r\n]*[#]')
    vm.run('luma-platform inventory')
    vm.run('luma-platform status')
    vm.run('systemctl is-active luma-broker.service luma-reference.service')
    vm.run('test "$(findmnt -n -o FSTYPE /)" = ext4 && veritysetup status root')
    vm.run('grep -Fx "luma-reference (enforce)" /sys/kernel/security/apparmor/profiles')
    if vm.secure_boot:
        vm.run('test "$(od -An -tu1 -j4 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c | tr -d \' \\n\')" = 1')
    vm.run('systemctl is-active media-luma.mount && test -s /media/luma/release.json && test -s /media/luma/release.sig')
    vm.run('stat -c "%F %u %g %a" /dev/tpmrm0 && luma-platform tpm-probe')


def install(vm: VM,model: str='manual-only') -> None:
    print('VM: signed bundle verification and installation',flush=True)
    vm.run('mkdir /tmp/bad-bundle && cp /media/luma/release.json /media/luma/release.sig /tmp/bad-bundle/')
    mutation="import json; from pathlib import Path; p=Path('/tmp/bad-bundle/release.json'); m=json.loads(p.read_text()); m['sequence']+=1; p.write_text(json.dumps(m))"
    vm.run('python3 -c '+shlex.quote(mutation))
    vm.run(f'head -c 1048576 {TARGET} | sha256sum > /tmp/before-install.sha256')
    refused = vm.run(f'luma-platform install {TARGET} /tmp/bad-bundle --model manual-only',expected=1)
    if b'release signature verification failed' not in refused:
        raise RuntimeError('tampered bundle was not rejected at signature verification')
    vm.run(f'head -c 1048576 {TARGET} | sha256sum | cmp - /tmp/before-install.sha256')
    if model=='manual-only':
        refused=vm.run(f'luma-platform install {TARGET} /media/luma --model qwen3-4b-q4-k-m',expected=1)
        if b'cannot be admitted' not in refused:raise RuntimeError('4 GiB fixture did not reject the 4B RAM requirement')
        vm.run(f'head -c 1048576 {TARGET} | sha256sum | cmp - /tmp/before-install.sha256')
    vm.send(f'luma-platform install {TARGET} /media/luma --model {shlex.quote(model)}')
    vm.action(rb'Type exactly: ERASE LUMA-VM-TARGET',900);vm.send('ERASE LUMA-VM-TARGET')
    for prompt,value in [(b'First user login name:','lumauser'),(b'Separate administrator login name:','lumaadmin')]:
        vm.expect(prompt);vm.send(value)
    for label,value in [('User password',USER_PASSWORD),('Administrator password',ADMIN_PASSWORD),
                        ('Data unlock passphrase',DATA_PASSWORD),
                        ('Independent recovery passphrase (retain off this disk)',RECOVERY_PASSWORD)]:
        vm.expect(re.escape(label.encode())+rb' \(at least 16 characters\):');vm.send(value)
        vm.expect(re.escape(('Repeat '+label+':').encode()));vm.send(value)
    vm.action(b'INSTALLATION COMPLETE:',3900 if model!='manual-only' else 900);vm.expect(rb'root@[^\r\n]*[#]');vm.run('sync')


def installed_login(vm: VM) -> None:
    vm.expect(b'LUMA_DATA_UNLOCK: enter data or independent recovery passphrase:');vm.send(DATA_PASSWORD)
    vm.expect(rb'luma-native login:');vm.send('lumaadmin')
    vm.expect(b'Password:');vm.send(ADMIN_PASSWORD);vm.expect(rb'lumaadmin@[^\r\n]*[$]')
    vm.send('sudo -p LUMA_SUDO_PASSWORD: -i')
    vm.expect(rb'[\r\n]LUMA_SUDO_PASSWORD:');vm.send(ADMIN_PASSWORD)
    vm.expect(rb'root@[^\r\n]*[#]')


def installed_ready(vm: VM) -> None:
    installed_login(vm)
    vm.run('grep -qw luma.slot=a /proc/cmdline')
    vm.run('luma-platform boot-health')
    vm.run('systemctl is-active luma-broker.service luma-reference.service luma-boot-health.service')
    vm.run('veritysetup status root && cryptsetup status luma-data')
    vm.run('test "$(getent passwd | awk -F: \'$3 == 1000 {n++} END {print n}\')" = 1')
    vm.run('test ! -e /media/luma/release.json')
    vm.run('touch /etc/luma-must-not-write',expected=1)
    vm.run('systemctl show luma-reference.service -p MemoryMax -p MemorySwapMax -p TasksMax -p NoNewPrivileges -p AppArmorProfile')
    vm.run('aa-exec -p luma-reference -- /usr/bin/python3 -c '+shlex.quote("open('/etc/shadow').read()"),expected=1)
    vm.run('aa-exec -p luma-reference -- /usr/bin/python3 -c '+shlex.quote("open('/dev/vda', 'rb').read(1)"),expected=1)
    vm.run('runuser -u lumauser -- luma-platform status',expected=1)
    vm.run('runuser -u luma-control -- luma-platform status')
    probe="import socket,struct,json,time; s=socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect('/run/luma-broker/control.sock'); b=json.dumps({'schema_version':1,'request_id':'forged-peer','caller':0,'deadline':int(time.time())+10,'action':'stop-worker'}).encode(); s.sendall(struct.pack('!I',len(b))+b); n=struct.unpack('!I',s.recv(4))[0]; assert n<=16384; assert json.loads(s.recv(n))['result']=='denied'"
    vm.run('runuser -u luma-control -- python3 -c '+shlex.quote(probe))
    expired=probe.replace("'forged-peer'","'expired'").replace('int(time.time())+10','0')
    vm.run('python3 -c '+shlex.quote(expired))
    oversized="import socket,struct,json; s=socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect('/run/luma-broker/control.sock'); s.sendall(struct.pack('!I',16385)); n=struct.unpack('!I',s.recv(4))[0]; assert n<=16384; assert json.loads(s.recv(n))['result']=='denied'"
    vm.run('python3 -c '+shlex.quote(oversized))
    vm.run('systemctl is-active luma-broker.service luma-reference.service')
    status=vm.run('pid=$(systemctl show --value -p MainPID luma-reference.service); grep -E \'^(NoNewPrivs:|Seccomp:|CapEff:)\' /proc/$pid/status')
    for field,value in [(b'NoNewPrivs',b'1'),(b'Seccomp',b'2'),(b'CapEff',b'0000000000000000')]:
        if not re.search(field+rb':\s*'+value+rb'\s',status):
            raise RuntimeError(f'Kernel worker restriction not active: {field!r}')
    vm.run('test "$(cat /sys/fs/cgroup/system.slice/luma-reference.service/memory.max)" = 536870912')
    vm.run('test "$(cat /sys/fs/cgroup/system.slice/luma-reference.service/memory.swap.max)" = 0')
    vm.run('test "$(cat /sys/fs/cgroup/system.slice/luma-reference.service/pids.max)" = 64')
    vm.run('printf persistent-fixture > /home/lumauser/recovery-test.txt && sync')


def inject_trial_failure(vm: VM) -> None:
    # Real filesystem failure in the essential health checkpoint, not a mocked
    # boot counter. Only this harness's disposable installed disk is affected.
    vm.run('test "$(cat /var/lib/luma-os/health-probe)" = durable && rm /var/lib/luma-os/health-probe && mkdir /var/lib/luma-os/health-probe')
    code="from pathlib import Path; p=list(Path('/efi/EFI/Linux').glob('luma-a-*.efi')); assert len(p)==1 and '+' not in p[0].name; stem=p[0].stem; p[0].rename(p[0].with_name(stem+'+3.efi')); Path('/efi/loader/loader.conf').write_text('default '+stem+'+[1-3]*.efi\\ntimeout 3\\neditor no\\nauto-entries no\\n')"
    vm.run('python3 -c '+shlex.quote(code));vm.run('sync')


def failed_trial(vm: VM) -> None:
    vm.expect(b'LUMA_DATA_UNLOCK: enter data or independent recovery passphrase:');vm.send(DATA_PASSWORD)
    vm.expect(rb'luma-platform: Is a directory')
    if vm.wait_exit()!=0:
        raise RuntimeError('Trial failure did not request the expected reboot')


def fallback_ready(vm: VM) -> None:
    installed_login(vm)
    vm.run('grep -qw luma.slot=b /proc/cmdline')
    code="from pathlib import Path; p=list(Path('/efi/EFI/Linux').glob('luma-a-*.efi')); assert len(p)==1 and p[0].name.endswith('+0-3.efi')"
    vm.run('python3 -c '+shlex.quote(code))
    vm.run('grep -Fx persistent-fixture /home/lumauser/recovery-test.txt')
    vm.run('rmdir /var/lib/luma-os/health-probe')
    vm.run('systemctl reset-failed luma-boot-health.service && systemctl start luma-boot-health.service')
    vm.run('luma-platform boot-health');vm.run('sync')


def recovery(vm: VM) -> None:
    print('VM: independent recovery unlock, export, disable, and repair',flush=True)
    for action in ('repair-data','unlock','export','disable-model'):
        if action=='export':vm.run('mkdir /tmp/luma-export')
        suffix=' /tmp/luma-export' if action=='export' else ''
        vm.send(f'luma-platform recover {action} {TARGET}{suffix}')
        verb='REPAIR-DATA' if action=='repair-data' else 'RECOVER'
        vm.expect(('Type exactly: '+verb+' LUMA-VM-TARGET').encode());vm.send(verb+' LUMA-VM-TARGET')
        vm.expect(b'Enter data or independent recovery passphrase:');vm.send(RECOVERY_PASSWORD)
        success={'repair-data':b'Encrypted data filesystem checked/repaired','unlock':b'successfully unlocked','export':b'Encrypted data exported','disable-model':b'Model disabled.'}[action]
        vm.action(success);vm.expect(rb'root@[^\r\n]*[#]')
    vm.run('tar -xOf /tmp/luma-export/luma-user-data.tar home/lumauser/recovery-test.txt | grep -Fx persistent-fixture')
    vm.send(f'luma-platform recover repair-b {TARGET} /media/luma')
    vm.action(b'Type exactly: REPAIR LUMA-VM-TARGET',900);vm.send('REPAIR LUMA-VM-TARGET')
    vm.action(b'Selected system slot repaired; encrypted data was not formatted.',900)
    vm.expect(rb'root@[^\r\n]*[#]');vm.run('sync')


def repaired_ready(vm: VM,slot: str='b') -> None:
    installed_login(vm)
    vm.run('luma-platform boot-health')
    vm.run(f'grep -qw luma.slot={slot} /proc/cmdline')
    vm.run('grep -Fx persistent-fixture /home/lumauser/recovery-test.txt')
    vm.run('test -f /var/lib/luma-os/model-disabled')
    vm.run('systemctl is-active luma-reference.service')
    vm.run('test "$(systemctl is-active luma-model.service)" = inactive')
    vm.run('luma-platform status')
    vm.run('sync')


def corrupt_inactive_root(vm: VM) -> None:
    repaired_ready(vm)
    vm.run('dd if=/dev/zero of=/dev/disk/by-partlabel/luma-root-a bs=4096 count=1 conv=notrunc,fsync')
    code="from pathlib import Path; p=list(Path('/efi/EFI/Linux').glob('luma-a-*.efi')); assert len(p)==1; stem=p[0].stem.split('+')[0]; p[0].rename(p[0].with_name(stem+'+3.efi')); Path('/efi/loader/loader.conf').write_text('default '+stem+'+[1-3]*.efi\\ntimeout 3\\neditor no\\nauto-entries no\\n')"
    vm.run('python3 -c '+shlex.quote(code));vm.run('sync')


def corrupted_trial(vm: VM) -> None:
    vm.expect(rb'device-mapper: verity:[^\r\n]*data block 0 is corrupted')
    vm.expect(rb'Kernel panic',30)
    if vm.wait_exit(timeout=60)!=0:raise RuntimeError('corrupted trial did not reboot')


def repair_corrupted_a(vm: VM) -> None:
    vm.send(f'luma-platform recover repair-a {TARGET} /media/luma')
    vm.action(b'Type exactly: REPAIR LUMA-VM-TARGET',900);vm.send('REPAIR LUMA-VM-TARGET')
    vm.action(b'Selected system slot repaired; encrypted data was not formatted.',900)
    vm.expect(rb'root@[^\r\n]*[#]');vm.run('sync')


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True);parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--timeout',type=int,default=1800);parser.add_argument('--smoke-only',action='store_true')
    parser.add_argument('--secure-boot',action='store_true')
    parser.add_argument('--accel',choices=('auto','kvm','tcg'),default='auto')
    args=parser.parse_args();image=args.image.resolve(strict=True);work=args.work.resolve()
    if not image.is_file() or not image.is_relative_to('/work/artifacts'):
        raise SystemExit('only generated regular-file images under /work/artifacts are accepted')
    if work.parent!=Path('/work') or not work.name.startswith('vm-') or work.exists():
        raise SystemExit('use a new /work/vm-<run> directory')
    work.mkdir();target=work/'target.qcow2'
    subprocess.run(['qemu-img','create','-f','qcow2',str(target),'32G'],check=True)
    stages=[]
    sequence=[('install',True),('installed',False),('trial-1',False),('trial-2',False),
              ('trial-3',False),('fallback',False),('recovery',True),('repaired',False),
              ('corrupt-trial-1',False),('corrupt-trial-2',False),('corrupt-trial-3',False),
              ('corrupt-fallback',False),('repair-corruption',True),('repaired-a',False)]
    for name,live in sequence:
        print('VM stage: '+name,flush=True);vm=VM(image,work/name,target,live,args.timeout,args.secure_boot,args.accel)
        try:
            if live:live_ready(vm)
            if name=='install' and not args.smoke_only:install(vm)
            elif name=='installed':installed_ready(vm);inject_trial_failure(vm)
            elif name.startswith('trial-'):failed_trial(vm)
            elif name=='fallback':fallback_ready(vm)
            elif name=='recovery':recovery(vm)
            elif name=='repaired':corrupt_inactive_root(vm)
            elif name.startswith('corrupt-trial-'):corrupted_trial(vm)
            elif name=='corrupt-fallback':
                repaired_ready(vm)
                code="from pathlib import Path; p=list(Path('/efi/EFI/Linux').glob('luma-a-*.efi')); assert len(p)==1 and p[0].name.endswith('+0-3.efi')"
                vm.run('python3 -c '+shlex.quote(code))
            elif name=='repair-corruption':repair_corrupted_a(vm)
            elif name=='repaired-a':repaired_ready(vm,'a')
            stages.append(name)
        finally:vm.close()
        if args.smoke_only:break
    with image.open('rb') as stream:image_hash=hashlib.file_digest(stream,'sha256').hexdigest()
    record={'result':'passed','stages':stages,'image_sha256':image_hash,'acceleration':vm.acceleration,
            'uefi':True,'secure_boot_tested':args.secure_boot,'installation_tested':not args.smoke_only,
            'gate_closing':False,'image':str(image),'physical_hardware_tested':False,
            'test_sources':TEST_SOURCES}
    (work/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record),flush=True)


if __name__=='__main__':main()
