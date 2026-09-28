#!/usr/bin/env python3
"""Cut VM power during actual inactive-slot writes, then recover and retry.

Uses only an overlay of a previously passed disposable installed fixture.
This is guest power-loss injection, not physical power-loss certification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import time
from vm_test import VM, TEST_SOURCES, installed_login


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


class QMP:
    def __init__(self,path):
        self.socket=socket.socket(socket.AF_UNIX);self.socket.settimeout(10);self.socket.connect(str(path))
        self.stream=self.socket.makefile('rwb',buffering=0)
        json.loads(self.stream.readline());self.command('qmp_capabilities')
    def command(self,name):
        self.stream.write(json.dumps({'execute':name}).encode()+b'\n')
        while True:
            message=json.loads(self.stream.readline())
            if 'return' in message:return message['return']
            if 'error' in message:raise RuntimeError(message['error'])
    def written(self):
        devices=self.command('query-blockstats')
        selected=[d['stats']['wr_bytes'] for d in devices if d.get('device')=='target']
        if len(selected)!=1:raise RuntimeError('could not identify target write counter')
        return selected[0]
    def close(self):self.stream.close();self.socket.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-image',type=Path,required=True)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--base-run',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True)
    a=parser.parse_args();base_image=a.base_image.resolve(strict=True);candidate=a.candidate.resolve(strict=True)
    base=a.base_run.resolve(strict=True);work=a.work.resolve()
    if not base_image.is_file() or not base_image.is_relative_to('/baseline/artifacts'):
        raise SystemExit('base image must be a readonly baseline artifact')
    if not candidate.is_file() or not candidate.is_relative_to('/work/artifacts'):
        raise SystemExit('candidate must be a generated artifact')
    if base.parent!=Path('/baseline') or not base.name.startswith('vm-'):
        raise SystemExit('base must be a retained baseline VM run')
    prior=json.loads((base/'result.json').read_text())
    if prior.get('result')!='passed' or prior.get('stages',[])[-1:]!=['repaired-a'] or prior['image_sha256']!=digest(base_image):
        raise SystemExit('base does not match passing full-suite evidence')
    current=json.loads((base_image.parent/'release.json').read_text())
    updated=json.loads((candidate.parent/'release.json').read_text())
    if updated['sequence']<=current['sequence']:raise SystemExit('candidate sequence must increase')
    if work.parent!=Path('/work') or not work.name.startswith('vm-') or work.exists():
        raise SystemExit('use a fresh generated VM directory')
    backing=(base/'target.qcow2').resolve(strict=True)
    if not backing.is_file() or not backing.is_relative_to(base):raise SystemExit('invalid baseline disk')
    work.mkdir();target=work/'target.qcow2'
    subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(backing),str(target)],check=True)
    stages=[];written=None
    for stage in ('cut-during-write','reconcile-and-retry','updated-after-cut'):
        print('Power-cut VM stage: '+stage,flush=True)
        media=base_image if stage=='updated-after-cut' else candidate
        vm=VM(media,work/stage,target,False,2400,attach_media=True)
        try:
            installed_login(vm);vm.run('luma-platform boot-health')
            vm.run('grep -Fx persistent-fixture /home/lumauser/recovery-test.txt')
            if stage in ('cut-during-write','reconcile-and-retry'):
                vm.run('grep -qw luma.slot=a /proc/cmdline')
                if stage=='reconcile-and-retry':
                    vm.run('test ! -e /var/lib/luma-os/pending.json && test -f /var/lib/luma-os/failed-update.json')
                qmp=QMP(vm.socket_dir/'qmp.sock') if stage=='cut-during-write' else None
                vm.send('luma-platform update /media/luma')
                vm.action(b'Type exactly: UPDATE LUMA-VM-TARGET',900)
                # Exclude the verified bundle snapshot written before consent.
                before=qmp.written() if qmp else None
                vm.send('UPDATE LUMA-VM-TARGET')
                vm.action(b'Writing and verifying system slot b',60)
                if qmp:
                    try:
                        end=time.monotonic()+30
                        while time.monotonic()<end:
                            written=qmp.written()-before
                            if written>=32*1024*1024:break
                            time.sleep(.05)
                        else:raise RuntimeError('no observed inactive-slot writes; refusing a false injection claim')
                        if written>=updated['root_bytes']:raise RuntimeError('missed bounded mid-write injection window')
                        vm.process.kill();vm.process.wait(timeout=10)
                    finally:qmp.close()
                else:
                    vm.action(b'Inactive slot staged for at most three trial boots.',900)
                    vm.expect(rb'root@[^\r\n]*[#]');vm.run('sync')
            else:
                vm.run('grep -qw luma.slot=b /proc/cmdline')
                vm.run('grep -Fx '+updated['release']+' /usr/share/luma-os/release-id')
                vm.run('test ! -e /var/lib/luma-os/pending.json')
                vm.run('systemctl is-active luma-reference.service')
                vm.run('test -f /var/lib/luma-os/model-disabled')
                vm.run('test "$(systemctl is-active luma-model.service)" = inactive')
                refusal=vm.run('luma-platform update /media/luma',expected=1,timeout=900)
                if b'update sequence must increase' not in refusal:
                    raise RuntimeError('older signed bundle was not refused')
                vm.run('test ! -e /var/lib/luma-os/pending.json')
                vm.run('sync')
            stages.append(stage)
        finally:vm.close()
    record={'result':'passed','stages':stages,'base_image_sha256':prior['image_sha256'],
        'candidate_image_sha256':digest(candidate),'observed_target_write_bytes_at_cut':written,
        'injection':'QEMU SIGKILL during inactive-slot writes','original_fixture_modified':False,
        'older_signed_sequence_refused':True,'model_disable_preserved':True,
        'physical_power_loss_tested':False,'secure_boot_tested':False,'gate_closing':False,'test_sources':TEST_SOURCES}
    (work/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record),flush=True)


if __name__=='__main__':main()
