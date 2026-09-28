#!/usr/bin/env python3
"""Probe only regular generated files on an explicitly mounted external directory."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    root=Path('/probe')
    if root.is_symlink() or not root.is_mount() or any(root.iterdir()):
        raise SystemExit('mount a new empty generated directory at /probe')
    fixture=root/'regular-file.bin'
    with fixture.open('xb') as stream:
        stream.write(b'Luma storage probe\n'+bytes(1024*1024))
        stream.flush();os.fsync(stream.fileno())
    with fixture.open('r+b') as stream:
        fcntl.lockf(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        code="import fcntl,sys; f=open(sys.argv[1],'r+b')\ntry: fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(0)\nelse: sys.exit(1)"
        subprocess.run([sys.executable,'-c',code,str(fixture)],check=True)
    disk=root/'probe.qcow2'
    subprocess.run(['qemu-img','create','-f','qcow2',str(disk),'32M'],check=True)
    subprocess.run(['qemu-io','-f','qcow2','-c','write -P 0xa5 0 1M','-c','flush',str(disk)],check=True)
    subprocess.run(['qemu-io','-f','qcow2','-c','read -P 0xa5 0 1M',str(disk)],check=True)
    subprocess.run(['qemu-img','check',str(disk)],check=True)
    record={'result':'passed','checks':['file fsync','cross-process exclusive lock','qcow2 write/read/check'],
        'probe_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest(),
        'qualification':False,'physical_disk_opened':False}
    (root/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record),flush=True)


if __name__=='__main__':main()
