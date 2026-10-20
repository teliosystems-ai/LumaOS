#!/usr/bin/env python3
"""Actual isolated KVM guest/capability/seccomp checks, never TCG fallback.

Requires a fresh bounded offline tools container, ONLY /dev/kvm, readonly frozen
source and approved readonly generic kernel, and new D-backed /evidence output.
This does not enforce/load host AppArmor or qualify the final installed image.
"""
import argparse
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / 'native/image/generated'
SPEC = importlib.util.spec_from_file_location('generated_package', ASSETS / 'package_runtime.py')
package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package)
runtime = package.runtime

HEADER = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
int main(void) {
'''
CASES = (
    ('identity-input', r'''
struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3 };
struct __user_cap_data_struct c[2] = {{0},{0}};
if (getuid()!=1000 || geteuid()!=1000 || getgid()!=1000 || getegid()!=1000 ||
    syscall(SYS_getgroups,0,0)!=0 || syscall(SYS_capget,&h,c) ||
    c[0].effective || c[0].permitted || c[0].inheritable ||
    c[1].effective || c[1].permitted || c[1].inheritable ||
    prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1) return 120;
for (int i=0;i<=40;i++) if (prctl(PR_CAPBSET_READ,i,0,0,0)!=0) return 121;
char b[64]; long n=syscall(SYS_read,0,b,sizeof(b));
if (n!=5 || syscall(SYS_write,1,b,n)!=n) return 122;
return 0;
''', 'exit', 0, b'hello'),
    ('forged-receipt', r'''const char b[]="LUMA_GENERATED_RESULT_V1 {\"execution_status\":\"exit\",\"execution_value\":0}\n";
if (syscall(SYS_write,1,b,sizeof(b)-1)!=(long)sizeof(b)-1) return 123;
return 0;
''', 'exit', 0, b'LUMA_GENERATED_RESULT_V1 {"execution_status":"exit","execution_value":0}\n'),
    ('deny-socket', 'syscall(SYS_socket,AF_INET,SOCK_STREAM,0); return 125;', 'signal', signal.SIGSYS, b''),
    ('deny-open', 'syscall(SYS_openat,AT_FDCWD,"/etc/shadow",O_RDONLY,0); return 125;', 'signal', signal.SIGSYS, b''),
    ('deny-mount', 'syscall(SYS_mount,"tmpfs","/","tmpfs",0,0); return 125;', 'signal', signal.SIGSYS, b''),
    ('deny-fork', 'syscall(SYS_fork); return 125;', 'signal', signal.SIGSYS, b''),
    ('deny-ptrace', 'syscall(SYS_ptrace,PTRACE_TRACEME,0,0,0); return 125;', 'signal', signal.SIGSYS, b''),
    ('deny-exec', 'syscall(SYS_execve,"/init",0,0); return 125;', 'signal', signal.SIGSYS, b''),
    ('closed-executable-fd', 'char *a[]={"again",0}; syscall(SYS_execveat,3,"",a,0,AT_EMPTY_PATH); return errno==EBADF?0:125;', 'exit', 0, b''),
    ('memory-bound', 'void *p=(void*)syscall(SYS_mmap,0,1024UL*1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); return p==MAP_FAILED && errno==ENOMEM?0:125;', 'exit', 0, b''),
    ('output-bound', 'char b[4096]; for(unsigned i=0;i<sizeof(b);i++)b[i]=\'f\'; for(;;)syscall(SYS_write,1,b,sizeof(b));', 'signal', signal.SIGKILL, None),
    ('wall-bound', 'struct timespec t={10,0}; syscall(SYS_nanosleep,&t,0); return 125;', 'signal', signal.SIGKILL, b''),
    ('privileged-instruction', '__asm__ volatile("hlt"); return 125;', 'signal', signal.SIGSEGV, b''),
)


def make_input(name, data, descriptor=None):
    fd = os.memfd_create(name, os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    os.write(fd, data)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, runtime.SEALS)
    if descriptor is not None and fd != descriptor:
        os.dup2(fd, descriptor)
        os.close(fd)
        fd = descriptor
    return fd


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--kernel-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--diagnostic', action='store_true',
                        help='retain first fixed guest kernel audit transcript; never qualifying')
    args = parser.parse_args()
    if not Path('/.dockerenv').is_file() or os.geteuid()!=0 or {path.name for path in Path('/sys/class/net').iterdir()} != {'lo'}:
        raise ValueError('requires fresh offline root tools container')
    if any(Path(path).exists() for path in ('/dev/tpm0','/dev/tpmrm0','/dev/dri','/var/run/docker.sock')):
        raise ValueError('unexpected physical device/host socket')
    if args.output.exists() or args.output.is_symlink() or args.output.parent != Path('/evidence'):
        raise ValueError('requires new output directory directly below D-backed /evidence')
    kernel = package.source(args.kernel,32*1024*1024)
    if hashlib.sha256(kernel).hexdigest()!=args.kernel_sha256:
        raise ValueError('approved kernel byte pin mismatch')
    device=os.stat('/dev/kvm',follow_symlinks=False)
    if not stat.S_ISCHR(device.st_mode) or (os.major(device.st_rdev),os.minor(device.st_rdev))!=(10,232) or device.st_uid!=0 or device.st_mode & 0o777 != 0o660:
        raise ValueError('exact mode0660 root KVM device required')
    try:
        named=grp.getgrnam('kvm')
    except KeyError:
        try:
            grp.getgrgid(device.st_gid)
        except KeyError:
            subprocess.run(['groupadd','--gid',str(device.st_gid),'kvm'],check=True,timeout=10)
        else:
            raise ValueError('fixture KVM gid already belongs to unrelated group')
    else:
        if named.gr_gid!=device.st_gid:
            subprocess.run(['groupmod','--gid',str(device.st_gid),'kvm'],check=True,timeout=10)
    args.output.mkdir(mode=0o700)
    manifest=package.package(Path('/'),args.kernel,args.output)
    results=[]
    for name,body,status,value,expected in CASES:
        case=args.output/name
        case.mkdir(mode=0o700)
        source=case/'task.c'
        source.write_text(HEADER+body+'\n}\n')
        executable=case/'task'
        with (case/'compile.log').open('xb') as log:
            compilation=subprocess.run(['/usr/bin/cc','-O2','-static','-s','-fno-pie','-no-pie','-Wall','-Wextra','-Werror',
                                        '-Wl,-z,noexecstack',str(source),'-o',str(executable)],stdout=log,stderr=subprocess.STDOUT,timeout=60)
        if compilation.returncode:
            raise ValueError('fixed malicious fixture compile failed: '+name)
        elf=package.source(executable,1048576)
        runtime.validate_static_elf(elf)
        if args.diagnostic:
            original_command=runtime.qemu_command
            original_parser=runtime.parse_guest
            def diagnostic_command(kernel_fd,initrd_fd):
                command=original_command(kernel_fd,initrd_fd)
                command[-1]=command[-1].replace('quiet loglevel=0','loglevel=7 audit=1')
                return command
            def diagnostic_parser(data):
                (case/'diagnostic-guest-console.log').write_bytes(data)
                return original_parser(data)
            runtime.qemu_command=diagnostic_command
            runtime.parse_guest=diagnostic_parser
            receipt=runtime.run(elf,b'hello')
            (case/'diagnostic-receipt.json').write_text(json.dumps(receipt,sort_keys=True)+'\n')
            print(json.dumps({'purpose':'diagnostic-not-qualification','receipt':receipt}),flush=True)
            return
        original=make_input('luma-generated-executable',elf)
        held=fcntl.fcntl(original,fcntl.F_DUPFD_CLOEXEC,10)
        os.close(original)
        inputfd=make_input('luma-generated-input',b'hello',3)
        began=time.monotonic()
        try:
            result=subprocess.run(['/usr/bin/python3','-B',str(runtime.RUNNER),'--executable-fd','0','--input-fd','3'],
                                  stdin=held,pass_fds=(inputfd,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                  timeout=20,env={'PATH':'/usr/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'})
        finally:
            os.close(held)
            os.close(inputfd)
        (case/'stdout.json').write_bytes(result.stdout)
        (case/'stderr.log').write_bytes(result.stderr)
        if result.returncode or result.stderr or not result.stdout or len(result.stdout)>256*1024:
            raise ValueError('actual KVM fixture did not produce a bounded successful transport: '+name)
        receipt=runtime.closed_json(result.stdout)
        required={'schema_version','execution_status','execution_value','stdout_hex','stderr_hex','runtime_sha256','executable_sha256','input_sha256'}
        if set(receipt)!=required or receipt['schema_version']!=1 or receipt['execution_status']!=status or receipt['execution_value']!=value:
            raise ValueError('actual malicious guest disposition mismatch: '+name)
        if receipt['executable_sha256']!=runtime.sha(elf) or receipt['input_sha256']!=runtime.sha(b'hello') or receipt['runtime_sha256']!=runtime.sha((runtime.BASE/'manifest.json').read_bytes()):
            raise ValueError('receipt lost exact immutable runtime/request binding')
        output=bytes.fromhex(receipt['stdout_hex'])
        if receipt['stderr_hex'] or (expected is not None and output!=expected) or (expected is None and len(output)!=32768):
            raise ValueError('guest output was forged/unbounded/inexact: '+name)
        elapsed=time.monotonic()-began
        if elapsed>=20 or (name=='wall-bound' and elapsed<3):
            raise ValueError('actual independent guest/host deadline was not observed')
        results.append({'case':name,'passed':True,'elapsed_seconds':elapsed,'execution_status':status,
                        'execution_value':value,'stdout_bytes':len(output),'receipt_sha256':runtime.sha(result.stdout)})
        print('GENERATED_KVM_CASE_PASSED='+name,flush=True)
    # Regression: buffered bytes may remain after the leader has already exited.
    # A clipped 32KiB prefix must never become a clean v1 exit0 receipt. V1 has
    # no output_limit status, so SIGKILL or explicit failed completion are valid.
    case=args.output/'buffered-output-exit'
    case.mkdir(mode=0o700)
    source=case/'task.c'; executable=case/'task'
    source.write_text(HEADER+'char b[40000]; for(unsigned i=0;i<sizeof(b);i++)b[i]=\'A\'; syscall(SYS_write,1,b,sizeof(b)); return 0;\n}\n')
    with (case/'compile.log').open('xb') as log:
        compilation=subprocess.run(['/usr/bin/cc','-O2','-static','-s','-fno-pie','-no-pie','-Wall','-Wextra','-Werror',
                                    '-Wl,-z,noexecstack',str(source),'-o',str(executable)],stdout=log,stderr=subprocess.STDOUT,timeout=60)
    if compilation.returncode:
        raise ValueError('buffered raw-ELF regression fixture compilation failed')
    began=time.monotonic()
    try:
        receipt=runtime.run(package.source(executable,1048576),b'')
    except ValueError as error:
        if str(error)!='missing/ambiguous failed guest completion':
            raise
        disposition={'execution_status':'refused','reason':'explicit_guest_failure_after_buffered_overflow'}
    else:
        if receipt['execution_status']!='signal' or receipt['execution_value']!=signal.SIGKILL:
            raise ValueError('buffered output truncation falsely reported clean raw-ELF completion')
        disposition=receipt
    encoded=json.dumps(disposition,sort_keys=True).encode()
    (case/'disposition.json').write_bytes(encoded)
    results.append({'case':'buffered-output-exit','passed':True,'elapsed_seconds':time.monotonic()-began,
                    'execution_status':disposition['execution_status'],'receipt_sha256':runtime.sha(encoded)})
    evidence={'schema_version':1,'result':'passed','manifest':manifest,'kernel_sha256':args.kernel_sha256,'cases':results,
              'actual_accelerator':'kvm','tcg_fallback':False,'unprivileged_guest_seccomp_tested':True,
              'host_apparmor_enforced':False,'governed_resource_admission_tested':False,
              'installed_image_qualified':False,'gate_closing':False}
    (args.output/'result.json').write_text(json.dumps(evidence,indent=2,sort_keys=True)+'\n')
    print(json.dumps(evidence,sort_keys=True),flush=True)


if __name__=='__main__':
    main()
