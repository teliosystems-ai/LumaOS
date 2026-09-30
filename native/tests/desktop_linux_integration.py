#!/usr/bin/env python3
"""Real GNOME/Wayland application smoke test in a disposable Linux container.

No host display, GPU, system bus, TPM, credentials, or input devices are used.
This is not GDM login, installed-image, lock-screen or physical qualification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'image'))
import desktop_policy


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def wait_for(predicate, processes, timeout=30):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        if any(process.poll() is not None for process in processes):
            raise RuntimeError('graphical process exited before the expected observation')
        time.sleep(.1)
    raise TimeoutError('bounded graphical observation timed out')


def child(work):
    if os.geteuid() != 1000:
        raise RuntimeError('compositor and applications must run unprivileged')
    processes = []
    handles = []
    def launch(name, command, debug=False):
        log = (work/(name+'.log')).open('wb')
        handles.append(log)
        environment = dict(os.environ)
        if debug:
            environment['WAYLAND_DEBUG'] = 'client'
        process = subprocess.Popen(command, env=environment, stdout=log, stderr=log,
                                   start_new_session=True)
        processes.append(process)
        return process
    try:
        compositor = launch('compositor', [
            '/usr/bin/gnome-shell', '--wayland', '--headless', '--no-x11',
            '--virtual-monitor=1280x720', '--wayland-display=luma-test-0',
        ])
        socket = Path(os.environ['XDG_RUNTIME_DIR'])/'luma-test-0'
        wait_for(lambda: socket.is_socket(), [compositor])
        if socket.stat().st_uid != 1000:
            raise RuntimeError('wrong compositor socket owner')
        fixture = work/'manual-file.txt'
        fixture.write_text('Luma manual file fixture; no model is running.\n')
        results = []
        for name, command in (
            ('editor', ['/usr/bin/gnome-text-editor', str(fixture)]),
            ('files', ['/usr/bin/nautilus', '--new-window', str(work)]),
            ('terminal', ['/usr/bin/kgx', '--', '/usr/bin/sleep', '20']),
        ):
            application = launch(name, command, True)
            def mapped():
                log = (work/(name+'.log')).read_bytes()
                return b'xdg_surface' in log and b'ack_configure' in log and b'wl_surface' in log and b'.commit(' in log
            wait_for(mapped, [compositor, application])
            results.append({'application': name, 'wayland_surface_configured': True})
            stop(application)
        if fixture.read_text() != 'Luma manual file fixture; no model is running.\n':
            raise RuntimeError('manual file fixture changed unexpectedly')
        if b'Created surfaceless renderer without GPU' not in (work/'compositor.log').read_bytes():
            raise RuntimeError('software-renderer evidence missing')
        record = {'result': 'passed', 'compositor': 'gnome-shell-wayland-headless',
                  'uid': os.geteuid(), 'applications': results,
                  'model_running': False, 'gdm_login_tested': False,
                  'installed_image_tested': False, 'physical_hardware_tested': False,
                  'gate_closing': False}
        (work/'result.json').write_text(json.dumps(record, indent=2)+'\n')
    finally:
        for process in reversed(processes):
            stop(process)
        for handle in handles:
            handle.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--child', type=Path)
    args = parser.parse_args()
    if args.child:
        child(args.child)
        return
    if not Path('/.dockerenv').is_file() or os.geteuid() != 0:
        raise RuntimeError('use a fresh disposable desktop-root container')
    if not args.output or args.output.parent != Path('/evidence') or args.output.exists():
        raise RuntimeError('select a new directory directly beneath /evidence')
    args.output.mkdir(mode=0o700)
    desktop_policy.configure(Path('/'), 'desktop')
    account = pwd.getpwuid(1000)
    with tempfile.TemporaryDirectory(prefix='luma-wayland-') as temporary:
        work = Path(temporary)
        os.chown(work, 1000, 1000)
        runtime = work/'runtime'
        runtime.mkdir(mode=0o700)
        os.chown(runtime, 1000, 1000)
        environment = {'PATH': '/usr/bin:/bin', 'HOME': account.pw_dir,
                       'USER': account.pw_name, 'LOGNAME': account.pw_name,
                       'XDG_RUNTIME_DIR': str(runtime), 'XDG_SESSION_TYPE': 'wayland',
                       'XDG_CURRENT_DESKTOP': 'GNOME', 'WAYLAND_DISPLAY': 'luma-test-0',
                       'GDK_BACKEND': 'wayland', 'LIBGL_ALWAYS_SOFTWARE': '1',
                       'GSETTINGS_BACKEND': 'memory', 'GIO_USE_VFS': 'local',
                       'PYTHONDONTWRITEBYTECODE': '1'}
        # A private container system bus is required by GNOME Shell even with
        # the headless renderer. Never mount or connect to the host system bus.
        Path('/run/dbus').mkdir(exist_ok=True)
        if Path('/run/dbus/system_bus_socket').exists():
            raise RuntimeError('fixture requires its own initially absent system bus')
        bus_log = (work/'system-bus.log').open('wb')
        bus = subprocess.Popen(['/usr/bin/dbus-daemon', '--system', '--nofork', '--nopidfile'],
                               stdout=bus_log, stderr=bus_log, start_new_session=True)
        login = None
        login_log = (work/'logind.log').open('wb')
        try:
            wait_for(lambda: Path('/run/dbus/system_bus_socket').is_socket(), [bus], timeout=10)
            # Real packaged logind, still entirely inside the container; no
            # fake identity/session API and no host service or device mounts.
            login = subprocess.Popen(['/usr/lib/systemd/systemd-logind'],
                                     stdout=login_log, stderr=login_log, start_new_session=True)
            def login_ready():
                reply = subprocess.run(['/usr/bin/busctl', '--system', '--no-pager', 'list'],
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3)
                return reply.returncode == 0 and b'org.freedesktop.login1 ' in reply.stdout
            wait_for(login_ready, [bus, login], timeout=10)
            with (work/'session.log').open('wb') as session_log:
                subprocess.run(['/usr/bin/setpriv', '--reuid=1000', '--regid=1000', '--clear-groups',
                                '/usr/bin/dbus-run-session', '--', '/usr/bin/python3',
                                str(Path(__file__).resolve()), '--child', str(work)],
                               env=environment, check=True, timeout=150,
                               stdout=session_log, stderr=session_log)
        finally:
            if login is not None:
                stop(login)
            login_log.close()
            stop(bus)
            bus_log.close()
            # Export only explicit public test logs/results, not runtime sockets
            # or account/session configuration. Preserve failures as failures.
            for name in ('compositor.log', 'editor.log', 'files.log', 'terminal.log',
                         'system-bus.log', 'logind.log', 'session.log', 'result.json'):
                source = work/name
                if source.is_file() and source.stat().st_size <= 8*1024*1024:
                    shutil.copyfile(source, args.output/name)
    packages = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}=${Version}\n'], text=True)
    (args.output/'packages.lock').write_text(packages)
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in (Path(__file__), Path(desktop_policy.__file__))}
    (args.output/'sources.json').write_text(json.dumps(hashes, indent=2)+'\n')
    print((args.output/'result.json').read_text())


if __name__ == '__main__':
    main()
