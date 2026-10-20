#!/usr/bin/env python3
"""Real merged image-bus policy proof, only in a disposable root container.

The provider observes transport delivery, not hardware writes. No host bus,
backlight, power daemon, TPM, account or product Admin authority is exercised.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def child(address, destination, interface, member):
    from gi.repository import Gio, GLib
    connection = Gio.DBusConnection.new_for_address_sync(address,
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
        None, None)
    try:
        body = (GLib.Variant('(ssu)', ('backlight', 'intel_backlight', 10))
                if member == 'SetBrightness' else
                GLib.Variant('(ssv)', (destination if destination in ('net.hadess.PowerProfiles', 'org.freedesktop.UPower.PowerProfiles') else 'org.freedesktop.UPower.PowerProfiles', 'ActiveProfile', GLib.Variant('s', 'balanced')))
                if member == 'Set' else
                GLib.Variant('(sss)', ('power-saver', 'fixture', 'luma-policy-fixture'))
                if member == 'HoldProfile' else
                GLib.Variant('(ss)', (destination, 'ActiveProfile'))
                if member == 'Get' else
                GLib.Variant('(u)', (1,)))
        path = ('/org/freedesktop/login1/session/fixture' if member == 'SetBrightness' else
                '/net/hadess/PowerProfiles' if destination == 'net.hadess.PowerProfiles' else
                '/org/freedesktop/UPower/PowerProfiles')
        message = Gio.DBusMessage.new()
        message.set_message_type(Gio.DBusMessageType.METHOD_CALL)
        message.set_destination(destination)
        message.set_path(path)
        if interface:
            message.set_interface(interface)
        message.set_member(member)
        message.set_body(body)
        reply, unused = connection.send_message_with_reply_sync(message,
            Gio.DBusSendMessageFlags.NONE, 1000, None)
        if reply.get_message_type() == Gio.DBusMessageType.ERROR:
            print(reply.get_error_name())
        elif reply.get_message_type() == Gio.DBusMessageType.METHOD_RETURN:
            print('delivered')
        else:
            raise RuntimeError('unexpected actual bus reply type')
    except GLib.Error as error:
        print(Gio.DBusError.get_remote_error(error) or str(error))
    finally:
        connection.close_sync(None)


def main():
    if len(sys.argv) == 6 and sys.argv[1] == '--client':
        child(*sys.argv[2:])
        return
    if os.getpid() != 1 or os.geteuid() != 0 or not Path('/.dockerenv').is_file() or len(sys.argv) != 3:
        raise RuntimeError('this image-mediation proof requires its own disposable root container as PID1')
    from gi.repository import Gio, GLib
    repo, package = Path(sys.argv[1]), Path(sys.argv[2])
    spec = importlib.util.spec_from_file_location('hardware_policy', repo / 'native/image/hardware_policy.py')
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    for destination in policy.POWER:
        relative = 'usr/share/dbus-1/system.d/' + destination + '.conf'
        original = (package / 'extracted' / relative).read_bytes()
        if hashlib.sha256(original).hexdigest() != policy.ORIGINALS[relative]:
            raise RuntimeError('fixture package differs from the exact pinned policy')
        shutil.copyfile(package / 'extracted' / relative, Path('/') / relative)
    for relative, expected in policy.PPD_FILES.items():
        source = package / 'extracted' / relative
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise RuntimeError('fixture package executable/service tuple differs')
        destination = Path('/') / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(source.stat().st_mode & 0o777)
    configured = policy.configure(Path('/'), 'desktop')
    verified = policy.verify(Path('/'))
    original_manifest = Path('/' + policy.MANIFEST).read_bytes()
    rule = Path('/' + policy.POLKIT_NAME)
    original_rule = rule.read_bytes()
    tamper_refusals = 0
    try:
        rule.write_bytes(original_rule + b'// changed bytes\n')
        for rehash_manifest in (False, True):
            if rehash_manifest:
                changed = json.loads(original_manifest)
                changed['ordinary_writer_inputs'][policy.POLKIT_NAME] = hashlib.sha256(rule.read_bytes()).hexdigest()
                Path('/' + policy.MANIFEST).write_text(json.dumps(changed, sort_keys=True, separators=(',', ':')) + '\n')
            try:
                policy.verify(Path('/'))
            except ValueError:
                tamper_refusals += 1
            else:
                raise RuntimeError('runtime policy verifier accepted changed/self-rehashed mediation')
    finally:
        rule.write_bytes(original_rule)
        Path('/' + policy.MANIFEST).write_bytes(original_manifest)
    if policy.verify(Path('/')) != verified or tamper_refusals != 2:
        raise RuntimeError('restored exact policy verification differs')
    installed = Path('/usr/libexec/luma-os/hardware_writer_verify.py')
    installed.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    shutil.copyfile(repo / 'native/image/hardware_policy.py', installed)
    installed.chmod(0o644)
    command = ['/usr/bin/python3', '-I', '-B', str(installed), '--verify']
    actual_cli = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=3, check=True, env={'PATH': '/usr/bin', 'LC_ALL': 'C'})
    if actual_cli.stderr or json.loads(actual_cli.stdout) != verified:
        raise RuntimeError('actual installed isolated verifier CLI differs from complete current closure')
    refused_cli = subprocess.run(command + ['/arbitrary-root'], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=3, check=False, env={'PATH': '/usr/bin', 'LC_ALL': 'C'})
    if refused_cli.returncode == 0 or refused_cli.stdout:
        raise RuntimeError('installed verifier accepted arbitrary root/extra arguments')
    Path('/run/dbus').mkdir(mode=0o755, exist_ok=True)
    socket = '/run/luma-hardware-policy-fixture.sock'
    # Load the ACTUAL image system.conf and its actual merged includedirs. Only
    # the added isolated listener differs; its stock /run/dbus listener is also
    # private to this empty container. No alternate hand-written policy is used.
    private = Path('/run/luma-hardware-policy-fixture.conf')
    private.write_text('<busconfig><include>/usr/share/dbus-1/system.conf</include><listen>unix:path=' + socket + '</listen></busconfig>')
    process = subprocess.Popen(['/usr/bin/dbus-daemon', '--config-file=' + str(private), '--nofork', '--nopidfile'],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    server = None
    observed = []
    results = []
    try:
        deadline = time.monotonic() + 5
        while not Path(socket).exists():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('actual merged image-bus daemon did not become ready')
            time.sleep(.02)
        address = 'unix:path=' + socket
        server = Gio.DBusConnection.new_for_address_sync(address,
            Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
            None, None)
        def receive(connection, message, incoming, unused):
            if incoming and message.get_message_type() == Gio.DBusMessageType.METHOD_CALL:
                observed.append((message.get_interface(), message.get_member(), message.get_sender()))
                response = Gio.DBusMessage.new_method_reply(message)
                response.set_body(GLib.Variant('()', ()))
                connection.send_message(response, Gio.DBusSendMessageFlags.NONE)
                return None
            return message
        server.add_filter(receive, None)
        for name in (policy.LOGIN, *policy.POWER):
            value = server.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus',
                'org.freedesktop.DBus', 'RequestName', GLib.Variant('(su)', (name, 0)),
                GLib.VariantType.new('(u)'), Gio.DBusCallFlags.NONE, 1000, None)
            if value.unpack() != (1,):
                raise RuntimeError('root provider did not own the exact supported service name')
        calls = [(policy.LOGIN, policy.LOGIN + '.Session', 'SetBrightness'),
                 (policy.LOGIN, '', 'SetBrightness'),
                 (server.get_unique_name(), policy.LOGIN + '.Session', 'SetBrightness')]
        for name in policy.POWER:
            calls.extend([(name, 'org.freedesktop.DBus.Properties', 'Set'),
                          (name, '', 'Set'), (name, name, 'HoldProfile'),
                          (name, name, 'ReleaseProfile')])
        calls.extend([(server.get_unique_name(), 'org.freedesktop.DBus.Properties', 'Set'),
                      (server.get_unique_name(), policy.POWER[0], 'HoldProfile')])
        for destination, interface, member in calls:
            for uid in (65534, 0):
                before = len(observed)
                def ordinary():
                    os.setgroups([])
                    os.setgid(65534)
                    os.setuid(65534)
                completed = subprocess.run(['/usr/bin/python3', '-B', str(Path(__file__)), '--client',
                    address, destination, interface, member], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=3, check=False,
                    preexec_fn=ordinary if uid else None,
                    env={'PATH': '/usr/bin', 'LC_ALL': 'C'})
                result = completed.stdout.decode().strip()
                if completed.returncode:
                    raise RuntimeError('fixture client failed: ' + completed.stderr.decode(errors='replace')[:8192])
                if uid and (result != 'org.freedesktop.DBus.Error.AccessDenied' or len(observed) != before):
                    raise RuntimeError('ordinary caller crossed actual merged write policy: ' + repr((destination, interface, member, result)))
                if not uid and (result != 'delivered' or len(observed) != before + 1):
                    raise RuntimeError('trusted root provider path was blocked: ' + repr((destination, interface, member, result)))
                results.append({'uid': uid, 'destination': destination, 'interface': interface,
                                'member': member, 'result': result})
        for destination in policy.POWER:
            before = len(observed)
            def ordinary_read():
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
            completed = subprocess.run(['/usr/bin/python3', '-B', str(Path(__file__)), '--client',
                address, destination, 'org.freedesktop.DBus.Properties', 'Get'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, check=True,
                preexec_fn=ordinary_read, env={'PATH': '/usr/bin', 'LC_ALL': 'C'})
            if completed.stdout.decode().strip() != 'delivered' or len(observed) != before + 1:
                raise RuntimeError('ordinary read-only manual status path was blocked')
            results.append({'uid': 65534, 'destination': destination,
                            'interface': 'org.freedesktop.DBus.Properties', 'member': 'Get',
                            'result': 'delivered'})
        output = {'schema_version': 1, 'status': 'passed', 'cases': results,
                  'read_only_verifier': verified, 'actual_tamper_refusals': tamper_refusals,
                  'actual_installed_isolated_cli': True, 'arbitrary_root_cli_refused': True,
                  'actual_merged_bus_inputs': configured['bus_inputs'],
                  'writer_inputs': configured['ordinary_writer_inputs'],
                  'source_sha256': {name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
                      for name in ('native/image/hardware_policy.py', 'native/tests/hardware_bus_integration.py')},
                  'host_configuration_changed': False, 'actual_hardware_written': False,
                  'product_authority_qualified': False, 'installed_qualified': False}
        print(json.dumps(output, sort_keys=True))
    finally:
        if server is not None:
            server.close_sync(None)
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        stdout, stderr = process.communicate()
        if stderr:
            print(stderr.decode(errors='replace'), file=sys.stderr)


if __name__ == '__main__':
    main()
