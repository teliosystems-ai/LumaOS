"""Real private D-Bus transport fixture, not desktop permission qualification.

Uses a disposable dbus-daemon and a closed scripted portal-shaped fixture.
No desktop bus, microphone, PipeWire service, screen or camera is accessed.
"""
import importlib.util
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import unittest

import gi
gi.require_version('Gio', '2.0')
from gi.repository import Gio, GLib

SPEC = importlib.util.spec_from_file_location('luma_portal_transport', Path(__file__).resolve().parents[1]/'desktop/workspace_capture.py')
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)

XML = '''<node>
<interface name="org.freedesktop.portal.ScreenCast">
<method name="CreateSession"><arg type="a{sv}" direction="in"/><arg type="o" direction="out"/></method>
<method name="SelectSources"><arg type="o" direction="in"/><arg type="a{sv}" direction="in"/><arg type="o" direction="out"/></method>
<method name="Start"><arg type="o" direction="in"/><arg type="s" direction="in"/><arg type="a{sv}" direction="in"/><arg type="o" direction="out"/></method>
<method name="OpenPipeWireRemote"><arg type="o" direction="in"/><arg type="a{sv}" direction="in"/><arg type="h" direction="out"/></method>
</interface>
<interface name="org.freedesktop.portal.Screenshot">
<method name="Screenshot"><arg type="s" direction="in"/><arg type="a{sv}" direction="in"/><arg type="o" direction="out"/></method>
</interface>
<interface name="org.freedesktop.portal.Session"><method name="Close"/></interface>
<interface name="org.freedesktop.portal.Request"><method name="Close"/></interface>
</node>'''


class PortalTransport(unittest.TestCase):
    def setUp(self):
        self.original_address = os.environ.get('DBUS_SESSION_BUS_ADDRESS')
        self.daemon = subprocess.Popen(['/usr/bin/dbus-daemon', '--session', '--nofork', '--print-address=1'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        with selectors.DefaultSelector() as ready:
            ready.register(self.daemon.stdout, selectors.EVENT_READ)
            self.assertTrue(ready.select(3), 'private bus did not become ready')
        address = self.daemon.stdout.readline().decode().strip()
        self.assertTrue(address.startswith('unix:'))
        os.environ['DBUS_SESSION_BUS_ADDRESS'] = address
        self.server = Gio.DBusConnection.new_for_address_sync(address,
            Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
        self.server.set_exit_on_close(False)
        result = self.server.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus',
            'RequestName', GLib.Variant('(su)', (CAPTURE.Portal.NAME, 0)), GLib.VariantType.new('(u)'),
            Gio.DBusCallFlags.NONE, 1000, None).unpack()
        self.assertEqual(result, (1,))
        self.registrations, self.methods, self.options = [], [], []
        self.node = Gio.DBusNodeInfo.new_for_xml(XML)
        for name in ('org.freedesktop.portal.ScreenCast', 'org.freedesktop.portal.Screenshot'):
            self.registrations.append(self.server.register_object(CAPTURE.Portal.PATH, self.node.lookup_interface(name), self.method, None, None))
        self.mode = 'success'
        self.session = None
        self.portals = []
        self.sockets = []
        self.errors = []

    def tearDown(self):
        for portal in self.portals:
            portal.close()
        for descriptor in self.sockets:
            descriptor.close()
        for registration in self.registrations:
            self.server.unregister_object(registration)
        if not self.server.is_closed():
            self.server.close_sync(None)
        self.daemon.terminate()
        self.daemon.communicate(timeout=3)
        if self.original_address is None:
            os.environ.pop('DBUS_SESSION_BUS_ADDRESS', None)
        else:
            os.environ['DBUS_SESSION_BUS_ADDRESS'] = self.original_address

    def spin(self, finished, seconds=3):
        loop = GLib.MainLoop()
        timed_out = [False]
        def inspect():
            if finished() or self.errors:
                loop.quit(); return False
            return True
        def timeout():
            timed_out[0] = True; loop.quit(); return False
        watcher = GLib.timeout_add(5, inspect)
        timer = GLib.timeout_add_seconds(seconds, timeout)
        loop.run()
        if not timed_out[0]:
            GLib.source_remove(timer)
        else:
            GLib.source_remove(watcher)
        self.assertFalse(self.errors, self.errors)
        self.assertFalse(timed_out[0], 'private portal fixture timed out')

    def method(self, _connection, sender, _path, _interface, method, parameters, invocation):
        try:
            self.methods.append(method)
            arguments = parameters.unpack()
            options = arguments[-1]
            self.options.append(options)
            if method == 'OpenPipeWireRemote':
                self.assertEqual(arguments, (self.session, {}))
                left, right = socket.socketpair()
                self.sockets.extend((left, right))
                descriptors = Gio.UnixFDList.new()
                index = descriptors.append(left.fileno())
                invocation.return_value_with_unix_fd_list(GLib.Variant('(h)', (index,)), descriptors)
                return
            token = options['handle_token']
            self.assertRegex(token, r'^luma_[0-9a-f]{32}$')
            client = sender[1:].replace('.', '_')
            path = f'/org/freedesktop/portal/desktop/request/{client}/{token}'
            self.registrations.append(self.server.register_object(path,
                self.node.lookup_interface('org.freedesktop.portal.Request'), self.close_request, None, None))
            invocation.return_value(GLib.Variant('(o)', (path+'/substituted' if self.mode == 'substitution' else path,)))
            results = {}
            if method == 'CreateSession':
                self.session = f'/org/freedesktop/portal/desktop/session/{client}/'+options['session_handle_token']
                self.registrations.append(self.server.register_object(self.session,
                    self.node.lookup_interface('org.freedesktop.portal.Session'), self.close_request, None, None))
                results = {'session_handle': GLib.Variant('s', self.session)}
            elif method == 'SelectSources':
                self.assertEqual(arguments[0], self.session)
                self.assertEqual({key: value for key, value in options.items() if key != 'handle_token'}, {'types': 3, 'multiple': False, 'persist_mode': 0})
                self.assertNotIn('restore_token', options)
            elif method == 'Start':
                self.assertEqual(arguments[:2], (self.session, ''))
                streams = [(17, {'pipewire-serial': GLib.Variant('t', 12345)})]
                if self.mode == 'multiple':
                    streams += [(18, {})]
                results = {'streams': GLib.Variant('a(ua{sv})', streams)}
            elif method == 'Screenshot':
                self.assertTrue(options['interactive'])
                self.assertTrue(options['modal'])
                results = {'uri': GLib.Variant('s', 'file:///fixture-selected.png')}
            def response():
                if not self.server.is_closed():
                    self.server.emit_signal(None, path, 'org.freedesktop.portal.Request', 'Response',
                        GLib.Variant('(ua{sv})', (1 if self.mode == 'denied' else 0, results)))
                return False
            GLib.timeout_add(50 if self.mode == 'stop-race' else 1, response)
        except Exception as error:
            self.errors.append(repr(error))
            invocation.return_dbus_error('org.freedesktop.portal.Error.Failed', 'fixture contract failure')

    def close_request(self, _connection, _sender, _path, _interface, method, _parameters, invocation):
        self.methods.append(method)
        invocation.return_value(None)

    def portal(self):
        portal = CAPTURE.Portal(Gio, GLib)
        self.portals.append(portal)
        return portal

    def test_interactive_screenshot_requires_actual_success_response(self):
        result = []
        self.portal().screenshot(lambda *values: result.append(values))
        self.spin(lambda: bool(result))
        self.assertEqual(result, [({'uri': 'file:///fixture-selected.png'}, None)])
        self.assertEqual(self.methods, ['Screenshot'])

    def test_deny_and_substituted_request_handle_fail_closed(self):
        for mode in ('denied', 'substitution'):
            self.mode = mode
            result = []
            portal = self.portal()
            portal.screenshot(lambda *values: result.append(values))
            self.spin(lambda: bool(result))
            self.assertIsNone(result[0][0])
            self.assertTrue(result[0][1])
            self.assertTrue(portal.closed)

    def test_nonpersistent_single_stream_and_real_descriptor_then_revocation(self):
        result, revoked = [], []
        portal = self.portal()
        portal.on_revoked = lambda: revoked.append(True)
        portal.screen(lambda *values: result.append(values))
        self.spin(lambda: bool(result))
        self.assertIsNone(result[0][1])
        descriptor, target = result[0][0]
        try:
            self.assertEqual(target, '12345')
            self.sockets[-1].sendall(b'actual-fixture-socket-bytes')
            self.assertEqual(os.read(descriptor, 100), b'actual-fixture-socket-bytes')
        finally:
            os.close(descriptor)
        self.server.emit_signal(None, self.session, 'org.freedesktop.portal.Session', 'Closed', GLib.Variant('(a{sv})', ({},)))
        self.spin(lambda: bool(revoked))
        self.assertTrue(portal.closed)
        self.assertEqual(self.methods[:4], ['CreateSession', 'SelectSources', 'Start', 'OpenPipeWireRemote'])

    def test_multiple_stream_substitution_refuses_before_remote_open(self):
        self.mode = 'multiple'
        result = []
        portal = self.portal()
        portal.screen(lambda *values: result.append(values))
        self.spin(lambda: bool(result))
        self.assertIsNone(result[0][0])
        self.assertTrue(result[0][1])
        self.assertNotIn('OpenPipeWireRemote', self.methods)
        self.assertTrue(portal.closed)

    def test_stop_during_session_creation_disconnects_own_client(self):
        self.mode = 'stop-race'
        portal, results = self.portal(), []
        client = portal.bus.get_unique_name()
        portal.screen(lambda *values: results.append(values))
        self.spin(lambda: 'CreateSession' in self.methods)
        portal.close()
        self.assertTrue(portal.bus.is_closed())
        names = self.server.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus',
            'ListNames', None, GLib.VariantType.new('(as)'), Gio.DBusCallFlags.NONE, 1000, None).unpack()[0]
        self.assertNotIn(client, names)
        self.assertEqual(results, [])

    def test_session_bus_loss_revokes_immediately_and_cancels_pending_request(self):
        self.mode = 'stop-race'
        portal, revoked = self.portal(), []
        portal.on_revoked = lambda: revoked.append(True)
        portal.screenshot(lambda *_: None)
        self.spin(lambda: 'Screenshot' in self.methods)
        self.daemon.terminate()
        self.spin(lambda: bool(revoked))
        self.assertTrue(portal.closed)
        self.assertTrue(portal.bus.is_closed())
        self.assertEqual(portal.pending, {})


if __name__ == '__main__':
    unittest.main()
