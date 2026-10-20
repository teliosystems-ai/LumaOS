"""Real private D-Bus lock-query transport, not desktop/hardware qualification.

The scripted service is confined to a new disposable bus; no existing session,
microphone, screen, speaker, product grant or model is accessed.
"""
import importlib.util
from pathlib import Path
import selectors
import subprocess
import sys
import unittest

import gi
gi.require_version('Gio','2.0')
from gi.repository import Gio,GLib

SPEC=importlib.util.spec_from_file_location('luma_session_transport',Path(__file__).parents[1]/'desktop/workspace_capture.py')
capture=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(capture)
FLAGS=Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT|Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION
NAME='org.gnome.ScreenSaver';PATH='/org/gnome/ScreenSaver'


def server(address):
    connection=Gio.DBusConnection.new_for_address_sync(address,FLAGS,None,None)
    connection.set_exit_on_close(False)
    loop=GLib.MainLoop();state={'active':False}
    node=Gio.DBusNodeInfo.new_for_xml('''<node><interface name="org.gnome.ScreenSaver">
      <method name="GetActive"><arg type="b" direction="out"/></method>
      <method name="SetFixtureActive"><arg type="b" direction="in"/></method>
      <signal name="ActiveChanged"><arg type="b"/></signal>
    </interface></node>''')
    def method(_connection,_sender,_path,_interface,name,arguments,invocation):
        if name=='GetActive':invocation.return_value(GLib.Variant('(b)',(state['active'],)))
        elif name=='SetFixtureActive':
            state['active']=arguments.unpack()[0]
            connection.emit_signal(None,PATH,NAME,'ActiveChanged',GLib.Variant('(b)',(state['active'],)))
            invocation.return_value(GLib.Variant('()',()))
        else:invocation.return_dbus_error('org.luma.Fixture.Unknown','unknown fixture method')
    registration=connection.register_object(PATH,node.interfaces[0],method,None,None)
    response=connection.call_sync('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus',
        'RequestName',GLib.Variant('(su)',(NAME,0)),GLib.VariantType.new('(u)'),Gio.DBusCallFlags.NONE,1000,None)
    if response.unpack()!=(1,):raise ValueError('fixture failed to own its private name')
    print('READY',flush=True)
    try:loop.run()
    finally:
        connection.unregister_object(registration);connection.close_sync(None)


class SessionTransport(unittest.TestCase):
    def ready_line(self,process):
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout,selectors.EVENT_READ)
            self.assertTrue(ready.select(3),'private service did not become ready')
        return process.stdout.readline().decode().strip()

    def setUp(self):
        self.processes=[]
        self.daemon=subprocess.Popen(['/usr/bin/dbus-daemon','--session','--nofork','--print-address=1'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.processes.append(self.daemon)
        address=self.ready_line(self.daemon);self.assertTrue(address.startswith('unix:'))
        self.fixture=subprocess.Popen([sys.executable,'-B',__file__,'--server',address],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.processes.append(self.fixture)
        self.assertEqual(self.ready_line(self.fixture),'READY')
        self.bus=Gio.DBusConnection.new_for_address_sync(address,FLAGS,None,None)
        self.bus.set_exit_on_close(False)
        self.fence=capture.SessionPermission(lambda:capture.unlocked_session(self.bus,Gio,GLib))

    def tearDown(self):
        if getattr(self,'bus',None) is not None and not self.bus.is_closed():self.bus.close_sync(None)
        for process in reversed(self.processes):
            if process.poll() is None:process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
            process.stdout.close();process.stderr.close()

    def active(self,value):
        self.bus.call_sync(NAME,PATH,NAME,'SetFixtureActive',GLib.Variant('(b)',(value,)),
            GLib.VariantType.new('()'),Gio.DBusCallFlags.NO_AUTO_START,1000,None)

    def test_actual_lock_query_refuses_queued_renewal_before_event_dispatch(self):
        token=self.fence.fresh();self.active(True)
        # The GLib signal queue has deliberately not been iterated. A click or
        # accepted modal dialog cannot use a stale earlier unlocked result.
        with self.assertRaises(ValueError):self.fence.fresh()
        with self.assertRaises(ValueError):self.fence.check(token)
        self.fence.revoke();self.active(False)
        with self.assertRaises(ValueError):self.fence.check(token)
        self.fence.check(self.fence.fresh())

    def test_actual_service_owner_loss_is_not_an_unlocked_fallback(self):
        token=self.fence.fresh();self.fixture.terminate();self.fixture.wait(timeout=3)
        with self.assertRaises(ValueError):self.fence.fresh()
        with self.assertRaises(ValueError):self.fence.check(token)

    def test_actual_connection_loss_latches_closed_and_refuses_new_permissions(self):
        token=self.fence.fresh();self.bus.close_sync(None);self.fence.close()
        with self.assertRaises(ValueError):self.fence.current(token)
        with self.assertRaises(ValueError):self.fence.fresh()


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--server':server(sys.argv[2])
    else:unittest.main()
