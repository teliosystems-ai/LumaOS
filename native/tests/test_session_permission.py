"""Ordered local-consent and owner-query tests; no desktop/hardware accessed."""
import importlib.util
from pathlib import Path
import types
import unittest

SPEC=importlib.util.spec_from_file_location('luma_session_permission_tests',Path(__file__).parents[1]/'desktop/workspace_capture.py')
capture=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(capture)


class TransportError(Exception): pass
class Value:
    def __init__(self, value):self.value=value
    def unpack(self):return self.value


class Bus:
    def __init__(self):
        self.closed=False;self.owner=':1.7';self.active=False;self.calls=[];self.malformed=None;self.unavailable=False
    def is_closed(self):return self.closed
    def call_sync(self,*args):
        self.calls.append(args)
        if args[3]=='GetNameOwner':
            if args[4].value[0]!='org.gnome.ScreenSaver' or self.owner is None:raise TransportError('no owner')
            return Value((self.owner,))
        if args[3]=='GetActive':
            if self.unavailable:raise TransportError('owner did not answer')
            if args[0]!=self.owner:raise TransportError('wrong unique owner')
            return Value(self.malformed if self.malformed is not None else (self.active,))
        raise AssertionError('unexpected query')


GIO=types.SimpleNamespace(DBusCallFlags=types.SimpleNamespace(NO_AUTO_START=2))
GLIB=types.SimpleNamespace(Error=TransportError,Variant=lambda _signature,value:Value(value),
    VariantType=types.SimpleNamespace(new=lambda signature:signature))


class SessionConsent(unittest.TestCase):
    def fixture(self):
        bus=Bus();fence=capture.SessionPermission(lambda:capture.unlocked_session(bus,GIO,GLIB))
        return bus,fence

    def test_fresh_queries_unique_owner_with_no_activation_and_bounded_calls(self):
        bus,fence=self.fixture();token=fence.fresh();fence.check(token)
        self.assertEqual(token,(0,(('org.gnome.ScreenSaver',':1.7'),)))
        for call in bus.calls:
            self.assertEqual(call[-3:-1],(2,500))
            if call[3]=='GetActive':self.assertEqual(call[0],':1.7')

    def test_lock_before_signal_dispatch_refuses_queued_click_or_modal_acceptance(self):
        bus,fence=self.fixture();token=fence.fresh();bus.active=True
        with self.assertRaises(ValueError):fence.fresh()
        with self.assertRaises(ValueError):fence.check(token)
        fence.revoke();bus.active=False
        with self.assertRaises(ValueError):fence.check(token)
        renewed=fence.fresh();self.assertNotEqual(renewed,token);fence.check(renewed)

    def test_bus_loss_is_latched_and_cannot_renew_after_stale_unlock(self):
        bus,fence=self.fixture();token=fence.fresh();bus.closed=True
        with self.assertRaises(ValueError):fence.fresh()
        fence.close();bus.closed=False;bus.active=False
        with self.assertRaises(ValueError):fence.fresh()
        with self.assertRaises(ValueError):fence.current(token)

    def test_owner_replacement_refuses_original_modal_and_absence_is_not_unlocked(self):
        bus,fence=self.fixture();token=fence.fresh();bus.owner=':1.8'
        with self.assertRaises(ValueError):fence.check(token)
        bus.owner=None
        with self.assertRaises(ValueError):fence.fresh()

    def test_known_owner_cannot_be_silently_skipped_for_failed_or_malformed_state(self):
        bus,fence=self.fixture();bus.unavailable=True
        with self.assertRaises(ValueError):fence.fresh()
        bus.unavailable=False
        for value in ((),(False,False),(0,),('false',),(True,)):
            bus.malformed=value
            with self.assertRaises(ValueError):fence.fresh()
        bus.malformed=None;bus.owner='not-a-unique-owner'
        with self.assertRaises(ValueError):fence.fresh()

    def test_reentrant_revocation_during_fresh_query_never_returns_permission(self):
        bus,fence=self.fixture();original=fence.query
        def revoke_during_query():
            value=original();fence.revoke();return value
        fence.query=revoke_during_query
        with self.assertRaises(ValueError):fence.fresh()


if __name__=='__main__':unittest.main()
