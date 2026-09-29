"""The booted-image authentication fixture must reject false-positive results."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

IMAGE = Path(__file__).resolve().parents[1]/'image'
spec = importlib.util.spec_from_file_location('admin_vm', IMAGE/'admin_vm_test.py')
admin_vm = importlib.util.module_from_spec(spec)
with patch.object(sys, 'path', [str(IMAGE), *sys.path]):
    spec.loader.exec_module(admin_vm)


class Console:
    def __init__(self, output):
        self.output = output
        self.prompts = 0

    def send(self, value):
        pass

    def expect(self, pattern):
        self.prompts += 1
        return b'Account password (authentication only):' if self.prompts == 1 else self.output


class AuthenticationFixtureTests(unittest.TestCase):
    @staticmethod
    def result(**changes):
        record = dict(authenticated_uid=1001, product_admin_active=False,
                      role_grant=False, gate_closing=False)
        record.update(changes)
        return json.dumps(record).encode()+b'\r\n__AUTH_RC=0__\r\n'

    def test_accepts_exact_non_authority_observation(self):
        admin_vm.authenticate(Console(self.result()), 'public-test-password', 0)

    def test_rejects_authority_claim_and_wrong_identity(self):
        for changes in ({'product_admin_active':True}, {'role_grant':True},
                        {'gate_closing':True}, {'authenticated_uid':0}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                admin_vm.authenticate(Console(self.result(**changes)), 'public-test-password', 0)

    def test_rejects_password_echo_and_missing_success(self):
        for output in (b'public-test-password'+self.result(), b'\r\n__AUTH_RC=0__\r\n',
                       b'\r\n__AUTH_RC=1__\r\n'):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                admin_vm.authenticate(Console(output), 'public-test-password', 0)

    def test_wrong_password_must_fail(self):
        admin_vm.authenticate(Console(b'denied\r\n__AUTH_RC=1__\r\n'), 'incorrect-fixture', 1)
        with self.assertRaises(RuntimeError):
            admin_vm.authenticate(Console(self.result()), 'incorrect-fixture', 1)


if __name__ == '__main__':
    unittest.main()
