"""Real inert staging/protocol checks; no sudo/PAM/desktop host launch."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('luma_workspace_auth_tests', ROOT / 'native/desktop/workspace_auth.py')
auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth)


def request():
    return dict(schema_version=1, operation='inspection', login='alice', read_grant='', effect_grant='', approval='',
                request=json.dumps(dict(schema_version=1, login='alice', binding=dict(installation='1' * 64, owner='2' * 64, owner_generation=1),
                                        operation=dict(kind='current', artifact_id='document'))))


def response(canonical):
    return dict(schema_version=1, result=dict(operation='native-request', canonical_request=canonical,
                request_sha256=hashlib.sha256(canonical.encode()).hexdigest(), private_content_read=False),
                owner_authenticated=False, authority_returned=False, committed=False, certified=False, gate_closing=False)


class WorkspaceAuthTests(unittest.TestCase):
    def test_office_export_selects_fixed_original_scope_without_passing_target_to_root(self):
        value=dict(request(),operation='office-proposal')
        args=auth.terminal_arguments(value,Path('/run/request.json'))
        self.assertEqual(args[4:],["content-office-export-proposal","alice","/run/request.json"])
        value=dict(value,operation='office-export',read_grant='read-office',effect_grant='export-office',output_path='/var/home/alice/document.pdf')
        args=auth.terminal_arguments(value,Path('/run/request.json'))
        self.assertEqual(args[4:],["content-office-export","alice","read-office","export-office","/run/request.json"])
        self.assertNotIn(value['output_path'],args)
        canonical=auth.encoded(auth.strict_json(value['request'])).decode()
        output=response(canonical);output['result']['operation']='office-request'
        self.assertEqual(auth.canonical_response(value,auth.encoded(output)),canonical)
        for changed in (dict(value,approval='write:'+'a'*64),dict(value,effect_grant='read-office')):
            with self.assertRaises(ValueError):
                auth.proposal(changed)
        with patch.object(auth.subprocess,'call') as spawn:
            with self.assertRaises(ValueError):
                auth.export_pdf(dict(value,output_path='/tmp/../invalid.pdf'),[])
            spawn.assert_not_called()

    def test_actual_bounded_file_sink_never_overwrites_and_retains_interrupted_partial(self):
        root=os.environ['LUMA_STORAGE_TEST_ROOT']
        with tempfile.TemporaryDirectory(prefix='luma-office-sink-',dir=root) as temporary:
            parent=Path(temporary)
            target=parent/'document.pdf'
            value=dict(request(),operation='office-export',read_grant='read-office',effect_grant='export-office',output_path=str(target))
            pdf=b'%PDF-1.4\nisolated sink transport fixture, not a LibreOffice qualification\n%%EOF\n'
            command=['/usr/bin/python3','-I','-c','import os; os.write(1,'+repr(pdf)+')']
            self.assertEqual(auth.export_pdf(value,command),0)
            self.assertEqual(target.read_bytes(),pdf)
            self.assertEqual(list(parent.iterdir()),[target])
            with patch.object(auth.subprocess,'call') as spawn:
                with self.assertRaises(FileExistsError):
                    auth.export_pdf(value,command)
                spawn.assert_not_called()
            self.assertEqual(target.read_bytes(),pdf)
            value['output_path']=str(parent/'incomplete.pdf')
            self.assertEqual(auth.export_pdf(value,['/usr/bin/python3','-I','-c','import os; os.write(1,b"partial"); raise SystemExit(2)']),2)
            self.assertFalse((parent/'incomplete.pdf').exists())
            self.assertEqual(len(list(parent.glob('.incomplete.pdf.luma-export-*.partial'))),1)
            value['output_path']=str(parent/'wrong.pdf')
            with self.assertRaises(ValueError):
                auth.export_pdf(value,['/usr/bin/python3','-I','-c','print("not PDF")'])
            self.assertFalse((parent/'wrong.pdf').exists())
            self.assertEqual(len(list(parent.glob('.wrong.pdf.luma-export-*.partial'))),1)

    def test_closed_operations_and_no_shell_arguments(self):
        value = request()
        for operation in ('inspection', 'review', 'apply'):
            value['operation'] = operation
            value['read_grant'] = 'read-1' if operation != 'inspection' else ''
            value['effect_grant'] = 'effect-1' if operation == 'apply' else ''
            value['approval'] = 'write:' + 'a' * 64 if operation == 'apply' else ''
            args = auth.terminal_arguments(value, Path('/run/user/1000/request.json'))
            self.assertEqual(args[:4], ['/usr/bin/sudo', '--', auth.NATIVE, 'granted-run'])
            self.assertNotIn('sh', args)
            self.assertEqual(args[-1], '/run/user/1000/request.json')
        for field, invalid in [('schema_version', True), ('login', 'alice;id'), ('operation', 'shell'),
                               ('read_grant', '-flag'), ('request', '{"login":"another"}'), ('approval', 'automatic')]:
            wrong = dict(value, **{field: invalid})
            with self.assertRaises(ValueError):
                auth.proposal(wrong)
        wrong = dict(request(), password='never')
        with self.assertRaises(ValueError):
            auth.proposal(wrong)
        with self.assertRaises(ValueError):
            auth.strict_json('{"login":"alice","login":"other"}')

    def test_canonical_native_response_changes_only_representation_not_typed_data(self):
        value = request()
        canonical = auth.encoded(auth.strict_json(value['request'])).decode()
        output = response(canonical)
        self.assertEqual(auth.canonical_response(value, auth.encoded(output)), canonical)
        for mutation in range(7):
            wrong = copy.deepcopy(output)
            if mutation == 0:
                wrong['committed'] = True
            elif mutation == 1:
                wrong['extra'] = False
            elif mutation == 2:
                wrong['schema_version'] = True
            elif mutation == 3:
                wrong['result']['private_content_read'] = True
            elif mutation == 4:
                wrong['result']['request_sha256'] = 'f' * 64
            else:
                tree = auth.strict_json(canonical)
                tree['binding']['owner_generation'] = True if mutation == 5 else 2
                substituted = auth.encoded(tree).decode()
                wrong = response(substituted)
            with self.assertRaises(ValueError):
                auth.canonical_response(value, auth.encoded(wrong))

    def test_real_staging_requires_private_single_link_exact_file(self):
        with tempfile.TemporaryDirectory(prefix='luma-auth-fixture-') as temporary:
            directory = Path(temporary)
            path = directory / ('a' * 32 + '.json')
            path.write_bytes(auth.encoded(request()))
            path.chmod(0o600)
            value, _ = auth.held_read(path, directory)
            self.assertEqual(value, request())
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                auth.held_read(path, directory)
            path.chmod(0o600)
            linked = directory / 'hardlink'
            os.link(path, linked)
            with self.assertRaises(ValueError):
                auth.held_read(path, directory)
            linked.unlink()
            alias = directory / ('b' * 32 + '.json')
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                auth.held_read(alias, directory)
            fifo = directory / ('c' * 32 + '.json')
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(ValueError):
                auth.held_read(fifo, directory)
            with self.assertRaises(ValueError):
                auth.held_read(directory / '../outside.json', directory)

    def test_terminal_handoff_retains_proposal_without_claiming_completion(self):
        with tempfile.TemporaryDirectory(prefix='luma-auth-launch-fixture-') as temporary:
            directory = Path(temporary)
            with patch.object(auth, 'runtime', return_value=directory), patch.object(auth, 'protected'), patch.object(auth.subprocess, 'Popen') as spawn:
                result = auth.launch(request())
            self.assertEqual(result, dict(state='terminal-launched', authenticated=False, committed=False, completion_observed=False))
            args = spawn.call_args.args[0]
            self.assertEqual(args[:6], ['/usr/bin/kgx', '--', '/usr/bin/python3', '-I', auth.HELPER, '--terminal'])
            path = Path(args[6])
            self.assertEqual(auth.held_read(path, directory)[0], request())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(len(list(directory.iterdir())), 1)
            self.assertNotIn('password', path.read_text())
            for number in range(15):
                (directory / f'owned-{number}').write_bytes(b'')
            with patch.object(auth, 'runtime', return_value=directory), patch.object(auth, 'protected'), patch.object(auth.subprocess, 'Popen') as spawn:
                with self.assertRaises(ValueError):
                    auth.launch(request())
                spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
