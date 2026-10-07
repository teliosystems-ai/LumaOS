"""Native CLI plus explicit test-only publication store/crash fixtures.

Production publishers must refuse absent resources. Successful publication here
uses a separate Rust unit-test executable, not a production broker fallback.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from assemble import package_skill_registry
from test_catalog_cli import exercise_catalog


def main():
    if (not Path('/.dockerenv').is_file() or os.geteuid() != 0
            or Path('/dev/tpm0').exists() or Path('/dev/tpmrm0').exists()
            or os.environ.get('LD_PRELOAD') != '/tmp/luma-artifact-test.so'
            or Path('/proc/cmdline').read_text().strip() !=
            'luma.mode=installed luma.slot=a luma.fixture=artifact-cli'):
        raise SystemExit('requires a fresh disposable container with the artifact test cmdline')
    os.umask(0o077)
    binary = Path(os.environ['CARGO_TARGET_DIR'])/'debug/luma-platform'
    test_binary = Path(os.environ['LUMA_PUBLICATION_TEST_EXECUTABLE'])
    if not test_binary.is_file() or test_binary.parent != binary.parent/'deps':
        raise SystemExit('requires the current Cargo-reported Rust unit-test executable')
    source = Path('/repo/examples/invoices.csv').read_bytes()
    share = Path('/usr/share/luma-os')
    state = Path('/var/lib/luma-os')
    if share.exists() or state.exists():
        raise SystemExit('artifact CLI fixture requires absent Luma runtime state')
    (share/'workflows').mkdir(parents=True)
    shutil.copyfile(Path(__file__).parent/'overlay/usr/share/luma-os/workflows/file-to-artifact-v1.json',
                    share/'workflows/file-to-artifact-v1.json')
    (state/'principals').mkdir(parents=True, mode=0o700)
    state.chmod(0o700)
    (state/'principals/registry.json').write_text(json.dumps({
        'schema_version':1,'installation':'a'*64,'principals':[
            {'id':'c'*64,'generation':1,'login':'admin','uid':1001,'enabled':True},
        ]},separators=(',',':')))
    (state/'principals/registry.json').chmod(0o600)
    with tempfile.TemporaryDirectory(prefix='luma-artifact-cli-') as temporary:
        keys = Path(temporary)
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(keys/'release.key')],check=True)
        subprocess.run(['openssl','pkey','-in',str(keys/'release.key'),'-pubout','-out',str(share/'release.pub')],check=True)
        package_skill_registry(Path('/'),keys)

        def run(*args, data=None, success=True, uid=None, fault=None, exit_code=None,
                native=False, resource_fault=None, resource_generation=None):
            environment = dict(os.environ)
            if fault is not None:
                environment['LUMA_ARTIFACT_TEST_FAULT'] = fault
            publication_fixture = (not native and args[0] in
                ('artifact-publish-invoice','artifact-catalog-publish-invoice','artifact-reconcile'))
            command = [str(binary),*args]
            if publication_fixture:
                environment['LUMA_PUBLICATION_TEST_ARGS'] = json.dumps(args,separators=(',',':'))
                if resource_fault is not None:
                    environment['LUMA_PUBLICATION_TEST_RESOURCE_FAULT'] = resource_fault
                if resource_generation is not None:
                    environment['LUMA_PUBLICATION_TEST_GENERATION'] = str(resource_generation)
                command = [str(test_binary),'--exact','publication_fixture::disposable_publication',
                           '--nocapture','--test-threads=1']
            result = subprocess.run(command,input=data,capture_output=True,
                                    timeout=30,env=environment,preexec_fn=(lambda: os.setuid(uid)) if uid is not None else None)
            if (result.returncode == 0) != success:
                raise AssertionError(f'{args[0]} unexpected exit {result.returncode}: {result.stderr.decode()}')
            if exit_code is not None and result.returncode != exit_code:
                raise AssertionError(f'{args[0]} did not execute the requested abrupt-exit fixture')
            if publication_fixture and success:
                lines = [line for line in result.stdout.splitlines() if line.startswith(b'{')]
                assert len(lines) == 1, result.stdout
                value = json.loads(lines[0])
                assert value['synthetic_computation_fixture'] is True
                return lines[0]
            return result.stdout

        run('artifact-store-status',success=False)
        run('artifact-store-init')
        run('artifact-store-init',success=False)
        pure = run('invoice-calculate',data=source).rstrip(b'\n')
        before = json.loads(run('artifact-store-status'))
        run('artifact-publish-invoice','no-resource',data=source,success=False,native=True)
        run('artifact-publish-invoice','no-admission',data=source,success=False,resource_fault='calculate')
        run('artifact-publish-invoice','fenced-admission',data=source,success=False,resource_fault='recheck-1')
        assert json.loads(run('artifact-store-status')) == before
        published = json.loads(run('artifact-publish-invoice','request-1',data=source))
        assert published['replayed'] is False
        assert published['receipt']['content_sha256'] == hashlib.sha256(pure).hexdigest()
        assert published['receipt']['source_sha256'] == hashlib.sha256(source).hexdigest()
        retry = json.loads(run('artifact-publish-invoice','request-1',data=source,resource_generation=2))
        assert retry['replayed'] is True and retry['receipt'] == published['receipt']
        assert retry['calculation_lease']['generation'] == '2'
        assert run('artifact-read','request-1') == pure
        run('artifact-publish-invoice','request-1',data=source.replace(b'184.25',b'184.26'),success=False)
        run('artifact-publish-invoice','../escape',data=source,success=False)
        run('artifact-publish-invoice','bad-csv',data=b'not,csv\n',success=False)
        run('artifact-store-status',success=False,uid=990)
        status = json.loads(run('artifact-store-status'))
        assert len(status['records']) == 1 and status['pending'] is None
        assert status['product_admin_active'] is False and status['rollback_protected'] is False

        # Simulate a process that stopped after syncing content, before receipt.
        interrupted = state/'artifacts/pending/interrupted'
        interrupted.mkdir(mode=0o700)
        (interrupted/'report.json').write_bytes(pure)
        (interrupted/'report.json').chmod(0o400)
        pending = json.loads(run('artifact-store-status'))['pending']
        assert pending['state'] == 'incomplete' and pending['review_sha256'] is None
        run('artifact-publish-invoice','request-2',data=source,success=False)
        run('artifact-reconcile','interrupted','f'*64,success=False)
        run('artifact-abort','interrupted','f'*64,success=False)
        review = pending['abort_review_sha256']
        run('artifact-abort','interrupted',review)
        run('artifact-abort','interrupted',review)
        assert (state/'artifacts/retained/interrupted/report.json').read_bytes() == pure
        run('artifact-publish-invoice','interrupted',data=source,success=False)
        run('artifact-publish-invoice','request-2',data=source)

        # Fence after a complete pair was synced, before the publication rename.
        run('artifact-publish-invoice','fenced-prepared',data=source,success=False,
            resource_fault='recheck-2')
        fenced = json.loads(run('artifact-store-status'))['pending']
        assert fenced['state'] == 'prepared' and fenced['receipt']['resource_lease'] is not None
        run('artifact-reconcile','fenced-prepared',fenced['review_sha256'],success=False,native=True)
        run('artifact-reconcile','fenced-prepared',fenced['review_sha256'],success=False,
            resource_fault='recheck-1')
        assert json.loads(run('artifact-store-status'))['pending'] == fenced
        run('artifact-abort','fenced-prepared',fenced['abort_review_sha256'])
        assert (state/'artifacts/retained/fenced-prepared/report.json').read_bytes() == pure

        # Simulate a complete synced pair with publication not yet acknowledged.
        prepared = state/'artifacts/pending/prepared'
        prepared.mkdir(mode=0o700)
        (prepared/'report.json').write_bytes(pure)
        (prepared/'report.json').chmod(0o400)
        receipt = dict(published['receipt'],request_id='prepared')
        receipt['resource_lease'] = {key:receipt['resource_lease'][key]
                                     for key in ('lease_id','generation','manager_epoch')}
        # Receipt field order is the native serializer's declaration order.
        order = ['schema_version','installation','request_id','authenticated_uid',
                 'workflow_sha256','source_sha256','content_sha256','content_bytes',
                 'filename','media_type','version','resource_lease']
        (prepared/'receipt.json').write_text(json.dumps(
            {key:receipt[key] for key in order},separators=(',',':')))
        (prepared/'receipt.json').chmod(0o400)
        pending = json.loads(run('artifact-store-status'))['pending']
        assert pending['state'] == 'prepared'
        # Operator review is not a replacement for unavailable broker provenance.
        run('artifact-reconcile','prepared',pending['review_sha256'],success=False,native=True)
        assert json.loads(run('artifact-store-status'))['pending'] == pending
        run('artifact-reconcile','prepared','f'*64,success=False)
        run('artifact-reconcile','prepared',pending['review_sha256'])
        run('artifact-reconcile','prepared',pending['review_sha256'])
        assert run('artifact-read','prepared') == pure
        run('artifact-abort','prepared',pending['abort_review_sha256'],success=False)
        status = json.loads(run('artifact-store-status'))
        assert len(status['records']) == 3 and status['pending'] is None
        assert len(status['retained']) == 2
        exercise_catalog(run,state,source,pure)
        report = state/'artifacts/committed/request-1/report.json'
        report.chmod(0o600)
        report.write_bytes(b'tampered')
        run('artifact-read','request-1',success=False)
        run('artifact-publish-invoice','request-1',data=source,success=False)
    print('ARTIFACT_CLI_FIXTURE_PASSED: native absent-resource refusal, init, read, reviewed recovery, retained abort, conflicts, denial, tamper; publication/replay use explicit synthetic test executable')


if __name__ == '__main__':
    main()
