"""Actual native CLI exercise in a fresh disposable tools container."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from assemble import package_skill_registry


def main():
    if (not Path('/.dockerenv').is_file() or os.geteuid() != 0
            or Path('/dev/tpm0').exists() or Path('/dev/tpmrm0').exists()
            or os.environ.get('LD_PRELOAD') != '/tmp/luma-artifact-test.so'
            or Path('/proc/cmdline').read_text().strip() !=
            'luma.mode=installed luma.slot=a luma.fixture=artifact-cli'):
        raise SystemExit('requires a fresh disposable container with the artifact test cmdline')
    os.umask(0o077)
    binary = Path(os.environ['CARGO_TARGET_DIR'])/'debug/luma-platform'
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

        def run(*args, data=None, success=True, uid=None):
            result = subprocess.run([str(binary),*args],input=data,capture_output=True,
                                    timeout=30,preexec_fn=(lambda: os.setuid(uid)) if uid is not None else None)
            if (result.returncode == 0) != success:
                raise AssertionError(f'{args[0]} unexpected exit {result.returncode}: {result.stderr.decode()}')
            return result.stdout

        run('artifact-store-status',success=False)
        run('artifact-store-init')
        run('artifact-store-init',success=False)
        pure = run('invoice-calculate',data=source).rstrip(b'\n')
        published = json.loads(run('artifact-publish-invoice','request-1',data=source))
        assert published['replayed'] is False
        assert published['receipt']['content_sha256'] == hashlib.sha256(pure).hexdigest()
        assert published['receipt']['source_sha256'] == hashlib.sha256(source).hexdigest()
        assert json.loads(run('artifact-publish-invoice','request-1',data=source))['replayed'] is True
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

        # Simulate a complete synced pair with publication not yet acknowledged.
        prepared = state/'artifacts/pending/prepared'
        prepared.mkdir(mode=0o700)
        (prepared/'report.json').write_bytes(pure)
        (prepared/'report.json').chmod(0o400)
        receipt = dict(published['receipt'],request_id='prepared')
        # Receipt field order is the native serializer's declaration order.
        order = ['schema_version','installation','request_id','authenticated_uid',
                 'workflow_sha256','source_sha256','content_sha256','content_bytes',
                 'filename','media_type','version']
        (prepared/'receipt.json').write_text(json.dumps(
            {key:receipt[key] for key in order},separators=(',',':')))
        (prepared/'receipt.json').chmod(0o400)
        pending = json.loads(run('artifact-store-status'))['pending']
        assert pending['state'] == 'prepared'
        run('artifact-reconcile','prepared','f'*64,success=False)
        run('artifact-reconcile','prepared',pending['review_sha256'])
        run('artifact-reconcile','prepared',pending['review_sha256'])
        assert run('artifact-read','prepared') == pure
        run('artifact-abort','prepared',pending['abort_review_sha256'],success=False)
        status = json.loads(run('artifact-store-status'))
        assert len(status['records']) == 3 and status['pending'] is None
        assert len(status['retained']) == 1
        report = state/'artifacts/committed/request-1/report.json'
        report.chmod(0o600)
        report.write_bytes(b'tampered')
        run('artifact-read','request-1',success=False)
        run('artifact-publish-invoice','request-1',data=source,success=False)
    print('ARTIFACT_CLI_FIXTURE_PASSED: init, publication, replay, read, reviewed recovery, retained abort, conflicts, denial, tamper')


if __name__ == '__main__':
    main()
