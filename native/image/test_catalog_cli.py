"""Native catalog CLI checks, called only by the disposable artifact fixture."""
import hashlib
import json
import sqlite3
from contextlib import closing
from test_workflow_cli import exercise_workflow


def exercise_catalog(run,state,source,pure):
    run('artifact-catalog-status',success=False)
    run('artifact-catalog-init')
    run('artifact-catalog-init',success=False)
    catalog = state/'artifact-catalog'
    publish = 'artifact-catalog-publish-invoice'
    first = json.loads(run(publish,'catalog-1','invoices','0',data=source))
    assert first['receipt']['version'] == 1 and first['replayed'] is False
    assert json.loads(run(publish,'catalog-1','invoices','0',data=source))['replayed'] is True
    assert run('artifact-catalog-read','invoices','1') == pure
    changed = source.replace(b'184.25',b'184.26')
    run(publish,'catalog-1','invoices','0',data=changed,success=False)
    run(publish,'catalog-2','invoices','1',data=changed)
    run(publish,'catalog-stale','invoices','1',data=source,success=False)
    run(publish,'catalog-other','other','0',data=source)
    run(publish,'../escape','other','0',data=source,success=False)
    run(publish,'invalid-version','other','01',data=source,success=False)
    run('artifact-catalog-status',success=False,uid=990)
    status = json.loads(run('artifact-catalog-status'))
    assert len(status['records']) == 3 and status['orphans'] == []
    assert len(list((catalog/'objects').iterdir())) == 2
    assert run('artifact-catalog-read','invoices','1') == pure

    # These exits skip native destructors, unlike returned-error unit hooks.
    for index,(fault,code) in enumerate([('after-object',88),('before-commit',86),('after-commit',87)]):
        request = 'crash-'+fault
        artifact = 'crash-artifact-'+str(index)
        new_source = source.replace(b'184.25',f'184.{30+index}'.encode())
        before = len(status['records'])
        run(publish,request,artifact,'0',data=new_source,success=False,fault=fault,exit_code=code)
        status = json.loads(run('artifact-catalog-status'))
        if fault == 'after-commit':
            assert len(status['records']) == before+1
        else:
            assert len(status['records']) == before and len(status['orphans']) == 1
        replay = json.loads(run(publish,request,artifact,'0',data=new_source))
        assert replay['replayed'] is (fault == 'after-commit')
        status = json.loads(run('artifact-catalog-status'))
        assert len(status['records']) == before+1 and status['orphans'] == []

    # A stopped partial write is retained, not truncated or automatically deleted.
    partial = catalog/'pending/partial'
    partial.write_bytes(b'part')
    partial.chmod(0o400)
    status = json.loads(run('artifact-catalog-status'))
    review = status['pending'][0]['retain_review_sha256']
    run(publish,'partial','partial-artifact','0',data=source,success=False)
    run('artifact-catalog-retain','partial','f'*64,success=False)
    run('artifact-catalog-retain','partial',review)
    run('artifact-catalog-retain','partial',review)
    assert (catalog/'retained/partial').read_bytes() == b'part'
    run(publish,'partial','partial-artifact','0',data=source,success=False)
    run(publish,'after-retain','next-artifact','0',data=source)

    # Inspect and attack the real schema only while the native owner is closed.
    with closing(sqlite3.connect(catalog/'metadata.sqlite3')) as connection:
        assert connection.execute('PRAGMA journal_mode').fetchone() == ('wal',)
        assert connection.execute('SELECT count(*) FROM receipts').fetchone() == (7,)
        for sql in ['DELETE FROM receipts','UPDATE receipts SET canonical=\'changed\'',
                    'DELETE FROM versions','UPDATE versions SET content_bytes=1']:
            try:
                connection.execute(sql)
            except sqlite3.IntegrityError:
                pass
            else:
                raise AssertionError('append-only schema accepted mutation')
        connection.rollback()
    exercise_legacy_import(run,state,source,pure)
    exercise_workflow(run,state,source,pure)
    obj = catalog/'objects'/hashlib.sha256(pure).hexdigest()
    obj.chmod(0o600)
    obj.write_bytes(b'tampered')
    run('artifact-catalog-status',success=False)
    run('artifact-catalog-read','invoices','1',success=False)
    print('CATALOG_CLI_FIXTURE_PASSED: WAL, versions, dedup, CAS, abrupt process exits, replay, retention, append-only, tamper')


def exercise_legacy_import(run,state,source,pure):
    legacy = state/'artifacts'
    inspect = 'artifact-catalog-legacy-inspect'
    import_command = 'artifact-catalog-import-legacy'
    def source_inventory():
        return {str(file.relative_to(legacy)):hashlib.sha256(file.read_bytes()).hexdigest()
                for file in legacy.rglob('*') if file.is_file()}
    before = source_inventory()
    preview = json.loads(run(inspect,'request-1'))
    source_receipt = (legacy/'committed/request-1/receipt.json').read_bytes()
    expected_id = hashlib.sha256(b'luma-artifact-legacy-import-v1\0'+source_receipt).hexdigest()
    assert preview['catalog_proposal']['artifact_id'] == expected_id
    assert preview['review_sha256'] == hashlib.sha256(source_receipt).hexdigest()
    run(import_command,'request-1','f'*64,success=False)
    run(inspect,'request-1',success=False,uid=990)
    run(import_command,'request-1',preview['review_sha256'],success=False,uid=990)
    result = json.loads(run(import_command,'request-1',preview['review_sha256']))
    assert result['replayed'] is False and result['source_preserved'] is True
    assert json.loads(run(import_command,'request-1',preview['review_sha256']))['replayed'] is True
    assert run('artifact-catalog-read',expected_id,'1') == pure
    assert source_inventory() == before
    updated = source.replace(b'184.25',b'184.38')
    run('artifact-catalog-publish-invoice','update-imported',expected_id,'1',data=updated)
    repeated = json.loads(run(import_command,'request-1',preview['review_sha256']))
    assert repeated['replayed'] is True and repeated['receipt']['version'] == 1
    assert run('artifact-catalog-read',expected_id,'1') == pure
    assert run('artifact-catalog-read',expected_id,'2') == run('invoice-calculate',data=updated).rstrip(b'\n')
    assert source_inventory() == before

    for index,(fault,code) in enumerate([('after-object',88),('before-commit',86),('after-commit',87)]):
        request = 'import-crash-'+str(index)
        changed = source.replace(b'184.25',f'184.{40+index}'.encode())
        run('artifact-publish-invoice',request,data=changed)
        preview = json.loads(run(inspect,request))
        before = source_inventory()
        count = len(json.loads(run('artifact-catalog-status'))['records'])
        run(import_command,request,preview['review_sha256'],success=False,fault=fault,exit_code=code)
        status = json.loads(run('artifact-catalog-status'))
        assert len(status['records']) == count+int(fault=='after-commit')
        assert source_inventory() == before
        result = json.loads(run(import_command,request,preview['review_sha256']))
        assert result['replayed'] is (fault=='after-commit')
        status = json.loads(run('artifact-catalog-status'))
        assert len(status['records']) == count+1 and status['orphans'] == []
        assert source_inventory() == before

    pending = legacy/'pending/import-unfinished'
    pending.mkdir(mode=0o700)
    run(inspect,'request-1',success=False)
    review = hashlib.sha256(source_receipt).hexdigest()
    run(import_command,'request-1',review,success=False)
    assert pending.exists()
    abort_review = json.loads(run('artifact-store-status'))['pending']['abort_review_sha256']
    run('artifact-abort','import-unfinished',abort_review)
    assert json.loads(run(import_command,'request-1',review))['replayed'] is True
    print('LEGACY_IMPORT_CLI_FIXTURE_PASSED: reviewed copy, stable IDs, source preservation, abrupt exits, exact retry after version advance, pending fence, non-root denial')
