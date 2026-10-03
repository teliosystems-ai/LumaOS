"""Native catalog CLI checks, called only by the disposable artifact fixture."""
import hashlib
import json
import sqlite3
from contextlib import closing


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
    obj = catalog/'objects'/hashlib.sha256(pure).hexdigest()
    obj.chmod(0o600)
    obj.write_bytes(b'tampered')
    run('artifact-catalog-status',success=False)
    run('artifact-catalog-read','invoices','1',success=False)
    print('CATALOG_CLI_FIXTURE_PASSED: WAL, versions, dedup, CAS, abrupt process exits, replay, retention, append-only, tamper')
