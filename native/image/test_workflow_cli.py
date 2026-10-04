"""Native checkpoint runner, only through the disposable installed-root fixture."""
import hashlib
import json
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path


def exercise_workflow(run, state, source, pure):
    prepare = 'workflow-invoice-prepare'
    status = 'workflow-invoice-status'
    advance = 'workflow-invoice-advance'
    cancel = 'workflow-invoice-cancel'
    run('workflow-store-status', success=False)
    run('workflow-store-init')
    run('workflow-store-init', success=False)
    first = json.loads(run(prepare, 'workflow-1', 'workflow-summary', '0', data=source))
    assert first['state'] == 'prepared' and first['replayed'] is False
    assert first['folder_grant'] is False and first['gate_closing'] is False
    assert json.loads(run(prepare, 'workflow-1', 'workflow-summary', '0', data=source))['replayed'] is True
    run(prepare, 'workflow-1', 'other', '0', data=source, success=False)
    run(prepare, 'bad', 'other', '00', data=source, success=False)
    run(prepare, 'bad-csv', 'other', '0', data=b'not,csv\n', success=False)
    run(advance, 'workflow-1', 'f'*64, success=False)
    run(status, 'workflow-1', success=False, uid=990)
    run(advance, 'workflow-1', first['review_sha256'], success=False, uid=990)
    run(cancel, 'workflow-1', first['review_sha256'], success=False, uid=990)
    count = len(json.loads(run('artifact-catalog-status'))['records'])
    # Quiescent snapshot only. No SQL connection is open during native ownership.
    catalog = state/'artifact-catalog'
    backup = state/'workflow-test-prior-catalog'
    shutil.copytree(catalog, backup)
    for expected in ['source-read', 'calculated', 'completed', 'completed']:
        previous = json.loads(run(status, 'workflow-1'))
        result = json.loads(run(advance, 'workflow-1', previous['review_sha256']))
        assert result['state'] == expected
        assert json.loads(run(advance, 'workflow-1', previous['review_sha256']))['state'] == expected
    assert len(json.loads(run('artifact-catalog-status'))['records']) == count+1
    assert run('artifact-catalog-read', 'workflow-summary', '1') == pure
    current = state/'workflow-test-current-catalog'
    catalog.rename(current)
    backup.rename(catalog)
    # A completed coordinator cannot create a missing receipt after catalog rollback.
    run(advance, 'workflow-1', result['review_sha256'], success=False)
    assert len(json.loads(run('artifact-catalog-status'))['records']) == count
    catalog.rename(backup)
    current.rename(catalog)
    run(advance, 'workflow-1', first['review_sha256'], success=False)
    run(cancel, 'workflow-1', result['review_sha256'], success=False)
    updated = source.replace(b'184.25', b'184.51')
    run('artifact-catalog-publish-invoice', 'workflow-later', 'workflow-summary', '1', data=updated)
    run(advance, 'workflow-1', result['review_sha256'])
    assert run('artifact-catalog-read', 'workflow-summary', '2') == run('invoice-calculate', data=updated).rstrip(b'\n')

    for stage in range(3):
        request = 'workflow-cancel-'+str(stage)
        result = json.loads(run(prepare, request, 'cancelled-summary', '0', data=source))
        for _ in range(stage):
            result = json.loads(run(advance, request, result['review_sha256']))
        cancel_review = result['review_sha256']
        result = json.loads(run(cancel, request, cancel_review))
        assert result['state'] == 'cancelled'
        run(cancel, request, cancel_review)
        run(cancel, request, result['review_sha256'])
        run(advance, request, result['review_sha256'], success=False)

    for index, (fault, code, expected) in enumerate([
            ('workflow-before-applying', 92, 'calculated'),
            ('workflow-after-applying', 93, 'applying'),
            ('after-object', 88, 'applying'),
            ('workflow-after-artifact', 89, 'applying'),
            ('workflow-before-completion', 90, 'applying'),
            ('workflow-after-completion', 91, 'completed')]):
        request = 'workflow-crash-'+str(index)
        artifact = 'workflow-crash-summary-'+str(index)
        changed = source.replace(b'184.25', f'184.{60+index}'.encode())
        result = json.loads(run(prepare, request, artifact, '0', data=changed))
        for _ in range(2):
            result = json.loads(run(advance, request, result['review_sha256']))
        before = len(json.loads(run('artifact-catalog-status'))['records'])
        advance_review = result['review_sha256']
        run(advance, request, advance_review, success=False, fault=fault, exit_code=code)
        result = json.loads(run(status, request))
        assert result['state'] == expected
        committed = fault in ['workflow-after-artifact', 'workflow-before-completion', 'workflow-after-completion']
        assert len(json.loads(run('artifact-catalog-status'))['records']) == before+int(committed)
        if expected == 'applying':
            run(cancel, request, result['review_sha256'], success=False)
        result = json.loads(run(advance, request, advance_review))
        assert result['state'] == 'completed'
        assert len(json.loads(run('artifact-catalog-status'))['records']) == before+1
        assert run('artifact-catalog-read', artifact, '1') == run('invoice-calculate', data=changed).rstrip(b'\n')

    # Withdrawal blocks advancement but never prevents cancellation before an effect.
    result = json.loads(run(prepare, 'withdrawn-run', 'withdrawn-summary', '0', data=source))
    # Fixed fixture image location, not a caller-selected runtime override.
    signature = Path('/usr/share/luma-os/skills/registry.sig')
    original = signature.read_bytes()
    signature.write_bytes(b'X'*64)
    run(advance, 'withdrawn-run', result['review_sha256'], success=False)
    assert json.loads(run(cancel, 'withdrawn-run', result['review_sha256']))['state'] == 'cancelled'
    signature.write_bytes(original)

    store = state/'workflow-runs'
    with closing(sqlite3.connect(store/'metadata.sqlite3')) as db:
        assert db.execute('PRAGMA journal_mode').fetchone() == ('wal',)
        for sql in ['DELETE FROM checkpoints', 'UPDATE checkpoints SET canonical=\'{}\'',
                    'DELETE FROM runs', 'UPDATE runs SET current_stage=4 WHERE current_stage=5']:
            try:
                db.execute(sql)
            except sqlite3.IntegrityError:
                pass
            else:
                raise AssertionError('workflow history mutation was accepted')
        db.rollback()
    # Incomplete objects stay intact, never silently overwritten.
    content = source.replace(b'184.25', b'184.90')
    name = hashlib.sha256(content).hexdigest()
    pending = store/'pending'/name
    pending.write_bytes(b'part')
    pending.chmod(0o400)
    run(prepare, 'partial-run', 'partial-summary', '0', data=content, success=False)
    assert pending.read_bytes() == b'part'
    assert json.loads(run('workflow-store-status'))['pending'][0]['preserved'] is True
    print('WORKFLOW_CLI_FIXTURE_PASSED: durable steps, cancellation, real catalog effects, crash recovery, replay, withdrawal, immutable history, retained partial bytes')
