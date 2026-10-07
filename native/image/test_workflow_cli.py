"""Native checkpoint runner, only through the disposable installed-root fixture."""
import hashlib
import json
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path


def exercise_unavailable_workflow_resources(run, state, source):
    """The tools fixture has no installed resource broker or block-backed /var.

    Assert this boundary, rather than injecting an unleased production fallback.
    Coordinator transitions have explicit calculator fixtures in the Rust tests;
    exercise_workflow below requires the genuine installed helper boundary.
    """
    run('workflow-store-status', success=False)
    run('workflow-store-init')
    run('workflow-store-init', success=False)
    before = json.loads(run('workflow-store-status'))
    for data in (source, b'not,csv\n'):
        run('workflow-invoice-prepare', 'unavailable-resource', 'summary', '0', data=data, success=False)
    after = json.loads(run('workflow-store-status'))
    assert before == after and after['runs'] == 0 and after['pending'] == []
    assert list((state/'workflow-runs/objects').iterdir()) == []
    run('workflow-invoice-status', 'unavailable-resource', success=False)
    run('workflow-invoice-advance', 'unavailable-resource', 'a'*64, success=False)
    run('workflow-invoice-cancel', 'unavailable-resource', 'a'*64, success=False)
    run('workflow-invoice-prepare', 'unavailable-resource', 'summary', '0', data=source, success=False, uid=990)
    print('WORKFLOW_RESOURCE_REFUSAL_CLI_PASSED: unavailable broker/storage never calculates or checkpoints')


def exercise_workflow(run, state, source, pure):
    prepare = 'workflow-invoice-prepare'
    status = 'workflow-invoice-status'
    advance = 'workflow-invoice-advance'
    cancel = 'workflow-invoice-cancel'
    reconcile = 'workflow-invoice-reconcile'
    run('workflow-store-status', success=False)
    run('workflow-store-init')
    run('workflow-store-init', success=False)
    first = json.loads(run(prepare, 'workflow-1', 'workflow-summary', '0', data=source))
    run(reconcile, 'workflow-1', success=False)
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
    committed_review = json.loads(run(reconcile, 'workflow-1'))['review_sha256']
    current = state/'workflow-test-current-catalog'
    catalog.rename(current)
    backup.rename(catalog)
    # A completed coordinator cannot create a missing receipt after catalog rollback.
    run(advance, 'workflow-1', result['review_sha256'], success=False)
    run(reconcile, 'workflow-1', '--publish-committed', committed_review, success=False)
    assert len(json.loads(run('artifact-catalog-status'))['records']) == count
    catalog.rename(backup)
    current.rename(catalog)
    run(advance, 'workflow-1', first['review_sha256'], success=False)
    run(cancel, 'workflow-1', result['review_sha256'], success=False)
    updated = source.replace(b'184.25', b'184.51')
    run('artifact-catalog-publish-invoice', 'workflow-later', 'workflow-summary', '1', data=updated)
    run(advance, 'workflow-1', result['review_sha256'])
    assert json.loads(run(reconcile, 'workflow-1', '--publish-committed', committed_review))['replayed'] is True
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
        if not committed:
            run(reconcile, request, success=False)
            run(reconcile, request, '--publish-committed', result['review_sha256'], success=False)
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

    exercise_committed_reconciliation(run, state, source, signature)

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


def exercise_committed_reconciliation(run, state, source, signature):
    prepare = 'workflow-invoice-prepare'
    advance = 'workflow-invoice-advance'
    status = 'workflow-invoice-status'
    reconcile = 'workflow-invoice-reconcile'
    original_signature = signature.read_bytes()
    for index, fault in enumerate([None, 'before-commit', 'after-commit']):
        request = 'acknowledge-committed-'+str(index)
        artifact = 'acknowledged-summary-'+str(index)
        changed = source.replace(b'184.25', f'184.{75+index}'.encode())
        current = json.loads(run(prepare, request, artifact, '0', data=changed))
        for _ in range(2):
            current = json.loads(run(advance, request, current['review_sha256']))
        run(advance, request, current['review_sha256'], success=False,
            fault='workflow-after-artifact', exit_code=89)
        current = json.loads(run(status, request))
        assert current['state'] == 'applying'
        before = json.loads(run('artifact-catalog-status'))
        signature.write_bytes(b'X'*64)
        try:
            run(advance, request, current['review_sha256'], success=False)
            inspection = json.loads(run(reconcile, request))
            assert inspection['observation'] == 'verified-committed-receipt'
            assert inspection['state'] == 'applying' and inspection['effect_executed'] is False
            token = inspection['review_sha256']
            run(reconcile, request, success=False, uid=990)
            run(reconcile, request, '--publish-committed', token, success=False, uid=990)
            run(reconcile, request, '--publish-committed', 'f'*64, success=False)
            if index == 0:
                object_path = state/'artifact-catalog/objects'/inspection['receipt']['content_sha256']
                original_bytes = object_path.read_bytes()
                original_mode = object_path.stat().st_mode & 0o777
                object_path.chmod(0o600)
                try:
                    object_path.write_bytes(b'corrupted after review')
                    run(reconcile, request, '--publish-committed', token, success=False)
                    assert json.loads(run(status, request))['state'] == 'applying'
                finally:
                    object_path.write_bytes(original_bytes)
                    object_path.chmod(original_mode)
            if fault:
                run(reconcile, request, '--publish-committed', token, success=False,
                    fault=fault, exit_code=86 if fault == 'before-commit' else 87)
                assert json.loads(run(status, request))['state'] == ('applying' if fault == 'before-commit' else 'completed')
            outcome = json.loads(run(reconcile, request, '--publish-committed', token))
            assert outcome['state'] == 'completed' and outcome['effect_executed'] is False
            assert outcome['replayed'] is (fault == 'after-commit')
            assert outcome['review_sha256'] == token
            assert json.loads(run(reconcile, request, '--publish-committed', token))['replayed'] is True
            # Reconciliation did not restore execution authority for withdrawn skills.
            run(advance, request, current['review_sha256'], success=False)
            assert json.loads(run('artifact-catalog-status')) == before
            assert run('artifact-catalog-read', artifact, '1') == run('invoice-calculate', data=changed).rstrip(b'\n')
        finally:
            signature.write_bytes(original_signature)
        with closing(sqlite3.connect(state/'workflow-runs/metadata.sqlite3')) as db:
            assert db.execute('SELECT count(*) FROM checkpoints WHERE request_id=?', (request,)).fetchone() == (5,)

    # A conflicting receipt under the effect ID is not proof of this workflow.
    current = json.loads(run(prepare, 'acknowledge-conflict', 'conflict-summary', '0', data=source))
    for _ in range(2):
        current = json.loads(run(advance, 'acknowledge-conflict', current['review_sha256']))
    run('artifact-catalog-publish-invoice', current['effect_request_id'], 'foreign-summary', '0', data=source)
    run(advance, 'acknowledge-conflict', current['review_sha256'], success=False)
    run(reconcile, 'acknowledge-conflict', success=False)
    assert json.loads(run(status, 'acknowledge-conflict'))['state'] == 'applying'
    print('WORKFLOW_RECONCILIATION_CLI_PASSED: verified past commits after withdrawal, review, non-root denial, checkpoint crash/retry, no redispatch, missing/conflicting receipt refusal')
