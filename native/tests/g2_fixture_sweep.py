#!/usr/bin/env python3
"""Serialized offline G2 fixtures in fresh, bounded D-backed Docker containers.

Run from the Linux build environment, not inside a product or test container.
The frozen source must carry build-inputs.json. Every selected lane must produce
positive execution evidence; excluded mount/graphical/hardware qualification is
reported explicitly and is never counted as passed. No host devices are passed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import tarfile
import time
from requirement1_sweep import source_target

IMAGE = 'luma-native-tools:20260927'
BUILD_ROOTS = (Path('/mnt/luma-build'), Path('/mnt/d/LumaOS-builds'))
CAPS = ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID', 'SETPCAP',
        'KILL', 'SYS_CHROOT', 'AUDIT_WRITE')
MAX_LOG = 64 * 1024 * 1024
MAX_FIXTURE_FILE = 8 * 1024 * 1024 * 1024
SUMMARY = re.compile(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; '
                     r'(\d+) ignored; (\d+) measured; (\d+) filtered out;', re.M)


def names(module, *functions):
    return tuple(module + '::tests::' + function for function in functions)


KERNEL = names('admin_service', 'kernel_human_connection') + names(
    'admin_service::peer', 'kernel_fsuid_change_fences_peer_even_after_restore') + names(
    'credential_observer', 'kernel_credential_change', 'kernel_fd_census',
    'kernel_task_inventory_limit')
UTC = names('utc_protocol', 'c_publisher_cross_language_frame',
            'c_publisher_cross_language_envelope') + names(
    'utc_receiver', 'kernel_datagram_boundary', 'kernel_keeper_composition',
    'kernel_final_queue_recheck', 'kernel_shared_history_composition')
RESOURCE = names('tpm', 'emulator_admin_and_resource_authorities_have_independent_handles_and_secrets') + names(
    'resource_checkpoint', 'emulator_resource_enrollment_sealed_restart_and_exact_extend',
    'emulator_resource_lost_publication_is_explicit_finalize_without_nv_replay',
    'emulator_resource_parent_lost_reply_reconciles_predispatch_name_without_persistence_replay')
ENROLL = names('admin_credentials', 'emulator_sealed_delivery') + names(
    'admin_enrollment', 'emulator_existing_owner_seal_refusal', 'emulator_enrollment',
    'emulator_enrolled_delivery')
NATIVE_SEAL = names('tpm', 'emulator_existing_owner_parent_provisioning',
                    'emulator_native_sealed_child') + names('owner_credential', 'emulator_native_envelope')
TPM = names('tpm', 'emulator_install_admission', 'emulator_nv_journal_and_rollback',
            'emulator_restart_and_external_change', 'emulator_rejects_missing_or_redefined_index') + names(
    'sealed_credential', 'emulator_signed_credential') + names('authentication', 'local_pam_account')
MOUNT_TEST = names('recovery_export', 'actual_full_filesystem_retains_partial_and_never_publishes_final')[0]
MODEL_CUSTODY_CASES = tuple('MODEL_CUSTODY_SCOPE_CASE=' + case for case in (
    'actual-nonadmin-pam-and-tpm-purpose', 'wrong-actual-pam-principal',
    'ordinary-admin-refused', 'general-session-refused',
    'changed-intent-refused', 'revoked-assignment-refused'))

# Child entries are not independently launchable. The enclosing test asserts
# the owned child's exact status; hidden .output() children are not invented as
# additional directly observed executions in the report.
CHILDREN = {
    'admin_service::tests::kernel_human_child': ('kernel', 'admin_service::tests::kernel_human_connection'),
    'admin_service::peer::tests::kernel_fsuid_child': ('kernel', 'admin_service::peer::tests::kernel_fsuid_change_fences_peer_even_after_restore'),
    'credential_observer::tests::kernel_credential_child': ('kernel', 'credential_observer::tests::kernel_credential_change'),
    'admin_service::tests::pam_catalog_child': ('pam-catalog', 'admin_service::tests::pam_catalog_connection'),
    'utc_receiver::tests::kernel_sender_child': ('utc-boundaries', 'utc_receiver::tests::kernel_datagram_boundary'),
    'model::tests::prior_restore_umask_child': ('model-process', 'model::tests::prior_restoration_publishes_service_modes_under_restrictive_umask'),
    'model::validation::tests::owned_process_helper': ('model-process', 'model::validation::tests::supervisor_observes_normal_and_failed_owned_runtime_exit_with_verified_descriptors'),
}

LANES = {
    'kernel': {'required': KERNEL, 'timeout': 600},
    'utc-boundaries': {'required': UTC, 'timeout': 600},
    'principal-pam': {'script': 'principal_pam_integration.py', 'required': names('authentication', 'local_pam_account'), 'marker': 'PRINCIPAL_PAM_CASES_PASSED=6', 'timeout': 600},
    'pam-catalog': {'script': 'admin_service_pam_integration.py', 'required': names('admin_credentials', 'emulator_sealed_delivery') + names('admin_enrollment', 'emulator_existing_owner_seal_refusal', 'emulator_enrollment') + names('admin_governance', 'emulator_bootstrap') + names('admin_service', 'pam_catalog_connection'), 'marker': 'ADMIN_SERVICE_PAM_KERNEL_PEER_TPM_CATALOG_PASSED', 'required_markers': MODEL_CUSTODY_CASES, 'timeout': 1800},
    'resource-tpm': {'script': 'resource_checkpoint_integration.py', 'required': RESOURCE, 'marker': 'RESOURCE_CHECKPOINT_SOFTWARE_TPM_PASSED', 'timeout': 1800},
    'admin-enrollment': {'script': 'admin_enrollment_integration.py', 'required': ENROLL, 'marker': 'EXISTING_OWNER_NATIVE_CHECKPOINT_ENROLLMENT_PASSED', 'timeout': 1800},
    'admin-pending': {'script': 'admin_enrollment_pending_integration.py', 'required': names('admin_credentials', 'emulator_sealed_delivery') + names('admin_enrollment', 'emulator_pending_enrollment_publication'), 'marker': 'PENDING_ENROLLMENT_MODE_PASSED=lost-after-rename', 'timeout': 2400},
    'admin-resume': {'script': 'admin_enrollment_resume_integration.py', 'required': names('admin_credentials', 'emulator_sealed_delivery') + names('admin_enrollment', 'emulator_resume_bound_parent_without_reallocation'), 'marker': 'REVIEWED_BOUND_PARENT_CONTINUATION_SOFTWARE_TPM_PASSED', 'timeout': 900},
    'admin-bootstrap': {'script': 'admin_bootstrap_integration.py', 'required': names('admin_credentials', 'emulator_sealed_delivery') + names('admin_enrollment', 'emulator_existing_owner_seal_refusal', 'emulator_enrollment') + names('admin_governance', 'emulator_bootstrap'), 'marker': 'ADMIN_BOOTSTRAP_EXISTING_OWNER_SOFTWARE_TPM_PASSED', 'timeout': 1200},
    'admin-recovery': {'script': 'admin_recovery_integration.py', 'required': names('tpm', 'emulator_committed_journal_recovery'), 'marker': 'ADMIN_COMMITTED_RECOVERY_SOFTWARE_TPM_PASSED', 'timeout': 600},
    'sealed-delivery': {'script': 'admin_credential_integration.py', 'required': names('admin_credentials', 'emulator_sealed_delivery'), 'marker': 'SEALED_DELIVERY_SOFTWARE_TPM_PASSED', 'timeout': 1200},
    'native-seal': {'script': 'admin_native_seal_integration.py', 'required': NATIVE_SEAL, 'marker': 'NATIVE_OWNER_SEALED_CHILD_SOFTWARE_TPM_PASSED', 'timeout': 1800},
    'existing-owner': {'script': 'existing_owner_integration.py', 'required': names('tpm', 'emulator_existing_owner_parent_provisioning', 'emulator_existing_owner_provisioning'), 'marker': 'EXISTING_OWNER_PROVISIONING_PASSED', 'timeout': 900},
    'tpm-journal': {'script': 'tpm_integration.py', 'required': TPM, 'timeout': 2400, 'baseline': True},
    'model-process': {'required': ('model::tests::prior_restoration_publishes_service_modes_under_restrictive_umask', 'model::validation::tests::supervisor_observes_normal_and_failed_owned_runtime_exit_with_verified_descriptors'), 'timeout': 1200, 'allowed_ignored': 1},
    'broker-cli': {'script': 'broker_client_integration.py', 'required': (), 'timeout': 600, 'synthetic_authority': True},
    'resource-history-cli': {'script': 'resource_history_integration.py', 'required': (), 'marker': 'RESOURCE_HISTORY_NATIVE_CLI_UNIX_PASSED cases=', 'timeout': 600, 'synthetic_authority': True},
    'model-chat-cli': {'script': 'model_chat_integration.py', 'required': (), 'marker': 'MODEL_REPLY_CLI_UNIX_HTTP_PASSED cases=', 'timeout': 600, 'synthetic_authority': True},
    'native-source': {'required': (), 'timeout': 1200, 'unittest': True},
    'public-trust': {'required': (), 'timeout': 180, 'unittest': True},
    'model-public': {'required': (), 'timeout': 180, 'unittest': True},
    'utc-authentication': {'required': (), 'timeout': 180, 'unittest': True},
    'utc-upstream-units': {'required': (), 'timeout': 900, 'capless': True},
    'qmp-display': {'script': 'qmp_display_integration.py', 'required': (), 'timeout': 120},
    'storage': {'script': 'staging_linux_integration.py', 'required': (), 'timeout': 900, 'mounts': True},
    'recovery-enospc': {'required': (MOUNT_TEST,), 'timeout': 600, 'mounts': True},
}


def digest(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def bounded(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as file:
        before = os.fstat(file.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise ValueError('linked/nonregular/oversized evidence input: ' + str(path))
        data = file.read(limit + 1)
        after = os.fstat(file.fileno())
        def identity(metadata):
            return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
                    metadata.st_gid, metadata.st_nlink, metadata.st_size,
                    metadata.st_mtime_ns, metadata.st_ctime_ns)
        if identity(before) != identity(after) or identity(before) != identity(os.stat(path, follow_symlinks=False)) or len(data) != before.st_size:
            raise ValueError('evidence input changed: ' + str(path))
        return data


def ignored_inventory(repo):
    result = {}
    for path in sorted((repo / 'rust/luma-platform/src').rglob('*.rs')):
        relative = path.relative_to(repo / 'rust/luma-platform/src')
        module = '::'.join(relative.with_suffix('').parts)
        for reason, function in re.findall(r'#\[ignore(?:\s*=\s*"([^"]*)")?\]\s*fn\s+([A-Za-z_][A-Za-z0-9_]*)', bounded(path, 2 * 1024 * 1024).decode()):
            name = module + '::tests::' + function
            if name in result:
                raise ValueError('duplicate ignored entry')
            result[name] = {'path': relative.as_posix(), 'reason': reason}
    covered = set(CHILDREN) | {name for lane in LANES.values() for name in lane['required']}
    if set(result) - covered or set(CHILDREN) - set(result):
        raise ValueError('unmapped or disappeared ignored entries: ' + repr(sorted(set(result) ^ (covered & set(result))) + sorted(set(CHILDREN) - set(result))))
    return result


def verify_source(repo):
    manifest = bounded(repo / 'build-inputs.json', 1024 * 1024)
    record = json.loads(manifest)
    if set(record) != {'schema_version', 'files'} or record['schema_version'] != 1 or not 1 <= len(record['files']) <= 4096:
        raise ValueError('source requires closed frozen build-inputs manifest')
    seen = set()
    total = 0
    for entry in record['files']:
        if set(entry) != {'path', 'bytes', 'sha256'} or not isinstance(entry['path'], str):
            raise ValueError('invalid source member')
        relative = Path(entry['path'])
        if relative.is_absolute() or '..' in relative.parts or not relative.parts or relative.as_posix() != entry['path'] or entry['path'] in seen:
            raise ValueError('redirected/duplicate source member')
        if type(entry['bytes']) is not int or not 0 <= entry['bytes'] <= 16 * 1024 * 1024 or not re.fullmatch('[a-f0-9]{64}', entry['sha256']):
            raise ValueError('invalid source member size/hash')
        seen.add(entry['path'])
        total += entry['bytes']
        if total > 64 * 1024 * 1024:
            raise ValueError('source exceeds bounded snapshot size')
        path = repo / relative
        for parent in path.parents:
            if parent == repo:
                break
            if parent.is_symlink():
                raise ValueError('linked source parent')
        data = bounded(path, 16 * 1024 * 1024)
        if len(data) != entry['bytes'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise ValueError('source bytes changed: ' + entry['path'])
    # Every executable fixture and Rust input must be accounted for, not just
    # whichever subset a caller placed in the otherwise valid manifest.
    required = {path.relative_to(repo).as_posix() for directory in ('rust', 'native/tests', 'native/image')
                for path in (repo / directory).rglob('*') if path.is_file()
                and path.suffix in ('.rs', '.c', '.h', '.py', '.sh', '.toml', '.json', '.lock')}
    if required - seen:
        raise ValueError('unmanifested fixture/build inputs: ' + repr(sorted(required - seen)))
    return hashlib.sha256(manifest).hexdigest()


def verify_execution(lane_name, texts, inventory):
    lane = LANES[lane_name]
    text = '\n'.join(texts)
    summaries = SUMMARY.findall(text)
    named = {match: len(re.findall(r'\btest ' + re.escape(match) + r' \.\.\.', text)) for match in lane['required']}
    if lane['required']:
        if not summaries or any(int(row[2]) or row[0] != 'ok' or int(row[1]) == 0 or int(row[4]) for row in summaries):
            raise ValueError('missing, empty, failed or measured Rust execution')
        ignored = sum(int(row[3]) for row in summaries)
        allowed = len(inventory) if lane.get('baseline') else lane.get('allowed_ignored', 0)
        if ignored != allowed:
            raise ValueError('unexpected unexecuted Rust entries: ' + str(ignored))
        if not all(named.values()):
            raise ValueError('required named entries did not execute: ' + repr([name for name, count in named.items() if not count]))
    if lane.get('marker'):
        marker = lane['marker']
        if marker not in text:
            raise ValueError('missing completed fixture marker: ' + marker)
        if marker.endswith('cases=') and not re.search(re.escape(marker) + r'[1-9][0-9]*\b', text):
            raise ValueError('zero/invalid fixture case count')
    for marker in lane.get('required_markers', ()):
        if not re.search(r'^' + re.escape(marker) + r'$', text, re.M):
            raise ValueError('missing exact completed fixture case: ' + marker)
    if lane.get('unittest'):
        summaries_native = re.findall(r'^Ran ([1-9][0-9]*) tests? in .+$', text, re.M)
        terminal = re.findall(r'^(OK|FAILED)(?: \(([^\n]*)\))?$', text, re.M)
        if len(summaries_native) != 1 or terminal != [('OK', '')]:
            raise ValueError('selected Python suite must pass nonempty with no skips/expected failures')
    return {'named_executions': named, 'rust_summaries': [dict(zip(
        ('status', 'passed', 'failed', 'ignored', 'measured', 'filtered_out'), row)) for row in summaries],
        'owned_children': [{'entry': child, 'parent': parent, 'directly_counted': False,
                            'evidence': 'parent asserts exact owned-child status'}
                           for child, (owner_lane, parent) in CHILDREN.items() if owner_lane == lane_name]}


def limited_child():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG, MAX_LOG))


def fixture_child():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Oversized pinned-model fixtures deliberately create multi-GiB sparse
    # files. Bound their extent separately from the transcript byte ceiling.
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FIXTURE_FILE, MAX_FIXTURE_FILE))


def temporary_mounts(lane_name, temporary):
    if lane_name not in LANES:
        raise ValueError('unknown fixture lane')
    # Real PAM uses disposable /etc and publishes the fixture registry by
    # atomic rename. Both must share this fresh container's D-backed layer.
    # A separate /tmp bind would create an artificial EXDEV failure.
    if lane_name == 'pam-catalog':
        return []
    return ['--mount', f'type=bind,source={temporary},target=/tmp']


def execute(command, cwd, env, output, index, timeout):
    log = output / ('command-%03d.log' % index)
    began = time.monotonic()
    with log.open('xb') as stream:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=fixture_child)
        timed_out, log_limit_exceeded = False, False
        deadline = began + timeout
        while process.poll() is None:
            log_limit_exceeded = os.fstat(stream.fileno()).st_size > MAX_LOG
            timed_out = time.monotonic() >= deadline
            if timed_out or log_limit_exceeded:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
                break
            try:
                process.wait(timeout=min(0.1, max(0.001, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                pass
        log_limit_exceeded |= os.fstat(stream.fileno()).st_size > MAX_LOG
    item = {'command': [str(arg) for arg in command], 'exit_code': process.returncode,
            'timed_out': timed_out, 'log_limit_exceeded': log_limit_exceeded,
            'seconds': round(time.monotonic() - began, 3),
            'transcript': log.name, 'sha256': digest(log)}
    print('G2_COMMAND_RESULT=' + json.dumps(item, sort_keys=True), flush=True)
    if timed_out or log_limit_exceeded or process.returncode:
        raise RuntimeError('fixture command failed; exact transcript preserved: ' + log.name)
    return bounded(log, MAX_LOG).decode(errors='replace'), item


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def extract_reviewed_utc(repo, output):
    verifier = load_module(repo / 'native/image/utc/verify_release.py', 'g2_utc_verifier')
    snapshot = verifier.snapshot(Path('/utc-input/chrony-4.9.tar.gz'), output / 'authenticated-utc',
                                 signature=verifier.ASSETS / 'chrony-4.9.tar.gz.asc', work=output)
    raw = output / 'upstream'
    raw.mkdir(mode=0o700)
    with tarfile.open(snapshot / verifier.ARCHIVE_NAME, 'r:gz') as archive:
        members = archive.getmembers()
        if len(members) > 4096 or sum(member.size for member in members) > 32 * 1024 * 1024:
            raise ValueError('UTC extraction exceeds bounds')
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != 'chrony-4.9' or not (member.isfile() or member.isdir()):
                raise ValueError('UTC extraction redirected/nonregular member')
        archive.extractall(raw, members=members, filter='data')
    return raw / 'chrony-4.9'


def inside(lane_name):
    if not Path('/.dockerenv').is_file() or os.geteuid() != 0:
        raise ValueError('inner fixture requires fresh disposable root container')
    if any(Path(path).exists() for path in ('/dev/tpm0', '/dev/tpmrm0', '/dev/kvm', '/var/run/docker.sock')):
        raise ValueError('host device/socket attached to fixture')
    if {path.name for path in Path('/sys/class/net').iterdir()} != {'lo'}:
        raise ValueError('fixtures require network none')
    repo, output = Path('/repo'), Path('/evidence')
    identity = verify_source(repo)
    inventory = ignored_inventory(repo)
    lane = LANES[lane_name]
    if lane_name == 'pam-catalog' and os.stat('/tmp').st_dev != os.stat('/etc').st_dev:
        raise ValueError('disposable PAM account and registry staging must share a filesystem')
    environment = dict(os.environ, CARGO_TARGET_DIR=source_target(identity), CARGO_INCREMENTAL='0',
                       CARGO_PROFILE_TEST_DEBUG='0', CARGO_PROFILE_DEV_DEBUG='0',
                       RUSTFLAGS='-Dwarnings', PYTHONDONTWRITEBYTECODE='1', TMPDIR='/tmp',
                       LUMA_STORAGE_TEST_ROOT=str(output), TSS2_LOG='all+NONE')
    texts, commands = [], []
    def run(argv, cwd=repo / 'rust', timeout=300):
        text, result = execute([str(arg) for arg in argv], cwd, environment, output, len(commands), timeout)
        texts.append(text)
        commands.append(result)
        return text
    def exact(name, ignored=True):
        return ['cargo', 'test', '--offline', '--locked', name, '--', '--exact',
                *(('--ignored',) if ignored else ()), '--nocapture', '--test-threads=1']
    if lane_name in ('kernel', 'utc-boundaries'):
        if lane_name == 'utc-boundaries':
            assets = repo / 'native/image/utc'
            policy = hashlib.sha256(b'luma-native-approved-utc-policy-v1\0' + (assets / 'approved-policy.json').read_bytes()).digest()
            (output / 'luma_policy_digest.h').write_text('static const unsigned char luma_policy_digest[32] = {' + ','.join(str(byte) for byte in policy) + '};\n')
            run(['cc', '-Wall', '-Wextra', '-Werror', '-I', assets, '-I', output,
                 assets / 'publisher.c', assets / 'test_publisher.c', '-lm', '-o', output / 'publisher'], repo)
            run([output / 'publisher', output / 'frame', output / 'envelope'], repo)
            environment['LUMA_UTC_C_FRAME'] = str(output / 'frame')
            environment['LUMA_UTC_C_ENVELOPE'] = str(output / 'envelope')
        for test in lane['required']:
            run(exact(test))
    elif lane_name == 'model-process':
        run(exact(lane['required'][0], ignored=False))
        run(['cargo', 'test', '--offline', '--locked', 'model::validation::tests::', '--', '--nocapture', '--test-threads=1'], timeout=900)
    elif lane_name in ('broker-cli', 'resource-history-cli', 'model-chat-cli', 'storage'):
        run(['cargo', 'build', '--offline', '--locked'])
        binary = Path(environment['CARGO_TARGET_DIR']) / 'debug/luma-platform'
        Path('/usr/libexec/luma-os').mkdir(parents=True)
        run(['install', '-m', '0755', binary, '/usr/libexec/luma-os/luma-platform'], repo)
        script = repo / 'native/tests' / lane['script']
        if lane_name == 'broker-cli':
            run(['/usr/bin/python3', '-B', script, '--binary', binary, '--output', output / 'broker'], repo)
        elif lane_name == 'storage':
            run(['unshare', '--mount', '--propagation', 'private', '/usr/bin/python3', '-B', script,
                 '--binary', binary, '--output', output / 'storage.json'], repo, 600)
        else:
            run(['cc', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC', repo / 'native/tests/resource_history_cmdline_fixture.c',
                 '-o', '/tmp/resource-history-cmdline-fixture.so', '-ldl'], repo)
            run(['/usr/bin/python3', '-B', script], repo)
    elif lane_name == 'recovery-enospc':
        run(['unshare', '--mount', '--propagation', 'private', 'env', 'LUMA_EXPORT_MOUNT_TEST=1', *exact(MOUNT_TEST)])
    elif lane_name == 'native-source':
        environment['LUMA_CHRONY_RELEASE_UPSTREAM'] = str(extract_reviewed_utc(repo, output))
        run(['/usr/bin/python3', '-B', '-W', 'error', '-m', 'unittest', 'discover', '-s', 'native/tests', '-p', 'test_*.py', '-v'], repo, 900)
    elif lane_name == 'public-trust':
        run(['/usr/bin/python3', '-B', '-W', 'error', '-m', 'unittest', 'discover', '-s', 'native/image', '-p', 'test_public_trust.py', '-v'], repo)
    elif lane_name == 'model-public':
        run(['/usr/bin/python3', '-B', '-W', 'error', '-m', 'unittest', 'discover', '-s', 'native/image', '-p', 'test_model_inputs.py', '-v'], repo)
    elif lane_name == 'utc-authentication':
        run(['/usr/bin/python3', '-B', repo / 'native/image/utc/test_release_authentication.py',
             '--archive', '/utc-input/chrony-4.9.tar.gz', '--work', output], repo)
    elif lane_name == 'utc-upstream-units':
        run(['/usr/bin/python3', '-B', repo / 'native/image/utc/test_release_units.py',
             '--archive', '/utc-input/chrony-4.9.tar.gz', '--output', output / 'units'], repo, 800)
        evidence = json.loads(bounded(output / 'units/evidence.json', 1024 * 1024))
        expected = {(name, seed) for name in ('hash', 'cmac', 'siv', 'ntp_ext', 'ntp_auth',
                                             'nts_ntp_auth', 'nts_ntp_client', 'nts_ke_session') for seed in (1, 2)}
        results = evidence['results']
        if len(results) != 16 or {(item['unit'], item['seed']) for item in results} != expected or any(item['result'] != 'PASS' for item in results):
            raise ValueError('UTC upstream lane did not execute exact 16 unskipped cases')
    elif lane_name == 'qmp-display':
        run(['/usr/bin/python3', '-B', repo / 'native/tests' / lane['script'], '--output', output / 'display'], repo)
    elif lane_name == 'tpm-journal':
        run(['/usr/bin/python3', '-B', repo / 'native/tests' / lane['script'], '--repository', repo,
             '--output', output / 'tpm'], repo / 'rust', 2300)
        texts.append(bounded(output / 'tpm/transcript.txt', MAX_LOG).decode(errors='replace'))
    else:
        run(['/usr/bin/python3', '-B', repo / 'native/tests' / lane['script']], timeout=lane['timeout'] - 30)
    # These transport/storage runners persist a concrete nonempty case record.
    if lane_name in ('broker-cli', 'storage', 'qmp-display', 'tpm-journal'):
        result_path = {'broker-cli': output / 'broker/result.json', 'storage': output / 'storage.json',
                       'qmp-display': output / 'display/result.json', 'tpm-journal': output / 'tpm/result.json'}[lane_name]
        result = json.loads(bounded(result_path, 1024 * 1024))
        if result.get('result') != 'passed' or (lane_name != 'qmp-display' and not result.get('cases')):
            raise ValueError('fixture lacks nonempty completed retained result')
    execution = verify_execution(lane_name, texts, inventory)
    if verify_source(repo) != identity:
        raise ValueError('source changed during fixture execution')
    evidence = {'schema_version': 1, 'lane': lane_name, 'result': 'passed',
                'source_manifest_sha256': identity, 'commands': commands, 'execution': execution,
                'synthetic_authority': bool(lane.get('synthetic_authority')), 'physical_hardware_tested': False,
                'installed_image_qualified': False, 'gate_closing': False}
    with (output / 'lane.json').open('x') as file:
        json.dump(evidence, file, sort_keys=True, indent=2)
        file.write('\n')
    print('G2_LANE_RESULT=' + json.dumps(evidence, sort_keys=True), flush=True)


def d_path(path, exists=True):
    if not path.is_absolute() or any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError('D work/cache path must be absolute and unredirected')
    resolved = path.resolve(strict=exists)
    if not any(resolved.is_relative_to(root) and resolved != root for root in BUILD_ROOTS):
        raise ValueError('work/cache/output must be below fixed D build roots')
    return resolved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--utc-archive', type=Path)
    parser.add_argument('--private-mounts', action='store_true')
    parser.add_argument('--lane', action='append', choices=tuple(LANES))
    parser.add_argument('--inside-lane', choices=tuple(LANES), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside_lane:
        inside(args.inside_lane)
        return
    if os.name != 'posix' or os.geteuid() != 0 or Path('/.dockerenv').exists() or any(value is None for value in (args.repository, args.output, args.cache, args.utc_archive)):
        raise SystemExit('use the Linux build host with --repository --output --cache --utc-archive')
    repo = args.repository.resolve(strict=True)
    if args.repository.is_symlink():
        raise ValueError('source snapshot must not be redirected')
    identity = verify_source(repo)
    inventory = ignored_inventory(repo)
    cache, output, archive = d_path(args.cache), d_path(args.output, False), d_path(args.utc_archive)
    if not cache.is_dir() or cache.stat().st_mode & 0o111 != 0o111:
        raise ValueError('D cache directory must be searchable by owned unprivileged fixture children')
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError('output must be a new direct child of an existing D directory')
    lanes = args.lane or [name for name, lane in LANES.items() if not lane.get('mounts') or args.private_mounts]
    if len(lanes) != len(set(lanes)) or any(LANES[name].get('mounts') and not args.private_mounts for name in lanes):
        raise ValueError('duplicate lanes or private mount lane without explicit approval flag')
    docker_root = subprocess.check_output(['docker', 'info', '--format', '{{.DockerRootDir}}'], timeout=30, text=True).strip()
    d_path(Path(docker_root))
    image = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', IMAGE], timeout=30, text=True).strip()
    if not re.fullmatch('sha256:[a-f0-9]{64}', image):
        raise ValueError('tools image lacks an immutable local identity')
    output.mkdir(mode=0o700)
    results = []
    for index, name in enumerate(lanes):
        lane = LANES[name]
        directory = output / name
        directory.mkdir(mode=0o700)
        temporary = directory / 'temporary'
        temporary.mkdir(mode=0o1777)
        temporary.chmod(0o1777)
        container = 'luma-g2-fixture-' + hashlib.sha256(str(output).encode()).hexdigest()[:12] + '-' + str(index)
        command = ['docker', 'run', '--rm', '--pull', 'never', '--name', container, '--network', 'none',
                   '--memory', '4g', '--memory-swap', '4g', '--cpus', '2', '--pids-limit', '256',
                   '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                   '--mount', f'type=bind,source={repo},target=/repo,readonly',
                   '--mount', f'type=bind,source={cache},target=/cache',
                   '--mount', f'type=bind,source={directory},target=/evidence',
                   '--mount', f'type=bind,source={archive},target=/utc-input/chrony-4.9.tar.gz,readonly',
                   '--env', 'PYTHONDONTWRITEBYTECODE=1']
        command.extend(temporary_mounts(name, temporary))
        if not lane.get('capless'):
            for capability in CAPS:
                command.extend(('--cap-add', capability))
        if lane.get('mounts'):
            command.extend(('--cap-add', 'SYS_ADMIN', '--security-opt', 'seccomp=unconfined',
                            '--security-opt', 'apparmor=unconfined'))
        command.extend((image, '/usr/bin/python3', '-B', '/repo/native/tests/g2_fixture_sweep.py', '--inside-lane', name))
        log = directory / 'docker.log'
        began = time.monotonic()
        timed_out, error = False, None
        print('G2 isolated fixture: ' + name, flush=True)
        with log.open('xb') as stream:
            process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=limited_child)
            try:
                process.wait(timeout=lane['timeout'] + 120)
            except subprocess.TimeoutExpired:
                timed_out = True
                # The exact named disposable container is the only stop target.
                subprocess.run(['docker', 'kill', container], stdout=stream, stderr=subprocess.STDOUT, timeout=30)
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
        try:
            inner = json.loads(bounded(directory / 'lane.json', 1024 * 1024))
            if inner.get('result') != 'passed' or inner.get('source_manifest_sha256') != identity or inner.get('lane') != name:
                raise ValueError('missing/stale completed lane evidence')
            verify_source(repo)
        except (OSError, ValueError, KeyError) as failure:
            inner, error = None, str(failure)
        results.append({'lane': name, 'exit_code': process.returncode, 'timed_out': timed_out,
                        'verification_error': error, 'seconds': round(time.monotonic() - began, 3),
                        'docker_log_sha256': digest(log), 'evidence': inner})
        print(json.dumps(results[-1], sort_keys=True), flush=True)
    coverage = []
    for name, entry in inventory.items():
        if name in CHILDREN:
            lane, parent = CHILDREN[name]
            relation = {'kind': 'owned-child-only', 'parent': parent, 'lanes': [lane]}
        else:
            relation = {'kind': 'external-fixture', 'lanes': [lane for lane, spec in LANES.items() if name in spec['required']]}
        selected = [lane for lane in relation['lanes'] if lane in lanes]
        passed = any(item['lane'] in selected and item['exit_code'] == 0 and not item['verification_error'] for item in results)
        coverage.append(dict(entry=name, **entry, **relation, selected=selected, covered_by_passed_fixture=passed))
    result = {'schema_version': 1, 'scope': 'offline-disposable-G2-development-not-native-certification',
              'result': 'passed' if all(item['exit_code'] == 0 and not item['timed_out'] and not item['verification_error'] for item in results) else 'failed',
              'source_manifest_sha256': identity, 'runner_sha256': digest(repo / 'native/tests/g2_fixture_sweep.py'),
              'tools_image': image, 'private_mounts_requested': args.private_mounts, 'cases': results,
              'ignored_entry_coverage': coverage,
              'not_executed': {'lanes': [name for name in LANES if name not in lanes],
                               'qualification': ['native NTS/provider connectivity and host clock/confinement',
                                                 'signed-image destructive install/boot/A-B/power-loss recovery',
                                                 'physical TPM/GPU/storage/hardware certification',
                                                 'installed GNOME login/lock/security qualification',
                                                 'production external custody and first-boot Admin activation']},
              'physical_hardware_tested': False, 'installed_image_qualified': False, 'gate_closing': False}
    with (output / 'result.json').open('x') as file:
        json.dump(result, file, indent=2, sort_keys=True)
        file.write('\n')
    raise SystemExit(0 if result['result'] == 'passed' else 1)


if __name__ == '__main__':
    main()
