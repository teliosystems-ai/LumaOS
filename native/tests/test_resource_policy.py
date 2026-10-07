"""Resource integration guards, not installed enforcement qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ResourcePolicyTests(unittest.TestCase):
    def test_invoice_publishers_never_use_unleased_calculation_or_test_dispatch(self):
        for name in ('artifacts.rs', 'artifact_catalog.rs'):
            source = (ROOT/'rust/luma-platform/src'/name).read_text()
            production = source.split('#[cfg(test)]')[0]
            self.assertNotIn('calculation::report_bytes(', production)
            entry = production.split('pub fn publish_invoice(')[1].split('pub(crate) fn invoice_publication(')[0]
            self.assertIn('workflow_resource::calculate', entry)
            self.assertIn('workflow_resource::Calculation::recheck', entry)
            publication = production.split('pub(crate) fn invoice_publication(')[1].split('pub fn read(')[0]
            self.assertIn('recheck(&result, &source, &receipt.installation)', publication)
            self.assertIn('resource_lease: Some(result.lease.clone())', publication)
            self.assertIn('previous.resource_lease.clone()', publication)
            self.assertNotIn('LUMA_PUBLICATION_TEST', production)
        artifacts = (ROOT/'rust/luma-platform/src/artifacts.rs').read_text()
        reconciliation = artifacts.split('pub fn reconcile(')[1].split('pub fn abort(')[0]
        for boundary in ('workflow_resource::recheck_report', 'receipt.resource_lease.as_ref()',
                         'prepared legacy artifact lacks resource provenance', 'if let Some((expected, report))'):
            self.assertIn(boundary, reconciliation)
        main = (ROOT/'rust/luma-platform/src/main.rs').read_text()
        self.assertIn('#[cfg(test)]\nmod publication_fixture;', main)
        self.assertNotIn('publication_fixture::', main)

    def test_broker_is_the_only_resource_writer_and_uses_existing_transport(self):
        source = (ROOT/'rust/luma-platform/src/service.rs').read_text()
        self.assertEqual(source.count('UnixListener::bind(SOCKET)'), 1)
        self.assertIn('SO_PEERPIDFD', source)
        self.assertIn('peer_pidfd(&incoming.stream)', source)
        self.assertIn('kernel peer authentication', source)
        self.assertIn('resource_manager::Manager::open()', source)
        self.assertNotIn('resources::initialize', source)
        unit = (ROOT/'native/image/overlay/etc/systemd/system/luma-broker.service').read_text()
        self.assertIn('ReadOnlyPaths=/sys/fs/cgroup', unit)
        self.assertIn('ReadWritePaths=/sys/fs/cgroup/lumamodel.slice', unit)
        self.assertIn('CapabilityBoundingSet=\n', unit)

    def test_lease_precedes_weight_loading_and_runtime_execution(self):
        source = (ROOT/'rust/luma-platform/src/model.rs').read_text()
        serve = source.split('pub fn serve()')[1].split('#[cfg(test)]')[0]
        self.assertLess(serve.index('WorkerLease::acquire'), serve.index('verified_runtime_file('))
        self.assertLess(serve.index('WorkerLease::acquire'), serve.index('supervision::run'))
        self.assertIn('lease.check()', serve)
        self.assertIn('fence.check(', serve)

    def test_physical_drainage_not_a_worker_message_returns_capacity(self):
        source = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        maintain = source.split('pub(crate) fn maintain')[1].split('pub(crate) fn handle')[0]
        self.assertIn('for kind in [Kind::Model, Kind::Acquisition]', maintain)
        self.assertIn('Kind::Model => &self.group', maintain)
        self.assertIn('Kind::Acquisition => &self.acquisition', maintain)
        self.assertIn('group.populated()', maintain)
        self.assertIn('group.current()', maintain)
        self.assertLess(maintain.index('group.kill()'), maintain.index('finish_draining('))
        self.assertIn('cgroup.freeze', maintain)
        self.assertNotIn('"resource-release"', source.split('#[cfg(test)]')[0])
        drop = source.split('impl Drop for Heartbeat')[1].split('pub(crate) fn client')[0]
        self.assertNotIn('resource_exchange', drop)

    def test_installer_initializes_private_resource_state_and_model_is_cgroup_bound(self):
        platform = (ROOT/'rust/luma-platform/src/platform.rs').read_text()
        self.assertIn('crate::resources::initialize(&data.at.join("lib/luma-broker/resources"))?', platform)
        model = (ROOT/'native/image/overlay/etc/systemd/system/luma-model.service').read_text()
        for directive in ('Slice=lumamodel.slice', 'BindsTo=luma-broker.service',
                          'OOMPolicy=kill', 'MemorySwapMax=0', 'LimitMEMLOCK=0',
                          'IOReadBandwidthMax=/var 64M', 'IOWriteBandwidthMax=/var 64M',
                          'KillMode=control-group', 'ProtectControlGroups=yes'):
            self.assertIn(directive, model)
        profile = (ROOT/'native/image/overlay/etc/apparmor.d/luma-model').read_text()
        self.assertIn('/run/luma-broker/control.sock rw,', profile)
        self.assertNotIn('/var/lib/luma-broker/resources', profile)

    def test_resource_implementation_contains_no_unimplemented_paths(self):
        for name in ('resources.rs', 'resource_manager.rs', 'acquisition.rs', 'storage_io.rs',
                     'service/ingress.rs', 'model/layout.rs', 'resource_manager/recovery.rs',
                     'resource_manager/requests.rs', 'resource_manager/requests/journal.rs',
                     'resource_manager/history.rs', 'resource_manager/peer.rs',
                     'workflow_resource.rs',
                     'resource_manager/requests/gateway.rs', 'model/gateway.rs'):
            source = (ROOT/'rust/luma-platform/src'/name).read_text()
            for marker in ('todo!', 'unimplemented!', '// TODO', '// FIXME'):
                self.assertNotIn(marker, source)

    def test_invoice_workflow_uses_leased_closed_calculation_without_a_root_fallback(self):
        worker = (ROOT/'rust/luma-platform/src/workflow_resource.rs').read_text()
        compute = worker.split('pub(crate) fn worker(')[1].split('#[cfg(test)]')[0]
        self.assertLess(compute.index('WorkerLease::acquire_acquisition'), compute.index('sealed_source('))
        self.assertLess(compute.index('lease.complete_output('), compute.index('stdout().lock().write_all'))
        self.assertIn('F_GET_SEALS', worker)
        self.assertIn('resource-output-receipt', worker)
        self.assertIn('token.manager_epoch != ledger.manager_epoch', worker)
        self.assertIn('physical_release_granted', worker)
        workflow = (ROOT/'rust/luma-platform/src/workflow_runs.rs').read_text().split('#[cfg(test)]')[0]
        self.assertIn('calculator: workflow_resource::calculate', workflow)
        self.assertNotIn('calculation::report_bytes', workflow)
        self.assertIn('next.resource_lease = Some(result.lease.clone())', workflow)
        self.assertIn('calculation_check: workflow_resource::Calculation::recheck', workflow)
        finish = workflow.split('fn finish(')[1].split('fn reconciliation_input(')[0]
        self.assertGreaterEqual(finish.count('(self.calculation_check)(&calculation, &source, &plan.installation)'), 3)
        launch = (ROOT/'rust/luma-platform/src/acquisition.rs').read_text()
        self.assertIn('"RestrictAddressFamilies=AF_UNIX"', launch)
        self.assertIn('"RuntimeMaxSec=30"', launch)
        self.assertIn('"LimitFSIZE=4M"', launch)
        self.assertIn('if action == "invoice"', launch)
        ledger = (ROOT/'rust/luma-platform/src/resources.rs').read_text()
        completion = ledger.split('pub(crate) fn complete_output(')[1].split('pub(crate) fn revoke(')[0]
        self.assertIn('self.assert_active(token, owner, now)?', completion)
        self.assertNotIn('finish_draining', completion)

    def test_reference_gateway_runs_only_inside_the_existing_leased_supervisor(self):
        service = (ROOT/'rust/luma-platform/src/service.rs').read_text()
        self.assertIn('Some("resource-gateway")', service)
        self.assertIn('.handle_gateway(', service)
        gateway = (ROOT/'rust/luma-platform/src/resource_manager/requests/gateway.rs').read_text()
        for marker in ('assert_active(token, &observed, time)', 'owner(peer.pid',
                       'Caller::observe_supported', 'self.requests.begin(',
                       'self.requests.admit(', 'self.requests.finish(', 'wire_bound(&planned)',
                       'self.requests.persist(', 'gateway queue full or replay differs'):
            self.assertIn(marker, gateway)
        model = (ROOT/'rust/luma-platform/src/model.rs').read_text()
        self.assertIn('gateway.tick(', model)
        driver = (ROOT/'rust/luma-platform/src/model/gateway.rs').read_text()
        self.assertLess(driver.index('Message::Admit'), driver.index('let completion: Completion = post('))
        self.assertIn('127.0.0.1:8081', driver)
        self.assertNotIn('UnixListener', gateway+driver)
        client = (ROOT/'src/luma_os/native_inference.py').read_text()
        self.assertIn('socket.SO_PEERCRED', client)
        self.assertNotIn('model_api_key', client)
        self.assertNotIn('urllib', client)
        unit = (ROOT/'native/image/overlay/etc/systemd/system/luma-broker.service').read_text()
        self.assertIn('RestrictAddressFamilies=AF_UNIX', unit)
        self.assertIn('self.gateway_serving(expected, now()?)?', gateway)
        fetch = gateway.split('Message::Fetch { nonce, worker } =>')[1].split('Message::Cancel { nonce, worker } =>')[0]
        self.assertEqual(fetch.count('self.gateway_serving(Some(worker), time)?'), 2)
        manager = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        maintain = manager.split('pub(crate) fn maintain')[1].split('fn retained')[0]
        self.assertGreater(maintain.index('self.maintain_gateway(now()?)'), maintain.index('finish_draining('))

    def test_current_credentials_and_both_fixed_worker_confinements_are_rechecked(self):
        peer = (ROOT/'rust/luma-platform/src/resource_manager/peer.rs').read_text()
        for marker in ('luma-model (enforce)', 'luma-acquisition (enforce)',
                       '"NoNewPrivs"', '"Seccomp"', '"CapEff"', '"CapBnd"',
                       '"CapPrm"', '"CapInh"', '"CapAmb"', 'values.len() != 4'):
            self.assertIn(marker, peer)
        manager = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        owner = manager.split('fn owner(')[1].split('fn inventory(')[0]
        self.assertEqual(owner.count('peer::worker_generation('), 2)
        handle = manager.split('pub(crate) fn handle(')[1].split('fn validate(')[0]
        self.assertLess(handle.index('peer::live_generation'), handle.index('self.maintain()'))
        self.assertIn('peer::live_generation(peer, &reply_pin)? != current_peer', handle)
        requests = (ROOT/'rust/luma-platform/src/resource_manager/requests.rs').read_text()
        self.assertIn('self.maintain_checked(ledger, time, Caller::live)', requests)
        self.assertIn('Caller::observe(peer, &reply_pin)? != caller', requests)
        history = (ROOT/'rust/luma-platform/src/resource_manager/history.rs').read_text()
        self.assertEqual(history.split('impl Manager {')[1].split('pub(crate) fn export(')[0].count('live_generation('), 2)

    def test_operator_admission_uses_exact_tokens_and_preserves_physical_capacity(self):
        helper = (ROOT/'native/image/overlay/usr/libexec/luma-os/model-chat.py').read_text()
        inference = helper.split('def inference(options):')[1].split('def main():')[0]
        self.assertLess(inference.index("'operation': 'begin'"), inference.index("'/apply-template'"))
        self.assertLess(inference.index("'operation': 'admit'"), inference.index("'/completion'"))
        self.assertLess(inference.index("'operation': 'finish'"), inference.index("return {'model'"))
        self.assertIn("'prompt': tokens", inference)
        self.assertIn("'cache_prompt': False", inference)
        self.assertIn("'operation': 'cancel'", inference)
        self.assertIn("peer.connect('/run/luma-broker/control.sock')", helper)
        source = (ROOT/'rust/luma-platform/src/resource_manager/requests.rs').read_text().split('\n#[cfg(test)]\nmod tests {')[0]
        self.assertIn('uid!=0', ''.join(source.split()))
        self.assertIn('prompt_tokens.checked_add(record.limit)', ''.join(source.split()))
        self.assertIn('pidfd_alive', source)
        self.assertIn('WIRE_SCHEMA: u32 = 2',source)
        self.assertIn('prior.input_digest.as_ref() != Some(input_digest)',source)
        self.assertLess(inference.index("input_digest = hashlib.sha256"),inference.index("'operation': 'begin'"))
        self.assertIn('worker_resources_released', source)
        self.assertNotIn('finish_draining', source)
        main = (ROOT/'rust/luma-platform/src/main.rs').read_text()
        launch = main.split('Some("model-chat") => {')[1].split('Some(')[0]
        self.assertIn('CommandExt', launch)
        self.assertIn('.exec()', launch)
        self.assertNotIn('.status()', launch)

    def test_request_history_is_private_durable_reviewed_and_not_a_worker_release(self):
        manager = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        self.assertIn('requests::Gate::open(&store)?', manager)
        self.assertNotIn('requests: requests::Gate::new()', manager)
        requests = (ROOT/'rust/luma-platform/src/resource_manager/requests.rs').read_text()
        dispatch = requests.split('pub(crate) fn handle_inference(')[1]
        self.assertLess(dispatch.index('self.requests.persist(&self.store, true)?'),
                        dispatch.index('"result":"ok"'))
        journal = (ROOT/'rust/luma-platform/src/resource_manager/requests/journal.rs').read_text()
        for term in ('create_new(true)', 'RENAME_NOREPLACE', 'sync_all()',
                     'self.retention.poisoned = true', 'retention.retired',
                     'ReviewedLegacyMigration', 'MAX_ARCHIVES: usize = 64'):
            self.assertIn(term, journal)
        production = journal.split('#[cfg(test)]')[0]
        self.assertNotIn('remove_file', production)
        self.assertNotIn('finish_draining', production)
        self.assertNotIn('ledger.leases.clear()', production)
        unit = (ROOT/'native/image/overlay/etc/systemd/system/luma-broker.service').read_text()
        self.assertIn('RestrictAddressFamilies=AF_UNIX', unit)

    def test_suspend_stops_model_execution_and_lease_deadlines_include_sleep_time(self):
        assembly = (ROOT/'native/image/assemble.py').read_text()
        self.assertIn('Conflicts=luma-reference.service luma-model.service', assembly)
        resource = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        self.assertIn('libc::CLOCK_BOOTTIME', resource)

    def test_history_export_and_recovery_keep_existing_transport_and_physical_fences(self):
        history = (ROOT/'rust/luma-platform/src/resource_manager/history.rs').read_text().split('#[cfg(test)]')[0]
        for limit in ('CHUNK_BYTES: u64 = 2048', 'EXPORT_BYTES: u64 = 1024 * 1024',
                      'checked_add(30_000)', 'validate_chunk', 'Sha256::digest(&bytes)'):
            self.assertIn(limit, history)
        export = history.split('pub(crate) fn export(')[1].split('fn collect(')[0]
        self.assertLess(export.index('collect('), export.index('write_all(&bytes)'))
        journal = (ROOT/'rust/luma-platform/src/resource_manager/requests/journal.rs').read_text().split('#[cfg(test)]')[0]
        self.assertIn('State::Released', journal)
        self.assertIn('.requests-retained-', journal)
        self.assertIn('RENAME_NOREPLACE', journal)
        self.assertIn('observe()?;', journal)
        self.assertNotIn('remove_file', journal)
        manager = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        self.assertIn('recover_stage_checked(', manager)
        service = (ROOT/'rust/luma-platform/src/service.rs').read_text()
        self.assertIn('resource_export_exchange', service)
        shape = service.split('let shape = match request.action.as_str()')[1].split('if !shape')[0]
        for action in ('resource-request-status', 'resource-request-archive',
                       'resource-request-recovery-status', 'resource-request-recover'):
            self.assertIn(action, shape)

    def test_archival_is_broker_only_reviewed_and_not_a_capacity_release(self):
        source = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        archive = source.split('"resource-archive" => {')[1].split('_ => return Err')[0]
        self.assertIn('self.group.populated()', archive)
        self.assertIn('self.owners.is_empty()', archive)
        self.assertIn('self.store.archive(', archive)
        ledger = (ROOT/'rust/luma-platform/src/resources.rs').read_text()
        cut = ledger.split('pub(crate) fn archive(')[1].split('fn transaction')[0]
        self.assertIn('State::Released', cut)
        self.assertIn('l.leases.clear()', cut)
        self.assertNotIn('l.generation =', cut)
        self.assertNotIn('remove_file', cut)

    def test_idle_reclaim_requires_empty_group_and_observed_bytes_not_write_success(self):
        resource = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        reclaim = resource.split('fn reclaim_idle')[1].split('fn oom')[0]
        self.assertIn('self.populated()', reclaim)
        self.assertIn('memory.reclaim', reclaim)
        self.assertIn('libc::EAGAIN', reclaim)
        maintain = resource.split('pub(crate) fn maintain')[1].split('pub(crate) fn handle')[0]
        actual = maintain.split('group.reclaim_idle()?;')[1]
        self.assertLess(actual.index('self.retained(&ledger, None)?'), actual.index('l.observe('))

    def test_acquisition_gets_an_independent_lease_before_download_and_hashing(self):
        worker = (ROOT/'rust/luma-platform/src/acquisition.rs').read_text()
        dispatch = worker.split('pub(crate) fn worker(')[1].split('#[cfg(test)]')[0]
        self.assertLess(dispatch.index('WorkerLease::acquire_acquisition('), dispatch.index('prepare_model_contents('))
        self.assertLess(dispatch.index('WorkerLease::acquire_acquisition('), dispatch.index('verify_acquired_model('))
        self.assertIn('lease.check()?;', dispatch)
        self.assertIn('0::/lumaacquisition.slice/luma-acquisition.service', worker)
        self.assertIn('RuntimeMaxSec=3700', worker)
        broker = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        self.assertIn('profile.binding(&storage)?', broker)
        self.assertIn('Self::Model(profile) => acquisition_binding(profile, device)', broker)
        self.assertIn('reservation_plan(kind, memory)', broker)
        self.assertIn('self.acquisition_bindings.insert', ''.join(broker.split()))
        self.assertNotIn('r.capacity', broker)

    def test_live_initialization_never_resets_on_broker_restart(self):
        broker = (ROOT/'native/image/overlay/etc/systemd/system/luma-broker.service').read_text()
        self.assertIn('luma-resource-live.service', broker)
        self.assertIn('/sys/fs/cgroup/lumaacquisition.slice', broker)
        live = (ROOT/'native/image/overlay/etc/systemd/system/luma-resource-live.service').read_text()
        for setting in ('ConditionKernelCommandLine=luma.mode=live', 'Type=oneshot',
                        'RemainAfterExit=yes', 'resource-live-initialize'):
            self.assertIn(setting, live)
        manager = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        init = manager.split('pub(crate) fn initialize_live(')[1].split('fn migration_store(')[0]
        self.assertIn('0x01021994', init)
        self.assertIn('resources::initialize', init)
        self.assertNotIn('remove_file', init)
        source = (ROOT/'rust/luma-platform/src/service.rs').read_text()
        self.assertNotIn('resources::initialize', source)

    def test_transport_workers_cannot_mutate_resource_authority_and_startup_failure_fences(self):
        ingress = (ROOT/'rust/luma-platform/src/service/ingress.rs').read_text()
        for operation in ('Store::open', 'Manager::open', 'group.kill()', 'handle_request('):
            self.assertNotIn(operation, ingress)
        self.assertIn('sync_channel(MAX_READERS)', ingress)
        self.assertIn('broker peer transport quota exhausted', ingress)
        service = (ROOT/'rust/luma-platform/src/service.rs').read_text()
        self.assertIn('resource_manager::fence_unavailable()', service)
        self.assertIn('ingress.receive()', service)
        self.assertIn('legacy effect coordinator busy', service)

    def test_whole_disk_throttle_identity_is_resolved_without_device_access_or_fallback(self):
        storage = (ROOT/'rust/luma-platform/src/storage_io.rs').read_text()
        for boundary in ('/sys/dev/block', '/sys/devices', '0x62656572', 'CRYPT-',
                         'cyclic block storage topology', 'block topology exceeds supported bound'):
            self.assertIn(boundary, storage)
        self.assertNotIn('Command::new', storage)
        self.assertNotIn('libc::ioctl', storage)
        manager = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        self.assertIn('crate::storage_io::device_for_path', manager)

    def test_cpu_runtime_caches_copies_and_batching_have_explicit_closed_policies(self):
        source = (ROOT/'rust/luma-platform/src/model.rs').read_text()
        serve = source.split('pub fn serve()')[1].split('#[cfg(test)]')[0]
        for option in ('--no-kv-offload', '--no-op-offload', '--no-cache-prompt',
                       '--no-cache-idle-slots', '--no-repack', '--no-cont-batching',
                       '--no-kv-unified', '--no-mmproj'):
            self.assertIn('"'+option+'"', serve)
        flat = ''.join(serve.split())
        for option, value in (('--cache-type-k','f16'), ('--cache-type-v','f16'),
                              ('--cache-ram','0'), ('--ctx-checkpoints','0'),
                              ('--batch-size','256'), ('--ubatch-size','128'),
                              ('--threads-http','2'), ('--fit','off'),
                              ('--load-mode','mmap'), ('--lazy-mode','off'),
                              ('--parallel','1'), ('--device','none')):
            self.assertIn('"'+option+'","'+value+'"', flat)

    def test_root_verification_has_no_unleased_production_fallback(self):
        source = (ROOT/'rust/luma-platform/src/model.rs').read_text()
        verify = source.split('fn verify_file(')[1].split('fn runtime_lock(')[0]
        self.assertIn('crate::acquisition::verify_path(at, p)', verify)
        self.assertIn('#[cfg(test)]\n    if let Some(verifier)', verify)
        self.assertIn('#[cfg(test)]\nfn verified_file(', source)
        acquisition = (ROOT/'rust/luma-platform/src/acquisition.rs').read_text()
        routing = acquisition.split('pub(crate) fn verify_path(')[1].split('pub(crate) fn run(')[0]
        self.assertIn('run(&verification_target(at, &profile.id)?, profile, "verify")', routing)

    def test_verified_layout_precedes_publication_and_execution_under_live_lease(self):
        source = (ROOT/'rust/luma-platform/src/model.rs').read_text()
        verify = source.split('fn verified_runtime_file(')[1].split('fn verify_file(')[0]
        self.assertLess(verify.index('verified_file_checked('), verify.index('layout::verify('))
        self.assertIn('file.metadata()', verify)
        self.assertIn('SeekFrom::Start(0)', verify)
        fetch = source.split('fn fetch(')[1].split('fn operation_lock(')[0]
        self.assertLess(fetch.index('verified_runtime_file('), fetch.index('fs::rename('))
        serve = source.split('pub fn serve()')[1].split('#[cfg(test)]')[0]
        self.assertLess(serve.index('verified_runtime_file('), serve.index('supervision::run('))
        layout = (ROOT/'rust/luma-platform/src/model/layout.rs').read_text()
        for boundary in ('MAX_METADATA', 'MAX_KEYS', 'MAX_ARRAY', 'MAX_STRING',
                         '(self.check)()', 'duplicate GGUF', 'checked_mul', 'checked_sub'):
            self.assertIn(boundary, layout)
        self.assertNotIn('Command::new', layout)
        self.assertNotIn('Store::open', layout)

    def test_socket_uses_service_user_acl_without_world_or_shared_database_group(self):
        service = (ROOT/'rust/luma-platform/src/service.rs').read_text()
        self.assertIn('restrict_socket(Path::new(SOCKET))?', service)
        self.assertIn('system.posix_acl_access', service)
        self.assertNotIn('from_mode(0o666)', service)
        self.assertIn('no permissive fallback', service)
        unit = (ROOT/'native/image/overlay/etc/systemd/system/luma-model.service').read_text()
        self.assertNotIn('SupplementaryGroups=luma-control', unit)

    def test_absent_runtime_exclusion_recovery_requires_loaded_masks_and_complete_census(self):
        recovery = (ROOT/'rust/luma-platform/src/resource_manager/recovery.rs').read_text()
        production = recovery.split('#[cfg(test)]')[0]
        for boundary in ('manager_masks()?', 'no_model_tasks(&trusted_proc()?)?',
                         'visible_proc_mount', 'systemd PID namespace', 'MAX_TASKS',
                         'model::resource_recovery_exclusion()', 'Store::open',
                         'State::Released', 'observation()?.review()? != reviewed'):
            self.assertIn(boundary, production)
        for operation in ('resources::initialize(', '.transact(', '.revoke(',
                          'remove_file(', '"unmask"', '"restart"'):
            self.assertNotIn(operation, production)
        self.assertIn('"resources_released":false', ''.join(production.split()))
        main = (ROOT/'rust/luma-platform/src/main.rs').read_text()
        self.assertIn('Some("resource-runtime-lock-status")', main)
        self.assertIn('Some("resource-runtime-lock-recover")', main)


if __name__ == '__main__':
    unittest.main()
