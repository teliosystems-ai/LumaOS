"""Pinned hook/asset regressions, not live NTS or installed-clock qualification."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / 'native/image/utc'
spec = importlib.util.spec_from_file_location('prepare_chrony', ASSETS / 'prepare_chrony.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PublisherAssets(unittest.TestCase):
    def test_exact_patch_anchor_required(self):
        self.assertEqual(prepare.once('abc', 'b', 'd'), 'adc')
        for text in ('ac', 'abbc'):
            with self.assertRaises(ValueError):
                prepare.once(text, 'b', 'd')

    def test_destination_refuses_existing_and_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            source.mkdir()
            with self.assertRaisesRegex(ValueError, 'must be new'):
                prepare.prepare(source, source)
            with self.assertRaisesRegex(ValueError, 'overlap'):
                prepare.prepare(source, source / 'nested')

    def test_gpl_linked_sources_and_non_authorizing_flags(self):
        for name in ('publisher.c', 'publisher.h', 'chrony_hook.c', 'chrony_hook.h', 'test_publisher.c'):
            self.assertIn('SPDX-License-Identifier: GPL-2.0-only', (ASSETS / name).read_text())
        governance = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text()
        self.assertRegex(governance, r'"trusted_utc_available"\s*:\s*false')
        self.assertRegex(governance, r'"gate_closing"\s*:\s*false')

    def test_no_image_activation_or_report_scraper(self):
        root = (ROOT / 'native/image/Dockerfile.root').read_text()
        self.assertIn('systemd-timesyncd', root)
        self.assertNotIn('chrony_hook', root)
        hook = (ASSETS / 'chrony_hook.c').read_text()
        self.assertIn('/run/luma-utc/measurements.sock', hook)
        self.assertNotIn('popen(', hook)
        self.assertNotIn('system(', hook)
        self.assertIn('MSG_DONTWAIT', hook)

    def test_unknown_source_duplicate_alias_and_relaxed_tls_disable(self):
        hook = (ASSETS / 'chrony_hook.c').read_text()
        self.assertIn('i == 3 || !strict_nts || owners[i]', hook)
        self.assertIn('fence(); publisher.disabled = 1;', hook)
        script = (ASSETS / 'prepare_chrony.py').read_text()
        self.assertIn('params->offset == 0.0', script)
        self.assertIn('params->cert_set == 0', script)
        self.assertIn('CNF_GetNoCertTimeCheck() == 0', script)

    def test_receiver_is_not_a_product_listener_or_serialized_authority(self):
        receiver = (ROOT / 'rust/luma-platform/src/utc_receiver.rs').read_text()
        production = receiver.rsplit('\n#[cfg(test)]\nmod tests {', 1)[0]
        self.assertNotIn('UnixDatagram::bind', production)
        self.assertNotIn('Deserialize', production)
        self.assertNotIn('Serialize', production)
        self.assertNotIn('estimate:', production)
        main = (ROOT / 'rust/luma-platform/src/main.rs').read_text()
        self.assertNotIn('Some("utc-receiver")', main)

    def test_receiver_uses_per_message_credentials_and_closes_delivered_descriptors(self):
        receiver = (ROOT / 'rust/luma-platform/src/utc_receiver.rs').read_text().rsplit('\n#[cfg(test)]\nmod tests {', 1)[0]
        for boundary in ('SO_PASSCRED', 'SCM_CREDENTIALS', 'SYS_pidfd_open',
                         'MSG_CMSG_CLOEXEC', 'SCM_RIGHTS', 'libc::close(fd)', 'MSG_CTRUNC'):
            self.assertIn(boundary, receiver)
        self.assertNotIn('SO_PEERCRED', receiver)

    def test_json_transport_has_no_binary_runtime_fallback(self):
        protocol = (ROOT / 'rust/luma-platform/src/utc_protocol.rs').read_text()
        receiver = (ROOT / 'rust/luma-platform/src/utc_receiver.rs').read_text().rsplit('\n#[cfg(test)]\nmod tests {', 1)[0]
        self.assertIn('utc_protocol::decode_envelope(', receiver)
        self.assertNotIn('utc_protocol::decode(', receiver)
        self.assertIn('credentials.pid', receiver)
        self.assertIn('credentials.uid', receiver)
        self.assertEqual(protocol.count('#[serde(deny_unknown_fields)]'), 4)
        for check in ('MAX_ENVELOPE_SIZE: usize = 2048', 'u32::from_be_bytes(',
                      'envelope.caller.pid != kernel_pid', 'envelope.caller.uid != kernel_uid',
                      'm.captured_boottime_ms.checked_add(999)', 'envelope.deadline_clock != "boottime"'):
            self.assertIn(check, protocol)
        hook = (ASSETS / 'chrony_hook.c').read_text()
        self.assertIn('LU_Envelope(', hook)
        self.assertIn('(uint32_t)getpid()', hook)
        self.assertIn('(uint32_t)getuid()', hook)
        self.assertIn('sendto(sock, frame, length,', hook)
        self.assertNotIn('LU_Frame(', hook)

    def test_utc_history_shares_admin_checkpoint_without_new_writer_endpoint(self):
        history = (ROOT / 'rust/luma-platform/src/utc_history.rs').read_text()
        governance = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text().split('\n#[cfg(test)]\nfn execute_catalog', 1)[0]
        self.assertIn('entry.activity == utc_history::ACTIVITY', governance)
        self.assertIn('snapshot.prefix_heads.get(position)', governance)
        self.assertIn('history.apply(&record)?', governance)
        self.assertIn('store.append(entry.clone()', governance)
        self.assertIn('fn execute_history<', governance)
        self.assertNotIn('pub fn execute_history', governance)
        self.assertNotIn('pub(crate) fn execute_history', governance)
        self.assertNotIn('LocalAnchor', history)
        self.assertNotIn('advance(', history)
        main = (ROOT / 'rust/luma-platform/src/main.rs').read_text()
        self.assertNotIn('Some("admin-utc-history', main)
        service = (ROOT / 'rust/luma-platform/src/admin_service.rs').read_text()
        self.assertNotIn('execute_history', service)

    def test_utc_history_records_do_not_restore_live_estimates(self):
        history = (ROOT / 'rust/luma-platform/src/utc_history.rs').read_text()
        governance = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text().split('\n#[cfg(test)]\nfn execute_catalog', 1)[0]
        self.assertIn('record.statement.floor_ms <= self.floor_ms', history)
        self.assertRegex(history, r'self\s*\.version\s*\.checked_add\(1\)')
        self.assertIn('self.floor_ms > lower', history)
        self.assertGreaterEqual(governance.count('statement.supported_by(&observe()?)?'), 3)
        self.assertIn('context.recheck(&mut authenticate)', governance)
        for forbidden in ('clock_settime(', 'nocerttimecheck', 'pub fn seed', 'reacquire('):
            self.assertNotIn(forbidden, history)

    def test_receiver_preserves_all_rounds_for_keeper_lifecycle(self):
        receiver = (ROOT / 'rust/luma-platform/src/utc_receiver.rs').read_text().rsplit('\n#[cfg(test)]\nmod tests {', 1)[0]
        self.assertIn('Result<Vec<ProducerRound>>', receiver)
        self.assertIn('rounds.push(round)', receiver)
        self.assertNotIn('Result<Option<ProducerRound>>', receiver)
        stream = (ROOT / 'rust/luma-platform/src/utc_stream.rs').read_text().split('#[cfg(test)]')[0]
        self.assertIn('for producer in rounds', stream)
        self.assertIn('self.receiver.recheck_quiet()?', stream)
        self.assertIn('self.keeper.candidate_at(now)', stream)

    def test_stream_does_not_enable_authority_or_automatic_recovery(self):
        stream = (ROOT / 'rust/luma-platform/src/utc_stream.rs').read_text().split('#[cfg(test)]')[0]
        for forbidden in ('Serialize', 'Deserialize', 'UnixDatagram::bind',
                          'pub(crate) fn reacquire', 'pub(crate) fn assign'):
            self.assertNotIn(forbidden, stream)
        self.assertIn('history_floor_ms', stream)
        self.assertRegex(stream, r'now\s*\.boottime_ms\s*\.checked_sub\(capture\)')
        self.assertNotIn('Some("utc-stream")', (ROOT / 'rust/luma-platform/src/main.rs').read_text())

    def test_step_watch_is_owned_read_only_nonblocking_and_fail_closed(self):
        watch = (ROOT / 'rust/luma-platform/src/utc_step_watch.rs').read_text().split('#[cfg(test)]')[0]
        for mechanism in ('CLOCK_REALTIME', 'TFD_NONBLOCK', 'TFD_CLOEXEC',
                          'TFD_TIMER_ABSTIME', 'TFD_TIMER_CANCEL_ON_SET', 'ECANCELED',
                          'self.fenced = true', 'libc::read('):
            self.assertIn(mechanism, watch)
        for forbidden in ('clock_settime(', 'settimeofday(', 'adjtimex(',
                          'CLOCK_REALTIME_ALARM', 'Serialize', 'Deserialize'):
            self.assertNotIn(forbidden, watch)
        self.assertEqual(watch.count('libc::timerfd_settime('), 1)

    def test_stream_checks_step_watch_before_and_after_candidate_work(self):
        stream = (ROOT / 'rust/luma-platform/src/utc_stream.rs').read_text()
        poll = stream.split('pub(crate) fn poll(', 1)[1].split('fn candidate_after_history(', 1)[0]
        self.assertEqual(poll.count('self.step_watch.check()?'), 2)
        before, middle, after = poll.split('self.step_watch.check()?')
        self.assertNotIn('self.receiver.poll()', before)
        self.assertIn('self.receiver.poll()', middle)
        self.assertIn('.candidate_at(', middle)
        self.assertIn('Ok(candidate)', after)
        self.assertIn('self.invalidate()', after)

    def test_bound_stream_requires_semantic_history_and_reprojects_after_blocking_reads(self):
        stream = (ROOT / 'rust/luma-platform/src/utc_stream.rs').read_text()
        bound = stream.split('impl BoundStream {', 1)[1].split('#[cfg(test)]', 1)[0]
        self.assertIn("reader: &mut HistoryReader<'_, A>", bound)
        self.assertIn('history = reader.read()?', bound)
        self.assertEqual(bound.count('self.history.recheck(reader)?'), 2)
        poll = bound.split('pub(crate) fn poll<', 1)[1]
        self.assertLess(poll.index('self.stream.poll()?'), poll.rindex('self.history.recheck(reader)?'))
        self.assertLess(poll.rindex('self.history.recheck(reader)?'), poll.index('self.stream.candidate_after_history()'))
        self.assertIn('self.invalidate()', poll)
        self.assertNotIn('history_floor_ms: i64', bound)
        numeric = stream.split('pub(crate) fn attach(', 1)[0]
        self.assertTrue(numeric.rstrip().endswith('#[cfg(test)]'))

    def test_history_binding_is_not_a_wire_token_or_separate_tpm_owner(self):
        governance = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text()
        reader = governance.split('pub(crate) struct HistoryBinding', 1)[1].split('// Deliberately private', 1)[0]
        self.assertIn("store: &'a mut Store<A>", reader)
        self.assertIn('context.bootstrap_state(&snapshot)?', reader)
        self.assertIn('context.history(&snapshot, None)?', reader)
        self.assertIn('self.fenced = true', reader)
        self.assertIn('last_clock.elapsed_since(first_clock)?', reader)
        self.assertEqual(reader.count('self.replay()?'), 2)
        for forbidden in ('Serialize', 'Deserialize', 'advance(', 'LocalAnchor', 'eligible', 'reacquire('):
            self.assertNotIn(forbidden, reader)

    @unittest.skipUnless(os.environ.get('LUMA_CHRONY_UPSTREAM'), 'needs isolated pinned source fixture')
    def test_pinned_hook_follows_actual_authentication_guard(self):
        source = Path(os.environ['LUMA_CHRONY_UPSTREAM'])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'patched'
            prepare.prepare(source, output)
            core = (output / 'ntp_core.c').read_text()
            self.assertEqual(core.count('LUH_Good('), 1)
            self.assertIn('if (valid_packet) {\n    LUH_Leap(inst->luma_operator, pkt_leap == LEAP_Normal);', core)
            self.assertIn('if (good_packet) {\n      LUH_Good(inst->luma_operator, &sample, pkt_leap == LEAP_Normal);', core)
            self.assertLess(core.index('test5 = saved || NAU_CheckResponseAuth'), core.index('LUH_Good('))
            self.assertIn('valid_packet = test1 && test2 && test3 && test5;', core)
            self.assertIn('synced_packet = valid_packet && test6 && test7;', core)
            self.assertLess(core.index('LUH_Good('), core.index('process_sample(inst, &sample)'))
            auth = (output / 'ntp_auth.c').read_text()
            self.assertIn('info->auth.mode != instance->mode', auth)
            self.assertIn('NNC_CheckResponseAuth(instance->nts, response, info)', auth)

    @unittest.skipUnless(os.environ.get('LUMA_CHRONY_UPSTREAM'), 'needs isolated pinned source fixture')
    def test_modified_upstream_pin_refuses_preparation(self):
        source = Path(os.environ['LUMA_CHRONY_UPSTREAM'])
        with tempfile.TemporaryDirectory() as directory:
            altered = Path(directory) / 'altered'
            altered.mkdir()
            (altered / 'ntp_core.c').write_bytes((source / 'ntp_core.c').read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'pin mismatch'):
                prepare.prepare(altered, Path(directory) / 'patched')
            self.assertFalse((Path(directory) / 'patched').exists())
