"""Backup export source/confinement integration checks, not native qualification.

Executable Rust/C tests exercise the protocol and ciphertext. These checks keep
the separately owned launcher, broker, worker and image policies joined; they
do not claim PAM/TPM/AppArmor enforcement on an unbooted host.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "rust/luma-platform/src"
POLICY = ROOT / "native/image/overlay/etc/apparmor.d"


class ContentBackupIntegration(unittest.TestCase):
    def test_production_export_requires_real_custody_not_a_lab_flag_upgrade(self):
        source = (RUST / "main.rs").read_text()
        backup = (RUST / "content_backup.rs").read_text()
        self.assertIn("mod backup_crypto;", source)
        self.assertIn("mod content_backup;", source)
        self.assertIn('content_backup::prepare_stdin()', source)
        self.assertIn('content_backup::command(&args)', source)
        self.assertIn('production_image()?', backup)
        self.assertIn('require_production_activation()?', backup)
        self.assertIn('production export refuses manually selected laboratory recipients', backup)
        self.assertIn('governed-content-custody-v1-', backup)
        self.assertIn('custody::backup_cut', backup)
        self.assertIn('repository.require_state', backup)
        self.assertIn('custody::backup_receipt', backup)
        self.assertIn('custody_receipt.is_some()', backup)
        self.assertIn('require_installed()?', backup)
        for forbidden in ('content-backup-restore', 'content-backup-decrypt'):
            self.assertNotIn('"' + forbidden + '"', source)
        for flag in ('production_qualified', 'restore_permitted'):
            self.assertRegex(backup, re.escape(flag) + r'\s*:\s*false\b')

    def test_current_custody_measures_ciphertext_before_anchoring_and_signing(self):
        custody = (RUST / 'content_custody/backup.rs').read_text()
        protocol = (RUST / 'content_custody/protocol.rs').read_text()
        backup = (RUST / 'content_backup.rs').read_text()
        self.assertIn('read_live(&mut transfer', protocol)
        self.assertIn('digest.update(&block[..count])', protocol)
        self.assertIn('received ciphertext differs from measured receipt commitment', protocol)
        self.assertIn('backup custody transfer has uncommitted trailing bytes', protocol)
        self.assertIn('store.commit(Event::Backup(body.clone()), check)?', custody)
        self.assertLess(custody.index('store.commit(Event::Backup(body.clone()), check)?'),
                        custody.index('super::signer::sign_receipt'))
        self.assertIn('original.operation_id', custody)
        self.assertIn('!recipients.request.active', custody)
        self.assertIn('body.source_state != current', custody)
        self.assertIn('origin_spki_sha256', custody)
        self.assertIn('MAX_EXPORT_BYTES', backup)
        self.assertIn('captured.at', backup)
        self.assertIn('governed', backup.lower())

    def test_portable_public_verification_requires_independent_origin_not_live_authority(self):
        main = (RUST / 'main.rs').read_text()
        capsule = (RUST / 'content_capsule.rs').read_text()
        receipt = (RUST / 'content_custody/backup.rs').read_text()
        self.assertIn('content-backup-receipt-verify', main)
        self.assertIn('content-backup-capsule-verify', main)
        verification = re.search(r'receipt\.verify_origin\(expected_origin,\s*check\)\?', capsule)
        self.assertIsNotNone(verification)
        self.assertLess(verification.start(), capsule.index('ciphertext.try_reserve_exact(length)?'))
        self.assertIn('capsule ciphertext differs from independently authenticated commitment', capsule)
        self.assertIn('capsule has trailing uncommitted data', capsule)
        self.assertIn('self.body.origin_spki_sha256 != expected_origin', receipt)
        self.assertIn('"outer_delivery_lease_authenticated":false', capsule)
        self.assertIn('"current_custody_qualified":false', capsule)
        self.assertIn('"restore_permitted":false', capsule)

    def test_receipt_helper_stacks_confinement_under_no_new_privileges(self):
        custody = (POLICY / 'luma-content-custody').read_text()
        signer = (POLICY / 'luma-receipt-signer').read_text()
        unit = (ROOT / 'native/image/overlay/etc/systemd/system/luma-content-custody.service').read_text()
        self.assertIn('NoNewPrivileges=yes', unit)
        self.assertIn('rpx -> &luma-receipt-signer,', custody)
        self.assertNotIn('rpx -> luma-receipt-signer,', custody)
        self.assertIn('label="luma-content-custody//&luma-receipt-signer"', custody)
        self.assertIn('peer="luma-content-custody//&luma-receipt-signer"', custody)
        self.assertIn('deny /var/**', signer)
        self.assertIn('deny /dev/{tpm*', signer)

    def test_original_export_purpose_pair_survives_every_broker_checkpoint(self):
        backup = (RUST / "content_backup.rs").read_text()
        admin = (RUST / "admin_governance.rs").read_text()
        acquisition = (RUST / "service/granted_acquisition.rs").read_text()
        gateway = (RUST / "service/granted_gateway.rs").read_text()
        self.assertIn('with_backup_export_grants', admin)
        self.assertIn('crate::content_backup::export_pair', admin)
        self.assertIn('SessionPurpose::Export', acquisition)
        self.assertIn('Some(pending)', acquisition)
        self.assertIn('boundary.stream_check(pending)', acquisition)
        self.assertIn('native-content-backup-export-v1', gateway)
        self.assertIn('BrokerPurpose::Export', gateway)
        self.assertIn('args.len() != 9', backup)
        self.assertIn('args[6] != "--export-channel"', backup)
        self.assertIn('account.generation != input.binding.owner_generation', backup)
        self.assertIn('account.uid != guard.subject_uid()?', backup)
        self.assertIn('self.lease.check()', backup)

    def test_private_snapshots_and_memfds_are_permitted_without_private_store_access(self):
        client = (POLICY / "luma-granted-client").read_text()
        broker = (POLICY / "luma-broker").read_text()
        worker = (POLICY / "luma-content-backup").read_text()
        backup = (RUST / "content_backup.rs").read_text()
        gateway = (RUST / "service/granted_gateway.rs").read_text()
        for policy in (client, broker):
            self.assertIn('/run/luma-granted-client/requests/*/content-backup.json r,', policy)
        for name in ('luma-content-backup-request', 'luma-content-backup-output'):
            self.assertIn('memory_file("' + name + '"', backup)
        self.assertIn('/memfd:luma-content-backup-{request,output}', client)
        self.assertIn('/memfd:luma-content-backup-request r,', worker)
        self.assertIn('/memfd:luma-content-backup-output rw,', worker)
        self.assertIn('deny /var/lib/luma-os/content-store/** rwklx,', client)
        self.assertIn('InputStage::capture(&bytes, "content-backup.json")', gateway)
        self.assertIn('crate::content_backup::MAX_REQUEST', gateway)

    def test_crypto_worker_budget_is_separate_and_has_no_caller_executable(self):
        backup = (RUST / "content_backup.rs").read_text()
        acquisition = (RUST / "acquisition.rs").read_text()
        resources = (RUST / "resource_manager.rs").read_text()
        crypto = (RUST / "backup_crypto.rs").read_text()
        self.assertIn('(256 + 704) * 1024 * 1024', backup)
        self.assertIn('640 * 1024 * 1024', backup)
        self.assertIn('pub(crate) const TASKS: u64 = 4', backup)
        self.assertIn('"backup-export"', acquisition)
        self.assertIn('content-backup-resource-worker', acquisition)
        self.assertIn('requires_original_authority', resources)
        self.assertIn('Self::Backup', resources)
        self.assertIn('/usr/libexec/luma-os/luma-backup-crypto', crypto)
        self.assertIn('crypto::encrypt_backup_data', backup)
        self.assertIn('repository.backup_data', backup)

    def test_ciphertext_only_delivery_is_bounded_cancellable_and_receipted(self):
        backup = (RUST / "content_backup.rs").read_text()
        gateway = (RUST / "service/granted_gateway.rs").read_text()
        self.assertIn('required_export_writer()?', backup)
        self.assertIn('write_checked', backup)
        self.assertIn('finish_checked', backup)
        self.assertIn('verify_receipt(&captured.metadata)', backup)
        self.assertIn('metadata.encryption.cms_sha256', backup)
        self.assertIn('supervise_owned_controller', backup)
        self.assertNotIn('Command::new("/usr/bin/systemctl")', backup)
        self.assertIn('set_nonblocking(true)', gateway)
        self.assertIn('backup relay acknowledgement deadline expired', gateway)
        self.assertIn('backup export requires its original acknowledged payload relay', gateway)


if __name__ == "__main__":
    unittest.main()
