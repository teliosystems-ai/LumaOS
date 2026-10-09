"""Password composition checks; not physical TPM or installed qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class AccountPasswordPolicyTests(unittest.TestCase):
    def test_secret_entry_is_hidden_local_and_not_a_command_argument(self):
        secret = (ROOT / 'rust/luma-platform/src/account_password.rs').read_text()
        for marker in ('/dev/tty', 'hidden_from(', 'PrivateBuffer', 'password_length(',
                       'luma_password_hash(', 'luma_password_verify(', 'no fallback'):
            self.assertIn(marker, secret)
        for forbidden in ('Serialize', 'derive(Debug', 'derive(Clone', 'println!',
                          'std::env::', 'Command::new', 'String::from_utf8'):
            self.assertNotIn(forbidden, secret.split('#[cfg(test)]\nmod tests')[0])
        governance = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text()
        entry = governance.split('pub fn account_password_command(')[1].split('pub fn account_lock_command(')[0]
        self.assertLess(entry.index('Password::local_confirmed('), entry.index('prepare_control('))
        self.assertLess(entry.index('prepare_control('), entry.index('authentication::local('))
        for marker in ('crate::require_root()?', 'platform::require_installed()?',
                       'Path::new(crate::principal::REGISTRY)', 'Path::new(crate::principal::IDENTITY)',
                       'prepared.issue(', 'password_proposal(', 'CatalogAttempt::prepare('):
            self.assertIn(marker, entry)
        for forbidden in ('args[6]', 'std::env::', 'fs::write', 'Command::new'):
            self.assertNotIn(forbidden, entry)

    def test_proposal_uses_owned_governed_projection_before_private_staging(self):
        source = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text()
        proposal = source.split('fn password_proposal<')[1].split('pub fn account_password_command(')[0]
        for marker in ('session.observe_store(', 'PrincipalReader::admin_at(',
                       'context.writer(&catalog)', 'Guard::retained_password(',
                       'projected.apply(&command)?', 'stage_password_proposal(||',
                       'current.head != snapshot.head', 'registry.current()?'):
            self.assertIn(marker, proposal)
        self.assertLess(proposal.index('projected.apply(&command)?'), proposal.index('stage_password_proposal('))
        boundary = source.split('fn account_boundary(')[1].split('struct RecoveryAttempt')[0]
        self.assertIn('Kind::Password', boundary)
        self.assertIn('Guard::retained_password(', boundary)

    def test_atomic_proposal_and_distribution_crypto_fail_closed(self):
        transition = (ROOT / 'rust/luma-platform/src/account_transition.rs').read_text()
        stage = transition.split('pub(crate) fn stage_password_proposal(')[1].split('pub(crate) fn stage(')[0]
        for marker in ('libc::SYS_renameat2', 'libc::RENAME_NOREPLACE', 'authorize()?',
                       'self.recheck()?', 'self.directory.sync_all()?', 'retained >= 128'):
            self.assertIn(marker, stage)
        adapter = (ROOT / 'rust/luma-platform/src/password_crypt.c').read_text()
        for marker in ('#include <crypt.h>', 'crypt_gensalt_rn("$y$", 0',
                       'crypt_r(', 'sizeof(struct crypt_data)', 'volatile unsigned char *wipe'):
            self.assertIn(marker, adapter)
        buffers = (ROOT / 'rust/luma-platform/src/sealed_credential.rs').read_text()
        self.assertIn('fn password_context(', buffers)
        self.assertIn('Self::allocate(capacity, 64 * 1024)', buffers)

    def test_password_change_preserves_aging_lock_and_unrelated_rows(self):
        source = (ROOT / 'rust/luma-platform/src/account_transition.rs').read_text()
        validation = source.split('fn validate_password_change(')[1].split('enum Replacement')[0]
        for marker in ('old_locked != new_locked', 'before[..old_start] != after[..new_start]',
                       'before[old_end..] != after[new_end..]', 'account_password::validate_hash('):
            self.assertIn(marker, validation)
        password = source.split('fn password_shadow(')[1].split('fn validate_password_change(')[0]
        for forbidden in ('SystemTime', 'Utc::now', 'Command::new', 'from_secs'):
            self.assertNotIn(forbidden, password)
        roles = (ROOT / 'rust/luma-platform/src/admin_roles.rs').read_text()
        self.assertIn('password changes cannot implicitly enable a disabled principal', roles)

    def test_image_declares_crypto_build_and_runtime_dependencies(self):
        self.assertIn('libcrypt-dev', (ROOT / 'native/image/Dockerfile.tools').read_text())
        self.assertIn('libcrypt1', (ROOT / 'native/image/Dockerfile.root').read_text())
        build = (ROOT / 'rust/luma-platform/build.rs').read_text()
        self.assertIn('cargo:rustc-link-lib=crypt', build)
        self.assertIn('src/password_crypt.c', build)
        profile = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-admin').read_text()
        self.assertIn('/var/lib/luma-os/identity/.password-proposal-*/{intent.json,shadow.new} rw,', profile)
        self.assertIn('/dev/tty rw,', profile)


if __name__ == '__main__':
    unittest.main()
