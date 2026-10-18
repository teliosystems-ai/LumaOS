"""Source-level guards only; offline compilation is not kernel qualification."""
from pathlib import Path
import re
import unittest


PROFILE = (
    Path(__file__).resolve().parents[2]
    / "native/image/overlay/etc/apparmor.d/luma-content-backup"
)


class ContentBackupConfinementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rules = "\n".join(
            line.strip()
            for line in PROFILE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )

    def test_no_coarse_unix_or_unrestricted_peer_allow(self) -> None:
        self.assertNotRegex(self.rules, r"(?m)^network\s+unix(?:\s|,)")
        self.assertNotRegex(self.rules, r"(?m)^unix\s*,")
        for line in self.rules.splitlines():
            if line.startswith("unix ") and "peer=" in line:
                self.assertIn("type=stream addr=none", line)
                self.assertRegex(
                    line,
                    r"peer=\((?:addr=none, label=luma-content-backup|label=luma-broker|label=luma-content-custody)\),$",
                )

    def test_only_fixed_broker_custody_and_anonymous_helper_are_explicitly_admitted(self) -> None:
        for required in (
            "unix (create) type=stream,",
            "unix (getattr, getopt, setopt, shutdown) type=stream addr=none,",
            "unix (send, receive) type=stream addr=none peer=(addr=none, label=luma-content-backup),",
            "unix (connect, send, receive) type=stream addr=none peer=(label=luma-broker),",
            "/run/luma-broker/control.sock rw,",
            "unix (connect, send, receive) type=stream addr=none peer=(label=luma-content-custody),",
            "/run/luma-content-custody/control.sock rw,",
        ):
            self.assertIn(required, self.rules)
        writable_run_paths = re.findall(r"(?m)^(/\S*run/\S+)\s+rw,", self.rules)
        self.assertEqual(writable_run_paths, ["/run/luma-broker/control.sock", "/run/luma-content-custody/control.sock"])

    def test_abstract_denials_override_inherited_base_rules_and_cover_slashes(self) -> None:
        self.assertIn("deny unix (bind, listen, accept) addr=@**,", self.rules)
        self.assertIn("deny unix (connect, send, receive) peer=(addr=@**),", self.rules)
        self.assertNotIn("addr=@*,", self.rules)
        self.assertNotIn("addr=@*),", self.rules)

    def test_unused_base_logging_and_uuid_endpoints_are_explicitly_denied(self) -> None:
        for required in (
            "deny /dev/log rw,",
            "deny /{,var/}run/uuidd/request rw,",
            "deny /{,var/}run/systemd/journal/{dev-log,socket,stdout} rw,",
            "deny network inet,",
            "deny network inet6,",
        ):
            self.assertIn(required, self.rules)

    def test_real_kernel_feature_gate_precedes_private_repository_access(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source = (root / "rust/luma-platform/src/content_backup.rs").read_text(encoding="utf-8")
        gate = (root / "rust/luma-platform/src/backup_confinement.rs").read_text(encoding="utf-8")
        worker = source[source.index("fn worker(id: &str)"):]
        self.assertLess(worker.index("confinement::KernelUnix::capture()?"), worker.index("Repository::open_at"))
        self.assertIn("self.confinement.check()?", source)
        for required in ("0x7363_6673", "libc::O_NOFOLLOW", "libc::fstatfs", "b\"yes\\n\"", "\"af_unix\""):
            self.assertIn(required, gate)
        self.assertIn("/sys/kernel/security/apparmor/features/network/af_unix r,", self.rules)
        self.assertNotIn("/sys/kernel/security/**", self.rules)

    def test_restore_credential_exec_intermediaries_override_inherited_ptrace(self) -> None:
        profiles = PROFILE.parent
        for name in ('luma-granted-client', 'luma-content-restore', 'luma-admin',
                     'luma-content-custody', 'luma-content-backup',
                     'luma-receipt-signer', 'luma-utc-windows', 'luma-utc-windows-crypto'):
            with self.subTest(profile=name):
                rules = (profiles / name).read_text(encoding='utf-8')
                self.assertIn('#include <abstractions/base>', rules)
                self.assertIn('deny ptrace (trace, tracedby),', rules)
                self.assertIn(f'deny ptrace (readby) peer={name},', rules)
                self.assertIn('deny ptrace (readby) peer=unconfined,', rules)
                if name not in ('luma-admin', 'luma-receipt-signer', 'luma-utc-windows-crypto'):
                    self.assertIn('ptrace (readby) peer=luma-broker,', rules)
                self.assertNotRegex(rules, r'(?m)^\s*deny ptrace\s*,')
        self.assertIn('/usr/bin/systemd-run ix,', (profiles / 'luma-granted-client').read_text())
        self.assertIn('/usr/libexec/luma-os/luma-backup-crypto mrix,',
                      (profiles / 'luma-content-restore').read_text())


if __name__ == "__main__":
    unittest.main()
