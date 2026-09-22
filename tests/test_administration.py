from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.administration import (  # noqa: E402
    ADMIN_ROLE,
    AdminAuthority,
    AdministrationConflict,
    AdministrationDenied,
    AdministrationValidationError,
)
from luma_os.policy import CapabilityGrant, PolicyBroker, PolicyDenied  # noqa: E402


class AdministrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 22, 15, tzinfo=UTC)
        identifiers = iter(f"id-{number}" for number in range(1, 50))
        self.authority = AdminAuthority(
            "primary-admin",
            activities=(
                "policy.grant.install",
                "policy.grant.revoke",
                "model-pack.sign",
                "evidence.sign",
            ),
            clock=lambda: self.now,
            id_factory=lambda: next(identifiers),
        )

    def test_admin_governs_finite_activities_and_delegates_roles(self) -> None:
        self.assertTrue(self.authority.has_activity("primary-admin", "model-pack.sign"))
        role = self.authority.define_role(
            "primary-admin",
            "ReleaseSigner",
            ("model-pack.sign", "evidence.sign"),
        )
        assignment = self.authority.assign_role(
            "primary-admin",
            "release-user",
            role.name,
            expires_at=self.now + timedelta(hours=1),
        )
        self.assertTrue(self.authority.has_activity("release-user", "model-pack.sign"))
        self.assertFalse(self.authority.has_activity("release-user", "policy.grant.install"))
        self.assertEqual("primary-admin", assignment.assigned_by)
        self.assertEqual(2, len(self.authority.receipts))
        self.assertIsNone(self.authority.receipts[0].previous_digest)
        self.assertEqual(
            self.authority.receipts[0].digest,
            self.authority.receipts[1].previous_digest,
        )

    def test_admin_is_not_a_wildcard_or_ordinary_delegable_role(self) -> None:
        self.assertFalse(self.authority.has_activity("primary-admin", "future.undefined"))
        with self.assertRaises(AdministrationValidationError):
            self.authority.register_activity("primary-admin", "*")
        with self.assertRaises(AdministrationValidationError):
            self.authority.define_role("primary-admin", ADMIN_ROLE, ("evidence.sign",))
        with self.assertRaises(AdministrationDenied):
            self.authority.assign_role(
                "primary-admin",
                "model-worker",
                ADMIN_ROLE,
                expires_at=self.now + timedelta(minutes=5),
            )

    def test_only_admin_can_define_assign_and_revoke(self) -> None:
        with self.assertRaises(AdministrationDenied):
            self.authority.define_role("model-worker", "Signer", ("model-pack.sign",))
        role = self.authority.define_role(
            "primary-admin", "PolicyOperator", ("policy.grant.install",)
        )
        assignment = self.authority.assign_role(
            "primary-admin",
            "policy-user",
            role.name,
            expires_at=self.now + timedelta(minutes=10),
        )
        with self.assertRaises(AdministrationDenied):
            self.authority.revoke_assignment(
                "policy-user", assignment.assignment_id, expected_version=1
            )
        revoked = self.authority.revoke_assignment(
            "primary-admin", assignment.assignment_id, expected_version=1
        )
        self.assertEqual(2, revoked.version)
        self.assertFalse(self.authority.has_activity("policy-user", "policy.grant.install"))
        with self.assertRaises(AdministrationConflict):
            self.authority.revoke_assignment(
                "primary-admin", assignment.assignment_id, expected_version=1
            )

    def test_expired_assignments_fail_closed(self) -> None:
        self.authority.define_role("primary-admin", "Signer", ("model-pack.sign",))
        self.authority.assign_role(
            "primary-admin",
            "short-lived",
            "Signer",
            expires_at=self.now + timedelta(seconds=1),
        )
        self.assertTrue(self.authority.has_activity("short-lived", "model-pack.sign"))
        self.assertFalse(
            self.authority.has_activity(
                "short-lived", "model-pack.sign", at=self.now + timedelta(seconds=1)
            )
        )

    def test_policy_grant_mutation_uses_admin_delegation(self) -> None:
        self.authority.define_role(
            "primary-admin",
            "PolicyOperator",
            ("policy.grant.install", "policy.grant.revoke"),
        )
        self.authority.assign_role(
            "primary-admin",
            "policy-user",
            "PolicyOperator",
            expires_at=self.now + timedelta(hours=1),
        )
        broker = PolicyBroker(
            clock=lambda: self.now,
            id_factory=lambda: "decision-admin",
            grant_mutation_authorizer=self.authority.require_activity,
        )
        grant = CapabilityGrant(
            grant_id="grant-admin-1",
            subject="alice",
            capability="folder.read",
            resource_kind="folder-grant",
            resource_id="source-1",
            operations=("read",),
            issued_at=self.now,
            expires_at=self.now + timedelta(hours=1),
        )
        with self.assertRaises(PolicyDenied):
            broker.install(grant, actor="model-worker")
        broker.install(grant, actor="policy-user")
        broker.revoke("grant-admin-1", expected_version=1, actor="policy-user")
        with self.assertRaises(PolicyDenied):
            broker.install(grant)


if __name__ == "__main__":
    unittest.main()
