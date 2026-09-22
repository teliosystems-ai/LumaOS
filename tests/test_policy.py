from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.policy import (  # noqa: E402
    CapabilityGrant,
    PolicyBroker,
    PolicyConflict,
    PolicyDenied,
    PolicyRequest,
    PolicyValidationError,
    ReasonCode,
)


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 22, 12, tzinfo=UTC)
        self.broker = PolicyBroker(clock=lambda: self.now, id_factory=lambda: "decision-1")
        self.grant = CapabilityGrant(
            grant_id="grant-1",
            subject="alice",
            capability="folder.read",
            resource_kind="folder-grant",
            resource_id="source-1",
            operations=("read", "inspect", "read"),
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(hours=1),
        )
        self.broker.install(self.grant)

    def request(self, **overrides: object) -> PolicyRequest:
        values: dict[str, object] = {
            "subject": "alice",
            "capability": "folder.read",
            "resource_kind": "folder-grant",
            "resource_id": "source-1",
            "operation": "read",
            "expected_grant_id": "grant-1",
            "expected_grant_version": 1,
        }
        values.update(overrides)
        return PolicyRequest(**values)  # type: ignore[arg-type]

    def test_exact_current_grant_allows_and_records_identity(self) -> None:
        decision = self.broker.require(self.request())
        self.assertTrue(decision.allowed)
        self.assertEqual(ReasonCode.ALLOWED, decision.reason_code)
        self.assertEqual("grant-1", decision.grant_id)
        self.assertEqual(1, decision.grant_version)
        self.assertEqual(64, len(decision.policy_digest))
        self.assertIn("revocation", decision.evaluated_constraints)

    def test_missing_substituted_and_wildcard_authority_fail_closed(self) -> None:
        cases = (
            (self.request(subject="bob"), ReasonCode.SUBJECT_MISMATCH),
            (self.request(resource_id="source-2"), ReasonCode.RESOURCE_MISMATCH),
            (self.request(operation="write"), ReasonCode.OPERATION_DENIED),
            (self.request(expected_grant_id="missing"), ReasonCode.NO_MATCHING_GRANT),
        )
        for request, reason in cases:
            with self.subTest(reason=reason):
                decision = self.broker.decide(request)
                self.assertFalse(decision.allowed)
                self.assertEqual(reason, decision.reason_code)
        with self.assertRaises(PolicyValidationError):
            self.request(resource_id="*")

    def test_effect_time_revocation_and_generation_fencing(self) -> None:
        revoked = self.broker.revoke("grant-1", expected_version=1)
        self.assertEqual(2, revoked.version)
        stale = self.broker.decide(self.request())
        self.assertEqual(ReasonCode.STALE_VERSION, stale.reason_code)
        current = self.broker.decide(self.request(expected_grant_version=2))
        self.assertEqual(ReasonCode.REVOKED, current.reason_code)
        with self.assertRaises(PolicyDenied):
            self.broker.require(self.request(expected_grant_version=2))
        with self.assertRaises(PolicyConflict):
            self.broker.revoke("grant-1", expected_version=1)

    def test_expiry_and_not_yet_valid_are_denied(self) -> None:
        self.assertEqual(
            ReasonCode.EXPIRED,
            self.broker.decide(self.request(), at=self.now + timedelta(hours=2)).reason_code,
        )
        self.assertEqual(
            ReasonCode.NOT_YET_VALID,
            self.broker.decide(self.request(), at=self.now - timedelta(hours=2)).reason_code,
        )


if __name__ == "__main__":
    unittest.main()
