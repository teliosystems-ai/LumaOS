from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.fake_inference import DeterministicFakeInferenceBackend  # noqa: E402
from luma_os.inference_gateway import (  # noqa: E402
    AuthenticationFailed,
    DeadlineExceeded,
    GatewayRequest,
    LocalInferenceGateway,
    StaticTokenAuthenticator,
)
from luma_os.policy import CapabilityGrant, PolicyBroker, PolicyDenied  # noqa: E402
from luma_os.resources import MemoryDomain, MemoryReservation, ResourceLedger, StaleLeaseError  # noqa: E402
from luma_os.runtime_contracts import PlacementPlan, RuntimeProfile, admit_placement  # noqa: E402


class InferenceGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 22, 12, tzinfo=UTC)
        self.ledger = ResourceLedger((MemoryDomain("host", 4096),), id_factory=lambda: "lease-1")
        self.profile = RuntimeProfile(
            "compact-local",
            "test-compact",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            "fake",
            "1",
            2048,
            128,
            1,
        )
        plan = PlacementPlan("plan-1", self.profile.profile_id, (MemoryReservation("host", 1024),))
        self.allocation = admit_placement(
            self.ledger,
            owner_id="modeld",
            profile=self.profile,
            plan=plan,
            idempotency_key="allocation-1",
        )
        self.policy = PolicyBroker(clock=lambda: self.now, id_factory=lambda: "decision-1")
        self.policy.install(
            CapabilityGrant(
                grant_id="infer-grant",
                subject="session-1",
                capability="model.infer",
                resource_kind="runtime-profile",
                resource_id=self.profile.profile_id,
                operations=("infer",),
                issued_at=self.now - timedelta(minutes=1),
                expires_at=self.now + timedelta(hours=1),
            )
        )
        self.gateway = LocalInferenceGateway(
            profile=self.profile,
            allocation=self.allocation,
            ledger=self.ledger,
            policy=self.policy,
            authenticate=StaticTokenAuthenticator({"session-1": "secret-token"}),
            backend=DeterministicFakeInferenceBackend(self.ledger, model_id="test-compact"),
            clock=lambda: self.now,
        )

    def request(self, **overrides: object) -> GatewayRequest:
        values: dict[str, object] = {
            "request_id": "request-1",
            "session_id": "session-1",
            "session_token": "secret-token",
            "prompt": "hello",
            "max_output_tokens": 16,
            "deadline": self.now + timedelta(minutes=1),
            "expected_grant_id": "infer-grant",
            "expected_grant_version": 1,
        }
        values.update(overrides)
        return GatewayRequest(**values)  # type: ignore[arg-type]

    def test_gateway_binds_explicit_profile_policy_lease_and_no_remote_fallback(self) -> None:
        result = self.gateway.infer(self.request())
        self.assertTrue(result.inference.simulated)
        self.assertEqual(self.profile.model_manifest_sha256, result.model_manifest_sha256)
        self.assertEqual("decision-1", result.policy_decision_id)
        self.assertFalse(result.remote_fallback_used)

    def test_authentication_deadline_revocation_and_stale_lease_fail_closed(self) -> None:
        with self.assertRaises(AuthenticationFailed):
            self.gateway.infer(self.request(session_token="wrong"))
        with self.assertRaises(DeadlineExceeded):
            self.gateway.infer(self.request(deadline=self.now))
        self.policy.revoke("infer-grant", expected_version=1)
        with self.assertRaises(PolicyDenied):
            self.gateway.infer(self.request(expected_grant_version=2))

        # A fresh policy broker isolates lease fencing from the revocation case.
        policy = PolicyBroker(clock=lambda: self.now)
        policy.install(
            CapabilityGrant(
                "grant-2",
                "session-1",
                "model.infer",
                "runtime-profile",
                self.profile.profile_id,
                ("infer",),
                self.now - timedelta(minutes=1),
                self.now + timedelta(hours=1),
            )
        )
        gateway = LocalInferenceGateway(
            profile=self.profile,
            allocation=self.allocation,
            ledger=self.ledger,
            policy=policy,
            authenticate=StaticTokenAuthenticator({"session-1": "secret-token"}),
            backend=DeterministicFakeInferenceBackend(self.ledger, model_id="test-compact"),
            clock=lambda: self.now,
        )
        self.ledger.release(self.allocation.lease)
        with self.assertRaises(StaleLeaseError):
            gateway.infer(self.request(expected_grant_id="grant-2"))


if __name__ == "__main__":
    unittest.main()
