from __future__ import annotations

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.fake_inference import InferenceReplayConflict, InferenceRequest  # noqa: E402
from luma_os.real_inference import (  # noqa: E402
    OpenAICompatibleInferenceBackend,
    RealInferenceError,
)
from luma_os.resources import (  # noqa: E402
    MemoryDomain,
    MemoryReservation,
    ResourceLedger,
    StaleLeaseError,
)


class StubClient:
    model = "qwen-test"

    def __init__(self) -> None:
        self.calls = 0

    def chat_completion(self, messages, *, temperature=0.0, max_tokens=None, seed=None):
        self.calls += 1
        return {
            "choices": [{"message": {"content": "LUMA_OK"}}],
            "usage": {"completion_tokens": 3},
        }


class RealInferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = ResourceLedger(
            (MemoryDomain("host", 4096),), id_factory=lambda: "lease-real-1"
        )
        self.lease = self.ledger.admit(
            "modeld",
            (MemoryReservation("host", 2048),),
            idempotency_key="real-allocation-1",
        )
        self.client = StubClient()
        self.backend = OpenAICompatibleInferenceBackend(
            self.ledger,
            self.client,
            model_id="qwen-test",
            required_reservations={"host": 1024},
            temperature=0.7,
            seed=42,
        )

    def test_real_result_is_measured_lease_bound_and_not_simulated(self) -> None:
        request = InferenceRequest("request-real-1", "hello", 16)
        result = self.backend.infer(self.lease, request)
        self.assertEqual("LUMA_OK", result.text)
        self.assertEqual(3, result.output_tokens)
        self.assertFalse(result.simulated)
        self.assertEqual(self.lease.lease_id, result.lease_id)
        self.assertEqual(1, self.client.calls)
        self.assertEqual(result, self.backend.infer(self.lease, request))
        self.assertEqual(1, self.client.calls)

    def test_replay_drift_and_stale_lease_fail_closed(self) -> None:
        self.backend.infer(self.lease, InferenceRequest("request-real-1", "one", 16))
        with self.assertRaises(InferenceReplayConflict):
            self.backend.infer(self.lease, InferenceRequest("request-real-1", "two", 16))
        self.ledger.release(self.lease)
        with self.assertRaises(StaleLeaseError):
            self.backend.infer(self.lease, InferenceRequest("request-real-2", "three", 16))

    def test_missing_measured_usage_is_rejected(self) -> None:
        class MissingUsageClient(StubClient):
            def chat_completion(self, messages, *, temperature=0.0, max_tokens=None, seed=None):
                return {"choices": [{"message": {"content": "unmeasured"}}]}

        backend = OpenAICompatibleInferenceBackend(
            self.ledger,
            MissingUsageClient(),
            model_id="qwen-test",
        )
        with self.assertRaises(RealInferenceError):
            backend.infer(self.lease, InferenceRequest("request-real-3", "hello", 16))


if __name__ == "__main__":
    unittest.main()
