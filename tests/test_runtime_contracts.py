from __future__ import annotations

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.resources import MemoryDomain, MemoryReservation, ResourceLedger, ResourceValidationError  # noqa: E402
from luma_os.runtime_contracts import (  # noqa: E402
    CacheIsolationError,
    CacheItemTooLarge,
    IsolatedByteCache,
    PlacementPlan,
    RuntimeProfile,
    admit_placement,
)


class RuntimeContractTests(unittest.TestCase):
    def profile(self) -> RuntimeProfile:
        return RuntimeProfile(
            profile_id="compact-local",
            model_id="test-compact",
            model_manifest_sha256="a" * 64,
            tokenizer_sha256="b" * 64,
            template_sha256="c" * 64,
            backend="fake",
            backend_version="1",
            context_tokens=4096,
            max_output_tokens=512,
            max_concurrent_requests=1,
        )

    def test_exact_placement_admission_binds_plan_profile_and_lease(self) -> None:
        ledger = ResourceLedger((MemoryDomain("host", 1000, reserved_bytes=100),))
        plan = PlacementPlan(
            "plan-1",
            "compact-local",
            (MemoryReservation("host", 400),),
        )
        allocation = admit_placement(
            ledger,
            owner_id="modeld",
            profile=self.profile(),
            plan=plan,
            idempotency_key="placement-1",
        )
        self.assertEqual(plan.reservations, allocation.lease.reservations)
        self.assertEqual("compact-local", allocation.runtime_profile_id)

    def test_profile_denies_remote_fallback_and_plan_mismatch(self) -> None:
        values = self.profile()
        with self.assertRaises(ResourceValidationError):
            RuntimeProfile(
                values.profile_id,
                values.model_id,
                values.model_manifest_sha256,
                values.tokenizer_sha256,
                values.template_sha256,
                values.backend,
                values.backend_version,
                values.context_tokens,
                values.max_output_tokens,
                values.max_concurrent_requests,
                remote_fallback=True,
            )
        ledger = ResourceLedger((MemoryDomain("host", 1000),))
        wrong = PlacementPlan("plan-2", "other", (MemoryReservation("host", 1),))
        with self.assertRaises(ResourceValidationError):
            admit_placement(
                ledger,
                owner_id="modeld",
                profile=values,
                plan=wrong,
                idempotency_key="wrong",
            )

    def test_cache_isolation_lru_eviction_and_exact_accounting(self) -> None:
        cache = IsolatedByteCache(owner_id="session-a", quota_bytes=6)
        cache.put("session-a", "one", b"111")
        cache.put("session-a", "two", b"22")
        self.assertEqual(b"111", cache.get("session-a", "one"))
        result = cache.put("session-a", "three", b"333")
        self.assertEqual(("two",), result.evicted_keys)
        self.assertEqual(("one", "three"), cache.keys(owner_id="session-a"))
        self.assertEqual(6, cache.used_bytes)
        with self.assertRaises(CacheIsolationError):
            cache.get("session-b", "one")
        with self.assertRaises(CacheItemTooLarge):
            cache.put("session-a", "huge", b"1234567")


if __name__ == "__main__":
    unittest.main()
