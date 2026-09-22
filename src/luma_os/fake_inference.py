"""Deterministic fake inference bound to resource-ledger leases."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import threading

from .resources import (
    ResourceLease,
    ResourceLedger,
    ResourceLedgerError,
    ResourceValidationError,
    checked_u64,
)


class FakeInferenceError(ResourceLedgerError):
    """A scripted fake inference request failed."""


class InferenceReplayConflict(ResourceLedgerError):
    """An inference request ID was replayed with different inputs."""


@dataclass(frozen=True, slots=True)
class InferenceRequest:
    request_id: str
    prompt: str
    max_output_tokens: int = 64

    def __post_init__(self) -> None:
        if (
            not isinstance(self.request_id, str)
            or not self.request_id
            or self.request_id != self.request_id.strip()
        ):
            raise ResourceValidationError("request_id must be a non-empty, trimmed string")
        if len(self.request_id) > 256:
            raise ResourceValidationError("request_id must not exceed 256 characters")
        if not isinstance(self.prompt, str):
            raise ResourceValidationError("prompt must be a string")
        limit = checked_u64(self.max_output_tokens, field="max_output_tokens")
        if limit == 0:
            raise ResourceValidationError("max_output_tokens must be greater than zero")


@dataclass(frozen=True, slots=True)
class InferenceResult:
    request_id: str
    model_id: str
    text: str
    output_tokens: int
    prompt_sha256: str
    lease_id: str
    lease_generation: int
    simulated: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "model_id": self.model_id,
            "text": self.text,
            "output_tokens": self.output_tokens,
            "prompt_sha256": self.prompt_sha256,
            "lease_id": self.lease_id,
            "lease_generation": self.lease_generation,
            "simulated": self.simulated,
        }


class DeterministicFakeInferenceBackend:
    """A reproducible test double that never loads or executes a model.

    The backend validates a live, generation-fenced lease on every call.  It can
    require minimum reservations per memory domain and provides request-level
    idempotency.  Its results are explicitly marked simulated and therefore are
    not hardware or model-performance evidence.
    """

    def __init__(
        self,
        ledger: ResourceLedger,
        *,
        model_id: str = "deterministic-fake-v1",
        required_reservations: Mapping[str, int] | None = None,
        responses: Mapping[str, str] | None = None,
        failing_request_ids: frozenset[str] | None = None,
    ) -> None:
        if not isinstance(ledger, ResourceLedger):
            raise ResourceValidationError("ledger must be a ResourceLedger")
        if not isinstance(model_id, str) or not model_id or model_id != model_id.strip():
            raise ResourceValidationError("model_id must be a non-empty, trimmed string")
        requirements: dict[str, int] = {}
        for domain_id, size in (required_reservations or {}).items():
            if not isinstance(domain_id, str) or not domain_id or domain_id != domain_id.strip():
                raise ResourceValidationError("required domain IDs must be non-empty and trimmed")
            value = checked_u64(size, field=f"required_reservations[{domain_id!r}]")
            if value == 0:
                raise ResourceValidationError("required reservation bytes must be greater than zero")
            requirements[domain_id] = value
        configured_responses = dict(responses or {})
        if any(not isinstance(key, str) or not isinstance(value, str) for key, value in configured_responses.items()):
            raise ResourceValidationError("fake responses must map strings to strings")
        failures = frozenset(failing_request_ids or ())
        if any(not isinstance(item, str) or not item for item in failures):
            raise ResourceValidationError("failing request IDs must be non-empty strings")

        self._ledger = ledger
        self.model_id = model_id
        self._required_reservations = requirements
        self._responses = configured_responses
        self._failures = failures
        self._completed: dict[str, tuple[str, InferenceResult]] = {}
        self._lock = threading.Lock()

    def infer(self, lease: ResourceLease, request: InferenceRequest) -> InferenceResult:
        if not isinstance(request, InferenceRequest):
            raise ResourceValidationError("request must be an InferenceRequest")
        # Holding the ledger lock closes the active-check/release race for this
        # deliberately immediate fake operation.
        with self._ledger.hold(lease) as admitted:
            for domain_id, minimum in self._required_reservations.items():
                if admitted.bytes_for(domain_id) < minimum:
                    raise FakeInferenceError(
                        f"lease does not satisfy the {domain_id!r} reservation requirement"
                    )
            fingerprint = self._fingerprint(admitted, request)
            with self._lock:
                replay = self._completed.get(request.request_id)
                if replay is not None:
                    original_fingerprint, result = replay
                    if original_fingerprint != fingerprint:
                        raise InferenceReplayConflict(
                            "request ID was already used with different inference inputs"
                        )
                    return result
                if request.request_id in self._failures:
                    raise FakeInferenceError("scripted deterministic inference failure")

                prompt_digest = hashlib.sha256(request.prompt.encode("utf-8")).hexdigest()
                text = self._responses.get(
                    request.prompt, f"fake-response-{prompt_digest[:24]}"
                )
                words = text.split()
                if len(words) > request.max_output_tokens:
                    words = words[: request.max_output_tokens]
                    text = " ".join(words)
                result = InferenceResult(
                    request_id=request.request_id,
                    model_id=self.model_id,
                    text=text,
                    output_tokens=len(words),
                    prompt_sha256=prompt_digest,
                    lease_id=admitted.lease_id,
                    lease_generation=admitted.generation,
                )
                self._completed[request.request_id] = (fingerprint, result)
                return result

    def _fingerprint(self, lease: ResourceLease, request: InferenceRequest) -> str:
        fields = (
            self.model_id,
            lease.lease_id,
            str(lease.generation),
            request.prompt,
            str(request.max_output_tokens),
        )
        digest = hashlib.sha256()
        for field in fields:
            encoded = field.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        return digest.hexdigest()
