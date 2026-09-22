"""Lease-fenced adapter for a real loopback OpenAI-compatible model runtime."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import threading
from typing import Any, Protocol

from .fake_inference import InferenceReplayConflict, InferenceRequest, InferenceResult
from .resources import ResourceLease, ResourceLedger, ResourceValidationError


class ChatCompletionClient(Protocol):
    model: str | None

    def chat_completion(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        seed: int | None = None,
    ) -> dict[str, Any]: ...


class RealInferenceError(RuntimeError):
    """The local runtime returned an invalid or unusable inference result."""


class OpenAICompatibleInferenceBackend:
    """Execute a real model call while holding a generation-fenced lease.

    The adapter refuses to estimate token counts.  A runtime used as evidence
    must return the OpenAI ``usage.completion_tokens`` field so the result is
    measured rather than inferred from whitespace or bytes.
    """

    def __init__(
        self,
        ledger: ResourceLedger,
        client: ChatCompletionClient,
        *,
        model_id: str,
        required_reservations: Mapping[str, int] | None = None,
        temperature: float = 0.7,
        seed: int = 42,
    ) -> None:
        if not isinstance(ledger, ResourceLedger):
            raise ResourceValidationError("ledger must be a ResourceLedger")
        if not isinstance(model_id, str) or not model_id or model_id != model_id.strip():
            raise ResourceValidationError("model_id must be a non-empty, trimmed string")
        if client.model != model_id:
            raise ResourceValidationError("client model identity does not match model_id")
        if not isinstance(temperature, (int, float)) or isinstance(temperature, bool):
            raise ResourceValidationError("temperature must be numeric")
        if temperature < 0 or temperature > 2:
            raise ResourceValidationError("temperature must be between zero and two")
        if not isinstance(seed, int) or isinstance(seed, bool):
            raise ResourceValidationError("seed must be an integer")
        requirements: dict[str, int] = {}
        for domain_id, minimum in (required_reservations or {}).items():
            if not isinstance(domain_id, str) or not domain_id or domain_id != domain_id.strip():
                raise ResourceValidationError("required domain IDs must be non-empty and trimmed")
            if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
                raise ResourceValidationError("required reservation bytes must be positive integers")
            requirements[domain_id] = minimum
        self._ledger = ledger
        self._client = client
        self.model_id = model_id
        self._required_reservations = requirements
        self._temperature = float(temperature)
        self._seed = seed
        self._completed: dict[str, tuple[str, InferenceResult]] = {}
        self._lock = threading.Lock()

    def infer(self, lease: ResourceLease, request: InferenceRequest) -> InferenceResult:
        if not isinstance(request, InferenceRequest):
            raise ResourceValidationError("request must be an InferenceRequest")
        with self._ledger.hold(lease) as admitted:
            for domain_id, minimum in self._required_reservations.items():
                if admitted.bytes_for(domain_id) < minimum:
                    raise RealInferenceError(
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
                response = self._client.chat_completion(
                    [{"role": "user", "content": request.prompt}],
                    temperature=self._temperature,
                    max_tokens=request.max_output_tokens,
                    seed=self._seed,
                )
                text, output_tokens = self._parse_response(response)
                result = InferenceResult(
                    request_id=request.request_id,
                    model_id=self.model_id,
                    text=text,
                    output_tokens=output_tokens,
                    prompt_sha256=hashlib.sha256(request.prompt.encode("utf-8")).hexdigest(),
                    lease_id=admitted.lease_id,
                    lease_generation=admitted.generation,
                    simulated=False,
                )
                self._completed[request.request_id] = (fingerprint, result)
                return result

    @staticmethod
    def _parse_response(response: object) -> tuple[str, int]:
        try:
            if not isinstance(response, dict):
                raise TypeError
            text = response["choices"][0]["message"]["content"]
            output_tokens = response["usage"]["completion_tokens"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RealInferenceError(
                "runtime response must contain assistant content and measured completion_tokens"
            ) from exc
        if not isinstance(text, str):
            raise RealInferenceError("runtime assistant content must be a string")
        if (
            not isinstance(output_tokens, int)
            or isinstance(output_tokens, bool)
            or output_tokens < 0
        ):
            raise RealInferenceError("runtime completion_tokens must be a non-negative integer")
        return text, output_tokens

    def _fingerprint(self, lease: ResourceLease, request: InferenceRequest) -> str:
        fields = (
            self.model_id,
            lease.lease_id,
            str(lease.generation),
            request.prompt,
            str(request.max_output_tokens),
            str(self._temperature),
            str(self._seed),
        )
        digest = hashlib.sha256()
        for field in fields:
            encoded = field.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        return digest.hexdigest()
