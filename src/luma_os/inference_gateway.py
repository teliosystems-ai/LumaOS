"""Authenticated, policy-gated local inference gateway contract."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hmac
import threading
from typing import Protocol

from .fake_inference import InferenceRequest, InferenceResult
from .policy import PolicyBroker, PolicyRequest
from .resources import ResourceLease, ResourceLedger, ResourceValidationError
from .runtime_contracts import ResourceAllocation, RuntimeProfile


class InferenceGatewayError(RuntimeError):
    """Base class for gateway request rejection."""


class AuthenticationFailed(InferenceGatewayError):
    """The local caller did not present valid session authentication."""


class DeadlineExceeded(InferenceGatewayError):
    """The request deadline elapsed before a result could be accepted."""


class GatewayBusy(InferenceGatewayError):
    """The runtime profile's explicit concurrency limit is full."""


class LocalInferenceBackend(Protocol):
    model_id: str

    def infer(self, lease: ResourceLease, request: InferenceRequest) -> InferenceResult: ...


Authenticator = Callable[[str, str], bool]


def _identifier(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 256:
        raise ResourceValidationError(f"{field_name} must be a non-empty trimmed string")
    if "\x00" in value:
        raise ResourceValidationError(f"{field_name} cannot contain NUL")
    return value


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ResourceValidationError("deadline must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class GatewayRequest:
    request_id: str
    session_id: str
    session_token: str = field(repr=False)
    prompt: str
    max_output_tokens: int
    deadline: datetime
    expected_grant_id: str
    expected_grant_version: int

    def __post_init__(self) -> None:
        for name in ("request_id", "session_id", "session_token", "expected_grant_id"):
            _identifier(getattr(self, name), name)
        if not isinstance(self.prompt, str):
            raise ResourceValidationError("prompt must be a string")
        if (
            not isinstance(self.max_output_tokens, int)
            or isinstance(self.max_output_tokens, bool)
            or self.max_output_tokens < 1
        ):
            raise ResourceValidationError("max_output_tokens must be positive")
        if (
            not isinstance(self.expected_grant_version, int)
            or isinstance(self.expected_grant_version, bool)
            or self.expected_grant_version < 1
        ):
            raise ResourceValidationError("expected_grant_version must be positive")
        object.__setattr__(self, "deadline", _utc(self.deadline))


@dataclass(frozen=True, slots=True)
class GatewayResult:
    inference: InferenceResult
    runtime_profile_id: str
    model_manifest_sha256: str
    tokenizer_sha256: str
    template_sha256: str
    policy_decision_id: str
    remote_fallback_used: bool = False


class StaticTokenAuthenticator:
    """Constant-time local test/development session authenticator."""

    def __init__(self, tokens: dict[str, str]) -> None:
        if not tokens:
            raise ResourceValidationError("at least one session token is required")
        self._tokens = {
            _identifier(session, "session_id"): _identifier(token, "session_token")
            for session, token in tokens.items()
        }

    def __call__(self, session_id: str, session_token: str) -> bool:
        expected = self._tokens.get(session_id)
        return expected is not None and hmac.compare_digest(expected, session_token)


class LocalInferenceGateway:
    """Bind identity, current policy, exact profile, deadline, and live lease."""

    def __init__(
        self,
        *,
        profile: RuntimeProfile,
        allocation: ResourceAllocation,
        ledger: ResourceLedger,
        policy: PolicyBroker,
        authenticate: Authenticator,
        backend: LocalInferenceBackend,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if allocation.runtime_profile_id != profile.profile_id:
            raise ResourceValidationError("allocation and runtime profile do not match")
        if profile.remote_fallback:
            raise ResourceValidationError("local gateway cannot enable remote fallback")
        if backend.model_id != profile.model_id:
            raise ResourceValidationError("backend model identity does not match runtime profile")
        self._profile = profile
        self._allocation = allocation
        self._ledger = ledger
        self._policy = policy
        self._authenticate = authenticate
        self._backend = backend
        self._clock = clock or (lambda: datetime.now(UTC))
        self._slots = threading.BoundedSemaphore(profile.max_concurrent_requests)

    def infer(self, request: GatewayRequest) -> GatewayResult:
        if not isinstance(request, GatewayRequest):
            raise ResourceValidationError("request must be a GatewayRequest")
        if not self._authenticate(request.session_id, request.session_token):
            raise AuthenticationFailed("session authentication failed")
        now = _utc(self._clock())
        if now >= request.deadline:
            raise DeadlineExceeded("inference deadline has elapsed")
        if request.max_output_tokens > self._profile.max_output_tokens:
            raise ResourceValidationError("request exceeds runtime output-token limit")
        if not self._slots.acquire(blocking=False):
            raise GatewayBusy("runtime profile concurrency limit reached")
        try:
            # Revalidation occurs after acquiring a runtime slot and immediately
            # before the backend call.  The backend independently fences the
            # lease for the duration of its operation.
            decision = self._policy.require(
                PolicyRequest(
                    subject=request.session_id,
                    capability="model.infer",
                    resource_kind="runtime-profile",
                    resource_id=self._profile.profile_id,
                    operation="infer",
                    expected_grant_id=request.expected_grant_id,
                    expected_grant_version=request.expected_grant_version,
                ),
                at=now,
            )
            self._ledger.assert_active(
                self._allocation.lease,
                owner_id=self._allocation.lease.owner_id,
            )
            inference = self._backend.infer(
                self._allocation.lease,
                InferenceRequest(
                    request_id=request.request_id,
                    prompt=request.prompt,
                    max_output_tokens=request.max_output_tokens,
                ),
            )
            if _utc(self._clock()) >= request.deadline:
                raise DeadlineExceeded("inference completed after its deadline")
            return GatewayResult(
                inference=inference,
                runtime_profile_id=self._profile.profile_id,
                model_manifest_sha256=self._profile.model_manifest_sha256,
                tokenizer_sha256=self._profile.tokenizer_sha256,
                template_sha256=self._profile.template_sha256,
                policy_decision_id=decision.decision_id,
                remote_fallback_used=False,
            )
        finally:
            self._slots.release()
