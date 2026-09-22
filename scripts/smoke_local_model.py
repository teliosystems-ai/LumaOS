#!/usr/bin/env python3
"""Exercise a loopback model runtime through the Luma inference gateway.

This is a development smoke harness, not a certification or signed-model-pack
tool.  It creates an explicitly unsigned runtime tuple in memory, admits a
resource lease, installs a short-lived capability grant, authenticates a local
session, and makes one real OpenAI-compatible chat-completion request.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from time import monotonic
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from luma_os.inference_gateway import (  # noqa: E402
    GatewayRequest,
    LocalInferenceGateway,
    StaticTokenAuthenticator,
)
from luma_os.models import OpenAICompatibleClient  # noqa: E402
from luma_os.policy import CapabilityGrant, PolicyBroker  # noqa: E402
from luma_os.real_inference import OpenAICompatibleInferenceBackend  # noqa: E402
from luma_os.resources import MemoryDomain, MemoryReservation, ResourceLedger  # noqa: E402
from luma_os.runtime_contracts import (  # noqa: E402
    PlacementPlan,
    RuntimeProfile,
    admit_placement,
)


DEFAULT_PROMPT = "/no_think Reply with exactly LUMA_GATEWAY_OK and nothing else."


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256(value: str) -> str:
    normalized = value.lower()
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise argparse.ArgumentTypeError("expected a 64-character SHA-256 digest")
    return normalized


class _CapturingClient:
    """Record non-secret runtime response metadata while satisfying the client protocol."""

    def __init__(self, client: OpenAICompatibleClient) -> None:
        self._client = client
        self.model = client.model
        self.last_response: dict[str, Any] | None = None

    def chat_completion(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        seed: int | None = None,
    ) -> dict[str, Any]:
        response = self._client.chat_completion(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
            seed=seed,
        )
        self.last_response = response
        return response


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="http://127.0.0.1:18080/v1")
    parser.add_argument("--model-id", default="qwen3-1.7b-dev")
    parser.add_argument("--model-sha256", required=True, type=_sha256)
    parser.add_argument("--backend-version", default="llama.cpp-b11100")
    parser.add_argument("--api-key-env", default="LUMA_LOCAL_MODEL_API_KEY")
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--context-tokens", type=int, default=4096)
    parser.add_argument("--max-output-tokens", type=int, default=32)
    parser.add_argument("--host-budget-bytes", type=int, default=8 * 1024**3)
    parser.add_argument("--reservation-bytes", type=int, default=2 * 1024**3)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--expected-response", default="LUMA_GATEWAY_OK")
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be positive")
    if args.reservation_bytes < 1 or args.host_budget_bytes < args.reservation_bytes:
        raise SystemExit("host budget must be at least the positive reservation")

    # These digests identify an unsigned development tuple only.  They do not
    # assert that a governed or signed model pack exists.
    tuple_descriptor = {
        "artifact_sha256": args.model_sha256,
        "backend": "llama.cpp",
        "backend_version": args.backend_version,
        "context_tokens": args.context_tokens,
        "model_id": args.model_id,
        "scope": "unsigned-development-tuple",
    }
    tuple_json = json.dumps(tuple_descriptor, sort_keys=True, separators=(",", ":"))
    model_manifest_sha256 = _sha256_text(tuple_json)
    tokenizer_contract_sha256 = _sha256_text(
        f"gguf-embedded-tokenizer:{args.model_sha256}"
    )
    template_contract_sha256 = _sha256_text(
        f"llama.cpp-chat-template:{args.model_sha256}"
    )

    client = OpenAICompatibleClient(
        args.endpoint,
        args.model_id,
        api_key=os.environ.get(args.api_key_env),
        timeout=args.timeout_seconds,
    )
    status = client.status()
    if not status["available"]:
        print(json.dumps({"status": "error", "runtime_status": status}, sort_keys=True))
        return 2
    capturing_client = _CapturingClient(client)

    now = datetime.now(UTC)
    ledger = ResourceLedger((MemoryDomain("host", args.host_budget_bytes),))
    profile = RuntimeProfile(
        profile_id="qwen3-1.7b-dev-loopback",
        model_id=args.model_id,
        model_manifest_sha256=model_manifest_sha256,
        tokenizer_sha256=tokenizer_contract_sha256,
        template_sha256=template_contract_sha256,
        backend="llama.cpp",
        backend_version=args.backend_version,
        context_tokens=args.context_tokens,
        max_output_tokens=args.max_output_tokens,
        max_concurrent_requests=1,
    )
    plan = PlacementPlan(
        "qwen3-1.7b-dev-host-plan",
        profile.profile_id,
        (MemoryReservation("host", args.reservation_bytes),),
    )
    allocation = admit_placement(
        ledger,
        owner_id="modeld-development-smoke",
        profile=profile,
        plan=plan,
        idempotency_key="qwen3-1.7b-dev-smoke-allocation",
    )
    policy = PolicyBroker()
    policy.install(
        CapabilityGrant(
            grant_id="qwen3-1.7b-dev-smoke-grant",
            subject="development-smoke-session",
            capability="model.infer",
            resource_kind="runtime-profile",
            resource_id=profile.profile_id,
            operations=("infer",),
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=10),
        )
    )
    session_token = secrets.token_urlsafe(32)
    backend = OpenAICompatibleInferenceBackend(
        ledger,
        capturing_client,
        model_id=args.model_id,
        required_reservations={"host": args.reservation_bytes},
        temperature=0.0,
        seed=42,
    )
    gateway = LocalInferenceGateway(
        profile=profile,
        allocation=allocation,
        ledger=ledger,
        policy=policy,
        authenticate=StaticTokenAuthenticator(
            {"development-smoke-session": session_token}
        ),
        backend=backend,
    )

    started = monotonic()
    result = gateway.infer(
        GatewayRequest(
            request_id="qwen3-1.7b-dev-smoke-request",
            session_id="development-smoke-session",
            session_token=session_token,
            prompt=args.prompt,
            max_output_tokens=args.max_output_tokens,
            deadline=now + timedelta(seconds=args.timeout_seconds + 5),
            expected_grant_id="qwen3-1.7b-dev-smoke-grant",
            expected_grant_version=1,
        )
    )
    elapsed_ms = round((monotonic() - started) * 1000, 3)
    raw_response = capturing_client.last_response or {}
    timings = raw_response.get("timings")
    usage = raw_response.get("usage")
    response_matched = result.inference.text == args.expected_response

    evidence = {
        "status": "pass" if response_matched else "fail",
        "evidence_scope": "development-smoke-only",
        "gate_closing": False,
        "runtime_tuple_signed": False,
        "runtime_tuple": tuple_descriptor,
        "derived_tuple_digests": {
            "model_manifest_sha256": result.model_manifest_sha256,
            "template_contract_sha256": result.template_sha256,
            "tokenizer_contract_sha256": result.tokenizer_sha256,
        },
        "gateway": {
            "authenticated": True,
            "lease_generation": result.inference.lease_generation,
            "lease_id": result.inference.lease_id,
            "policy_decision_id": result.policy_decision_id,
            "remote_fallback_used": result.remote_fallback_used,
            "runtime_profile_id": result.runtime_profile_id,
        },
        "inference": {
            "elapsed_ms": elapsed_ms,
            "model_id": result.inference.model_id,
            "output_tokens": result.inference.output_tokens,
            "prompt_sha256": result.inference.prompt_sha256,
            "response_matched": response_matched,
            "response_text": result.inference.text,
            "simulated": result.inference.simulated,
            "timings": timings if isinstance(timings, dict) else None,
            "usage": usage if isinstance(usage, dict) else None,
        },
        "runtime_status": status,
    }
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0 if response_matched else 3


if __name__ == "__main__":
    raise SystemExit(main())
