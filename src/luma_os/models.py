"""Optional local OpenAI-compatible model adapter.

The core workflow does not depend on this client. Ollama can expose the same
interface at ``http://127.0.0.1:11434/v1`` when configured by the user.
"""

from __future__ import annotations

import json
import socket
from typing import Any
from urllib import error, request

from .errors import ValidationError


class OpenAICompatibleClient:
    def __init__(self, endpoint: str | None, model: str | None, *, api_key: str | None = None, timeout: float = 2.0) -> None:
        self.endpoint = endpoint.rstrip("/") if endpoint else None
        self.model = model
        self.api_key = api_key
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.endpoint and self.model)

    def status(self, *, probe: bool = True) -> dict[str, Any]:
        base = {
            "configured": self.configured,
            "available": False,
            "endpoint": self.endpoint,
            "model": self.model,
            "required_for_workflows": False,
        }
        if not self.configured:
            base["detail"] = "No local model endpoint configured; deterministic workflows remain available."
            return base
        if not probe:
            base["detail"] = "Configured but not probed."
            return base
        try:
            response = self._request("GET", "/models")
            model_ids = [item.get("id") for item in response.get("data", []) if isinstance(item, dict)]
            base["available"] = self.model in model_ids if model_ids else True
            base["detail"] = "Local model endpoint responded." if base["available"] else "Endpoint responded but configured model was not listed."
        except (OSError, ValueError, error.URLError) as exc:
            base["detail"] = f"Local model endpoint unavailable: {type(exc).__name__}"
        return base

    def complete(self, messages: list[dict[str, str]], *, temperature: float = 0.0) -> str:
        if not self.configured:
            raise ValidationError("No local model endpoint is configured")
        payload = self._request(
            "POST",
            "/chat/completions",
            {"model": self.model, "messages": messages, "temperature": temperature},
        )
        try:
            return str(payload["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("Model endpoint returned an unexpected response") from exc

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.endpoint:
            raise ValidationError("No model endpoint is configured")
        # Local-first MVP: refuse a non-loopback model endpoint. Remote model
        # connectors require a separate policy and consent design.
        from urllib.parse import urlparse

        parsed = urlparse(self.endpoint)
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValidationError("Model endpoint must be a loopback HTTP endpoint in this release")
        headers = {"Accept": "application/json"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        call = request.Request(f"{self.endpoint}{path}", data=body, headers=headers, method=method)
        try:
            with request.urlopen(call, timeout=self.timeout) as response:  # noqa: S310 - loopback enforced above
                if response.length is not None and response.length > 2 * 1024 * 1024:
                    raise ValueError("Model endpoint response is too large")
                raw = response.read(2 * 1024 * 1024 + 1)
        except socket.timeout as exc:
            raise OSError("Model endpoint timed out") from exc
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("Model endpoint response is too large")
        decoded = json.loads(raw)
        if not isinstance(decoded, dict):
            raise ValueError("Model endpoint returned a non-object response")
        return decoded
