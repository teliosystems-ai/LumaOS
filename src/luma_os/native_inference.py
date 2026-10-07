"""Native reference inference over the existing authenticated broker socket.

This resource interface grants no effects or product Admin authority. It never
receives a runtime API key or falls back to a direct HTTP model connection.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import socket
import struct
import time
from typing import Any

from .errors import ValidationError

SOCKET = "/run/luma-broker/control.sock"
FIELDS = {"kind", "nonce", "worker", "phase", "profile", "input_digest",
          "max_output_tokens", "context_tokens", "request_deadline", "prompt_tokens",
          "token_digest", "output_tokens", "result_digest", "slot_released", "worker_resources_released"}


class NativeInferenceError(RuntimeError):
    """Native admission or execution did not produce a verified result."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def strict_json(raw: bytes) -> Any:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise NativeInferenceError("ambiguous native reply")
            result[key] = value
        return result
    def invalid(value):
        raise NativeInferenceError("nonfinite native reply")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise NativeInferenceError("malformed native reply") from error


def boot_ms() -> int:
    if not hasattr(time, "CLOCK_BOOTTIME"):
        raise NativeInferenceError("native boot-time clock unavailable")
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1_000_000


def decimal(value: Any) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal() or len(value) > 20:
        raise NativeInferenceError("invalid lossless native count")
    result = int(value)
    if str(result) != value or result > 2**64-1:
        raise NativeInferenceError("noncanonical native count")
    return result


def digest(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise NativeInferenceError("invalid native digest")
    return value


def worker(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"lease_id", "generation", "manager_epoch"}:
        raise NativeInferenceError("invalid native generation")
    for key in ("lease_id", "manager_epoch"):
        if not isinstance(value[key], str) or len(value[key]) != 32 or any(c not in "0123456789abcdef" for c in value[key]):
            raise NativeInferenceError("invalid native generation")
    if decimal(value["generation"]) == 0:
        raise NativeInferenceError("invalid native generation")
    return value


class NativeGatewayClient:
    def __init__(self, model: str | None, *, timeout: float = 180.0) -> None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 1 <= timeout <= 1800:
            raise ValidationError("Native inference timeout must be 1..1800 seconds")
        if model is not None and (not isinstance(model, str) or not 1 <= len(model) <= 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for c in model)):
            raise ValidationError("Invalid native model identity")
        self.model = model
        self.timeout = timeout
        self.endpoint = "unix:" + SOCKET

    @property
    def configured(self) -> bool:
        return self.model is not None

    def _exchange(self, payload: dict[str, Any], until: int) -> dict[str, Any]:
        if not hasattr(os, "geteuid") or os.geteuid() != 990:
            raise NativeInferenceError("native reference peer identity required")
        deadline = min(until, boot_ms()+4000)
        request_id = secrets.token_hex(16)
        body = canonical({"schema_version": 1, "request_id": request_id, "caller": 990,
                          "deadline": str(deadline), "action": "resource-gateway", "payload": payload})
        if not 1 <= len(body) <= 16384:
            raise NativeInferenceError("native request exceeds frame bound")
        def remaining():
            left = (deadline - boot_ms()) / 1000
            if left <= 0:
                raise NativeInferenceError("native exchange deadline expired")
            return min(left, 2.0)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(remaining())
            peer.connect(SOCKET)
            credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            if struct.unpack("3i", credentials)[1] != 0:
                raise NativeInferenceError("native broker is not root")
            frame = memoryview(struct.pack("!I", len(body)) + body)
            while frame:
                peer.settimeout(remaining())
                sent = peer.send(frame)
                if sent <= 0:
                    raise NativeInferenceError("native frame write ended")
                frame = frame[sent:]
            def exact(size):
                result = bytearray()
                while len(result) < size:
                    peer.settimeout(remaining())
                    part = peer.recv(size-len(result))
                    if not part:
                        raise NativeInferenceError("native frame truncated")
                    result.extend(part)
                remaining()
                return bytes(result)
            size = struct.unpack("!I", exact(4))[0]
            if not 1 <= size <= 16384:
                raise NativeInferenceError("native reply exceeds frame bound")
            reply = strict_json(exact(size))
        if (not isinstance(reply, dict) or set(reply) != {"schema_version", "request_id", "caller", "result", "status"}
                or type(reply["schema_version"]) is not int or reply["schema_version"] != 1
                or type(reply["caller"]) is not int or reply["caller"] != 990
                or reply["request_id"] != request_id or reply["result"] != "ok"
                or not isinstance(reply["status"], dict)):
            raise NativeInferenceError("native reply identity or shape differs")
        return reply["status"]

    def _inspect(self, until: int) -> dict[str, Any]:
        info = self._exchange({"operation": "inspect"}, until)
        if (set(info) != {"kind", "worker", "profile", "context_tokens", "max_output_tokens", "slots"}
                or info["kind"] != "worker" or info["profile"] != self.model
                or decimal(info["context_tokens"]) != 2048 or decimal(info["max_output_tokens"]) != 128 or info["slots"] != "1"):
            raise NativeInferenceError("native selected inventory differs")
        worker(info["worker"])
        return info

    def status(self, *, probe: bool = True) -> dict[str, Any]:
        result = {"configured": self.configured, "available": False, "endpoint": self.endpoint,
                  "model": self.model, "required_for_workflows": False}
        if not self.configured or not probe:
            result["detail"] = "Native model not configured." if not self.configured else "Configured but not probed."
        else:
            try:
                self._inspect(boot_ms()+4000)
                result.update(available=True, detail="Native broker reports a ready serving generation.")
            except (OSError, NativeInferenceError):
                result["detail"] = "Native serving generation unavailable."
        return result

    @staticmethod
    def _permit(status, expected, phases):
        receipt = status.get("receipt")
        if not isinstance(receipt, dict) or set(receipt) != FIELDS:
            raise NativeInferenceError("native receipt shape differs")
        for key, value in expected.items():
            if receipt[key] != value:
                raise NativeInferenceError("native receipt substituted")
        if (receipt["kind"] != "permit" or receipt["phase"] not in phases
                or receipt["worker_resources_released"] is not False
                or receipt["slot_released"] is not (receipt["phase"] == "completed")):
            raise NativeInferenceError("native receipt phase differs")
        prompt, output = receipt["prompt_tokens"], receipt["output_tokens"]
        if receipt["phase"] == "preparing":
            if any(receipt[key] is not None for key in ("prompt_tokens", "token_digest", "output_tokens", "result_digest")):
                raise NativeInferenceError("native preparing counts differ")
        else:
            if not 1 <= decimal(prompt) <= 2048-decimal(receipt["max_output_tokens"]):
                raise NativeInferenceError("native prompt exceeds context")
            digest(receipt["token_digest"])
            if receipt["phase"] == "admitted":
                if output is not None or receipt["result_digest"] is not None:
                    raise NativeInferenceError("native admitted result premature")
            else:
                if not 1 <= decimal(output) <= decimal(receipt["max_output_tokens"]):
                    raise NativeInferenceError("native output exceeds budget")
                digest(receipt["result_digest"])
        return receipt

    def chat_completion(self, messages: list[dict[str, str]], *, temperature: float = 0.7,
                        max_tokens: int | None = None, seed: int | None = None) -> dict[str, Any]:
        if not self.configured:
            raise ValidationError("No native model configured")
        if isinstance(temperature, bool) or temperature != 0.7 or seed is not None:
            raise ValidationError("Native pinned sampling requires temperature 0.7 and no seed")
        maximum = 128 if max_tokens is None else max_tokens
        if type(maximum) is not int or not 1 <= maximum <= 128:
            raise ValidationError("Native output budget must be 1..128 tokens")
        if not isinstance(messages, list) or not 1 <= len(messages) <= 16:
            raise ValidationError("Native input requires 1..16 messages")
        canonical_messages = []
        total = 0
        for message in messages:
            if (not isinstance(message, dict) or set(message) != {"role", "content"}
                    or message["role"] not in ("system", "user", "assistant")
                    or not isinstance(message["content"], str) or not message["content"]):
                raise ValidationError("Invalid native message")
            try:
                total += len(message["content"].encode("utf-8"))
            except UnicodeError as error:
                raise ValidationError("Invalid native UTF-8 input") from error
            canonical_messages.append({"role": message["role"], "content": message["content"]})
        if total > 8192 or canonical_messages[-1]["role"] != "user":
            raise ValidationError("Native messages exceed bounds or do not end with user")
        until = boot_ms()+int(self.timeout*1000)
        info = self._inspect(until)
        nonce = secrets.token_hex(16)
        binding = hashlib.sha256(b"luma-native-gateway-messages-v1\0"+canonical(canonical_messages)).hexdigest()
        expected = {"nonce": nonce, "worker": info["worker"], "profile": self.model, "input_digest": binding,
                    "max_output_tokens": str(maximum), "context_tokens": "2048", "request_deadline": str(until)}
        identity = {"nonce": nonce, "worker": info["worker"]}
        acknowledged = False
        try:
            status = self._exchange({"operation": "submit", **identity, "profile": self.model,
                                     "messages": canonical_messages, "max_output_tokens": str(maximum), "request_deadline": str(until)}, until)
            if set(status) != {"kind", "receipt"} or status["kind"] != "permit":
                raise NativeInferenceError("native submit reply differs")
            self._permit(status, expected, ("preparing",))
            while True:
                if boot_ms() >= until:
                    raise NativeInferenceError("native inference deadline expired")
                status = self._exchange({"operation": "fetch", **identity}, until)
                if status.get("kind") == "result":
                    if set(status) != {"kind", "receipt", "output"}:
                        raise NativeInferenceError("native result shape differs")
                    receipt = self._permit(status, expected, ("completed",))
                    output = status["output"]
                    if (not isinstance(output, dict) or set(output) != {"text", "prompt_tokens", "output_tokens"}
                            or not isinstance(output["text"], str) or not output["text"].strip()
                            or len(output["text"].encode("utf-8")) > 8192
                            or output["prompt_tokens"] != receipt["prompt_tokens"] or output["output_tokens"] != receipt["output_tokens"]):
                        raise NativeInferenceError("native result differs from receipt")
                    ordered = {"text": output["text"], "prompt_tokens": output["prompt_tokens"], "output_tokens": output["output_tokens"]}
                    result_digest = hashlib.sha256(b"luma-native-gateway-result-v1\0"+canonical(ordered)).hexdigest()
                    if result_digest != receipt["result_digest"]:
                        raise NativeInferenceError("native result digest differs")
                    ack = self._exchange({"operation": "ack", **identity, "result_digest": result_digest}, until)
                    if set(ack) != {"kind", "receipt"} or ack["kind"] != "permit" or self._permit(ack, expected, ("completed",)) != receipt:
                        raise NativeInferenceError("native result acknowledgement differs")
                    if boot_ms() >= until:
                        raise NativeInferenceError("native result publication deadline expired")
                    acknowledged = True
                    prompt, predicted = decimal(output["prompt_tokens"]), decimal(output["output_tokens"])
                    return {"model": self.model, "choices": [{"message": {"role": "assistant", "content": output["text"]}, "finish_reason": "stop"}],
                            "usage": {"prompt_tokens": prompt, "completion_tokens": predicted, "total_tokens": prompt+predicted},
                            "resource_worker": info["worker"], "resource_request": nonce, "resource_input_digest": binding,
                            "effects_executed": False, "certification_closing": False}
                if set(status) != {"kind", "receipt"} or status["kind"] != "permit":
                    raise NativeInferenceError("native pending reply differs")
                self._permit(status, expected, ("preparing", "admitted"))
                time.sleep(min(0.1, max(0, (until-boot_ms())/1000)))
        finally:
            if not acknowledged:
                try:
                    self._exchange({"operation": "cancel", **identity}, boot_ms()+4000)
                except (OSError, NativeInferenceError):
                    # Durable caller/deadline fencing remains authoritative.
                    # No cancellation acknowledgement means no cleanup claim.
                    pass

    def complete(self, messages: list[dict[str, str]], **options: Any) -> str:
        return self.chat_completion(messages, **options)["choices"][0]["message"]["content"]
