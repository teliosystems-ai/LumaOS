"""Native gateway protocol fixtures, not installed peer/controller qualification."""
import copy
import hashlib
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from luma_os import native_inference as native
from luma_os.config import LumaConfig
from luma_os.errors import ValidationError
from luma_os.service import LumaService

TOKEN = {"lease_id": "a"*32, "generation": "1", "manager_epoch": "b"*32}
MODEL = "qwen3-1-7b-q4-k-m"


class Protocol(native.NativeGatewayClient):
    """Synthetic broker: validates client sequencing, never grants OS authority."""
    def __init__(self, *, alter=None, pending=False):
        super().__init__(MODEL, timeout=1)
        self.calls = []
        self.receipt = None
        self.alter = alter
        self.pending = pending

    def _exchange(self, payload, until):
        operation = payload["operation"]
        self.calls.append(copy.deepcopy(payload))
        if operation == "inspect":
            status = {"kind": "worker", "worker": copy.deepcopy(TOKEN), "profile": MODEL,
                      "context_tokens": "2048", "max_output_tokens": "128", "slots": "1"}
        elif operation == "submit":
            self.receipt = {"kind": "permit", "nonce": payload["nonce"], "worker": copy.deepcopy(TOKEN),
                            "phase": "preparing", "profile": MODEL,
                            "input_digest": hashlib.sha256(b"luma-native-gateway-messages-v1\0"+native.canonical(payload["messages"])).hexdigest(),
                            "max_output_tokens": payload["max_output_tokens"], "context_tokens": "2048",
                            "request_deadline": payload["request_deadline"], "prompt_tokens": None,
                            "token_digest": None, "output_tokens": None, "result_digest": None,
                            "slot_released": False, "worker_resources_released": False}
            status = {"kind": "permit", "receipt": copy.deepcopy(self.receipt)}
        elif operation == "fetch":
            self.receipt.update(phase="admitted", prompt_tokens="8", token_digest="c"*64)
            if self.pending:
                self.pending = False
                status = {"kind": "permit", "receipt": copy.deepcopy(self.receipt)}
            else:
                output = {"text": "LUMA ✓", "prompt_tokens": "8", "output_tokens": "2"}
                binding = hashlib.sha256(b"luma-native-gateway-result-v1\0"+native.canonical(output)).hexdigest()
                self.receipt.update(phase="completed", output_tokens="2", result_digest=binding, slot_released=True)
                status = {"kind": "result", "receipt": copy.deepcopy(self.receipt), "output": output}
        elif operation == "ack":
            if payload["result_digest"] != self.receipt["result_digest"]:
                raise AssertionError("client did not acknowledge the exact result")
            status = {"kind": "permit", "receipt": copy.deepcopy(self.receipt)}
        elif operation == "cancel":
            return {"kind": "permit"}
        else:
            raise AssertionError(operation)
        if self.alter:
            self.alter(operation, status)
        return status


class NativeClientTests(unittest.TestCase):
    def test_exact_result_is_acknowledged_before_publication_without_effect_authority(self):
        client = Protocol(pending=True)
        result = client.chat_completion([{"content": "Hello ✓", "role": "user"}], max_tokens=16)
        self.assertEqual("LUMA ✓", result["choices"][0]["message"]["content"])
        self.assertEqual({"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10}, result["usage"])
        self.assertEqual(["inspect", "submit", "fetch", "fetch", "ack"], [c["operation"] for c in client.calls])
        self.assertEqual(TOKEN, result["resource_worker"])
        self.assertFalse(result["effects_executed"])
        self.assertFalse(result["certification_closing"])
        self.assertEqual(["role", "content"], list(client.calls[1]["messages"][0]))

    def test_wrong_inventory_never_reserves_a_job(self):
        for field, value in [("profile", "other"), ("slots", "2"), ("context_tokens", "2049"),
                             ("max_output_tokens", "129"), ("worker", {**TOKEN, "generation": "0"})]:
            with self.subTest(field=field):
                def alter(operation, status):
                    if operation == "inspect": status[field] = value
                client = Protocol(alter=alter)
                with self.assertRaises(native.NativeInferenceError): client.complete([{"role": "user", "content": "hi"}])
                self.assertEqual(["inspect"], [c["operation"] for c in client.calls])

    def test_substituted_receipts_refuse_and_request_cancel_without_cleanup_claim(self):
        alterations = {"nonce": "d"*32, "worker": {**TOKEN, "generation": "2"}, "profile": "other",
                       "input_digest": "e"*64, "max_output_tokens": "127", "context_tokens": "4096",
                       "request_deadline": "1", "phase": "released", "worker_resources_released": True,
                       "slot_released": True, "prompt_tokens": "1", "token_digest": "f"*64,
                       "output_tokens": "1", "result_digest": "f"*64, "extra": 1}
        for field, value in alterations.items():
            with self.subTest(field=field):
                def alter(operation, status):
                    if operation == "submit": status["receipt"][field] = value
                client = Protocol(alter=alter)
                with self.assertRaises(native.NativeInferenceError): client.complete([{"role": "user", "content": "hi"}])
                self.assertEqual(["inspect", "submit", "cancel"], [c["operation"] for c in client.calls])

    def test_result_content_counts_and_digest_must_all_match(self):
        for target, field, value in [("output", "text", "substitute"), ("output", "prompt_tokens", "9"),
                                    ("output", "output_tokens", "3"), ("output", "extra", 1),
                                    ("output", "text", " "), ("output", "text", "x"*8193),
                                    ("receipt", "result_digest", "e"*64), ("receipt", "output_tokens", "129"),
                                    ("receipt", "token_digest", "z"*64), ("receipt", "prompt_tokens", "2048")]:
            with self.subTest(target=target, field=field):
                def alter(operation, status):
                    if operation == "fetch": status[target][field] = value
                client = Protocol(alter=alter)
                with self.assertRaises(native.NativeInferenceError): client.complete([{"role": "user", "content": "hi"}])
                self.assertNotIn("ack", [c["operation"] for c in client.calls])
                self.assertEqual("cancel", client.calls[-1]["operation"])

    def test_lost_or_changed_acknowledgement_publishes_no_result(self):
        for mode in ("lost", "changed"):
            with self.subTest(mode=mode):
                def alter(operation, status):
                    if operation == "ack":
                        if mode == "lost": raise OSError("fixture acknowledgement loss")
                        status["receipt"]["token_digest"] = "d"*64
                client = Protocol(alter=alter)
                with self.assertRaises((OSError, native.NativeInferenceError)): client.complete([{"role": "user", "content": "hi"}])
                self.assertEqual("cancel", client.calls[-1]["operation"])

    def test_expired_publication_refuses_even_an_exact_ack(self):
        clock = [100]
        def alter(operation, status):
            if operation == "ack": clock[0] = 1100
        client = Protocol(alter=alter)
        with patch.object(native, "boot_ms", side_effect=lambda: clock[0]):
            with self.assertRaises(native.NativeInferenceError): client.complete([{"role": "user", "content": "hi"}])
        self.assertEqual("cancel", client.calls[-1]["operation"])

    def test_request_deadline_stops_polling(self):
        clock = [100]
        def alter(operation, status):
            if operation == "submit": clock[0] = 1100
        client = Protocol(alter=alter)
        with patch.object(native, "boot_ms", side_effect=lambda: clock[0]):
            with self.assertRaises(native.NativeInferenceError): client.complete([{"role": "user", "content": "hi"}])
        self.assertEqual(["inspect", "submit", "cancel"], [c["operation"] for c in client.calls])

    def test_pending_reply_cannot_report_a_completed_slot_or_early_output(self):
        for field, value in [("slot_released", True), ("output_tokens", "1"), ("result_digest", "e"*64)]:
            with self.subTest(field=field):
                def alter(operation, status):
                    if operation == "fetch": status["receipt"][field] = value
                client = Protocol(alter=alter, pending=True)
                with self.assertRaises(native.NativeInferenceError): client.complete([{"role": "user", "content": "hi"}])
                self.assertEqual("cancel", client.calls[-1]["operation"])

    def test_input_and_sampling_validation_precedes_any_reservation(self):
        bad_messages = [[], [{"role": "assistant", "content": "hi"}], [{"role": "tool", "content": "hi"}],
                        [{"role": "user", "content": ""}], [{"role": "user", "content": "\ud800"}],
                        [{"role": "user", "content": "x"*8193}], [{"role": "user", "content": "hi", "extra": 1}],
                        [{"role": "user", "content": "hi"}]*17]
        for messages in bad_messages:
            client = Protocol()
            with self.assertRaises(ValidationError): client.complete(messages)
            self.assertEqual([], client.calls)
        for options in ({"max_tokens": True}, {"max_tokens": 0}, {"max_tokens": 129},
                        {"temperature": 0}, {"temperature": True}, {"seed": 1}):
            client = Protocol()
            with self.assertRaises(ValidationError): client.complete([{"role": "user", "content": "hi"}], **options)
            self.assertEqual([], client.calls)

    def test_unconfigured_and_nonprobed_status_does_not_contact_broker(self):
        client = native.NativeGatewayClient(None)
        with patch.object(client, "_exchange", side_effect=AssertionError("unexpected contact")):
            self.assertFalse(client.status()["available"])
            with self.assertRaises(ValidationError): client.complete([{"role": "user", "content": "hi"}])
        client = Protocol()
        self.assertFalse(client.status(probe=False)["available"])
        self.assertEqual([], client.calls)

    def test_lossless_decimal_and_digest_validation(self):
        self.assertEqual(2**64-1, native.decimal(str(2**64-1)))
        for value in (True, 1, "01", "-1", "1.0", "١", str(2**64), ""):
            with self.assertRaises(native.NativeInferenceError): native.decimal(value)
        for value in ("a"*63, "A"*64, "z"*64, None):
            with self.assertRaises(native.NativeInferenceError): native.digest(value)

    def test_duplicate_nonfinite_and_non_utf8_json_is_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'"\xff"', b'{'):
            with self.assertRaises(native.NativeInferenceError): native.strict_json(raw)

    def test_canonical_digest_cross_language_vectors(self):
        messages = [{"role": "user", "content": "hello"}]
        output = {"text": "hello", "prompt_tokens": "1", "output_tokens": "1"}
        self.assertEqual("97c789eaa3d9479f0fc8ecfad11bebf8f5d2693dd5073469a198ee3f1b2ff4ce",
                         hashlib.sha256(b"luma-native-gateway-messages-v1\0"+native.canonical(messages)).hexdigest())
        self.assertEqual("186e3180d6090f3943fcae8df5fc45a043a207ce3a14e8be0ef884204d4b3a87",
                         hashlib.sha256(b"luma-native-gateway-result-v1\0"+native.canonical(output)).hexdigest())

    def test_invalid_transport_configuration_fails_before_state_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/"absent"
            for values in ({"LUMA_MODEL_TRANSPORT": "bad"},
                           {"LUMA_MODEL_TRANSPORT": "native-broker", "LUMA_MODEL_API_KEY": "secret"},
                           {"LUMA_MODEL_TRANSPORT": "native-broker", "LUMA_MODEL_ENDPOINT": "http://127.0.0.1:8081"}):
                with self.assertRaises(ValidationError): LumaConfig.from_env(values, data_dir=root)
                self.assertFalse(root.exists())
            config = LumaConfig(root, root/"db", root/"objects", model_transport="native-broker", model_api_key="secret")
            with self.assertRaises(ValidationError): LumaService(config)
            self.assertFalse(root.exists())

    def test_opt_in_transport_selects_native_client_without_http_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            config = LumaConfig.from_env({"LUMA_MODEL_TRANSPORT": "native-broker", "LUMA_MODEL_NAME": MODEL}, data_dir=directory)
            service = LumaService(config)
            self.assertIsInstance(service.models, native.NativeGatewayClient)
            self.assertIsNone(config.model_api_key)
            self.assertIsNone(config.model_endpoint)

    def test_nonreference_uid_never_opens_a_connection(self):
        client = native.NativeGatewayClient(MODEL)
        with patch.object(native.os, "geteuid", return_value=1000), patch.object(native.socket, "socket", side_effect=AssertionError("unexpected socket")):
            with self.assertRaises(native.NativeInferenceError): client._exchange({"operation": "inspect"}, native.boot_ms()+4000)

    def test_framed_client_refuses_nonroot_malformed_substituted_and_expired_replies(self):
        clock = [100]
        class Peer:
            def __init__(self, mode): self.mode, self.sent, self.body = mode, bytearray(), None
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def settimeout(self, value): self.timeout = value
            def connect(self, path): self.path = path
            def getsockopt(self, *args): return struct.pack("3i", 1, 989 if self.mode == "nonroot" else 0, 0)
            def send(self, raw):
                count = min(len(raw), 3)
                self.sent.extend(raw[:count])
                return count
            def recv(self, size):
                if self.mode == "trickle": clock[0] += 200
                if self.body is None:
                    request = native.strict_json(bytes(self.sent[4:]))
                    reply = {"schema_version": 1, "request_id": request["request_id"], "caller": 990,
                             "result": "ok", "status": {"kind": "fixture"}}
                    if self.mode == "schema": reply["schema_version"] = True
                    if self.mode == "caller": reply["caller"] = 0
                    if self.mode == "correlation": reply["request_id"] = "different"
                    if self.mode == "extra": reply["extra"] = True
                    if self.mode == "denial": reply["result"] = "denied"
                    if self.mode == "status": reply["status"] = []
                    raw = native.canonical(reply)
                    if self.mode == "duplicate": raw = raw[:-1]+b',"caller":990}'
                    if self.mode == "utf8": raw = b'"\xff"'
                    length = 0 if self.mode == "zero" else 16385 if self.mode == "oversize" else len(raw)
                    self.body = struct.pack("!I", length)+raw
                    if self.mode == "truncated": self.body = self.body[:-1]
                    if self.mode == "header": self.body = self.body[:3]
                part = self.body[:min(size, 3)]
                self.body = self.body[len(part):]
                return part
        modes = ("nonroot", "schema", "caller", "correlation", "extra", "denial", "status", "duplicate",
                 "utf8", "zero", "oversize", "truncated", "header", "trickle")
        for mode in ("good", *modes):
            with self.subTest(mode=mode):
                clock[0] = 100
                peer = Peer(mode)
                with patch.object(native.os, "geteuid", return_value=990), patch.object(native, "boot_ms", side_effect=lambda: clock[0]), patch.object(native.socket, "socket", return_value=peer):
                    client = native.NativeGatewayClient(MODEL)
                    if mode == "good": self.assertEqual({"kind": "fixture"}, client._exchange({"operation": "inspect"}, 4100))
                    else:
                        with self.assertRaises(native.NativeInferenceError): client._exchange({"operation": "inspect"}, 4100)
                if mode == "nonroot": self.assertEqual(bytearray(), peer.sent)
                self.assertEqual(native.SOCKET, peer.path)

    def test_real_unix_framing_with_root_fixture_peer_and_fragmented_reply(self):
        # geteuid is synthetic here; kernel SO_PEERCRED on the broker is real.
        # Installed broker admission of UID/PIDFD/cgroup is not simulated as passed.
        errors = []
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory)/"control.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(1)
                listener.settimeout(2)
                def serve():
                    try:
                        with listener.accept()[0] as peer:
                            peer.settimeout(2)
                            def exact(size):
                                result = b""
                                while len(result) < size:
                                    part = peer.recv(size-len(result))
                                    if not part: raise AssertionError("truncated fixture request")
                                    result += part
                                return result
                            request = json.loads(exact(struct.unpack("!I", exact(4))[0]))
                            self.assertEqual("resource-gateway", request["action"])
                            self.assertEqual(990, request["caller"])
                            reply = native.canonical({"schema_version": 1, "request_id": request["request_id"],
                                                      "caller": 990, "result": "ok", "status": {"kind": "fixture"}})
                            frame = struct.pack("!I", len(reply))+reply
                            for start in range(0, len(frame), 3): peer.sendall(frame[start:start+3])
                    except BaseException as error: errors.append(error)
                thread = threading.Thread(target=serve)
                thread.start()
                try:
                    with patch.object(native, "SOCKET", path), patch.object(native.os, "geteuid", return_value=990):
                        status = native.NativeGatewayClient(MODEL)._exchange({"operation": "inspect"}, native.boot_ms()+4000)
                    self.assertEqual({"kind": "fixture"}, status)
                finally:
                    thread.join(3)
                self.assertFalse(thread.is_alive())
                self.assertEqual([], errors)


if __name__ == "__main__":
    unittest.main()
