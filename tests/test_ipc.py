from __future__ import annotations

import json
from pathlib import Path
import struct
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.ipc import (  # noqa: E402
    IpcDeadlineExceeded,
    IpcEnvelope,
    IpcMalformed,
    IpcPeerMismatch,
    decode_frame,
    encode_frame,
)


class IpcContractTests(unittest.TestCase):
    def envelope(self) -> IpcEnvelope:
        return IpcEnvelope(
            request_id="request-1",
            caller="luma-control",
            method="resource.admit",
            deadline_unix_ms=2000,
            payload={"bytes": 1024},
            idempotency_key="admit-1",
            lease_id="lease-1",
            lease_generation=1,
        )

    def test_round_trip_requires_authenticated_matching_peer_and_future_deadline(self) -> None:
        envelope = self.envelope()
        decoded = decode_frame(
            encode_frame(envelope),
            peer_identity="luma-control",
            now_unix_ms=1000,
        )
        self.assertEqual(envelope, decoded)

    def test_peer_deadline_length_and_utf8_fail_closed(self) -> None:
        frame = encode_frame(self.envelope())
        with self.assertRaises(IpcPeerMismatch):
            decode_frame(frame, peer_identity="other-service", now_unix_ms=1000)
        with self.assertRaises(IpcDeadlineExceeded):
            decode_frame(frame, peer_identity="luma-control", now_unix_ms=2000)
        with self.assertRaises(IpcMalformed):
            decode_frame(frame[:-1], peer_identity="luma-control", now_unix_ms=1000)
        with self.assertRaises(IpcMalformed):
            decode_frame(struct.pack(">I", 1) + b"\xff", peer_identity="luma-control", now_unix_ms=1000)

    def test_unknown_fields_oversize_and_partial_lease_are_rejected(self) -> None:
        document = self.envelope().as_dict()
        document["ambient_authority"] = True
        body = json.dumps(document).encode("utf-8")
        frame = struct.pack(">I", len(body)) + body
        with self.assertRaises(IpcMalformed):
            decode_frame(frame, peer_identity="luma-control", now_unix_ms=1000)
        with self.assertRaises(IpcMalformed):
            encode_frame(self.envelope(), max_frame_bytes=8)
        with self.assertRaises(IpcMalformed):
            IpcEnvelope("r", "c", "m", 1, {}, lease_id="lease-only")


if __name__ == "__main__":
    unittest.main()
