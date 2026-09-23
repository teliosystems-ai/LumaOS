from __future__ import annotations

import inspect
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from luma_os.ed25519_provider import (  # noqa: E402
    ED25519_PUBLIC_KEY_BYTES,
    ED25519_SIGNATURE_BYTES,
    OpenSSLEd25519InputError,
    OpenSSLEd25519ProviderError,
    OpenSSLEd25519ProviderUnavailable,
    OpenSSLEd25519PublicKeyVerifier,
    OpenSSLEd25519Verifier,
    ProviderProcessResult,
    resolve_trusted_system_openssl,
)


PUBLIC_KEY = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc"
    "9c982ccf2ec4968cc0cd55f12af4660c"
)
SIGNATURE = bytes.fromhex(
    "92a009a9f0d4cab8720e820b5f642540"
    "a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8"
    "c387b2eaeb4302aeeb00d291612bb0c00"
)
RFC8032_MESSAGE = bytes.fromhex("72")
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class RecordingRunner:
    def __init__(self, result: object = None, error: BaseException | None = None) -> None:
        self.result = result if result is not None else ProviderProcessResult(0)
        self.error = error
        self.calls: list[dict[str, object]] = []

    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        env: object,
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> ProviderProcessResult:
        call = {
            "argv": argv,
            "cwd": cwd,
            "env": dict(env),  # type: ignore[arg-type]
            "timeout_seconds": timeout_seconds,
            "output_limit_bytes": output_limit_bytes,
            "key": (cwd / "public-key.der").read_bytes(),
            "message": (cwd / "message.bin").read_bytes(),
            "signature": (cwd / "signature.bin").read_bytes(),
            "config": (cwd / "openssl.cnf").read_bytes(),
        }
        if os.name == "posix":
            call["directory_mode"] = stat.S_IMODE(cwd.stat().st_mode)
            call["file_modes"] = {
                item.name: stat.S_IMODE(item.stat().st_mode)
                for item in cwd.iterdir()
            }
        self.calls.append(call)
        if self.error is not None:
            raise self.error
        return self.result  # type: ignore[return-value]


def trusted_test_executable() -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return (ROOT / f"test-openssl{suffix}").resolve()


def accept_test_executable(path: Path) -> Path:
    if not path.is_absolute():
        raise AssertionError("test executable was not absolute")
    return path


def available_system_openssl() -> Path | None:
    if os.name != "posix":
        return None
    try:
        return resolve_trusted_system_openssl()
    except OpenSSLEd25519ProviderUnavailable:
        return None


SYSTEM_OPENSSL = available_system_openssl()


class OpenSSLEd25519ProviderTests(unittest.TestCase):
    def make_verifier(
        self,
        runner: RecordingRunner,
        **overrides: object,
    ) -> OpenSSLEd25519Verifier:
        options: dict[str, object] = {
            "openssl_executable": trusted_test_executable(),
            "runner": runner,
            "provenance_validator": accept_test_executable,
        }
        options.update(overrides)
        return OpenSSLEd25519Verifier(
            {"rfc8032-test-2": PUBLIC_KEY},
            **options,  # type: ignore[arg-type]
        )

    def make_public_key_verifier(
        self,
        runner: RecordingRunner,
        **overrides: object,
    ) -> OpenSSLEd25519PublicKeyVerifier:
        options: dict[str, object] = {
            "openssl_executable": trusted_test_executable(),
            "runner": runner,
            "provenance_validator": accept_test_executable,
        }
        options.update(overrides)
        return OpenSSLEd25519PublicKeyVerifier(
            **options,  # type: ignore[arg-type]
        )

    def test_public_key_primitive_matches_signing_trust_protocol(self) -> None:
        runner = RecordingRunner()
        verifier = self.make_public_key_verifier(runner)
        self.assertTrue(
            verifier.verify_strict(
                b"trust bundle",
                SIGNATURE,
                public_key=PUBLIC_KEY,
            )
        )
        self.assertEqual(SPKI_PREFIX + PUBLIC_KEY, runner.calls[0]["key"])
        parameters = inspect.signature(verifier.verify).parameters
        self.assertEqual(
            ["message", "signature", "public_key"],
            list(parameters),
        )
        self.assertNotIn("key_id", parameters)
        self.assertFalse(any("private" in name.lower() for name in parameters))

        for public_key in (
            b"",
            b"x" * (ED25519_PUBLIC_KEY_BYTES - 1),
            b"x" * (ED25519_PUBLIC_KEY_BYTES + 1),
            bytearray(PUBLIC_KEY),
        ):
            with self.assertRaises(OpenSSLEd25519InputError):
                verifier.verify_strict(
                    b"trust bundle",
                    SIGNATURE,
                    public_key=public_key,  # type: ignore[arg-type]
                )
            self.assertFalse(
                verifier.verify(
                    b"trust bundle",
                    SIGNATURE,
                    public_key=public_key,  # type: ignore[arg-type]
                )
            )
        self.assertEqual(1, len(runner.calls))

    def test_public_only_fixed_process_contract_and_private_inputs(self) -> None:
        runner = RecordingRunner(ProviderProcessResult(0, b"verified\n", b""))
        with tempfile.TemporaryDirectory() as temporary:
            verifier = self.make_verifier(
                runner,
                timeout_seconds=2.5,
                maximum_output_bytes=4096,
                temporary_root=Path(temporary).resolve(),
            )
            self.assertTrue(verifier.verify_strict(b"message", SIGNATURE, key_id="rfc8032-test-2"))

        self.assertEqual(1, len(runner.calls))
        call = runner.calls[0]
        argv = call["argv"]
        self.assertIsInstance(argv, tuple)
        self.assertEqual(str(trusted_test_executable()), argv[0])  # type: ignore[index]
        self.assertEqual(
            (
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
            ),
            argv[1:5],  # type: ignore[index]
        )
        self.assertEqual(
            (
                "-keyform",
                "DER",
                "-rawin",
                "-in",
            ),
            argv[6:10],  # type: ignore[index]
        )
        self.assertEqual("-sigfile", argv[11])  # type: ignore[index]
        self.assertEqual(
            ("-provider", "default", "-propquery", "provider=default"),
            argv[13:],  # type: ignore[index]
        )
        for index in (5, 10, 12):
            self.assertTrue(Path(argv[index]).is_absolute())  # type: ignore[index]
        environment = call["env"]
        self.assertEqual({"LANG", "LC_ALL", "OPENSSL_CONF"}, set(environment))  # type: ignore[arg-type]
        self.assertNotIn("PATH", environment)
        self.assertNotIn("HOME", environment)
        self.assertNotIn("OPENSSL_MODULES", environment)
        self.assertEqual(call["config"], b"")
        self.assertEqual(call["key"], SPKI_PREFIX + PUBLIC_KEY)
        self.assertEqual(call["message"], b"message")
        self.assertEqual(call["signature"], SIGNATURE)
        self.assertEqual(call["timeout_seconds"], 2.5)
        self.assertEqual(call["output_limit_bytes"], 4096)
        self.assertFalse(Path(call["cwd"]).exists())  # type: ignore[arg-type]
        if os.name == "posix":
            self.assertEqual(call["directory_mode"], 0o700)
            self.assertEqual({0o600}, set(call["file_modes"].values()))  # type: ignore[union-attr]

        constructor_names = inspect.signature(OpenSSLEd25519Verifier).parameters
        self.assertFalse(any("private" in name.lower() for name in constructor_names))
        self.assertFalse(hasattr(verifier, "sign"))

    def test_invalid_signature_is_false_and_operational_failure_is_typed(self) -> None:
        invalid = RecordingRunner(
            ProviderProcessResult(1, b"Signature Verification Failure\n", b"")
        )
        verifier = self.make_verifier(invalid)
        self.assertFalse(verifier.verify_strict(b"", SIGNATURE, key_id="rfc8032-test-2"))

        ambiguous = RecordingRunner(ProviderProcessResult(1, b"", b"provider load error"))
        verifier = self.make_verifier(ambiguous)
        with self.assertRaises(OpenSSLEd25519ProviderError):
            verifier.verify_strict(b"", SIGNATURE, key_id="rfc8032-test-2")
        self.assertFalse(verifier.verify(b"", SIGNATURE, key_id="rfc8032-test-2"))

    def test_unknown_key_and_noncanonical_signature_never_enter_provider(self) -> None:
        runner = RecordingRunner()
        verifier = self.make_verifier(runner)
        for key_id, signature in (
            ("missing", SIGNATURE),
            ("bad key id!", SIGNATURE),
            ("rfc8032-test-2", SIGNATURE[:-1]),
            ("rfc8032-test-2", SIGNATURE + b"x"),
            ("rfc8032-test-2", bytearray(SIGNATURE)),
        ):
            self.assertFalse(verifier.verify_strict(b"message", signature, key_id=key_id))  # type: ignore[arg-type]
        self.assertEqual([], runner.calls)

    def test_public_key_and_constructor_bounds_are_strict(self) -> None:
        common = {
            "openssl_executable": trusted_test_executable(),
            "runner": RecordingRunner(),
            "provenance_validator": accept_test_executable,
        }
        for key in (b"", b"x" * 31, b"x" * 33, bytearray(PUBLIC_KEY)):
            with self.assertRaises(OpenSSLEd25519InputError):
                OpenSSLEd25519Verifier({"key": key}, **common)  # type: ignore[arg-type]
        for key_id in ("", "bad key", "x" * 129):
            with self.assertRaises(OpenSSLEd25519InputError):
                OpenSSLEd25519Verifier({key_id: PUBLIC_KEY}, **common)
        with self.assertRaises(OpenSSLEd25519InputError):
            OpenSSLEd25519Verifier({}, **common)
        with self.assertRaises(OpenSSLEd25519InputError):
            OpenSSLEd25519Verifier(
                {"key": PUBLIC_KEY},
                openssl_executable="relative-openssl",
                runner=RecordingRunner(),
                provenance_validator=accept_test_executable,
            )
        with self.assertRaises(OpenSSLEd25519InputError):
            self.make_verifier(RecordingRunner(), timeout_seconds=0)
        with self.assertRaises(OpenSSLEd25519InputError):
            self.make_verifier(RecordingRunner(), maximum_output_bytes=True)

    def test_message_bound_is_typed_and_protocol_api_fails_closed(self) -> None:
        runner = RecordingRunner()
        verifier = self.make_verifier(runner, maximum_message_bytes=4)
        self.assertTrue(verifier.verify_strict(b"1234", SIGNATURE, key_id="rfc8032-test-2"))
        with self.assertRaises(OpenSSLEd25519InputError):
            verifier.verify_strict(b"12345", SIGNATURE, key_id="rfc8032-test-2")
        with self.assertRaises(OpenSSLEd25519InputError):
            verifier.verify_strict(bytearray(b"1234"), SIGNATURE, key_id="rfc8032-test-2")  # type: ignore[arg-type]
        self.assertFalse(verifier.verify(b"12345", SIGNATURE, key_id="rfc8032-test-2"))

    def test_provenance_is_rechecked_and_unavailable_is_typed(self) -> None:
        observed: list[Path] = []

        def provenance(path: Path) -> Path:
            observed.append(path)
            if len(observed) > 1:
                raise OpenSSLEd25519ProviderUnavailable("revoked executable")
            return path

        runner = RecordingRunner()
        verifier = self.make_verifier(runner, provenance_validator=provenance)
        self.assertTrue(verifier.verify_strict(b"first", SIGNATURE, key_id="rfc8032-test-2"))
        with self.assertRaises(OpenSSLEd25519ProviderUnavailable):
            verifier.verify_strict(b"second", SIGNATURE, key_id="rfc8032-test-2")
        self.assertFalse(verifier.verify(b"third", SIGNATURE, key_id="rfc8032-test-2"))
        self.assertEqual(3, len(observed))
        self.assertEqual(1, len(runner.calls))

        def broken_provenance(_path: Path) -> Path:
            raise RuntimeError("platform provenance backend failed")

        verifier = self.make_verifier(
            RecordingRunner(),
            provenance_validator=broken_provenance,
        )
        with self.assertRaises(OpenSSLEd25519ProviderUnavailable):
            verifier.verify_strict(b"message", SIGNATURE, key_id="rfc8032-test-2")
        self.assertFalse(
            verifier.verify(b"message", SIGNATURE, key_id="rfc8032-test-2")
        )

    def test_workspace_creation_failure_is_typed_and_fail_closed(self) -> None:
        verifier = self.make_verifier(RecordingRunner())
        with mock.patch(
            "luma_os.ed25519_provider.tempfile.mkdtemp",
            side_effect=OSError("workspace unavailable"),
        ):
            with self.assertRaises(OpenSSLEd25519ProviderError):
                verifier.verify_strict(
                    b"message", SIGNATURE, key_id="rfc8032-test-2"
                )
            self.assertFalse(
                verifier.verify(b"message", SIGNATURE, key_id="rfc8032-test-2")
            )

    def test_runner_failures_and_output_contract_are_fail_closed(self) -> None:
        failures: tuple[tuple[RecordingRunner, type[BaseException]], ...] = (
            (RecordingRunner(error=FileNotFoundError()), OpenSSLEd25519ProviderUnavailable),
            (
                RecordingRunner(
                    error=subprocess.TimeoutExpired(cmd="openssl", timeout=1)
                ),
                OpenSSLEd25519ProviderError,
            ),
            (RecordingRunner(result=object()), OpenSSLEd25519ProviderError),
            (
                RecordingRunner(result=ProviderProcessResult(0, b"x" * 17, b"")),
                OpenSSLEd25519ProviderError,
            ),
        )
        for runner, error_type in failures:
            with self.subTest(error=error_type.__name__):
                verifier = self.make_verifier(runner, maximum_output_bytes=16)
                with self.assertRaises(error_type):
                    verifier.verify_strict(b"message", SIGNATURE, key_id="rfc8032-test-2")
                self.assertFalse(
                    verifier.verify(b"message", SIGNATURE, key_id="rfc8032-test-2")
                )

    def test_constants_express_the_raw_ed25519_boundary(self) -> None:
        self.assertEqual(32, ED25519_PUBLIC_KEY_BYTES)
        self.assertEqual(64, ED25519_SIGNATURE_BYTES)

    @unittest.skipUnless(
        SYSTEM_OPENSSL is not None,
        "a provenance-qualified fixed-path POSIX OpenSSL is not available",
    )
    def test_rfc8032_vector_with_real_trusted_openssl(self) -> None:
        primitive = OpenSSLEd25519PublicKeyVerifier()
        self.assertTrue(
            primitive.verify_strict(
                RFC8032_MESSAGE, SIGNATURE, public_key=PUBLIC_KEY
            )
        )
        altered = SIGNATURE[:-1] + bytes([SIGNATURE[-1] ^ 1])
        self.assertFalse(
            primitive.verify_strict(
                RFC8032_MESSAGE, altered, public_key=PUBLIC_KEY
            )
        )


if __name__ == "__main__":
    unittest.main()
