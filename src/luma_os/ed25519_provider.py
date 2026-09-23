"""Public-only Ed25519 verification through a constrained OpenSSL process.

The adapter deliberately has no signing or private-key interface.  It accepts
only raw 32-byte public keys and raw 64-byte signatures, converts public keys
to the RFC 8410 SubjectPublicKeyInfo form, and invokes a provenance-checked
absolute OpenSSL executable with a fixed argument vector.

``verify`` implements the fail-closed ``RawEd25519Verifier`` shape used by the
model-pack contracts.  ``verify_strict`` is available to operators that need
to distinguish an invalid signature from an unavailable or malfunctioning
provider.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from types import MappingProxyType
from typing import Protocol


ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64
MAX_MESSAGE_BYTES = 4 * 1024 * 1024
MAX_PROVIDER_OUTPUT_BYTES = 16 * 1024
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_PUBLIC_KEYS = 256

# RFC 8410: SEQUENCE { SEQUENCE { id-Ed25519 }, BIT STRING <32 raw bytes> }.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}\Z")
_INVALID_SIGNATURE_MARKERS = (
    b"signature verification failure",
    b"signature verification failed",
    b"bad signature",
)
_FIXED_POSIX_OPENSSL_CANDIDATES = (
    Path("/usr/bin/openssl"),
    Path("/bin/openssl"),
    Path("/usr/local/bin/openssl"),
)


class OpenSSLEd25519Error(RuntimeError):
    """Base class for constrained OpenSSL verification failures."""


class OpenSSLEd25519InputError(ValueError, OpenSSLEd25519Error):
    """The public verifier configuration or input is malformed."""


class OpenSSLEd25519ProviderUnavailable(OpenSSLEd25519Error):
    """No provenance-qualified OpenSSL verification provider is available."""


class OpenSSLEd25519ProviderError(OpenSSLEd25519Error):
    """The trusted provider failed, timed out, or violated its process contract."""


@dataclass(frozen=True, slots=True)
class ProviderProcessResult:
    """Bounded result returned by an injected provider runner."""

    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


class ProviderRunner(Protocol):
    """Injectable process boundary used by deterministic cross-platform tests."""

    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> ProviderProcessResult: ...


ProvenanceValidator = Callable[[Path], Path]


def _validate_positive_bound(value: object, field: str, *, maximum: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise OpenSSLEd25519InputError(f"{field} must be numeric")
    result = float(value)
    if not 0 < result <= maximum:
        raise OpenSSLEd25519InputError(f"{field} must be greater than zero and at most {maximum}")
    return result


def _validate_byte_bound(value: object, field: str, *, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise OpenSSLEd25519InputError(
            f"{field} must be an integer from 1 through {maximum}"
        )
    return value


def validate_trusted_openssl_executable(candidate: Path) -> Path:
    """Resolve and validate a root-controlled POSIX OpenSSL executable.

    The resolved executable and every ancestor through ``/`` must be owned by
    uid 0 and must not be group- or world-writable.  Windows callers must
    inject a platform-specific provenance validator; this project cannot infer
    a trustworthy Windows ACL from a pathname.
    """

    if os.name != "posix":
        raise OpenSSLEd25519ProviderUnavailable(
            "default OpenSSL provenance validation is available only on POSIX"
        )
    if not isinstance(candidate, Path) or not candidate.is_absolute():
        raise OpenSSLEd25519ProviderUnavailable(
            "OpenSSL executable must be an absolute path"
        )
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise OpenSSLEd25519ProviderUnavailable(
            "OpenSSL executable is unavailable"
        ) from exc

    paths = (resolved, *resolved.parents)
    for index, path in enumerate(paths):
        try:
            metadata = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise OpenSSLEd25519ProviderUnavailable(
                "OpenSSL executable provenance cannot be inspected"
            ) from exc
        expected_kind = stat.S_ISREG if index == 0 else stat.S_ISDIR
        if not expected_kind(metadata.st_mode):
            raise OpenSSLEd25519ProviderUnavailable(
                "OpenSSL executable provenance contains an unexpected file type"
            )
        if metadata.st_uid != 0:
            raise OpenSSLEd25519ProviderUnavailable(
                "OpenSSL executable and ancestors must be owned by root"
            )
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise OpenSSLEd25519ProviderUnavailable(
                "OpenSSL executable and ancestors must not be group- or world-writable"
            )
    executable_mode = resolved.stat(follow_symlinks=False).st_mode
    if not executable_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise OpenSSLEd25519ProviderUnavailable("OpenSSL path is not executable")
    return resolved


def resolve_trusted_system_openssl() -> Path:
    """Resolve OpenSSL from a fixed path list without consulting ``PATH``."""

    failures: list[OpenSSLEd25519ProviderUnavailable] = []
    for candidate in _FIXED_POSIX_OPENSSL_CANDIDATES:
        try:
            return validate_trusted_openssl_executable(candidate)
        except OpenSSLEd25519ProviderUnavailable as exc:
            failures.append(exc)
    raise OpenSSLEd25519ProviderUnavailable(
        "no trusted OpenSSL executable exists at a fixed system path"
    ) from (failures[-1] if failures else None)


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if os.name == "posix":
        mode = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
        if mode != 0o600:
            raise OpenSSLEd25519ProviderError(
                "verification input file permissions are not private"
            )


def _bounded_subprocess_runner(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
    output_limit_bytes: int,
) -> ProviderProcessResult:
    """Run one fixed OpenSSL command while bounding captured output."""

    try:
        process = subprocess.Popen(
            list(argv),
            cwd=os.fspath(cwd),
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
        )
    except (FileNotFoundError, PermissionError) as exc:
        raise OpenSSLEd25519ProviderUnavailable(
            "trusted OpenSSL executable cannot be started"
        ) from exc
    except OSError as exc:
        raise OpenSSLEd25519ProviderError("OpenSSL process cannot be started") from exc

    if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
        process.kill()
        raise OpenSSLEd25519ProviderError("OpenSSL output pipes were not created")

    outputs = (bytearray(), bytearray())
    total = 0
    lock = threading.Lock()
    overflow = threading.Event()
    reader_errors: list[BaseException] = []

    def drain(stream: object, destination: bytearray) -> None:
        nonlocal total
        try:
            while True:
                block = stream.read(4096)  # type: ignore[attr-defined]
                if not block:
                    return
                with lock:
                    available = max(0, output_limit_bytes - total)
                    accepted = min(len(block), available)
                    destination.extend(block[:accepted])
                    total += accepted
                    if accepted != len(block):
                        overflow.set()
                if overflow.is_set():
                    try:
                        process.kill()
                    except OSError:
                        pass
        except BaseException as exc:  # Preserve reader failures for the caller.
            reader_errors.append(exc)
            try:
                process.kill()
            except OSError:
                pass

    threads = (
        threading.Thread(target=drain, args=(process.stdout, outputs[0]), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, outputs[1]), daemon=True),
    )
    for thread in threads:
        thread.start()
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        for thread in threads:
            thread.join(timeout=1.0)
        process.stdout.close()
        process.stderr.close()
        raise OpenSSLEd25519ProviderError("OpenSSL verification timed out") from exc
    for thread in threads:
        thread.join(timeout=1.0)
    process.stdout.close()
    process.stderr.close()
    if any(thread.is_alive() for thread in threads) or reader_errors:
        raise OpenSSLEd25519ProviderError("OpenSSL output could not be collected safely")
    if overflow.is_set():
        raise OpenSSLEd25519ProviderError("OpenSSL output exceeded its configured bound")
    return ProviderProcessResult(returncode, bytes(outputs[0]), bytes(outputs[1]))


class OpenSSLEd25519PublicKeyVerifier:
    """Public-key primitive compatible with ``signing_trust``.

    The caller supplies the already-selected public key for each operation.
    This class performs no key-ID or trust-policy selection.
    """

    def __init__(
        self,
        *,
        openssl_executable: str | os.PathLike[str] | None = None,
        runner: ProviderRunner | None = None,
        provenance_validator: ProvenanceValidator | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        maximum_message_bytes: int = MAX_MESSAGE_BYTES,
        maximum_output_bytes: int = MAX_PROVIDER_OUTPUT_BYTES,
        temporary_root: str | os.PathLike[str] | None = None,
    ) -> None:
        self._requested_executable: Path | None = None
        if openssl_executable is not None:
            requested = Path(os.fspath(openssl_executable))
            if not requested.is_absolute():
                raise OpenSSLEd25519InputError(
                    "OpenSSL executable must be supplied as an absolute path"
                )
            self._requested_executable = requested
        self._runner = runner or _bounded_subprocess_runner
        if not callable(self._runner):
            raise OpenSSLEd25519InputError("runner must be callable")
        self._provenance_validator = (
            provenance_validator or validate_trusted_openssl_executable
        )
        if not callable(self._provenance_validator):
            raise OpenSSLEd25519InputError("provenance_validator must be callable")
        self._timeout_seconds = _validate_positive_bound(
            timeout_seconds, "timeout_seconds", maximum=30.0
        )
        self._maximum_message_bytes = _validate_byte_bound(
            maximum_message_bytes,
            "maximum_message_bytes",
            maximum=64 * 1024 * 1024,
        )
        self._maximum_output_bytes = _validate_byte_bound(
            maximum_output_bytes,
            "maximum_output_bytes",
            maximum=1024 * 1024,
        )
        self._temporary_root: Path | None = None
        if temporary_root is not None:
            root = Path(os.fspath(temporary_root))
            if not root.is_absolute():
                raise OpenSSLEd25519InputError("temporary_root must be absolute")
            self._temporary_root = root

    def verify(self, message: bytes, signature: bytes, *, public_key: bytes) -> bool:
        """Return ``True`` only after successful trusted-provider verification.

        Invalid signatures, malformed inputs, and provider failures all return
        ``False`` at this protocol boundary.  Operators that require typed
        diagnostics should call :meth:`verify_strict`.
        """

        try:
            return self.verify_strict(message, signature, public_key=public_key)
        except OpenSSLEd25519Error:
            return False

    def verify_strict(
        self,
        message: bytes,
        signature: bytes,
        *,
        public_key: bytes,
    ) -> bool:
        """Verify or raise a typed input/provider exception.

        A cryptographically invalid signature is the only ordinary ``False``
        result.  Provider absence, timeout, ambiguous exit, or unsafe
        provenance raises a typed exception instead.
        """

        if type(message) is not bytes:
            raise OpenSSLEd25519InputError("message must be immutable bytes")
        if len(message) > self._maximum_message_bytes:
            raise OpenSSLEd25519InputError("message exceeds the configured bound")
        if type(public_key) is not bytes or len(public_key) != ED25519_PUBLIC_KEY_BYTES:
            raise OpenSSLEd25519InputError(
                "Ed25519 public key must be exactly 32 immutable bytes"
            )
        if type(signature) is not bytes or len(signature) != ED25519_SIGNATURE_BYTES:
            return False

        executable = self._resolve_executable()
        try:
            directory = Path(
                tempfile.mkdtemp(
                    prefix="luma-ed25519-",
                    dir=os.fspath(self._temporary_root) if self._temporary_root else None,
                )
            )
        except OSError as exc:
            raise OpenSSLEd25519ProviderError(
                "private verification workspace cannot be created"
            ) from exc
        try:
            try:
                if os.name == "posix":
                    os.chmod(directory, 0o700)
                    mode = stat.S_IMODE(directory.stat(follow_symlinks=False).st_mode)
                    if mode != 0o700:
                        raise OpenSSLEd25519ProviderError(
                            "verification temporary directory is not private"
                        )
                key_path = directory / "public-key.der"
                message_path = directory / "message.bin"
                signature_path = directory / "signature.bin"
                config_path = directory / "openssl.cnf"
                _write_exclusive(key_path, _ED25519_SPKI_PREFIX + public_key)
                _write_exclusive(message_path, message)
                _write_exclusive(signature_path, signature)
                _write_exclusive(config_path, b"")
            except OpenSSLEd25519Error:
                raise
            except OSError as exc:
                raise OpenSSLEd25519ProviderError(
                    "private verification inputs cannot be prepared"
                ) from exc

            argv = (
                os.fspath(executable),
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                os.fspath(key_path),
                "-keyform",
                "DER",
                "-rawin",
                "-in",
                os.fspath(message_path),
                "-sigfile",
                os.fspath(signature_path),
                "-provider",
                "default",
                "-propquery",
                "provider=default",
            )
            environment = MappingProxyType(
                {
                    "LANG": "C",
                    "LC_ALL": "C",
                    "OPENSSL_CONF": os.fspath(config_path),
                }
            )
            result = self._invoke(
                argv,
                cwd=directory,
                env=environment,
            )
            if result.returncode == 0:
                return True
            combined = (result.stdout + b"\n" + result.stderr).lower()
            if result.returncode == 1 and any(
                marker in combined for marker in _INVALID_SIGNATURE_MARKERS
            ):
                return False
            raise OpenSSLEd25519ProviderError(
                "OpenSSL returned an ambiguous verification failure"
            )
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def _resolve_executable(self) -> Path:
        if self._requested_executable is None:
            return resolve_trusted_system_openssl()
        try:
            resolved = self._provenance_validator(self._requested_executable)
        except OpenSSLEd25519Error:
            raise
        except Exception as exc:
            raise OpenSSLEd25519ProviderUnavailable(
                "OpenSSL executable provenance was rejected"
            ) from exc
        if not isinstance(resolved, Path) or not resolved.is_absolute():
            raise OpenSSLEd25519ProviderUnavailable(
                "provenance validator did not return an absolute executable"
            )
        return resolved

    def _invoke(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        env: Mapping[str, str],
    ) -> ProviderProcessResult:
        try:
            result = self._runner(
                argv,
                cwd=cwd,
                env=env,
                timeout_seconds=self._timeout_seconds,
                output_limit_bytes=self._maximum_output_bytes,
            )
        except OpenSSLEd25519Error:
            raise
        except (FileNotFoundError, PermissionError) as exc:
            raise OpenSSLEd25519ProviderUnavailable(
                "trusted OpenSSL executable cannot be started"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise OpenSSLEd25519ProviderError("OpenSSL verification timed out") from exc
        except OSError as exc:
            raise OpenSSLEd25519ProviderError("OpenSSL verification failed") from exc
        except Exception as exc:
            raise OpenSSLEd25519ProviderError(
                "provider runner violated its execution contract"
            ) from exc
        if not isinstance(result, ProviderProcessResult):
            raise OpenSSLEd25519ProviderError(
                "provider runner returned an invalid result"
            )
        if (
            not isinstance(result.returncode, int)
            or isinstance(result.returncode, bool)
            or type(result.stdout) is not bytes
            or type(result.stderr) is not bytes
        ):
            raise OpenSSLEd25519ProviderError(
                "provider runner returned malformed process data"
            )
        if len(result.stdout) + len(result.stderr) > self._maximum_output_bytes:
            raise OpenSSLEd25519ProviderError(
                "OpenSSL output exceeded its configured bound"
            )
        return result


class OpenSSLEd25519Verifier:
    """Key-ID adapter for the model-pack ``RawEd25519Verifier`` protocol.

    Trust policy chooses and installs this immutable key mapping.  Cryptographic
    work is delegated to :class:`OpenSSLEd25519PublicKeyVerifier`, so the
    public-key primitive used by trust-bundle verification and this key-ID
    adapter share exactly the same hardened process boundary.
    """

    def __init__(
        self,
        public_keys: Mapping[str, bytes],
        *,
        openssl_executable: str | os.PathLike[str] | None = None,
        runner: ProviderRunner | None = None,
        provenance_validator: ProvenanceValidator | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        maximum_message_bytes: int = MAX_MESSAGE_BYTES,
        maximum_output_bytes: int = MAX_PROVIDER_OUTPUT_BYTES,
        temporary_root: str | os.PathLike[str] | None = None,
    ) -> None:
        if not isinstance(public_keys, Mapping) or not public_keys:
            raise OpenSSLEd25519InputError("at least one public key is required")
        if len(public_keys) > MAX_PUBLIC_KEYS:
            raise OpenSSLEd25519InputError("public key count exceeds the safe limit")
        copied: dict[str, bytes] = {}
        for key_id, raw_key in public_keys.items():
            if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
                raise OpenSSLEd25519InputError("public key ID is not canonical")
            if type(raw_key) is not bytes or len(raw_key) != ED25519_PUBLIC_KEY_BYTES:
                raise OpenSSLEd25519InputError(
                    "Ed25519 public keys must be exactly 32 immutable bytes"
                )
            copied[key_id] = raw_key
        self._public_keys = MappingProxyType(copied)
        self._primitive = OpenSSLEd25519PublicKeyVerifier(
            openssl_executable=openssl_executable,
            runner=runner,
            provenance_validator=provenance_validator,
            timeout_seconds=timeout_seconds,
            maximum_message_bytes=maximum_message_bytes,
            maximum_output_bytes=maximum_output_bytes,
            temporary_root=temporary_root,
        )

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        """Fail closed for malformed, unknown, invalid, or unavailable inputs."""

        try:
            return self.verify_strict(message, signature, key_id=key_id)
        except OpenSSLEd25519Error:
            return False

    def verify_strict(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        """Verify using the immutable key mapping or raise a provider error."""

        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            return False
        public_key = self._public_keys.get(key_id)
        if public_key is None:
            return False
        return self._primitive.verify_strict(
            message,
            signature,
            public_key=public_key,
        )


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "ED25519_PUBLIC_KEY_BYTES",
    "ED25519_SIGNATURE_BYTES",
    "MAX_MESSAGE_BYTES",
    "MAX_PROVIDER_OUTPUT_BYTES",
    "OpenSSLEd25519Error",
    "OpenSSLEd25519InputError",
    "OpenSSLEd25519ProviderError",
    "OpenSSLEd25519ProviderUnavailable",
    "OpenSSLEd25519PublicKeyVerifier",
    "OpenSSLEd25519Verifier",
    "ProviderProcessResult",
    "ProviderRunner",
    "resolve_trusted_system_openssl",
    "validate_trusted_openssl_executable",
]
