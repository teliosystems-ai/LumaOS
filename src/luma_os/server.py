"""Loopback-only standard-library HTTP and static-web adapter."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import ipaddress
import json
import mimetypes
import os
from pathlib import Path, PurePosixPath
import secrets
from typing import Any
from urllib.parse import unquote, urlsplit

from .errors import LumaError, NotFoundError, ValidationError
from .service import LumaService


MAX_REQUEST_BYTES = 2 * 1024 * 1024


def is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class LumaHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        service: LumaService,
        *,
        web_root: Path,
        unsafe_allow_network: bool = False,
    ) -> None:
        host, _ = address
        if not is_loopback_host(host) and not unsafe_allow_network:
            raise ValidationError(
                "Non-loopback binding is disabled. Use the explicit unsafe override only in an isolated development environment."
            )
        self.service = service
        self.web_root = web_root.resolve(strict=True)
        self.session_token = secrets.token_urlsafe(32)
        self.bind_host = host
        self.unsafe_allow_network = unsafe_allow_network
        super().__init__(address, LumaRequestHandler)

    @property
    def local_port(self) -> int:
        return int(self.server_address[1])


class LumaRequestHandler(BaseHTTPRequestHandler):
    server: LumaHTTPServer
    server_version = "LumaOS/0.1"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802
        try:
            self._route_get()
        except LumaError as exc:
            self._json(exc.status, exc.as_dict())
        except Exception:
            self._json(500, {"error": {"code": "internal_error", "message": "The local service encountered an error."}})

    def do_POST(self) -> None:  # noqa: N802
        try:
            self._route_post()
        except LumaError as exc:
            self._json(exc.status, exc.as_dict())
        except json.JSONDecodeError:
            self._json(400, {"error": {"code": "invalid_json", "message": "Request body must be valid JSON."}})
        except Exception:
            self._json(500, {"error": {"code": "internal_error", "message": "The local service encountered an error."}})

    def log_message(self, format: str, *args: object) -> None:
        # Avoid printing paths or request bodies. CLI emits its own startup line.
        return

    def _route_get(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/health":
            self._validate_host()
            self._json(200, self.server.service.health(), set_session=True)
            return
        if path.startswith("/api/"):
            self._authorize(mutating=False)
            owner = self._owner()
            if path == "/api/status":
                self._json(200, self.server.service.status())
            elif path == "/api/models/status":
                self._json(200, self.server.service.models.status())
            elif path == "/api/grants":
                self._json(200, {"items": self.server.service.grants.list(owner, include_revoked=True)})
            elif path == "/api/workflows":
                self._json(200, {"items": self.server.service.workflows.list(owner)})
            elif path.startswith("/api/workflows/"):
                workflow_id = self._single_id(path, "/api/workflows/")
                self._json(200, self.server.service.workflows.get(owner, workflow_id))
            elif path == "/api/artifacts":
                self._json(200, {"items": self.server.service.artifacts.list(owner)})
            elif path.startswith("/api/artifacts/") and path.endswith("/content"):
                artifact_id = path[len("/api/artifacts/") : -len("/content")].strip("/")
                if not artifact_id or "/" in artifact_id:
                    raise NotFoundError("API route was not found")
                metadata, content = self.server.service.artifacts.read(owner, artifact_id)
                self.send_response(200)
                self.send_header("Content-Type", str(metadata["media_type"]))
                self.send_header("Content-Length", str(len(content)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Disposition", f"attachment; filename={json.dumps(metadata['filename'])}")
                self.end_headers()
                self.wfile.write(content)
            elif path == "/api/receipts":
                items = self.server.service.receipts.list(owner) + self.server.service.receipts.list("_system")
                items.sort(key=lambda item: int(item["sequence"]), reverse=True)
                self._json(200, {"items": items[:100]})
            else:
                raise NotFoundError("API route was not found")
            return
        self._serve_static(path)

    def _route_post(self) -> None:
        path = urlsplit(self.path).path
        self._authorize(mutating=True)
        owner = self._owner()
        body = self._body()
        if path == "/api/grants/enroll":
            permissions = body.get("permissions")
            scope = body.get("scope", "read")
            if permissions is not None:
                if not isinstance(permissions, list) or not permissions:
                    raise ValidationError("permissions must be a non-empty array")
                permission_set = set(permissions)
                allowed = {"read", "index", "write", "export"}
                if not permission_set <= allowed or "read" not in permission_set:
                    raise ValidationError("permissions must include read and contain only supported values")
                scope = "read_write" if permission_set & {"write", "export"} else "read"
            item = self.server.service.grants.enroll(
                owner,
                str(body.get("path", "")),
                display_name=body.get("display_name"),
                scope=str(scope),
            )
            self._json(201, item)
            return
        if path == "/api/workflows":
            kind = body.get("kind", body.get("type", "invoice_report.v1"))
            if kind not in {"invoice_report.v1", "invoice_to_report"}:
                raise ValidationError("This release supports only invoice_report.v1")
            grant_id = body.get("grant_id")
            files = body.get("files")
            source_path = body.get("source_path")
            if source_path:
                grant_id, relative = self._grant_for_source(owner, str(source_path))
                files = [relative]
            if files is not None and not isinstance(files, list):
                raise ValidationError("files must be an array of relative paths")
            workflow = self.server.service.workflows.submit(
                owner,
                grant_id=str(grant_id) if grant_id else None,
                files=[str(item) for item in files] if files else None,
                source_text=body.get("source_text"),
                source_format=str(body.get("source_format", "text")),
                source_name=str(body.get("source_name", "pasted-invoices.txt")),
                currency=body.get("currency"),
                idempotency_key=body.get("idempotency_key") or self.headers.get("Idempotency-Key"),
            )
            self._json(201, workflow)
            return
        if path.startswith("/api/workflows/") and path.endswith("/run"):
            workflow_id = path[len("/api/workflows/") : -len("/run")].strip("/")
            self._json(200, self.server.service.workflows.run(owner, workflow_id))
            return
        if path.startswith("/api/workflows/") and path.endswith("/manual"):
            workflow_id = path[len("/api/workflows/") : -len("/manual")].strip("/")
            rows = body.get("rows")
            if not isinstance(rows, list):
                raise ValidationError("rows must be an array")
            self._json(200, self.server.service.workflows.provide_manual_rows(owner, workflow_id, rows))
            return
        if path.startswith("/api/workflows/") and path.endswith("/cancel"):
            workflow_id = path[len("/api/workflows/") : -len("/cancel")].strip("/")
            self._json(200, self.server.service.workflows.cancel(owner, workflow_id))
            return
        raise NotFoundError("API route was not found")

    def _grant_for_source(self, owner: str, source_path: str) -> tuple[str, str]:
        if not os.path.isabs(source_path):
            raise ValidationError("source_path must be absolute")
        try:
            # Canonicalization handles platform path aliases such as /var ->
            # /private/var on macOS. The subsequent descriptor-relative open
            # remains the security check and refuses symlink substitution.
            source_absolute = str(Path(source_path).resolve(strict=True))
        except OSError as exc:
            raise ValidationError("source_path does not identify an accessible file") from exc
        matches: list[tuple[int, dict[str, object], str]] = []
        for grant in self.server.service.grants.list(owner):
            root = str(grant["root_path"])
            try:
                if os.path.commonpath((root, source_absolute)) != root:
                    continue
            except ValueError:
                continue
            relative = os.path.relpath(source_absolute, root)
            matches.append((len(root), grant, relative))
        if not matches:
            raise ValidationError("source_path is not covered by an active folder grant")
        _, grant, relative = max(matches, key=lambda item: item[0])
        self.server.service.grants.inspect_file(owner, str(grant["grant_id"]), relative)
        return str(grant["grant_id"]), relative

    def _authorize(self, *, mutating: bool) -> None:
        try:
            self._validate_host()
            bearer = self.headers.get("Authorization", "")
            bearer_token = bearer[7:] if bearer.startswith("Bearer ") else ""
            cookie_token = self._cookie("luma_session")
            bearer_ok = bool(bearer_token) and hmac.compare_digest(bearer_token, self.server.session_token)
            cookie_ok = bool(cookie_token) and hmac.compare_digest(cookie_token, self.server.session_token)
            if not (bearer_ok or cookie_ok):
                raise LumaError("unauthorized", "A valid local session is required", status=401)
            if mutating:
                origin = self.headers.get("Origin")
                if cookie_ok and not bearer_ok and not origin:
                    raise LumaError("origin_required", "Browser mutations require a same-origin Origin header", status=403)
                if origin:
                    parsed = urlsplit(origin)
                    if parsed.scheme != "http" or not self._origin_matches_host(parsed.netloc):
                        raise LumaError("invalid_origin", "Request origin does not match the local service", status=403)
        except LumaError as exc:
            self._record_denial(exc.code)
            raise

    def _validate_host(self) -> None:
        host = self.headers.get("Host", "")
        if not host or not self._host_allowed(host):
            raise LumaError("invalid_host", "Request Host is not permitted", status=403)

    def _host_allowed(self, authority: str) -> bool:
        parsed = urlsplit(f"//{authority}")
        try:
            port = parsed.port
        except ValueError:
            return False
        hostname = (parsed.hostname or "").lower()
        effective_port = 80 if port is None else port
        if effective_port != self.server.local_port:
            return False
        if self.server.unsafe_allow_network:
            return hostname == self.server.bind_host.lower()
        return hostname in {"127.0.0.1", "localhost", "::1"}

    def _origin_matches_host(self, origin_authority: str) -> bool:
        if not self._host_allowed(origin_authority):
            return False
        origin = urlsplit(f"//{origin_authority}")
        host = urlsplit(f"//{self.headers.get('Host', '')}")
        try:
            origin_port = origin.port or 80
            host_port = host.port or 80
        except ValueError:
            return False
        return (origin.hostname or "").lower() == (host.hostname or "").lower() and origin_port == host_port

    def _record_denial(self, reason: str) -> None:
        try:
            self.server.service.receipts.record(
                "_system",
                idempotency_key=f"denied:{secrets.token_hex(16)}",
                effect_type="http.request",
                target=urlsplit(self.path).path[:500],
                status="DENIED",
                result={"reason": reason, "remote": self.client_address[0]},
            )
        except Exception:
            pass

    def _serve_static(self, raw_path: str) -> None:
        self._validate_host()
        decoded = unquote(raw_path)
        relative = "index.html" if decoded in {"", "/"} else decoded.lstrip("/")
        parts = PurePosixPath(relative).parts
        if any(part in {"", ".", ".."} for part in parts):
            raise NotFoundError("Static file was not found")
        destination = self.server.web_root.joinpath(*parts)
        try:
            resolved = destination.resolve(strict=True)
        except OSError as exc:
            raise NotFoundError("Static file was not found") from exc
        if self.server.web_root not in resolved.parents and resolved != self.server.web_root:
            raise NotFoundError("Static file was not found")
        if not resolved.is_file():
            raise NotFoundError("Static file was not found")
        content = resolved.read_bytes()
        media_type = mimetypes.guess_type(resolved.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", f"{media_type}; charset=utf-8" if media_type.startswith("text/") or media_type == "application/javascript" else media_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self._session_header()
        self.end_headers()
        self.wfile.write(content)

    def _body(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise LumaError("unsupported_media_type", "Content-Type must be application/json", status=415)
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise LumaError("invalid_length", "Content-Length is invalid", status=400) from exc
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise LumaError("invalid_length", "JSON request body is empty or too large", status=413 if length > MAX_REQUEST_BYTES else 400)
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValidationError("JSON request body must be an object")
        return value

    def _json(self, status: int, payload: object, *, set_session: bool = False) -> None:
        content = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if set_session:
            self._session_header()
        self.end_headers()
        self.wfile.write(content)

    def _session_header(self) -> None:
        self.send_header("Set-Cookie", f"luma_session={self.server.session_token}; Path=/; HttpOnly; SameSite=Strict")

    def _cookie(self, name: str) -> str | None:
        raw = self.headers.get("Cookie", "")
        for item in raw.split(";"):
            key, separator, value = item.strip().partition("=")
            if separator and key == name:
                return value
        return None

    def _owner(self) -> str:
        # The v0.1 HTTP surface is intentionally single-user. Accepting a
        # caller-selected identity here would turn a cosmetic header into an
        # authorization bypass. Multi-user identity belongs to a later broker.
        requested = self.headers.get("X-Luma-User")
        if requested is not None and requested.strip() != "local-user":
            raise ValidationError("This release exposes only the local-user HTTP workspace")
        return "local-user"

    @staticmethod
    def _single_id(path: str, prefix: str) -> str:
        value = path[len(prefix) :].strip("/")
        if not value or "/" in value:
            raise NotFoundError("API route was not found")
        return value


def create_server(
    service: LumaService,
    *,
    host: str | None = None,
    port: int | None = None,
    web_root: str | os.PathLike[str] | None = None,
    unsafe_allow_network: bool = False,
) -> LumaHTTPServer:
    if web_root:
        root = Path(web_root)
    else:
        module_root = Path(__file__).resolve()
        packaged = module_root.parent / "web"
        source_tree = module_root.parents[2] / "web"
        root = packaged if packaged.is_dir() else source_tree
    return LumaHTTPServer(
        (host or service.config.host, service.config.port if port is None else port),
        service,
        web_root=root,
        unsafe_allow_network=unsafe_allow_network,
    )
