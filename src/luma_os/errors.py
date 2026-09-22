"""Domain errors shared by the Luma OS MVP services and HTTP adapter."""

from __future__ import annotations

from typing import Any


class LumaError(Exception):
    """An expected, safe-to-return service error."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            error["details"] = self.details
        return {"error": error}


class NotFoundError(LumaError):
    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__("not_found", message, status=404, details=details)


class ConflictError(LumaError):
    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__("conflict", message, status=409, details=details)


class AuthorizationError(LumaError):
    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__("forbidden", message, status=403, details=details)


class ValidationError(LumaError):
    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__("validation_error", message, status=422, details=details)
