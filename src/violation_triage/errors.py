"""领域错误及 HTTP 状态映射。"""
from __future__ import annotations


class DomainError(Exception):
    """所有可预期业务错误的基类。"""

    status = 400
    code = "bad_request"

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict:
        result = {"error": self.code, "message": self.message}
        if self.details:
            result["details"] = self.details
        return result


class ValidationError(DomainError):
    status = 400
    code = "validation_failed"


class AuthError(DomainError):
    status = 401
    code = "unauthorized"


class PermissionError(DomainError):  # noqa: A001 - 领域内有意遮蔽内建名
    status = 403
    code = "forbidden"


class NotFoundError(DomainError):
    status = 404
    code = "not_found"


class ConflictError(DomainError):
    status = 409
    code = "conflict"
