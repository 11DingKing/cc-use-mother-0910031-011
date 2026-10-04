"""领域异常：统一映射到 HTTP 状态码与错误码。"""
from __future__ import annotations


class DomainError(Exception):
    status = 400
    code = "DOMAIN_ERROR"


class ValidationError(DomainError):
    status = 400
    code = "VALIDATION"


class Unauthorized(DomainError):
    status = 401
    code = "UNAUTHORIZED"


class Forbidden(DomainError):
    status = 403
    code = "FORBIDDEN"


class NotFound(DomainError):
    status = 404
    code = "NOT_FOUND"


class StateConflict(DomainError):
    """当前状态不允许该操作。"""

    status = 409
    code = "STATE_CONFLICT"


class LeaseConflict(DomainError):
    """租约被他人持有、令牌不匹配或已过期。"""

    status = 409
    code = "LEASE_CONFLICT"


class LeaseRequired(LeaseConflict):
    """处置操作需要有效租约令牌。"""

    code = "LEASE_REQUIRED"


class DomainViolation(DomainError):
    """违反领域规则（如存在生效中的临时措施时归档）。"""

    status = 422
    code = "DOMAIN_VIOLATION"
