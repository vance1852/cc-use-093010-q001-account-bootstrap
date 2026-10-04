"""服务层可观察错误。"""


class ServiceError(RuntimeError):
    code = "service_error"
    status = 400


class NotFound(ServiceError):
    code = "not_found"
    status = 404


class Conflict(ServiceError):
    code = "conflict"
    status = 409


class Forbidden(ServiceError):
    code = "forbidden"
    status = 403


class InvalidState(ServiceError):
    code = "invalid_state"
    status = 409


class ValidationFailed(ServiceError):
    code = "validation_failed"
    status = 422


class Unauthorized(ServiceError):
    """凭据缺失、伪造或账号不可用。对调用方统一口径，详细原因只进授权审计。"""

    code = "unauthorized"
    status = 401


class MissingCredentials(Unauthorized):
    code = "missing_credentials"


class TokenExpired(Unauthorized):
    code = "token_expired"


class TokenRevoked(Unauthorized):
    code = "token_revoked"
