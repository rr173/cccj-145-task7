"""中继错误：稳定机器码 + HTTP 状态 + 拒绝归类。

``reject_reason`` 为真的错误表示租户请求被安全拒绝且**不移动消费位点**，
会落入租户隔离的拒绝日志并显示在运维页。
"""

from __future__ import annotations


class RelayError(Exception):
    code = "relay_error"
    status = 500
    reject_reason: str | None = None  # 非空表示这是一条对外可见的拒绝原因

    def __init__(self, message: str = "", *, detail: dict | None = None):
        super().__init__(message or self.code)
        self.message = message or self.code
        self.detail = detail or {}

    def to_dict(self) -> dict:
        d = {"error": self.code, "message": self.message}
        d.update(self.detail)
        return d


class InvalidBody(RelayError):
    code = "invalid_body"
    status = 400


class Unauthorized(RelayError):
    code = "unauthorized"
    status = 401


class TenantInactive(RelayError):
    """已停用租户的一切投递/确认请求都拒绝且不动位点。"""

    code = "tenant_inactive"
    status = 403
    reject_reason = "tenant_inactive"


class FilterLocked(RelayError):
    """租户一旦开始消费（有在途/已确认投递），其筛选规则即冻结。"""

    code = "filter_locked"
    status = 409
    reject_reason = "filter_locked"


class LeaseConflict(RelayError):
    """另一个 consumer 持有当前活动短租约（双消费者抢租约）。"""

    code = "lease_conflict"
    status = 409
    reject_reason = "lease_conflict"


class AckEndMismatch(RelayError):
    """确认位置不是当前包末端（跳段确认）。"""

    code = "ack_end_mismatch"
    status = 409
    reject_reason = "ack_end_mismatch"


class StaleLease(RelayError):
    """用旧租约（已超时被回收并改投）确认。"""

    code = "stale_lease"
    status = 409
    reject_reason = "stale_lease"


class BadDelivery(RelayError):
    """delivery_id 不属于该租户（越租户/未知 id）。"""

    code = "bad_delivery"
    status = 403
    reject_reason = "bad_delivery"


class FilterInvalid(RelayError):
    code = "filter_invalid"
    status = 400


class TenantNotFound(RelayError):
    code = "tenant_not_found"
    status = 404


class TenantAlreadyExists(RelayError):
    code = "tenant_already_exists"
    status = 409


class UpstreamError(RelayError):
    """拉取/验证失败：上游暂不可用、回退、坏签名、证明缺口等。

    同步在最后可信位置*停止前进*；这不是 4xx 客户端错误，同步循环捕获后
    只记运维事件，绝不伪造记录。
    """

    code = "upstream_error"
    status = 502

    def __init__(self, message: str = "", *, reason: str = "upstream_unavailable",
                 trusted_size: int | None = None, detail: dict | None = None):
        super().__init__(message, detail=detail)
        self.reason = reason
        self.trusted_size = trusted_size
        self.detail.setdefault("reason", reason)
        if trusted_size is not None:
            self.detail["trusted_tree_size"] = trusted_size
