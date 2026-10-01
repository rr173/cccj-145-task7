"""中继错误：稳定机器码 + HTTP 状态 + 拒绝归类。

``reject_reason`` 为真的错误表示 worker/租户请求被安全拒绝且**不移动任何
窗口状态或提交屏障**，会落入租户隔离的拒绝日志并显示在运维页：

    重复提交          -> 幂等成功（idempotent=true），不是错误
    越过窗口末端      -> window_end_mismatch
    跨租户 window_id  -> bad_window
    旧持有者迟到提交  -> stale_lease（超时接管后 epoch 已前进）
    筛选规则已变更    -> filter_changed
    停用租户          -> tenant_inactive
    抢未超时的他人租约 -> lease_conflict
    达到在途上限      -> inflight_cap_reached
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


class InvalidParam(RelayError):
    code = "invalid_param"
    status = 400


class Unauthorized(RelayError):
    code = "unauthorized"
    status = 401


class TenantInactive(RelayError):
    """已停用租户的一切领取/提交请求都拒绝，屏障与窗口历史保留不动。"""

    code = "tenant_inactive"
    status = 403
    reject_reason = "tenant_inactive"


class BadWindow(RelayError):
    """window_id 不属于该租户（跨租户 / 未知 id）；不泄露归属。"""

    code = "bad_window"
    status = 403
    reject_reason = "bad_window"


class LeaseConflict(RelayError):
    """另一个 worker 仍持有该窗口的有效租约（未超时不得抢）。"""

    code = "lease_conflict"
    status = 409
    reject_reason = "lease_conflict"


class StaleLease(RelayError):
    """旧持有者在超时被接管（epoch 已前进）后迟到提交。"""

    code = "stale_lease"
    status = 409
    reject_reason = "stale_lease"


class WindowEndMismatch(RelayError):
    """提交末端与窗口固定末端不一致（越过窗口末端/部分提交）。"""

    code = "window_end_mismatch"
    status = 409
    reject_reason = "window_end_mismatch"


class FilterChanged(RelayError):
    """在途窗口的筛选版本落后于租户当前筛选版本；提交不得推进屏障。"""

    code = "filter_changed"
    status = 409
    reject_reason = "filter_changed"


class InFlightCap(RelayError):
    """活动（未超时）在途窗口数已达租户 max_inflight。"""

    code = "inflight_cap_reached"
    status = 409
    reject_reason = "inflight_cap_reached"


class TenantNotFound(RelayError):
    code = "tenant_not_found"
    status = 404


class WindowNotFound(RelayError):
    code = "window_not_found"
    status = 404


class TenantAlreadyExists(RelayError):
    code = "tenant_already_exists"
    status = 409


class StreamSealed(RelayError):
    code = "stream_sealed"
    status = 409
