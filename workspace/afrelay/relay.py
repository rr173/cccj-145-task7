"""审计馈送中继核心。

同步（镜像）侧::

    sync_once():  GET /transparency → 逐叶 GET inclusion/<i>?tree_size=i+1
                  → 独立验签 + 内容地址 + 折根 + prev 链衔接
                  → 单叶单事务落库并把 trusted_tree_size 推到 i+1
    任何一步失败（不可用 / 回退 / 坏签名 / 证明缺口）都**保留**旧的可信
    高度并记录停止原因；恢复后下一轮从同一高度继续。中继绝不生成叶子。

投递（租户）侧 —— 并行窗口 + 连续提交屏障：

* 中继把**相邻、互不重叠**的原始序号区间切成窗口，租给不同 worker 并行
  处理，而不是等上一包确认才发下一包；
* 每个租户有 ``max_inflight`` 个在途窗口槽位（可动态收缩，但收缩**绝不**
  抢走有效持有者，只阻止发放新窗口）；
* 窗口内容与 delivery_id 是已镜像叶子的确定性纯函数：超时被新 worker 接管
  或进程重启后，重新领取返回**同一 delivery_id 与逐字节相同的 JSON**，窗口
  边界永不改变；接管使租约 epoch +1，旧持有者随后的提交以 stale_lease 拒绝；
* 靠后的窗口先完成时**只登记完成事实**（state=completed），可见提交点
  （``cursor_end`` 连续提交屏障）必须等前面的空洞补齐、完成窗口连成稠密
  前缀后才一次推进；单个慢窗口不阻塞其他租户或同租户后续窗口。
"""

from __future__ import annotations

import json
import secrets as pysecrets
import sqlite3
import threading
import time
from typing import Any, Callable

from . import PACKAGE_FORMAT
from .canonical import (
    dumps_canon,
    hmac_hex,
    token_hash,
    utcnow,
)
from .errors import (
    AckEndMismatch,
    BadDelivery,
    DeliveryNotFound,
    FilterInvalid,
    FilterLocked,
    InFlightCapReached,
    InvalidBody,
    InvalidConfig,
    LeaseConflict,
    RelayError,
    StaleLease,
    TenantInactive,
    TenantNotFound,
    TenantAlreadyExists,
    Unauthorized,
    UpstreamError,
)
from .merkle import inclusion_nodes, merkle_root

VALID_EVENT_TYPES = (
    "release_sealed", "release_voided", "share_issued", "share_revoked",
)

MIN_INFLIGHT = 1
MAX_INFLIGHT_HARD = 1024


# --------------------------------------------------------------------------- #
# tenant filters (isolated per tenant; validated, no regex/eval)
# --------------------------------------------------------------------------- #

def validate_filter(rule: Any) -> dict:
    """校验并规范化筛选规则；非法即拒绝（不会产生半租户状态）。"""
    if rule is None:
        rule = {}
    if not isinstance(rule, dict):
        raise FilterInvalid("filter must be an object")
    out: dict[str, Any] = {}
    ets = rule.get("event_types")
    if ets is not None:
        if not isinstance(ets, list) or not ets or \
                not all(isinstance(x, str) for x in ets):
            raise FilterInvalid("filter.event_types must be a non-empty string list")
        bad = [x for x in ets if x not in VALID_EVENT_TYPES]
        if bad:
            raise FilterInvalid("unknown event_types: " + ",".join(sorted(set(bad))))
        out["event_types"] = sorted(set(ets))
    for key in ("event_key_prefix", "subject_prefix"):
        val = rule.get(key)
        if val is not None:
            if not isinstance(val, str):
                raise FilterInvalid(f"filter.{key} must be a string")
            out[key] = val
    pe = rule.get("payload_field_equals")
    if pe is not None:
        if not isinstance(pe, dict) or not pe or \
                not all(isinstance(k, str) for k in pe):
            raise FilterInvalid(
                "filter.payload_field_equals must be a non-empty {field: value}")
        out["payload_field_equals"] = pe
    return out


def leaf_matches(rule: dict, envelope: dict) -> bool:
    ets = rule.get("event_types")
    if ets and envelope.get("event_type") not in ets:
        return False
    kp = rule.get("event_key_prefix")
    if kp and not str(envelope.get("event_key", "")).startswith(kp):
        return False
    sp = rule.get("subject_prefix")
    if sp and not str(envelope.get("subject_id", "")).startswith(sp):
        return False
    pe = rule.get("payload_field_equals")
    if pe:
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            return False
        for field, want in pe.items():
            if payload.get(field) != want:
                return False
    return True


def _clamp_inflight(value: Any) -> int:
    """校验最大在途窗口数配置（建租户/动态收缩共用）。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidConfig("max_inflight must be an integer")
    if value < MIN_INFLIGHT or value > MAX_INFLIGHT_HARD:
        raise InvalidConfig(
            f"max_inflight must be within [{MIN_INFLIGHT},{MAX_INFLIGHT_HARD}]")
    return value


class Relay:
    def __init__(self, conn: sqlite3.Connection, client, packet_secret: bytes, *,
                 default_ttl_seconds: int = 30, batch_size: int = 100,
                 default_max_inflight: int = 8,
                 clock: Callable[[], float] | None = None):
        self.db = conn
        self.client = client                      # GatewayClient | None
        self.packet_secret = packet_secret
        self.default_ttl = max(1, int(default_ttl_seconds))
        self.batch_size = max(1, int(batch_size))
        self.default_max_inflight = _clamp_inflight(default_max_inflight)
        self._clock = clock or time.time
        self._lock = threading.RLock()
        self._poll_thread: threading.Thread | None = None
        self._poll_stop = threading.Event()

    def close(self):
        self.stop_poller()
        self.db.close()

    # ------------------------------------------------------------------ #
    # internal helpers
    # ------------------------------------------------------------------ #

    def _now(self) -> float:
        return self._clock()

    def _state_row(self) -> sqlite3.Row:
        return self.db.execute("SELECT * FROM mirror_state WHERE id=1").fetchone()

    def _event(self, kind: str, *, tenant_id: str | None = None,
               delivery_id: str | None = None, reason: str | None = None,
               detail: dict | None = None) -> None:
        self.db.execute(
            """INSERT INTO relay_events
               (created_at, kind, tenant_id, delivery_id, reason, detail_json)
               VALUES (?,?,?,?,?,?)""",
            (utcnow(), kind, tenant_id, delivery_id, reason,
             dumps_canon(detail or {})))

    def _set_state(self, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        self.db.execute(
            f"UPDATE mirror_state SET {cols} WHERE id=1", tuple(fields.values()))

    # ------------------------------------------------------------------ #
    # synchronisation: pull signed heads + leaves, verify, then mirror
    # ------------------------------------------------------------------ #

    def sync_once(self) -> dict:
        """执行一轮拉取；返回同步报告。失败时停在最后可信位置。"""
        with self._lock:
            if self.client is None:
                return self._sync_fail(
                    UpstreamError("no upstream gateway configured",
                                  reason="upstream_unavailable"))
            trusted = self._state_row()["trusted_tree_size"]
            try:
                up = self.client.state()
                up_size = int(up["tree_size"])
                up_frozen = bool(up.get("frozen"))
                frozen_size = up.get("frozen_tree_size")
                frozen_size = int(frozen_size) if isinstance(frozen_size, int) else None
                self.db.execute("BEGIN IMMEDIATE")
                self._set_state(
                    upstream_tree_size=up_size,
                    upstream_frozen=1 if up_frozen else 0,
                    frozen_reason=up.get("freeze_reason"),
                    frozen_tree_size=frozen_size,
                    last_attempt_at=utcnow())
                self.db.execute("COMMIT")

                if up_size < trusted:
                    raise UpstreamError(
                        f"upstream tree size {up_size} is behind trusted {trusted}; "
                        "refusing to move backwards",
                        reason="upstream_rollback", trusted_size=trusted)

                target = up_size
                frozen_cap = False
                if up_frozen and frozen_size is not None and frozen_size < target:
                    # 冻结的上游只允许读到最后可信（冻结）树头
                    target = frozen_size
                    frozen_cap = True
                if target < trusted:
                    raise UpstreamError(
                        f"upstream frozen cap {target} is behind trusted {trusted}",
                        reason="upstream_rollback", trusted_size=trusted)

                first_ever = self._state_row()["synced"] == 0
                advanced_from = trusted
                if trusted == 0 and not self._has_cp(0):
                    self._anchor_genesis()

                # 交叉核对：状态文档声称的根必须与我们*将要镜像到*的高度
                # （冻结时即冻结封顶高度/最后可信树头）的已签名 checkpoint
                # 一致；状态文档本身未签名，不能单独作为信任依据
                head_size = target
                signed = self.db.execute(
                    "SELECT root_hash FROM mirror_cps WHERE tree_size=?",
                    (head_size,)).fetchone()
                if signed is None:
                    head_cp = self.client.verify_checkpoint_doc(
                        self.client.checkpoint(head_size))
                    signed_root = head_cp["root_hash"]
                else:
                    signed_root = signed["root_hash"]
                state_root = up.get("root_hash")
                if not frozen_cap and state_root != signed_root:
                    raise UpstreamError(
                        "state root disagrees with the signed checkpoint head",
                        reason="upstream_bad_signature", trusted_size=trusted)
                if frozen_cap and state_root != signed_root and up_size == target:
                    # 仅当冻结高度恰好等于当前高度时状态根才必须等于封顶根
                    raise UpstreamError(
                        "state root disagrees with the signed frozen head",
                        reason="upstream_bad_signature", trusted_size=trusted)

                for index in range(trusted, target):
                    self._mirror_one(index)

                new_trusted = self._state_row()["trusted_tree_size"]
                status = "caught_up_frozen" if frozen_cap else "caught_up"
                self.db.execute("BEGIN IMMEDIATE")
                self._set_state(
                    synced=1, last_status=status, last_stop_reason=None,
                    last_error=None, consecutive_failures=0,
                    last_success_at=utcnow())
                if first_ever:
                    self._event("first_sync", detail={"tree_size": new_trusted})
                if new_trusted > advanced_from:
                    self._event("mirror_advanced",
                                detail={"from": advanced_from, "to": new_trusted})
                if frozen_cap:
                    self._event("upstream_frozen_cap",
                                detail={"trusted_tree_size": new_trusted,
                                        "reason": up.get("freeze_reason")})
                self.db.execute("COMMIT")
                return {"ok": True, "trusted_tree_size": new_trusted,
                        "upstream_tree_size": up_size, "frozen_cap": frozen_cap,
                        "status": status}
            except UpstreamError as exc:
                return self._sync_fail(exc)
            except Exception as exc:  # defensive: never fabricate, never raise out
                return self._sync_fail(
                    UpstreamError(f"unexpected sync failure: {exc}",
                                  reason="upstream_internal"))

    def _sync_fail(self, exc: UpstreamError) -> dict:
        """记录停止原因；可信高度与镜像内容保持不动。"""
        row = self._state_row()
        try:
            try:
                self.db.execute("ROLLBACK")  # 清理任何未完成事务
            except sqlite3.Error:
                pass
            self.db.execute("BEGIN IMMEDIATE")
            self._set_state(
                last_status="stopped",
                last_stop_reason=exc.reason,
                last_error=exc.message[:500],
                last_attempt_at=utcnow(),
                consecutive_failures=row["consecutive_failures"] + 1)
            self._event("sync_stopped", reason=exc.reason,
                        detail={"error": exc.message,
                                "trusted_tree_size": row["trusted_tree_size"]})
            self.db.execute("COMMIT")
        except sqlite3.Error:
            self.db.execute("ROLLBACK")
        return {"ok": False, "reason": exc.reason, "error": exc.message,
                "trusted_tree_size": row["trusted_tree_size"], "status": "stopped"}

    def _has_cp(self, size: int) -> bool:
        return self.db.execute(
            "SELECT 1 FROM mirror_cps WHERE tree_size=?", (size,)).fetchone() is not None

    def _anchor_genesis(self) -> None:
        doc = self.client.checkpoint(0)
        cp = self.client.verify_checkpoint_doc(doc)
        self.db.execute("BEGIN IMMEDIATE")
        committed = False
        try:
            if not self._has_cp(0):
                self.db.execute(
                    """INSERT INTO mirror_cps
                       (tree_size, root_hash, prev_size, prev_root_hash,
                        checkpoint_json, mirrored_at)
                       VALUES (0, ?, NULL, NULL, ?, ?)""",
                    (cp["root_hash"], dumps_canon(cp), utcnow()))
            self.db.execute("COMMIT")
            committed = True
        finally:
            if not committed:
                self.db.execute("ROLLBACK")

    def _mirror_one(self, index: int) -> None:
        """拉取并验证叶 index（锚定高度 index+1），通过则单事务落库。"""
        doc = self.client.inclusion(index, index + 1)
        v = self.client.verify_inclusion_doc(doc)
        if v["leaf_index"] != index or v["tree_size"] != index + 1:
            raise UpstreamError(
                f"range gap at index {index}: got leaf {v['leaf_index']} "
                f"at size {v['tree_size']}", reason="upstream_proof_gap",
                trusted_size=index)

        self.db.execute("BEGIN IMMEDIATE")
        committed = False
        try:
            cur = self._state_row()["trusted_tree_size"]
            if cur != index:
                raise UpstreamError(
                    f"trusted position moved to {cur} while fetching {index}",
                    reason="upstream_proof_gap", trusted_size=cur)
            prev = self.db.execute(
                "SELECT root_hash FROM mirror_cps WHERE tree_size=?",
                (index,)).fetchone()
            if prev is None:
                raise UpstreamError(
                    f"checkpoint interval gap at height {index}",
                    reason="upstream_proof_gap", trusted_size=index)
            # prev 链必须严格衔接：新 checkpoint 必须引用我们存档的上一高度
            if v["prev_size"] != index or v["prev_root_hash"] != prev["root_hash"]:
                raise UpstreamError(
                    f"checkpoint at {index + 1} is not chained to trusted head "
                    f"{index}", reason="upstream_proof_gap", trusted_size=index)
            dup = self.db.execute(
                "SELECT leaf_index FROM mirror_leaves WHERE event_key=?",
                (v["event_key"],)).fetchone()
            if dup is not None:
                raise UpstreamError(
                    f"event_key {v['event_key']} already mirrored at "
                    f"{dup['leaf_index']}", reason="upstream_proof_gap",
                    trusted_size=index)

            self.db.execute(
                """INSERT INTO mirror_leaves
                   (leaf_index, event_key, event_type, leaf_hash,
                    envelope_json, mirrored_at)
                   VALUES (?,?,?,?,?,?)""",
                (index, v["event_key"], v["event_type"], v["leaf_hash"],
                 dumps_canon(v["envelope"]), utcnow()))
            self.db.execute(
                """INSERT INTO mirror_cps
                   (tree_size, root_hash, prev_size, prev_root_hash,
                    checkpoint_json, mirrored_at)
                   VALUES (?,?,?,?,?,?)""",
                (index + 1, v["root_hash"], index, prev["root_hash"],
                 dumps_canon(v["checkpoint"]), utcnow()))
            self._set_state(trusted_tree_size=index + 1)
            self.db.execute("COMMIT")
            committed = True
        except Exception:
            if not committed:
                self.db.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------------ #
    # background poller (独立线程；只调 sync_once，租户读路径不被其串行阻塞)
    # ------------------------------------------------------------------ #

    def start_poller(self, interval: float = 2.0) -> None:
        with self._lock:
            if self._poll_thread is not None:
                return
            self._poll_stop.clear()

            def loop():
                while not self._poll_stop.wait(interval):
                    self.sync_once()

            t = threading.Thread(target=loop, name="afrelay-sync", daemon=True)
            self._poll_thread = t
            t.start()

    def stop_poller(self) -> None:
        self._poll_stop.set()
        t = self._poll_thread
        if t is not None and t is not threading.current_thread():
            t.join(timeout=5)
        self._poll_thread = None

    # ------------------------------------------------------------------ #
    # admin auth / tenant administration
    # ------------------------------------------------------------------ #

    def check_admin(self, token: str) -> bool:
        row = self.db.execute(
            "SELECT value FROM meta WHERE key='admin_token_sha256'").fetchone()
        return row is not None and row["value"] == token_hash(token)

    def _tenant_by_token(self, token: str) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM tenants WHERE token_sha256=?",
            (token_hash(token),)).fetchone()
        if row is None:
            raise Unauthorized("invalid tenant token")
        return row

    def _require_tenant_id(self, tenant_id: str) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM tenants WHERE tenant_id=?", (tenant_id,)).fetchone()
        if row is None:
            raise TenantNotFound(f"tenant {tenant_id} not found")
        return row

    def create_tenant(self, tenant_id: str, name: str, filter_rule: dict | None,
                      *, token: str, max_inflight: int | None = None) -> dict:
        rule = validate_filter(filter_rule)
        inflight = self.default_max_inflight if max_inflight is None \
            else _clamp_inflight(max_inflight)
        with self._lock:
            exists = self.db.execute(
                "SELECT 1 FROM tenants WHERE tenant_id=? OR name=?",
                (tenant_id, name)).fetchone()
            if exists is not None:
                raise TenantAlreadyExists("tenant id or name already exists")
            plain = "dprt_" + pysecrets.token_urlsafe(24)
            self.db.execute(
                """INSERT INTO tenants
                   (tenant_id, name, token_sha256, filter_json, active,
                    cursor_end, max_inflight, filter_locked, created_at)
                   VALUES (?,?,?,?,1,0,?,0,?)""",
                (tenant_id, name, token_hash(plain), dumps_canon(rule),
                 inflight, utcnow()))
            self._event("tenant_created", tenant_id=tenant_id,
                        detail={"name": name, "filter": rule,
                                "max_inflight": inflight})
            return {"tenant_id": tenant_id, "name": name, "token": plain,
                    "filter": rule, "active": True,
                    "max_inflight": inflight}

    def set_filter(self, tenant_id: str, filter_rule: dict | None) -> dict:
        rule = validate_filter(filter_rule)
        with self._lock:
            row = self._require_tenant_id(tenant_id)
            if not row["active"]:
                raise TenantInactive("tenant is deactivated")
            # 只要租户已经开始消费（发出过任何窗口，无论是否含匹配记录或
            # 是否已提交），筛选规则即冻结，不允许运行中更改
            started = self.db.execute(
                "SELECT 1 FROM deliveries WHERE tenant_id=? LIMIT 1",
                (tenant_id,)).fetchone()
            if started is not None:
                self._reject(tenant_id, "filter_locked",
                             detail={"cursor_end": row["cursor_end"]})
                raise FilterLocked(
                    "filter is locked after delivery started; rule change rejected")
            self.db.execute(
                "UPDATE tenants SET filter_json=? WHERE tenant_id=?",
                (dumps_canon(rule), tenant_id))
            self._event("filter_updated", tenant_id=tenant_id, detail={"filter": rule})
            return {"tenant_id": tenant_id, "filter": rule, "filter_locked": False}

    def set_max_inflight(self, tenant_id: str, max_inflight: int) -> dict:
        """动态设置最大在途窗口数。

        收缩**不抢占**任何有效持有者：只更新上限并立即对新的领取生效。若
        当前在途窗口数仍高于新上限，响应里 ``shrink_pending=True``，这些
        窗口继续属于其持有者（含已完成待补洞的窗口），等它们提交/越过屏障
        后在途数自然降到新上限以下，期间新的领取一律背压。
        """
        new_limit = _clamp_inflight(max_inflight)
        with self._lock:
            row = self._require_tenant_id(tenant_id)
            old_limit = int(row["max_inflight"])
            self.db.execute(
                "UPDATE tenants SET max_inflight=? WHERE tenant_id=?",
                (new_limit, tenant_id))
            inflight = self._inflight_count(tenant_id)
            detail = {"old": old_limit, "new": new_limit,
                      "inflight": inflight,
                      "shrink_pending": new_limit < inflight}
            if new_limit < old_limit:
                kind = "max_inflight_shrunk"
            elif new_limit > old_limit:
                kind = "max_inflight_grown"
            else:
                kind = "max_inflight_unchanged"
            self._event(kind, tenant_id=tenant_id, detail=detail)
            return {"tenant_id": tenant_id, "max_inflight": new_limit,
                    "old_max_inflight": old_limit, "inflight": inflight,
                    "shrink_pending": detail["shrink_pending"]}

    def deactivate_tenant(self, tenant_id: str, reason: str = "") -> dict:
        with self._lock:
            self._require_tenant_id(tenant_id)
            self.db.execute(
                """UPDATE tenants SET active=0, disabled_at=?, disable_reason=?
                   WHERE tenant_id=?""",
                (utcnow(), reason, tenant_id))
            self._event("tenant_deactivated", tenant_id=tenant_id, reason=reason)
            return {"tenant_id": tenant_id, "active": False, "reason": reason}

    def list_tenants(self) -> list[dict]:
        rows = self.db.execute("SELECT * FROM tenants ORDER BY tenant_id").fetchall()
        return [self._tenant_brief(r) for r in rows]

    def tenant_windows(self, tenant_id: str, *, include_committed: bool = False,
                       limit: int = 200) -> dict:
        """单个租户的窗口清单（含连续提交屏障/空洞/阻塞窗口）。"""
        with self._lock:
            self._require_tenant_id(tenant_id)
            summary = self._window_summary(tenant_id)
            if include_committed:
                rows = self.db.execute(
                    "SELECT * FROM deliveries WHERE tenant_id=? ORDER BY seq "
                    "DESC LIMIT ?", (tenant_id, int(limit))).fetchall()
                summary["committed_windows"] = [
                    self._window_view(r) for r in reversed(rows)
                    if r["state"] == "committed"]
            return summary

    def force_expire_window(self, tenant_id: str, delivery_id: str,
                            *, reason: str = "admin_force_expire") -> dict:
        """运维手段：立即让一个在途租约到期，供新 worker 接管（可观察超时接管）。

        不改窗口边界、不登记完成、不动提交屏障；旧持有者随后提交将因 epoch
        失效被拒绝。只允许作用于仍处于 leased 的窗口。
        """
        with self._lock:
            self._require_tenant_id(tenant_id)
            row = self.db.execute(
                "SELECT * FROM deliveries WHERE delivery_id=? AND tenant_id=?",
                (delivery_id, tenant_id)).fetchone()
            if row is None:
                raise DeliveryNotFound(
                    f"delivery {delivery_id} not found for tenant {tenant_id}")
            if row["state"] != "leased":
                raise InvalidConfig(
                    f"window is {row['state']}, not leased; cannot expire")
            self.db.execute(
                "UPDATE deliveries SET lease_expires_at=? WHERE delivery_id=?",
                (str(self._now() - 1.0), delivery_id))
            self._event("window_force_expired", tenant_id=tenant_id,
                        delivery_id=delivery_id, reason=reason,
                        detail={"lease_owner": row["lease_owner"],
                                "lease_count": row["lease_count"],
                                "start": row["start_index"],
                                "end": row["end_index"]})
            return {"delivery_id": delivery_id, "tenant_id": tenant_id,
                    "lease_expires_at": _iso_at(self._now() - 1.0),
                    "state": "leased", "retakeable": True}

    # ------------------------------------------------------------------ #
    # rejections (isolated audit trail per tenant)
    # ------------------------------------------------------------------ #

    def _reject(self, tenant_id: str, reason: str, *,
                delivery_id: str | None = None, detail: dict | None = None) -> None:
        self._event("reject", tenant_id=tenant_id, delivery_id=delivery_id,
                    reason=reason, detail=detail)

    # ------------------------------------------------------------------ #
    # window leases (parallel, non-overlapping, deterministic, replayable)
    # ------------------------------------------------------------------ #

    def _packet_delivery_id(self, tenant_id: str, seq: int, start: int,
                            end: int, leaf_hashes: list[str]) -> str:
        material = dumps_canon({
            "tenant_id": tenant_id, "seq": seq, "start_index": start,
            "end_index": end, "leaf_hashes": leaf_hashes,
        })
        return "afd_" + hmac_hex(self.packet_secret, material.encode("utf-8"))[:32]

    def _build_packet(self, tenant_row: sqlite3.Row, seq: int, start: int,
                      matched: list[sqlite3.Row]) -> dict:
        """从已镜像叶子确定性地构造 afp1 投递包（无租约易变字段）。"""
        end = matched[-1]["leaf_index"] + 1
        leaf_rows = self.db.execute(
            "SELECT leaf_index, leaf_hash FROM mirror_leaves "
            "WHERE leaf_index < ? ORDER BY leaf_index", (end,)).fetchall()
        hashes = [bytes.fromhex(r["leaf_hash"]) for r in leaf_rows]
        root = merkle_root(hashes).hex()
        cp_row = self.db.execute(
            "SELECT checkpoint_json FROM mirror_cps WHERE tree_size=?",
            (end,)).fetchone()
        checkpoint = json.loads(cp_row["checkpoint_json"])

        records = []
        for lr in matched:
            idx = lr["leaf_index"]
            path = [h.hex() for h in inclusion_nodes(hashes, idx)]
            envelope = json.loads(lr["envelope_json"])
            records.append({
                "leaf_index": idx,
                "event_key": lr["event_key"],
                "event_type": lr["event_type"],
                "leaf_hash": lr["leaf_hash"],
                "envelope": envelope,
                "inclusion_path": path,
                "tree_size": end,
                "root_hash": root,
            })
        leaf_hashes = [lr["leaf_hash"] for lr in matched]
        delivery_id = self._packet_delivery_id(
            tenant_row["tenant_id"], seq, start, end, leaf_hashes)
        rule = json.loads(tenant_row["filter_json"])
        body = {
            "packet_version": PACKAGE_FORMAT,
            "delivery_id": delivery_id,
            "tenant_id": tenant_row["tenant_id"],
            "seq": seq,
            "start_index": start,
            "end_index": end,
            "leaf_count": len(records),
            "leaf_hashes": leaf_hashes,
            "filter": rule,
            "records": records,
            "checkpoint": checkpoint,
        }
        body["sig"] = hmac_hex(self.packet_secret,
                               dumps_canon({k: v for k, v in body.items()
                                            if k != "sig"}).encode("utf-8"))
        return body

    # ---- window inventory helpers ----

    def _inflight_count(self, tenant_id: str) -> int:
        """在途窗口数：已租出 + 已完成待补洞（尚未越过提交屏障）。

        已完成（completed）窗口仍占槽位：它的区间还没有越过连续提交屏障，
        与在处理的窗口一样构成租户的在途窗口集合。
        """
        row = self.db.execute(
            "SELECT COUNT(*) c FROM deliveries "
            "WHERE tenant_id=? AND state IN ('leased','completed')",
            (tenant_id,)).fetchone()
        return int(row["c"])

    def _frontier(self, tenant_id: str) -> int:
        """已发放窗口的最远末端（原始序号）；新窗口从这里切，保证相邻不重叠。"""
        row = self.db.execute(
            "SELECT COALESCE(MAX(end_index), 0) f FROM deliveries "
            "WHERE tenant_id=?", (tenant_id,)).fetchone()
        return int(row["f"])

    def _match_range(self, rule: dict, start: int, trusted: int,
                     limit: int) -> list[sqlite3.Row]:
        """在原始序号区间 [start, trusted) 内按序收集至多 limit 条匹配叶子。"""
        if start >= trusted:
            return []
        out: list[sqlite3.Row] = []
        rows = self.db.execute(
            "SELECT * FROM mirror_leaves WHERE leaf_index >= ? AND leaf_index < ? "
            "ORDER BY leaf_index", (start, trusted)).fetchall()
        for lr in rows:
            if leaf_matches(rule, json.loads(lr["envelope_json"])):
                out.append(lr)
                if len(out) >= limit:
                    break
        return out

    def _window_view(self, row: sqlite3.Row) -> dict:
        expires = float(row["lease_expires_at"]) if row["lease_expires_at"] else None
        now = self._now()
        return {
            "delivery_id": row["delivery_id"],
            "seq": row["seq"],
            "start_index": row["start_index"],
            "end_index": row["end_index"],
            "state": row["state"],
            "lease_owner": row["lease_owner"],
            "lease_epoch": int(row["lease_count"]),
            "lease_expires_at": _iso_at(expires) if expires is not None else None,
            "lease_expired": (expires is not None and now >= expires),
            "lease_count": int(row["lease_count"]),
            "retries": int(row["lease_count"]) - 1,
            "created_at": row["created_at"],
            "last_leased_at": row["last_leased_at"],
            "completed_at": row["completed_at"],
            "committed_at": row["committed_at"],
        }

    def _inflight_rows(self, tenant_id: str) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM deliveries WHERE tenant_id=? "
            "AND state IN ('leased','completed') ORDER BY seq",
            (tenant_id,)).fetchall()

    def _window_summary(self, tenant_id: str, *,
                        trusted: int | None = None) -> dict:
        """连续提交屏障 / 在途窗口 / 空洞 / 待发区间（HTTP/CLI/运维页共用）。"""
        if trusted is None:
            trusted = self._state_row()["trusted_tree_size"]
        rows = self._inflight_rows(tenant_id)
        barrier = self.db.execute(
            "SELECT cursor_end, max_inflight FROM tenants WHERE tenant_id=?",
            (tenant_id,)).fetchone()
        cursor = int(barrier["cursor_end"])
        windows = [self._window_view(r) for r in rows]
        # 空洞 = 屏障之后、在途窗口区间里尚未被任何窗口覆盖的原始序号段；
        # 在途窗口覆盖到的区间里，未完成（leased 且未 completed）的最前窗口
        # 就是挡住屏障推进的那一个
        holes: list[dict] = []
        pos = cursor
        blocking = None
        for w in windows:
            if w["start_index"] > pos:
                holes.append({"from": pos, "to": w["start_index"]})
            if w["state"] == "leased" and blocking is None:
                blocking = w
            pos = max(pos, w["end_index"])
        return {
            "commit_barrier": cursor,
            "max_inflight": int(barrier["max_inflight"]),
            "inflight": len(windows),
            "windows": windows,
            "blocking_window": blocking,
            "holes": holes,
            "frontier": self._frontier(tenant_id),
            "mirror_tree_size": trusted,
        }

    # ---- claim ----

    def claim(self, token: str, consumer: str, *,
              ttl_seconds: int | None = None) -> dict:
        """领取一个窗口：租约内重放 / 超时接管 / 发放新的相邻窗口。"""
        if not isinstance(consumer, str) or not consumer:
            raise InvalidBody("consumer is required")
        ttl = max(1, int(ttl_seconds or self.default_ttl))
        with self._lock:
            tenant = self._tenant_by_token(token)
            if not tenant["active"]:
                # 停用检查在任何写事务之前；拒绝本身单独落库且不动屏障
                self._reject(tenant["tenant_id"], "tenant_inactive")
                raise TenantInactive("tenant is deactivated")
            tid = tenant["tenant_id"]
            trusted = self._state_row()["trusted_tree_size"]

            self.db.execute("BEGIN IMMEDIATE")
            try:
                rows = self._inflight_rows(tid)

                # 1) 调用方仍持有**有效**租约：重新领取只回放原窗口标识与
                #    逐字节相同的原始字节（幂等，不消耗第二个槽位）
                mine = next((r for r in rows if r["state"] == "leased"
                             and r["lease_owner"] == consumer
                             and self._now() < float(r["lease_expires_at"])),
                            None)
                if mine is not None:
                    packet = json.loads(mine["packet_json"])
                    self.db.execute("COMMIT")
                    return self._lease_response(
                        mine, packet, redispatched=False,
                        max_inflight=int(tenant["max_inflight"]),
                        inflight=len(rows))

                # 2) 有超时窗口（含已租出未完成）：按窗口顺序接管最前面一个，
                #    边界/字节/delivery_id 不变，只换持有者并令 epoch+1
                expired = next((r for r in rows if r["state"] == "leased"
                                and self._now() >= float(r["lease_expires_at"])),
                               None)
                if expired is not None:
                    resp = self._takeover(tenant, expired, consumer, ttl)
                    self.db.execute("COMMIT")
                    return resp

                # 3) 还有在途槽位 → 发放一个新的相邻窗口
                max_inflight = int(tenant["max_inflight"])
                if len(rows) < max_inflight:
                    resp = self._issue_window(tenant, consumer, ttl, trusted,
                                              inflight=len(rows))
                    self.db.execute("COMMIT")
                    return resp

                # 4) 槽位已满：若调用方在等的“自己的窗口”之外还有新数据可切，
                #    这是并行度背压；否则只是没有可做的活
                pending = self._has_pending(tid, trusted)
                if pending:
                    raise InFlightCapReached(
                        f"max_inflight={max_inflight} windows already leased or "
                        "completed ahead of the barrier; shrink cannot preempt "
                        "holders, retry after commits",
                        detail={"max_inflight": max_inflight,
                                "inflight": len(rows),
                                "commit_barrier": tenant["cursor_end"]})
                # 满槽但没有新数据：若是别的 worker 持有活动租约，保持“窗口
                # 有主”的争抢语义；否则就是暂无工作可领
                other_lease = next((r for r in rows if r["state"] == "leased"),
                                   None)
                if other_lease is not None:
                    raise LeaseConflict(
                        f"delivery {other_lease['delivery_id']} is leased to "
                        f"{other_lease['lease_owner']} until "
                        f"{other_lease['lease_expires_at']}",
                        detail={"lease_owner": other_lease["lease_owner"],
                                "lease_expires_at": _iso_at(float(
                                    other_lease["lease_expires_at"])),
                                "delivery_id": other_lease["delivery_id"],
                                "challenger": consumer})
                return self._idle_response(tenant, trusted, len(rows))
            except RelayError as exc:
                # 拒绝：回滚业务写（屏障/租约/窗口状态不变），再把拒绝原因
                # 独立持久化
                self.db.execute("ROLLBACK")
                if exc.reject_reason:
                    did = exc.detail.get("delivery_id")
                    self._reject(tid, exc.reject_reason, delivery_id=did,
                                 detail=exc.detail)
                raise
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def _has_pending(self, tenant_id: str, trusted: int) -> bool:
        rule = json.loads(self.db.execute(
            "SELECT filter_json FROM tenants WHERE tenant_id=?",
            (tenant_id,)).fetchone()["filter_json"])
        return bool(self._match_range(rule, self._frontier(tenant_id),
                                      trusted, 1))

    def _issue_window(self, tenant: sqlite3.Row, consumer: str, ttl: int,
                      trusted: int, *, inflight: int) -> dict:
        tid = tenant["tenant_id"]
        start = self._frontier(tid)
        rule = json.loads(tenant["filter_json"])
        matched = self._match_range(rule, start, trusted, self.batch_size)
        if not matched:
            return self._idle_response(tenant, trusted, inflight)

        seq_row = self.db.execute(
            "SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM deliveries "
            "WHERE tenant_id=?", (tid,)).fetchone()
        seq = seq_row["next_seq"]
        packet = self._build_packet(tenant, seq, start, matched)
        now = self._now()
        expires_epoch = now + ttl
        lease_token = pysecrets.token_hex(16)
        self.db.execute(
            """INSERT INTO deliveries
               (delivery_id, tenant_id, seq, start_index, end_index, packet_json,
                state, lease_owner, lease_expires_at, lease_count, lease_epoch,
                lease_token, created_at, last_leased_at)
               VALUES (?,?,?,?,?,?,'leased',?,?,1,1,?,?,?)""",
            (packet["delivery_id"], tid, seq, start, packet["end_index"],
             dumps_canon(packet), consumer, expires_epoch, lease_token,
             utcnow(), utcnow()))
        if not tenant["filter_locked"]:
            self.db.execute(
                "UPDATE tenants SET filter_locked=1 WHERE tenant_id=?", (tid,))
        self._event("window_issued", tenant_id=tid,
                    delivery_id=packet["delivery_id"],
                    detail={"seq": seq, "start": start,
                            "end": packet["end_index"],
                            "records": packet["leaf_count"], "consumer": consumer,
                            "inflight": inflight + 1,
                            "max_inflight": tenant["max_inflight"]})
        row = self.db.execute(
            "SELECT * FROM deliveries WHERE delivery_id=?",
            (packet["delivery_id"],)).fetchone()
        return self._lease_response(row, packet, redispatched=False,
                                   max_inflight=int(tenant["max_inflight"]),
                                   inflight=inflight + 1, lease_token=lease_token)

    def _takeover(self, tenant: sqlite3.Row, row: sqlite3.Row,
                  consumer: str, ttl: int) -> dict:
        """超时接管：窗口边界与字节不变，持有者替换，epoch/retries +1。"""
        new_count = int(row["lease_count"]) + 1
        new_token = pysecrets.token_hex(16)
        expires_epoch = self._now() + ttl
        self.db.execute(
            """UPDATE deliveries
               SET lease_owner=?, lease_expires_at=?, lease_count=?,
                   lease_epoch=?, lease_token=?, last_leased_at=?
               WHERE delivery_id=?""",
            (consumer, expires_epoch, new_count, new_count, new_token,
             utcnow(), row["delivery_id"]))
        self._event("window_retaken", tenant_id=tenant["tenant_id"],
                    delivery_id=row["delivery_id"],
                    detail={"old_owner": row["lease_owner"],
                            "new_owner": consumer,
                            "lease_count": new_count,
                            "start": row["start_index"],
                            "end": row["end_index"]})
        packet = json.loads(row["packet_json"])
        row = self.db.execute(
            "SELECT * FROM deliveries WHERE delivery_id=?",
            (row["delivery_id"],)).fetchone()
        inflight = self._inflight_count(tenant["tenant_id"])
        return self._lease_response(row, packet, redispatched=True,
                                   max_inflight=int(tenant["max_inflight"]),
                                   inflight=inflight, lease_token=new_token)

    def _lease_response(self, row: sqlite3.Row, packet: dict, *,
                        redispatched: bool, max_inflight: int, inflight: int,
                        lease_token: str | None = None) -> dict:
        expires_epoch = float(row["lease_expires_at"])
        # lease_token 仅在“本次发放/接管”时作为新机密返回；回放已有租约时
        # 沿用行内保存的值，同一个持有者重新领取必须能继续提交
        token_value = lease_token if lease_token is not None else row["lease_token"]
        return {
            "delivery": packet,
            "delivery_id": packet["delivery_id"],
            "seq": row["seq"],
            "start_index": row["start_index"],
            "end_index": row["end_index"],
            "lease_owner": row["lease_owner"],
            "lease_epoch": int(row["lease_count"]),
            "lease_token": token_value,
            "lease_expires_at": _iso_at(expires_epoch),
            "lease_expires_epoch": expires_epoch,
            "lease_expired": self._now() >= expires_epoch,
            "lease_count": row["lease_count"],
            "retries": row["lease_count"] - 1,
            "redispatched": redispatched,
            "max_inflight": max_inflight,
            "inflight": inflight,
        }

    def _idle_response(self, tenant: sqlite3.Row, trusted: int,
                       inflight: int) -> dict:
        return {"delivery": None, "tenant_id": tenant["tenant_id"],
                "commit_barrier": tenant["cursor_end"],
                "cursor_end": tenant["cursor_end"],
                "mirror_tree_size": trusted,
                "backlog": max(0, trusted - tenant["cursor_end"]),
                "max_inflight": tenant["max_inflight"], "inflight": inflight}

    # ---- complete (ack) ----

    def complete(self, token: str, delivery_id: str, end_index: int,
                 consumer: str, *, lease_token: str | None = None) -> dict:
        """登记一个窗口完成（原 ack）。

        靠后的窗口先完成只登记完成事实；连续提交屏障等前面的空洞补齐后才
        一次推进。任何非法提交（旧 epoch、越权、越过窗口末端、重复变体、
        停用、筛选变更）都被拒绝且**不**推进屏障。
        """
        with self._lock:
            tenant = self._tenant_by_token(token)
            if not tenant["active"]:
                # 停用拒绝在任何写事务之前；拒绝审计单独落库，屏障保留
                self._reject(tenant["tenant_id"], "tenant_inactive",
                             delivery_id=delivery_id)
                raise TenantInactive("tenant is deactivated")
            tid = tenant["tenant_id"]

            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute(
                    "SELECT * FROM deliveries WHERE delivery_id=?",
                    (delivery_id,)).fetchone()
                if row is None or row["tenant_id"] != tid:
                    # 越租户令牌/未知 id：不泄露归属，不动任何屏障
                    raise BadDelivery(
                        "delivery_id does not belong to this tenant",
                        detail={"delivery_id": delivery_id,
                                "end_index": end_index})

                if not isinstance(end_index, int):
                    raise AckEndMismatch("end_index must be an integer",
                                         detail={"delivery_id": delivery_id})

                if row["state"] == "committed":
                    # 已越过屏障的窗口：重复提交幂等，但越过末端仍然拒绝
                    if end_index != row["end_index"]:
                        raise AckEndMismatch(
                            f"delivery already committed at {row['end_index']}; "
                            f"ack {end_index} rejected",
                            detail={"delivery_id": delivery_id,
                                    "ack_end": end_index,
                                    "packet_end": row["end_index"]})
                    self.db.execute("COMMIT")
                    return self._complete_response(row, idempotent=True,
                                                   advanced_to=row["end_index"])

                # leased / completed（在途）：先验当前持有者与 epoch
                self._require_valid_lease(row, consumer, lease_token)

                if end_index != row["end_index"]:
                    # 越过窗口末端（或部分确认）：单个窗口必须整体完成
                    raise AckEndMismatch(
                        f"ack end {end_index} is not window end "
                        f"{row['end_index']}; past-end/partial submit rejected",
                        detail={"delivery_id": delivery_id,
                                "ack_end": end_index,
                                "packet_end": row["end_index"]})

                if row["state"] == "completed":
                    # 同一有效持有者对“已完成待补洞”窗口重复登记：幂等，
                    # 屏障是否推进取决于它此刻是否已成为连续前缀的一部分
                    advanced_to = self._advance_barrier(tid)
                    self.db.execute("COMMIT")
                    row = self._reload(delivery_id)
                    return self._complete_response(
                        row, idempotent=True, advanced_to=advanced_to)

                # 首次登记完成事实
                self.db.execute(
                    "UPDATE deliveries SET state='completed', completed_at=? "
                    "WHERE delivery_id=?", (utcnow(), delivery_id))
                self._event("window_completed", tenant_id=tid,
                            delivery_id=delivery_id,
                            detail={"seq": row["seq"], "start": row["start_index"],
                                    "end": row["end_index"],
                                    "commit_barrier": tenant["cursor_end"]})
                advanced_to = self._advance_barrier(tid)
                self.db.execute("COMMIT")
                row = self._reload(delivery_id)
                return self._complete_response(row, idempotent=False,
                                               advanced_to=advanced_to)
            except RelayError as exc:
                # 拒绝：先回滚（屏障/租约/窗口状态一律不动），再独立记录拒绝
                self.db.execute("ROLLBACK")
                if exc.reject_reason:
                    self._reject(tid, exc.reject_reason,
                                 delivery_id=exc.detail.get("delivery_id"),
                                 detail=exc.detail)
                raise
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    # 向后兼容的方法名
    ack = complete

    def _reload(self, delivery_id: str) -> sqlite3.Row:
        return self.db.execute(
            "SELECT * FROM deliveries WHERE delivery_id=?",
            (delivery_id,)).fetchone()

    def _require_valid_lease(self, row: sqlite3.Row, consumer: str,
                             lease_token: str | None) -> None:
        if consumer != row["lease_owner"]:
            raise StaleLease(
                f"lease belongs to {row['lease_owner']}; stale submit rejected",
                detail={"delivery_id": row["delivery_id"],
                        "holder": row["lease_owner"], "consumer": consumer})
        if self._now() >= float(row["lease_expires_at"]):
            raise StaleLease(
                "lease has expired; window was retaken, old epoch submit rejected",
                detail={"delivery_id": row["delivery_id"],
                        "lease_count": row["lease_count"]})
        # 首个 epoch 沿用无令牌提交（兼容）；一旦发生过接管（lease_count>1），
        # 必须出示当前 epoch 发放的 lease_token —— 旧持有者拿不到新令牌，
        # 即使 consumer 标识相同也会在此被拒绝
        if int(row["lease_count"]) > 1:
            stored = row["lease_token"]
            if not lease_token or lease_token != stored:
                raise StaleLease(
                    "lease_token mismatch: this window has been retaken with a "
                    "new epoch; old holder's submission is rejected",
                    detail={"delivery_id": row["delivery_id"],
                            "lease_count": row["lease_count"]})

    def _advance_barrier(self, tenant_id: str) -> int:
        """把已完成窗口连成的稠密前缀一次越过连续提交屏障。

        从当前 ``cursor_end`` 起按窗口顺序消费 completed 窗口，遇到第一个
        leased（未完成）窗口即停——它前面的空洞没补齐，靠后已完成的窗口
        只能继续等待。返回推进后的屏障末端。
        """
        tenant_row = self.db.execute(
            "SELECT cursor_end FROM tenants WHERE tenant_id=?",
            (tenant_id,)).fetchone()
        barrier = int(tenant_row["cursor_end"])
        rows = self.db.execute(
            "SELECT * FROM deliveries WHERE tenant_id=? AND end_index > ? "
            "ORDER BY seq", (tenant_id, barrier)).fetchall()
        pos = barrier
        advanced = 0
        for r in rows:
            # 窗口在发放时即保证相邻（后一个 start == 前一个 end），这里仍
            # 防御性校验，出现缝隙说明有缺口未补，绝不能跳过
            if r["start_index"] != pos or r["state"] != "completed":
                break
            self.db.execute(
                "UPDATE deliveries SET state='committed', committed_at=? "
                "WHERE delivery_id=?", (utcnow(), r["delivery_id"]))
            pos = int(r["end_index"])
            advanced += 1
        if pos > barrier:
            self.db.execute(
                "UPDATE tenants SET cursor_end=? WHERE tenant_id=?",
                (pos, tenant_id))
            self._event("window_barrier_advanced", tenant_id=tenant_id,
                        detail={"from": barrier, "to": pos,
                                "committed_windows": advanced})
        return pos

    def _complete_response(self, row: sqlite3.Row, *, idempotent: bool,
                           advanced_to: int) -> dict:
        state = "acked" if row["state"] == "committed" else row["state"]
        return {"delivery_id": row["delivery_id"], "tenant_id": row["tenant_id"],
                "seq": row["seq"], "start_index": row["start_index"],
                "end_index": row["end_index"], "state": state,
                "window_state": row["state"],
                "idempotent": idempotent,
                "advanced": bool(advanced_to > int(row["end_index"])
                                 or (row["state"] == "committed"
                                     and not idempotent)),
                "commit_barrier": advanced_to,
                "cursor_end": advanced_to,
                "acknowledged_at": row["completed_at"],
                "committed_at": row["committed_at"]}

    # ------------------------------------------------------------------ #
    # status / observability
    # ------------------------------------------------------------------ #

    def _tenant_brief(self, row: sqlite3.Row) -> dict:
        trusted = self._state_row()["trusted_tree_size"]
        summary = self._window_summary(row["tenant_id"], trusted=trusted)
        windows = summary["windows"]
        rule = json.loads(row["filter_json"])
        matching = self._backlog_matching(row, trusted)
        # current_delivery：在途窗口里最靠前的一个（运维页向后兼容字段）
        current = windows[0] if windows else None
        out = {
            "tenant_id": row["tenant_id"],
            "name": row["name"],
            "active": bool(row["active"]),
            "filter": rule,
            "filter_locked": bool(row["filter_locked"]),
            "cursor_end": row["cursor_end"],
            "commit_barrier": summary["commit_barrier"],
            "max_inflight": summary["max_inflight"],
            "inflight": summary["inflight"],
            "frontier": summary["frontier"],
            "blocking_window": summary["blocking_window"],
            "holes": summary["holes"],
            "windows": windows,
            "mirror_tree_size": trusted,
            "backlog": max(0, trusted - row["cursor_end"]),
            "backlog_matching": matching,
            "disabled_reason": row["disable_reason"],
        }
        out["current_delivery"] = current
        return out

    def _backlog_matching(self, row: sqlite3.Row, trusted: int) -> int:
        if row["cursor_end"] >= trusted:
            return 0
        rule = json.loads(row["filter_json"])
        count = 0
        for lr in self.db.execute(
                "SELECT envelope_json FROM mirror_leaves WHERE leaf_index >= ? "
                "AND leaf_index < ? ORDER BY leaf_index",
                (row["cursor_end"], trusted)).fetchall():
            if leaf_matches(rule, json.loads(lr["envelope_json"])):
                count += 1
        return count

    def mirror_status(self) -> dict:
        row = self._state_row()
        return {
            "trusted_tree_size": row["trusted_tree_size"],
            "upstream_tree_size": row["upstream_tree_size"],
            "upstream_frozen": bool(row["upstream_frozen"]),
            "frozen_reason": row["frozen_reason"],
            "frozen_tree_size": row["frozen_tree_size"],
            "synced": bool(row["synced"]),
            "last_status": row["last_status"],
            "last_stop_reason": row["last_stop_reason"],
            "last_error": row["last_error"],
            "consecutive_failures": row["consecutive_failures"],
            "last_attempt_at": row["last_attempt_at"],
            "last_success_at": row["last_success_at"],
        }

    def list_leaves(self, *, limit: int = 500) -> list[dict]:
        rows = self.db.execute(
            "SELECT leaf_index, event_key, event_type, leaf_hash, mirrored_at "
            "FROM mirror_leaves ORDER BY leaf_index DESC LIMIT ?",
            (min(int(limit), 10000),)).fetchall()
        return [dict(r) for r in rows]

    def recent_events(self, *, tenant_id: str | None = None,
                      limit: int = 50) -> list[dict]:
        if tenant_id:
            rows = self.db.execute(
                "SELECT * FROM relay_events WHERE tenant_id=? "
                "ORDER BY id DESC LIMIT ?", (tenant_id, int(limit))).fetchall()
        else:
            rows = self.db.execute(
                "SELECT * FROM relay_events ORDER BY id DESC LIMIT ?",
                (int(limit),)).fetchall()
        out = []
        for r in reversed(rows):
            out.append({"id": r["id"], "created_at": r["created_at"],
                        "kind": r["kind"], "tenant_id": r["tenant_id"],
                        "delivery_id": r["delivery_id"], "reason": r["reason"],
                        "detail": json.loads(r["detail_json"])})
        return out

    def reject_counts(self, *, tenant_id: str | None = None) -> dict:
        if tenant_id:
            rows = self.db.execute(
                "SELECT reason, COUNT(*) c FROM relay_events "
                "WHERE kind='reject' AND tenant_id=? GROUP BY reason",
                (tenant_id,)).fetchall()
        else:
            rows = self.db.execute(
                "SELECT reason, COUNT(*) c FROM relay_events "
                "WHERE kind='reject' GROUP BY reason").fetchall()
        return {r["reason"]: r["c"] for r in rows}

    def status(self, *, tenant_id: str | None = None, events_limit: int = 40) -> dict:
        with self._lock:
            tenants = self.list_tenants()
            if tenant_id is not None:
                tenants = [t for t in tenants if t["tenant_id"] == tenant_id]
            return {
                "mirror": self.mirror_status(),
                "tenants": tenants,
                "reject_counts": self.reject_counts(tenant_id=tenant_id),
                "events": self.recent_events(tenant_id=tenant_id,
                                             limit=events_limit),
            }

    def tenant_status(self, token: str) -> dict:
        with self._lock:
            row = self._tenant_by_token(token)
            return self.status(tenant_id=row["tenant_id"])


def _iso_at(epoch_seconds: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch_seconds, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ")
