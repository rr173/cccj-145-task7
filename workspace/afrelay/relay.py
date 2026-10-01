"""审计馈送中继核心。

同步（镜像）侧::

    sync_once():  GET /transparency → 逐叶 GET inclusion/<i>?tree_size=i+1
                  → 独立验签 + 内容地址 + 折根 + prev 链衔接
                  → 单叶单事务落库并把 trusted_tree_size 推到 i+1
    任何一步失败（不可用 / 回退 / 坏签名 / 证明缺口）都**保留**旧的可信
    高度并记录停止原因；恢复后下一轮从同一高度继续。中继绝不生成叶子。

投递（租户）侧：每租户隔离筛选规则与消费位点；短租约发放的包跨越
``[start, end)`` 原始序号连续区间（区间内不匹配的叶子跳过）；包内容与
delivery_id 是已镜像叶子的确定性纯函数，因此超时重投/进程重启返回**同一
delivery_id 与逐字节相同的 JSON**；确认只接受当前包末端，重复确认幂等。
"""

from __future__ import annotations

import json
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
    FilterInvalid,
    FilterLocked,
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


class Relay:
    def __init__(self, conn: sqlite3.Connection, client, packet_secret: bytes, *,
                 default_ttl_seconds: int = 30, batch_size: int = 100,
                 clock: Callable[[], float] | None = None):
        self.db = conn
        self.client = client                      # GatewayClient | None
        self.packet_secret = packet_secret
        self.default_ttl = int(default_ttl_seconds)
        self.batch_size = max(1, int(batch_size))
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
                      *, token: str) -> dict:
        import secrets as pysecrets

        rule = validate_filter(filter_rule)
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
                    cursor_end, filter_locked, created_at)
                   VALUES (?,?,?,?,1,0,0,?)""",
                (tenant_id, name, token_hash(plain), dumps_canon(rule), utcnow()))
            self._event("tenant_created", tenant_id=tenant_id,
                        detail={"name": name, "filter": rule})
            return {"tenant_id": tenant_id, "name": name, "token": plain,
                    "filter": rule, "active": True}

    def set_filter(self, tenant_id: str, filter_rule: dict | None) -> dict:
        rule = validate_filter(filter_rule)
        with self._lock:
            row = self._require_tenant_id(tenant_id)
            if not row["active"]:
                raise TenantInactive("tenant is deactivated")
            # 只要租户已经开始消费（发出过任何投递包，无论是否含匹配记录或
            # 是否已确认），筛选规则即冻结，不允许运行中更改
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

    # ------------------------------------------------------------------ #
    # rejections (isolated audit trail per tenant)
    # ------------------------------------------------------------------ #

    def _reject(self, tenant_id: str, reason: str, *,
                delivery_id: str | None = None, detail: dict | None = None) -> None:
        self._event("reject", tenant_id=tenant_id, delivery_id=delivery_id,
                    reason=reason, detail=detail)

    # ------------------------------------------------------------------ #
    # delivery packets
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

    def _lease_response(self, row: sqlite3.Row, packet: dict, *,
                        redispatched: bool, conflict_holder: bool = False) -> dict:
        expires_epoch = float(row["lease_expires_at"])
        return {
            "delivery": packet,
            "delivery_id": packet["delivery_id"],
            "seq": row["seq"],
            "start_index": row["start_index"],
            "end_index": row["end_index"],
            "lease_owner": row["lease_owner"],
            "lease_expires_at": _iso_at(expires_epoch),
            "lease_expires_epoch": expires_epoch,
            "lease_expired": self._now() >= expires_epoch,
            "lease_count": row["lease_count"],
            "retries": row["lease_count"] - 1,
            "redispatched": redispatched,
        }

    def claim(self, token: str, consumer: str, *,
              ttl_seconds: int | None = None) -> dict:
        """领取（或重放/重投）当前投递包。"""
        if not isinstance(consumer, str) or not consumer:
            from .errors import InvalidBody
            raise InvalidBody("consumer is required")
        ttl = int(ttl_seconds or self.default_ttl)
        with self._lock:
            tenant = self._tenant_by_token(token)
            if not tenant["active"]:
                # 停用检查在任何写事务之前；拒绝本身单独落库且不动位点
                self._reject(tenant["tenant_id"], "tenant_inactive")
                raise TenantInactive("tenant is deactivated")
            tid = tenant["tenant_id"]
            trusted = self._state_row()["trusted_tree_size"]

            self.db.execute("BEGIN IMMEDIATE")
            try:
                active = self.db.execute(
                    "SELECT * FROM deliveries WHERE tenant_id=? AND state='leased'",
                    (tid,)).fetchone()
                if active is not None:
                    resp = self._claim_existing(tenant, active, consumer)
                else:
                    resp = self._claim_new(tenant, consumer, ttl, trusted)
                self.db.execute("COMMIT")
                return resp
            except RelayError as exc:
                # 拒绝：回滚业务写（位点/租约不变），再把拒绝原因独立持久化
                self.db.execute("ROLLBACK")
                if exc.reject_reason:
                    did = exc.detail.get("delivery_id")
                    self._reject(tid, exc.reject_reason, delivery_id=did,
                                 detail=exc.detail)
                raise
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def _claim_existing(self, tenant: sqlite3.Row, row: sqlite3.Row,
                        consumer: str) -> dict:
        packet = json.loads(row["packet_json"])
        expired = self._now() >= float(row["lease_expires_at"])
        same_owner = row["lease_owner"] == consumer
        if not expired and not same_owner:
            # 双消费者抢租约：活动短租约只属于当前 holder
            raise LeaseConflict(
                f"delivery {row['delivery_id']} is leased to "
                f"{row['lease_owner']} until {row['lease_expires_at']}",
                detail={"lease_owner": row["lease_owner"],
                        "lease_expires_at": _iso_at(float(row["lease_expires_at"])),
                        "delivery_id": row["delivery_id"],
                        "challenger": consumer})
        if not expired and same_owner:
            # 租约内重复拉取：同 delivery_id、逐字节相同的包
            return self._lease_response(row, packet, redispatched=False)
        # 租约已超时：回收并以相同 delivery_id/包字节重投（同 consumer 或新
        # consumer 都一样——超时后任何人都可接租，但旧租约的确认会被拒绝）
        expires_epoch = self._now() + self.default_ttl
        self.db.execute(
            """UPDATE deliveries
               SET lease_owner=?, lease_expires_at=?, lease_count=lease_count+1,
                   last_leased_at=?
               WHERE delivery_id=?""",
            (consumer, expires_epoch, utcnow(), row["delivery_id"]))
        self._event("delivery_retried", tenant_id=tenant["tenant_id"],
                    delivery_id=row["delivery_id"],
                    detail={"new_owner": consumer,
                            "lease_count": row["lease_count"] + 1})
        row = self.db.execute(
            "SELECT * FROM deliveries WHERE delivery_id=?",
            (row["delivery_id"],)).fetchone()
        return self._lease_response(row, packet, redispatched=True)

    def _claim_new(self, tenant: sqlite3.Row, consumer: str, ttl: int,
                   trusted: int) -> dict:
        tid = tenant["tenant_id"]
        start = tenant["cursor_end"]
        rule = json.loads(tenant["filter_json"])
        if start < trusted:
            candidates = self.db.execute(
                "SELECT * FROM mirror_leaves WHERE leaf_index >= ? "
                "AND leaf_index < ? ORDER BY leaf_index",
                (start, trusted)).fetchall()
        else:
            candidates = []
        matched = []
        for lr in candidates:
            if leaf_matches(rule, json.loads(lr["envelope_json"])):
                matched.append(lr)
                if len(matched) >= self.batch_size:
                    break
        if not matched:
            return {"delivery": None, "tenant_id": tid,
                    "cursor_end": start, "mirror_tree_size": trusted,
                    "backlog": max(0, trusted - start)}

        seq_row = self.db.execute(
            "SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM deliveries "
            "WHERE tenant_id=?", (tid,)).fetchone()
        seq = seq_row["next_seq"]
        packet = self._build_packet(tenant, seq, start, matched)
        now = self._now()
        expires_epoch = now + ttl
        self.db.execute(
            """INSERT INTO deliveries
               (delivery_id, tenant_id, seq, start_index, end_index, packet_json,
                state, lease_owner, lease_expires_at, lease_count,
                created_at, last_leased_at)
               VALUES (?,?,?,?,?,?,'leased',?,?,1,?,?)""",
            (packet["delivery_id"], tid, seq, start, packet["end_index"],
             dumps_canon(packet), consumer, expires_epoch, utcnow(), utcnow()))
        if not tenant["filter_locked"]:
            self.db.execute(
                "UPDATE tenants SET filter_locked=1 WHERE tenant_id=?", (tid,))
        self._event("delivery_issued", tenant_id=tid,
                    delivery_id=packet["delivery_id"],
                    detail={"seq": seq, "start": start,
                            "end": packet["end_index"],
                            "records": packet["leaf_count"], "consumer": consumer})
        row = self.db.execute(
            "SELECT * FROM deliveries WHERE delivery_id=?",
            (packet["delivery_id"],)).fetchone()
        return self._lease_response(row, packet, redispatched=False)

    def ack(self, token: str, delivery_id: str, end_index: int,
            consumer: str) -> dict:
        """确认一个投递包末端；重复确认幂等，其余全部拒绝且不动位点。"""
        with self._lock:
            tenant = self._tenant_by_token(token)
            if not tenant["active"]:
                # 停用拒绝在任何写事务之前；拒绝审计单独落库，位点保留
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
                    # 越租户令牌/未知 id：不泄露归属，不动任何位点
                    raise BadDelivery(
                        "delivery_id does not belong to this tenant",
                        detail={"delivery_id": delivery_id,
                                "end_index": end_index})

                if not isinstance(end_index, int):
                    raise AckEndMismatch("end_index must be an integer",
                                         detail={"delivery_id": delivery_id})

                if row["state"] == "acked":
                    if end_index != row["end_index"]:
                        raise AckEndMismatch(
                            f"delivery already acked at {row['end_index']}; "
                            f"ack {end_index} rejected",
                            detail={"delivery_id": delivery_id,
                                    "ack_end": end_index,
                                    "packet_end": row["end_index"]})
                    self.db.execute("COMMIT")
                    return self._ack_response(row, idempotent=True)

                # 当前在途包：租约有效性先于末端检查
                if consumer != row["lease_owner"]:
                    raise StaleLease(
                        f"lease belongs to {row['lease_owner']}; stale ack rejected",
                        detail={"delivery_id": delivery_id,
                                "holder": row["lease_owner"],
                                "consumer": consumer})
                if self._now() >= float(row["lease_expires_at"]):
                    raise StaleLease(
                        "lease has expired; re-claim and redeliver",
                        detail={"delivery_id": delivery_id})
                if end_index != row["end_index"]:
                    raise AckEndMismatch(
                        f"ack end {end_index} is not the current packet end "
                        f"{row['end_index']}; gap/partial ack rejected",
                        detail={"delivery_id": delivery_id,
                                "ack_end": end_index,
                                "packet_end": row["end_index"]})

                self.db.execute(
                    """UPDATE deliveries
                       SET state='acked', acked_at=?
                       WHERE delivery_id=?""",
                    (utcnow(), delivery_id))
                self.db.execute(
                    "UPDATE tenants SET cursor_end=? WHERE tenant_id=?",
                    (row["end_index"], tid))
                self._event("delivery_acked", tenant_id=tid,
                            delivery_id=delivery_id,
                            detail={"seq": row["seq"], "end": row["end_index"]})
                row = self.db.execute(
                    "SELECT * FROM deliveries WHERE delivery_id=?",
                    (delivery_id,)).fetchone()
                resp = self._ack_response(row, idempotent=False)
                self.db.execute("COMMIT")
                return resp
            except RelayError as exc:
                # 拒绝：先回滚（位点/租约/包状态一律不动），再独立记录拒绝
                self.db.execute("ROLLBACK")
                if exc.reject_reason:
                    self._reject(tid, exc.reject_reason,
                                 delivery_id=exc.detail.get("delivery_id"),
                                 detail=exc.detail)
                raise
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def _ack_response(self, row: sqlite3.Row, *, idempotent: bool) -> dict:
        return {"delivery_id": row["delivery_id"], "tenant_id": row["tenant_id"],
                "seq": row["seq"], "end_index": row["end_index"],
                "state": "acked", "idempotent": idempotent,
                "cursor_end": row["end_index"],
                "acknowledged_at": row["acked_at"]}

    # ------------------------------------------------------------------ #
    # status / observability
    # ------------------------------------------------------------------ #

    def _tenant_brief(self, row: sqlite3.Row) -> dict:
        trusted = self._state_row()["trusted_tree_size"]
        active = self.db.execute(
            "SELECT * FROM deliveries WHERE tenant_id=? AND state='leased'",
            (row["tenant_id"],)).fetchone()
        rule = json.loads(row["filter_json"])
        matching = self._backlog_matching(row, trusted)
        out = {
            "tenant_id": row["tenant_id"],
            "name": row["name"],
            "active": bool(row["active"]),
            "filter": rule,
            "filter_locked": bool(row["filter_locked"]),
            "cursor_end": row["cursor_end"],
            "mirror_tree_size": trusted,
            "backlog": max(0, trusted - row["cursor_end"]),
            "backlog_matching": matching,
            "disabled_reason": row["disable_reason"],
        }
        if active is not None:
            out["current_delivery"] = {
                "delivery_id": active["delivery_id"],
                "seq": active["seq"],
                "start_index": active["start_index"],
                "end_index": active["end_index"],
                "lease_owner": active["lease_owner"],
                "lease_expires_at": _iso_at(float(active["lease_expires_at"])),
                "lease_expired": self._now() >= float(active["lease_expires_at"]),
                "lease_count": active["lease_count"],
                "retries": active["lease_count"] - 1,
                "last_leased_at": active["last_leased_at"],
            }
        else:
            out["current_delivery"] = None
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
