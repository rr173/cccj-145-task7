"""并行窗口中继核心。

窗口（window）语义::

    每个租户有一条只增字节流，按固定 window_size 切成相邻、互不重叠的
    原序区间窗口 seq=0,1,2,...：窗口 i = [i*size, (i+1)*size)。封口
    （seal）前尾窗未填满不发放；封口后尾窗以真实长度定型，边界此后永不
    改变。窗口首次物化时把原始字节 payload 固化，因此超时重投/进程重启
    后重新领取返回**同一 window_id 与逐字节相同的原始字节**。

租约（lease）与栅栏（fencing）::

    claim 可并行领取最多 max_inflight 个活动（未超时）窗口；窗口带单调
    lease_epoch，超时后任意 worker 可接管（epoch+1、retry_count+1），
    旧持有者迟到提交以 stale_lease 拒绝。收缩 max_inflight 只阻止继续
    领取新窗口，绝不抢占仍有效的持有者。

提交（commit）与连续前缀::

    靠后的窗口可以先完成：只登记 completed 事实。连续提交屏障
    commit_barrier 在每次提交后从当前屏障开始，吃掉所有连续 completed
    窗口，一次推进到最长连续前缀末端。前面的空洞补齐前，后面的完成事实
    保留但屏障不动。重复提交幂等、越窗末端、跨租户 id、停用、筛选版本
    变更都不能推进屏障。单个慢窗口不挡同租户后续窗口，也不挡其他租户。
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import threading
import time
from typing import Any, Callable

from .canonical import dumps_canon, hmac_hex, token_hash, utcnow
from .errors import (
    BadWindow,
    FilterChanged,
    InFlightCap,
    InvalidBody,
    InvalidParam,
    LeaseConflict,
    RelayError,
    StaleLease,
    StreamSealed,
    TenantAlreadyExists,
    TenantInactive,
    TenantNotFound,
    Unauthorized,
    WindowEndMismatch,
    WindowNotFound,
)

VALID_EVENT_TYPES = (
    "release_sealed", "release_voided", "share_issued", "share_revoked",
    "record_appended",
)


# --------------------------------------------------------------------------- #
# tenant filters (isolated per tenant; validated, no regex/eval)
# --------------------------------------------------------------------------- #

def validate_filter(rule: Any) -> dict:
    """校验并规范化筛选规则；非法即拒绝（不会产生半租户状态）。"""
    if rule is None:
        rule = {}
    if not isinstance(rule, dict):
        raise InvalidParam("filter must be an object")
    out: dict[str, Any] = {}
    ets = rule.get("event_types")
    if ets is not None:
        if not isinstance(ets, list) or not ets or \
                not all(isinstance(x, str) for x in ets):
            raise InvalidParam("filter.event_types must be a non-empty string list")
        bad = [x for x in ets if x not in VALID_EVENT_TYPES]
        if bad:
            raise InvalidParam("unknown event_types: " + ",".join(sorted(set(bad))))
        out["event_types"] = sorted(set(ets))
    for key in ("event_key_prefix", "subject_prefix", "bytes_prefix"):
        val = rule.get(key)
        if val is not None:
            if not isinstance(val, str):
                raise InvalidParam(f"filter.{key} must be a string")
            out[key] = val
    pe = rule.get("payload_field_equals")
    if pe is not None:
        if not isinstance(pe, dict) or not pe or \
                not all(isinstance(k, str) for k in pe):
            raise InvalidParam(
                "filter.payload_field_equals must be a non-empty {field: value}")
        out["payload_field_equals"] = pe
    return out


def record_matches(rule: dict, record: dict) -> bool:
    ets = rule.get("event_types")
    if ets and record.get("event_type") not in ets:
        return False
    kp = rule.get("event_key_prefix")
    if kp and not str(record.get("event_key", "")).startswith(kp):
        return False
    sp = rule.get("subject_prefix")
    if sp and not str(record.get("subject_id", "")).startswith(sp):
        return False
    pe = rule.get("payload_field_equals")
    if pe:
        payload = record.get("payload")
        if not isinstance(payload, dict):
            return False
        for field, want in pe.items():
            if payload.get(field) != want:
                return False
    return True


def parse_records(payload: bytes) -> list[dict]:
    """把窗口原始字节按行解析成记录（每行一个 JSON 对象；坏行跳过）。"""
    records: list[dict] = []
    for line in payload.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(rec, dict):
            records.append(rec)
    return records


class Relay:
    def __init__(self, conn: sqlite3.Connection, packet_secret: bytes, *,
                 default_ttl_seconds: int = 30,
                 default_window_size: int = 64,
                 default_max_inflight: int = 4,
                 clock: Callable[[], float] | None = None):
        self.db = conn
        self.packet_secret = packet_secret
        self.default_ttl = max(1, int(default_ttl_seconds))
        self.default_window_size = max(1, int(default_window_size))
        self.default_max_inflight = max(1, int(default_max_inflight))
        self._clock = clock or time.time
        self._lock = threading.RLock()

    def close(self):
        self.db.close()

    # ------------------------------------------------------------------ #
    # crash recovery (restart must not change boundaries/completion/order)
    # ------------------------------------------------------------------ #

    def recover(self) -> dict:
        """进程重启后调用：从窗口完成事实重建每个租户的连续提交屏障。

        窗口区间与字节在物化时已固化（``windows`` 行持久），完成事实在
        ``state='completed'``。这里只重算 *连续前缀*：从 seq=0 起吃掉
        completed 窗口到第一个空洞为止。乱序完成不会在重启后越洞推进——
        提交顺序严格等于窗口原序。
        """
        report: dict[str, int] = {}
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                tenants = self.db.execute(
                    "SELECT * FROM tenants ORDER BY tenant_id").fetchall()
                for t in tenants:
                    tid = t["tenant_id"]
                    size = int(t["window_size"])
                    seq = 0
                    barrier = 0
                    while True:
                        w = self.db.execute(
                            "SELECT * FROM windows WHERE tenant_id=? AND seq=?",
                            (tid, seq)).fetchone()
                        if w is None or w["state"] != "completed":
                            break
                        barrier = int(w["end_offset"])
                        seq += 1
                    if barrier != int(t["commit_barrier"]):
                        self.db.execute(
                            "UPDATE tenants SET commit_barrier=? WHERE tenant_id=?",
                            (barrier, tid))
                        self._event("barrier_recovered", tenant_id=tid,
                                    detail={"from": int(t["commit_barrier"]),
                                            "to": barrier})
                    report[tid] = barrier
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
        return report

    # ------------------------------------------------------------------ #
    # internal helpers
    # ------------------------------------------------------------------ #

    def _now(self) -> float:
        return self._clock()

    def _event(self, kind: str, *, tenant_id: str | None = None,
               window_id: str | None = None, reason: str | None = None,
               detail: dict | None = None) -> None:
        self.db.execute(
            """INSERT INTO wrelay_events
               (created_at, kind, tenant_id, window_id, reason, detail_json)
               VALUES (?,?,?,?,?,?)""",
            (utcnow(), kind, tenant_id, window_id, reason,
             dumps_canon(detail or {})))

    def _reject(self, tenant_id: str, reason: str, *,
                window_id: str | None = None, detail: dict | None = None) -> None:
        self._event("reject", tenant_id=tenant_id, window_id=window_id,
                    reason=reason, detail=detail)

    # ------------------------------------------------------------------ #
    # auth / tenant administration
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
                      *, window_size: int | None = None,
                      max_inflight: int | None = None,
                      token: str | None = None) -> dict:
        import secrets as pysecrets

        rule = validate_filter(filter_rule)
        wsize = int(window_size if window_size is not None
                    else self.default_window_size)
        cap = int(max_inflight if max_inflight is not None
                  else self.default_max_inflight)
        if wsize < 1:
            raise InvalidParam("window_size must be >= 1")
        if cap < 1:
            raise InvalidParam("max_inflight must be >= 1")
        with self._lock:
            exists = self.db.execute(
                "SELECT 1 FROM tenants WHERE tenant_id=? OR name=?",
                (tenant_id, name)).fetchone()
            if exists is not None:
                raise TenantAlreadyExists("tenant id or name already exists")
            plain = "dprt_" + pysecrets.token_urlsafe(24)
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute(
                    """INSERT INTO tenants
                       (tenant_id, name, token_sha256, window_size, max_inflight,
                        filter_json, filter_version, active, stream_length,
                        stream_sealed, commit_barrier, created_at)
                       VALUES (?,?,?,?,?,?,?,1,0,0,0,?)""",
                    (tenant_id, name, token_hash(plain), wsize, cap,
                     dumps_canon(rule), 1, utcnow()))
                self._event("tenant_created", tenant_id=tenant_id,
                            detail={"name": name, "filter": rule,
                                    "window_size": wsize, "max_inflight": cap})
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            return {"tenant_id": tenant_id, "name": name, "token": plain,
                    "window_size": wsize, "max_inflight": cap,
                    "filter": rule, "active": True}

    def set_max_inflight(self, tenant_id: str, max_inflight: int) -> dict:
        """动态调整在途上限。

        收缩**不抢占**任何仍有效的持有者：只更新上限，随后的 claim 按新
        上限计数；已有租约自然到期/完成/被接管。放大立即生效。
        """
        if not isinstance(max_inflight, int) or max_inflight < 1:
            raise InvalidParam("max_inflight must be an integer >= 1")
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self._require_tenant_id(tenant_id)
                old = int(row["max_inflight"])
                self.db.execute(
                    "UPDATE tenants SET max_inflight=? WHERE tenant_id=?",
                    (max_inflight, tenant_id))
                self._event("max_inflight_changed", tenant_id=tenant_id,
                            detail={"old": old, "new": max_inflight,
                                    "shrink": max_inflight < old})
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            return {"tenant_id": tenant_id, "max_inflight": max_inflight,
                    "previous": old}

    def set_filter(self, tenant_id: str, filter_rule: dict | None) -> dict:
        """更新筛选规则并把 filter_version 前进一步。

        不抢占、不过期任何活动租约（收缩式安全）：旧窗口仍可完成，但其
        提交以 filter_changed 拒绝，直到它按新版本重投（同持有者租约内
        重领，或超时接管）。尚无窗口的租户改规则不产生在途失配。
        """
        rule = validate_filter(filter_rule)
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self._require_tenant_id(tenant_id)
                if not row["active"]:
                    raise TenantInactive("tenant is deactivated")
                new_version = int(row["filter_version"]) + 1
                self.db.execute(
                    "UPDATE tenants SET filter_json=?, filter_version=? "
                    "WHERE tenant_id=?",
                    (dumps_canon(rule), new_version, tenant_id))
                leased = self.db.execute(
                    "SELECT COUNT(*) c FROM windows WHERE tenant_id=? "
                    "AND state='leased'", (tenant_id,)).fetchone()["c"]
                self._event("filter_updated", tenant_id=tenant_id,
                            detail={"filter": rule,
                                    "filter_version": new_version,
                                    "inflight_windows": int(leased)})
                self.db.execute("COMMIT")
            except RelayError:
                self.db.execute("ROLLBACK")
                raise
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            return {"tenant_id": tenant_id, "filter": rule,
                    "filter_version": new_version,
                    "inflight_windows": int(leased)}

    def deactivate_tenant(self, tenant_id: str, reason: str = "") -> dict:
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self._require_tenant_id(tenant_id)
                self.db.execute(
                    """UPDATE tenants SET active=0, disabled_at=?, disable_reason=?
                       WHERE tenant_id=?""",
                    (utcnow(), reason, tenant_id))
                self._event("tenant_deactivated", tenant_id=tenant_id,
                            reason=reason)
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            return {"tenant_id": tenant_id, "active": False, "reason": reason}

    def list_tenants(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT * FROM tenants ORDER BY tenant_id").fetchall()
        return [self._tenant_brief(r) for r in rows]

    # ------------------------------------------------------------------ #
    # stream ingestion (window source)
    # ------------------------------------------------------------------ #

    def append_bytes(self, tenant_id: str, data: bytes) -> dict:
        if not isinstance(data, (bytes, bytearray)):
            raise InvalidBody("data must be raw bytes")
        data = bytes(data)
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self._require_tenant_id(tenant_id)
                if row["stream_sealed"]:
                    raise StreamSealed("stream is sealed; no more appends")
                seq = self.db.execute(
                    "SELECT COALESCE(MAX(seq), -1) + 1 AS n FROM stream_chunks "
                    "WHERE tenant_id=?", (tenant_id,)).fetchone()["n"]
                self.db.execute(
                    """INSERT INTO stream_chunks
                       (tenant_id, seq, chunk, length, appended_at)
                       VALUES (?,?,?,?,?)""",
                    (tenant_id, seq, data, len(data), utcnow()))
                new_len = int(row["stream_length"]) + len(data)
                self.db.execute(
                    "UPDATE tenants SET stream_length=? WHERE tenant_id=?",
                    (new_len, tenant_id))
                self._event("stream_appended", tenant_id=tenant_id,
                            detail={"seq": seq, "bytes": len(data),
                                    "stream_length": new_len})
                self.db.execute("COMMIT")
            except RelayError:
                self.db.execute("ROLLBACK")
                raise
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            return {"tenant_id": tenant_id, "appended": len(data),
                    "stream_length": new_len, "sealed": False}

    def append_records(self, tenant_id: str, records: list[dict]) -> dict:
        """把一组记录按 JSON Lines 追加到该租户的字节流。"""
        if not isinstance(records, list) or \
                not all(isinstance(r, dict) for r in records):
            raise InvalidBody("records must be a list of objects")
        buf = b""
        for r in records:
            buf += dumps_canon(r).encode("utf-8") + b"\n"
        return self.append_bytes(tenant_id, buf)

    def seal_stream(self, tenant_id: str) -> dict:
        """封口：尾窗（若有部分字节）按真实长度定型，边界此后固定。"""
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self._require_tenant_id(tenant_id)
                self.db.execute(
                    "UPDATE tenants SET stream_sealed=1 WHERE tenant_id=?",
                    (tenant_id,))
                self._event("stream_sealed", tenant_id=tenant_id,
                            detail={"stream_length": row["stream_length"]})
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            return {"tenant_id": tenant_id, "sealed": True,
                    "stream_length": row["stream_length"]}

    # ------------------------------------------------------------------ #
    # window materialisation (deterministic boundaries + stable bytes)
    # ------------------------------------------------------------------ #

    def _window_id(self, tenant_id: str, seq: int, start: int, end: int) -> str:
        material = dumps_canon({
            "tenant_id": tenant_id, "seq": seq,
            "start_offset": start, "end_offset": end,
        })
        return "afw_" + hmac_hex(self.packet_secret,
                                 material.encode("utf-8"))[:32]

    def _read_stream_slice(self, tenant_id: str, start: int, end: int) -> bytes:
        """从只增块里取出原序字节区间 [start,end)。"""
        out = bytearray()
        rows = self.db.execute(
            "SELECT chunk, length FROM stream_chunks WHERE tenant_id=? "
            "ORDER BY seq", (tenant_id,)).fetchall()
        pos = 0
        remaining_lo, remaining_hi = start, end
        for r in rows:
            chunk, length = r["chunk"], int(r["length"])
            chunk_start, chunk_end = pos, pos + length
            if chunk_end > remaining_lo and chunk_start < remaining_hi:
                lo = max(remaining_lo, chunk_start) - chunk_start
                hi = min(remaining_hi, chunk_end) - chunk_start
                out += chunk[lo:hi]
            pos = chunk_end
            if pos >= remaining_hi:
                break
        return bytes(out)

    def _available_window_count(self, t: sqlite3.Row) -> int:
        """可发放的窗口数：封口前只含整窗；封口后含定型尾窗。"""
        length, size = int(t["stream_length"]), int(t["window_size"])
        full = length // size
        if t["stream_sealed"] and length % size:
            full += 1
        return full

    def _ensure_window(self, t: sqlite3.Row, seq: int) -> sqlite3.Row:
        """物化（首次）并返回窗口 seq；区间与字节此后固化不变。"""
        size = int(t["window_size"])
        start = seq * size
        avail = self._available_window_count(t)
        if seq < 0 or seq >= avail:
            raise WindowNotFound(f"window seq {seq} is not available")
        end = min((seq + 1) * size, int(t["stream_length"]))
        wid = self._window_id(t["tenant_id"], seq, start, end)
        row = self.db.execute(
            "SELECT * FROM windows WHERE tenant_id=? AND seq=?",
            (t["tenant_id"], seq)).fetchone()
        if row is not None:
            # 边界/字节固化不变：若区间意外变化属于内部不变量被破坏
            if row["window_id"] != wid or row["end_offset"] != end:
                raise RelayError("window boundary drift detected")
            return row
        payload = self._read_stream_slice(t["tenant_id"], start, end)
        rec_count = len(parse_records(payload))
        self.db.execute(
            """INSERT INTO windows
               (tenant_id, seq, window_id, start_offset, end_offset, payload,
                record_count, state, lease_epoch, retry_count, filter_version,
                created_at)
               VALUES (?,?,?,?,?,?,?,'pending',0,0,?,?)""",
            (t["tenant_id"], seq, wid, start, end, payload, rec_count,
             int(t["filter_version"]), utcnow()))
        return self.db.execute(
            "SELECT * FROM windows WHERE tenant_id=? AND seq=?",
            (t["tenant_id"], seq)).fetchone()

    def _active_lease_count(self, tid: str, now: float) -> int:
        """活动（已出租且未超时、未完成）窗口数 —— 这是受 max_inflight 约束的量。"""
        row = self.db.execute(
            "SELECT COUNT(*) c FROM windows WHERE tenant_id=? AND state='leased' "
            "AND lease_expires_at > ?", (tid, now)).fetchone()
        return int(row["c"])

    # ------------------------------------------------------------------ #
    # claim / re-lease / timeout takeover
    # ------------------------------------------------------------------ #

    def claim(self, token: str, worker: str, *,
              ttl_seconds: int | None = None) -> dict:
        """领取一个可处理窗口（并行，最多 max_inflight 个活动在途）。

        优先把**已超时**的窗口改投给当前 worker（补洞优先，避免慢窗口
        长期挡住屏障）；否则领取最靠前的未完成且未在活动租约中的窗口；
        没有可领窗口但达到在途上限时返回 window=None + 原因。
        """
        if not isinstance(worker, str) or not worker:
            raise InvalidBody("worker is required")
        ttl = max(1, int(ttl_seconds or self.default_ttl))
        with self._lock:
            tenant = self._tenant_by_token(token)
            if not tenant["active"]:
                self._reject(tenant["tenant_id"], "tenant_inactive")
                raise TenantInactive("tenant is deactivated")
            tid = tenant["tenant_id"]
            self.db.execute("BEGIN IMMEDIATE")
            try:
                resp = self._claim_locked(tenant, worker, ttl)
                self.db.execute("COMMIT")
                return resp
            except RelayError as exc:
                self.db.execute("ROLLBACK")
                if exc.reject_reason:
                    self._reject(tid, exc.reject_reason,
                                 window_id=exc.detail.get("window_id"),
                                 detail=exc.detail)
                raise
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def _claim_locked(self, tenant: sqlite3.Row, worker: str,
                      ttl: int) -> dict:
        tid = tenant["tenant_id"]
        now = self._now()
        avail = self._available_window_count(tenant)

        # 1) 已超时窗口优先补洞（最靠前），任何 worker 都可接管
        expired = self.db.execute(
            "SELECT * FROM windows WHERE tenant_id=? AND state='leased' "
            "AND lease_expires_at <= ? ORDER BY seq", (tid, now)).fetchall()
        if expired:
            return self._takeover(tenant, expired[0], worker, ttl,
                                  reason="timeout_takeover")

        # 2) 在途上限：活动（未超时）窗口计数；收缩不抢持有者，只拦新领取
        active = self._active_lease_count(tid, now)
        if active >= int(tenant["max_inflight"]):
            raise InFlightCap(
                f"tenant {tid}: {active} active in-flight windows, "
                f"max_inflight={tenant['max_inflight']}",
                detail={"active": active,
                        "max_inflight": int(tenant["max_inflight"])})

        # 3) 最靠前的未完成窗口（pending 优先；leased 活动窗口被排除）
        for seq in range(avail):
            t = self._require_row(tenant)
            w = self.db.execute(
                "SELECT * FROM windows WHERE tenant_id=? AND seq=?",
                (tid, seq)).fetchone()
            if w is None:
                w = self._ensure_window(t, seq)
            if w["state"] == "completed":
                continue
            if w["state"] == "leased" and float(w["lease_expires_at"]) > now:
                continue  # 他人活动租约
            # pending（新窗口）
            return self._lease_new(tenant, w, worker, ttl)

        # 没有可发放窗口：可能是真的没有未完成窗口，也可能全在活动租约
        return {"window": None, "tenant_id": tid, "worker": worker,
                "reason": "no_window_available",
                "available_windows": avail,
                "active_inflight": active,
                "max_inflight": int(tenant["max_inflight"]),
                "commit_barrier": int(self._require_row(tenant)["commit_barrier"])}

    def _require_row(self, t: sqlite3.Row) -> sqlite3.Row:
        return self.db.execute(
            "SELECT * FROM tenants WHERE tenant_id=?",
            (t["tenant_id"],)).fetchone()

    def _lease_payload(self, tenant: sqlite3.Row, w: sqlite3.Row) -> dict:
        """构造对外窗口载荷：window_id/区间/持有者/原始字节（base64）。"""
        rule = json.loads(self._require_row(tenant)["filter_json"])
        records = parse_records(w["payload"])
        matched = sum(1 for rec in records if record_matches(rule, rec))
        return {
            "window_id": w["window_id"],
            "tenant_id": tenant["tenant_id"],
            "seq": w["seq"],
            "start_offset": w["start_offset"],
            "end_offset": w["end_offset"],
            "size": int(w["end_offset"]) - int(w["start_offset"]),
            "record_count": w["record_count"],
            "matched_count": matched,
            "holder": w["lease_owner"],
            "lease_epoch": w["lease_epoch"],
            "filter_version": w["filter_version"],
            "filter": rule,
            "payload_b64": base64.b64encode(w["payload"]).decode("ascii"),
            "payload_sha256": hashlib.sha256(w["payload"]).hexdigest(),
        }

    def _lease_response(self, tenant: sqlite3.Row, w: sqlite3.Row, *,
                        redispatched: bool, reason: str = "leased") -> dict:
        expires = float(w["lease_expires_at"])
        return {
            "window": self._lease_payload(tenant, w),
            "window_id": w["window_id"],
            "tenant_id": tenant["tenant_id"],
            "seq": w["seq"],
            "start_offset": w["start_offset"],
            "end_offset": w["end_offset"],
            "holder": w["lease_owner"],
            "lease_epoch": w["lease_epoch"],
            "filter_version": w["filter_version"],
            "lease_expires_at": _iso_at(expires),
            "lease_expires_epoch": expires,
            "lease_expired": self._now() >= expires,
            "retry_count": w["retry_count"],
            "redispatched": redispatched,
            "reason": reason,
        }

    def _lease_new(self, tenant: sqlite3.Row, w: sqlite3.Row, worker: str,
                   ttl: int) -> dict:
        tid = tenant["tenant_id"]
        now = self._now()
        expires = now + ttl
        fv = int(self._require_row(tenant)["filter_version"])
        self.db.execute(
            """UPDATE windows
               SET state='leased', lease_owner=?, lease_epoch=1,
                   lease_expires_at=?, retry_count=0, filter_version=?,
                   last_leased_at=?
               WHERE tenant_id=? AND seq=? AND state='pending'""",
            (worker, expires, fv, utcnow(), tid, w["seq"]))
        self._event("window_leased", tenant_id=tid, window_id=w["window_id"],
                    detail={"seq": w["seq"], "start": w["start_offset"],
                            "end": w["end_offset"], "worker": worker,
                            "lease_epoch": 1, "filter_version": fv})
        row = self.db.execute(
            "SELECT * FROM windows WHERE tenant_id=? AND seq=?",
            (tid, w["seq"])).fetchone()
        return self._lease_response(tenant, row, redispatched=False)

    def _takeover(self, tenant: sqlite3.Row, w: sqlite3.Row, worker: str,
                  ttl: int, *, reason: str) -> dict:
        """超时接管：同一 window_id/原始字节，epoch+1、retry+1、换新持有者。"""
        tid = tenant["tenant_id"]
        now = self._now()
        expires = now + ttl
        new_epoch = int(w["lease_epoch"]) + 1
        new_retry = int(w["retry_count"]) + 1
        fv = int(self._require_row(tenant)["filter_version"])
        old_owner = w["lease_owner"]
        self.db.execute(
            """UPDATE windows
               SET lease_owner=?, lease_epoch=?, lease_expires_at=?,
                   retry_count=?, filter_version=?, last_leased_at=?
               WHERE tenant_id=? AND seq=?""",
            (worker, new_epoch, expires, new_retry, fv, utcnow(), tid, w["seq"]))
        self._event("window_taken_over", tenant_id=tid,
                    window_id=w["window_id"],
                    detail={"seq": w["seq"], "old_owner": old_owner,
                            "new_owner": worker, "lease_epoch": new_epoch,
                            "retry_count": new_retry,
                            "filter_version": fv})
        row = self.db.execute(
            "SELECT * FROM windows WHERE tenant_id=? AND seq=?",
            (tid, w["seq"])).fetchone()
        return self._lease_response(tenant, row, redispatched=True, reason=reason)

    def fetch(self, token: str, worker: str, window_id: str, *,
              ttl_seconds: int | None = None) -> dict:
        """重新领取一个**具体**窗口（补洞期重新领取仍返回原标识与原始字节）。

        * 持有者本人 + 租约活动：幂等重放同 window_id/字节（不增 retry）；
        * 租约已超时（任何人）：接管，epoch+1/retry+1，原 window_id/字节不变；
        * 他人活动租约：lease_conflict；
        * 窗口已完成：返回 completed 事实（不再出租）。
        """
        if not isinstance(worker, str) or not worker:
            raise InvalidBody("worker is required")
        ttl = max(1, int(ttl_seconds or self.default_ttl))
        with self._lock:
            tenant = self._tenant_by_token(token)
            if not tenant["active"]:
                self._reject(tenant["tenant_id"], "tenant_inactive",
                             window_id=window_id)
                raise TenantInactive("tenant is deactivated")
            tid = tenant["tenant_id"]
            self.db.execute("BEGIN IMMEDIATE")
            try:
                w = self.db.execute(
                    "SELECT * FROM windows WHERE window_id=?",
                    (window_id,)).fetchone()
                if w is None or w["tenant_id"] != tid:
                    raise BadWindow(
                        "window_id does not belong to this tenant",
                        detail={"window_id": window_id})
                if w["state"] == "completed":
                    self.db.execute("COMMIT")
                    return self._completed_fetch(tenant, w)
                now = self._now()
                expired = now >= float(w["lease_expires_at"])
                same_owner = w["lease_owner"] == worker
                if not expired and not same_owner:
                    raise LeaseConflict(
                        f"window {window_id} is leased to {w['lease_owner']}",
                        detail={"window_id": window_id,
                                "holder": w["lease_owner"],
                                "challenger": worker})
                if not expired and same_owner:
                    # 持有者租约内重领：窗口 id/字节/epoch 不变（不抢占、
                    # 不增重试）。若期间筛选规则已前进，则把本次出租刷新到
                    # 新筛选版本，使持有者按新规则重新处理后可提交。
                    cur_fv = int(self._require_row(tenant)["filter_version"])
                    if int(w["filter_version"]) != cur_fv:
                        self.db.execute(
                            "UPDATE windows SET filter_version=? "
                            "WHERE tenant_id=? AND seq=?",
                            (cur_fv, tid, w["seq"]))
                        self._event("window_filter_refreshed", tenant_id=tid,
                                    window_id=w["window_id"],
                                    detail={"seq": w["seq"], "worker": worker,
                                            "old_filter_version":
                                                int(w["filter_version"]),
                                            "new_filter_version": cur_fv,
                                            "lease_epoch": w["lease_epoch"]})
                        w = self.db.execute(
                            "SELECT * FROM windows WHERE tenant_id=? AND seq=?",
                            (tid, w["seq"])).fetchone()
                        self.db.execute("COMMIT")
                        return self._lease_response(
                            tenant, w, redispatched=False,
                            reason="filter_refreshed")
                    self.db.execute("COMMIT")
                    return self._lease_response(
                        tenant, w, redispatched=False, reason="replayed")
                resp = self._takeover(tenant, w, worker, ttl,
                                      reason="timeout_takeover")
                self.db.execute("COMMIT")
                return resp
            except RelayError as exc:
                self.db.execute("ROLLBACK")
                if exc.reject_reason:
                    self._reject(tid, exc.reject_reason,
                                 window_id=exc.detail.get("window_id", window_id),
                                 detail=exc.detail)
                raise
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def _completed_fetch(self, tenant: sqlite3.Row, w: sqlite3.Row) -> dict:
        t = self._require_row(tenant)
        return {"window": None, "window_id": w["window_id"],
                "tenant_id": tenant["tenant_id"], "seq": w["seq"],
                "start_offset": w["start_offset"], "end_offset": w["end_offset"],
                "state": "completed", "completed": True,
                "completed_by": w["completed_by"],
                "commit_barrier": int(t["commit_barrier"])}

    # ------------------------------------------------------------------ #
    # commit: register completion, then advance the contiguous prefix
    # ------------------------------------------------------------------ #

    def commit(self, token: str, window_id: str, end_offset: int,
               worker: str, *, filter_version: int | None = None) -> dict:
        """登记窗口完成并尽力推进连续提交屏障。

        校验顺序（任一失败都不改窗口/屏障，并落 reject 审计）：
        租户停用 → 跨租户/未知 id → 非整数末端 → 已完成（幂等）→
        栅栏（持有者 + epoch 经 lease_owner 匹配）→ 末端 == 窗口末端 →
        筛选版本一致。
        """
        with self._lock:
            tenant = self._tenant_by_token(token)
            if not tenant["active"]:
                self._reject(tenant["tenant_id"], "tenant_inactive",
                             window_id=window_id)
                raise TenantInactive("tenant is deactivated")
            tid = tenant["tenant_id"]
            self.db.execute("BEGIN IMMEDIATE")
            try:
                w = self.db.execute(
                    "SELECT * FROM windows WHERE window_id=?",
                    (window_id,)).fetchone()
                if w is None or w["tenant_id"] != tid:
                    raise BadWindow(
                        "window_id does not belong to this tenant",
                        detail={"window_id": window_id,
                                "end_offset": end_offset})
                if not isinstance(end_offset, int):
                    raise WindowEndMismatch("end_offset must be an integer",
                                            detail={"window_id": window_id})

                # 重复提交：同一已完成窗口幂等返回；不重复推进、不增事件
                if w["state"] == "completed":
                    if end_offset != w["end_offset"]:
                        raise WindowEndMismatch(
                            f"window already completed at {w['end_offset']}; "
                            f"commit {end_offset} rejected",
                            detail={"window_id": window_id,
                                    "commit_end": end_offset,
                                    "window_end": w["end_offset"]})
                    barrier_before = int(self._require_row(tenant)["commit_barrier"])
                    self.db.execute("COMMIT")
                    resp = self._commit_response(w, barrier_before, barrier_before,
                                                 advanced=0, idempotent=True)
                    return resp

                # 栅栏：必须是当前持有者（超时接管后 lease_owner 已换人，
                # 旧持有者在此被拒绝）
                if worker != w["lease_owner"]:
                    raise StaleLease(
                        f"window leased to {w['lease_owner']}; "
                        f"stale commit by {worker} rejected",
                        detail={"window_id": window_id,
                                "holder": w["lease_owner"],
                                "worker": worker,
                                "lease_epoch": w["lease_epoch"]})
                # 越过窗口末端 / 部分提交
                if end_offset != w["end_offset"]:
                    raise WindowEndMismatch(
                        f"commit end {end_offset} != window end "
                        f"{w['end_offset']}; over/partial commit rejected",
                        detail={"window_id": window_id,
                                "commit_end": end_offset,
                                "window_end": w["end_offset"]})

                # 筛选规则在途变更：旧筛选版本窗口的提交不得推进
                cur_fv = int(self._require_row(tenant)["filter_version"])
                win_fv = int(w["filter_version"])
                if filter_version is not None and \
                        int(filter_version) != win_fv:
                    raise FilterChanged(
                        f"commit filter_version {filter_version} != window "
                        f"lease filter_version {win_fv}",
                        detail={"window_id": window_id,
                                "commit_filter_version": filter_version,
                                "window_filter_version": win_fv,
                                "current_filter_version": cur_fv})
                if win_fv != cur_fv:
                    raise FilterChanged(
                        f"window leased under filter_version {win_fv} but "
                        f"tenant is at {cur_fv}; re-lease then commit",
                        detail={"window_id": window_id,
                                "window_filter_version": win_fv,
                                "current_filter_version": cur_fv})

                # —— 登记完成事实（屏障可能尚不能越过它）——
                self.db.execute(
                    """UPDATE windows
                       SET state='completed', completed_at=?, completed_by=?
                       WHERE tenant_id=? AND seq=?""",
                    (utcnow(), worker, tid, w["seq"]))
                self._event("window_completed", tenant_id=tid,
                            window_id=window_id,
                            detail={"seq": w["seq"], "start": w["start_offset"],
                                    "end": w["end_offset"], "worker": worker,
                                    "lease_epoch": w["lease_epoch"],
                                    "commit_barrier_before":
                                        int(self._require_row(tenant)
                                            ["commit_barrier"])})

                # —— 补洞推进：从当前屏障起吃掉连续 completed 前缀 ——
                advanced, new_barrier, filled = self._advance_barrier(tid)
                row = self.db.execute(
                    "SELECT * FROM windows WHERE window_id=?",
                    (window_id,)).fetchone()
                resp = self._commit_response(
                    row, new_barrier - advanced, new_barrier,
                    advanced=advanced, idempotent=False, filled=filled)
                self.db.execute("COMMIT")
                return resp
            except RelayError as exc:
                self.db.execute("ROLLBACK")
                if exc.reject_reason:
                    self._reject(tid, exc.reject_reason,
                                 window_id=exc.detail.get("window_id", window_id),
                                 detail=exc.detail)
                raise
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def _advance_barrier(self, tid: str) -> tuple[int, int, list[int]]:
        """从当前连续提交屏障开始推进到最长连续 completed 前缀。

        返回 (推进字节数, 新屏障, 本次补齐的窗口 seq 列表)。靠后已完成但
        前方有空洞的窗口保留 completed，屏障停在空洞前不动。
        """
        t = self.db.execute("SELECT * FROM tenants WHERE tenant_id=?",
                            (tid,)).fetchone()
        size = int(t["window_size"])
        barrier = int(t["commit_barrier"])
        filled: list[int] = []
        # barrier 一定落在窗口边界；从 barrier//size 起顺序吃 completed 窗口
        seq = barrier // size
        advanced = 0
        while True:
            w = self.db.execute(
                "SELECT * FROM windows WHERE tenant_id=? AND seq=?",
                (tid, seq)).fetchone()
            if w is None or w["state"] != "completed":
                break
            barrier = int(w["end_offset"])
            advanced += int(w["end_offset"]) - int(w["start_offset"])
            filled.append(seq)
            seq += 1
        if barrier != int(t["commit_barrier"]):
            self.db.execute(
                "UPDATE tenants SET commit_barrier=? WHERE tenant_id=?",
                (barrier, tid))
            self._event("barrier_advanced", tenant_id=tid,
                        detail={"from": int(t["commit_barrier"]),
                                "to": barrier, "filled_windows": filled})
        return advanced, barrier, filled

    def _commit_response(self, w: sqlite3.Row, barrier_before: int,
                         barrier_after: int, *, advanced: int,
                         idempotent: bool, filled: list[int] | None = None) -> dict:
        return {
            "window_id": w["window_id"], "tenant_id": w["tenant_id"],
            "seq": w["seq"], "start_offset": w["start_offset"],
            "end_offset": w["end_offset"], "state": "completed",
            "completed_by": w["completed_by"],
            "idempotent": idempotent,
            "barrier_before": barrier_before,
            "commit_barrier": barrier_after,
            "barrier_advanced_bytes": advanced,
            "filled_windows": filled or [],
            "hole_remains": self._first_hole(w["tenant_id"], barrier_after)
                            is not None,
        }

    def _max_completed_seq(self, tid: str) -> int | None:
        row = self.db.execute(
            "SELECT MAX(seq) m FROM windows WHERE tenant_id=? "
            "AND state='completed'", (tid,)).fetchone()
        m = row["m"]
        return int(m) if m is not None else None

    def _first_hole(self, tid: str, barrier: int) -> int | None:
        """屏障之后、最远完成点之前第一个未完成窗口 seq（空洞）。

        只统计“已有更靠后的完成事实、但它前面仍缺”的窗口；更远的、尚未
        物化/领取的积压窗口不算空洞（它们由 available_windows 表达）。
        """
        t = self.db.execute("SELECT * FROM tenants WHERE tenant_id=?",
                            (tid,)).fetchone()
        size = int(t["window_size"])
        max_completed = self._max_completed_seq(tid)
        if max_completed is None:
            return None
        for seq in range(barrier // size, max_completed + 1):
            w = self.db.execute(
                "SELECT state FROM windows WHERE tenant_id=? AND seq=?",
                (tid, seq)).fetchone()
            if w is None or w["state"] != "completed":
                return seq
        return None

    # ------------------------------------------------------------------ #
    # status / observability
    # ------------------------------------------------------------------ #

    def _window_view(self, w: sqlite3.Row, now: float) -> dict:
        expired = w["state"] == "leased" and \
            float(w["lease_expires_at"]) <= now
        return {
            "window_id": w["window_id"],
            "seq": w["seq"],
            "start_offset": w["start_offset"],
            "end_offset": w["end_offset"],
            "size": int(w["end_offset"]) - int(w["start_offset"]),
            "record_count": w["record_count"],
            "state": w["state"],                 # pending | leased | completed
            "holder": w["lease_owner"],
            "lease_epoch": w["lease_epoch"],
            "lease_expires_at": _iso_at(float(w["lease_expires_at"]))
                                if w["lease_expires_at"] is not None else None,
            "lease_expired": expired,
            "retry_count": w["retry_count"],
            "filter_version": w["filter_version"],
            "completed_by": w["completed_by"],
            "completed_at": w["completed_at"],
            "last_leased_at": w["last_leased_at"],
        }

    def _tenant_brief(self, row: sqlite3.Row) -> dict:
        now = self._now()
        tid = row["tenant_id"]
        avail = self._available_window_count(row)
        wins = self.db.execute(
            "SELECT * FROM windows WHERE tenant_id=? ORDER BY seq",
            (tid,)).fetchall()
        win_views = [self._window_view(w, now) for w in wins]

        active = [v for v in win_views
                  if v["state"] == "leased" and not v["lease_expired"]]
        expired = [v for v in win_views
                   if v["state"] == "leased" and v["lease_expired"]]
        completed = [v for v in win_views if v["state"] == "completed"]
        barrier = int(row["commit_barrier"])

        # 高水位：最远完成窗口的末端（屏障可能因前方空洞落后于它）
        high_water = barrier
        max_completed_seq = None
        for v in completed:
            if v["end_offset"] > high_water:
                high_water = v["end_offset"]
            if max_completed_seq is None or v["seq"] > max_completed_seq:
                max_completed_seq = v["seq"]

        # 空洞：屏障之后、最远完成点之前仍未完成的窗口（未来积压不算空洞）
        holes: list[int] = []
        if max_completed_seq is not None:
            for seq in range(barrier // int(row["window_size"]),
                            max_completed_seq + 1):
                w = self.db.execute(
                    "SELECT state FROM windows WHERE tenant_id=? AND seq=?",
                    (tid, seq)).fetchone()
                if w is None or w["state"] != "completed":
                    holes.append(seq)

        # 已租在途但位于屏障之前/之后的序号（观察并行在途）
        leased_ahead = sorted(v["seq"] for v in win_views
                              if v["state"] == "leased")

        return {
            "tenant_id": tid,
            "name": row["name"],
            "active": bool(row["active"]),
            "window_size": int(row["window_size"]),
            "max_inflight": int(row["max_inflight"]),
            "filter": json.loads(row["filter_json"]),
            "filter_version": int(row["filter_version"]),
            "stream_length": int(row["stream_length"]),
            "stream_sealed": bool(row["stream_sealed"]),
            "available_windows": avail,
            "commit_barrier": barrier,                       # 连续提交屏障
            "high_water": high_water,                        # 最远完成点
            "holes": holes,                                  # 屏障后空洞 seq
            "active_inflight": len(active),
            "expired_inflight": len(expired),
            "leased_window_seqs": leased_ahead,
            "completed_count": len(completed),
            "windows": win_views,
            "disabled_reason": row["disable_reason"],
        }

    def recent_events(self, *, tenant_id: str | None = None,
                      limit: int = 60) -> list[dict]:
        if tenant_id:
            rows = self.db.execute(
                "SELECT * FROM wrelay_events WHERE tenant_id=? "
                "ORDER BY id DESC LIMIT ?", (tenant_id, int(limit))).fetchall()
        else:
            rows = self.db.execute(
                "SELECT * FROM wrelay_events ORDER BY id DESC LIMIT ?",
                (int(limit),)).fetchall()
        out = []
        for r in reversed(rows):
            out.append({"id": r["id"], "created_at": r["created_at"],
                        "kind": r["kind"], "tenant_id": r["tenant_id"],
                        "window_id": r["window_id"], "reason": r["reason"],
                        "detail": json.loads(r["detail_json"])})
        return out

    def reject_counts(self, *, tenant_id: str | None = None) -> dict:
        if tenant_id:
            rows = self.db.execute(
                "SELECT reason, COUNT(*) c FROM wrelay_events "
                "WHERE kind='reject' AND tenant_id=? GROUP BY reason",
                (tenant_id,)).fetchall()
        else:
            rows = self.db.execute(
                "SELECT reason, COUNT(*) c FROM wrelay_events "
                "WHERE kind='reject' GROUP BY reason").fetchall()
        return {r["reason"]: r["c"] for r in rows}

    def status(self, *, tenant_id: str | None = None,
               events_limit: int = 60) -> dict:
        with self._lock:
            tenants = self.list_tenants()
            if tenant_id is not None:
                tenants = [t for t in tenants if t["tenant_id"] == tenant_id]
            return {
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
