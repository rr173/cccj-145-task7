"""中继的独立 SQLite 持久化。

与网关数据库**完全分离**（不同文件、不同 schema），中继永不打开网关库。

表：

* ``meta``           -- 版本/管理员令牌哈希/默认窗口大小等
* ``mirror_state``   -- 单行：最后可信树高、上游观察高度、停止原因、冻结观察
* ``mirror_leaves``  -- 稠密镜像叶子 0..trusted-1（内容寻址，含规范信封）
* ``mirror_cps``     -- 每个已验证高度的已签名 checkpoint（逐字节存档）
* ``tenants``        -- 隔离的审计租户：自有令牌、筛选规则、连续提交屏障、
                        最大在途窗口数、启停
* ``deliveries``     -- **窗口**（相邻、互不重叠的原始序号区间）：确定性包
                        字节、租约持有者/到期/epoch/不透明租约令牌、接管
                        次数、状态（leased 已租出 | completed 已完成待补洞 |
                        committed 已越过连续提交屏障）
* ``relay_events``   -- 运维事件：同步推进/停止、发放/接管/完成/补洞推进/
                        拒绝、收缩冲突、停用…

窗口边界（``start_index/end_index``）在首次发放时落库，此后**永不改变**：
超时接管只换租约持有者与 epoch，进程重启也返回同一窗口标识与同一包字节；
乱序完成只把窗口置 ``completed``，连续提交屏障（``tenants.cursor_end``）
必须等前面的空洞补齐、窗口按序连成稠密前缀后才一次推进。
"""

from __future__ import annotations

import os
import sqlite3

from . import SCHEMA_VERSION

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mirror_state (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),
    trusted_tree_size    INTEGER NOT NULL DEFAULT 0,
    upstream_tree_size   INTEGER NOT NULL DEFAULT 0,
    upstream_frozen      INTEGER NOT NULL DEFAULT 0,
    frozen_reason        TEXT,
    frozen_tree_size     INTEGER,
    synced               INTEGER NOT NULL DEFAULT 0,   -- 完成过至少一次有效同步
    last_status          TEXT NOT NULL DEFAULT 'never',-- never|synced|caught_up|stopped
    last_stop_reason     TEXT,
    last_error           TEXT,
    last_attempt_at      TEXT,
    last_success_at      TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mirror_leaves (
    leaf_index  INTEGER PRIMARY KEY,
    event_key   TEXT NOT NULL UNIQUE,
    event_type  TEXT NOT NULL,
    leaf_hash   TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    mirrored_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mirror_cps (
    tree_size       INTEGER PRIMARY KEY,
    root_hash       TEXT NOT NULL,
    prev_size       INTEGER,
    prev_root_hash  TEXT,
    checkpoint_json TEXT NOT NULL,
    mirrored_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id     TEXT PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    token_sha256  TEXT NOT NULL UNIQUE,
    filter_json   TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1,
    -- 连续提交屏障：已提交连续前缀末端（原始序号上界，不含）。乱序完成不会
    -- 立即移动它；只有前缀窗口连成稠密完成段时才一次推进
    cursor_end    INTEGER NOT NULL DEFAULT 0,
    max_inflight  INTEGER NOT NULL DEFAULT 8,   -- 最大在途窗口数（可动态收缩）
    filter_locked INTEGER NOT NULL DEFAULT 0,   -- 首个窗口发出即锁定
    created_at    TEXT NOT NULL,
    disabled_at   TEXT,
    disable_reason TEXT
);

CREATE TABLE IF NOT EXISTS deliveries (
    delivery_id    TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(tenant_id),
    seq            INTEGER NOT NULL,           -- 租户内单调的窗口序号
    start_index    INTEGER NOT NULL,
    end_index      INTEGER NOT NULL,
    packet_json    TEXT NOT NULL,              -- afp1 完整包（含 sig），逐字节重放
    state          TEXT NOT NULL,              -- leased | completed | committed
    lease_owner    TEXT,                       -- 当前 consumer 标识
    lease_expires_at TEXT,
    lease_count    INTEGER NOT NULL DEFAULT 1, -- 租约发放次数（首次+超时接管）
    lease_epoch    INTEGER NOT NULL DEFAULT 1, -- 接管即 +1；旧 epoch 提交拒绝
    lease_token    TEXT,                       -- 每次发放/接管生成的不透明令牌
    created_at     TEXT NOT NULL,
    last_leased_at TEXT NOT NULL,
    completed_at   TEXT,
    committed_at   TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_deliveries_tenant_seq
    ON deliveries(tenant_id, seq);
CREATE INDEX IF NOT EXISTS ix_deliveries_tenant_state
    ON deliveries(tenant_id, state);
CREATE INDEX IF NOT EXISTS ix_deliveries_state ON deliveries(state);

CREATE TABLE IF NOT EXISTS relay_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    kind       TEXT NOT NULL,
    tenant_id  TEXT,
    delivery_id TEXT,
    reason     TEXT,
    detail_json TEXT
);
CREATE INDEX IF NOT EXISTS ix_relay_events_id ON relay_events(id);
CREATE INDEX IF NOT EXISTS ix_relay_events_tenant ON relay_events(tenant_id, id);
"""

# 旧版本（afr1 单在途包）可能存在的对象；打开时幂等清理，不影响行数据。
_DROP_LEGACY = (
    "DROP INDEX IF EXISTS ux_deliveries_tenant_active",
)
_ADD_TENANT_COLUMNS = (
    ("max_inflight", "ALTER TABLE tenants ADD COLUMN max_inflight "
                     "INTEGER NOT NULL DEFAULT 8"),
)
_ADD_DELIVERY_COLUMNS = (
    ("lease_epoch", "ALTER TABLE deliveries ADD COLUMN lease_epoch "
                    "INTEGER NOT NULL DEFAULT 1"),
    ("lease_token", "ALTER TABLE deliveries ADD COLUMN lease_token TEXT"),
    ("completed_at", "ALTER TABLE deliveries ADD COLUMN completed_at TEXT"),
    ("committed_at", "ALTER TABLE deliveries ADD COLUMN committed_at TEXT"),
)


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r["name"] for r in conn.execute(
        f"PRAGMA table_info({table})").fetchall()}


def _migrate(conn: sqlite3.Connection) -> None:
    for stmt in _DROP_LEGACY:
        conn.execute(stmt)
    existing_tenants = _column_names(conn, "tenants")
    for name, ddl in _ADD_TENANT_COLUMNS:
        if name not in existing_tenants:
            conn.execute(ddl)
    if _column_names(conn, "deliveries"):  # 旧库可能已有 deliveries 表
        existing_del = _column_names(conn, "deliveries")
        for name, ddl in _ADD_DELIVERY_COLUMNS:
            if name not in existing_del:
                conn.execute(ddl)
        # 旧状态 'acked' 语义 == 已越过屏障；统一映射为 committed
        if "acked_at" in existing_del:
            conn.execute(
                "UPDATE deliveries SET state='committed', "
                "committed_at=COALESCE(committed_at, acked_at) "
                "WHERE state='acked'")
        else:
            conn.execute(
                "UPDATE deliveries SET state='committed' WHERE state='acked'")
        # 旧行没有 lease_epoch/token：lease_count>1 的旧在途窗口补发一个 token，
        # 之后只有出示该 token（或首次租约的无 token 提交）才被接受
        conn.execute(
            "UPDATE deliveries SET lease_token=lower(hex(randomblob(16))) "
            "WHERE lease_token IS NULL AND state='leased' AND lease_count > 1")


def connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    # isolation_level=None：全部事务由代码显式 BEGIN IMMEDIATE / COMMIT 管理，
    # 避免 sqlite3 模块隐式开启事务与显式 BEGIN 嵌套
    conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False,
                           isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.execute(
        "INSERT OR IGNORE INTO mirror_state (id) VALUES (1)")
    conn.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES(?,?)",
        ("schema_version", SCHEMA_VERSION))
    return conn
