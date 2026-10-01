"""中继的独立 SQLite 持久化。

与网关数据库**完全分离**（不同文件、不同 schema），中继永不打开网关库。

表：

* ``meta``           -- 版本/管理员令牌哈希/单租户投递批大小等
* ``mirror_state``   -- 单行：最后可信树高、上游观察高度、停止原因、冻结观察
* ``mirror_leaves``  -- 稠密镜像叶子 0..trusted-1（内容寻址，含规范信封）
* ``mirror_cps``     -- 每个已验证高度的已签名 checkpoint（逐字节存档）
* ``tenants``        -- 隔离的审计租户：自有令牌、筛选规则、消费位点、启停
* ``deliveries``     -- 持久化投递包：内容/租约/重试/确认，确定可重放
* ``relay_events``   -- 运维事件：同步推进/停止、拒绝、重投、停用…
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
    cursor_end    INTEGER NOT NULL DEFAULT 0,   -- 已确认末端（原始序号上界，不含）
    filter_locked INTEGER NOT NULL DEFAULT 0,   -- 首个包发出即锁定
    created_at    TEXT NOT NULL,
    disabled_at   TEXT,
    disable_reason TEXT
);

CREATE TABLE IF NOT EXISTS deliveries (
    delivery_id    TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(tenant_id),
    seq            INTEGER NOT NULL,           -- 租户内单调的包序号
    start_index    INTEGER NOT NULL,
    end_index      INTEGER NOT NULL,
    packet_json    TEXT NOT NULL,              -- afp1 完整包（含 sig），逐字节重放
    state          TEXT NOT NULL,              -- leased | acked
    lease_owner    TEXT,                       -- consumer 标识
    lease_expires_at TEXT,
    lease_count    INTEGER NOT NULL DEFAULT 1, -- 发放次数（首次+超时重投）
    created_at     TEXT NOT NULL,
    last_leased_at TEXT NOT NULL,
    acked_at       TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_deliveries_tenant_active
    ON deliveries(tenant_id) WHERE state = 'leased';
CREATE UNIQUE INDEX IF NOT EXISTS ux_deliveries_tenant_seq
    ON deliveries(tenant_id, seq);
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
    conn.execute(
        "INSERT OR IGNORE INTO mirror_state (id) VALUES (1)")
    conn.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES(?,?)",
        ("schema_version", SCHEMA_VERSION))
    return conn
