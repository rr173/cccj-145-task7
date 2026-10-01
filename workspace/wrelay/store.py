"""并行窗口中继的独立 SQLite 持久化。

与 afrelay 一样用 SQLite + 显式 ``BEGIN IMMEDIATE`` 事务串行所有变更，
崩溃不留半状态；与任何上游/其它服务库**完全分离**（不同文件、不同
schema）。

模型::

    stream_chunks  每租户一条只增字节流（append 源数据）；sealed 后边界固定
    tenants        审计租户：令牌哈希、窗口大小、max_inflight、筛选规则与
                   版本、启停、连续提交屏障
    windows        固定区间 [start,end) 的窗口：原始字节、租约持有者/到期/
                   epoch（栅栏）、retry 次数、筛选版本、完成事实
    wrelay_events  只增运维/审计事件（领取/接管/完成/屏障推进/拒绝/管理变更）

关键不变量（与代码配合保证）：

* ``windows`` 按 ``(tenant_id, seq)`` 唯一：窗口首次物化即把
  ``payload``/``start``/``end`` 固化，之后永不修改区间与字节；
* 完成事实写在 ``windows.completed``，连续提交屏障只存于
  ``tenants.commit_barrier``，二者都能从事件/窗口表在重启后重建；
* ``lease_epoch`` 单调递增，超时接管 +1，旧持有者无法再提交；
* 部分唯一索引 + 代码计数共同把「活动（未超时）在途窗口」数限制在
  ``max_inflight`` 之内（超时窗口不算活动，允许接管）。
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

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id        TEXT PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    token_sha256     TEXT NOT NULL UNIQUE,
    window_size      INTEGER NOT NULL,        -- 每窗口原始字节数（建租户时固定）
    max_inflight     INTEGER NOT NULL,        -- 活动在途窗口上限（可动态调整）
    filter_json      TEXT NOT NULL,
    filter_version   INTEGER NOT NULL DEFAULT 1,
    active           INTEGER NOT NULL DEFAULT 1,
    stream_length    INTEGER NOT NULL DEFAULT 0,  -- 已 append 字节数
    stream_sealed    INTEGER NOT NULL DEFAULT 0,  -- 封口后不再追加、窗口边界最终固定
    commit_barrier   INTEGER NOT NULL DEFAULT 0,  -- 连续提交屏障（原序偏移，不含）
    created_at       TEXT NOT NULL,
    disabled_at      TEXT,
    disable_reason   TEXT
);

CREATE TABLE IF NOT EXISTS stream_chunks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  TEXT NOT NULL REFERENCES tenants(tenant_id),
    seq        INTEGER NOT NULL,              -- 追加块序号（0 起，只增）
    chunk      BLOB NOT NULL,
    length     INTEGER NOT NULL,
    appended_at TEXT NOT NULL,
    UNIQUE(tenant_id, seq)
);

CREATE TABLE IF NOT EXISTS windows (
    tenant_id       TEXT NOT NULL REFERENCES tenants(tenant_id),
    seq             INTEGER NOT NULL,         -- 租户内窗口序号（偏移/window_size）
    window_id       TEXT NOT NULL UNIQUE,     -- 全局唯一 afw_ 标识（可跨租户识别）
    start_offset    INTEGER NOT NULL,
    end_offset      INTEGER NOT NULL,         -- 固定窗口末端（含尾窗封口后）
    payload         BLOB NOT NULL,            -- 原始字节（物化即固化，重放逐字节相同）
    record_count    INTEGER NOT NULL DEFAULT 0,
    state           TEXT NOT NULL,            -- pending | leased | completed
    lease_owner     TEXT,
    lease_epoch     INTEGER NOT NULL DEFAULT 0,   -- 栅栏令牌：接管即 +1
    lease_expires_at REAL,                    -- epoch 秒；NULL=未出租
    retry_count     INTEGER NOT NULL DEFAULT 0,   -- 超时/接管次数（首次发放后计）
    filter_version  INTEGER NOT NULL,         -- 本次出租时的筛选版本
    completed_at    TEXT,
    completed_by    TEXT,
    created_at      TEXT NOT NULL,
    last_leased_at  TEXT,
    PRIMARY KEY (tenant_id, seq)
);
CREATE INDEX IF NOT EXISTS ix_windows_state ON windows(tenant_id, state);

CREATE TABLE IF NOT EXISTS wrelay_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    kind        TEXT NOT NULL,
    tenant_id   TEXT,
    window_id   TEXT,
    reason      TEXT,
    detail_json TEXT
);
CREATE INDEX IF NOT EXISTS ix_wrelay_events_id ON wrelay_events(id);
CREATE INDEX IF NOT EXISTS ix_wrelay_events_tenant ON wrelay_events(tenant_id, id);
"""


def connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    # isolation_level=None：全部事务由代码显式 BEGIN IMMEDIATE / COMMIT 管理。
    conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False,
                           isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")   # 崩溃/掉电不丢已提交的窗口与完成事实
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.executescript(SCHEMA)
    conn.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES(?,?)",
        ("schema_version", SCHEMA_VERSION))
    return conn
