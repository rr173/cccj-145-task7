"""SQLite storage for gateway metadata: teams, snapshots, budgets, results,
freezes and the append-only audit log.

The single gateway database is guarded at the application layer by an RLock
(see :mod:`dpgw.gateway`); every state-changing operation runs inside one
``BEGIN IMMEDIATE`` transaction so concurrent requests can never overspend a
budget.  Snapshot row data never lives here -- only immutable snapshot files
are read, always read-only.
"""

from __future__ import annotations

import sqlite3

SCHEMA_VERSION = "gw1"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS teams (
    team_id     TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    token_sha256 TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL,
    created_by  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id   TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    path          TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1,
    published_at  TEXT NOT NULL,
    published_by  TEXT NOT NULL,
    UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS budgets (
    team_id       TEXT NOT NULL REFERENCES teams(team_id),
    snapshot_id   TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    epsilon_limit REAL NOT NULL,
    delta_limit   REAL NOT NULL,
    epsilon_spent REAL NOT NULL DEFAULT 0,
    delta_spent   REAL NOT NULL DEFAULT 0,
    allocated_at  TEXT NOT NULL,
    allocated_by  TEXT NOT NULL,
    PRIMARY KEY (team_id, snapshot_id)
);

CREATE TABLE IF NOT EXISTS results (
    result_id      TEXT PRIMARY KEY,
    team_id        TEXT NOT NULL,
    snapshot_id    TEXT NOT NULL,
    query_hash     TEXT NOT NULL,
    family_id      TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    mechanism      TEXT NOT NULL,
    epsilon        REAL NOT NULL,
    delta          REAL NOT NULL,
    dimension      INTEGER NOT NULL,
    sensitivity_l1 REAL NOT NULL,
    scale          REAL NOT NULL,
    coords_json    TEXT NOT NULL,
    values_json    TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    UNIQUE(team_id, snapshot_id, query_hash)
);

CREATE TABLE IF NOT EXISTS freezes (
    freeze_id   TEXT PRIMARY KEY,
    family_id   TEXT NOT NULL,
    scope       TEXT NOT NULL,            -- global | team | snapshot | team_snapshot
    team_id     TEXT,
    snapshot_id TEXT,
    reason      TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_freezes_family ON freezes(family_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    team_id     TEXT,
    snapshot_id TEXT,
    result_id   TEXT,
    query_hash  TEXT,
    family_id   TEXT,
    request_id  TEXT,
    epsilon     REAL,
    delta       REAL,
    detail_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_result ON audit_log(result_id);
CREATE INDEX IF NOT EXISTS idx_audit_family ON audit_log(family_id);

-- -----------------------------------------------------------------------
-- resumable multi-statement analysis jobs
--
-- Lifecycle: reserved -> executing -> completed
--                                  \\-> failed (validation failed at confirm,
--                                               or crash while executing)
--            reserved -> cancelled | expired
--
-- A job in *reserved*/*executing* owns budget_holds rows: epsilon/delta that
-- are neither spent nor available to anybody else until the job completes,
-- is cancelled, or its ticket expires.  Holds are deleted the moment the job
-- leaves the active states, so reservations can never dangle.
-- -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS jobs (
    job_id             TEXT PRIMARY KEY,
    team_id            TEXT NOT NULL,
    request_key        TEXT NOT NULL,
    payload_hash       TEXT NOT NULL,
    state              TEXT NOT NULL,   -- reserved|executing|completed|failed|cancelled|expired
    epsilon_reserved   REAL NOT NULL DEFAULT 0,
    delta_reserved     REAL NOT NULL DEFAULT 0,
    epsilon_consumed   REAL NOT NULL DEFAULT 0,
    delta_consumed     REAL NOT NULL DEFAULT 0,
    statement_count    INTEGER NOT NULL,
    ttl_seconds        INTEGER NOT NULL,
    created_at         TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    confirmed_at       TEXT,
    finished_at        TEXT,
    error_code         TEXT,
    error_message      TEXT,
    created_by         TEXT NOT NULL,
    UNIQUE(team_id, request_key)
);
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state);

CREATE TABLE IF NOT EXISTS job_statements (
    job_id         TEXT NOT NULL,
    position       INTEGER NOT NULL,
    snapshot_id    TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    query_hash     TEXT NOT NULL,
    family_id      TEXT NOT NULL,
    mechanism      TEXT NOT NULL,
    epsilon        REAL NOT NULL,
    delta          REAL NOT NULL,
    dimension      INTEGER NOT NULL,
    scale          REAL NOT NULL,
    sensitivity_l1 REAL NOT NULL,
    already_cached INTEGER NOT NULL DEFAULT 0,  -- free replay known at reserve time
    result_id      TEXT,
    charged        INTEGER NOT NULL DEFAULT 0,  -- 1 if this statement's job paid
    PRIMARY KEY (job_id, position)
);
CREATE INDEX IF NOT EXISTS idx_job_stmt_result ON job_statements(result_id);

-- one hold per (job, team, snapshot); amounts count against available budget
CREATE TABLE IF NOT EXISTS budget_holds (
    team_id     TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    job_id      TEXT NOT NULL,
    epsilon     REAL NOT NULL,
    delta       REAL NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    PRIMARY KEY (team_id, snapshot_id, job_id)
);
CREATE INDEX IF NOT EXISTS idx_holds_job ON budget_holds(job_id);

-- -----------------------------------------------------------------------
-- amendable joint publication batches
--
-- A *batch* (pub_batches) is a series led by the analysis owner.  The owner
-- fixes the statistical specification once (ordered statements + their
-- snapshots), the minimum number of distinct participating teams (quorum)
-- and a books-closing instant for each *version* (pub_versions).
--
-- Version lifecycle: collecting -> sealed (one signed release manifest)
--                                \\-> void   (deadline passed below quorum;
--                                             every hold released)
--
-- A revision of a sealed version creates a child collecting version with the
-- SAME fixed specification (spec_hash lineage).  The chain is linear: a batch
-- may have at most one open (collecting) version at a time, so a late
-- contribution can never be ambiguous about which version it belongs to.
-- Late contributions to a closed version are rejected outright and must
-- enter the next (amended) version.
--
-- Teams register/withdraw while a version is collecting.  Registration places
-- pub_holds rows (exactly like job holds: spent is untouched but the amount is
-- unavailable to contenders); sealing computes every team's contribution in
-- ONE transaction -- results, budget charges, hold release, signed release --
-- or rolls the whole thing back leaving the version and ledger untouched.
-- Withdrawal or voiding releases the holds.  Duplicate registration replays
-- the stored contribution and never double-charges.
-- -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pub_batches (
    batch_id       TEXT PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    spec_hash      TEXT NOT NULL,   -- fixed statistical specification identity
    min_participants INTEGER NOT NULL,
    statement_count INTEGER NOT NULL,
    created_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pub_versions (
    version_id     TEXT PRIMARY KEY,
    batch_id       TEXT NOT NULL REFERENCES pub_batches(batch_id),
    seq            INTEGER NOT NULL,            -- 1 for the original, 2+ revisions
    parent_version_id TEXT,                      -- NULL for the original
    state          TEXT NOT NULL,               -- collecting | sealed | void
    close_at       TEXT NOT NULL,
    sealed_at      TEXT,
    voided_at      TEXT,
    manifest_json  TEXT,                         -- signed release once sealed
    manifest_digest TEXT,                        -- sha256 of the canonical manifest body
    created_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    UNIQUE(batch_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_pubver_state ON pub_versions(state);
CREATE INDEX IF NOT EXISTS idx_pubver_batch ON pub_versions(batch_id);

CREATE TABLE IF NOT EXISTS pub_statements (
    version_id     TEXT NOT NULL,
    position       INTEGER NOT NULL,
    snapshot_id    TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    query_hash     TEXT NOT NULL,
    family_id      TEXT NOT NULL,
    mechanism      TEXT NOT NULL,
    epsilon        REAL NOT NULL,
    delta          REAL NOT NULL,
    dimension      INTEGER NOT NULL,
    scale          REAL NOT NULL,
    sensitivity_l1 REAL NOT NULL,
    PRIMARY KEY (version_id, position)
);

-- one row per team that ever registered on a version; a withdrawn team keeps
-- the row (state='withdrawn') so its history and any re-registration replay
-- remain auditable
CREATE TABLE IF NOT EXISTS pub_contributions (
    version_id     TEXT NOT NULL,
    team_id        TEXT NOT NULL,
    state          TEXT NOT NULL,   -- registered | withdrawn
    epsilon_held   REAL NOT NULL DEFAULT 0,
    delta_held     REAL NOT NULL DEFAULT 0,
    epsilon_charged REAL NOT NULL DEFAULT 0,
    delta_charged  REAL NOT NULL DEFAULT 0,
    registered_at  TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (version_id, team_id)
);
CREATE INDEX IF NOT EXISTS idx_pubcontr_team ON pub_contributions(team_id);

-- per (version, team, snapshot) hold; counts against the team's available
-- budget exactly like budget_holds for multi-statement jobs
CREATE TABLE IF NOT EXISTS pub_holds (
    team_id     TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    version_id  TEXT NOT NULL,
    epsilon     REAL NOT NULL,
    delta       REAL NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (team_id, snapshot_id, version_id)
);
CREATE INDEX IF NOT EXISTS idx_pubholds_version ON pub_holds(version_id);

-- dense per-position member entries of a sealed release; the attribution of
-- every privacy charge to a team/result is re-checkable offline
CREATE TABLE IF NOT EXISTS pub_release_members (
    version_id  TEXT NOT NULL,
    position    INTEGER NOT NULL,
    team_id     TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    query_hash  TEXT NOT NULL,
    result_id   TEXT NOT NULL,
    charged     INTEGER NOT NULL,   -- 1 if this team paid for the result here
    epsilon     REAL NOT NULL,
    delta       REAL NOT NULL,
    PRIMARY KEY (version_id, position, team_id)
);
CREATE INDEX IF NOT EXISTS idx_pubrel_result ON pub_release_members(result_id);

-- -----------------------------------------------------------------------
-- controlled sharing packages
--
-- A *share* is a team-authorised, field-trimmed redistribution of one sealed
-- release manifest.  At creation the owner fixes the release (a sealed pub
-- version), an audience team and the exact field paths the team may receive;
-- every field must be inside the audience team's per-release field grant
-- (share_field_grants), so authorisation can never widen at request time.
--
-- Lifecycle: creating -> sealed (one immutable signed package, one share_key)
--                       \\-> failed (creation crashed/interrupted before seal)
--            sealed -> revoked (new retrievals rejected; the package file and
--                      its signature stay valid offline forever)
--
-- A sealed package binds, under the share HMAC: the release manifest_digest,
-- the parent release digest (lineage), the trimmed field set, the audience
-- team and the expiry instant -- so trimming/rebinding/extension attacks are
-- detectable offline.  Package bytes are content-addressed in home/shares;
-- the partial unique indexes guarantee one live share per
-- (version, team, field-set) and one share_key per live share, so concurrent
-- creates seal exactly one package and repeats replay the original.
-- -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS share_field_grants (
    version_id   TEXT NOT NULL,
    team_id      TEXT NOT NULL,
    fields_json  TEXT NOT NULL,       -- sorted canonical JSON field-path list
    granted_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    PRIMARY KEY (version_id, team_id)
);

CREATE TABLE IF NOT EXISTS shares (
    share_id        TEXT PRIMARY KEY,
    version_id      TEXT NOT NULL,
    team_id         TEXT NOT NULL,    -- audience
    fields_json     TEXT NOT NULL,    -- sorted field paths actually released
    fields_hash     TEXT NOT NULL,    -- sha256 of canonical fields_json
    state           TEXT NOT NULL,    -- creating | sealed | failed | revoked
    package_digest  TEXT,             -- sha256 of package bytes (content name)
    manifest_digest TEXT NOT NULL,    -- release manifest digest at creation
    parent_digest   TEXT,             -- parent release digest (lineage)
    share_key_hash  TEXT,             -- sha256(bearer share_key), live rows only
    ttl_seconds     INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    sealed_at       TEXT,
    revoked_at      TEXT,
    revoke_reason   TEXT,
    created_by      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shares_team ON shares(team_id);
CREATE INDEX IF NOT EXISTS idx_shares_version ON shares(version_id);
CREATE INDEX IF NOT EXISTS idx_shares_state ON shares(state);
-- exactly one live package per authorisation scope; terminal rows are excluded
-- so a failed/expired/revoked request may later be re-created cleanly
CREATE UNIQUE INDEX IF NOT EXISTS idx_share_scope_live ON shares(version_id, team_id, fields_hash)
    WHERE state IN ('creating', 'sealed');
CREATE UNIQUE INDEX IF NOT EXISTS idx_share_key_live ON shares(share_key_hash)
    WHERE state IN ('creating', 'sealed');

-- one row per (sealed share, retrieval attempt); repeated retrievals return
-- the SAME package and never regenerate it, but remain auditable
CREATE TABLE IF NOT EXISTS share_retrievals (
    share_id    TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    actor       TEXT NOT NULL,        -- team:<id> | admin
    outcome     TEXT NOT NULL,        -- ok | reject_revoked | reject_expired
    PRIMARY KEY (share_id, retrieved_at)
);

-- -----------------------------------------------------------------------
-- anti-fork transparency ledger
--
-- Every signed release (sealed / void publication version) and every
-- controlled-share issuance or revocation becomes one content-addressed leaf
-- of a single append-only Merkle log.  Business transactions first durable-row
-- their intent into tl_outbox *inside the same BEGIN IMMEDIATE transaction*
-- that performs the business change; after commit the same gateway lock
-- deterministically drains pending rows into tl_leaves and one monotonic
-- signed tl_checkpoints row per leaf.  A crash therefore leaves either no
-- business change or a recoverable outbox entry -- never a lost leaf, a gap,
-- a duplicate sequence or a second history.
--
-- event_key is the idempotency identity: replaying the same business event
-- returns the ORIGINAL leaf index; the same key with a different payload hash
-- is rejected (tl_outbox UNIQUE + explicit conflict).  The log never deletes
-- or rewrites; two different roots at the same tree size are a fork, which an
-- auditor submits as signed evidence to freeze all subsequent issuance.
-- -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tl_outbox (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,  -- deterministic drain order
    event_key    TEXT NOT NULL UNIQUE,               -- idempotency identity
    event_type   TEXT NOT NULL,   -- release_sealed | release_voided | share_issued | share_revoked
    leaf_hash    TEXT NOT NULL,   -- content-addressed leaf hash (sha256 hex)
    payload_hash TEXT NOT NULL,   -- replay-conflict detection
    envelope_json TEXT NOT NULL,  -- full canonical leaf envelope
    subject_id   TEXT NOT NULL,   -- version_id / share_id (recovery indexing)
    created_at   TEXT NOT NULL,
    actor        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tl_leaves (
    leaf_index   INTEGER PRIMARY KEY,   -- 0-based, dense, never reused
    event_key    TEXT NOT NULL UNIQUE,
    event_type   TEXT NOT NULL,
    leaf_hash    TEXT NOT NULL UNIQUE,  -- content address
    payload_hash TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    outbox_seq   INTEGER NOT NULL UNIQUE,
    incorporated_at TEXT NOT NULL
);

-- exactly one signed checkpoint per tree size; the single history is enforced
-- by tree_size PRIMARY KEY plus the strictly-monotonic prev_root chain
CREATE TABLE IF NOT EXISTS tl_checkpoints (
    tree_size      INTEGER PRIMARY KEY,   -- 0 = genesis
    root_hash      TEXT NOT NULL,
    prev_size      INTEGER,               -- NULL for the genesis checkpoint
    prev_root_hash TEXT,
    checkpoint_json TEXT NOT NULL,        -- signed, self-contained document
    created_at     TEXT NOT NULL
);

-- fork freeze: at most one row; its presence blocks every new issuance
CREATE TABLE IF NOT EXISTS tl_freeze (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    reason        TEXT NOT NULL,          -- fork_evidence | local_integrity_failure
    evidence_json TEXT,                   -- the two conflicting signed checkpoints
    frozen_by     TEXT NOT NULL,
    frozen_at     TEXT NOT NULL,
    tree_size     INTEGER NOT NULL        -- log height at which issuance stopped
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    # check_same_thread=False: the ThreadingHTTPServer hands work to worker
    # threads; all access is serialised by Gateway._lock + BEGIN IMMEDIATE.
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None,
                           check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=FULL")
    conn.executescript(SCHEMA)
    return conn
