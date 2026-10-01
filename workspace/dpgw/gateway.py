"""Core gateway service: budget accounting, idempotent execution, freezes,
snapshots and auditing.

Concurrency model
-----------------
One RLock serialises every mutating operation.  Query execution happens inside
``BEGIN IMMEDIATE`` so SQLite hands the write lock to exactly one request at a
time; the *reserve-or-cache* decision and the budget update are one atomic
transaction.  Concurrent retries of the same canonical query: the winner
computes and charges, the losers re-read the unique result row and return it as
``cached`` with no second charge.  Concurrent distinct queries that together
exceed a budget: the over-budget transaction is rolled back and rejected,
having charged nothing.

Failure accounting
------------------
Any failure before commit (inactive snapshot, frozen family, insufficient
budget, aggregation error, snapshot tampering) rolls the whole transaction
back, so failed queries are never charged.  Every attempt is still written to
the append-only audit log in its own transaction.

Snapshot replacement
--------------------
Snapshots are content addressed (new data => new snapshot_id).  Old snapshot
directories stay on disk and old signed receipts remain verifiable, but once a
(name, version) is deactivated/superseded no *new* query may execute against
it -- so an old cache can never spend the new snapshot's budget (budgets are
also keyed by (team, snapshot_id)).
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import sqlite3
import threading
from typing import Any

from . import snapshot as snapmod
from .canonical import (
    family_fingerprint,
    normalize_query,
    query_hash,
)
from .engine import aggregate
from .errors import (
    DPGWError,
    Forbidden,
    FrozenQuery,
    InvalidSnapshot,
    BudgetExceeded,
    BudgetInvalid,
    ResultNotFound,
    SnapshotAlreadyExists,
    SnapshotInactive,
    SnapshotNotFound,
    TeamAlreadyExists,
    TeamNotFound,
)
from .privacy import expected_cost, noisy_vector, round6
from .receipts import build_result_receipt, dumps_canon, hmac_sign, signed, token_hash

from .util import EPS_TOLERANCE, new_id, utcnow

# Job support lives in dpgw.jobs; both modules share dpgw.util primitives, so
# there is no import cycle regardless of which module is imported first.
from .jobs import JobsMixin  # noqa: E402
from .publications import PublishingMixin  # noqa: E402
from .shares import SharingMixin  # noqa: E402
from .transparency import TransparencyMixin  # noqa: E402


class Gateway(JobsMixin, PublishingMixin, SharingMixin, TransparencyMixin):
    def __init__(self, db_conn: sqlite3.Connection, snap_root: str, secrets_: dict):
        self.db = db_conn
        self.snap_root = snap_root
        self.noise_seed = secrets_["noise_master_seed"]
        self.receipt_key = secrets_["receipt_secret"]
        # dedicated HMAC key for controlled sharing packages (secrets.json);
        # offline verifiers need the same key to validate downloaded packages
        self.share_secret = secrets_["share_secret"]
        # dedicated key signing transparency checkpoints; fork-evidence
        # verification only trusts checkpoints signed with this key
        self.transparency_key = secrets_["transparency_secret"]
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ #
    # internal helpers
    # ------------------------------------------------------------------ #

    def _audit(
        self,
        *,
        actor: str,
        action: str,
        outcome: str,
        team_id: str | None = None,
        snapshot_id: str | None = None,
        result_id: str | None = None,
        query_hash_hex: str | None = None,
        family_id: str | None = None,
        request_id: str | None = None,
        epsilon: float | None = None,
        delta: float | None = None,
        detail: Any = None,
    ):
        with self._lock:
            self.db.execute(
                """INSERT INTO audit_log
                   (ts, actor, action, outcome, team_id, snapshot_id, result_id,
                    query_hash, family_id, request_id, epsilon, delta, detail_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    utcnow(),
                    actor,
                    action,
                    outcome,
                    team_id,
                    snapshot_id,
                    result_id,
                    query_hash_hex,
                    family_id,
                    request_id,
                    epsilon,
                    delta,
                    None if detail is None else dumps_canon(detail),
                ),
            )

    def _get_team_conn(self, team_id: str) -> sqlite3.Row:
        row = self.db.execute("SELECT * FROM teams WHERE team_id=?", (team_id,)).fetchone()
        if row is None:
            raise TeamNotFound(f"team {team_id!r} not found")
        return row

    def authenticate(self, token: str) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM teams WHERE token_sha256=?", (token_hash(token),)
        ).fetchone()
        if row is None:
            raise Forbidden("invalid team token")
        return row

    def check_admin(self, token: str) -> bool:
        """Constant-time check of the bootstrap admin token."""
        stored = self.db.execute("SELECT value FROM meta WHERE key='admin_token_sha256'").fetchone()
        if stored is None:
            return False
        return hmac.compare_digest(stored["value"], token_hash(token))

    def _resolve_snapshot(self, ref: dict) -> sqlite3.Row:
        if ref.get("snapshot_id"):
            row = self.db.execute(
                "SELECT * FROM snapshots WHERE snapshot_id=?", (ref["snapshot_id"],)
            ).fetchone()
        else:
            name = ref.get("name")
            version = ref.get("version")
            if not name or not version:
                raise SnapshotNotFound("snapshot ref requires snapshot_id or name+version")
            row = self.db.execute(
                "SELECT * FROM snapshots WHERE name=? AND version=?", (name, version)
            ).fetchone()
        if row is None:
            raise SnapshotNotFound("snapshot not registered")
        return row

    def _matching_freeze(self, fam_masked: str, fam_exact: str,
                         team_id: str, snapshot_id: str) -> sqlite3.Row | None:
        for fid in (fam_masked, fam_exact):
            rows = self.db.execute(
                "SELECT * FROM freezes WHERE family_id=?", (fid,)
            ).fetchall()
            for r in rows:
                scope = r["scope"]
                if scope == "global":
                    return r
                if scope == "team" and r["team_id"] == team_id:
                    return r
                if scope == "snapshot" and r["snapshot_id"] == snapshot_id:
                    return r
                if (
                    scope == "team_snapshot"
                    and r["team_id"] == team_id
                    and r["snapshot_id"] == snapshot_id
                ):
                    return r
        return None

    # ------------------------------------------------------------------ #
    # team administration
    # ------------------------------------------------------------------ #

    def create_team(self, name: str, *, actor: str = "admin") -> dict:
        with self._lock:
            team_id = new_id("team")
            token = "dpt_" + secrets.token_urlsafe(24)
            try:
                self.db.execute(
                    "INSERT INTO teams (team_id, name, token_sha256, created_at, created_by)"
                    " VALUES (?,?,?,?,?)",
                    (team_id, name, token_hash(token), utcnow(), actor),
                )
            except sqlite3.IntegrityError:
                raise TeamAlreadyExists(f"team name {name!r} already exists")
            self._audit(actor=actor, action="admin_create_team", outcome="ok",
                        team_id=team_id, detail={"name": name})
            return {"team_id": team_id, "name": name, "token": token}

    def list_teams(self) -> list[dict]:
        rows = self.db.execute("SELECT team_id, name, created_at, created_by FROM teams").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ #
    # snapshots
    # ------------------------------------------------------------------ #

    def publish_snapshot(self, snap_dir: str, *, actor: str = "admin",
                         activate: bool = True) -> dict:
        """Register a built snapshot directory; verifies content hashes first."""
        with self._lock:
            path = os.path.abspath(snap_dir)
            manifest = snapmod.load_manifest_file(os.path.join(path, snapmod.MANIFEST_NAME))
            sid = manifest["snapshot_id"]

            check = snapmod.verify_snapshot_dir(path)
            if not check["ok"]:
                raise InvalidSnapshot("snapshot content verification failed")

            existing = self.db.execute(
                "SELECT * FROM snapshots WHERE name=? AND version=?",
                (manifest["name"], manifest["version"]),
            ).fetchone()
            if existing is not None:
                raise SnapshotAlreadyExists(
                    f"snapshot {manifest['name']}@{manifest['version']} already exists"
                )
            if self.db.execute("SELECT 1 FROM snapshots WHERE snapshot_id=?", (sid,)).fetchone():
                raise SnapshotAlreadyExists(f"snapshot_id {sid} already registered")

            # canonical storage: copy/register under snap_root/<snapshot_id>
            dest = os.path.join(self.snap_root, sid)
            if os.path.abspath(path) != os.path.abspath(dest):
                if os.path.exists(dest):
                    raise SnapshotAlreadyExists("snapshot storage path already exists")
                # copy read-only files
                os.makedirs(dest)
                for fn in (snapmod.MANIFEST_NAME, snapmod.DATA_NAME):
                    src_f = os.path.join(path, fn)
                    dst_f = os.path.join(dest, fn)
                    with open(src_f, "rb") as a, open(dst_f, "wb") as b:
                        b.write(a.read())
                    os.chmod(dst_f, 0o444)
                stored = dest
            else:
                stored = dest

            self.db.execute(
                """INSERT INTO snapshots
                   (snapshot_id, name, version, path, manifest_json, active,
                    published_at, published_by)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    sid,
                    manifest["name"],
                    manifest["version"],
                    stored,
                    dumps_canon(manifest),
                    1 if activate else 0,
                    utcnow(),
                    actor,
                ),
            )
            self._audit(actor=actor, action="admin_publish_snapshot", outcome="ok",
                        snapshot_id=sid,
                        detail={"name": manifest["name"], "version": manifest["version"],
                                "active": activate})
            return {"snapshot_id": sid, "name": manifest["name"],
                    "version": manifest["version"], "active": activate, "path": stored}

    def set_snapshot_active(self, snapshot_id: str, active: bool, *, actor: str = "admin"):
        with self._lock:
            row = self.db.execute("SELECT 1 FROM snapshots WHERE snapshot_id=?",
                                  (snapshot_id,)).fetchone()
            if row is None:
                raise SnapshotNotFound(snapshot_id)
            self.db.execute("UPDATE snapshots SET active=? WHERE snapshot_id=?",
                            (1 if active else 0, snapshot_id))
            self._audit(actor=actor,
                        action="admin_set_snapshot_active" if active else "admin_deactivate_snapshot",
                        outcome="ok", snapshot_id=snapshot_id, detail={"active": active})

    def list_snapshots(self, include_inactive: bool = True) -> list[dict]:
        sql = "SELECT snapshot_id, name, version, active, published_at, published_by FROM snapshots"
        if not include_inactive:
            sql += " WHERE active=1"
        sql += " ORDER BY published_at"
        return [dict(r) for r in self.db.execute(sql).fetchall()]

    # ------------------------------------------------------------------ #
    # budgets
    # ------------------------------------------------------------------ #

    def allocate_budget(self, team_id: str, snapshot_id: str,
                        epsilon_limit: float, delta_limit: float,
                        *, actor: str = "admin") -> dict:
        with self._lock:
            self._get_team_conn(team_id)
            if self.db.execute("SELECT 1 FROM snapshots WHERE snapshot_id=?",
                               (snapshot_id,)).fetchone() is None:
                raise SnapshotNotFound(snapshot_id)
            if not isinstance(epsilon_limit, (int, float)) or epsilon_limit <= 0:
                raise BudgetInvalid("epsilon_limit must be positive")
            if not isinstance(delta_limit, (int, float)) or not (0 <= delta_limit < 1):
                raise BudgetInvalid("delta_limit must satisfy 0 <= delta_limit < 1")
            epsilon_limit, delta_limit = float(epsilon_limit), float(delta_limit)

            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute(
                    "SELECT epsilon_spent, delta_spent FROM budgets WHERE team_id=? AND snapshot_id=?",
                    (team_id, snapshot_id),
                ).fetchone()
                if row is not None:
                    if epsilon_limit < row["epsilon_spent"] - EPS_TOLERANCE:
                        raise BudgetInvalid(
                            f"cannot lower epsilon below spent {row['epsilon_spent']}"
                        )
                    if delta_limit < row["delta_spent"] - EPS_TOLERANCE:
                        raise BudgetInvalid(
                            f"cannot lower delta below spent {row['delta_spent']}"
                        )
                    self.db.execute(
                        """UPDATE budgets SET epsilon_limit=?, delta_limit=?,
                           allocated_at=?, allocated_by=? WHERE team_id=? AND snapshot_id=?""",
                        (epsilon_limit, delta_limit, utcnow(), actor, team_id, snapshot_id),
                    )
                else:
                    self.db.execute(
                        """INSERT INTO budgets
                           (team_id, snapshot_id, epsilon_limit, delta_limit,
                            epsilon_spent, delta_spent, allocated_at, allocated_by)
                           VALUES (?,?,?,?,0,0,?,?)""",
                        (team_id, snapshot_id, epsilon_limit, delta_limit, utcnow(), actor),
                    )
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            self._audit(actor=actor, action="admin_allocate_budget", outcome="ok",
                        team_id=team_id, snapshot_id=snapshot_id,
                        epsilon=epsilon_limit, delta=delta_limit)
            return self.get_budget(team_id, snapshot_id)

    def get_budget(self, team_id: str, snapshot_id: str) -> dict:
        row = self.db.execute(
            "SELECT * FROM budgets WHERE team_id=? AND snapshot_id=?",
            (team_id, snapshot_id),
        ).fetchone()
        if row is None:
            raise BudgetInvalid("no budget allocated for team on snapshot")
        d = dict(row)
        he, hd = self._holds_total(team_id, snapshot_id)
        d["epsilon_held"] = round(he, 9)
        d["delta_held"] = round(hd, 12)
        d["epsilon_remaining"] = round(d["epsilon_limit"] - d["epsilon_spent"] - he, 9)
        d["delta_remaining"] = round(d["delta_limit"] - d["delta_spent"] - hd, 12)
        return d

    def list_budgets(self, team_id: str | None = None) -> list[dict]:
        if team_id:
            rows = self.db.execute(
                "SELECT * FROM budgets WHERE team_id=? ORDER BY allocated_at", (team_id,)
            ).fetchall()
        else:
            rows = self.db.execute("SELECT * FROM budgets ORDER BY allocated_at").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            he, hd = self._holds_total(d["team_id"], d["snapshot_id"])
            d["epsilon_held"] = round(he, 9)
            d["delta_held"] = round(hd, 12)
            d["epsilon_remaining"] = round(d["epsilon_limit"] - d["epsilon_spent"] - he, 9)
            d["delta_remaining"] = round(d["delta_limit"] - d["delta_spent"] - hd, 12)
            out.append(d)
        return out

    # ------------------------------------------------------------------ #
    # query planning (no charge, no execution)
    # ------------------------------------------------------------------ #

    def plan(self, team_id: str, snapshot_ref: dict, query: dict,
             *, request_id: str | None = None) -> dict:
        """Normalise + sensitivity + estimated cost.  Never charges budget."""
        with self._lock:
            snap_row = self._resolve_snapshot(snapshot_ref)
            manifest = json.loads(snap_row["manifest_json"])
            canonical = normalize_query(query, manifest)
            qhash = query_hash(canonical)
            fam_masked = family_fingerprint(canonical, mask_literals=True)
            fam_exact = family_fingerprint(canonical, mask_literals=False)

            dim = self._dimension(canonical, manifest)
            cost = expected_cost(canonical, dim)

            cached = self.db.execute(
                "SELECT result_id FROM results WHERE team_id=? AND snapshot_id=? AND query_hash=?",
                (team_id, snap_row["snapshot_id"], qhash),
            ).fetchone()
            budget = self.db.execute(
                "SELECT * FROM budgets WHERE team_id=? AND snapshot_id=?",
                (team_id, snap_row["snapshot_id"]),
            ).fetchone()
            frozen = self._matching_freeze(fam_masked, fam_exact,
                                           team_id, snap_row["snapshot_id"])
            return {
                "snapshot_id": snap_row["snapshot_id"],
                "snapshot_active": bool(snap_row["active"]),
                "query_hash": qhash,
                "family_id": fam_masked,
                "family_id_exact": fam_exact,
                "canonical": canonical,
                "dimension": dim,
                "sensitivity_l1": cost["params"]["sensitivity_l1"],
                "sensitivity_l2": cost["params"]["sensitivity_l2"],
                "mechanism": cost["params"]["mechanism"],
                "noise_scale": cost["params"]["scale"],
                "estimated_cost": {"epsilon": cost["epsilon"], "delta": cost["delta"]},
                "already_cached": cached is not None,
                "frozen": frozen is not None,
                "budget": (
                    None
                    if budget is None
                    else {
                        "epsilon_limit": budget["epsilon_limit"],
                        "delta_limit": budget["delta_limit"],
                        "epsilon_spent": budget["epsilon_spent"],
                        "delta_spent": budget["delta_spent"],
                        "epsilon_remaining": budget["epsilon_limit"] - budget["epsilon_spent"],
                        "delta_remaining": budget["delta_limit"] - budget["delta_spent"],
                    }
                ),
            }

    def _dimension(self, canonical: dict, manifest: dict) -> int:
        if canonical["type"] == "count":
            return 1
        if canonical["type"] == "grouped_count":
            columns = {c["name"]: c for c in manifest["columns"]}
            dim = 1
            for name in canonical["group_by"]:
                dim *= len(columns[name]["domain"])
            return dim + 1
        return len(canonical["bin_edges"])  # n-1 bins + null bin

    # ------------------------------------------------------------------ #
    # query execution
    # ------------------------------------------------------------------ #

    def execute_query(self, team_id: str, snapshot_ref: dict, query: dict,
                      *, actor: str | None = None, request_id: str | None = None) -> dict:
        actor = actor or ("team:" + team_id)
        with self._lock:
            snap_row = self._resolve_snapshot(snapshot_ref)
            sid = snap_row["snapshot_id"]
            manifest = json.loads(snap_row["manifest_json"])

            canonical = normalize_query(query, manifest)

            qhash = query_hash(canonical)
            fam_masked = family_fingerprint(canonical, mask_literals=True)
            fam_exact = family_fingerprint(canonical, mask_literals=False)

            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                # 1) idempotent cache hit -> original result, zero charge, even
                #    when the family is now frozen or the snapshot superseded.
                cached = self.db.execute(
                    "SELECT * FROM results WHERE team_id=? AND snapshot_id=? AND query_hash=?",
                    (team_id, sid, qhash),
                ).fetchone()
                if cached is not None:
                    budget = self._budget_row(team_id, sid)
                    self.db.execute("COMMIT")
                    committed = True
                    resp = self._result_response(cached, budget, cached_=True)
                    self._audit(actor=actor, action="query", outcome="ok_cached",
                                team_id=team_id, snapshot_id=sid,
                                result_id=cached["result_id"], query_hash_hex=qhash,
                                family_id=fam_masked, request_id=request_id)
                    return resp

                # 2) not cached: snapshot must be active
                if not snap_row["active"]:
                    raise SnapshotInactive(
                        f"snapshot {manifest['name']}@{manifest['version']} is no longer active; "
                        "re-submit the query against the current snapshot",
                        family_id=fam_masked,
                    )

                # 3) suspected combination-attack family freeze -> uniform reject
                freeze = self._matching_freeze(fam_masked, fam_exact, team_id, sid)
                if freeze is not None:
                    raise FrozenQuery(
                        f"query family {freeze['family_id']} is frozen: {freeze['reason']}",
                        action="reject_frozen",
                        family_id=fam_masked,
                    )

                # 4) budget must exist and comfortably cover the full cost.
                # Budget locked by pending multi-statement jobs is unavailable:
                # concurrent contenders must never overspend the shared ledger.
                eps_remaining, delta_remaining, budget = self._available_budget(team_id, sid)
                dimension = self._dimension(canonical, manifest)
                cost = expected_cost(canonical, dimension)
                eps_need, delta_need = cost["epsilon"], cost["delta"]
                if eps_need > eps_remaining + EPS_TOLERANCE or delta_need > delta_remaining + EPS_TOLERANCE:
                    raise BudgetExceeded(
                        f"need (eps={eps_need},delta={delta_need}); "
                        f"remaining (eps={round(eps_remaining, 9)},"
                        f"delta={round(delta_remaining, 12)})",
                        action="reject_budget",
                        family_id=fam_masked,
                        epsilon=eps_need, delta=delta_need,
                    )

                # 5) verify snapshot integrity, compute the true vector
                check = snapmod.verify_snapshot(os.path.dirname(snap_row["path"]), sid)
                if not check["ok"]:
                    raise InvalidSnapshot("snapshot integrity check failed")
                conn = snapmod.open_data(os.path.dirname(snap_row["path"]), sid)
                try:
                    agg = aggregate(canonical, manifest, conn)
                finally:
                    conn.close()

                # 6) stable noise from the master seed
                params = cost["params"]
                noise = noisy_vector(
                    self.noise_seed, team_id, sid, qhash, agg["coords"], params
                )
                values = [round6(t + n) for t, n in zip(agg["true"], noise)]

                result_id = new_id("res")
                created_at = utcnow()
                self.db.execute(
                    """INSERT INTO results
                       (result_id, team_id, snapshot_id, query_hash, family_id,
                        canonical_json, mechanism, epsilon, delta, dimension,
                        sensitivity_l1, scale, coords_json, values_json, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        result_id, team_id, sid, qhash, fam_masked,
                        dumps_canon(canonical), params["mechanism"], eps_need, delta_need,
                        dimension, params["sensitivity_l1"], params["scale"],
                        dumps_canon(agg["coords"]), dumps_canon(values), created_at,
                    ),
                )
                self.db.execute(
                    """UPDATE budgets SET epsilon_spent=epsilon_spent+?,
                       delta_spent=delta_spent+? WHERE team_id=? AND snapshot_id=?""",
                    (eps_need, delta_need, team_id, sid),
                )
                self.db.execute("COMMIT")
                committed = True
            except DPGWError:
                if not committed:
                    self.db.execute("ROLLBACK")
                raise
            except Exception:
                if not committed:
                    self.db.execute("ROLLBACK")
                raise
            finally:
                # audit the attempt outcome after the transaction settles
                if not committed:
                    pass  # audited by callers below via exception mapping

            row = self.db.execute("SELECT * FROM results WHERE result_id=?", (result_id,)).fetchone()
            budget = self._budget_row(team_id, sid)
            resp = self._result_response(row, budget, cached_=False)
            self._audit(actor=actor, action="query", outcome="ok_executed",
                        team_id=team_id, snapshot_id=sid, result_id=result_id,
                        query_hash_hex=qhash, family_id=fam_masked,
                        request_id=request_id, epsilon=eps_need, delta=delta_need)
            return resp

    def _budget_row(self, team_id: str, sid: str) -> sqlite3.Row:
        budget = self.db.execute(
            "SELECT * FROM budgets WHERE team_id=? AND snapshot_id=?", (team_id, sid)
        ).fetchone()
        if budget is None:
            raise BudgetExceeded("no privacy budget allocated for team on this snapshot",
                                 action="reject_budget")
        return budget

    def _result_response(self, row: sqlite3.Row, budget: sqlite3.Row, *, cached_: bool) -> dict:
        coords = json.loads(row["coords_json"])
        values = json.loads(row["values_json"])
        canonical = json.loads(row["canonical_json"])
        created = row["created_at"]

        if row["mechanism"] == "laplace":
            dp = {"epsilon": row["epsilon"], "delta": 0.0}
        else:
            dp = {"epsilon": row["epsilon"], "delta": row["delta"]}

        receipt_body = build_result_receipt(
            result_id=row["result_id"], team_id=row["team_id"],
            snapshot_id=row["snapshot_id"], query_hash=row["query_hash"],
            family_id=row["family_id"], canonical=canonical,
            mechanism=row["mechanism"], epsilon=row["epsilon"], delta=row["delta"],
            dimension=row["dimension"], sensitivity_l1=row["sensitivity_l1"],
            scale=row["scale"], coords=coords, values=values, created_at=created,
        )
        receipt = signed(receipt_body, self.receipt_key)

        return {
            "result_id": row["result_id"],
            "snapshot_id": row["snapshot_id"],
            "query_hash": row["query_hash"],
            "family_id": row["family_id"],
            "canonical": canonical,
            "mechanism": row["mechanism"],
            "privacy_cost": dp,
            "dimension": row["dimension"],
            "sensitivity_l1": row["sensitivity_l1"],
            "noise_scale": row["scale"],
            "coords": coords,
            "values": values,
            "cached": cached_,
            "charged": not cached_,
            "created_at": created,
            "budget": self._budget_summary(budget),
            "receipt": receipt,
        }

    def _budget_summary(self, budget: sqlite3.Row) -> dict:
        he, hd = self._holds_total(budget["team_id"], budget["snapshot_id"])
        return {
            "epsilon_limit": budget["epsilon_limit"],
            "delta_limit": budget["delta_limit"],
            "epsilon_spent": budget["epsilon_spent"],
            "delta_spent": budget["delta_spent"],
            "epsilon_held": round(he, 9),
            "delta_held": round(hd, 12),
            "epsilon_remaining": round(budget["epsilon_limit"] - budget["epsilon_spent"] - he, 9),
            "delta_remaining": round(budget["delta_limit"] - budget["delta_spent"] - hd, 12),
        }

    # exception-mapped wrapper used by the HTTP layer so every rejected query
    # gets one audit entry regardless of rejection reason
    def run_query(self, team_id: str, snapshot_ref: dict, query: dict,
                  *, request_id: str | None = None) -> dict:
        actor = "team:" + team_id
        try:
            return self.execute_query(team_id, snapshot_ref, query,
                                      actor=actor, request_id=request_id)
        except (BudgetExceeded, FrozenQuery, SnapshotInactive, DPGWError) as e:
            outcome = {
                BudgetExceeded: "reject_budget",
                FrozenQuery: "reject_frozen",
                SnapshotInactive: "reject_inactive",
            }.get(type(e), "reject_" + e.code)
            self._audit(actor=actor, action="query", outcome=outcome,
                        team_id=team_id, request_id=request_id,
                        family_id=e.extra.get("family_id"),
                        epsilon=e.extra.get("epsilon"),
                        delta=e.extra.get("delta"),
                        detail={"error": e.message})
            raise

    def get_result(self, team_id: str, result_id: str) -> dict:
        """Fetch an already-executed result (cache replay; never charges)."""
        row = self.db.execute(
            "SELECT * FROM results WHERE result_id=? AND team_id=?",
            (result_id, team_id),
        ).fetchone()
        if row is None:
            raise ResultNotFound(result_id)
        budget = self._budget_row(team_id, row["snapshot_id"])
        return self._result_response(row, budget, cached_=True)

    def list_results(self, team_id: str, snapshot_id: str | None = None) -> list[dict]:
        if snapshot_id:
            rows = self.db.execute(
                "SELECT * FROM results WHERE team_id=? AND snapshot_id=? ORDER BY created_at",
                (team_id, snapshot_id),
            ).fetchall()
        else:
            rows = self.db.execute(
                "SELECT * FROM results WHERE team_id=? ORDER BY created_at", (team_id,)
            ).fetchall()
        return [
            {
                "result_id": r["result_id"],
                "snapshot_id": r["snapshot_id"],
                "query_hash": r["query_hash"],
                "family_id": r["family_id"],
                "type": json.loads(r["canonical_json"])["type"],
                "mechanism": r["mechanism"],
                "epsilon": r["epsilon"],
                "delta": r["delta"],
                "dimension": r["dimension"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------ #
    # freezes
    # ------------------------------------------------------------------ #

    def freeze_family(self, family_id: str, *, scope: str = "global",
                      team_id: str | None = None, snapshot_id: str | None = None,
                      reason: str = "", actor: str = "admin") -> dict:
        if scope not in ("global", "team", "snapshot", "team_snapshot"):
            raise BudgetInvalid("scope must be global|team|snapshot|team_snapshot")
        if scope in ("team", "team_snapshot") and not team_id:
            raise BudgetInvalid("team scope requires team_id")
        if scope in ("snapshot", "team_snapshot") and not snapshot_id:
            raise BudgetInvalid("snapshot scope requires snapshot_id")
        if len(family_id) != 32:
            raise BudgetInvalid("family_id must be a 32-char fingerprint (see /v1/plan)")
        with self._lock:
            freeze_id = new_id("frz")
            self.db.execute(
                """INSERT INTO freezes
                   (freeze_id, family_id, scope, team_id, snapshot_id, reason,
                    created_by, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (freeze_id, family_id, scope, team_id, snapshot_id, reason, actor, utcnow()),
            )
            self._audit(actor=actor, action="admin_freeze", outcome="ok",
                        team_id=team_id, snapshot_id=snapshot_id, family_id=family_id,
                        detail={"freeze_id": freeze_id, "scope": scope, "reason": reason})
            return {"freeze_id": freeze_id, "family_id": family_id, "scope": scope,
                    "team_id": team_id, "snapshot_id": snapshot_id, "reason": reason,
                    "created_at": utcnow()}

    def list_freezes(self) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM freezes ORDER BY created_at").fetchall()]

    def unfreeze(self, freeze_id: str, *, actor: str = "admin"):
        with self._lock:
            row = self.db.execute("SELECT * FROM freezes WHERE freeze_id=?",
                                  (freeze_id,)).fetchone()
            if row is None:
                raise ResultNotFound(f"freeze {freeze_id} not found")
            self.db.execute("DELETE FROM freezes WHERE freeze_id=?", (freeze_id,))
            self._audit(actor=actor, action="admin_unfreeze", outcome="ok",
                        family_id=row["family_id"], detail={"freeze_id": freeze_id})

    # ------------------------------------------------------------------ #
    # audit
    # ------------------------------------------------------------------ #

    def list_audit(self, *, family_id: str | None = None, team_id: str | None = None,
                   snapshot_id: str | None = None, result_id: str | None = None,
                   limit: int = 200) -> list[dict]:
        where, params = [], []
        for col, val in (("family_id", family_id), ("team_id", team_id),
                         ("snapshot_id", snapshot_id), ("result_id", result_id)):
            if val:
                where.append(f"{col}=?")
                params.append(val)
        sql = "SELECT * FROM audit_log"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(min(int(limit), 5000))
        out = []
        for r in self.db.execute(sql, params).fetchall():
            d = dict(r)
            if d.get("detail_json"):
                d["detail"] = json.loads(d["detail_json"])
            del d["detail_json"]
            out.append(d)
        return out
