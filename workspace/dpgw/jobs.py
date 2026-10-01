"""Recoverable multi-statement analysis jobs (two-phase tickets).

An analyst submits a batch of statistical statements in one call.  The gateway

1. parses *every* statement (any failure rejects the whole submission -- no
   ticket, no charge, no hold);
2. issues a signed *ticket* with an expiry, simultaneously placing
   ``budget_holds`` rows that lock exactly the epsilon/delta the job needs per
   (team, snapshot) -- cache replays it already owes need no hold;
3. on confirmation, validates the world once more (snapshot still active,
   family not frozen, ticket not expired, budget still covers the hold) and
   then runs the whole batch inside ONE ``BEGIN IMMEDIATE`` transaction:
   every result row and every budget update commits together, or none do.

Cancellation and expiry return every still-unconsumed hold.  The state machine
is crash safe: ``executing`` jobs left behind by a restart (or jobs expiring
before confirm) are reconciled by :meth:`JobsMixin.recover_pending_jobs`, and
terminal jobs can never keep holds.

Idempotency: ``(team_id, request_key)`` is UNIQUE.  Retrying the same key
replays the first ticket; reusing a key with a different payload is a
``job_conflict``.  Because all holds are taken inside a write transaction and
the single-query path also subtracts active holds from the available budget,
concurrent contenders for one budget can never overspend it.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from . import snapshot as snapmod
from .canonical import family_fingerprint, normalize_query, query_hash
from .engine import aggregate
from .errors import (
    BudgetExceeded,
    DPGWError,
    FrozenQuery,
    InvalidQuery,
    InvalidSnapshot,
    JobConflict,
    JobInvalid,
    JobNotFound,
    JobStateConflict,
    JobTicketExpired,
    SnapshotInactive,
)
from .privacy import expected_cost, noisy_vector
from .receipts import (
    JOB_MANIFEST_VERSION,
    JOB_TICKET_VERSION,
    build_result_receipt,
    dumps_canon,
    sha256_hex,
    signed,
)
from .util import EPS_TOLERANCE, new_id, utcnow

MAX_JOB_STATEMENTS = 200
DEFAULT_TTL_SECONDS = 600
MAX_TTL_SECONDS = 86400

ACTIVE_STATES = ("reserved", "executing")


def _parse_ts(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def _plus_ttl(now: datetime, ttl_seconds: int) -> str:
    return (now + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class JobsMixin:
    """Resumable multi-statement job support; mixed into :class:`Gateway`."""

    # ------------------------------------------------------------------ #
    # shared budget arithmetic (also used by the single-query path)
    # ------------------------------------------------------------------ #

    def _holds_total(self, team_id: str, snapshot_id: str,
                     exclude_job: str | None = None,
                     exclude_pub_version: str | None = None) -> tuple[float, float]:
        """Sum of epsilon/delta locked by active job holds and open
        publication-batch holds (both kinds keep budget unavailable)."""
        job_sql = (
            "SELECT h.epsilon, h.delta FROM budget_holds h "
            "JOIN jobs j ON j.job_id = h.job_id "
            "WHERE h.team_id=? AND h.snapshot_id=? AND j.state IN ('reserved','executing')"
        )
        job_params: list[Any] = [team_id, snapshot_id]
        if exclude_job:
            job_sql += " AND h.job_id != ?"
            job_params.append(exclude_job)
        pub_sql = (
            "SELECT p.epsilon, p.delta FROM pub_holds p "
            "JOIN pub_versions v ON v.version_id = p.version_id "
            "WHERE p.team_id=? AND p.snapshot_id=? AND v.state='collecting'"
        )
        pub_params: list[Any] = [team_id, snapshot_id]
        if exclude_pub_version:
            pub_sql += " AND p.version_id != ?"
            pub_params.append(exclude_pub_version)
        row = self.db.execute(
            "SELECT COALESCE(SUM(x.epsilon),0) e, COALESCE(SUM(x.delta),0) d FROM ("
            + job_sql + " UNION ALL " + pub_sql + ") x",
            job_params + pub_params,
        ).fetchone()
        return float(row["e"]), float(row["d"])

    def _available_budget(self, team_id: str, snapshot_id: str,
                          exclude_job: str | None = None,
                          exclude_pub_version: str | None = None
                          ) -> tuple[float, float, sqlite3.Row]:
        """(epsilon_available, delta_available, budget_row) counting active holds."""
        budget = self._budget_row(team_id, snapshot_id)
        he, hd = self._holds_total(team_id, snapshot_id, exclude_job,
                                   exclude_pub_version)
        return (
            budget["epsilon_limit"] - budget["epsilon_spent"] - he,
            budget["delta_limit"] - budget["delta_spent"] - hd,
            budget,
        )

    # ------------------------------------------------------------------ #
    # statement preparation (read-only validation, nothing is written)
    # ------------------------------------------------------------------ #

    def _prepare_statements(self, team_id: str, statements: list) -> list[dict]:
        """Resolve + normalise + cost every member.  All-or-nothing validation."""
        if not isinstance(statements, list) or not statements:
            raise JobInvalid("job requires a non-empty 'statements' list")
        if len(statements) > MAX_JOB_STATEMENTS:
            raise JobInvalid(f"a job may contain at most {MAX_JOB_STATEMENTS} statements")

        prepared: list[dict] = []
        for pos, item in enumerate(statements):
            if not isinstance(item, dict):
                raise InvalidQuery(f"statement[{pos}] must be an object")
            snap_ref = item.get("snapshot")
            query = item.get("query")
            if not isinstance(snap_ref, dict) or not isinstance(query, dict):
                raise InvalidQuery(
                    f"statement[{pos}] requires 'snapshot' (object) and 'query' (object)"
                )
            snap_row = self._resolve_snapshot(snap_ref)
            sid = snap_row["snapshot_id"]
            manifest = json.loads(snap_row["manifest_json"])
            canonical = normalize_query(query, manifest)
            qhash = query_hash(canonical)
            fam = family_fingerprint(canonical, mask_literals=True)
            dim = self._dimension(canonical, manifest)
            cost = expected_cost(canonical, dim)
            prepared.append({
                "position": pos,
                "snapshot_id": sid,
                "snapshot_active": bool(snap_row["active"]),
                "manifest": manifest,
                "snap_path": snap_row["path"],
                "canonical": canonical,
                "query_hash": qhash,
                "family_id": fam,
                "epsilon": cost["epsilon"],
                "delta": cost["delta"],
                "params": cost["params"],
                "dimension": dim,
            })
        return prepared

    @staticmethod
    def _payload_hash(team_id: str, prepared: list[dict]) -> str:
        """Identity of the submitted batch; reusing a key with another payload conflicts."""
        members = [
            {
                "p": m["position"],
                "s": m["snapshot_id"],
                "q": m["query_hash"],
                "e": m["epsilon"],
                "d": m["delta"],
            }
            for m in prepared
        ]
        return sha256_hex(team_id + ":" + dumps_canon(members))

    # ------------------------------------------------------------------ #
    # phase 1: create the ticket and lock the budget
    # ------------------------------------------------------------------ #

    def create_job(self, team_id: str, statements: list, *,
                   request_key: str | None = None, ttl_seconds: int | None = None,
                   actor: str | None = None, request_id: str | None = None) -> dict:
        actor = actor or ("team:" + team_id)
        if not request_key or not isinstance(request_key, str):
            raise JobInvalid("job submission requires a client-supplied request_key")
        ttl = DEFAULT_TTL_SECONDS if ttl_seconds is None else int(ttl_seconds)
        if not (1 <= ttl <= MAX_TTL_SECONDS):
            raise JobInvalid(f"ttl_seconds must be in 1..{MAX_TTL_SECONDS}")

        # all-or-nothing parse before anything is written
        prepared = self._prepare_statements(team_id, statements)
        payload_hash = self._payload_hash(team_id, prepared)

        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            job_id = eps_res = delta_res = None
            try:
                existing = self.db.execute(
                    "SELECT * FROM jobs WHERE team_id=? AND request_key=?",
                    (team_id, request_key),
                ).fetchone()
                if existing is not None:
                    self.db.execute("COMMIT")
                    committed = True
                    if existing["payload_hash"] != payload_hash:
                        self._audit(actor=actor, action="job", outcome="reject_conflict",
                                    team_id=team_id, request_id=request_id,
                                    detail={"job_id": existing["job_id"],
                                            "request_key": request_key,
                                            "reason": "request_key reused with different payload"})
                        raise JobConflict(
                            "request_key already belongs to a different job "
                            + existing["job_id"],
                            job_id=existing["job_id"],
                        )
                    # identical retry -> replay the first ticket, never a second hold
                    return self._job_response(existing, ticket_=True)

                # reject a batch that is already hopeless (no ticket, no hold)
                self._validate_members(team_id, prepared)

                # dedupe members within the same batch by (snapshot, query_hash):
                # the unique result row would only be paid once, so reserve once
                seen: set[tuple[str, str]] = set()
                need: dict[str, list[float]] = {}  # snapshot_id -> [eps, delta]
                for m in prepared:
                    key = (m["snapshot_id"], m["query_hash"])
                    if key in seen:
                        m["already_cached"] = False
                        continue
                    cached = self.db.execute(
                        "SELECT 1 FROM results WHERE team_id=? AND snapshot_id=? AND query_hash=?",
                        (team_id, m["snapshot_id"], m["query_hash"]),
                    ).fetchone()
                    m["already_cached"] = cached is not None
                    seen.add(key)
                    if cached is None:
                        n = need.setdefault(m["snapshot_id"], [0.0, 0.0])
                        n[0] += m["epsilon"]
                        n[1] += m["delta"]

                for sid, (eps_need, delta_need) in need.items():
                    eps_av, delta_av, _ = self._available_budget(team_id, sid)
                    if eps_need > eps_av + EPS_TOLERANCE \
                            or delta_need > delta_av + EPS_TOLERANCE:
                        raise BudgetExceeded(
                            f"job needs (eps={eps_need},delta={delta_need}) on {sid}; "
                            f"available incl. holds (eps={round(eps_av, 9)},"
                            f"delta={round(delta_av, 12)})",
                            action="reject_budget", snapshot_id=sid,
                            epsilon=eps_need, delta=delta_need)

                job_id = new_id("job")
                now = datetime.now(timezone.utc)
                created_at = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                expires_at = _plus_ttl(now, ttl)
                eps_res = sum(v[0] for v in need.values())
                delta_res = sum(v[1] for v in need.values())

                self.db.execute(
                    """INSERT INTO jobs
                       (job_id, team_id, request_key, payload_hash, state,
                        epsilon_reserved, delta_reserved, epsilon_consumed, delta_consumed,
                        statement_count, ttl_seconds, created_at, expires_at, created_by)
                       VALUES (?,?,?,?,'reserved',?,?,?,?,?,?,?,?,?)""",
                    (job_id, team_id, request_key, payload_hash,
                     eps_res, delta_res, eps_res, delta_res,
                     len(prepared), ttl, created_at, expires_at, actor),
                )
                for m in prepared:
                    self.db.execute(
                        """INSERT INTO job_statements
                           (job_id, position, snapshot_id, canonical_json, query_hash,
                            family_id, mechanism, epsilon, delta, dimension, scale,
                            sensitivity_l1, already_cached, result_id, charged)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,0)""",
                        (job_id, m["position"], m["snapshot_id"], dumps_canon(m["canonical"]),
                         m["query_hash"], m["family_id"], m["params"]["mechanism"],
                         m["epsilon"], m["delta"], m["dimension"], m["params"]["scale"],
                         m["params"]["sensitivity_l1"], 1 if m.get("already_cached") else 0),
                    )
                for sid, (eps_h, delta_h) in need.items():
                    self.db.execute(
                        """INSERT INTO budget_holds
                           (team_id, snapshot_id, job_id, epsilon, delta, created_at, expires_at)
                           VALUES (?,?,?,?,?,?,?)""",
                        (team_id, sid, job_id, eps_h, delta_h, created_at, expires_at),
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

            row = self.db.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            self._audit(actor=actor, action="job", outcome="job_reserved",
                        team_id=team_id, request_id=request_id,
                        epsilon=eps_res, delta=delta_res,
                        detail={"job_id": job_id, "statements": len(prepared),
                                "ttl_seconds": ttl, "expires_at": expires_at})
            return self._job_response(row, ticket_=True)

    def _validate_members(self, team_id: str, prepared: list[dict]) -> None:
        """Pre-execution world checks shared by reserve and confirm.

        Any member failing them aborts the whole job -- no partial outcome.
        Member dicts only need snapshot_id/snapshot_active/family_id/position.
        """
        for m in prepared:
            sid = m["snapshot_id"]
            if not m.get("snapshot_active", True):
                raise SnapshotInactive(
                    f"statement[{m['position']}] snapshot {sid} is no longer active",
                    family_id=m["family_id"], snapshot_id=sid)
            fam = m["family_id"]
            freeze = self._matching_freeze(fam, fam, team_id, sid)
            if freeze is not None:
                raise FrozenQuery(
                    f"statement[{m['position']}] family {freeze['family_id']} is frozen: "
                    + freeze["reason"],
                    action="reject_frozen", family_id=fam, snapshot_id=sid)

    # ------------------------------------------------------------------ #
    # phase 2: confirm -> all results in one transaction or total rollback
    # ------------------------------------------------------------------ #

    def confirm_job(self, job_id: str, team_id: str, *,
                    actor: str | None = None, request_id: str | None = None) -> dict:
        actor = actor or ("team:" + team_id)
        with self._lock:
            job = self._load_job_locked(job_id, team_id)
            job = self._expire_if_due_locked(job, actor=actor, request_id=request_id)

            if job["state"] == "completed":
                return self._job_response(job, ticket_=False)
            if job["state"] == "expired":
                raise JobTicketExpired("ticket expired at " + job["expires_at"],
                                       job_id=job_id)
            if job["state"] == "cancelled":
                raise JobStateConflict("job was cancelled", job_id=job_id)
            if job["state"] == "failed":
                raise JobStateConflict(
                    "job failed at confirm: " + (job["error_message"] or job["error_code"] or ""),
                    job_id=job_id)
            # 'reserved' (or a recovered 'executing' from a crashed attempt)
            return self._execute_job_locked(job, actor=actor, request_id=request_id)

    def _execute_job_locked(self, job: sqlite3.Row, *, actor: str,
                            request_id: str | None) -> dict:
        job_id = job["job_id"]
        team_id = job["team_id"]
        stmt_rows = self.db.execute(
            "SELECT * FROM job_statements WHERE job_id=? ORDER BY position", (job_id,)
        ).fetchall()

        # re-prepare from stored canonical JSON: manifests may have changed
        # since reserve, and crash recovery must not trust in-memory state
        prepared: list[dict] = []
        snap_cache: dict[str, sqlite3.Row] = {}
        for s in stmt_rows:
            sid = s["snapshot_id"]
            snap_row = snap_cache.get(sid)
            if snap_row is None:
                snap_row = self.db.execute(
                    "SELECT * FROM snapshots WHERE snapshot_id=?", (sid,)).fetchone()
                snap_cache[sid] = snap_row
            prepared.append({
                "stmt": s,
                "snap_row": snap_row,
                "manifest": json.loads(snap_row["manifest_json"]),
                "canonical": json.loads(s["canonical_json"]),
            })

        # validation pass BEFORE the write transaction ---------------------
        if self._job_is_due(job):
            failure: DPGWError | None = JobTicketExpired(
                "ticket expired at " + job["expires_at"], job_id=job_id)
        else:
            failure = None
            try:
                members = [{
                    "position": p["stmt"]["position"],
                    "snapshot_id": p["snap_row"]["snapshot_id"],
                    "snapshot_active": bool(p["snap_row"]["active"]),
                    "family_id": p["stmt"]["family_id"],
                } for p in prepared]
                self._validate_members(team_id, members)
            except DPGWError as e:
                failure = e
        if failure is not None:
            self._terminal_fail_locked(job, failure, actor=actor, request_id=request_id)
            raise failure

        # true values via read-only snapshot opens; tampering fails the batch
        computed: list[dict] = []
        try:
            for p in prepared:
                s = p["stmt"]
                snap_dir = os.path.dirname(p["snap_row"]["path"])
                check = snapmod.verify_snapshot(snap_dir, p["snap_row"]["snapshot_id"])
                if not check["ok"]:
                    raise InvalidSnapshot(
                        f"statement[{s['position']}] snapshot integrity check failed")
                conn = snapmod.open_data(snap_dir, p["snap_row"]["snapshot_id"])
                try:
                    agg = aggregate(p["canonical"], p["manifest"], conn)
                finally:
                    conn.close()
                computed.append({**p, "agg": agg})
        except DPGWError as e:
            self._terminal_fail_locked(job, e, actor=actor, request_id=request_id)
            raise

        self.db.execute("BEGIN IMMEDIATE")
        committed = False
        result_by_key: dict[tuple[str, str], sqlite3.Row] = {}
        charged_flags: dict[int, bool] = {}
        try:
            # re-validate under the write lock against anything that raced in
            job = self.db.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if job["state"] not in ACTIVE_STATES:
                raise JobStateConflict(
                    f"job cannot execute from state {job['state']}", job_id=job_id)
            if self._job_is_due(job):
                raise JobTicketExpired("ticket expired", job_id=job_id)
            # re-read snapshot rows *inside* the txn: a deactivation that raced
            # with confirmation must still abort the whole batch
            fresh_members = []
            for p in prepared:
                srow = self.db.execute(
                    "SELECT active, snapshot_id FROM snapshots WHERE snapshot_id=?",
                    (p["snap_row"]["snapshot_id"],)).fetchone()
                fresh_members.append({
                    "position": p["stmt"]["position"],
                    "snapshot_id": srow["snapshot_id"],
                    "snapshot_active": bool(srow["active"]),
                    "family_id": p["stmt"]["family_id"],
                })
            self._validate_members(team_id, fresh_members)

            holds = {r["snapshot_id"]: r for r in self.db.execute(
                "SELECT * FROM budget_holds WHERE job_id=?", (job_id,)).fetchall()}

            # which members pay? cache check + coverage check per snapshot
            needs_pay: dict[tuple[str, str], bool] = {}
            paid: dict[str, list[float]] = {}
            sids = {s["snapshot_id"] for s in stmt_rows}
            budgets = {sid: self._budget_row(team_id, sid) for sid in sids}
            pay_seen: set[tuple[str, str]] = set()
            for p in computed:
                s = p["stmt"]
                key = (s["snapshot_id"], s["query_hash"])
                if key in needs_pay:
                    continue
                existing = self.db.execute(
                    "SELECT * FROM results WHERE team_id=? AND snapshot_id=? AND query_hash=?",
                    (team_id, s["snapshot_id"], s["query_hash"])).fetchone()
                if existing is not None:
                    needs_pay[key] = False
                    result_by_key[key] = existing
                    continue
                hold = holds.get(s["snapshot_id"])
                if hold is None:
                    raise BudgetExceeded(
                        f"missing budget hold for job {job_id} on {s['snapshot_id']}",
                        action="reject_budget", snapshot_id=s["snapshot_id"])
                budget = budgets[s["snapshot_id"]]
                he, hd = self._holds_total(team_id, s["snapshot_id"], exclude_job=job_id)
                eps_av = budget["epsilon_limit"] - budget["epsilon_spent"] - he
                delta_av = budget["delta_limit"] - budget["delta_spent"] - hd
                if hold["epsilon"] > eps_av + EPS_TOLERANCE \
                        or hold["delta"] > delta_av + EPS_TOLERANCE:
                    raise BudgetExceeded(
                        "budget no longer covers the locked job hold",
                        action="reject_budget", snapshot_id=s["snapshot_id"],
                        epsilon=hold["epsilon"], delta=hold["delta"])
                needs_pay[key] = True

            self.db.execute("UPDATE jobs SET state='executing' WHERE job_id=?", (job_id,))

            # write results ------------------------------------------------
            created_at = utcnow()
            for p in computed:
                s = p["stmt"]
                key = (s["snapshot_id"], s["query_hash"])
                if not needs_pay[key] or key in pay_seen:
                    pay_seen.add(key)
                    continue
                pay_seen.add(key)
                cost = expected_cost(p["canonical"], s["dimension"])
                params = cost["params"]
                noise = noisy_vector(
                    self.noise_seed, team_id, s["snapshot_id"], s["query_hash"],
                    p["agg"]["coords"], params)
                values = [round(t + n, 6) for t, n in zip(p["agg"]["true"], noise)]
                result_id = new_id("res")
                self.db.execute(
                    """INSERT INTO results
                       (result_id, team_id, snapshot_id, query_hash, family_id,
                        canonical_json, mechanism, epsilon, delta, dimension,
                        sensitivity_l1, scale, coords_json, values_json, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (result_id, team_id, s["snapshot_id"], s["query_hash"], s["family_id"],
                     s["canonical_json"], s["mechanism"], s["epsilon"], s["delta"],
                     s["dimension"], s["sensitivity_l1"], s["scale"],
                     dumps_canon(p["agg"]["coords"]), dumps_canon(values), created_at),
                )
                n = paid.setdefault(s["snapshot_id"], [0.0, 0.0])
                n[0] += s["epsilon"]
                n[1] += s["delta"]
                result_by_key[key] = self.db.execute(
                    "SELECT * FROM results WHERE result_id=?", (result_id,)).fetchone()

            # one budget update per snapshot; holds cover exactly this amount
            for sid, (eps_paid, delta_paid) in paid.items():
                self.db.execute(
                    """UPDATE budgets SET epsilon_spent=epsilon_spent+?,
                       delta_spent=delta_spent+? WHERE team_id=? AND snapshot_id=?""",
                    (eps_paid, delta_paid, team_id, sid),
                )

            payer_seen: set[tuple[str, str]] = set()
            eps_consumed = delta_consumed = 0.0
            for p in computed:
                s = p["stmt"]
                key = (s["snapshot_id"], s["query_hash"])
                is_payer = needs_pay[key] and key not in payer_seen
                payer_seen.add(key)
                rrow = result_by_key[key]
                self.db.execute(
                    "UPDATE job_statements SET result_id=?, charged=? WHERE job_id=? AND position=?",
                    (rrow["result_id"], 1 if is_payer else 0, job_id, s["position"]),
                )
                charged_flags[s["position"]] = is_payer
                if is_payer:
                    eps_consumed += s["epsilon"]
                    delta_consumed += s["delta"]

            # locks are fully consumed: release them, job completes
            self.db.execute("DELETE FROM budget_holds WHERE job_id=?", (job_id,))
            finished_at = utcnow()
            self.db.execute(
                """UPDATE jobs SET state='completed', epsilon_consumed=?, delta_consumed=?,
                   confirmed_at=?, finished_at=?, error_code=NULL, error_message=NULL
                   WHERE job_id=?""",
                (eps_consumed, delta_consumed, created_at, finished_at, job_id),
            )
            self.db.execute("COMMIT")
            committed = True
        except DPGWError as e:
            if not committed:
                self.db.execute("ROLLBACK")
            fresh = self.db.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            self._terminal_fail_locked(fresh, e, actor=actor, request_id=request_id)
            raise
        except Exception:
            if not committed:
                self.db.execute("ROLLBACK")
            # the whole txn rolled back, so state is 'reserved' with its hold
            # intact: the caller (or a restart) can safely retry confirm.
            raise

        row = self.db.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        self._audit(actor=actor, action="job", outcome="job_completed",
                    team_id=team_id, request_id=request_id,
                    epsilon=row["epsilon_consumed"], delta=row["delta_consumed"],
                    detail={"job_id": job_id, "statements": len(stmt_rows)})
        for p in computed:
            s = p["stmt"]
            rrow = result_by_key[(s["snapshot_id"], s["query_hash"])]
            payer = charged_flags[s["position"]]
            self._audit(
                actor=actor, action="job_statement",
                outcome="ok_executed" if payer else "ok_cached",
                team_id=team_id, snapshot_id=s["snapshot_id"],
                result_id=rrow["result_id"], query_hash_hex=s["query_hash"],
                family_id=s["family_id"], request_id=request_id,
                epsilon=s["epsilon"] if payer else None,
                delta=s["delta"] if payer else None,
                detail={"job_id": job_id, "position": s["position"]})
        return self._job_response(row, ticket_=False)

    # ------------------------------------------------------------------ #
    # terminal failure helpers (holds released, nothing ever charged)
    # ------------------------------------------------------------------ #

    _FAIL_OUTCOMES = (
        (BudgetExceeded, "reject_budget"),
        (FrozenQuery, "reject_frozen"),
        (SnapshotInactive, "reject_inactive"),
        (InvalidSnapshot, "reject_invalid"),
        (InvalidQuery, "reject_invalid"),
        (JobTicketExpired, "job_expired"),
    )

    def _terminal_fail_locked(self, job: sqlite3.Row | None, err: DPGWError, *,
                              actor: str, request_id: str | None,
                              state: str = "failed",
                              outcome: str | None = None) -> None:
        """Move an active job to a terminal state and release ALL its holds."""
        if job is None:
            return
        job_id = job["job_id"]
        if outcome is None:
            outcome = dict(self._FAIL_OUTCOMES).get(type(err), "job_failed")
        if isinstance(err, JobTicketExpired):
            state = "expired"
        self.db.execute("BEGIN IMMEDIATE")
        try:
            cur = self.db.execute("SELECT state FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if cur is not None and cur["state"] in ACTIVE_STATES:
                self.db.execute("DELETE FROM budget_holds WHERE job_id=?", (job_id,))
                self.db.execute(
                    """UPDATE jobs SET state=?, epsilon_consumed=0, delta_consumed=0,
                       confirmed_at=COALESCE(confirmed_at,?), finished_at=?,
                       error_code=?, error_message=? WHERE job_id=?""",
                    (state, utcnow(), utcnow(), err.code, err.message, job_id),
                )
                self.db.execute("COMMIT")
                self._audit(actor=actor, action="job", outcome=outcome,
                            team_id=job["team_id"], request_id=request_id,
                            detail={"job_id": job_id, "error": err.message})
            else:
                self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------------ #
    # cancel / expire
    # ------------------------------------------------------------------ #

    def cancel_job(self, job_id: str, team_id: str, *,
                   actor: str | None = None, request_id: str | None = None) -> dict:
        actor = actor or ("team:" + team_id)
        with self._lock:
            job = self._load_job_locked(job_id, team_id)
            job = self._expire_if_due_locked(job, actor=actor, request_id=request_id)
            if job["state"] == "cancelled":
                return self._job_response(job, ticket_=False)
            if job["state"] == "completed":
                raise JobStateConflict("completed job cannot be cancelled", job_id=job_id)
            if job["state"] in ("failed", "expired"):
                raise JobStateConflict(f"job already {job['state']}", job_id=job_id)
            self.db.execute("BEGIN IMMEDIATE")
            try:
                released = self.db.execute(
                    "SELECT COALESCE(SUM(epsilon),0) e, COALESCE(SUM(delta),0) d "
                    "FROM budget_holds WHERE job_id=?", (job_id,)).fetchone()
                self.db.execute("DELETE FROM budget_holds WHERE job_id=?", (job_id,))
                self.db.execute(
                    """UPDATE jobs SET state='cancelled', epsilon_consumed=0, delta_consumed=0,
                       finished_at=? WHERE job_id=?""",
                    (utcnow(), job_id))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            self._audit(actor=actor, action="job", outcome="job_cancelled",
                        team_id=team_id, request_id=request_id,
                        epsilon=released["e"], delta=released["d"],
                        detail={"job_id": job_id, "released_epsilon": released["e"],
                                "released_delta": released["d"]})
            row = self.db.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            return self._job_response(row, ticket_=False)

    @staticmethod
    def _job_is_due(job: sqlite3.Row) -> bool:
        return _parse_ts(job["expires_at"]) <= datetime.now(timezone.utc)

    def _expire_if_due_locked(self, job: sqlite3.Row, *, actor: str,
                              request_id: str | None) -> sqlite3.Row:
        if job["state"] == "reserved" and self._job_is_due(job):
            self._terminal_fail_locked(
                job, JobTicketExpired("ticket expired at " + job["expires_at"],
                                      job_id=job["job_id"]),
                actor=actor, request_id=request_id)
            return self.db.execute("SELECT * FROM jobs WHERE job_id=?",
                                   (job["job_id"],)).fetchone()
        return job

    def sweep_expired_jobs(self, *, actor: str = "system", limit: int = 500) -> int:
        """Expire all due reserved jobs and release their holds.  Safe anytime."""
        with self._lock:
            due = self.db.execute(
                "SELECT job_id FROM jobs WHERE state='reserved' AND expires_at <= ?",
                (utcnow(),),
            ).fetchall()
            n = 0
            for r in due[:limit]:
                job = self.db.execute("SELECT * FROM jobs WHERE job_id=?",
                                      (r["job_id"],)).fetchone()
                self._terminal_fail_locked(
                    job, JobTicketExpired("ticket expired at " + job["expires_at"],
                                          job_id=job["job_id"]),
                    actor=actor, request_id=None)
                n += 1
            return n

    # ------------------------------------------------------------------ #
    # restart recovery
    # ------------------------------------------------------------------ #

    def recover_pending_jobs(self, *, actor: str = "system") -> dict:
        """Reconcile jobs/holds after a restart (also safe to run periodically).

        * expired reserved jobs -> ``expired``, holds released;
        * jobs stuck in ``executing`` (crash mid-confirm) -> ``failed`` with
          holds released: no result/budget row can have committed without the
          hold deletion because execution is one atomic transaction;
        * any hold whose job is terminal/missing is deleted.
        """
        report = {"expired": [], "failed_interrupted": [], "orphan_holds": 0}
        with self._lock:
            now = datetime.now(timezone.utc)
            for job in self.db.execute(
                "SELECT * FROM jobs WHERE state IN ('reserved','executing')"
            ).fetchall():
                if job["state"] == "executing":
                    self._terminal_fail_locked(
                        job, JobStateConflict(
                            "interrupted by service restart before commit",
                            job_id=job["job_id"]),
                        actor=actor, request_id=None,
                        state="failed", outcome="job_interrupted")
                    report["failed_interrupted"].append(job["job_id"])
                elif _parse_ts(job["expires_at"]) <= now:
                    self._terminal_fail_locked(
                        job, JobTicketExpired("ticket expired at " + job["expires_at"],
                                              job_id=job["job_id"]),
                        actor=actor, request_id=None)
                    report["expired"].append(job["job_id"])

            cur = self.db.execute(
                """DELETE FROM budget_holds WHERE job_id IN (
                       SELECT job_id FROM jobs WHERE state NOT IN ('reserved','executing'))""")
            report["orphan_holds"] += cur.rowcount or 0
            cur = self.db.execute(
                "DELETE FROM budget_holds WHERE job_id NOT IN (SELECT job_id FROM jobs)")
            report["orphan_holds"] += cur.rowcount or 0
        return report

    # ------------------------------------------------------------------ #
    # read APIs
    # ------------------------------------------------------------------ #

    def _load_job_locked(self, job_id: str, team_id: str) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM jobs WHERE job_id=? AND team_id=?", (job_id, team_id)
        ).fetchone()
        if row is None:
            raise JobNotFound(job_id)
        return row

    def get_job(self, job_id: str, team_id: str) -> dict:
        with self._lock:
            job = self._load_job_locked(job_id, team_id)
            job = self._expire_if_due_locked(job, actor="team:" + team_id, request_id=None)
            return self._job_response(
                job, ticket_=job["state"] == "reserved", manifest_=True)

    def list_jobs(self, team_id: str | None = None, *, state: str | None = None,
                  limit: int = 200) -> list[dict]:
        where, params = [], []
        if team_id:
            where.append("team_id=?")
            params.append(team_id)
        if state:
            where.append("state=?")
            params.append(state)
        sql = "SELECT * FROM jobs"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(min(int(limit), 2000))
        out = []
        for r in self.db.execute(sql, params).fetchall():
            d = dict(r)
            d.pop("payload_hash", None)
            out.append(d)
        return out

    def list_holds(self, team_id: str | None = None, snapshot_id: str | None = None) -> list[dict]:
        where, params = [], []
        if team_id:
            where.append("h.team_id=?")
            params.append(team_id)
        if snapshot_id:
            where.append("h.snapshot_id=?")
            params.append(snapshot_id)
        sql = (
            "SELECT h.team_id, h.snapshot_id, h.job_id, h.epsilon, h.delta, "
            "h.created_at, h.expires_at, j.state, j.request_key "
            "FROM budget_holds h JOIN jobs j ON j.job_id=h.job_id")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY h.expires_at"
        return [dict(r) for r in self.db.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------ #
    # tickets, responses and signed batch manifests
    # ------------------------------------------------------------------ #

    def _ticket(self, job: sqlite3.Row) -> dict:
        body = {
            "ticket_version": JOB_TICKET_VERSION,
            "job_id": job["job_id"],
            "team_id": job["team_id"],
            "request_key": job["request_key"],
            "state": job["state"],
            "epsilon_reserved": job["epsilon_reserved"],
            "delta_reserved": job["delta_reserved"],
            "statement_count": job["statement_count"],
            "created_at": job["created_at"],
            "expires_at": job["expires_at"],
            "ttl_seconds": job["ttl_seconds"],
        }
        return signed(body, self.receipt_key)

    def _statement_entries(self, job_id: str) -> list[dict]:
        rows = self.db.execute(
            "SELECT * FROM job_statements WHERE job_id=? ORDER BY position", (job_id,)
        ).fetchall()
        return [{
            "position": s["position"],
            "snapshot_id": s["snapshot_id"],
            "query_hash": s["query_hash"],
            "family_id": s["family_id"],
            "epsilon": s["epsilon"],
            "delta": s["delta"],
            "charged": bool(s["charged"]),
            "result_id": s["result_id"],
        } for s in rows]

    def _receipt_dict(self, row: sqlite3.Row) -> dict:
        body = build_result_receipt(
            result_id=row["result_id"], team_id=row["team_id"],
            snapshot_id=row["snapshot_id"], query_hash=row["query_hash"],
            family_id=row["family_id"], canonical=json.loads(row["canonical_json"]),
            mechanism=row["mechanism"], epsilon=row["epsilon"], delta=row["delta"],
            dimension=row["dimension"], sensitivity_l1=row["sensitivity_l1"],
            scale=row["scale"], coords=json.loads(row["coords_json"]),
            values=json.loads(row["values_json"]), created_at=row["created_at"])
        return signed(body, self.receipt_key)

    def build_job_manifest(self, job: sqlite3.Row) -> dict:
        """Signed manifest over the whole batch and every member receipt."""
        receipts = []
        for s in self.db.execute(
                "SELECT result_id FROM job_statements WHERE job_id=? ORDER BY position",
                (job["job_id"],)).fetchall():
            rrow = self.db.execute("SELECT * FROM results WHERE result_id=?",
                                   (s["result_id"],)).fetchone()
            receipts.append(self._receipt_dict(rrow))
        body = {
            "manifest_version": JOB_MANIFEST_VERSION,
            "job_id": job["job_id"],
            "team_id": job["team_id"],
            "request_key": job["request_key"],
            "state": job["state"],
            "created_at": job["created_at"],
            "expires_at": job["expires_at"],
            "confirmed_at": job["confirmed_at"],
            "finished_at": job["finished_at"],
            "epsilon_reserved": job["epsilon_reserved"],
            "delta_reserved": job["delta_reserved"],
            "epsilon_consumed": job["epsilon_consumed"],
            "delta_consumed": job["delta_consumed"],
            "statement_count": job["statement_count"],
            "members": self._statement_entries(job["job_id"]),
            "receipts": receipts,
        }
        return signed(body, self.receipt_key)

    def _job_response(self, job: sqlite3.Row, *, ticket_: bool,
                      manifest_: bool = False) -> dict:
        d = {
            "job_id": job["job_id"],
            "team_id": job["team_id"],
            "request_key": job["request_key"],
            "state": job["state"],
            "statement_count": job["statement_count"],
            "epsilon_reserved": job["epsilon_reserved"],
            "delta_reserved": job["delta_reserved"],
            "epsilon_consumed": job["epsilon_consumed"],
            "delta_consumed": job["delta_consumed"],
            "created_at": job["created_at"],
            "expires_at": job["expires_at"],
            "confirmed_at": job["confirmed_at"],
            "finished_at": job["finished_at"],
            "error_code": job["error_code"],
            "error_message": job["error_message"],
            "statements": self._statement_entries(job["job_id"]),
        }
        if ticket_:
            d["ticket"] = self._ticket(job)
        if job["state"] == "completed":
            # confirm is one call: signed batch manifest + every member receipt
            d["manifest"] = self.build_job_manifest(job)
            d["results"] = []
            for e in d["statements"]:
                rrow = self.db.execute("SELECT * FROM results WHERE result_id=?",
                                       (e["result_id"],)).fetchone()
                budget = self._budget_row(job["team_id"], rrow["snapshot_id"])
                d["results"].append(
                    self._result_response(rrow, budget, cached_=not e["charged"]))
        elif manifest_ and job["state"] == "completed":
            d["manifest"] = self.build_job_manifest(job)
        return d
