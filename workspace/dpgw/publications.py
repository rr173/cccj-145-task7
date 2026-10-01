"""Amendable joint publication batches for differential-privacy results.

A publication *batch* is a series led by the analysis owner (administrator).
The owner fixes once:

* the **statistical specification** -- an ordered list of (snapshot, canonical
  query) statements every participating team contributes; its identity is a
  ``spec_hash`` shared by every version of the batch;
* ``min_participants`` -- the minimum number of *distinct* teams for a valid
  release (the quorum);
* a ``close_at`` books-closing instant per version.

While a version is ``collecting`` each team registers (placing budget holds,
exactly like multi-statement jobs) or withdraws (releasing them).  Duplicate
registration is an idempotent replay: no second hold, no second charge, and
statements already present in the team's result cache are free at sealing.

At seal time (owner action, or the deadline sweep once the quorum is met) the
gateway re-validates the world for **every** participant -- snapshots still
active, families not frozen, snapshot files intact, budgets still covering the
holds -- and then produces the release in ONE ``BEGIN IMMEDIATE`` transaction:
all result rows, all budget charges, hold release, contribution attribution
and the single signed release manifest commit together, or nothing changes at
all (batch and ledger stay as they were).

Late contributions to a closed version are rejected (``publication_closed``);
they belong to the next version.  A revision of a *sealed* version opens a new
``collecting`` child version with the same fixed specification; the chain is
linear (one open version per batch at a time) and every old signed manifest
stays verifiable forever.  A deadline reached below the quorum ``void``s the
version and releases every hold.

Crash safety: holds/version rows are durable before sealing; an unreachable
seal transaction leaves the version ``collecting`` (continuable after restart),
and :meth:`PublishingMixin.recover_open_publications` sweeps due versions and
deletes orphan holds at startup.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from . import snapshot as snapmod
from .canonical import family_fingerprint, normalize_query, query_hash
from .engine import aggregate
from .errors import (
    BudgetExceeded,
    DPGWError,
    FrozenQuery,
    InvalidSnapshot,
    NotParticipating,
    PublicationClosed,
    PublicationInvalid,
    PublicationNotFound,
    PublicationStateConflict,
    QuorumNotMet,
    SnapshotInactive,
    SpecificationChanged,
)
from .privacy import expected_cost, noisy_vector
from .receipts import (
    PUB_RELEASE_VERSION,
    dumps_canon,
    sha256_hex,
    signed,
)
from .transparency import (
    RELEASE_SEALED,
    RELEASE_VOIDED,
)
from .util import EPS_TOLERANCE, new_id, utcnow

COLLECTING = "collecting"
SEALED = "sealed"
VOID = "void"


def _parse_ts(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def _fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_close_at(value: str) -> str:
    """Accept ISO-8601 (``...Z`` or explicit offset); store the canonical form."""
    if not isinstance(value, str) or not value:
        raise PublicationInvalid("close_at must be an ISO-8601 timestamp")
    text = value.strip()
    try:
        if text.endswith("Z"):
            dt = datetime.fromisoformat(text[:-1] + "+00:00")
        else:
            dt = datetime.fromisoformat(text)
    except ValueError:
        raise PublicationInvalid(f"close_at {value!r} is not a valid ISO-8601 timestamp")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return _fmt_ts(dt)


class PublishingMixin:
    """Joint publication batches; mixed into :class:`Gateway`."""

    # ------------------------------------------------------------------ #
    # specification helpers
    # ------------------------------------------------------------------ #

    def _prepare_pub_statements(self, statements: list) -> list[dict]:
        """Resolve + normalise every fixed statement (all-or-nothing)."""
        if not isinstance(statements, list) or not statements:
            raise PublicationInvalid("a publication requires a non-empty 'statements' list")
        prepared: list[dict] = []
        for pos, item in enumerate(statements):
            if not isinstance(item, dict):
                raise PublicationInvalid(f"statement[{pos}] must be an object")
            snap_ref = item.get("snapshot")
            query = item.get("query")
            if not isinstance(snap_ref, dict) or not isinstance(query, dict):
                raise PublicationInvalid(
                    f"statement[{pos}] requires 'snapshot' (object) and 'query' (object)")
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
    def _spec_hash(prepared: list[dict]) -> str:
        """Identity of the fixed statistical specification."""
        members = [
            {"p": m["position"], "s": m["snapshot_id"], "q": m["query_hash"],
             "e": m["epsilon"], "d": m["delta"]}
            for m in prepared
        ]
        return sha256_hex(dumps_canon(members))

    def _owner_validate(self, prepared: list[dict]) -> None:
        """Owner-independent world checks (snapshot active, global/snapshot freeze).

        Team- and team+snapshot-scoped freezes are per participant and are
        enforced at registration/seal instead.
        """
        for m in prepared:
            sid = m["snapshot_id"]
            if not m.get("snapshot_active", True):
                raise SnapshotInactive(
                    f"statement[{m['position']}] snapshot {sid} is not active",
                    family_id=m["family_id"], snapshot_id=sid)
            freeze = self._matching_freeze(m["family_id"], m["family_id"], None, sid)
            if freeze is not None:
                raise FrozenQuery(
                    f"statement[{m['position']}] family {freeze['family_id']} is frozen: "
                    + freeze["reason"],
                    action="reject_frozen", family_id=m["family_id"], snapshot_id=sid)

    def _participant_validate(self, team_id: str, members: list[dict]) -> None:
        """Per-team world checks at registration and again at seal."""
        for m in members:
            sid = m["snapshot_id"]
            snap = self.db.execute(
                "SELECT active FROM snapshots WHERE snapshot_id=?", (sid,)).fetchone()
            if snap is None:
                raise InvalidSnapshot(f"statement[{m['position']}] snapshot {sid} is gone")
            if not snap["active"]:
                raise SnapshotInactive(
                    f"statement[{m['position']}] snapshot {sid} is no longer active",
                    family_id=m["family_id"], snapshot_id=sid)
            freeze = self._matching_freeze(m["family_id"], m["family_id"], team_id, sid)
            if freeze is not None:
                raise FrozenQuery(
                    f"statement[{m['position']}] family {freeze['family_id']} is frozen: "
                    + freeze["reason"],
                    action="reject_frozen", family_id=m["family_id"], snapshot_id=sid)

    # ------------------------------------------------------------------ #
    # owner: create a batch (original version)
    # ------------------------------------------------------------------ #

    def create_publication(self, name: str, statements: list, min_participants: int,
                           close_at: str, *, actor: str = "admin",
                           request_id: str | None = None) -> dict:
        if not isinstance(name, str) or not name.strip():
            raise PublicationInvalid("publication requires a non-empty 'name'")
        name = name.strip()
        if not isinstance(min_participants, int) or isinstance(min_participants, bool) \
                or min_participants < 1:
            raise PublicationInvalid("min_participants must be a positive integer")
        close = parse_close_at(close_at)
        if _parse_ts(close) <= datetime.now(timezone.utc):
            raise PublicationInvalid("close_at must be in the future")

        prepared = self._prepare_pub_statements(statements)
        spec_hash = self._spec_hash(prepared)

        with self._lock:
            self._owner_validate(prepared)
            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                if self.db.execute("SELECT 1 FROM pub_batches WHERE name=?", (name,)).fetchone():
                    raise PublicationInvalid(f"publication batch {name!r} already exists")
                batch_id = new_id("pubb")
                version_id = new_id("pubv")
                now = utcnow()
                self.db.execute(
                    """INSERT INTO pub_batches
                       (batch_id, name, spec_hash, min_participants, statement_count,
                        created_by, created_at) VALUES (?,?,?,?,?,?,?)""",
                    (batch_id, name, spec_hash, min_participants, len(prepared), actor, now))
                self.db.execute(
                    """INSERT INTO pub_versions
                       (version_id, batch_id, seq, parent_version_id, state, close_at,
                        created_by, created_at)
                       VALUES (?,?,1,NULL,'collecting',?,?,?)""",
                    (version_id, batch_id, close, actor, now))
                self._insert_statements(version_id, prepared)
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

        self._audit(actor=actor, action="publication", outcome="pub_created",
                    request_id=request_id,
                    detail={"batch_id": batch_id, "version_id": version_id, "name": name,
                            "min_participants": min_participants, "statement_count": len(prepared),
                            "close_at": close, "spec_hash": spec_hash})
        row = self._get_version(version_id)
        return self._version_response(row)

    def _insert_statements(self, version_id: str, prepared: list[dict]) -> None:
        for m in prepared:
            self.db.execute(
                """INSERT INTO pub_statements
                   (version_id, position, snapshot_id, canonical_json, query_hash, family_id,
                    mechanism, epsilon, delta, dimension, scale, sensitivity_l1)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (version_id, m["position"], m["snapshot_id"], dumps_canon(m["canonical"]),
                 m["query_hash"], m["family_id"], m["params"]["mechanism"],
                 m["epsilon"], m["delta"], m["dimension"], m["params"]["scale"],
                 m["params"]["sensitivity_l1"]))

    # ------------------------------------------------------------------ #
    # owner: revise a sealed version (new child, same fixed specification)
    # ------------------------------------------------------------------ #

    def amend_publication(self, ref: str, close_at: str, *, actor: str = "admin",
                          request_id: str | None = None) -> dict:
        close = parse_close_at(close_at)
        if _parse_ts(close) <= datetime.now(timezone.utc):
            raise PublicationInvalid("close_at must be in the future")
        with self._lock:
            parent = self._resolve_version_locked(ref)
            batch = self.db.execute(
                "SELECT * FROM pub_batches WHERE batch_id=?", (parent["batch_id"],)).fetchone()
            if parent["state"] != SEALED:
                raise PublicationStateConflict(
                    f"only sealed versions can be amended; parent is {parent['state']}",
                    version_id=parent["version_id"])
            latest = self.db.execute(
                "SELECT seq, state FROM pub_versions WHERE batch_id=? ORDER BY seq DESC LIMIT 1",
                (parent["batch_id"],)).fetchone()
            if latest["seq"] != parent["seq"]:
                raise PublicationStateConflict(
                    "amend the latest version of the batch instead",
                    version_id=parent["version_id"])
            # linear chain: there can be no open successor
            open_child = self.db.execute(
                "SELECT version_id FROM pub_versions WHERE batch_id=? AND state='collecting'",
                (parent["batch_id"],)).fetchone()
            if open_child is not None:
                raise PublicationStateConflict(
                    "the batch already has an open collecting version",
                    version_id=open_child["version_id"])

            stmts = self.db.execute(
                "SELECT * FROM pub_statements WHERE version_id=? ORDER BY position",
                (parent["version_id"],)).fetchall()
            # the child must not start hopeless: snapshots/families re-checked
            prepared = []
            for s in stmts:
                snap = self.db.execute(
                    "SELECT active, manifest_json FROM snapshots WHERE snapshot_id=?",
                    (s["snapshot_id"],)).fetchone()
                if snap is None:
                    raise InvalidSnapshot(f"statement[{s['position']}] snapshot is gone")
                prepared.append({
                    "position": s["position"], "snapshot_id": s["snapshot_id"],
                    "snapshot_active": bool(snap["active"]),
                    "canonical": json.loads(s["canonical_json"]),
                    "query_hash": s["query_hash"], "family_id": s["family_id"],
                    "epsilon": s["epsilon"], "delta": s["delta"],
                    "params": {"mechanism": s["mechanism"], "scale": s["scale"],
                               "sensitivity_l1": s["sensitivity_l1"]},
                    "dimension": s["dimension"],
                })
            self._owner_validate(prepared)
            if self._spec_hash(prepared) != batch["spec_hash"]:
                # stored statements must reproduce the fixed specification
                raise SpecificationChanged("stored statements diverge from the fixed spec hash")

            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                child_id = new_id("pubv")
                now = utcnow()
                self.db.execute(
                    """INSERT INTO pub_versions
                       (version_id, batch_id, seq, parent_version_id, state, close_at,
                        created_by, created_at)
                       VALUES (?,?,?,?,'collecting',?,?,?)""",
                    (child_id, batch["batch_id"], parent["seq"] + 1, parent["version_id"],
                     close, actor, now))
                self._insert_statements(child_id, prepared)
                self.db.execute("COMMIT")
                committed = True
            except Exception:
                if not committed:
                    self.db.execute("ROLLBACK")
                raise

        self._audit(actor=actor, action="publication", outcome="pub_amended",
                    request_id=request_id,
                    detail={"batch_id": batch["batch_id"], "parent_version_id": parent["version_id"],
                            "version_id": child_id, "seq": parent["seq"] + 1,
                            "close_at": close})
        row = self._get_version(child_id)
        return self._version_response(row)

    # ------------------------------------------------------------------ #
    # team: register / withdraw a contribution
    # ------------------------------------------------------------------ #

    def register_contribution(self, ref: str, team_id: str, *,
                              actor: str | None = None,
                              request_id: str | None = None) -> dict:
        actor = actor or ("team:" + team_id)
        try:
            return self._register_contribution(ref, team_id, actor=actor, request_id=request_id)
        except DPGWError as e:
            self._pub_reject(e, actor=actor, team_id=team_id, request_id=request_id, ref=ref)
            raise

    def _register_contribution(self, ref: str, team_id: str, *, actor: str,
                               request_id: str | None) -> dict:
        self._get_team_conn(team_id)
        with self._lock:
            v = self._resolve_version_locked(ref)
            v = self._settle_if_due_locked(v, actor=actor)
            if v["state"] != COLLECTING:
                raise PublicationClosed(
                    f"publication version {v['version_id']} is {v['state']}; late contributions "
                    "enter the next version (ask the owner to amend)",
                    version_id=v["version_id"])

            stmts = self.db.execute(
                "SELECT * FROM pub_statements WHERE version_id=? ORDER BY position",
                (v["version_id"],)).fetchall()
            members = [{"position": s["position"], "snapshot_id": s["snapshot_id"],
                        "family_id": s["family_id"]} for s in stmts]
            self._participant_validate(team_id, members)

            # need = cost of statements not already cached for this team;
            # duplicate (snapshot, query_hash) positions are paid at most once
            need: dict[str, list[float]] = {}
            seen: set[tuple[str, str]] = set()
            for s in stmts:
                key = (s["snapshot_id"], s["query_hash"])
                if key in seen:
                    continue
                seen.add(key)
                cached = self.db.execute(
                    "SELECT 1 FROM results WHERE team_id=? AND snapshot_id=? AND query_hash=?",
                    (team_id, s["snapshot_id"], s["query_hash"])).fetchone()
                if cached is None:
                    n = need.setdefault(s["snapshot_id"], [0.0, 0.0])
                    n[0] += s["epsilon"]
                    n[1] += s["delta"]
            for sid, (eps_need, delta_need) in need.items():
                eps_av, delta_av, _ = self._available_budget(
                    team_id, sid, exclude_pub_version=v["version_id"])
                if eps_need > eps_av + EPS_TOLERANCE \
                        or delta_need > delta_av + EPS_TOLERANCE:
                    raise BudgetExceeded(
                        f"contribution needs (eps={eps_need},delta={delta_need}) on {sid}; "
                        f"available incl. holds (eps={round(eps_av, 9)},"
                        f"delta={round(delta_av, 12)})",
                        action="reject_budget", snapshot_id=sid,
                        epsilon=eps_need, delta=delta_need)

            existing = self.db.execute(
                "SELECT * FROM pub_contributions WHERE version_id=? AND team_id=?",
                (v["version_id"], team_id)).fetchone()
            replayed = existing is not None and existing["state"] == "registered"
            if replayed:
                # identical retry: replay, never place a second hold or charge twice
                return self._version_response(v, registration="replayed")

            now = utcnow()
            eps_held = sum(x[0] for x in need.values())
            delta_held = sum(x[1] for x in need.values())
            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                self.db.execute(
                    "DELETE FROM pub_holds WHERE version_id=? AND team_id=?",
                    (v["version_id"], team_id))
                for sid, (eh, dh) in need.items():
                    self.db.execute(
                        """INSERT INTO pub_holds
                           (team_id, snapshot_id, version_id, epsilon, delta, created_at)
                           VALUES (?,?,?,?,?,?)""",
                        (team_id, sid, v["version_id"], eh, dh, now))
                if existing is None:
                    self.db.execute(
                        """INSERT INTO pub_contributions
                           (version_id, team_id, state, epsilon_held, delta_held,
                            epsilon_charged, delta_charged, registered_at, updated_at)
                           VALUES (?,?, 'registered', ?,?,0,0,?,?)""",
                        (v["version_id"], team_id, eps_held, delta_held, now, now))
                else:
                    self.db.execute(
                        """UPDATE pub_contributions SET state='registered',
                           epsilon_held=?, delta_held=?, updated_at=?
                           WHERE version_id=? AND team_id=?""",
                        (eps_held, delta_held, now, v["version_id"], team_id))
                self.db.execute("COMMIT")
                committed = True
            except Exception:
                if not committed:
                    self.db.execute("ROLLBACK")
                raise

            outcome = "pub_reregistered" if existing is not None else "pub_registered"
            self._audit(actor=actor, action="publication", outcome=outcome,
                        team_id=team_id, request_id=request_id, epsilon=eps_held,
                        delta=delta_held,
                        detail={"batch_id": v["batch_id"], "version_id": v["version_id"],
                                "holds": {sid: {"epsilon": x[0], "delta": x[1]}
                                          for sid, x in need.items()}})
            row = self._get_version(v["version_id"])
            return self._version_response(
                row, registration="rejoined" if existing is not None else "registered")

    def withdraw_contribution(self, ref: str, team_id: str, *,
                              actor: str | None = None,
                              request_id: str | None = None) -> dict:
        actor = actor or ("team:" + team_id)
        try:
            return self._withdraw_contribution(ref, team_id, actor=actor,
                                               request_id=request_id)
        except DPGWError as e:
            self._pub_reject(e, actor=actor, team_id=team_id, request_id=request_id, ref=ref)
            raise

    def _withdraw_contribution(self, ref: str, team_id: str, *, actor: str,
                               request_id: str | None) -> dict:
        with self._lock:
            v = self._resolve_version_locked(ref)
            v = self._settle_if_due_locked(v, actor=actor)
            if v["state"] != COLLECTING:
                raise PublicationStateConflict(
                    f"cannot withdraw from a {v['state']} version",
                    version_id=v["version_id"])
            contr = self.db.execute(
                "SELECT * FROM pub_contributions WHERE version_id=? AND team_id=?",
                (v["version_id"], team_id)).fetchone()
            if contr is None or contr["state"] == "withdrawn":
                if contr is not None:
                    return self._version_response(v, registration="withdrawn_replayed")
                raise NotParticipating("team has no registered contribution on this version",
                                       version_id=v["version_id"])

            released = self.db.execute(
                "SELECT COALESCE(SUM(epsilon),0) e, COALESCE(SUM(delta),0) d "
                "FROM pub_holds WHERE version_id=? AND team_id=?",
                (v["version_id"], team_id)).fetchone()
            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                self.db.execute("DELETE FROM pub_holds WHERE version_id=? AND team_id=?",
                                (v["version_id"], team_id))
                self.db.execute(
                    """UPDATE pub_contributions SET state='withdrawn', epsilon_held=0,
                       delta_held=0, updated_at=? WHERE version_id=? AND team_id=?""",
                    (utcnow(), v["version_id"], team_id))
                self.db.execute("COMMIT")
                committed = True
            except Exception:
                if not committed:
                    self.db.execute("ROLLBACK")
                raise
            self._audit(actor=actor, action="publication", outcome="pub_withdrawn",
                        team_id=team_id, request_id=request_id,
                        epsilon=released["e"], delta=released["d"],
                        detail={"batch_id": v["batch_id"], "version_id": v["version_id"],
                                "released_epsilon": released["e"],
                                "released_delta": released["d"]})
            row = self._get_version(v["version_id"])
            return self._version_response(row, registration="withdrawn")

    # ------------------------------------------------------------------ #
    # sealing: one signed release in one transaction, or nothing changes
    # ------------------------------------------------------------------ #

    def seal_publication(self, ref: str, *, actor: str = "admin",
                         request_id: str | None = None) -> dict:
        with self._lock:
            v = self._resolve_version_locked(ref)
            if v["state"] != COLLECTING:
                raise PublicationStateConflict(
                    f"version is {v['state']}, only collecting versions can be sealed",
                    version_id=v["version_id"])
            return self._seal_version_locked(v, actor=actor, request_id=request_id, via="explicit")

    def void_publication(self, ref: str, *, actor: str = "admin",
                         request_id: str | None = None) -> dict:
        """Void a due, below-quorum version and release every hold."""
        with self._lock:
            v = self._resolve_version_locked(ref)
            if v["state"] != COLLECTING:
                raise PublicationStateConflict(
                    f"version is {v['state']}", version_id=v["version_id"])
            # fork freeze takes precedence: a frozen log refuses the void leaf
            # explicitly even when the deadline has passed, changing nothing
            self._tl_require_not_frozen_locked("publication voiding")
            if not self._is_due(v):
                raise PublicationStateConflict(
                    "a version can only be voided after its close_at",
                    version_id=v["version_id"])
            n = self._registered_count(v["version_id"])
            batch = self._batch_row(v["batch_id"])
            if n >= batch["min_participants"]:
                raise QuorumNotMet(
                    f"quorum met ({n} >= {batch['min_participants']}); seal instead of voiding",
                    version_id=v["version_id"])
            tl_key = self._void_version_locked(v, actor=actor, request_id=request_id,
                                      reason=f"deadline reached with {n} < "
                                             f"{batch['min_participants']} participants")
            response = self._version_response(self._get_version(v["version_id"]))
            if tl_key is not None:
                anchor = self._tl_anchor_for_event_locked(tl_key)
                if anchor is not None:
                    response["transparency"] = self._tl_anchor_brief(anchor)
            return response

    def _seal_version_locked(self, v: sqlite3.Row, *, actor: str,
                             request_id: str | None, via: str) -> dict:
        # a fork-freezed transparency log refuses every new signed release;
        # the rejection happens before any write, so the ledger stays untouched
        self._tl_require_not_frozen_locked("publication sealing")
        version_id, batch_id = v["version_id"], v["batch_id"]
        batch = self._batch_row(batch_id)
        stmts = self.db.execute(
            "SELECT * FROM pub_statements WHERE version_id=? ORDER BY position",
            (version_id,)).fetchall()
        contr_rows = self.db.execute(
            "SELECT * FROM pub_contributions WHERE version_id=? AND state='registered'",
            (version_id,)).fetchall()
        team_ids = [c["team_id"] for c in contr_rows]

        # ---- quorum (explicit early-close is allowed once it is met) ----
        if len(team_ids) < batch["min_participants"]:
            err = QuorumNotMet(
                f"need {batch['min_participants']} teams, {len(team_ids)} registered",
                version_id=version_id)
            self._pub_reject(err, actor=actor, request_id=request_id, version_row=v)
            raise err

        # ---- world validation + budget coverage for every participant ----
        members = [{"position": s["position"], "snapshot_id": s["snapshot_id"],
                    "family_id": s["family_id"]} for s in stmts]
        try:
            for tid in team_ids:
                self._participant_validate(tid, members)
            for c in contr_rows:
                holds = self.db.execute(
                    "SELECT * FROM pub_holds WHERE version_id=? AND team_id=?",
                    (version_id, c["team_id"])).fetchall()
                for h in holds:
                    eps_av, delta_av, _ = self._available_budget(
                        c["team_id"], h["snapshot_id"], exclude_pub_version=version_id)
                    if h["epsilon"] > eps_av + EPS_TOLERANCE \
                            or h["delta"] > delta_av + EPS_TOLERANCE:
                        raise BudgetExceeded(
                            "budget no longer covers the locked publication hold",
                            action="reject_budget", snapshot_id=h["snapshot_id"],
                            team_id=c["team_id"], epsilon=h["epsilon"], delta=h["delta"])

            # ---- snapshot integrity + true values (once per statement) ----
            snap_cache: dict[str, sqlite3.Row] = {}
            computed: dict[int, dict] = {}
            for s in stmts:
                srow = snap_cache.get(s["snapshot_id"])
                if srow is None:
                    srow = self.db.execute(
                        "SELECT * FROM snapshots WHERE snapshot_id=?",
                        (s["snapshot_id"],)).fetchone()
                    snap_cache[s["snapshot_id"]] = srow
                check = snapmod.verify_snapshot(os.path.dirname(srow["path"]),
                                                srow["snapshot_id"])
                if not check["ok"]:
                    raise InvalidSnapshot(
                        f"statement[{s['position']}] snapshot integrity check failed")
                conn = snapmod.open_data(os.path.dirname(srow["path"]), srow["snapshot_id"])
                try:
                    canonical = json.loads(s["canonical_json"])
                    manifest = json.loads(srow["manifest_json"])
                    agg = aggregate(canonical, manifest, conn)
                finally:
                    conn.close()
                computed[s["position"]] = {"stmt": s, "agg": agg}
        except DPGWError as e:
            # seal aborted before any write: version + ledger stay untouched
            self._pub_reject(e, actor=actor, request_id=request_id, version_row=v)
            raise

        # ------------------------- one write transaction ------------------------
        self.db.execute("BEGIN IMMEDIATE")
        committed = False
        result_by_key: dict[tuple[str, str, str], sqlite3.Row] = {}
        payer_keys: set[tuple[str, str, str]] = set()
        try:
            fresh = self.db.execute("SELECT state FROM pub_versions WHERE version_id=?",
                                    (version_id,)).fetchone()
            if fresh["state"] != COLLECTING:
                raise PublicationStateConflict(
                    f"version is {fresh['state']}", version_id=version_id)
            fresh_teams = [r["team_id"] for r in self.db.execute(
                "SELECT team_id FROM pub_contributions WHERE version_id=? AND state='registered'",
                (version_id,)).fetchall()]
            if len(fresh_teams) < batch["min_participants"]:
                raise QuorumNotMet("quorum lost before sealing", version_id=version_id)
            for tid in fresh_teams:
                self._participant_validate(tid, members)

            sealed_at = utcnow()
            # canonical key (team, snapshot, query_hash) -> first position owning
            # the (single) result row; duplicate positions share it and never pay
            owner_by_canon: dict[tuple[str, str, str], tuple[str, str, str]] = {}
            for tid in fresh_teams:
                dedup_seen: set[tuple[str, str]] = set()
                for s in stmts:
                    key = (tid, s["snapshot_id"], s["query_hash"])
                    ckey = key  # identical: result uniqueness is per (team,sid,qhash)
                    existing = self.db.execute(
                        "SELECT * FROM results WHERE team_id=? AND snapshot_id=? AND query_hash=?",
                        (tid, s["snapshot_id"], s["query_hash"])).fetchone()
                    if existing is not None:
                        result_by_key[key] = existing
                        owner_by_canon.setdefault(ckey, key)
                        continue
                    ckey_owner = owner_by_canon.get(ckey)
                    if ckey_owner is not None:
                        # duplicate position whose canonical sibling already paid
                        # or was cached: just alias its result row
                        result_by_key[key] = result_by_key[ckey_owner]
                        continue
                    dedup = (s["snapshot_id"], s["query_hash"])
                    if dedup in dedup_seen:
                        continue  # defensive: duplicate before any owner (cannot pay)
                    dedup_seen.add(dedup)
                    c = computed[s["position"]]
                    cost = expected_cost(json.loads(s["canonical_json"]), s["dimension"])
                    params = cost["params"]
                    noise = noisy_vector(
                        self.noise_seed, tid, s["snapshot_id"], s["query_hash"],
                        c["agg"]["coords"], params)
                    values = [round(t + n, 6) for t, n in
                              zip(c["agg"]["true"], noise)]
                    result_id = new_id("res")
                    self.db.execute(
                        """INSERT INTO results
                           (result_id, team_id, snapshot_id, query_hash, family_id,
                            canonical_json, mechanism, epsilon, delta, dimension,
                            sensitivity_l1, scale, coords_json, values_json, created_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (result_id, tid, s["snapshot_id"], s["query_hash"], s["family_id"],
                         s["canonical_json"], s["mechanism"], s["epsilon"], s["delta"],
                         s["dimension"], s["sensitivity_l1"], s["scale"],
                         dumps_canon(c["agg"]["coords"]), dumps_canon(values), sealed_at))
                    payer_keys.add(key)
                    owner_by_canon[ckey] = key
                    result_by_key[key] = self.db.execute(
                        "SELECT * FROM results WHERE result_id=?", (result_id,)).fetchone()

            # one budget update per (team, snapshot); holds covered these amounts
            paid: dict[tuple[str, str], list[float]] = {}
            for (tid, sid, _qhash) in payer_keys:
                rrow = result_by_key[(tid, sid, _qhash)]
                n = paid.setdefault((tid, sid), [0.0, 0.0])
                n[0] += rrow["epsilon"]
                n[1] += rrow["delta"]
            for (tid, sid), (eps_paid, delta_paid) in paid.items():
                self.db.execute(
                    """UPDATE budgets SET epsilon_spent=epsilon_spent+?,
                       delta_spent=delta_spent+? WHERE team_id=? AND snapshot_id=?""",
                    (eps_paid, delta_paid, tid, sid))

            # dense, per-position attribution rows
            charged_by_team: dict[str, list[float]] = {tid: [0.0, 0.0] for tid in fresh_teams}
            charge_seen: set[tuple[str, str, str]] = set()
            for tid in fresh_teams:
                for s in stmts:
                    key = (tid, s["snapshot_id"], s["query_hash"])
                    rrow = result_by_key[key]
                    charged = key in payer_keys and key not in charge_seen
                    charge_seen.add(key)
                    self.db.execute(
                        """INSERT INTO pub_release_members
                           (version_id, position, team_id, snapshot_id, query_hash,
                            result_id, charged, epsilon, delta)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        (version_id, s["position"], tid, s["snapshot_id"], s["query_hash"],
                         rrow["result_id"], 1 if charged else 0, s["epsilon"], s["delta"]))
                    if charged:
                        charged_by_team[tid][0] += s["epsilon"]
                        charged_by_team[tid][1] += s["delta"]

            for tid in fresh_teams:
                self.db.execute(
                    """UPDATE pub_contributions SET epsilon_charged=?, delta_charged=?,
                       epsilon_held=0, delta_held=0, updated_at=?
                       WHERE version_id=? AND team_id=?""",
                    (charged_by_team[tid][0], charged_by_team[tid][1], sealed_at,
                     version_id, tid))

            self.db.execute("DELETE FROM pub_holds WHERE version_id=?", (version_id,))

            manifest = self.build_release_manifest(
                self.db.execute("SELECT * FROM pub_versions WHERE version_id=?",
                                (version_id,)).fetchone())
            digest = sha256_hex(
                dumps_canon({k: v for k, v in manifest.items() if k != "sig"}))
            self.db.execute(
                """UPDATE pub_versions SET state='sealed', sealed_at=?, manifest_json=?,
                   manifest_digest=? WHERE version_id=?""",
                (sealed_at, dumps_canon(manifest), digest, version_id))
            # transparency outbox in the SAME transaction: commit is impossible
            # with the business change but without the durable leaf intent
            tl_key, tl_hash, _tl_existing = self._tl_enqueue_locked(
                RELEASE_SEALED, version_id,
                {"version_id": version_id, "batch_id": batch_id,
                 "seq": self.db.execute(
                     "SELECT seq FROM pub_versions WHERE version_id=?",
                     (version_id,)).fetchone()["seq"],
                 "manifest_digest": digest,
                 "parent_manifest_digest": manifest.get("parent_manifest_digest"),
                 "teams": sorted(fresh_teams)},
                created_at=sealed_at, actor=actor)
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

        # still holding the gateway lock: append the leaf deterministically and
        # advance the monotonic checkpoint before anyone can observe the seal
        self.tl_drain_locked()
        sealed_row = self._get_version(version_id)
        eps_total = sum(v[0] for v in charged_by_team.values())
        delta_total = sum(v[1] for v in charged_by_team.values())
        self._audit(actor=actor, action="publication", outcome="pub_sealed",
                    request_id=request_id, epsilon=eps_total, delta=delta_total,
                    detail={"batch_id": batch_id, "version_id": version_id,
                            "seq": sealed_row["seq"], "teams": len(fresh_teams),
                            "via": via, "manifest_digest": sealed_row["manifest_digest"]})
        # one ok_executed per paid result, ok_cached otherwise (dense members)
        for tid in fresh_teams:
            for s in stmts:
                key = (tid, s["snapshot_id"], s["query_hash"])
                rrow = result_by_key[key]
                payer = key in payer_keys
                self._audit(
                    actor=actor, action="pub_result",
                    outcome="ok_executed" if payer else "ok_cached",
                    team_id=tid, snapshot_id=s["snapshot_id"], result_id=rrow["result_id"],
                    query_hash_hex=s["query_hash"], family_id=s["family_id"],
                    request_id=request_id,
                    epsilon=s["epsilon"] if payer else None,
                    delta=s["delta"] if payer else None,
                    detail={"batch_id": batch_id, "version_id": version_id,
                            "position": s["position"]})
        response = self._version_response(sealed_row)
        anchor = self._tl_anchor_for_event_locked(tl_key)
        if anchor is not None:
            response["transparency"] = self._tl_anchor_brief(anchor)
        return response

    def _void_version_locked(self, v: sqlite3.Row, *, actor: str,
                             request_id: str | None, reason: str) -> str | None:
        """Void the version atomically and log the transparency event.

        Returns the event_key for anchoring the response, or None when the
        version was already settled by a concurrent call.
        """
        self._tl_require_not_frozen_locked("publication voiding")
        released = self.db.execute(
            "SELECT COALESCE(SUM(epsilon),0) e, COALESCE(SUM(delta),0) d FROM pub_holds "
            "WHERE version_id=?", (v["version_id"],)).fetchone()
        tl_key = None
        self.db.execute("BEGIN IMMEDIATE")
        committed = False
        try:
            cur = self.db.execute("SELECT state FROM pub_versions WHERE version_id=?",
                                  (v["version_id"],)).fetchone()
            if cur["state"] != COLLECTING:
                self.db.execute("COMMIT")
                committed = True
                return None
            voided_at = utcnow()
            self.db.execute("DELETE FROM pub_holds WHERE version_id=?", (v["version_id"],))
            self.db.execute(
                "UPDATE pub_versions SET state='void', voided_at=? WHERE version_id=?",
                (voided_at, v["version_id"]))
            self.db.execute(
                "UPDATE pub_contributions SET state='withdrawn', epsilon_held=0, delta_held=0 "
                "WHERE version_id=? AND state='registered'", (v["version_id"],))
            # transparency outbox in the SAME transaction as the void change
            tl_key, _tl_hash, _tl_existing = self._tl_enqueue_locked(
                RELEASE_VOIDED, v["version_id"],
                {"version_id": v["version_id"], "batch_id": v["batch_id"],
                 "reason": reason},
                created_at=voided_at, actor=actor)
            self.db.execute("COMMIT")
            committed = True
        except Exception:
            if not committed:
                self.db.execute("ROLLBACK")
            raise
        self.tl_drain_locked()
        self._audit(actor=actor, action="publication", outcome="pub_voided",
                    request_id=request_id, epsilon=released["e"], delta=released["d"],
                    detail={"batch_id": v["batch_id"], "version_id": v["version_id"],
                            "reason": reason})
        return tl_key

    # ------------------------------------------------------------------ #
    # deadline sweep + restart recovery
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_due(v: sqlite3.Row) -> bool:
        return _parse_ts(v["close_at"]) <= datetime.now(timezone.utc)

    def _registered_count(self, version_id: str) -> int:
        return self.db.execute(
            "SELECT COUNT(*) c FROM pub_contributions WHERE version_id=? AND state='registered'",
            (version_id,)).fetchone()["c"]

    def _settle_if_due_locked(self, v: sqlite3.Row, *, actor: str) -> sqlite3.Row:
        """Lazily seal/void a due collecting version touched by a team call."""
        if v["state"] == COLLECTING and self._is_due(v):
            self._sweep_one_locked(v, actor=actor)
            return self._get_version(v["version_id"])
        return v

    def _sweep_one_locked(self, v: sqlite3.Row, *, actor: str) -> str | None:
        """Settle one due collecting version. Returns 'sealed'/'void'/None."""
        # a fork-freezed log never settles due versions: no new signed release
        # or void leaf may be issued; the open version stays as-is for review
        if self._tl_freeze_row_locked() is not None:
            return None
        batch = self._batch_row(v["batch_id"])
        n = self._registered_count(v["version_id"])
        if n >= batch["min_participants"]:
            try:
                self._seal_version_locked(v, actor=actor, request_id=None, via="deadline")
                return "sealed"
            except DPGWError:
                # freeze/inactive/budget/integrity failure: keep collecting with
                # its holds; the rejection reason was audited inside the seal
                return None
        self._void_version_locked(
            v, actor=actor, request_id=None,
            reason=f"deadline reached with {n} < {batch['min_participants']} participants")
        return "void"

    def sweep_due_publications(self, *, actor: str = "system", limit: int = 500) -> dict:
        """Settle every due collecting version.  Safe to run at any time."""
        report = {"sealed": [], "void": [], "deferred": []}
        with self._lock:
            due = self.db.execute(
                "SELECT * FROM pub_versions WHERE state='collecting' AND close_at <= ?",
                (utcnow(),)).fetchall()
            for v in due[:limit]:
                outcome = self._sweep_one_locked(v, actor=actor)
                if outcome == "sealed":
                    report["sealed"].append(v["version_id"])
                elif outcome == "void":
                    report["void"].append(v["version_id"])
                else:
                    report["deferred"].append(v["version_id"])
            report["orphan_holds"] = self._delete_orphan_pub_holds()
        return report

    def _delete_orphan_pub_holds(self) -> int:
        cur = self.db.execute(
            """DELETE FROM pub_holds WHERE version_id IN (
                   SELECT version_id FROM pub_versions WHERE state != 'collecting')""")
        n = cur.rowcount or 0
        cur = self.db.execute(
            "DELETE FROM pub_holds WHERE version_id NOT IN "
            "(SELECT version_id FROM pub_versions)")
        return n + (cur.rowcount or 0)

    def recover_open_publications(self, *, actor: str = "system") -> dict:
        """Reconcile publication versions/holds after a restart.

        Due collecting versions are sealed (quorum met) or voided (below
        quorum, holds released).  Sealing failures leave the version
        collecting with its holds intact for a later retry; orphan holds are
        removed either way.
        """
        report = {"sealed": [], "void": [], "deferred": []}
        with self._lock:
            for v in self.db.execute(
                    "SELECT * FROM pub_versions WHERE state='collecting'").fetchall():
                if self._is_due(v):
                    outcome = self._sweep_one_locked(v, actor=actor)
                    if outcome == "sealed":
                        report["sealed"].append(v["version_id"])
                    elif outcome == "void":
                        report["void"].append(v["version_id"])
                    else:
                        report["deferred"].append(v["version_id"])
            report["orphan_holds"] = self._delete_orphan_pub_holds()
        return report

    # ------------------------------------------------------------------ #
    # rejection auditing
    # ------------------------------------------------------------------ #

    _REJECT_OUTCOMES = {
        BudgetExceeded: "reject_budget",
        FrozenQuery: "reject_frozen",
        SnapshotInactive: "reject_inactive",
        InvalidSnapshot: "reject_invalid",
        QuorumNotMet: "reject_quorum",
        PublicationClosed: "reject_late",
        NotParticipating: "reject_conflict",
        PublicationStateConflict: "reject_conflict",
        SpecificationChanged: "reject_conflict",
        PublicationInvalid: "reject_invalid",
    }

    def _pub_reject(self, err: DPGWError, *, actor: str,
                    team_id: str | None = None, request_id: str | None = None,
                    ref: str | None = None, version_row: sqlite3.Row | None = None) -> None:
        outcome = self._REJECT_OUTCOMES.get(type(err), "pub_reject")
        detail: dict[str, Any] = {"error": err.code, "message": err.message}
        vid = err.extra.get("version_id")
        if version_row is not None:
            vid = vid or version_row["version_id"]
            detail["batch_id"] = version_row["batch_id"]
        if ref is not None and vid is None and ref.startswith("pubv_"):
            vid = ref
        if vid:
            detail["version_id"] = vid
        self._audit(actor=actor, action="publication", outcome=outcome, team_id=team_id,
                    snapshot_id=err.extra.get("snapshot_id"),
                    family_id=err.extra.get("family_id"),
                    request_id=request_id,
                    epsilon=err.extra.get("epsilon"), delta=err.extra.get("delta"),
                    detail=detail)

    # ------------------------------------------------------------------ #
    # read APIs
    # ------------------------------------------------------------------ #

    def _get_version(self, version_id: str) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM pub_versions WHERE version_id=?", (version_id,)).fetchone()
        if row is None:
            raise PublicationNotFound(version_id)
        return row

    def _batch_row(self, batch_id: str) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM pub_batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            raise PublicationNotFound(batch_id)
        return row

    def _resolve_version_locked(self, ref: str) -> sqlite3.Row:
        if not isinstance(ref, str) or not ref:
            raise PublicationNotFound(str(ref))
        if ref.startswith("pubv_"):
            return self._get_version(ref)
        # batch reference -> latest version of the series
        row = self.db.execute(
            """SELECT v.* FROM pub_versions v JOIN pub_batches b ON b.batch_id=v.batch_id
               WHERE b.batch_id=? OR b.name=? ORDER BY v.seq DESC LIMIT 1""",
            (ref, ref)).fetchone()
        if row is None:
            raise PublicationNotFound(ref)
        return row

    def get_publication(self, ref: str) -> dict:
        with self._lock:
            v = self._resolve_version_locked(ref)
            return self._version_response(v, include_rejections=True)

    def list_publications(self, *, state: str | None = None,
                          batch_id: str | None = None, limit: int = 200) -> list[dict]:
        where, params = [], []
        if state:
            if state not in (COLLECTING, SEALED, VOID):
                raise PublicationInvalid(f"unknown state {state!r}")
            where.append("v.state=?")
            params.append(state)
        if batch_id:
            where.append("v.batch_id=?")
            params.append(batch_id)
        sql = ("SELECT v.*, b.name batch_name, b.min_participants min_participants, "
               "b.spec_hash spec_hash, b.statement_count statement_count_b "
               "FROM pub_versions v JOIN pub_batches b ON b.batch_id=v.batch_id")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY b.created_at DESC, v.seq DESC LIMIT ?"
        params.append(min(int(limit), 2000))
        out = []
        for r in self.db.execute(sql, params).fetchall():
            n = self._registered_count(r["version_id"])
            out.append({
                "batch_id": r["batch_id"], "batch_name": r["batch_name"],
                "version_id": r["version_id"], "seq": r["seq"],
                "parent_version_id": r["parent_version_id"], "state": r["state"],
                "spec_hash": r["spec_hash"], "min_participants": r["min_participants"],
                "statement_count": r["statement_count_b"],
                "participant_count": n,
                "quorum_met": n >= r["min_participants"],
                "created_at": r["created_at"], "close_at": r["close_at"],
                "sealed_at": r["sealed_at"], "voided_at": r["voided_at"],
                "manifest_digest": r["manifest_digest"],
            })
        return out

    def list_lineage(self, ref: str) -> list[dict]:
        with self._lock:
            v = self._resolve_version_locked(ref)
            rows = self.db.execute(
                """SELECT v.*, b.name batch_name, b.min_participants min_participants
                   FROM pub_versions v JOIN pub_batches b ON b.batch_id=v.batch_id
                   WHERE v.batch_id=? ORDER BY v.seq""", (v["batch_id"],)).fetchall()
            return [{
                "seq": r["seq"], "version_id": r["version_id"],
                "parent_version_id": r["parent_version_id"], "state": r["state"],
                "close_at": r["close_at"], "sealed_at": r["sealed_at"],
                "voided_at": r["voided_at"], "manifest_digest": r["manifest_digest"],
                "participant_count": self._registered_count(r["version_id"]),
                "min_participants": r["min_participants"],
            } for r in rows]

    def list_pub_holds(self, team_id: str | None = None,
                       snapshot_id: str | None = None) -> list[dict]:
        where, params = [], []
        if team_id:
            where.append("h.team_id=?")
            params.append(team_id)
        if snapshot_id:
            where.append("h.snapshot_id=?")
            params.append(snapshot_id)
        sql = (
            "SELECT h.team_id, h.snapshot_id, h.version_id, h.epsilon, h.delta, "
            "h.created_at, v.close_at, v.state, b.batch_id, b.name batch_name "
            "FROM pub_holds h JOIN pub_versions v ON v.version_id=h.version_id "
            "JOIN pub_batches b ON b.batch_id=v.batch_id")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY v.close_at"
        return [dict(r) for r in self.db.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------ #
    # signed release manifest + response shaping
    # ------------------------------------------------------------------ #

    def _statement_brief(self, version_id: str) -> list[dict]:
        rows = self.db.execute(
            "SELECT * FROM pub_statements WHERE version_id=? ORDER BY position",
            (version_id,)).fetchall()
        return [{
            "position": s["position"], "snapshot_id": s["snapshot_id"],
            "query_hash": s["query_hash"], "family_id": s["family_id"],
            "epsilon": s["epsilon"], "delta": s["delta"], "mechanism": s["mechanism"],
            "dimension": s["dimension"], "scale": s["scale"],
            "sensitivity_l1": s["sensitivity_l1"],
            "canonical": json.loads(s["canonical_json"]),
        } for s in rows]

    def _participant_entries(self, version_id: str, *, sealed_only: bool) -> list[dict]:
        sql = "SELECT * FROM pub_contributions WHERE version_id=?"
        if sealed_only:
            sql += " AND state='registered'"
        sql += " ORDER BY team_id"
        out = []
        for c in self.db.execute(sql, (version_id,)).fetchall():
            entry = {
                "team_id": c["team_id"], "state": c["state"],
                "epsilon_held": c["epsilon_held"], "delta_held": c["delta_held"],
                "epsilon_charged": c["epsilon_charged"],
                "delta_charged": c["delta_charged"],
            }
            if sealed_only:
                entry["result_count"] = self.db.execute(
                    "SELECT COUNT(DISTINCT result_id) c FROM pub_release_members "
                    "WHERE version_id=? AND team_id=? AND charged=1",
                    (version_id, c["team_id"])).fetchone()["c"]
            out.append(entry)
        return out

    def build_release_manifest(self, v: sqlite3.Row) -> dict:
        """Signed manifest over the fixed spec, participants and every receipt."""
        batch = self._batch_row(v["batch_id"])
        statements = self._statement_brief(v["version_id"])
        participants = self._participant_entries(v["version_id"], sealed_only=True)

        member_rows = self.db.execute(
            "SELECT * FROM pub_release_members WHERE version_id=? ORDER BY position, team_id",
            (v["version_id"],)).fetchall()
        members = [{
            "position": m["position"], "team_id": m["team_id"],
            "snapshot_id": m["snapshot_id"], "query_hash": m["query_hash"],
            "result_id": m["result_id"], "charged": bool(m["charged"]),
            "epsilon": m["epsilon"], "delta": m["delta"],
        } for m in member_rows]

        # unique receipts in deterministic (position, team) first-seen order
        receipts: list[dict] = []
        seen_results: set[str] = set()
        for m in member_rows:
            if m["result_id"] in seen_results:
                continue
            seen_results.add(m["result_id"])
            rrow = self.db.execute("SELECT * FROM results WHERE result_id=?",
                                   (m["result_id"],)).fetchone()
            receipts.append(self._receipt_dict(rrow))

        parent_digest = None
        if v["parent_version_id"] is not None:
            parent = self.db.execute(
                "SELECT manifest_digest FROM pub_versions WHERE version_id=?",
                (v["parent_version_id"],)).fetchone()
            parent_digest = parent["manifest_digest"] if parent is not None else None

        body = {
            "release_version": PUB_RELEASE_VERSION,
            "batch_id": batch["batch_id"],
            "batch_name": batch["name"],
            "version_id": v["version_id"],
            "seq": v["seq"],
            "parent_version_id": v["parent_version_id"],
            "parent_manifest_digest": parent_digest,
            "spec_hash": batch["spec_hash"],
            "min_participants": batch["min_participants"],
            "statement_count": batch["statement_count"],
            "created_at": v["created_at"],
            "close_at": v["close_at"],
            "sealed_at": v["sealed_at"],
            "statements": statements,
            "participants": participants,
            "members": members,
            "receipts": receipts,
        }
        return signed(body, self.receipt_key)

    def _recent_rejections(self, version_id: str, limit: int = 10) -> list[dict]:
        rows = self.db.execute(
            """SELECT * FROM audit_log WHERE action='publication'
               AND outcome LIKE 'reject_%' AND detail_json LIKE ?
               ORDER BY id DESC LIMIT ?""",
            ('%"' + version_id + '"%', limit)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            if d.get("detail_json"):
                d["detail"] = json.loads(d["detail_json"])
            del d["detail_json"]
            out.append(d)
        return out

    def _version_response(self, v: sqlite3.Row, registration: str | None = None,
                          include_rejections: bool = False) -> dict:
        batch = self._batch_row(v["batch_id"])
        participants = self._participant_entries(
            v["version_id"], sealed_only=v["state"] == SEALED)
        registered = [p for p in participants if p["state"] == "registered"]
        d: dict[str, Any] = {
            "batch_id": batch["batch_id"],
            "batch_name": batch["name"],
            "version_id": v["version_id"],
            "seq": v["seq"],
            "parent_version_id": v["parent_version_id"],
            "state": v["state"],
            "spec_hash": batch["spec_hash"],
            "min_participants": batch["min_participants"],
            "statement_count": batch["statement_count"],
            "created_at": v["created_at"],
            "close_at": v["close_at"],
            "sealed_at": v["sealed_at"],
            "voided_at": v["voided_at"],
            "manifest_digest": v["manifest_digest"],
            "participant_count": len(registered),
            "quorum_met": len(registered) >= batch["min_participants"],
            "participants": participants,
        }
        if registration is not None:
            d["registration"] = registration
        if v["state"] == COLLECTING:
            d["statements"] = [{
                "position": s["position"], "snapshot_id": s["snapshot_id"],
                "query_hash": s["query_hash"], "family_id": s["family_id"],
                "epsilon": s["epsilon"], "delta": s["delta"],
            } for s in self.db.execute(
                "SELECT * FROM pub_statements WHERE version_id=? ORDER BY position",
                (v["version_id"],)).fetchall()]
        if v["state"] == SEALED:
            d["manifest"] = json.loads(v["manifest_json"])
        if include_rejections or v["state"] == COLLECTING:
            d["rejections"] = self._recent_rejections(v["version_id"])
        return d
