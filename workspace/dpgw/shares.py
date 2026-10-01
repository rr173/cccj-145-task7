"""Controlled sharing packages: team-authorised, field-trimmed redistributions
of a signed joint-publication release manifest.

A *share* is created by the analysis owner (administrator) from one **sealed**
publication version.  At creation three things are fixed and then never move:

* the **release** -- a sealed ``pub_versions`` row identified by its
  ``manifest_digest``;
* the **audience** -- exactly one existing team;
* the **field set** -- the exact release-manifest paths the audience may
  receive; every path must already be inside that team's per-release field
  grant (``share_field_grants``), so authorisation can never widen at request
  time or while a request is in flight.

The result is one immutable, HMAC-signed *package* whose signature binds the
release ``manifest_digest``, the parent release digest (lineage), the audience,
the trimmed field set and the expiry instant.  Package bytes are
content-addressed under ``home/shares``.

Lifecycle::

    creating -> sealed          (one package, one share_key, one file)
             \\-> failed         (interrupted creation proven unrecoverable)
    sealed -> revoked            (new retrievals rejected; the already
                                  downloaded file stays verifiable offline)

Idempotency / concurrency
-------------------------
Partial unique indexes enforce one live share per (version, team, field-set)
and one live share per share_key.  Concurrent creates for the same scope both
reserve a ``creating`` row; the loser finds the winner's reservation and helps
finish it deterministically (the package is a pure function of the reserved
row), so exactly one package is ever sealed.  Repeated retrievals stream the
same bytes and never regenerate the file.

Crash safety
------------
The ``creating`` row and its inputs (fields, ttl, expiry) commit before any
file is written; the package is a deterministic function of that row, so a
restart either completes the reservation (materialise + seal) or -- when the
world has become invalid (release voided/replaced, audience deleted, grant no
longer covering the fields) -- marks it ``failed`` and removes any partial
file.  No half-sealed package is ever observable.
"""

from __future__ import annotations

import hmac
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from .errors import (
    DPGWError,
    PublicationNotFound,
    ShareForbidden,
    ShareInvalid,
    ShareNotFound,
    ShareRevoked,
    ShareStateConflict,
    ShareExpired,
    TeamNotFound,
)
from .receipts import dumps_canon, sha256_hex
from .transparency import SHARE_ISSUED, SHARE_REVOKED
from .util import new_id, utcnow

SHARE_PACKAGE_VERSION = "sh1"
DEFAULT_TTL_SECONDS = 7 * 24 * 3600

CREATING = "creating"
SEALED = "sealed"
FAILED = "failed"
REVOKED = "revoked"

# release-manifest identity/lineage scalars always carried by every package --
# they make the trimmed object self-describing but carry no result content.
RELEASE_IDENTITY_FIELDS = (
    "release_version", "batch_id", "batch_name", "version_id", "seq",
    "parent_version_id", "parent_manifest_digest", "spec_hash",
    "min_participants", "statement_count", "created_at", "close_at", "sealed_at",
)

# grantable content fields, grouped by release-manifest collection.  Granting a
# bare collection name ("receipts") covers every subpath of that collection.
COLLECTION_FIELDS: dict[str, tuple[str, ...]] = {
    "statements": (
        "position", "snapshot_id", "query_hash", "family_id", "epsilon", "delta",
        "mechanism", "dimension", "scale", "sensitivity_l1", "canonical",
    ),
    "participants": (
        "team_id", "state", "epsilon_held", "delta_held",
        "epsilon_charged", "delta_charged", "result_count",
    ),
    "members": (
        "position", "team_id", "snapshot_id", "query_hash", "result_id",
        "charged", "epsilon", "delta",
    ),
    "receipts": (
        "receipt_version", "result_id", "team_id", "snapshot_id", "query_hash",
        "family_id", "canonical", "mechanism", "privacy", "dimension",
        "sensitivity_l1", "noise_scale", "coords", "values", "created_at",
    ),
}

# per-collection linkage keys that always travel with a projection so the
# trimmed rows stay self-describing; they carry no statistical content.
COLLECTION_KEY_FIELDS: dict[str, tuple[str, ...]] = {
    "statements": ("position",),
    "participants": ("team_id",),
    "members": ("position", "team_id"),
    "receipts": ("result_id",),
}

# a projected receipt can be independently re-verified (replay the original
# HMAC over its complete body) only when every signed key is carried; partial
# receipts are anchored by the share signature + release digest instead.
RECEIPT_VERIFY_KEYS = frozenset({
    "receipt_version", "result_id", "team_id", "snapshot_id", "query_hash",
    "family_id", "canonical", "mechanism", "privacy", "dimension",
    "sensitivity_l1", "noise_scale", "coords", "values", "created_at", "sig",
})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def _fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_expiry(expires_at: str | None, ttl_seconds: int | None) -> tuple[str, int]:
    """Resolve (expires_at | ttl_seconds) to a canonical future instant."""
    if expires_at is not None and ttl_seconds is not None:
        raise ShareInvalid("pass either expires_at or ttl_seconds, not both")
    if expires_at is not None:
        if not isinstance(expires_at, str) or not expires_at.strip():
            raise ShareInvalid("expires_at must be an ISO-8601 timestamp")
        text = expires_at.strip()
        try:
            dt = (datetime.fromisoformat(text[:-1] + "+00:00") if text.endswith("Z")
                  else datetime.fromisoformat(text))
        except ValueError:
            raise ShareInvalid(f"expires_at {expires_at!r} is not ISO-8601")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        ttl = int((dt - _now()).total_seconds())
    else:
        if ttl_seconds is None:
            ttl_seconds = DEFAULT_TTL_SECONDS
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) \
                or ttl_seconds <= 0:
            raise ShareInvalid("ttl_seconds must be a positive integer")
        ttl = ttl_seconds
        dt = _now() + timedelta(seconds=ttl)
    if dt <= _now():
        raise ShareInvalid("share expiry must be in the future")
    return _fmt_ts(dt), ttl


def all_catalog_fields() -> list[str]:
    out = list(COLLECTION_FIELDS)
    for coll, subs in COLLECTION_FIELDS.items():
        out.extend(f"{coll}.{s}" for s in subs)
    return out


def normalize_fields(fields: Any) -> list[str]:
    """Validate + dedup + sort a requested/granted field list."""
    if not isinstance(fields, list) or not fields:
        raise ShareInvalid("fields must be a non-empty list of field paths")
    selected: set[str] = set()
    for f in fields:
        if not isinstance(f, str) or not f:
            raise ShareInvalid("field paths must be non-empty strings")
        if f in COLLECTION_FIELDS:
            selected.add(f)
            continue
        if "." in f:
            coll, sub = f.split(".", 1)
            if sub in COLLECTION_FIELDS.get(coll, ()):
                selected.add(f)
                continue
        raise ShareInvalid(f"unknown share field path {f!r}")
    # a bare collection grant makes its subpaths redundant
    expanded = {f for f in selected
                if "." not in f or f.split(".", 1)[0] not in selected}
    return sorted(expanded)


def fields_covered(fields: list[str], grant: list[str]) -> list[str]:
    """Return the requested paths that are NOT covered by the grant."""
    gset = set(grant)
    missing = []
    for f in fields:
        if f in gset:
            continue
        coll = f.split(".", 1)[0]
        if coll in gset:
            continue
        missing.append(f)
    return missing


def fields_hash(fields: list[str]) -> str:
    return sha256_hex(dumps_canon(fields))


def project_release(manifest: dict, fields: list[str]) -> dict:
    """Deterministically trim a signed release manifest to *fields*.

    Identity/lineage scalars are always retained; collection content is kept
    only as authorised.  The original release ``sig`` is intentionally dropped
    (it authenticates the *full* body, not the projection) -- provenance of the
    trimmed object is anchored by ``release_digest`` inside the signed share
    package, and cross-checked against the full release when it is available
    offline.
    """
    out: dict[str, Any] = {k: manifest.get(k) for k in RELEASE_IDENTITY_FIELDS
                           if k in manifest}
    chosen: dict[str, set[str]] = {}
    whole: set[str] = set()
    for f in fields:
        if "." not in f:
            whole.add(f)
            chosen.setdefault(f, set())
        else:
            coll, sub = f.split(".", 1)
            chosen.setdefault(coll, set()).add(sub)
    for coll, rows in (("statements", manifest.get("statements")),
                       ("participants", manifest.get("participants")),
                       ("members", manifest.get("members")),
                       ("receipts", manifest.get("receipts"))):
        if rows is None or coll not in chosen:
            continue
        keys = set(COLLECTION_FIELDS[coll]) if coll in whole else set(chosen[coll])
        # linkage keys are always retained so rows stay self-describing
        keys.update(COLLECTION_KEY_FIELDS[coll])
        if coll == "receipts" and coll in whole:
            keys.add("sig")  # whole-receipt grant keeps receipts self-verifying
        catalogue = COLLECTION_FIELDS[coll] + (("sig",) if coll == "receipts" else ())
        out[coll] = [{k: item[k] for k in catalogue if k in keys and k in item}
                     for item in rows]
    return out


class SharingMixin:
    """Controlled sharing packages; mixed into :class:`Gateway`."""

    # ------------------------------------------------------------------ #
    # keying
    # ------------------------------------------------------------------ #

    def _share_dir(self) -> str:
        path = os.path.join(self.snap_root, "..", "shares")
        return os.path.abspath(path)

    def _derive_share_key(self, share_id: str) -> str:
        mac = hmac.new(self.share_secret, ("share_key:" + share_id).encode("utf-8"),
                       digestmod="sha256").hexdigest()
        return "shk_" + mac

    def _hash_share_key(self, key: str) -> str:
        return sha256_hex(key)

    # ------------------------------------------------------------------ #
    # per-release field grants (whitelist administration)
    # ------------------------------------------------------------------ #

    def grant_share_fields(self, ref: str, team_id: str, fields: list, *,
                          actor: str = "admin", request_id: str | None = None) -> dict:
        """Set (replace) the audience team's field whitelist on one release."""
        norm = normalize_fields(fields)
        with self._lock:
            v = self._resolve_version_locked(ref)
            if self.db.execute("SELECT 1 FROM teams WHERE team_id=?",
                               (team_id,)).fetchone() is None:
                raise TeamNotFound(f"audience team {team_id!r} not found")
            now = utcnow()
            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                self.db.execute(
                    """INSERT INTO share_field_grants
                       (version_id, team_id, fields_json, granted_by, created_at)
                       VALUES (?,?,?,?,?)
                       ON CONFLICT(version_id, team_id) DO UPDATE SET
                         fields_json=excluded.fields_json,
                         granted_by=excluded.granted_by,
                         created_at=excluded.created_at""",
                    (v["version_id"], team_id, dumps_canon(norm), actor, now))
                self.db.execute("COMMIT")
                committed = True
            except Exception:
                if not committed:
                    self.db.execute("ROLLBACK")
                raise
        self._audit(actor=actor, action="share", outcome="share_grant_set",
                    team_id=team_id, request_id=request_id,
                    detail={"version_id": v["version_id"], "fields": norm})
        return {"version_id": v["version_id"], "team_id": team_id, "fields": norm,
                "updated_at": now}

    def get_share_grant(self, version_id: str, team_id: str) -> dict | None:
        row = self.db.execute(
            "SELECT * FROM share_field_grants WHERE version_id=? AND team_id=?",
            (version_id, team_id)).fetchone()
        return None if row is None else {
            "version_id": row["version_id"], "team_id": row["team_id"],
            "fields": json.loads(row["fields_json"]),
            "granted_by": row["granted_by"], "created_at": row["created_at"]}

    def list_share_grants(self, version_id: str | None = None) -> list[dict]:
        sql = "SELECT * FROM share_field_grants"
        params: list = []
        if version_id:
            sql += " WHERE version_id=?"
            params.append(version_id)
        sql += " ORDER BY version_id, team_id"
        return [{
            "version_id": r["version_id"], "team_id": r["team_id"],
            "fields": json.loads(r["fields_json"]),
            "granted_by": r["granted_by"], "created_at": r["created_at"],
        } for r in self.db.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------ #
    # package construction (deterministic pure function of a stored row)
    # ------------------------------------------------------------------ #

    def _build_package_locked(self, row: sqlite3.Row) -> tuple[dict, str, bytes]:
        v = self.db.execute("SELECT * FROM pub_versions WHERE version_id=?",
                            (row["version_id"],)).fetchone()
        if v is None or v["state"] != "sealed" or not v["manifest_json"]:
            raise ShareStateConflict("release is not sealed", version_id=row["version_id"])
        if v["manifest_digest"] != row["manifest_digest"]:
            raise ShareStateConflict("release manifest_digest changed under the share",
                                     version_id=row["version_id"])
        fields = json.loads(row["fields_json"])
        manifest = json.loads(v["manifest_json"])
        parent_digest = manifest.get("parent_manifest_digest")
        if parent_digest != row["parent_digest"]:
            raise ShareStateConflict("parent release digest mismatch",
                                     version_id=row["version_id"])
        trimmed = project_release(manifest, fields)
        body = {
            "share_version": SHARE_PACKAGE_VERSION,
            "share_id": row["share_id"],
            "version_id": row["version_id"],
            "batch_id": manifest["batch_id"],
            "team_id": row["team_id"],
            "fields": fields,
            "fields_hash": fields_hash(fields),
            "release_digest": row["manifest_digest"],
            "release_parent_digest": parent_digest,
            "release": trimmed,
            "created_at": row["created_at"],
            "ttl_seconds": row["ttl_seconds"],
            "expires_at": row["expires_at"],
        }
        body["sig"] = hmac.new(
            self.share_secret,
            dumps_canon({k: x for k, x in body.items() if k != "sig"}).encode("utf-8"),
            digestmod="sha256").hexdigest()
        raw = dumps_canon(body).encode("utf-8")
        digest = sha256_hex(dumps_canon(
            {k: x for k, x in body.items() if k != "sig"}))
        return body, digest, raw

    def _package_path(self, digest: str) -> str:
        return os.path.join(self._share_dir(), digest + ".json")

    def _write_package_atomic(self, digest: str, raw: bytes) -> None:
        directory = self._share_dir()
        os.makedirs(directory, exist_ok=True)
        final = self._package_path(digest)
        if os.path.exists(final):
            with open(final, "rb") as fh:
                if fh.read() == raw:
                    return  # identical content-addressed package already present
        tmp = os.path.join(directory, ".tmp-" + digest[:16] + "-" + new_id("w")[2:])
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(raw)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, final)
            try:
                dfd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                pass
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _fail_creating_locked(self, row: sqlite3.Row, reason: str) -> None:
        """Terminally abort an invalid reservation; best-effort remove its file."""
        self.db.execute("BEGIN IMMEDIATE")
        committed = False
        try:
            cur = self.db.execute("SELECT state FROM shares WHERE share_id=?",
                                  (row["share_id"],)).fetchone()
            if cur is not None and cur["state"] == CREATING:
                self.db.execute("UPDATE shares SET state='failed' WHERE share_id=?",
                                (row["share_id"],))
            self.db.execute("COMMIT")
            committed = True
        except Exception:
            if not committed:
                self.db.execute("ROLLBACK")
            raise
        self._audit(actor="system", action="share", outcome="share_creation_failed",
                    team_id=row["team_id"],
                    detail={"share_id": row["share_id"], "version_id": row["version_id"],
                            "reason": reason})

    def _seal_creating_locked(self, row: sqlite3.Row, *,
                              crash: dict | None = None
                              ) -> tuple[sqlite3.Row, str | None]:
        """Finish an interrupted/in-progress reservation.

        Deterministic in the row's own inputs, so a concurrent loser or a
        restart may run it on the winner's behalf.  Semantic invalidity fails
        the share safely; unexpected (transient) errors propagate and leave the
        reservation creating for a later retry.

        Returns ``(sealed_row, event_key)`` -- event_key is None on an
        idempotent replay against an already-sealed sibling.
        """
        fresh = self._get_share_row(row["share_id"])
        if fresh["state"] == SEALED:
            return fresh, None
        if fresh["state"] != CREATING:
            raise ShareStateConflict(f"share is {fresh['state']}",
                                     share_id=row["share_id"])
        # a fork-freezed log issues no new packages: the reservation stays
        # creating (nothing observable is produced) and the request fails
        self._tl_require_not_frozen_locked("share issuance")
        # world re-validation: audience + whitelist still hold
        team = self.db.execute("SELECT 1 FROM teams WHERE team_id=?",
                               (fresh["team_id"],)).fetchone()
        if team is None:
            self._fail_creating_locked(fresh, "audience team no longer exists")
            raise ShareForbidden("audience team no longer exists")
        grant = self.db.execute(
            "SELECT fields_json FROM share_field_grants WHERE version_id=? AND team_id=?",
            (fresh["version_id"], fresh["team_id"])).fetchone()
        fields = json.loads(fresh["fields_json"])
        if grant is None or fields_covered(fields, json.loads(grant["fields_json"])):
            self._fail_creating_locked(fresh, "fields outside the team grant")
            raise ShareForbidden("requested fields are outside the team grant")
        try:
            body, digest, raw = self._build_package_locked(fresh)
        except DPGWError as e:
            # release voided/replaced/digest changed: safe termination
            self._fail_creating_locked(fresh, e.message)
            raise
        self._write_package_atomic(digest, raw)
        if crash and crash.get("after_write"):
            raise RuntimeError("crash injected after package write")
        key = self._derive_share_key(fresh["share_id"])
        sealed_at = utcnow()
        tl_key = None
        self.db.execute("BEGIN IMMEDIATE")
        committed = False
        try:
            cur = self.db.execute("SELECT state FROM shares WHERE share_id=?",
                                  (fresh["share_id"],)).fetchone()
            if cur["state"] == SEALED:
                self.db.execute("COMMIT")
                committed = True
                return self._get_share_row(fresh["share_id"]), None
            if cur["state"] != CREATING:
                raise ShareStateConflict(f"share is {cur['state']}")
            self.db.execute(
                """UPDATE shares SET state='sealed', package_digest=?, share_key_hash=?,
                   sealed_at=? WHERE share_id=?""",
                (digest, self._hash_share_key(key), sealed_at, fresh["share_id"]))
            # transparency outbox in the SAME transaction as the issuance:
            # a share can never be sealed without its durable leaf intent
            tl_key, _tl_hash, _tl_existing = self._tl_enqueue_locked(
                SHARE_ISSUED, fresh["share_id"],
                {"share_id": fresh["share_id"], "version_id": fresh["version_id"],
                 "team_id": fresh["team_id"], "fields": fields,
                 "fields_hash": fresh["fields_hash"],
                 "package_digest": digest,
                 "manifest_digest": fresh["manifest_digest"],
                 "parent_digest": fresh["parent_digest"],
                 "expires_at": fresh["expires_at"]},
                created_at=sealed_at, actor="system")
            self.db.execute("COMMIT")
            committed = True
        except Exception:
            if not committed:
                self.db.execute("ROLLBACK")
            raise
        self.tl_drain_locked()
        return self._get_share_row(fresh["share_id"]), tl_key

    # ------------------------------------------------------------------ #
    # creation: validate -> reserve (creating) -> materialise -> seal
    # ------------------------------------------------------------------ #

    def create_share(self, ref: str, team_id: str, fields: list, *,
                     expires_at: str | None = None, ttl_seconds: int | None = None,
                     actor: str = "admin", request_id: str | None = None,
                     _crash: dict | None = None) -> dict:
        norm = normalize_fields(fields)
        expires, ttl = parse_expiry(expires_at, ttl_seconds)
        try:
            return self._create_share(ref, team_id, norm, expires, ttl,
                                      actor=actor, request_id=request_id, crash=_crash)
        except DPGWError as e:
            self._share_reject(e, actor=actor, team_id=team_id, request_id=request_id,
                               ref=ref)
            raise

    def _create_share(self, ref: str, team_id: str, fields: list[str],
                      expires: str, ttl: int, *, actor: str,
                      request_id: str | None, crash: dict | None) -> dict:
        with self._lock:
            v = self._resolve_version_locked(ref)
            if v["state"] != "sealed":
                if v["state"] == "void":
                    raise ShareStateConflict(
                        f"release version {v['version_id']} is void; no shares can be made",
                        version_id=v["version_id"])
                raise ShareStateConflict(
                    f"release version {v['version_id']} is {v['state']}; "
                    "only sealed releases can be shared",
                    version_id=v["version_id"])
            if _parse_ts(v["close_at"]) <= _now():
                # a sealed release past its own close instant is final; shares
                # bind the sealed digest -- this branch guards tampered clocks
                pass
            if self.db.execute("SELECT 1 FROM teams WHERE team_id=?",
                               (team_id,)).fetchone() is None:
                raise TeamNotFound(f"audience team {team_id!r} not found")
            grant = self.db.execute(
                "SELECT fields_json FROM share_field_grants WHERE version_id=? AND team_id=?",
                (v["version_id"], team_id)).fetchone()
            if grant is None:
                raise ShareForbidden(
                    f"team {team_id} has no field grant on release {v['version_id']}",
                    version_id=v["version_id"])
            overreach = fields_covered(fields, json.loads(grant["fields_json"]))
            if overreach:
                raise ShareForbidden(
                    f"fields outside the team grant: {overreach}",
                    version_id=v["version_id"], fields=overreach)

            fhash = fields_hash(fields)
            existing = self.db.execute(
                "SELECT * FROM shares WHERE version_id=? AND team_id=? AND fields_hash=? "
                "AND state IN ('creating','sealed')",
                (v["version_id"], team_id, fhash)).fetchone()
            replayed = False
            if existing is None:
                # genuinely new scope: a fork freeze refuses the new issuance
                # before any reservation row exists (nothing to roll back)
                self._tl_require_not_frozen_locked("share creation")
                share_id = new_id("shr")
                now = utcnow()
                parent_digest = None
                if v["parent_version_id"] is not None:
                    parent = self.db.execute(
                        "SELECT manifest_digest FROM pub_versions WHERE version_id=?",
                        (v["parent_version_id"],)).fetchone()
                    parent_digest = parent["manifest_digest"] if parent else None
                self.db.execute("BEGIN IMMEDIATE")
                committed = False
                try:
                    try:
                        self.db.execute(
                            """INSERT INTO shares
                               (share_id, version_id, team_id, fields_json, fields_hash,
                                state, manifest_digest, parent_digest, ttl_seconds,
                                created_at, expires_at, created_by)
                               VALUES (?,?,?,?,?, 'creating', ?,?,?,?,?,?)""",
                            (share_id, v["version_id"], team_id, dumps_canon(fields), fhash,
                             v["manifest_digest"], parent_digest, ttl, now, expires, actor))
                    except sqlite3.IntegrityError:
                        # concurrent create for the same scope won the reservation
                        sibling = self.db.execute(
                            "SELECT * FROM shares WHERE version_id=? AND team_id=? "
                            "AND fields_hash=? AND state IN ('creating','sealed')",
                            (v["version_id"], team_id, fhash)).fetchone()
                        existing = sibling
                    self.db.execute("COMMIT")
                    committed = True
                except Exception:
                    if not committed:
                        self.db.execute("ROLLBACK")
                    raise
                if existing is None:
                    existing = self._get_share_row(share_id)
                else:
                    replayed = True
            else:
                replayed = True

            if crash and crash.get("after_insert") and not replayed:
                raise RuntimeError("crash injected after reservation insert")

            # a sealed sibling is an idempotent replay: same package, same key
            if existing["state"] == SEALED:
                sealed, issued_key = existing, None
            elif existing["state"] == CREATING:
                # help finish the in-flight reservation (ours or a concurrent one)
                sealed, issued_key = self._seal_creating_locked(existing, crash=crash)
            else:  # pragma: no cover - live index excludes terminal rows
                raise ShareStateConflict(f"sibling share is {existing['state']}")

            key = self._derive_share_key(sealed["share_id"])
            self._audit(actor=actor, action="share",
                        outcome="share_replayed" if replayed else "share_created",
                        team_id=team_id, request_id=request_id,
                        detail={"share_id": sealed["share_id"],
                                "version_id": v["version_id"],
                                "manifest_digest": v["manifest_digest"],
                                "package_digest": sealed["package_digest"],
                                "fields": fields, "expires_at": expires})
            response = self._share_response(sealed, share_key=key, created=not replayed)
            if issued_key is not None:
                anchor = self._tl_anchor_for_event_locked(issued_key)
                if anchor is not None:
                    response["transparency"] = self._tl_anchor_brief(anchor)
            return response

    # ------------------------------------------------------------------ #
    # retrieval: same key -> same package, never regenerated; revocation/
    # expiry reject new fetches while downloaded files verify offline
    # ------------------------------------------------------------------ #

    def fetch_share(self, share_key: str, *, actor: str | None = None,
                    team_id: str | None = None,
                    request_id: str | None = None) -> dict:
        key_hash = self._hash_share_key(share_key.strip())
        with self._lock:
            # creating rows carry no share_key_hash yet, so a key lookup can
            # only address a sealed/revoked package; it can never complete a
            # reservation owned by an in-flight create on the recipient's behalf
            row = self.db.execute(
                "SELECT * FROM shares WHERE share_key_hash=?",
                (key_hash,)).fetchone()
            if row is None or row["state"] in (FAILED, CREATING):
                raise ShareNotFound("no live share matches the supplied share_key")
            # constant-time key equality
            if not hmac.compare_digest(self._hash_share_key(self._derive_share_key(row["share_id"])),
                                       key_hash):
                raise ShareNotFound("no live share matches the supplied share_key")
            # an authenticated recipient must be the audience; an unauthenticated
            # caller that simply holds the bearer key is accepted (offline/CLI)
            if team_id is not None and team_id != row["team_id"]:
                self._record_retrieval(row, "reject_audience", actor)
                raise ShareNotFound("no live share matches the supplied share_key")
            if row["state"] == REVOKED:
                self._record_retrieval(row, "reject_revoked", actor)
                raise ShareRevoked("share has been revoked", share_id=row["share_id"])
            if _parse_ts(row["expires_at"]) <= _now():
                self._record_retrieval(row, "reject_expired", actor)
                raise ShareExpired("share has expired", share_id=row["share_id"])
            body, digest, raw = self._read_package_locked(row)
            self._record_retrieval(row, "ok", actor)
            return body

    def _read_package_locked(self, row: sqlite3.Row) -> tuple[dict, str, bytes]:
        path = self._package_path(row["package_digest"])
        if not os.path.exists(path):
            # file lost from storage: regenerate the SAME bytes (digest is fixed)
            body, digest, raw = self._build_package_locked(row)
            if digest != row["package_digest"]:
                raise ShareStateConflict("share package digest is no longer reproducible",
                                         share_id=row["share_id"])
            self._write_package_atomic(digest, raw)
        else:
            with open(path, "rb") as fh:
                raw = fh.read()
            doc = json.loads(raw.decode("utf-8"))
            digest = sha256_hex(dumps_canon(
                {k: x for k, x in doc.items() if k != "sig"}))
            if digest != row["package_digest"]:
                raise ShareStateConflict("stored package digest mismatch",
                                         share_id=row["share_id"])
            body = doc
        if not hmac.compare_digest(body.get("sig", ""), hmac.new(
                self.share_secret,
                dumps_canon({k: x for k, x in body.items() if k != "sig"}).encode("utf-8"),
                digestmod="sha256").hexdigest()):
            raise ShareStateConflict("stored package signature invalid",
                                     share_id=row["share_id"])
        return body, digest, raw

    def _record_retrieval(self, row: sqlite3.Row, outcome: str,
                          actor: str | None) -> None:
        self.db.execute(
            "INSERT INTO share_retrievals (share_id, retrieved_at, actor, outcome) "
            "VALUES (?,?,?,?)",
            (row["share_id"], utcnow(), actor or ("team:" + row["team_id"]), outcome))

    # ------------------------------------------------------------------ #
    # revocation
    # ------------------------------------------------------------------ #

    def revoke_share(self, share_id: str, *, reason: str = "", actor: str = "admin",
                     request_id: str | None = None) -> dict:
        with self._lock:
            row = self._get_share_row(share_id)
            if row["state"] == REVOKED:
                return self._share_response(row)  # idempotent
            if row["state"] == CREATING:
                # finish first so the operation is unambiguous; the package file
                # remains the immutable artifact of record
                row, _issued = self._seal_creating_locked(row)
            if row["state"] != SEALED:
                raise ShareStateConflict(f"cannot revoke a {row['state']} share",
                                         share_id=share_id)
            # freeze check after any deterministic completion: revoking after a
            # fork freeze is itself a new leaf and must be refused
            self._tl_require_not_frozen_locked("share revocation")
            revoked_at = utcnow()
            tl_key = None
            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                cur = self.db.execute("SELECT state FROM shares WHERE share_id=?",
                                      (share_id,)).fetchone()
                if cur["state"] == REVOKED:
                    self.db.execute("COMMIT")
                    committed = True
                    return self._share_response(
                        self._get_share_row(share_id))
                self.db.execute(
                    "UPDATE shares SET state='revoked', revoked_at=?, revoke_reason=? "
                    "WHERE share_id=?",
                    (revoked_at, reason or None, share_id))
                # transparency outbox in the SAME transaction as the revocation
                tl_key, _tl_hash, _tl_existing = self._tl_enqueue_locked(
                    SHARE_REVOKED, share_id,
                    {"share_id": share_id, "version_id": row["version_id"],
                     "team_id": row["team_id"], "package_digest": row["package_digest"],
                     "manifest_digest": row["manifest_digest"],
                     "reason": reason or None},
                    created_at=revoked_at, actor=actor)
                self.db.execute("COMMIT")
                committed = True
            except Exception:
                if not committed:
                    self.db.execute("ROLLBACK")
                raise
            self.tl_drain_locked()
            self._audit(actor=actor, action="share", outcome="share_revoked",
                        team_id=row["team_id"], request_id=request_id,
                        detail={"share_id": share_id, "version_id": row["version_id"],
                                "reason": reason})
            response = self._share_response(self._get_share_row(share_id))
            anchor = self._tl_anchor_for_event_locked(tl_key)
            if anchor is not None:
                response["transparency"] = self._tl_anchor_brief(anchor)
            return response

    # ------------------------------------------------------------------ #
    # restart recovery: every interrupted reservation completes or fails
    # ------------------------------------------------------------------ #

    def recover_pending_shares(self, *, actor: str = "system",
                               crash: dict | None = None) -> dict:
        """Reconcile ``creating`` rows after a restart.

        Each is completed deterministically when still valid or safely
        ``failed`` (audience/whitelist/release invalidity); unexpected errors
        leave it creating and reported as deferred for a later sweep.
        """
        report = {"sealed": [], "failed": [], "deferred": []}
        with self._lock:
            pending = self.db.execute(
                "SELECT * FROM shares WHERE state='creating'").fetchall()
            frozen = self._tl_freeze_row_locked() is not None
            for row in pending:
                if frozen:
                    # a share whose issuance never committed must not materialise
                    # while the log cannot record it
                    report["deferred"].append(row["share_id"])
                    continue
                try:
                    self._seal_creating_locked(row, crash=crash)
                    report["sealed"].append(row["share_id"])
                except DPGWError:
                    # _seal_creating_locked already terminalised semantic failures
                    cur = self._get_share_row(row["share_id"])
                    report[ "failed" if cur["state"] == FAILED else "deferred"].append(
                        row["share_id"])
                except Exception:
                    report["deferred"].append(row["share_id"])
        return report

    # ------------------------------------------------------------------ #
    # read APIs
    # ------------------------------------------------------------------ #

    def _get_share_row(self, share_id: str) -> sqlite3.Row:
        row = self.db.execute("SELECT * FROM shares WHERE share_id=?",
                              (share_id,)).fetchone()
        if row is None:
            raise ShareNotFound(share_id)
        return row

    def get_share(self, share_id: str, *, include_key: bool = False) -> dict:
        with self._lock:
            row = self._get_share_row(share_id)
            key = self._derive_share_key(row["share_id"]) if include_key else None
            return self._share_response(row, share_key=key)

    def list_shares(self, *, version_id: str | None = None, team_id: str | None = None,
                    state: str | None = None, limit: int = 500) -> list[dict]:
        if state is not None and state not in (CREATING, SEALED, FAILED, REVOKED):
            raise ShareInvalid(f"unknown state {state!r}")
        where, params = [], []
        if version_id:
            where.append("version_id=?")
            params.append(version_id)
        if team_id:
            where.append("team_id=?")
            params.append(team_id)
        if state:
            where.append("state=?")
            params.append(state)
        sql = "SELECT * FROM shares"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(min(int(limit), 5000))
        return [self._share_response(r) for r in self.db.execute(sql, params).fetchall()]

    def list_retrievals(self, share_id: str | None = None) -> list[dict]:
        sql = "SELECT * FROM share_retrievals"
        params: list = []
        if share_id:
            sql += " WHERE share_id=?"
            params.append(share_id)
        sql += " ORDER BY retrieved_at DESC LIMIT 500"
        return [dict(r) for r in self.db.execute(sql, params).fetchall()]

    def _share_response(self, row: sqlite3.Row, *, share_key: str | None = None,
                        created: bool | None = None) -> dict:
        expired = row["state"] in (SEALED, CREATING) and _parse_ts(row["expires_at"]) <= _now()
        d: dict[str, Any] = {
            "share_id": row["share_id"],
            "version_id": row["version_id"],
            "team_id": row["team_id"],
            "fields": json.loads(row["fields_json"]),
            "fields_hash": row["fields_hash"],
            "state": row["state"],
            "manifest_digest": row["manifest_digest"],
            "parent_digest": row["parent_digest"],
            "package_digest": row["package_digest"],
            "ttl_seconds": row["ttl_seconds"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "sealed_at": row["sealed_at"],
            "revoked_at": row["revoked_at"],
            "revoke_reason": row["revoke_reason"],
            "expired": bool(expired),
            "live": row["state"] == SEALED and not expired,
        }
        if share_key is not None:
            d["share_key"] = share_key
        if created is not None:
            d["created"] = created
        return d

    # ------------------------------------------------------------------ #
    # rejection auditing
    # ------------------------------------------------------------------ #

    _SHARE_REJECT_OUTCOMES = {
        TeamNotFound: "reject_share_audience",
        ShareForbidden: "reject_share_field",
        ShareStateConflict: "reject_share_state",
        ShareInvalid: "reject_share_invalid",
        PublicationNotFound: "reject_share_not_found",
        ShareNotFound: "reject_share_not_found",
        ShareRevoked: "reject_revoked",
        ShareExpired: "reject_expired",
    }

    def _share_reject(self, err: DPGWError, *, actor: str,
                      team_id: str | None = None, request_id: str | None = None,
                      ref: str | None = None) -> None:
        outcome = self._SHARE_REJECT_OUTCOMES.get(type(err), "share_reject")
        detail: dict[str, Any] = {"error": err.code, "message": err.message}
        vid = err.extra.get("version_id")
        if vid:
            detail["version_id"] = vid
        if err.extra.get("fields"):
            detail["fields"] = err.extra["fields"]
        self._audit(actor=actor, action="share", outcome=outcome, team_id=team_id,
                    request_id=request_id, detail=detail)
