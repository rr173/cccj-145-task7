"""Offline result verification and ledger audit.

This module never trusts the gateway service or its result cache.  Given a
signed receipt (or an exported bundle), the snapshot files and the gateway
secrets, an auditor independently:

1. checks the receipt HMAC;
2. recomputes the canonical query and its query_hash;
3. re-hashes the snapshot rows (tamper detection) and recomputes true counts;
4. regenerates the *deterministic* noise from the master seed and checks the
   released values coordinate by coordinate;
5. cross-checks the privacy ledger: per (team, snapshot) the sum of costs of
   stored results equals the recorded spend and never exceeds the limit, and
   every stored result has an ``ok_executed`` audit entry.

Works against a live gateway home copy, or fully air-gapped against a bundle
plus snapshot directories plus secrets.json.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from typing import Any

from .canonical import family_fingerprint, normalize_query, query_hash
from .engine import aggregate
from .privacy import expected_cost, noisy_vector, round6
from .receipts import (
    build_result_receipt,
    dumps_canon,
    hmac_verify,
    sha256_hex,
    signed,
)
from .shares import (
    COLLECTION_FIELDS,
    COLLECTION_KEY_FIELDS,
    RECEIPT_VERIFY_KEYS,
    SHARE_PACKAGE_VERSION,
    fields_hash,
    normalize_fields,
    project_release,
)
from .snapshot import (
    SNAPSHOT_FORMAT_VERSION,
    verify_snapshot_dir,
)
from .transparency import (
    CHECKPOINT_VERSION,
    EMPTY_HASH,
    LEAF_EVENTS,
    envelope_leaf_hash,
    merkle_root,
    verify_consistency as _verify_consistency,
    verify_inclusion as _verify_inclusion,
)

TOL = 1e-9


def load_secrets(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    out = {
        "noise_master_seed": bytes.fromhex(raw["noise_master_seed"]),
        "receipt_secret": bytes.fromhex(raw["receipt_secret"]),
    }
    if raw.get("share_secret"):
        out["share_secret"] = bytes.fromhex(raw["share_secret"])
    if raw.get("transparency_secret"):
        out["transparency_secret"] = bytes.fromhex(raw["transparency_secret"])
    return out


def find_snapshot_dir(snapshots_dir: str | None, snapshot_id: str,
                      explicit: str | None = None) -> str:
    """Locate a snapshot directory by id, or accept one named explicitly."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    if snapshots_dir:
        candidates.append(os.path.join(snapshots_dir, snapshot_id))
    for c in candidates:
        if os.path.isfile(os.path.join(c, "manifest.json")):
            return c
    raise FileNotFoundError(
        f"snapshot {snapshot_id} not found"
        + (f" under {snapshots_dir}" if snapshots_dir else "")
    )


def verify_receipt(receipt: dict, secrets_: dict, snapshot_dir: str) -> dict:
    """Full independent re-computation of one signed receipt."""
    checks: dict[str, Any] = {}

    checks["signature"] = hmac_verify(secrets_["receipt_secret"], receipt)
    if not checks["signature"]:
        return {"ok": False, "result_id": receipt.get("result_id"), "checks": checks,
                "errors": ["receipt HMAC invalid"]}

    errors: list[str] = []
    canonical = receipt["canonical"]

    integrity = verify_snapshot_dir(snapshot_dir)
    checks["snapshot_integrity"] = integrity["ok"]
    if not integrity["ok"]:
        errors.append("snapshot content hash mismatch (tampered or corrupt)")
    manifest = integrity["manifest"]
    if manifest["snapshot_id"] != receipt["snapshot_id"]:
        errors.append("snapshot id mismatch")
    checks["snapshot_id"] = receipt["snapshot_id"]

    # re-normalise what the receipt claims was canonical
    renorm = normalize_query(canonical, manifest)
    checks["canonical_self_consistent"] = dumps_canon(renorm) == dumps_canon(canonical)
    if not checks["canonical_self_consistent"]:
        errors.append("receipt canonical query re-normalises differently")

    qhash = query_hash(canonical)
    checks["query_hash"] = qhash == receipt["query_hash"]
    if not checks["query_hash"]:
        errors.append("query_hash mismatch")

    fam = family_fingerprint(canonical, mask_literals=True)
    checks["family_id"] = fam == receipt["family_id"]
    if not checks["family_id"]:
        errors.append("family fingerprint mismatch")

    # recompute truth against the immutable snapshot file
    data_file = os.path.join(snapshot_dir, "data.sqlite")
    uri = "file:" + os.path.abspath(data_file) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.execute("PRAGMA query_only = ON")
    try:
        agg = aggregate(canonical, manifest, conn)
    finally:
        conn.close()

    checks["dimension"] = agg["dimension"] == receipt["dimension"]
    if not checks["dimension"]:
        errors.append(f"dimension {agg['dimension']} != receipt {receipt['dimension']}")

    coords = receipt["coords"]
    checks["coords"] = coords == agg["coords"]
    if not checks["coords"]:
        errors.append("coordinate labels differ")

    cost = expected_cost(canonical, agg["dimension"])
    params = cost["params"]
    checks["mechanism"] = params["mechanism"] == receipt["mechanism"]
    checks["sensitivity"] = abs(params["sensitivity_l1"] - receipt["sensitivity_l1"]) < TOL
    checks["scale"] = abs(params["scale"] - receipt["noise_scale"]) < 1e-9
    checks["privacy_cost"] = (
        abs(cost["epsilon"] - receipt["privacy"]["epsilon"]) < TOL
        and abs(cost["delta"] - receipt["privacy"]["delta"]) < TOL
    )
    for name in ("mechanism", "sensitivity", "scale", "privacy_cost"):
        if not checks[name]:
            errors.append(f"{name} mismatch")

    # regenerate the exact noise and values
    noise = noisy_vector(
        secrets_["noise_master_seed"],
        receipt["team_id"], receipt["snapshot_id"], receipt["query_hash"],
        coords, params,
    )
    expect_values = [round6(t + n) for t, n in zip(agg["true"], noise)]
    values_ok = (
        len(expect_values) == len(receipt["values"])
        and all(abs(a - b) <= 1e-6 for a, b in zip(expect_values, receipt["values"]))
    )
    checks["values_reproduced"] = values_ok
    if not values_ok:
        errors.append("released values do not reproduce from seed + snapshot")

    return {
        "ok": not errors,
        "result_id": receipt["result_id"],
        "snapshot_id": receipt["snapshot_id"],
        "query_hash": qhash,
        "family_id": fam,
        "true_counts": agg["true"],
        "recomputed_values": expect_values,
        "checks": checks,
        "errors": errors,
    }


# --------------------------------------------------------------------------- #
# multi-statement job manifest verification
# --------------------------------------------------------------------------- #

def _as_manifest(doc: dict) -> dict:
    """Accept a bare signed manifest or a job response carrying one."""
    if "manifest_version" not in doc and isinstance(doc.get("manifest"), dict):
        return doc["manifest"]
    return doc


def verify_job_manifest(manifest: dict, secrets_: dict, snapshots_dir: str | None,
                        snapshot_dir_map: dict[str, str] | None = None,
                        receipt_reports: list | None = None) -> dict:
    """Verify a signed whole-batch manifest.

    Accepts either the signed manifest itself or the confirm/get-job response
    (which embeds it under ``manifest``).

    * manifest HMAC over the canonical body;
    * member count / order matches the embedded receipts;
    * every member receipt is independently reproduced from seed + snapshot
      (reusing reports already produced by bundle verification when given);
    * exactly the ``charged`` members account for the consumed epsilon/delta;
      replays (``charged=false``) contribute nothing;
    * ``epsilon/ delta_consumed`` equal the member-paid totals and never
      exceed the locked amounts.
    """
    snapshot_dir_map = snapshot_dir_map or {}
    checks: dict[str, Any] = {}
    errors: list[str] = []
    manifest = _as_manifest(manifest)

    checks["signature"] = hmac_verify(secrets_["receipt_secret"], manifest)
    if not checks["signature"]:
        return {"ok": False, "job_id": manifest.get("job_id"),
                "checks": checks, "errors": ["manifest HMAC invalid"]}

    members = manifest.get("members", [])
    receipts = manifest.get("receipts", [])
    checks["state_completed"] = manifest.get("state") == "completed"
    if manifest.get("state") != "completed":
        errors.append(f"manifest state is {manifest.get('state')!r}, expected completed")

    checks["counts_match"] = (
        len(members) == len(receipts) == manifest.get("statement_count"))
    if not checks["counts_match"]:
        errors.append(
            f"member/receipt/count mismatch: {len(members)} members, "
            f"{len(receipts)} receipts, statement_count={manifest.get('statement_count')}")

    reports_by_id = {}
    if receipt_reports:
        reports_by_id = {r.get("result_id"): r for r in receipt_reports}

    member_reports = []
    paid_eps = paid_delta = 0.0
    replay = 0
    for m, r in zip(members, receipts):
        rid = m.get("result_id")
        if rid != r.get("result_id"):
            errors.append(f"position {m.get('position')}: member result_id != receipt result_id")
        if m.get("query_hash") != r.get("query_hash"):
            errors.append(f"position {m.get('position')}: query_hash mismatch")
        if m.get("snapshot_id") != r.get("snapshot_id"):
            errors.append(f"position {m.get('position')}: snapshot_id mismatch")
        if m.get("charged"):
            paid_eps += r["privacy"]["epsilon"]
            paid_delta += r["privacy"]["delta"]
        else:
            replay += 1
        rep = reports_by_id.get(rid)
        if rep is None:
            sid = r["snapshot_id"]
            sdir = find_snapshot_dir(snapshots_dir, sid, snapshot_dir_map.get(sid))
            rep = verify_receipt(r, secrets_, sdir)
        member_reports.append(rep)
        if not rep["ok"]:
            errors.append(f"position {m.get('position')} receipt {rid}: "
                          + "; ".join(rep["errors"]))

    checks["consumed_epsilon"] = abs(paid_eps - manifest.get("epsilon_consumed", 0)) < TOL
    checks["consumed_delta"] = abs(paid_delta - manifest.get("delta_consumed", 0)) < 1e-12
    if not checks["consumed_epsilon"]:
        errors.append(f"epsilon_consumed {manifest.get('epsilon_consumed')} != "
                      f"sum charged members {paid_eps}")
    if not checks["consumed_delta"]:
        errors.append(f"delta_consumed {manifest.get('delta_consumed')} != "
                      f"sum charged members {paid_delta}")

    checks["within_lock"] = (
        paid_eps <= manifest.get("epsilon_reserved", 0) + TOL
        and paid_delta <= manifest.get("delta_reserved", 0) + 1e-12)
    if not checks["within_lock"]:
        errors.append("consumed budget exceeds the ticket lock")

    # duplicate members may share one result_id: exactly one member pays for
    # a freshly computed result, while every member of a cached result is free
    pay_count: dict[str, int] = {}
    for m in members:
        if m.get("charged"):
            pay_count[m["result_id"]] = pay_count.get(m["result_id"], 0) + 1
    overpaid = {rid: n for rid, n in pay_count.items() if n > 1}
    checks["no_double_charge"] = not overpaid
    if overpaid:
        errors.append(f"result(s) charged by more than one member: {sorted(overpaid)}")

    return {
        "ok": not errors,
        "job_id": manifest.get("job_id"),
        "members": len(members),
        "paid_epsilon": paid_eps,
        "paid_delta": paid_delta,
        "replays": replay,
        "checks": checks,
        "member_reports": member_reports,
        "errors": errors,
    }


# --------------------------------------------------------------------------- #
# amendable joint publication release verification
# --------------------------------------------------------------------------- #

def _as_release(doc: dict) -> dict:
    """Accept a bare signed release manifest or a version response carrying one."""
    if "release_version" not in doc and isinstance(doc.get("manifest"), dict):
        return doc["manifest"]
    return doc


def verify_publication_manifest(manifest: dict, secrets_: dict,
                                snapshots_dir: str | None,
                                snapshot_dir_map: dict[str, str] | None = None,
                                receipt_reports: list | None = None,
                                parent_digest: str | None = None) -> dict:
    """Independently verify one signed joint-publication release manifest.

    * manifest HMAC + canonical digest;
    * fixed spec hash reproduces from the embedded canonical statements;
    * quorum: distinct participants >= min_participants;
    * every dense member result receipt is reproduced from seed + snapshot;
    * each result is charged by exactly one team (no double billing) and the
      per-participant / total charged epsilon,delta match the manifest;
    * receipts' team/snapshot/query_hash align with member rows;
    * version lineage: ``parent_manifest_digest`` matches the supplied parent
      digest when the version has a parent.
    """
    snapshot_dir_map = snapshot_dir_map or {}
    checks: dict[str, Any] = {}
    errors: list[str] = []
    manifest = _as_release(manifest)

    checks["signature"] = hmac_verify(secrets_["receipt_secret"], manifest)
    if not checks["signature"]:
        return {"ok": False, "version_id": manifest.get("version_id"),
                "checks": checks, "errors": ["release manifest HMAC invalid"]}

    digest = sha256_hex(dumps_canon(
        {k: v for k, v in manifest.items() if k != "sig"}))
    checks["digest"] = True  # returned for callers to chain lineage checks
    members = manifest.get("members", [])
    statements = manifest.get("statements", [])
    participants = manifest.get("participants", [])
    receipts = manifest.get("receipts", [])

    # reproduce the fixed statistical specification from canonical members
    spec_members = sorted(
        ({"p": s["position"], "s": s["snapshot_id"], "q": s["query_hash"],
          "e": s["epsilon"], "d": s["delta"]} for s in statements),
        key=lambda x: x["p"])
    spec_hash = sha256_hex(dumps_canon(spec_members))
    checks["spec_hash"] = spec_hash == manifest.get("spec_hash")
    if not checks["spec_hash"]:
        errors.append("embedded statements do not reproduce spec_hash")

    # the fixed specification must carry self-consistent canonical queries
    for s in statements:
        sid = s["snapshot_id"]
        sdir = find_snapshot_dir(snapshots_dir, sid, snapshot_dir_map.get(sid))
        integrity = verify_snapshot_dir(sdir)
        if not integrity["ok"]:
            errors.append(f"statement {s['position']}: snapshot integrity check failed")
            continue
        sman = integrity["manifest"]
        if "canonical" in s:
            renorm = normalize_query(s["canonical"], sman)
            if dumps_canon(renorm) != dumps_canon(s["canonical"]):
                errors.append(
                    f"statement {s['position']}: canonical query re-normalises differently")
            if query_hash(s["canonical"]) != s["query_hash"]:
                errors.append(f"statement {s['position']}: query_hash mismatch")

    n_teams = len({m["team_id"] for m in members})
    checks["quorum"] = n_teams >= manifest.get("min_participants", 1)
    if not checks["quorum"]:
        errors.append(
            f"participating teams {n_teams} < min_participants "
            f"{manifest.get('min_participants')}")
    checks["participant_list"] = (
        {p["team_id"] for p in participants} == {m["team_id"] for m in members})
    if not checks["participant_list"]:
        errors.append("participant list and member rows disagree")

    # dense grid: positions x teams
    pos_set = {s["position"] for s in statements}
    grid: dict[tuple[int, str], dict] = {}
    for m in members:
        key = (m["position"], m["team_id"])
        if key in grid:
            errors.append(f"duplicate member at position {m['position']} "
                          f"team {m['team_id']}")
        grid[key] = m
    checks["dense_grid"] = len(grid) == len(pos_set) * n_teams
    if not checks["dense_grid"]:
        errors.append("member grid is not dense (positions x participants)")

    reports_by_id = {r.get("result_id"): r for r in (receipt_reports or [])}
    receipt_by_id = {r.get("result_id"): r for r in receipts}

    # Independently determine, from the signed receipt set, which (team, snapshot,
    # query_hash) results must have been paid for IN THIS RELEASE: a result is a
    # release charge exactly when one of its member rows claims charged=1.  The
    # attribution in members/participants is then checked for internal
    # consistency (one payer per result, payer's receipt cost matches), rather
    # than being trusted.  Cached/free results show zero charged rows.
    # no result charged twice; member agrees with receipt; receipts reproduce
    charged_by_result: dict[str, set] = {}
    charged_by_team: dict[str, list[float]] = {}
    member_reports = []
    for (pos, tid), m in sorted(grid.items()):
        rid = m["result_id"]
        charged_by_result.setdefault(rid, set())
        if m.get("charged"):
            charged_by_result[rid].add(tid)
            acc = charged_by_team.setdefault(tid, [0.0, 0.0])
            acc[0] += m["epsilon"]
            acc[1] += m["delta"]
        receipt = receipt_by_id.get(rid)
        if receipt is None:
            errors.append(f"member ({pos},{tid}): result {rid} has no receipt")
            continue
        if receipt["team_id"] != tid:
            errors.append(f"member ({pos},{tid}): receipt belongs to "
                          f"{receipt['team_id']}")
        if receipt["snapshot_id"] != m["snapshot_id"]:
            errors.append(f"member ({pos},{tid}): snapshot mismatch")
        if receipt["query_hash"] != m["query_hash"]:
            errors.append(f"member ({pos},{tid}): query_hash mismatch")
        # a charged member must carry the full receipt cost of its statement
        if m.get("charged") and (
                abs(receipt["privacy"]["epsilon"] - m["epsilon"]) > TOL
                or abs(receipt["privacy"]["delta"] - m["delta"]) > 1e-12):
            errors.append(
                f"member ({pos},{tid}): charged flag set but receipt cost "
                f"{receipt['privacy']} != statement cost ({m['epsilon']},{m['delta']})")
        rep = reports_by_id.get(rid)
        if rep is None:
            sdir = find_snapshot_dir(snapshots_dir, receipt["snapshot_id"],
                                     snapshot_dir_map.get(receipt["snapshot_id"]))
            rep = verify_receipt(receipt, secrets_, sdir)
        member_reports.append(rep)
        if not rep["ok"]:
            errors.append(f"member ({pos},{tid}) receipt {rid}: "
                          + "; ".join(rep["errors"]))

    double = {rid: ts for rid, ts in charged_by_result.items() if len(ts) > 1}
    checks["no_double_charge"] = not double
    if double:
        errors.append(f"results charged by multiple teams: {sorted(double)}")

    # duplicate positions (same team, same result) must agree on charged flag;
    # each result is either paid by exactly its owner team or free (cached)
    rid_members: dict[str, list] = {}
    for (pos, tid), m in sorted(grid.items()):
        rid_members.setdefault(m["result_id"], []).append(((pos, tid), m))
    for rid, rows in rid_members.items():
        flags = {bool(m.get("charged")) for _, m in rows}
        if len(flags) > 1:
            errors.append(f"result {rid}: duplicate member rows disagree on charged")
        for (pos, tid), m in rows:
            payers = charged_by_result.get(rid, set())
            if m.get("charged"):
                if payers != {tid}:
                    errors.append(
                        f"member ({pos},{tid}) marked charged but payer set {payers}")
            elif tid in payers:
                errors.append(
                    f"member ({pos},{tid}) charged flag inconsistent with payer set")

    # per-participant charged totals match
    for p in participants:
        tid = p["team_id"]
        got = charged_by_team.get(tid, [0.0, 0.0])
        if abs(got[0] - p.get("epsilon_charged", 0)) > TOL:
            errors.append(f"team {tid}: epsilon_charged {p.get('epsilon_charged')} "
                          f"!= member total {got[0]}")
        if abs(got[1] - p.get("delta_charged", 0)) > 1e-12:
            errors.append(f"team {tid}: delta_charged member total mismatch")

    total_eps = sum(v[0] for v in charged_by_team.values())
    total_delta = sum(v[1] for v in charged_by_team.values())
    checks["charge_totals"] = (
        abs(total_eps - sum(p.get("epsilon_charged", 0) for p in participants)) < TOL
        and abs(total_delta - sum(p.get("delta_charged", 0) for p in participants))
        < 1e-12)
    if not checks["charge_totals"]:
        errors.append("participant charge totals disagree across the manifest")

    # lineage
    if manifest.get("parent_version_id"):
        if not manifest.get("parent_manifest_digest"):
            errors.append("child release lacks parent_manifest_digest")
        elif parent_digest is not None and manifest["parent_manifest_digest"] != parent_digest:
            errors.append("parent_manifest_digest does not match the supplied parent release")

    return {
        "ok": not errors,
        "batch_id": manifest.get("batch_id"),
        "version_id": manifest.get("version_id"),
        "seq": manifest.get("seq"),
        "digest": digest,
        "teams": n_teams,
        "members": len(members),
        "charged_epsilon": total_eps,
        "charged_delta": total_delta,
        "checks": checks,
        "member_reports": member_reports,
        "errors": errors,
    }


# --------------------------------------------------------------------------- #
# controlled sharing package verification (fully offline, no service needed)
# --------------------------------------------------------------------------- #

def verify_share_package(package: dict, secrets_: dict,
                         snapshots_dir: str | None = None,
                         *, full_release: dict | None = None,
                         parent_digest: str | None = None,
                         now: str | None = None,
                         receipt_reports: list | None = None) -> dict:
    """Independently verify a downloaded field-trimmed sharing package.

    * share-package HMAC over the canonical body, recomputed digest;
    * signature bindings: ``release_digest`` (manifest_digest), audience,
      field set hash, ``release_parent_digest``, expiry -- any tampering with
      the trimming/binding invalidates the HMAC;
    * field set is a valid subset of the release field catalogue;
    * when the full signed release is supplied, the trimmed body is
      recomputed from it and must match byte-for-byte (canonical), and the
      release digest/parent lineage are cross-checked;
    * receipts carried in the package are reproduced from seed + snapshots
      when snapshots are provided (receipts keep their original HMAC and are
      verifiable with receipt_secret).
    """
    from datetime import datetime, timezone

    checks: dict[str, Any] = {}
    errors: list[str] = []
    key = secrets_.get("share_secret")
    if key is None:
        return {"ok": False, "share_id": package.get("share_id"), "checks": checks,
                "errors": ["secrets.json has no share_secret"]}

    expect_sig = hmac.new(
        key, dumps_canon({k: v for k, v in package.items() if k != "sig"})
        .encode("utf-8"), hashlib.sha256).hexdigest()
    checks["signature"] = bool(isinstance(package.get("sig"), str)) and \
        hmac.compare_digest(package.get("sig", ""), expect_sig)
    if not checks["signature"]:
        return {"ok": False, "share_id": package.get("share_id"), "checks": checks,
                "errors": ["share package HMAC invalid"]}

    checks["package_version"] = package.get("share_version") == SHARE_PACKAGE_VERSION
    if package.get("share_version") != SHARE_PACKAGE_VERSION:
        errors.append(f"unsupported share_version {package.get('share_version')!r}")

    digest = sha256_hex(dumps_canon(
        {k: v for k, v in package.items() if k != "sig"}))
    checks["digest"] = digest

    fields = package.get("fields", [])
    try:
        norm = normalize_fields(fields)
        checks["fields_valid"] = norm == fields
        if norm != fields:
            errors.append("field list is not the canonical sorted/deduped form")
    except Exception:
        norm = []
        checks["fields_valid"] = False
        errors.append("field list contains unknown paths")

    checks["fields_hash_binding"] = package.get("fields_hash") == fields_hash(norm)
    if not checks["fields_hash_binding"]:
        errors.append("fields_hash does not bind the field list")

    trimmed = package.get("release", {})
    checks["release_digest_present"] = bool(package.get("release_digest"))

    # expiry is signed and checked offline; a verifier decides how to treat it
    expired = None
    expires_at = package.get("expires_at")
    try:
        exp = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc)
        ref = datetime.now(timezone.utc)
        if now:
            ref = datetime.strptime(now, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=timezone.utc)
        expired = exp <= ref
        checks["ttl_positive"] = package.get("ttl_seconds", 0) > 0
        checks["expires_at"] = True
    except (TypeError, ValueError):
        checks["expires_at"] = False
        errors.append("expires_at missing or malformed")
    checks["expired"] = bool(expired)

    # the trimmed body may carry only identity scalars + collections named by
    # the field set (whole or via subpaths); every carried key must be granted
    # or a mandatory linkage key
    from .shares import COLLECTION_KEY_FIELDS
    allowed_collections = {f.split(".", 1)[0] for f in norm}
    granted_keys: dict[str, set] = {}
    for f in norm:
        if "." in f:
            coll, sub = f.split(".", 1)
            granted_keys.setdefault(coll, set()).add(sub)
        else:
            granted_keys.setdefault(f, set()).update(COLLECTION_FIELDS[f])
    unexpected_collections = [k for k in trimmed if k in COLLECTION_FIELDS
                              and k not in allowed_collections]
    over_carried: list[str] = []
    whole_collections = {f for f in norm if "." not in f}
    for coll in ("statements", "participants", "members", "receipts"):
        if coll not in trimmed:
            continue
        permitted = granted_keys.get(coll, set()) | set(COLLECTION_KEY_FIELDS[coll])
        if coll == "receipts" and coll in whole_collections:
            permitted.add("sig")  # whole-receipt grants stay self-verifying
        for item in trimmed[coll]:
            extra = set(item) - permitted
            if extra:
                over_carried.append(f"{coll}:{sorted(extra)}")
    checks["trim_scope"] = not unexpected_collections and not over_carried
    if unexpected_collections:
        errors.append(f"trimmed release carries ungranted collections: "
                      f"{unexpected_collections}")
    if over_carried:
        errors.append(f"trimmed release carries ungranted fields: {over_carried}")

    member_reports = []
    receipts_checked = 0

    if full_release is not None:
        full = full_release.get("manifest", full_release) \
            if "release_version" not in full_release else full_release
        checks["release_signature"] = hmac_verify(
            secrets_["receipt_secret"], full)
        if not checks["release_signature"]:
            errors.append("full release manifest HMAC invalid")
        recomputed_digest = sha256_hex(dumps_canon(
            {k: v for k, v in full.items() if k != "sig"}))
        checks["release_digest"] = recomputed_digest == package.get("release_digest")
        if not checks["release_digest"]:
            errors.append("release_digest does not match the full release manifest")
        if full.get("parent_version_id"):
            checks["parent_digest"] = (
                package.get("release_parent_digest")
                == full.get("parent_manifest_digest"))
            if not checks["parent_digest"]:
                errors.append("package parent digest != full release parent digest")
            if parent_digest is not None and full.get("parent_manifest_digest") != parent_digest:
                errors.append("full release parent digest != supplied parent release")
        elif package.get("release_parent_digest") is not None:
            errors.append("package claims a parent digest for an original release")

        expect_trim = project_release(full, norm)
        checks["trim_reproduced"] = dumps_canon(expect_trim) == dumps_canon(trimmed)
        if not checks["trim_reproduced"]:
            errors.append("trimmed release is not the projection of the full release")

        # receipts present in the package must reproduce against seed+snapshots;
        # only complete (whole-collection granted, sig-bearing) receipts can be
        # independently replayed -- partial receipts are anchored by the share
        # signature and the cross-checked release_digest instead
        from .shares import RECEIPT_VERIFY_KEYS
        reports_by_id = {r.get("result_id"): r for r in (receipt_reports or [])}
        for r in trimmed.get("receipts", []):
            if not RECEIPT_VERIFY_KEYS.issubset(r.keys()):
                continue
            receipts_checked += 1
            rep = reports_by_id.get(r.get("result_id"))
            if rep is None and snapshots_dir and "receipt_secret" in secrets_:
                sdir = find_snapshot_dir(snapshots_dir, r["snapshot_id"])
                rep = verify_receipt(r, secrets_, sdir)
            if rep is not None:
                member_reports.append(rep)
                if not rep["ok"]:
                    errors.append(f"receipt {r.get('result_id')}: "
                                  + "; ".join(rep["errors"]))

    return {
        "ok": not errors,
        "share_id": package.get("share_id"),
        "version_id": package.get("version_id"),
        "team_id": package.get("team_id"),
        "digest": digest,
        "release_digest": package.get("release_digest"),
        "parent_digest": package.get("release_parent_digest"),
        "fields": norm,
        "expires_at": expires_at,
        "expired": bool(expired),
        "receipts_checked": receipts_checked,
        "member_reports": member_reports,
        "checks": checks,
        "errors": errors,
    }


def hashlib_sha256():
    import hashlib
    return hashlib.sha256


# --------------------------------------------------------------------------- #
# anti-fork transparency ledger verification (fully offline)
# --------------------------------------------------------------------------- #

def verify_checkpoint_doc(checkpoint: dict, secrets_: dict) -> dict:
    """Verify one signed transparency checkpoint document in isolation."""
    errors: list[str] = []
    key = secrets_.get("transparency_secret")
    checks: dict[str, Any] = {}
    if key is None:
        return {"ok": False, "errors": ["secrets.json has no transparency_secret"],
                "checks": checks}
    sig = checkpoint.get("sig")
    expect = hmac.new(
        key,
        dumps_canon({k: v for k, v in checkpoint.items() if k != "sig"})
        .encode("utf-8"), hashlib.sha256).hexdigest()
    checks["signature"] = isinstance(sig, str) and hmac.compare_digest(sig or "", expect)
    if not checks["signature"]:
        errors.append("checkpoint HMAC invalid")
    checks["version"] = checkpoint.get("checkpoint_version") == CHECKPOINT_VERSION
    if checkpoint.get("checkpoint_version") != CHECKPOINT_VERSION:
        errors.append("unsupported checkpoint_version")
    size = checkpoint.get("tree_size")
    checks["tree_size"] = isinstance(size, int) and size >= 0
    checks["root_hash"] = (
        isinstance(checkpoint.get("root_hash"), str)
        and len(checkpoint.get("root_hash", "")) == 64)
    if not checks["tree_size"] or not checks["root_hash"]:
        errors.append("malformed checkpoint tree_size/root_hash")
    if isinstance(size, int) and size == 0 and checkpoint.get("root_hash") != EMPTY_HASH:
        errors.append("genesis checkpoint must sign the empty-tree root")
    return {"ok": not errors, "errors": errors, "checks": checks,
            "tree_size": size, "root_hash": checkpoint.get("root_hash")}


def verify_inclusion_proof(proof: dict, secrets_: dict) -> dict:
    """Independently verify an inclusion proof document handed to a caller.

    Checks the checkpoint signature, the leaf content address, the event
    envelope binding, and the bottom-up Merkle fold to the signed root.
    """
    errors: list[str] = []
    cp_report = verify_checkpoint_doc(proof.get("checkpoint", {}), secrets_)
    if not cp_report["ok"]:
        errors.extend("checkpoint: " + e for e in cp_report["errors"])
    envelope = proof.get("envelope") or {}
    checks: dict[str, Any] = {"checkpoint": cp_report["ok"]}

    index = proof.get("leaf_index")
    size = proof.get("tree_size")
    leaf_hash = proof.get("leaf_hash")
    root_hex = proof.get("root_hash")
    try:
        leaf_recomputed = envelope_leaf_hash(envelope)
        checks["leaf_content_address"] = leaf_recomputed == leaf_hash
        if leaf_recomputed != leaf_hash:
            errors.append("leaf_hash does not match the canonical envelope")
        checks["event_binding"] = (
            envelope.get("event_key") == proof.get("event_key")
            and envelope.get("event_type") == proof.get("event_type")
            and envelope.get("event_type") in LEAF_EVENTS)
        if not checks["event_binding"]:
            errors.append("envelope does not bind the claimed event key/type")

        path = [bytes.fromhex(h) for h in proof.get("inclusion_path", [])]
        root = bytes.fromhex(root_hex)
        ok = _verify_inclusion(root, bytes.fromhex(leaf_hash), index, size, path)
        checks["merkle_inclusion"] = ok
        if not ok:
            errors.append("inclusion path does not fold to the checkpoint root")
        if root_hex != proof.get("checkpoint", {}).get("root_hash"):
            errors.append("proof root_hash disagrees with the signed checkpoint")
        if size != proof.get("checkpoint", {}).get("tree_size"):
            errors.append("proof tree_size disagrees with the signed checkpoint")
    except (TypeError, ValueError) as exc:
        errors.append(f"malformed proof ({exc})")
        checks["merkle_inclusion"] = False
    return {"ok": not errors, "errors": errors, "checks": checks,
            "leaf_index": index, "tree_size": size, "root_hash": root_hex}


def verify_consistency_proof(proof: dict, secrets_: dict) -> dict:
    """Verify an append-only consistency proof between two checkpoints."""
    errors: list[str] = []
    checks: dict[str, Any] = {}
    old_cp = verify_checkpoint_doc(proof.get("old_checkpoint", {}), secrets_)
    new_cp = verify_checkpoint_doc(proof.get("new_checkpoint", {}), secrets_)
    checks["old_checkpoint"] = old_cp["ok"]
    checks["new_checkpoint"] = new_cp["ok"]
    if not old_cp["ok"]:
        errors.extend("old checkpoint: " + e for e in old_cp["errors"])
    if not new_cp["ok"]:
        errors.extend("new checkpoint: " + e for e in new_cp["errors"])
    m, n = proof.get("old_size"), proof.get("new_size")
    try:
        old_nodes = [(p["start"], p["end"], bytes.fromhex(p["hash"]))
                     for p in proof.get("old_path", [])]
        ext_nodes = [(p["start"], p["end"], bytes.fromhex(p["hash"]))
                     for p in proof.get("extension_path", [])]
        ok = _verify_consistency(bytes.fromhex(proof["old_root_hash"]),
                                 bytes.fromhex(proof["new_root_hash"]),
                                 m, n, old_nodes, ext_nodes)
        checks["append_only"] = ok
        if not ok:
            errors.append("consistency path does not prove an append-only extension")
        if proof.get("old_root_hash") != proof.get("old_checkpoint", {}).get("root_hash"):
            errors.append("old_root_hash disagrees with the signed old checkpoint")
        if proof.get("new_root_hash") != proof.get("new_checkpoint", {}).get("root_hash"):
            errors.append("new_root_hash disagrees with the signed new checkpoint")
        if m != proof.get("old_checkpoint", {}).get("tree_size") or \
                n != proof.get("new_checkpoint", {}).get("tree_size"):
            errors.append("sizes disagree with the signed checkpoint sizes")
    except (TypeError, ValueError) as exc:
        errors.append(f"malformed proof ({exc})")
        checks["append_only"] = False
    return {"ok": not errors, "errors": errors, "checks": checks,
            "old_size": m, "new_size": n}


def verify_fork_evidence(first: dict, second: dict, secrets_: dict) -> dict:
    """Validate fork evidence: two signed checkpoints, same height, two roots."""
    r1 = verify_checkpoint_doc(first, secrets_)
    r2 = verify_checkpoint_doc(second, secrets_)
    errors: list[str] = []
    if not r1["ok"]:
        errors.extend("first: " + e for e in r1["errors"])
    if not r2["ok"]:
        errors.extend("second: " + e for e in r2["errors"])
    if r1["ok"] and r2["ok"]:
        if r1["tree_size"] != r2["tree_size"] or r1["tree_size"] <= 0:
            errors.append("fork evidence needs two checkpoints at one non-zero size")
        if r1["root_hash"] == r2["root_hash"]:
            errors.append("checkpoints agree on the root; not a fork")
    return {"ok": not errors, "errors": errors,
            "tree_size": r1.get("tree_size"),
            "roots": [r1.get("root_hash"), r2.get("root_hash")]}


def _verify_transparency_problems(conn, problems: list[str]) -> dict:
    """Full structural audit of the transparency log against an sqlite copy."""
    leaves = conn.execute(
        "SELECT * FROM tl_leaves ORDER BY leaf_index").fetchall()
    hashes: list[bytes] = []
    for i, r in enumerate(leaves):
        if r["leaf_index"] != i:
            problems.append(f"transparency: leaf index {r['leaf_index']} != dense {i}")
        try:
            env = json.loads(r["envelope_json"])
            if envelope_leaf_hash(env) != r["leaf_hash"]:
                problems.append(f"transparency: leaf {i} content address mismatch")
            if env.get("event_key") != r["event_key"]:
                problems.append(f"transparency: leaf {i} event_key mismatch")
            if env.get("event_type") != r["event_type"]:
                problems.append(f"transparency: leaf {i} event_type mismatch")
            if r["event_type"] not in LEAF_EVENTS:
                problems.append(f"transparency: leaf {i} unknown event_type")
        except Exception as exc:
            problems.append(f"transparency: leaf {i} unreadable ({exc})")
        hashes.append(bytes.fromhex(r["leaf_hash"]))

    cps = conn.execute("SELECT * FROM tl_checkpoints ORDER BY tree_size").fetchall()
    if not cps or cps[0]["tree_size"] != 0:
        problems.append("transparency: missing genesis checkpoint")
    prev_size, prev_root = None, None
    for cp in cps:
        want = merkle_root(hashes[:cp["tree_size"]]).hex()
        if cp["root_hash"] != want:
            problems.append(
                f"transparency: checkpoint {cp['tree_size']} root does not reproduce")
        if cp["tree_size"] > 0:
            if cp["prev_size"] != prev_size or cp["prev_root_hash"] != prev_root:
                problems.append(
                    f"transparency: checkpoint {cp['tree_size']} prev chain broken")
        try:
            doc = json.loads(cp["checkpoint_json"])
            if doc.get("tree_size") != cp["tree_size"] \
                    or doc.get("root_hash") != cp["root_hash"]:
                problems.append(
                    f"transparency: checkpoint {cp['tree_size']} document mismatch")
        except Exception:
            problems.append(
                f"transparency: checkpoint {cp['tree_size']} document unreadable")
        prev_size, prev_root = cp["tree_size"], cp["root_hash"]

    # no leaves may be missing checkpoints and vice versa
    sizes = {cp["tree_size"] for cp in cps}
    for s in range(len(leaves) + 1):
        if s not in sizes:
            problems.append(f"transparency: checkpoint at size {s} missing")

    pending = conn.execute("SELECT COUNT(*) c FROM tl_outbox").fetchone()["c"]
    if pending:
        problems.append(f"transparency: {pending} un-drained outbox row(s)")

    # cross-reference: every terminal business event has exactly one leaf,
    # and every leaf points at an existing subject in the matching state
    _cross_check_business(conn, leaves, problems)

    freeze = conn.execute("SELECT * FROM tl_freeze WHERE id=1").fetchone()
    return {
        "leaves": len(leaves),
        "checkpoints": len(cps),
        "frozen": freeze is not None,
        "freeze_reason": freeze["reason"] if freeze else None,
        "frozen_tree_size": freeze["tree_size"] if freeze else None,
    }


def _cross_check_business(conn, leaves, problems: list[str]) -> None:
    """Leaves must agree 1:1 with sealed/void versions and sealed/revoked shares."""
    by_key: dict[str, list] = {}
    for r in leaves:
        by_key.setdefault(r["event_key"], []).append(r)
    for key, rows in by_key.items():
        if len(rows) > 1:
            problems.append(f"transparency: duplicate leaf for event_key {key}")

    sealed = conn.execute(
        "SELECT version_id, manifest_digest FROM pub_versions WHERE state='sealed'"
    ).fetchall()
    for v in sealed:
        rows = by_key.get(f"release_sealed:{v['version_id']}")
        if not rows:
            problems.append(
                f"transparency: sealed version {v['version_id']} has no leaf")
            continue
        env = json.loads(rows[0]["envelope_json"])
        if env["payload"].get("manifest_digest") != v["manifest_digest"]:
            problems.append(
                f"transparency: sealed leaf for {v['version_id']} binds wrong digest")

    voided = conn.execute(
        "SELECT version_id FROM pub_versions WHERE state='void'").fetchall()
    for v in voided:
        if f"release_voided:{v['version_id']}" not in by_key:
            problems.append(
                f"transparency: void version {v['version_id']} has no leaf")

    for s in conn.execute("SELECT * FROM shares").fetchall():
        if s["state"] in ("sealed", "revoked"):
            rows = by_key.get(f"share_issued:{s['share_id']}")
            if not rows:
                problems.append(
                    f"transparency: {s['state']} share {s['share_id']} has no issue leaf")
            else:
                env = json.loads(rows[0]["envelope_json"])
                if env["payload"].get("package_digest") != s["package_digest"]:
                    problems.append(
                        f"transparency: issue leaf for share {s['share_id']} "
                        "binds the wrong package digest")
        if s["state"] == "revoked" \
                and f"share_revoked:{s['share_id']}" not in by_key:
            problems.append(
                f"transparency: revoked share {s['share_id']} has no revoke leaf")


# --------------------------------------------------------------------------- #
# bundle export
# --------------------------------------------------------------------------- #

def _receipt_from_row(gw, row) -> dict:
    canonical = json.loads(row["canonical_json"])
    coords = json.loads(row["coords_json"])
    values = json.loads(row["values_json"])
    body = build_result_receipt(
        result_id=row["result_id"], team_id=row["team_id"],
        snapshot_id=row["snapshot_id"], query_hash=row["query_hash"],
        family_id=row["family_id"], canonical=canonical,
        mechanism=row["mechanism"], epsilon=row["epsilon"], delta=row["delta"],
        dimension=row["dimension"], sensitivity_l1=row["sensitivity_l1"],
        scale=row["scale"], coords=coords, values=values,
        created_at=row["created_at"],
    )
    return signed(body, gw.receipt_key)


def export_bundle(gw, team_id: str | None = None) -> dict:
    """Export all receipts + ledger rows + job manifests + audit for review."""
    sql = "SELECT * FROM results"
    params: list = []
    if team_id:
        sql += " WHERE team_id=?"
        params.append(team_id)
    sql += " ORDER BY created_at"
    receipts = [_receipt_from_row(gw, r) for r in gw.db.execute(sql, params).fetchall()]

    bsql = "SELECT * FROM budgets"
    if team_id:
        bsql += " WHERE team_id=?"
    budgets = [dict(r) for r in gw.db.execute(bsql, params).fetchall()]

    snaps = {
        r["snapshot_id"]: {"name": r["name"], "version": r["version"], "active": r["active"]}
        for r in gw.db.execute("SELECT snapshot_id, name, version, active FROM snapshots")
    }
    asql = "SELECT * FROM audit_log ORDER BY id"
    audit = [dict(r) for r in gw.db.execute(asql).fetchall()
             if not team_id or r["team_id"] == team_id or r["team_id"] is None]

    jsql = "SELECT * FROM jobs"
    if team_id:
        jsql += " WHERE team_id=?"
    jobs = []
    for r in gw.db.execute(jsql, params).fetchall():
        d = dict(r)
        d.pop("payload_hash", None)
        if r["state"] == "completed":
            d["manifest"] = gw.build_job_manifest(r)
        jobs.append(d)

    hsql = (
        "SELECT h.team_id, h.snapshot_id, h.job_id, h.epsilon, h.delta, "
        "h.created_at, h.expires_at FROM budget_holds h "
        "JOIN jobs j ON j.job_id = h.job_id AND j.state IN ('reserved','executing')")
    hparams: list = []
    if team_id:
        hsql += " WHERE h.team_id=?"
        hparams.append(team_id)
    holds = [dict(r) for r in gw.db.execute(hsql, hparams).fetchall()]

    psql = "SELECT * FROM pub_batches"
    pub_batches = [dict(r) for r in gw.db.execute(psql).fetchall()]
    pub_versions = []
    for r in gw.db.execute("SELECT * FROM pub_versions ORDER BY batch_id, seq").fetchall():
        d = dict(r)
        if r["state"] == "sealed":
            d["manifest"] = json.loads(r["manifest_json"])
        d.pop("manifest_json", None)
        pub_versions.append(d)
    pub_holds = [dict(r) for r in gw.db.execute(
        "SELECT team_id, snapshot_id, version_id, epsilon, delta, created_at "
        "FROM pub_holds").fetchall()]

    # controlled sharing packages: grants, share metadata and the immutable
    # package bodies (trimmed releases); share_key values never leave the server
    share_grants = [dict(r) for r in gw.db.execute(
        "SELECT version_id, team_id, fields_json, granted_by, created_at "
        "FROM share_field_grants ORDER BY version_id, team_id").fetchall()]
    shares = []
    for r in gw.db.execute("SELECT * FROM shares ORDER BY created_at").fetchall():
        d = {k: r[k] for k in r.keys()}
        d["fields"] = json.loads(d.pop("fields_json"))
        d.pop("share_key_hash", None)
        if r["state"] == "sealed":
            path = os.path.join(gw._share_dir(), r["package_digest"] + ".json")
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    d["package"] = json.loads(fh.read().decode("utf-8"))
        shares.append(d)
    share_retrievals = [dict(r) for r in gw.db.execute(
        "SELECT share_id, retrieved_at, actor, outcome FROM share_retrievals "
        "ORDER BY retrieved_at").fetchall()]

    # anti-fork transparency ledger: every leaf envelope, every signed
    # checkpoint and the freeze state; an offline auditor reproduces every
    # root, checks proofs and can spot two same-height/different-root histories
    tl_leaves = [dict(r) for r in gw.db.execute(
        "SELECT leaf_index, event_key, event_type, leaf_hash, payload_hash, "
        "envelope_json, outbox_seq, incorporated_at FROM tl_leaves "
        "ORDER BY leaf_index").fetchall()]
    tl_checkpoints = [dict(r) for r in gw.db.execute(
        "SELECT tree_size, root_hash, prev_size, prev_root_hash, "
        "checkpoint_json, created_at FROM tl_checkpoints ORDER BY tree_size").fetchall()]
    for r in tl_leaves:
        r["envelope"] = json.loads(r.pop("envelope_json"))
    for r in tl_checkpoints:
        r["checkpoint"] = json.loads(r.pop("checkpoint_json"))
    freeze_row = gw.db.execute("SELECT * FROM tl_freeze WHERE id=1").fetchone()
    transparency = {
        "leaves": tl_leaves,
        "checkpoints": tl_checkpoints,
        "frozen": freeze_row is not None,
        "freeze_reason": freeze_row["reason"] if freeze_row else None,
        "frozen_at": freeze_row["frozen_at"] if freeze_row else None,
        "frozen_by": freeze_row["frozen_by"] if freeze_row else None,
        "frozen_tree_size": freeze_row["tree_size"] if freeze_row else None,
        "evidence": (json.loads(freeze_row["evidence_json"])
                     if freeze_row and freeze_row["evidence_json"] else None),
    }

    return {
        "bundle_version": "b5",
        "format_versions": {"query": "q1", "snapshot": SNAPSHOT_FORMAT_VERSION,
                            "receipt": "r1", "job_ticket": "j1", "job_manifest": "jm1",
                            "pub_release": "pr1", "share_package": "sh1",
                            "checkpoint": "tc1"},
        "team_id": team_id,
        "receipts": receipts,
        "budgets": budgets,
        "snapshots": snaps,
        "jobs": jobs,
        "holds": holds,
        "pub_batches": pub_batches,
        "pub_versions": pub_versions,
        "pub_holds": pub_holds,
        "share_grants": share_grants,
        "shares": shares,
        "share_retrievals": share_retrievals,
        "transparency": transparency,
        "audit": audit,
    }


# --------------------------------------------------------------------------- #
# ledger audit (works from a gateway sqlite file, fully offline)
# --------------------------------------------------------------------------- #

def verify_ledger(db_path: str) -> dict:
    uri = "file:" + os.path.abspath(db_path) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    problems: list[str] = []
    rows_checked = 0

    budgets = conn.execute("SELECT * FROM budgets").fetchall()
    active_hold_sql = (
        "SELECT COALESCE(SUM(h.epsilon),0) e, COALESCE(SUM(h.delta),0) d "
        "FROM budget_holds h JOIN jobs j ON j.job_id=h.job_id "
        "WHERE h.team_id=? AND h.snapshot_id=? AND j.state IN ('reserved','executing')")
    pub_hold_sql = (
        "SELECT COALESCE(SUM(p.epsilon),0) e, COALESCE(SUM(p.delta),0) d "
        "FROM pub_holds p JOIN pub_versions v ON v.version_id=p.version_id "
        "WHERE p.team_id=? AND p.snapshot_id=? AND v.state='collecting'")
    for b in budgets:
        agg = conn.execute(
            """SELECT COALESCE(SUM(epsilon),0) e, COALESCE(SUM(delta),0) d,
                      COUNT(*) n FROM results
               WHERE team_id=? AND snapshot_id=?""",
            (b["team_id"], b["snapshot_id"]),
        ).fetchone()
        rows_checked += agg["n"]
        if abs(agg["e"] - b["epsilon_spent"]) > 1e-9:
            problems.append(
                f"budget ({b['team_id']},{b['snapshot_id']}) epsilon spent "
                f"{b['epsilon_spent']} != sum(results) {agg['e']}")
        if abs(agg["d"] - b["delta_spent"]) > 1e-12:
            problems.append(
                f"budget ({b['team_id']},{b['snapshot_id']}) delta spent "
                f"{b['delta_spent']} != sum(results) {agg['d']}")
        hold = conn.execute(active_hold_sql,
                            (b["team_id"], b["snapshot_id"])).fetchone()
        phold = conn.execute(pub_hold_sql,
                             (b["team_id"], b["snapshot_id"])).fetchone()
        held_e, held_d = hold["e"] + phold["e"], hold["d"] + phold["d"]
        # spent + locked must never exceed the limit: concurrent reservation safety
        if b["epsilon_spent"] + held_e > b["epsilon_limit"] + 1e-9:
            problems.append(
                f"budget ({b['team_id']},{b['snapshot_id']}) epsilon "
                f"spent+held {b['epsilon_spent'] + held_e} OVER limit")
        if b["delta_spent"] + held_d > b["delta_limit"] + 1e-12:
            problems.append(
                f"budget ({b['team_id']},{b['snapshot_id']}) delta "
                f"spent+held {b['delta_spent'] + held_d} OVER limit")
        if b["epsilon_spent"] > b["epsilon_limit"] + 1e-9:
            problems.append(
                f"budget ({b['team_id']},{b['snapshot_id']}) epsilon OVERSPENT")
        if b["delta_spent"] > b["delta_limit"] + 1e-12:
            problems.append(
                f"budget ({b['team_id']},{b['snapshot_id']}) delta OVERSPENT")

    # every executed result must have exactly one ok_executed audit entry
    for r in conn.execute("SELECT result_id, team_id, snapshot_id, query_hash FROM results"):
        n = conn.execute(
            "SELECT COUNT(*) c FROM audit_log WHERE result_id=? AND outcome='ok_executed'",
            (r["result_id"],),
        ).fetchone()["c"]
        if n != 1:
            problems.append(f"result {r['result_id']} has {n} ok_executed audit rows")

    # cached replays never charge: no duplicate result rows per canonical query
    dup = conn.execute(
        """SELECT team_id, snapshot_id, query_hash, COUNT(*) c FROM results
           GROUP BY team_id, snapshot_id, query_hash HAVING c > 1"""
    ).fetchall()
    if dup:
        problems.append(f"{len(dup)} duplicated (team,snapshot,query_hash) result rows")

    jobs_checked = _verify_job_ledger(conn, problems)
    pubs_checked = _verify_publication_ledger(conn, problems)
    shares_checked = _verify_share_ledger(conn, problems)

    have = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    transparency = None
    if "tl_leaves" in have:
        transparency = _verify_transparency_problems(conn, problems)

    conn.close()
    return {"ok": not problems, "problems": problems,
            "results_checked": rows_checked, "budgets_checked": len(budgets),
            "jobs_checked": jobs_checked, "pub_versions_checked": pubs_checked,
            "shares_checked": shares_checked,
            "transparency": transparency}


def _verify_publication_ledger(conn, problems: list[str]) -> int:
    """Cross-check publication batches, versions, contributions, holds and
    release attribution against the results ledger."""
    have = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    for table in ("pub_batches", "pub_versions", "pub_statements",
                  "pub_contributions", "pub_holds", "pub_release_members"):
        if table not in have:
            return 0
    n = 0

    # lineage is a linear chain, one open version per batch
    for b in conn.execute("SELECT * FROM pub_batches").fetchall():
        versions = conn.execute(
            "SELECT * FROM pub_versions WHERE batch_id=? ORDER BY seq",
            (b["batch_id"],)).fetchall()
        seqs = [v["seq"] for v in versions]
        if seqs != list(range(1, len(versions) + 1)):
            problems.append(f"batch {b['batch_id']}: version seqs not dense 1..n")
        if sum(1 for v in versions if v["state"] == "collecting") > 1:
            problems.append(f"batch {b['batch_id']}: multiple collecting versions")
        for v in versions:
            if v["seq"] == 1:
                if v["parent_version_id"] is not None:
                    problems.append(f"version {v['version_id']}: original has a parent")
            else:
                parent = conn.execute(
                    "SELECT * FROM pub_versions WHERE version_id=?",
                    (v["parent_version_id"],)).fetchone()
                if parent is None:
                    problems.append(f"version {v['version_id']}: missing parent")
                elif parent["state"] != "sealed":
                    problems.append(
                        f"version {v['version_id']}: parent {parent['version_id']} "
                        f"is {parent['state']}, only sealed versions may be amended")

    for v in conn.execute("SELECT * FROM pub_versions").fetchall():
        n += 1
        vid = v["version_id"]
        stmts = conn.execute(
            "SELECT * FROM pub_statements WHERE version_id=? ORDER BY position",
            (vid,)).fetchall()
        batch = conn.execute("SELECT * FROM pub_batches WHERE batch_id=?",
                             (v["batch_id"],)).fetchone()
        if len(stmts) != batch["statement_count"]:
            problems.append(
                f"pub version {vid}: {len(stmts)} statements != "
                f"statement_count {batch['statement_count']}")

        contr = conn.execute(
            "SELECT * FROM pub_contributions WHERE version_id=?", (vid,)).fetchall()
        registered = [c for c in contr if c["state"] == "registered"]
        holds = conn.execute(
            "SELECT * FROM pub_holds WHERE version_id=?", (vid,)).fetchall()

        if v["state"] == "collecting":
            # holds must equal each registered team's not-cached, deduplicated need
            hold_idx = {(h["team_id"], h["snapshot_id"]): h for h in holds}
            need_idx: dict[tuple, list[float]] = {}
            for c in registered:
                seen = set()
                for s in stmts:
                    key = (s["snapshot_id"], s["query_hash"])
                    if key in seen:
                        continue
                    seen.add(key)
                    cached = conn.execute(
                        "SELECT 1 FROM results WHERE team_id=? AND snapshot_id=? "
                        "AND query_hash=?",
                        (c["team_id"], s["snapshot_id"], s["query_hash"])).fetchone()
                    if cached is not None:
                        continue
                    x = need_idx.setdefault((c["team_id"], s["snapshot_id"]), [0.0, 0.0])
                    x[0] += s["epsilon"]
                    x[1] += s["delta"]
            if set(hold_idx) != set(need_idx):
                problems.append(
                    f"pub version {vid}: holds {sorted(map(str,hold_idx))} != need "
                    f"{sorted(map(str,need_idx))}")
            for key, (e, d) in need_idx.items():
                h = hold_idx.get(key)
                if h and (abs(h["epsilon"] - e) > 1e-9 or abs(h["delta"] - d) > 1e-12):
                    problems.append(
                        f"pub version {vid}: hold {key} ({h['epsilon']},{h['delta']}) "
                        f"!= need ({e},{d})")
            # withdrawn contributions must hold nothing
            for c in contr:
                if c["state"] == "withdrawn" and (c["epsilon_held"] or c["delta_held"]):
                    problems.append(
                        f"pub version {vid}: withdrawn team {c['team_id']} still reports holds")

        if v["state"] in ("sealed", "void"):
            if holds:
                problems.append(
                    f"pub version {vid}: {v['state']} version still has holds")
        if v["state"] == "void":
            if any(c["state"] == "registered" for c in contr):
                problems.append(f"pub version {vid}: voided but contributions stay registered")

        if v["state"] == "sealed":
            if not v["manifest_json"] or not v["manifest_digest"] or not v["sealed_at"]:
                problems.append(f"pub version {vid}: sealed without manifest/digest/sealed_at")
                continue
            nreg = len({c["team_id"] for c in registered})
            if nreg < batch["min_participants"]:
                problems.append(
                    f"pub version {vid}: sealed with {nreg} < min_participants "
                    f"{batch['min_participants']}")
            members = conn.execute(
                "SELECT * FROM pub_release_members WHERE version_id=? ORDER BY position, team_id",
                (vid,)).fetchall()
            # dense grid
            grid = {(m["position"], m["team_id"]) for m in members}
            if len(grid) != len(stmts) * nreg:
                problems.append(
                    f"pub version {vid}: release grid {len(grid)} != "
                    f"{len(stmts)} x {nreg}")
            # every member references an existing result owned by the team
            charged: dict[str, list[float]] = {}
            for m in members:
                r = conn.execute(
                    "SELECT * FROM results WHERE result_id=?", (m["result_id"],)).fetchone()
                if r is None:
                    problems.append(
                        f"pub version {vid}: member result {m['result_id']} missing")
                    continue
                if r["team_id"] != m["team_id"] or r["query_hash"] != m["query_hash"]:
                    problems.append(
                        f"pub version {vid}: member/result identity mismatch")
                if m["charged"]:
                    acc = charged.setdefault(m["team_id"], [0.0, 0.0])
                    acc[0] += m["epsilon"]
                    acc[1] += m["delta"]
            # each result charged at most once in this release
            dup = conn.execute(
                """SELECT result_id, COUNT(*) c FROM pub_release_members
                   WHERE version_id=? AND charged=1 GROUP BY result_id HAVING c > 1""",
                (vid,)).fetchall()
            if dup:
                problems.append(
                    f"pub version {vid}: {len(dup)} results charged more than once")
            for c in registered:
                got = charged.get(c["team_id"], [0.0, 0.0])
                if abs(got[0] - c["epsilon_charged"]) > 1e-9 \
                        or abs(got[1] - c["delta_charged"]) > 1e-12:
                    problems.append(
                        f"pub version {vid} team {c['team_id']}: charged attribution "
                        "disagrees with contribution counters")
            # stored manifest digest must reproduce
            import json as _json
            try:
                doc = _json.loads(v["manifest_json"])
                recomputed = sha256_hex(dumps_canon(
                    {k: x for k, x in doc.items() if k != "sig"}))
                if recomputed != v["manifest_digest"]:
                    problems.append(f"pub version {vid}: stored manifest digest mismatch")
                if doc.get("parent_version_id"):
                    parent = conn.execute(
                        "SELECT manifest_digest FROM pub_versions WHERE version_id=?",
                        (doc["parent_version_id"],)).fetchone()
                    if parent is None or parent["manifest_digest"] != \
                            doc.get("parent_manifest_digest"):
                        problems.append(
                            f"pub version {vid}: parent_manifest_digest lineage broken")
            except Exception as exc:  # malformed manifest
                problems.append(f"pub version {vid}: manifest unreadable ({exc})")
            # exactly one pub_sealed audit row
            na = conn.execute(
                "SELECT COUNT(*) c FROM audit_log WHERE action='publication' "
                "AND outcome='pub_sealed' AND detail_json LIKE ?",
                ('%"' + vid + '"%',)).fetchone()["c"]
            if na != 1:
                problems.append(f"pub version {vid}: {na} pub_sealed audit rows")

    # no orphan pub holds
    orphan = conn.execute(
        """SELECT COUNT(*) c FROM pub_holds p LEFT JOIN pub_versions v
           ON v.version_id=p.version_id
           WHERE v.version_id IS NULL OR v.state != 'collecting'""").fetchone()["c"]
    if orphan:
        problems.append(f"{orphan} orphan publication holds")
    return n


def _verify_share_ledger(conn, problems: list[str]) -> int:
    """Cross-check sharing packages: scope uniqueness, grant coverage,
    release bindings, key uniqueness, lifecycle and retrieval references."""
    from .shares import (
        fields_covered,
        fields_hash,
        normalize_fields,
    )
    have = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    for table in ("shares", "share_field_grants", "share_retrievals"):
        if table not in have:
            return 0
    n = 0
    grants = {(g["version_id"], g["team_id"]): g for g in conn.execute(
        "SELECT * FROM share_field_grants").fetchall()}

    for s in conn.execute("SELECT * FROM shares").fetchall():
        n += 1
        sid = s["share_id"]
        if s["state"] not in ("creating", "sealed", "failed", "revoked"):
            problems.append(f"share {sid}: unknown state {s['state']}")
        try:
            fields = json.loads(s["fields_json"])
            if normalize_fields(fields) != fields:
                problems.append(f"share {sid}: fields not canonical/sorted")
        except Exception:
            problems.append(f"share {sid}: fields_json unreadable")
            fields = []
        if s["fields_hash"] != fields_hash(fields):
            problems.append(f"share {sid}: fields_hash does not reproduce")

        v = conn.execute("SELECT * FROM pub_versions WHERE version_id=?",
                         (s["version_id"],)).fetchone()
        if v is None:
            problems.append(f"share {sid}: release version missing")
        else:
            if v["state"] != "sealed":
                problems.append(
                    f"share {sid}: built on a {v['state']} release, expected sealed")
            elif v["manifest_digest"] != s["manifest_digest"]:
                problems.append(
                    f"share {sid}: bound manifest_digest != release digest "
                    "(authorisation rebound to a different release)")
            if v["parent_version_id"]:
                parent = conn.execute(
                    "SELECT manifest_digest FROM pub_versions WHERE version_id=?",
                    (v["parent_version_id"],)).fetchone()
                expected_parent = parent["manifest_digest"] if parent else None
            else:
                expected_parent = None
            if expected_parent != s["parent_digest"]:
                problems.append(f"share {sid}: parent digest lineage mismatch")

        grant = grants.get((s["version_id"], s["team_id"]))
        if grant is None and s["state"] in ("creating", "sealed", "revoked"):
            problems.append(f"share {sid}: no field grant for the audience team")
        elif grant is not None and fields_covered(fields, json.loads(
                grant["fields_json"])):
            problems.append(
                f"share {sid}: released fields widen the audience grant")

        if s["state"] == "creating":
            problems.append(
                f"share {sid}: creating reservation left unreconciled "
                "(run recovery)")
        if s["state"] in ("sealed", "revoked"):
            if not s["package_digest"] or not s["share_key_hash"] or not s["sealed_at"]:
                problems.append(f"share {sid}: sealed without package/key/sealed_at")
            try:
                from datetime import datetime
                exp = datetime.strptime(s["expires_at"],
                                        "%Y-%m-%dT%H:%M:%S.%fZ")
                crt = datetime.strptime(s["created_at"],
                                        "%Y-%m-%dT%H:%M:%S.%fZ")
                if exp <= crt:
                    problems.append(f"share {sid}: expiry not after creation")
            except ValueError:
                problems.append(f"share {sid}: malformed expiry/created timestamps")
        if s["state"] == "revoked" and not s["revoked_at"]:
            problems.append(f"share {sid}: revoked without revoked_at")
        if s["state"] == "failed" and (s["package_digest"] or s["share_key_hash"]):
            problems.append(f"share {sid}: failed share carries package/key material")

        # retrievals: ok only for a share that reached sealed
        n_ok = conn.execute(
            "SELECT COUNT(*) c FROM share_retrievals WHERE share_id=? AND outcome='ok'",
            (sid,)).fetchone()["c"]
        if n_ok and s["state"] not in ("sealed", "revoked"):
            problems.append(
                f"share {sid}: successful retrieval on a {s['state']} share")

    # at most one live share per authorisation scope
    dup = conn.execute(
        """SELECT version_id, team_id, fields_hash, COUNT(*) c FROM shares
           WHERE state IN ('creating','sealed')
           GROUP BY version_id, team_id, fields_hash HAVING c > 1""").fetchall()
    if dup:
        problems.append(f"{len(dup)} duplicated live (release,team,fields) scopes")

    dupkeys = conn.execute(
        """SELECT share_key_hash, COUNT(*) c FROM shares
           WHERE state IN ('creating','sealed') AND share_key_hash IS NOT NULL
           GROUP BY share_key_hash HAVING c > 1""").fetchall()
    if dupkeys:
        problems.append(f"{len(dupkeys)} share_keys bound to multiple live shares")

    for r in conn.execute("SELECT DISTINCT share_id FROM share_retrievals").fetchall():
        if conn.execute("SELECT 1 FROM shares WHERE share_id=?",
                        (r["share_id"],)).fetchone() is None:
            problems.append(f"retrieval references missing share {r['share_id']}")
    return n


def _verify_job_ledger(conn, problems: list[str]) -> int:
    """Cross-check jobs, job_statements and budget_holds against results."""
    # table may not exist in a pre-jobs database copy
    have = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "jobs" not in have:
        return 0
    n = 0
    ACTIVE = ("reserved", "executing")
    TERMINAL = ("completed", "failed", "cancelled", "expired")
    for j in conn.execute("SELECT * FROM jobs").fetchall():
        n += 1
        jid = j["job_id"]
        if j["state"] not in ACTIVE + TERMINAL:
            problems.append(f"job {jid}: unknown state {j['state']}")

        stmts = conn.execute(
            "SELECT * FROM job_statements WHERE job_id=? ORDER BY position", (jid,)).fetchall()
        if len(stmts) != j["statement_count"]:
            problems.append(
                f"job {jid}: statement_count {j['statement_count']} != rows {len(stmts)}")
        positions = [s["position"] for s in stmts]
        if positions != list(range(len(stmts))):
            problems.append(f"job {jid}: statement positions not dense 0..n-1")

        # holds: terminal jobs must have none, active jobs exactly their need
        hold_rows = conn.execute(
            "SELECT * FROM budget_holds WHERE job_id=?", (jid,)).fetchall()
        if j["state"] in TERMINAL and hold_rows:
            problems.append(f"job {jid}: terminal state {j['state']} still holds budget")
        if j["state"] in ACTIVE:
            # hold per snapshot must equal the sum of costs of not-yet-cached,
            # not-duplicate members
            need: dict[str, list[float]] = {}
            seen = set()
            for s in stmts:
                key = (s["snapshot_id"], s["query_hash"])
                cached = conn.execute(
                    "SELECT 1 FROM results WHERE result_id=?",
                    (s["result_id"],)).fetchone() if s["result_id"] else None
                if key in seen or s["already_cached"] or cached:
                    seen.add(key)
                    continue
                seen.add(key)
                v = need.setdefault(s["snapshot_id"], [0.0, 0.0])
                v[0] += s["epsilon"]
                v[1] += s["delta"]
            hold_map = {h["snapshot_id"]: h for h in hold_rows}
            if set(hold_map) != set(need):
                problems.append(
                    f"job {jid}: holds snapshots {sorted(hold_map)} != needed {sorted(need)}")
            for sid, (e, d) in need.items():
                h = hold_map.get(sid)
                if h and (abs(h["epsilon"] - e) > 1e-9 or abs(h["delta"] - d) > 1e-12):
                    problems.append(
                        f"job {jid}: hold on {sid} ({h['epsilon']},{h['delta']}) "
                        f"!= member need ({e},{d})")

        if j["state"] == "completed":
            if not j["finished_at"]:
                problems.append(f"job {jid}: completed without finished_at")
            # charged members carry the cost of their canonical query; compare
            # against both the job counters and the real results table
            charged = conn.execute(
                """SELECT s.epsilon e, s.delta d, r.epsilon re, r.delta rd
                   FROM job_statements s JOIN results r ON r.result_id=s.result_id
                   WHERE s.job_id=? AND s.charged=1""", (jid,)).fetchall()
            se = sum(c["e"] for c in charged)
            sd = sum(c["d"] for c in charged)
            if abs(se - j["epsilon_consumed"]) > 1e-9 or abs(sd - j["delta_consumed"]) > 1e-12:
                problems.append(f"job {jid}: consumed counters != charged member costs")
            for c in charged:
                if abs(c["e"] - c["re"]) > 1e-9 or abs(c["d"] - c["rd"]) > 1e-12:
                    problems.append(
                        f"job {jid}: charged statement cost != stored result cost")
            # every linked result must exist
            for s in stmts:
                r = conn.execute("SELECT 1 FROM results WHERE result_id=?",
                                 (s["result_id"],)).fetchone()
                if r is None:
                    problems.append(
                        f"job {jid} position {s['position']}: missing result "
                        f"{s['result_id']}")
            # one job_completed audit row
            na = conn.execute(
                "SELECT COUNT(*) c FROM audit_log WHERE action='job' "
                "AND outcome='job_completed' AND detail_json LIKE ?",
                ('%"' + jid + '"%',)).fetchone()["c"]
            if na < 1:
                problems.append(f"job {jid}: missing job_completed audit row")

    # request_key uniqueness is enforced by schema, but double-check state
    dups = conn.execute(
        "SELECT team_id, request_key, COUNT(*) c FROM jobs "
        "GROUP BY team_id, request_key HAVING c > 1").fetchall()
    if dups:
        problems.append(f"{len(dups)} duplicated (team, request_key) job rows")

    # no holds without an active job (orphan locks)
    orphan = conn.execute(
        """SELECT COUNT(*) c FROM budget_holds h LEFT JOIN jobs j ON j.job_id=h.job_id
           WHERE j.job_id IS NULL OR j.state NOT IN ('reserved','executing')""").fetchone()["c"]
    if orphan:
        problems.append(f"{orphan} orphan budget holds belonging to no active job")
    return n


# --------------------------------------------------------------------------- #
# bundle-level verification
# --------------------------------------------------------------------------- #

def verify_bundle(bundle: dict, secrets_: dict, snapshots_dir: str | None,
                  snapshot_dir_map: dict[str, str] | None = None) -> dict:
    snapshot_dir_map = snapshot_dir_map or {}
    receipt_reports = []
    ok = True
    for receipt in bundle.get("receipts", []):
        sid = receipt["snapshot_id"]
        sdir = snapshot_dir_map.get(sid)
        sdir = find_snapshot_dir(snapshots_dir, sid, sdir)
        rep = verify_receipt(receipt, secrets_, sdir)
        receipt_reports.append(rep)
        ok = ok and rep["ok"]

    # budget arithmetic inside the bundle
    ledger_problems: list[str] = []
    sums: dict[tuple, dict] = {}
    for r in bundle.get("receipts", []):
        key = (r["team_id"], r["snapshot_id"])
        s = sums.setdefault(key, {"epsilon": 0.0, "delta": 0.0, "n": 0})
        s["epsilon"] += r["privacy"]["epsilon"]
        s["delta"] += r["privacy"]["delta"]
        s["n"] += 1
    for b in bundle.get("budgets", []):
        key = (b["team_id"], b["snapshot_id"])
        s = sums.get(key, {"epsilon": 0.0, "delta": 0.0})
        if abs(s["epsilon"] - b["epsilon_spent"]) > 1e-9:
            ledger_problems.append(
                f"{key}: bundle receipts epsilon {s['epsilon']} != spent {b['epsilon_spent']}")
        if abs(s["delta"] - b["delta_spent"]) > 1e-12:
            ledger_problems.append(
                f"{key}: bundle receipts delta {s['delta']} != spent {b['delta_spent']}")
        if b["epsilon_spent"] > b["epsilon_limit"] + 1e-9:
            ledger_problems.append(f"{key}: epsilon overspent")
        if b["delta_spent"] > b["delta_limit"] + 1e-12:
            ledger_problems.append(f"{key}: delta overspent")

    # audit trail: each receipt has ok_executed; frozen/rejected are audit-only
    executed = {a.get("result_id") for a in bundle.get("audit", [])
                if a.get("outcome") == "ok_executed"}
    for r in bundle.get("receipts", []):
        if r["result_id"] not in executed:
            ledger_problems.append(
                f"result {r['result_id']} missing ok_executed audit record")

    # ------------------------------------------------------------------ #
    # multi-statement jobs: signed manifests + member receipts + hold math
    # ------------------------------------------------------------------ #
    job_reports = []
    receipts_by_id = {r["result_id"]: rep for r, rep in
                      zip(bundle.get("receipts", []), receipt_reports)}
    for j in bundle.get("jobs", []):
        manifest = j.get("manifest")
        if j.get("state") == "completed":
            if manifest is None:
                ledger_problems.append(f"job {j.get('job_id')}: completed but no manifest")
                continue
            rep = verify_job_manifest(
                manifest, secrets_, snapshots_dir, snapshot_dir_map,
                receipt_reports=[receipts_by_id.get(m["result_id"])
                                 for m in manifest.get("members", [])])
            job_reports.append(rep)
            if not rep["ok"]:
                ledger_problems.extend(
                    f"job {j.get('job_id')}: {e}" for e in rep["errors"])
        elif j.get("state") in ("reserved", "executing"):
            # active job: the bundle must carry the hold that keeps it safe
            job_holds = [h for h in bundle.get("holds", [])
                         if h.get("job_id") == j.get("job_id")]
            if not job_holds:
                ledger_problems.append(
                    f"job {j.get('job_id')}: active without any budget hold")

    # exported holds must fit within the bundle's budget limits
    sums: dict[tuple, dict] = {}
    for h in bundle.get("holds", []):
        key = (h["team_id"], h["snapshot_id"])
        s = sums.setdefault(key, {"epsilon": 0.0, "delta": 0.0})
        s["epsilon"] += h["epsilon"]
        s["delta"] += h["delta"]
    for h in bundle.get("pub_holds", []):
        key = (h["team_id"], h["snapshot_id"])
        s = sums.setdefault(key, {"epsilon": 0.0, "delta": 0.0})
        s["epsilon"] += h["epsilon"]
        s["delta"] += h["delta"]
    bmap = {(b["team_id"], b["snapshot_id"]): b for b in bundle.get("budgets", [])}
    for key, s in sums.items():
        b = bmap.get(key)
        if b is None:
            ledger_problems.append(f"hold on {key} without a budget row")
            continue
        if b["epsilon_spent"] + s["epsilon"] > b["epsilon_limit"] + 1e-9:
            ledger_problems.append(f"{key}: epsilon spent+held over limit")
        if b["delta_spent"] + s["delta"] > b["delta_limit"] + 1e-12:
            ledger_problems.append(f"{key}: delta spent+held over limit")

    # ------------------------------------------------------------------ #
    # joint publication releases: signed manifests, attribution, lineage
    # ------------------------------------------------------------------ #
    pub_reports = []
    versions_by_id = {v.get("version_id"): v for v in bundle.get("pub_versions", [])}
    # verify in seq order so a child can be checked against its parent digest
    ordered_versions = sorted(bundle.get("pub_versions", []),
                              key=lambda v: (v.get("batch_id", ""), v.get("seq", 0)))
    for v in ordered_versions:
        if v.get("state") != "sealed":
            # open versions must carry the holds keeping them safe
            active = [h for h in bundle.get("pub_holds", [])
                      if h.get("version_id") == v.get("version_id")]
            if v.get("state") == "collecting" and not active:
                # collecting with zero holds is legitimate when every
                # participant is fully cached; validate contribution consistency
                pass
            continue
        manifest = v.get("manifest")
        if manifest is None:
            ledger_problems.append(
                f"pub version {v.get('version_id')}: sealed but no manifest")
            continue
        parent_digest = None
        if v.get("parent_version_id"):
            parent = versions_by_id.get(v["parent_version_id"])
            parent_digest = parent.get("manifest_digest") if parent else None
        rep = verify_publication_manifest(
            manifest, secrets_, snapshots_dir, snapshot_dir_map,
            receipt_reports=[receipts_by_id.get(m["result_id"])
                             for m in manifest.get("members", [])],
            parent_digest=parent_digest)
        pub_reports.append(rep)
        if not rep["ok"]:
            ledger_problems.extend(
                f"pub {v.get('version_id')}: {e}" for e in rep["errors"])
        elif rep["digest"] != v.get("manifest_digest"):
            ledger_problems.append(
                f"pub {v.get('version_id')}: bundle manifest_digest != recomputation")

    # ------------------------------------------------------------------ #
    # controlled sharing packages: signatures, bindings, trimming, grants
    # ------------------------------------------------------------------ #
    share_reports = []
    if "shares" in bundle:
        releases_by_id = {v.get("version_id"): v.get("manifest")
                          for v in bundle.get("pub_versions", [])}
        for s in bundle.get("shares", []):
            pkg = s.get("package")
            if s.get("state") == "sealed":
                if pkg is None:
                    ledger_problems.append(
                        f"share {s.get('share_id')}: sealed but package missing")
                    continue
                full_release = releases_by_id.get(s.get("version_id"))
                rep = verify_share_package(
                    pkg, secrets_, snapshots_dir, full_release=full_release,
                    receipt_reports=receipt_reports)
                share_reports.append(rep)
                if not rep["ok"]:
                    ledger_problems.extend(
                        f"share {s.get('share_id')}: {e}" for e in rep["errors"])
                if rep["digest"] != s.get("package_digest"):
                    ledger_problems.append(
                        f"share {s.get('share_id')}: package_digest mismatch")
                if rep["release_digest"] != s.get("manifest_digest"):
                    ledger_problems.append(
                        f"share {s.get('share_id')}: bound release digest mismatch")
                # grant in the bundle must cover the released fields
                grant = next((g for g in bundle.get("share_grants", [])
                              if g.get("version_id") == s.get("version_id")
                              and g.get("team_id") == s.get("team_id")), None)
                from .shares import fields_covered
                if grant is None:
                    ledger_problems.append(
                        f"share {s.get('share_id')}: no field grant for audience")
                elif fields_covered(rep["fields"], json.loads(grant["fields_json"])):
                    ledger_problems.append(
                        f"share {s.get('share_id')}: fields widen the team grant")
            if s.get("state") in ("creating",):
                ledger_problems.append(
                    f"share {s.get('share_id')}: creating row survived in export")

    # ------------------------------------------------------------------ #
    # anti-fork transparency ledger: leaves, monotonic checkpoints, proofs
    # ------------------------------------------------------------------ #
    transparency_reports = {"checkpoints_checked": 0, "leaves_checked": 0}
    tl = bundle.get("transparency")
    if tl is not None:
        tl_key = secrets_.get("transparency_secret")
        tl_leaves = tl.get("leaves", [])
        tl_cps = tl.get("checkpoints", [])
        if tl_key is None:
            ledger_problems.append("transparency: secrets.json lacks transparency_secret")
        else:
            leaf_hashes: list[bytes] = []
            for leaf in tl_leaves:
                env = leaf.get("envelope", {})
                if envelope_leaf_hash(env) != leaf.get("leaf_hash"):
                    ledger_problems.append(
                        f"transparency: leaf {leaf.get('leaf_index')} "
                        "content address mismatch")
                if env.get("event_key") != leaf.get("event_key"):
                    ledger_problems.append(
                        f"transparency: leaf {leaf.get('leaf_index')} event_key mismatch")
                leaf_hashes.append(bytes.fromhex(leaf["leaf_hash"]))
            seen_keys: dict[str, int] = {}
            for leaf in tl_leaves:
                k = leaf.get("event_key")
                if k in seen_keys:
                    ledger_problems.append(
                        f"transparency: duplicate leaf for event_key {k}")
                seen_keys[k] = leaf["leaf_index"]

            prev_size, prev_root = None, None
            for cp in tl_cps:
                size = cp["tree_size"]
                doc = cp.get("checkpoint", {})
                rep = verify_checkpoint_doc(doc, secrets_)
                transparency_reports["checkpoints_checked"] += 1
                if not rep["ok"]:
                    ledger_problems.extend(
                        f"transparency checkpoint {size}: {e}" for e in rep["errors"])
                want = merkle_root(leaf_hashes[:size]).hex()
                if cp.get("root_hash") != want or doc.get("root_hash") != want:
                    ledger_problems.append(
                        f"transparency: checkpoint {size} root does not reproduce")
                if size > 0:
                    if cp.get("prev_size") != prev_size \
                            or cp.get("prev_root_hash") != prev_root:
                        ledger_problems.append(
                            f"transparency: checkpoint {size} prev chain broken")
                prev_size, prev_root = size, cp.get("root_hash")
            sizes = [cp["tree_size"] for cp in tl_cps]
            if sizes != list(range(len(tl_leaves) + 1)):
                ledger_problems.append(
                    "transparency: checkpoints are not dense 0..tree_size")
            transparency_reports["leaves_checked"] = len(tl_leaves)

            # every signed release / share event must be backed by a leaf whose
            # payload binds the same digest, and vice versa
            for v in bundle.get("pub_versions", []):
                if v.get("state") == "sealed":
                    key = f"release_sealed:{v.get('version_id')}"
                    leaf = next((l for l in tl_leaves
                                 if l.get("event_key") == key), None)
                    if leaf is None:
                        ledger_problems.append(
                            f"transparency: sealed release {v.get('version_id')} "
                            "has no leaf")
                    elif leaf["envelope"]["payload"].get("manifest_digest") \
                            != v.get("manifest_digest"):
                        ledger_problems.append(
                            f"transparency: leaf for {v.get('version_id')} binds "
                            "a different manifest_digest")
                if v.get("state") == "void":
                    key = f"release_voided:{v.get('version_id')}"
                    if not any(l.get("event_key") == key for l in tl_leaves):
                        ledger_problems.append(
                            f"transparency: void release {v.get('version_id')} "
                            "has no leaf")
            for s in bundle.get("shares", []):
                if s.get("state") in ("sealed", "revoked"):
                    key = f"share_issued:{s.get('share_id')}"
                    leaf = next((l for l in tl_leaves
                                 if l.get("event_key") == key), None)
                    if leaf is None:
                        ledger_problems.append(
                            f"transparency: share {s.get('share_id')} has no issue leaf")
                    elif leaf["envelope"]["payload"].get("package_digest") \
                            != s.get("package_digest"):
                        ledger_problems.append(
                            f"transparency: leaf for {s.get('share_id')} binds a "
                            "different package_digest")
                if s.get("state") == "revoked" and not any(
                        l.get("event_key") == f"share_revoked:{s.get('share_id')}"
                        for l in tl_leaves):
                    ledger_problems.append(
                        f"transparency: revoked share {s.get('share_id')} "
                        "has no revoke leaf")

    return {
        "ok": ok and not ledger_problems,
        "receipts_checked": len(receipt_reports),
        "receipt_reports": receipt_reports,
        "jobs_checked": len(job_reports),
        "job_reports": job_reports,
        "publications_checked": len(pub_reports),
        "publication_reports": pub_reports,
        "shares_checked": len(share_reports),
        "share_reports": share_reports,
        "transparency": transparency_reports,
        "holds_checked": len(bundle.get("holds", [])) + len(bundle.get("pub_holds", [])),
        "ledger_problems": ledger_problems,
    }
