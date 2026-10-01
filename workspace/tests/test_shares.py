"""Controlled sharing packages: per-team field grants (whitelist), audience
checks, one immutable content-addressed package per authorisation scope,
idempotent retrievals that never regenerate, revocation/expiry semantics,
crash recovery, concurrency, version-revision bindings and offline verification.
"""

import json
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from harness import Harness  # noqa: E402

from dpgw.app import open_gateway  # noqa: E402
from dpgw.errors import (  # noqa: E402
    ShareExpired,
    ShareForbidden,
    ShareInvalid,
    ShareNotFound,
    ShareRevoked,
    ShareStateConflict,
    TeamNotFound,
)
from dpgw.verify import (  # noqa: E402
    export_bundle,
    load_secrets,
    verify_bundle,
    verify_ledger,
    verify_share_package,
)


def stmt(sid, city="BJ", eps=0.3):
    return {"snapshot": {"snapshot_id": sid},
            "query": {"type": "count", "epsilon": eps,
                      "filter": {"op": "cmp", "column": "city",
                                 "predicate": "=", "value": city}}}


MEMBERS = ["members.position", "members.team_id", "members.charged"]
RECEIPT_PARTS = ["receipts.result_id", "receipts.team_id", "receipts.snapshot_id",
                 "receipts.query_hash", "receipts.values"]
FIELDS = sorted(MEMBERS + RECEIPT_PARTS + ["statements.position", "statements.query_hash"])
FULL = ["statements", "members", "receipts"]


class ShareTestBase(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.snap, _, _ = self.h.publish("v1")
        self.sid = self.snap["snapshot_id"]
        for name in ("alpha", "beta", "gamma"):
            self.h.grant(name, self.sid, 5.0)
        self.ta, self.tb, self.tg = (self.h.tid(n) for n in ("alpha", "beta", "gamma"))
        self.g = self.h.gw

    def seal_release(self, fields_statements=2, close="2099-01-01T00:00:00Z",
                     name="joint"):
        cities = ["BJ", "SH", "SZ"][:fields_statements]
        v = self.g.create_publication(
            name, [stmt(self.sid, c) for c in cities], 1, close, actor="test")
        self.g.register_contribution(v["version_id"], self.ta, actor="test")
        return self.g.seal_publication(v["version_id"], actor="test")

    def grant(self, vid, tid, fields):
        self.g.grant_share_fields(vid, tid, fields, actor="test")

    def secrets(self):
        return load_secrets(os.path.join(self.h.home, "secrets.json"))

    def tearDown(self):
        self.h.gw.db.close()
        self.h.tmp.cleanup()


class ShareCreationTests(ShareTestBase):
    def test_audience_and_whitelist_validated(self):
        sealed = self.seal_release()
        vid = sealed["version_id"]
        # audience must exist
        with self.assertRaises(TeamNotFound):
            self.g.create_share(vid, "team_ghost", FIELDS, ttl_seconds=3600)
        # no grant at all
        with self.assertRaises(ShareForbidden):
            self.g.create_share(vid, self.tb, FIELDS, ttl_seconds=3600)
        # grant exists but does not cover the requested fields
        self.grant(vid, self.ta, ["statements.position"])
        with self.assertRaises(ShareForbidden):
            self.g.create_share(vid, self.ta, FIELDS, ttl_seconds=3600)
        # unknown field paths rejected
        with self.assertRaises(ShareInvalid):
            self.g.create_share(vid, self.ta, ["receipts.secret_key"],
                                ttl_seconds=3600)
        with self.assertRaises(ShareInvalid):
            self.g.create_share(vid, self.ta, [], ttl_seconds=3600)

    def test_rejected_creation_leaves_no_state(self):
        sealed = self.seal_release()
        with self.assertRaises(ShareForbidden):
            self.g.create_share(sealed["version_id"], self.tb, FIELDS,
                                ttl_seconds=3600)
        self.assertEqual(self.g.list_shares(), [])
        self.assertEqual(self.g.list_retrievals(), [])
        self.assertEqual(os.listdir(os.path.join(self.h.home, "shares")), [])
        # rejection was audited but touched nothing else
        rejects = [a for a in self.g.list_audit()
                   if a["action"] == "share" and a["outcome"].startswith("reject_")]
        self.assertTrue(rejects)

    def test_only_sealed_releases_can_be_shared(self):
        v = self.g.create_publication(
            "open", [stmt(self.sid)], 1, "2099-01-01T00:00:00Z", actor="test")
        self.grant(v["version_id"], self.ta, ["statements.position"])
        with self.assertRaises(ShareStateConflict):
            self.g.create_share(v["version_id"], self.ta, ["statements.position"],
                                ttl_seconds=3600)
        # void releases too
        vid = v["version_id"]
        self.g.db.execute(
            "UPDATE pub_versions SET state='void', close_at=? WHERE version_id=?",
            ("2000-01-01T00:00:00.000000Z", vid))
        with self.assertRaises(ShareStateConflict):
            self.g.create_share(vid, self.ta, ["statements.position"],
                                ttl_seconds=3600)

    def test_expiry_validation(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, ["statements.position"])
        with self.assertRaises(ShareInvalid):
            self.g.create_share(sealed["version_id"], self.ta,
                                ["statements.position"], expires_at="2000-01-01T00:00:00Z")
        with self.assertRaises(ShareInvalid):
            self.g.create_share(sealed["version_id"], self.ta,
                                ["statements.position"], ttl_seconds=0)
        with self.assertRaises(ShareInvalid):
            self.g.create_share(sealed["version_id"], self.ta,
                                ["statements.position"],
                                ttl_seconds=60, expires_at="2099-01-01T00:00:00Z")

    def test_create_returns_one_key_and_binds_digests(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, FIELDS)
        r = self.g.create_share(sealed["version_id"], self.ta, FIELDS,
                                ttl_seconds=3600)
        self.assertEqual(r["state"], "sealed")
        self.assertTrue(r["created"])
        self.assertTrue(r["share_key"].startswith("shk_"))
        self.assertEqual(r["manifest_digest"], sealed["manifest_digest"])
        pkg = self.g.fetch_share(r["share_key"], actor="cli")
        self.assertEqual(pkg["release_digest"], sealed["manifest_digest"])
        self.assertIsNone(pkg["release_parent_digest"])

    def test_field_projection_carries_only_granted_fields(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, FIELDS)
        r = self.g.create_share(sealed["version_id"], self.ta, FIELDS,
                                ttl_seconds=3600)
        pkg = self.g.fetch_share(r["share_key"], actor="cli")
        self.assertNotIn("participants", pkg["release"])
        self.assertEqual(set(pkg["release"]["statements"][0]),
                         {"position", "query_hash"})
        self.assertEqual(set(pkg["release"]["members"][0]),
                         {"position", "team_id", "charged"})
        receipt = pkg["release"]["receipts"][0]
        self.assertIn("values", receipt)
        for sensitive in ("canonical", "coords", "privacy", "sig"):
            self.assertNotIn(sensitive, receipt)


class ShareIdempotencyTests(ShareTestBase):
    def test_repeat_create_replays_same_package(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, FIELDS)
        r1 = self.g.create_share(sealed["version_id"], self.ta, FIELDS,
                                 ttl_seconds=3600)
        r2 = self.g.create_share(sealed["version_id"], self.ta, FIELDS,
                                 ttl_seconds=99999)
        self.assertFalse(r2["created"])
        self.assertEqual(r1["share_id"], r2["share_id"])
        self.assertEqual(r1["share_key"], r2["share_key"])
        self.assertEqual(r1["package_digest"], r2["package_digest"])
        # the expiry of the original reservation is immutable on replay
        self.assertEqual(r1["expires_at"], r2["expires_at"])
        self.assertEqual(len(os.listdir(os.path.join(self.h.home, "shares"))), 1)
        audit = [a["outcome"] for a in self.g.list_audit() if a["action"] == "share"]
        self.assertEqual(audit.count("share_created"), 1)
        self.assertIn("share_replayed", audit)

    def test_different_field_sets_are_different_packages(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, FIELDS + ["statements.mechanism"])
        a = self.g.create_share(sealed["version_id"], self.ta, FIELDS,
                                ttl_seconds=3600)
        b = self.g.create_share(
            sealed["version_id"], self.ta,
            sorted(set(FIELDS + ["statements.mechanism"])), ttl_seconds=3600)
        self.assertNotEqual(a["share_id"], b["share_id"])
        self.assertNotEqual(a["package_digest"], b["package_digest"])

    def test_repeat_fetch_returns_same_bytes(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, FIELDS)
        r = self.g.create_share(sealed["version_id"], self.ta, FIELDS,
                                ttl_seconds=3600)
        p1 = self.g.fetch_share(r["share_key"], actor="team:alpha", team_id=self.ta)
        p2 = self.g.fetch_share(r["share_key"], actor="team:alpha", team_id=self.ta)
        self.assertEqual(json.dumps(p1, sort_keys=True),
                         json.dumps(p2, sort_keys=True))
        self.assertEqual(len(os.listdir(os.path.join(self.h.home, "shares"))), 1)
        oks = self.g.db.execute(
            "SELECT COUNT(*) c FROM share_retrievals WHERE outcome='ok'").fetchone()["c"]
        self.assertEqual(oks, 2)

    def test_unknown_key_is_not_found(self):
        with self.assertRaises(ShareNotFound):
            self.g.fetch_share("shk_" + "0" * 64, actor="x")

    def test_cross_team_token_cannot_fetch(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, FIELDS)
        r = self.g.create_share(sealed["version_id"], self.ta, FIELDS,
                                ttl_seconds=3600)
        with self.assertRaises(ShareNotFound):
            self.g.fetch_share(r["share_key"], actor="team:beta", team_id=self.tb)
        # audience team can
        pkg = self.g.fetch_share(r["share_key"], actor="team:alpha", team_id=self.ta)
        self.assertEqual(pkg["team_id"], self.ta)


class ShareRevocationExpiryTests(ShareTestBase):
    def test_revocation_blocks_new_fetches_but_file_stays_valid(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, FIELDS)
        r = self.g.create_share(sealed["version_id"], self.ta, FIELDS,
                                ttl_seconds=3600)
        pkg = self.g.fetch_share(r["share_key"], actor="team:alpha", team_id=self.ta)
        self.g.revoke_share(r["share_id"], reason="incident")
        with self.assertRaises(ShareRevoked):
            self.g.fetch_share(r["share_key"], actor="team:alpha", team_id=self.ta)
        # idempotent revoke
        self.assertEqual(self.g.revoke_share(r["share_id"])["state"], "revoked")
        # downloaded artifact remains verifiable offline forever
        report = verify_share_package(pkg, self.secrets())
        self.assertTrue(report["ok"])
        # revoked scope is freed for a fresh package
        r2 = self.g.create_share(sealed["version_id"], self.ta, FIELDS,
                                 ttl_seconds=7200)
        self.assertTrue(r2["created"])
        self.assertNotEqual(r["share_id"], r2["share_id"])

    def test_expired_share_rejects_fetches_signature_still_valid(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, ["statements.position"])
        r = self.g.create_share(sealed["version_id"], self.ta,
                                ["statements.position"], ttl_seconds=1)
        path = os.path.join(self.h.home, "shares", r["package_digest"] + ".json")
        with open(path, "rb") as fh:
            pkg = json.loads(fh.read().decode("utf-8"))
        time.sleep(1.15)
        with self.assertRaises(ShareExpired):
            self.g.fetch_share(r["share_key"], actor="team:alpha", team_id=self.ta)
        rep = verify_share_package(pkg, self.secrets())
        self.assertTrue(rep["ok"])  # HMAC binds expiry; authenticity independent
        rep_future = verify_share_package(
            pkg, self.secrets(), now="2099-01-01T00:00:00.000000Z")
        self.assertTrue(rep_future["expired"])


class ShareRecoveryTests(ShareTestBase):
    def test_crash_after_reservation_completes_on_restart(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, ["statements.position"])
        with self.assertRaises(RuntimeError):
            self.g.create_share(sealed["version_id"], self.ta,
                                ["statements.position"], ttl_seconds=3600,
                                _crash={"after_insert": True})
        self.assertEqual(
            [r["state"] for r in self.g.db.execute("SELECT state FROM shares")],
            ["creating"])
        self.assertEqual(os.listdir(os.path.join(self.h.home, "shares")), [])
        self.g.db.close()

        gw2 = open_gateway(self.h.home)
        row = gw2.db.execute("SELECT * FROM shares").fetchone()
        self.assertEqual(row["state"], "sealed")
        self.assertIsNotNone(row["share_key_hash"])
        self.assertIsNotNone(row["package_digest"])
        key = gw2._derive_share_key(row["share_id"])
        pkg = gw2.fetch_share(key, actor="cli")
        self.assertTrue(verify_share_package(pkg, self.secrets())["ok"])
        # replay after recovery stays on the same row
        again = gw2.create_share(sealed["version_id"], self.ta,
                                 ["statements.position"], ttl_seconds=3600)
        self.assertFalse(again["created"])
        self.assertEqual(again["share_id"], row["share_id"])
        gw2.db.close()

    def test_invalid_reservation_is_safely_terminated(self):
        sealed = self.seal_release()
        fields = ["members.position", "members.charged"]
        self.grant(sealed["version_id"], self.ta, fields)
        with self.assertRaises(RuntimeError):
            self.g.create_share(sealed["version_id"], self.ta, fields,
                                ttl_seconds=3600, _crash={"after_insert": True})
        # the whitelist disappears before recovery -> safe failure, no artifact
        self.g.db.execute(
            "DELETE FROM share_field_grants WHERE version_id=? AND team_id=?",
            (sealed["version_id"], self.ta))
        self.g.db.close()
        gw2 = open_gateway(self.h.home)
        row = gw2.db.execute("SELECT * FROM shares").fetchone()
        self.assertEqual(row["state"], "failed")
        self.assertIsNone(row["package_digest"])
        self.assertIsNone(row["share_key_hash"])
        # the failed scope is freed and a fresh grant allows a clean package
        gw2.grant_share_fields(sealed["version_id"], self.ta, fields, actor="test")
        r = gw2.create_share(sealed["version_id"], self.ta, fields,
                             ttl_seconds=3600)
        self.assertTrue(r["created"])
        self.assertEqual(r["state"], "sealed")
        gw2.db.close()


class ShareConcurrencyTests(ShareTestBase):
    def test_concurrent_creates_seal_one_package(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, FIELDS)
        results, errors = [], []
        barrier = threading.Barrier(12)

        def create():
            barrier.wait()
            try:
                results.append(self.g.create_share(
                    sealed["version_id"], self.ta, FIELDS, ttl_seconds=3600))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=create) for _ in range(12)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertFalse(errors)
        self.assertEqual(len({r["share_id"] for r in results}), 1)
        self.assertEqual(len({r["share_key"] for r in results}), 1)
        self.assertEqual(len({r["package_digest"] for r in results}), 1)
        flags = [r["created"] for r in results]
        self.assertEqual(flags.count(True), 1)
        self.assertEqual(flags.count(False), 11)
        self.assertEqual(len(os.listdir(os.path.join(self.h.home, "shares"))), 1)

    def test_concurrent_fetch_and_revoke_never_corrupt(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, FIELDS)
        r = self.g.create_share(sealed["version_id"], self.ta, FIELDS,
                                ttl_seconds=3600)
        counts = {"ok": 0, "rejected": 0}
        lock = threading.Lock()

        def fetch():
            try:
                pkg = self.g.fetch_share(
                    r["share_key"], actor="team:alpha", team_id=self.ta)
                self.assertEqual(pkg["release_digest"], sealed["manifest_digest"])
                with lock:
                    counts["ok"] += 1
            except ShareRevoked:
                with lock:
                    counts["rejected"] += 1

        workers = [threading.Thread(target=fetch) for _ in range(24)]
        workers.append(threading.Thread(
            target=lambda: self.g.revoke_share(r["share_id"], reason="race")))
        [t.start() for t in workers]
        [t.join() for t in workers]
        self.assertEqual(counts["ok"] + counts["rejected"], 24)
        with self.assertRaises(ShareRevoked):
            self.g.fetch_share(r["share_key"], actor="team:alpha", team_id=self.ta)

    def test_concurrent_distinct_audiences_get_distinct_packages(self):
        sealed = self.seal_release()
        for tid in (self.ta, self.tb, self.tg):
            self.grant(sealed["version_id"], tid, FIELDS)
        results, errors = [], []
        barrier = threading.Barrier(3)

        def create(tid):
            barrier.wait()
            try:
                results.append(self.g.create_share(
                    sealed["version_id"], tid, FIELDS, ttl_seconds=3600))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=create, args=(t,))
                   for t in (self.ta, self.tb, self.tg)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertFalse(errors)
        self.assertEqual(len({r["share_id"] for r in results}), 3)
        self.assertEqual({r["team_id"] for r in results},
                         {self.ta, self.tb, self.tg})


class ShareLineageAndOfflineTests(ShareTestBase):
    def test_package_binds_parent_digest_across_revision(self):
        sealed = self.seal_release()
        v2 = self.g.amend_publication(sealed["version_id"],
                                      "2099-02-01T00:00:00Z", actor="test")
        self.g.register_contribution(v2["version_id"], self.ta, actor="test")
        sealed2 = self.g.seal_publication(v2["version_id"], actor="test")
        self.grant(v2["version_id"], self.ta, FIELDS)
        r = self.g.create_share(v2["version_id"], self.ta, FIELDS,
                                ttl_seconds=3600)
        pkg = self.g.fetch_share(r["share_key"], actor="cli")
        self.assertEqual(pkg["release_parent_digest"], sealed["manifest_digest"])
        rep = verify_share_package(
            pkg, self.secrets(), os.path.join(self.h.home, "snapshots"),
            full_release=sealed2["manifest"],
            parent_digest=sealed["manifest_digest"])
        self.assertTrue(rep["ok"], rep["errors"])
        # wrong claimed parent digest is detected
        with self.assertRaises(AssertionError):
            rep_bad = verify_share_package(
                pkg, self.secrets(), os.path.join(self.h.home, "snapshots"),
                full_release=sealed2["manifest"],
                parent_digest="0" * 64)
            self.assertTrue(rep_bad["ok"])

    def test_revision_does_not_change_existing_share_digest(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, FIELDS)
        r = self.g.create_share(sealed["version_id"], self.ta, FIELDS,
                                ttl_seconds=3600)
        pkg = self.g.fetch_share(r["share_key"], actor="cli")
        self.g.revoke_share(r["share_id"], reason="superseded")
        v2 = self.g.amend_publication(sealed["version_id"],
                                      "2099-02-01T00:00:00Z", actor="test")
        self.g.register_contribution(v2["version_id"], self.ta, actor="test")
        self.g.seal_publication(v2["version_id"], actor="test")
        row = self.g.db.execute(
            "SELECT manifest_digest, state FROM shares WHERE share_id=?",
            (r["share_id"],)).fetchone()
        self.assertEqual(row["manifest_digest"], sealed["manifest_digest"])
        self.assertEqual(row["state"], "revoked")
        # artifact still verifies against the old, retained release
        self.assertTrue(verify_share_package(pkg, self.secrets())["ok"])

    def test_offline_trim_and_tamper_detection(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, FIELDS)
        r = self.g.create_share(sealed["version_id"], self.ta, FIELDS,
                                ttl_seconds=3600)
        pkg = self.g.fetch_share(r["share_key"], actor="cli")
        sec = self.secrets()
        rep = verify_share_package(
            pkg, sec, os.path.join(self.h.home, "snapshots"),
            full_release=sealed["manifest"])
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertTrue(rep["checks"]["trim_reproduced"])
        self.assertTrue(rep["checks"]["release_digest"])
        # partial receipts cannot be re-signed/replayed: anchored to share HMAC
        tampered = json.loads(json.dumps(pkg))
        tampered["release"]["receipts"][0]["values"] = [9999.0]
        self.assertFalse(verify_share_package(tampered, sec)["ok"])
        tampered = json.loads(json.dumps(pkg))
        tampered["expires_at"] = "2099-12-31T00:00:00.000000Z"
        self.assertFalse(verify_share_package(tampered, sec)["ok"])
        tampered = json.loads(json.dumps(pkg))
        tampered["team_id"] = self.tb
        self.assertFalse(verify_share_package(tampered, sec)["ok"])

    def test_whole_receipt_grant_keeps_receipts_self_verifying(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, FULL)
        r = self.g.create_share(sealed["version_id"], self.ta, FULL,
                                ttl_seconds=3600)
        pkg = self.g.fetch_share(r["share_key"], actor="cli")
        self.assertIn("sig", pkg["release"]["receipts"][0])
        rep = verify_share_package(
            pkg, self.secrets(), os.path.join(self.h.home, "snapshots"),
            full_release=sealed["manifest"])
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertEqual(rep["receipts_checked"], 2)  # two statements

    def test_parent_digest_mismatch_is_safely_terminated(self):
        v1 = self.seal_release(name="chain")
        v2 = self.g.amend_publication(v1["version_id"],
                                      "2099-02-01T00:00:00Z", actor="test")
        self.g.register_contribution(v2["version_id"], self.ta, actor="test")
        self.g.seal_publication(v2["version_id"], actor="test")
        self.grant(v2["version_id"], self.ta, ["statements.position"])
        with self.assertRaises(RuntimeError):
            self.g.create_share(v2["version_id"], self.ta,
                                ["statements.position"], ttl_seconds=3600,
                                _crash={"after_insert": True})
        # corrupt the bound parent digest before the reservation is sealed
        self.g.db.execute(
            "UPDATE shares SET parent_digest=? WHERE state='creating'",
            ("f" * 64,))
        self.g.db.close()
        gw2 = open_gateway(self.h.home)
        row = gw2.db.execute(
            "SELECT state, package_digest, share_key_hash FROM shares").fetchone()
        self.assertEqual(row["state"], "failed")
        self.assertIsNone(row["package_digest"])
        self.assertIsNone(row["share_key_hash"])
        self.assertEqual(os.listdir(os.path.join(self.h.home, "shares")), [])
        reasons = [a["detail"].get("reason", "") for a in gw2.list_audit()
                   if a["outcome"] == "share_creation_failed"]
        self.assertTrue(any("parent" in r for r in reasons), reasons)
        gw2.db.close()
        # reopen via a fresh gateway for the shared tearDown (it opens its own)
        self.h.gw = open_gateway(self.h.home)

    def test_bundle_and_ledger_verification(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, FIELDS)
        r = self.g.create_share(sealed["version_id"], self.ta, FIELDS,
                                ttl_seconds=3600)
        self.g.fetch_share(r["share_key"], actor="team:alpha", team_id=self.ta)
        ledger = verify_ledger(os.path.join(self.h.home, "gateway.sqlite"))
        self.assertTrue(ledger["ok"], ledger["problems"])
        self.assertGreaterEqual(ledger["shares_checked"], 1)
        bundle = export_bundle(self.g)
        self.assertEqual(bundle["bundle_version"], "b5")
        rep = verify_bundle(bundle, self.secrets(),
                            os.path.join(self.h.home, "snapshots"))
        self.assertTrue(rep["ok"], rep["ledger_problems"])
        self.assertGreaterEqual(rep["shares_checked"], 1)

    def test_ledger_detects_widened_or_rebound_share(self):
        sealed = self.seal_release()
        self.grant(sealed["version_id"], self.ta, FIELDS)
        r = self.g.create_share(sealed["version_id"], self.ta, FIELDS,
                                ttl_seconds=3600)
        # tamper: rebind the stored share to a different release digest
        self.g.db.execute(
            "UPDATE shares SET manifest_digest=? WHERE share_id=?",
            ("0" * 64, r["share_id"]))
        ledger = verify_ledger(os.path.join(self.h.home, "gateway.sqlite"))
        self.assertFalse(ledger["ok"])
        self.assertTrue(any("manifest_digest" in p for p in ledger["problems"]))


if __name__ == "__main__":
    unittest.main()
