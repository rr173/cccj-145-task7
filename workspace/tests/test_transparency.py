"""Anti-fork transparency ledger tests.

Every signed release (sealed / void) and controlled-share event (issued /
revoked) appends one content-addressed Merkle leaf and advances a signed,
monotonic checkpoint.  These tests cover:

* genesis + dense append order; every root reproduces; checkpoint chain;
* inclusion proofs (valid/tampered/missing/stale) and event_key lookup;
* adjacent-checkpoint consistency proofs (valid/tampered, genesis, equal size);
* event_key replay returns the original leaf index;
* fork evidence (two same-height/different-root signed checkpoints) freezes
  issuance; same-root / bad-signature / wrong-height submissions fail without
  touching the ledger; post-freeze seal/void/issue/revoke all 423 while reads,
  proofs and idempotent replays keep working;
* many threads sealing / making packages / revoking / reading checkpoints
  concurrently: no lost leaf, no double numbering, no root regression;
* recoverable outbox: a process interrupted with committed business rows drains
  in fixed order on restart, reproducing the same single history;
* HTTP endpoints and offline ledger/bundle verification.
"""

import json
import os
import sys
import threading
import unittest
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))
from harness import Harness  # noqa: E402

from dpgw.app import open_gateway  # noqa: E402
from dpgw.errors import (  # noqa: E402
    PublicationStateConflict,
    TransparencyCheckpointExpired,
    TransparencyFrozen,
    TransparencyNotFound,
    TransparencyProofInvalid,
)
from dpgw.receipts import dumps_canon  # noqa: E402
from dpgw.shares import all_catalog_fields  # noqa: E402
from dpgw.transparency import merkle_root  # noqa: E402
from dpgw.verify import (  # noqa: E402
    export_bundle,
    load_secrets,
    verify_bundle,
    verify_checkpoint_doc,
    verify_consistency_proof,
    verify_fork_evidence,
    verify_inclusion_proof,
    verify_ledger,
)
from dpgw.server import serve  # noqa: E402


def q(city, eps=0.3):
    return {"type": "count", "epsilon": 0.3 if city else eps,
            "filter": {"op": "cmp", "column": "city", "predicate": "=",
                       "value": city}}


def iso_in(seconds):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def iso_ago(seconds=1):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ")


class TransparencyBase(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.snap, _, _ = self.h.publish("v1")
        self.sid = self.snap["snapshot_id"]
        self.g = self.h.gw
        for name in ("alpha", "beta", "gamma"):
            self.h.grant(name, self.sid, 5.0)
        self.ta, self.tb, self.tg = (self.h.tid(n) for n in
                                     ("alpha", "beta", "gamma"))
        self.secrets = load_secrets(os.path.join(self.h.home, "secrets.json"))

    def tearDown(self):
        self.h.gw.db.close()
        self.h.tmp.cleanup()

    def stmt(self, city="BJ"):
        return {"snapshot": {"snapshot_id": self.sid}, "query": q(city)}

    def create_batch(self, name, minp=2, city="BJ", close_seconds=3600):
        return self.g.create_publication(
            name, [self.stmt(city)], minp, iso_in(close_seconds), actor="lead")

    def seal_batch(self, name, *teams, minp=2, city="BJ"):
        v = self.create_batch(name, minp=minp, city=city)
        for t in teams:
            self.g.register_contribution(v["version_id"], t)
        resp = self.g.seal_publication(v["version_id"])
        return v["version_id"], resp

    def void_batch(self, name, minp=3):
        v = self.create_batch(name, minp=minp)
        self.g.db.execute(
            "UPDATE pub_versions SET close_at=? WHERE version_id=?",
            (iso_ago(), v["version_id"]))
        return self.g.void_publication(v["version_id"]), v["version_id"]

    def make_share(self, vid, team=None, fields=None):
        team = team or self.ta
        fields = fields or all_catalog_fields()
        self.g.grant_share_fields(vid, team, fields)
        return self.g.create_share(vid, team, fields, ttl_seconds=3600)


class GenesisAndAppendTests(TransparencyBase):
    def test_genesis_checkpoint_exists_with_empty_tree(self):
        st = self.g.tl_state()
        self.assertEqual(st["tree_size"], 0)
        self.assertEqual(st["root_hash"],
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertFalse(st["frozen"])
        self.assertEqual(st["pending_outbox"], 0)
        cp = self.g.tl_checkpoint(0)["checkpoint"]
        self.assertTrue(verify_checkpoint_doc(cp, self.secrets)["ok"])

    def test_seal_void_issue_revoke_append_dense_leaves_and_roots(self):
        vid, sealed = self.seal_batch("b1", self.ta, self.tb)
        self.assertIn("transparency", sealed)
        anchor = sealed["transparency"]
        self.assertEqual(anchor["leaf_index"], 0)
        self.assertEqual(anchor["event_type"], "release_sealed")
        self.assertEqual(anchor["tree_size"], 1)

        sh = self.make_share(vid)
        self.assertEqual(sh["transparency"]["leaf_index"], 1)
        self.assertEqual(sh["transparency"]["event_type"], "share_issued")
        rv = self.g.revoke_share(sh["share_id"], reason="r")
        self.assertEqual(rv["transparency"]["leaf_index"], 2)
        self.assertEqual(rv["transparency"]["event_type"], "share_revoked")

        voided, _ = self.void_batch("b2")
        self.assertEqual(voided["transparency"]["leaf_index"], 3)
        self.assertEqual(voided["transparency"]["event_type"], "release_voided")

        st = self.g.tl_state()
        self.assertEqual(st["tree_size"], 4)
        # every stored leaf and every checkpoint root recompute independently
        chain = self.g.tl_verify_local_chain_locked()
        self.assertTrue(chain["ok"], chain["problems"])
        leaves = self.g.tl_list_leaves()
        self.assertEqual([l["leaf_index"] for l in reversed(leaves)],
                         [0, 1, 2, 3])
        # content address: leaf hash over canonical envelope
        stored = self.g.db.execute(
            "SELECT leaf_hash, envelope_json FROM tl_leaves ORDER BY leaf_index")
        from dpgw.transparency import envelope_leaf_hash
        for lh, env in stored:
            self.assertEqual(envelope_leaf_hash(json.loads(env)), lh)
        # checkpoint prev chain is strictly monotonic
        cps = self.g.db.execute(
            "SELECT tree_size, root_hash, prev_size, prev_root_hash "
            "FROM tl_checkpoints ORDER BY tree_size").fetchall()
        self.assertEqual([c["tree_size"] for c in cps], [0, 1, 2, 3, 4])
        for i, c in enumerate(cps[1:], start=1):
            self.assertEqual(c["prev_size"], cps[i - 1]["tree_size"])
            self.assertEqual(c["prev_root_hash"], cps[i - 1]["root_hash"])
            self.assertNotEqual(c["root_hash"], c["prev_root_hash"])

    def test_seal_anchor_proof_verifies_offline(self):
        vid, _ = self.seal_batch("b1", self.ta, self.tb)
        proof = self.g.tl_inclusion(0)
        rep = verify_inclusion_proof(proof, self.secrets)
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertEqual(rep["tree_size"], 1)


class InclusionProofTests(TransparencyBase):
    def test_inclusion_for_every_leaf_at_latest_and_past_sizes(self):
        vid, _ = self.seal_batch("b1", self.ta, self.tb)
        sh = self.make_share(vid)
        self.g.revoke_share(sh["share_id"])
        for idx in range(3):
            for size in range(idx + 1, 4):
                rep = verify_inclusion_proof(
                    self.g.tl_inclusion(idx, size), self.secrets)
                self.assertTrue(rep["ok"], (idx, size, rep["errors"]))

    def test_tampered_inclusion_path_rejected(self):
        vid, _ = self.seal_batch("b1", self.ta, self.tb)
        sh = self.make_share(vid)
        proof = self.g.tl_lookup_event(f"share_issued:{sh['share_id']}")
        self.assertTrue(verify_inclusion_proof(proof, self.secrets)["ok"])
        bad = json.loads(json.dumps(proof))
        bad["inclusion_path"][0] = "00" * 32
        self.assertFalse(verify_inclusion_proof(bad, self.secrets)["ok"])
        # tamper with the envelope payload but keep the path: content address
        # check fails before any folding
        bad2 = json.loads(json.dumps(proof))
        bad2["envelope"]["payload"]["package_digest"] = "ff" * 32
        self.assertFalse(verify_inclusion_proof(bad2, self.secrets)["ok"])

    def test_missing_leaf_and_stale_checkpoint_fail_explicitly(self):
        self.seal_batch("b1", self.ta, self.tb)
        with self.assertRaises(TransparencyNotFound):
            self.g.tl_inclusion(5)
        with self.assertRaises(TransparencyCheckpointExpired):
            self.g.tl_inclusion(0, tree_size=99)
        with self.assertRaises(TransparencyNotFound):
            self.g.tl_inclusion(0, tree_size=0)  # leaf cannot exist at genesis
        with self.assertRaises(TransparencyNotFound):
            self.g.tl_lookup_event("release_sealed:pubv_doesnotexist")
        with self.assertRaises(TransparencyCheckpointExpired):
            self.g.tl_checkpoint(99)

    def test_event_key_replay_returns_original_leaf(self):
        vid, resp = self.seal_batch("b1", self.ta, self.tb)
        key = resp["transparency"]["event_key"]
        first = self.g.tl_lookup_event(key)
        self.assertEqual(first["leaf_index"], 0)
        # sealing an already-sealed version conflicts; re-fetch same key gives
        # the same leaf index forever
        again = self.g.tl_lookup_event(key)
        self.assertEqual(again["leaf_hash"], first["leaf_hash"])
        # share create replays: same share, no second leaf
        sh1 = self.make_share(vid)
        size_after = self.g.tl_state()["tree_size"]
        sh2 = self.g.create_share(vid, self.ta, all_catalog_fields(),
                                  ttl_seconds=999)
        self.assertEqual(sh1["share_id"], sh2["share_id"])
        self.assertEqual(self.g.tl_state()["tree_size"], size_after)
        # revoke is idempotent and produces no second revoke leaf
        self.g.revoke_share(sh1["share_id"])
        size2 = self.g.tl_state()["tree_size"]
        self.g.revoke_share(sh1["share_id"])
        self.assertEqual(self.g.tl_state()["tree_size"], size2)


class ConsistencyProofTests(TransparencyBase):
    def _grow(self, n_leaves):
        vid = None
        i = 0
        while self.g.tl_state()["tree_size"] < n_leaves:
            i += 1
            vid, _ = self.seal_batch(f"b{i}", self.ta, self.tb)
        return vid

    def test_consistency_all_pairs_verify_offline(self):
        self._grow(6)
        for m in range(7):
            for n in range(m, 7):
                rep = verify_consistency_proof(
                    self.g.tl_consistency(m, n), self.secrets)
                self.assertTrue(rep["ok"], (m, n, rep["errors"]))

    def test_genesis_consistency_is_empty_path(self):
        self._grow(2)
        c = self.g.tl_consistency(0, 2)
        self.assertEqual(c["old_path"], [])
        self.assertEqual(c["extension_path"], [])
        self.assertTrue(verify_consistency_proof(c, self.secrets)["ok"])

    def test_tampered_consistency_rejected(self):
        self._grow(4)
        c = self.g.tl_consistency(2, 4)
        self.assertTrue(verify_consistency_proof(c, self.secrets)["ok"])
        if c["extension_path"]:
            bad = json.loads(json.dumps(c))
            bad["extension_path"][0]["hash"] = "ab" * 32
            self.assertFalse(verify_consistency_proof(bad, self.secrets)["ok"])
        if c["old_path"]:
            bad = json.loads(json.dumps(c))
            bad["old_path"][0]["hash"] = "cd" * 32
            self.assertFalse(verify_consistency_proof(bad, self.secrets)["ok"])
        # a forged "new root" at the old size (fork) can never be proven to
        # extend the honest checkpoint
        forged = json.loads(json.dumps(c))
        forged["new_root_hash"] = "11" * 32
        forged["new_checkpoint"]["root_hash"] = "11" * 32
        import hashlib
        import hmac
        forged["new_checkpoint"]["sig"] = hmac.new(
            self.secrets["transparency_secret"],
            dumps_canon({k: x for k, x in forged["new_checkpoint"].items()
                         if k != "sig"}).encode(), hashlib.sha256).hexdigest()
        self.assertFalse(verify_consistency_proof(forged, self.secrets)["ok"])

    def test_reversed_sizes_rejected(self):
        self._grow(3)
        with self.assertRaises(TransparencyProofInvalid):
            self.g.tl_consistency(3, 2)


class ForkFreezeTests(TransparencyBase):
    def _signed_fork_cp(self, size, alt_root="11" * 32):
        import hashlib
        import hmac
        cp = self.g.tl_checkpoint(size)["checkpoint"]
        fake = dict(cp)
        fake["root_hash"] = alt_root
        fake["sig"] = hmac.new(
            self.secrets["transparency_secret"],
            dumps_canon({k: x for k, x in fake.items()
                         if k != "sig"}).encode(), hashlib.sha256).hexdigest()
        return cp, fake

    def test_fork_evidence_freezes_and_blocks_issuance(self):
        vid, _ = self.seal_batch("b1", self.ta, self.tb)
        sh = self.make_share(vid)
        live = self.make_share(vid, self.tg)  # second live package pre-freeze
        self.assertEqual(self.g.tl_state()["tree_size"], 3)
        cp, fake = self._signed_fork_cp(2)
        res = self.g.tl_submit_fork(cp, fake, actor="auditor", reason="split world")
        self.assertTrue(res["frozen"])
        self.assertEqual(res["reason"], "fork_evidence")
        st = self.g.tl_state()
        self.assertTrue(st["frozen"])
        self.assertEqual(st["freeze_reason"], "fork_evidence")

        size_after = st["tree_size"]
        # every issuing operation now fails 423 without changing the ledger
        v2 = self.create_batch("b2")
        self.g.register_contribution(v2["version_id"], self.ta)
        with self.assertRaises(TransparencyFrozen):
            self.g.seal_publication(v2["version_id"])
        # due-void is also refused even past close_at
        self.g.db.execute(
            "UPDATE pub_versions SET close_at=? WHERE version_id=?",
            (iso_ago(), v2["version_id"]))
        with self.assertRaises(TransparencyFrozen):
            self.g.void_publication(v2["version_id"])
        # a new sharing package on the sealed release is refused
        self.g.grant_share_fields(vid, self.tb, all_catalog_fields())
        with self.assertRaises(TransparencyFrozen):
            self.g.create_share(vid, self.tb, all_catalog_fields())
        # revoking the two still-live packages needs new leaves -> refused
        with self.assertRaises(TransparencyFrozen):
            self.g.revoke_share(sh["share_id"])
        with self.assertRaises(TransparencyFrozen):
            self.g.revoke_share(live["share_id"])
        self.assertEqual(self.g.tl_state()["tree_size"], size_after)
        self.assertEqual(
            self.g.db.execute("SELECT state FROM shares WHERE share_id=?",
                              (sh["share_id"],)).fetchone()["state"], "sealed")

        # reads and proofs keep working
        self.assertTrue(verify_inclusion_proof(
            self.g.tl_inclusion(0), self.secrets)["ok"])
        self.assertTrue(verify_consistency_proof(
            self.g.tl_consistency(0, size_after), self.secrets)["ok"])

    def test_fork_submission_validates_evidence_and_is_idempotent(self):
        vid, _ = self.seal_batch("b1", self.ta, self.tb)
        self.make_share(vid)
        cp, fake = self._signed_fork_cp(2)
        # same roots: not a fork
        with self.assertRaises(TransparencyProofInvalid):
            self.g.tl_submit_fork(cp, json.loads(json.dumps(cp)))
        # bad signature on one side
        badsig = dict(fake)
        badsig["sig"] = "00" * 32
        with self.assertRaises(TransparencyProofInvalid):
            self.g.tl_submit_fork(cp, badsig)
        # different heights
        other = self._signed_fork_cp(1)[1]
        with self.assertRaises(TransparencyProofInvalid):
            self.g.tl_submit_fork(cp, other)
        # genesis (size 0) cannot be fork evidence
        g0 = self.g.tl_checkpoint(0)["checkpoint"]
        g0fake = self._signed_fork_cp(0)[1]
        with self.assertRaises(TransparencyProofInvalid):
            self.g.tl_submit_fork(g0, g0fake)
        # nothing changed: log still writable
        self.assertFalse(self.g.tl_state()["frozen"])
        # genuine evidence freezes; a repeat submission reports same freeze
        self.g.tl_submit_fork(cp, fake)
        again = self.g.tl_submit_fork(cp, fake)
        self.assertTrue(again["frozen"])
        self.assertEqual(again["reason"], "fork_evidence")
        # the offline evidence checker agrees
        self.assertTrue(verify_fork_evidence(cp, fake, self.secrets)["ok"])
        self.assertFalse(verify_fork_evidence(cp, cp, self.secrets)["ok"])

    def test_deadline_sweep_and_lazy_settlement_do_not_issue_while_frozen(self):
        v = self.create_batch("b1", minp=2)
        self.g.register_contribution(v["version_id"], self.ta)
        self.g.register_contribution(v["version_id"], self.tb)
        self.g.db.execute(
            "UPDATE pub_versions SET close_at=? WHERE version_id=?",
            (iso_ago(), v["version_id"]))
        # freeze after one unrelated sealed release (height 1)
        self.seal_batch("other", self.ta, self.tg)
        cp, fake = self._signed_fork_cp(1)
        self.g.tl_submit_fork(cp, fake)
        size = self.g.tl_state()["tree_size"]
        report = self.g.sweep_due_publications(actor="admin")
        self.assertEqual(report["sealed"], [])
        self.assertEqual(report["void"], [])
        # lazy settlement on team touch also leaves the version collecting
        touched = self.g.register_contribution(v["version_id"], self.tg)
        self.assertEqual(touched["state"], "collecting")
        self.assertEqual(self.g.tl_state()["tree_size"], size)


class ConcurrencyTests(TransparencyBase):
    def test_concurrent_seals_issues_revokes_lose_no_leaves(self):
        # 6 batches each sealed by a different pair of teams, 6 packages and
        # revokes, all racing against checkpoint readers
        batches = []
        for i in range(6):
            v = self.create_batch(f"cb{i}", minp=2,
                                  city=("BJ" if i % 2 else "SH"))
            teams = [self.ta, self.tb] if i % 2 else [self.ta, self.tg]
            for t in teams:
                self.g.register_contribution(v["version_id"], t)
            batches.append(v["version_id"])

        errors: list[Exception] = []
        n_workers = len(batches) * 2 + 1  # seals + issue/revokes + reader
        seal_barrier = threading.Barrier(n_workers)
        share_barrier = threading.Barrier(n_workers)

        def seal(vid):
            try:
                seal_barrier.wait()
                self.g.seal_publication(vid)
                share_barrier.wait()
            except Exception as e:  # noqa: BLE001
                share_barrier.abort()
                errors.append(e)

        def issue_revoke(vid):
            try:
                seal_barrier.wait()
                share_barrier.wait()  # only cut packages once every seal landed
                self.g.grant_share_fields(vid, self.ta, all_catalog_fields())
                sh = self.g.create_share(vid, self.ta, all_catalog_fields(),
                                         ttl_seconds=3600)
                self.g.revoke_share(sh["share_id"])
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        def reader():
            try:
                seal_barrier.wait()
                share_barrier.wait()
                for _ in range(50):
                    st = self.g.tl_state()
                    # roots never regress: each read must fold from stored leaves
                    leaves = [bytes.fromhex(r[0]) for r in self.g.db.execute(
                        "SELECT leaf_hash FROM tl_leaves ORDER BY leaf_index")]
                    self.assertEqual(merkle_root(leaves).hex(), st["root_hash"])
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = []
        for vid in batches:
            threads.append(threading.Thread(target=seal, args=(vid,)))
            threads.append(threading.Thread(target=issue_revoke, args=(vid,)))
        threads.append(threading.Thread(target=reader))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

        # exact leaf set: 6 seals + 6 issues + 6 revokes, dense and unique
        self.assertEqual(self.g.tl_state()["tree_size"], 18)
        rows = self.g.db.execute(
            "SELECT leaf_index, event_key, COUNT(*) c FROM tl_leaves "
            "GROUP BY leaf_index, event_key").fetchall()
        indices = sorted(r["leaf_index"] for r in rows)
        self.assertEqual(indices, list(range(18)))
        keys = [r["event_key"] for r in rows]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertTrue(self.g.tl_verify_local_chain_locked()["ok"])
        self.assertEqual(self.g.db.execute(
            "SELECT COUNT(*) c FROM tl_outbox").fetchone()["c"], 0)
        # every consistency pair still verifies
        for m in range(19):
            rep = verify_consistency_proof(self.g.tl_consistency(m, 18),
                                           self.secrets)
            self.assertTrue(rep["ok"], rep["errors"])


class OutboxRecoveryTests(TransparencyBase):
    def test_interrupted_outbox_drains_in_fixed_order_on_restart(self):
        # commit three business changes but crash before the in-process drain
        # by temporarily neutralising tl_drain_locked, then reopen the gateway.
        vid, resp = self.seal_batch("b1", self.ta, self.tb)
        # the normal path already drained; simulate a crash window by directly
        # inserting post-commit outbox rows for new business states.
        original_drain = self.g.tl_drain_locked
        self.g.tl_drain_locked = lambda *a, **k: []  # process dies post-commit
        try:
            sh = self.make_share(vid)
            self.g.revoke_share(sh["share_id"])
        finally:
            self.g.tl_drain_locked = original_drain
        # two business transactions committed but their leaves are pending;
        # sealed/revoked state must already be durable
        self.assertEqual(self.g.db.execute(
            "SELECT state FROM shares WHERE share_id=?",
            (sh["share_id"],)).fetchone()["state"], "revoked")
        pending = [r["event_key"] for r in self.g.db.execute(
            "SELECT event_key FROM tl_outbox ORDER BY seq")]
        self.assertEqual(pending, [f"share_issued:{sh['share_id']}",
                                   f"share_revoked:{sh['share_id']}"])
        # readers during the crash window only see the old checkpoint (no
        # uncommitted leaf exposed), never a half-built tree
        self.assertEqual(self.g.tl_state()["tree_size"], 1)

        # restart: fixed-order drain completes the same single history
        self.g.db.close()
        gw2 = open_gateway(self.h.home)
        try:
            self.assertEqual(gw2.tl_state()["tree_size"], 3)
            self.assertEqual(gw2.db.execute(
                "SELECT COUNT(*) c FROM tl_outbox").fetchone()["c"], 0)
            leaves = [r["event_key"] for r in gw2.db.execute(
                "SELECT event_key FROM tl_leaves ORDER BY leaf_index")]
            self.assertEqual(leaves, [
                resp["transparency"]["event_key"],
                f"share_issued:{sh['share_id']}",
                f"share_revoked:{sh['share_id']}"])
            self.assertTrue(gw2.tl_verify_local_chain_locked()["ok"])
            for idx in range(3):
                self.assertTrue(verify_inclusion_proof(
                    gw2.tl_inclusion(idx), self.secrets)["ok"])
            # reopening again is a no-op (no second history)
        finally:
            gw2.db.close()
        gw3 = open_gateway(self.h.home)
        try:
            self.assertEqual(gw3.tl_state()["tree_size"], 3)
            self.assertEqual(gw3.db.execute(
                "SELECT COUNT(*) c FROM tl_leaves").fetchone()["c"], 3)
        finally:
            gw3.db.close()
        # keep one open connection for tearDown's close()
        self.g = open_gateway(self.h.home)

    def test_recovering_a_partially_incorporated_leaf_is_idempotent(self):
        vid, _ = self.seal_batch("b1", self.ta, self.tb)
        # fabricate a leaf row without its checkpoint (crash between the two):
        # recovery must not duplicate the leaf and must extend the chain
        row = self.g.db.execute(
            "SELECT * FROM tl_outbox ORDER BY seq LIMIT 1").fetchone()
        # outbox already drained in the happy path; emulate crash mid-drain by
        # appending one pending event and pre-inserting only the leaf
        self.g.tl_drain_locked = lambda *a, **k: []
        sh = self.make_share(vid)
        self.g.tl_drain_locked = self.g.__class__.tl_drain_locked
        pending = self.g.db.execute(
            "SELECT * FROM tl_outbox ORDER BY seq LIMIT 1").fetchone()
        self.g.db.execute(
            "INSERT INTO tl_leaves (leaf_index,event_key,event_type,leaf_hash,"
            "payload_hash,envelope_json,outbox_seq,incorporated_at) "
            "VALUES (1,?,?,?,?,?,?,?)",
            (pending["event_key"], pending["event_type"], pending["leaf_hash"],
             pending["payload_hash"], pending["envelope_json"], pending["seq"],
             "2026-01-01T00:00:00.000000Z"))
        self.g.db.close()
        gw2 = open_gateway(self.h.home)
        try:
            self.assertEqual(gw2.tl_state()["tree_size"], 2)
            self.assertEqual(gw2.db.execute(
                "SELECT COUNT(*) c FROM tl_leaves WHERE event_key=?",
                (pending["event_key"],)).fetchone()["c"], 1)
            self.assertTrue(gw2.tl_verify_local_chain_locked()["ok"])
        finally:
            gw2.db.close()
        self.g = open_gateway(self.h.home)

    def test_local_root_tamper_freezes_instead_of_appending(self):
        self.seal_batch("b1", self.ta, self.tb)
        # corrupt a stored leaf hash: integrity recovery detects it and freezes
        self.g.db.execute(
            "UPDATE tl_leaves SET leaf_hash=? WHERE leaf_index=0",
            ("aa" * 32,))
        report = self.g.recover_transparency_log()
        self.assertFalse(report["integrity"]["ok"])
        self.assertTrue(self.g.tl_state()["frozen"])
        self.assertEqual(self.g.tl_state()["freeze_reason"],
                         "local_integrity_failure")


class OfflineLedgerAndBundleTests(TransparencyBase):
    def test_verify_ledger_and_bundle_cover_transparency(self):
        vid, _ = self.seal_batch("b1", self.ta, self.tb)
        sh = self.make_share(vid)
        self.g.revoke_share(sh["share_id"])
        resp, _v2 = self.void_batch("b2")
        rep = verify_ledger(os.path.join(self.h.home, "gateway.sqlite"))
        self.assertTrue(rep["ok"], rep["problems"])
        self.assertEqual(rep["transparency"]["leaves"], 4)
        bundle = export_bundle(self.g)
        self.assertEqual(bundle["bundle_version"], "b5")
        brep = verify_bundle(bundle, self.secrets,
                             os.path.join(self.h.home, "snapshots"))
        self.assertTrue(brep["ok"], brep["ledger_problems"])
        self.assertEqual(brep["transparency"]["leaves_checked"], 4)
        self.assertEqual(brep["transparency"]["checkpoints_checked"], 5)

    def test_offline_ledger_flags_missing_leaf_for_sealed_release(self):
        vid, _ = self.seal_batch("b1", self.ta, self.tb)
        self.g.db.execute("DELETE FROM tl_leaves WHERE leaf_index=0")
        rep = verify_ledger(os.path.join(self.h.home, "gateway.sqlite"))
        self.assertFalse(rep["ok"])
        self.assertTrue(any("no leaf" in p for p in rep["problems"]),
                        rep["problems"])

    def test_offline_ledger_flags_undrained_outbox(self):
        vid, _ = self.seal_batch("b1", self.ta, self.tb)
        # a stray pending row means the durable outbox was not completed
        leaf = self.g.db.execute(
            "SELECT * FROM tl_leaves WHERE leaf_index=0").fetchone()
        self.g.db.execute(
            "INSERT INTO tl_outbox (event_key,event_type,leaf_hash,payload_hash,"
            "envelope_json,subject_id,created_at,actor) VALUES (?,?,?,?,?,?,?,?)",
            (leaf["event_key"] + ":stray", leaf["event_type"], leaf["leaf_hash"],
             leaf["payload_hash"], leaf["envelope_json"], "stray-subject",
             "2026-01-01T00:00:00.000000Z", "test"))
        rep = verify_ledger(os.path.join(self.h.home, "gateway.sqlite"))
        self.assertFalse(rep["ok"])
        self.assertTrue(any("outbox" in p for p in rep["problems"]))


class TransparencyHTTPTests(TransparencyBase):
    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        super().setUp()
        self.server = serve(self.g, "127.0.0.1", 0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def _req(self, method, path, body=None, token=None):
        import urllib.error
        data = json.dumps(body).encode() if body is not None else None
        headers = {}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_transparency_endpoints_and_freeze_status(self):
        vid, _ = self.seal_batch("b1", self.ta, self.tb)
        st, body = self._req("GET", "/v1/transparency", token=self.h.admin_token)
        self.assertEqual(st, 200)
        self.assertEqual(body["tree_size"], 1)
        # team token is enough for read-only proofs
        st, body = self._req("GET", "/v1/transparency/inclusion/0",
                             token=self.h.teams["alpha"]["token"])
        self.assertEqual(st, 200)
        self.assertTrue(verify_inclusion_proof(body, self.secrets)["ok"])
        st, body = self._req(
            "GET", "/v1/transparency/consistency?old_size=0&new_size=1",
            token=self.h.admin_token)
        self.assertEqual(st, 200)
        self.assertTrue(verify_consistency_proof(body, self.secrets)["ok"])
        st, body = self._req(
            "GET", f"/v1/transparency/events/release_sealed:{vid}",
            token=self.h.admin_token)
        self.assertEqual(st, 200)
        self.assertEqual(body["leaf_index"], 0)
        # error cases mapped over HTTP
        st, body = self._req("GET", "/v1/transparency/inclusion/9",
                             token=self.h.admin_token)
        self.assertEqual(st, 404)
        st, body = self._req(
            "GET", "/v1/transparency/consistency?old_size=0&new_size=99",
            token=self.h.admin_token)
        self.assertEqual(st, 410)
        # unauthenticated reads rejected
        st, _ = self._req("GET", "/v1/transparency")
        self.assertEqual(st, 401)
        # fork submission needs the admin token
        import hashlib
        import hmac
        cp = self.g.tl_checkpoint(1)["checkpoint"]
        fake = dict(cp)
        fake["root_hash"] = "22" * 32
        fake["sig"] = hmac.new(
            self.secrets["transparency_secret"],
            dumps_canon({k: x for k, x in fake.items()
                         if k != "sig"}).encode(), hashlib.sha256).hexdigest()
        st, body = self._req("POST", "/v1/admin/transparency/fork",
                             {"first": cp, "second": fake},
                             token=self.h.teams["alpha"]["token"])
        self.assertEqual(st, 401)
        st, body = self._req("POST", "/v1/admin/transparency/fork",
                             {"first": cp, "second": fake},
                             token=self.h.admin_token)
        self.assertEqual(st, 200)
        self.assertTrue(body["frozen"])
        # post-freeze seal over HTTP is 423
        v2 = self.create_batch("b2")
        self.g.register_contribution(v2["version_id"], self.ta)
        st, body = self._req(
            "POST", f"/v1/admin/publications/{v2['version_id']}/seal", {},
            token=self.h.admin_token)
        self.assertEqual(st, 423)
        self.assertEqual(body["error"], "transparency_frozen")


if __name__ == "__main__":
    unittest.main()
