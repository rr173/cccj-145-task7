"""Amendable joint publication batches: fixed specification, registration /
withdrawal holds, atomic sealing (one signed release), quorum, late
contributions, revisions with verifiable lineage, no double publishing /
double charging under concurrency, deadline sweep + restart recovery, and
offline recomputation of participation, attribution and signatures.
"""

import os
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))
from harness import Harness  # noqa: E402

from dpgw.app import open_gateway  # noqa: E402
from dpgw.errors import (  # noqa: E402
    BudgetExceeded,
    FrozenQuery,
    PublicationClosed,
    PublicationInvalid,
    PublicationStateConflict,
    QuorumNotMet,
    SnapshotInactive,
)
from dpgw.verify import (  # noqa: E402
    export_bundle,
    load_secrets,
    verify_bundle,
    verify_ledger,
    verify_publication_manifest,
)


def q(city, eps=0.3):
    return {"type": "count", "epsilon": eps,
            "filter": {"op": "cmp", "column": "city", "predicate": "=", "value": city}}


def stmt(sid, query):
    return {"snapshot": {"snapshot_id": sid}, "query": query}


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.snap, _, _ = self.h.publish("v1")
        self.sid = self.snap["snapshot_id"]
        for name, eps in (("alpha", 1.0), ("beta", 1.0), ("gamma", 1.0)):
            self.h.grant(name, self.sid, eps)
        self.ta = self.h.tid("alpha")
        self.tb = self.h.tid("beta")
        self.tg = self.h.tid("gamma")
        self.g = self.h.gw

    def tearDown(self):
        self.h.gw.db.close()
        self.h.tmp.cleanup()

    def close_in(self, seconds=3600):
        return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()

    def make_due(self, version_id):
        """Force a version's close_at into the past without lazy settlement."""
        past = (datetime.now(timezone.utc) - timedelta(seconds=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ")
        self.g.db.execute("UPDATE pub_versions SET close_at=? WHERE version_id=?",
                          (past, version_id))

    def create(self, name="weekly-joint", min_participants=2, statements=None,
               close_seconds=3600):
        statements = statements if statements is not None else [stmt(self.sid, q("BJ"))]
        return self.g.create_publication(
            name, statements, min_participants, self.close_in(close_seconds), actor="lead")

    def register_all(self, vid, *teams):
        for t in teams:
            self.g.register_contribution(vid, t)

    # ------------------------------------------------------------------ #

    def test_create_carries_fixed_spec_and_collecting_state(self):
        v = self.create(statements=[stmt(self.sid, q("BJ")),
                                    stmt(self.sid, q("SH", 0.2))])
        self.assertEqual(v["state"], "collecting")
        self.assertEqual(v["seq"], 1)
        self.assertIsNone(v["parent_version_id"])
        self.assertEqual(v["participant_count"], 0)
        self.assertFalse(v["quorum_met"])
        self.assertEqual(len(v["statements"]), 2)
        self.assertEqual(len(v["spec_hash"]), 64)

    def test_create_rejects_bad_arguments_and_inactive_snapshot(self):
        past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
        with self.assertRaises(PublicationInvalid):
            self.g.create_publication("p", [stmt(self.sid, q("BJ"))], 2, past)
        with self.assertRaises(PublicationInvalid):
            self.create(min_participants=0)
        with self.assertRaises(PublicationInvalid):
            self.create(statements=[])
        self.g.set_snapshot_active(self.sid, False, actor="lead")
        with self.assertRaises(SnapshotInactive):
            self.create()

    def test_register_holds_budget_duplicate_replays_free(self):
        v = self.create()
        r = self.g.register_contribution(v["version_id"], self.ta)
        self.assertEqual(r["registration"], "registered")
        self.assertEqual(r["participant_count"], 1)
        b = self.g.get_budget(self.ta, self.sid)
        self.assertAlmostEqual(b["epsilon_held"], 0.3)
        self.assertAlmostEqual(b["epsilon_remaining"], 0.7)

        r2 = self.g.register_contribution(v["version_id"], self.ta)
        self.assertEqual(r2["registration"], "replayed")
        self.assertEqual(r2["participant_count"], 1)
        b = self.g.get_budget(self.ta, self.sid)
        self.assertAlmostEqual(b["epsilon_held"], 0.3)  # no second hold

    def test_budget_insufficient_rejects_and_keeps_batch_and_ledger(self):
        # gamma only has 0.5 total budget
        self.g.allocate_budget(self.tg, self.sid, 0.5, 0.0, actor="lead")
        v = self.create(min_participants=1,
                        statements=[stmt(self.sid, q("BJ", eps=0.9))])
        before = self.g.get_budget(self.tg, self.sid)
        with self.assertRaises(BudgetExceeded):
            self.g.register_contribution(v["version_id"], self.tg)
        after = self.g.get_budget(self.tg, self.sid)
        self.assertEqual(before["epsilon_held"], after["epsilon_held"])
        self.assertEqual(self.g.get_publication(v["version_id"])["state"], "collecting")

    def test_withdraw_releases_hold_and_is_idempotent(self):
        v = self.create()
        self.g.register_contribution(v["version_id"], self.ta)
        w = self.g.withdraw_contribution(v["version_id"], self.ta)
        self.assertEqual(w["registration"], "withdrawn")
        self.assertEqual(w["participant_count"], 0)
        self.assertEqual(self.g.get_budget(self.ta, self.sid)["epsilon_held"], 0.0)
        # second withdraw replays, no error
        w2 = self.g.withdraw_contribution(v["version_id"], self.ta)
        self.assertEqual(w2["registration"], "withdrawn_replayed")
        # rejoin locks again
        r = self.g.register_contribution(v["version_id"], self.ta)
        self.assertEqual(r["registration"], "rejoined")
        self.assertEqual(self.g.get_budget(self.ta, self.sid)["epsilon_held"], 0.3)

    def test_seal_below_quorum_rejects_and_changes_nothing(self):
        v = self.create(min_participants=3)
        self.g.register_contribution(v["version_id"], self.ta)
        self.g.register_contribution(v["version_id"], self.tb)
        with self.assertRaises(QuorumNotMet):
            self.g.seal_publication(v["version_id"], actor="lead")
        fresh = self.g.get_publication(v["version_id"])
        self.assertEqual(fresh["state"], "collecting")
        self.assertEqual(self.g.get_budget(self.ta, self.sid)["epsilon_held"], 0.3)
        # rejection reason is surfaced with the version
        self.assertTrue(any(r["outcome"] == "reject_quorum" for r in fresh["rejections"]))

    def test_seal_produces_one_signed_release_and_charges_once(self):
        v = self.create(statements=[stmt(self.sid, q("BJ")),
                                    stmt(self.sid, q("SH", 0.2))])
        self.register_all(v["version_id"], self.ta, self.tb)
        sealed = self.g.seal_publication(v["version_id"], actor="lead")
        self.assertEqual(sealed["state"], "sealed")
        self.assertEqual(sealed["participant_count"], 2)
        manifest = sealed["manifest"]
        self.assertEqual(manifest["release_version"], "pr1")
        self.assertIn("sig", manifest)
        self.assertEqual(len(manifest["statements"]), 2)
        self.assertEqual(len(manifest["participants"]), 2)
        # dense 2 positions x 2 teams; 4 unique receipts
        self.assertEqual(len(manifest["members"]), 4)
        self.assertEqual(len(manifest["receipts"]), 4)
        # each team paid 0.5 once, holds released
        for tid in (self.ta, self.tb):
            b = self.g.get_budget(tid, self.sid)
            self.assertAlmostEqual(b["epsilon_spent"], 0.5)
            self.assertEqual(b["epsilon_held"], 0.0)
        # re-seal is a state conflict, never a second release
        with self.assertRaises(PublicationStateConflict):
            self.g.seal_publication(v["version_id"], actor="lead")
        # exactly one pub_sealed audit row
        n = [a for a in self.g.list_audit(limit=1000)
             if a["outcome"] == "pub_sealed" and a["detail"]["version_id"] == v["version_id"]]
        self.assertEqual(len(n), 1)

    def test_cached_statement_is_free_and_not_double_charged(self):
        # alpha already ran the query directly
        self.g.run_query(self.ta, {"snapshot_id": self.sid}, q("BJ"))
        v = self.create()
        self.register_all(v["version_id"], self.ta, self.tb)
        sealed = self.g.seal_publication(v["version_id"], actor="lead")
        alpha = next(p for p in sealed["manifest"]["participants"]
                     if p["team_id"] == self.ta)
        beta = next(p for p in sealed["manifest"]["participants"]
                    if p["team_id"] == self.tb)
        self.assertEqual(alpha["epsilon_charged"], 0.0)
        self.assertEqual(alpha["result_count"], 0)
        self.assertAlmostEqual(beta["epsilon_charged"], 0.3)
        self.assertAlmostEqual(self.g.get_budget(self.ta, self.sid)["epsilon_spent"], 0.3)

    def test_late_contribution_rejected_enters_next_version(self):
        v = self.create()
        self.register_all(v["version_id"], self.ta, self.tb)
        self.g.seal_publication(v["version_id"], actor="lead")
        with self.assertRaises(PublicationClosed):
            self.g.register_contribution(v["version_id"], self.tg)

    def test_amend_opens_new_version_with_same_spec_old_still_verifiable(self):
        v1 = self.create()
        self.register_all(v1["version_id"], self.ta, self.tb)
        s1 = self.g.seal_publication(v1["version_id"], actor="lead")

        v2 = self.g.amend_publication(v1["version_id"], self.close_in(), actor="lead")
        self.assertEqual(v2["seq"], 2)
        self.assertEqual(v2["parent_version_id"], v1["version_id"])
        self.assertEqual(v2["spec_hash"], v1["spec_hash"])
        self.assertEqual(v2["state"], "collecting")
        # late team joins v2; alpha's cached contribution registers for free
        self.g.register_contribution(v2["version_id"], self.tg)
        self.g.register_contribution(v2["version_id"], self.ta)
        s2 = self.g.seal_publication(v2["version_id"], actor="lead")
        self.assertEqual(s2["manifest"]["parent_manifest_digest"],
                         s1["manifest_digest"])
        lineage = self.g.list_lineage(v1["batch_id"])
        self.assertEqual([(x["seq"], x["state"]) for x in lineage],
                         [(1, "sealed"), (2, "sealed")])
        # only one open version allowed: cannot amend while collecting child exists
        v3 = self.g.amend_publication(v2["version_id"], self.close_in(), actor="lead")
        with self.assertRaises(PublicationStateConflict):
            self.g.amend_publication(v2["version_id"], self.close_in(), actor="lead")
        self.assertEqual(v3["seq"], 3)
        # sealed revisions are listed in the lineage view
        sealed = self.g.list_publications(state="sealed")
        self.assertEqual(sorted({p["batch_name"] for p in sealed}), ["weekly-joint"])

    def test_amend_requires_sealed_parent(self):
        v = self.create()
        with self.assertRaises(PublicationStateConflict):
            self.g.amend_publication(v["version_id"], self.close_in(), actor="lead")

    def test_deadline_below_quorum_voids_and_releases_holds(self):
        # due + quorum already met: a team touch lazily seals, late join rejected
        v = self.create(min_participants=1)
        self.g.register_contribution(v["version_id"], self.ta)
        self.make_due(v["version_id"])
        with self.assertRaises(PublicationClosed):
            self.g.register_contribution(v["version_id"], self.tb)
        self.assertEqual(self.g.get_publication(v["version_id"])["state"], "sealed")

        # genuinely below-quorum: one registration, quorum 2 -> void
        v2 = self.create(name="lone-batch")
        self.g.register_contribution(v2["version_id"], self.ta)
        self.make_due(v2["version_id"])
        with self.assertRaises(PublicationClosed):
            self.g.register_contribution(v2["version_id"], self.ta)
        fresh = self.g.get_publication(v2["version_id"])
        self.assertEqual(fresh["state"], "void")
        self.assertEqual(self.g.get_budget(self.ta, self.sid)["epsilon_held"], 0.0)
        with self.assertRaises(PublicationStateConflict):
            self.g.seal_publication(v2["version_id"], actor="lead")

    def test_deadline_with_quorum_auto_seals(self):
        v = self.create()
        self.register_all(v["version_id"], self.ta, self.tb)
        self.make_due(v["version_id"])
        rep = self.g.sweep_due_publications(actor="cron")
        self.assertEqual(rep["sealed"], [v["version_id"]])
        self.assertEqual(self.g.get_publication(v["version_id"])["state"], "sealed")

    def test_seal_aborts_on_frozen_family_snapshot_inactive_and_holds_intact(self):
        v = self.create()
        self.register_all(v["version_id"], self.ta, self.tb)
        plan = self.g.plan(self.ta, {"snapshot_id": self.sid}, q("BJ"))
        self.g.freeze_family(plan["family_id"], scope="global",
                             reason="combination suspected", actor="lead")
        with self.assertRaises(FrozenQuery):
            self.g.seal_publication(v["version_id"], actor="lead")
        fresh = self.g.get_publication(v["version_id"])
        self.assertEqual(fresh["state"], "collecting")
        self.assertAlmostEqual(self.g.get_budget(self.ta, self.sid)["epsilon_held"], 0.3)
        self.assertTrue(any(r["outcome"] == "reject_frozen" for r in fresh["rejections"]))
        # no results were published
        self.assertEqual(self.g.list_results(self.ta, self.sid), [])

    def test_seal_aborts_when_snapshot_deactivated_between_register_and_seal(self):
        v = self.create()
        self.register_all(v["version_id"], self.ta, self.tb)
        self.g.set_snapshot_active(self.sid, False, actor="lead")
        with self.assertRaises(SnapshotInactive):
            self.g.seal_publication(v["version_id"], actor="lead")
        fresh = self.g.get_publication(v["version_id"])
        self.assertEqual(fresh["state"], "collecting")
        # ledger untouched: holds still in place, no spend
        self.assertAlmostEqual(self.g.get_budget(self.ta, self.sid)["epsilon_held"], 0.3)
        self.assertEqual(self.g.get_budget(self.ta, self.sid)["epsilon_spent"], 0.0)
        self.assertEqual(self.g.list_results(self.ta, self.sid), [])

    def test_recover_open_publications_after_restart(self):
        v_open = self.create(name="open-batch")
        v_due = self.create(name="due-batch")
        self.g.register_contribution(v_due["version_id"], self.ta)
        self.g.register_contribution(v_due["version_id"], self.tb)
        self.g.register_contribution(v_open["version_id"], self.ta)
        # close the one version without touching it: recovery must settle it
        self.make_due(v_due["version_id"])
        gw2 = open_gateway(self.h.home)
        self.assertEqual(gw2.get_publication(v_due["version_id"])["state"], "sealed")
        openv = gw2.get_publication(v_open["version_id"])
        self.assertEqual(openv["state"], "collecting")
        self.assertEqual(openv["participant_count"], 1)
        # can still complete it after restart
        gw2.register_contribution(v_open["version_id"], self.tb)
        s = gw2.seal_publication(v_open["version_id"], actor="lead")
        self.assertEqual(s["state"], "sealed")

    def test_concurrent_registration_and_seal_no_double_publish_or_charge(self):
        v = self.create()
        errors = []

        def reg(tid):
            try:
                self.g.register_contribution(v["version_id"], tid)
            except Exception as e:  # late rejections after seal are expected
                errors.append(e)

        t1 = threading.Thread(target=reg, args=(self.ta,))
        t2 = threading.Thread(target=reg, args=(self.tb,))
        t1.start(); t2.start()
        t1.join(); t2.join()
        sealed = self.g.seal_publication(v["version_id"], actor="lead")
        self.assertEqual(sealed["state"], "sealed")
        # hammer duplicate registrations post-seal: all late, none charged twice
        threads = [threading.Thread(target=reg, args=(tid,))
                   for tid in (self.ta, self.tb, self.tg) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for tid in (self.ta, self.tb):
            self.assertAlmostEqual(self.g.get_budget(tid, self.sid)["epsilon_spent"], 0.3)
        # gamma never spent anything (late)
        self.assertEqual(self.g.get_budget(self.tg, self.sid)["epsilon_spent"], 0.0)
        # one result per team, one manifest row
        n_man = self.g.db.execute(
            "SELECT COUNT(*) c FROM pub_versions WHERE version_id=? AND state='sealed'",
            (v["version_id"],)).fetchone()["c"]
        self.assertEqual(n_man, 1)

    def test_concurrent_seal_single_winner(self):
        v = self.create()
        self.register_all(v["version_id"], self.ta, self.tb)
        outcomes = []

        def seal():
            try:
                self.g.seal_publication(v["version_id"], actor="lead")
                outcomes.append("sealed")
            except Exception:
                outcomes.append("conflict")

        threads = [threading.Thread(target=seal) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(outcomes.count("sealed"), 1)
        self.assertEqual(outcomes.count("conflict"), 5)
        for tid in (self.ta, self.tb):
            self.assertAlmostEqual(self.g.get_budget(tid, self.sid)["epsilon_spent"], 0.3)

    # ------------------------------------------------------------------ #
    # offline verification
    # ------------------------------------------------------------------ #

    def test_offline_manifest_ledger_and_bundle_recompute(self):
        v1 = self.create(statements=[stmt(self.sid, q("BJ")),
                                     stmt(self.sid, q("SH", 0.2))])
        self.register_all(v1["version_id"], self.ta, self.tb)
        s1 = self.g.seal_publication(v1["version_id"], actor="lead")
        v2 = self.g.amend_publication(v1["version_id"], self.close_in(), actor="lead")
        self.register_all(v2["version_id"], self.tg, self.ta)
        s2 = self.g.seal_publication(v2["version_id"], actor="lead")

        secrets_ = load_secrets(os.path.join(self.h.home, "secrets.json"))
        snap_dir = os.path.join(self.h.home, "snapshots", self.sid)

        rep1 = verify_publication_manifest(s1["manifest"], secrets_, None,
                                           {self.sid: snap_dir})
        self.assertTrue(rep1["ok"], rep1["errors"])
        self.assertEqual(rep1["teams"], 2)
        self.assertEqual(rep1["members"], 4)

        # v2 lineage: parent digest must match v1
        rep2 = verify_publication_manifest(
            s2["manifest"], secrets_, None, {self.sid: snap_dir},
            parent_digest=s1["manifest_digest"])
        self.assertTrue(rep2["ok"], rep2["errors"])
        bad = verify_publication_manifest(
            s2["manifest"], secrets_, None, {self.sid: snap_dir},
            parent_digest="0" * 64)
        self.assertFalse(bad["ok"])

        ledger = verify_ledger(os.path.join(self.h.home, "gateway.sqlite"))
        self.assertTrue(ledger["ok"], ledger["problems"])
        self.assertGreaterEqual(ledger["pub_versions_checked"], 2)

        bundle = export_bundle(self.g)
        brep = verify_bundle(bundle, secrets_, None, {self.sid: snap_dir})
        self.assertTrue(brep["ok"], brep["ledger_problems"])
        self.assertEqual(brep["publications_checked"], 2)

    def test_tampered_release_value_fails_offline_verification(self):
        v = self.create()
        self.register_all(v["version_id"], self.ta, self.tb)
        s = self.g.seal_publication(v["version_id"], actor="lead")
        secrets_ = load_secrets(os.path.join(self.h.home, "secrets.json"))
        snap_dir = os.path.join(self.h.home, "snapshots", self.sid)
        tampered = dict(s["manifest"])
        tampered["receipts"] = [dict(r, values=[v_ + 1.0 for v_ in r["values"]])
                                for r in tampered["receipts"]]
        rep = verify_publication_manifest(tampered, secrets_, None,
                                          {self.sid: snap_dir})
        self.assertFalse(rep["ok"])

    def test_duplicate_statement_positions_paid_once_even_if_first_cached(self):
        # alpha pre-runs the query: the first duplicate position is a cache hit
        self.g.run_query(self.ta, {"snapshot_id": self.sid}, q("BJ", 0.3))
        # same canonical query appears twice in the fixed specification
        v = self.create(statements=[stmt(self.sid, q("BJ", 0.3)),
                                    stmt(self.sid, q("BJ", 0.3))])
        self.register_all(v["version_id"], self.ta, self.tb)
        sealed = self.g.seal_publication(v["version_id"], actor="lead")
        self.assertEqual(sealed["state"], "sealed")
        # alpha paid nothing (both cached), beta paid once for the duplicate pair
        self.assertAlmostEqual(self.g.get_budget(self.ta, self.sid)["epsilon_spent"], 0.3)
        self.assertAlmostEqual(self.g.get_budget(self.tb, self.sid)["epsilon_spent"], 0.3)
        beta = next(p for p in sealed["manifest"]["participants"]
                    if p["team_id"] == self.tb)
        self.assertAlmostEqual(beta["epsilon_charged"], 0.3)
        # dense grid: both positions attributed for both teams
        self.assertEqual(len(sealed["manifest"]["members"]), 4)

    def test_pub_holds_count_against_single_query_and_jobs(self):
        v = self.create(statements=[stmt(self.sid, q("BJ", eps=0.8))])
        self.g.register_contribution(v["version_id"], self.ta)
        # only 0.2 remains: a concurrent direct query for 0.3 must be rejected
        with self.assertRaises(BudgetExceeded):
            self.g.run_query(self.ta, {"snapshot_id": self.sid}, q("SH", 0.3))
        # after withdrawal the budget is available again
        self.g.withdraw_contribution(v["version_id"], self.ta)
        res = self.g.run_query(self.ta, {"snapshot_id": self.sid}, q("SH", 0.3))
        self.assertFalse(res["cached"])


if __name__ == "__main__":
    unittest.main()
