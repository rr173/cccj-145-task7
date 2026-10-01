"""End-to-end gateway semantics."""

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from harness import Harness  # noqa: E402

from dpgw.errors import (  # noqa: E402
    BudgetExceeded,
    FrozenQuery,
    SnapshotInactive,
)
from dpgw.verify import (  # noqa: E402
    export_bundle,
    load_secrets,
    verify_bundle,
    verify_ledger,
    verify_receipt,
)

COUNT_BJ = {"type": "count", "epsilon": 0.5,
            "filter": {"op": "cmp", "column": "city", "predicate": "=", "value": "BJ"}}
COUNT_BJ_ALT = {"type": "count", "epsilon": 0.5,
                "filter": {"op": "and", "args": [
                    {"op": "cmp", "column": "city", "predicate": "=", "value": "BJ"}]}}
COUNT_SH = {"type": "count", "epsilon": 0.5,
            "filter": {"op": "cmp", "column": "city", "predicate": "=", "value": "SH"}}
GROUP_CITY = {"type": "grouped_count", "epsilon": 0.5, "group_by": ["city"]}
HIST_SAL = {"type": "histogram", "epsilon": 0.5, "column": "salary"}


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.snap, self.manifest, self.snap_dir = self.h.publish("v1")
        self.sid = self.snap["snapshot_id"]
        self.h.grant("alpha", self.sid, 1.0)
        self.h.grant("beta", self.sid, 0.4)

    def tearDown(self):
        self.h.gw.db.close()
        self.h.tmp.cleanup()

    # ---------------------------------------------------------------- #

    def test_count_true_value_matches_data(self):
        r = self.h.gw.run_query(self.h.tid("alpha"), {"snapshot_id": self.sid}, COUNT_BJ)
        # 3 BJ rows; noisy value within generous bound of 3
        self.assertEqual(r["dimension"], 1)
        self.assertAlmostEqual(r["values"][0], 3, delta=20)
        self.assertTrue(r["charged"])
        self.assertFalse(r["cached"])

    def test_retry_is_same_result_and_free(self):
        g = self.h.gw
        tid = self.h.tid("alpha")
        r1 = g.run_query(tid, {"snapshot_id": self.sid}, COUNT_BJ)
        spent_after_first = g.get_budget(tid, self.sid)["epsilon_spent"]
        self.assertEqual(spent_after_first, 0.5)

        # semantically identical filter shape (AND with one child) -> same hash
        r2 = g.run_query(tid, {"snapshot_id": self.sid}, COUNT_BJ_ALT)
        self.assertEqual(r1["result_id"], r2["result_id"])
        self.assertEqual(r1["values"], r2["values"])
        self.assertTrue(r2["cached"])
        self.assertFalse(r2["charged"])
        spent_after_retry = g.get_budget(tid, self.sid)["epsilon_spent"]
        self.assertEqual(spent_after_first, spent_after_retry)

        # direct replay endpoint also works
        r3 = g.get_result(tid, r1["result_id"])
        self.assertEqual(r3["values"], r1["values"])

    def test_distinct_query_charges_distinct_budget(self):
        g = self.h.gw
        tid = self.h.tid("alpha")
        g.run_query(tid, {"snapshot_id": self.sid}, COUNT_BJ)
        g.run_query(tid, {"snapshot_id": self.sid}, COUNT_SH)
        self.assertEqual(g.get_budget(tid, self.sid)["epsilon_spent"], 1.0)

    def test_concurrent_same_query_charges_once(self):
        g = self.h.gw
        tid = self.h.tid("alpha")
        results = []
        errors = []

        def fire():
            try:
                results.append(g.run_query(tid, {"snapshot_id": self.sid}, COUNT_BJ))
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=fire) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 12)
        ids = {r["result_id"] for r in results}
        self.assertEqual(len(ids), 1)
        self.assertEqual(sum(1 for r in results if r["charged"]), 1)
        self.assertEqual(g.get_budget(tid, self.sid)["epsilon_spent"], 0.5)

    def test_concurrent_distinct_queries_never_overspend(self):
        g = self.h.gw
        tid = self.h.tid("beta")  # 0.4 initially
        # raise to 0.6: exactly one 0.5 query can fit, the other must reject
        g.allocate_budget(tid, self.sid, 0.6, 0.0, actor="test")
        accepted, rejected_budget, other = [], [], []
        lock = threading.Lock()

        def fire(age):
            q = {"type": "count", "epsilon": 0.5,
                 "filter": {"op": "cmp", "column": "age",
                            "predicate": ">", "value": age}}
            try:
                r = g.run_query(tid, {"snapshot_id": self.sid}, q)
                with lock:
                    accepted.append(r)
            except BudgetExceeded:
                with lock:
                    rejected_budget.append(True)
            except Exception:
                with lock:
                    other.append(True)

        threads = [threading.Thread(target=fire, args=(a,)) for a in (20, 60)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(other, [])
        self.assertEqual(len(accepted), 1)
        self.assertEqual(len(rejected_budget), 1)
        b = g.get_budget(tid, self.sid)
        self.assertEqual(b["epsilon_spent"], 0.5)  # never 1.0

    def test_failed_invalid_query_charges_nothing(self):
        g = self.h.gw
        tid = self.h.tid("alpha")
        with self.assertRaises(Exception):
            g.run_query(tid, {"snapshot_id": self.sid},
                        {"type": "count", "epsilon": 0.5,
                         "filter": {"op": "cmp", "column": "nope",
                                    "predicate": "=", "value": 1}})
        self.assertEqual(g.get_budget(tid, self.sid)["epsilon_spent"], 0.0)

    def test_no_budget_rejected_not_charged(self):
        g = self.h.gw
        # gamma has no allocation at all
        tid = self.h.tid("gamma")
        with self.assertRaises(BudgetExceeded):
            g.run_query(tid, {"snapshot_id": self.sid}, COUNT_BJ)
        audit = g.list_audit(team_id=tid)
        self.assertTrue(any(a["outcome"] == "reject_budget" for a in audit))

    def test_insufficient_budget_partial_is_not_consumed(self):
        g = self.h.gw
        tid = self.h.tid("beta")  # 0.4 < 0.5
        with self.assertRaises(BudgetExceeded):
            g.run_query(tid, {"snapshot_id": self.sid}, COUNT_BJ)
        self.assertEqual(g.get_budget(tid, self.sid)["epsilon_spent"], 0.0)

    def test_grouped_counts_cover_fixed_domain_plus_overflow(self):
        g = self.h.gw
        tid = self.h.tid("alpha")
        r = g.run_query(tid, {"snapshot_id": self.sid}, GROUP_CITY)
        labels = r["coords"]
        self.assertEqual(labels[:3], ['["BJ"]', '["SH"]', '["SZ"]'])
        self.assertEqual(labels[-1], "__other__")
        true_sums = None  # noisy; structural check only
        self.assertEqual(r["dimension"], 4)

    def test_histogram_bins_plus_null(self):
        g = self.h.gw
        tid = self.h.tid("alpha")
        r = g.run_query(tid, {"snapshot_id": self.sid}, HIST_SAL)
        self.assertEqual(
            r["coords"],
            ["(-inf,100.0)", "[100.0,200.0)", "[200.0,+inf)", "__null__"],
        )

    def test_freeze_blocks_unexecuted_but_keeps_cached_and_audit(self):
        g = self.h.gw
        tid = self.h.tid("alpha")
        r = g.run_query(tid, {"snapshot_id": self.sid}, COUNT_BJ)
        fam = r["family_id"]

        g.freeze_family(fam, scope="global", reason="suspected reconstruction")

        # same canonical query -> still cached, still free, despite freeze
        rcached = g.run_query(tid, {"snapshot_id": self.sid}, COUNT_BJ_ALT)
        self.assertTrue(rcached["cached"])
        self.assertEqual(rcached["values"], r["values"])

        # a *different* query of the same family is uniformly rejected
        with self.assertRaises(FrozenQuery):
            g.run_query(tid, {"snapshot_id": self.sid}, COUNT_SH)
        self.assertEqual(g.get_budget(tid, self.sid)["epsilon_spent"], 0.5)

        # the executed result remains fetchable and audited
        got = g.get_result(tid, r["result_id"])
        self.assertEqual(got["result_id"], r["result_id"])
        fam_audit = g.list_audit(family_id=fam)
        outcomes = {a["outcome"] for a in fam_audit}
        self.assertIn("ok_executed", outcomes)
        self.assertIn("reject_frozen", outcomes)

    def test_team_scoped_freeze_does_not_hit_other_team(self):
        g = self.h.gw
        a, b = self.h.tid("alpha"), self.h.tid("beta")
        plan = g.plan(a, {"snapshot_id": self.sid}, COUNT_BJ)
        g.freeze_family(plan["family_id"], scope="team", team_id=a, reason="x")
        with self.assertRaises(FrozenQuery):
            g.run_query(a, {"snapshot_id": self.sid}, COUNT_BJ)
        # beta not covered by the team freeze (but has too little budget anyway;
        # freeze check happens before budget check so assert not FrozenQuery)
        try:
            g.run_query(b, {"snapshot_id": self.sid}, COUNT_BJ)
        except FrozenQuery:
            self.fail("team-scoped freeze leaked to another team")
        except BudgetExceeded:
            pass

    def test_snapshot_replacement_old_cache_verifiable_new_budget_isolated(self):
        g = self.h.gw
        tid = self.h.tid("alpha")
        old = g.run_query(tid, {"snapshot_id": self.sid}, COUNT_BJ)

        # publish v2 with different rows -> different content id
        snap2, _, snap2_dir = self.h.publish("v2", rows=[
            (1, "BJ", "eng", 90, 28, True),
            (2, "SH", "sales", 120, 29, True),
        ])
        sid2 = snap2["snapshot_id"]
        self.assertNotEqual(sid2, self.sid)

        # deactivate old snapshot
        g.set_snapshot_active(self.sid, False, actor="test")

        # old cached result still retrievable and verifiable
        replay = g.get_result(tid, old["result_id"])
        secrets_ = load_secrets(os.path.join(self.h.home, "secrets.json"))
        rep = verify_receipt(replay["receipt"], secrets_, self.snap_dir)
        self.assertTrue(rep["ok"], rep["errors"])

        # but no NEW query may run against the old snapshot (no bypass via old cache)
        with self.assertRaises(SnapshotInactive):
            g.run_query(tid, {"snapshot_id": self.sid}, COUNT_SH)

        # new snapshot starts with NO budget for alpha until granted
        with self.assertRaises(BudgetExceeded):
            g.run_query(tid, {"snapshot_id": sid2}, COUNT_BJ)
        g.allocate_budget(tid, sid2, 1.0, 0.0, actor="test")
        r2 = g.run_query(tid, {"snapshot_id": sid2}, COUNT_BJ)
        self.assertFalse(r2["cached"])
        # same logical query, different snapshot -> different noise/value
        self.assertNotEqual(r2["values"], old["values"])
        # old budget untouched by v2 spend and vice versa
        self.assertEqual(g.get_budget(tid, self.sid)["epsilon_spent"], 0.5)
        self.assertEqual(g.get_budget(tid, sid2)["epsilon_spent"], 0.5)

    def test_offline_bundle_and_ledger_verification(self):
        g = self.h.gw
        tid = self.h.tid("alpha")
        r1 = g.run_query(tid, {"snapshot_id": self.sid}, COUNT_BJ)
        g.run_query(tid, {"snapshot_id": self.sid}, GROUP_CITY)

        bundle = export_bundle(g)
        secrets_ = load_secrets(os.path.join(self.h.home, "secrets.json"))
        report = verify_bundle(bundle, secrets_,
                               snapshots_dir=os.path.join(self.h.home, "snapshots"))
        self.assertTrue(report["ok"], report["ledger_problems"])
        for rr in report["receipt_reports"]:
            self.assertTrue(rr["ok"], rr["errors"])

        ledger = verify_ledger(os.path.join(self.h.home, "gateway.sqlite"))
        self.assertTrue(ledger["ok"], ledger["problems"])

    def test_verify_detects_tampered_values(self):
        import shutil
        import sqlite3

        g = self.h.gw
        tid = self.h.tid("alpha")
        r = g.run_query(tid, {"snapshot_id": self.sid}, COUNT_BJ)
        receipt = dict(r["receipt"])

        # signature is still valid; tamper the underlying snapshot rows instead
        bad_dir = os.path.join(self.h.root, "tampered_snap")
        shutil.copytree(self.snap_dir, bad_dir)
        db_file = os.path.join(bad_dir, "data.sqlite")
        os.chmod(db_file, 0o644)
        conn = sqlite3.connect(db_file)
        conn.execute("UPDATE data SET city='BJ' WHERE id=4")  # add a BJ row
        conn.commit()
        conn.close()

        secrets_ = load_secrets(os.path.join(self.h.home, "secrets.json"))
        rep = verify_receipt(receipt, secrets_, bad_dir)
        self.assertFalse(rep["ok"])
        self.assertTrue(rep["checks"]["signature"])
        self.assertFalse(rep["checks"]["snapshot_integrity"])
        self.assertFalse(rep["checks"]["values_reproduced"])

    def test_verify_detects_tampered_signature(self):
        g = self.h.gw
        tid = self.h.tid("alpha")
        r = g.run_query(tid, {"snapshot_id": self.sid}, COUNT_BJ)
        receipt = dict(r["receipt"])
        receipt["sig"] = "0" * 64
        secrets_ = load_secrets(os.path.join(self.h.home, "secrets.json"))
        rep = verify_receipt(receipt, secrets_, self.snap_dir)
        self.assertFalse(rep["ok"])
        self.assertFalse(rep["checks"]["signature"])

    def test_plan_is_free_and_reports_cost_freeze_cache(self):
        g = self.h.gw
        tid = self.h.tid("alpha")
        plan = g.plan(tid, {"snapshot_id": self.sid}, COUNT_BJ)
        self.assertEqual(plan["estimated_cost"], {"epsilon": 0.5, "delta": 0.0})
        self.assertEqual(plan["sensitivity_l1"], 1.0)
        self.assertFalse(plan["already_cached"])
        self.assertFalse(plan["frozen"])
        # planning didn't charge anything
        self.assertEqual(g.get_budget(tid, self.sid)["epsilon_spent"], 0.0)
        g.run_query(tid, {"snapshot_id": self.sid}, COUNT_BJ)
        plan2 = g.plan(tid, {"snapshot_id": self.sid}, COUNT_BJ_ALT)
        self.assertTrue(plan2["already_cached"])

    def test_audit_records_all_outcomes(self):
        g = self.h.gw
        tid = self.h.tid("alpha")
        g.run_query(tid, {"snapshot_id": self.sid}, COUNT_BJ)
        with self.assertRaises(BudgetExceeded):
            g.run_query(self.h.tid("beta"), {"snapshot_id": self.sid}, COUNT_BJ)
        rows = g.list_audit(team_id=tid)
        self.assertTrue(any(r["outcome"] == "ok_executed" for r in rows))
        # every audit row has timestamp + action
        for r in rows:
            self.assertTrue(r["ts"])
            self.assertTrue(r["action"])


if __name__ == "__main__":
    unittest.main()
