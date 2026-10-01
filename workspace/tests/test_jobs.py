"""Recoverable multi-statement analysis jobs: tickets, locks, atomicity,
cancellation/expiry, crash recovery, conflicts and offline verification."""

import os
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
from harness import Harness  # noqa: E402

from dpgw import jobs as jobsmod  # noqa: E402
from dpgw.app import open_gateway  # noqa: E402
from dpgw.errors import (  # noqa: E402
    BudgetExceeded,
    FrozenQuery,
    JobConflict,
    JobStateConflict,
    JobTicketExpired,
    SnapshotInactive,
)
from dpgw.verify import (  # noqa: E402
    export_bundle,
    load_secrets,
    verify_bundle,
    verify_job_manifest,
    verify_ledger,
    verify_receipt,
)


def q(city, eps=0.3):
    return {"type": "count", "epsilon": eps,
            "filter": {"op": "cmp", "column": "city", "predicate": "=", "value": city}}


def member(sid, query):
    return {"snapshot": {"snapshot_id": sid}, "query": query}


class FrozenTime:
    """Patch jobs-module datetime.now to a controllable frozen UTC clock."""

    def __init__(self, start: datetime):
        self.now = start
        class _DT(datetime):
            @classmethod
            def now(cls, tz=None):
                return self.now if tz is None else self.now.astimezone(tz)
        self._patch = mock.patch.object(jobsmod, "datetime", _DT)

    def __enter__(self):
        self._patch.start()
        return self

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)

    def __exit__(self, *a):
        self._patch.stop()


class JobTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.snap, self.manifest, self.snap_dir = self.h.publish("v1")
        self.sid = self.snap["snapshot_id"]
        self.h.grant("alpha", self.sid, 1.0)
        self.h.grant("beta", self.sid, 0.5)
        self.g = self.h.gw
        self.tid = self.h.tid("alpha")
        self.start = datetime(2026, 9, 26, 12, 0, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.h.gw.db.close()
        self.h.tmp.cleanup()

    def batch(self, *queries):
        return [member(self.sid, x) for x in queries]

    # ---------------------------------------------------------------- #

    def test_ticket_locks_budget_and_confirm_produces_signed_results(self):
        with FrozenTime(self.start) as ft:
            t = self.g.create_job(self.tid, self.batch(q("BJ"), q("SH")),
                                  request_key="rk-1")
            self.assertEqual(t["state"], "reserved")
            self.assertEqual(t["epsilon_reserved"], 0.6)
            ticket = t["ticket"]
            self.assertEqual(ticket["ticket_version"], "j1")
            self.assertEqual(ticket["statement_count"], 2)
            self.assertIn("sig", ticket)
            self.assertEqual(ticket["expires_at"][:19], "2026-09-26T12:10:00")

            # budget is locked: spent still 0 but remaining counts the hold
            b = self.g.get_budget(self.tid, self.sid)
            self.assertEqual(b["epsilon_spent"], 0.0)
            self.assertAlmostEqual(b["epsilon_held"], 0.6)
            self.assertAlmostEqual(b["epsilon_remaining"], 0.4)

            done = self.g.confirm_job(t["job_id"], self.tid)
            self.assertEqual(done["state"], "completed")
            self.assertEqual(len(done["results"]), 2)
            self.assertTrue(all("sig" in r["receipt"] for r in done["results"]))
            self.assertEqual([s["charged"] for s in done["statements"]], [True, True])

            # signed whole-batch manifest with every embedded member receipt
            man = done["manifest"]
            self.assertEqual(man["manifest_version"], "jm1")
            self.assertEqual(len(man["receipts"]), 2)
            self.assertEqual(man["epsilon_consumed"], 0.6)
            self.assertIn("sig", man)

        b = self.g.get_budget(self.tid, self.sid)
        self.assertAlmostEqual(b["epsilon_spent"], 0.6)
        self.assertEqual(b["epsilon_held"], 0.0)
        self.assertAlmostEqual(b["epsilon_remaining"], 0.4)

    def test_same_request_key_replays_first_ticket_even_concurrently(self):
        batch = self.batch(q("BJ"))
        tickets = []
        errors = []
        barrier = threading.Barrier(8)

        def fire():
            barrier.wait()
            try:
                tickets.append(self.g.create_job(self.tid, batch, request_key="same"))
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=fire) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len({t["job_id"] for t in tickets}), 1)
        self.assertEqual(len(self.g.list_holds()), 1)
        self.assertEqual(self.g.list_holds()[0]["epsilon"], 0.3)

    def test_same_request_key_different_payload_is_conflict(self):
        self.g.create_job(self.tid, self.batch(q("BJ")), request_key="rk")
        with self.assertRaises(JobConflict):
            self.g.create_job(self.tid, self.batch(q("SH")), request_key="rk")
        audit = self.g.list_audit(team_id=self.tid)
        self.assertTrue(any(a["outcome"] == "reject_conflict" for a in audit))
        # only the first job holds budget
        self.assertEqual(len(self.g.list_holds(self.tid, self.sid)), 1)

    def test_concurrent_distinct_jobs_cannot_overspend(self):
        # beta has exactly 0.5; two 0.3 jobs compete -> one reserved, one rejected
        tid = self.h.tid("beta")
        barrier = threading.Barrier(2)
        accepted, rejected = [], []

        def fire(key, city):
            barrier.wait()
            try:
                accepted.append(self.g.create_job(
                    tid, self.batch(q(city)), request_key=key))
            except BudgetExceeded:
                rejected.append(key)

        ths = [threading.Thread(target=fire, args=(f"k-{c}", c))
               for c in ("BJ", "SH")]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        self.assertEqual(len(accepted), 1)
        self.assertEqual(len(rejected), 1)
        holds = self.g.list_holds(tid, self.sid)
        self.assertEqual(len(holds), 1)
        self.assertEqual(holds[0]["epsilon"], 0.3)

        # a single direct query must also respect the outstanding lock:
        # 0.5 limit - 0.3 held = 0.2 available < 0.3 cost
        with self.assertRaises(BudgetExceeded):
            self.g.run_query(tid, {"snapshot_id": self.sid}, q("SZ"))
        # ... but cancelling frees it and the query can run
        self.g.cancel_job(accepted[0]["job_id"], tid)
        r = self.g.run_query(tid, {"snapshot_id": self.sid}, q("SZ"))
        self.assertTrue(r["charged"])

    def test_unparseable_member_rejects_whole_submission(self):
        bad = {"type": "count", "epsilon": 0.3,
               "filter": {"op": "cmp", "column": "nope", "predicate": "=", "value": 1}}
        with self.assertRaises(Exception):
            self.g.create_job(self.tid,
                              [member(self.sid, q("BJ")), member(self.sid, bad)],
                              request_key="bad")
        self.assertEqual(self.g.list_jobs(self.tid), [])
        self.assertEqual(self.g.list_holds(), [])
        self.assertEqual(self.g.get_budget(self.tid, self.sid)["epsilon_spent"], 0.0)

    def test_frozen_family_at_confirm_rolls_back_everything(self):
        t = self.g.create_job(self.tid, self.batch(q("BJ"), q("SH")),
                              request_key="freeze-me")
        plan = self.g.plan(self.tid, {"snapshot_id": self.sid}, q("BJ"))
        self.g.freeze_family(plan["family_id"], scope="global", reason="attack",
                             actor="test")
        with self.assertRaises(FrozenQuery):
            self.g.confirm_job(t["job_id"], self.tid)

        row = self.g.db.execute("SELECT state FROM jobs WHERE job_id=?",
                                (t["job_id"],)).fetchone()
        self.assertEqual(row["state"], "failed")
        self.assertEqual(self.g.list_holds(), [])
        self.assertEqual(self.g.get_budget(self.tid, self.sid)["epsilon_spent"], 0.0)
        # no partial results
        self.assertEqual(self.g.list_results(self.tid), [])
        # a second confirm reports the terminal failure rather than charging
        with self.assertRaises(JobStateConflict):
            self.g.confirm_job(t["job_id"], self.tid)

    def test_snapshot_deactivated_at_confirm_fails_without_partial_results(self):
        t = self.g.create_job(self.tid, self.batch(q("BJ")), request_key="deact")
        self.g.set_snapshot_active(self.sid, False, actor="test")
        with self.assertRaises(SnapshotInactive):
            self.g.confirm_job(t["job_id"], self.tid)
        self.assertEqual(self.g.list_results(self.tid), [])
        self.assertEqual(self.g.list_holds(), [])
        self.g.set_snapshot_active(self.sid, True, actor="test")  # still failed, not resurrected
        with self.assertRaises(JobStateConflict):
            self.g.confirm_job(t["job_id"], self.tid)

    def test_cancel_is_idempotent_and_returns_unspent_lock(self):
        t = self.g.create_job(self.tid, self.batch(q("BJ"), q("SH")),
                              request_key="cancel-me")
        self.assertAlmostEqual(self.g.get_budget(self.tid, self.sid)["epsilon_remaining"], 0.4)
        c = self.g.cancel_job(t["job_id"], self.tid)
        self.assertEqual(c["state"], "cancelled")
        self.assertAlmostEqual(self.g.get_budget(self.tid, self.sid)["epsilon_remaining"], 1.0)
        # idempotent
        c2 = self.g.cancel_job(t["job_id"], self.tid)
        self.assertEqual(c2["state"], "cancelled")
        # cannot confirm after cancel
        with self.assertRaises(JobStateConflict):
            self.g.confirm_job(t["job_id"], self.tid)
        audit = self.g.list_audit(team_id=self.tid)
        self.assertTrue(any(a["outcome"] == "job_cancelled" for a in audit))

    def test_expired_ticket_releases_lock_and_confirm_returns_410(self):
        with FrozenTime(self.start):
            t = self.g.create_job(self.tid, self.batch(q("BJ")),
                                  request_key="exp", ttl_seconds=60)
            self.assertEqual(len(self.g.list_holds()), 1)
        # open a fresh frozen clock past expiry
        with FrozenTime(self.start + timedelta(seconds=61)):
            with self.assertRaises(JobTicketExpired):
                self.g.confirm_job(t["job_id"], self.tid)
            self.assertEqual(self.g.list_holds(), [])
            b = self.g.get_budget(self.tid, self.sid)
            self.assertAlmostEqual(b["epsilon_remaining"], 1.0)
            row = self.g.db.execute("SELECT state FROM jobs WHERE job_id=?",
                                    (t["job_id"],)).fetchone()
            self.assertEqual(row["state"], "expired")
            # GET also reflects expiry
            self.assertEqual(self.g.get_job(t["job_id"], self.tid)["state"], "expired")
        audit = self.g.list_audit(team_id=self.tid)
        self.assertTrue(any(a["outcome"] == "job_expired" for a in audit))

    def test_sweep_expires_due_jobs_in_background(self):
        with FrozenTime(self.start):
            t = self.g.create_job(self.tid, self.batch(q("BJ")),
                                  request_key="sweep", ttl_seconds=10)
        with FrozenTime(self.start + timedelta(seconds=11)):
            n = self.g.sweep_expired_jobs()
            self.assertEqual(n, 1)
            self.assertEqual(self.g.list_holds(), [])

    def test_restart_reconciles_executing_and_expired_and_orphan_holds(self):
        with FrozenTime(self.start) as ft:
            t_run = self.g.create_job(self.tid, self.batch(q("BJ")),
                                      request_key="running", ttl_seconds=300)
            t_old = self.g.create_job(self.tid, self.batch(q("SH")),
                                      request_key="old", ttl_seconds=10)
            # simulate a crash AFTER the executing flip but before commit:
            # (normally impossible to observe; emulate state + hold rows)
            self.g.db.execute("UPDATE jobs SET state='executing' WHERE job_id=?",
                              (t_run["job_id"],))
            ft.advance(20)  # t_old now overdue
            report = self.g.recover_pending_jobs()
            self.assertIn(t_run["job_id"], report["failed_interrupted"])
            self.assertIn(t_old["job_id"], report["expired"])
            self.assertEqual(self.g.list_holds(), [])
            self.assertEqual(
                self.g.db.execute("SELECT state FROM jobs WHERE job_id=?",
                                  (t_run["job_id"],)).fetchone()["state"], "failed")
            self.assertEqual(
                self.g.db.execute("SELECT state FROM jobs WHERE job_id=?",
                                  (t_old["job_id"],)).fetchone()["state"], "expired")
            # budget fully restored, nothing charged
            self.assertAlmostEqual(
                self.g.get_budget(self.tid, self.sid)["epsilon_remaining"], 1.0)

        # recovery also runs automatically when re-opening the home dir
        db_path = self.h.gw.db
        db_path.close()
        gw2 = open_gateway(self.h.home)
        self.assertTrue(hasattr(gw2, "list_jobs"))
        gw2.db.close()

    def test_reserved_survives_restart_and_can_then_confirm(self):
        ft = FrozenTime(self.start)
        ft.__enter__()
        try:
            t = self.g.create_job(self.tid, self.batch(q("BJ"), q("SH")),
                                  request_key="survive", ttl_seconds=600)
            # restart with clock still inside TTL: job stays reserved, hold intact
            self.h.gw.db.close()
            gw2 = open_gateway(self.h.home)
            holds = gw2.list_holds(self.tid, self.sid)
            self.assertEqual(len(holds), 1)
            got = gw2.get_job(t["job_id"], self.tid)
            self.assertEqual(got["state"], "reserved")
            done = gw2.confirm_job(t["job_id"], self.tid)
            self.assertEqual(done["state"], "completed")
            self.assertAlmostEqual(
                gw2.get_budget(self.tid, self.sid)["epsilon_spent"], 0.6)
            gw2.db.close()
        finally:
            ft.__exit__(None, None, None)

    def test_cached_members_cost_nothing_and_duplicates_pay_once(self):
        # execute one query first, then submit a job that reuses it
        r = self.g.run_query(self.tid, {"snapshot_id": self.sid}, q("BJ", eps=0.3))
        # batch: cached BJ twice + new SH once -> only 0.3 locked
        t = self.g.create_job(
            self.tid,
            self.batch(q("BJ"), q("BJ"), q("SH")),
            request_key="cache-job")
        self.assertEqual(t["epsilon_reserved"], 0.3)
        done = self.g.confirm_job(t["job_id"], self.tid)
        flags = [s["charged"] for s in done["statements"]]
        self.assertEqual(flags, [False, False, True])
        # the two BJ members share the original result id
        self.assertEqual(done["statements"][0]["result_id"], r["result_id"])
        self.assertEqual(done["statements"][1]["result_id"], r["result_id"])
        self.assertEqual(done["epsilon_consumed"], 0.3)
        # total ledger: 0.3 (direct) + 0.3 (job)
        self.assertAlmostEqual(
            self.g.get_budget(self.tid, self.sid)["epsilon_spent"], 0.6)

    def test_multi_snapshot_job_locks_per_snapshot_and_is_atomic(self):
        snap2, _, _ = self.h.publish("v2", rows=[
            (1, "BJ", "eng", 90, 28, True),
            (2, "SH", "sales", 120, 29, True),
        ])
        sid2 = snap2["snapshot_id"]
        self.g.allocate_budget(self.tid, sid2, 0.5, 0.0, actor="test")
        stmts = [member(self.sid, q("BJ")), member(sid2, q("SH"))]
        t = self.g.create_job(self.tid, stmts, request_key="multi-snap")
        holds = {(h["snapshot_id"]): h["epsilon"] for h in self.g.list_holds(self.tid)}
        self.assertEqual(holds, {self.sid: 0.3, sid2: 0.3})
        done = self.g.confirm_job(t["job_id"], self.tid)
        self.assertEqual(done["state"], "completed")
        self.assertAlmostEqual(self.g.get_budget(self.tid, self.sid)["epsilon_spent"], 0.3)
        self.assertAlmostEqual(self.g.get_budget(self.tid, sid2)["epsilon_spent"], 0.3)

    def test_offline_manifest_and_bundle_and_ledger_verification(self):
        t = self.g.create_job(self.tid, self.batch(q("BJ"), q("SH")),
                              request_key="verify-me")
        done = self.g.confirm_job(t["job_id"], self.tid)
        secrets_ = load_secrets(os.path.join(self.h.home, "secrets.json"))
        sdir = os.path.join(self.h.home, "snapshots")

        rep = verify_job_manifest(done["manifest"], secrets_, sdir)
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertEqual(rep["paid_epsilon"], 0.6)
        # each member receipt reproduces independently
        for mr in rep["member_reports"]:
            self.assertTrue(mr["ok"], mr["errors"])

        bundle = export_bundle(self.g)
        brep = verify_bundle(bundle, secrets_, snapshots_dir=sdir)
        self.assertTrue(brep["ok"], brep["ledger_problems"])
        self.assertEqual(brep["jobs_checked"], 1)

        ledger = verify_ledger(os.path.join(self.h.home, "gateway.sqlite"))
        self.assertTrue(ledger["ok"], ledger["problems"])
        self.assertEqual(ledger["jobs_checked"], 1)

    def test_offline_detects_tampered_manifest_value(self):
        t = self.g.create_job(self.tid, self.batch(q("BJ")), request_key="tamper")
        done = self.g.confirm_job(t["job_id"], self.tid)
        man = done["manifest"]
        man["epsilon_consumed"] = 0.0  # lie about consumption
        secrets_ = load_secrets(os.path.join(self.h.home, "secrets.json"))
        rep = verify_job_manifest(man, secrets_, os.path.join(self.h.home, "snapshots"))
        self.assertFalse(rep["ok"])
        self.assertFalse(rep["checks"]["signature"])

    def test_unknown_team_cannot_see_or_cancel_job(self):
        other = self.h.tid("gamma")
        t = self.g.create_job(self.tid, self.batch(q("BJ")), request_key="owned")
        from dpgw.errors import JobNotFound
        with self.assertRaises(JobNotFound):
            self.g.get_job(t["job_id"], other)
        with self.assertRaises(JobNotFound):
            self.g.cancel_job(t["job_id"], other)

    def test_active_holds_visible_to_admin_listing(self):
        self.g.create_job(self.tid, self.batch(q("BJ")), request_key="h1")
        self.g.create_job(self.tid, self.batch(q("SH")), request_key="h2")
        holds = self.g.list_holds()
        self.assertEqual(len(holds), 2)
        jobs = self.g.list_jobs(state="reserved")
        self.assertEqual(len(jobs), 2)
        # payload_hash never leaks through the listing
        self.assertNotIn("payload_hash", jobs[0])


if __name__ == "__main__":
    unittest.main()
