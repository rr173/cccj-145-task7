"""HTTP API integration tests against a real threaded server."""

import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
from harness import Harness  # noqa: E402

from dpgw.server import serve  # noqa: E402


class Client:
    def __init__(self, base):
        self.base = base

    def call(self, method, path, body=None, token=None, raw=False):
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                payload = resp.read()
                if raw:
                    return resp.status, payload.decode()
                return resp.status, json.loads(payload)
        except urllib.error.HTTPError as e:
            payload = e.read()
            if raw:
                return e.code, payload.decode()
            return e.code, json.loads(payload)


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h = Harness()
        cls.snap, cls.manifest, cls.snap_dir = cls.h.publish("v1")
        cls.sid = cls.snap["snapshot_id"]
        cls.team = cls.h.gw.create_team("httpteam", actor="test")
        cls.h.gw.allocate_budget(cls.team["team_id"], cls.sid, 2.0, 0.0, actor="test")

        cls.server = serve(cls.h.gw, "127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.api = Client(f"http://127.0.0.1:{cls.port}")
        cls.admin = cls.h.admin_token
        cls.token = cls.team["token"]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.h.gw.db.close()
        cls.h.tmp.cleanup()

    def q(self, extra=None):
        body = {"type": "count", "epsilon": 0.5,
                "filter": {"op": "cmp", "column": "city",
                           "predicate": "=", "value": "BJ"}}
        body.update(extra or {})
        return body

    def test_health_and_ui(self):
        st, body = self.api.call("GET", "/healthz")
        self.assertEqual(st, 200)
        self.assertTrue(body["ok"])
        st, html = self.api.call("GET", "/ui/", raw=True)
        self.assertEqual(st, 200)
        self.assertIn("DP Gateway", html)

    def test_auth_required(self):
        st, body = self.api.call("POST", "/v1/query",
                                 {"snapshot": {"snapshot_id": self.sid}, "query": self.q()})
        self.assertEqual(st, 401)
        self.assertEqual(body["error"], "unauthorized")

    def test_admin_routes_reject_team_token(self):
        st, body = self.api.call("GET", "/v1/admin/teams", token=self.token)
        self.assertEqual(st, 401)

    def test_query_plan_retry_flow(self):
        payload = {"snapshot": {"snapshot_id": self.sid}, "query": self.q()}

        st, plan = self.api.call("POST", "/v1/plan", payload, token=self.token)
        self.assertEqual(st, 200)
        self.assertEqual(plan["estimated_cost"]["epsilon"], 0.5)
        self.assertFalse(plan["already_cached"])

        st, r1 = self.api.call("POST", "/v1/query", payload, token=self.token)
        self.assertEqual(st, 200)
        self.assertFalse(r1["cached"])
        self.assertTrue(r1["charged"])
        self.assertIn("sig", r1["receipt"])

        st, r2 = self.api.call("POST", "/v1/query", payload, token=self.token)
        self.assertEqual(st, 200)
        self.assertTrue(r2["cached"])
        self.assertFalse(r2["charged"])
        self.assertEqual(r1["values"], r2["values"])

        st, r3 = self.api.call("GET", f"/v1/results/{r1['result_id']}", token=self.token)
        self.assertEqual(st, 200)
        self.assertEqual(r3["values"], r1["values"])

        st, lst = self.api.call("GET", "/v1/results", token=self.token)
        self.assertEqual(st, 200)
        self.assertEqual(len(lst["results"]), 1)

    def test_budget_overspend_http(self):
        team = self.h.gw.create_team("poor", actor="test")
        self.h.gw.allocate_budget(team["team_id"], self.sid, 0.1, 0.0, actor="test")
        st, body = self.api.call("POST", "/v1/query",
                                 {"snapshot": {"snapshot_id": self.sid}, "query": self.q()},
                                 token=team["token"])
        self.assertEqual(st, 409)
        self.assertEqual(body["error"], "budget_exceeded")

    def test_admin_team_budget_freeze_audit_flow(self):
        st, created = self.api.call("POST", "/v1/admin/teams",
                                    {"name": "viahttp"}, token=self.admin)
        self.assertEqual(st, 201)
        tid = created["team_id"]
        self.assertTrue(created["token"].startswith("dpt_"))

        st, budgets = self.api.call("POST", "/v1/admin/budgets", {
            "team_id": tid, "snapshot_id": self.sid,
            "epsilon": 1.0, "delta": 0}, token=self.admin)
        self.assertEqual(st, 200)
        self.assertEqual(budgets["epsilon_limit"], 1.0)

        # distinct query shape (dept filter) so the global freeze can't
        # contaminate other tests' queries
        freezable_q = {"type": "count", "epsilon": 0.5,
                       "filter": {"op": "cmp", "column": "dept",
                                  "predicate": "=", "value": "eng"}}
        payload = {"snapshot": {"snapshot_id": self.sid}, "query": freezable_q}

        try:
            st, plan = self.api.call("POST", "/v1/plan", payload, token=created["token"])
            self.assertEqual(st, 200)
            fam = plan["family_id"]

            st, frz = self.api.call("POST", "/v1/admin/freezes",
                                    {"family_id": fam, "scope": "global",
                                     "reason": "reconnaissance"}, token=self.admin)
            self.assertEqual(st, 201)
            freeze_id = frz["freeze_id"]

            st, body = self.api.call("POST", "/v1/query", payload, token=created["token"])
            self.assertEqual(st, 403)
            self.assertEqual(body["error"], "query_family_frozen")

            st, audit = self.api.call("GET", "/v1/admin/audit?family_id=" + fam,
                                      token=self.admin)
            self.assertEqual(st, 200)
            self.assertTrue(any(a["outcome"] == "reject_frozen" for a in audit["audit"]))

            st, lst = self.api.call("GET", "/v1/admin/freezes", token=self.admin)
            self.assertEqual(st, 200)
        finally:
            st, lst = self.api.call("GET", "/v1/admin/freezes", token=self.admin)
            for f in lst["freezes"]:
                self.api.call("DELETE", f"/v1/admin/freezes/{f['freeze_id']}",
                              token=self.admin)

    def test_job_ticket_confirm_cancel_admin_flow(self):
        team = self.h.gw.create_team("jobteam", actor="test")
        self.h.gw.allocate_budget(team["team_id"], self.sid, 1.0, 0.0, actor="test")
        statements = [
            {"snapshot": {"snapshot_id": self.sid}, "query": self.q()},
            {"snapshot": {"snapshot_id": self.sid},
             "query": {"type": "count", "epsilon": 0.3,
                       "filter": {"op": "cmp", "column": "city",
                                  "predicate": "=", "value": "SH"}}},
        ]
        body = {"request_key": "http-key-1", "ttl_seconds": 120,
                "statements": statements}

        st, t1 = self.api.call("POST", "/v1/jobs", body, token=team["token"])
        self.assertEqual(st, 201)
        self.assertEqual(t1["state"], "reserved")
        self.assertIn("sig", t1["ticket"])
        job_id = t1["job_id"]

        # identical retry -> same first ticket
        st, t1b = self.api.call("POST", "/v1/jobs", body, token=team["token"])
        self.assertEqual(st, 201)
        self.assertEqual(t1b["job_id"], job_id)

        st, holds = self.api.call("GET", "/v1/admin/holds", token=self.admin)
        self.assertEqual(st, 200)
        self.assertEqual(len(holds["holds"]), 1)

        st, jobs = self.api.call("GET", "/v1/admin/jobs?state=reserved", token=self.admin)
        self.assertEqual(st, 200)
        self.assertTrue(any(j["job_id"] == job_id for j in jobs["jobs"]))

        st, done = self.api.call("POST", f"/v1/jobs/{job_id}/confirm", {},
                                 token=team["token"])
        self.assertEqual(st, 200)
        self.assertEqual(done["state"], "completed")
        self.assertEqual(len(done["results"]), 2)
        self.assertIn("sig", done["manifest"])

        st, got = self.api.call("GET", f"/v1/jobs/{job_id}", token=team["token"])
        self.assertEqual(st, 200)
        self.assertEqual(got["state"], "completed")

    def test_job_cancel_and_conflict_http(self):
        team = self.h.gw.create_team("jobteam2", actor="test")
        self.h.gw.allocate_budget(team["team_id"], self.sid, 1.0, 0.0, actor="test")

        def submit(key, city):
            return self.api.call("POST", "/v1/jobs", {
                "request_key": key,
                "statements": [{"snapshot": {"snapshot_id": self.sid},
                                "query": {"type": "count", "epsilon": 0.3,
                                          "filter": {"op": "cmp", "column": "city",
                                                     "predicate": "=", "value": city}}}]},
                token=team["token"])

        st, t = submit("ck", "BJ")
        self.assertEqual(st, 201)
        st, conflict = submit("ck", "SH")
        self.assertEqual(st, 409)
        self.assertEqual(conflict["error"], "job_conflict")

        st, c = self.api.call("POST", f"/v1/jobs/{t['job_id']}/cancel", {},
                              token=team["token"])
        self.assertEqual(st, 200)
        self.assertEqual(c["state"], "cancelled")
        st, again = self.api.call("POST", f"/v1/jobs/{t['job_id']}/confirm", {},
                                  token=team["token"])
        self.assertEqual(st, 409)
        self.assertEqual(again["error"], "job_state_conflict")

    def test_concurrent_http_requests(self):
        team = self.h.gw.create_team("concurrent", actor="test")
        self.h.gw.allocate_budget(team["team_id"], self.sid, 3.0, 0.0, actor="test")
        payload = {"snapshot": {"snapshot_id": self.sid}, "query": self.q()}
        results = []
        errors = []

        def fire():
            try:
                st, body = self.api.call("POST", "/v1/query", payload,
                                         token=team["token"])
                results.append((st, body))
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=fire) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertTrue(all(st == 200 for st, _ in results))
        charged = sum(1 for _, b in results if b["charged"])
        self.assertEqual(charged, 1)
        spent = self.h.gw.get_budget(team["team_id"], self.sid)["epsilon_spent"]
        self.assertEqual(spent, 0.5)

    def test_publication_batch_http_lifecycle(self):
        from datetime import datetime, timedelta, timezone
        # dedicated teams so the shared class-level team's result cache stays clean
        t1 = self.h.gw.create_team("pubhttp1", actor="test")
        t2 = self.h.gw.create_team("pubhttp2", actor="test")
        self.h.gw.allocate_budget(t1["team_id"], self.sid, 2.0, 0.0, actor="test")
        self.h.gw.allocate_budget(t2["team_id"], self.sid, 2.0, 0.0, actor="test")
        close = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")

        # owner creates the batch (admin token only)
        pub_q = {"type": "count", "epsilon": 0.3,
                 "filter": {"op": "cmp", "column": "city",
                            "predicate": "=", "value": "BJ"}}
        st, body = self.api.call("POST", "/v1/admin/publications", {
            "name": "http-weekly",
            "statements": [{"snapshot": {"snapshot_id": self.sid}, "query": pub_q}],
            "min_participants": 2, "close_at": close}, token=self.admin)
        self.assertEqual(st, 201, body)
        vid = body["version_id"]
        self.assertEqual(body["state"], "collecting")

        # team token cannot create; unauthenticated cannot register
        st, _ = self.api.call("POST", "/v1/admin/publications", {}, token=self.token)
        self.assertEqual(st, 401)
        st, _ = self.api.call("POST", f"/v1/publications/{vid}/register", {})
        self.assertEqual(st, 401)

        # both teams register; duplicate registration replays
        st, r1 = self.api.call("POST", f"/v1/publications/{vid}/register", {},
                               token=t1["token"])
        self.assertEqual(st, 200)
        self.assertEqual(r1["registration"], "registered")
        st, r1b = self.api.call("POST", f"/v1/publications/{vid}/register", {},
                                token=t1["token"])
        self.assertEqual(st, 200)
        self.assertEqual(r1b["registration"], "replayed")
        st, r2 = self.api.call("POST", f"/v1/publications/{vid}/register", {},
                               token=t2["token"])
        self.assertEqual(st, 200)
        self.assertTrue(r2["quorum_met"])

        # owner seals: one signed release
        st, sealed = self.api.call("POST", f"/v1/admin/publications/{vid}/seal", {},
                                   token=self.admin)
        self.assertEqual(st, 200, sealed)
        self.assertEqual(sealed["state"], "sealed")
        self.assertIn("sig", sealed["manifest"])

        # late contribution is 410 publication_closed
        late = self.h.gw.create_team("lateteam", actor="test")
        self.h.gw.allocate_budget(late["team_id"], self.sid, 2.0, 0.0, actor="test")
        st, body = self.api.call("POST", f"/v1/publications/{vid}/register", {},
                                 token=late["token"])
        self.assertEqual(st, 410)
        self.assertEqual(body["error"], "publication_closed")

        # owner amends; late team joins the new collecting version
        st, v2 = self.api.call("POST", f"/v1/admin/publications/{vid}/amend",
                               {"close_at": close}, token=self.admin)
        self.assertEqual(st, 201)
        self.assertEqual(v2["seq"], 2)
        self.assertEqual(v2["parent_version_id"], vid)
        st, lineage = self.api.call("GET", f"/v1/admin/publications/{vid}/lineage",
                                    token=self.admin)
        self.assertEqual(st, 200)
        self.assertEqual([v["state"] for v in lineage["versions"]],
                         ["sealed", "collecting"])

        # list / holds endpoints
        st, listing = self.api.call("GET", "/v1/admin/publications?state=sealed",
                                    token=self.admin)
        self.assertEqual(st, 200)
        self.assertTrue(any(p["version_id"] == vid for p in listing["publications"]))
        st, holds = self.api.call("GET", "/v1/admin/publications/holds",
                                  token=self.admin)
        self.assertEqual(st, 200)
        self.assertIn("holds", holds)


class ShareHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h = Harness()
        cls.snap, _, _ = cls.h.publish("v1")
        cls.sid = cls.snap["snapshot_id"]
        cls.teams = {}
        for name in ("share-a", "share-b"):
            t = cls.h.gw.create_team("http-" + name, actor="test")
            cls.h.gw.allocate_budget(t["team_id"], cls.sid, 5.0, 0.0, actor="test")
            cls.teams[name] = t
        cls.server = serve(cls.h.gw, "127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.api = Client(f"http://127.0.0.1:{cls.port}")
        cls.admin = cls.h.admin_token

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.h.gw.db.close()
        cls.h.tmp.cleanup()

    def _sealed(self, name="http-joint"):
        statement = {"snapshot": {"snapshot_id": self.sid},
                     "query": {"type": "count", "epsilon": 0.3,
                               "filter": {"op": "cmp", "column": "city",
                                          "predicate": "=", "value": "BJ"}}}
        st, v = self.api.call("POST", "/v1/admin/publications", {
            "name": name, "statements": [statement], "min_participants": 1,
            "close_at": "2099-01-01T00:00:00Z"}, token=self.admin)
        self.assertEqual(st, 201, v)
        vid = v["version_id"]
        st, _ = self.api.call("POST", f"/v1/publications/{vid}/register", {},
                              token=self.teams["share-a"]["token"])
        self.assertEqual(st, 200)
        st, sealed = self.api.call("POST", f"/v1/admin/publications/{vid}/seal",
                                   {}, token=self.admin)
        self.assertEqual(st, 200)
        return vid, sealed

    def test_grant_create_fetch_revoke_flow(self):
        vid, sealed = self._sealed()
        ta = self.teams["share-a"]
        fields = ["statements.position", "members.charged", "receipts.values"]
        # whitelist
        st, grant = self.api.call("POST", "/v1/admin/share-grants", {
            "ref": vid, "team_id": ta["team_id"], "fields": fields},
            token=self.admin)
        self.assertEqual(st, 200, grant)
        self.assertEqual(grant["fields"], sorted(fields))
        st, grants = self.api.call("GET", f"/v1/admin/share-grants?version_id={vid}",
                                   token=self.admin)
        self.assertEqual(st, 200)
        self.assertEqual(len(grants["grants"]), 1)

        # create (auth required)
        st, unauth = self.api.call("POST", "/v1/admin/shares", {
            "ref": vid, "team_id": ta["team_id"], "fields": fields,
            "ttl_seconds": 3600}, token=ta["token"])
        self.assertEqual(st, 401)
        st, created = self.api.call("POST", "/v1/admin/shares", {
            "ref": vid, "team_id": ta["team_id"], "fields": fields,
            "ttl_seconds": 3600}, token=self.admin)
        self.assertEqual(st, 201, created)
        self.assertTrue(created["created"])
        share_id, key = created["share_id"], created["share_key"]
        # idempotent create replays
        st, replay = self.api.call("POST", "/v1/admin/shares", {
            "ref": vid, "team_id": ta["team_id"], "fields": fields,
            "ttl_seconds": 99999}, token=self.admin)
        self.assertEqual(st, 201)
        self.assertFalse(replay["created"])
        self.assertEqual(replay["share_id"], share_id)
        self.assertEqual(replay["package_digest"], created["package_digest"])

        # recipient fetches; wrong team token rejected
        st, bad = self.api.call("POST", "/v1/shares/fetch",
                                {"share_key": key},
                                token=self.teams["share-b"]["token"])
        self.assertEqual(st, 404, bad)
        st, pkg = self.api.call("POST", "/v1/shares/fetch", {"share_key": key},
                                token=ta["token"])
        self.assertEqual(st, 200, pkg)
        self.assertEqual(pkg["team_id"], ta["team_id"])
        self.assertEqual(pkg["release_digest"], sealed["manifest_digest"])
        self.assertEqual(set(pkg["release"]["statements"][0]),
                         {"position"})
        # bad key
        st, nope = self.api.call("POST", "/v1/shares/fetch",
                                 {"share_key": "shk_" + "0" * 64},
                                 token=ta["token"])
        self.assertEqual(st, 404)

        # admin inspection + retrieval log
        st, detail = self.api.call(
            "GET", f"/v1/admin/shares/{share_id}", token=self.admin)
        self.assertEqual(st, 200)
        self.assertNotIn("share_key", detail)  # hidden by default
        st, detail = self.api.call(
            "GET", f"/v1/admin/shares/{share_id}?reveal_key=1", token=self.admin)
        self.assertEqual(st, 200)
        self.assertEqual(detail["share_key"], key)
        st, log = self.api.call(
            "GET", f"/v1/admin/shares/{share_id}/retrievals", token=self.admin)
        self.assertEqual(st, 200)
        outcomes = [r["outcome"] for r in log["retrievals"]]
        self.assertEqual(outcomes.count("ok"), 1)
        self.assertIn("reject_audience", outcomes)

        # revoke -> subsequent fetches 410
        st, rev = self.api.call("POST", f"/v1/admin/shares/{share_id}/revoke",
                                {"reason": "incident"}, token=self.admin)
        self.assertEqual(st, 200)
        self.assertEqual(rev["state"], "revoked")
        st, gone = self.api.call("POST", "/v1/shares/fetch", {"share_key": key},
                                 token=ta["token"])
        self.assertEqual(st, 410)
        self.assertEqual(gone["error"], "share_revoked")

        # list filter
        st, listing = self.api.call("GET", "/v1/admin/shares?state=revoked",
                                    token=self.admin)
        self.assertEqual(st, 200)
        self.assertTrue(any(s["share_id"] == share_id for s in listing["shares"]))


if __name__ == "__main__":
    unittest.main()
