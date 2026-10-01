"""审计馈送中继测试。

覆盖需求场景：首次同步、断线续传（不可用/回退/坏签名/证明缺口停在最后
可信位置并恢复）、冻结上游封顶、绝不补造记录、筛选隔离、双消费者抢租约、
超时重投（同 delivery_id/同字节）、重启确定性、重复确认幂等、错误确认
（越租户/跳段/旧租约）、运行中改筛选拒绝、已停用租户拒绝、慢租户不阻塞、
离线验签（有效/篡改/错钥）、HTTP API。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
from relay_harness import FaultyUpstream, GatewayWorld  # noqa: E402

from afrelay.app import bootstrap, open_relay  # noqa: E402
from afrelay.canonical import dumps_canon  # noqa: E402
from afrelay.errors import (  # noqa: E402
    AckEndMismatch,
    BadDelivery,
    FilterLocked,
    InFlightCapReached,
    InvalidConfig,
    LeaseConflict,
    StaleLease,
    TenantInactive,
)
from afrelay.server import serve as serve_relay  # noqa: E402
from afrelay.verify import load_relay_keys, verify_packet  # noqa: E402


def http(method, url, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + (token or ""),
        "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


class RelayTestBase(unittest.TestCase):
    upstream_via_real_http = True

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.relay_home = os.path.join(self.tmp.name, "relay")
        self.world = GatewayWorld()
        self.fault = FaultyUpstream(self.world)
        info = bootstrap(
            self.relay_home,
            upstream_url=self.fault.base,
            upstream_token=self.world.token,
            transparency_secret_hex=self.world.transparency_key_hex,
            default_ttl_seconds=30, batch_size=10,
            default_max_inflight=8)
        self.admin = info["admin_token"]
        self.clock = {"t": 1_000_000.0}
        self.relay = open_relay(self.relay_home,
                                clock=lambda: self.clock["t"])

    def tearDown(self):
        self.relay.close()
        self.fault.close()
        self.world.close()
        self.tmp.cleanup()

    def advance(self, seconds):
        self.clock["t"] += seconds

    def seal_n(self, n, prefix="b"):
        for i in range(n):
            self.world.seal(f"{prefix}-{i}")

    def make_tenant(self, tid="aud-a", name="A", rule=None, max_inflight=None):
        t = self.relay.create_tenant(tid, name, rule, token=self.admin,
                                     max_inflight=max_inflight)
        return t["token"]

    def claim(self, tok, consumer="c1", ttl=None):
        return self.relay.claim(tok, consumer, ttl_seconds=ttl)

    def ack(self, tok, did, end, consumer="c1", lease_token=None):
        return self.relay.complete(tok, did, end, consumer,
                                   lease_token=lease_token)

    def set_inflight(self, tid, n):
        return self.relay.set_max_inflight(tid, n)

    def tenant_summary(self, tid="aud-a"):
        return self.relay.tenant_windows(tid)

    def trusted(self):
        return self.relay.mirror_status()["trusted_tree_size"]


# --------------------------------------------------------------------------- #
# synchronisation
# --------------------------------------------------------------------------- #

class FirstSyncTests(RelayTestBase):
    def test_first_sync_mirrors_verified_leaves_and_events(self):
        self.seal_n(3)
        report = self.relay.sync_once()
        self.assertTrue(report["ok"])
        self.assertEqual(report["trusted_tree_size"], 3)
        status = self.relay.mirror_status()
        self.assertEqual(status["last_status"], "caught_up")
        self.assertEqual(status["consecutive_failures"], 0)
        self.assertTrue(status["synced"])
        kinds = [e["kind"] for e in self.relay.recent_events(limit=10)]
        self.assertIn("first_sync", kinds)
        self.assertIn("mirror_advanced", kinds)
        # dense leaves in the independent mirror store
        leaves = self.relay.list_leaves()
        self.assertEqual(sorted(l["leaf_index"] for l in leaves), [0, 1, 2])

    def test_empty_upstream_syncs_genesis_only(self):
        report = self.relay.sync_once()
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["trusted_tree_size"], 0)
        self.assertFalse(self.relay.list_leaves())
        # genesis signed checkpoint is archived independently
        row = self.relay.db.execute(
            "SELECT root_hash FROM mirror_cps WHERE tree_size=0").fetchone()
        self.assertTrue(row["root_hash"])

    def test_incremental_sync_resumes_from_last_trusted(self):
        self.seal_n(2)
        self.relay.sync_once()
        self.assertEqual(self.trusted(), 2)
        self.seal_n(2, prefix="more")
        report = self.relay.sync_once()
        self.assertEqual(report["trusted_tree_size"], 4)
        # leaves 0..3 dense; nothing fabricated
        self.assertEqual(
            self.relay.db.execute("SELECT COUNT(*) c FROM mirror_leaves")
            .fetchone()["c"], 4)


class StopAndResumeTests(RelayTestBase):
    def test_unavailable_upstream_holds_position(self):
        self.seal_n(2)
        self.relay.sync_once()
        self.seal_n(3, prefix="later")
        self.fault.director["mode"] = "down"
        report = self.relay.sync_once()
        self.assertFalse(report["ok"])
        self.assertEqual(report["reason"], "upstream_unavailable")
        self.assertEqual(self.trusted(), 2)  # held
        st = self.relay.mirror_status()
        self.assertEqual(st["last_status"], "stopped")
        self.assertEqual(st["last_stop_reason"], "upstream_unavailable")
        self.assertEqual(st["consecutive_failures"], 1)
        # recovery resumes exactly from 2
        self.fault.director["mode"] = "ok"
        report = self.relay.sync_once()
        self.assertTrue(report["ok"])
        self.assertEqual(self.trusted(), 5)
        self.assertEqual(
            self.relay.mirror_status()["consecutive_failures"], 0)

    def test_rollback_height_refused_and_recovers(self):
        self.seal_n(3)
        self.relay.sync_once()
        self.fault.director["mode"] = "rollback"
        report = self.relay.sync_once()
        self.assertFalse(report["ok"])
        self.assertEqual(report["reason"], "upstream_rollback")
        self.assertEqual(self.trusted(), 3)
        rejects = [e for e in self.relay.recent_events(limit=5)
                   if e["kind"] == "sync_stopped"]
        self.assertTrue(rejects)
        self.fault.director["mode"] = "ok"
        self.assertTrue(self.relay.sync_once()["ok"])

    def test_bad_signature_halts_and_never_writes(self):
        self.seal_n(1)
        self.relay.sync_once()
        self.seal_n(1, prefix="x")
        self.fault.director["mode"] = "bad_signature"
        report = self.relay.sync_once()
        self.assertEqual(report["reason"], "upstream_bad_signature")
        self.assertEqual(self.trusted(), 1)
        self.assertEqual(
            self.relay.db.execute("SELECT COUNT(*) c FROM mirror_leaves")
            .fetchone()["c"], 1)
        self.fault.director["mode"] = "ok"
        self.assertTrue(self.relay.sync_once()["ok"])
        self.assertEqual(self.trusted(), 2)

    def test_tampered_leaf_content_address_halts(self):
        self.seal_n(1)
        self.relay.sync_once()
        self.seal_n(1, prefix="x")
        self.fault.director["mode"] = "bad_leaf"
        report = self.relay.sync_once()
        self.assertFalse(report["ok"])
        self.assertEqual(report["reason"], "upstream_bad_leaf")
        self.assertEqual(self.trusted(), 1)

    def test_proof_gap_halts_at_last_trusted(self):
        self.seal_n(2)
        self.relay.sync_once()
        self.seal_n(1, prefix="x")
        self.fault.director["mode"] = "proof_gap"
        report = self.relay.sync_once()
        self.assertFalse(report["ok"])
        self.assertEqual(report["reason"], "upstream_proof_gap")
        self.assertEqual(self.trusted(), 2)
        self.fault.director["mode"] = "ok"
        self.assertTrue(self.relay.sync_once()["ok"])
        self.assertEqual(self.trusted(), 3)

    def test_frozen_upstream_caps_at_last_trusted_head(self):
        self.seal_n(2)
        self.relay.sync_once()  # trusted=2
        # upstream grows to 4 THEN is frozen at 2 (only read up to the frozen head)
        self.seal_n(2, prefix="after-freeze")
        self.fault.director["mode"] = "freeze"
        self.fault.director["freeze_at"] = 2
        report = self.relay.sync_once()
        self.assertTrue(report["ok"], report)
        self.assertTrue(report["frozen_cap"])
        self.assertEqual(self.trusted(), 2)
        st = self.relay.mirror_status()
        self.assertTrue(st["upstream_frozen"])
        self.assertEqual(st["frozen_reason"], "fork_evidence")

    def test_relay_never_fabricates_when_upstream_empty_after_start(self):
        # mirror 2, upstream claims 5 but can only serve 2 valid leaves:
        # proof gap on leaf 2 means relay must not invent leaves 2..4
        self.seal_n(2)
        self.relay.sync_once()
        self.fault.director["mode"] = "proof_gap"
        # real gateway still at 2 -> nothing happens; force a lying state by
        # adding the leaves but corrupting their proofs
        self.seal_n(3, prefix="more")
        report = self.relay.sync_once()
        self.assertEqual(self.trusted(), 2)
        gaps = self.relay.db.execute(
            "SELECT COUNT(*) c FROM mirror_leaves WHERE leaf_index >= 2").fetchone()
        self.assertEqual(gaps["c"], 0)
        self.assertEqual(report["reason"], "upstream_proof_gap")


# --------------------------------------------------------------------------- #
# tenants, filters, leases
# --------------------------------------------------------------------------- #

class FilterTests(RelayTestBase):
    def test_isolated_filters_and_cursors(self):
        vid = self.world.seal("a1")              # leaf 0 release_sealed
        self.world.make_share(vid)               # leaf 1 share_issued
        self._void_one("void1", minp=3)          # leaf 2 release_voided
        self.world.seal("a2")                    # leaf 3 release_sealed
        self.relay.sync_once()
        tok_seal = self.make_tenant(
            "seals", "S", {"event_types": ["release_sealed"]})
        tok_all = self.make_tenant("all", "ALL", None)
        p1 = self.claim(tok_seal)["delivery"]
        self.assertEqual({r["event_type"] for r in p1["records"]},
                         {"release_sealed"})
        self.assertEqual(p1["leaf_count"], 2)
        p2 = self.claim(tok_all)["delivery"]
        self.assertEqual(p2["leaf_count"], 4)
        # intervals stay contiguous in original index space
        self.assertEqual(p1["start_index"], 0)
        self.assertEqual(p1["end_index"], 4)
        self.assertEqual([r["leaf_index"] for r in p1["records"]], [0, 3])

    def _void_one(self, name, minp=3):
        from datetime import datetime, timedelta, timezone

        def iso_in(s):
            return (datetime.now(timezone.utc) + timedelta(seconds=s)).isoformat()

        def iso_ago(s=1):
            return (datetime.now(timezone.utc) - timedelta(seconds=s)).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ")

        q = {"type": "count", "epsilon": 0.3,
             "filter": {"op": "cmp", "column": "city", "predicate": "=",
                        "value": "BJ"}}
        stmt = {"snapshot": {"snapshot_id": self.world.sid}, "query": q}
        v = self.world.h.gw.create_publication(
            name, [stmt], minp, iso_in(3600), actor="lead")
        # 复刻网关既有测试手法：把截止时刻改到过去再作废
        self.world.h.gw.db.execute(
            "UPDATE pub_versions SET close_at=? WHERE version_id=?",
            (iso_ago(), v["version_id"]))
        self.world.h.gw.void_publication(v["version_id"])

    def test_filter_change_allowed_before_first_delivery(self):
        tok = self.make_tenant("t", "T", {"event_types": ["share_issued"]})
        self.relay.set_filter("t", {"event_types": ["release_sealed"]})
        self.assertFalse(
            self.relay.list_tenants()[0]["filter_locked"])

    def test_filter_change_rejected_after_delivery_started(self):
        rule = {"event_types": ["release_sealed", "release_voided",
                                "share_issued", "share_revoked"]}
        tok = self.make_tenant("t", "T", rule)
        self.seal_n(1)
        self.relay.sync_once()
        claimed = self.claim(tok)
        self.assertIsNotNone(claimed["delivery"])
        with self.assertRaises(FilterLocked):
            self.relay.set_filter("t", {"event_types": ["release_sealed"]})
        # rule unchanged
        self.assertEqual(self.relay.list_tenants()[0]["filter"], rule)

    def test_invalid_filter_rejected(self):
        from afrelay.errors import FilterInvalid
        with self.assertRaises(FilterInvalid):
            self.make_tenant("bad", "bad", {"event_types": ["nope"]})
        with self.assertRaises(FilterInvalid):
            self.make_tenant("bad2", "bad2", {"event_types": []})


class LeaseTests(RelayTestBase):
    def test_two_consumers_contend_one_holds_lease(self):
        self.seal_n(1)
        self.relay.sync_once()
        tok = self.make_tenant(max_inflight=1)
        first = self.claim(tok, "owner-1")
        with self.assertRaises(LeaseConflict):
            self.claim(tok, "owner-2")
        # owner may re-fetch identical bytes within its lease
        again = self.claim(tok, "owner-1")
        self.assertEqual(again["delivery_id"], first["delivery_id"])
        self.assertEqual(dumps_canon(again["delivery"]),
                         dumps_canon(first["delivery"]))

    def test_parallel_consumers_get_non_overlapping_adjacent_windows(self):
        # 同一租户的多个 worker 并行领取互不重叠的相邻窗口，无需等前一包提交
        self.seal_n(4)
        self.relay.sync_once()
        self.relay.batch_size = 1
        tok = self.make_tenant(max_inflight=4)
        w1 = self.claim(tok, "w1")
        w2 = self.claim(tok, "w2")
        w3 = self.claim(tok, "w3")
        self.assertEqual(w1["start_index"], 0)
        self.assertEqual(w1["end_index"], w2["start_index"])
        self.assertEqual(w2["end_index"], w3["start_index"])
        self.assertEqual(len({w1["delivery_id"], w2["delivery_id"],
                              w3["delivery_id"]}), 3)
        summary = self.tenant_summary()
        self.assertEqual(summary["inflight"], 3)
        self.assertEqual(summary["commit_barrier"], 0)

    def test_inflight_cap_backpressures_new_claims(self):
        self.seal_n(4)
        self.relay.sync_once()
        self.relay.batch_size = 1
        tok = self.make_tenant(max_inflight=2)
        w1 = self.claim(tok, "w1")
        w2 = self.claim(tok, "w2")
        self.assertEqual(w1["inflight"], 1)
        self.assertEqual(w2["inflight"], 2)
        # 第三个窗口：达到并行度上限且还有未切数据 -> 背压
        with self.assertRaises(InFlightCapReached):
            self.claim(tok, "w3")
        counts = self.relay.reject_counts(tenant_id="aud-a")
        self.assertEqual(counts.get("inflight_cap_reached"), 1)

    def test_timeout_redelivers_same_id_and_bytes(self):
        self.seal_n(1)
        self.relay.sync_once()
        tok = self.make_tenant()
        first = self.claim(tok, "slow", ttl=30)
        self.advance(31)
        second = self.claim(tok, "fast")
        self.assertTrue(second["redispatched"])
        self.assertEqual(second["delivery_id"], first["delivery_id"])
        self.assertEqual(dumps_canon(second["delivery"]),
                         dumps_canon(first["delivery"]))
        self.assertEqual(second["retries"], 1)
        self.assertEqual(second["lease_owner"], "fast")
        # 接管返回新 epoch 的不透明租约令牌
        self.assertTrue(second["lease_token"])
        self.assertNotEqual(second["lease_token"], first["lease_token"])

    def test_old_lease_ack_rejected_after_timeout(self):
        self.seal_n(1)
        self.relay.sync_once()
        tok = self.make_tenant()
        first = self.claim(tok, "slow", ttl=30)
        self.advance(31)
        second = self.claim(tok, "fast")
        # 旧持有者（无新令牌）提交 -> 拒绝
        with self.assertRaises(StaleLease):
            self.ack(tok, first["delivery_id"], first["end_index"], "slow")
        # 即使旧持有者知道/复用新 consumer 名但没有新令牌也拒绝
        with self.assertRaises(StaleLease):
            self.ack(tok, first["delivery_id"], first["end_index"], "fast")
        # 新持有者出示新令牌提交 -> 接受
        ok = self.ack(tok, second["delivery_id"], second["end_index"], "fast",
                      lease_token=second["lease_token"])
        self.assertEqual(ok["state"], "acked")
        self.assertEqual(ok["commit_barrier"], first["end_index"])

    def test_delivery_persists_across_restart(self):
        self.seal_n(1)
        self.relay.sync_once()
        tok = self.make_tenant()
        first = self.claim(tok, "c1", ttl=30)
        self.advance(5)
        self.relay.close()
        self.relay = open_relay(self.relay_home, clock=lambda: self.clock["t"])
        again = self.relay.claim(tok, "c1")
        self.assertEqual(again["delivery_id"], first["delivery_id"])
        self.assertEqual(dumps_canon(again["delivery"]),
                         dumps_canon(first["delivery"]))
        # and the lease can be acked after restart
        done = self.relay.complete(tok, first["delivery_id"],
                                   first["end_index"], "c1")
        self.assertEqual(done["state"], "acked")


class AckTests(RelayTestBase):
    def _one(self):
        self.seal_n(1)
        self.relay.sync_once()
        tok = self.make_tenant()
        p = self.claim(tok)
        return tok, p

    def test_ack_advances_only_to_packet_end(self):
        tok, p = self._one()
        resp = self.ack(tok, p["delivery_id"], p["end_index"])
        self.assertEqual(resp["cursor_end"], p["end_index"])
        self.assertEqual(resp["idempotent"], False)
        self.assertEqual(
            self.relay.list_tenants()[0]["cursor_end"], p["end_index"])

    def test_duplicate_ack_idempotent(self):
        tok, p = self._one()
        first = self.ack(tok, p["delivery_id"], p["end_index"])
        second = self.ack(tok, p["delivery_id"], p["end_index"])
        self.assertEqual(second["state"], "acked")
        self.assertTrue(second["idempotent"])
        self.assertEqual(second["cursor_end"], first["cursor_end"])

    def test_gap_ack_rejected_no_move(self):
        tok, p = self._one()
        with self.assertRaises(AckEndMismatch):
            self.ack(tok, p["delivery_id"], p["end_index"] + 5)
        with self.assertRaises(AckEndMismatch):
            self.ack(tok, p["delivery_id"], p["end_index"] - 1)
        self.assertEqual(self.relay.list_tenants()[0]["cursor_end"], 0)

    def test_cross_tenant_delivery_id_rejected(self):
        self.seal_n(1)
        self.relay.sync_once()
        t1 = self.make_tenant("a", "A")
        t2 = self.make_tenant("b", "B")
        p1 = self.claim(t1)
        # t2 presenting a's delivery id -> rejected, nothing moves
        with self.assertRaises(BadDelivery):
            self.ack(t2, p1["delivery_id"], p1["end_index"])
        self.assertEqual(
            [x for x in self.relay.list_tenants() if x["tenant_id"] == "b"][0]
            ["cursor_end"], 0)

    def test_unknown_delivery_id_rejected(self):
        tok = self.make_tenant("a", "A")
        with self.assertRaises(BadDelivery):
            self.ack(tok, "afd_doesnotexist", 3)

    def test_wrong_consumer_ack_is_stale(self):
        self.seal_n(1)
        self.relay.sync_once()
        tok = self.make_tenant()
        p = self.claim(tok, "legit")
        with self.assertRaises(StaleLease):
            self.ack(tok, p["delivery_id"], p["end_index"], "impostor")

    def test_rejections_recorded_isolated_with_reasons(self):
        tok, p = self._one()
        with self.assertRaises(AckEndMismatch):
            self.ack(tok, p["delivery_id"], p["end_index"] + 1)
        counts = self.relay.reject_counts(tenant_id="aud-a")
        self.assertEqual(counts.get("ack_end_mismatch"), 1)
        events = [e for e in self.relay.recent_events(tenant_id="aud-a")
                  if e["kind"] == "reject"]
        self.assertTrue(events)


class DeactivationTests(RelayTestBase):
    def test_deactivated_tenant_claim_and_ack_rejected_cursor_kept(self):
        self.seal_n(2)
        self.relay.sync_once()
        tok = self.make_tenant()
        p = self.claim(tok)
        self.ack(tok, p["delivery_id"], p["end_index"])
        self.relay.deactivate_tenant("aud-a", reason="offboarded")
        with self.assertRaises(TenantInactive):
            self.claim(tok)
        self.seal_n(1, prefix="new")
        self.relay.sync_once()
        # cannot resume consumption after deactivation; cursor retained
        with self.assertRaises(TenantInactive):
            self.claim(tok)
        t = [x for x in self.relay.list_tenants()
             if x["tenant_id"] == "aud-a"][0]
        self.assertFalse(t["active"])
        self.assertEqual(t["cursor_end"], 2)


class SlowTenantTests(RelayTestBase):
    def test_slow_tenant_does_not_block_others_or_sync(self):
        self.seal_n(2)
        self.relay.sync_once()
        slow = self.make_tenant("slow", "slow")
        fast = self.make_tenant("fast", "fast")
        ps = self.claim(slow, "sc")
        pf = self.claim(fast, "fc")
        self.assertEqual(ps["delivery_id"] != pf["delivery_id"], True)
        # slow never acks; fast keeps consuming newly mirrored leaves
        self.ack(fast, pf["delivery_id"], pf["end_index"], "fc")
        self.seal_n(2, prefix="m")
        self.relay.sync_once()
        pf2 = self.claim(fast, "fc")
        self.assertEqual(pf2["end_index"], 4)
        self.ack(fast, pf2["delivery_id"], pf2["end_index"], "fc")
        slow_t = [t for t in self.relay.list_tenants()
                  if t["tenant_id"] == "slow"][0]
        fast_t = [t for t in self.relay.list_tenants()
                  if t["tenant_id"] == "fast"][0]
        self.assertEqual(slow_t["cursor_end"], 0)
        self.assertEqual(fast_t["cursor_end"], 4)


# --------------------------------------------------------------------------- #
# parallel windows: out-of-order completion + contiguous commit barrier
# --------------------------------------------------------------------------- #

class BarrierTests(RelayTestBase):
    def _three_windows(self):
        self.seal_n(3)
        self.relay.sync_once()
        self.relay.batch_size = 1
        tok = self.make_tenant("par", "PAR", max_inflight=3)
        w1 = self.claim(tok, "w1", ttl=30)
        w2 = self.claim(tok, "w2", ttl=30)
        w3 = self.claim(tok, "w3", ttl=30)
        return tok, [w1, w2, w3]

    def test_out_of_order_completion_registers_but_barrier_waits(self):
        tok, wins = self._three_windows()
        # 靠后的窗口先完成：只登记事实，屏障不动
        r3 = self.ack(tok, wins[2]["delivery_id"], wins[2]["end_index"], "w3",
                      lease_token=wins[2]["lease_token"])
        self.assertEqual(r3["window_state"], "completed")
        self.assertEqual(r3["state"], "completed")
        self.assertEqual(r3["commit_barrier"], 0)
        r2 = self.ack(tok, wins[1]["delivery_id"], wins[1]["end_index"], "w2",
                      lease_token=wins[1]["lease_token"])
        self.assertEqual(r2["commit_barrier"], 0)
        summary = self.tenant_summary("par")
        self.assertEqual(summary["commit_barrier"], 0)
        # 最前面的未完成窗口就是挡住屏障的那一个；在途仍 3（完成待补洞占槽）
        self.assertEqual(summary["blocking_window"]["delivery_id"],
                         wins[0]["delivery_id"])
        self.assertEqual(summary["inflight"], 3)
        states = {w["seq"]: w["state"] for w in summary["windows"]}
        self.assertEqual(states, {wins[0]["seq"]: "leased",
                                  wins[1]["seq"]: "completed",
                                  wins[2]["seq"]: "completed"})

    def test_filling_the_hole_advances_barrier_once(self):
        tok, wins = self._three_windows()
        self.ack(tok, wins[2]["delivery_id"], wins[2]["end_index"], "w3",
                 lease_token=wins[2]["lease_token"])
        self.ack(tok, wins[1]["delivery_id"], wins[1]["end_index"], "w2",
                 lease_token=wins[1]["lease_token"])
        # 补齐最前空洞：屏障一次性推进穿过稠密完成前缀到 w3 末端
        r1 = self.ack(tok, wins[0]["delivery_id"], wins[0]["end_index"], "w1",
                      lease_token=wins[0]["lease_token"])
        self.assertEqual(r1["state"], "acked")
        self.assertEqual(r1["window_state"], "committed")
        self.assertEqual(r1["commit_barrier"], wins[2]["end_index"])
        summary = self.tenant_summary("par")
        self.assertEqual(summary["commit_barrier"], wins[2]["end_index"])
        self.assertEqual(summary["inflight"], 0)
        self.assertIsNone(summary["blocking_window"])
        adv = [e for e in self.relay.recent_events(tenant_id="par", limit=50)
               if e["kind"] == "window_barrier_advanced"]
        self.assertEqual(adv[0]["detail"],
                         {"from": 0, "to": wins[2]["end_index"],
                          "committed_windows": 3})

    def test_duplicate_completed_submit_is_idempotent_and_does_not_jump(self):
        tok, wins = self._three_windows()
        self.ack(tok, wins[2]["delivery_id"], wins[2]["end_index"], "w3",
                 lease_token=wins[2]["lease_token"])
        # 同一持有者对已完成待补洞窗口重复登记：幂等，屏障仍不动
        again = self.ack(tok, wins[2]["delivery_id"], wins[2]["end_index"],
                         "w3", lease_token=wins[2]["lease_token"])
        self.assertTrue(again["idempotent"])
        self.assertEqual(again["commit_barrier"], 0)

    def test_barrier_jumps_only_over_present_prefix(self):
        # w1 慢、w2 先完成；补 w1 后屏障推进到 w2，w3 尚未完成则停在 w2
        tok, wins = self._three_windows()
        self.ack(tok, wins[1]["delivery_id"], wins[1]["end_index"], "w2",
                 lease_token=wins[1]["lease_token"])
        r1 = self.ack(tok, wins[0]["delivery_id"], wins[0]["end_index"], "w1",
                      lease_token=wins[0]["lease_token"])
        self.assertEqual(r1["commit_barrier"], wins[1]["end_index"])
        summary = self.tenant_summary("par")
        self.assertEqual(summary["blocking_window"]["delivery_id"],
                         wins[2]["delivery_id"])


class InFlightShrinkTests(RelayTestBase):
    def test_shrink_does_not_preempt_valid_holders(self):
        self.seal_n(3)
        self.relay.sync_once()
        self.relay.batch_size = 1
        tok = self.make_tenant("sh", "SH", max_inflight=3)
        w1 = self.claim(tok, "w1", ttl=30)
        w2 = self.claim(tok, "w2", ttl=30)
        # 在途 2 时把上限收缩到 1：两个窗口继续属于各自持有者
        res = self.set_inflight("sh", 1)
        self.assertTrue(res["shrink_pending"])
        self.assertEqual(res["inflight"], 2)
        summary = self.tenant_summary("sh")
        owners = {w["delivery_id"]: w["lease_owner"] for w in summary["windows"]}
        self.assertEqual(owners[w1["delivery_id"]], "w1")
        self.assertEqual(owners[w2["delivery_id"]], "w2")
        # 收缩后新领取被背压（w1/w2 仍有效，无超时窗口可接管）
        with self.assertRaises(InFlightCapReached):
            self.claim(tok, "w3")
        # 提交两个窗口后在途归零，新的领取才按上限 1 放行
        self.ack(tok, w1["delivery_id"], w1["end_index"], "w1",
                 lease_token=w1["lease_token"])
        self.ack(tok, w2["delivery_id"], w2["end_index"], "w2",
                 lease_token=w2["lease_token"])
        n1 = self.claim(tok, "w3", ttl=30)
        self.assertEqual(n1["start_index"], 2)
        self.assertEqual(n1["max_inflight"], 1)
        # 数据已全部切出（3 个窗口覆盖 [0,3)），此时再领只是争抢 w3 的
        # 活动租约：保持“窗口有主”的 LeaseConflict，而非误发新窗口
        with self.assertRaises(LeaseConflict):
            self.claim(tok, "w4")

    def test_invalid_inflight_rejected(self):
        self.make_tenant("iv", "IV")
        with self.assertRaises(InvalidConfig):
            self.set_inflight("iv", 0)
        with self.assertRaises(InvalidConfig):
            self.set_inflight("iv", -2)

    def test_grow_releases_more_slots(self):
        self.seal_n(3)
        self.relay.sync_once()
        self.relay.batch_size = 1
        tok = self.make_tenant("gr", "GR", max_inflight=1)
        w1 = self.claim(tok, "w1", ttl=30)
        with self.assertRaises(InFlightCapReached):
            self.claim(tok, "w2")
        self.set_inflight("gr", 3)
        w2 = self.claim(tok, "w2", ttl=30)
        w3 = self.claim(tok, "w3", ttl=30)
        self.assertEqual(w2["start_index"], w1["end_index"])
        self.assertEqual(w3["start_index"], w2["end_index"])


class TimeoutTakeoverTests(RelayTestBase):
    def test_force_expire_allows_new_worker_and_rejects_old(self):
        self.seal_n(2)
        self.relay.sync_once()
        self.relay.batch_size = 1
        tok = self.make_tenant("tx", "TX", max_inflight=2)
        w1 = self.claim(tok, "slow", ttl=300)
        w2 = self.claim(tok, "ok", ttl=300)
        # 管理员强制让 w1 到期（不碰边界/完成状态/屏障）
        fe = self.relay.force_expire_window("tx", w1["delivery_id"])
        self.assertTrue(fe["retakeable"])
        taken = self.claim(tok, "new", ttl=300)
        self.assertEqual(taken["delivery_id"], w1["delivery_id"])
        self.assertEqual(taken["start_index"], w1["start_index"])
        self.assertEqual(taken["end_index"], w1["end_index"])
        self.assertEqual(taken["lease_owner"], "new")
        self.assertEqual(taken["retries"], 1)
        self.assertEqual(dumps_canon(taken["delivery"]),
                         dumps_canon(w1["delivery"]))
        # 旧持有者提交被拒
        with self.assertRaises(StaleLease):
            self.ack(tok, w1["delivery_id"], w1["end_index"], "slow",
                     lease_token=w1["lease_token"])
        # 新持有者用新令牌可提交；屏障随之推进
        ok = self.ack(tok, taken["delivery_id"], taken["end_index"], "new",
                      lease_token=taken["lease_token"])
        self.assertEqual(ok["commit_barrier"], w1["end_index"])
        # w2 未完成，屏障停在 w2 起点
        summary = self.tenant_summary("tx")
        self.assertEqual(summary["blocking_window"]["delivery_id"],
                         w2["delivery_id"])


class RestartBarrierTests(RelayTestBase):
    def test_boundaries_completions_and_barrier_survive_restart(self):
        self.seal_n(4)
        self.relay.sync_once()
        self.relay.batch_size = 1
        tok = self.make_tenant("rs", "RS", max_inflight=4)
        wins = [self.claim(tok, f"w{i+1}", ttl=300) for i in range(4)]
        # 乱序完成 w2/w4（屏障不动）
        for i in (1, 3):
            self.ack(tok, wins[i]["delivery_id"], wins[i]["end_index"],
                     f"w{i+1}", lease_token=wins[i]["lease_token"])

        self.relay.close()
        self.relay = open_relay(self.relay_home,
                                clock=lambda: self.clock["t"])
        # 重启后边界不变：重新领取 w1 返回原 delivery_id 与原始字节
        again = self.relay.claim(tok, "w1")
        self.assertEqual(again["delivery_id"], wins[0]["delivery_id"])
        self.assertEqual(dumps_canon(again["delivery"]),
                         dumps_canon(wins[0]["delivery"]))
        summary = self.relay.tenant_windows("rs")
        self.assertEqual(summary["commit_barrier"], 0)
        self.assertEqual({w["seq"]: w["state"] for w in summary["windows"]},
                         {wins[0]["seq"]: "leased",
                          wins[1]["seq"]: "completed",
                          wins[2]["seq"]: "leased",
                          wins[3]["seq"]: "completed"})
        # 按序补齐 w1 -> 屏障推进到 w2 末端（w3 未完成，停住）
        r1 = self.relay.complete(tok, wins[0]["delivery_id"],
                                 wins[0]["end_index"], "w1")
        self.assertEqual(r1["commit_barrier"], wins[1]["end_index"])
        # 再补 w3 -> 屏障一次穿过 w3/w4 到流末端
        # w3 在重启后租约仍有效（未超时），可直接提交
        r3 = self.relay.complete(tok, wins[2]["delivery_id"],
                                 wins[2]["end_index"], "w3")
        self.assertEqual(r3["commit_barrier"], wins[3]["end_index"])
        # 重启不改变 max_inflight
        self.assertEqual(self.relay.tenant_windows("rs")["max_inflight"], 4)


class PollerTests(RelayTestBase):
    def test_background_poller_retries_and_resumes(self):
        self.seal_n(1)
        self.relay.sync_once()
        self.seal_n(2, prefix="later")
        self.fault.director["mode"] = "down"
        self.relay.start_poller(interval=0.05)
        # while down, mirror stays at the last trusted position
        import time
        deadline = time.time() + 2
        while time.time() < deadline and \
                self.relay.mirror_status()["consecutive_failures"] == 0:
            time.sleep(0.02)
        self.assertEqual(self.trusted(), 1)
        self.assertGreaterEqual(
            self.relay.mirror_status()["consecutive_failures"], 1)
        # recovery: poller catches up by itself
        self.fault.director["mode"] = "ok"
        deadline = time.time() + 3
        while time.time() < deadline and self.trusted() != 3:
            time.sleep(0.05)
        self.relay.stop_poller()
        self.assertEqual(self.trusted(), 3)
        self.assertEqual(
            self.relay.mirror_status()["consecutive_failures"], 0)


class ObservabilityTests(RelayTestBase):
    def test_status_shows_height_backlog_holder_retries_reasons(self):
        self.seal_n(3)
        self.relay.sync_once()
        tok = self.make_tenant()
        c = self.claim(tok, "c1", ttl=30)
        self.advance(31)
        c2 = self.claim(tok, "c2")  # redelivered; retries == 1
        st = self.relay.status()
        self.assertEqual(st["mirror"]["trusted_tree_size"], 3)
        t = st["tenants"][0]
        self.assertEqual(t["backlog"], 3)
        self.assertEqual(t["current_delivery"]["lease_owner"], "c2")
        self.assertEqual(t["current_delivery"]["retries"], 1)
        self.assertTrue(t["current_delivery"]["lease_expired"] is False)
        # trigger a past-end submit rejection and verify it surfaces with a reason
        with self.assertRaises(AckEndMismatch):
            self.ack(tok, c2["delivery_id"], 1, "c2",
                     lease_token=c2["lease_token"])
        st = self.relay.status()
        self.assertEqual(st["reject_counts"]["ack_end_mismatch"], 1)
        reasons = {e["reason"] for e in st["events"] if e["kind"] == "reject"}
        self.assertIn("ack_end_mismatch", reasons)


class OfflineVerifyTests(RelayTestBase):
    def test_valid_packet_verifies_offline(self):
        self.seal_n(2)
        self.relay.sync_once()
        tok = self.make_tenant()
        packet = self.claim(tok)["delivery"]
        keys = load_relay_keys(self.relay_home)
        rep = verify_packet(packet, keys, expected_tenant="aud-a")
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertTrue(rep["checks"]["packet_signature"])
        self.assertTrue(rep["checks"]["checkpoint_signature"])

    def test_tampered_packet_fails(self):
        self.seal_n(1)
        self.relay.sync_once()
        tok = self.make_tenant()
        packet = self.claim(tok)["delivery"]
        keys = load_relay_keys(self.relay_home)
        tampered = json.loads(json.dumps(packet))
        tampered["records"][0]["envelope"]["payload"]["x"] = "injected"
        self.assertFalse(verify_packet(tampered, keys)["ok"])

    def test_wrong_keys_fail(self):
        self.seal_n(1)
        self.relay.sync_once()
        tok = self.make_tenant()
        packet = self.claim(tok)["delivery"]
        keys = load_relay_keys(self.relay_home)
        k2 = dict(keys)
        k2["relay_packet_secret"] = bytes(32)
        self.assertFalse(verify_packet(packet, k2)["ok"])
        k3 = dict(keys)
        k3["transparency_secret"] = bytes(32)
        self.assertFalse(verify_packet(packet, k3)["ok"])


# --------------------------------------------------------------------------- #
# HTTP API
# --------------------------------------------------------------------------- #

class HttpApiTests(RelayTestBase):
    def setUp(self):
        super().setUp()
        self.srv = serve_relay(self.relay, "127.0.0.1", 0)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        super().tearDown()

    def test_full_http_flow_and_rejections(self):
        self.seal_n(2)
        status, _ = http("POST", self.url + "/v1/admin/sync", self.admin)
        self.assertEqual(status, 200)
        status, body = http("POST", self.url + "/v1/admin/tenants", self.admin,
                            {"tenant_id": "t1", "name": "T1",
                             "max_inflight": 1,
                             "filter": {"event_types": ["release_sealed"]}})
        self.assertEqual(status, 201)
        token = body["token"]
        self.assertEqual(body["max_inflight"], 1)

        st, body = http("POST", self.url + "/v1/relay/claim", token,
                        {"consumer": "c1"})
        self.assertEqual(st, 200)
        did, end = body["delivery_id"], body["end_index"]

        # cross consumer contention
        st, body = http("POST", self.url + "/v1/relay/claim", token,
                        {"consumer": "intruder"})
        self.assertEqual(st, 409)
        self.assertEqual(body["error"], "lease_conflict")

        # bad token
        st, _ = http("POST", self.url + "/v1/relay/claim", "garbage",
                     {"consumer": "c1"})
        self.assertEqual(st, 401)

        # gap ack
        st, body = http("POST", self.url + "/v1/relay/ack", token,
                        {"delivery_id": did, "end_index": end + 1,
                         "consumer": "c1"})
        self.assertEqual(st, 409)
        self.assertEqual(body["error"], "ack_end_mismatch")

        # correct ack + duplicate
        for idem in (False, True):
            st, body = http("POST", self.url + "/v1/relay/ack", token,
                            {"delivery_id": did, "end_index": end,
                             "consumer": "c1"})
            self.assertEqual(st, 200)
            self.assertEqual(body["idempotent"], idem)

        # filter locked after consumption
        st, body = http("POST", self.url + "/v1/admin/tenants/t1/filter",
                        self.admin, {"filter": {"event_types": ["share_issued"]}})
        self.assertEqual(st, 409)
        self.assertEqual(body["error"], "filter_locked")

        # deactivation then claim 403
        st, _ = http("POST", self.url + "/v1/admin/tenants/t1/deactivate",
                     self.admin, {"reason": "done"})
        self.assertEqual(st, 200)
        st, body = http("POST", self.url + "/v1/relay/claim", token,
                        {"consumer": "c1"})
        self.assertEqual(st, 403)
        self.assertEqual(body["error"], "tenant_inactive")

        # observability
        st, body = http("GET", self.url + "/v1/admin/status?events=100",
                        self.admin)
        self.assertEqual(st, 200)
        self.assertEqual(body["mirror"]["trusted_tree_size"], 2)
        tenants = {t["tenant_id"]: t for t in body["tenants"]}
        self.assertEqual(tenants["t1"]["cursor_end"], end)
        self.assertIn("ack_end_mismatch", body["reject_counts"])
        self.assertIn("lease_conflict", body["reject_counts"])
        self.assertIn("tenant_inactive", body["reject_counts"])
        kinds = {e["kind"] for e in body["events"]}
        self.assertIn("first_sync", kinds)

    def test_admin_routes_require_admin(self):
        st, _ = http("GET", self.url + "/v1/admin/status", "not-admin")
        self.assertEqual(st, 401)
        st, _ = http("POST", self.url + "/v1/admin/sync", "not-admin")
        self.assertEqual(st, 401)

    def test_parallel_windows_barrier_shrink_takeover_over_http(self):
        self.seal_n(5)
        http("POST", self.url + "/v1/admin/sync", self.admin)
        # 小窗口：每片叶子一个窗口，便于并行领取多个相邻窗口
        self.relay.batch_size = 1
        st, body = http("POST", self.url + "/v1/admin/tenants", self.admin,
                        {"tenant_id": "pw", "name": "PW",
                         "max_inflight": 3})
        self.assertEqual(st, 201)
        tok = body["token"]

        def claim(c):
            return http("POST", self.url + "/v1/relay/claim", tok,
                        {"consumer": c, "ttl_seconds": 300})

        st, w1 = claim("w1")
        st, w2 = claim("w2")
        st, w3 = claim("w3")
        self.assertEqual(w1["end_index"], w2["start_index"])
        self.assertEqual(w2["end_index"], w3["start_index"])

        # 租户侧窗口视图
        st, body = http("GET", self.url + "/v1/relay/windows", tok)
        self.assertEqual(st, 200)
        self.assertEqual(body["inflight"], 3)
        self.assertEqual(body["commit_barrier"], 0)

        # 还有 2 片未切叶子，槽位已满 -> 并发领取上限背压
        st, body = claim("w9")
        self.assertEqual(st, 409)
        self.assertEqual(body["error"], "inflight_cap_reached")
        self.assertEqual(body["max_inflight"], 3)
        self.assertEqual(body["inflight"], 3)

        # 乱序提交 w3 -> 只完成，屏障不动
        st, body = http("POST", self.url + "/v1/relay/complete", tok,
                        {"delivery_id": w3["delivery_id"],
                         "end_index": w3["end_index"], "consumer": "w3",
                         "lease_token": w3["lease_token"]})
        self.assertEqual(st, 200)
        self.assertEqual(body["state"], "completed")
        self.assertEqual(body["commit_barrier"], 0)

        # 管理端收缩到 1（不抢占），随后新领取仍被背压
        st, body = http("POST", self.url + "/v1/admin/tenants/pw/max-inflight",
                        self.admin, {"max_inflight": 1})
        self.assertEqual(st, 200)
        self.assertTrue(body["shrink_pending"])
        st, body = claim("w9")
        self.assertEqual(st, 409)
        self.assertEqual(body["error"], "inflight_cap_reached")

        # 强制接管 w1
        st, body = http(
            "POST",
            f"{self.url}/v1/admin/tenants/pw/deliveries/"
            f"{w1['delivery_id']}/force-expire",
            self.admin, {"reason": "stuck"})
        self.assertEqual(st, 200)
        st, taken = claim("new1")
        self.assertEqual(st, 200)
        self.assertEqual(taken["delivery_id"], w1["delivery_id"])
        self.assertEqual(taken["lease_owner"], "new1")
        # 旧持有者提交被拒
        st, body = http("POST", self.url + "/v1/relay/ack", tok,
                        {"delivery_id": w1["delivery_id"],
                         "end_index": w1["end_index"], "consumer": "w1",
                         "lease_token": w1["lease_token"]})
        self.assertEqual(st, 409)
        self.assertEqual(body["error"], "stale_lease")

        # 补 w1（新持有者）-> 屏障停在 w2；补 w2 -> 穿过 w3 到末端
        st, body = http("POST", self.url + "/v1/relay/ack", tok,
                        {"delivery_id": taken["delivery_id"],
                         "end_index": taken["end_index"], "consumer": "new1",
                         "lease_token": taken["lease_token"]})
        self.assertEqual(body["commit_barrier"], w1["end_index"])
        st, body = http("POST", self.url + "/v1/relay/ack", tok,
                        {"delivery_id": w2["delivery_id"],
                         "end_index": w2["end_index"], "consumer": "w2",
                         "lease_token": w2["lease_token"]})
        self.assertEqual(body["commit_barrier"], w3["end_index"])

        # 管理端窗口视图：全部越过屏障，在途归零
        st, body = http("GET",
                        self.url + "/v1/admin/tenants/pw/windows?committed=1",
                        self.admin)
        self.assertEqual(st, 200)
        self.assertEqual(body["inflight"], 0)
        self.assertEqual(body["commit_barrier"], 3)
        self.assertEqual(len(body["committed_windows"]), 3)

    def test_ui_served(self):
        with urllib.request.urlopen(self.url + "/ui", timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("审计馈送中继", resp.read().decode("utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
