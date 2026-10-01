"""wrelay 并行窗口中继：全语义场景测试（零第三方，可直接运行或 pytest）。

覆盖：
并行领取上限、乱序完成+补洞推进屏障、幂等重放稳定字节、超时接管+旧持有者
拒绝、重复提交、越过窗口末端、跨租户 id、停用拒绝、筛选变更拒绝、收缩不抢
持有者、慢窗口不阻塞、重启恢复窗口边界/完成记录/提交顺序、HTTP API。
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest

from wrelay.app import bootstrap, open_relay
from wrelay.errors import (
    BadWindow, FilterChanged, InFlightCap, LeaseConflict, StaleLease,
    TenantInactive, WindowEndMismatch,
)
from wrelay.relay import Relay
from wrelay.store import connect


class FakeClock:
    def __init__(self, t: float = 1000.0):
        self.t = t
        self.cond = threading.Condition()

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float):
        self.t += dt


def make_record(i: int) -> dict:
    return {"event_type": "record_appended", "event_key": f"rec:{i:04d}",
            "subject_id": "subj", "payload": {"i": i}}


def feed(relay: Relay, tenant_id: str, n: int, *, start: int = 0):
    relay.append_records(tenant_id, [make_record(i) for i in range(start,
                                                                   start + n)])


class RelayCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = os.path.join(self.tmp.name, "whome")
        self.clock = FakeClock()
        bootstrap(self.home, window_size=60, max_inflight=3,
                  default_ttl_seconds=30)
        self.secrets_path = os.path.join(self.home, "secrets.json")
        self.relay = open_relay(self.home, clock=self.clock)

    def tearDown(self):
        self.relay.close()
        self.tmp.cleanup()

    def tenant(self, tid="aud-a", *, size=60, cap=3):
        info = self.relay.create_tenant(
            tid, tid, None, window_size=size, max_inflight=cap)
        return info["token"]

    # --------------------------------------------------------------- #
    # 1. 并行领取上限
    # --------------------------------------------------------------- #
    def test_parallel_claim_respects_max_inflight(self):
        token = self.tenant(cap=3)
        feed(self.relay, "aud-a", 300)  # 每条约 60 字节 → 5 个整窗
        w0 = self.relay.claim(token, "w1")
        w1 = self.relay.claim(token, "w2")
        w2 = self.relay.claim(token, "w3")
        self.assertEqual([w0["seq"], w1["seq"], w2["seq"]], [0, 1, 2])
        # 第 4 个活动在途窗口被上限拒绝
        with self.assertRaises(InFlightCap):
            self.relay.claim(token, "w4")
        st = self.relay.status(tenant_id="aud-a")["tenants"][0]
        self.assertEqual(st["active_inflight"], 3)
        self.assertEqual(st["max_inflight"], 3)

    # --------------------------------------------------------------- #
    # 2. 乱序完成：先完成靠后窗口，屏障不前进；补洞后一次推进连续前缀
    # --------------------------------------------------------------- #
    def test_out_of_order_completion_then_prefix_advance(self):
        token = self.tenant(cap=4)
        feed(self.relay, "aud-a", 300)
        w0 = self.relay.claim(token, "w1")
        w1 = self.relay.claim(token, "w2")
        w2 = self.relay.claim(token, "w3")
        w3 = self.relay.claim(token, "w4")

        # 乱序：先提交 #2、#3（都在 #0/#1 之前完成）
        c2 = self.relay.commit(token, w2["window_id"], w2["end_offset"], "w3")
        self.assertEqual(c2["commit_barrier"], 0)
        self.assertTrue(c2["hole_remains"])
        c3 = self.relay.commit(token, w3["window_id"], w3["end_offset"], "w4")
        self.assertEqual(c3["commit_barrier"], 0)   # 屏障纹丝不动
        self.assertEqual(c3["high_water"] if "high_water" in c3 else 0, 0)

        st = self.relay.status(tenant_id="aud-a")["tenants"][0]
        self.assertEqual(st["commit_barrier"], 0)
        self.assertEqual(st["high_water"], 240)     # 最远完成到 #3 末端
        self.assertEqual(st["holes"], [0, 1])       # 空洞 = #0,#1

        # 补 #0：连续前缀仍被 #1 挡住 → 屏障只到 #0 末端
        c0 = self.relay.commit(token, w0["window_id"], w0["end_offset"], "w1")
        self.assertEqual(c0["commit_barrier"], 60)
        self.assertEqual(c0["filled_windows"], [0])
        # 补 #1：一次吃掉 #1,#2,#3，屏障跳到 240
        c1 = self.relay.commit(token, w1["window_id"], w1["end_offset"], "w2")
        self.assertEqual(c1["commit_barrier"], 240)
        self.assertEqual(c1["filled_windows"], [1, 2, 3])
        self.assertEqual(c1["barrier_advanced_bytes"], 180)
        self.assertFalse(c1["hole_remains"])

    # --------------------------------------------------------------- #
    # 3. 租约内重放：同 window_id + 逐字节相同
    # --------------------------------------------------------------- #
    def test_lease_replay_same_id_and_bytes(self):
        token = self.tenant()
        feed(self.relay, "aud-a", 120)
        a = self.relay.claim(token, "w1")
        b = self.relay.fetch(token, "w1", a["window_id"])
        self.assertFalse(b["redispatched"])
        self.assertEqual(b["reason"], "replayed")
        self.assertEqual(b["window_id"], a["window_id"])
        self.assertEqual(b["window"]["payload_b64"], a["window"]["payload_b64"])
        self.assertEqual(b["retry_count"], 0)

    # --------------------------------------------------------------- #
    # 4. 超时接管：同 id/字节，epoch+1/retry+1；旧持有者提交被拒
    # --------------------------------------------------------------- #
    def test_timeout_takeover_fences_old_holder(self):
        token = self.tenant()
        feed(self.relay, "aud-a", 120)
        a = self.relay.claim(token, "slow")
        self.assertEqual(a["lease_epoch"], 1)
        self.clock.advance(31)  # 超过 30s TTL
        b = self.relay.fetch(token, "fast", a["window_id"])
        self.assertTrue(b["redispatched"])
        self.assertEqual(b["window_id"], a["window_id"])           # 标识不变
        self.assertEqual(b["window"]["payload_b64"],
                         a["window"]["payload_b64"])               # 字节不变
        self.assertEqual(b["lease_epoch"], 2)
        self.assertEqual(b["retry_count"], 1)
        self.assertEqual(b["holder"], "fast")

        # 旧持有者迟到提交：栅栏拒绝
        with self.assertRaises(StaleLease):
            self.relay.commit(token, a["window_id"], a["end_offset"], "slow")
        # 新持有者可提交
        c = self.relay.commit(token, a["window_id"], a["end_offset"], "fast")
        self.assertEqual(c["commit_barrier"], 60)

    def test_active_lease_cannot_be_stolen(self):
        token = self.tenant()
        feed(self.relay, "aud-a", 120)
        a = self.relay.claim(token, "owner")
        with self.assertRaises(LeaseConflict):
            self.relay.fetch(token, "thief", a["window_id"])

    # --------------------------------------------------------------- #
    # 5. 重复提交幂等，不重复推进
    # --------------------------------------------------------------- #
    def test_duplicate_commit_idempotent(self):
        token = self.tenant()
        feed(self.relay, "aud-a", 120)
        a = self.relay.claim(token, "w1")
        c1 = self.relay.commit(token, a["window_id"], a["end_offset"], "w1")
        c2 = self.relay.commit(token, a["window_id"], a["end_offset"], "w1")
        self.assertTrue(c2["idempotent"])
        self.assertEqual(c2["commit_barrier"], 60)
        self.assertEqual(c2["barrier_advanced_bytes"], 0)
        self.assertEqual(c1["commit_barrier"], c2["commit_barrier"])

    # --------------------------------------------------------------- #
    # 6. 越过窗口末端 / 部分提交拒绝
    # --------------------------------------------------------------- #
    def test_commit_end_mismatch_rejected(self):
        token = self.tenant()
        feed(self.relay, "aud-a", 120)
        a = self.relay.claim(token, "w1")
        with self.assertRaises(WindowEndMismatch):
            self.relay.commit(token, a["window_id"], 9999, "w1")  # 越过末端
        with self.assertRaises(WindowEndMismatch):
            self.relay.commit(token, a["window_id"], 30, "w1")    # 部分提交
        st = self.relay.status(tenant_id="aud-a")["tenants"][0]
        self.assertEqual(st["commit_barrier"], 0)
        self.assertEqual(st["windows"][0]["state"], "leased")

    # --------------------------------------------------------------- #
    # 7. 跨租户 window_id 拒绝
    # --------------------------------------------------------------- #
    def test_cross_tenant_window_rejected(self):
        ta = self.tenant("aud-a")
        tb = self.tenant("aud-b")
        feed(self.relay, "aud-a", 120)
        feed(self.relay, "aud-b", 120)
        wa = self.relay.claim(ta, "wA")
        with self.assertRaises(BadWindow):
            self.relay.commit(tb, wa["window_id"], wa["end_offset"], "wB")
        with self.assertRaises(BadWindow):
            self.relay.fetch(tb, "wB", wa["window_id"])

    # --------------------------------------------------------------- #
    # 8. 停用拒绝（历史与屏障保留）
    # --------------------------------------------------------------- #
    def test_deactivated_tenant_rejected_but_history_retained(self):
        token = self.tenant()
        feed(self.relay, "aud-a", 120)
        a = self.relay.claim(token, "w1")
        self.relay.commit(token, a["window_id"], a["end_offset"], "w1")
        self.relay.deactivate_tenant("aud-a", "离场")
        with self.assertRaises(TenantInactive):
            self.relay.claim(token, "w1")
        with self.assertRaises(TenantInactive):
            self.relay.commit(token, a["window_id"], a["end_offset"], "w1")
        st = self.relay.status(tenant_id="aud-a")["tenants"][0]
        self.assertFalse(st["active"])
        self.assertEqual(st["commit_barrier"], 60)   # 历史保留

    # --------------------------------------------------------------- #
    # 9. 在途期间筛选规则变更：旧版本窗口提交被拒，重投后可提交
    # --------------------------------------------------------------- #
    def test_filter_change_rejects_stale_window_commit(self):
        token = self.tenant()
        feed(self.relay, "aud-a", 120)
        a = self.relay.claim(token, "w1")
        self.assertEqual(a["filter_version"], 1)
        self.relay.set_filter("aud-a", {"event_types": ["share_issued"]})
        # 用旧筛选版本的在途窗口提交 → 拒绝，屏障不动
        with self.assertRaises(FilterChanged):
            self.relay.commit(token, a["window_id"], a["end_offset"], "w1")
        # 持有者立即重领（租约内，不超时）获得新筛选版本，仍可提交
        b = self.relay.fetch(token, "w1", a["window_id"])
        self.assertEqual(b["window"]["filter_version"], 2)
        # 注：租约内重领不前进 epoch；提交仍以新版本通过
        c = self.relay.commit(token, a["window_id"], a["end_offset"], "w1")
        self.assertEqual(c["commit_barrier"], 60)

    def test_filter_change_without_inflight_is_fine(self):
        token = self.tenant()
        # 还没有任何窗口，改规则不产生在途失配
        self.relay.set_filter("aud-a", {"event_types": ["share_issued"]})
        feed(self.relay, "aud-a", 60)
        a = self.relay.claim(token, "w1")
        self.assertEqual(a["filter_version"], 2)

    # --------------------------------------------------------------- #
    # 10. 动态收缩 max_inflight：不抢有效持有者，只阻止继续领取
    # --------------------------------------------------------------- #
    def test_shrink_does_not_preempt_valid_holders(self):
        token = self.tenant(cap=4)
        feed(self.relay, "aud-a", 300)
        w0 = self.relay.claim(token, "w1")
        w1 = self.relay.claim(token, "w2")
        self.relay.set_max_inflight("aud-a", 1)   # 4 → 1
        # 两个持有者仍有效，未被抢占
        for w in (w0, w1):
            r = self.relay.fetch(token, w["holder"], w["window_id"])
            self.assertEqual(r["holder"], w["holder"])
            self.assertFalse(r["redispatched"])
        # 收缩后不能再领新窗口（已有 2 个活动 > 上限 1）
        with self.assertRaises(InFlightCap):
            self.relay.claim(token, "w3")
        # 完成一个，释放活动槽；但仍有 1 活动 == 上限 1，不能再领
        self.relay.commit(token, w0["window_id"], w0["end_offset"], "w1")
        with self.assertRaises(InFlightCap):
            self.relay.claim(token, "w3")
        # 再完成一个，活动降到 0，又可以领取（收缩冲突解除）
        self.relay.commit(token, w1["window_id"], w1["end_offset"], "w2")
        w2 = self.relay.claim(token, "w3")
        self.assertEqual(w2["seq"], 2)

    def test_grow_allows_more_windows(self):
        token = self.tenant(cap=1)
        feed(self.relay, "aud-a", 300)
        self.relay.claim(token, "w1")
        with self.assertRaises(InFlightCap):
            self.relay.claim(token, "w2")
        self.relay.set_max_inflight("aud-a", 3)
        self.assertEqual(self.relay.claim(token, "w2")["seq"], 1)
        self.assertEqual(self.relay.claim(token, "w3")["seq"], 2)

    # --------------------------------------------------------------- #
    # 11. 慢窗口不阻塞：同租户后续窗口 + 其他租户
    # --------------------------------------------------------------- #
    def test_slow_window_does_not_block_others(self):
        ta = self.tenant("aud-a", cap=4)
        tb = self.tenant("aud-b", cap=2)
        feed(self.relay, "aud-a", 300)
        feed(self.relay, "aud-b", 180)
        a0 = self.relay.claim(ta, "slow-a")
        a1 = self.relay.claim(ta, "fast-a")
        a2 = self.relay.claim(ta, "fast-a2")
        # #0 卡住，先把 #1,#2 完成
        self.relay.commit(ta, a1["window_id"], a1["end_offset"], "fast-a")
        self.relay.commit(ta, a2["window_id"], a2["end_offset"], "fast-a2")
        # 租户 B 完全不受影响：领取并提交，屏障推进
        b0 = self.relay.claim(tb, "wB")
        b1 = self.relay.claim(tb, "wB2")
        cb = self.relay.commit(tb, b0["window_id"], b0["end_offset"], "wB")
        self.assertEqual(cb["commit_barrier"], 60)
        self.relay.commit(tb, b1["window_id"], b1["end_offset"], "wB2")
        stb = self.relay.status(tenant_id="aud-b")["tenants"][0]
        self.assertEqual(stb["commit_barrier"], 120)
        # 租户 A 屏障仍卡在 0（#0 空洞），但后续窗口已完成
        sta = self.relay.status(tenant_id="aud-a")["tenants"][0]
        self.assertEqual(sta["commit_barrier"], 0)
        self.assertEqual(sta["holes"][0], 0)
        # 慢窗口最终完成，屏障一次补齐
        ca = self.relay.commit(ta, a0["window_id"], a0["end_offset"], "slow-a")
        self.assertEqual(ca["commit_barrier"], 180)
        self.assertEqual(ca["filled_windows"], [0, 1, 2])

    # --------------------------------------------------------------- #
    # 12. 重启恢复：边界/完成记录/提交顺序不变
    # --------------------------------------------------------------- #
    def test_restart_preserves_boundaries_completion_and_order(self):
        token = self.tenant(cap=4)
        feed(self.relay, "aud-a", 300)
        w0 = self.relay.claim(token, "w1")
        w1 = self.relay.claim(token, "w2")
        w2 = self.relay.claim(token, "w3")
        # 乱序完成 #2，屏障不动
        self.relay.commit(token, w2["window_id"], w2["end_offset"], "w3")
        # 一个仍在租约内的窗口
        expected_id = w1["window_id"]
        expected_bytes = w1["window"]["payload_b64"]

        self.relay.close()
        # 新进程、新时钟打开（open_relay 会 recover）
        clock2 = FakeClock(self.clock.t - 5)  # 让 #1 租约仍未超时
        relay2 = open_relay(self.home, clock=clock2)
        st = relay2.status(tenant_id="aud-a")["tenants"][0]
        self.assertEqual(st["commit_barrier"], 0)       # 重启不越洞推进
        self.assertEqual(st["high_water"], 180)
        self.assertEqual(st["holes"], [0, 1])
        # 窗口边界与字节稳定
        self.assertEqual(st["windows"][1]["start_offset"], 60)
        self.assertEqual(st["windows"][1]["end_offset"], 120)
        # 重新领取仍在租约窗口 → 同 id 同字节
        rf = relay2.fetch(token, "w2", expected_id)
        self.assertEqual(rf["window_id"], expected_id)
        self.assertEqual(rf["window"]["payload_b64"], expected_bytes)
        # 继续补洞：#0 完成后 #1 仍卡；#1 完成后屏障补齐到 180
        relay2.commit(token, w0["window_id"], w0["end_offset"], "w1")
        c1 = relay2.commit(token, w1["window_id"], w1["end_offset"], "w2")
        self.assertEqual(c1["commit_barrier"], 180)
        relay2.close()

    def test_restart_advances_barrier_when_hole_filled_before_crash(self):
        token = self.tenant(cap=2)
        feed(self.relay, "aud-a", 180)
        w0 = self.relay.claim(token, "w1")
        w1 = self.relay.claim(token, "w2")
        # 全部完成，但直接验证 recover 能重建到正确屏障
        self.relay.commit(token, w0["window_id"], w0["end_offset"], "w1")
        self.relay.commit(token, w1["window_id"], w1["end_offset"], "w2")
        self.relay.close()
        relay2 = open_relay(self.home, clock=FakeClock())
        st = relay2.status(tenant_id="aud-a")["tenants"][0]
        self.assertEqual(st["commit_barrier"], 120)
        relay2.close()

    # --------------------------------------------------------------- #
    # 13. 封口尾窗：边界定型
    # --------------------------------------------------------------- #
    def test_sealed_tail_window_has_fixed_boundary(self):
        token = self.tenant(size=64, cap=4)
        # 精确喂 80 字节：一个 64 字节整窗 + 16 字节未填满尾窗
        self.relay.append_bytes("aud-a", b"x" * 80)
        w0 = self.relay.claim(token, "w1")
        self.assertEqual((w0["start_offset"], w0["end_offset"]), (0, 64))
        # 尾窗未封口、未填满 → 暂不可领
        none = self.relay.claim(token, "w2")
        self.assertIsNone(none["window"])
        self.relay.seal_stream("aud-a")
        w1 = self.relay.claim(token, "w2")
        self.assertEqual((w1["start_offset"], w1["end_offset"]), (64, 80))
        self.assertEqual(w1["window"]["size"], 16)
        self.relay.commit(token, w0["window_id"], w0["end_offset"], "w1")
        c = self.relay.commit(token, w1["window_id"], w1["end_offset"], "w2")
        self.assertEqual(c["commit_barrier"], 80)

    # --------------------------------------------------------------- #
    # 14. 拒绝全部落审计事件
    # --------------------------------------------------------------- #
    def test_rejections_are_audited(self):
        token = self.tenant()
        feed(self.relay, "aud-a", 120)
        a = self.relay.claim(token, "w1")
        for fn in (
            lambda: self.relay.commit(token, a["window_id"], 1, "w1"),
            lambda: self.relay.commit(token, "afw_nope", 60, "w1"),
        ):
            try:
                fn()
            except Exception:
                pass
        counts = self.relay.reject_counts(tenant_id="aud-a")
        self.assertIn("window_end_mismatch", counts)
        self.assertIn("bad_window", counts)


# --------------------------------------------------------------------------- #
# HTTP 端到端
# --------------------------------------------------------------------------- #

class HttpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = os.path.join(self.tmp.name, "whome")
        self.clock = FakeClock()
        info = bootstrap(self.home, window_size=60, max_inflight=3,
                         default_ttl_seconds=30)
        self.admin = info["admin_token"]
        self.relay = open_relay(self.home, clock=self.clock)
        from wrelay.server import serve

        self.httpd = serve(self.relay, "127.0.0.1", 0)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)
        self.thread.start()
        import urllib.request
        self.urlopen = urllib.request.urlopen
        import urllib.error
        self.httperror = urllib.error.HTTPError

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        self.relay.close()
        self.tmp.cleanup()

    def call(self, method, path, token=None, body=None):
        import urllib.request

        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with self.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode())
        except self.httperror as e:
            return e.code, json.loads(e.read().decode())

    def test_http_full_flow_and_ui(self):
        st, body = self.call("POST", "/v1/admin/tenants", self.admin, {
            "tenant_id": "aud-a", "name": "aud-a",
            "window_size": 60, "max_inflight": 3})
        self.assertEqual(st, 201)
        token = body["token"]
        self.call("POST", "/v1/admin/tenants/aud-a/append", self.admin,
                  {"records": [make_record(i) for i in range(24)]})
        st, w0 = self.call("POST", "/v1/relay/claim", token, {"worker": "w1"})
        self.assertEqual(st, 200)
        st, w1 = self.call("POST", "/v1/relay/claim", token, {"worker": "w2"})
        self.assertEqual(st, 200)
        # cap
        st, cap = self.call("POST", "/v1/relay/claim", token, {"worker": "w3"})
        st, cap = self.call("POST", "/v1/relay/claim", token, {"worker": "w4"})
        self.assertEqual(st, 409)
        self.assertEqual(cap["error"], "inflight_cap_reached")
        # 乱序提交 #1
        st, c1 = self.call("POST", "/v1/relay/commit", token,
                           {"window_id": w1["window_id"],
                            "end_offset": w1["end_offset"], "worker": "w2"})
        self.assertEqual(c1["commit_barrier"], 0)
        # 补 #0
        st, c0 = self.call("POST", "/v1/relay/commit", token,
                           {"window_id": w0["window_id"],
                            "end_offset": w0["end_offset"], "worker": "w1"})
        self.assertEqual(c0["commit_barrier"], 120)
        # 状态
        st, status = self.call("GET", "/v1/relay/status", token)
        t0 = status["tenants"][0]
        self.assertEqual(t0["commit_barrier"], 120)
        self.assertTrue(any(w["state"] == "completed" for w in t0["windows"]))
        # 运维页可达
        import urllib.request
        with self.urlopen(f"http://127.0.0.1:{self.port}/ui", timeout=10) as r:
            html = r.read().decode()
        self.assertIn("并行窗口中继", html)
        # healthz
        st, h = self.call("GET", "/healthz")
        self.assertTrue(h["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
