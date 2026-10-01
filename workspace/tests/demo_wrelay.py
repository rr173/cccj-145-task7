"""wrelay 端到端演示：真实 HTTP 服务 + 跨进程重启。

用法::

    PYTHONPATH=/workspace python3 tests/demo_wrelay.py

脚本依次启动/停止/重启服务，打印六个可在 HTTP/CLI/运维页观察到的场景：

  1. 并发领取上限（max_inflight）
  2. 乱序完成后补洞推进连续提交屏障
  3. 超时接管（旧持有者迟到提交被拒）
  4. 动态收缩不抢持有者 + 慢窗口不阻塞其他租户
  5. 停用拒绝
  6. 进程重启恢复窗口边界/完成记录/提交顺序
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Client:
    def __init__(self, base: str):
        self.base = base

    def call(self, method, path, token=None, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())


def banner(n, title):
    print("\n" + "=" * 74)
    print(f"场景 {n}：{title}")
    print("=" * 74)


def wait_up(c: Client, timeout=8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c.call("GET", "/healthz")
            return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("server did not come up")


def main() -> int:
    home = tempfile.mkdtemp(prefix="wrelay-demo-")
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    c = Client(base)
    env = dict(os.environ, PYTHONPATH=ROOT)
    procs = []

    def start():
        if not os.path.exists(os.path.join(home, "config.json")):
            initp = subprocess.run(
                [PY, "-m", "wrelay", "init", home,
                 "--window-size", "60", "--max-inflight", "4", "--ttl", "2"],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            assert initp.returncode == 0
        srv = subprocess.Popen(
            [PY, "-m", "wrelay", "serve", home, "--port", str(port)],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(srv)
        wait_up(c)
        return srv

    def stop(srv):
        srv.send_signal(signal.SIGINT)
        srv.wait(timeout=8)

    try:
        srv = start()

        # ---- 初始化（init 只在 home 为空时生效；取 admin token）----
        secrets = json.load(open(os.path.join(home, "secrets.json")))
        admin = secrets["admin_token"]

        # ---- 建两个租户，喂数据 ----
        _, ta = c.call("POST", "/v1/admin/tenants", admin, {
            "tenant_id": "aud-a", "name": "A组审计",
            "window_size": 60, "max_inflight": 4})
        _, tb = c.call("POST", "/v1/admin/tenants", admin, {
            "tenant_id": "aud-b", "name": "B组审计",
            "window_size": 60, "max_inflight": 2})
        token_a, token_b = ta["token"], tb["token"]
        recs = [{"event_type": "record_appended", "event_key": f"r{i:03d}",
                 "subject_id": "s", "payload": {"i": i}} for i in range(40)]
        c.call("POST", "/v1/admin/tenants/aud-a/append", admin,
               {"records": recs})
        c.call("POST", "/v1/admin/tenants/aud-b/append", admin,
               {"records": recs[:12]})
        c.call("POST", "/v1/admin/tenants/aud-b/seal", admin, {})

        # ---- 场景 1：并发领取上限 ----
        banner(1, "并发领取上限（max_inflight=4）")
        wins = []
        for worker in ("w1", "w2", "w3", "w4"):
            st, r = c.call("POST", "/v1/relay/claim", token_a,
                           {"worker": worker, "ttl_seconds": 30})
            wins.append(r)
            print(f"  {worker} 领取 #{r['seq']} 区间"
                  f"[{r['start_offset']},{r['end_offset']}) id={r['window_id'][:16]}…")
        st, r = c.call("POST", "/v1/relay/claim", token_a,
                       {"worker": "w5", "ttl_seconds": 30})
        print(f"  w5 再领 → HTTP {st} {r['error']}（活动在途已达上限）")

        # ---- 场景 2：乱序完成 + 补洞推进 ----
        banner(2, "乱序完成后补洞，连续提交屏障一次推进")

        def commit(token, w, worker, end=None):
            return c.call("POST", "/v1/relay/commit", token,
                          {"window_id": w["window_id"],
                           "end_offset": w["end_offset"] if end is None else end,
                           "worker": worker})

        st, r = commit(token_a, wins[3], "w4")
        print(f"  先完成 #3（w4）：屏障={r['commit_barrier']} "
              f"空洞残留={r['hole_remains']}（只登记完成事实）")
        st, r = commit(token_a, wins[2], "w3")
        print(f"  再完成 #2（w3）：屏障={r['commit_barrier']}（前方 #0,#1 仍缺）")
        st, r = commit(token_a, wins[0], "w1")
        print(f"  补 #0（w1）：屏障={r['commit_barrier']}（仍被 #1 挡住）")
        st, r = commit(token_a, wins[1], "w2")
        print(f"  补 #1（w2）：屏障={r['commit_barrier']} "
              f"本次补齐窗口={r['filled_windows']} "
              f"推进字节={r['barrier_advanced_bytes']}")

        # ---- 场景 3：超时接管 ----
        banner(3, "超时接管：新 worker 接走窗口，旧持有者提交被拒")
        st, slow = c.call("POST", "/v1/relay/claim", token_a,
                          {"worker": "slow", "ttl_seconds": 1})
        print(f"  slow 领取 #{slow['seq']}，TTL=1s，epoch={slow['lease_epoch']}")
        time.sleep(1.3)
        st, fast = c.call("POST", "/v1/relay/fetch", token_a,
                          {"worker": "fast", "window_id": slow["window_id"],
                           "ttl_seconds": 30})
        print(f"  超时后 fast 接管：同 id={fast['window_id']==slow['window_id']} "
              f"字节相同={fast['window']['payload_b64']==slow['window']['payload_b64']} "
              f"epoch={fast['lease_epoch']} 重试={fast['retry_count']}")
        st, r = commit(token_a, slow, "slow")
        print(f"  旧持有者 slow 迟到提交 → HTTP {st} {r['error']}（栅栏拒绝）")
        st, r = commit(token_a, fast, "fast")
        print(f"  新持有者 fast 提交 → HTTP {st}，屏障={r['commit_barrier']}")

        # ---- 场景 4：收缩不抢持有者 + 慢窗口不阻塞 B ----
        banner(4, "动态收缩不抢持有者；慢窗口不阻塞其他租户")
        # 先让 A 持有两个有效在途窗口，再收缩到 1
        st, h1 = c.call("POST", "/v1/relay/claim", token_a,
                        {"worker": "hold1", "ttl_seconds": 60})
        st, h2 = c.call("POST", "/v1/relay/claim", token_a,
                        {"worker": "hold2", "ttl_seconds": 60})
        st, r = c.call("POST", "/v1/admin/tenants/aud-a/inflight", admin,
                       {"max_inflight": 1})
        print(f"  A 持有 #{h1['seq']},#{h2['seq']} 两个有效窗口；"
              f"max_inflight 4→1")
        st, more = c.call("POST", "/v1/relay/claim", token_a, {"worker": "w9"})
        print(f"  收缩后领新窗口 → HTTP {st} {more.get('error')}"
              f"（2 个活动在途 > 上限 1；已有持有者不被抢占）")
        st, r = commit(token_a, h1, "hold1")
        print(f"  完成 #{h1['seq']} 后活动在途=1，仍不可领新窗口")
        st, more = c.call("POST", "/v1/relay/claim", token_a, {"worker": "w9"})
        print(f"    再领 → HTTP {st} {more.get('error')}")
        st, r = commit(token_a, h2, "hold2")
        st, more = c.call("POST", "/v1/relay/claim", token_a,
                          {"worker": "hold3"})
        print(f"  完成 #{h2['seq']} 后活动在途=0，领取恢复 → "
              f"#{more['seq']}（收缩冲突随槽位释放解除）")
        commit(token_a, more, "hold3")
        # B 租户完全独立推进（与 A 的慢窗口互不影响）
        b_wins = []
        for wk in ("b1", "b2"):
            st, w = c.call("POST", "/v1/relay/claim", token_b,
                           {"worker": wk, "ttl_seconds": 30})
            b_wins.append(w)
        st, cb2 = commit(token_b, b_wins[1], "b2")  # 乱序
        print(f"  B 先完成高窗口：屏障={cb2['commit_barrier']}")
        st, cb1 = commit(token_b, b_wins[0], "b1")
        print(f"  B 补齐后屏障={cb1['commit_barrier']}（不受 A 的慢窗口影响）")

        # ---- 场景 5：停用拒绝 ----
        banner(5, "停用租户：claim/commit 一律拒绝，屏障历史保留")
        c.call("POST", "/v1/admin/tenants/aud-b/deactivate", admin,
               {"reason": "审计离场"})
        st, r = c.call("POST", "/v1/relay/claim", token_b, {"worker": "x"})
        print(f"  停用后 claim → HTTP {st} {r['error']}")
        st, r = c.call("POST", "/v1/relay/commit", token_b,
                       {"window_id": b_wins[0]["window_id"],
                        "end_offset": b_wins[0]["end_offset"], "worker": "b1"})
        print(f"  停用后 commit → HTTP {st} {r['error']}")
        st, status = c.call("GET", "/v1/admin/status", admin)
        bstat = next(t for t in status["tenants"] if t["tenant_id"] == "aud-b")
        print(f"  B 历史保留：active={bstat['active']} 屏障={bstat['commit_barrier']}")

        # ---- 场景 6：重启恢复 ----
        banner(6, "进程重启：窗口边界/完成记录/提交顺序不变")
        c.call("POST", "/v1/admin/tenants/aud-a/inflight", admin,
               {"max_inflight": 4})
        # 制造一个乱序未补洞现场：领取两个相邻窗口，只完成靠后的那个
        st, g0 = c.call("POST", "/v1/relay/claim", token_a,
                        {"worker": "g0", "ttl_seconds": 600})
        st, g1 = c.call("POST", "/v1/relay/claim", token_a,
                        {"worker": "g1", "ttl_seconds": 600})
        st, r = commit(token_a, g1, "g1")
        print(f"  重启前乱序完成 #{g1['seq']}，屏障停在 {r['commit_barrier']}，"
              f"前有空洞 #{g0['seq']}")
        stop(srv)
        print("  --- 进程已退出，重新启动 ---")
        srv = start()
        st, status = c.call("GET", "/v1/admin/status", admin)
        astat = next(t for t in status["tenants"] if t["tenant_id"] == "aud-a")
        print(f"  重启后屏障={astat['commit_barrier']}（未越洞），"
              f"高水位={astat['high_water']}，空洞={astat['holes']}")
        # 重新领取仍在租约窗口：同 id 同字节
        st, rf = c.call("POST", "/v1/relay/fetch", token_a,
                        {"worker": "g0", "window_id": g0["window_id"]})
        same = rf["window_id"] == g0["window_id"] and \
            rf["window"]["payload_b64"] == g0["window"]["payload_b64"]
        print(f"  重新领取 #{g0['seq']}：同窗口标识与原始字节={same}，"
              f"重试次数={rf['retry_count']}（租约未超时，不接管）")
        st, r = commit(token_a, g0, "g0")
        print(f"  补齐空洞 #{g0['seq']}：屏障推进到 {r['commit_barrier']} "
              f"补齐窗口={r['filled_windows']}")

        print("\n运维页：", base + "/ui")
        print("提示：保持本脚本的 home 已随进程退出清理；可手动 `python -m "
              "wrelay serve <home>` 打开页面观察。")
        return 0
    finally:
        for p in procs:
            if p.poll() is None:
                p.send_signal(signal.SIGINT)
                try:
                    p.wait(timeout=5)
                except Exception:
                    p.kill()
        shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
