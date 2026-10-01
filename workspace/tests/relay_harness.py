"""afrelay 测试共用夹具。

* :class:`GatewayWorld` -- 用 dpgw 测试夹具产出真实已签名透明度叶子，并以
  真实 HTTP 提供只读接口（/v1/transparency*），供中继通过网络拉取；
* :class:`FaultyUpstream` -- 包在真实上游外面的可脚本化故障服务器，可模拟
  上游不可用、回退高度、坏签名 checkpoint、inclusion 证明缺口/错误叶子，
  以及“冻结在某个高度”。
"""

from __future__ import annotations

import json
import os
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(__file__))
from harness import Harness  # noqa: E402


class GatewayWorld:
    """一个产出真实叶子的 dpgw 网关 + 真实只读 HTTP 服务。"""

    def __init__(self):
        self.h = Harness()
        snap, _, _ = self.h.publish("v1")
        self.sid = snap["snapshot_id"]
        for name in ("alpha", "beta", "gamma"):
            self.h.grant(name, self.sid, 5.0)
        self.ta, self.tb, self.tg = (self.h.tid(n) for n in
                                     ("alpha", "beta", "gamma"))
        self.server = serve_gateway(self.h.gw, self.h.admin_token)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.token = self.h.admin_token

    def seal(self, name="b", *teams, minp=2, city="BJ"):
        from datetime import datetime, timedelta, timezone

        def iso_in(s):
            return (datetime.now(timezone.utc) + timedelta(seconds=s)).isoformat()

        q = {"type": "count", "epsilon": 0.3,
             "filter": {"op": "cmp", "column": "city", "predicate": "=",
                        "value": city}}
        stmt = {"snapshot": {"snapshot_id": self.sid}, "query": q}
        v = self.h.gw.create_publication(
            name, [stmt], minp, iso_in(3600), actor="lead")
        teams = teams or (self.ta, self.tb)
        for t in teams:
            self.h.gw.register_contribution(v["version_id"], t)
        self.h.gw.seal_publication(v["version_id"])
        return v["version_id"]

    def make_share(self, vid=None):
        from dpgw.shares import all_catalog_fields
        if vid is None:
            vid = self.seal("shareb")
        self.h.gw.grant_share_fields(vid, self.ta, all_catalog_fields())
        return self.h.gw.create_share(vid, self.ta, all_catalog_fields(),
                                      ttl_seconds=3600)

    def revoke(self, share):
        return self.h.gw.revoke_share(share["share_id"], reason="test")

    @property
    def transparency_key_hex(self):
        with open(os.path.join(self.h.home, "secrets.json")) as fh:
            return json.load(fh)["transparency_secret"]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.h.close()


# --------------------------------------------------------------------------- #
# real read-only gateway HTTP server
# --------------------------------------------------------------------------- #

class _GWHandler(BaseHTTPRequestHandler):
    server_version = "gw-test/1.0"

    def log_message(self, *a):
        return

    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        if self.headers.get("Authorization") != "Bearer " + self.server.token:
            return self._send(401, {"error": "unauthorized"})
        parsed = urlparse(self.path)
        q = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
        gw = self.server.gw
        try:
            if parsed.path == "/v1/transparency":
                return self._send(200, gw.tl_state())
            if parsed.path == "/v1/transparency/checkpoint":
                return self._send(200, gw.tl_checkpoint(int(q["tree_size"])))
            if parsed.path.startswith("/v1/transparency/inclusion/"):
                idx = int(parsed.path.rsplit("/", 1)[-1])
                return self._send(200, gw.tl_inclusion(idx, int(q["tree_size"])))
            self._send(404, {"error": "not_found"})
        except Exception as exc:
            self._send(500, {"error": "boom", "message": str(exc)})


def serve_gateway(gw, token: str) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _GWHandler)
    srv.gw = gw
    srv.token = token
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# --------------------------------------------------------------------------- #
# scriptable faulty upstream
# --------------------------------------------------------------------------- #

class FaultyUpstream:
    """Proxy in front of a real gateway that can misbehave per scenario.

    modes (set ``director['mode']``):

    * ``ok``             pass through
    * ``down``           close the connection (upstream unavailable)
    * ``rollback``       report tree_size one less than the real head
    * ``bad_signature``  checkpoint with a recomputed-but-wrong sig
    * ``bad_leaf``       inclusion envelope tampered (content address fails)
    * ``proof_gap``      drop/invalidate the inclusion path
    * ``freeze``         state reports frozen with ``frozen_tree_size`` cap
    """

    def __init__(self, world: GatewayWorld):
        self.world = world
        self.director = {"mode": "ok", "freeze_at": None}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _FaultHandler)
        self.server.director = self.director
        self.server.upstream = world.base
        self.server.token = world.token
        srv = self.server
        srv.daemon_threads = True
        self.thread = threading.Thread(target=srv.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{srv.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class _FaultHandler(BaseHTTPRequestHandler):
    server_version = "faulty/1.0"

    def log_message(self, *a):
        return

    def _upstream(self, path: str) -> dict:
        url = self.server.upstream + path
        req = urllib.request.Request(url, headers={
            "Authorization": "Bearer " + self.server.token})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())

    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        d = self.server.director
        mode = d["mode"]
        parsed = urlparse(self.path)
        q = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
        if mode == "down":
            # kill the socket abruptly
            self.close_connection = True
            return
        try:
            if parsed.path == "/v1/transparency":
                st = self._upstream(self.path)
                if mode == "rollback":
                    st["tree_size"] = max(0, st["tree_size"] - 1)
                if mode == "freeze":
                    cap = d["freeze_at"]
                    if cap is None:
                        cap = st["tree_size"]
                    st["frozen"] = True
                    st["freeze_reason"] = "fork_evidence"
                    st["frozen_tree_size"] = cap
                return self._send(200, st)

            if parsed.path == "/v1/transparency/checkpoint":
                doc = self._upstream(self.path)
                if mode == "bad_signature":
                    cp = doc["checkpoint"]
                    cp["sig"] = "0" * len(cp["sig"])
                    doc["checkpoint"] = cp
                return self._send(200, doc)

            if parsed.path.startswith("/v1/transparency/inclusion/"):
                doc = self._upstream(self.path)
                if mode == "bad_leaf":
                    doc["envelope"]["subject_id"] = "forged-by-upstream"
                if mode == "proof_gap" and doc["inclusion_path"]:
                    doc["inclusion_path"][0] = "00" * 32
                return self._send(200, doc)
            self._send(404, {"error": "not_found"})
        except Exception as exc:
            self._send(502, {"error": "fault", "message": str(exc)})
