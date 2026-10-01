"""中继 HTTP API + 运维页。

租户侧（租户令牌 ``dprt_…``）::

    POST /v1/relay/claim   {"consumer": "...", "ttl_seconds"?: int}
    POST /v1/relay/ack     {"delivery_id","end_index","consumer"}
    GET  /v1/relay/status
    GET  /v1/relay/mirror

管理侧（管理员令牌 ``afra_…``，前缀 /v1/admin）::

    GET  /v1/admin/status                 镜像/全部租户/拒绝/事件
    POST /v1/admin/sync                   立即触发一轮拉取
    GET  /v1/admin/mirror/leaves
    POST /v1/admin/tenants                创建租户（返回一次性令牌）
    GET  /v1/admin/tenants
    POST /v1/admin/tenants/<id>/filter    消费开始前可改；开始后 409
    POST /v1/admin/tenants/<id>/deactivate
    GET  /ui                              运维单页
"""

from __future__ import annotations

import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .errors import InvalidBody, RelayError, Unauthorized
from .webui import UI_ASSETS


class _Handler(BaseHTTPRequestHandler):
    server_version = "afrelay/1.0"

    def log_message(self, fmt, *args):  # noqa: N802
        return

    @property
    def relay(self):
        return self.server.relay

    # ------------------------------------------------------------------ #

    def _send(self, status: int, body=None, *, raw: bytes | None = None,
              content_type: str = "application/json"):
        payload = raw if raw is not None else \
            json.dumps(body, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise InvalidBody("invalid JSON body")
        if not isinstance(data, dict):
            raise InvalidBody("JSON body must be an object")
        return data

    def _bearer(self) -> str:
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            raise Unauthorized("missing bearer token")
        return h[len("Bearer "):].strip()

    def _tenant_token(self) -> str:
        return self._bearer()

    def _admin(self) -> None:
        if not self.relay.check_admin(self._bearer()):
            raise Unauthorized("admin token required")

    def _query(self) -> dict:
        parsed = urllib.parse.urlparse(self.path)
        return {k: v[-1] for k, v in urllib.parse.parse_qs(parsed.query).items()}

    # ------------------------------------------------------------------ #

    def do_GET(self):  # noqa: N802
        self._dispatch("GET")

    def do_POST(self):  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str):
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/healthz" and method == "GET":
                return self._send(200, {"ok": True, "service": "afrelay"})
            if path == "/" or path.startswith("/ui"):
                return self._serve_ui(path)
            routes = self.server.routes.get(method, {})
            for pattern, handler in routes.items():
                m = pattern.match(path)
                if m:
                    return handler(self, **m.groupdict())
            self._send(404, {"error": "not_found", "message": f"{method} {path}"})
        except RelayError as e:
            self._send(e.status, e.to_dict())
        except Exception:
            self._send(500, {"error": "internal_error",
                             "message": "internal error"})

    def _serve_ui(self, path: str):
        rel = "index.html" if path in ("/", "/ui", "/ui/") else path[len("/ui/"):]
        asset = UI_ASSETS.get(rel)
        if asset is None:
            return self._send(404, {"error": "not_found", "message": rel})
        ctype = "text/html" if rel.endswith(".html") else "application/javascript"
        self._send(200, raw=asset.encode("utf-8"), content_type=ctype)

    # ------------------------------------------------------------------ #
    # tenant side
    # ------------------------------------------------------------------ #

    def ep_claim(self):
        body = self._read_json()
        resp = self.relay.claim(
            self._tenant_token(), str(body.get("consumer") or ""),
            ttl_seconds=body.get("ttl_seconds"))
        self._send(200, resp)

    def ep_ack(self):
        body = self._read_json()
        end = body.get("end_index")
        if not isinstance(end, int):
            raise InvalidBody("end_index (integer) is required")
        did = body.get("delivery_id")
        if not isinstance(did, str) or not did:
            raise InvalidBody("delivery_id is required")
        resp = self.relay.ack(
            self._tenant_token(), did, end, str(body.get("consumer") or ""))
        self._send(200, resp)

    def ep_tenant_status(self):
        self._send(200, self.relay.tenant_status(self._tenant_token()))

    def ep_mirror_public(self):
        self._send(200, self.relay.mirror_status())

    # ------------------------------------------------------------------ #
    # admin side
    # ------------------------------------------------------------------ #

    def ep_admin_status(self):
        self._admin()
        self._send(200, self.relay.status(
            events_limit=int(self._query().get("events", "60"))))

    def ep_admin_sync(self):
        self._admin()
        self._send(200, self.relay.sync_once())

    def ep_admin_leaves(self):
        self._admin()
        self._send(200, {"leaves": self.relay.list_leaves(
            limit=int(self._query().get("limit", "500")))})

    def ep_admin_tenants_list(self):
        self._admin()
        self._send(200, {"tenants": self.relay.list_tenants()})

    def ep_admin_tenants_create(self):
        self._admin()
        body = self._read_json()
        tid = body.get("tenant_id")
        name = body.get("name") or tid
        if not isinstance(tid, str) or not tid:
            raise InvalidBody("tenant_id is required")
        resp = self.relay.create_tenant(tid, str(name), body.get("filter"),
                                        token=self._bearer())
        self._send(201, resp)

    def ep_admin_filter(self, tenant_id: str):
        self._admin()
        body = self._read_json()
        self._send(200, self.relay.set_filter(tenant_id, body.get("filter")))

    def ep_admin_deactivate(self, tenant_id: str):
        self._admin()
        body = self._read_json()
        self._send(200, self.relay.deactivate_tenant(
            tenant_id, str(body.get("reason") or "")))


def _build_routes() -> dict[str, dict]:
    import re

    def rx(path: str) -> re.Pattern:
        return re.compile("^" + re.sub(r"<(\w+)>", r"(?P<\1>[^/]+)", path) + "$")

    get = [
        ("/v1/relay/status", _Handler.ep_tenant_status),
        ("/v1/relay/mirror", _Handler.ep_mirror_public),
        ("/v1/admin/status", _Handler.ep_admin_status),
        ("/v1/admin/mirror/leaves", _Handler.ep_admin_leaves),
        ("/v1/admin/tenants", _Handler.ep_admin_tenants_list),
    ]
    post = [
        ("/v1/relay/claim", _Handler.ep_claim),
        ("/v1/relay/ack", _Handler.ep_ack),
        ("/v1/admin/sync", _Handler.ep_admin_sync),
        ("/v1/admin/tenants", _Handler.ep_admin_tenants_create),
        ("/v1/admin/tenants/<tenant_id>/filter", _Handler.ep_admin_filter),
        ("/v1/admin/tenants/<tenant_id>/deactivate",
         _Handler.ep_admin_deactivate),
    ]
    return {"GET": {rx(p): h for p, h in get},
            "POST": {rx(p): h for p, h in post}}


def serve(relay, host: str = "127.0.0.1", port: int = 8090) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _Handler)
    server.relay = relay
    server.routes = _build_routes()
    server.daemon_threads = True
    return server
