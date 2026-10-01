"""并行窗口中继 HTTP API + 运维页。

租户侧（租户令牌 ``dprt_…``）::

    POST /v1/relay/claim                  {"worker","ttl_seconds"?}
    POST /v1/relay/fetch                  {"worker","window_id","ttl_seconds"?}
    POST /v1/relay/commit                 {"window_id","end_offset","worker",
                                           "filter_version"?}
    GET  /v1/relay/status                 本租户窗口/屏障/空洞/租约/重试/拒绝

管理侧（管理员令牌 ``afra_…``，前缀 /v1/admin）::

    GET  /v1/admin/status                 全部租户 + 窗口 + 事件
    POST /v1/admin/tenants                创建租户（返回一次性令牌）
    GET  /v1/admin/tenants
    POST /v1/admin/tenants/<id>/inflight  {"max_inflight"}
    POST /v1/admin/tenants/<id>/filter    {"filter"}
    POST /v1/admin/tenants/<id>/deactivate
    POST /v1/admin/tenants/<id>/append    {"records":[...]} 或 {"bytes_b64":"..."}
    POST /v1/admin/tenants/<id>/seal
    GET  /ui                              运维单页
"""

from __future__ import annotations

import base64
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .errors import InvalidBody, RelayError, Unauthorized
from .webui import UI_ASSETS


class _Handler(BaseHTTPRequestHandler):
    server_version = "wrelay/1.0"

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
                return self._send(200, {"ok": True, "service": "wrelay"})
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
            self._bearer(), str(body.get("worker") or ""),
            ttl_seconds=body.get("ttl_seconds"))
        self._send(200, resp)

    def ep_fetch(self):
        body = self._read_json()
        wid = body.get("window_id")
        if not isinstance(wid, str) or not wid:
            raise InvalidBody("window_id is required")
        resp = self.relay.fetch(
            self._bearer(), str(body.get("worker") or ""), wid,
            ttl_seconds=body.get("ttl_seconds"))
        self._send(200, resp)

    def ep_commit(self):
        body = self._read_json()
        wid = body.get("window_id")
        end = body.get("end_offset")
        if not isinstance(wid, str) or not wid:
            raise InvalidBody("window_id is required")
        if not isinstance(end, int):
            raise InvalidBody("end_offset (integer) is required")
        fv = body.get("filter_version")
        if fv is not None and not isinstance(fv, int):
            raise InvalidBody("filter_version must be an integer")
        resp = self.relay.commit(
            self._bearer(), wid, end, str(body.get("worker") or ""),
            filter_version=fv)
        self._send(200, resp)

    def ep_tenant_status(self):
        self._send(200, self.relay.tenant_status(self._bearer()))

    # ------------------------------------------------------------------ #
    # admin side
    # ------------------------------------------------------------------ #

    def ep_admin_status(self):
        self._admin()
        self._send(200, self.relay.status(
            events_limit=int(self._query().get("events", "80"))))

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
        resp = self.relay.create_tenant(
            tid, str(name), body.get("filter"),
            window_size=body.get("window_size"),
            max_inflight=body.get("max_inflight"),
            token=self._bearer())
        self._send(201, resp)

    def ep_admin_inflight(self, tenant_id: str):
        self._admin()
        body = self._read_json()
        cap = body.get("max_inflight")
        if not isinstance(cap, int):
            raise InvalidBody("max_inflight (integer) is required")
        self._send(200, self.relay.set_max_inflight(tenant_id, cap))

    def ep_admin_filter(self, tenant_id: str):
        self._admin()
        body = self._read_json()
        self._send(200, self.relay.set_filter(tenant_id, body.get("filter")))

    def ep_admin_deactivate(self, tenant_id: str):
        self._admin()
        body = self._read_json()
        self._send(200, self.relay.deactivate_tenant(
            tenant_id, str(body.get("reason") or "")))

    def ep_admin_append(self, tenant_id: str):
        self._admin()
        body = self._read_json()
        if "records" in body:
            records = body.get("records")
            if not isinstance(records, list):
                raise InvalidBody("records must be a list")
            self._send(200, self.relay.append_records(tenant_id, records))
        elif "bytes_b64" in body:
            try:
                data = base64.b64decode(str(body["bytes_b64"]))
            except Exception:
                raise InvalidBody("bytes_b64 must be base64")
            self._send(200, self.relay.append_bytes(tenant_id, data))
        else:
            raise InvalidBody("provide records or bytes_b64")

    def ep_admin_seal(self, tenant_id: str):
        self._admin()
        self._read_json()
        self._send(200, self.relay.seal_stream(tenant_id))


def _build_routes() -> dict[str, dict]:
    import re

    def rx(path: str) -> re.Pattern:
        return re.compile("^" + re.sub(r"<(\w+)>", r"(?P<\1>[^/]+)", path) + "$")

    get = [
        ("/v1/relay/status", _Handler.ep_tenant_status),
        ("/v1/admin/status", _Handler.ep_admin_status),
        ("/v1/admin/tenants", _Handler.ep_admin_tenants_list),
    ]
    post = [
        ("/v1/relay/claim", _Handler.ep_claim),
        ("/v1/relay/fetch", _Handler.ep_fetch),
        ("/v1/relay/commit", _Handler.ep_commit),
        ("/v1/admin/tenants", _Handler.ep_admin_tenants_create),
        ("/v1/admin/tenants/<tenant_id>/inflight", _Handler.ep_admin_inflight),
        ("/v1/admin/tenants/<tenant_id>/filter", _Handler.ep_admin_filter),
        ("/v1/admin/tenants/<tenant_id>/deactivate",
         _Handler.ep_admin_deactivate),
        ("/v1/admin/tenants/<tenant_id>/append", _Handler.ep_admin_append),
        ("/v1/admin/tenants/<tenant_id>/seal", _Handler.ep_admin_seal),
    ]
    return {"GET": {rx(p): h for p, h in get},
            "POST": {rx(p): h for p, h in post}}


def serve(relay, host: str = "127.0.0.1", port: int = 8095) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _Handler)
    server.relay = relay
    server.routes = _build_routes()
    server.daemon_threads = True
    return server
