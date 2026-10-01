"""wrelay 命令行（同时也是 HTTP 客户端 / 本地运维工具）。

本地 home 命令::

    python -m wrelay init HOME [--window-size N] [--max-inflight N] [--ttl S]
    python -m wrelay serve HOME [--host H] [--port P]

HTTP 子命令（默认 --base-url http://127.0.0.1:8095）::

    wrelay tenants list|create ...          （管理员）
    wrelay inflight TENANT --max N          （管理员，动态收缩/放大）
    wrelay filter   TENANT --filter f.json  （管理员，筛选版本前进）
    wrelay deactivate TENANT --reason ...   （管理员）
    wrelay append TENANT --records r.json   （管理员，追加字节流）
    wrelay seal   TENANT                    （管理员，尾窗定型）
    wrelay status                           （管理员总览）
    wrelay claim  --token dprt_… --worker w1 [--ttl S]
    wrelay fetch  --token dprt_… --worker w1 --window-id afw_… [--out f]
    wrelay commit --token dprt_… --worker w1 --window-id afw_… --end-offset N
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

from .app import bootstrap, open_relay
from .errors import RelayError

DEFAULT_BASE_URL = "http://127.0.0.1:8095"


def _j(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)


def _read_filter(path: str | None):
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def http_call(method: str, url: str, token: str | None, body: dict | None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode("utf-8"))
        except Exception:
            payload = {"error": "http_error", "message": str(e)}
        return e.code, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wrelay",
                                     description="parallel-window relay")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="initialise a window-relay home")
    p.add_argument("home")
    p.add_argument("--window-size", type=int, default=64)
    p.add_argument("--max-inflight", type=int, default=4)
    p.add_argument("--ttl", type=int, default=30)
    p.add_argument("--force", action="store_true")

    p = sub.add_parser("serve", help="run HTTP API + ops UI")
    p.add_argument("home")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8095)

    p = sub.add_parser("status", help="full overview (admin token)")
    p.add_argument("--admin-token", required=True)
    p.add_argument("--tenant")

    p = sub.add_parser("tenants", help="tenant administration")
    ts = p.add_subparsers(dest="sub", required=True)
    tl = ts.add_parser("list")
    tl.add_argument("--admin-token", required=True)
    tc = ts.add_parser("create")
    tc.add_argument("--tenant-id", required=True)
    tc.add_argument("--name", default="")
    tc.add_argument("--filter", help="filter JSON file")
    tc.add_argument("--window-size", type=int)
    tc.add_argument("--max-inflight", type=int)
    tc.add_argument("--admin-token", required=True)

    p = sub.add_parser("inflight", help="dynamically change max in-flight")
    p.add_argument("tenant_id")
    p.add_argument("--max", dest="max_inflight", type=int, required=True)
    p.add_argument("--admin-token", required=True)

    p = sub.add_parser("filter", help="advance a tenant filter rule/version")
    p.add_argument("tenant_id")
    p.add_argument("--filter", required=True)
    p.add_argument("--admin-token", required=True)

    p = sub.add_parser("deactivate", help="deactivate a tenant")
    p.add_argument("tenant_id")
    p.add_argument("--reason", default="")
    p.add_argument("--admin-token", required=True)

    p = sub.add_parser("append", help="append records (JSONL bytes) to a stream")
    p.add_argument("tenant_id")
    p.add_argument("--records", required=True, help="JSON file: list of records")
    p.add_argument("--admin-token", required=True)

    p = sub.add_parser("seal", help="seal a tenant stream (final tail window)")
    p.add_argument("tenant_id")
    p.add_argument("--admin-token", required=True)

    p = sub.add_parser("claim", help="claim the next available window")
    p.add_argument("--token", required=True)
    p.add_argument("--worker", required=True)
    p.add_argument("--ttl", type=int)

    p = sub.add_parser("fetch", help="re-fetch a specific window (stable bytes)")
    p.add_argument("--token", required=True)
    p.add_argument("--worker", required=True)
    p.add_argument("--window-id", required=True)
    p.add_argument("--ttl", type=int)
    p.add_argument("--out", help="write raw window bytes (base64-decoded) here")

    p = sub.add_parser("commit", help="commit a window end (fenced)")
    p.add_argument("--token", required=True)
    p.add_argument("--worker", required=True)
    p.add_argument("--window-id", required=True)
    p.add_argument("--end-offset", type=int, required=True)
    p.add_argument("--filter-version", type=int)

    args = parser.parse_args(argv)

    try:
        return _dispatch(args)
    except RelayError as e:
        print(json.dumps(e.to_dict(), ensure_ascii=False), file=sys.stderr)
        return 1
    except FileExistsError as e:
        print(str(e), file=sys.stderr)
        return 3
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 3


def _admin_url(args, path: str) -> str:
    return args.base_url.rstrip("/") + path


def _emit(status: int, payload: dict) -> int:
    print(_j(payload))
    return 0 if 200 <= status < 300 else 1


def _dispatch(args) -> int:
    if args.cmd == "init":
        info = bootstrap(
            args.home, default_ttl_seconds=args.ttl,
            window_size=args.window_size, max_inflight=args.max_inflight,
            force=args.force)
        print(_j({"home": info["home"], "admin_token": info["admin_token"],
                  "note": "admin token shown only once"}))
        return 0

    if args.cmd == "serve":
        relay = open_relay(args.home)
        from .server import serve

        httpd = serve(relay, args.host, args.port)
        print(f"wrelay on http://{args.host}:{args.port}/ui", file=sys.stderr)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
            relay.close()
        return 0

    base = args.base_url.rstrip("/")

    if args.cmd == "status":
        q = "?tenant=" + args.tenant if getattr(args, "tenant", None) else ""
        st, body = http_call("GET", base + "/v1/admin/status" + q,
                             args.admin_token, None)
        return _emit(st, body)

    if args.cmd == "tenants":
        if args.sub == "list":
            st, body = http_call("GET", base + "/v1/admin/tenants",
                                 args.admin_token, None)
        else:
            st, body = http_call("POST", base + "/v1/admin/tenants",
                                 args.admin_token,
                                 {"tenant_id": args.tenant_id,
                                  "name": args.name or args.tenant_id,
                                  "filter": _read_filter(args.filter),
                                  "window_size": args.window_size,
                                  "max_inflight": args.max_inflight})
        return _emit(st, body)

    if args.cmd == "inflight":
        st, body = http_call(
            "POST", f"{base}/v1/admin/tenants/{args.tenant_id}/inflight",
            args.admin_token, {"max_inflight": args.max_inflight})
        return _emit(st, body)

    if args.cmd == "filter":
        st, body = http_call(
            "POST", f"{base}/v1/admin/tenants/{args.tenant_id}/filter",
            args.admin_token, {"filter": _read_filter(args.filter)})
        return _emit(st, body)

    if args.cmd == "deactivate":
        st, body = http_call(
            "POST", f"{base}/v1/admin/tenants/{args.tenant_id}/deactivate",
            args.admin_token, {"reason": args.reason})
        return _emit(st, body)

    if args.cmd == "append":
        with open(args.records, "r", encoding="utf-8") as fh:
            records = json.load(fh)
        st, body = http_call(
            "POST", f"{base}/v1/admin/tenants/{args.tenant_id}/append",
            args.admin_token, {"records": records})
        return _emit(st, body)

    if args.cmd == "seal":
        st, body = http_call(
            "POST", f"{base}/v1/admin/tenants/{args.tenant_id}/seal",
            args.admin_token, {})
        return _emit(st, body)

    if args.cmd == "claim":
        body = {"worker": args.worker}
        if args.ttl is not None:
            body["ttl_seconds"] = args.ttl
        st, payload = http_call("POST", base + "/v1/relay/claim",
                                args.token, body)
        return _emit(st, payload)

    if args.cmd == "fetch":
        body = {"worker": args.worker, "window_id": args.window_id}
        if args.ttl is not None:
            body["ttl_seconds"] = args.ttl
        st, payload = http_call("POST", base + "/v1/relay/fetch",
                                args.token, body)
        if st == 200 and args.out and payload.get("window"):
            import base64

            with open(args.out, "wb") as fh:
                fh.write(base64.b64decode(payload["window"]["payload_b64"]))
        return _emit(st, payload)

    if args.cmd == "commit":
        body = {"worker": args.worker, "window_id": args.window_id,
                "end_offset": args.end_offset}
        if args.filter_version is not None:
            body["filter_version"] = args.filter_version
        st, payload = http_call("POST", base + "/v1/relay/commit",
                                args.token, body)
        return _emit(st, payload)

    return 0


if __name__ == "__main__":
    sys.exit(main())
