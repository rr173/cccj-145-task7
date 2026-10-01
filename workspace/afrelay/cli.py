"""afrelay 命令行。

    python -m afrelay init HOME --upstream-url URL --upstream-token TOKEN \
        [--gateway-secrets PATH | --transparency-secret HEX]
    python -m afrelay serve HOME [--host H] [--port P] [--interval S] [--no-poll]
    python -m afrelay sync  HOME                 # 手动触发一轮拉取
    python -m afrelay status HOME --admin-token afra_…
    python -m afrelay tenants HOME create --tenant-id ID --name N \
        [--filter filter.json] [--max-inflight 8] --admin-token afra_…
    python -m afrelay tenants HOME list --admin-token afra_…
    python -m afrelay windows HOME TENANT [--committed] --admin-token afra_…
    python -m afrelay set-inflight HOME TENANT --max-inflight N --admin-token …
    python -m afrelay force-expire HOME TENANT DELIVERY_ID --admin-token …
    python -m afrelay filter  HOME TENANT --filter filter.json --admin-token …
    python -m afrelay deactivate HOME TENANT --reason "..." --admin-token …
    python -m afrelay claim HOME --token dprt_… --consumer w1 [--ttl 30]
    python -m afrelay ack   HOME --token dprt_… --delivery-id afd_… \
        --end-index N --consumer w1 [--lease-token afw_…]
    python -m afrelay complete HOME ...   # ack 的别名（并行窗口语义）
    python -m afrelay fetch HOME --token dprt_… --consumer w1 --out packet.json
    python -m afrelay verify packet --packet packet.json --secrets HOME/secrets.json \
        [--expect-tenant T]
"""

from __future__ import annotations

import argparse
import json
import sys

from .app import bootstrap, open_relay
from .errors import RelayError
from .verify import load_relay_keys, verify_packet

def _j(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)


def _read_filter(path: str | None):
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="afrelay",
                                     description="audit-feed relay")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="initialise an independent relay home")
    p.add_argument("home")
    p.add_argument("--upstream-url", required=True)
    p.add_argument("--upstream-token", required=True)
    p.add_argument("--gateway-secrets",
                   help="path to the gateway secrets.json (transparency anchor)")
    p.add_argument("--transparency-secret",
                   help="transparency_secret hex (alternative to --gateway-secrets)")
    p.add_argument("--ttl", type=int, default=30)
    p.add_argument("--batch-size", type=int, default=100)
    p.add_argument("--max-inflight", type=int, default=8,
                   help="default max parallel in-flight windows per new tenant")
    p.add_argument("--force", action="store_true")

    p = sub.add_parser("serve", help="run HTTP API + ops UI")
    p.add_argument("home")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8090)
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--no-poll", action="store_true")

    p = sub.add_parser("sync", help="run one pull round and print the report")
    p.add_argument("home")

    p = sub.add_parser("status", help="mirror/tenant/lease/reject overview")
    p.add_argument("home")
    p.add_argument("--admin-token", required=True)
    p.add_argument("--tenant", help="scope the view to one tenant id")

    p = sub.add_parser("tenants", help="tenant administration")
    p.add_argument("home")
    ts = p.add_subparsers(dest="sub", required=True)
    tc = ts.add_parser("create")
    tc.add_argument("--tenant-id", required=True)
    tc.add_argument("--name", default="")
    tc.add_argument("--filter", help="filter JSON file")
    tc.add_argument("--max-inflight", type=int, default=None,
                   help="max parallel in-flight windows (default from config)")
    tc.add_argument("--admin-token", required=True)
    tl = ts.add_parser("list")
    tl.add_argument("--admin-token", required=True)

    p = sub.add_parser("windows", help="list a tenant's windows/barrier/holes")
    p.add_argument("home")
    p.add_argument("tenant_id")
    p.add_argument("--committed", action="store_true",
                   help="also include committed windows")
    p.add_argument("--admin-token", required=True)

    p = sub.add_parser("set-inflight",
                       help="dynamically shrink/grow max in-flight windows "
                            "(never preempts valid holders)")
    p.add_argument("home")
    p.add_argument("tenant_id")
    p.add_argument("--max-inflight", type=int, required=True)
    p.add_argument("--admin-token", required=True)

    p = sub.add_parser("force-expire",
                       help="make a leased window immediately retakeable")
    p.add_argument("home")
    p.add_argument("tenant_id")
    p.add_argument("delivery_id")
    p.add_argument("--reason", default="admin_force_expire")
    p.add_argument("--admin-token", required=True)

    p = sub.add_parser("filter", help="set a tenant filter before first delivery")
    p.add_argument("home")
    p.add_argument("tenant_id")
    p.add_argument("--filter", required=True)
    p.add_argument("--admin-token", required=True)

    p = sub.add_parser("deactivate", help="deactivate a tenant (cursor retained)")
    p.add_argument("home")
    p.add_argument("tenant_id")
    p.add_argument("--reason", default="")
    p.add_argument("--admin-token", required=True)

    p = sub.add_parser("claim", help="claim/replay/take-over a parallel window")
    p.add_argument("home")
    p.add_argument("--token", required=True)
    p.add_argument("--consumer", required=True)
    p.add_argument("--ttl", type=int)

    p = sub.add_parser("fetch", help="claim and save the window packet bytes")
    p.add_argument("home")
    p.add_argument("--token", required=True)
    p.add_argument("--consumer", required=True)
    p.add_argument("--ttl", type=int)
    p.add_argument("--out", required=True)

    p = sub.add_parser("ack", help="complete exactly a window end (submit)")
    p.add_argument("home")
    p.add_argument("--token", required=True)
    p.add_argument("--delivery-id", required=True)
    p.add_argument("--end-index", type=int, required=True)
    p.add_argument("--consumer", required=True)
    p.add_argument("--lease-token",
                   help="opaque token returned by claim (required after take-over)")

    p = sub.add_parser("complete", help="alias for ack")
    p.add_argument("home")
    p.add_argument("--token", required=True)
    p.add_argument("--delivery-id", required=True)
    p.add_argument("--end-index", type=int, required=True)
    p.add_argument("--consumer", required=True)
    p.add_argument("--lease-token")

    p = sub.add_parser("verify", help="offline verifiers")
    vs = p.add_subparsers(dest="sub", required=True)
    vp = vs.add_parser("packet", help="verify an afp1 delivery packet offline")
    vp.add_argument("--packet", required=True)
    vp.add_argument("--secrets", required=True,
                    help="relay secrets.json (may also contain transparency_secret)")
    vp.add_argument("--expect-tenant")

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


def _dispatch(args) -> int:
    if args.cmd == "init":
        if not (args.gateway_secrets or args.transparency_secret):
            print("one of --gateway-secrets or --transparency-secret is required",
                  file=sys.stderr)
            return 3
        info = bootstrap(
            args.home, upstream_url=args.upstream_url,
            upstream_token=args.upstream_token,
            transparency_secret_hex=args.transparency_secret,
            gateway_secrets_path=args.gateway_secrets,
            default_ttl_seconds=args.ttl, batch_size=args.batch_size,
            default_max_inflight=args.max_inflight,
            force=args.force)
        print(_j({"home": info["home"],
                  "admin_token": info["admin_token"],
                  "note": "admin token shown only once"}))
        return 0

    if args.cmd == "verify":
        return _verify(args)

    relay = open_relay(args.home)
    try:
        if args.cmd == "sync":
            print(_j(relay.sync_once()))
            return 0

        if args.cmd == "status":
            if not relay.check_admin(args.admin_token):
                raise RelayError("invalid admin token")
            print(_j(relay.status(tenant_id=args.tenant)))
            return 0

        if args.cmd == "tenants":
            if not relay.check_admin(args.admin_token):
                raise RelayError("invalid admin token")
            if args.sub == "create":
                resp = relay.create_tenant(
                    args.tenant_id, args.name or args.tenant_id,
                    _read_filter(args.filter), token=args.admin_token,
                    max_inflight=args.max_inflight)
                print(_j({"tenant_id": resp["tenant_id"],
                          "token": resp["token"],
                          "max_inflight": resp["max_inflight"],
                          "note": "shown only once"}))
            else:
                print(_j({"tenants": relay.list_tenants()}))
            return 0

        if args.cmd == "windows":
            if not relay.check_admin(args.admin_token):
                raise RelayError("invalid admin token")
            print(_j(relay.tenant_windows(args.tenant_id,
                                          include_committed=args.committed)))
            return 0

        if args.cmd == "set-inflight":
            if not relay.check_admin(args.admin_token):
                raise RelayError("invalid admin token")
            print(_j(relay.set_max_inflight(args.tenant_id,
                                            args.max_inflight)))
            return 0

        if args.cmd == "force-expire":
            if not relay.check_admin(args.admin_token):
                raise RelayError("invalid admin token")
            print(_j(relay.force_expire_window(
                args.tenant_id, args.delivery_id, reason=args.reason)))
            return 0

        if args.cmd == "filter":
            if not relay.check_admin(args.admin_token):
                raise RelayError("invalid admin token")
            print(_j(relay.set_filter(args.tenant_id,
                                      _read_filter(args.filter))))
            return 0

        if args.cmd == "deactivate":
            if not relay.check_admin(args.admin_token):
                raise RelayError("invalid admin token")
            print(_j(relay.deactivate_tenant(args.tenant_id, args.reason)))
            return 0

        if args.cmd == "claim":
            print(_j(relay.claim(args.token, args.consumer,
                                 ttl_seconds=args.ttl)))
            return 0

        if args.cmd == "fetch":
            resp = relay.claim(args.token, args.consumer, ttl_seconds=args.ttl)
            if resp.get("delivery") is None:
                print(_j(resp))
                return 4
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(resp["delivery"], indent=2,
                                    sort_keys=True, ensure_ascii=False))
            print(_j({"saved": args.out,
                      "delivery_id": resp["delivery_id"],
                      "end_index": resp["end_index"],
                      "lease_token": resp.get("lease_token"),
                      "inflight": resp.get("inflight"),
                      "max_inflight": resp.get("max_inflight"),
                      "lease_expires_at": resp["lease_expires_at"]}))
            return 0

        if args.cmd in ("ack", "complete"):
            print(_j(relay.complete(
                args.token, args.delivery_id, args.end_index, args.consumer,
                lease_token=args.lease_token)))
            return 0

        if args.cmd == "serve":
            from .server import serve

            if not args.no_poll:
                relay.sync_once()
                relay.start_poller(args.interval)
            httpd = serve(relay, args.host, args.port)
            print(f"afrelay on http://{args.host}:{args.port}/ui", file=sys.stderr)
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                httpd.server_close()
                relay.close()
            return 0
    finally:
        if args.cmd != "serve":
            relay.close()
    return 0


def _verify(args) -> int:
    with open(args.packet, "r", encoding="utf-8") as fh:
        packet = json.load(fh)
    keys = load_relay_keys(args.secrets)
    report = verify_packet(packet, keys, expected_tenant=args.expect_tenant)
    print(_j(report))
    return 0 if report["ok"] else 2
