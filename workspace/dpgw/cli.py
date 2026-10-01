"""Command line interface.

    python -m dpgw init        HOME
    python -m dpgw serve       HOME --host 127.0.0.1 --port 8080
    python -m dpgw snapshot build --spec spec.json --csv data.csv --out DIR
    python -m dpgw team        HOME create --name "风控分析组"
    python -m dpgw publish     HOME --snapshot-dir DIR
    python -m dpgw budget      HOME allocate --team TEAM --snapshot SID --epsilon 3 --delta 1e-6
    python -m dpgw plan        HOME --token TOKEN --snapshot SID --query query.json
    python -m dpgw query       HOME --token TOKEN --snapshot SID --query query.json
    python -m dpgw results     HOME --token TOKEN [--snapshot SID]
    python -m dpgw jobs        HOME submit  --token TOKEN --request-key KEY --batch jobs.json [--ttl 600]
    python -m dpgw jobs        HOME get     --token TOKEN --job JOB_ID [--out manifest.json]
    python -m dpgw jobs        HOME confirm --token TOKEN --job JOB_ID [--out results.json]
    python -m dpgw jobs        HOME cancel  --token TOKEN --job JOB_ID
    python -m dpgw jobs        HOME list    [--team TID] [--state reserved]
    python -m dpgw holds       HOME [--team TID]
    python -m dpgw publications HOME create --admin-token dpa_... --name N \
                                --batch pub.json --min-participants 3 --close-at ISO
    python -m dpgw publications HOME register --token dpt_... --ref pubv_xxx
    python -m dpgw publications HOME withdraw --token dpt_... --ref pubv_xxx
    python -m dpgw publications HOME get|lineage [--token dpt_...] --ref REF
    python -m dpgw publications HOME list [--state collecting]
    python -m dpgw publications HOME seal|void --admin-token dpa_... --ref pubv_xxx
    python -m dpgw publications HOME amend --admin-token dpa_... --ref pubv_xxx --close-at ISO
    python -m dpgw publications HOME sweep --admin-token dpa_...
    python -m dpgw publications HOME holds
    python -m dpgw freeze      HOME family_id --scope global --reason "..."
    python -m dpgw unfreeze    HOME freeze_id
    python -m dpgw audit       HOME [--family ...] [--team ...]
    python -m dpgw bundle      HOME export [--team TID] --out bundle.json
    python -m dpgw verify      receipt --receipt r.json --secrets HOME/secrets.json --snapshot-dir DIR
    python -m dpgw verify      job --manifest jobm.json --secrets ... --snapshots-dir DIR
    python -m dpgw verify      publication --manifest r1.json --secrets ... \
                               --snapshots-dir DIR [--parent-digest HEX]
    python -m dpgw verify      bundle  --bundle bundle.json --secrets ... --snapshots-dir DIR
    python -m dpgw verify      ledger  --db HOME/gateway.sqlite
"""

from __future__ import annotations

import argparse
import json
import sys

from .app import bootstrap, open_gateway
from .errors import DPGWError, Unauthorized
from .snapshot import build_snapshot
from .verify import (
    load_secrets,
    verify_bundle,
    verify_job_manifest,
    verify_ledger,
    verify_publication_manifest,
    verify_receipt,
    verify_share_package,
)


def _j(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)


def _read_query(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dpgw", description="differential privacy gateway")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="initialise a gateway home")
    p.add_argument("home")
    p.add_argument("--force", action="store_true")

    p = sub.add_parser("serve", help="run HTTP API + admin UI")
    p.add_argument("home")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)

    p = sub.add_parser("snapshot", help="snapshot operations")
    ss = p.add_subparsers(dest="sub", required=True)
    b = ss.add_parser("build", help="build immutable snapshot from spec+csv")
    b.add_argument("--spec", required=True)
    b.add_argument("--csv", required=True)
    b.add_argument("--out", required=True)

    p = sub.add_parser("team", help="team administration")
    p.add_argument("home")
    ts = p.add_subparsers(dest="sub", required=True)
    tc = ts.add_parser("create")
    tc.add_argument("--name", required=True)
    tl = ts.add_parser("list")

    p = sub.add_parser("publish", help="publish a built snapshot")
    p.add_argument("home")
    p.add_argument("--snapshot-dir", required=True)
    p.add_argument("--inactive", action="store_true")

    p = sub.add_parser("snapshots", help="list snapshots")
    p.add_argument("home")

    p = sub.add_parser("deactivate", help="deactivate a snapshot (version replacement)")
    p.add_argument("home")
    p.add_argument("--snapshot", required=True)

    p = sub.add_parser("budget", help="budget administration")
    p.add_argument("home")
    bs = p.add_subparsers(dest="sub", required=True)
    ba = bs.add_parser("allocate")
    ba.add_argument("--team", required=True)
    ba.add_argument("--snapshot", required=True)
    ba.add_argument("--epsilon", type=float, required=True)
    ba.add_argument("--delta", type=float, default=0.0)
    bl = bs.add_parser("list")
    bl.add_argument("--team")

    p = sub.add_parser("plan", help="normalise + sensitivity + estimated cost (no charge)")
    p.add_argument("home")
    p.add_argument("--token", required=True)
    p.add_argument("--snapshot", required=True, help="snapshot id or name@version")
    p.add_argument("--query", required=True, help="query JSON file")

    p = sub.add_parser("query", help="execute a DP query")
    p.add_argument("home")
    p.add_argument("--token", required=True)
    p.add_argument("--snapshot", required=True)
    p.add_argument("--query", required=True)
    p.add_argument("--request-id")

    p = sub.add_parser("results", help="list team results")
    p.add_argument("home")
    p.add_argument("--token", required=True)
    p.add_argument("--snapshot")

    p = sub.add_parser("jobs", help="multi-statement analysis jobs")
    p.add_argument("home")
    js = p.add_subparsers(dest="sub", required=True)
    for name in ("submit", "get", "confirm", "cancel", "list"):
        sp = js.add_parser(name)
        if name != "list":
            sp.add_argument("--token", required=True)
        if name == "submit":
            sp.add_argument("--request-key", required=True)
            sp.add_argument("--batch", required=True,
                           help="JSON file: {\"snapshot\": {...}, \"statements\": [query,...]} "
                                "or {\"statements\": [{\"snapshot\":...,\"query\":...}]}")
            sp.add_argument("--ttl", type=int, dest="ttl")
        if name in ("get", "confirm", "cancel"):
            sp.add_argument("--job", required=True)
        if name in ("get", "confirm"):
            sp.add_argument("--out", help="write the signed manifest/results to a file")
        if name == "list":
            sp.add_argument("--team")
            sp.add_argument("--state")

    p = sub.add_parser("holds", help="list active budget locks")
    p.add_argument("home")
    p.add_argument("--team")
    p.add_argument("--snapshot")

    p = sub.add_parser("publications", help="amendable joint publication batches")
    p.add_argument("home")
    ps = p.add_subparsers(dest="sub", required=True)
    pc = ps.add_parser("create", help="analysis owner: fix the specification + open v1")
    pc.add_argument("--admin-token", required=True)
    pc.add_argument("--name", required=True)
    pc.add_argument("--batch", required=True,
                    help='JSON file: {"statements":[{"snapshot":...,"query":...}]}')
    pc.add_argument("--min-participants", type=int, required=True, dest="min_participants")
    pc.add_argument("--close-at", required=True, dest="close_at",
                    help="ISO-8601 books-closing instant, e.g. 2026-09-30T18:00:00Z")
    pr = ps.add_parser("register", help="team: register a contribution (idempotent)")
    pr.add_argument("--token", required=True)
    pr.add_argument("--ref", required=True, help="version id (pubv_…) or batch id/name")
    pw = ps.add_parser("withdraw", help="team: withdraw before the books close")
    pw.add_argument("--token", required=True)
    pw.add_argument("--ref", required=True)
    pget = ps.add_parser("get", help="version status incl. participants/rejections")
    pget.add_argument("--token")
    pget.add_argument("--ref", required=True)
    pget.add_argument("--out")
    pli = ps.add_parser("lineage", help="version genealogy of a batch")
    pli.add_argument("--token")
    pli.add_argument("--ref", required=True)
    plist = ps.add_parser("list")
    plist.add_argument("--state", choices=["collecting", "sealed", "void"])
    plist.add_argument("--batch")
    pseal = ps.add_parser("seal", help="owner: close the books and release one version")
    pseal.add_argument("--admin-token", required=True, dest="admin_token")
    pseal.add_argument("--ref", required=True)
    pseal.add_argument("--out")
    pam = ps.add_parser("amend", help="owner: revise a sealed version (new child)")
    pam.add_argument("--admin-token", required=True, dest="admin_token")
    pam.add_argument("--ref", required=True)
    pam.add_argument("--close-at", required=True, dest="close_at")
    pvoid = ps.add_parser("void", help="owner: void a due below-quorum version")
    pvoid.add_argument("--admin-token", required=True, dest="admin_token")
    pvoid.add_argument("--ref", required=True)
    psweep = ps.add_parser("sweep", help="settle every due collecting version")
    psweep.add_argument("--admin-token", required=True, dest="admin_token")
    ph = ps.add_parser("holds", help="publication budget holds")
    ph.add_argument("--team")
    ph.add_argument("--snapshot")

    p = sub.add_parser("shares", help="controlled sharing packages")
    p.add_argument("home")
    ss = p.add_subparsers(dest="sub", required=True)
    sg = ss.add_parser("grant", help="set a team's field whitelist on a release")
    sg.add_argument("--admin-token", required=True, dest="admin_token")
    sg.add_argument("--ref", required=True, help="sealed version id (pubv_…)")
    sg.add_argument("--team", required=True)
    sg.add_argument("--fields", required=True,
                    help="comma-separated field paths, e.g. "
                         "'statements.query_hash,members.charged,receipts.values' "
                         "or 'all' for the whole field catalogue")
    sgl = ss.add_parser("grants", help="list per-release field whitelists")
    sgl.add_argument("--ref")
    sc = ss.add_parser("create", help="cut a field-trimmed package for one team")
    sc.add_argument("--admin-token", required=True, dest="admin_token")
    sc.add_argument("--ref", required=True, help="sealed version id (pubv_…)")
    sc.add_argument("--team", required=True)
    sc.add_argument("--fields", required=True, help="comma-separated paths or 'all'")
    sc.add_argument("--ttl", type=int, dest="ttl")
    sc.add_argument("--expires-at", dest="expires_at", help="ISO-8601 instead of --ttl")
    sc.add_argument("--out", help="also write the signed package envelope to a file")
    sf = ss.add_parser("fetch", help="recipient: retrieve the same package with a key")
    sf.add_argument("--token", required=True, help="team token (dpt_…)")
    sf.add_argument("--share-key", required=True, dest="share_key")
    sf.add_argument("--out")
    sl = ss.add_parser("list", help="list sharing packages")
    sl.add_argument("--team")
    sl.add_argument("--version", dest="version_id")
    sl.add_argument("--state", choices=["creating", "sealed", "failed", "revoked"])
    sget = ss.add_parser("get", help="inspect one share (admin; reveal key on demand)")
    sget.add_argument("--admin-token", required=True, dest="admin_token")
    sget.add_argument("--share", required=True)
    sget.add_argument("--reveal-key", action="store_true", dest="reveal_key")
    sr = ss.add_parser("revoke", help="revoke: block new retrievals, file stays valid")
    sr.add_argument("--admin-token", required=True, dest="admin_token")
    sr.add_argument("--share", required=True)
    sr.add_argument("--reason", default="")
    srt = ss.add_parser("retrievals", help="audit trail of fetch attempts")
    srt.add_argument("--admin-token", required=True, dest="admin_token")
    srt.add_argument("--share")
    srec = ss.add_parser("recover", help="reconcile interrupted package materialisations")
    srec.add_argument("--admin-token", required=True, dest="admin_token")

    p = sub.add_parser("transparency", help="anti-fork transparency ledger")
    p.add_argument("home")
    ts = p.add_subparsers(dest="sub", required=True)
    tstate = ts.add_parser("state", help="latest tree size/root and freeze state")
    tstate.add_argument("--token", help="team token; admin token also accepted")
    tcp = ts.add_parser("checkpoint", help="fetch one signed checkpoint")
    tcp.add_argument("--tree-size", type=int, dest="tree_size")
    tcp.add_argument("--token", help="team token; admin token also accepted")
    tcp.add_argument("--out")
    tleaves = ts.add_parser("leaves", help="list content-addressed leaves")
    tleaves.add_argument("--type", dest="event_type",
                         choices=["release_sealed", "release_voided",
                                  "share_issued", "share_revoked"])
    tleaves.add_argument("--token")
    ti = ts.add_parser("inclusion", help="inclusion proof for one leaf index")
    ti.add_argument("leaf_index", type=int)
    ti.add_argument("--tree-size", type=int, dest="tree_size")
    ti.add_argument("--token", required=True)
    tev = ts.add_parser("event", help="inclusion proof looked up by event_key")
    tev.add_argument("event_key")
    tev.add_argument("--tree-size", type=int, dest="tree_size")
    tev.add_argument("--token", required=True)
    tcon = ts.add_parser("consistency", help="append-only proof between checkpoints")
    tcon.add_argument("old_size", type=int)
    tcon.add_argument("--new-size", type=int, dest="new_size")
    tcon.add_argument("--token", required=True)
    tcon.add_argument("--out")
    tfork = ts.add_parser("submit-fork", help="submit two same-height/different-root "
                                              "signed checkpoints and freeze issuance")
    tfork.add_argument("--first", required=True, help="signed checkpoint JSON file")
    tfork.add_argument("--second", required=True, help="signed checkpoint JSON file")
    tfork.add_argument("--admin-token", required=True, dest="admin_token")
    tfork.add_argument("--reason", default="")
    trec = ts.add_parser("recover", help="drain the durable outbox after an interruption")
    trec.add_argument("--admin-token", required=True, dest="admin_token")

    p = sub.add_parser("freeze", help="freeze a query family")
    p.add_argument("home")
    p.add_argument("family_id")
    p.add_argument("--scope", default="global",
                   choices=["global", "team", "snapshot", "team_snapshot"])
    p.add_argument("--team")
    p.add_argument("--snapshot")
    p.add_argument("--reason", default="")

    p = sub.add_parser("freezes", help="list freezes")
    p.add_argument("home")

    p = sub.add_parser("unfreeze", help="remove a freeze")
    p.add_argument("home")
    p.add_argument("freeze_id")

    p = sub.add_parser("audit", help="show audit log")
    p.add_argument("home")
    p.add_argument("--family")
    p.add_argument("--team")
    p.add_argument("--snapshot")
    p.add_argument("--result")
    p.add_argument("--limit", type=int, default=50)

    p = sub.add_parser("bundle", help="verification bundle")
    p.add_argument("home")
    bsub = p.add_subparsers(dest="sub", required=True)
    be = bsub.add_parser("export")
    be.add_argument("--team")
    be.add_argument("--out", required=True)

    p = sub.add_parser("verify", help="offline verification tools")
    vs = p.add_subparsers(dest="sub", required=True)
    vr = vs.add_parser("receipt")
    vr.add_argument("--receipt", required=True)
    vr.add_argument("--secrets", required=True)
    vr.add_argument("--snapshot-dir", required=True)
    vj = vs.add_parser("job")
    vj.add_argument("--manifest", required=True)
    vj.add_argument("--secrets", required=True)
    vj.add_argument("--snapshots-dir")
    vp = vs.add_parser("publication")
    vp.add_argument("--manifest", required=True)
    vp.add_argument("--secrets", required=True)
    vp.add_argument("--snapshots-dir")
    vp.add_argument("--parent-digest", dest="parent_digest")
    vsh = vs.add_parser("share")
    vsh.add_argument("--package", required=True, help="downloaded sharing package JSON")
    vsh.add_argument("--secrets", required=True)
    vsh.add_argument("--snapshots-dir")
    vsh.add_argument("--release", help="full signed release manifest to cross-check "
                                       "the trimming and release digest")
    vsh.add_argument("--parent-digest", dest="parent_digest")
    vsh.add_argument("--now", help="override current time (ISO-8601) for expiry check")
    vb = vs.add_parser("bundle")
    vb.add_argument("--bundle", required=True)
    vb.add_argument("--secrets", required=True)
    vb.add_argument("--snapshots-dir")
    vl = vs.add_parser("ledger")
    vl.add_argument("--db", required=True)
    vc2 = vs.add_parser("checkpoint", help="verify one signed transparency checkpoint")
    vc2.add_argument("--checkpoint", required=True, help="checkpoint JSON file")
    vc2.add_argument("--secrets", required=True)
    vi = vs.add_parser("inclusion", help="verify a leaf inclusion proof document")
    vi.add_argument("--proof", required=True, help="inclusion proof JSON (from HTTP/CLI)")
    vi.add_argument("--secrets", required=True)
    vcons = vs.add_parser("consistency",
                          help="verify an append-only consistency proof document")
    vcons.add_argument("--proof", required=True)
    vcons.add_argument("--secrets", required=True)
    vfork = vs.add_parser("fork-evidence",
                          help="validate two signed checkpoints as fork evidence")
    vfork.add_argument("--first", required=True)
    vfork.add_argument("--second", required=True)
    vfork.add_argument("--secrets", required=True)

    args = parser.parse_args(argv)

    try:
        return _dispatch(args)
    except DPGWError as e:
        print(json.dumps(e.to_dict(), ensure_ascii=False), file=sys.stderr)
        return 1
    except FileExistsError as e:
        print(json.dumps({"error": "exists", "message": str(e)}, ensure_ascii=False),
              file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(json.dumps({"error": "not_found", "message": str(e)}, ensure_ascii=False),
              file=sys.stderr)
        return 1


def _snapshot_ref(token: str) -> dict:
    if "@" in token and len(token) != 32:
        name, version = token.split("@", 1)
        return {"name": name, "version": version}
    return {"snapshot_id": token}


def _dispatch(args) -> int:
    if args.cmd == "init":
        info = bootstrap(args.home, force=args.force)
        print(_j(info))
        print("!! 管理员令牌仅显示这一次，请立即安全保存", file=sys.stderr)
        return 0

    if args.cmd == "serve":
        from .server import serve

        gw = open_gateway(args.home)
        httpd = serve(gw, host=args.host, port=args.port)
        print(f"DP gateway listening on http://{args.host}:{args.port} "
              f"(admin UI at /ui)", file=sys.stderr)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
        return 0

    if args.cmd == "snapshot" and args.sub == "build":
        with open(args.spec, "r", encoding="utf-8") as fh:
            spec = json.load(fh)
        manifest = build_snapshot(spec, args.csv, args.out)
        print(_j({"out": args.out, "snapshot_id": manifest["snapshot_id"],
                  "row_count": manifest["row_count"]}))
        return 0

    if args.cmd == "verify":
        secrets_ = load_secrets(args.secrets) if hasattr(args, "secrets") else None
        if args.sub == "receipt":
            with open(args.receipt, "r", encoding="utf-8") as fh:
                receipt = json.load(fh)
            report = verify_receipt(receipt, secrets_, args.snapshot_dir)
        elif args.sub == "bundle":
            with open(args.bundle, "r", encoding="utf-8") as fh:
                bundle = json.load(fh)
            report = verify_bundle(bundle, secrets_, args.snapshots_dir)
        elif args.sub == "job":
            with open(args.manifest, "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
            report = verify_job_manifest(manifest, secrets_, args.snapshots_dir)
        elif args.sub == "publication":
            with open(args.manifest, "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
            report = verify_publication_manifest(
                manifest, secrets_, args.snapshots_dir,
                parent_digest=args.parent_digest)
        elif args.sub == "share":
            with open(args.package, "r", encoding="utf-8") as fh:
                package = json.load(fh)
            full_release = None
            if args.release:
                with open(args.release, "r", encoding="utf-8") as fh:
                    doc = json.load(fh)
                full_release = doc.get("manifest", doc)
            report = verify_share_package(
                package, secrets_, args.snapshots_dir, full_release=full_release,
                parent_digest=args.parent_digest, now=args.now)
        elif args.sub == "checkpoint":
            from .verify import verify_checkpoint_doc
            with open(args.checkpoint, "r", encoding="utf-8") as fh:
                report = verify_checkpoint_doc(json.load(fh), secrets_)
        elif args.sub == "inclusion":
            from .verify import verify_inclusion_proof
            with open(args.proof, "r", encoding="utf-8") as fh:
                report = verify_inclusion_proof(json.load(fh), secrets_)
        elif args.sub == "consistency":
            from .verify import verify_consistency_proof
            with open(args.proof, "r", encoding="utf-8") as fh:
                report = verify_consistency_proof(json.load(fh), secrets_)
        elif args.sub == "fork-evidence":
            from .verify import verify_fork_evidence
            with open(args.first, "r", encoding="utf-8") as a, \
                    open(args.second, "r", encoding="utf-8") as b:
                report = verify_fork_evidence(json.load(a), json.load(b), secrets_)
        else:
            report = verify_ledger(args.db)
        print(_j(report))
        # an expired-but-authentic package is a distinct exit code
        if args.sub == "share" and report["ok"] and report.get("expired"):
            return 3
        return 0 if report["ok"] else 2

    gw = open_gateway(args.home)

    if args.cmd == "team":
        if args.sub == "create":
            print(_j(gw.create_team(args.name, actor="cli")))
        else:
            print(_j({"teams": gw.list_teams()}))
        return 0

    if args.cmd == "publish":
        print(_j(gw.publish_snapshot(args.snapshot_dir, actor="cli",
                                    activate=not args.inactive)))
        return 0

    if args.cmd == "snapshots":
        print(_j({"snapshots": gw.list_snapshots()}))
        return 0

    if args.cmd == "deactivate":
        gw.set_snapshot_active(args.snapshot, False, actor="cli")
        print(_j({"snapshot_id": args.snapshot, "active": False}))
        return 0

    if args.cmd == "budget":
        if args.sub == "allocate":
            print(_j(gw.allocate_budget(args.team, args.snapshot,
                                        args.epsilon, args.delta, actor="cli")))
        else:
            print(_j({"budgets": gw.list_budgets(args.team)}))
        return 0

    if args.cmd in ("plan", "query"):
        team = gw.authenticate(args.token)
        query = _read_query(args.query)
        ref = _snapshot_ref(args.snapshot)
        if args.cmd == "plan":
            print(_j(gw.plan(team["team_id"], ref, query)))
        else:
            print(_j(gw.run_query(team["team_id"], ref, query,
                                  request_id=args.request_id)))
        return 0

    if args.cmd == "results":
        team = gw.authenticate(args.token)
        print(_j({"results": gw.list_results(team["team_id"], args.snapshot)}))
        return 0

    if args.cmd == "jobs":
        team = gw.authenticate(args.token) if getattr(args, "token", None) else None
        tid = team["team_id"] if team else None
        if args.sub == "submit":
            with open(args.batch, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            if "statements" in doc:
                statements = doc["statements"]
            else:
                statements = [{"snapshot": doc["snapshot"], "query": q}
                              for q in doc.get("queries", [])]
            resp = gw.create_job(tid, statements, request_key=args.request_key,
                                 ttl_seconds=args.ttl, actor="cli")
            print(_j(resp))
            return 0
        if args.sub == "list":
            print(_j({"jobs": gw.list_jobs(team_id=args.team, state=args.state)}))
            return 0
        if args.sub == "get":
            resp = gw.get_job(args.job, tid)
            if args.out and "manifest" in resp:
                with open(args.out, "w", encoding="utf-8") as fh:
                    json.dump(resp["manifest"], fh, indent=2, sort_keys=True, ensure_ascii=False)
            print(_j(resp))
            return 0
        if args.sub == "confirm":
            resp = gw.confirm_job(args.job, tid)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    json.dump(resp, fh, indent=2, sort_keys=True, ensure_ascii=False)
            print(_j(resp))
            return 0
        if args.sub == "cancel":
            print(_j(gw.cancel_job(args.job, tid)))
            return 0

    if args.cmd == "holds":
        print(_j({"holds": gw.list_holds(team_id=args.team, snapshot_id=args.snapshot)}))
        return 0

    if args.cmd == "publications":
        if args.sub == "create":
            if not gw.check_admin(args.admin_token):
                raise Unauthorized("admin token required")
            with open(args.batch, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            resp = gw.create_publication(
                args.name, doc["statements"], args.min_participants, args.close_at,
                actor="cli")
            print(_j(resp))
            return 0
        if args.sub == "list":
            print(_j({"publications": gw.list_publications(
                state=args.state, batch_id=args.batch)}))
            return 0
        if args.sub == "holds":
            print(_j({"holds": gw.list_pub_holds(team_id=args.team,
                                                 snapshot_id=args.snapshot)}))
            return 0
        if args.sub == "sweep":
            if not gw.check_admin(args.admin_token):
                raise Unauthorized("admin token required")
            print(_j(gw.sweep_due_publications(actor="cli")))
            return 0
        if args.sub == "lineage":
            if args.token:
                gw.authenticate(args.token)
            print(_j({"versions": gw.list_lineage(args.ref)}))
            return 0
        if args.sub == "get":
            if args.token:
                gw.authenticate(args.token)
            resp = gw.get_publication(args.ref)
            if args.out and "manifest" in resp:
                with open(args.out, "w", encoding="utf-8") as fh:
                    json.dump(resp["manifest"], fh, indent=2, sort_keys=True,
                              ensure_ascii=False)
            print(_j(resp))
            return 0
        if args.sub == "register":
            team = gw.authenticate(args.token)
            print(_j(gw.register_contribution(args.ref, team["team_id"], actor="cli")))
            return 0
        if args.sub == "withdraw":
            team = gw.authenticate(args.token)
            print(_j(gw.withdraw_contribution(args.ref, team["team_id"], actor="cli")))
            return 0
        if args.sub == "seal":
            if not gw.check_admin(args.admin_token):
                raise Unauthorized("admin token required")
            resp = gw.seal_publication(args.ref, actor="cli")
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    json.dump(resp["manifest"], fh, indent=2, sort_keys=True,
                              ensure_ascii=False)
            print(_j(resp))
            return 0
        if args.sub == "amend":
            if not gw.check_admin(args.admin_token):
                raise Unauthorized("admin token required")
            print(_j(gw.amend_publication(args.ref, args.close_at, actor="cli")))
            return 0
        if args.sub == "void":
            if not gw.check_admin(args.admin_token):
                raise Unauthorized("admin token required")
            print(_j(gw.void_publication(args.ref, actor="cli")))
            return 0

    if args.cmd == "shares":
        from .shares import all_catalog_fields

        def _fields(text: str) -> list[str]:
            if text.strip() == "all":
                return all_catalog_fields()
            return [x.strip() for x in text.split(",") if x.strip()]

        if args.sub == "grant":
            if not gw.check_admin(args.admin_token):
                raise Unauthorized("admin token required")
            print(_j(gw.grant_share_fields(args.ref, args.team,
                                           _fields(args.fields), actor="cli")))
            return 0
        if args.sub == "grants":
            print(_j({"grants": gw.list_share_grants(args.ref)}))
            return 0
        if args.sub == "create":
            if not gw.check_admin(args.admin_token):
                raise Unauthorized("admin token required")
            resp = gw.create_share(args.ref, args.team, _fields(args.fields),
                                   expires_at=args.expires_at,
                                   ttl_seconds=args.ttl, actor="cli")
            if args.out:
                pkg = gw.fetch_share(resp["share_key"], actor="cli")
                with open(args.out, "w", encoding="utf-8") as fh:
                    json.dump(pkg, fh, indent=2, sort_keys=True, ensure_ascii=False)
                resp["package_out"] = args.out
            print(_j(resp))
            return 0
        if args.sub == "fetch":
            team = gw.authenticate(args.token)
            pkg = gw.fetch_share(args.share_key, actor="team:" + team["team_id"],
                                 team_id=team["team_id"])
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    json.dump(pkg, fh, indent=2, sort_keys=True, ensure_ascii=False)
                print(_j({"out": args.out, "share_id": pkg["share_id"],
                          "share_version": pkg["share_version"],
                          "release_digest": pkg["release_digest"],
                          "fields": pkg["fields"], "expires_at": pkg["expires_at"]}))
            else:
                print(_j(pkg))
            return 0
        if args.sub == "list":
            print(_j({"shares": gw.list_shares(team_id=args.team,
                                               version_id=args.version_id,
                                               state=args.state)}))
            return 0
        if args.sub == "get":
            if not gw.check_admin(args.admin_token):
                raise Unauthorized("admin token required")
            print(_j(gw.get_share(args.share, include_key=args.reveal_key)))
            return 0
        if args.sub == "revoke":
            if not gw.check_admin(args.admin_token):
                raise Unauthorized("admin token required")
            print(_j(gw.revoke_share(args.share, reason=args.reason, actor="cli")))
            return 0
        if args.sub == "retrievals":
            if not gw.check_admin(args.admin_token):
                raise Unauthorized("admin token required")
            print(_j({"retrievals": gw.list_retrievals(args.share)}))
            return 0
        if args.sub == "recover":
            if not gw.check_admin(args.admin_token):
                raise Unauthorized("admin token required")
            print(_j(gw.recover_pending_shares(actor="cli")))
            return 0

    if args.cmd == "transparency":
        if args.sub == "state":
            if args.token and not gw.check_admin(args.token):
                gw.authenticate(args.token)
            print(_j(gw.tl_state()))
            return 0
        if args.sub == "checkpoint":
            if args.token and not gw.check_admin(args.token):
                gw.authenticate(args.token)
            resp = gw.tl_checkpoint(args.tree_size)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    json.dump(resp["checkpoint"], fh, indent=2, sort_keys=True,
                              ensure_ascii=False)
            print(_j(resp))
            return 0
        if args.sub == "leaves":
            if args.token and not gw.check_admin(args.token):
                gw.authenticate(args.token)
            print(_j({"leaves": gw.tl_list_leaves(event_type=args.event_type)}))
            return 0
        if args.sub == "inclusion":
            gw.authenticate(args.token)
            print(_j(gw.tl_inclusion(args.leaf_index, args.tree_size)))
            return 0
        if args.sub == "event":
            gw.authenticate(args.token)
            print(_j(gw.tl_lookup_event(args.event_key, args.tree_size)))
            return 0
        if args.sub == "consistency":
            gw.authenticate(args.token)
            resp = gw.tl_consistency(args.old_size, args.new_size)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    json.dump(resp, fh, indent=2, sort_keys=True, ensure_ascii=False)
            print(_j(resp))
            return 0
        if args.sub == "submit-fork":
            if not gw.check_admin(args.admin_token):
                raise Unauthorized("admin token required")
            with open(args.first, "r", encoding="utf-8") as a, \
                    open(args.second, "r", encoding="utf-8") as b:
                first, second = json.load(a), json.load(b)
            print(_j(gw.tl_submit_fork(first, second, actor="cli",
                                       reason=args.reason)))
            return 0
        if args.sub == "recover":
            if not gw.check_admin(args.admin_token):
                raise Unauthorized("admin token required")
            print(_j(gw.recover_transparency_log(actor="cli")))
            return 0

    if args.cmd == "freeze":
        print(_j(gw.freeze_family(args.family_id, scope=args.scope,
                                  team_id=args.team, snapshot_id=args.snapshot,
                                  reason=args.reason, actor="cli")))
        return 0

    if args.cmd == "freezes":
        print(_j({"freezes": gw.list_freezes()}))
        return 0

    if args.cmd == "unfreeze":
        gw.unfreeze(args.freeze_id, actor="cli")
        print(_j({"deleted": args.freeze_id}))
        return 0

    if args.cmd == "audit":
        print(_j({"audit": gw.list_audit(family_id=args.family, team_id=args.team,
                                         snapshot_id=args.snapshot, result_id=args.result,
                                         limit=args.limit)}))
        return 0

    if args.cmd == "bundle" and args.sub == "export":
        from .verify import export_bundle

        bundle = export_bundle(gw, team_id=args.team)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh, indent=2, sort_keys=True, ensure_ascii=False)
        print(_j({"out": args.out, "receipts": len(bundle["receipts"]),
                  "budgets": len(bundle["budgets"])}))
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
