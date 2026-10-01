"""HTTP API + embedded admin UI.

ThreadingHTTPServer in front of one Gateway: mutating paths are serialised by
the gateway lock/SQLite IMMEDIATE transactions, so concurrent analyst requests
are safe.

Auth: ``Authorization: Bearer <token>`` -- team tokens on /v1/*, admin token
on /v1/admin/*.  Error bodies are always {"error", "message"}.
"""

from __future__ import annotations

import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from .errors import DPGWError, InvalidBody, Unauthorized
from .webui import UI_ASSETS


class _Handler(BaseHTTPRequestHandler):
    server_version = "dpgw/1.0"

    # silence default noisy logging; callers plug in structured access logs
    def log_message(self, fmt, *args):  # noqa: N802
        return

    # ------------------------------------------------------------------ #
    # plumbing
    # ------------------------------------------------------------------ #

    @property
    def gw(self):
        return self.server.gw

    def _send(self, status: int, body: Any = None, *, raw: bytes | None = None,
              content_type: str = "application/json"):
        if raw is not None:
            payload = raw
        else:
            payload = json.dumps(body, allow_nan=False).encode("utf-8")
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

    def _team(self):
        return self.gw.authenticate(self._bearer())

    def _admin(self):
        if not self.gw.check_admin(self._bearer()):
            raise Unauthorized("admin token required")

    def _query_params(self) -> dict:
        parsed = urllib.parse.urlparse(self.path)
        return {k: v[-1] for k, v in urllib.parse.parse_qs(parsed.query).items()}

    # ------------------------------------------------------------------ #
    # routing
    # ------------------------------------------------------------------ #

    def do_GET(self):  # noqa: N802
        self._dispatch("GET")

    def do_POST(self):  # noqa: N802
        self._dispatch("POST")

    def do_DELETE(self):  # noqa: N802
        self._dispatch("DELETE")

    def _dispatch(self, method: str):
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/healthz" and method == "GET":
                return self._send(200, {"ok": True, "service": "dpgw"})

            if path == "/" or path.startswith("/ui"):
                return self._serve_ui(path)

            routes = self.server.routes.get(method, {})
            for pattern, handler in routes.items():
                m = pattern.match(path)
                if m:
                    return handler(self, **m.groupdict())
            self._send(404, {"error": "not_found", "message": f"{method} {path}"})
        except DPGWError as e:
            self._send(e.status, e.to_dict())
        except Exception as e:  # never leak internals; audit as 500
            self._send(500, {"error": "internal_error", "message": "internal error"})

    def _serve_ui(self, path: str):
        rel = "index.html" if path in ("/", "/ui", "/ui/") else path[len("/ui/"):]
        asset = UI_ASSETS.get(rel)
        if asset is None:
            return self._send(404, {"error": "not_found", "message": rel})
        ctype = "text/html" if rel.endswith(".html") else "application/javascript"
        self._send(200, raw=asset.encode("utf-8"), content_type=ctype)

    # ------------------------------------------------------------------ #
    # analyst endpoints
    # ------------------------------------------------------------------ #

    def ep_query(self):
        team = self._team()
        body = self._read_json()
        resp = self.gw.run_query(
            team["team_id"],
            body.get("snapshot", {}),
            body.get("query", {}),
            request_id=body.get("request_id"),
        )
        self._send(200, resp)

    def ep_plan(self):
        team = self._team()
        body = self._read_json()
        resp = self.gw.plan(
            team["team_id"], body.get("snapshot", {}), body.get("query", {}),
            request_id=body.get("request_id"),
        )
        self._send(200, resp)

    def ep_result_get(self, result_id: str):
        team = self._team()
        self._send(200, self.gw.get_result(team["team_id"], result_id))

    def ep_results_list(self):
        team = self._team()
        params = self._query_params()
        self._send(200, {"results": self.gw.list_results(
            team["team_id"], params.get("snapshot_id"))})

    def ep_team_budgets(self):
        team = self._team()
        self._send(200, {"budgets": self.gw.list_budgets(team["team_id"])})

    # ------------------------------------------------------------------ #
    # multi-statement analysis jobs
    # ------------------------------------------------------------------ #

    def ep_jobs_create(self):
        team = self._team()
        body = self._read_json()
        resp = self.gw.create_job(
            team["team_id"], body.get("statements", []),
            request_key=body.get("request_key"),
            ttl_seconds=body.get("ttl_seconds"),
            request_id=body.get("request_id"),
        )
        self._send(201, resp)

    def ep_job_get(self, job_id: str):
        team = self._team()
        self._send(200, self.gw.get_job(job_id, team["team_id"]))

    def ep_job_confirm(self, job_id: str):
        team = self._team()
        body = self._read_json()
        resp = self.gw.confirm_job(
            job_id, team["team_id"], request_id=body.get("request_id"))
        self._send(200, resp)

    def ep_job_cancel(self, job_id: str):
        team = self._team()
        body = self._read_json()
        resp = self.gw.cancel_job(
            job_id, team["team_id"], request_id=body.get("request_id"))
        self._send(200, resp)

    # ------------------------------------------------------------------ #
    # amendable joint publication batches (team side)
    # ------------------------------------------------------------------ #

    def ep_pub_get(self, ref: str):
        team = self._team()
        self._send(200, self.gw.get_publication(ref))

    def ep_pub_list(self):
        team = self._team()
        params = self._query_params()
        self._send(200, {"publications": self.gw.list_publications(
            state=params.get("state"), batch_id=params.get("batch_id"))})

    def ep_pub_register(self, ref: str):
        team = self._team()
        body = self._read_json()
        resp = self.gw.register_contribution(
            ref, team["team_id"], request_id=body.get("request_id"))
        self._send(200, resp)

    def ep_pub_withdraw(self, ref: str):
        team = self._team()
        body = self._read_json()
        resp = self.gw.withdraw_contribution(
            ref, team["team_id"], request_id=body.get("request_id"))
        self._send(200, resp)

    def ep_pub_lineage(self, ref: str):
        team = self._team()
        self._send(200, {"batch_ref": ref, "versions": self.gw.list_lineage(ref)})

    # ------------------------------------------------------------------ #
    # controlled sharing packages (recipient side)
    # ------------------------------------------------------------------ #

    def ep_share_fetch(self):
        team = self._team()
        body = self._read_json()
        key = body.get("share_key") or self._query_params().get("share_key", "")
        pkg = self.gw.fetch_share(key, actor="team:" + team["team_id"],
                                  team_id=team["team_id"],
                                  request_id=body.get("request_id"))
        self._send(200, pkg)

    # ------------------------------------------------------------------ #
    # admin endpoints
    # ------------------------------------------------------------------ #

    def ep_admin_teams_list(self):
        self._admin()
        self._send(200, {"teams": self.gw.list_teams()})

    def ep_admin_teams_create(self):
        self._admin()
        body = self._read_json()
        self._send(201, self.gw.create_team(body.get("name", ""), actor="admin"))

    def ep_admin_snapshots_list(self):
        self._admin()
        self._send(200, {"snapshots": self.gw.list_snapshots()})

    def ep_admin_snapshots_publish(self):
        self._admin()
        body = self._read_json()
        resp = self.gw.publish_snapshot(body["path"], actor="admin",
                                        activate=bool(body.get("active", True)))
        self._send(201, resp)

    def ep_admin_snapshot_active(self, snapshot_id: str):
        self._admin()
        body = self._read_json()
        self.gw.set_snapshot_active(snapshot_id, bool(body.get("active", True)), actor="admin")
        self._send(200, {"snapshot_id": snapshot_id, "active": bool(body.get("active", True))})

    def ep_admin_budgets_list(self):
        self._admin()
        params = self._query_params()
        self._send(200, {"budgets": self.gw.list_budgets(params.get("team_id"))})

    def ep_admin_budgets_allocate(self):
        self._admin()
        body = self._read_json()
        resp = self.gw.allocate_budget(
            body["team_id"], body["snapshot_id"],
            float(body["epsilon"]), float(body.get("delta", 0.0)),
            actor="admin",
        )
        self._send(200, resp)

    def ep_admin_freezes_list(self):
        self._admin()
        self._send(200, {"freezes": self.gw.list_freezes()})

    def ep_admin_freezes_create(self):
        self._admin()
        body = self._read_json()
        resp = self.gw.freeze_family(
            body["family_id"],
            scope=body.get("scope", "global"),
            team_id=body.get("team_id"),
            snapshot_id=body.get("snapshot_id"),
            reason=body.get("reason", ""),
            actor="admin",
        )
        self._send(201, resp)

    def ep_admin_freeze_delete(self, freeze_id: str):
        self._admin()
        self.gw.unfreeze(freeze_id, actor="admin")
        self._send(200, {"deleted": freeze_id})

    def ep_admin_audit(self):
        self._admin()
        p = self._query_params()
        self._send(200, {"audit": self.gw.list_audit(
            family_id=p.get("family_id"), team_id=p.get("team_id"),
            snapshot_id=p.get("snapshot_id"), result_id=p.get("result_id"),
            limit=int(p.get("limit", "200")),
        )})

    def ep_admin_bundle(self):
        from .verify import export_bundle

        self._admin()
        p = self._query_params()
        team_id = p.get("team_id")
        bundle = export_bundle(self.gw, team_id=team_id)
        self._send(200, bundle)

    def ep_admin_jobs(self):
        self._admin()
        p = self._query_params()
        self._send(200, {"jobs": self.gw.list_jobs(
            team_id=p.get("team_id"), state=p.get("state"))})

    def ep_admin_holds(self):
        self._admin()
        p = self._query_params()
        self._send(200, {"holds": self.gw.list_holds(
            team_id=p.get("team_id"), snapshot_id=p.get("snapshot_id"))})

    # ------------------------------------------------------------------ #
    # joint publication batches (analysis-owner / admin side)
    # ------------------------------------------------------------------ #

    def ep_admin_pub_create(self):
        self._admin()
        body = self._read_json()
        resp = self.gw.create_publication(
            body.get("name", ""), body.get("statements", []),
            int(body.get("min_participants", 1)), body.get("close_at", ""),
            actor="admin", request_id=body.get("request_id"))
        self._send(201, resp)

    def ep_admin_pub_list(self):
        self._admin()
        p = self._query_params()
        self._send(200, {"publications": self.gw.list_publications(
            state=p.get("state"), batch_id=p.get("batch_id"))})

    def ep_admin_pub_get(self, ref: str):
        self._admin()
        self._send(200, self.gw.get_publication(ref))

    def ep_admin_pub_lineage(self, ref: str):
        self._admin()
        self._send(200, {"batch_ref": ref, "versions": self.gw.list_lineage(ref)})

    def ep_admin_pub_seal(self, ref: str):
        self._admin()
        body = self._read_json()
        resp = self.gw.seal_publication(
            ref, actor="admin", request_id=body.get("request_id"))
        self._send(200, resp)

    def ep_admin_pub_amend(self, ref: str):
        self._admin()
        body = self._read_json()
        resp = self.gw.amend_publication(
            ref, body.get("close_at", ""), actor="admin",
            request_id=body.get("request_id"))
        self._send(201, resp)

    def ep_admin_pub_void(self, ref: str):
        self._admin()
        body = self._read_json()
        resp = self.gw.void_publication(
            ref, actor="admin", request_id=body.get("request_id"))
        self._send(200, resp)

    def ep_admin_pub_sweep(self):
        self._admin()
        self._send(200, self.gw.sweep_due_publications(actor="admin"))

    def ep_admin_pub_holds(self):
        self._admin()
        p = self._query_params()
        self._send(200, {"holds": self.gw.list_pub_holds(
            team_id=p.get("team_id"), snapshot_id=p.get("snapshot_id"))})

    # ------------------------------------------------------------------ #
    # controlled sharing packages (owner / admin side)
    # ------------------------------------------------------------------ #

    def ep_admin_share_grants(self):
        self._admin()
        p = self._query_params()
        self._send(200, {"grants": self.gw.list_share_grants(p.get("version_id"))})

    def ep_admin_share_grant_set(self):
        self._admin()
        body = self._read_json()
        resp = self.gw.grant_share_fields(
            body.get("ref", ""), body.get("team_id", ""), body.get("fields", []),
            actor="admin", request_id=body.get("request_id"))
        self._send(200, resp)

    def ep_admin_shares_list(self):
        self._admin()
        p = self._query_params()
        self._send(200, {"shares": self.gw.list_shares(
            version_id=p.get("version_id"), team_id=p.get("team_id"),
            state=p.get("state"))})

    def ep_admin_share_create(self):
        self._admin()
        body = self._read_json()
        resp = self.gw.create_share(
            body.get("ref", ""), body.get("team_id", ""), body.get("fields", []),
            expires_at=body.get("expires_at"), ttl_seconds=body.get("ttl_seconds"),
            actor="admin", request_id=body.get("request_id"))
        self._send(201, resp)

    def ep_admin_share_get(self, share_id: str):
        self._admin()
        p = self._query_params()
        # the share_key is only returned when the owner explicitly asks for it
        self._send(200, self.gw.get_share(
            share_id, include_key=p.get("reveal_key") == "1"))

    def ep_admin_share_revoke(self, share_id: str):
        self._admin()
        body = self._read_json()
        resp = self.gw.revoke_share(
            share_id, reason=body.get("reason", ""), actor="admin",
            request_id=body.get("request_id"))
        self._send(200, resp)

    def ep_admin_share_retrievals(self, share_id: str):
        self._admin()
        self._send(200, {"retrievals": self.gw.list_retrievals(share_id)})

    def ep_admin_shares_recover(self):
        self._admin()
        self._send(200, self.gw.recover_pending_shares(actor="admin"))

    # ------------------------------------------------------------------ #
    # anti-fork transparency ledger
    # ------------------------------------------------------------------ #

    def _auth_any(self):
        """Accept either a team token or the admin token (read-only proofs)."""
        token = self._bearer()
        if self.gw.check_admin(token):
            return
        self.gw.authenticate(token)  # raises Forbidden for invalid tokens

    def ep_tl_state(self):
        self._auth_any()
        self._send(200, self.gw.tl_state())

    def ep_tl_checkpoint(self):
        self._auth_any()
        p = self._query_params()
        size = p.get("tree_size")
        self._send(200, self.gw.tl_checkpoint(None if size is None else int(size)))

    def ep_tl_leaves_list(self):
        self._auth_any()
        p = self._query_params()
        self._send(200, {"leaves": self.gw.tl_list_leaves(
            event_type=p.get("event_type"))})

    def ep_tl_inclusion(self, leaf_index: str):
        self._auth_any()
        p = self._query_params()
        size = p.get("tree_size")
        self._send(200, self.gw.tl_inclusion(
            int(leaf_index), None if size is None else int(size)))

    def ep_tl_event(self, event_key: str):
        self._auth_any()
        p = self._query_params()
        size = p.get("tree_size")
        self._send(200, self.gw.tl_lookup_event(
            event_key, None if size is None else int(size)))

    def ep_tl_consistency(self):
        self._auth_any()
        p = self._query_params()
        if "old_size" not in p:
            raise InvalidBody("old_size query parameter is required")
        new = p.get("new_size")
        self._send(200, self.gw.tl_consistency(
            int(p["old_size"]), None if new is None else int(new)))

    def ep_admin_tl_fork(self):
        self._admin()
        body = self._read_json()
        first, second = body.get("first"), body.get("second")
        if not isinstance(first, dict) or not isinstance(second, dict):
            raise InvalidBody("fork evidence requires 'first' and 'second' signed "
                              "checkpoint objects")
        self._send(200, self.gw.tl_submit_fork(
            first, second, actor="admin", reason=body.get("reason", "")))

    def ep_admin_tl_recover(self):
        self._admin()
        self._send(200, self.gw.recover_transparency_log(actor="admin"))


def _build_routes() -> dict[str, dict]:
    import re

    def rx(path: str) -> re.Pattern:
        return re.compile("^" + re.sub(r"<(\w+)>", r"(?P<\1>[^/]+)", path) + "$")

    get: list[tuple[str, Callable]] = [
        ("/v1/jobs/<job_id>", _Handler.ep_job_get),
        ("/v1/results", _Handler.ep_results_list),
        ("/v1/results/<result_id>", _Handler.ep_result_get),
        ("/v1/budgets", _Handler.ep_team_budgets),
        ("/v1/publications", _Handler.ep_pub_list),
        ("/v1/publications/<ref>/lineage", _Handler.ep_pub_lineage),
        ("/v1/publications/<ref>", _Handler.ep_pub_get),
        ("/v1/admin/jobs", _Handler.ep_admin_jobs),
        ("/v1/admin/holds", _Handler.ep_admin_holds),
        ("/v1/admin/teams", _Handler.ep_admin_teams_list),
        ("/v1/admin/snapshots", _Handler.ep_admin_snapshots_list),
        ("/v1/admin/snapshots/<snapshot_id>/active", _Handler.ep_admin_snapshot_active),
        ("/v1/admin/budgets", _Handler.ep_admin_budgets_list),
        ("/v1/admin/freezes", _Handler.ep_admin_freezes_list),
        ("/v1/admin/freezes/<freeze_id>", _Handler.ep_admin_freeze_delete),
        ("/v1/admin/audit", _Handler.ep_admin_audit),
        ("/v1/admin/bundle", _Handler.ep_admin_bundle),
        ("/v1/admin/publications", _Handler.ep_admin_pub_list),
        ("/v1/admin/publications/sweep", _Handler.ep_admin_pub_sweep),
        ("/v1/admin/publications/holds", _Handler.ep_admin_pub_holds),
        ("/v1/admin/publications/<ref>/lineage", _Handler.ep_admin_pub_lineage),
        ("/v1/admin/publications/<ref>", _Handler.ep_admin_pub_get),
        ("/v1/admin/shares", _Handler.ep_admin_shares_list),
        ("/v1/admin/shares/<share_id>/retrievals", _Handler.ep_admin_share_retrievals),
        ("/v1/admin/shares/<share_id>", _Handler.ep_admin_share_get),
        ("/v1/admin/share-grants", _Handler.ep_admin_share_grants),
        ("/v1/admin/transparency/recover", _Handler.ep_admin_tl_recover),
        ("/v1/admin/transparency/fork", _Handler.ep_admin_tl_fork),
        ("/v1/transparency/consistency", _Handler.ep_tl_consistency),
        ("/v1/transparency/checkpoint", _Handler.ep_tl_checkpoint),
        ("/v1/transparency/leaves", _Handler.ep_tl_leaves_list),
        ("/v1/transparency/events/<event_key>", _Handler.ep_tl_event),
        ("/v1/transparency/inclusion/<leaf_index>", _Handler.ep_tl_inclusion),
        ("/v1/transparency", _Handler.ep_tl_state),
    ]
    post: list[tuple[str, Callable]] = [
        ("/v1/jobs", _Handler.ep_jobs_create),
        ("/v1/jobs/<job_id>/confirm", _Handler.ep_job_confirm),
        ("/v1/jobs/<job_id>/cancel", _Handler.ep_job_cancel),
        ("/v1/query", _Handler.ep_query),
        ("/v1/plan", _Handler.ep_plan),
        ("/v1/publications/<ref>/register", _Handler.ep_pub_register),
        ("/v1/publications/<ref>/withdraw", _Handler.ep_pub_withdraw),
        ("/v1/shares/fetch", _Handler.ep_share_fetch),
        ("/v1/admin/teams", _Handler.ep_admin_teams_create),
        ("/v1/admin/snapshots/publish", _Handler.ep_admin_snapshots_publish),
        ("/v1/admin/budgets", _Handler.ep_admin_budgets_allocate),
        ("/v1/admin/freezes", _Handler.ep_admin_freezes_create),
        ("/v1/admin/publications", _Handler.ep_admin_pub_create),
        ("/v1/admin/publications/<ref>/seal", _Handler.ep_admin_pub_seal),
        ("/v1/admin/publications/<ref>/amend", _Handler.ep_admin_pub_amend),
        ("/v1/admin/publications/<ref>/void", _Handler.ep_admin_pub_void),
        ("/v1/admin/share-grants", _Handler.ep_admin_share_grant_set),
        ("/v1/admin/shares", _Handler.ep_admin_share_create),
        ("/v1/admin/shares/recover", _Handler.ep_admin_shares_recover),
        ("/v1/admin/shares/<share_id>/revoke", _Handler.ep_admin_share_revoke),
        ("/v1/admin/transparency/fork", _Handler.ep_admin_tl_fork),
    ]
    delete: list[tuple[str, Callable]] = [
        ("/v1/admin/freezes/<freeze_id>", _Handler.ep_admin_freeze_delete),
    ]
    return {
        "GET": {rx(p): h for p, h in get},
        "POST": {rx(p): h for p, h in post},
        "DELETE": {rx(p): h for p, h in delete},
    }


def serve(gw, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _Handler)
    server.gw = gw
    server.routes = _build_routes()
    server.daemon_threads = True
    return server
