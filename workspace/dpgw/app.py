"""Gateway home layout and bootstrap.

Home directory (created by ``dpgw init``)::

    home/
      gateway.sqlite    metadata, budgets, results, freezes, audit log
      secrets.json      noise master seed + receipt HMAC key + admin token (0600)
      snapshots/
        <snapshot_id>/manifest.json, data.sqlite

The noise master seed is the root of deterministic result reproducibility;
the receipt secret signs result receipts.  Both live only in secrets.json.
"""

from __future__ import annotations

import json
import os
import secrets as pysecrets

from .gateway import Gateway
from .receipts import token_hash
from .store import SCHEMA_VERSION, connect


def _read_secrets(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def bootstrap(home: str, *, force: bool = False) -> dict:
    """Initialise a gateway home directory and return (admin token info)."""
    os.makedirs(home, exist_ok=True)
    snap_root = os.path.join(home, "snapshots")
    os.makedirs(snap_root, exist_ok=True)
    os.makedirs(os.path.join(home, "shares"), exist_ok=True)
    secrets_path = os.path.join(home, "secrets.json")

    if os.path.exists(secrets_path) and not force:
        raise FileExistsError(f"{secrets_path} already exists; refusing to overwrite")

    admin_token = "dpa_" + pysecrets.token_urlsafe(24)
    data = {
        "schema_version": SCHEMA_VERSION,
        "noise_master_seed": pysecrets.token_hex(32),
        "receipt_secret": pysecrets.token_hex(32),
        "share_secret": pysecrets.token_hex(32),
        "transparency_secret": pysecrets.token_hex(32),
    }
    with open(secrets_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    os.chmod(secrets_path, 0o600)

    conn = connect(os.path.join(home, "gateway.sqlite"))
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES(?,?)",
        ("admin_token_sha256", token_hash(admin_token)),
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES(?,?)",
        ("schema_version", SCHEMA_VERSION),
    )
    conn.close()
    return {"home": os.path.abspath(home), "admin_token": admin_token}


def _ensure_share_secret(home: str, raw: dict, secrets_path: str) -> bytes:
    """Backfill share_secret into an older home's secrets.json (0600)."""
    existing = raw.get("share_secret")
    if existing:
        return bytes.fromhex(existing)
    raw["share_secret"] = pysecrets.token_hex(32)
    tmp = secrets_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(raw, fh, indent=2, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, secrets_path)
    return bytes.fromhex(raw["share_secret"])


def _ensure_secret(home: str, raw: dict, secrets_path: str, key: str) -> bytes:
    """Backfill one HMAC secret into an older home's secrets.json (0600)."""
    existing = raw.get(key)
    if existing:
        return bytes.fromhex(existing)
    raw[key] = pysecrets.token_hex(32)
    tmp = secrets_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(raw, fh, indent=2, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, secrets_path)
    return bytes.fromhex(raw[key])


def open_gateway(home: str, *, recover: bool = True) -> Gateway:
    secrets_path = os.path.join(home, "secrets.json")
    raw = _read_secrets(secrets_path)
    os.makedirs(os.path.join(home, "shares"), exist_ok=True)
    share_secret = _ensure_share_secret(home, raw, secrets_path)
    transparency_secret = _ensure_secret(home, raw, secrets_path,
                                         "transparency_secret")
    conn = connect(os.path.join(home, "gateway.sqlite"))
    gw = Gateway(
        conn,
        os.path.join(home, "snapshots"),
        {
            "noise_master_seed": bytes.fromhex(raw["noise_master_seed"]),
            "receipt_secret": bytes.fromhex(raw["receipt_secret"]),
            "share_secret": share_secret,
            "transparency_secret": transparency_secret,
        },
    )
    if recover:
        # finish any transparency outbox rows whose business change committed
        # before the crash BEFORE business recovery may produce new events:
        # the log resumes in fixed order and can never fork a second history
        gw.recover_transparency_log()
        # expire overdue tickets and cleanly fail jobs interrupted mid-confirm
        # so pending work is either continuable or safely rolled back
        gw.recover_pending_jobs()
        # seal due publication versions that reached their quorum, void those
        # below it (releasing holds), and leave open versions recoverable
        gw.recover_open_publications()
        # complete interrupted sharing-package materialisations deterministically
        # or safely terminate the ones whose authorisation no longer holds
        gw.recover_pending_shares()
        # guarantee no event committed by business recovery is left pending
        gw.recover_transparency_log()
    return gw
