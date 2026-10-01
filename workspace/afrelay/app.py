"""中继 home 布局与引导（独立于网关 home）::

    relay-home/
      relay.sqlite    独立镜像库 + 租户/位点/租约/事件
      config.json     上游 base_url、只读令牌、批大小/租约 TTL（0600）
      secrets.json    relay_packet_secret；可内联 transparency_secret，
                      或指向网关 secrets.json（离线验锚用）

中继只信任 transparency_secret：它与网关 secrets.json 中的同名字段一致，
由机构带外分发；中继从不读取网关的其它密钥或数据库。
"""

from __future__ import annotations

import json
import os
import secrets as pysecrets

from .canonical import token_hash
from .relay import Relay
from .store import SCHEMA_VERSION, connect
from .upstream import GatewayClient

DEFAULT_TTL = 30
DEFAULT_BATCH = 100
DEFAULT_MAX_INFLIGHT = 8


def _write_0600(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def bootstrap(home: str, *, upstream_url: str, upstream_token: str,
              transparency_secret_hex: str | None = None,
              gateway_secrets_path: str | None = None,
              default_ttl_seconds: int = DEFAULT_TTL,
              batch_size: int = DEFAULT_BATCH,
              default_max_inflight: int = DEFAULT_MAX_INFLIGHT,
              force: bool = False) -> dict:
    os.makedirs(home, exist_ok=True)
    secrets_path = os.path.join(home, "secrets.json")
    config_path = os.path.join(home, "config.json")
    if (os.path.exists(secrets_path) or os.path.exists(config_path)) and not force:
        raise FileExistsError(
            f"{home} already initialised; refusing to overwrite (use --force)")

    packet_secret = pysecrets.token_hex(32)
    admin_token = "afra_" + pysecrets.token_urlsafe(24)
    transparency_hex = transparency_secret_hex
    if transparency_hex is None and gateway_secrets_path:
        # 只把透明度信任锚这一个字段复制进中继自己的 secrets.json，使离线
        # 校验器自包含；网关的其它密钥一律不读、不存
        with open(gateway_secrets_path, "r", encoding="utf-8") as fh:
            gw = json.load(fh)
        transparency_hex = gw.get("transparency_secret")
    if not transparency_hex:
        raise FileNotFoundError(
            "could not obtain transparency_secret from --gateway-secrets")
    secrets_doc = {"relay_packet_secret": packet_secret,
                   "admin_token": admin_token,
                   "transparency_secret": transparency_hex}
    _write_0600(secrets_path, secrets_doc)

    config = {
        "schema_version": SCHEMA_VERSION,
        "upstream_url": upstream_url.rstrip("/"),
        "upstream_token": upstream_token,
        "gateway_secrets_path": gateway_secrets_path,
        "default_ttl_seconds": int(default_ttl_seconds),
        "batch_size": int(batch_size),
        "default_max_inflight": int(default_max_inflight),
    }
    _write_0600(config_path, config)

    conn = connect(os.path.join(home, "relay.sqlite"))
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES(?,?)",
        ("admin_token_sha256", token_hash(admin_token)))
    conn.commit()
    conn.close()
    return {"home": os.path.abspath(home), "admin_token": admin_token}


def load_relay_secrets(home: str) -> dict:
    with open(os.path.join(home, "secrets.json"), "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    out = {
        "relay_packet_secret": bytes.fromhex(raw["relay_packet_secret"]),
        "admin_token": raw.get("admin_token"),
    }
    if raw.get("transparency_secret"):
        out["transparency_secret"] = bytes.fromhex(raw["transparency_secret"])
    return out


def resolve_transparency_key(home: str, config: dict,
                             relay_secrets: dict) -> bytes:
    key = relay_secrets.get("transparency_secret")
    if key is not None:
        return key
    path = config.get("gateway_secrets_path")
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            gw = json.load(fh)
        if gw.get("transparency_secret"):
            return bytes.fromhex(gw["transparency_secret"])
    raise FileNotFoundError(
        "no transparency trust anchor: set transparency_secret in "
        f"{home}/secrets.json or gateway_secrets_path in config.json")


def open_relay(home: str, *, with_client: bool = True,
               clock=None) -> Relay:
    with open(os.path.join(home, "config.json"), "r", encoding="utf-8") as fh:
        config = json.load(fh)
    relay_secrets = load_relay_secrets(home)
    conn = connect(os.path.join(home, "relay.sqlite"))
    client = None
    if with_client:
        tkey = resolve_transparency_key(home, config, relay_secrets)
        client = GatewayClient(config["upstream_url"], config["upstream_token"],
                               tkey)
    return Relay(
        conn, client, relay_secrets["relay_packet_secret"],
        default_ttl_seconds=int(config.get("default_ttl_seconds", DEFAULT_TTL)),
        batch_size=int(config.get("batch_size", DEFAULT_BATCH)),
        default_max_inflight=int(config.get("default_max_inflight",
                                           DEFAULT_MAX_INFLIGHT)),
        clock=clock)
