"""并行窗口中继 home 布局与引导（自包含，无上游依赖）::

    wrelay-home/
      wrelay.sqlite   租户字节流 + 窗口/租约/完成事实 + 事件
      config.json     默认窗口大小、默认在途上限、租约 TTL（0600）
      secrets.json    window_packet_secret 与管理员令牌（0600）

中继不镜像任何外部系统：窗口源数据由管理员经 HTTP/CLI 逐租户 append
（JSON Lines 原始字节）。窗口边界在 (租户, window_size, seq) 上确定，
首次物化即固化原始字节，重启不改变。
"""

from __future__ import annotations

import json
import os
import secrets as pysecrets

from .canonical import token_hash
from .relay import Relay
from .store import SCHEMA_VERSION, connect

DEFAULT_TTL = 30
DEFAULT_WINDOW_SIZE = 64
DEFAULT_MAX_INFLIGHT = 4


def _write_0600(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def bootstrap(home: str, *, default_ttl_seconds: int = DEFAULT_TTL,
              window_size: int = DEFAULT_WINDOW_SIZE,
              max_inflight: int = DEFAULT_MAX_INFLIGHT,
              force: bool = False) -> dict:
    os.makedirs(home, exist_ok=True)
    secrets_path = os.path.join(home, "secrets.json")
    config_path = os.path.join(home, "config.json")
    if (os.path.exists(secrets_path) or os.path.exists(config_path)) and not force:
        raise FileExistsError(
            f"{home} already initialised; refusing to overwrite (use --force)")
    if int(window_size) < 1:
        raise ValueError("window_size must be >= 1")
    if int(max_inflight) < 1:
        raise ValueError("max_inflight must be >= 1")

    packet_secret = pysecrets.token_hex(32)
    admin_token = "afra_" + pysecrets.token_urlsafe(24)
    _write_0600(secrets_path,
                {"window_packet_secret": packet_secret,
                 "admin_token": admin_token})

    config = {
        "schema_version": SCHEMA_VERSION,
        "default_ttl_seconds": int(default_ttl_seconds),
        "window_size": int(window_size),
        "max_inflight": int(max_inflight),
    }
    _write_0600(config_path, config)

    conn = connect(os.path.join(home, "wrelay.sqlite"))
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES(?,?)",
        ("admin_token_sha256", token_hash(admin_token)))
    conn.commit()
    conn.close()
    return {"home": os.path.abspath(home), "admin_token": admin_token}


def load_relay_secrets(home: str) -> dict:
    with open(os.path.join(home, "secrets.json"), "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return {
        "window_packet_secret": bytes.fromhex(raw["window_packet_secret"]),
        "admin_token": raw.get("admin_token"),
    }


def open_relay(home: str, *, clock=None, recover: bool = True) -> Relay:
    with open(os.path.join(home, "config.json"), "r", encoding="utf-8") as fh:
        config = json.load(fh)
    relay_secrets = load_relay_secrets(home)
    conn = connect(os.path.join(home, "wrelay.sqlite"))
    relay = Relay(
        conn, relay_secrets["window_packet_secret"],
        default_ttl_seconds=int(config.get("default_ttl_seconds", DEFAULT_TTL)),
        default_window_size=int(config.get("window_size", DEFAULT_WINDOW_SIZE)),
        default_max_inflight=int(config.get("max_inflight", DEFAULT_MAX_INFLIGHT)),
        clock=clock)
    if recover:
        relay.recover()
    return relay
