"""确定性 JSON 与 HMAC 原语。

规范编码与 afrelay/dpgw 一致（sorted keys、无空白、ensure_ascii、禁
NaN），因此 window_id / 包 HMAC / 字节摘要在超时重投与进程重启后逐字节
可复算。
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any


def dumps_canon(obj: Any) -> str:
    """用于哈希与签名的确定性 JSON。"""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def hmac_sign(key: bytes, body: dict) -> str:
    """对去掉 ``sig`` 字段的规范体做 HMAC-SHA256。"""
    stripped = {k: v for k, v in body.items() if k != "sig"}
    return hmac.new(key, dumps_canon(stripped).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, doc: dict) -> bool:
    sig = doc.get("sig")
    if not isinstance(sig, str):
        return False
    return hmac.compare_digest(sig, hmac_sign(key, doc))


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
