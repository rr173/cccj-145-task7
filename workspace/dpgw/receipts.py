"""Canonical JSON serialisation and receipt signing.

Receipts must be byte-for-byte reproducible offline, so JSON encoding is
deterministic: sorted keys, ``,``/``:`` separators no whitespace, ensure_ascii.
Signatures are HMAC-SHA256 over the canonical encoding of the receipt body
(body = receipt dict without the ``sig`` field).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

RECEIPT_VERSION = "r1"
JOB_TICKET_VERSION = "j1"
JOB_MANIFEST_VERSION = "jm1"
PUB_RELEASE_VERSION = "pr1"


def dumps_canon(obj: Any) -> str:
    """Deterministic JSON used for hashes, signatures and receipts."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hmac_sign(key: bytes, body: dict) -> str:
    """Return hex HMAC-SHA256 over the canonical body (``sig`` stripped)."""
    body = {k: v for k, v in body.items() if k != "sig"}
    return hmac.new(key, dumps_canon(body).encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, receipt: dict) -> bool:
    sig = receipt.get("sig")
    if not isinstance(sig, str):
        return False
    expect = hmac_sign(key, receipt)
    return hmac.compare_digest(sig, expect)


def token_hash(token: str) -> str:
    """Hash of an API token as stored in the gateway database."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def signed(obj: dict, key: bytes) -> dict:
    """Return a copy of *obj* with a canonical-body ``sig`` attached."""
    out = dict(obj)
    out["sig"] = hmac_sign(key, out)
    return out


def build_result_receipt(*, result_id: str, team_id: str, snapshot_id: str,
                         query_hash: str, family_id: str, canonical: dict,
                         mechanism: str, epsilon: float, delta: float,
                         dimension: int, sensitivity_l1: float, scale: float,
                         coords: list, values: list, created_at: str) -> dict:
    """Assemble the canonical (unsigned) body of one result receipt."""
    return {
        "receipt_version": RECEIPT_VERSION,
        "result_id": result_id,
        "team_id": team_id,
        "snapshot_id": snapshot_id,
        "query_hash": query_hash,
        "family_id": family_id,
        "canonical": canonical,
        "mechanism": mechanism,
        "privacy": (
            {"epsilon": epsilon, "delta": 0.0}
            if mechanism == "laplace"
            else {"epsilon": epsilon, "delta": delta}
        ),
        "dimension": dimension,
        "sensitivity_l1": sensitivity_l1,
        "noise_scale": scale,
        "coords": coords,
        "values": values,
        "created_at": created_at,
    }
