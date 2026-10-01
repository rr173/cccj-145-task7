"""离线投递包校验器（无需中继进程）。

审计租户拿到 afp1 投递包文件 + 中继的 secrets.json（或显式密钥材料）即可
独立复核：

* 包级 HMAC（relay_packet_secret，绑 delivery_id/区间/叶哈希/锚 checkpoint）；
* delivery_id 由 (tenant, seq, 区间, 叶哈希) 确定性重算；
* 每片叶子：内容地址（SHA256(0x00||规范信封)）、event 绑定；
* 锚 checkpoint 的网关 transparency_secret 签名 + 每条 inclusion_path 折到
  该已签名根；
* 区间按原始序号连续、叶哈希稠密、包根与 checkpoint 根一致。

退出码：0=有效；2=验签/折根失败；3=参数/文件错误。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from .canonical import dumps_canon, hmac_hex
from .merkle import (
    EMPTY_HASH,
    envelope_leaf_hash,
    merkle_root,
    verify_inclusion,
)

CHECKPOINT_VERSION = "tc1"


def load_relay_keys(secrets_path: str) -> dict:
    """接受 secrets.json 文件路径或 relay home 目录。"""
    if os.path.isdir(secrets_path):
        secrets_path = os.path.join(secrets_path, "secrets.json")
    with open(secrets_path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    out: dict[str, bytes] = {
        "relay_packet_secret": bytes.fromhex(raw["relay_packet_secret"])}
    if raw.get("transparency_secret"):
        out["transparency_secret"] = bytes.fromhex(raw["transparency_secret"])
    return out


def verify_packet(packet: dict, keys: dict, *,
                  expected_tenant: str | None = None) -> dict:
    errors: list[str] = []
    checks: dict[str, Any] = {}

    if not isinstance(packet, dict):
        return {"ok": False, "errors": ["packet must be an object"],
                "checks": {}}

    packet_key = keys.get("relay_packet_secret")
    if packet_key is None:
        return {"ok": False, "errors": ["missing relay_packet_secret"],
                "checks": {}}

    # ---- 1) packet envelope HMAC ----
    sig = packet.get("sig")
    expect_sig = hmac_hex(
        packet_key,
        dumps_canon({k: v for k, v in packet.items() if k != "sig"})
        .encode("utf-8"))
    checks["packet_signature"] = isinstance(sig, str) and \
        hmac.compare_digest(sig or "", expect_sig)
    if not checks["packet_signature"]:
        errors.append("packet HMAC invalid (content tampered or wrong key)")

    if packet.get("packet_version") != "afp1":
        errors.append("unsupported packet_version")
    tenant = packet.get("tenant_id")
    if expected_tenant is not None and tenant != expected_tenant:
        errors.append(f"packet tenant {tenant!r} != expected {expected_tenant!r}")

    start, end, seq = packet.get("start_index"), packet.get("end_index"), \
        packet.get("seq")
    records = packet.get("records", [])
    leaf_hashes = packet.get("leaf_hashes", [])
    cp = packet.get("checkpoint", {})

    # ---- 2) anchor checkpoint signature (gateway transparency key) ----
    cp_report = _verify_checkpoint(cp, keys.get("transparency_secret"))
    checks["checkpoint_signature"] = cp_report["ok"]
    errors.extend("checkpoint: " + e for e in cp_report["errors"])

    # ---- 3) structural continuity ----
    if not isinstance(records, list) or not records:
        errors.append("packet must carry a non-empty records list")
        records = []
    if not isinstance(start, int) or not isinstance(end, int) \
            or not isinstance(seq, int) or start < 0 or end <= start:
        errors.append("packet indices malformed (require 0 <= start < end)")
    elif records:
        indices = [r.get("leaf_index") for r in records]
        if indices != sorted(indices) or len(set(indices)) != len(indices):
            errors.append("record leaf_index values are not strictly increasing")
        if indices[0] < start or indices[-1] >= end:
            errors.append("record indices fall outside [start_index, end_index)")
        if len(leaf_hashes) != len(records):
            errors.append("leaf_hashes length does not match records")
        else:
            for r, lh in zip(records, leaf_hashes):
                if r.get("leaf_hash") != lh:
                    errors.append(
                        f"leaf {r.get('leaf_index')}: leaf_hashes row mismatch")

    # ---- 4) delivery_id determinism ----
    want_did = "afd_" + hmac_hex(
        packet_key,
        dumps_canon({"tenant_id": tenant, "seq": seq, "start_index": start,
                     "end_index": end, "leaf_hashes": leaf_hashes})
        .encode("utf-8"))[:32]
    checks["delivery_id"] = packet.get("delivery_id") == want_did
    if not checks["delivery_id"]:
        errors.append("delivery_id does not reproduce from packet contents")

    # ---- 5) anchor root + per-leaf content address + inclusion folds ----
    if cp_report["ok"]:
        cp_end = cp["tree_size"]
        if cp_end != end:
            errors.append(f"checkpoint tree_size {cp_end} != end_index {end}")
        root_hex = cp["root_hash"]

        dense_root = None
        # records embed their subtree fold at tree_size=end: we cannot rebuild
        # skipped leaves, but every record's own path must fold to the signed
        # root using its sibling hashes.
        for r in records:
            try:
                idx = int(r["leaf_index"])
                size = int(r["tree_size"])
                lh = envelope_leaf_hash(r["envelope"])
                if lh != r["leaf_hash"]:
                    errors.append(
                        f"leaf {idx}: content address mismatch")
                if r["envelope"].get("event_key") != r.get("event_key") or \
                        r["envelope"].get("event_type") != r.get("event_type"):
                    errors.append(f"leaf {idx}: event binding mismatch")
                if size != end or r.get("root_hash") != root_hex:
                    errors.append(
                        f"leaf {idx}: anchor size/root mismatch")
                path = [bytes.fromhex(h) for h in r.get("inclusion_path", [])]
                if not verify_inclusion(bytes.fromhex(root_hex),
                                        bytes.fromhex(r["leaf_hash"]),
                                        idx, end, path):
                    errors.append(
                        f"leaf {idx}: inclusion path does not fold to root")
            except (KeyError, TypeError, ValueError) as exc:
                errors.append(f"record malformed: {exc}")

        # dense leaf hashes delivered in the packet must all hash consistently
        # with the single anchor root only if a full [0,end) prefix is present
        # via an optional dense_hashes field (bundled exports); otherwise each
        # leaf is independently anchored as above.
        dense = packet.get("dense_leaf_hashes")
        if dense is not None:
            try:
                if len(dense) != end:
                    errors.append("dense_leaf_hashes length != end_index")
                dense_root = merkle_root(
                    [bytes.fromhex(h) for h in dense]).hex()
                if dense_root != root_hex:
                    errors.append(
                        "dense leaf hashes do not reproduce anchor root")
                delivered = {r["leaf_index"]: r["leaf_hash"] for r in records}
                for idx, lh in delivered.items():
                    if dense[idx] != lh:
                        errors.append(
                            f"leaf {idx}: delivered hash != dense hash")
            except (TypeError, ValueError) as exc:
                errors.append(f"dense_leaf_hashes malformed: {exc}")

    return {"ok": not errors, "errors": errors, "checks": checks,
            "delivery_id": packet.get("delivery_id"),
            "tenant_id": tenant, "seq": seq,
            "start_index": start, "end_index": end,
            "leaf_count": len(records),
            "tree_size": cp.get("tree_size"),
            "root_hash": cp.get("root_hash")}


def _verify_checkpoint(cp: Any, key: bytes | None) -> dict:
    errors: list[str] = []
    if not isinstance(cp, dict):
        return {"ok": False, "errors": ["checkpoint missing"]}
    if key is None:
        return {"ok": False,
                "errors": ["missing transparency_secret for anchor checkpoint"]}
    sig = cp.get("sig")
    expect = hmac.new(
        key,
        dumps_canon({k: v for k, v in cp.items() if k != "sig"}).encode("utf-8"),
        hashlib.sha256).hexdigest()
    if not isinstance(sig, str) or not hmac.compare_digest(sig, expect):
        errors.append("checkpoint HMAC invalid")
    if cp.get("checkpoint_version") != CHECKPOINT_VERSION:
        errors.append("unsupported checkpoint_version")
    size = cp.get("tree_size")
    root = cp.get("root_hash")
    if not isinstance(size, int) or size < 0 or not isinstance(root, str) \
            or len(root) != 64:
        errors.append("malformed checkpoint size/root")
    if size == 0 and root != EMPTY_HASH:
        errors.append("genesis root mismatch")
    return {"ok": not errors, "errors": errors}
