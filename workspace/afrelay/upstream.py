"""现有 DPGW 网关透明度日志的只读客户端。

中继对网关**只发 GET**（state / checkpoint / inclusion），不使用任何写
接口，也不打开网关 SQLite。每个取回的文档都在这里用机构分发的
``transparency_secret`` 独立验签并折根；任何对不上的响应都归为
:class:`UpstreamError`（坏签名/证明缺口/回退/不可用），由同步循环停在最后
可信位置。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.error
import urllib.parse
import urllib.request

from .canonical import dumps_canon
from .errors import UpstreamError
from .merkle import (
    EMPTY_HASH,
    envelope_leaf_hash,
    verify_inclusion,
)

CHECKPOINT_VERSION = "tc1"


class GatewayClient:
    def __init__(self, base_url: str, token: str, transparency_key: bytes,
                 *, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.key = transparency_key
        self.timeout = timeout

    # ------------------------------------------------------------------ #
    # HTTP
    # ------------------------------------------------------------------ #

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(
                {k: v for k, v in params.items() if v is not None})
        req = urllib.request.Request(url, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read().decode("utf-8"))
            except Exception:
                body = {}
            raise UpstreamError(
                f"upstream {path} returned HTTP {exc.code}",
                reason="upstream_http_error",
                detail={"path": path, "http_status": exc.code,
                        "upstream_error": body.get("error")})
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise UpstreamError(
                f"upstream {path} unreachable: {exc}",
                reason="upstream_unavailable", detail={"path": path})
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise UpstreamError(f"upstream {path} returned non-JSON",
                                reason="upstream_malformed", detail={"path": path})

    # ------------------------------------------------------------------ #
    # read-only transparency endpoints
    # ------------------------------------------------------------------ #

    def state(self) -> dict:
        st = self._get("/v1/transparency")
        for field in ("tree_size", "root_hash", "frozen"):
            if field not in st:
                raise UpstreamError("state document missing " + field,
                                    reason="upstream_malformed")
        return st

    def checkpoint(self, tree_size: int) -> dict:
        doc = self._get("/v1/transparency/checkpoint",
                        {"tree_size": tree_size})
        # HTTP 包装：{"tree_size","root_hash","prev_*","checkpoint": <签名体>}
        if isinstance(doc, dict) and isinstance(doc.get("checkpoint"), dict):
            return doc["checkpoint"]
        return doc

    def inclusion(self, leaf_index: int, tree_size: int) -> dict:
        return self._get(f"/v1/transparency/inclusion/{leaf_index}",
                         {"tree_size": tree_size})

    # ------------------------------------------------------------------ #
    # independent verification (the relay's trust anchor)
    # ------------------------------------------------------------------ #

    def verify_checkpoint_doc(self, doc: dict) -> dict:
        """验一个已签名 checkpoint，返回解析后的主体。"""
        if not isinstance(doc, dict):
            raise UpstreamError("checkpoint must be an object",
                                reason="upstream_bad_signature")
        sig = doc.get("sig")
        if not isinstance(sig, str):
            raise UpstreamError("checkpoint missing sig",
                                reason="upstream_bad_signature")
        body = {k: v for k, v in doc.items() if k != "sig"}
        expect = hmac.new(self.key, dumps_canon(body).encode("utf-8"),
                          hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expect):
            raise UpstreamError("checkpoint signature invalid",
                                reason="upstream_bad_signature")
        if doc.get("checkpoint_version") != CHECKPOINT_VERSION:
            raise UpstreamError("unsupported checkpoint_version",
                                reason="upstream_bad_signature")
        size = doc.get("tree_size")
        root = doc.get("root_hash")
        if not isinstance(size, int) or size < 0 or not isinstance(root, str) \
                or len(root) != 64:
            raise UpstreamError("malformed checkpoint size/root",
                                reason="upstream_bad_signature")
        if size == 0 and root != EMPTY_HASH:
            raise UpstreamError("genesis checkpoint must sign the empty root",
                                reason="upstream_bad_signature")
        return doc

    def verify_inclusion_doc(self, doc: dict) -> dict:
        """验一片叶子的 inclusion 文档：checkpoint 签名 + 内容地址 + 折根。

        全部通过才返回规范化过的片段；任何一项不符都是证明缺口/签名错误，
        调用方必须停在该叶子之前，绝不写入。
        """
        cp = doc.get("checkpoint")
        self.verify_checkpoint_doc(cp if isinstance(cp, dict) else {})
        try:
            index = int(doc["leaf_index"])
            size = int(doc["tree_size"])
            leaf_hash_hex = doc["leaf_hash"]
            root_hex = doc["root_hash"]
            envelope = doc["envelope"]
            path = [bytes.fromhex(h) for h in doc["inclusion_path"]]
        except (KeyError, TypeError, ValueError) as exc:
            raise UpstreamError(f"inclusion document malformed: {exc}",
                                reason="upstream_proof_gap")
        if size != cp["tree_size"] or root_hex != cp["root_hash"]:
            raise UpstreamError(
                "inclusion anchor disagrees with signed checkpoint",
                reason="upstream_proof_gap")
        if index < 0 or index >= size:
            raise UpstreamError("inclusion leaf index outside tree",
                                reason="upstream_proof_gap")
        if envelope_leaf_hash(envelope) != leaf_hash_hex:
            raise UpstreamError(
                f"leaf {index}: hash does not reproduce from envelope",
                reason="upstream_bad_leaf")
        if envelope.get("event_key") != doc.get("event_key") or \
                envelope.get("event_type") != doc.get("event_type"):
            raise UpstreamError(
                f"leaf {index}: envelope event binding mismatch",
                reason="upstream_bad_leaf")
        root_ok = verify_inclusion(
            bytes.fromhex(root_hex), bytes.fromhex(leaf_hash_hex),
            index, size, path)
        if not root_ok:
            raise UpstreamError(
                f"leaf {index}: inclusion path does not fold to signed root",
                reason="upstream_proof_gap",
                detail={"leaf_index": index, "tree_size": size})
        return {
            "leaf_index": index,
            "tree_size": size,
            "root_hash": root_hex,
            "leaf_hash": leaf_hash_hex,
            "event_key": doc["event_key"],
            "event_type": doc["event_type"],
            "envelope": envelope,
            "checkpoint": cp,
            "prev_size": cp.get("prev_size"),
            "prev_root_hash": cp.get("prev_root_hash"),
        }
