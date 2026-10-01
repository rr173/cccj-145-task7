"""RFC 9162 风格 Merkle 日志纯函数。

与 dpgw.transparency 的叶/节点哈希完全一致：

    leaf hash  = SHA256(0x00 || canonical(envelope))
    inner hash = SHA256(0x01 || L || R)

中继在自己的镜像库里按原始序号稠密保存每片叶子，因此可以**本地**重算任意
叶在任意高度的包含路径，投递包字节内容在超时重投/重启后逐字节确定。
"""

from __future__ import annotations

import hashlib

from .canonical import NODE_PREFIX, LEAF_PREFIX, dumps_canon

EMPTY_HASH = hashlib.sha256(b"").hexdigest()


def leaf_hash_bytes(leaf_bytes: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + leaf_bytes).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def fold_level(level: list[bytes]) -> list[bytes]:
    out: list[bytes] = []
    for i in range(0, len(level) - 1, 2):
        out.append(node_hash(level[i], level[i + 1]))
    if len(level) % 2:
        out.append(level[-1])  # 奇数节点原样上提
    return out


def merkle_root(leaf_hashes) -> bytes:
    level = list(leaf_hashes)
    if not level:
        return bytes.fromhex(EMPTY_HASH)
    while len(level) > 1:
        level = fold_level(level)
    return level[0]


def envelope_leaf_hash(envelope: dict) -> str:
    return leaf_hash_bytes(dumps_canon(envelope).encode("utf-8")).hex()


def inclusion_nodes(leaf_hashes: list[bytes], index: int) -> list[bytes]:
    """自底向上把一片叶子折到根所需的兄弟哈希（侧边由验证方按位置自推）。"""
    n = len(leaf_hashes)
    if not (0 <= index < n):
        raise IndexError("leaf index out of range")
    level = list(leaf_hashes)
    pos = index
    proof: list[bytes] = []
    while len(level) > 1:
        if pos % 2:
            proof.append(level[pos - 1])
        elif pos + 1 < len(level):
            proof.append(level[pos + 1])
        pos //= 2
        level = fold_level(level)
    return proof


def verify_inclusion(root: bytes, leaf: bytes, index: int, tree_size: int,
                     proof_hashes: list[bytes]) -> bool:
    """自底向上重折单片叶子，每个兄弟的左右侧由位置/层宽重新推导。"""
    if tree_size <= 0 or not (0 <= index < tree_size):
        return False
    pos = index
    size = tree_size
    h = leaf
    pi = 0
    while size > 1:
        if pos % 2 == 1:
            if pi >= len(proof_hashes):
                return False
            h = node_hash(proof_hashes[pi], h)
            pi += 1
        elif pos + 1 < size:
            if pi >= len(proof_hashes):
                return False
            h = node_hash(h, proof_hashes[pi])
            pi += 1
        # 被上提的奇数节点不消耗 proof 项
        pos //= 2
        size = (size + 1) // 2
    return pi == len(proof_hashes) and h == root
