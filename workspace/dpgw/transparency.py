"""Anti-fork transparency ledger for signed releases and trimmed distributions.

One append-only Merkle log records every terminal business event of the
publication/sharing subsystem:

* ``release_sealed``  -- a joint-publication version sealed (one signed release);
* ``release_voided``  -- a version voided at its deadline below quorum;
* ``share_issued``    -- a field-trimmed sharing package sealed;
* ``share_revoked``   -- a share revoked (online retrieval blocked).

Each event is first inserted into ``tl_outbox`` **inside the same
``BEGIN IMMEDIATE`` transaction** as the business change, then drained -- while
the gateway lock is still held -- into ``tl_leaves`` and a new signed
``tl_checkpoints`` row.  Every appended leaf advances the tree by exactly one
size and every checkpoint signs (tree_size, root, prev_size, prev_root), so:

* leaves are content-addressed (``leaf_hash`` = RFC-6962-style Merkle leaf) and
  indexed densely 0..n-1; the same ``event_key`` replay returns the original
  leaf index, the same key with a different payload is a conflict;
* callers obtain an *inclusion proof* for a leaf and a *consistency proof*
  between any two adjacent (or non-adjacent) checkpoints;
* an auditor who observes two validly signed checkpoints with the SAME tree
  size but DIFFERENT roots submits both as fork evidence and freezes every
  subsequent issuance;
* a crash leaves either no business change or a recoverable outbox row; restart
  drains the outbox in its fixed AUTOINCREMENT order, so the interrupted
  process resumes deterministically and can never produce a second history.

Merkle hashing follows RFC 9162 (Certificate Transparency):

    leaf hash  = SHA256(0x00 || leaf_bytes)
    inner hash = SHA256(0x01 || left || right)

The genesis checkpoint signs the empty tree (size 0, root = SHA256("")).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Iterable

from .errors import (
    TransparencyCheckpointExpired,
    TransparencyConflict,
    TransparencyFrozen,
    TransparencyNotFound,
    TransparencyProofInvalid,
)
from .receipts import dumps_canon, sha256_hex
from .util import utcnow

CHECKPOINT_VERSION = "tc1"

RELEASE_SEALED = "release_sealed"
RELEASE_VOIDED = "release_voided"
SHARE_ISSUED = "share_issued"
SHARE_REVOKED = "share_revoked"

LEAF_EVENTS = (RELEASE_SEALED, RELEASE_VOIDED, SHARE_ISSUED, SHARE_REVOKED)

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_HASH = hashlib.sha256(b"").hexdigest()


# --------------------------------------------------------------------------- #
# pure Merkle math (no I/O; shared by the gateway and the offline verifier)
# --------------------------------------------------------------------------- #

def leaf_hash_bytes(leaf_bytes: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + leaf_bytes).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def fold_level(level: list[bytes]) -> list[bytes]:
    out: list[bytes] = []
    for i in range(0, len(level) - 1, 2):
        out.append(node_hash(level[i], level[i + 1]))
    if len(level) % 2:
        out.append(level[-1])  # odd node is promoted unchanged
    return out


def merkle_root(leaf_hashes: Iterable[bytes]) -> bytes:
    level = list(leaf_hashes)
    if not level:
        return bytes.fromhex(EMPTY_HASH)
    while len(level) > 1:
        level = fold_level(level)
    return level[0]


def _highest_power_of_two(n: int) -> int:
    """Largest power of two strictly smaller than n (0 when n < 2)."""
    if n < 2:
        return 0
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _interval_hash(start: int, end: int, leaves: list[bytes],
                   cache: dict[tuple[int, int], bytes]) -> bytes:
    """Hash of the aligned perfect subtree covering [start, end)."""
    if (start, end) in cache:
        return cache[(start, end)]
    length = end - start
    if length == 1:
        return leaves[start]
    k = _highest_power_of_two(length)
    h = node_hash(_interval_hash(start, start + k, leaves, cache),
                  _interval_hash(start + k, end, leaves, cache))
    cache[(start, end)] = h
    return h


def aligned_partition(n: int, start: int = 0) -> list[tuple[int, int]]:
    """Canonical perfect-subtree decomposition of [start, n), ascending starts.

    Component widths strictly descend (a Merkle frontier).
    """
    out: list[tuple[int, int]] = []
    pos = start
    while pos < n:
        k = 1
        while pos % (k * 2) == 0 and pos + k * 2 <= n:
            k *= 2
        out.append((pos, pos + k))
        pos += k
    return out


def extension_intervals(old_size: int, new_size: int) -> list[tuple[int, int]]:
    """Aligned perfect subtrees covering [old_size, new_size).

    Deterministic from the two sizes alone, so an offline verifier derives the
    exact same expected intervals and a prover cannot drop or reorder a node.
    """
    return aligned_partition(new_size, old_size)


def inclusion_nodes(leaf_hashes: list[bytes], index: int) -> list[bytes]:
    """Bottom-up sibling hashes needed to fold one leaf to the tree root.

    At every level the verifier knows its own position and the level width, so
    sibling sides are re-derived; the proof only carries sibling hashes.
    """
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
    """Re-fold one leaf bottom-up, re-deriving each sibling side by position."""
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
        # a promoted odd node consumes no proof entry
        pos //= 2
        size = (size + 1) // 2
    return pi == len(proof_hashes) and h == root


def consistency_nodes(leaf_hashes: list[bytes], old_size: int,
                      new_size: int
                      ) -> tuple[list[tuple[int, int, bytes]],
                                 list[tuple[int, int, bytes]]]:
    """Tagged proof nodes for append-only consistency (old_size -> new_size).

    Returns ``(old_nodes, extension_nodes)`` where ``old_nodes`` are the hashes
    of the old tree's canonical frontier (partition D(old_size)) and
    ``extension_nodes`` are the aligned subtrees covering [old_size, new_size).
    A verifier folds the old frontier to the old root, then merges the
    extension subtrees (whose intervals it derives itself) to the new root --
    binding both signed checkpoints to one append history.
    """
    n, m = new_size, old_size
    if not (0 <= m <= n):
        raise ValueError("require 0 <= old_size <= new_size")
    if m == n or m == 0:
        return [], []
    cache: dict[tuple[int, int], bytes] = {}
    old = [(a, b, _interval_hash(a, b, leaf_hashes, cache))
           for a, b in aligned_partition(m)]
    ext = [(a, b, _interval_hash(a, b, leaf_hashes, cache))
           for a, b in extension_intervals(m, n)]
    return old, ext


def _fold_frontier(nodes: list[tuple[int, int, bytes]]) -> bytes:
    """Root of a canonical partition; widths strictly descend."""
    h = nodes[-1][2]
    for _, _, hh in reversed(nodes[:-1]):
        h = node_hash(hh, h)
    return h


def verify_consistency(old_root: bytes, new_root: bytes, old_size: int,
                       new_size: int,
                       old_nodes: list[tuple[int, int, bytes]],
                       extension_nodes: list[tuple[int, int, bytes]]) -> bool:
    """Verify an append-only consistency proof between two signed roots."""
    if old_size < 0 or old_size > new_size:
        return False
    if old_size == new_size:
        return old_root == new_root and not old_nodes and not extension_nodes
    if old_size == 0:
        return (old_root.hex() == EMPTY_HASH
                and not old_nodes and not extension_nodes)

    expect_old = aligned_partition(old_size)
    if [(a, b) for a, b, _ in old_nodes] != expect_old:
        return False
    expect_ext = extension_intervals(old_size, new_size)
    if [(a, b) for a, b, _ in extension_nodes] != expect_ext:
        return False
    if _fold_frontier(old_nodes) != old_root:
        return False

    # replay appending the extension subtrees onto the old frontier;
    # the resulting frontier must be exactly D(new_size) and fold to new_root
    # replay appending the extension subtrees (start, end, hash) onto the old
    # frontier, merging equal-width adjacent components and hashing them -- the
    # verifier derives every interior hash itself; resulting frontier must be
    # exactly D(new_size) and fold to the new root
    hmap = {(a, b): hh for a, b, hh in old_nodes + extension_nodes}
    stack: list[tuple[int, int, bytes]] = list(old_nodes)
    for a, b in expect_ext:
        end, width = b, b - a
        node = hmap[(a, b)]
        while stack and (stack[-1][1] - stack[-1][0]) == width \
                and stack[-1][1] == end - width:
            s0, _s1, left_hash = stack.pop()
            node = node_hash(left_hash, node)
            width *= 2
            end = s0 + width
        stack.append((end - width, end, node))
    if [(a, b) for a, b, _ in stack] != aligned_partition(new_size):
        return False
    return _fold_frontier(stack) == new_root


# --------------------------------------------------------------------------- #
# leaf envelopes
# --------------------------------------------------------------------------- #

def event_key(event_type: str, subject_id: str) -> str:
    return f"{event_type}:{subject_id}"


def build_leaf_envelope(event_type: str, subject_id: str, payload: dict,
                        *, created_at: str) -> dict:
    """Assemble the canonical, content-addressed leaf envelope.

    ``event_seq`` is absent from the envelope: leaf identity is independent of
    its eventual position (a leaf is the same leaf in the one and only log).
    """
    return {
        "leaf_version": "tl1",
        "event_type": event_type,
        "event_key": event_key(event_type, subject_id),
        "subject_id": subject_id,
        "created_at": created_at,
        "payload": payload,
    }


def envelope_leaf_hash(envelope: dict) -> str:
    return leaf_hash_bytes(dumps_canon(envelope).encode("utf-8")).hex()


# --------------------------------------------------------------------------- #
# mixin
# --------------------------------------------------------------------------- #

class TransparencyMixin:
    """Append-only transparency log; mixed into :class:`Gateway`."""

    # ------------------------------------------------------------------ #
    # bootstrap / freeze state
    # ------------------------------------------------------------------ #

    def tl_ensure_genesis_locked(self) -> None:
        if self.db.execute("SELECT 1 FROM tl_checkpoints WHERE tree_size=0").fetchone():
            return
        cp = self._tl_sign_checkpoint_locked(0, bytes.fromhex(EMPTY_HASH), None, None)
        self.db.execute(
            """INSERT OR IGNORE INTO tl_checkpoints
               (tree_size, root_hash, prev_size, prev_root_hash,
                checkpoint_json, created_at)
               VALUES (0, ?, NULL, NULL, ?, ?)""",
            (EMPTY_HASH, dumps_canon(cp), utcnow()))

    def _tl_freeze_row_locked(self) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM tl_freeze WHERE id=1").fetchone()

    def tl_state(self) -> dict:
        with self._lock:
            self.tl_ensure_genesis_locked()
            cp = self.db.execute(
                "SELECT * FROM tl_checkpoints ORDER BY tree_size DESC LIMIT 1").fetchone()
            pending = self.db.execute("SELECT COUNT(*) c FROM tl_outbox").fetchone()["c"]
            freeze = self._tl_freeze_row_locked()
            return {
                "tree_size": cp["tree_size"],
                "root_hash": cp["root_hash"],
                "frozen": freeze is not None,
                "freeze_reason": freeze["reason"] if freeze else None,
                "frozen_at": freeze["frozen_at"] if freeze else None,
                "frozen_by": freeze["frozen_by"] if freeze else None,
                "frozen_tree_size": freeze["tree_size"] if freeze else None,
                "pending_outbox": pending,
                "checkpoint": json.loads(cp["checkpoint_json"]),
            }

    def _tl_require_not_frozen_locked(self, action: str) -> None:
        freeze = self._tl_freeze_row_locked()
        if freeze is not None:
            raise TransparencyFrozen(
                f"transparency log is frozen ({freeze['reason']}); {action} rejected; "
                "the existing ledger is unchanged",
                tree_size=freeze["tree_size"], reason=freeze["reason"])

    # ------------------------------------------------------------------ #
    # outbox: written INSIDE the caller's business transaction
    # ------------------------------------------------------------------ #

    def _tl_enqueue_locked(self, event_type: str, subject_id: str,
                           payload: dict, *, created_at: str, actor: str
                           ) -> tuple[str, str, int | None]:
        """Insert one pending event into the outbox.

        Must be called with the gateway lock held and inside the same
        ``BEGIN IMMEDIATE`` transaction as the business change.  A replay of an
        already-incorporated event returns its original leaf index (the caller
        does not enqueue twice); a same-key/different-payload retry conflicts
        and the surrounding transaction rolls back.

        Returns ``(event_key, leaf_hash, existing_leaf_index | None)``.
        """
        key = event_key(event_type, subject_id)
        envelope = build_leaf_envelope(event_type, subject_id, payload,
                                       created_at=created_at)
        lh = envelope_leaf_hash(envelope)
        phash = sha256_hex(dumps_canon(payload))

        leaf = self.db.execute(
            "SELECT leaf_index, payload_hash FROM tl_leaves WHERE event_key=?",
            (key,)).fetchone()
        if leaf is not None:
            if leaf["payload_hash"] != phash:
                raise TransparencyConflict(
                    f"event_key {key} already logged as leaf {leaf['leaf_index']} "
                    "with a different payload")
            return key, lh, leaf["leaf_index"]

        pending = self.db.execute(
            "SELECT payload_hash FROM tl_outbox WHERE event_key=?", (key,)).fetchone()
        if pending is not None:
            if pending["payload_hash"] != phash:
                raise TransparencyConflict(
                    f"event_key {key} already pending with a different payload")
            return key, lh, None

        self.db.execute(
            """INSERT INTO tl_outbox
               (event_key, event_type, leaf_hash, payload_hash, envelope_json,
                subject_id, created_at, actor)
               VALUES (?,?,?,?,?,?,?,?)""",
            (key, event_type, lh, phash, dumps_canon(envelope),
             subject_id, created_at, actor))
        return key, lh, None

    def _tl_repair_tail_locked(self) -> None:
        """Rebuild checkpoints missing behind already-inserted leaf rows.

        A crash between the leaf INSERT and the checkpoint INSERT leaves a
        valid leaf whose tree tail was never signed.  Roots are a pure function
        of stored leaves, so the missing checkpoints reproduce deterministically
        and the interrupted process still converges on the single same history.
        Must run inside a write transaction.
        """
        last = self.db.execute(
            "SELECT * FROM tl_checkpoints ORDER BY tree_size DESC LIMIT 1").fetchone()
        n_leaves = self.db.execute(
            "SELECT COUNT(*) c FROM tl_leaves").fetchone()["c"]
        if last["tree_size"] == n_leaves:
            return
        leaves = self.db.execute(
            "SELECT * FROM tl_leaves ORDER BY leaf_index").fetchall()
        hashes = [bytes.fromhex(r["leaf_hash"]) for r in leaves]
        prev_size = last["tree_size"]
        prev_root = bytes.fromhex(last["root_hash"])
        for size in range(prev_size + 1, n_leaves + 1):
            root = merkle_root(hashes[:size])
            cp = self._tl_sign_checkpoint_locked(size, root, prev_size, prev_root)
            ts = leaves[size - 1]["incorporated_at"]
            self.db.execute(
                """INSERT OR IGNORE INTO tl_checkpoints
                   (tree_size, root_hash, prev_size, prev_root_hash,
                    checkpoint_json, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (size, root.hex(), prev_size, prev_root.hex(),
                 dumps_canon(cp), ts))
            prev_size, prev_root = size, root

    def _tl_incorporate_one_locked(self, row: sqlite3.Row) -> int:
        """Move exactly one outbox row into a leaf + signed checkpoint.

        Runs in its own transaction.  Leaf index, content address and the
        monotonic root chain are all derived inside it, so concurrent helpers
        (all serialised by the gateway lock) can never drop a leaf, reuse a
        sequence or move the root backwards.
        """
        envelope = json.loads(row["envelope_json"])
        lh = envelope_leaf_hash(envelope)
        if lh != row["leaf_hash"]:
            raise TransparencyProofInvalid("outbox leaf_hash does not reproduce")

        self.db.execute("BEGIN IMMEDIATE")
        committed = False
        try:
            # idempotent against a crash between leaf insert and checkpoint
            already = self.db.execute(
                "SELECT * FROM tl_leaves WHERE event_key=?",
                (row["event_key"],)).fetchone()
            if already is not None:
                # a crash may have inserted the leaf but not its checkpoint:
                # rebuild the missing tail deterministically from stored leaves
                self._tl_repair_tail_locked()
                self.db.execute("DELETE FROM tl_outbox WHERE seq=?", (row["seq"],))
                self.db.execute("COMMIT")
                return already["leaf_index"]

            last = self.db.execute(
                "SELECT * FROM tl_checkpoints ORDER BY tree_size DESC LIMIT 1").fetchone()
            index = last["tree_size"]
            n_leaves = self.db.execute(
                "SELECT COUNT(*) c FROM tl_leaves").fetchone()["c"]
            if n_leaves != index:
                # any surviving leaf beyond the latest checkpoint means a
                # crashed mid-drain; repair must have produced its checkpoint
                raise TransparencyProofInvalid(
                    "leaf/checkpoint desynchronisation: refusing to extend")
            prev_hashes = [r[0] for r in self.db.execute(
                "SELECT leaf_hash FROM tl_leaves ORDER BY leaf_index").fetchall()]
            prev_hashes.append(lh)
            root = merkle_root([bytes.fromhex(h) for h in prev_hashes])

            incorporated_at = utcnow()
            self.db.execute(
                """INSERT INTO tl_leaves
                   (leaf_index, event_key, event_type, leaf_hash, payload_hash,
                    envelope_json, outbox_seq, incorporated_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (index, row["event_key"], row["event_type"], lh, row["payload_hash"],
                 row["envelope_json"], row["seq"], incorporated_at))
            cp = self._tl_sign_checkpoint_locked(
                index + 1, root, last["tree_size"], bytes.fromhex(last["root_hash"]))
            self.db.execute(
                """INSERT INTO tl_checkpoints
                   (tree_size, root_hash, prev_size, prev_root_hash,
                    checkpoint_json, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (index + 1, root.hex(), last["tree_size"], last["root_hash"],
                 dumps_canon(cp), incorporated_at))
            self.db.execute("DELETE FROM tl_outbox WHERE seq=?", (row["seq"],))
            self.db.execute("COMMIT")
            committed = True
        except Exception:
            if not committed:
                self.db.execute("ROLLBACK")
            raise

        self._audit(actor=row["actor"], action="transparency",
                    outcome="tl_leaf_appended",
                    detail={"leaf_index": index, "event_type": row["event_type"],
                            "event_key": row["event_key"], "tree_size": index + 1,
                            "root_hash": root.hex()})
        return index

    def tl_drain_locked(self) -> list[int]:
        """Incorporate every pending outbox row, in fixed AUTOINCREMENT order.

        Called after each business commit (still under the gateway lock) and at
        startup.  Drain continues even when the log is frozen: rows that
        already committed with their business transaction must be incorporated
        so the local history stays complete; the freeze only blocks NEW
        issuances.
        """
        indices: list[int] = []
        while True:
            row = self.db.execute(
                "SELECT * FROM tl_outbox ORDER BY seq LIMIT 1").fetchone()
            if row is None:
                break
            indices.append(self._tl_incorporate_one_locked(row))
        return indices

    def _tl_anchor_for_event_locked(self, key: str) -> dict | None:
        """Inclusion anchor returned on the business response for *key*."""
        leaf = self.db.execute(
            "SELECT leaf_index FROM tl_leaves WHERE event_key=?", (key,)).fetchone()
        if leaf is None:
            return None
        return self.tl_inclusion(leaf["leaf_index"])

    @staticmethod
    def _tl_anchor_brief(proof: dict) -> dict:
        """Compact inclusion anchor embedded in seal/issue/revoke responses."""
        return {
            "event_key": proof["event_key"],
            "event_type": proof["event_type"],
            "leaf_index": proof["leaf_index"],
            "tree_size": proof["tree_size"],
            "root_hash": proof["root_hash"],
            "leaf_hash": proof["leaf_hash"],
            "inclusion_path": proof["inclusion_path"],
            "checkpoint": proof["checkpoint"],
        }

    # ------------------------------------------------------------------ #
    # signed checkpoints
    # ------------------------------------------------------------------ #

    def _tl_sign_checkpoint_locked(self, tree_size: int, root: bytes,
                                   prev_size: int | None,
                                   prev_root: bytes | None) -> dict:
        body = {
            "checkpoint_version": CHECKPOINT_VERSION,
            "tree_size": tree_size,
            "root_hash": root.hex(),
            "prev_size": prev_size,
            "prev_root_hash": prev_root.hex() if prev_root is not None else None,
            "issued_at": utcnow(),
        }
        body["sig"] = self._tl_hmac(body)
        return body

    def _tl_hmac(self, body: dict) -> str:
        import hmac as _hmac

        return _hmac.new(
            self.transparency_key,
            dumps_canon({k: v for k, v in body.items() if k != "sig"}).encode("utf-8"),
            hashlib.sha256).hexdigest()

    def _tl_checkpoint_row(self, tree_size: int) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM tl_checkpoints WHERE tree_size=?", (tree_size,)).fetchone()
        if row is None:
            raise TransparencyNotFound(f"no checkpoint at tree size {tree_size}")
        return row

    def tl_checkpoint(self, tree_size: int | str | None = None) -> dict:
        """Return one signed checkpoint (default: the latest).

        ``tree_size`` past the latest tree is 410 checkpoint_expired; a missing
        size is 404.
        """
        with self._lock:
            self.tl_ensure_genesis_locked()
            latest = self.db.execute(
                "SELECT tree_size FROM tl_checkpoints ORDER BY tree_size DESC LIMIT 1"
            ).fetchone()["tree_size"]
            if tree_size is None:
                size = latest
            else:
                size = int(tree_size)
                if size > latest:
                    raise TransparencyCheckpointExpired(
                        f"requested tree size {size} is ahead of the latest checkpoint "
                        f"{latest}")
            row = self._tl_checkpoint_row(size)
            return {
                "tree_size": row["tree_size"],
                "root_hash": row["root_hash"],
                "prev_size": row["prev_size"],
                "prev_root_hash": row["prev_root_hash"],
                "checkpoint": json.loads(row["checkpoint_json"]),
            }

    # ------------------------------------------------------------------ #
    # proofs
    # ------------------------------------------------------------------ #

    def _tl_leaf_rows(self) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM tl_leaves ORDER BY leaf_index").fetchall()

    def tl_inclusion(self, leaf_index: int, tree_size: int | None = None) -> dict:
        with self._lock:
            self.tl_ensure_genesis_locked()
            latest = self.db.execute(
                "SELECT tree_size FROM tl_checkpoints ORDER BY tree_size DESC LIMIT 1"
            ).fetchone()["tree_size"]
            if leaf_index < 0 or leaf_index >= latest:
                raise TransparencyNotFound(f"no leaf at index {leaf_index}")
            size = latest if tree_size is None else int(tree_size)
            if size > latest:
                raise TransparencyCheckpointExpired(
                    f"tree size {size} is ahead of the latest checkpoint {latest}")
            if size <= leaf_index:
                raise TransparencyNotFound(
                    f"leaf {leaf_index} does not exist at tree size {size}")
            leaves = self._tl_leaf_rows()
            hashes = [bytes.fromhex(r["leaf_hash"]) for r in leaves[:size]]
            proof = [h.hex() for h in inclusion_nodes(hashes, leaf_index)]
            cp_row = self._tl_checkpoint_row(size)
            leaf_row = leaves[leaf_index]
            return {
                "leaf_index": leaf_index,
                "tree_size": size,
                "root_hash": cp_row["root_hash"],
                "leaf_hash": leaf_row["leaf_hash"],
                "event_key": leaf_row["event_key"],
                "event_type": leaf_row["event_type"],
                "envelope": json.loads(leaf_row["envelope_json"]),
                "inclusion_path": proof,
                "checkpoint": json.loads(cp_row["checkpoint_json"]),
            }

    def tl_lookup_event(self, event_key: str, tree_size: int | None = None) -> dict:
        with self._lock:
            leaf = self.db.execute(
                "SELECT leaf_index FROM tl_leaves WHERE event_key=?",
                (event_key,)).fetchone()
            if leaf is None:
                raise TransparencyNotFound(f"event_key {event_key} not in the log")
            return self.tl_inclusion(leaf["leaf_index"], tree_size)

    def tl_consistency(self, old_size: int, new_size: int | None = None) -> dict:
        with self._lock:
            self.tl_ensure_genesis_locked()
            latest = self.db.execute(
                "SELECT tree_size FROM tl_checkpoints ORDER BY tree_size DESC LIMIT 1"
            ).fetchone()["tree_size"]
            m, n = int(old_size), latest if new_size is None else int(new_size)
            if m < 0 or n < 0 or m > n:
                raise TransparencyProofInvalid(
                    "require 0 <= old_size <= new_size")
            if n > latest:
                raise TransparencyCheckpointExpired(
                    f"tree size {n} is ahead of the latest checkpoint {latest}")
            self._tl_checkpoint_row(m)
            leaves = self._tl_leaf_rows()
            hashes = [bytes.fromhex(r["leaf_hash"]) for r in leaves[:n]]
            old_nodes, ext_nodes = consistency_nodes(hashes, m, n)
            old_path = [{"start": a, "end": b, "hash": h.hex()}
                        for a, b, h in old_nodes]
            extension_path = [{"start": a, "end": b, "hash": h.hex()}
                              for a, b, h in ext_nodes]
            old_row = self._tl_checkpoint_row(m)
            new_row = self._tl_checkpoint_row(n)
            return {
                "old_size": m,
                "new_size": n,
                "old_root_hash": old_row["root_hash"],
                "new_root_hash": new_row["root_hash"],
                "old_path": old_path,
                "extension_path": extension_path,
                "old_checkpoint": json.loads(old_row["checkpoint_json"]),
                "new_checkpoint": json.loads(new_row["checkpoint_json"]),
            }

    # ------------------------------------------------------------------ #
    # fork evidence
    # ------------------------------------------------------------------ #

    def tl_submit_fork(self, first: dict, second: dict, *,
                       actor: str = "auditor", reason: str = "") -> dict:
        """Freeze the log given two valid checkpoints: same size, different roots.

        Both documents must carry valid transparency HMAC signatures over their
        canonical bodies, identical non-trivial tree sizes and distinct roots.
        Anything else is rejected without touching the ledger.  A repeat
        submission while already frozen reports the existing freeze.
        """
        with self._lock:
            self.tl_ensure_genesis_locked()
            v1, err1 = self._tl_verify_checkpoint_doc(first)
            v2, err2 = self._tl_verify_checkpoint_doc(second)
            if err1 or err2:
                raise TransparencyProofInvalid(
                    "fork evidence requires two valid signed checkpoints: "
                    + "; ".join(x for x in (err1, err2) if x))
            if v1["tree_size"] != v2["tree_size"] or v1["tree_size"] <= 0:
                raise TransparencyProofInvalid(
                    "fork checkpoints must share one non-zero tree size")
            if v1["root_hash"] == v2["root_hash"]:
                raise TransparencyProofInvalid(
                    "checkpoints agree on the root; this is not a fork")

            existing = self._tl_freeze_row_locked()
            if existing is not None:
                return self._tl_freeze_response_locked(existing)

            latest = self.db.execute(
                "SELECT tree_size FROM tl_checkpoints ORDER BY tree_size DESC LIMIT 1"
            ).fetchone()["tree_size"]
            now = utcnow()
            evidence = dumps_canon({"first": v1, "second": v2, "reason": reason})
            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                self.db.execute(
                    """INSERT INTO tl_freeze
                       (id, reason, evidence_json, frozen_by, frozen_at, tree_size)
                       VALUES (1, 'fork_evidence', ?, ?, ?, ?)""",
                    (evidence, actor, now, latest))
                self.db.execute("COMMIT")
                committed = True
            except Exception:
                if not committed:
                    self.db.execute("ROLLBACK")
                raise
            self._audit(actor=actor, action="transparency",
                        outcome="tl_fork_frozen",
                        detail={"tree_size": latest,
                                "fork_size": v1["tree_size"],
                                "root_a": v1["root_hash"],
                                "root_b": v2["root_hash"], "reason": reason})
            return self._tl_freeze_response_locked(self._tl_freeze_row_locked())

    def _tl_verify_checkpoint_doc(self, doc: Any) -> tuple[dict | None, str | None]:
        if not isinstance(doc, dict):
            return None, "checkpoint must be an object"
        sig = doc.get("sig")
        if not isinstance(sig, str):
            return None, "checkpoint missing sig"
        expect = self._tl_hmac(doc)
        import hmac as _hmac

        if not _hmac.compare_digest(sig, expect):
            return None, "checkpoint signature invalid"
        if doc.get("checkpoint_version") != CHECKPOINT_VERSION:
            return None, "unsupported checkpoint version"
        size = doc.get("tree_size")
        root = doc.get("root_hash")
        if not isinstance(size, int) or size < 0 or not isinstance(root, str):
            return None, "malformed checkpoint"
        body = {k: v for k, v in doc.items()}
        return body, None

    def _tl_freeze_response_locked(self, row: sqlite3.Row) -> dict:
        return {
            "frozen": True,
            "reason": row["reason"],
            "frozen_by": row["frozen_by"],
            "frozen_at": row["frozen_at"],
            "tree_size": row["tree_size"],
            "evidence": json.loads(row["evidence_json"]) if row["evidence_json"] else None,
        }

    # ------------------------------------------------------------------ #
    # restart recovery
    # ------------------------------------------------------------------ #

    def recover_transparency_log(self, *, actor: str = "system") -> dict:
        """Drain the durable outbox after a restart and self-check the chain.

        Pending rows (their business transactions committed before the crash)
        are incorporated in fixed order -- the interrupted process finishes
        deterministically and no second history can appear.  A local root/chain
        inconsistency freezes the log with ``local_integrity_failure`` instead
        of appending over corruption.
        """
        with self._lock:
            self.tl_ensure_genesis_locked()
            # first converge any crash-split leaf/checkpoint tails; repair only
            # re-derives roots from stored leaves and never changes leaf content
            try:
                self.db.execute("BEGIN IMMEDIATE")
                self._tl_repair_tail_locked()
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            integrity = self.tl_verify_local_chain_locked()
            if not integrity["ok"]:
                if self._tl_freeze_row_locked() is None:
                    latest = self.db.execute(
                        "SELECT tree_size FROM tl_checkpoints "
                        "ORDER BY tree_size DESC LIMIT 1").fetchone()["tree_size"]
                    now = utcnow()
                    self.db.execute(
                        """INSERT OR IGNORE INTO tl_freeze
                           (id, reason, evidence_json, frozen_by, frozen_at, tree_size)
                           VALUES (1, 'local_integrity_failure', ?, ?, ?, ?)""",
                        (dumps_canon({"problems": integrity["problems"][:20]}),
                         actor, now, latest))
                    self._audit(actor=actor, action="transparency",
                                outcome="tl_integrity_freeze",
                                detail={"problems": integrity["problems"][:20]})
                return {"incorporated": [], "integrity": integrity}
            indices = self.tl_drain_locked()
            return {"incorporated": indices, "integrity": integrity}

    def tl_verify_local_chain_locked(self) -> dict:
        """Recompute every root from stored leaves and check the cp chain."""
        problems: list[str] = []
        leaves = self._tl_leaf_rows()
        hashes: list[bytes] = []
        expected_size = 0
        for r in leaves:
            if r["leaf_index"] != expected_size:
                problems.append(
                    f"leaf index gap/reorder at {r['leaf_index']} (expected {expected_size})")
            try:
                envelope = json.loads(r["envelope_json"])
                if envelope_leaf_hash(envelope) != r["leaf_hash"]:
                    problems.append(f"leaf {r['leaf_index']}: hash != envelope")
                if envelope["event_key"] != r["event_key"]:
                    problems.append(f"leaf {r['leaf_index']}: event_key mismatch")
            except Exception as exc:
                problems.append(f"leaf {r['leaf_index']}: unreadable envelope ({exc})")
            hashes.append(bytes.fromhex(r["leaf_hash"]))
            expected_size += 1

        cps = self.db.execute(
            "SELECT * FROM tl_checkpoints ORDER BY tree_size").fetchall()
        prev_size, prev_root = None, None
        for cp in cps:
            size = cp["tree_size"]
            want = merkle_root(hashes[:size]).hex()
            if cp["root_hash"] != want:
                problems.append(
                    f"checkpoint {size}: stored root {cp['root_hash'][:16]}… != "
                    f"recomputed {want[:16]}…")
            if size > 0:
                if cp["prev_size"] != prev_size or cp["prev_root_hash"] != prev_root:
                    problems.append(f"checkpoint {size}: prev chain broken")
            doc = json.loads(cp["checkpoint_json"])
            if self._tl_verify_checkpoint_doc(doc)[1]:
                problems.append(f"checkpoint {size}: signature invalid")
            prev_size, prev_root = size, cp["root_hash"]
        return {"ok": not problems, "problems": problems, "tree_size": len(leaves)}

    # ------------------------------------------------------------------ #
    # read APIs
    # ------------------------------------------------------------------ #

    def tl_list_leaves(self, *, event_type: str | None = None,
                       limit: int = 500) -> list[dict]:
        with self._lock:
            sql = ("SELECT leaf_index, event_key, event_type, leaf_hash, "
                   "incorporated_at FROM tl_leaves")
            params: list = []
            if event_type:
                sql += " WHERE event_type=?"
                params.append(event_type)
            sql += " ORDER BY leaf_index DESC LIMIT ?"
            params.append(min(int(limit), 10000))
            return [dict(r) for r in self.db.execute(sql, params).fetchall()]
