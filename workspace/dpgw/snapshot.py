"""Immutable, content-addressed dataset snapshots.

A snapshot directory contains::

    manifest.json   -- schema, declared group domains / bin sets, hashes, ids
    data.sqlite     -- read-only table with the raw rows

Snapshots are *content addressed*: their id is a hash of schema + rows, so the
same published dataset always gets the same id on any machine, and an offline
verifier rebuilding or opening the snapshot can detect tampering.

The data steward builds snapshots with :func:`build_snapshot` (CLI:
``dpgw snapshot build``) from CSV, then registers the directory with the
gateway (``dpgw snapshot publish``).  The gateway never writes into a snapshot
directory and opens ``data.sqlite`` read-only.
"""

from __future__ import annotations

import csv
import json
import os
import shutil
import sqlite3
from typing import Any

from .errors import InvalidSnapshot
from .receipts import dumps_canon, sha256_hex

SNAPSHOT_FORMAT_VERSION = "s1"
MANIFEST_NAME = "manifest.json"
DATA_NAME = "data.sqlite"

_SQL_TYPES = {"integer": "INTEGER", "real": "REAL", "text": "TEXT", "boolean": "INTEGER"}


# --------------------------------------------------------------------------- #
# build
# --------------------------------------------------------------------------- #

def _coerce_cell(col: dict, raw: Any) -> Any:
    dtype = col["dtype"]
    if raw is None or raw == "":
        return None
    try:
        if dtype == "integer":
            if isinstance(raw, bool):
                raise ValueError
            return int(raw)
        if dtype == "real":
            f = float(raw)
            if f != f or f in (float("inf"), float("-inf")):
                raise ValueError("non-finite")
            return f
        if dtype == "text":
            return str(raw)
        s = str(raw).strip().lower()
        if s in ("true", "1", "t", "yes", "y"):
            return 1
        if s in ("false", "0", "f", "no", "n"):
            return 0
        raise ValueError("boolean must be true/false")
    except (TypeError, ValueError) as e:
        raise InvalidSnapshot(
            f"column {col['name']!r} ({dtype}) cannot parse value {raw!r}: {e}"
        )


def _validate_spec(spec: dict) -> dict:
    if not isinstance(spec, dict):
        raise InvalidSnapshot("snapshot spec must be an object")
    name = spec.get("name")
    version = spec.get("version")
    if not isinstance(name, str) or not name:
        raise InvalidSnapshot("spec.name required")
    if not isinstance(version, str) or not version:
        raise InvalidSnapshot("spec.version required")

    cols = spec.get("columns")
    if not isinstance(cols, list) or not cols:
        raise InvalidSnapshot("spec.columns must list at least one column")
    seen = set()
    norm_cols = []
    for c in cols:
        if not isinstance(c, dict) or not isinstance(c.get("name"), str):
            raise InvalidSnapshot("each column needs a name")
        cname = c["name"]
        if cname in seen:
            raise InvalidSnapshot(f"duplicate column {cname!r}")
        seen.add(cname)
        dtype = c.get("dtype", "text")
        if dtype not in _SQL_TYPES:
            raise InvalidSnapshot(f"column {cname!r} bad dtype {dtype!r}")
        nc = {
            "name": cname,
            "dtype": dtype,
            "filterable": bool(c.get("filterable", True)),
        }
        if c.get("groupable"):
            domain = c.get("domain")
            if not isinstance(domain, list) or not domain:
                raise InvalidSnapshot(f"groupable column {cname!r} needs a domain")
            if dtype == "integer":
                domain = [int(v) if not isinstance(v, bool) else v for v in domain]
            elif dtype == "real":
                domain = [float(v) for v in domain]
            elif dtype == "boolean":
                raise InvalidSnapshot("boolean columns cannot be groupable")
            nc["groupable"] = True
            nc["domain"] = domain
        norm_cols.append(nc)

    bin_sets = []
    for b in spec.get("bin_sets", []):
        if set(b) != {"name", "column", "edges"}:
            raise InvalidSnapshot("bin_set requires name, column, edges")
        col = next((c for c in norm_cols if c["name"] == b["column"]), None)
        if col is None or col["dtype"] not in ("integer", "real"):
            raise InvalidSnapshot(f"bin set {b['name']!r} needs a numeric column")
        edges = b["edges"]
        if not isinstance(edges, list) or len(edges) < 2:
            raise InvalidSnapshot(f"bin set {b['name']!r} needs >=2 edges")
        norm_edges = [None if e is None else float(e) for e in edges]
        for i, e in enumerate(norm_edges):
            if e is None and i not in (0, len(norm_edges) - 1):
                raise InvalidSnapshot("null edge only at either end")
        for a, z in zip(norm_edges, norm_edges[1:]):
            if a is not None and z is not None and not a < z:
                raise InvalidSnapshot(f"bin set {b['name']!r} edges must increase")
        bin_sets.append(
            {"name": b["name"], "column": b["column"], "edges": norm_edges}
        )

    names = [b["name"] for b in bin_sets]
    if len(set(names)) != len(names):
        raise InvalidSnapshot("duplicate bin set names")

    max_groups = int(spec.get("max_groups", 500))
    if max_groups < 1:
        raise InvalidSnapshot("max_groups must be positive")

    return {
        "name": name,
        "version": version,
        "table": "data",
        "columns": norm_cols,
        "bin_sets": bin_sets,
        "max_groups": max_groups,
    }


def build_snapshot(spec: dict, csv_path: str, out_dir: str) -> dict:
    """Build an immutable snapshot directory from a spec + CSV file.

    Returns the manifest.  Raises if ``out_dir`` already exists.
    """
    manifest = _validate_spec(spec)
    cols = manifest["columns"]
    colnames = [c["name"] for c in cols]

    rows: list[tuple] = []
    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None or set(reader.fieldnames) != set(colnames):
            raise InvalidSnapshot(
                f"CSV header {reader.fieldnames!r} does not match columns {colnames!r}"
            )
        for raw in reader:
            rows.append(tuple(_coerce_cell(c, raw[c["name"]]) for c in cols))

    # Two-level content identity:
    #   data_fingerprint -- hash of schema + exact rows (tamper detection, dedup)
    #   snapshot_id      -- hash of (name, version, data_fingerprint): the
    #                      publication identity, so a new steward *version* gets
    #                      its own budget/cache/noise namespace even when rows
    #                      happen to be identical to an older version.
    data_fingerprint = sha256_hex(
        SNAPSHOT_FORMAT_VERSION + ":" + dumps_canon(
            {"columns": cols, "bin_sets": manifest["bin_sets"], "rows": [list(r) for r in rows]}
        )
    )
    snapshot_id = sha256_hex(
        SNAPSHOT_FORMAT_VERSION + ":pub:" + dumps_canon(
            {"name": manifest["name"], "version": manifest["version"],
             "data_fingerprint": data_fingerprint}
        )
    )[:32]
    manifest["format_version"] = SNAPSHOT_FORMAT_VERSION
    manifest["snapshot_id"] = snapshot_id
    manifest["data_fingerprint"] = data_fingerprint
    manifest["row_count"] = len(rows)
    manifest["data_sha256"] = sha256_hex("rows:" + dumps_canon([list(r) for r in rows]))

    os.makedirs(out_dir)
    try:
        db_path = os.path.join(out_dir, DATA_NAME)
        conn = sqlite3.connect(db_path)
        try:
            ddl = ", ".join(
                f'"{c["name"]}" {_SQL_TYPES[c["dtype"]]}' for c in cols
            )
            conn.execute(f"CREATE TABLE {manifest['table']} ({ddl})")
            placeholders = ",".join("?" for _ in cols)
            qcols = ",".join(f'"{c}"' for c in colnames)
            conn.executemany(
                f"INSERT INTO {manifest['table']} ({qcols}) VALUES ({placeholders})",
                rows,
            )
            conn.commit()
        finally:
            conn.close()
        os.chmod(db_path, 0o444)

        with open(os.path.join(out_dir, MANIFEST_NAME), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
        os.chmod(os.path.join(out_dir, MANIFEST_NAME), 0o444)
    except BaseException:
        shutil.rmtree(out_dir, ignore_errors=True)
        raise
    return manifest


# --------------------------------------------------------------------------- #
# load / verify
# --------------------------------------------------------------------------- #

def snapshot_path(snap_root: str, snapshot_id: str) -> str:
    return os.path.join(snap_root, snapshot_id)


def manifest_path(snap_root: str, snapshot_id: str) -> str:
    return os.path.join(snapshot_path(snap_root, snapshot_id), MANIFEST_NAME)


def load_manifest_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    if manifest.get("format_version") != SNAPSHOT_FORMAT_VERSION:
        raise InvalidSnapshot("unsupported snapshot format version")
    if not manifest.get("snapshot_id"):
        raise InvalidSnapshot("manifest missing snapshot_id")
    return manifest


def load_manifest(snap_root: str, snapshot_id: str) -> dict:
    return load_manifest_file(manifest_path(snap_root, snapshot_id))


def open_data(snap_root: str, snapshot_id: str) -> sqlite3.Connection:
    """Open a snapshot data file strictly read-only."""
    path = os.path.join(snapshot_path(snap_root, snapshot_id), DATA_NAME)
    uri = "file:" + os.path.abspath(path) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.execute("PRAGMA query_only = ON")
    return conn


def verify_snapshot(snap_root: str, snapshot_id: str) -> dict:
    """Re-hash rows from the sqlite file and compare with manifest hashes."""
    return verify_snapshot_dir(snapshot_path(snap_root, snapshot_id))


def verify_snapshot_dir(path: str) -> dict:
    """Verify a snapshot directory (any location) against its manifest."""
    manifest = load_manifest_file(os.path.join(path, MANIFEST_NAME))
    uri = "file:" + os.path.abspath(os.path.join(path, DATA_NAME)) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.execute("PRAGMA query_only = ON")
    try:
        cols = [c["name"] for c in manifest["columns"]]
        qcols = ",".join(f'"{c}"' for c in cols)
        rows = [list(r) for r in conn.execute(
            f'SELECT {qcols} FROM {manifest["table"]}'
        )]
    finally:
        conn.close()
    data_hash = sha256_hex("rows:" + dumps_canon(rows))
    data_fingerprint = sha256_hex(
        SNAPSHOT_FORMAT_VERSION + ":" + dumps_canon(
            {"columns": manifest["columns"], "bin_sets": manifest["bin_sets"], "rows": rows}
        )
    )
    snapshot_id = sha256_hex(
        SNAPSHOT_FORMAT_VERSION + ":pub:" + dumps_canon(
            {"name": manifest["name"], "version": manifest["version"],
             "data_fingerprint": data_fingerprint}
        )
    )[:32]
    ok = (
        data_hash == manifest.get("data_sha256")
        and data_fingerprint == manifest.get("data_fingerprint")
        and snapshot_id == manifest.get("snapshot_id")
        and len(rows) == manifest.get("row_count")
    )
    return {"ok": ok, "rows": len(rows), "manifest": manifest,
            "recomputed_id": snapshot_id, "recomputed_fingerprint": data_fingerprint}
