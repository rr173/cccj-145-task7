"""True-value aggregation engine, shared by gateway and offline verifier.

The gateway never stores raw counts.  Both the live path and the offline
verifier call :func:`aggregate` against the immutable snapshot file, then the
caller adds calibrated noise from :mod:`dpgw.privacy`.  Keeping the engine in
one place means an auditor recomputes exactly what the service computed.

Coordinate conventions (these strings are the noise-seed labels, so they are
part of the specification and must not change):

* count             -> ["scalar"]
* grouped_count     -> canonical JSON of the domain tuple per group, then
                       "__other__" for rows whose tuple is outside the fixed
                       declared domain (including NULLs)
* histogram         -> "[a,b)" / "(-inf,b)" / "[a,+inf)" per bin, then
                       "__null__" for rows with NULL value
"""

from __future__ import annotations

import itertools
import sqlite3

from .canonical import filter_sql
from .errors import InvalidQuery
from .privacy import round6
from .receipts import dumps_canon

OTHER_LABEL = "__other__"
NULL_LABEL = "__null__"


def _where(canonical: dict) -> tuple[str, list]:
    sql, params = filter_sql(canonical.get("filter"))
    return (" WHERE " + sql) if sql else "", params


def _count(conn: sqlite3.Connection, canonical: dict, extra_sql: str = "", extra_params: list | None = None) -> int:
    where, params = _where(canonical)
    sql = f'SELECT COUNT(*) FROM "{canonical["table"]}"{where}'
    if extra_sql:
        sql += (" AND " if where else " WHERE ") + extra_sql
    cur = conn.execute(sql, params + (extra_params or []))
    return int(cur.fetchone()[0])


def _group_label(combo: tuple) -> str:
    return dumps_canon(list(combo))


def _bin_label(lo, hi) -> str:
    def fmt(x):
        return dumps_canon(x)

    if lo is None:
        return f"(-inf,{fmt(hi)})"
    if hi is None:
        return f"[{fmt(lo)},+inf)"
    return f"[{fmt(lo)},{fmt(hi)})"


def aggregate(canonical: dict, manifest: dict, conn: sqlite3.Connection) -> dict:
    """Return coordinates, dimension and true counts for a canonical query."""
    qtype = canonical["type"]
    table = canonical["table"]

    if qtype == "count":
        return {"coords": ["scalar"], "dimension": 1, "true": [_count(conn, canonical)]}

    if qtype == "grouped_count":
        columns = {c["name"]: c for c in manifest["columns"]}
        gb = canonical["group_by"]
        domains = [columns[name]["domain"] for name in gb]
        dimension = 1
        for d in domains:
            dimension *= len(d)
        dimension += 1  # overflow category
        max_groups = manifest.get("max_groups", 500)
        if dimension > max_groups:
            raise InvalidQuery(
                f"group domain size {dimension} exceeds snapshot max_groups {max_groups}"
            )

        where, params = _where(canonical)
        qcols = ",".join(f'"{n}"' for n in gb)
        sql = f'SELECT {qcols}, COUNT(*) FROM "{table}"{where} GROUP BY {qcols}'
        observed: dict[tuple, int] = {}
        for row in conn.execute(sql, params):
            observed[tuple(row[:-1])] = int(row[-1])

        coords, true = [], []
        matched = 0
        for combo in itertools.product(*domains):
            coords.append(_group_label(combo))
            n = observed.get(combo, 0)
            true.append(n)
            matched += n
        total = _count(conn, canonical)
        coords.append(OTHER_LABEL)
        true.append(total - matched)
        return {"coords": coords, "dimension": dimension, "true": true}

    # histogram ----------------------------------------------------------------
    edges = canonical["bin_edges"]
    col = '"' + canonical["column"].replace('"', '""') + '"'
    coords, true = [], []
    for lo, hi in zip(edges, edges[1:]):
        coords.append(_bin_label(lo, hi))
        if lo is None:
            cond = f"{col} < ?"
            vals = [hi]
        elif hi is None:
            cond = f"{col} >= ?"
            vals = [lo]
        else:
            cond = f"{col} >= ? AND {col} < ?"
            vals = [lo, hi]
        true.append(_count(conn, canonical, cond, vals))
    coords.append(NULL_LABEL)
    true.append(_count(conn, canonical, f"{col} IS NULL"))
    return {"coords": coords, "dimension": len(coords), "true": true}


def apply_noise(true: list[int], noise: list[float]) -> list[float]:
    return [round6(t + n) for t, n in zip(true, noise)]
