"""Query normalisation.

An analyst submits a (possibly loosely phrased) query; this module validates
it and converts it into a *canonical query*.  The canonical JSON of that query
hashes to a stable ``query_hash``; identical requests from one team against
one snapshot always share the same hash, which is what makes idempotent
retry-without-recharge possible.

A coarser *family fingerprint* ignores the epsilon/delta allocation and
predicate literal values, so that a group of queries with the same shape (the
kind a combination attack reuses with different literals) can be frozen as a
single family.

Supported query types
---------------------
count(condition)
grouped_count(group_by=[columns], condition)  -- fixed domains from manifest
histogram(column, bin_edges, condition)        -- fixed binning from manifest

Allowed condition AST nodes
---------------------------
{"op":"and"|"or", "args":[...]}
{"op":"not", "arg": node}
{"op":"cmp", "column": str, "predicate": "="|"<>"|"<"|"<="|">"|">=", "value": typed}
{"op":"in", "column": str, "values": [typed, ...]}
{"op":"is_null", "column": str, "negated": bool}
"""

from __future__ import annotations

import copy
import math
from typing import Any

from .errors import InvalidQuery
from .receipts import dumps_canon, sha256_hex

# Bumped if the canonical format ever changes; it is embedded in query_hash so
# cached results never become ambiguous across format generations.
QUERY_FORMAT_VERSION = "q1"

PREDICATES = ("=", "<>", "<", "<=", ">", ">=")
DTYPES = ("integer", "real", "text", "boolean")
QTYPES = ("count", "grouped_count", "histogram")

# Hard safety limits regardless of manifest settings.
MAX_GROUP_COLS = 4
MAX_IN_VALUES = 1024
MAX_BIN_EDGES = 256
MAX_FILTER_DEPTH = 20
MAX_FILTER_NODES = 500


# --------------------------------------------------------------------------- #
# typed literal coercion
# --------------------------------------------------------------------------- #

def _coerce_value(column: dict, value: Any) -> Any:
    dtype = column["dtype"]
    cname = column["name"]
    if dtype == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise InvalidQuery(f"column {cname!r} expects integer literal")
        return value
    if dtype == "real":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise InvalidQuery(f"column {cname!r} expects numeric literal")
        f = float(value)
        if not math.isfinite(f):
            raise InvalidQuery(f"column {cname!r} literal must be finite")
        return f
    if dtype == "text":
        if not isinstance(value, str):
            raise InvalidQuery(f"column {cname!r} expects text literal")
        return value
    # boolean
    if not isinstance(value, bool):
        raise InvalidQuery(f"column {cname!r} expects boolean literal")
    return value


def _node_count(node: dict) -> int:
    op = node["op"]
    if op in ("and", "or"):
        return 1 + sum(_node_count(a) for a in node["args"])
    return 1


def _norm_filter(node: Any, columns: dict[str, dict], depth: int = 0) -> dict:
    if depth > MAX_FILTER_DEPTH:
        raise InvalidQuery("filter nested too deeply")
    if not isinstance(node, dict):
        raise InvalidQuery("filter node must be an object")
    op = node.get("op")

    if op in ("and", "or"):
        args = node.get("args")
        if not isinstance(args, list) or not args:
            raise InvalidQuery(f"{op} requires a non-empty args list")
        norms = [_norm_filter(a, columns, depth + 1) for a in args]
        if len(norms) == 1:
            # single-child conjunction collapses to its child, so equivalent
            # phrasings canonicalise identically
            return norms[0]
        # idempotent canonical ordering of associative sets
        norms.sort(key=lambda n: dumps_canon(n))
        out = {"op": op, "args": norms}
    elif op == "not":
        if set(node) != {"op", "arg"}:
            raise InvalidQuery("not node must contain only op and arg")
        out = {"op": "not", "arg": _norm_filter(node["arg"], columns, depth + 1)}
    elif op == "cmp":
        if set(node) != {"op", "column", "predicate", "value"}:
            raise InvalidQuery("cmp node must contain op, column, predicate, value")
        col = _lookup_col(node.get("column"), columns)
        pred = node.get("predicate")
        if pred not in PREDICATES:
            raise InvalidQuery(f"unsupported predicate {pred!r}")
        out = {
            "op": "cmp",
            "column": col["name"],
            "predicate": pred,
            "value": _coerce_value(col, node.get("value")),
        }
    elif op == "in":
        if set(node) != {"op", "column", "values"}:
            raise InvalidQuery("in node must contain op, column, values")
        col = _lookup_col(node.get("column"), columns)
        values = node.get("values")
        if not isinstance(values, list) or not values:
            raise InvalidQuery("in requires a non-empty list of values")
        if len(values) > MAX_IN_VALUES:
            raise InvalidQuery(f"in list exceeds {MAX_IN_VALUES} values")
        coerced = [_coerce_value(col, v) for v in values]
        # de-duplicate and sort deterministically; in-set membership is all that matters
        unique = sorted(set(coerced), key=lambda v: dumps_canon(v))
        out = {"op": "in", "column": col["name"], "values": unique}
    elif op == "is_null":
        if set(node) != {"op", "column", "negated"}:
            raise InvalidQuery("is_null node must contain op, column, negated")
        col = _lookup_col(node.get("column"), columns)
        if not isinstance(node.get("negated"), bool):
            raise InvalidQuery("is_null negated must be boolean")
        out = {"op": "is_null", "column": col["name"], "negated": node["negated"]}
    else:
        raise InvalidQuery(f"unknown filter op {op!r}")

    if _node_count(out) > MAX_FILTER_NODES:
        raise InvalidQuery(f"filter exceeds {MAX_FILTER_NODES} nodes")
    return out


def _lookup_col(name: Any, columns: dict[str, dict]) -> dict:
    if not isinstance(name, str) or name not in columns:
        raise InvalidQuery(f"unknown column {name!r}")
    col = columns[name]
    if not col.get("filterable", True):
        raise InvalidQuery(f"column {name!r} is not filterable")
    return col


def _norm_edges(edges: Any, column: dict) -> list:
    if not isinstance(edges, list) or len(edges) < 2:
        raise InvalidQuery("histogram bin_edges must be a list of at least 2 edges")
    if len(edges) > MAX_BIN_EDGES:
        raise InvalidQuery(f"histogram exceeds {MAX_BIN_EDGES} edges")
    out = []
    for i, e in enumerate(edges):
        if e is None:
            if i not in (0, len(edges) - 1):
                raise InvalidQuery("null edge only allowed at either end")
            out.append(None)
        else:
            if column["dtype"] not in ("integer", "real"):
                raise InvalidQuery("histogram column must be numeric")
            if isinstance(e, bool) or not isinstance(e, (int, float)):
                raise InvalidQuery("bin edges must be numbers or null ends")
            fe = float(e)
            if not math.isfinite(fe):
                raise InvalidQuery("bin edges must be finite")
            out.append(fe)
    for a, b in zip(out, out[1:]):
        if a is not None and b is not None and not a < b:
            raise InvalidQuery("bin edges must be strictly increasing")
    return out


def _check_privacy(q: dict) -> tuple[float, float]:
    eps = q.get("epsilon")
    if isinstance(eps, bool) or not isinstance(eps, (int, float)):
        raise InvalidQuery("epsilon must be a positive number")
    eps = float(eps)
    if not (eps > 0) or not math.isfinite(eps):
        raise InvalidQuery("epsilon must be positive and finite")
    delta = q.get("delta", 0.0)
    if isinstance(delta, bool) or not isinstance(delta, (int, float)):
        raise InvalidQuery("delta must be a number in [0, 1)")
    delta = float(delta)
    if not (0.0 <= delta < 1.0) or not math.isfinite(delta):
        raise InvalidQuery("delta must satisfy 0 <= delta < 1")
    return eps, delta


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #

def normalize_query(query: Any, manifest: dict) -> dict:
    """Validate an analyst query against a snapshot manifest; return canonical form."""
    if not isinstance(query, dict):
        raise InvalidQuery("query must be an object")

    # ``v`` is our own canonical-format marker; accept it only if it matches.
    if "v" in query and query["v"] != QUERY_FORMAT_VERSION:
        raise InvalidQuery(f"unsupported query format version {query['v']!r}")
    allowed_base = {"type", "table", "filter", "epsilon", "delta", "v"}

    qtype = query.get("type")
    if qtype not in QTYPES:
        raise InvalidQuery(f"type must be one of {QTYPES}")

    table = query.get("table", "data")
    if table != manifest["table"]:
        raise InvalidQuery(f"unknown table {table!r}")

    columns: dict[str, dict] = {c["name"]: c for c in manifest["columns"]}

    eps, delta = _check_privacy(query)

    filt = query.get("filter")
    norm_filter = None if filt is None else _norm_filter(filt, columns)

    canonical: dict = {
        "v": QUERY_FORMAT_VERSION,
        "type": qtype,
        "table": table,
        "filter": norm_filter,
        "epsilon": eps,
        "delta": delta,
    }

    if qtype == "count":
        if set(query) - allowed_base:
            raise InvalidQuery("unexpected fields for count query")

    elif qtype == "grouped_count":
        gb = query.get("group_by")
        if not isinstance(gb, list) or not gb or len(gb) > MAX_GROUP_COLS:
            raise InvalidQuery(f"group_by must be a list of 1..{MAX_GROUP_COLS} columns")
        resolved = []
        for name in gb:
            if not isinstance(name, str) or name not in columns:
                raise InvalidQuery(f"unknown group column {name!r}")
            col = columns[name]
            if not col.get("groupable"):
                raise InvalidQuery(f"column {name!r} is not groupable")
            if not isinstance(col.get("domain"), list) or not col["domain"]:
                raise InvalidQuery(f"groupable column {name!r} has no declared domain")
            resolved.append(name)
        if len(set(resolved)) != len(resolved):
            raise InvalidQuery("duplicate group_by columns")
        canonical["group_by"] = resolved
        if set(query) - allowed_base - {"group_by"}:
            raise InvalidQuery("unexpected fields for grouped_count query")

    else:  # histogram
        colname = query.get("column")
        if not isinstance(colname, str) or colname not in columns:
            raise InvalidQuery(f"unknown histogram column {colname!r}")
        col = columns[colname]
        declared = manifest.get("bin_sets", [])
        allowed = None
        raw_edges = query.get("bin_edges")
        if raw_edges is None:
            # manifest may declare exactly one bin set for this column
            for b in declared:
                if b["column"] == colname:
                    if allowed is not None:
                        raise InvalidQuery(
                            f"column {colname!r} has multiple bin sets; bin_edges required"
                        )
                    allowed = b
            if allowed is None:
                raise InvalidQuery(f"no bin set declared for column {colname!r}")
            bin_name = allowed["name"]
            edges = _norm_edges(allowed["edges"], col)
        else:
            edges = _norm_edges(raw_edges, col)
            match = None
            for b in declared:
                if b["column"] == colname and _norm_edges(b["edges"], col) == edges:
                    match = b
                    break
            if match is None:
                raise InvalidQuery(
                    f"bin_edges not in declared bin sets for column {colname!r}"
                )
            bin_name = match["name"]
        canonical["column"] = colname
        canonical["bin_set"] = bin_name
        canonical["bin_edges"] = edges
        if set(query) - allowed_base - {"column", "bin_edges", "bin_set"}:
            raise InvalidQuery("unexpected fields for histogram query")

    return canonical


def query_hash(canonical: dict) -> str:
    """Stable identity of a canonical query (format-version prefixed)."""
    return sha256_hex(QUERY_FORMAT_VERSION + ":" + dumps_canon(canonical))


def _family_skeleton(canonical: dict, mask_literals: bool = True) -> dict:
    """Shape-only view: allocations and (optionally) filter literals removed.

    Two queries belong to the same family when they ask the same kind of
    statistic over the same table/columns/bin-set with the same filter shape.
    Privacy allocations are never part of the family (a retry with a bigger
    epsilon is the same attack pattern).
    """
    skel: dict = {"v": QUERY_FORMAT_VERSION, "type": canonical["type"], "table": canonical["table"]}

    if canonical["type"] == "grouped_count":
        skel["group_by"] = list(canonical["group_by"])
    elif canonical["type"] == "histogram":
        skel["column"] = canonical["column"]
        skel["bin_set"] = canonical["bin_set"]

    filt = canonical.get("filter")

    def mask(node):
        node = copy.deepcopy(node)
        op = node["op"]
        if op in ("and", "or"):
            node["args"] = [mask(a) for a in node["args"]]
        elif op == "not":
            node["arg"] = mask(node["arg"])
        elif op == "cmp":
            if mask_literals:
                node.pop("value")
        elif op == "in":
            if mask_literals:
                node.pop("values")
        return node

    skel["filter"] = None if filt is None else mask(filt)
    return skel


def family_fingerprint(canonical: dict, *, mask_literals: bool = True) -> str:
    """Stable id of a query family (128-bit hex truncation)."""
    skel = _family_skeleton(canonical, mask_literals=mask_literals)
    flag = "L" if mask_literals else "E"
    return sha256_hex(flag + ":" + dumps_canon(skel))[:32]


# --------------------------------------------------------------------------- #
# canonical filter -> SQL (used by gateway and by the offline verifier)
# --------------------------------------------------------------------------- #

def filter_sql(node: dict | None) -> tuple[str, list]:
    """Translate a canonical filter to parameterised SQL WHERE clause."""
    if node is None:
        return "", []
    op = node["op"]
    if op == "and" or op == "or":
        parts, params = [], []
        for a in node["args"]:
            sql, p = filter_sql(a)
            parts.append("(" + sql + ")")
            params.extend(p)
        return (" " + op.upper() + " ").join(parts), params
    if op == "not":
        sql, p = filter_sql(node["arg"])
        return "NOT (" + sql + ")", p
    col = '"' + node["column"].replace('"', '""') + '"'
    if op == "is_null":
        return col + (" IS NOT NULL" if node["negated"] else " IS NULL"), []
    if op == "in":
        placeholders = ",".join("?" for _ in node["values"])
        return col + " IN (" + placeholders + ")", list(node["values"])
    return f"{col} {node['predicate']} ?", [node["value"]]
