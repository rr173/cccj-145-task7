"""Small shared primitives used by both the single-query gateway and the
multi-statement job machinery -- kept in a leaf module so importing either
``dpgw.gateway`` or ``dpgw.jobs`` first cannot create an import cycle.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

EPS_TOLERANCE = 1e-9


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def new_id(prefix: str) -> str:
    return prefix + "_" + secrets.token_hex(10)
