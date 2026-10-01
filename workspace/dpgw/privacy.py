"""Sensitivity, mechanism calibration and stable noise generation.

Sensitivity model
-----------------
All queries are counts over a single table.  Adding or removing one row of a
neighbouring database can change any count vector by at most 1 in L1:

* count               -> scalar count, L1 = L2 = 1
* grouped_count       -> fixed domain, so all categories incl. overflow total
                         the global count; L1 = 1, L2 = 1
* histogram           -- one row falls in exactly one bin, including NULL
                         rows in an explicit ``__null__`` bin; L1 = 1, L2 = 1

Mechanisms
----------
* delta == 0  -> Laplace(b = sensitivity/epsilon)            (pure epsilon DP)
* delta  > 0  -> Gaussian(sigma = sqrt(2 ln(1.25/delta)) * sensitivity / epsilon)
                 (Gaussian mechanism, (epsilon, delta)-DP)

Determinism
-----------
Noise must be reproducible offline from (master_seed, team, snapshot,
canonical query) without trusting the gateway result cache.  We therefore
ship a small MT19937 implementation instead of relying on CPython's random
module, so the draw sequence is pinned by specification, not interpreter
behaviour.  Every output coordinate gets its own coordinate seed derived via
HMAC-SHA256 domain separation.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from typing import Sequence

# --------------------------------------------------------------------------- #
# deterministic MT19937 (32-bit), independent of CPython's random internals
# --------------------------------------------------------------------------- #

_N = 624
_M = 397
_A = 0x9908B0DF
_UPPER = 0x80000000
_LOWER = 0x7FFFFFFF


class MT19937:
    def __init__(self, seed: int):
        self.mt = [0] * _N
        self.index = _N
        self.mt[0] = seed & 0xFFFFFFFF
        for i in range(1, _N):
            prev = self.mt[i - 1]
            self.mt[i] = (
                1812433253 * (prev ^ (prev >> 30)) + i
            ) & 0xFFFFFFFF

    def _generate(self):
        for i in range(_N):
            y = (self.mt[i] & _UPPER) | (self.mt[(i + 1) % _N] & _LOWER)
            self.mt[i] = self.mt[(i + _M) % _N] ^ (y >> 1)
            if y & 1:
                self.mt[i] ^= _A
        self.index = 0

    def randuint32(self) -> int:
        if self.index >= _N:
            self._generate()
        y = self.mt[self.index]
        self.index += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & 0xFFFFFFFF

    def uniform01(self) -> float:
        """Uniform double in (0, 1); endpoints rejected so logs are defined."""
        while True:
            u = ((self.randuint32() >> 5) * 67108864.0 + (self.randuint32() >> 6))
            u /= 9007199254740992.0  # 2^53
            if 0.0 < u < 1.0:
                return u

    def laplace(self, scale: float) -> float:
        u = self.uniform01() - 0.5  # (-0.5, 0.5)
        return -scale * math.copysign(math.log1p(-2.0 * abs(u)), u)

    def gaussian(self, sigma: float) -> float:
        """Standard normal via Box-Muller; deterministic single draw pair."""
        u1 = self.uniform01()
        u2 = self.uniform01()
        r = math.sqrt(-2.0 * math.log(u1))
        return sigma * r * math.cos(2.0 * math.pi * u2)


# --------------------------------------------------------------------------- #
# seed derivation
# --------------------------------------------------------------------------- #

def result_seed(master_seed: bytes, team_id: str, snapshot_id: str, query_hash_hex: str) -> bytes:
    """HMAC-derived per-(team, snapshot, canonical-query) seed material."""
    msg = team_id.encode() + b"\x00" + snapshot_id.encode() + b"\x00" + query_hash_hex.encode()
    return hmac.new(master_seed, msg, hashlib.sha256).digest()


def coord_seed(result_seed_bytes: bytes, coord: str) -> int:
    """Coordinate-specific 32-bit seed ("scalar" for 1-D results)."""
    d = hmac.new(result_seed_bytes, coord.encode("utf-8"), hashlib.sha256).digest()
    return int.from_bytes(d[:4], "big")


# --------------------------------------------------------------------------- #
# sensitivity + calibration
# --------------------------------------------------------------------------- #

def sensitivity_l1(canonical: dict, dimension: int) -> float:
    """L1 sensitivity of a count vector; always 1 for our fixed-domain counts."""
    if dimension < 1:
        raise ValueError("dimension must be >= 1")
    return 1.0


def mechanism_params(canonical: dict, dimension: int) -> dict:
    eps = canonical["epsilon"]
    delta = canonical["delta"]
    s1 = sensitivity_l1(canonical, dimension)
    if delta == 0.0:
        return {
            "mechanism": "laplace",
            "sensitivity_l1": s1,
            "sensitivity_l2": s1,
            "scale": s1 / eps,
            "epsilon": eps,
            "delta": 0.0,
            "dimension": dimension,
        }
    sigma = math.sqrt(2.0 * math.log(1.25 / delta)) * s1 / eps
    return {
        "mechanism": "gaussian",
        "sensitivity_l1": s1,
        "sensitivity_l2": s1,
        "scale": sigma,
        "epsilon": eps,
        "delta": delta,
        "dimension": dimension,
    }


def expected_cost(canonical: dict, dimension: int) -> dict:
    """Privacy loss the gateway will charge for one execution.

    Basic (parallel-independent here, sequential in the ledger) composition:
    epsilon and delta add linearly.  Conservative and easy to audit offline.
    """
    p = mechanism_params(canonical, dimension)
    return {"epsilon": p["epsilon"], "delta": p["delta"], "params": p}


def round6(x: float) -> float:
    """Half-to-even rounding to 6 decimals; deterministic canonical rounding."""
    # repr + decimal-style round: Python round is banker's and float-stable
    # enough given the fixed, seeded draws.
    return round(x, 6)


def noisy_vector(
    master_seed: bytes,
    team_id: str,
    snapshot_id: str,
    query_hash_hex: str,
    coords: Sequence[str],
    params: dict,
) -> list[float]:
    """Add calibrated deterministic noise to each coordinate label.

    ``coords`` order defines the vector order; each label seeds its own RNG.
    """
    seed = result_seed(master_seed, team_id, snapshot_id, query_hash_hex)
    out = []
    for label in coords:
        rng = MT19937(coord_seed(seed, str(label)))
        if params["mechanism"] == "laplace":
            out.append(round6(rng.laplace(params["scale"])))
        else:
            out.append(round6(rng.gaussian(params["scale"])))
    return out
