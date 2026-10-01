"""Query canonicalisation, family fingerprints and sensitivity model."""

import unittest

from dpgw.canonical import (
    family_fingerprint,
    filter_sql,
    normalize_query,
    query_hash,
)
from dpgw.privacy import (
    MT19937,
    expected_cost,
    mechanism_params,
    noisy_vector,
    result_seed,
)

MANIFEST = {
    "table": "data",
    "columns": [
        {"name": "city", "dtype": "text", "filterable": True, "groupable": True,
         "domain": ["BJ", "SH"]},
        {"name": "age", "dtype": "integer", "filterable": True},
        {"name": "active", "dtype": "boolean", "filterable": True},
    ],
    "bin_sets": [],
}


class TestNormalize(unittest.TestCase):
    def test_and_ordering_does_not_matter(self):
        q1 = {"type": "count", "epsilon": 0.5,
              "filter": {"op": "and", "args": [
                  {"op": "cmp", "column": "city", "predicate": "=", "value": "BJ"},
                  {"op": "cmp", "column": "age", "predicate": ">=", "value": 30}]}}
        q2 = {"type": "count", "epsilon": 0.5,
              "filter": {"op": "and", "args": [
                  {"op": "cmp", "column": "age", "predicate": ">=", "value": 30},
                  {"op": "cmp", "column": "city", "predicate": "=", "value": "BJ"}]}}
        self.assertEqual(normalize_query(q1, MANIFEST), normalize_query(q2, MANIFEST))
        self.assertEqual(query_hash(normalize_query(q1, MANIFEST)),
                         query_hash(normalize_query(q2, MANIFEST)))

    def test_in_dedup_sort(self):
        q = {"type": "count", "epsilon": 1,
             "filter": {"op": "in", "column": "city", "values": ["SH", "BJ", "BJ"]}}
        c = normalize_query(q, MANIFEST)
        self.assertEqual(c["filter"]["values"], ["BJ", "SH"])

    def test_epsilon_changes_hash_but_not_family(self):
        base = {"type": "count", "epsilon": 0.5,
                "filter": {"op": "cmp", "column": "city", "predicate": "=", "value": "BJ"}}
        bigger = dict(base, epsilon=2.0)
        c1, c2 = normalize_query(base, MANIFEST), normalize_query(bigger, MANIFEST)
        self.assertNotEqual(query_hash(c1), query_hash(c2))
        self.assertEqual(family_fingerprint(c1), family_fingerprint(c2))

    def test_family_masks_filter_literals(self):
        def q(v):
            return normalize_query(
                {"type": "count", "epsilon": 0.5,
                 "filter": {"op": "cmp", "column": "age", "predicate": ">", "value": v}},
                MANIFEST)
        q1, q2 = q(30), q(40)
        self.assertEqual(family_fingerprint(q1), family_fingerprint(q2))
        self.assertNotEqual(family_fingerprint(q1, mask_literals=False),
                            family_fingerprint(q2, mask_literals=False))

    def test_grouped_requires_domain(self):
        with self.assertRaises(Exception):
            normalize_query({"type": "grouped_count", "epsilon": 1, "group_by": ["age"]},
                            MANIFEST)

    def test_grouped_ok(self):
        c = normalize_query({"type": "grouped_count", "epsilon": 1,
                             "group_by": ["city"]}, MANIFEST)
        self.assertEqual(c["group_by"], ["city"])

    def test_bad_types(self):
        for bad in (
            {"type": "count", "epsilon": 0},
            {"type": "count", "epsilon": -1},
            {"type": "count", "epsilon": 0.5, "delta": 1},
            {"type": "nope", "epsilon": 1},
            {"type": "count", "epsilon": 1,
             "filter": {"op": "cmp", "column": "city", "predicate": "~", "value": "x"}},
            {"type": "count", "epsilon": 1,
             "filter": {"op": "cmp", "column": "age", "predicate": "=", "value": "old"}},
            {"type": "count", "epsilon": 1,
             "filter": {"op": "cmp", "column": "ghost", "predicate": "=", "value": 1}},
        ):
            with self.assertRaises(Exception, msg=bad):
                normalize_query(bad, MANIFEST)

    def test_unfilterable_column_rejected(self):
        manifest = {"table": "data", "columns": [
            {"name": "id", "dtype": "integer", "filterable": False}], "bin_sets": []}
        with self.assertRaises(Exception):
            normalize_query({"type": "count", "epsilon": 1,
                             "filter": {"op": "cmp", "column": "id",
                                        "predicate": "=", "value": 1}}, manifest)

    def test_filter_sql(self):
        q = normalize_query(
            {"type": "count", "epsilon": 1, "filter": {"op": "is_null",
                                                        "column": "age",
                                                        "negated": False}},
            MANIFEST)
        sql, params = filter_sql(q["filter"])
        self.assertEqual(sql, '"age" IS NULL')
        self.assertEqual(params, [])


class TestMechanism(unittest.TestCase):
    def test_laplace_scale_and_cost(self):
        c = normalize_query({"type": "count", "epsilon": 0.5}, MANIFEST)
        p = mechanism_params(c, 1)
        self.assertEqual(p["mechanism"], "laplace")
        self.assertEqual(p["scale"], 2.0)
        self.assertEqual(expected_cost(c, 1)["epsilon"], 0.5)

    def test_gaussian(self):
        c = normalize_query({"type": "count", "epsilon": 1.0, "delta": 1e-5}, MANIFEST)
        p = mechanism_params(c, 1)
        self.assertEqual(p["mechanism"], "gaussian")
        self.assertGreater(p["scale"], 0)

    def test_deterministic_noise_vector(self):
        seed = b"\x11" * 32
        params = {"mechanism": "laplace", "scale": 1.0}
        a = noisy_vector(seed, "team_a", "snap1", "h" * 8, ["scalar"], params)
        b = noisy_vector(seed, "team_a", "snap1", "h" * 8, ["scalar"], params)
        self.assertEqual(a, b)
        # different team => different noise
        c = noisy_vector(seed, "team_b", "snap1", "h" * 8, ["scalar"], params)
        self.assertNotEqual(a, c)
        # different snapshot => different noise (old cache can't be replayed)
        d = noisy_vector(seed, "team_a", "snap2", "h" * 8, ["scalar"], params)
        self.assertNotEqual(a, d)

    def test_mt19937_known_vector(self):
        # pin the RNG: first uint32 of MT19937 seeded with 5489 is a known constant
        rng = MT19937(5489)
        self.assertEqual(rng.randuint32(), 3499211612)


if __name__ == "__main__":
    unittest.main()
