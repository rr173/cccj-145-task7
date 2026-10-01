"""Test harness shared helpers: build a tiny dataset + gateway in tmp dirs."""

from __future__ import annotations

import csv
import json
import os
import tempfile

from dpgw.app import bootstrap, open_gateway
from dpgw.snapshot import build_snapshot

SPEC = {
    "name": "people",
    "version": "v1",
    "max_groups": 100,
    "columns": [
        {"name": "id", "dtype": "integer", "filterable": False},
        {"name": "city", "dtype": "text", "groupable": True,
         "domain": ["BJ", "SH", "SZ"]},
        {"name": "dept", "dtype": "text", "groupable": True,
         "domain": ["eng", "sales"]},
        {"name": "salary", "dtype": "integer", "filterable": True},
        {"name": "age", "dtype": "integer", "filterable": True},
        {"name": "active", "dtype": "boolean", "filterable": True},
    ],
    "bin_sets": [
        {"name": "sal_bands", "column": "salary",
         "edges": [None, 100, 200, None]},
    ],
}

ROWS = [
    (1, "BJ", "eng", 90, 28, True),
    (2, "BJ", "eng", 150, 41, True),
    (3, "BJ", "sales", 210, 35, False),
    (4, "SH", "eng", 80, 52, True),
    (5, "SH", "sales", 120, 29, True),
    (6, "SZ", "eng", 260, 44, False),
    (7, "SZ", "sales", 190, 31, True),
    (8, "BJ", "eng", 175, 38, True),
]


def write_dataset(dirpath: str, spec: dict | None = None, rows=None,
                  version_tag: str = "v1") -> tuple[str, dict]:
    spec = json.loads(json.dumps(spec or SPEC))
    spec["version"] = version_tag
    rows = ROWS if rows is None else rows
    spec_path = os.path.join(dirpath, "spec.json")
    csv_path = os.path.join(dirpath, "data.csv")
    out_dir = os.path.join(dirpath, "snap_" + version_tag)
    with open(spec_path, "w") as fh:
        json.dump(spec, fh)
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow([c["name"] for c in spec["columns"]])
        w.writerows(rows)
    manifest = build_snapshot(spec, csv_path, out_dir)
    return out_dir, manifest


class Harness:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.home = os.path.join(self.root, "home")
        self.bootstrap = bootstrap(self.home)
        self.admin_token = self.bootstrap["admin_token"]
        self.gw = open_gateway(self.home)
        self.teams = {}

    def publish(self, version_tag: str = "v1", rows=None, activate: bool = True):
        stage = os.path.join(self.root, "stage_" + version_tag)
        os.makedirs(stage, exist_ok=True)
        snap_dir, manifest = write_dataset(stage, version_tag=version_tag, rows=rows)
        info = self.gw.publish_snapshot(snap_dir, actor="test", activate=activate)
        return info, manifest, snap_dir

    def team(self, name: str) -> dict:
        if name not in self.teams:
            self.teams[name] = self.gw.create_team(name, actor="test")
        return self.teams[name]

    def grant(self, team_name: str, snapshot_id: str, epsilon: float, delta: float = 0.0):
        return self.gw.allocate_budget(
            self.team(team_name)["team_id"], snapshot_id, epsilon, delta, actor="test")

    def tid(self, name: str) -> str:
        return self.team(name)["team_id"]

    def token(self, name: str) -> str:
        return self.team(name)["token"]

    def close(self):
        self.gw.db.close()
        self.tmp.cleanup()
