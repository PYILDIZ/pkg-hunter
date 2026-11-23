"""SQLite storage for scan results."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .analyzer import ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    name       TEXT NOT NULL,
    version    TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    score      REAL NOT NULL,
    result     TEXT NOT NULL,
    PRIMARY KEY (name, version)
);
CREATE INDEX IF NOT EXISTS idx_scans_score ON scans(score);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    def seen(self, name: str, version: str) -> bool:
        row = self.db.execute("SELECT 1 FROM scans WHERE name=? AND version=?",
                              (name.lower(), version)).fetchone()
        return row is not None

    def seen_keys(self) -> set[tuple[str, str]]:
        return set(self.db.execute("SELECT name, version FROM scans").fetchall())

    def save(self, r: ScanResult) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?)",
            (r.name.lower(), r.version or "", r.scanned_at, r.verdict, r.score, json.dumps(r.to_dict())),
        )
        self.db.commit()

    def results(self, min_score: float = 0) -> list[ScanResult]:
        rows = self.db.execute("SELECT result FROM scans WHERE score >= ? ORDER BY score DESC",
                               (min_score,)).fetchall()
        return [ScanResult.from_dict(json.loads(r[0])) for r in rows]

    def verdict_counts(self) -> dict[str, int]:
        return dict(self.db.execute("SELECT verdict, COUNT(*) FROM scans GROUP BY verdict").fetchall())
