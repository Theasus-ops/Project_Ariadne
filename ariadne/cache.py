"""Local SQLite cache of raw API responses.

Every stored record keeps the source URL, the fetch timestamp, and a SHA-256 of
the exact bytes returned. This gives two things at once:

  1. Speed - we never re-fetch the same data.
  2. Provenance - a court-defensible trail proving exactly what data any
     conclusion was based on, and that it was not altered after the fact.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Optional


class ProvenanceCache:
    def __init__(self, path: str | Path = "cache/ariadne_cache.sqlite") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS responses (
                key        TEXT PRIMARY KEY,
                url        TEXT NOT NULL,
                fetched_at REAL NOT NULL,
                sha256     TEXT NOT NULL,
                body       TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, key: str) -> Optional[object]:
        row = self._conn.execute(
            "SELECT body FROM responses WHERE key = ?", (key,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key: str, url: str, body: object) -> str:
        text = json.dumps(body, separators=(",", ":"), sort_keys=True)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        self._conn.execute(
            "INSERT OR REPLACE INTO responses (key, url, fetched_at, sha256, body) "
            "VALUES (?, ?, ?, ?, ?)",
            (key, url, time.time(), digest, text),
        )
        self._conn.commit()
        return digest

    def close(self) -> None:
        self._conn.close()
