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
import threading
import time
from pathlib import Path
from typing import Optional


class ProvenanceCache:
    def __init__(self, path: str | Path = "cache/ariadne_cache.sqlite") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
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
        # Keys touched (read or written) since the last mark — the basis for a
        # per-investigation chain of custody. See ariadne.evidence.
        self._accessed: set[str] = set()
        # The connection is shared across the tracer's worker threads; serialise.
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[object]:
        with self._lock:
            row = self._conn.execute(
                "SELECT body FROM responses WHERE key = ?", (key,)
            ).fetchone()
            if row:
                self._accessed.add(key)
        return json.loads(row[0]) if row else None

    def put(self, key: str, url: str, body: object) -> str:
        text = json.dumps(body, separators=(",", ":"), sort_keys=True)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO responses (key, url, fetched_at, sha256, body) "
                "VALUES (?, ?, ?, ?, ?)",
                (key, url, time.time(), digest, text),
            )
            self._conn.commit()
            self._accessed.add(key)
        return digest

    def mark(self) -> None:
        """Reset the access set (call before a run to scope its custody trail)."""
        self._accessed = set()

    def accessed_keys(self) -> set[str]:
        return set(self._accessed)

    def provenance(self, keys: "Optional[set[str]]" = None) -> list[dict]:
        """Return the (key, url, fetched_at, sha256) custody records for `keys`
        (defaults to everything accessed since the last mark), sorted by key."""
        if keys is None:
            keys = self._accessed
        records: list[dict] = []
        for key in sorted(keys):
            row = self._conn.execute(
                "SELECT key, url, fetched_at, sha256 FROM responses WHERE key = ?", (key,)
            ).fetchone()
            if row:
                records.append(
                    {"key": row[0], "url": row[1], "fetched_at": row[2], "sha256": row[3]}
                )
        return records

    def close(self) -> None:
        self._conn.close()
