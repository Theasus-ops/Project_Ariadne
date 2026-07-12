"""Versioned attribution store — the moat, done properly.

A flat ``labels.json`` cannot answer the questions a real intelligence workflow
asks: *When did we first attribute this address? Who says so, and how sure are
they? Has that attribution been superseded by better information?* This store
adds those axes:

  * **Provenance & confidence** per attribution (source feed + a 0–1 confidence),
    so a KuCoin label from a curated exchange feed outranks a low-confidence guess.
  * **Bitemporal history** — first_seen / last_seen and a version chain. New,
    conflicting information does not overwrite the old record; it *supersedes* it,
    and the history is preserved (an auditor can see how an attribution evolved).
  * **Compounding** — Ariadne writes back its *own* derived attributions (e.g. a
    discovered exchange deposit address, see :mod:`ariadne.core.deposit`), so the
    tool's coverage grows with use instead of being frozen at import time.

It is a superset of the label store: :meth:`as_label_store` projects the current
best attributions into the :class:`LabelStore` the rest of the engine consumes,
so nothing downstream needs to change.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .labels import Label, LabelCategory, LabelStore, norm_addr

# Default confidence for an attribution when a feed does not supply one.
_CATEGORY_CONFIDENCE: dict[str, float] = {
    "sanctioned": 1.0,
    "ransomware": 0.92,
    "darknet": 0.88,
    "scam": 0.85,
    "mixer": 0.80,
    "exchange": 0.72,
    "bridge": 0.62,
    "dex": 0.60,
    "gambling": 0.55,
    "service": 0.45,
    "other": 0.40,
}


def default_confidence(category: str) -> float:
    return _CATEGORY_CONFIDENCE.get(category, 0.40)


@dataclass
class Attribution:
    address: str
    chain: str
    category: str
    name: str
    source: str
    confidence: float
    provenance: str
    first_seen: int
    last_seen: int
    version: int
    superseded: bool


class AttributionStore:
    def __init__(self, path: str | Path = "knowledge/attribution.sqlite") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS attributions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL, chain TEXT DEFAULT '',
                category TEXT NOT NULL, name TEXT DEFAULT '',
                source TEXT DEFAULT '', confidence REAL DEFAULT 0.4,
                provenance TEXT DEFAULT '',
                first_seen INTEGER, last_seen INTEGER,
                version INTEGER DEFAULT 1, superseded INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS ix_attr_addr ON attributions(address);
            CREATE INDEX IF NOT EXISTS ix_attr_live ON attributions(address, superseded);
            """
        )
        self._conn.commit()

    def _current(self, address: str, source: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM attributions WHERE address=? AND source=? AND superseded=0 "
            "ORDER BY version DESC LIMIT 1",
            (address, source),
        ).fetchone()

    def upsert(
        self,
        address: str,
        category: str,
        name: str = "",
        source: str = "",
        confidence: float | None = None,
        chain: str = "",
        provenance: str = "",
    ) -> None:
        """Record an attribution. Same (address, source) that is unchanged just
        refreshes last_seen; a changed one supersedes the prior version."""
        address = norm_addr(address)
        now = int(time.time())
        conf = default_confidence(category) if confidence is None else max(0.0, min(1.0, confidence))
        existing = self._current(address, source)

        if existing is not None:
            unchanged = (
                existing["category"] == category
                and existing["name"] == name
                and abs(existing["confidence"] - conf) < 1e-9
            )
            if unchanged:
                self._conn.execute(
                    "UPDATE attributions SET last_seen=? WHERE id=?", (now, existing["id"])
                )
                self._conn.commit()
                return
            # Supersede the old record, insert a new version.
            self._conn.execute(
                "UPDATE attributions SET superseded=1 WHERE id=?", (existing["id"],)
            )
            version = existing["version"] + 1
            first_seen = existing["first_seen"]
        else:
            version = 1
            first_seen = now

        self._conn.execute(
            "INSERT INTO attributions (address, chain, category, name, source, confidence, "
            "provenance, first_seen, last_seen, version, superseded) VALUES (?,?,?,?,?,?,?,?,?,?,0)",
            (address, chain, category, name, source, conf, provenance, first_seen, now, version),
        )
        self._conn.commit()

    def best(self, address: str) -> Optional[Attribution]:
        row = self._conn.execute(
            "SELECT * FROM attributions WHERE address=? AND superseded=0 "
            "ORDER BY confidence DESC, last_seen DESC LIMIT 1",
            (norm_addr(address),),
        ).fetchone()
        return self._row_to_attr(row) if row else None

    def history(self, address: str) -> list[Attribution]:
        rows = self._conn.execute(
            "SELECT * FROM attributions WHERE address=? ORDER BY version ASC, id ASC",
            (norm_addr(address),),
        ).fetchall()
        return [self._row_to_attr(r) for r in rows]

    @staticmethod
    def _row_to_attr(row: sqlite3.Row) -> Attribution:
        return Attribution(
            address=row["address"], chain=row["chain"], category=row["category"],
            name=row["name"], source=row["source"], confidence=row["confidence"],
            provenance=row["provenance"], first_seen=row["first_seen"],
            last_seen=row["last_seen"], version=row["version"],
            superseded=bool(row["superseded"]),
        )

    def import_labels(self, labels: Iterable[Label], provenance: str = "") -> int:
        count = 0
        for lab in labels:
            self.upsert(
                lab.address, lab.category.value, lab.name, lab.source or "feed",
                provenance=provenance or lab.description,
            )
            count += 1
        return count

    def as_label_store(self, base: LabelStore | None = None) -> LabelStore:
        """Project current best attributions into a LabelStore for the engine."""
        store = base or LabelStore()
        rows = self._conn.execute(
            "SELECT address, category, name, source FROM attributions WHERE superseded=0"
        ).fetchall()
        for r in rows:
            try:
                category = LabelCategory(r["category"])
            except ValueError:
                category = LabelCategory.OTHER
            store.add(Label(r["address"], category, r["name"], r["source"]))
        return store

    def stats(self) -> dict:
        c = self._conn
        by_cat = {
            row["category"]: row["n"]
            for row in c.execute(
                "SELECT category, COUNT(*) n FROM attributions WHERE superseded=0 GROUP BY category"
            ).fetchall()
        }
        return {
            "live": c.execute("SELECT COUNT(*) FROM attributions WHERE superseded=0").fetchone()[0],
            "superseded": c.execute("SELECT COUNT(*) FROM attributions WHERE superseded=1").fetchone()[0],
            "addresses": c.execute("SELECT COUNT(DISTINCT address) FROM attributions").fetchone()[0],
            "by_category": by_cat,
        }

    def close(self) -> None:
        self._conn.close()
