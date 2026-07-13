"""Targeted watchlist — "tell me the instant THIS address moves."

The block monitor surfaces *unknown* suspects by pattern. But the most common
operational need is the opposite: an investigator already has a suspect address and
wants to know the moment it transacts. Sampling random block transactions would
miss it, so the watchlist works by **address polling** — it records each watched
address's confirmed transaction count as a baseline and, on each scan, flags any
address whose count has grown (i.e. it moved).

State (baseline tx count, last check) is persisted so movement is detected across
restarts. A watchlist hit is always top-priority; when wired into the live scorer,
any transaction touching a watched address is scored critical regardless of its
other features.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path


class Watchlist:
    def __init__(self, path: str | Path = "knowledge/watchlist.sqlite") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS watch (
                address TEXT PRIMARY KEY, chain TEXT, note TEXT, priority INTEGER DEFAULT 1,
                added_at INTEGER, last_tx_count INTEGER, last_checked INTEGER
            )
            """
        )
        self._conn.commit()

    def add(self, address: str, chain: str, note: str = "", priority: int = 1) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO watch (address, chain, note, priority, added_at, last_tx_count, last_checked) "
            "VALUES (?,?,?,?,?, COALESCE((SELECT last_tx_count FROM watch WHERE address=?), NULL), "
            "COALESCE((SELECT last_checked FROM watch WHERE address=?), NULL))",
            (address, chain.lower(), note, priority, int(time.time()), address, address),
        )
        self._conn.commit()

    def remove(self, address: str) -> bool:
        cur = self._conn.execute("DELETE FROM watch WHERE address=?", (address,))
        self._conn.commit()
        return cur.rowcount > 0

    def list(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM watch ORDER BY priority DESC, added_at DESC").fetchall()]

    def watched_addresses(self, chain: str | None = None) -> set[str]:
        if chain:
            rows = self._conn.execute("SELECT address FROM watch WHERE chain=?", (chain.lower(),)).fetchall()
        else:
            rows = self._conn.execute("SELECT address FROM watch").fetchall()
        return {r["address"] for r in rows}

    def is_watched(self, address: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM watch WHERE address=?", (address,)).fetchone()
        return dict(row) if row else None

    def check_movements(self, build_provider, cache) -> list[dict]:
        """Poll every watched address; return alerts for those that moved.

        ``build_provider(chain, cache)`` builds a provider. The first check of an
        address records a baseline (no alert); subsequent growth in its confirmed
        tx count is a movement.
        """
        alerts: list[dict] = []
        now = int(time.time())
        for entry in self.list():
            addr, chain = entry["address"], entry["chain"]
            try:
                provider = build_provider(chain, cache)
                new_count = provider.address_tx_count(provider.normalize(addr))
            except Exception:
                continue
            prev = entry["last_tx_count"]
            if prev is not None and new_count > prev:
                alerts.append({
                    "address": addr, "chain": chain, "note": entry["note"],
                    "priority": entry["priority"],
                    "previous_tx_count": prev, "new_tx_count": new_count,
                    "new_transactions": new_count - prev,
                    "time": now,
                })
            self._conn.execute(
                "UPDATE watch SET last_tx_count=?, last_checked=? WHERE address=?", (new_count, now, addr)
            )
        self._conn.commit()
        return alerts

    def close(self) -> None:
        self._conn.close()
