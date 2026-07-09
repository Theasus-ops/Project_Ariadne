"""Ariadne's persistent knowledge base.

Every trace used to be amnesiac: it forgot the moment it finished. This store
makes Ariadne *cumulative* -- it records what each investigation found so that the
next one can recall it ("we have seen this wallet before; last time it graded
HIGH and connected to WannaCry").

Two design choices make it suitable for evidence work:

  * **Tamper-evident.** The investigation log is hash-chained: each record stores
    the SHA-256 of (previous hash + its own content), so any later edit to a past
    record breaks the chain and ``verify_integrity`` detects exactly where.
  * **Parameterised everywhere.** No string-built SQL, so the store itself is not
    an injection surface.

Tables:
  investigations  one row per completed trace (hash-chained)
  entities        one row per address ever seen (accumulated attributes)
  observations    address x investigation (role, confidence at that time)
  edges           cumulative observed value flows between addresses
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

_GENESIS = "GENESIS"


def _now_ms() -> int:
    return int(time.time() * 1000)


class KnowledgeStore:
    def __init__(self, path: str | Path = "knowledge/ariadne_knowledge.sqlite") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER, seed TEXT, chain TEXT, direction TEXT,
                addresses INTEGER, flows INTEGER, findings INTEGER,
                top_confidence TEXT, summary TEXT,
                prev_hash TEXT, record_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS entities (
                address TEXT PRIMARY KEY, chain TEXT,
                first_seen INTEGER, last_seen INTEGER, times_seen INTEGER DEFAULT 0,
                best_confidence TEXT DEFAULT 'info', best_score INTEGER DEFAULT 0,
                roles TEXT, labels TEXT
            );
            CREATE TABLE IF NOT EXISTS observations (
                investigation_id INTEGER, address TEXT, role TEXT,
                confidence TEXT, score INTEGER, dirty REAL,
                PRIMARY KEY (investigation_id, address)
            );
            CREATE TABLE IF NOT EXISTS edges (
                src TEXT, dst TEXT, chain TEXT,
                total_value INTEGER DEFAULT 0, times_seen INTEGER DEFAULT 0, last_seen INTEGER,
                PRIMARY KEY (src, dst, chain)
            );
            CREATE INDEX IF NOT EXISTS ix_obs_addr ON observations(address);
            """
        )
        self._conn.commit()

    # ---- hash chain ----
    @staticmethod
    def _hash(prev: str, payload: dict) -> str:
        return hashlib.sha256((prev + json.dumps(payload, sort_keys=True)).encode("utf-8")).hexdigest()

    def _last_hash(self) -> str:
        row = self._conn.execute(
            "SELECT record_hash FROM investigations ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["record_hash"] if row else _GENESIS

    @staticmethod
    def _payload(created_at, seed, chain, direction, addresses, flows, findings, top_confidence, summary_text) -> dict:
        return {
            "created_at": created_at, "seed": seed, "chain": chain, "direction": direction,
            "addresses": addresses, "flows": flows, "findings": findings,
            "top_confidence": top_confidence, "summary_text": summary_text,
        }

    # ---- writes ----
    def record_trace(self, report: dict, chain: str) -> int:
        """Persist a completed trace (a dict from report.build_report)."""
        conn = self._conn
        now = _now_ms()
        trace = report.get("trace", {})
        seed = trace.get("seed", "")
        direction = trace.get("direction", "forward")
        summary = report.get("summary", {})
        findings = report.get("findings", [])
        summary_text = report.get("summary_text", "")
        top_conf = findings[0]["confidence"]["level"] if findings else "info"
        addresses = int(summary.get("addresses", 0))
        flows = int(summary.get("flows", 0))

        prev = self._last_hash()
        payload = self._payload(now, seed, chain, direction, addresses, flows, len(findings), top_conf, summary_text)
        record_hash = self._hash(prev, payload)

        cur = conn.execute(
            "INSERT INTO investigations (created_at, seed, chain, direction, addresses, flows, findings, "
            "top_confidence, summary, prev_hash, record_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (now, seed, chain, direction, addresses, flows, len(findings), top_conf, summary_text, prev, record_hash),
        )
        inv_id = cur.lastrowid

        for node in report.get("nodes", []):
            self._upsert_entity(node, chain, now)
        for f in findings:
            conn.execute(
                "INSERT OR REPLACE INTO observations (investigation_id, address, role, confidence, score, dirty) "
                "VALUES (?,?,?,?,?,?)",
                (inv_id, f["address"], f.get("type", ""), f["confidence"]["level"],
                 int(f["confidence"]["score"]), float(f.get("dirty_received", 0) or 0)),
            )
            conn.execute(
                "UPDATE entities SET best_confidence=?, best_score=? WHERE address=? AND best_score < ?",
                (f["confidence"]["level"], int(f["confidence"]["score"]), f["address"], int(f["confidence"]["score"])),
            )
        for e in report.get("edges", []):
            self._upsert_edge(e["src"], e["dst"], chain, int(e.get("raw", 0) or 0), now)

        conn.commit()
        return inv_id

    def _upsert_entity(self, node: dict, chain: str, now: int) -> None:
        addr = node["address"]
        role = node.get("type", "")
        label = node.get("label") or ""
        row = self._conn.execute("SELECT roles, labels FROM entities WHERE address=?", (addr,)).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO entities (address, chain, first_seen, last_seen, times_seen, roles, labels) "
                "VALUES (?,?,?,?,1,?,?)",
                (addr, chain, now, now, json.dumps([role] if role else []), json.dumps([label] if label else [])),
            )
        else:
            roles = set(json.loads(row["roles"] or "[]"))
            if role:
                roles.add(role)
            labels = set(json.loads(row["labels"] or "[]"))
            if label:
                labels.add(label)
            self._conn.execute(
                "UPDATE entities SET last_seen=?, times_seen=times_seen+1, roles=?, labels=? WHERE address=?",
                (now, json.dumps(sorted(roles)), json.dumps(sorted(labels)), addr),
            )

    def _upsert_edge(self, src: str, dst: str, chain: str, value: int, now: int) -> None:
        self._conn.execute(
            "INSERT INTO edges (src, dst, chain, total_value, times_seen, last_seen) VALUES (?,?,?,?,1,?) "
            "ON CONFLICT(src, dst, chain) DO UPDATE SET total_value=total_value+?, times_seen=times_seen+1, last_seen=?",
            (src, dst, chain, value, now, value, now),
        )

    # ---- reads ----
    def recall(self, address: str) -> dict:
        conn = self._conn
        ent = conn.execute("SELECT * FROM entities WHERE address=?", (address,)).fetchone()
        obs = conn.execute(
            "SELECT o.investigation_id, o.role, o.confidence, o.score, o.dirty, "
            "i.created_at, i.seed, i.chain, i.direction "
            "FROM observations o JOIN investigations i ON o.investigation_id=i.id "
            "WHERE o.address=? ORDER BY i.created_at DESC LIMIT 25",
            (address,),
        ).fetchall()
        return {
            "known": ent is not None,
            "entity": dict(ent) if ent else None,
            "appearances": [dict(r) for r in obs],
        }

    def verify_integrity(self) -> dict:
        rows = self._conn.execute(
            "SELECT id, created_at, seed, chain, direction, addresses, flows, findings, "
            "top_confidence, summary, prev_hash, record_hash FROM investigations ORDER BY id ASC"
        ).fetchall()
        prev = _GENESIS
        for r in rows:
            payload = self._payload(
                r["created_at"], r["seed"], r["chain"], r["direction"], r["addresses"],
                r["flows"], r["findings"], r["top_confidence"], r["summary"],
            )
            expect = self._hash(prev, payload)
            if r["prev_hash"] != prev or r["record_hash"] != expect:
                return {"ok": False, "records": len(rows), "broken_at": r["id"]}
            prev = r["record_hash"]
        return {"ok": True, "records": len(rows), "broken_at": None}

    def stats(self) -> dict:
        c = self._conn
        return {
            "investigations": c.execute("SELECT COUNT(*) FROM investigations").fetchone()[0],
            "entities": c.execute("SELECT COUNT(*) FROM entities").fetchone()[0],
            "edges": c.execute("SELECT COUNT(*) FROM edges").fetchone()[0],
            "flagged_entities": c.execute("SELECT COUNT(*) FROM entities WHERE best_score>=50").fetchone()[0],
        }

    def recent(self, limit: int = 10) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, created_at, seed, chain, direction, addresses, flows, findings, top_confidence "
            "FROM investigations ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        self._conn.close()
