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


def _money_to_int(v) -> int:
    """Read a persisted money value back to an exact integer.

    Money is stored as TEXT (a decimal string) so wei-scale values (>2**63) survive
    SQLite, which cannot hold them as INTEGER and silently degrades them to float.
    This tolerates legacy REAL/float rows too."""
    if v is None:
        return 0
    try:
        return int(v)
    except (ValueError, TypeError):
        try:
            return int(float(v))
        except (ValueError, TypeError):
            return 0


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
                confidence TEXT, score INTEGER, dirty TEXT DEFAULT '0',
                PRIMARY KEY (investigation_id, address)
            );
            CREATE TABLE IF NOT EXISTS edges (
                src TEXT, dst TEXT, chain TEXT,
                total_value TEXT DEFAULT '0', times_seen INTEGER DEFAULT 0, last_seen INTEGER,
                PRIMARY KEY (src, dst, chain)
            );
            CREATE INDEX IF NOT EXISTS ix_obs_addr ON observations(address);
            CREATE TABLE IF NOT EXISTS entity_clusters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                seed TEXT, member_count INTEGER, categories TEXT, risk TEXT, created_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS entity_members (
                entity_id INTEGER, address TEXT, PRIMARY KEY (entity_id, address)
            );
            CREATE INDEX IF NOT EXISTS ix_entmem_addr ON entity_members(address);
            """
        )
        self._conn.commit()
        self._migrate_money_to_text()

    def _col_type(self, table: str, column: str) -> str:
        for r in self._conn.execute(f"PRAGMA table_info({table})").fetchall():
            if r[1] == column:
                return (r[2] or "").upper()
        return ""

    def _migrate_money_to_text(self) -> None:
        """Legacy databases stored money as INTEGER/REAL, which cannot hold wei-scale
        values (>2**63) and silently degrades them to float. Rebuild those columns as
        TEXT, preserving existing values. Idempotent — only runs when needed."""
        if self._col_type("edges", "total_value") != "TEXT":
            self._conn.executescript(
                """
                CREATE TABLE edges_new (
                    src TEXT, dst TEXT, chain TEXT,
                    total_value TEXT DEFAULT '0', times_seen INTEGER DEFAULT 0, last_seen INTEGER,
                    PRIMARY KEY (src, dst, chain)
                );
                INSERT INTO edges_new SELECT src, dst, chain,
                    CAST(CAST(total_value AS INTEGER) AS TEXT), times_seen, last_seen FROM edges;
                DROP TABLE edges;
                ALTER TABLE edges_new RENAME TO edges;
                """
            )
            self._conn.commit()
        if self._col_type("observations", "dirty") != "TEXT":
            self._conn.executescript(
                """
                CREATE TABLE observations_new (
                    investigation_id INTEGER, address TEXT, role TEXT,
                    confidence TEXT, score INTEGER, dirty TEXT DEFAULT '0',
                    PRIMARY KEY (investigation_id, address)
                );
                INSERT INTO observations_new SELECT investigation_id, address, role,
                    confidence, score, CAST(CAST(dirty AS INTEGER) AS TEXT) FROM observations;
                DROP TABLE observations;
                ALTER TABLE observations_new RENAME TO observations;
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
                 int(f["confidence"]["score"]), str(int(f.get("dirty_received", 0) or 0))),
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
        # Money is TEXT and can exceed 2**63 (wei), so sum in Python, not SQL — SQLite
        # would coerce a big-int string to a lossy float in an arithmetic expression.
        row = self._conn.execute(
            "SELECT total_value FROM edges WHERE src=? AND dst=? AND chain=?", (src, dst, chain)
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO edges (src, dst, chain, total_value, times_seen, last_seen) VALUES (?,?,?,?,1,?)",
                (src, dst, chain, str(int(value)), now),
            )
        else:
            new_total = _money_to_int(row[0]) + int(value)
            self._conn.execute(
                "UPDATE edges SET total_value=?, times_seen=times_seen+1, last_seen=? "
                "WHERE src=? AND dst=? AND chain=?",
                (str(new_total), now, src, dst, chain),
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
            "appearances": [{**dict(r), "dirty": _money_to_int(dict(r).get("dirty"))} for r in obs],
        }

    def save_entity(self, entity: dict) -> int:
        """Persist an entity profile + its membership; supersedes any prior cluster
        for the same seed. Returns the entity id."""
        now = _now_ms()
        self._conn.execute("DELETE FROM entity_members WHERE entity_id IN "
                           "(SELECT id FROM entity_clusters WHERE seed=?)", (entity["seed"],))
        self._conn.execute("DELETE FROM entity_clusters WHERE seed=?", (entity["seed"],))
        cur = self._conn.execute(
            "INSERT INTO entity_clusters (seed, member_count, categories, risk, created_at) VALUES (?,?,?,?,?)",
            (entity["seed"], entity["member_count"], json.dumps(entity.get("category_counts", {})),
             entity.get("risk", "low"), now),
        )
        eid = cur.lastrowid
        for addr in entity.get("members", []):
            self._conn.execute("INSERT OR IGNORE INTO entity_members (entity_id, address) VALUES (?,?)", (eid, addr))
        self._conn.commit()
        return eid

    def find_entity(self, address: str) -> dict | None:
        """Return the persisted entity (id, seed, member_count, members) an address belongs to."""
        row = self._conn.execute(
            "SELECT e.id, e.seed, e.member_count, e.categories, e.risk, e.created_at "
            "FROM entity_members m JOIN entity_clusters e ON m.entity_id = e.id WHERE m.address=? "
            "ORDER BY e.created_at DESC LIMIT 1",
            (address,),
        ).fetchone()
        if row is None:
            return None
        members = [r["address"] for r in self._conn.execute(
            "SELECT address FROM entity_members WHERE entity_id=?", (row["id"],)).fetchall()]
        d = dict(row)
        d["members"] = members
        return d

    def cross_references(self, addresses: list[str], current_seed: str) -> list[dict]:
        """Find addresses in this trace that appeared in PRIOR investigations of a
        *different* seed — automatic case-linking through shared infrastructure."""
        addresses = [a for a in addresses if a and a != current_seed]
        if not addresses:
            return []
        placeholders = ",".join("?" * len(addresses))
        rows = self._conn.execute(
            f"SELECT o.address, o.investigation_id, o.confidence, i.seed, i.chain, i.created_at "
            f"FROM observations o JOIN investigations i ON o.investigation_id = i.id "
            f"WHERE o.address IN ({placeholders}) AND i.seed != ? "
            f"ORDER BY i.created_at DESC",
            (*addresses, current_seed),
        ).fetchall()
        grouped: dict[str, dict] = {}
        for r in rows:
            slot = grouped.setdefault(r["address"], {"address": r["address"], "links": []})
            slot["links"].append({
                "investigation_id": r["investigation_id"],
                "other_seed": r["seed"], "chain": r["chain"],
                "created_at": r["created_at"], "confidence": r["confidence"],
            })
        return list(grouped.values())

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

    def all_edges(self) -> list[dict]:
        """Every accumulated flow edge — the substrate for graph analytics."""
        rows = self._conn.execute(
            "SELECT src, dst, chain, total_value, times_seen FROM edges"
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["total_value"] = _money_to_int(d["total_value"])  # exact int for graph analytics
            out.append(d)
        return out

    def entity_labels(self) -> dict[str, str]:
        """address -> a human label (best known role/label) for graph annotation."""
        out: dict[str, str] = {}
        for r in self._conn.execute("SELECT address, labels, roles FROM entities").fetchall():
            labels = json.loads(r["labels"] or "[]")
            roles = json.loads(r["roles"] or "[]")
            if labels:
                out[r["address"]] = labels[0]
            elif roles:
                out[r["address"]] = roles[0]
        return out

    def recent(self, limit: int = 10) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, created_at, seed, chain, direction, addresses, flows, findings, top_confidence "
            "FROM investigations ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        self._conn.close()
