"""Lawful authorization & tamper-evident accountability — the *lawful* in lawful intelligence.

A capable tracer is a tool. A government intelligence *program* is something more: a
system in which every investigation is tied to a **legal authorization**, every
action is recorded in a way that **cannot be quietly altered**, and data is retained
only as long as its lawful basis holds. That accountability is not bureaucratic
overhead — it is the difference between lawful intelligence and surveillance, and no
agency (least of all under EU/GDPR) can deploy a tool that lacks it.

This module provides that layer:

* **Authorizations** — a register of legal bases (warrant / prosecutor order / MLAT
  reference / statute), each with an issuing authority, a responsible officer, a
  scope, and an expiry. An investigation should point at one.
* **A tamper-evident audit chain** — every recorded action is sealed with a SHA-256
  hash over the previous entry, so the log is append-only *and verifiable*: altering
  or deleting any past entry breaks the chain and `verify_chain()` names where. This
  upgrades a log you must trust into a log you can check.
* **Retention review** — actions whose authorization has expired and that are older
  than a retention window are surfaced for minimisation (data-protection hygiene).
* **Oversight report** — the summary an oversight body reviews: authorizations
  (active / expired / revoked), actions taken, any action that ran **without** a
  valid covering authorization (a compliance flag), and the chain-integrity result.

Pure SQLite + hashlib; deterministic given a clock, so every figure is reproducible
and every claim is checkable offline.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

GENESIS_HASH = "0" * 64
_DAY = 86400.0


@dataclass
class Authorization:
    id: str
    case_ref: str
    subject: str            # what/who is authorised (free-text description)
    legal_basis: str        # statute / warrant / prosecutor order / MLAT reference
    authority: str          # issuing body (court, prosecutor, FIU, ...)
    officer: str            # responsible / authorising officer
    granted_at: float
    expires_at: float
    scope_addresses: list = field(default_factory=list)  # explicit addresses; empty = case-level
    status: str = "active"  # active | revoked

    def is_valid(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return self.status == "active" and self.granted_at <= now < self.expires_at

    def covers(self, address: str) -> bool:
        """A case-level authorisation (no explicit scope) covers any address; a
        scoped one covers only the addresses it names."""
        if not self.scope_addresses:
            return True
        return address in set(self.scope_addresses)


class AuthorityStore:
    def __init__(self, path: str | Path = "knowledge/authority.sqlite") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS authorizations (
                id TEXT PRIMARY KEY, case_ref TEXT, subject TEXT, legal_basis TEXT,
                authority TEXT, officer TEXT, granted_at REAL, expires_at REAL,
                scope_addresses TEXT, status TEXT
            );
            CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY, ts REAL, actor TEXT, action TEXT, target TEXT,
                authorization_id TEXT, authorized INTEGER, prev_hash TEXT, entry_hash TEXT
            );
            """
        )
        self._conn.commit()

    # ---- authorizations ----
    def add_authorization(
        self, case_ref: str, subject: str, legal_basis: str, authority: str, officer: str,
        valid_days: float = 90.0, scope_addresses: list | None = None, now: float | None = None,
    ) -> Authorization:
        if not legal_basis.strip() or not authority.strip():
            raise ValueError("an authorization requires a legal basis and an issuing authority")
        now = time.time() if now is None else now
        auth = Authorization(
            id=uuid.uuid4().hex[:12], case_ref=case_ref, subject=subject, legal_basis=legal_basis,
            authority=authority, officer=officer, granted_at=now, expires_at=now + valid_days * _DAY,
            scope_addresses=list(scope_addresses or []), status="active",
        )
        self._conn.execute(
            "INSERT INTO authorizations VALUES (?,?,?,?,?,?,?,?,?,?)",
            (auth.id, auth.case_ref, auth.subject, auth.legal_basis, auth.authority, auth.officer,
             auth.granted_at, auth.expires_at, json.dumps(auth.scope_addresses), auth.status),
        )
        self._conn.commit()
        return auth

    def _row_to_auth(self, r) -> Authorization:
        return Authorization(
            id=r[0], case_ref=r[1], subject=r[2], legal_basis=r[3], authority=r[4], officer=r[5],
            granted_at=r[6], expires_at=r[7], scope_addresses=json.loads(r[8] or "[]"), status=r[9],
        )

    def get_authorization(self, auth_id: str) -> Authorization | None:
        r = self._conn.execute("SELECT * FROM authorizations WHERE id=?", (auth_id,)).fetchone()
        return self._row_to_auth(r) if r else None

    def list_authorizations(self) -> list[Authorization]:
        rows = self._conn.execute("SELECT * FROM authorizations ORDER BY granted_at DESC").fetchall()
        return [self._row_to_auth(r) for r in rows]

    def revoke(self, auth_id: str) -> bool:
        cur = self._conn.execute("UPDATE authorizations SET status='revoked' WHERE id=?", (auth_id,))
        self._conn.commit()
        return cur.rowcount > 0

    def valid_authorization_for(self, address: str, now: float | None = None) -> Authorization | None:
        """The first active, unexpired authorization that covers ``address``."""
        for auth in self.list_authorizations():
            if auth.is_valid(now) and auth.covers(address):
                return auth
        return None

    # ---- tamper-evident audit chain ----
    def _last(self) -> tuple[int, str]:
        r = self._conn.execute("SELECT seq, entry_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return (r[0], r[1]) if r else (0, GENESIS_HASH)

    @staticmethod
    def _hash(prev_hash: str, seq: int, ts: float, actor: str, action: str,
              target: str, authorization_id: str, authorized: int) -> str:
        canonical = f"{prev_hash}|{seq}|{ts:.6f}|{actor}|{action}|{target}|{authorization_id}|{authorized}"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def record_action(
        self, actor: str, action: str, target: str = "",
        authorization_id: str | None = None, now: float | None = None,
    ) -> dict:
        """Append a hash-chained audit entry. Records whether the action was covered
        by a valid authorization, so the oversight report can flag any that were not."""
        now = time.time() if now is None else now
        auth = self.get_authorization(authorization_id) if authorization_id else None
        authorized = 1 if (auth is not None and auth.is_valid(now) and auth.covers(target)) else 0
        last_seq, prev_hash = self._last()
        seq = last_seq + 1
        entry_hash = self._hash(prev_hash, seq, now, actor, action, target,
                                authorization_id or "", authorized)
        self._conn.execute(
            "INSERT INTO audit VALUES (?,?,?,?,?,?,?,?,?)",
            (seq, now, actor, action, target, authorization_id or "", authorized, prev_hash, entry_hash),
        )
        self._conn.commit()
        return {"seq": seq, "ts": now, "actor": actor, "action": action, "target": target,
                "authorization_id": authorization_id or "", "authorized": bool(authorized),
                "prev_hash": prev_hash, "entry_hash": entry_hash}

    def audit_entries(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT seq, ts, actor, action, target, authorization_id, authorized, prev_hash, entry_hash "
            "FROM audit ORDER BY seq"
        ).fetchall()
        return [
            {"seq": r[0], "ts": r[1], "actor": r[2], "action": r[3], "target": r[4],
             "authorization_id": r[5], "authorized": bool(r[6]), "prev_hash": r[7], "entry_hash": r[8]}
            for r in rows
        ]

    def verify_chain(self) -> dict:
        """Re-walk the audit chain and confirm no entry was altered or removed."""
        prev = GENESIS_HASH
        entries = self.audit_entries()
        for i, e in enumerate(entries, start=1):
            if e["seq"] != i or e["prev_hash"] != prev:
                return {"ok": False, "length": len(entries), "broken_at": e["seq"], "reason": "chain-link"}
            recomputed = self._hash(e["prev_hash"], e["seq"], e["ts"], e["actor"], e["action"],
                                    e["target"], e["authorization_id"], int(e["authorized"]))
            if recomputed != e["entry_hash"]:
                return {"ok": False, "length": len(entries), "broken_at": e["seq"], "reason": "entry-hash"}
            prev = e["entry_hash"]
        return {"ok": True, "length": len(entries), "broken_at": None}

    # ---- retention & oversight ----
    def retention_review(self, max_age_days: float, now: float | None = None) -> dict:
        """Audit actions older than the retention window whose authorization is no
        longer valid — eligible for minimisation under a data-protection policy."""
        now = time.time() if now is None else now
        cutoff = now - max_age_days * _DAY
        stale = []
        for e in self.audit_entries():
            if e["ts"] >= cutoff:
                continue
            auth = self.get_authorization(e["authorization_id"]) if e["authorization_id"] else None
            if auth is None or not auth.is_valid(now):
                stale.append(e)
        return {"max_age_days": max_age_days, "eligible_for_minimisation": len(stale), "entries": stale}

    def oversight_report(self, days: float | None = None, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        auths = self.list_authorizations()
        active = [a for a in auths if a.is_valid(now)]
        revoked = [a for a in auths if a.status == "revoked"]
        expired = [a for a in auths if a.status == "active" and a.expires_at <= now]

        entries = self.audit_entries()
        if days is not None:
            since = now - days * _DAY
            entries = [e for e in entries if e["ts"] >= since]
        unauthorized = [e for e in entries if not e["authorized"]]

        return {
            "generated_at": now,
            "window_days": days,
            "authorizations": {
                "total": len(auths), "active": len(active),
                "expired": len(expired), "revoked": len(revoked),
            },
            "actions": {
                "total": len(entries),
                "authorized": len(entries) - len(unauthorized),
                "unauthorized": len(unauthorized),
            },
            "compliance_flags": [
                {"seq": e["seq"], "actor": e["actor"], "action": e["action"], "target": e["target"]}
                for e in unauthorized
            ],
            "audit_chain": self.verify_chain(),
            "note": (
                "Actions flagged unauthorized ran without a valid covering authorization and must be "
                "reviewed. A broken audit chain means the record was tampered with and is not admissible."
            ),
        }

    def close(self) -> None:
        self._conn.close()
