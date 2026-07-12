"""Security and audit primitives for a defensible intelligence workflow."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class EvidenceSigner:
    """Cryptographic signer for evidence bundles.

    Backed by Ed25519 (see :mod:`ariadne.evidence`) so a signature proves *both*
    integrity and authorship — not just a recomputable hash. A process-wide signer
    is reused so the public key is stable across a session.
    """

    _signer = None

    @classmethod
    def _get(cls, key_path=None):
        if cls._signer is None:
            from .evidence import Signer
            cls._signer = Signer(key_path)
        return cls._signer

    @classmethod
    def sign(cls, payload: dict[str, Any]) -> dict[str, str]:
        """Return an Ed25519 signature block over ``payload``."""
        return cls._get().sign_dict(payload)

    @classmethod
    def public_key(cls) -> str:
        return cls._get().public_key_hex

    @staticmethod
    def digest(payload: dict[str, Any]) -> str:
        """Plain SHA-256 digest (integrity only) — retained for internal use."""
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


class AuditLogger:
    """Append-only JSONL audit logger for operator actions."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else Path("reports/audit.jsonl")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def log(self, event: str, actor: str, action: str, details: dict[str, Any] | None = None) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "actor": actor,
            "action": action,
            "details": details or {},
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
