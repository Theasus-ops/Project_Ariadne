"""Evidence integrity — cryptographic signing, chain of custody, reproducibility.

A forensic report is only worth as much as its integrity guarantees. This module
turns an Ariadne report into an *evidence bundle* that a court or oversight body
can trust:

  * **Non-repudiable signature.** The bundle is signed with **Ed25519** (a real
    asymmetric signature, via the vetted ``cryptography`` library — not a bare
    hash anyone can recompute). Anyone with the analyst's public key can verify
    the bundle was produced by the holder of the private key and not altered
    since. The prior "signature" was a SHA-256 digest, which proves integrity but
    not authorship; this proves both.

  * **Chain of custody.** Every conclusion is backed by the exact upstream data it
    used. The provenance cache already records each API response with its URL,
    fetch time, and SHA-256; here we extract the precise set the investigation
    *touched* (via the cache's access log) into a custody list, and fold it into a
    single ``custody_root`` hash. Alter any source datum and the root changes.

  * **Reproducibility.** A manifest pins the tool version, taint model, trace
    parameters, runtime, and a content digest of the report computed over its
    substantive fields only (timestamps excluded). Re-running over the same cached
    data yields the same digest — a deterministic, checkable claim.

Verification (`verify_bundle`) needs no private key and no network: it recomputes
the custody root and checks the Ed25519 signature.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import __version__

BUNDLE_VERSION = "1"
_DEFAULT_KEY_PATH = Path("keys/ariadne_ed25519.key")
# Report fields that change between runs even on identical source data; excluded
# from the reproducibility digest so it is stable and re-checkable.
_VOLATILE_TOP = {"generated_at"}
_VOLATILE_TRACE = {"created_at"}


def canonical(obj: Any) -> bytes:
    """Deterministic JSON serialization used for hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Signer:
    """Ed25519 signer with on-disk key management.

    The private key lives at ``key_path`` (created on first use). Guard it like
    any signing key: whoever holds it can sign as this analyst/instance.
    """

    def __init__(self, key_path: str | Path | None = None) -> None:
        self.key_path = Path(key_path) if key_path is not None else _DEFAULT_KEY_PATH
        self._private = self._load_or_create()

    def _load_or_create(self) -> Ed25519PrivateKey:
        if self.key_path.exists():
            raw = bytes.fromhex(self.key_path.read_text(encoding="utf-8").strip())
            return Ed25519PrivateKey.from_private_bytes(raw)
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.write_text(raw.hex(), encoding="utf-8")
        try:  # best-effort tighten perms (POSIX); no-op on Windows
            self.key_path.chmod(0o600)
        except (OSError, NotImplementedError):
            pass
        return key

    @property
    def public_key_hex(self) -> str:
        raw = self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return raw.hex()

    def sign(self, data: bytes) -> str:
        return self._private.sign(data).hex()

    def sign_dict(self, obj: Any) -> dict:
        """Return a signature block over the canonical form of ``obj``."""
        return {
            "algorithm": "ed25519",
            "public_key": self.public_key_hex,
            "value": self.sign(canonical(obj)),
        }


def verify_signature(obj: Any, signature_block: dict) -> bool:
    """Verify a signature block (as produced by ``Signer.sign_dict``) over ``obj``."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signature_block["public_key"]))
        pub.verify(bytes.fromhex(signature_block["value"]), canonical(obj))
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False


def report_digest(report: dict) -> str:
    """Content hash over the report's substantive fields (timestamps excluded)."""
    clone = deepcopy(report)
    for key in _VOLATILE_TOP:
        clone.pop(key, None)
    trace = clone.get("trace")
    if isinstance(trace, dict):
        for key in _VOLATILE_TRACE:
            trace.pop(key, None)
    clone.pop("brief", None)  # brief is derived; digest the primary evidence only
    return _sha256(canonical(clone))


def custody_root(records: list[dict]) -> str:
    """Fold the per-source SHA-256s into one root hash (order-independent)."""
    digests = sorted(r.get("sha256", "") for r in records)
    return _sha256("".join(digests).encode("utf-8"))


def reproducibility_manifest(report: dict) -> dict:
    trace = report.get("trace", {})
    return {
        "tool": "Ariadne",
        "tool_version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "chain": report.get("asset"),
        "seed": trace.get("seed"),
        "direction": trace.get("direction"),
        "taint_model": trace.get("taint_model"),
        "parameters": trace.get("parameters", {}),
        "report_digest": report_digest(report),
    }


def build_evidence_bundle(
    report: dict,
    cache=None,
    custody: Optional[list[dict]] = None,
    signer: Optional[Signer] = None,
    key_path: str | Path | None = None,
) -> dict:
    """Assemble a signed, custody-backed, reproducible evidence bundle.

    ``custody`` may be supplied directly; otherwise it is drawn from the cache's
    access log (the exact source responses this investigation touched).
    """
    if custody is None:
        custody = cache.provenance() if cache is not None else []
    signer = signer or Signer(key_path)

    body = {
        "bundle_version": BUNDLE_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "manifest": reproducibility_manifest(report),
        "custody": custody,
        "custody_root": custody_root(custody),
        "custody_count": len(custody),
        "report": report,
    }
    body["signature"] = signer.sign_dict({k: v for k, v in body.items() if k != "signature"})
    return body


def verify_bundle(bundle: dict) -> dict:
    """Verify a bundle's custody root and Ed25519 signature. No key/network needed."""
    reasons: list[str] = []

    recomputed = custody_root(bundle.get("custody", []))
    if recomputed != bundle.get("custody_root"):
        reasons.append("custody root does not match the listed source hashes")

    manifest = bundle.get("manifest", {})
    report = bundle.get("report")
    if isinstance(report, dict) and manifest.get("report_digest") != report_digest(report):
        reasons.append("report digest does not match the embedded report")

    sig = bundle.get("signature")
    if not isinstance(sig, dict):
        reasons.append("missing signature")
    else:
        signed_body = {k: v for k, v in bundle.items() if k != "signature"}
        if not verify_signature(signed_body, sig):
            reasons.append("Ed25519 signature is invalid (bundle altered or wrong key)")

    return {
        "ok": not reasons,
        "reasons": reasons,
        "public_key": (bundle.get("signature") or {}).get("public_key"),
        "custody_count": bundle.get("custody_count", len(bundle.get("custody", []))),
    }


def write_bundle(bundle: dict, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return path
