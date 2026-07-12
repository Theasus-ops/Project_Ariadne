"""Monero-focused heuristics and data access layer.

Monero is privacy-preserving and does not expose the same transparent address-level
history as Bitcoin/Ethereum. This provider therefore focuses on observable
signals: outbound/inbound transactions, ring-membership metadata, and heuristic
countermeasures for privacy-coin laundering paths.
"""

from __future__ import annotations

from typing import Any

import requests

from ..cache import ProvenanceCache
from ..models import XMR, Transaction, TxInput, TxOutput
from .base import Provider


class MoneroProvider(Provider):
    name = "monero"

    def __init__(self, cache: ProvenanceCache | None = None, timeout_s: float = 20.0) -> None:
        self.asset_info = XMR
        self.base_url = "https://xmrchain.net/api"
        self.cache = cache or ProvenanceCache()
        self.timeout_s = timeout_s
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Ariadne/0.1 (monero-tracer)"})

    def _get(self, path: str, cache_key: str):
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            resp = self._session.get(f"{self.base_url}{path}", timeout=self.timeout_s)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            data = {}
        self.cache.put(cache_key, f"{self.base_url}{path}", data)
        return data

    def address_tx_count(self, address: str) -> int:
        return 0

    def latest_block_height(self) -> int:
        data = self._get("/block/height", "xmr:blockheight")
        if isinstance(data, dict):
            for key in ("height", "block_height", "data"):
                value = data.get(key)
                if isinstance(value, int):
                    return value
                if isinstance(value, dict):
                    v = value.get("height")
                    if isinstance(v, int):
                        return v
        return 0

    def get_block_transactions(self, height: int, max_txs: int = 25) -> list[Transaction]:
        return []

    def get_mempool_transactions(self, max_txs: int = 10) -> list[Transaction]:
        return []

    def get_transactions(self, address: str, max_txs: int = 200) -> list[Transaction]:
        data = self._get(f"/address/{address}", f"xmr:address:{address}")
        payload = data.get("txs") if isinstance(data, dict) else None
        if not isinstance(payload, list):
            return []
        out: list[Transaction] = []
        for raw in payload[:max_txs]:
            if isinstance(raw, dict):
                out.append(self._tx_from_payload(raw))
        return out

    def heuristic_risk(self, address: str) -> dict[str, Any]:
        txs = self.get_transactions(address, max_txs=20)
        risk = {"privacy_coin": True, "observed_txs": len(txs), "suspicious": False}
        if txs:
            suspicious = any(getattr(tx, "metadata", {}).get("ring_size", 0) > 2 for tx in txs)
            risk["suspicious"] = suspicious
        return risk

    def _tx_from_payload(self, raw: dict[str, Any]) -> Transaction:
        txid = raw.get("hash") or raw.get("txid") or raw.get("id") or ""
        ring_size = raw.get("ring_size") or raw.get("mixins") or 0
        inputs = [TxInput(address=None, value=0)] if ring_size else []
        outputs = [TxOutput(address=None, value=0, index=0)] if ring_size else []
        return Transaction(
            txid=txid,
            inputs=inputs,
            outputs=outputs,
            metadata={"source": "monero", "ring_size": ring_size, "privacy_coin": True},
        )
