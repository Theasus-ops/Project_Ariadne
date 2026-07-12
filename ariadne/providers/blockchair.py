"""Public multi-chain provider via Blockchair for BTC-like networks."""

from __future__ import annotations

import time
from typing import Any

import requests

from ..cache import ProvenanceCache
from ..models import BTC, DOGE, LTC, Transaction, TxInput, TxOutput
from .base import Provider


class BlockchairProvider(Provider):
    """Lightweight provider for BTC/LTC/DOGE using the public Blockchair API."""

    name = "blockchair"

    def __init__(
        self,
        chain: str = "btc",
        cache: ProvenanceCache | None = None,
        timeout_s: float = 30.0,
        proxies: dict | None = None,
        api_key: str | None = None,
    ) -> None:
        self.chain = chain.lower()
        self.asset_info = {
            "btc": BTC,
            "ltc": LTC,
            "doge": DOGE,
        }[self.chain]
        self.base_url = f"https://api.blockchair.com/{self.chain}"
        self.api_key = api_key
        self.cache = cache or ProvenanceCache()
        self.timeout_s = timeout_s
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Ariadne/0.1 (blockchain-tracer)"})
        if proxies:
            self._session.proxies.update(proxies)
        self._last_call = 0.0

    def _get(self, path: str, cache_key: str):
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        wait = 0.25 - (time.time() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        sep = "&" if "?" in path else "?"
        url = f"{self.base_url}{path}{sep}key={self.api_key}" if self.api_key else f"{self.base_url}{path}"
        try:
            resp = self._session.get(url, timeout=self.timeout_s)
            self._last_call = time.time()
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            data = {}
        self.cache.put(cache_key, f"{self.base_url}{path}", data)
        return data

    def address_tx_count(self, address: str) -> int:
        data = self._get(f"/dashboards/address/{address}", f"blockchair:address:{self.chain}:{address}")
        payload = data.get("data") or {}
        if isinstance(payload, dict):
            for key in ("transactions_count", "tx_count", "count"):
                value = payload.get(key)
                if isinstance(value, int):
                    return value
            dashboard = payload.get("address") or payload.get("dashboard") or {}
            if isinstance(dashboard, dict):
                for key in ("transactions_count", "tx_count", "count"):
                    value = dashboard.get(key)
                    if isinstance(value, int):
                        return value
        return 0

    def latest_block_height(self) -> int:
        data = self._get("/stats", f"blockchair:stats:{self.chain}")
        payload = data.get("data") or {}
        for key in ("best_height", "height", "block_height"):
            value = payload.get(key)
            if isinstance(value, int):
                return value
        blocks = payload.get("blocks") or {}
        for key in ("best_height", "height", "block_height"):
            value = blocks.get(key)
            if isinstance(value, int):
                return value
        return 0

    def get_block_transactions(self, height: int, max_txs: int = 25) -> list[Transaction]:
        data = self._get(f"/dashboards/block/{height}", f"blockchair:block:{self.chain}:{height}")
        payload = data.get("data") or {}
        txs = payload.get("transactions") or payload.get("txs") or []
        out: list[Transaction] = []
        for raw in txs[:max_txs]:
            out.append(self._tx_from_payload(raw))
        return out

    def get_mempool_transactions(self, max_txs: int = 10) -> list[Transaction]:
        return []

    def get_transactions(self, address: str, max_txs: int = 200) -> list[Transaction]:
        data = self._get(f"/dashboards/address/{address}", f"blockchair:txs:{self.chain}:{address}")
        payload = data.get("data") or {}
        txs = payload.get("transactions") or payload.get("txs") or []
        out: list[Transaction] = []
        for raw in txs[:max_txs]:
            out.append(self._tx_from_payload(raw))
        return out

    def _tx_from_payload(self, raw: Any) -> Transaction:
        if isinstance(raw, dict):
            txid = raw.get("hash") or raw.get("txid") or raw.get("id") or ""
            inputs = []
            outputs = []
            if isinstance(raw.get("inputs"), list):
                inputs = [
                    TxInput(address=self.normalize(i.get("recipient") or i.get("address") or i.get("prevout_address")), value=int(i.get("value") or 0))
                    for i in raw.get("inputs")
                    if isinstance(i, dict)
                ]
            if isinstance(raw.get("outputs"), list):
                outputs = [
                    TxOutput(address=self.normalize(o.get("recipient") or o.get("address") or o.get("scriptpubkey_address")), value=int(o.get("value") or 0), index=idx)
                    for idx, o in enumerate(raw.get("outputs"))
                    if isinstance(o, dict)
                ]
            return Transaction(txid=txid, inputs=inputs, outputs=outputs, metadata={"source": "blockchair", "chain": self.chain})
        return Transaction(txid=str(raw), inputs=[], outputs=[], metadata={"source": "blockchair", "chain": self.chain})
