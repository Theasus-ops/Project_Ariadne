"""Bitcoin data via the Blockstream Esplora API (keyless, public).

API reference: https://github.com/Blockstream/esplora/blob/master/API.md
"""

from __future__ import annotations

import threading
import time

import requests

from ..cache import ProvenanceCache
from ..models import BTC, Transaction, TxInput, TxOutput
from .base import Provider

# Esplora returns 25 confirmed transactions per page.
_PAGE_SIZE = 25


class BlockstreamProvider(Provider):
    name = "blockstream"
    asset_info = BTC

    def __init__(
        self,
        cache: ProvenanceCache | None = None,
        base_url: str = "https://blockstream.info/api",
        rate_limit_s: float = 0.4,
        timeout_s: float = 30.0,
        proxies: dict | None = None,
        offline: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.cache = cache or ProvenanceCache()
        self.offline = offline
        self.rate_limit_s = rate_limit_s
        self.timeout_s = timeout_s
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Ariadne/0.1 (blockchain-tracer)"})
        if proxies:
            self._session.proxies.update(proxies)
        self._last_call = 0.0
        self._throttle_lock = threading.Lock()

    def _throttle(self) -> None:
        """Space out request *initiations* across threads by rate_limit_s, so
        concurrent workers overlap latency without bursting past the rate limit."""
        with self._throttle_lock:
            now = time.time()
            wait = self.rate_limit_s - (now - self._last_call)
            if wait < 0:
                wait = 0.0
            self._last_call = now + wait
        if wait > 0:
            time.sleep(wait)

    def _get(self, path: str, cache_key: str | None = None):
        url = f"{self.base_url}{path}"
        if cache_key is not None:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached
        if self.offline:
            return {}  # replay mode: cache only, never touch the network

        last_exc: Exception | None = None
        for attempt in range(4):
            self._throttle()
            try:
                resp = self._session.get(url, timeout=self.timeout_s)
                if resp.status_code in (429, 502, 503, 504):
                    time.sleep(1.5 * (attempt + 1))
                    continue
                resp.raise_for_status()
                data = resp.json()
                if cache_key is not None:
                    self.cache.put(cache_key, url, data)
                return data
            except requests.RequestException as exc:
                last_exc = exc
                time.sleep(1.0 * (attempt + 1))
        raise RuntimeError(f"Request failed after retries: {url}") from last_exc

    def address_tx_count(self, address: str) -> int:
        data = self._get(f"/address/{address}", cache_key=f"addr:{address}")
        return int(data.get("chain_stats", {}).get("tx_count", 0))

    def address_received(self, address: str) -> int | None:
        # Same cached /address response as address_tx_count -> no extra request.
        data = self._get(f"/address/{address}", cache_key=f"addr:{address}")
        return int(data.get("chain_stats", {}).get("funded_txo_sum", 0))

    def latest_block_height(self) -> int:
        resp = self._session.get(f"{self.base_url}/blocks/tip/height", timeout=self.timeout_s)
        resp.raise_for_status()
        return int(resp.text.strip())

    def get_block_transactions(self, height: int, max_txs: int = 25) -> list[Transaction]:
        resp = self._session.get(f"{self.base_url}/block-height/{height}", timeout=self.timeout_s)
        resp.raise_for_status()
        block_hash = resp.text.strip()
        txs: list[Transaction] = []
        start = 0
        while len(txs) < max_txs:
            page = self._get(
                f"/block/{block_hash}/txs/{start}", cache_key=f"blocktxs:{block_hash}:{start}"
            )
            if not page:
                break
            for raw in page:
                txs.append(self._parse_tx(raw))
                if len(txs) >= max_txs:
                    break
            if len(page) < 25:
                break
            start += len(page)
        return txs

    def get_mempool_transactions(self, max_txs: int = 10) -> list[Transaction]:
        resp = self._session.get(f"{self.base_url}/mempool/recent", timeout=self.timeout_s)
        resp.raise_for_status()
        recent = resp.json()
        txs: list[Transaction] = []
        for entry in recent[:max_txs]:
            txid = entry.get("txid")
            if not txid:
                continue
            try:
                raw = self._get(f"/tx/{txid}", cache_key=f"tx:{txid}")
                txs.append(self._parse_tx(raw))
            except Exception:
                continue
        return txs

    def get_transactions(self, address: str, max_txs: int = 200) -> list[Transaction]:
        txs: list[Transaction] = []
        last_seen: str | None = None
        while len(txs) < max_txs:
            if last_seen is None:
                page = self._get(f"/address/{address}/txs", cache_key=f"txs:{address}:first")
            else:
                page = self._get(
                    f"/address/{address}/txs/chain/{last_seen}",
                    cache_key=f"txs:{address}:after:{last_seen}",
                )
            if not page:
                break
            for raw in page:
                txs.append(self._parse_tx(raw))
                if len(txs) >= max_txs:
                    break
            if len(page) < _PAGE_SIZE:
                break
            last_seen = page[-1]["txid"]
        return txs

    @staticmethod
    def _parse_tx(raw: dict) -> Transaction:
        inputs = [
            TxInput(
                address=(vin.get("prevout") or {}).get("scriptpubkey_address"),
                value=int((vin.get("prevout") or {}).get("value", 0)),
                prev_txid=vin.get("txid"),
                prev_vout=vin.get("vout"),
            )
            for vin in raw.get("vin", [])
        ]
        outputs = [
            TxOutput(
                address=vout.get("scriptpubkey_address"),
                value=int(vout.get("value", 0)),
                index=idx,
            )
            for idx, vout in enumerate(raw.get("vout", []))
        ]
        status = raw.get("status", {})
        return Transaction(
            txid=raw["txid"],
            inputs=inputs,
            outputs=outputs,
            block_height=status.get("block_height"),
            block_time=status.get("block_time"),
            fee=raw.get("fee"),
        )
