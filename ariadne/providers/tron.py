"""Tron TRC-20 USDT provider via the public TronScan API (keyless).

USDT-on-Tron is the dominant settlement rail for investment-scam ("pig
butchering") money. TronScan exposes TRC-20 transfers per address, which map onto
the same account-model Transaction shape (one from-input, one to-output) the
tracer already understands.
"""

from __future__ import annotations

import threading
import time

import requests

from ..cache import ProvenanceCache
from ..models import USDT, Transaction, TxInput, TxOutput
from .base import Provider

# Tether (USDT) TRC-20 contract on Tron.
_USDT_TRC20 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


class TronProvider(Provider):
    name = "tronscan"

    def __init__(
        self,
        cache: ProvenanceCache | None = None,
        base_url: str = "https://apilist.tronscanapi.com",
        rate_limit_s: float = 0.3,
        timeout_s: float = 30.0,
        proxies: dict | None = None,
    ) -> None:
        self.asset_info = USDT
        self.contract = _USDT_TRC20
        self.base_url = base_url.rstrip("/")
        self.cache = cache or ProvenanceCache()
        self.rate_limit_s = rate_limit_s
        self.timeout_s = timeout_s
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Ariadne/0.1 (tron-tracer)"})
        if proxies:
            self._session.proxies.update(proxies)
        self._last_call = 0.0
        self._throttle_lock = threading.Lock()

    def _throttle(self) -> None:
        with self._throttle_lock:
            now = time.time()
            wait = self.rate_limit_s - (now - self._last_call)
            if wait < 0:
                wait = 0.0
            self._last_call = now + wait
        if wait > 0:
            time.sleep(wait)

    def _get(self, path: str, cache_key: str):
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        last_exc: Exception | None = None
        for attempt in range(4):
            self._throttle()
            try:
                resp = self._session.get(f"{self.base_url}{path}", timeout=self.timeout_s)
                if resp.status_code in (429, 502, 503, 504):
                    time.sleep(1.5 * (attempt + 1))
                    continue
                resp.raise_for_status()
                data = resp.json()
                self.cache.put(cache_key, f"{self.base_url}{path}", data)
                return data
            except requests.RequestException as exc:
                last_exc = exc
                time.sleep(1.0 * (attempt + 1))
        raise RuntimeError(f"Tron request failed: {path}") from last_exc

    def _transfers_path(self, address: str, start: int, limit: int) -> str:
        return (
            f"/api/token_trc20/transfers?limit={limit}&start={start}"
            f"&relatedAddress={address}&contract_address={self.contract}"
        )

    def address_tx_count(self, address: str) -> int:
        data = self._get(self._transfers_path(address, 0, 1), f"trx:count:{address}")
        try:
            return int(data.get("total", 0))
        except (TypeError, ValueError):
            return 0

    def address_received(self, address: str, scan: int = 500) -> int | None:
        """All-time USDT received, summed from inbound TRC-20 transfers.

        As with Ethereum, Tron exposes no cheap total-received field, so we sum
        transfers *to* the address over a bounded scan. Gives the taint haircut a
        real denominator instead of the old traced-inflow fall-back.
        """
        try:
            txs = self.get_transactions(address, max_txs=scan)
        except Exception:
            return None
        total = sum(o.value for tx in txs for o in tx.outputs if o.address == address)
        return total or None

    def get_transactions(self, address: str, max_txs: int = 200) -> list[Transaction]:
        txs: list[Transaction] = []
        start = 0
        while len(txs) < max_txs:
            n = min(50, max_txs - len(txs))
            data = self._get(self._transfers_path(address, start, n), f"trx:transfers:{address}:{start}:{n}")
            rows = data.get("token_transfers")
            if not isinstance(rows, list) or not rows:
                break
            for r in rows:
                if r.get("contract_address") != self.contract:
                    continue
                if r.get("finalResult") not in (None, "SUCCESS") or r.get("contractRet") not in (None, "SUCCESS"):
                    continue
                txs.append(self._row_to_tx(r))
            if len(rows) < n:
                break
            start += len(rows)
        return txs

    @staticmethod
    def _row_to_tx(r: dict) -> Transaction:
        try:
            value = int(r.get("quant", "0") or 0)
        except (TypeError, ValueError):
            value = 0
        ts = r.get("block_ts")
        return Transaction(
            txid=r.get("transaction_id", ""),
            inputs=[TxInput(address=r.get("from_address"), value=value)],
            outputs=[TxOutput(address=r.get("to_address"), value=value, index=0)],
            block_height=r.get("block"),
            block_time=int(ts / 1000) if isinstance(ts, (int, float)) else None,
        )
