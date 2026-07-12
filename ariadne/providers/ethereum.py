"""Ethereum / EVM data via the Blockscout Etherscan-compatible API (keyless).

Traces native ETH or a single ERC-20 token (default USDT -- where most
investment-scam money actually moves). Ethereum is account-model, so each
transfer is mapped onto the same Transaction(inputs, outputs) shape the tracer
already understands: one from-address input and one to-address output. That lets
the whole engine -- tracing, taint, patterns, reporting -- work unchanged.
"""

from __future__ import annotations

import threading
import time

import requests

from ..cache import ProvenanceCache
from ..models import ETH, USDC, USDT, Transaction, TxInput, TxOutput
from .base import Provider

# Canonical mainnet contracts (lowercased) for supported tokens.
_KNOWN_TOKENS = {
    "USDT": ("0xdac17f958d2ee523a2206206994597c13d831ec7", USDT),
    "USDC": ("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", USDC),
}


class EthereumProvider(Provider):
    name = "blockscout-eth"

    def __init__(
        self,
        asset: str = "USDT",
        cache: ProvenanceCache | None = None,
        base_url: str = "https://eth.blockscout.com",
        rate_limit_s: float = 0.25,
        timeout_s: float = 30.0,
        proxies: dict | None = None,
    ) -> None:
        self.asset_symbol = asset.upper()
        if self.asset_symbol == "ETH":
            self.token_contract: str | None = None
            self.asset_info = ETH
        elif self.asset_symbol in _KNOWN_TOKENS:
            self.token_contract, self.asset_info = _KNOWN_TOKENS[self.asset_symbol]
        else:
            raise ValueError(f"Unsupported EVM asset: {asset!r} (try ETH, USDT, USDC)")

        self.base_url = base_url.rstrip("/")
        self.cache = cache or ProvenanceCache()
        self.rate_limit_s = rate_limit_s
        self.timeout_s = timeout_s
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Ariadne/0.1 (blockchain-tracer)"})
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

    def _get(self, url: str, cache_key: str):
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
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
                self.cache.put(cache_key, url, data)
                return data
            except requests.RequestException as exc:
                last_exc = exc
                time.sleep(1.0 * (attempt + 1))
        raise RuntimeError(f"Request failed after retries: {url}") from last_exc

    def address_tx_count(self, address: str) -> int:
        address = self.normalize(address)
        url = f"{self.base_url}/api/v2/addresses/{address}/counters"
        try:
            data = self._get(url, f"eth:counters:{address}")
        except Exception:
            return 0
        key = "token_transfers_count" if self.token_contract else "transactions_count"
        try:
            return int(data.get(key, 0))
        except (TypeError, ValueError):
            return 0

    def address_received(self, address: str, scan: int = 500) -> int | None:
        """All-time received, summed from inbound transfers (haircut denominator).

        The account model exposes no single "total received" field cheaply, so we
        sum the value of transfers *to* the address over a bounded scan of its most
        recent history. This is an approximation (it can undercount a very active
        address), but it replaces the old fall-back that pinned EVM taint near 1.0
        — a real denominator now dilutes mixed funds on ETH/USDT/USDC.
        """
        address = self.normalize(address)
        try:
            txs = self.get_transactions(address, max_txs=scan)
        except Exception:
            return None
        total = sum(o.value for tx in txs for o in tx.outputs if o.address == address)
        return total or None

    def get_transactions(self, address: str, max_txs: int = 200) -> list[Transaction]:
        address = self.normalize(address)
        if self.token_contract:
            return self._paged(address, max_txs, token=True)
        return self._paged(address, max_txs, token=False)

    def _paged(self, address: str, max_txs: int, token: bool) -> list[Transaction]:
        txs: list[Transaction] = []
        page = 1
        while len(txs) < max_txs:
            offset = min(100, max_txs - len(txs))
            if token:
                url = (
                    f"{self.base_url}/api?module=account&action=tokentx"
                    f"&contractaddress={self.token_contract}&address={address}"
                    f"&page={page}&offset={offset}&sort=desc"
                )
                key = f"eth:tokentx:{self.asset_symbol}:{address}:{page}:{offset}"
            else:
                url = (
                    f"{self.base_url}/api?module=account&action=txlist"
                    f"&address={address}&page={page}&offset={offset}&sort=desc"
                )
                key = f"eth:txlist:{address}:{page}:{offset}"

            data = self._get(url, key)
            rows = data.get("result")
            if not isinstance(rows, list) or not rows:
                break
            for row in rows:
                if token and row.get("contractAddress", "").lower() != self.token_contract:
                    continue
                if not token and row.get("isError") == "1":
                    continue
                if int(row.get("value", "0")) == 0:
                    continue
                txs.append(self._row_to_tx(row))
            if len(rows) < offset:
                break
            page += 1
        return txs

    def latest_block_height(self) -> int:
        try:
            data = self._get(
                f"{self.base_url}/api?module=proxy&action=eth_blockNumber",
                "eth:blockheight",
            )
        except Exception:
            return 0
        return self._parse_int(data.get("result"))

    def get_block_transactions(self, height: int, max_txs: int = 25) -> list[Transaction]:
        try:
            data = self._get(
                f"{self.base_url}/api?module=proxy&action=eth_getBlockByNumber&tag={hex(height)}&boolean=false",
                f"eth:block:{height}",
            )
        except Exception:
            return []

        result = data.get("result") or {}
        txs = result.get("transactions") or []
        out: list[Transaction] = []
        for raw in txs[:max_txs]:
            if not isinstance(raw, dict):
                continue
            out.append(self._row_to_tx(raw))
        return out

    def get_mempool_transactions(self, max_txs: int = 10) -> list[Transaction]:
        try:
            data = self._get(
                f"{self.base_url}/api?module=proxy&action=txpool_content",
                "eth:mempool",
            )
        except Exception:
            return []

        result = data.get("result") or {}
        buckets = []
        if isinstance(result.get("pending"), dict):
            buckets.append(result["pending"])
        if isinstance(result.get("queued"), dict):
            buckets.append(result["queued"])

        txs: list[Transaction] = []
        for bucket in buckets:
            for txid, raw in bucket.items():
                if isinstance(raw, dict):
                    txs.append(self._row_to_tx({**raw, "hash": txid}))
                else:
                    txs.append(Transaction(txid=txid, inputs=[], outputs=[]))
                if len(txs) >= max_txs:
                    return txs
        return txs

    @staticmethod
    def _parse_int(value) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            text = value.strip()
            if text.startswith(("0x", "0X")):
                try:
                    return int(text, 16)
                except ValueError:
                    pass
            try:
                return int(text)
            except ValueError:
                pass
        return 0

    def _row_to_tx(self, row: dict) -> Transaction:
        value = self._parse_int(row.get("value", "0"))
        ts = self._parse_int(row.get("timeStamp"))
        block = self._parse_int(row.get("blockNumber"))
        return Transaction(
            txid=row.get("hash", ""),
            inputs=[TxInput(address=self.normalize(row.get("from", "")), value=value)],
            outputs=[TxOutput(address=self.normalize(row.get("to", "")), value=value, index=0)],
            block_height=block or None,
            block_time=ts or None,
        )
