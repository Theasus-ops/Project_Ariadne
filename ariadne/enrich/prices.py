"""Fiat valuation — put money in the currency investigators, courts, and warrants use.

A trace that says "17.7 BTC left this wallet" is far less actionable than one that
says "≈ $1.2M (€1.1M) at the time it moved." This module values on-chain amounts in
USD and EUR, at the **time of movement** where a timestamp is available (forensically
what matters — a 2021 ransom was worth what BTC cost in 2021, not today), falling
back to the current price otherwise.

All sources are public and keyless:
  * **Binance klines** — historical daily close for BTC/ETH/LTC/DOGE (USDT pairs);
    `ticker/price` for the current spot.
  * **Frankfurter** (ECB reference rates) — historical/current USD→EUR.
  * Stablecoins (USDT/USDC) are pinned to $1.00.

Results are cached per (symbol, date) in a small SQLite so a trace over a bounded
set of dates costs a bounded number of requests, and a failed lookup degrades to
``None`` rather than crashing an investigation.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import requests

_BINANCE_PAIR = {
    "BTC": "BTCUSDT", "ETH": "ETHUSDT", "LTC": "LTCUSDT", "DOGE": "DOGEUSDT",
    "XMR": "XMRUSDT", "POL": "POLUSDT", "MATIC": "MATICUSDT",
}
_STABLE = {"USDT": 1.0, "USDC": 1.0, "DAI": 1.0}
_UA = {"User-Agent": "Ariadne/0.4 (fiat-valuation)"}


def _day(ts: int | None) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc) if ts else datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%d")


class PriceOracle:
    def __init__(self, path: str | Path = "knowledge/prices.sqlite", timeout_s: float = 20.0) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS prices (symbol TEXT, day TEXT, usd REAL, PRIMARY KEY (symbol, day));
            CREATE TABLE IF NOT EXISTS fx (day TEXT PRIMARY KEY, eur_per_usd REAL);
            """
        )
        self._conn.commit()
        self.timeout_s = timeout_s
        self._session = requests.Session()
        self._session.headers.update(_UA)

    # ---- USD spot / historical ----
    def usd_price(self, symbol: str, ts: int | None = None) -> float | None:
        symbol = symbol.upper()
        if symbol in _STABLE:
            return _STABLE[symbol]
        pair = _BINANCE_PAIR.get(symbol)
        if pair is None:
            return None
        day = _day(ts)
        row = self._conn.execute("SELECT usd FROM prices WHERE symbol=? AND day=?", (symbol, day)).fetchone()
        if row is not None:
            return row[0]
        price = self._fetch_usd(pair, ts)
        if price is not None:
            self._conn.execute("INSERT OR REPLACE INTO prices (symbol, day, usd) VALUES (?,?,?)", (symbol, day, price))
            self._conn.commit()
        return price

    def _fetch_usd(self, pair: str, ts: int | None) -> float | None:
        try:
            if ts is None:
                r = self._session.get("https://api.binance.com/api/v3/ticker/price",
                                      params={"symbol": pair}, timeout=self.timeout_s)
                r.raise_for_status()
                return float(r.json()["price"])
            start = int(datetime.strptime(_day(ts), "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()) * 1000
            r = self._session.get("https://api.binance.com/api/v3/klines",
                                  params={"symbol": pair, "interval": "1d", "startTime": start, "limit": 1},
                                  timeout=self.timeout_s)
            r.raise_for_status()
            data = r.json()
            return float(data[0][4]) if data else None  # daily close
        except Exception:
            return None

    # ---- USD -> EUR ----
    def usd_to_eur(self, ts: int | None = None) -> float | None:
        day = _day(ts)
        row = self._conn.execute("SELECT eur_per_usd FROM fx WHERE day=?", (day,)).fetchone()
        if row is not None:
            return row[0]
        rate = self._fetch_fx(ts)
        if rate is not None:
            self._conn.execute("INSERT OR REPLACE INTO fx (day, eur_per_usd) VALUES (?,?)", (day, rate))
            self._conn.commit()
        return rate

    def _fetch_fx(self, ts: int | None) -> float | None:
        try:
            endpoint = f"https://api.frankfurter.app/{_day(ts)}" if ts else "https://api.frankfurter.app/latest"
            r = self._session.get(endpoint, params={"from": "USD", "to": "EUR"}, timeout=self.timeout_s)
            r.raise_for_status()
            return float(r.json()["rates"]["EUR"])
        except Exception:
            return None

    # ---- valuation ----
    def value(self, symbol: str, amount_units: float, ts: int | None = None) -> dict:
        usd_rate = self.usd_price(symbol, ts)
        if usd_rate is None:
            return {"usd": None, "eur": None, "at": _day(ts), "usd_rate": None}
        usd = amount_units * usd_rate
        eur_rate = self.usd_to_eur(ts)
        return {
            "usd": round(usd, 2),
            "eur": round(usd * eur_rate, 2) if eur_rate is not None else None,
            "at": _day(ts),
            "usd_rate": round(usd_rate, 6),
        }

    def close(self) -> None:
        self._conn.close()


def _min_edge_time(report: dict, address: str, side: str) -> int | None:
    key = "dst" if side == "in" else "src"
    times = [e.get("first_time") for e in report.get("edges", []) if e.get(key) == address and e.get("first_time")]
    return min(times) if times else None


def enrich_prices(report: dict, oracle: PriceOracle) -> dict:
    """Annotate a report with USD/EUR values at the time funds moved. In place."""
    symbol = report.get("asset", "")
    seed = report.get("trace", {}).get("seed", "")

    total_cashout_usd = 0.0
    total_cashout_eur = 0.0
    have_eur = True
    for node in report.get("nodes", []):
        addr = node["address"]
        when = _min_edge_time(report, addr, "out" if addr == seed else "in")
        val = oracle.value(symbol, float(node.get("dirty_received") or 0), when)
        node["value_usd"] = val["usd"]
        node["value_eur"] = val["eur"]
        node["value_at"] = val["at"]
        if node.get("type") == "service" and val["usd"]:
            total_cashout_usd += val["usd"]
            if val["eur"] is not None:
                total_cashout_eur += val["eur"]
            else:
                have_eur = False

    seed_node = next((n for n in report.get("nodes", []) if n["address"] == seed), None)
    seed_val = {"usd": None, "eur": None}
    if seed_node is not None:
        seed_val = {"usd": seed_node.get("value_usd"), "eur": seed_node.get("value_eur")}

    # Fold values into the findings too (they mirror nodes by address).
    node_by_addr = {n["address"]: n for n in report.get("nodes", [])}
    for f in report.get("findings", []):
        n = node_by_addr.get(f["address"])
        if n is not None:
            f["value_usd"] = n.get("value_usd")
            f["value_eur"] = n.get("value_eur")

    report["valuation"] = {
        "currency": "USD/EUR",
        "seed_disbursed_usd": seed_val["usd"],
        "seed_disbursed_eur": seed_val["eur"],
        "total_cashout_usd": round(total_cashout_usd, 2) if total_cashout_usd else None,
        "total_cashout_eur": round(total_cashout_eur, 2) if (total_cashout_eur and have_eur) else None,
        "note": "Valued at the daily price on the date funds moved where a timestamp exists, else current spot.",
    }
    return report
