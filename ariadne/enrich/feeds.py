"""Intelligence feeds — pull real attribution data into the label store.

Sources are public, keyless, and reputable:

  * OFAC-sanctioned crypto addresses — the 0xB10C mirror of the US Treasury SDN
    list (BTC / ETH / LTC / XMR / USDT-TRC20), refreshed daily -> SANCTIONED.
  * Ethereum scam / phishing darklist (MyEtherWallet/ethereum-lists) -> SCAM.

This is the "attribution data at scale" that turns an unlabelled *high-activity
address* into a named lead. It is a *starting* pipeline, not the millions of
human-verified labels a commercial vendor maintains — but it is real data from
authoritative sources, and it is the right shape to grow.
"""

from __future__ import annotations

import requests

from .labels import Label, LabelCategory

_TIMEOUT = 30
_UA = {"User-Agent": "Ariadne/0.1 (intel-feeds)"}

_OFAC_BASE = "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists"
_OFAC_FILES = {
    "XBT": "sanctioned_addresses_XBT.txt",
    "ETH": "sanctioned_addresses_ETH.txt",
    "LTC": "sanctioned_addresses_LTC.txt",
    "XMR": "sanctioned_addresses_XMR.txt",
    "USDT_TRC20": "sanctioned_addresses_USDT_TRC20.txt",
}
_SCAM_URL = "https://raw.githubusercontent.com/MyEtherWallet/ethereum-lists/master/src/addresses/addresses-darklist.json"
_RANSOMWHERE_URL = "https://api.ransomwhe.re/export"
_ETHERSCAN_LABELS_URL = "https://raw.githubusercontent.com/brianleect/etherscan-labels/main/data/etherscan/combined/combinedAllLabels.json"

_EXCHANGE_TAGS = {
    "binance", "coinbase", "kraken", "kucoin", "okx", "okex", "huobi", "htx", "gate.io", "gate",
    "bitfinex", "bybit", "crypto-com", "bitstamp", "gemini", "poloniex", "mexc", "bittrex",
    "upbit", "bithumb", "exchange",
}
_MIXER_TAGS = {"tornado-cash", "tornado", "mixer"}
_DEX_TAGS = {"uniswap", "sushiswap", "balancer", "curve-fi", "1inch", "0x-protocol", "pancakeswap", "dex"}
_BRIDGE_TAGS = {"bridge", "wormhole", "multichain", "stargate", "synapse", "celer", "hop-protocol", "across"}
# Tokens indicating a stablecoin issuer has frozen/blacklisted an address.
_FROZEN_TAGS = {"blocked", "frozen", "tether-banned", "usdt-banned", "blacklist", "blacklisted", "banned"}


def _get(url: str) -> requests.Response:
    resp = requests.get(url, timeout=_TIMEOUT, headers=_UA)
    resp.raise_for_status()
    return resp


def fetch_ofac() -> list[Label]:
    labels: list[Label] = []
    for asset, fname in _OFAC_FILES.items():
        try:
            text = _get(f"{_OFAC_BASE}/{fname}").text
        except Exception:
            continue
        for line in text.splitlines():
            addr = line.strip()
            if not addr or addr.startswith("#"):
                continue
            labels.append(
                Label(
                    address=addr,
                    category=LabelCategory.SANCTIONED,
                    name=f"OFAC-sanctioned ({asset})",
                    source="OFAC SDN (0xB10C mirror)",
                    description="On the US Treasury OFAC Specially Designated Nationals list.",
                )
            )
    return labels


def fetch_scams() -> list[Label]:
    labels: list[Label] = []
    try:
        data = _get(_SCAM_URL).json()
    except Exception:
        return labels
    for entry in data if isinstance(data, list) else []:
        addr = str(entry.get("address") or "").strip()
        if not addr:
            continue
        comment = str(entry.get("comment") or "").strip()[:160] or "known scam / phishing address"
        labels.append(
            Label(
                address=addr,
                category=LabelCategory.SCAM,
                name="Scam / phishing",
                source="ethereum-lists darklist",
                description=comment,
            )
        )
    return labels


def fetch_ransomware() -> list[Label]:
    labels: list[Label] = []
    try:
        data = _get(_RANSOMWHERE_URL).json()
    except Exception:
        return labels
    rows = data.get("result") if isinstance(data, dict) else None
    for entry in rows or []:
        addr = str(entry.get("address") or "").strip()
        if not addr:
            continue
        family = str(entry.get("family") or "ransomware").strip()[:60]
        labels.append(
            Label(
                address=addr,
                category=LabelCategory.RANSOMWARE,
                name=f"Ransomware: {family}",
                source="Ransomwhere",
                description="Crowdsourced ransomware payment address.",
            )
        )
    return labels


def fetch_exchanges() -> list[Label]:
    """Named exchanges / mixers / DEXes from the public Etherscan-labels mirror.

    This is the attribution data that lets a trace NAME a cash-out (e.g. 'Binance
    hot wallet') instead of stopping at 'unlabelled high-activity address'.
    """
    labels: list[Label] = []
    try:
        data = _get(_ETHERSCAN_LABELS_URL).json()
    except Exception:
        return labels
    if not isinstance(data, dict):
        return labels
    for addr, info in data.items():
        if not isinstance(info, dict):
            continue
        tags = {str(t).lower() for t in (info.get("labels") or [])}
        name = str(info.get("name") or "").strip()
        if tags & _FROZEN_TAGS:
            category = LabelCategory.FROZEN
        elif tags & _EXCHANGE_TAGS:
            category = LabelCategory.EXCHANGE
        elif tags & _MIXER_TAGS:
            category = LabelCategory.MIXER
        elif tags & _BRIDGE_TAGS:
            category = LabelCategory.BRIDGE
        elif tags & _DEX_TAGS:
            category = LabelCategory.DEX
        else:
            continue
        labels.append(
            Label(
                address=addr,
                category=category,
                name=name or sorted(tags)[0],
                source="etherscan-labels",
                description="Public Etherscan address label.",
            )
        )
    return labels


def fetch_frozen() -> list[Label]:
    """Addresses frozen / blacklisted by a stablecoin issuer (Tether / Circle).

    A frozen address is a very strong signal — the issuer only freezes funds on a
    law-enforcement request or confirmed fraud. Sourced from the live etherscan-
    labels dataset filtered for freeze/block tags (real data from a live source,
    so this never becomes hollow surface even as the tag set evolves).
    """
    labels: list[Label] = []
    try:
        data = _get(_ETHERSCAN_LABELS_URL).json()
    except Exception:
        return labels
    if not isinstance(data, dict):
        return labels
    for addr, info in data.items():
        if not isinstance(info, dict):
            continue
        tags = {str(t).lower() for t in (info.get("labels") or [])}
        if tags & _FROZEN_TAGS:
            labels.append(
                Label(
                    address=addr,
                    category=LabelCategory.FROZEN,
                    name=str(info.get("name") or "").strip() or "Frozen / blacklisted",
                    source="etherscan-labels (issuer freeze)",
                    description="Frozen or blacklisted by a stablecoin issuer.",
                )
            )
    return labels


def fetch_all() -> list[Label]:
    return fetch_ofac() + fetch_scams() + fetch_ransomware() + fetch_exchanges()
