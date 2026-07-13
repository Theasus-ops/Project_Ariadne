"""Deployment configuration — opsec, self-hosting, and honest chain gating.

Three operational concerns a serious deployment has that a demo does not:

1. **Opsec.** Every query to a public explorer (blockstream.info, blockscout,
   tronscan) tells that third party which addresses your investigation cares
   about — a leak of the investigation itself. Two mitigations, both configurable
   here and applied to *all* provider traffic:
     * a **SOCKS/HTTP proxy** (e.g. ``socks5h://127.0.0.1:9050`` for Tor) so
       queries do not originate from your network; and
     * **self-hosted endpoints** — point each chain at your own indexer
       (electrs/esplora, Blockscout, a Tron node) so no third party sees anything
       and there is no rate limit.

2. **Self-hosting.** ``endpoints`` overrides the base URL per chain; the provider
   API is otherwise unchanged, so an esplora-compatible self-hosted node is a drop-in.

3. **Honest gating.** Chains that only work with a paid key (LTC/DOGE via
   Blockchair) or are not address-traceable at all (Monero) are **disabled by
   default** — offering a chain that silently returns nothing is worse than not
   offering it. Enable explicitly once you have provisioned the data.

Config precedence: environment variable > config file (``ariadne.config.json`` or
``$ARIADNE_CONFIG``) > built-in default. Environment keys are ``ARIADNE_<KEY>``;
per-chain endpoints are ``ARIADNE_ENDPOINT_<CHAIN>``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# Validated, keyless, working out of the box (Bitcoin, Tron, and the EVM chains).
_EVM = {
    "eth", "usdt", "usdc",
    "pol", "usdt-pol", "usdc-pol", "arb", "usdt-arb", "usdc-arb",
    "base", "usdc-base", "op", "usdt-op", "usdc-op",
}
WORKING_CHAINS = {"btc", "trx"} | _EVM
# Need a key (LTC/DOGE) or not traceable by design (XMR) -> gated off by default.
GATED_CHAINS = {"ltc", "doge", "xmr"}
ALL_CHAINS = WORKING_CHAINS | GATED_CHAINS


def _load_file() -> dict:
    path = Path(os.environ.get("ARIADNE_CONFIG", "ariadne.config.json"))
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def _file() -> dict:
    # Read fresh each call so tests / long-running processes see updates.
    return _load_file()


def _get(key: str, default=None):
    env = os.environ.get("ARIADNE_" + key.upper())
    if env is not None:
        return env
    return _file().get(key, default)


def proxy() -> dict | None:
    """Requests-style proxy mapping for all provider traffic, or None."""
    p = _get("proxy")
    if not p:
        return None
    return {"http": p, "https": p}


def endpoint(chain: str) -> str | None:
    """Self-hosted base URL override for a chain, or None to use the default."""
    chain = chain.lower()
    env = os.environ.get(f"ARIADNE_ENDPOINT_{chain.upper()}")
    if env:
        return env
    endpoints = _file().get("endpoints", {})
    return endpoints.get(chain) if isinstance(endpoints, dict) else None


def blockchair_key() -> str | None:
    return _get("blockchair_api_key") or os.environ.get("BLOCKCHAIR_API_KEY")


def _extra_enabled() -> set[str]:
    raw = _get("enable_chains") or ""
    if isinstance(raw, (list, tuple, set)):
        return {str(c).lower() for c in raw}
    return {c.strip().lower() for c in str(raw).split(",") if c.strip()}


def enabled_chains() -> set[str]:
    enabled = set(WORKING_CHAINS)
    enabled |= _extra_enabled() & ALL_CHAINS
    if blockchair_key():
        enabled |= {"ltc", "doge"}
    return enabled


def is_enabled(chain: str) -> bool:
    return chain.lower() in enabled_chains()


def gating_message(chain: str) -> str:
    chain = chain.lower()
    if chain in ("ltc", "doge"):
        return (
            f"chain '{chain}' is disabled: Blockchair rate-limits/blocks it without an API key. "
            f"Set BLOCKCHAIR_API_KEY, or ARIADNE_ENABLE_CHAINS={chain} to force it on."
        )
    if chain == "xmr":
        return (
            "chain 'xmr' is disabled: Monero is privacy-preserving and not address-traceable by "
            "design. Enable with ARIADNE_ENABLE_CHAINS=xmr only for the honest no-op."
        )
    return f"chain '{chain}' is not enabled (set ARIADNE_ENABLE_CHAINS={chain})."


def require_enabled(chain: str) -> None:
    if not is_enabled(chain):
        raise ValueError(gating_message(chain))


def provider_kwargs(chain: str) -> dict:
    """base_url / proxies / api_key overrides to pass into a provider constructor."""
    kwargs: dict = {}
    ep = endpoint(chain)
    if ep:
        kwargs["base_url"] = ep
    px = proxy()
    if px:
        kwargs["proxies"] = px
    if chain.lower() in ("ltc", "doge") and blockchair_key():
        kwargs["api_key"] = blockchair_key()
    return kwargs


def describe() -> dict:
    return {
        "enabled_chains": sorted(enabled_chains()),
        "gated_off": sorted(ALL_CHAINS - enabled_chains()),
        "proxy": _get("proxy"),
        "endpoints": {c: endpoint(c) for c in ALL_CHAINS if endpoint(c)},
        "blockchair_key_set": bool(blockchair_key()),
        "config_file": os.environ.get("ARIADNE_CONFIG", "ariadne.config.json"),
    }
