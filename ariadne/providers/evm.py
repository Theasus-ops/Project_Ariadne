"""EVM chain registry — the account-model chains Ariadne can trace.

Investment-scam ("pig-butchering") money does not stay on Ethereum. It moves as
USDT/USDC across the low-fee L2s and sidechains — **Polygon, Arbitrum, Base,
Optimism**. Every one of these exposes the same Etherscan-compatible API on a
public, keyless Blockscout instance, so the existing :class:`EthereumProvider`
traces them unchanged once pointed at the right endpoint and token contract.

Each entry is ``chain-code -> (blockscout base_url, asset symbol, decimals,
token_contract | None)``. Every Blockscout endpoint and every stablecoin contract
here was **verified live** (real, active, correct address) before inclusion — no
hollow chains, and never a look-alike scam token. BSC is deliberately absent: it
has no stable keyless Etherscan-compatible endpoint (BscScan needs an API key).
"""

from __future__ import annotations

_ETH = "https://eth.blockscout.com"
_POLY = "https://polygon.blockscout.com"
_ARB = "https://arbitrum.blockscout.com"
_BASE = "https://base.blockscout.com"
_OP = "https://optimism.blockscout.com"

# code -> (base_url, asset_symbol, decimals, token_contract or None for native)
EVM_CHAINS: dict[str, tuple[str, str, int, str | None]] = {
    # Ethereum mainnet (contracts resolved by EthereumProvider's built-in map).
    "eth":       (_ETH, "ETH", 18, None),
    "usdt":      (_ETH, "USDT", 6, "0xdac17f958d2ee523a2206206994597c13d831ec7"),
    "usdc":      (_ETH, "USDC", 6, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
    # Polygon
    "pol":       (_POLY, "POL", 18, None),
    "usdt-pol":  (_POLY, "USDT", 6, "0xc2132D05D31c914a87C6611C10748AEb04B58e8F"),
    "usdc-pol":  (_POLY, "USDC", 6, "0x3c499c542cEF5E3811e1192ce70d8cc03d5c3359"),
    # Arbitrum One
    "arb":       (_ARB, "ETH", 18, None),
    "usdt-arb":  (_ARB, "USDT", 6, "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9"),
    "usdc-arb":  (_ARB, "USDC", 6, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
    # Base
    "base":      (_BASE, "ETH", 18, None),
    "usdc-base": (_BASE, "USDC", 6, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
    # Optimism
    "op":        (_OP, "ETH", 18, None),
    "usdt-op":   (_OP, "USDT", 6, "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58"),
    "usdc-op":   (_OP, "USDC", 6, "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"),
}

# All EVM chain codes validate as a 0x-address (handled by is_valid_address("eth")).
EVM_CODES = frozenset(EVM_CHAINS)


def is_evm(code: str) -> bool:
    return code.lower() in EVM_CODES


def build_evm_provider(code: str, cache=None, proxies: dict | None = None, base_url: str | None = None):
    """Construct an EthereumProvider for any registered EVM chain code."""
    from .ethereum import EthereumProvider

    url, symbol, decimals, contract = EVM_CHAINS[code.lower()]
    return EthereumProvider(
        asset=symbol,
        cache=cache,
        base_url=base_url or url,
        proxies=proxies,
        token_contract=contract,
        asset_decimals=decimals,
    )
