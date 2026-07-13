"""Core data model for Ariadne.

Amounts are integers in the chain's smallest unit. For Bitcoin that is the
satoshi (1 BTC = 100,000,000 sat). Keeping money as integers avoids float error,
which matters when a trace may become evidence.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

SATS_PER_BTC = 100_000_000

_BTC_RE = re.compile(r"^(bc1[a-z0-9]{20,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})$")
_ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_LTC_RE = re.compile(r"^(ltc1[a-z0-9]{20,87}|[LM3][a-km-zA-HJ-NP-Z1-9]{25,39})$")
_DOGE_RE = re.compile(r"^(D|A|9)[A-Za-z0-9]{25,39}$")
_XMR_RE = re.compile(r"^(4|8)[0-9A-Za-z]{94,}$")
_TRX_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")


# EVM chain codes (Ethereum + L2s/sidechains) all use 0x-hex addresses.
_EVM_CHAINS = {
    "eth", "usdt", "usdc",
    "pol", "usdt-pol", "usdc-pol", "arb", "usdt-arb", "usdc-arb",
    "base", "usdc-base", "op", "usdt-op", "usdc-op",
}

# Chains with a UTXO model, where output-level ("utxo-*") taint applies. The
# single source of truth shared by the CLI, the web API and replay.
UTXO_CHAINS = {"btc", "ltc", "doge"}


def is_valid_address(address: str, chain: str = "") -> bool:
    """Validate an address for a chain. Rejects malformed / injection input."""
    address = (address or "").strip()
    if len(address) > 120:
        return False
    chain = (chain or "").lower()
    if chain in _EVM_CHAINS:
        return bool(_ETH_RE.match(address))
    if chain == "btc":
        return bool(_BTC_RE.match(address))
    if chain == "ltc":
        return bool(_LTC_RE.match(address))
    if chain == "doge":
        return bool(_DOGE_RE.match(address))
    if chain == "xmr":
        return bool(_XMR_RE.match(address))
    if chain in ("trx", "tron"):
        return bool(_TRX_RE.match(address))
    return bool(
        _BTC_RE.match(address) or _ETH_RE.match(address) or _LTC_RE.match(address)
        or _DOGE_RE.match(address) or _XMR_RE.match(address) or _TRX_RE.match(address)
    )


@dataclass(frozen=True)
class Asset:
    """A traceable asset and its smallest-unit precision (BTC=8, ETH=18, USDT=6)."""

    symbol: str
    decimals: int

    def to_units(self, value: int) -> float:
        return value / (10 ** self.decimals)

    def format(self, value: int) -> str:
        places = min(self.decimals, 8)
        return f"{value / (10 ** self.decimals):.{places}f}"


BTC = Asset("BTC", 8)
ETH = Asset("ETH", 18)
USDT = Asset("USDT", 6)
USDC = Asset("USDC", 6)
LTC = Asset("LTC", 8)
DOGE = Asset("DOGE", 8)
XMR = Asset("XMR", 12)


class NodeType(str, Enum):
    SEED = "seed"        # the address the trace started from
    ADDRESS = "address"  # an ordinary address reached during tracing
    SERVICE = "service"  # high-activity address: likely exchange/mixer (a cash-out point)


@dataclass(frozen=True)
class TxInput:
    address: Optional[str]  # None for non-standard scripts we cannot attribute
    value: int              # smallest unit (sat)
    prev_txid: Optional[str] = None
    prev_vout: Optional[int] = None


@dataclass(frozen=True)
class TxOutput:
    address: Optional[str]
    value: int              # smallest unit (sat)
    index: int = 0


@dataclass
class Transaction:
    txid: str
    inputs: list[TxInput]
    outputs: list[TxOutput]
    block_height: Optional[int] = None
    block_time: Optional[int] = None  # unix seconds
    fee: Optional[int] = None
    metadata: Optional[dict] = None

    def input_addresses(self) -> set[str]:
        return {i.address for i in self.inputs if i.address}

    def spends_from(self, address: str) -> bool:
        return address in self.input_addresses()


@dataclass
class FlowEdge:
    """Aggregated value flow from one address to another across one or more txs."""

    src: str
    dst: str
    value: int = 0
    txids: list[str] = field(default_factory=list)
    first_time: Optional[int] = None  # earliest block_time seen on this flow (for FIFO ordering)
    dirty_value: int = 0              # tainted portion of `value` (set by the taint engine)

    def add(self, value: int, txid: str) -> None:
        self.value += value
        if txid not in self.txids:
            self.txids.append(txid)

    def observe_time(self, block_time: Optional[int]) -> None:
        if block_time is None:
            return
        if self.first_time is None or block_time < self.first_time:
            self.first_time = block_time


@dataclass
class TraceNode:
    address: str
    node_type: NodeType
    depth: int
    tx_count: int = 0
    note: str = ""
    # attribution (Phase 4)
    label_name: str = ""
    label_category: str = ""
    label_source: str = ""
    # taint (Phase 3)
    taint_fraction: float = 0.0
    dirty_received: int = 0
    total_received: int = 0  # all-time on-chain received (haircut denominator)
    # counter-laundering
    entered_mixer: bool = False


@dataclass
class TraceResult:
    seed: str
    direction: str  # "forward" or "backward"
    params: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    asset: Asset = field(default_factory=lambda: BTC)
    nodes: dict[str, TraceNode] = field(default_factory=dict)
    edges: dict[tuple[str, str], FlowEdge] = field(default_factory=dict)
    mixing_events: list = field(default_factory=list)
    taint_model: str = "haircut"  # which taint methodology produced the numbers below
    coverage: dict = field(default_factory=dict)  # considered vs kept outflow (trace completeness)
    # Raw transactions retained during the trace (txid -> Transaction), populated only
    # when the tracer runs with collect_transactions=True. Feeds the UTXO-level taint
    # engine; not serialised into the report, so it never affects the evidence digest.
    transactions: dict = field(default_factory=dict)

    def add_node(self, node: TraceNode) -> None:
        existing = self.nodes.get(node.address)
        if existing is None or node.depth < existing.depth:
            self.nodes[node.address] = node

    def edge(self, src: str, dst: str) -> FlowEdge:
        key = (src, dst)
        e = self.edges.get(key)
        if e is None:
            e = FlowEdge(src, dst)
            self.edges[key] = e
        return e

    def services(self) -> list[TraceNode]:
        return [n for n in self.nodes.values() if n.node_type == NodeType.SERVICE]
