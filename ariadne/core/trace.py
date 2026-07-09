"""Multi-hop value-flow tracer.

Forward tracing answers "where did the money go?": for each address, we look at
the transactions where it SPENDS and follow the value to the receiving addresses,
up to a chosen number of hops.

High-activity addresses (tx_count above a threshold) are treated as terminal
SERVICE nodes -- almost always exchanges or mixers. These are the cash-out points
an investigator actually cares about, and expanding them is both meaningless
(a service commingles everyone's funds) and infeasible (millions of txs). So we
flag them and stop.
"""

from __future__ import annotations

from collections import deque

from ..enrich.labels import LabelCategory, LabelStore
from ..models import SATS_PER_BTC, NodeType, TraceNode, TraceResult
from ..providers.base import Provider
from .coinjoin import classify as classify_coinjoin

_SERVICE_CATEGORIES = {
    LabelCategory.EXCHANGE,
    LabelCategory.MIXER,
    LabelCategory.SERVICE,
    LabelCategory.DEX,
    LabelCategory.BRIDGE,
}


class Tracer:
    def __init__(
        self,
        provider: Provider,
        service_tx_threshold: int = 3000,
        max_txs_per_address: int = 200,
        label_store: LabelStore | None = None,
    ) -> None:
        self.provider = provider
        self.service_tx_threshold = service_tx_threshold
        self.max_txs_per_address = max_txs_per_address
        self.label_store = label_store

    def _stats(self, address: str) -> tuple[int, int]:
        """Address activity + total-received, resilient to provider failures."""
        try:
            tx_count = self.provider.address_tx_count(address)
        except Exception:
            tx_count = 0
        try:
            total_received = self.provider.address_received(address) or 0
        except Exception:
            total_received = 0
        return tx_count, total_received

    def _txs(self, address: str):
        """Fetch an address's transactions; a failed fetch yields no data, not a crash."""
        try:
            return self.provider.get_transactions(address, self.max_txs_per_address)
        except Exception:
            return []

    def trace_forward(
        self,
        seed: str,
        depth: int = 2,
        min_value: int = 100_000,
        max_branch: int = 8,
    ) -> TraceResult:
        seed = self.provider.normalize(seed)
        result = TraceResult(
            seed=seed,
            direction="forward",
            asset=self.provider.asset_info,
            params={
                "depth": depth,
                "min_value_sats": min_value,
                "max_branch": max_branch,
                "max_txs_per_address": self.max_txs_per_address,
                "service_tx_threshold": self.service_tx_threshold,
            },
        )
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(seed, 0)])

        while queue:
            address, d = queue.popleft()
            if address in visited:
                continue
            visited.add(address)

            tx_count, total_received = self._stats(address)
            label = self.label_store.get(address) if self.label_store else None

            is_service = tx_count > self.service_tx_threshold and address != seed
            if label is not None and label.category in _SERVICE_CATEGORIES and address != seed:
                is_service = True

            if address == seed:
                node_type = NodeType.SEED
            elif is_service:
                node_type = NodeType.SERVICE
            else:
                node_type = NodeType.ADDRESS

            node = TraceNode(address=address, node_type=node_type, depth=d, tx_count=tx_count)
            node.total_received = total_received
            if label is not None:
                node.label_name = label.name
                node.label_category = label.category.value
                node.label_source = label.source
            result.add_node(node)

            # Stop expanding at max depth or at a service/cash-out node.
            if d >= depth or is_service:
                continue

            txs = self._txs(address)

            # Aggregate outgoing value per recipient across all of this address's spends.
            next_hops: dict[str, dict] = {}
            for tx in txs:
                if not tx.spends_from(address):
                    continue

                # Counter-laundering: a CoinJoin hides which output is the target's.
                # Record it as a mixing break-point instead of naively fanning out
                # across every equal-value output (which explodes and mis-attributes).
                cj = classify_coinjoin(tx)
                if cj is not None:
                    result.mixing_events.append(
                        {
                            "address": address,
                            "txid": tx.txid,
                            "kind": cj.kind.value,
                            "anonymity_set": cj.anonymity_set,
                            "denomination_btc": cj.denomination / SATS_PER_BTC,
                        }
                    )
                    entry = result.nodes.get(address)
                    if entry is not None:
                        entry.entered_mixer = True
                    continue

                in_addrs = tx.input_addresses()

                # Apportion each output by this address's share of the tx inputs.
                # A Bitcoin tx can be funded by several addresses; attributing the
                # whole output to `address` would over-count value it never owned.
                total_in = sum(i.value for i in tx.inputs) or 1
                src_in = sum(i.value for i in tx.inputs if i.address == address)
                src_share = src_in / total_in

                for out in tx.outputs:
                    # Skip unparseable outputs and change returning to the spending cluster.
                    if not out.address or out.address in in_addrs:
                        continue
                    attributed = int(out.value * src_share)
                    if attributed <= 0:
                        continue
                    hop = next_hops.setdefault(out.address, {"value": 0, "txids": []})
                    hop["value"] += attributed
                    if tx.txid not in hop["txids"]:
                        hop["txids"].append(tx.txid)

            # Keep the strongest branches above the dust threshold.
            ranked = sorted(next_hops.items(), key=lambda kv: kv[1]["value"], reverse=True)
            kept = [(dst, hop) for dst, hop in ranked if hop["value"] >= min_value][:max_branch]
            for dst, hop in kept:
                edge = result.edge(address, dst)
                edge.value += hop["value"]
                edge.txids.extend(hop["txids"])
                if dst not in visited:
                    queue.append((dst, d + 1))

        return result

    def trace_backward(
        self,
        seed: str,
        depth: int = 2,
        min_value: int = 100_000,
        max_branch: int = 8,
    ) -> TraceResult:
        seed = self.provider.normalize(seed)
        result = TraceResult(
            seed=seed,
            direction="backward",
            asset=self.provider.asset_info,
            params={
                "depth": depth,
                "min_value_sats": min_value,
                "max_branch": max_branch,
                "max_txs_per_address": self.max_txs_per_address,
                "service_tx_threshold": self.service_tx_threshold,
            },
        )
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(seed, 0)])

        while queue:
            address, d = queue.popleft()
            if address in visited:
                continue
            visited.add(address)

            tx_count, total_received = self._stats(address)
            label = self.label_store.get(address) if self.label_store else None

            is_service = tx_count > self.service_tx_threshold and address != seed
            if label is not None and label.category in _SERVICE_CATEGORIES and address != seed:
                is_service = True

            if address == seed:
                node_type = NodeType.SEED
            elif is_service:
                node_type = NodeType.SERVICE
            else:
                node_type = NodeType.ADDRESS

            node = TraceNode(address=address, node_type=node_type, depth=d, tx_count=tx_count)
            node.total_received = total_received
            if label is not None:
                node.label_name = label.name
                node.label_category = label.category.value
                node.label_source = label.source
            result.add_node(node)

            if d >= depth or is_service:
                continue

            txs = self._txs(address)
            prev_hops: dict[str, dict] = {}
            for tx in txs:
                if not tx.outputs or not any(out.address == address for out in tx.outputs):
                    continue

                # Attribute incoming funding to the address's spenders by looking at
                # the transaction inputs that fund it. This gives a simple but
                # defensible source-of-funds view for investigations.
                total_out = sum(out.value for out in tx.outputs) or 1
                dst_share = sum(out.value for out in tx.outputs if out.address == address) / total_out
                for inp in tx.inputs:
                    if not inp.address or inp.address == address:
                        continue
                    attributed = int(inp.value * dst_share)
                    if attributed <= 0:
                        continue
                    hop = prev_hops.setdefault(inp.address, {"value": 0, "txids": []})
                    hop["value"] += attributed
                    if tx.txid not in hop["txids"]:
                        hop["txids"].append(tx.txid)

            ranked = sorted(prev_hops.items(), key=lambda kv: kv[1]["value"], reverse=True)
            kept = [(src, hop) for src, hop in ranked if hop["value"] >= min_value][:max_branch]
            for src, hop in kept:
                edge = result.edge(src, address)
                edge.value += hop["value"]
                edge.txids.extend(hop["txids"])
                if src not in visited:
                    queue.append((src, d + 1))

        return result
