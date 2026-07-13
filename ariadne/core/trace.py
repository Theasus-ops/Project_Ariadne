"""Multi-hop value-flow tracer.

Forward tracing answers "where did the money go?": for each address, we look at
the transactions where it SPENDS and follow the value to the receiving addresses,
up to a chosen number of hops. Backward tracing answers "where did it come from?".

High-activity addresses (tx_count above a threshold) are treated as terminal
SERVICE nodes -- almost always exchanges or mixers. These are the cash-out points
an investigator actually cares about, and expanding them is both meaningless
(a service commingles everyone's funds) and infeasible (millions of txs). So we
flag them and stop.

Performance: the search runs breadth-first level by level, and every address in a
level is fetched **concurrently** (``workers`` threads). Results are then applied
in a fixed order, so the output is deterministic regardless of thread timing.
Against a rate-limited public API the win is bounded by the rate limit; against a
self-hosted indexer (see ariadne.config) it is dramatic.
"""

from __future__ import annotations

import concurrent.futures
import heapq

from ..enrich.labels import HIGH_RISK, LabelCategory, LabelStore
from ..models import SATS_PER_BTC, NodeType, TraceNode, TraceResult
from ..providers.base import Provider
from .coinjoin import classify as classify_coinjoin

_SERVICE_CATEGORIES = {
    LabelCategory.EXCHANGE,
    LabelCategory.MIXER,
    LabelCategory.SERVICE,
    LabelCategory.DEX,
    LabelCategory.BRIDGE,
    LabelCategory.ATM,
    LabelCategory.GAMBLING,
}
# Illicit categories that must NOT be silently reclassified as a benign "service"
# just because the address is busy (mixers stay service — they are a break-point).
_ILLICIT_NONSERVICE = HIGH_RISK - _SERVICE_CATEGORIES


class Tracer:
    def __init__(
        self,
        provider: Provider,
        service_tx_threshold: int = 3000,
        max_txs_per_address: int = 200,
        label_store: LabelStore | None = None,
        workers: int = 1,
    ) -> None:
        self.provider = provider
        self.service_tx_threshold = service_tx_threshold
        self.max_txs_per_address = max_txs_per_address
        self.label_store = label_store
        self.workers = max(1, int(workers))

    # ---- resilient single-address fetches ----
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

    # ---- concurrent level fetches ----
    def _map(self, fn, items: list):
        """Apply ``fn`` to each item, concurrently when workers > 1, returning a dict."""
        if not items:
            return {}
        if self.workers <= 1 or len(items) == 1:
            return {it: fn(it) for it in items}
        out: dict = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            for it, val in zip(items, ex.map(fn, items), strict=False):
                out[it] = val
        return out

    def _emit_node(self, result: TraceResult, address: str, depth: int,
                   tx_count: int, total_received: int) -> bool:
        """Create and record a node; return whether it is a terminal service.

        Service detection is label-first: a labelled exchange/mixer/DEX/bridge is a
        terminal service regardless of activity. The tx-count heuristic is only a
        fall-back, and it never downgrades an illicit-labelled wallet (sanctioned,
        ransomware, scam, …) to a benign "service" — those stay attributable nodes.
        """
        label = self.label_store.get(address) if self.label_store else None
        is_service = False
        if address != result.seed:
            if label is not None and label.category in _SERVICE_CATEGORIES:
                is_service = True
            elif tx_count > self.service_tx_threshold and not (
                label is not None and label.category in _ILLICIT_NONSERVICE
            ):
                is_service = True

        if address == result.seed:
            node_type = NodeType.SEED
        elif is_service:
            node_type = NodeType.SERVICE
        else:
            node_type = NodeType.ADDRESS

        node = TraceNode(address=address, node_type=node_type, depth=depth, tx_count=tx_count)
        node.total_received = total_received
        if label is not None:
            node.label_name = label.name
            node.label_category = label.category.value
            node.label_source = label.source
        result.add_node(node)
        return is_service

    @staticmethod
    def _dedup(addresses: list[str], visited: set[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for a in addresses:
            if a in visited or a in seen:
                continue
            seen.add(a)
            out.append(a)
        return out

    def _levels(self, seed: str, depth: int, expand):
        """Shared BFS driver. ``expand(address, txs, add_edge)`` processes an
        address's transactions and returns the next-hop addresses."""
        visited: set[str] = set()
        current = [seed]
        for d in range(depth + 1):
            level = self._dedup(current, visited)
            if not level:
                break
            visited.update(level)

            stats = self._map(self._stats, level)
            expandable = []
            for address in level:
                tx_count, total_received = stats[address]
                is_service = self._emit_node_result(address, d, tx_count, total_received)
                if d < depth and not is_service:
                    expandable.append(address)

            txmap = self._map(self._txs, expandable)
            next_level: list[str] = []
            for address in expandable:
                next_level.extend(expand(address, txmap.get(address, [])))
            current = next_level

    # bound at call time (see trace_forward/backward) so _levels stays generic
    def _emit_node_result(self, address, d, tx_count, total_received):  # pragma: no cover - rebound
        raise NotImplementedError

    def _forward_dirty(self, result, seed, depth, min_value, max_branch, max_nodes) -> None:
        """Best-first forward traversal that **follows the dirty money**.

        Unlike level-BFS (which keeps each address's top branches independently and so
        can prune away a laundering path that fans out), this maintains one *global*
        priority frontier ranked by the **dirty value** each branch carries — an online
        haircut estimate — and spends a bounded node budget on the dirtiest paths first.
        It resists even-split and sub-threshold-peel evasion by never letting a fat,
        heavily-tainted branch lose to shallow-but-clean ones.
        """
        dirty_in: dict[str, float] = {}
        visited: set[str] = set()
        counter = 0
        frontier: list[tuple] = [(-float("inf"), 0, seed, 0)]  # max-heap by dirty carried
        expanded = 0

        while frontier and expanded < max_nodes:
            _, _, address, d = heapq.heappop(frontier)
            if address in visited:
                continue
            visited.add(address)
            tx_count, total_received = self._stats(address)
            is_service = self._emit_node(result, address, d, tx_count, total_received)
            expanded += 1

            if address == seed:
                node_taint = 1.0
            else:
                din = dirty_in.get(address, 0.0)
                node_taint = min(1.0, din / total_received) if total_received > 0 else (1.0 if din > 0 else 0.0)

            if d >= depth or is_service:
                continue

            next_hops: dict[str, dict] = {}
            for tx in self._txs(address):
                if not tx.spends_from(address):
                    continue
                cj = classify_coinjoin(tx)
                if cj is not None:
                    result.mixing_events.append({
                        "address": address, "txid": tx.txid, "kind": cj.kind.value,
                        "anonymity_set": cj.anonymity_set, "denomination_btc": cj.denomination / SATS_PER_BTC,
                    })
                    entry = result.nodes.get(address)
                    if entry is not None:
                        entry.entered_mixer = True
                    continue
                in_addrs = tx.input_addresses()
                total_in = sum(i.value for i in tx.inputs) or 1
                src_share = sum(i.value for i in tx.inputs if i.address == address) / total_in
                for out in tx.outputs:
                    if not out.address or out.address in in_addrs:
                        continue
                    attributed = int(out.value * src_share)
                    if attributed <= 0:
                        continue
                    hop = next_hops.setdefault(out.address, {"value": 0, "txids": [], "time": None})
                    hop["value"] += attributed
                    if tx.txid not in hop["txids"]:
                        hop["txids"].append(tx.txid)
                    if tx.block_time is not None and (hop["time"] is None or tx.block_time < hop["time"]):
                        hop["time"] = tx.block_time

            # Keep the branches carrying the most DIRTY value (value x this node's taint).
            ranked = sorted(next_hops.items(), key=lambda kv: kv[1]["value"] * node_taint, reverse=True)
            kept = [(dst, hop) for dst, hop in ranked if hop["value"] >= min_value][:max_branch]
            for dst, hop in kept:
                edge = result.edge(address, dst)
                edge.value += hop["value"]
                edge.txids.extend(hop["txids"])
                edge.observe_time(hop["time"])
                carried = hop["value"] * node_taint
                dirty_in[dst] = dirty_in.get(dst, 0.0) + carried
                if dst not in visited:
                    counter += 1
                    heapq.heappush(frontier, (-carried, counter, dst, d + 1))

        # If the node budget was exhausted, some frontier destinations were never
        # analysed; drop those edges so every edge connects two examined nodes.
        for key in [k for k, e in result.edges.items() if e.dst not in result.nodes]:
            del result.edges[key]

    def trace_forward(
        self,
        seed: str,
        depth: int = 2,
        min_value: int = 100_000,
        max_branch: int = 8,
        follow: str = "bfs",
        max_nodes: int | None = None,
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
                "workers": self.workers,
                "follow": follow,
            },
        )
        if follow == "dirty":
            budget = max_nodes if max_nodes is not None else max(50, max_branch * (depth + 1) * 4)
            self._forward_dirty(result, seed, depth, min_value, max_branch, budget)
            return result
        self._emit_node_result = lambda a, d, tc, tr: self._emit_node(result, a, d, tc, tr)

        def expand(address: str, txs) -> list[str]:
            next_hops: dict[str, dict] = {}
            for tx in txs:
                if not tx.spends_from(address):
                    continue
                # Counter-laundering: a CoinJoin hides which output is the target's.
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
                total_in = sum(i.value for i in tx.inputs) or 1
                src_in = sum(i.value for i in tx.inputs if i.address == address)
                src_share = src_in / total_in

                for out in tx.outputs:
                    if not out.address or out.address in in_addrs:
                        continue
                    attributed = int(out.value * src_share)
                    if attributed <= 0:
                        continue
                    hop = next_hops.setdefault(out.address, {"value": 0, "txids": [], "time": None})
                    hop["value"] += attributed
                    if tx.txid not in hop["txids"]:
                        hop["txids"].append(tx.txid)
                    if tx.block_time is not None and (hop["time"] is None or tx.block_time < hop["time"]):
                        hop["time"] = tx.block_time

            ranked = sorted(next_hops.items(), key=lambda kv: kv[1]["value"], reverse=True)
            kept = [(dst, hop) for dst, hop in ranked if hop["value"] >= min_value][:max_branch]
            # Coverage bookkeeping: how much outflow we followed vs. saw and dropped
            # (to min_value / max_branch pruning) — the basis for a completeness metric.
            considered = sum(h["value"] for h in next_hops.values())
            kept_val = sum(h["value"] for _, h in kept)
            result.coverage["considered_out"] = result.coverage.get("considered_out", 0) + considered
            result.coverage["kept_out"] = result.coverage.get("kept_out", 0) + kept_val
            nxt = []
            for dst, hop in kept:
                edge = result.edge(address, dst)
                edge.value += hop["value"]
                edge.txids.extend(hop["txids"])
                edge.observe_time(hop["time"])
                nxt.append(dst)
            return nxt

        self._levels(seed, depth, expand)
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
                "workers": self.workers,
            },
        )
        self._emit_node_result = lambda a, d, tc, tr: self._emit_node(result, a, d, tc, tr)

        def expand(address: str, txs) -> list[str]:
            prev_hops: dict[str, dict] = {}
            for tx in txs:
                if not tx.outputs or not any(out.address == address for out in tx.outputs):
                    continue
                total_out = sum(out.value for out in tx.outputs) or 1
                dst_share = sum(out.value for out in tx.outputs if out.address == address) / total_out
                for inp in tx.inputs:
                    if not inp.address or inp.address == address:
                        continue
                    attributed = int(inp.value * dst_share)
                    if attributed <= 0:
                        continue
                    hop = prev_hops.setdefault(inp.address, {"value": 0, "txids": [], "time": None})
                    hop["value"] += attributed
                    if tx.txid not in hop["txids"]:
                        hop["txids"].append(tx.txid)
                    if tx.block_time is not None and (hop["time"] is None or tx.block_time < hop["time"]):
                        hop["time"] = tx.block_time

            ranked = sorted(prev_hops.items(), key=lambda kv: kv[1]["value"], reverse=True)
            kept = [(src, hop) for src, hop in ranked if hop["value"] >= min_value][:max_branch]
            nxt = []
            for src, hop in kept:
                edge = result.edge(src, address)
                edge.value += hop["value"]
                edge.txids.extend(hop["txids"])
                edge.observe_time(hop["time"])
                nxt.append(src)
            return nxt

        self._levels(seed, depth, expand)
        return result
