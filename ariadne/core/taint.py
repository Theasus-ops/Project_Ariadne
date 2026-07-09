"""Taint analysis (Phase 3) - proportional "haircut" model.

The seed is 100% dirty. Dirty value propagates along traced flows: the dirty
amount moving along an edge src -> dst is the edge value scaled by the source's
taint fraction. A node's taint fraction is the dirty value it received divided by
its TOTAL on-chain received value (not just the traced portion), so a node that
also took in large amounts of untraced / clean funds is diluted accordingly. That
is what stops the over-attribution the first version suffered from.

Denominator source:
  * Bitcoin: the address's all-time received total (funded_txo_sum), taken from
    the same /address call used for activity, so it costs no extra request.
  * Account-model tokens (ETH / USDT) expose no cheap total-received yet, so the
    denominator falls back to traced inflow (taint tends toward 1.0 there -- a
    known limitation until per-token inflow summing is added).

It remains an address-level haircut (not UTXO- or time-precise), so treat taint
as a strong indicator, not a courtroom-final number.
"""

from __future__ import annotations

from ..models import TraceResult


def compute_taint(result: TraceResult) -> TraceResult:
    incoming: dict[str, list] = {}
    for edge in result.edges.values():
        incoming.setdefault(edge.dst, []).append(edge)

    fraction: dict[str, float] = {result.seed: 1.0}

    for node in sorted(result.nodes.values(), key=lambda n: n.depth):
        if node.address == result.seed:
            node.taint_fraction = 1.0
            node.dirty_received = sum(
                e.value for e in result.edges.values() if e.src == result.seed
            )
            continue

        ins = incoming.get(node.address, [])
        dirty_in = sum(e.value * fraction.get(e.src, 0.0) for e in ins)
        node.dirty_received = int(dirty_in)

        # Denominator: true on-chain total received when known, else traced inflow.
        denom = node.total_received if node.total_received > 0 else sum(e.value for e in ins)
        node.taint_fraction = min(1.0, dirty_in / denom) if denom > 0 else 0.0
        fraction[node.address] = node.taint_fraction

    return result
