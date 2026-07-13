"""UTXO-level (output-level) taint — reference-grade tracing for UTXO chains.

The address-level models in :mod:`ariadne.core.taint_models` treat an address as a
single pool: they dilute by the address's *total received* and cannot see which
specific coins moved where. That is a documented approximation. Real Bitcoin
forensics tracks **individual transaction outputs (UTXOs)**: an output is a
discrete parcel of value, dirty or clean in its own right, and a spend draws from
specific outputs — not from an averaged balance.

This module computes taint at that granularity. It consumes the raw transactions
retained during a forward trace (``TraceResult.transactions``) and propagates the
seed's dirt through the **output graph**:

* a transaction consumes input UTXOs and produces output UTXOs;
* the seed's own inputs are dirty by definition (the origin);
* an input that spends a previously-tainted output carries that output's dirt;
* each model then distributes the incoming dirt to the outputs.

Because a UTXO can only be spent *after* it is created, the output graph is a DAG
by construction — so processing transactions in (time, txid) order is a valid
topological order, and there is **no cyclic-undercount problem** the way there is
for single-pass address-level propagation over a graph with round-trips.

Models (output-level):

* **utxo-poison** — any output of a transaction with any dirty input is fully dirty.
* **utxo-haircut** — each output is dirty in proportion to the transaction's dirty
  input share (``dirty_in / total_in``); the fee absorbs its proportional share.
  Conservation-preserving.
* **utxo-fifo** — the *Clayton's Case* rule at output granularity: inputs are
  consumed in transaction input order (the canonical on-chain order) and outputs
  are paid in index order, drawing from the front of the dirty/clean queue — so an
  output is dirty only to the extent dirty coins sit at the front when it is paid.

The result is written back into the same ``TraceNode.dirty_received /
taint_fraction`` and ``FlowEdge.dirty_value`` fields the rest of the pipeline
already reads, so reports, confidence, screening and evidence are unchanged apart
from carrying more precise numbers.
"""

from __future__ import annotations

from ..models import TraceResult

# The output-level model identifiers (mirror TaintModel.UTXO_* values).
UTXO_MODELS = {"utxo-poison", "utxo-haircut", "utxo-fifo"}


def compute_utxo(result: TraceResult, model: str = "utxo-haircut") -> TraceResult:
    """Score ``result`` at UTXO granularity, in place. Records the model.

    Requires ``result.transactions`` (populate via ``Tracer(collect_transactions=
    True)``). With no transactions the result is left un-tainted but valid.
    """
    if model not in UTXO_MODELS:
        raise ValueError(f"unknown UTXO taint model: {model}")
    result.taint_model = model

    # Reset any prior per-edge taint so re-scoring is clean.
    for edge in result.edges.values():
        edge.dirty_value = 0

    seed = result.seed
    txs = list(result.transactions.values())
    # Deterministic topological order: a UTXO is created before it is spent, so
    # ordering by (block_time, txid) guarantees a creating tx precedes its spenders.
    txs.sort(key=lambda t: (t.block_time if t.block_time is not None else 0, t.txid))

    # Per-output-UTXO state: (txid, vout) -> [value, dirty_amount].
    utxo: dict[tuple[str, int], list[int]] = {}
    # Aggregations for the report.
    node_dirty: dict[str, int] = {}          # address -> dirty value received (as an output)
    node_traced_in: dict[str, int] = {}      # address -> traced value received (denominator fallback)
    seed_dirty_out = 0                        # dirty value the seed disbursed (its dirty_received, by convention)
    # Edge dirty attribution: (src_addr, dst_addr) -> dirty value src sent dst.
    edge_dirty: dict[tuple[str, str], int] = {}

    for tx in txs:
        total_in = sum(i.value for i in tx.inputs)
        if total_in <= 0:
            continue

        # Dirt entering this transaction, and the per-input dirty contribution.
        input_dirty: list[int] = []
        for inp in tx.inputs:
            if inp.address == seed:
                contrib = inp.value                          # origin: the seed's coins are dirty
            else:
                key = (inp.prev_txid, inp.prev_vout)
                carried = utxo.get(key, [0, 0])[1] if inp.prev_txid is not None else 0
                contrib = min(carried, inp.value)
            input_dirty.append(contrib)
        dirty_in = sum(input_dirty)
        if dirty_in > total_in:
            dirty_in = total_in

        # Record the seed's dirty disbursement (for the seed node's dirty_received).
        for inp, d in zip(tx.inputs, input_dirty, strict=True):
            if inp.address == seed:
                seed_dirty_out += d

        # Distribute dirt to outputs under the chosen model.
        out_dirty = _distribute(model, tx, dirty_in, total_in, input_dirty)

        for out, d in zip(tx.outputs, out_dirty, strict=True):
            if out.address is None:
                continue
            utxo[(tx.txid, out.index)] = [out.value, d]
            node_traced_in[out.address] = node_traced_in.get(out.address, 0) + out.value
            if out.address != seed:
                node_dirty[out.address] = node_dirty.get(out.address, 0) + d

        # Attribute each output's dirt back to the input addresses by input-value share,
        # so edge.dirty_value reflects how much dirty value src sent dst.
        in_share: dict[str, float] = {}
        for inp in tx.inputs:
            if inp.address:
                in_share[inp.address] = in_share.get(inp.address, 0.0) + inp.value / total_in
        for out, d in zip(tx.outputs, out_dirty, strict=True):
            if not out.address or d <= 0:
                continue
            for src, share in in_share.items():
                if src == out.address:
                    continue
                edge_dirty[(src, out.address)] = edge_dirty.get((src, out.address), 0) + int(d * share)

    _write_back(result, node_dirty, node_traced_in, seed_dirty_out, edge_dirty)
    return result


def _distribute(model: str, tx, dirty_in: int, total_in: int, input_dirty: list[int]) -> list[int]:
    """Return the dirty amount assigned to each output, per model."""
    outputs = tx.outputs
    if dirty_in <= 0:
        return [0] * len(outputs)

    if model == "utxo-poison":
        # Any dirty input taints every output fully.
        return [o.value for o in outputs]

    if model == "utxo-haircut":
        frac = dirty_in / total_in
        return [int(o.value * frac) for o in outputs]

    # utxo-fifo: consume inputs in transaction input order, pay outputs in index
    # order from the front of the (value, dirty) queue — first-in-first-out.
    queue: list[list[int]] = [[inp.value, d] for inp, d in zip(tx.inputs, input_dirty, strict=True)]
    out_dirty: list[int] = []
    for out in outputs:
        need = out.value
        drawn = 0
        while need > 0 and queue:
            seg = queue[0]
            take = min(need, seg[0])
            take_dirty = min(seg[1], take)
            drawn += take_dirty
            seg[0] -= take
            seg[1] -= take_dirty
            need -= take
            if seg[0] <= 0:
                queue.pop(0)
        out_dirty.append(drawn)
    return out_dirty


def _write_back(result: TraceResult, node_dirty, node_traced_in, seed_dirty_out, edge_dirty) -> None:
    """Fold the UTXO-level numbers into the address-level report fields."""
    for addr, node in result.nodes.items():
        if addr == result.seed:
            node.taint_fraction = 1.0
            node.dirty_received = int(seed_dirty_out)
            continue
        dirty = int(node_dirty.get(addr, 0))
        node.dirty_received = dirty
        denom = node.total_received if node.total_received > 0 else node_traced_in.get(addr, 0)
        node.taint_fraction = min(1.0, dirty / denom) if denom > 0 else 0.0

    for (src, dst), edge in result.edges.items():
        edge.dirty_value = int(min(edge.value, edge_dirty.get((src, dst), 0)))
