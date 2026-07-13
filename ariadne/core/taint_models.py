"""Selectable taint methodologies — the forensic-defensibility core.

A single "how dirty is this money" number is not defensible unless you can name
the *model* that produced it and reproduce it. Courts and expert witnesses do not
accept "our tool estimates"; they accept a named, documented tracing rule applied
consistently. Ariadne implements the three that matter and records which one was
used on every result (``TraceResult.taint_model``), so a finding reads "under the
FIFO model, 4.2 BTC of this output is traceable to the seed" — an auditable claim,
not a black-box score.

The models
----------
* **poison** (maximalist / "taint by association"). Any address that receives
  *any* tainted value is treated as 100% tainted, and all of its outflow is
  tainted. Over-attributes on purpose: it answers "what is the maximal set of
  addresses the dirty money could have touched?" Deliberately *not*
  conservation-preserving — dirty value grows as it fans out. Use it to draw the
  widest net (e.g. sanctions-exposure screening).

* **haircut** (proportional dilution). An address that mixes dirty and clean
  funds passes on dirtiness in proportion. A node's taint fraction is
  dirty-in / total-received, so untraced clean funds dilute it. Conservation-
  preserving: dirty value never exceeds what the seed disbursed. This is the
  balanced default and the model behind the existing engine.

* **fifo** (first-in-first-out, the "Clayton's Case" rule used in asset-tracing
  law). Money is spent in the order it arrived. Each address is an ordered ledger
  of receipts; outgoing spends draw from the front. Dirtiness is tracked per
  segment, so an output is dirty only to the extent that dirty receipts sit at the
  front of the queue when it is paid. Implemented at edge granularity over the
  traced subgraph, with the untraced balance treated as clean and ordered last;
  this is an explicit, documented approximation of the per-UTXO FIFO rule.

All three are pure functions of the ``TraceResult`` graph, so a result can be
re-scored under any model without re-fetching a single byte.
"""

from __future__ import annotations

from collections import defaultdict
from enum import Enum

from ..models import TraceResult


class TaintModel(str, Enum):
    POISON = "poison"
    HAIRCUT = "haircut"
    FIFO = "fifo"
    # UTXO / output-level variants (see ariadne.core.utxo_taint). These require the
    # raw transactions the tracer retains with collect_transactions=True and apply
    # only to UTXO chains (Bitcoin); account chains have no UTXOs.
    UTXO_POISON = "utxo-poison"
    UTXO_HAIRCUT = "utxo-haircut"
    UTXO_FIFO = "utxo-fifo"


DEFAULT_MODEL = TaintModel.HAIRCUT

# One-line methodology statement embedded in reports for the reader/court.
METHODOLOGY: dict[str, str] = {
    TaintModel.POISON.value: (
        "Poison model: any address receiving tainted value is treated as fully tainted "
        "and all its outflow is tainted. Maximal exposure; not conservation-preserving."
    ),
    TaintModel.HAIRCUT.value: (
        "Haircut model: taint propagates in proportion to the dirty share of an address's "
        "total received value; clean funds dilute it. Conservation-preserving."
    ),
    TaintModel.FIFO.value: (
        "FIFO model (first-in-first-out / Clayton's Case): funds are spent in the order "
        "received; outputs are dirty only to the extent dirty receipts sit at the front of "
        "the queue. Edge-level approximation over the traced subgraph."
    ),
    TaintModel.UTXO_POISON.value: (
        "UTXO poison model: output-level tracing — any output of a transaction with any "
        "dirty input is treated as fully dirty. Maximal exposure at output granularity."
    ),
    TaintModel.UTXO_HAIRCUT.value: (
        "UTXO haircut model: output-level tracing — each output is dirty in proportion to "
        "the transaction's dirty input share (dirty-in / total-in). Conservation-preserving."
    ),
    TaintModel.UTXO_FIFO.value: (
        "UTXO FIFO model (Clayton's Case at output granularity): inputs are consumed in "
        "transaction input order and outputs paid in index order from the front of the "
        "dirty/clean queue — first-in-first-out on individual outputs, not an address average."
    ),
}


def compute(result: TraceResult, model: TaintModel | str = DEFAULT_MODEL) -> TraceResult:
    """Score ``result`` under ``model`` in place; records the model on the result."""
    model = TaintModel(model)
    result.taint_model = model.value
    # Reset any per-edge taint from a previous scoring pass so re-scoring is clean.
    for edge in result.edges.values():
        edge.dirty_value = 0
    if model is TaintModel.POISON:
        return _poison(result)
    if model is TaintModel.FIFO:
        return _fifo(result)
    return _haircut(result)


def _incoming(result: TraceResult) -> dict[str, list]:
    incoming: dict[str, list] = defaultdict(list)
    for edge in result.edges.values():
        incoming[edge.dst].append(edge)
    return incoming


def _seed_outflow(result: TraceResult) -> int:
    return sum(e.value for e in result.edges.values() if e.src == result.seed)


# --------------------------------------------------------------------------- #
# Haircut — proportional dilution (conservation-preserving). This is the exact
# algorithm the original engine used; preserved bit-for-bit as the default.
# --------------------------------------------------------------------------- #
def _haircut(result: TraceResult) -> TraceResult:
    incoming = _incoming(result)
    fraction: dict[str, float] = {result.seed: 1.0}

    for node in sorted(result.nodes.values(), key=lambda n: n.depth):
        if node.address == result.seed:
            node.taint_fraction = 1.0
            node.dirty_received = _seed_outflow(result)
            for e in result.edges.values():
                if e.src == result.seed:
                    e.dirty_value = e.value
            continue

        ins = incoming.get(node.address, [])
        dirty_in = sum(e.value * fraction.get(e.src, 0.0) for e in ins)
        node.dirty_received = int(dirty_in)

        denom = node.total_received if node.total_received > 0 else sum(e.value for e in ins)
        frac = min(1.0, dirty_in / denom) if denom > 0 else 0.0
        node.taint_fraction = frac
        fraction[node.address] = frac
        for e in ins:
            e.dirty_value = int(e.value * fraction.get(e.src, 0.0))

    return result


# --------------------------------------------------------------------------- #
# Poison — maximalist taint by association (not conservation-preserving).
# --------------------------------------------------------------------------- #
def _poison(result: TraceResult) -> TraceResult:
    incoming = _incoming(result)
    tainted: set[str] = {result.seed}

    for node in sorted(result.nodes.values(), key=lambda n: n.depth):
        if node.address == result.seed:
            node.taint_fraction = 1.0
            node.dirty_received = _seed_outflow(result)
            for e in result.edges.values():
                if e.src == result.seed:
                    e.dirty_value = e.value
            continue

        ins = incoming.get(node.address, [])
        dirty_in = sum(e.value for e in ins if e.src in tainted)
        node.dirty_received = int(dirty_in)
        if dirty_in > 0:
            node.taint_fraction = 1.0
            tainted.add(node.address)
        else:
            node.taint_fraction = 0.0
        # Under poison, every unit leaving a tainted node is tainted.
        for e in ins:
            e.dirty_value = e.value if e.src in tainted else 0

    return result


# --------------------------------------------------------------------------- #
# FIFO — first-in-first-out (Clayton's Case). Edge-level over the traced subgraph.
# --------------------------------------------------------------------------- #
def _edge_time(edge) -> tuple[int, str]:
    """Deterministic ordering key: by first observed time, then destination."""
    return (edge.first_time if edge.first_time is not None else 0, edge.dst)


def _fifo(result: TraceResult) -> TraceResult:
    incoming = _incoming(result)
    outgoing: dict[str, list] = defaultdict(list)
    for edge in result.edges.values():
        outgoing[edge.src].append(edge)

    # Seed: 100% dirty; all outflow dirty.
    seed_node = result.nodes.get(result.seed)
    if seed_node is not None:
        seed_node.taint_fraction = 1.0
        seed_node.dirty_received = _seed_outflow(result)
    for e in outgoing.get(result.seed, []):
        e.dirty_value = e.value

    for node in sorted(result.nodes.values(), key=lambda n: n.depth):
        if node.address == result.seed:
            continue

        ins = sorted(incoming.get(node.address, []), key=_edge_time)
        traced_in = sum(e.value for e in ins)
        dirty_in = sum(e.dirty_value for e in ins)
        node.dirty_received = int(dirty_in)

        denom = node.total_received if node.total_received > 0 else traced_in
        node.taint_fraction = min(1.0, dirty_in / denom) if denom > 0 else 0.0

        # Build the FIFO queue of (amount, dirty?) segments in arrival order, then
        # append the untraced balance as a clean tail so dirty receipts are spent
        # first only if they arrived first — true to the ordering rule.
        queue: list[list[int]] = []  # each: [amount_remaining, dirty_amount_remaining]
        for e in ins:
            queue.append([e.value, e.dirty_value])
        clean_tail = max(0, denom - traced_in)
        if clean_tail > 0:
            queue.append([clean_tail, 0])

        # Pay outgoing edges in time order, drawing from the front of the queue.
        for e in sorted(outgoing.get(node.address, []), key=_edge_time):
            need = e.value
            dirty_drawn = 0
            while need > 0 and queue:
                seg = queue[0]
                take = min(need, seg[0])
                take_dirty = min(seg[1], take)
                dirty_drawn += take_dirty
                seg[0] -= take
                seg[1] -= take_dirty
                need -= take
                if seg[0] <= 0:
                    queue.pop(0)
            e.dirty_value = int(dirty_drawn)

    return result
