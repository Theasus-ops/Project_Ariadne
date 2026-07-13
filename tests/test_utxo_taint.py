"""Deterministic tests for output-level (UTXO) taint.

These verify the three output-level models against hand-computed answers, prove
UTXO-level taint diverges from the address-level average where it should (the
whole point), confirm the multi-hop DAG propagation, and exercise the end-to-end
path through the tracer with transaction collection. All offline.
"""

from ariadne.core.taint import compute_taint
from ariadne.core.trace import Tracer
from ariadne.core.utxo_taint import compute_utxo
from ariadne.models import BTC, NodeType, TraceNode, TraceResult, Transaction, TxInput, TxOutput


def _tx(txid, ins, outs, t=0):
    """ins: [(addr, value, prev_txid, prev_vout)]; outs: [(addr, value)]."""
    return Transaction(
        txid,
        [TxInput(a, v, pt, pv) for (a, v, pt, pv) in ins],
        [TxOutput(a, v, i) for i, (a, v) in enumerate(outs)],
        block_time=t,
    )


def _result(seed, txs, nodes):
    r = TraceResult(seed=seed, direction="forward", asset=BTC)
    for addr, ntype, depth, total_recv in nodes:
        n = TraceNode(addr, ntype, depth)
        n.total_received = total_recv
        r.add_node(n)
    r.transactions = {t.txid: t for t in txs}
    return r


# --------------------------------------------------------------------------- #
# haircut: proportional at output granularity
# --------------------------------------------------------------------------- #
def test_utxo_haircut_dilutes_by_dirty_input_share():
    # S (50, dirty) + X (50, clean) -> A(90), B(10). frac = 50/100 = 0.5.
    tx = _tx("t1", [("S", 50, "p0", 0), ("X", 50, "p1", 0)], [("A", 90), ("B", 10)])
    r = _result("S", [tx], [
        ("S", NodeType.SEED, 0, 0),
        ("A", NodeType.ADDRESS, 1, 0),
        ("B", NodeType.ADDRESS, 1, 0),
    ])
    compute_utxo(r, "utxo-haircut")
    assert r.nodes["A"].dirty_received == 45 and r.nodes["A"].taint_fraction == 0.5
    assert r.nodes["B"].dirty_received == 5 and r.nodes["B"].taint_fraction == 0.5
    assert r.taint_model == "utxo-haircut"


def test_utxo_poison_taints_every_output_fully():
    tx = _tx("t1", [("S", 50, "p0", 0), ("X", 50, "p1", 0)], [("A", 90), ("B", 10)])
    r = _result("S", [tx], [
        ("S", NodeType.SEED, 0, 0), ("A", NodeType.ADDRESS, 1, 0), ("B", NodeType.ADDRESS, 1, 0),
    ])
    compute_utxo(r, "utxo-poison")
    assert r.nodes["A"].dirty_received == 90 and r.nodes["A"].taint_fraction == 1.0
    assert r.nodes["B"].dirty_received == 10 and r.nodes["B"].taint_fraction == 1.0


# --------------------------------------------------------------------------- #
# FIFO: the dirty parcel lands in specific outputs, not spread evenly
# --------------------------------------------------------------------------- #
def test_utxo_fifo_puts_dirt_at_the_front():
    # Inputs in order: S(60 dirty) then X(40 clean). Outputs A(50), B(50).
    # FIFO fills A first from the dirty front: A=50 dirty; B draws 10 dirty (rest of S)
    # + 40 clean -> B=10 dirty. This is the divergence haircut cannot express.
    tx = _tx("t1", [("S", 60, "p0", 0), ("X", 40, "p1", 0)], [("A", 50), ("B", 50)])
    r = _result("S", [tx], [
        ("S", NodeType.SEED, 0, 0), ("A", NodeType.ADDRESS, 1, 0), ("B", NodeType.ADDRESS, 1, 0),
    ])
    compute_utxo(r, "utxo-fifo")
    assert r.nodes["A"].dirty_received == 50   # entirely dirty (front of the queue)
    assert r.nodes["B"].dirty_received == 10   # only the dirty remainder
    # Haircut on the same tx would call both outputs 60% dirty (30 and 30) — different.
    r2 = _result("S", [tx], [
        ("S", NodeType.SEED, 0, 0), ("A", NodeType.ADDRESS, 1, 0), ("B", NodeType.ADDRESS, 1, 0),
    ])
    compute_utxo(r2, "utxo-haircut")
    assert r2.nodes["A"].dirty_received == 30 and r2.nodes["B"].dirty_received == 30


# --------------------------------------------------------------------------- #
# multi-hop DAG propagation through prevout linkage
# --------------------------------------------------------------------------- #
def test_utxo_propagates_across_hops_via_prevout():
    # tx1: S(100) -> A(100) at vout0. tx2 spends (tx1,0): A(100) -> EX(100).
    tx1 = _tx("tx1", [("S", 100, "p0", 0)], [("A", 100)], t=1)
    tx2 = _tx("tx2", [("A", 100, "tx1", 0)], [("EX", 100)], t=2)
    r = _result("S", [tx1, tx2], [
        ("S", NodeType.SEED, 0, 0), ("A", NodeType.ADDRESS, 1, 0), ("EX", NodeType.SERVICE, 2, 0),
    ])
    compute_utxo(r, "utxo-haircut")
    # A received 100 fully dirty from the seed; that dirt flows on to EX.
    assert r.nodes["A"].dirty_received == 100 and r.nodes["A"].taint_fraction == 1.0
    assert r.nodes["EX"].dirty_received == 100 and r.nodes["EX"].taint_fraction == 1.0


def test_utxo_out_of_order_processing_is_correct():
    # Same as above but the spending tx has an EARLIER-looking id and is inserted
    # first; ordering by (time, txid) must still process the funding tx first.
    tx_fund = _tx("zzz_fund", [("S", 100, "p0", 0)], [("A", 100)], t=1)
    tx_spend = _tx("aaa_spend", [("A", 100, "zzz_fund", 0)], [("EX", 100)], t=2)
    r = _result("S", [tx_spend, tx_fund], [
        ("S", NodeType.SEED, 0, 0), ("A", NodeType.ADDRESS, 1, 0), ("EX", NodeType.SERVICE, 2, 0),
    ])
    compute_utxo(r, "utxo-haircut")
    assert r.nodes["EX"].dirty_received == 100


def test_untraced_clean_input_is_not_dirty():
    # An input that spends a UTXO we never traced (not the seed) contributes zero dirt.
    tx = _tx("t1", [("Z", 100, "unknown", 3)], [("A", 100)])
    r = _result("S", [tx], [("S", NodeType.SEED, 0, 0), ("A", NodeType.ADDRESS, 1, 0)])
    compute_utxo(r, "utxo-haircut")
    assert r.nodes["A"].dirty_received == 0 and r.nodes["A"].taint_fraction == 0.0


# --------------------------------------------------------------------------- #
# dispatch + end-to-end through the tracer
# --------------------------------------------------------------------------- #
def test_compute_taint_dispatches_utxo_models():
    tx = _tx("t1", [("S", 100, "p0", 0)], [("A", 100)])
    r = _result("S", [tx], [("S", NodeType.SEED, 0, 0), ("A", NodeType.ADDRESS, 1, 0)])
    compute_taint(r, "utxo-haircut")   # via the public entry point
    assert r.taint_model == "utxo-haircut" and r.nodes["A"].dirty_received == 100


class _UTXOProv:
    name = "fake-utxo"
    asset_info = BTC

    def __init__(self, db, service=()):
        self.db = db
        self.service = set(service)

    def normalize(self, a):
        return a

    def address_tx_count(self, a):
        return 9_000_000 if a in self.service else 3

    def address_received(self, a):
        return None

    def get_transactions(self, a, n):
        return self.db.get(a, [])


def test_tracer_collects_transactions_and_utxo_taint_runs_end_to_end():
    v = 1_000_000
    db = {
        "SEED": [_tx("t1", [("SEED", v, "p0", 0)], [("MID", v)], t=1)],
        "MID": [_tx("t2", [("MID", v, "t1", 0)], [("EXCH", v)], t=2)],
        "EXCH": [],
    }
    tracer = Tracer(_UTXOProv(db, service={"EXCH"}), collect_transactions=True)
    result = tracer.trace_forward("SEED", depth=2, min_value=1, max_branch=8)
    # transactions were retained for the UTXO engine
    assert set(result.transactions) == {"t1", "t2"}
    compute_taint(result, "utxo-haircut")
    assert result.nodes["MID"].dirty_received == v
    assert result.nodes["MID"].taint_fraction == 1.0
    # the seed's dirty disbursement is recorded on the seed node
    assert result.nodes["SEED"].dirty_received == v
