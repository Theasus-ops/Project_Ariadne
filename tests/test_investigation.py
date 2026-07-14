"""Tests for the multi-seed investigation logic (merge, shared infra, dossier)."""

from ariadne.core.investigation import (
    analyse,
    build_dossier,
    merge_results,
    shared_infrastructure,
)
from ariadne.models import BTC, NodeType, TraceNode, TraceResult


def _result(seed, nodes, edges):
    r = TraceResult(seed=seed, direction="forward", asset=BTC)
    for addr, depth in nodes:
        r.add_node(TraceNode(addr, NodeType.SEED if addr == seed else NodeType.ADDRESS, depth))
    for src, dst, val in edges:
        e = r.edge(src, dst)
        e.value += val
    return r


# Two seeds that both route into a common address EX (a shared cash-out).
A = _result("S1", [("S1", 0), ("X", 1), ("EX", 2)], [("S1", "X", 100), ("X", "EX", 90)])
B = _result("S2", [("S2", 0), ("Y", 1), ("EX", 2)], [("S2", "Y", 200), ("Y", "EX", 180)])


def test_merge_results_combines_graphs():
    m = merge_results([A, B])
    assert {"S1", "S2", "X", "Y", "EX"} <= set(m.nodes)
    assert m.edges[("X", "EX")].value == 90 and m.edges[("Y", "EX")].value == 180


def test_merge_results_empty():
    m = merge_results([])
    assert m.seed == "" and not m.nodes


def test_shared_infrastructure_finds_common_endpoint():
    shared = shared_infrastructure([A, B])
    addrs = {s["address"] for s in shared}
    assert addrs == {"EX"}                 # only EX is reached from both seeds
    assert shared[0]["seed_count"] == 2 and shared[0]["reached_from"] == ["S1", "S2"]


def test_analyse_returns_expected_structure():
    a = analyse([A, B])
    for key in ("merged", "graph", "summary", "shared_infrastructure", "hubs", "communities"):
        assert key in a
    assert a["summary"]["nodes"] == 5


def test_build_dossier_renders_seeds_and_shared_infra():
    a = analyse([A, B])
    rows = [
        {"seed": "S1", "chain": "btc", "risk": "high", "findings": 2, "cash_outs": 1},
        {"seed": "S2", "chain": "btc", "risk": "critical", "findings": 3, "cash_outs": 1},
    ]
    md = build_dossier("theseus", rows, a, asset="BTC")
    assert "# Operation theseus" in md
    assert "`S1`" in md and "`S2`" in md
    assert "Shared infrastructure" in md and "EX" in md   # the common cash-out is surfaced


def test_build_dossier_handles_no_shared_infra():
    lone = _result("S9", [("S9", 0), ("Z", 1)], [("S9", "Z", 10)])
    a = analyse([lone])
    md = build_dossier("solo", [{"seed": "S9", "chain": "btc"}], a)
    assert "No shared infrastructure" in md
