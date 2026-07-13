"""Deterministic tests for v0.5 (multi-chain EVM + investigation graph + anomaly)."""

from ariadne import config
from ariadne.core.anomaly import anomalies_in_trace, detect_anomalies
from ariadne.core.investigation import analyse, merge_results, shared_infrastructure
from ariadne.models import (
    BTC,
    NodeType,
    TraceNode,
    TraceResult,
    Transaction,
    TxInput,
    TxOutput,
    is_valid_address,
)
from ariadne.providers.evm import EVM_CHAINS, build_evm_provider, is_evm


# ---------------- multi-chain EVM ----------------
def test_evm_registry_contracts_and_construction():
    # Every EVM token entry has a 0x contract with correct decimals; natives have none.
    for _code, (base, _sym, dec, contract) in EVM_CHAINS.items():
        assert base.startswith("https://") and base.endswith(".blockscout.com")
        if contract is not None:
            assert contract.lower().startswith("0x") and len(contract) == 42
            assert dec in (6, 18)
    # A few key chains construct with the right asset + contract.
    p = build_evm_provider("usdt-pol")
    assert p.asset_info.symbol == "USDT" and p.token_contract == EVM_CHAINS["usdt-pol"][3].lower()
    assert "polygon" in p.base_url
    p2 = build_evm_provider("base")  # native ETH on Base
    assert p2.asset_info.symbol == "ETH" and p2.token_contract is None and "base" in p2.base_url


def test_evm_address_validation_and_routing():
    assert is_evm("usdc-arb") and is_evm("eth") and not is_evm("btc")
    for code in ("usdt-pol", "usdc-base", "usdt-op", "eth"):
        assert is_valid_address("0x28C6c06298d514Db089934071355E5743bf21d60", code)
        assert not is_valid_address("12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw", code)  # BTC addr


def test_evm_chains_enabled_by_default(monkeypatch):
    monkeypatch.delenv("ARIADNE_ENABLE_CHAINS", raising=False)
    enabled = config.enabled_chains()
    for code in ("usdt-pol", "usdc-arb", "usdc-base", "usdt-op", "pol", "arb"):
        assert code in enabled, code
    assert "xmr" not in enabled  # still gated


# ---------------- multi-seed investigation ----------------
def _trace(seed, path):
    r = TraceResult(seed=seed, direction="forward", asset=BTC)
    r.add_node(TraceNode(seed, NodeType.SEED, 0))
    prev = seed
    for i, a in enumerate(path, 1):
        r.add_node(TraceNode(a, NodeType.SERVICE if a == "EXCH" else NodeType.ADDRESS, i))
        r.edge(prev, a).value = 100
        prev = a
    return r


def test_multiseed_shared_infrastructure_and_hub():
    # Two separate suspects both route through MIX to the same EXCH.
    res = [_trace("scamA", ["a1", "MIX", "EXCH"]), _trace("scamB", ["b1", "MIX", "EXCH"])]
    merged = merge_results(res)
    assert len(merged.nodes) == 6 and len(merged.edges) == 5  # shared MIX->EXCH deduped

    shared = {s["address"]: s["seed_count"] for s in shared_infrastructure(res)}
    assert shared.get("MIX") == 2 and shared.get("EXCH") == 2

    analysis = analyse(res)
    top = [h for h in analysis["hubs"] if h["betweenness"] > 0]
    assert top and top[0]["address"] == "MIX"  # the broker both suspects route through


# ---------------- statistical anomaly layer ----------------
def test_anomaly_detects_outlier_with_explanation():
    items = [{"id": f"n{i}", "x": 1.0} for i in range(12)] + [{"id": "outlier", "x": 100.0}]
    res = {r["id"]: r for r in detect_anomalies(items, ["x"], threshold=3.5)}
    assert res["outlier"]["is_anomaly"] and res["outlier"]["drivers"][0]["feature"] == "x"
    assert not res["n0"]["is_anomaly"]


def test_anomaly_in_trace_flags_subdistributor_not_seed():
    r = TraceResult(seed="seed", direction="forward", asset=BTC)
    r.add_node(TraceNode("seed", NodeType.SEED, 0))
    for i in range(30):
        m = f"mule{i}"; r.add_node(TraceNode(m, NodeType.ADDRESS, 1)); r.edge("seed", m).value = 100
    for i in range(3):  # mule0 sub-distributes to 3 — the behavioural outlier
        n = f"norm{i}"; r.add_node(TraceNode(n, NodeType.ADDRESS, 2)); r.edge("mule0", n).value = 50
    flagged = {a["address"] for a in anomalies_in_trace(r)}
    assert "mule0" in flagged and "seed" not in flagged


# ---------------- autopilot ----------------
def test_autopilot_cycle(tmp_path):
    from ariadne.monitor.autopilot import Autopilot

    class FakeWatch:
        def __init__(self): self.calls = 0
        def list(self): return [{"address": "x"}]
        def check_movements(self, bp, cache):
            self.calls += 1
            return [{"address": "s1", "chain": "btc", "new_transactions": 2, "note": ""}] if self.calls == 1 else []

    class Cap:
        def __init__(self): self.events = []
        def alert(self, e): self.events.append(e)

    class FakeCache:
        def close(self): pass

    cap = Cap()
    refreshed = []
    ap = Autopilot(FakeWatch(), lambda c, cache: None, cap, FakeCache,
                   feed_interval=50, state_path=tmp_path / "st.json",
                   refresh_feeds=lambda: refreshed.append(1) or 100)
    r1 = ap.cycle(now=1000)          # movement + first-ever refresh (1000-0 >= 50)
    assert r1["watch_alerts"] == 1 and r1["feeds_refreshed"]
    r2 = ap.cycle(now=1010)          # no movement, feeds fresh (1010-1000 < 50)
    assert r2["watch_alerts"] == 0 and not r2["feeds_refreshed"]
    assert any(e["type"] == "watchlist_movement" for e in cap.events)


# ---------------- taint-guided tracing ----------------
def test_taint_guided_follows_dirty_branch():
    from ariadne.core.trace import Tracer

    def tx(txid, ins, outs):
        return Transaction(txid, [TxInput(a, v) for a, v in ins],
                           [TxOutput(a, v, i) for i, (a, v) in enumerate(outs)], block_time=1)

    db = {
        "seed": [tx("t0", [("seed", 100)], [("A", 90), ("B", 10)])],
        "A": [tx("tA", [("A", 90)], [("A2", 85)])],
        "A2": [tx("tA2", [("A2", 85)], [("A3", 80)])],
        "B": [tx("tB", [("B", 10)], [("B2", 9)])],
    }

    class P:
        name = "fake"; asset_info = BTC
        def normalize(self, a): return a
        def address_tx_count(self, a): return 3
        def address_received(self, a): return None
        def get_transactions(self, a, n=200): return db.get(a, [])

    # Under a tight budget, best-first spends it on the dirtiest (A) branch.
    r = Tracer(P()).trace_forward("seed", depth=4, min_value=1, max_branch=8, follow="dirty", max_nodes=3)
    assert "A2" in r.nodes and "B2" not in r.nodes
    assert all(e.dst in r.nodes for e in r.edges.values())  # no dangling edges


# ---------------- round-trip detection ----------------
def test_round_trip_detection():
    from ariadne.core.patterns import detect_round_trips
    r = TraceResult(seed="seed", direction="forward", asset=BTC)
    for a, d in [("seed", 0), ("a1", 1), ("a2", 2)]:
        r.add_node(TraceNode(a, NodeType.SEED if a == "seed" else NodeType.ADDRESS, d))
    r.edge("seed", "a1").value = 100
    r.edge("a1", "a2").value = 90
    r.edge("a2", "seed").value = 50   # returns to origin
    trips = detect_round_trips(r)
    assert trips and trips[0]["returns_to_seed"] and trips[0]["to"] == "seed"
