"""Deterministic tests for the gov-grade upgrade set (no network)."""

import copy

from ariadne import config, evidence
from ariadne.adversarial import run as adversarial_run
from ariadne.cache import ProvenanceCache
from ariadne.core.correlate import BridgeEvent, correlate_events, extract_bridge_events
from ariadne.core.deposit import DepositDetector
from ariadne.core.graph import MoneyGraph
from ariadne.core.taint import compute_taint
from ariadne.core.trace import Tracer
from ariadne.enrich.attribution import AttributionStore
from ariadne.enrich.labels import Label, LabelCategory, LabelStore
from ariadne.models import BTC, NodeType, TraceNode, TraceResult, Transaction, TxInput, TxOutput
from ariadne.providers.ethereum import EthereumProvider


def _tx(txid, ins, outs, t=None):
    return Transaction(txid, [TxInput(a, v) for a, v in ins],
                       [TxOutput(a, v, i) for i, (a, v) in enumerate(outs)], block_time=t)


def _graph_3():
    r = TraceResult(seed="S", direction="forward", asset=BTC)
    r.add_node(TraceNode("S", NodeType.SEED, 0))
    a = TraceNode("A", NodeType.ADDRESS, 1); a.total_received = 20 * 10**8; r.add_node(a)
    d = TraceNode("D", NodeType.ADDRESS, 2); d.total_received = 10 * 10**8; r.add_node(d)
    e1 = r.edge("S", "A"); e1.value = 5 * 10**8; e1.first_time = 100
    e2 = r.edge("A", "D"); e2.value = 5 * 10**8; e2.first_time = 300
    return r


# ---------------- taint models ----------------
def test_taint_models_differ():
    r = _graph_3(); compute_taint(r, "fifo")
    assert r.taint_model == "fifo"
    assert r.nodes["D"].dirty_received == 5 * 10**8  # FIFO spends the dirty receipt first

    r2 = _graph_3(); compute_taint(r2, "haircut")
    assert r2.nodes["D"].dirty_received < 5 * 10**8  # haircut dilutes

    r3 = _graph_3(); compute_taint(r3, "poison")
    assert r3.nodes["A"].taint_fraction == 1.0 and r3.nodes["D"].taint_fraction == 1.0


def test_taint_default_is_haircut_and_conserves():
    r = _graph_3(); compute_taint(r)
    assert r.taint_model == "haircut"
    assert r.nodes["D"].dirty_received <= r.nodes["S"].dirty_received + 1


# ---------------- evidence ----------------
def _report():
    return {
        "generated_at": "t", "asset": "BTC", "version": "x",
        "trace": {"seed": "S", "direction": "forward", "created_at": "t", "parameters": {}, "taint_model": "fifo"},
        "findings": [{"address": "X", "confidence": {"level": "high", "score": 80}, "dirty_received": 9.0}],
        "nodes": [], "edges": [], "brief": {"risk_level": "high"},
    }


def test_evidence_sign_verify_and_tamper(tmp_path):
    custody = [{"key": "k1", "url": "u1", "fetched_at": 1.0, "sha256": "aa" * 32}]
    bundle = evidence.build_evidence_bundle(_report(), custody=custody, key_path=tmp_path / "k.key")
    assert bundle["signature"]["algorithm"] == "ed25519"
    assert evidence.verify_bundle(bundle)["ok"]

    tampered = copy.deepcopy(bundle)
    tampered["report"]["findings"][0]["dirty_received"] = 999.0
    assert not evidence.verify_bundle(tampered)["ok"]

    tampered2 = copy.deepcopy(bundle)
    tampered2["custody"][0]["sha256"] = "bb" * 32
    assert not evidence.verify_bundle(tampered2)["ok"]


def test_evidence_report_digest_ignores_timestamps():
    r1 = _report()
    r2 = copy.deepcopy(r1); r2["generated_at"] = "later"; r2["trace"]["created_at"] = "later"
    assert evidence.report_digest(r1) == evidence.report_digest(r2)


# ---------------- attribution store ----------------
def test_attribution_versioning(tmp_path):
    store = AttributionStore(tmp_path / "attr.sqlite")
    store.upsert("0xabc", "exchange", "KuCoin 2", "feed")
    store.upsert("0xabc", "exchange", "KuCoin 2", "feed")   # unchanged -> refresh
    store.upsert("0xabc", "exchange", "KuCoin 5", "feed")   # changed -> supersede
    hist = store.history("0xabc")
    assert [h.version for h in hist] == [1, 2]
    assert hist[0].superseded and not hist[1].superseded
    assert store.best("0xabc").name == "KuCoin 5"
    ls = store.as_label_store()
    assert ls.get("0xabc").name == "KuCoin 5"
    store.close()


# ---------------- deposit discovery ----------------
def _deposit_provider():
    db = {"dep": [
        _tx("r1", [("f1", 100)], [("dep", 100)]),
        _tx("r2", [("f2", 100)], [("dep", 100)]),
        _tx("r3", [("f3", 100)], [("dep", 100)]),
        _tx("sw", [("dep", 300)], [("hot", 295), ("dep", 5)]),
    ]}

    class P:
        name = "fake"; asset_info = BTC
        def normalize(self, a): return a
        def address_tx_count(self, a): return 200000 if a == "hot" else 4
        def get_transactions(self, a, n=200): return db.get(a, [])
    return P()


def test_deposit_detector_named_and_unnamed():
    labels = LabelStore(); labels.add(Label("hot", LabelCategory.EXCHANGE, "Binance", "t"))
    f = DepositDetector(_deposit_provider(), label_store=labels).analyze("dep")
    assert f.is_deposit and f.confidence == "high" and "Binance" in f.attribution

    f2 = DepositDetector(_deposit_provider(), label_store=LabelStore()).analyze("dep")
    assert f2.is_deposit and f2.confidence == "medium"


# ---------------- graph analytics ----------------
def test_graph_path_hub_community():
    g = MoneyGraph.from_edges([("S1", "H", 1), ("S2", "H", 1), ("S3", "H", 1), ("H", "E", 3)],
                              labels={"E": "Binance"})
    assert g.shortest_path("S1", "E") == ["S1", "H", "E"]
    assert g.shortest_path("E", "S1") == []          # directed
    assert g.hubs(1)[0]["address"] == "H"            # broker has top betweenness
    comms = g.communities(min_size=2)
    assert comms and comms[0]["size"] == 5


# ---------------- cross-chain correlation ----------------
def test_correlate_matches_bridge_legs():
    deps = [BridgeEvent("TRX", "a", "br1", "scam", 50000.0, 1000, "in")]
    wds = [BridgeEvent("ETH", "b", "br2", "cash", 49900.0, 1300, "out"),
           BridgeEvent("ETH", "c", "br2", "other", 10.0, 1300, "out")]
    m = correlate_events(deps, wds, amount_tolerance=0.02, max_delay_seconds=3600)
    assert len(m) == 1 and m[0].confidence > 0.8 and m[0].withdrawal.amount == 49900.0


def test_extract_bridge_events_from_report():
    report = {"asset": "USDT", "nodes": [{"address": "b", "category": "bridge"}],
              "edges": [{"src": "s", "dst": "b", "amount": 100.0, "first_time": 1, "txids": ["t"]},
                        {"src": "b", "dst": "o", "amount": 99.0, "first_time": 2, "txids": ["u"]}]}
    d, w = extract_bridge_events(report)
    assert len(d) == 1 and len(w) == 1


# ---------------- adversarial suite ----------------
def test_adversarial_suite_all_pass():
    res = adversarial_run()
    assert res["passed"] == res["total"]
    assert res["detection_rate"] == 1.0 and res["false_alarm_rate"] == 0.0


# ---------------- config gating ----------------
def test_config_gating(monkeypatch):
    monkeypatch.delenv("ARIADNE_ENABLE_CHAINS", raising=False)
    monkeypatch.delenv("BLOCKCHAIR_API_KEY", raising=False)
    enabled = config.enabled_chains()
    assert {"btc", "eth", "usdt", "usdc", "trx"} <= enabled
    assert "xmr" not in enabled and "ltc" not in enabled
    monkeypatch.setenv("ARIADNE_ENABLE_CHAINS", "ltc")
    assert config.is_enabled("ltc")


def test_config_proxy_and_endpoint(monkeypatch):
    monkeypatch.setenv("ARIADNE_PROXY", "socks5h://127.0.0.1:9050")
    monkeypatch.setenv("ARIADNE_ENDPOINT_BTC", "http://mynode/api")
    assert config.proxy() == {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
    assert config.provider_kwargs("btc")["base_url"] == "http://mynode/api"


# ---------------- service detection refinement ----------------
def test_illicit_label_not_downgraded_to_service():
    labels = LabelStore(); labels.add(Label("bad", LabelCategory.SANCTIONED, "OFAC", "t"))

    class P:
        name = "fake"; asset_info = BTC
        def normalize(self, a): return a
        def address_tx_count(self, a): return 99999 if a == "bad" else 1  # busy
        def address_received(self, a): return None
        def get_transactions(self, a, n=200):
            if a == "seed":
                return [_tx("t", [("seed", 100)], [("bad", 100)], t=1)]
            return []

    r = Tracer(P(), label_store=labels, service_tx_threshold=3000).trace_forward("seed", depth=1, min_value=1)
    # A busy sanctioned address stays an ADDRESS node (attributable), not a benign SERVICE.
    assert r.nodes["bad"].node_type == NodeType.ADDRESS
    assert r.nodes["bad"].label_category == "sanctioned"


# ---------------- concurrency determinism ----------------
def test_concurrent_tracer_matches_serial():
    db = {"seed": [_tx("t1", [("seed", 100)], [("A", 60), ("B", 40)], t=1)],
          "A": [_tx("t2", [("A", 60)], [("C", 60)], t=2)],
          "B": [_tx("t3", [("B", 40)], [("D", 40)], t=3)]}

    class P:
        name = "fake"; asset_info = BTC
        def normalize(self, a): return a
        def address_tx_count(self, a): return 2
        def address_received(self, a): return None
        def get_transactions(self, a, n=200): return db.get(a, [])

    def edgeset(w):
        r = Tracer(P(), workers=w).trace_forward("seed", depth=3, min_value=1, max_branch=8)
        return sorted((e.src, e.dst, e.value) for e in r.edges.values())

    assert edgeset(1) == edgeset(6)


# ---------------- EVM address_received (taint denominator) ----------------
def test_evm_address_received_sums_inflow(monkeypatch):
    p = EthereumProvider(asset="USDT")
    inflow = [
        Transaction("i1", [TxInput("x", 1000)], [TxOutput("0xme", 1000, 0)]),
        Transaction("o1", [TxInput("0xme", 500)], [TxOutput("y", 500, 0)]),  # outbound, ignored
        Transaction("i2", [TxInput("z", 2000)], [TxOutput("0xme", 2000, 0)]),
    ]
    monkeypatch.setattr(p, "get_transactions", lambda a, max_txs=500: inflow)
    assert p.address_received("0xme") == 3000  # 1000 + 2000 received only


# ---------------- provenance custody ----------------
def test_cache_provenance_custody(tmp_path):
    cache = ProvenanceCache(tmp_path / "c.sqlite")
    cache.mark()
    cache.put("k1", "https://api/x", {"a": 1})
    cache.get("k1")
    recs = cache.provenance()
    assert len(recs) == 1 and recs[0]["url"] == "https://api/x" and len(recs[0]["sha256"]) == 64
    cache.close()
