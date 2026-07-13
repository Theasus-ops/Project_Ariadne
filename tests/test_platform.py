"""Deterministic tests for the v0.4 investigation-platform features (no network)."""

from ariadne.core.cluster import Cluster
from ariadne.core.entity import build_entity
from ariadne.core.taint import compute_taint
from ariadne.core.trace import Tracer
from ariadne.enrich.attribution import AttributionStore
from ariadne.enrich.labels import Label, LabelCategory, LabelStore
from ariadne.enrich.prices import PriceOracle, enrich_prices
from ariadne.knowledge import KnowledgeStore
from ariadne.models import BTC, Transaction, TxInput, TxOutput
from ariadne.monitor.scoring import TxScorer
from ariadne.monitor.watchlist import Watchlist
from ariadne.report.export import to_csv_edges, to_graphml
from ariadne.report.report import build_report


def _tx(txid, ins, outs, t=None):
    return Transaction(txid, [TxInput(a, v) for a, v in ins],
                       [TxOutput(a, v, i) for i, (a, v) in enumerate(outs)], block_time=t)


# ---------------- fiat valuation (offline via monkeypatch) ----------------
def test_price_valuation(tmp_path, monkeypatch):
    o = PriceOracle(tmp_path / "px.sqlite")
    monkeypatch.setattr(o, "_fetch_usd", lambda pair, ts: 70000.0)
    monkeypatch.setattr(o, "_fetch_fx", lambda ts: 0.9)
    v = o.value("BTC", 2.0, ts=1710460800)
    assert v["usd"] == 140000.0 and v["eur"] == 126000.0
    assert o.value("USDT", 1000.0)["usd"] == 1000.0  # stablecoin pinned
    o.close()


def test_enrich_prices_report(tmp_path, monkeypatch):
    o = PriceOracle(tmp_path / "px2.sqlite")
    monkeypatch.setattr(o, "_fetch_usd", lambda pair, ts: 100.0)
    monkeypatch.setattr(o, "_fetch_fx", lambda ts: 0.5)
    report = {"asset": "BTC", "trace": {"seed": "s"},
              "nodes": [{"address": "s", "type": "seed", "dirty_received": 10.0},
                        {"address": "ex", "type": "service", "dirty_received": 4.0}],
              "edges": [{"src": "s", "dst": "ex", "first_time": 1710460800}],
              "findings": [{"address": "ex"}]}
    enrich_prices(report, o)
    assert report["valuation"]["seed_disbursed_usd"] == 1000.0
    assert report["valuation"]["total_cashout_usd"] == 400.0
    assert report["findings"][0]["value_eur"] == 200.0
    o.close()


# ---------------- watchlist ----------------
def test_watchlist_movement_and_scorer(tmp_path):
    wl = Watchlist(tmp_path / "wl.sqlite")
    wl.add("suspect", "btc", note="ring lead")
    assert wl.watched_addresses() == {"suspect"}

    counts = {"suspect": 5}

    class P:
        name = "fake"; asset_info = BTC
        def normalize(self, a): return a
        def address_tx_count(self, a): return counts.get(a, 0)

    assert wl.check_movements(lambda c, cache: P(), None) == []   # baseline
    counts["suspect"] = 8
    alerts = wl.check_movements(lambda c, cache: P(), None)
    assert len(alerts) == 1 and alerts[0]["new_transactions"] == 3
    wl.close()

    scorer = TxScorer(BTC, LabelStore(), watchlist={"suspect"})
    sc = scorer.score(_tx("t", [("x", 10**8)], [("suspect", 10**8)]))
    assert sc.total >= 100 and sc.level == "critical"


# ---------------- cross-case linking ----------------
def _min_report(seed, extra_addr):
    return {
        "trace": {"seed": seed, "direction": "forward"},
        "summary": {"addresses": 2, "flows": 1, "findings": 1},
        "summary_text": "x",
        "findings": [{"address": extra_addr, "type": "service",
                      "confidence": {"level": "low", "score": 20}, "dirty_received": 1.0}],
        "nodes": [{"address": seed, "type": "seed", "label": None},
                  {"address": extra_addr, "type": "service", "label": "Shared Exchange"}],
        "edges": [{"src": seed, "dst": extra_addr, "raw": 100}],
    }


def test_cross_references(tmp_path):
    k = KnowledgeStore(tmp_path / "kb.sqlite")
    k.record_trace(_min_report("seedA", "sharedX"), "btc")
    k.record_trace(_min_report("seedB", "sharedX"), "btc")
    # Tracing seedB: sharedX also appeared under seedA.
    xrefs = k.cross_references(["seedB", "sharedX"], "seedB")
    assert len(xrefs) == 1 and xrefs[0]["address"] == "sharedX"
    assert xrefs[0]["links"][0]["other_seed"] == "seedA"
    k.close()


# ---------------- trace completeness ----------------
def test_trace_completeness_metric():
    # Seed sends to 3 recipients but max_branch=1 keeps only the biggest -> partial.
    db = {"seed": [_tx("t", [("seed", 100)], [("a", 60), ("b", 30), ("c", 10)], t=1)]}

    class P:
        name = "fake"; asset_info = BTC
        def normalize(self, a): return a
        def address_tx_count(self, a): return 2
        def address_received(self, a): return None
        def get_transactions(self, a, n=200): return db.get(a, [])

    r = Tracer(P()).trace_forward("seed", depth=2, min_value=1, max_branch=1)
    compute_taint(r)
    comp = build_report(r)["completeness"]
    assert comp["followed_fraction"] < 1.0          # only 60 of 100 kept
    assert abs(comp["followed_fraction"] - 0.6) < 0.01


# ---------------- graph export ----------------
def test_graph_export_formats():
    r = Tracer(_ExportProv()).trace_forward("seed", depth=1, min_value=1)
    compute_taint(r)
    gml = to_graphml(r)
    assert gml.startswith("<?xml") and "<graphml" in gml and "seed" in gml
    edges_csv = to_csv_edges(r)
    assert "src,dst,value" in edges_csv and "seed" in edges_csv


class _ExportProv:
    name = "fake"; asset_info = BTC
    def normalize(self, a): return a
    def address_tx_count(self, a): return 2
    def address_received(self, a): return None
    def get_transactions(self, a, n=200):
        return {"seed": [_tx("t", [("seed", 100)], [("dst", 100)], t=1)]}.get(a, [])


# ---------------- entities ----------------
def test_entity_build_and_persist(tmp_path):
    labels = LabelStore()
    labels.add(Label("mixerX", LabelCategory.MIXER, "Tornado", "t"))
    cluster = Cluster(seed="a")
    cluster.members = {"a", "b", "mixerX"}
    cluster.services_touched = {"mixerX": "mixer"}
    cluster.links = [{"txid": "t1", "addresses": ["a", "b"]}]
    entity = build_entity(cluster, labels)
    assert entity["member_count"] == 3 and "mixer" in entity["risk_flags"] and entity["risk"] == "high"

    k = KnowledgeStore(tmp_path / "ek.sqlite")
    eid = k.save_entity(entity)
    found = k.find_entity("b")
    assert found is not None and found["id"] == eid and "a" in found["members"]
    k.close()


# ---------------- analyst manual attribution ----------------
def test_analyst_label(tmp_path):
    store = AttributionStore(tmp_path / "attr.sqlite")
    store.upsert("bc1qcourier", "service", "Courier wallet", source="analyst", confidence=0.9, chain="btc")
    best = store.best("bc1qcourier")
    assert best is not None and best.name == "Courier wallet" and best.source == "analyst"
    ls = store.as_label_store()
    assert ls.get("bc1qcourier").category.value == "service"
    store.close()
