"""Deterministic tests for the intelligence-layer upgrades (no network)."""

from ariadne.core.change import identify_change, trailing_zeros
from ariadne.core.cluster import Clusterer
from ariadne.core.risk import assess_risk, classify
from ariadne.core.screening import screen
from ariadne.core.temporal import analyze, infer_utc_offset
from ariadne.models import BTC, Transaction, TxInput, TxOutput
from ariadne.report.expert import build_expert_report


def _tx(txid, ins, outs, t=None):
    return Transaction(txid, [TxInput(a, v) for a, v in ins],
                       [TxOutput(a, v, i) for i, (a, v) in enumerate(outs)], block_time=t)


# ---------------- temporal ----------------
def test_temporal_timezone_inference():
    base = 1699920000  # UTC midnight
    day = 86400
    # Busiest around 12:00 UTC -> operator ~UTC+2 (Eastern Europe / Greece).
    ts = [base + d * day + h * 3600 for d in range(20) for h in (10, 11, 12, 13, 14)]
    p = analyze(ts)
    assert p.events == 100
    assert p.likely_utc_offset == 2
    assert "Greece" in p.region_hint or "Eastern Europe" in p.region_hint
    assert p.median_interval_s is not None


def test_temporal_uniform_activity_has_no_offset():
    base = 1699920000
    ts = [base + d * 86400 + h * 3600 for d in range(5) for h in range(24)]
    assert infer_utc_offset(analyze(ts).hour_histogram) is None


# ---------------- change-address heuristic ----------------
def test_change_address_identification():
    assert trailing_zeros(50_000_000) == 7 and trailing_zeros(47_281_734) == 0
    tx = _tx("t", [("seed", 100_000_000)], [("merchant", 50_000_000), ("change", 47_281_734)])
    change = identify_change(tx, {"seed"})
    assert change is not None and change.address == "change"
    # Both round -> ambiguous -> None.
    amb = _tx("t2", [("seed", 100_000_000)], [("a", 50_000_000), ("b", 50_000_000)])
    assert identify_change(amb, {"seed"}) is None


def test_clustering_absorbs_change_address():
    tx = _tx("t", [("seed", 100_000_000)], [("merchant", 50_000_000), ("chg", 47_281_734)])

    class P:
        name = "fake"; asset_info = BTC
        def normalize(self, a): return a
        def address_tx_count(self, a): return 3
        def get_transactions(self, a, n=100): return {"seed": [tx]}.get(a, [])

    members = Clusterer(P()).cluster("seed").members
    assert "chg" in members and "seed" in members


# ---------------- risk / typology ----------------
def _laundering_report():
    return {
        "trace": {"seed": "wc1"},
        "asset": "BTC",
        "findings": [
            {"address": "wc1", "category": "ransomware", "confidence": {"level": "high", "score": 88}},
            {"address": "ex1", "category": "exchange", "confidence": {"level": "low", "score": 20}},
        ],
        "nodes": [
            {"address": "wc1", "category": "ransomware", "type": "seed", "depth": 0},
            {"address": "tc", "category": "mixer", "type": "address", "depth": 1, "dirty_received": 3.0},
            {"address": "ex1", "category": "exchange", "type": "service", "depth": 2, "dirty_received": 2.0},
        ],
        "mixing_events": [{"txid": "m1"}],
        "patterns": {"peel_chains": [["a", "b", "c"]], "off_ramps": [{"to": "ex1"}]},
    }


def test_risk_typology_classification():
    r = assess_risk(_laundering_report())
    assert r["level"] == "critical" and r["score"] >= 85
    ids = {t["id"] for t in r["typologies"]}
    assert "ransomware_cashout" in ids and "mixing_layering" in ids and "peel_chain_layering" in ids
    assert r["primary_typology"] == "Ransomware cash-out"


def test_sanctions_typology():
    rep = {"trace": {"seed": "s"}, "asset": "BTC",
           "findings": [{"address": "x", "category": "sanctioned", "confidence": {"level": "confirmed", "score": 100}}],
           "nodes": [{"address": "x", "category": "sanctioned", "type": "address", "depth": 1}],
           "mixing_events": [], "patterns": {}}
    assert any(t.id == "sanctions_exposure" for t in classify(rep))


# ---------------- sanctions screening ----------------
def test_screening_verdicts():
    direct = {"trace": {"seed": "s"}, "asset": "BTC", "nodes": [
        {"address": "s", "type": "seed", "depth": 0},
        {"address": "ofac", "category": "sanctioned", "depth": 1, "dirty_received": 5.0}]}
    assert screen(direct).verdict == "direct_exposure" and screen(direct).sanctioned

    indirect = {"trace": {"seed": "s"}, "asset": "BTC", "nodes": [
        {"address": "s", "type": "seed", "depth": 0},
        {"address": "ofac", "category": "sanctioned", "depth": 3, "dirty_received": 1.0}]}
    assert screen(indirect).verdict == "indirect_exposure"

    clear = {"trace": {"seed": "s"}, "asset": "BTC", "nodes": [{"address": "s", "depth": 0}]}
    assert screen(clear).verdict == "clear"

    self_sanc = {"trace": {"seed": "s"}, "asset": "BTC",
                 "nodes": [{"address": "s", "category": "sanctioned", "depth": 0}]}
    assert screen(self_sanc).verdict == "sanctioned_entity"


# ---------------- expert report ----------------
def test_expert_report_has_required_sections():
    md = build_expert_report(
        {**_laundering_report(),
         "version": "0.2.0",
         "summary_text": "Test summary.",
         "methodology": {"taint_model": "fifo", "taint_statement": "FIFO."},
         "summary": {"addresses": 3, "flows": 2},
         "risk": assess_risk(_laundering_report()),
         "screening": screen(_laundering_report()).as_dict(),
         "temporal": {"events": 0},
         "brief": {"recommended_next_steps": ["Subpoena the exchange."]}},
        bundle={"custody_count": 20, "custody_root": "root123",
                "signature": {"algorithm": "ed25519", "public_key": "pk"}},
        case_ref="HELLAS-2026-001",
    )
    for needle in ("Methodology", "Findings", "Limitations", "Chain of custody",
                   "root123", "HELLAS-2026-001", "Ransomware cash-out"):
        assert needle in md
