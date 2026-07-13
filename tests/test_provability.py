"""Deterministic tests for v0.6 provability: reproducibility digest + offline replay."""

import copy

import pytest

from ariadne import evidence
from ariadne.providers.ethereum import EthereumProvider


def _report():
    return {
        "generated_at": "t1", "asset": "BTC", "version": "x",
        "trace": {"seed": "S", "direction": "forward", "created_at": "t1", "taint_model": "haircut",
                  "chain": "btc", "parameters": {"depth": 2, "min_value_sats": 100000, "workers": 4}},
        "findings": [{"address": "X", "confidence": {"level": "high", "score": 80}, "dirty_received": 9.0}],
        "nodes": [{"address": "X", "type": "service", "dirty_received": 9.0}],
        "edges": [{"src": "S", "dst": "X", "raw": 900000000}],
    }


def test_report_digest_ignores_workers_and_enrichments():
    base = _report()
    # Same analysis, different perf knob + post-analysis enrichments must NOT change the digest.
    variant = copy.deepcopy(base)
    variant["generated_at"] = "t999"
    variant["trace"]["created_at"] = "t999"
    variant["trace"]["parameters"]["workers"] = 1            # perf knob
    variant["valuation"] = {"seed_disbursed_usd": 1234}      # fiat enrichment
    variant["cross_references"] = [{"address": "X"}]         # KB enrichment
    variant["atm_intel"] = [{"operator": "Bcash"}]           # registry enrichment
    variant["nodes"][0]["value_usd"] = 500000                # per-node fiat
    variant["findings"][0]["value_usd"] = 500000
    assert evidence.report_digest(base) == evidence.report_digest(variant)


def test_report_digest_reflects_substantive_change():
    base = _report()
    changed = copy.deepcopy(base)
    changed["findings"][0]["dirty_received"] = 999.0         # a real analytical change
    assert evidence.report_digest(base) != evidence.report_digest(changed)


def test_offline_provider_never_touches_network():
    # A fresh (empty) cache in offline mode must yield no data and make no request.
    p = EthereumProvider(asset="USDT", cache=_TmpCache(), offline=True)
    assert p.get_transactions("0x28C6c06298d514Db089934071355E5743bf21d60") == []
    assert p.address_tx_count("0x28C6c06298d514Db089934071355E5743bf21d60") == 0


class _TmpCache:
    """Minimal empty cache: every lookup misses; puts are ignored."""
    def get(self, key):
        return None

    def put(self, key, url, body):
        return "0" * 64


def test_benchmark_structure_and_perfect_label_recall():
    from ariadne import benchmark
    res = benchmark.run(per_category=20, negatives=30)
    # Labels are the ground truth, so label-assisted detection is perfect by construction;
    # the FP-rate on legitimate negatives must be 0 (it never falsely accuses).
    assert res["overall"]["metrics"]["false_positive_rate"] == 0.0
    assert set(res["per_category"]) <= {"sanctioned", "ransomware", "scam"}
    for cat in res["per_category"].values():
        assert cat["recall"] == 1.0
    md = benchmark.to_markdown(res)
    assert "accuracy benchmark" in md.lower() and "Per category" in md


def test_pdf_expert_report(tmp_path):
    pytest.importorskip("fpdf")  # optional dependency
    from ariadne.report.pdf import write_expert_pdf
    report = {
        "version": "0.6.0", "asset": "BTC", "summary_text": "Test.",
        "trace": {"seed": "12t9", "direction": "forward", "taint_model": "fifo", "parameters": {"depth": 4}},
        "summary": {"addresses": 3, "flows": 2, "findings": 1},
        "methodology": {"taint_statement": "FIFO."},
        "findings": [{"address": "0xabc", "type": "service", "label": "Binance",
                      "confidence": {"level": "low", "score": 20, "disposition": "Lead."}, "dirty_received": 9.0}],
        "risk": {"level": "critical", "score": 94, "primary_typology": "Ransomware cash-out", "typologies": []},
        "screening": {"verdict": "clear", "reasons": ["none"]},
        "brief": {"recommended_next_steps": ["Subpoena the exchange."]},
    }
    out = tmp_path / "expert.pdf"
    write_expert_pdf(report, out, bundle={"custody_count": 5, "custody_root": "x", "signature": {}}, case_ref="C-1")
    data = out.read_bytes()
    assert data[:5] == b"%PDF-" and len(data) > 1000
