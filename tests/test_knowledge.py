"""Tests for the persistent knowledge base (no network)."""

import pathlib
import tempfile

from ariadne.knowledge import KnowledgeStore


def _report(seed, level="high", score=88):
    return {
        "trace": {"seed": seed, "direction": "forward"},
        "summary": {"addresses": 2, "flows": 1, "findings": 1},
        "summary_text": "test trace",
        "findings": [
            {"address": seed, "type": "seed", "dirty_received": 1.5,
             "confidence": {"level": level, "score": score}}
        ],
        "nodes": [
            {"address": seed, "type": "seed", "label": "WannaCry"},
            {"address": "svc1", "type": "service", "label": None},
        ],
        "edges": [{"src": seed, "dst": "svc1", "raw": 100_000_000}],
    }


def _store():
    d = tempfile.mkdtemp()
    return KnowledgeStore(pathlib.Path(d) / "k.sqlite")


def test_record_and_recall():
    k = _store()
    k.record_trace(_report("SEED1"), "btc")
    r = k.recall("SEED1")
    assert r["known"] and r["entity"]["best_confidence"] == "high"
    assert len(r["appearances"]) == 1
    assert k.recall("never-seen")["known"] is False
    k.close()


def test_wei_scale_values_do_not_overflow_and_round_trip_exactly():
    # 15 ETH in wei = 1.5e19 > 2**63 (SQLite's INTEGER ceiling). Before the TEXT-money
    # fix this raised OverflowError and killed every EVM trace on persist.
    WEI = 15 * 10**18
    k = _store()
    report = {
        "trace": {"seed": "0xseed", "direction": "forward"},
        "summary": {"addresses": 2, "flows": 1, "findings": 1},
        "summary_text": "eth trace",
        "findings": [{"address": "0xseed", "type": "seed", "dirty_received": WEI,
                      "confidence": {"level": "high", "score": 80}}],
        "nodes": [{"address": "0xseed", "type": "seed", "label": None},
                  {"address": "0xsvc", "type": "service", "label": "Binance"}],
        "edges": [{"src": "0xseed", "dst": "0xsvc", "raw": WEI}],
    }
    k.record_trace(report, "eth")   # must not raise

    edges = {(e["src"], e["dst"]): e for e in k.all_edges()}
    assert edges[("0xseed", "0xsvc")]["total_value"] == WEI          # exact, not a lossy float
    assert isinstance(edges[("0xseed", "0xsvc")]["total_value"], int)
    assert k.recall("0xseed")["appearances"][0]["dirty"] == WEI      # exact big int

    # Python-side accumulation stays exact across records (SQL summing would go lossy-float).
    k.record_trace(report, "eth")
    assert {(e["src"], e["dst"]): e for e in k.all_edges()}[("0xseed", "0xsvc")]["total_value"] == 2 * WEI
    k.close()


def test_accumulates_across_investigations():
    k = _store()
    k.record_trace(_report("SEED1"), "btc")
    k.record_trace(_report("SEED1"), "btc")
    assert k.recall("SEED1")["entity"]["times_seen"] == 2
    k.close()


def test_integrity_and_tamper_detection():
    k = _store()
    k.record_trace(_report("A"), "btc")
    k.record_trace(_report("B"), "btc")
    assert k.verify_integrity()["ok"] is True
    # Silently alter a past record -> the hash chain must break.
    k._conn.execute("UPDATE investigations SET seed='HACKED' WHERE id=1")
    k._conn.commit()
    v = k.verify_integrity()
    assert v["ok"] is False and v["broken_at"] == 1
    k.close()


def test_stats():
    k = _store()
    k.record_trace(_report("A"), "btc")
    s = k.stats()
    assert s["investigations"] == 1 and s["entities"] >= 2 and s["edges"] >= 1
    k.close()


def test_tracer_survives_provider_failure():
    """A failing provider must degrade to a partial result, never crash the request."""
    from ariadne.core.trace import Tracer
    from ariadne.models import BTC

    class _BrokenProvider:
        name = "broken"
        asset_info = BTC

        def normalize(self, a):
            return a

        def address_tx_count(self, a):
            raise RuntimeError("api down")

        def address_received(self, a):
            raise RuntimeError("api down")

        def get_transactions(self, a, n):
            raise RuntimeError("api down")

    result = Tracer(_BrokenProvider()).trace_forward("seed", depth=2)
    assert result.seed == "seed" and len(result.nodes) == 1  # graceful, no exception


def test_daemon_alerts_and_dedups():
    """The daemon alerts on a suspicious tx once, and never re-alerts it."""
    from ariadne.enrich.labels import LabelStore
    from ariadne.models import BTC, Transaction, TxInput, TxOutput
    from ariadne.monitor.daemon import MonitorDaemon
    from ariadne.monitor.monitor import Monitor

    big = Transaction("txAAA", [TxInput("in", 1000 * 10**8)], [TxOutput("out", 1000 * 10**8, 0)])

    class _Prov:
        name = "fake"
        asset_info = BTC

        def normalize(self, a):
            return a

        def latest_block_height(self):
            return 100

        def get_block_transactions(self, h, n):
            return [big] if h == 100 else []

        def address_tx_count(self, a):
            return 1

        def address_received(self, a):
            return 0

        def get_transactions(self, a, n):
            return []

    monitor = Monitor(_Prov(), LabelStore(), threshold=10, large_value_units=1)
    events: list[dict] = []

    class _Notifier:
        def alert(self, e):
            events.append(e)

    state = pathlib.Path(tempfile.mkdtemp()) / "state.json"
    daemon = MonitorDaemon(monitor, _Notifier(), auto_trace=False, state_path=state)
    first = daemon.poll_once()
    second = daemon.poll_once()  # no new block -> nothing
    assert len(first) == 1 and first[0]["txid"] == "txAAA"
    assert second == []  # dedup + no new block
    assert len(events) == 1
