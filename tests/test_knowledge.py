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
