"""Deterministic tests for mixer de-anonymisation (no network)."""

from ariadne.core.demix import MixerCorrelator, coinjoin_linkability, extract_mixer_events
from ariadne.models import Transaction, TxInput, TxOutput


def _tx(ins, outs):
    return Transaction("t", [TxInput(a, v) for a, v in ins],
                       [TxOutput(a, v, i) for i, (a, v) in enumerate(outs)])


def test_perfect_mix_has_no_deterministic_linkage():
    d = 1_000_000
    wp = _tx([(f"in{i}", d) for i in range(5)], [(f"out{i}", d) for i in range(5)])
    r = coinjoin_linkability(wp)
    assert r["anonymity_set"] == 5 and r["all_outputs_equal"]
    assert r["deterministic_links"] == []           # honest: a perfect mix is not reversible
    assert "no deterministic linkage" in r["verdict"].lower()


def test_imperfect_mix_leaks_forced_links():
    # Distinct, unique amounts that can only balance one way.
    imp = _tx([("inA", 3_000_000), ("inB", 7_000_000)],
              [("outX", 3_000_000), ("outY", 7_000_000)])
    r = coinjoin_linkability(imp)
    links = {(dl["input"], dl["output"]) for dl in r["deterministic_links"]}
    assert ("inA", "outX") in links and ("inB", "outY") in links


def test_mixer_correlator_address_reuse_and_temporal_cap():
    deps = [{"address": "0xAlice", "txid": "d1", "amount": 1.0, "time": 1000},
            {"address": "0xBob", "txid": "d2", "amount": 1.0, "time": 1100}]
    wds = [{"address": "0xAlice", "txid": "w1", "amount": 1.0, "time": 2000},
           {"address": "0xCarol", "txid": "w2", "amount": 1.0, "time": 1200}]
    links = MixerCorrelator().correlate(deps, wds)
    top = links[0]
    assert top.deposit["address"] == "0xAlice" and top.withdrawal["address"] == "0xAlice"
    assert top.probability >= 0.9            # address reuse is near-certain
    # timing-only links are capped and never claim certainty
    timing = [m for m in links if m.deposit["address"] != m.withdrawal["address"]]
    assert timing and all(m.probability <= 0.5 for m in timing)


def test_mixer_correlator_requires_denomination_match():
    deps = [{"address": "a", "txid": "d", "amount": 1.0, "time": 1}]
    wds = [{"address": "b", "txid": "w", "amount": 10.0, "time": 2}]  # different pool
    assert MixerCorrelator().correlate(deps, wds) == []


def test_extract_mixer_events_from_report():
    report = {"asset": "ETH",
              "nodes": [{"address": "T", "category": "mixer"}],
              "edges": [{"src": "a", "dst": "T", "amount": 1.0, "first_time": 1, "txids": ["d"]},
                        {"src": "T", "dst": "b", "amount": 1.0, "first_time": 2, "txids": ["w"]}]}
    deps, wds = extract_mixer_events(report)
    assert len(deps) == 1 and deps[0]["address"] == "a"
    assert len(wds) == 1 and wds[0]["address"] == "b"
