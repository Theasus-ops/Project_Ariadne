"""Adversarial validation — a deterministic, per-technique detection scorecard.

The network corpus in :mod:`ariadne.validation` checks a handful of real wallets,
but it is small and non-reproducible (it depends on live chain state). Accreditation
needs the complement: a **deterministic** battery that constructs each laundering
technique with *ground truth known by construction*, runs the real engine over it,
and reports detection rates per technique. Because the scenarios are synthetic and
offline, the numbers are exactly reproducible on any machine — the property an
auditor or an expert witness needs.

Each scenario builds a fake provider whose transaction graph exhibits (or, for the
negative controls, does *not* exhibit) one technique, then asserts the detector
fires (or stays silent). The output is a per-technique confusion-style scorecard:
detections, false alarms, and misses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .core.patterns import detect_offramps, detect_peel_chains
from .core.taint import compute_taint
from .core.trace import Tracer
from .enrich.labels import Label, LabelCategory, LabelStore
from .models import BTC, Transaction, TxInput, TxOutput


class ScenarioProvider:
    """A deterministic in-memory provider for adversarial scenarios."""

    name = "adversarial"
    asset_info = BTC

    def __init__(self, db: dict, services: set | None = None, received: dict | None = None):
        self.db = db
        self.services = services or set()
        self.received = received or {}

    def normalize(self, a):
        return a

    def address_tx_count(self, a):
        return 9_000 if a in self.services else len(self.db.get(a, []))

    def address_received(self, a):
        return self.received.get(a)

    def get_transactions(self, a, n=200):
        return self.db.get(a, [])


def _tx(txid, ins, outs, t=None):
    return Transaction(
        txid,
        [TxInput(a, v) for a, v in ins],
        [TxOutput(a, v, i) for i, (a, v) in enumerate(outs)],
        block_time=t,
    )


@dataclass
class Scenario:
    name: str
    technique: str
    build: Callable[[], tuple]   # -> (provider, seed, labels, depth)
    detected: Callable          # (result) -> bool
    expect: bool                # True: technique present; False: negative control


# --------------------------------------------------------------------------- #
# Scenario builders
# --------------------------------------------------------------------------- #
def _coinjoin():
    # Seed spends into a 5-in / 5-out equal-denomination Whirlpool CoinJoin.
    D = 1_000_000
    tx = _tx("cj", [("seed", D)] + [(f"peer{i}", D) for i in range(4)],
             [(f"out{i}", D) for i in range(5)], t=1000)
    return ScenarioProvider({"seed": [tx]}), "seed", None, 2


def _peel_chain():
    # Main artery p0->p1->p2->p3, each forwarding ~70% and peeling ~30% aside.
    db = {}
    amt = 100_000_000
    nodes = ["p0", "p1", "p2", "p3"]
    for i, a in enumerate(nodes[:-1]):
        nxt = nodes[i + 1]
        main = int(amt * 0.7)
        peel = amt - main
        db[a] = [_tx(f"peel{i}", [(a, amt)], [(nxt, main), (f"side{i}", peel)], t=1000 + i)]
        amt = main
    return ScenarioProvider(db), "p0", None, 4


def _fanout():
    # Layering by fan-out: seed sprays to many fresh addresses in one tx.
    outs = [(f"mule{i}", 20_000_000) for i in range(6)]
    return ScenarioProvider({"seed": [_tx("spray", [("seed", 120_000_000)], outs, t=1000)]}), "seed", None, 2


def _offramp():
    # Direct cash-out: seed sends straight to a labelled exchange.
    labels = LabelStore()
    labels.add(Label("binance1", LabelCategory.EXCHANGE, "Binance hot wallet", "test"))
    tx = _tx("cash", [("seed", 50_000_000)], [("binance1", 50_000_000)], t=1000)
    return ScenarioProvider({"seed": [tx]}, services={"binance1"}), "seed", labels, 2


def _clean_negative():
    # Ordinary payment + change. No mixing, no peel, no off-ramp — must stay silent.
    tx = _tx("pay", [("seed", 100_000_000)], [("merchant", 40_000_000), ("seed", 60_000_000)], t=1000)
    return ScenarioProvider({"seed": [tx], "merchant": []}), "seed", None, 2


SCENARIOS = [
    Scenario("CoinJoin entry (Whirlpool)", "coinjoin", _coinjoin,
             lambda r: len(r.mixing_events) >= 1, True),
    Scenario("Peel-chain layering", "peel_chain", _peel_chain,
             lambda r: len(detect_peel_chains(r)) >= 1, True),
    Scenario("Fan-out / layering", "fanout", _fanout,
             lambda r: sum(1 for e in r.edges.values() if e.src == "seed") >= 5, True),
    Scenario("Direct off-ramp to exchange", "offramp", _offramp,
             lambda r: len(detect_offramps(r)) >= 1, True),
    Scenario("Clean payment (negative control)", "clean", _clean_negative,
             lambda r: bool(r.mixing_events) or bool(detect_peel_chains(r)) or bool(detect_offramps(r)), False),
]


@dataclass
class Result:
    scenario: str
    technique: str
    passed: bool
    detected: bool
    expected: bool
    detail: str = ""


def run() -> dict:
    results: list[Result] = []
    for sc in SCENARIOS:
        provider, seed, labels, depth = sc.build()
        tracer = Tracer(provider, label_store=labels, service_tx_threshold=3000, max_txs_per_address=50)
        r = tracer.trace_forward(seed, depth=depth, min_value=1, max_branch=10)
        compute_taint(r)
        detected = bool(sc.detected(r))
        passed = detected == sc.expect
        detail = "detected" if detected else "not detected"
        if not sc.expect:
            detail = "false alarm" if detected else "correctly silent"
        results.append(Result(sc.name, sc.technique, passed, detected, sc.expect, detail))

    positives = [r for r in results if r.expected]
    negatives = [r for r in results if not r.expected]
    return {
        "results": results,
        "total": len(results),
        "passed": sum(1 for r in results if r.passed),
        "detection_rate": sum(1 for r in positives if r.detected) / len(positives) if positives else 0.0,
        "false_alarm_rate": sum(1 for r in negatives if r.detected) / len(negatives) if negatives else 0.0,
    }
