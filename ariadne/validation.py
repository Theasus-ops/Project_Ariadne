"""A small, honest validation harness.

Runs Ariadne against publicly documented cases with known ground truth and
measures where it is right and where it is wrong. The point is NOT to prove
Ariadne works -- it is to expose, with numbers, exactly how far it is from a
deployable tool.

Checks are split into two categories, because they fail for different reasons:
  * detection  -- does it grade a known-bad seed correctly, and avoid false
                  positives on a clean one? (Ariadne is strong here.)
  * attribution -- can it *name* the cash-out point? (The honest gap: it usually
                   cannot, because free feeds lack exchange-address data.)

A gov-grade tool measures its own error rate. This does that.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


# ---- predicates over a report dict (from report.build_report) ----
def _seed_finding(report: dict):
    seed = report["trace"]["seed"]
    for f in report["findings"]:
        if f["address"] == seed:
            return f
    return None


def seed_grade_in(levels: set[str]) -> Callable[[dict], bool]:
    def check(report: dict) -> bool:
        f = _seed_finding(report)
        return bool(f) and f["confidence"]["level"] in levels
    return check


def reaches_cashout(report: dict) -> bool:
    return any(n["type"] == "service" for n in report["nodes"])


def cashout_named(report: dict) -> bool:
    return any(n["type"] == "service" and n.get("label") for n in report["nodes"])


def no_high_findings(report: dict) -> bool:
    return not any(f["confidence"]["level"] in ("high", "confirmed") for f in report["findings"])


@dataclass
class Case:
    name: str
    address: str
    chain: str
    ground_truth: str
    checks: list  # (description, predicate, category)
    depth: int = 2


CASES: list[Case] = [
    Case(
        "WannaCry ransomware", "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw", "btc",
        "One of the three hardcoded WannaCry ransom wallets (2017).",
        [
            ("seed graded high/confirmed", seed_grade_in({"high", "confirmed"}), "detection"),
            ("reaches a cash-out point", reaches_cashout, "attribution"),
            ("cash-out is NAMED (exchange identified)", cashout_named, "attribution"),
        ],
        depth=4,
    ),
    Case(
        "OFAC-sanctioned wallet", "123WBUDmSJv4GctdVEz6Qq6z8nXSKrJ4KX", "btc",
        "On the US Treasury OFAC SDN list (imported via update-intel).",
        [("seed graded confirmed", seed_grade_in({"confirmed"}), "detection")],
    ),
    Case(
        "Scam / phishing wallet", "0x09750ad360fdb7a2ee23669c4503c974d86d8694", "eth",
        "Listed on the ethereum-lists scam/phishing darklist.",
        [("seed graded high/confirmed", seed_grade_in({"high", "confirmed"}), "detection")],
    ),
    Case(
        "Clean wallet (false-positive check)", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "usdt",
        "Well-known legitimate address; must NOT be graded high.",
        [("no false high/confirmed finding", no_high_findings, "detection")],
    ),
]


def run_case(case: Case, build_provider, labels, cache, max_branch: int = 3) -> list[tuple]:
    """Return [(description, passed, category), ...] for one case."""
    from .core.taint import compute_taint
    from .core.trace import Tracer
    from .report import report as report_mod

    provider = build_provider(case.chain, cache)
    tracer = Tracer(provider, label_store=labels, max_txs_per_address=300, service_tx_threshold=2000)
    min_value = int(0.001 * (10 ** provider.asset_info.decimals))
    result = tracer.trace_forward(case.address, depth=case.depth, min_value=min_value, max_branch=max_branch)
    compute_taint(result)
    report = report_mod.build_report(result)
    return [(desc, bool(pred(report)), cat) for (desc, pred, cat) in case.checks]
