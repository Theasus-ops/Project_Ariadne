"""Confidence assessment: how sure are we a finding is tied to illegal activity?

This is separate from taint (how *much* dirty money reached an address).
Confidence answers the question a professional actually asks -- "how certain is
the illicit link, and what do I do about it?" -- and it is deliberately
conservative:

  * A sanctioned address is CONFIRMED illicit.
  * An exchange that received dirty funds is a LEAD, not an offender. The tool
    says so explicitly, because branding a regulated business a criminal would be
    wrong and would get the evidence thrown out.

Every assessment carries its reasons and a disposition (what it means + the next
step), so a reviewer always sees the logic, never a bare number.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import NodeType

CONFIRMED, HIGH, MEDIUM, LOW, INFO = "confirmed", "high", "medium", "low", "info"
_ILLICIT = {"sanctioned", "ransomware", "darknet", "scam"}


@dataclass
class Assessment:
    level: str
    score: int
    reasons: list[str] = field(default_factory=list)
    disposition: str = ""

    def as_dict(self) -> dict:
        return {
            "level": self.level,
            "score": self.score,
            "reasons": self.reasons,
            "disposition": self.disposition,
        }


def _level(score: int) -> str:
    if score >= 95:
        return CONFIRMED
    if score >= 75:
        return HIGH
    if score >= 50:
        return MEDIUM
    if score >= 25:
        return LOW
    return INFO


def assess(node, seed_category: str) -> Assessment:
    """Grade how confident we are that ``node`` is tied to illegal activity."""
    cat = node.label_category or ""
    taint = node.taint_fraction or 0.0
    illicit_origin = seed_category in _ILLICIT

    # 1. Direct attribution of this wallet.
    if cat == "sanctioned":
        return Assessment(
            CONFIRMED, 100, ["Listed on the OFAC sanctions list."],
            "Confirmed illicit — transacting with this address is itself an offence.",
        )
    if cat in ("ransomware", "darknet"):
        return Assessment(
            HIGH, 88, [f"Attributed to {cat} activity."],
            "Wallet tied to criminal operations — prioritise.",
        )
    if cat == "scam":
        return Assessment(
            HIGH, 82, ["Attributed to a known scam."],
            "Wallet tied to fraud — prioritise.",
        )

    # 2. Mixer / deliberate obfuscation.
    if cat == "mixer" or node.entered_mixer:
        score = 62
        reasons = ["Funds were passed through a mixer (deliberate obfuscation)."]
        if illicit_origin and taint > 0:
            score = min(85, score + int(20 * taint))
            reasons.append(f"~{int(taint * 100)}% of traced inflow originates from {seed_category} funds.")
        return Assessment(
            _level(score), score, reasons,
            "Obfuscation attempt — correlate deposits and withdrawals; treat as suspicious.",
        )

    # 3a. A service (exchange) that received *any* traced dirty funds is a cash-out
    #     lead -- regardless of proportion, since a drop is tiny against its volume.
    if illicit_origin and node.node_type == NodeType.SERVICE and node.dirty_received > 0:
        pct = int(round(taint * 100))
        score = min(55, 35 + int(20 * min(taint, 1.0)))
        return Assessment(
            _level(score), score,
            [
                f"Received funds traced from {seed_category} (~{pct}% of this address's inflow).",
                f"High-activity address ({node.tx_count:,} txns) — probable regulated exchange.",
            ],
            "Cash-out LEAD, not an offender — subpoena the exchange's records to identify the receiver.",
        )

    # 3b. A downstream wallet carrying a meaningful share of illicit funds.
    if illicit_origin and taint > 0.05:
        pct = int(round(taint * 100))
        score = min(90, 45 + int(45 * taint))
        return Assessment(
            _level(score), score,
            [f"Holds {pct}% of funds traced directly from {seed_category}."],
            "Wallet handling suspected proceeds — trace onward and identify the controller.",
        )

    # 4. Unlabeled high-activity service, no illicit link established.
    if node.node_type == NodeType.SERVICE:
        return Assessment(
            LOW, 20,
            [f"High-activity address ({node.tx_count:,} txns), likely a regulated service."],
            "Investigative lead only — no illicit association established in this trace.",
        )

    return Assessment(INFO, 10, ["No specific illicit indicators in this trace."], "Informational.")
