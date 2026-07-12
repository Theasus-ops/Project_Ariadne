"""Sanctions / illicit-exposure screening — a compliance-grade verdict.

Regulated entities and law-enforcement units screen an address before they touch
it: *is this counterparty exposed to sanctioned or illicit funds, how directly, and
how much?* This module answers exactly that from a completed trace — the on-chain
distance from the screened address to the nearest illicit node, whether the
exposure is direct (a one-hop transaction) or indirect (funds that passed through
intermediaries), and the traced value involved.

The verdict vocabulary is deliberate and conservative, aligned with how a
compliance officer must act:

  * ``sanctioned_entity``      — the address itself is sanctioned. Do not transact.
  * ``direct_exposure``        — one hop from a sanctioned/illicit address.
  * ``indirect_exposure``      — illicit funds reached it through intermediaries.
  * ``high_risk_exposure``     — exposure to mixers/ransomware/scam but not sanctions.
  * ``clear``                  — no illicit touchpoint in the screened window.

"Clear" means *within the traced window*, never "clean" in the absolute — the
report says so, because overclaiming a negative is its own compliance failure.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_SANCTION_CATS = {"sanctioned", "frozen"}
_ILLICIT_CATS = {"sanctioned", "frozen", "ransomware", "darknet", "scam", "mixer"}


@dataclass
class ExposureResult:
    address: str
    verdict: str
    nearest_hops: int | None = None
    direct_hits: list = field(default_factory=list)     # illicit nodes 1 hop away
    indirect_hits: list = field(default_factory=list)   # illicit nodes >1 hop away
    exposed_value: float = 0.0
    sanctioned: bool = False
    reasons: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "address": self.address,
            "verdict": self.verdict,
            "nearest_hops": self.nearest_hops,
            "direct_hits": self.direct_hits,
            "indirect_hits": self.indirect_hits,
            "exposed_value": round(self.exposed_value, 8),
            "sanctioned": self.sanctioned,
            "reasons": self.reasons,
            "note": "Exposure assessed within the traced window only; 'clear' is not a clean-bill.",
        }


def screen(report: dict) -> ExposureResult:
    seed = report.get("trace", {}).get("seed", "")
    nodes = report.get("nodes", [])
    asset = report.get("asset", "")

    seed_node = next((n for n in nodes if n.get("address") == seed), None)
    seed_cat = (seed_node or {}).get("category") or ""

    result = ExposureResult(address=seed, verdict="clear")

    if seed_cat in _SANCTION_CATS:
        result.verdict = "sanctioned_entity"
        result.sanctioned = True
        result.nearest_hops = 0
        result.reasons.append(f"The screened address itself is {seed_cat}.")
        return result

    illicit = [
        n for n in nodes
        if n.get("address") != seed and (n.get("category") in _ILLICIT_CATS)
    ]
    if not illicit:
        result.reasons.append("No sanctioned or illicit touchpoint within the traced window.")
        return result

    illicit.sort(key=lambda n: n.get("depth", 99))
    result.nearest_hops = illicit[0].get("depth")
    for n in illicit:
        entry = {
            "address": n["address"], "category": n.get("category"),
            "label": n.get("label"), "hops": n.get("depth"),
            "traced_value": n.get("dirty_received", 0),
        }
        (result.direct_hits if n.get("depth") == 1 else result.indirect_hits).append(entry)
        result.exposed_value += float(n.get("dirty_received") or 0)

    has_sanction = any(n.get("category") in _SANCTION_CATS for n in illicit)
    result.sanctioned = has_sanction
    if has_sanction and result.nearest_hops == 1:
        result.verdict = "direct_exposure"
        result.reasons.append(f"Directly transacts with a sanctioned address (1 hop, {asset}).")
    elif has_sanction:
        result.verdict = "indirect_exposure"
        result.reasons.append(f"Sanctioned funds reached the address via {result.nearest_hops} hop(s).")
    else:
        result.verdict = "high_risk_exposure"
        kinds = sorted({n.get("category") for n in illicit})
        result.reasons.append(f"Exposure to high-risk infrastructure ({', '.join(kinds)}) but not sanctions.")

    return result
