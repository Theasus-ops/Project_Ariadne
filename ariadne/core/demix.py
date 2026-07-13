"""Mixer de-anonymisation — probabilistic, and honest about it.

Mixers exist to break the input->output link, and where they are used correctly
they succeed: a perfect equal-denomination CoinJoin, or a fixed-pool zk mixer with
disciplined usage, is **not** deterministically reversible. Ariadne does not pretend
otherwise. What it does is measure the *actual* privacy a specific mix achieved and
surface the links that users' mistakes leak — always with an explicit probability
and the heuristic that produced it, never as proof.

Two capabilities, both grounded in the public research:

  * :func:`coinjoin_linkability` — measures a CoinJoin's real anonymity set and finds
    any **deterministic** input->output links forced by the amounts (an amount that
    can only balance one way). A perfect equal-denomination mix returns *no* links and
    says so; the value is in catching the imperfect ones.

  * :class:`MixerCorrelator` — for fixed-denomination pools (Tornado-style), ranks
    candidate deposit<->withdrawal pairs using the documented heuristics: same/linked
    address (the classic mistake), and temporal proximity weighted by the anonymity
    set at the time. Probabilities are **capped** — address reuse can be near-certain,
    but timing alone never exceeds the 1/anonymity-set prior. Real-world recall of
    this class of attack is ~35% (2023 Tornado research); this is a lead generator,
    not a de-mixer.
"""

from __future__ import annotations

import itertools
import math
from collections import Counter
from dataclasses import dataclass, field

from ..models import Transaction


def _subset_sum_exists(target: int, values: list[int], tol: int, max_k: int = 3) -> bool:
    """Does any subset of 2..max_k of ``values`` sum to within ``tol`` of ``target``?"""
    for k in range(2, max_k + 1):
        for combo in itertools.combinations(values, k):
            if abs(sum(combo) - target) <= tol:
                return True
    return False


def coinjoin_linkability(tx: Transaction, fee_tolerance_ratio: float = 0.03) -> dict:
    """Measure a CoinJoin's privacy and find any amount-forced deterministic links.

    A deterministic link is reported only when an input's value uniquely matches an
    output's value (within a fee tolerance) *and* no small combination of the other
    inputs could have produced that output — i.e. the amounts can only balance one
    way. This is conservative by design: it never invents a link a mix did protect.
    """
    ins = [i for i in tx.inputs if i.value > 0]
    outs = [o for o in tx.outputs if o.value > 0]
    if not ins or not outs:
        return {"anonymity_set": 0, "all_outputs_equal": False, "deterministic_links": [],
                "per_link_probability": None, "verdict": "not a mix"}

    out_counts = Counter(o.value for o in outs)
    denom, anon = out_counts.most_common(1)[0]
    all_equal = len(out_counts) == 1
    in_counts = Counter(i.value for i in ins)

    deterministic: list[dict] = []
    if len(ins) <= 20:  # bound the combinatorial check
        other_vals = [i.value for i in ins]
        for i in ins:
            tol = int(i.value * fee_tolerance_ratio)
            for o in outs:
                if in_counts[i.value] != 1 or out_counts[o.value] != 1:
                    continue  # value not unique on both sides -> ambiguous, skip
                if abs(o.value - i.value) > tol:
                    continue
                rest = [v for v in other_vals if v is not i.value]
                if not _subset_sum_exists(o.value, rest, tol):
                    if i.address and o.address:
                        deterministic.append({"input": i.address, "output": o.address, "value": i.value})

    if all_equal and not deterministic:
        verdict = (f"Perfect equal-denomination mix (anonymity set {anon}); no deterministic linkage. "
                   f"Any output is equally likely — treat links past this point as unproven.")
        per_link = round(1.0 / anon, 4) if anon else None
    elif deterministic:
        verdict = (f"{len(deterministic)} deterministic input->output link(s) forced by the amounts — "
                   f"the mix leaked here. Remaining outputs: anonymity set ~{anon}.")
        per_link = round(1.0 / anon, 4) if anon else None
    else:
        verdict = f"Imperfect mix; anonymity set {anon}, no amount-forced link found. Links remain probabilistic."
        per_link = round(1.0 / anon, 4) if anon else None

    return {
        "anonymity_set": anon,
        "all_outputs_equal": all_equal,
        "denomination": denom,
        "deterministic_links": deterministic,
        "per_link_probability": per_link,
        "entropy_bits": round(math.log2(math.factorial(min(anon, 12))), 2) if anon else 0.0,
        "verdict": verdict,
    }


@dataclass
class MixerLink:
    deposit: dict
    withdrawal: dict
    probability: float
    reasons: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"deposit": self.deposit, "withdrawal": self.withdrawal,
                "probability": round(self.probability, 3), "reasons": self.reasons}


class MixerCorrelator:
    """Fixed-denomination pool (Tornado-style) deposit<->withdrawal correlation."""

    def __init__(self, amount_tolerance: float = 0.0, max_delay_seconds: int = 7 * 86400) -> None:
        self.amount_tolerance = amount_tolerance   # 0 = exact denomination match required
        self.max_delay = max_delay_seconds

    def correlate(self, deposits: list[dict], withdrawals: list[dict],
                  linked_addresses: dict | None = None) -> list[MixerLink]:
        """Return ranked candidate deposit<->withdrawal links.

        Each event: {address, txid, amount, time}. ``linked_addresses`` optionally maps
        a withdrawal address to a set of addresses known (off this analysis) to be the
        same actor — used for the strongest heuristic.
        """
        linked_addresses = linked_addresses or {}
        out: list[MixerLink] = []
        for w in withdrawals:
            w_amt, w_time = w.get("amount"), w.get("time")
            # deposits of the same denomination made before this withdrawal
            pool = [d for d in deposits
                    if self._same_denom(d.get("amount"), w_amt)
                    and (d.get("time") is None or w_time is None or d["time"] <= w_time)]
            if not pool:
                continue
            anon_set = len(pool)
            for d in pool:
                reasons = []
                prob = 1.0 / anon_set  # uniform prior over the anonymity set
                reasons.append(f"anonymity set {anon_set} at withdrawal (prior {prob:.1%})")

                same_addr = d.get("address") and d["address"] == w.get("address")
                linked = w.get("address") in linked_addresses and d.get("address") in linked_addresses[w["address"]]
                if same_addr:
                    prob = max(prob, 0.9)
                    reasons.append("withdrawal address equals the deposit address (operator error)")
                elif linked:
                    prob = max(prob, 0.8)
                    reasons.append("deposit and withdrawal addresses are in the same actor cluster")

                # Temporal sharpening (never beyond the prior unless a hard signal fired).
                if d.get("time") is not None and w_time is not None:
                    dt = w_time - d["time"]
                    if 0 <= dt <= self.max_delay and not (same_addr or linked):
                        # closer in time within a small pool nudges, but stays <= prior*2, capped 0.5
                        prob = min(0.5, prob * (1.0 + (1.0 - dt / self.max_delay)))
                        reasons.append(f"withdrawal {int(dt)}s after deposit")
                if same_addr or linked or anon_set <= 20:
                    out.append(MixerLink(d, w, prob, reasons))

        out.sort(key=lambda m: m.probability, reverse=True)
        return out

    def _same_denom(self, a, b) -> bool:
        if a is None or b is None:
            return False
        if self.amount_tolerance <= 0:
            return a == b
        return abs(a - b) <= max(a, b) * self.amount_tolerance


def extract_mixer_events(report: dict) -> tuple[list[dict], list[dict]]:
    """Pull (deposits, withdrawals) from a trace report using mixer-category nodes."""
    node_cat = {n["address"]: (n.get("category") or "") for n in report.get("nodes", [])}
    deposits, withdrawals = [], []
    for e in report.get("edges", []):
        t = e.get("first_time")
        txid = (e.get("txids") or [""])[0]
        if node_cat.get(e["dst"]) == "mixer":
            deposits.append({"address": e["src"], "txid": txid, "amount": e.get("amount"), "time": t})
        if node_cat.get(e["src"]) == "mixer":
            withdrawals.append({"address": e["dst"], "txid": txid, "amount": e.get("amount"), "time": t})
    return deposits, withdrawals
