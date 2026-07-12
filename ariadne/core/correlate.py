"""Cross-chain / bridge correlation — following money through a chain hop.

Bridges (and centralised swap services) are a black box to a single-chain trace:
value goes *into* a bridge contract on chain A and equivalent value comes *out* on
chain B, with no on-chain link between the two legs. Investment-scam ("pig
butchering") money — the Greek-relevant case — routinely hops USDT between Tron
and Ethereum this way to break the trail.

There is no cryptographic link, but there is a strong statistical one: the
withdrawal on the far side matches the deposit in **amount** (minus a bridge fee)
and follows it closely in **time**. This module correlates the two legs:

    match a deposit to a withdrawal when the amounts agree within a tolerance and
    the withdrawal happens after the deposit within a bounded window.

Each match carries an explicit, decomposed confidence (amount closeness × time
proximity × uniqueness) so the analyst sees *why* two legs are linked and can
treat it as the probabilistic evidence it is — never as proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_BRIDGE_CATEGORIES = {"bridge", "dex"}


@dataclass
class BridgeEvent:
    chain: str
    txid: str
    address: str          # the bridge/service address on this leg
    counterparty: str     # the user address on this leg
    amount: float         # in asset units
    time: int | None      # unix seconds
    direction: str        # "in" (deposit into bridge) | "out" (withdrawal from bridge)

    def as_dict(self) -> dict:
        return {
            "chain": self.chain, "txid": self.txid, "address": self.address,
            "counterparty": self.counterparty, "amount": self.amount,
            "time": self.time, "direction": self.direction,
        }


@dataclass
class Correlation:
    deposit: BridgeEvent
    withdrawal: BridgeEvent
    amount_delta: float
    time_delta: int | None
    confidence: float
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "deposit": self.deposit.as_dict(),
            "withdrawal": self.withdrawal.as_dict(),
            "amount_delta": round(self.amount_delta, 6),
            "time_delta_seconds": self.time_delta,
            "confidence": round(self.confidence, 3),
            "reasons": self.reasons,
        }


def extract_bridge_events(report: dict) -> tuple[list[BridgeEvent], list[BridgeEvent]]:
    """Pull (deposits, withdrawals) from a trace report using bridge/dex nodes.

    A flow *to* a bridge node is a deposit (money entering the bridge on this
    chain); a flow *from* a bridge node is a withdrawal (money leaving it).
    """
    chain = report.get("asset", "")
    node_cat = {n["address"]: (n.get("category") or "") for n in report.get("nodes", [])}
    deposits: list[BridgeEvent] = []
    withdrawals: list[BridgeEvent] = []
    for e in report.get("edges", []):
        src, dst = e["src"], e["dst"]
        amount = float(e.get("amount") or 0)
        t = e.get("first_time")
        txid = (e.get("txids") or [""])[0]
        if node_cat.get(dst) in _BRIDGE_CATEGORIES:
            deposits.append(BridgeEvent(chain, txid, dst, src, amount, t, "in"))
        if node_cat.get(src) in _BRIDGE_CATEGORIES:
            withdrawals.append(BridgeEvent(chain, txid, src, dst, amount, t, "out"))
    return deposits, withdrawals


def _score(dep: BridgeEvent, wd: BridgeEvent, amount_tol: float, max_delay: int) -> Correlation | None:
    if dep.amount <= 0 or wd.amount <= 0:
        return None
    delta = abs(dep.amount - wd.amount)
    rel = delta / max(dep.amount, wd.amount)
    if rel > amount_tol:
        return None

    reasons = [f"amounts match within {rel:.2%} ({dep.amount} vs {wd.amount})"]
    amount_score = 1.0 - (rel / amount_tol)  # 1.0 = exact, 0 = at tolerance edge

    time_delta = None
    time_score = 0.5  # neutral when a timestamp is missing
    if dep.time is not None and wd.time is not None:
        time_delta = wd.time - dep.time
        if time_delta < 0 or time_delta > max_delay:
            return None
        time_score = 1.0 - (time_delta / max_delay)
        reasons.append(f"withdrawal {time_delta}s after deposit (within {max_delay}s window)")

    if dep.chain and wd.chain and dep.chain != wd.chain:
        reasons.append(f"cross-chain hop {dep.chain} → {wd.chain}")

    confidence = round(0.6 * amount_score + 0.4 * time_score, 3)
    return Correlation(dep, wd, delta, time_delta, confidence, reasons)


def correlate_events(
    deposits: list[BridgeEvent],
    withdrawals: list[BridgeEvent],
    amount_tolerance: float = 0.02,
    max_delay_seconds: int = 3600,
) -> list[Correlation]:
    """Greedy best-match correlation of deposits to withdrawals.

    Each withdrawal is matched to at most one deposit (its best-scoring candidate);
    a lone candidate scores higher (uniqueness) than one of many near-ties.
    """
    candidates: list[Correlation] = []
    for dep in deposits:
        for wd in withdrawals:
            if dep.txid and dep.txid == wd.txid:
                continue  # same leg, not a cross-bridge pair
            c = _score(dep, wd, amount_tolerance, max_delay_seconds)
            if c is not None:
                candidates.append(c)

    # Uniqueness bonus: penalise withdrawals that match many deposits.
    match_counts: dict[str, int] = {}
    for c in candidates:
        key = c.withdrawal.txid or id(c.withdrawal)
        match_counts[key] = match_counts.get(key, 0) + 1
    for c in candidates:
        key = c.withdrawal.txid or id(c.withdrawal)
        if match_counts[key] == 1:
            c.confidence = round(min(1.0, c.confidence + 0.1), 3)
            c.reasons.append("unique amount+time match (no competing withdrawals)")

    candidates.sort(key=lambda c: c.confidence, reverse=True)

    used_dep: set = set()
    used_wd: set = set()
    result: list[Correlation] = []
    for c in candidates:
        dk = c.deposit.txid or id(c.deposit)
        wk = c.withdrawal.txid or id(c.withdrawal)
        if dk in used_dep or wk in used_wd:
            continue
        used_dep.add(dk)
        used_wd.add(wk)
        result.append(c)
    return result


def correlate_reports(
    reports: list[dict],
    amount_tolerance: float = 0.02,
    max_delay_seconds: int = 3600,
) -> list[Correlation]:
    """Correlate bridge legs across several single-chain trace reports."""
    all_dep: list[BridgeEvent] = []
    all_wd: list[BridgeEvent] = []
    for rep in reports:
        d, w = extract_bridge_events(rep)
        all_dep += d
        all_wd += w
    return correlate_events(all_dep, all_wd, amount_tolerance, max_delay_seconds)
