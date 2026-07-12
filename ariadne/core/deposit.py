"""Exchange deposit-address discovery — closing the "name the cash-out" gap.

The measured attribution deficiency (Ariadne can *reach* a cash-out but not always
*name* it) exists because free feeds label exchange **hot wallets**, not the
millions of per-user **deposit addresses** an exchange hands out. Yet those
deposit addresses have a giveaway on-chain signature you do not need commercial
data to see:

    A deposit address RECEIVES from many unrelated funders and SWEEPS almost
    everything onward to ONE destination — the exchange's collection / hot wallet.

So when a trace ends at an unlabelled address that forwards ~all of its funds to a
*known* exchange (or to an address so active it is certainly an exchange hot
wallet), we can attribute the unlabelled address to that exchange: *"deposit
address that sweeps to Binance"*. That names the cash-out without any private data,
and it is written back to the attribution store so coverage compounds.

This is a heuristic and is graded as such (HIGH only when the sweep target is a
*labelled* exchange; MEDIUM when it is merely a very-high-activity hot wallet).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..enrich.labels import LabelCategory, LabelStore
from ..providers.base import Provider

_EXCHANGE_LIKE = {LabelCategory.EXCHANGE, LabelCategory.SERVICE}


@dataclass
class DepositFinding:
    address: str
    is_deposit: bool
    sweep_target: str = ""
    target_label: Optional[str] = None
    target_category: Optional[str] = None
    funders: int = 0
    forwarded_fraction: float = 0.0
    confidence: str = "low"          # high | medium | low
    attribution: str = ""            # e.g. "Binance deposit address"
    reason: str = ""
    evidence_txids: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "address": self.address,
            "is_deposit": self.is_deposit,
            "sweep_target": self.sweep_target,
            "target_label": self.target_label,
            "target_category": self.target_category,
            "funders": self.funders,
            "forwarded_fraction": round(self.forwarded_fraction, 4),
            "confidence": self.confidence,
            "attribution": self.attribution,
            "reason": self.reason,
            "evidence_txids": self.evidence_txids[:10],
        }


class DepositDetector:
    def __init__(
        self,
        provider: Provider,
        label_store: LabelStore | None = None,
        max_txs: int = 200,
        min_funders: int = 3,
        min_forward_fraction: float = 0.80,
        hot_wallet_tx_threshold: int = 50_000,
    ) -> None:
        self.provider = provider
        self.label_store = label_store
        self.max_txs = max_txs
        self.min_funders = min_funders
        self.min_forward_fraction = min_forward_fraction
        self.hot_wallet_tx_threshold = hot_wallet_tx_threshold

    def analyze(self, address: str) -> DepositFinding:
        address = self.provider.normalize(address)
        try:
            txs = self.provider.get_transactions(address, self.max_txs)
        except Exception:
            return DepositFinding(address, False, reason="no transaction data available")

        funders: set[str] = set()
        out_by_dest: dict[str, int] = {}
        total_out = 0
        evidence: list[str] = []

        for tx in txs:
            in_addrs = tx.input_addresses()
            receives = any(o.address == address for o in tx.outputs)
            spends = address in in_addrs

            if receives and not spends:
                for i in tx.inputs:
                    if i.address and i.address != address:
                        funders.add(i.address)
            if spends:
                # Value leaving this address, apportioned by its input share.
                total_in = sum(i.value for i in tx.inputs) or 1
                share = sum(i.value for i in tx.inputs if i.address == address) / total_in
                for o in tx.outputs:
                    if not o.address or o.address == address or o.address in in_addrs:
                        continue
                    attributed = int(o.value * share)
                    if attributed <= 0:
                        continue
                    out_by_dest[o.address] = out_by_dest.get(o.address, 0) + attributed
                    total_out += attributed
                    if tx.txid not in evidence:
                        evidence.append(tx.txid)

        if total_out <= 0 or not out_by_dest:
            return DepositFinding(address, False, funders=len(funders),
                                  reason="address does not sweep funds onward")

        sweep_target, swept = max(out_by_dest.items(), key=lambda kv: kv[1])
        forwarded_fraction = swept / total_out

        if len(funders) < self.min_funders or forwarded_fraction < self.min_forward_fraction:
            return DepositFinding(
                address, False, sweep_target=sweep_target, funders=len(funders),
                forwarded_fraction=forwarded_fraction,
                reason="pattern too weak (needs many funders + a dominant sweep target)",
            )

        # We have the deposit-address SHAPE. Is the sweep target an exchange?
        label = self.label_store.get(sweep_target) if self.label_store else None
        target_label = label.name if label else None
        target_category = label.category.value if label else None

        if label is not None and label.category in _EXCHANGE_LIKE:
            confidence = "high"
            attribution = f"{label.name} deposit address"
            reason = (
                f"Receives from {len(funders)} funders and sweeps {forwarded_fraction:.0%} to "
                f"{label.name} ({sweep_target}) — an exchange deposit-address signature."
            )
        else:
            try:
                target_activity = self.provider.address_tx_count(sweep_target)
            except Exception:
                target_activity = 0
            if target_activity >= self.hot_wallet_tx_threshold:
                confidence = "medium"
                attribution = "deposit address to an unnamed exchange hot wallet"
                reason = (
                    f"Receives from {len(funders)} funders and sweeps {forwarded_fraction:.0%} to a "
                    f"very-high-activity address ({target_activity:,} txns) — probable exchange hot wallet."
                )
            else:
                return DepositFinding(
                    address, False, sweep_target=sweep_target, funders=len(funders),
                    forwarded_fraction=forwarded_fraction, target_label=target_label,
                    target_category=target_category,
                    reason="sweeps to a single address, but it is not a known/likely exchange",
                    evidence_txids=evidence,
                )

        return DepositFinding(
            address=address, is_deposit=True, sweep_target=sweep_target,
            target_label=target_label, target_category=target_category,
            funders=len(funders), forwarded_fraction=forwarded_fraction,
            confidence=confidence, attribution=attribution, reason=reason,
            evidence_txids=evidence,
        )
