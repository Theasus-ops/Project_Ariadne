"""Transaction suspicion scoring (live monitoring).

A rule-based scorer that assigns a suspicion score to a transaction from a set of
well-defined, explainable filters. Every point carries a human-readable reason, so
an analyst always sees *why* something was flagged -- there is no black box, which
matters when a flag can trigger an investigation of a real person.

The rules are deliberately conservative and transparent. They are meant to surface
candidates for a human to review, never to accuse.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.coinjoin import classify as classify_coinjoin
from ..enrich.labels import LabelCategory, LabelStore
from ..models import Asset, Transaction

# Points contributed when a counterparty carries a given label.
_LABEL_POINTS = {
    LabelCategory.SANCTIONED: 60,
    LabelCategory.RANSOMWARE: 55,
    LabelCategory.DARKNET: 50,
    LabelCategory.SCAM: 50,
    LabelCategory.MIXER: 45,
    LabelCategory.BRIDGE: 20,
    LabelCategory.DEX: 15,
    LabelCategory.GAMBLING: 15,
    LabelCategory.EXCHANGE: 5,
}

_LEVELS = [(70, "critical"), (45, "high"), (25, "medium"), (0, "low")]


@dataclass
class Score:
    total: int = 0
    reasons: list[str] = field(default_factory=list)

    def add(self, points: int, reason: str) -> None:
        self.total += points
        self.reasons.append(f"[+{points}] {reason}")

    @property
    def level(self) -> str:
        for threshold, name in _LEVELS:
            if self.total >= threshold:
                return name
        return "low"


@dataclass
class TxScorer:
    asset: Asset
    labels: LabelStore
    large_value_units: float = 50.0      # asset units treated as "large"
    fanout_threshold: int = 10           # outputs -> distribution signal
    consolidation_threshold: int = 20    # inputs -> consolidation signal
    watchlist: "set[str] | None" = None  # analyst's targeted addresses

    def _large_raw(self) -> int:
        return int(self.large_value_units * (10 ** self.asset.decimals))

    def score(self, tx: Transaction) -> Score:
        s = Score()
        one_unit = 10 ** self.asset.decimals
        large_raw = self._large_raw()

        # 1. Labeled counterparties - the strongest, most specific signal.
        counterparties = set(tx.input_addresses())
        counterparties |= {o.address for o in tx.outputs if o.address}

        # 0. Watchlist — a targeted address of interest is always top-priority.
        if self.watchlist:
            for addr in counterparties & self.watchlist:
                s.add(100, f"WATCHLISTED address moved: {addr}")
        flagged: set[str] = set()
        for addr in counterparties:
            label = self.labels.get(addr)
            if label and label.category in _LABEL_POINTS and label.address not in flagged:
                flagged.add(label.address)
                name = label.name or addr[:12]
                s.add(_LABEL_POINTS[label.category], f"counterparty: {name} ({label.category.value})")

        # 2. Mixing (CoinJoin) - active obfuscation.
        cj = classify_coinjoin(tx)
        if cj is not None:
            s.add(30, f"{cj.kind.value} CoinJoin (anonymity set {cj.anonymity_set})")

        # 3. Large value moved.
        total_out = sum(o.value for o in tx.outputs)
        if total_out >= large_raw:
            s.add(20, f"large value: {self.asset.format(total_out)} {self.asset.symbol}")

        # 4. Round-number output above a meaningful size - a structuring signal.
        for o in tx.outputs:
            if o.value >= max(one_unit, large_raw // 10) and o.value % one_unit == 0:
                s.add(8, f"round-number output: {self.asset.format(o.value)} {self.asset.symbol}")
                break

        # 5. High fan-out - one source spraying to many destinations (distribution).
        real_outputs = [o for o in tx.outputs if o.address]
        if len(real_outputs) >= self.fanout_threshold:
            s.add(12, f"high fan-out: {len(real_outputs)} outputs")

        # 6. Wallet rotation / output spraying: many fresh-looking destinations can be a
        # deliberate evasion tactic, especially when the amounts are small and uniform.
        if len(real_outputs) >= self.fanout_threshold:
            fresh_like = [o for o in real_outputs if o.address and o.address.startswith("new-")]
            if fresh_like and len(fresh_like) == len(real_outputs):
                s.add(8, "wallet rotation: many fresh-looking outputs created in one transaction")

        # 7. Peel pattern - one dominant output plus a small remainder.
        if len(real_outputs) == 2:
            vals = sorted((o.value for o in real_outputs), reverse=True)
            if vals[1] > 0 and vals[0] >= 20 * vals[1] and vals[0] >= large_raw // 5:
                s.add(10, "peel pattern: large forward + small peel-off")

        # 8. Large consolidation - many inputs gathered before a move.
        if len(tx.inputs) >= self.consolidation_threshold:
            s.add(10, f"large consolidation: {len(tx.inputs)} inputs")

        # 9. Address reuse is a common laundering countermeasure; repeated use of the same
        # output address across many transactions is suspicious when mixed with other patterns.
        if len(real_outputs) >= 2:
            unique_outputs = {o.address for o in real_outputs if o.address}
            if len(unique_outputs) <= 2 and len(tx.inputs) >= 2:
                s.add(6, "address reuse: a small number of outputs were repeatedly reused")

        return s
