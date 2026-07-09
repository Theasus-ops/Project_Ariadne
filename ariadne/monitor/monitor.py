"""Live block monitor.

Polls a chain's newest block (or a specified one), scores every transaction with
the suspicion filters, and -- for anything above the alert threshold -- follows
the money forward and writes a detailed report for a human to review.

This is the "find them" half of Ariadne: instead of pointing the tracer at a
known-bad address, the monitor surfaces candidates on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..core.taint import compute_taint
from ..core.trace import Tracer
from ..enrich.labels import LabelStore
from ..models import Transaction
from ..providers.base import Provider
from ..report import report as report_mod
from .scoring import Score, TxScorer


@dataclass
class ScoredTx:
    tx: Transaction
    score: Score


class Monitor:
    def __init__(
        self,
        provider: Provider,
        labels: LabelStore,
        threshold: int = 25,
        sample: int = 25,
        trace_depth: int = 3,
        trace_max_branch: int = 4,
        large_value_units: float = 50.0,
    ) -> None:
        self.provider = provider
        self.labels = labels
        self.threshold = threshold
        self.sample = sample
        self.trace_depth = trace_depth
        self.trace_max_branch = trace_max_branch
        self.scorer = TxScorer(provider.asset_info, labels, large_value_units=large_value_units)

    def poll_block(self, height: int | None = None) -> tuple[int, list[ScoredTx]]:
        if height is None:
            height = self.provider.latest_block_height()
        txs = self.provider.get_block_transactions(height, self.sample)
        return height, [ScoredTx(tx, self.scorer.score(tx)) for tx in txs]

    def poll_mempool(self) -> list[ScoredTx]:
        txs = self.provider.get_mempool_transactions(self.sample)
        return [ScoredTx(tx, self.scorer.score(tx)) for tx in txs]

    def suspicious(self, scored: list[ScoredTx]) -> list[ScoredTx]:
        return [s for s in scored if s.score.total >= self.threshold]

    @staticmethod
    def seed_address(scored_tx: ScoredTx) -> str | None:
        """Best address to trace from a flagged tx — its largest output recipient."""
        real_outputs = [o for o in scored_tx.tx.outputs if o.address]
        if not real_outputs:
            return None
        return max(real_outputs, key=lambda o: o.value).address

    def investigate(self, scored_tx: ScoredTx, outdir: str | Path = "reports/alerts"):
        """Trace funds from the suspicious tx's largest output and write a report."""
        target = self.seed_address(scored_tx)
        if not target:
            return None

        tracer = Tracer(self.provider, max_txs_per_address=200, label_store=self.labels)
        min_value = int(0.01 * (10 ** self.provider.asset_info.decimals))
        result = tracer.trace_forward(
            target, depth=self.trace_depth, min_value=min_value, max_branch=self.trace_max_branch
        )
        compute_taint(result)

        # Carry the alert context into the report's provenance.
        result.params["alert"] = {
            "trigger_txid": scored_tx.tx.txid,
            "score": scored_tx.score.total,
            "level": scored_tx.score.level,
            "reasons": scored_tx.score.reasons,
        }
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        basename = f"alert_{scored_tx.score.total}_{scored_tx.tx.txid[:12]}_{stamp}"
        return report_mod.write_all(result, Path(outdir), basename)
