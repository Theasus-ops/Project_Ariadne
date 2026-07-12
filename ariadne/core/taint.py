"""Taint analysis (Phase 3) — model-selectable propagation.

Taint answers "how much of the money reaching an address originated from the
seed?" There is no single correct answer — it depends on the *tracing rule* you
adopt — so Ariadne implements three documented models (poison / haircut / FIFO)
in :mod:`ariadne.core.taint_models` and records which one produced every number.

``compute_taint(result)`` defaults to the **haircut** model for backward
compatibility: proportional dilution by an address's total on-chain received
value, so a node that also took in clean funds is diluted accordingly. The
denominator is the address's all-time received total when the provider exposes it
(Bitcoin's ``funded_txo_sum``), else the traced inflow. It is an address-level
haircut (not UTXO- or time-precise); for the temporally-precise rule use the FIFO
model, and for maximal exposure use poison.
"""

from __future__ import annotations

from ..models import TraceResult
from .taint_models import DEFAULT_MODEL, METHODOLOGY, TaintModel, compute


def compute_taint(result: TraceResult, model: TaintModel | str = DEFAULT_MODEL) -> TraceResult:
    """Score ``result`` in place under ``model`` (default: haircut)."""
    return compute(result, model)


__all__ = ["compute_taint", "TaintModel", "DEFAULT_MODEL", "METHODOLOGY"]
