"""Statistical anomaly detection — catch what the rules didn't, explainably.

The suspicion scorer and confidence grader are rule-based: transparent, defensible,
but blind to a *novel* pattern nobody wrote a rule for. This module adds a
complementary statistical layer that flags addresses which behave unlike their
peers — without becoming a black box.

It uses **robust z-scores** (median + MAD, the median absolute deviation), not the
mean/standard-deviation, so the outliers it is hunting for do not distort the very
baseline used to detect them. Every flag names the feature that drove it and by how
many robust deviations, e.g. *"fan-out 5.2σ above peers"* — so an analyst sees the
reason, and the output is always framed as **"statistical anomaly — review"**, never
an accusation.
"""

from __future__ import annotations

import statistics

from ..models import TraceResult

# A robust-z at/above this many deviations flags an anomaly. 3.5 ≈ the classic
# Iglewicz–Hoaglin outlier threshold.
DEFAULT_THRESHOLD = 3.5


def _robust_z(values: list[float]) -> list[float]:
    """Median/MAD robust z-scores; falls back to std, then to zeros."""
    n = len(values)
    if n < 3:
        return [0.0] * n
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values])
    scale = 1.4826 * mad if mad > 0 else statistics.pstdev(values)
    if scale <= 0:
        return [0.0] * n
    return [(v - med) / scale for v in values]


def detect_anomalies(items: list[dict], feature_keys: list[str], threshold: float = DEFAULT_THRESHOLD) -> list[dict]:
    """Flag items whose features are statistical outliers among the population.

    ``items`` is a list of dicts with an ``id`` and the numeric ``feature_keys``.
    Returns, for each item, its anomaly score and the driving features.
    """
    if len(items) < 3:
        return [{"id": it.get("id"), "is_anomaly": False, "score": 0.0, "drivers": []} for it in items]

    z_by_feature = {
        f: _robust_z([float(it.get(f, 0) or 0) for it in items]) for f in feature_keys
    }
    out = []
    for i, it in enumerate(items):
        drivers = []
        for f in feature_keys:
            z = z_by_feature[f][i]
            if abs(z) >= threshold:
                drivers.append({"feature": f, "z": round(z, 2)})
        drivers.sort(key=lambda d: abs(d["z"]), reverse=True)
        score = max((abs(d["z"]) for d in drivers), default=0.0)
        out.append({"id": it.get("id"), "is_anomaly": bool(drivers),
                    "score": round(score, 2), "drivers": drivers})
    return out


_FEATURES = ["out_degree", "in_degree", "dirty_received", "taint_fraction", "activity", "value_out"]

_HUMAN = {
    "out_degree": "fan-out (distinct recipients)",
    "in_degree": "consolidation (distinct funders)",
    "dirty_received": "dirty value received",
    "taint_fraction": "taint fraction",
    "activity": "on-chain activity",
    "value_out": "value forwarded",
}


def anomalies_in_trace(result: TraceResult, threshold: float = DEFAULT_THRESHOLD) -> list[dict]:
    """Per-node behavioural-outlier detection within a completed trace."""
    out_deg: dict[str, int] = {}
    in_deg: dict[str, int] = {}
    val_out: dict[str, int] = {}
    for e in result.edges.values():
        out_deg[e.src] = out_deg.get(e.src, 0) + 1
        in_deg[e.dst] = in_deg.get(e.dst, 0) + 1
        val_out[e.src] = val_out.get(e.src, 0) + e.value

    items = []
    for n in result.nodes.values():
        if n.address == result.seed:
            continue  # the root is trivially different from its peers — exclude it
        items.append({
            "id": n.address,
            "out_degree": out_deg.get(n.address, 0),
            "in_degree": in_deg.get(n.address, 0),
            "dirty_received": result.asset.to_units(n.dirty_received),
            "taint_fraction": n.taint_fraction,
            "activity": n.tx_count,
            "value_out": result.asset.to_units(val_out.get(n.address, 0)),
        })

    flagged = []
    for res in detect_anomalies(items, _FEATURES, threshold):
        if not res["is_anomaly"]:
            continue
        reasons = [f"{_HUMAN.get(d['feature'], d['feature'])} {d['z']:+g}σ vs peers" for d in res["drivers"]]
        flagged.append({
            "address": res["id"],
            "anomaly_score": res["score"],
            "drivers": res["drivers"],
            "reason": "Statistical anomaly (review required): " + "; ".join(reasons),
        })
    flagged.sort(key=lambda x: x["anomaly_score"], reverse=True)
    return flagged
