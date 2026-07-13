"""First-class entities — treat an actor, not 50 loose addresses.

Clustering reveals that many addresses belong to one actor, but downstream the tool
still reasons address-by-address. Real forensics reasons about the **entity**: its
whole wallet set, the labels attached anywhere in it, the cash-out infrastructure it
uses, and its aggregate risk. This module rolls a cluster up into an entity summary
and (via the knowledge base) makes it persistent, so a later trace can say "this
address belongs to the entity you profiled last week."
"""

from __future__ import annotations

from collections import Counter

_ILLICIT = {"sanctioned", "frozen", "ransomware", "darknet", "scam", "mixer"}


def build_entity(cluster, label_store=None) -> dict:
    """Aggregate a Clusterer result into an entity profile."""
    members = sorted(cluster.members)
    labels: dict[str, dict] = {}
    categories: Counter = Counter()
    for addr in members:
        lab = label_store.get(addr) if label_store else None
        if lab is not None:
            labels[addr] = {"name": lab.name, "category": lab.category.value}
            categories[lab.category.value] += 1
    risk_flags = sorted({c for c in categories if c in _ILLICIT})
    return {
        "seed": cluster.seed,
        "member_count": len(members),
        "members": members,
        "labels": labels,
        "category_counts": dict(categories),
        "services_touched": cluster.services_touched,
        "cash_out_count": len(cluster.services_touched),
        "cospend_links": len(cluster.links),
        "risk_flags": risk_flags,
        "risk": "high" if risk_flags else ("medium" if cluster.services_touched else "low"),
    }
