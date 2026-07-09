"""False-positive / false-negative measurement — the honest scoreboard.

Builds a labelled test set (known-illicit positives sampled from the intelligence
feeds, known-legitimate negatives sampled from named exchanges), grades each
address the way Ariadne grades a finding, and computes the confusion matrix:
precision, recall, false-positive rate, false-negative rate, accuracy.

It runs in TWO modes, because they answer different questions:

  * label-assisted -- the operational tool. Measures how *safe* it is: does it
    falsely accuse a legitimate address? (Its precision / false-positive rate.)

  * behavioural    -- the positives' own labels are REMOVED before grading.
    Measures its real *recall*: can it detect a bad actor it has no label for?

The behavioural recall is the honest measure of accuracy "by itself" -- and it is
the number that reveals accuracy is a function of attribution DATA, not code.
"""

from __future__ import annotations

import json
import random

from .core.confidence import assess
from .enrich.labels import (
    Label,
    LabelCategory,
    LabelStore,
    default_labels_path,
    intel_labels_path,
    norm_addr,
    ofac_labels_path,
)
from .models import NodeType, TraceNode

# A grade at or above these levels counts as "flagged as illicit-linked".
_FLAGGED = {"confirmed", "high", "medium"}
_LABEL_PATHS = (default_labels_path, ofac_labels_path, intel_labels_path)


def _raw_labels() -> list[dict]:
    out: list[dict] = []
    for path_fn in _LABEL_PATHS:
        p = path_fn()
        if p.exists():
            out.extend(json.loads(p.read_text(encoding="utf-8")).get("labels", []))
    return out


def build_corpus(per_category: int = 40, negatives: int = 60, seed: int = 42):
    """Positives = known illicit; negatives = legitimate exchange (service) addresses."""
    rng = random.Random(seed)
    by_cat: dict[str, list[str]] = {}
    for entry in _raw_labels():
        by_cat.setdefault(entry.get("category", ""), []).append(entry["address"])

    positives: list[tuple[str, str]] = []
    for cat in ("sanctioned", "ransomware", "scam"):
        addrs = list(dict.fromkeys(by_cat.get(cat, [])))
        rng.shuffle(addrs)
        positives += [(a, cat) for a in addrs[:per_category]]

    neg = list(dict.fromkeys(by_cat.get("exchange", [])))
    rng.shuffle(neg)
    return positives, neg[:negatives]


def _load_labels(exclude: set[str] | None = None) -> LabelStore:
    exclude = {norm_addr(a) for a in (exclude or set())}
    store = LabelStore()
    for entry in _raw_labels():
        if norm_addr(entry["address"]) in exclude:
            continue
        try:
            category = LabelCategory(entry.get("category", "other"))
        except ValueError:
            category = LabelCategory.OTHER
        store.add(
            Label(entry["address"], category, entry.get("name", ""), entry.get("source", ""),
                  entry.get("description", ""))
        )
    return store


def _grade(address: str, labels: LabelStore) -> str:
    node = TraceNode(address, NodeType.ADDRESS, 0)
    lab = labels.get(address)
    if lab is not None:
        node.label_category = lab.category.value
    return assess(node, "").level


def _confusion(positives, negatives, labels) -> tuple[int, int, int, int]:
    tp = fn = fp = tn = 0
    for addr, _cat in positives:
        if _grade(addr, labels) in _FLAGGED:
            tp += 1
        else:
            fn += 1
    for addr in negatives:
        if _grade(addr, labels) in _FLAGGED:
            fp += 1
        else:
            tn += 1
    return tp, fp, tn, fn


def _metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    total = tp + fp + tn + fn
    return {
        "precision": tp / (tp + fp) if (tp + fp) else 1.0,
        "recall": tp / (tp + fn) if (tp + fn) else 0.0,
        "false_positive_rate": fp / (fp + tn) if (fp + tn) else 0.0,
        "false_negative_rate": fn / (fn + tp) if (fn + tp) else 0.0,
        "accuracy": (tp + tn) / total if total else 0.0,
    }


def run(per_category: int = 40, negatives: int = 60) -> dict:
    positives, negs = build_corpus(per_category, negatives)

    labels_full = _load_labels()
    a = _confusion(positives, negs, labels_full)

    labels_heldout = _load_labels(exclude={a for a, _ in positives})
    b = _confusion(positives, negs, labels_heldout)

    return {
        "positives": len(positives),
        "negatives": len(negs),
        "label_assisted": {"confusion": a, "metrics": _metrics(*a)},
        "behavioural": {"confusion": b, "metrics": _metrics(*b)},
    }
