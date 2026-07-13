"""Accuracy benchmark — the measured-error-rate artifact accreditation needs.

`ariadne measure` proves the *shape* of the trade-off; this produces the document a
reviewer cites: **per-category** precision / recall / false-positive / false-negative
rates over a larger sampled corpus, plus the honest "behavioural" recall (how well
the grader detects a bad actor whose label has been *removed* — the real measure of
its own analytical power, independent of the attribution data).

It reuses the confusion-matrix machinery in :mod:`ariadne.measurement` and adds the
per-category breakdown, a structured JSON/Markdown report, and an optional Ed25519
signature so the accuracy claim is itself accountable.
"""

from __future__ import annotations

from .measurement import _FLAGGED, _grade, _load_labels, _metrics, build_corpus


def run(per_category: int = 100, negatives: int = 150) -> dict:
    positives, negs = build_corpus(per_category, negatives)
    labels = _load_labels()

    # Per-category recall (label-assisted): does it flag a known-bad address?
    by_category: dict[str, dict] = {}
    for cat in sorted({c for _, c in positives}):
        cat_pos = [a for a, c in positives if c == cat]
        detected = sum(1 for a in cat_pos if _grade(a, labels) in _FLAGGED)
        n = len(cat_pos)
        by_category[cat] = {
            "n": n, "detected": detected, "missed": n - detected,
            "recall": round(detected / n, 4) if n else 0.0,
        }

    # Overall confusion (positives vs legitimate negatives).
    tp = sum(1 for a, _ in positives if _grade(a, labels) in _FLAGGED)
    fn = len(positives) - tp
    fp = sum(1 for a in negs if _grade(a, labels) in _FLAGGED)
    tn = len(negs) - fp
    overall = _metrics(tp, fp, tn, fn)

    # Behavioural recall: remove the positives' own labels, then try to detect them.
    heldout = _load_labels(exclude={a for a, _ in positives})
    b_tp = sum(1 for a, _ in positives if _grade(a, heldout) in _FLAGGED)
    behavioural_recall = round(b_tp / len(positives), 4) if positives else 0.0

    return {
        "tool": "Ariadne accuracy benchmark",
        "sample": {"positives": len(positives), "negatives": len(negs), "per_category": per_category},
        "per_category": by_category,
        "overall": {"confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn}, "metrics": overall},
        "behavioural_recall": behavioural_recall,
        "interpretation": (
            "Label-assisted metrics measure operational safety (a 0% false-positive rate means it "
            "never falsely accuses a legitimate address). Behavioural recall measures analytical power "
            "independent of attribution data — the honest ceiling of detection without a label."
        ),
    }


def to_markdown(result: dict) -> str:
    L: list[str] = []
    ap = L.append
    s = result["sample"]
    m = result["overall"]["metrics"]
    ap("# Ariadne — accuracy benchmark")
    ap("")
    ap(f"Corpus: {s['positives']} illicit + {s['negatives']} legitimate addresses "
       f"({s['per_category']} per illicit category).")
    ap("")
    ap("## Overall (label-assisted)")
    ap("")
    ap(f"- Precision: **{m['precision'] * 100:.1f}%**  ·  Recall: **{m['recall'] * 100:.1f}%**")
    ap(f"- False-positive rate: **{m['false_positive_rate'] * 100:.1f}%**  ·  "
       f"False-negative rate: **{m['false_negative_rate'] * 100:.1f}%**  ·  "
       f"Accuracy: **{m['accuracy'] * 100:.1f}%**")
    ap(f"- Behavioural recall (labels removed): **{result['behavioural_recall'] * 100:.1f}%**")
    ap("")
    ap("## Per category (recall)")
    ap("")
    ap("| Category | Sample | Detected | Missed | Recall |")
    ap("|---|---|---|---|---|")
    for cat, d in result["per_category"].items():
        ap(f"| {cat} | {d['n']} | {d['detected']} | {d['missed']} | {d['recall'] * 100:.1f}% |")
    ap("")
    ap(f"> {result['interpretation']}")
    return "\n".join(L)
