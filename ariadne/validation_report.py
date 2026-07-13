"""The published validation report — measured error rates, with intervals.

Assembles the honest accuracy picture an outside reviewer would ask for, and does
it reproducibly and offline:

* **Operational safety** — the false-positive rate on legitimate infrastructure
  controls, with a Wilson confidence interval. This is the strong, defensible claim
  ("it does not falsely accuse"), stated with its uncertainty rather than as a bare
  0%.
* **Behavioural detection** — the detection rate on *constructed* laundering
  scenarios with ground truth by construction (the adversarial suite), with an
  interval. This measures analytical power independent of any label.
* **The honest ceiling** — behavioural recall on bare labelled addresses (their
  labels removed), which is low, because a bare address carries no behavioural
  signal. Reported plainly, because pretending otherwise is the opposite of the
  point.
* **Provenance** — where every ground-truth classification comes from
  (:mod:`ariadne.corpus`), so the numbers are auditable, not asserted.

Deterministic given the label set, so a reviewer can reproduce every figure.
"""

from __future__ import annotations

from . import adversarial, corpus, measurement
from .stats import rate_ci


def run(per_category: int = 100, negatives: int = 150) -> dict:
    m = measurement.run(per_category, negatives)

    tp, fp, tn, fn = m["label_assisted"]["confusion"]
    b_tp, b_fp, b_tn, b_fn = m["behavioural"]["confusion"]

    adv = adversarial.run()

    return {
        "tool": "Ariadne validation report",
        "corpus": corpus.summary(),
        "sample": {"illicit_positives": tp + fn, "legitimate_controls": fp + tn},
        "operational_safety": {
            "false_positive_rate": rate_ci(fp, fp + tn),
            "recall_label_assisted": rate_ci(tp, tp + fn),
            "note": "How safe: on legitimate infrastructure controls, does it falsely accuse?",
        },
        "behavioural_detection": {
            "adversarial_scenarios": rate_ci(adv["passed"], adv["total"]),
            "detection_rate_by_technique": adv["detection_rate"],
            "false_alarm_rate": adv["false_alarm_rate"],
            "note": "Detection on constructed scenarios with ground truth by construction — "
                    "analytical power independent of any label.",
        },
        "honest_ceiling": {
            "behavioural_recall_bare_address": rate_ci(b_tp, b_tp + b_fn),
            "note": "With labels removed, a bare address carries no behavioural signal; recall is "
                    "low by construction. Accuracy is bounded by attribution DATA, not code.",
        },
        "interpretation": (
            "The defensible claim is operational safety (a low, bounded false-positive rate). "
            "Behavioural detection is real on constructed laundering patterns but limited on bare "
            "addresses without attribution. All figures carry a 95% Wilson interval and a sample size."
        ),
    }


def _pct(ci: dict) -> str:
    return (f"{ci['rate'] * 100:.1f}% (95% CI {ci['ci_low'] * 100:.1f}"
            f"–{ci['ci_high'] * 100:.1f}%, n={ci['n']})")


def to_markdown(r: dict) -> str:
    L: list[str] = []
    ap = L.append
    s = r["sample"]
    ap("# Ariadne — validation report")
    ap("")
    ap(f"Corpus: **{s['illicit_positives']}** illicit positives + "
       f"**{s['legitimate_controls']}** legitimate controls, plus "
       f"**{r['corpus']['landmark_total']}** cited landmark cases. All rates carry a 95% "
       "Wilson confidence interval.")
    ap("")
    ap("## Operational safety (the defensible claim)")
    ap("")
    osf = r["operational_safety"]
    ap(f"- **False-positive rate:** {_pct(osf['false_positive_rate'])}")
    ap(f"- Recall (label-assisted): {_pct(osf['recall_label_assisted'])}")
    ap("")
    ap("## Behavioural detection (constructed ground truth)")
    ap("")
    bd = r["behavioural_detection"]
    ap(f"- **Adversarial scenarios passed:** {_pct(bd['adversarial_scenarios'])}")
    ap(f"- Technique detection rate: {bd['detection_rate_by_technique'] * 100:.0f}%  ·  "
       f"False-alarm rate: {bd['false_alarm_rate'] * 100:.0f}%")
    ap("")
    ap("## Honest ceiling (bare-address recall)")
    ap("")
    ap(f"- Behavioural recall, labels removed: {_pct(r['honest_ceiling']['behavioural_recall_bare_address'])}")
    ap(f"  > {r['honest_ceiling']['note']}")
    ap("")
    ap("## Ground-truth provenance")
    ap("")
    for f in r["corpus"]["feed_sources"]:
        ap(f"- **{f['name']}** — {f['provides']} ({f['basis']})")
    ap("")
    ap(f"> {r['interpretation']}")
    return "\n".join(L)
