"""Tests for the cited corpus and the reproducible validation report."""

from ariadne import corpus, validation_report


# --------------------------------------------------------------------------- #
# corpus provenance
# --------------------------------------------------------------------------- #
def test_landmark_cases_are_cited_and_well_formed():
    assert len(corpus.LANDMARK_CASES) >= 5
    for c in corpus.LANDMARK_CASES:
        assert c.address and c.chain and c.source           # every case carries a citation
        assert c.truth in ("illicit", "legitimate")
    # a mix of illicit and at least one clean control
    truths = {c.truth for c in corpus.LANDMARK_CASES}
    assert truths == {"illicit", "legitimate"}


def test_corpus_summary_reports_counts_and_sources():
    s = corpus.summary()
    assert s["landmark_total"] == len(corpus.LANDMARK_CASES)
    assert s["landmark_illicit"] >= 3 and s["landmark_legitimate"] >= 1
    assert len(s["feed_sources"]) >= 4
    for f in s["feed_sources"]:
        assert f["name"] and f["url"].startswith("http") and f["basis"]


# --------------------------------------------------------------------------- #
# validation report
# --------------------------------------------------------------------------- #
def test_report_structure_and_intervals():
    r = validation_report.run(per_category=10, negatives=20)
    for block in ("operational_safety", "behavioural_detection", "honest_ceiling", "corpus"):
        assert block in r

    fp = r["operational_safety"]["false_positive_rate"]
    for key in ("count", "n", "rate", "ci_low", "ci_high"):
        assert key in fp
    # every proportion sits inside its own interval
    assert fp["ci_low"] <= fp["rate"] <= fp["ci_high"]

    adv = r["behavioural_detection"]["adversarial_scenarios"]
    assert adv["n"] >= 1 and adv["ci_low"] <= adv["rate"] <= adv["ci_high"]

    ceil = r["honest_ceiling"]["behavioural_recall_bare_address"]
    assert ceil["ci_low"] <= ceil["rate"] <= ceil["ci_high"]


def test_report_is_deterministic():
    a = validation_report.run(per_category=10, negatives=20)
    b = validation_report.run(per_category=10, negatives=20)
    assert a["operational_safety"] == b["operational_safety"]
    assert a["honest_ceiling"] == b["honest_ceiling"]


def test_markdown_has_the_sections_and_provenance():
    md = validation_report.to_markdown(validation_report.run(per_category=10, negatives=20))
    assert "# Ariadne — validation report" in md
    assert "Operational safety" in md and "95% CI" in md
    assert "Ground-truth provenance" in md and "OFAC" in md
