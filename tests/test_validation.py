"""Tests for the cited corpus and the reproducible validation report."""

import json
import subprocess
import sys

import pytest

from ariadne import corpus, validation, validation_report


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


# --------------------------------------------------------------------------- #
# extensible corpus (data-file additions)
# --------------------------------------------------------------------------- #
def test_add_case_roundtrip(tmp_path):
    p = tmp_path / "cases.json"
    p.write_text('{"cases": []}', encoding="utf-8")
    c = corpus.add_case("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc", "scam", "illicit",
                        "Public example (test citation)", path=p)
    assert c.truth == "illicit"
    extra = corpus.load_extra_cases(p)
    assert len(extra) == 1 and extra[0].address == c.address
    # persisted with all fields
    doc = json.loads(p.read_text(encoding="utf-8"))
    assert doc["cases"][0]["source"].startswith("Public example")


def test_add_case_rejects_missing_source_bad_address_and_truth(tmp_path):
    p = tmp_path / "cases.json"
    p.write_text('{"cases": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="source"):
        corpus.add_case("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc", "scam", "illicit", "", path=p)
    with pytest.raises(ValueError, match="invalid address"):
        corpus.add_case("not-an-address", "btc", "scam", "illicit", "cite", path=p)
    with pytest.raises(ValueError, match="truth"):
        corpus.add_case("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc", "scam", "maybe", "cite", path=p)


def test_add_case_rejects_duplicate_of_landmark(tmp_path):
    p = tmp_path / "cases.json"
    p.write_text('{"cases": []}', encoding="utf-8")
    # a landmark address is already in the corpus -> must be refused
    with pytest.raises(ValueError, match="already in the corpus"):
        corpus.add_case("12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw", "btc", "ransomware", "illicit", "cite", path=p)


def test_malformed_data_file_is_ignored(tmp_path):
    p = tmp_path / "cases.json"
    p.write_text("{ not json", encoding="utf-8")
    assert corpus.load_extra_cases(p) == []      # never raises on a broken file


def test_load_extra_skips_entries_without_provenance(tmp_path):
    p = tmp_path / "cases.json"
    p.write_text(json.dumps({"cases": [
        {"address": "0xabc", "chain": "eth", "truth": "illicit"},          # no source -> dropped
        {"address": "0xdef", "chain": "eth", "truth": "bogus", "source": "x"},  # bad truth -> dropped
        {"address": "0x111", "chain": "eth", "truth": "illicit", "source": "cite"},  # kept
    ]}), encoding="utf-8")
    kept = corpus.load_extra_cases(p)
    assert [c.address for c in kept] == ["0x111"]


# --------------------------------------------------------------------------- #
# validate auto-includes data-file corpus cases
# --------------------------------------------------------------------------- #
def test_validate_all_cases_includes_corpus_additions(monkeypatch):
    extra = corpus.CorpusCase("0x111", "eth", "scam", "illicit", "cite")
    legit = corpus.CorpusCase("0x222", "eth", "legitimate", "legitimate", "cite")
    monkeypatch.setattr(corpus, "load_extra_cases", lambda path=None: [extra, legit])
    cases = validation.all_cases()
    addrs = {c.address for c in cases}
    assert "0x111" in addrs and "0x222" in addrs
    assert len(cases) == len(validation.CASES) + 2
    # the generated checks match the truth: illicit -> detection grade; legit -> no-false-high
    gen_illicit = next(c for c in cases if c.address == "0x111")
    gen_legit = next(c for c in cases if c.address == "0x222")
    assert gen_illicit.checks[0][1] is not gen_legit.checks[0][1]


# --------------------------------------------------------------------------- #
# `python -m ariadne` propagates exit codes
# --------------------------------------------------------------------------- #
def test_python_m_ariadne_exit_codes():
    ok = subprocess.run([sys.executable, "-m", "ariadne", "--version"], capture_output=True)
    assert ok.returncode == 0 and b"ariadne" in ok.stdout
    bad = subprocess.run([sys.executable, "-m", "ariadne", "trace", "--chain", "btc", "xyz"],
                         capture_output=True)
    assert bad.returncode == 2
