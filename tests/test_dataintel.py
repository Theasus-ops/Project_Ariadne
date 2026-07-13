"""Deterministic tests for the data-at-scale layer: feeds classifier + ATM registry."""

from ariadne.enrich.atm import ATMRegistry, atm_intel_for_report, haversine_km
from ariadne.enrich.feeds import classify_tags
from ariadne.enrich.labels import LabelCategory


# ---------------- feeds keyword classifier ----------------
def test_classify_tags_categories():
    assert classify_tags({"ofac-sanctions-lists"}) == LabelCategory.SANCTIONED
    assert classify_tags({"tornado-cash"}) == LabelCategory.MIXER
    assert classify_tags({"blocked"}) == LabelCategory.FROZEN
    assert classify_tags({"binance"}) == LabelCategory.EXCHANGE
    assert classify_tags({"sushiswap"}) == LabelCategory.DEX
    assert classify_tags({"bridge"}) == LabelCategory.BRIDGE
    assert classify_tags({"gambling"}) == LabelCategory.GAMBLING
    assert classify_tags({"aave"}) == LabelCategory.SERVICE
    assert classify_tags({"phishing"}) == LabelCategory.SCAM
    assert classify_tags({"bitcoin-atm"}) == LabelCategory.ATM
    assert classify_tags({"some-random-token"}) is None


def test_classify_tags_no_false_positives():
    # 'bancor' must not trip the 'ban' -> frozen path (exact-tag sets used).
    assert classify_tags({"bancor"}) == LabelCategory.DEX
    # 'sorbet-finance' must not trip 'bet' -> gambling.
    assert classify_tags({"sorbet-finance"}) != LabelCategory.GAMBLING
    # 'marketing' must not trip darknet 'market'.
    assert classify_tags({"marketing"}) != LabelCategory.DARKNET


def test_classify_priority_illicit_wins():
    # An address tagged both an exchange and sanctioned is classified sanctioned.
    assert classify_tags({"binance", "ofac-sanctions-lists"}) == LabelCategory.SANCTIONED


# ---------------- haversine ----------------
def test_haversine_athens_thessaloniki():
    # Athens (37.98,23.72) to Thessaloniki (40.64,22.94) ~ 300 km.
    d = haversine_km(37.98, 23.72, 40.64, 22.94)
    assert 290 < d < 320


# ---------------- ATM registry ----------------
def _registry(tmp_path):
    reg = ATMRegistry(tmp_path / "atm.sqlite")
    reg.add("node/1", "Bcash", 37.96376, 23.72298, city="Athina", country="GR", street="Dimitrakopoulou 84")
    reg.add("node/2", "Bcash", 40.60782, 22.96305, city="Thessaloniki", country="GR")
    reg.add("node/3", "Athena Bitcoin", 40.71, -74.00, city="New York", country="US")
    return reg


def test_atm_registry_near_and_operator(tmp_path):
    reg = _registry(tmp_path)
    near = reg.near(37.98, 23.72, radius_km=10)
    assert len(near) == 1 and near[0]["operator"] == "Bcash" and near[0]["distance_km"] < 3
    ops = {o["operator"]: o["machines"] for o in reg.operators()}
    assert ops["Bcash"] == 2 and ops["Athena Bitcoin"] == 1
    assert reg.stats()["machines"] == 3 and reg.stats()["countries"] == 2
    assert len(reg.by_operator("bcash")) == 2  # case-insensitive substring
    reg.close()


def test_atm_intel_for_report(tmp_path):
    reg = _registry(tmp_path)
    report = {"nodes": [
        {"address": "0xatm", "category": "atm", "label": "Bcash", "type": "service"},
        {"address": "0xother", "category": "exchange", "label": "Binance", "type": "service"},
    ]}
    intel = atm_intel_for_report(report, reg)
    assert len(intel) == 1
    assert intel[0]["operator"] == "Bcash" and intel[0]["machine_count"] == 2
    assert intel[0]["candidate_locations"][0]["lat"] is not None
    assert "operator" in intel[0]["note"].lower()
    reg.close()
