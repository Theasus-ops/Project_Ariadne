"""Deterministic tests for address-poisoning and dusting detection."""

from ariadne.core.poisoning import (
    Counterparty,
    compare_form,
    detect_address_poisoning,
    detect_dusting,
    is_dust,
    looks_alike,
    match_strength,
)

# A genuine counterparty and a ground-out look-alike sharing head "abcd" + tail "ef01".
REAL = "0xabcd" + "1" * 32 + "ef01"
POISON = "0xABCD" + "9" * 32 + "EF01"   # different case on purpose (EVM is case-insensitive)
UNRELATED = "0x" + "0" * 40


# --------------------------------------------------------------------------- #
# primitives
# --------------------------------------------------------------------------- #
def test_compare_form_strips_0x_and_lowercases():
    assert compare_form("0xABCdef") == "abcdef"
    assert compare_form("1BitcoinAddr") == "1BitcoinAddr"  # base58 kept as-is


def test_looks_alike_prefix_suffix_and_case_insensitivity():
    assert looks_alike(REAL, POISON) is True          # same head+tail, different middle, mixed case
    assert looks_alike(REAL, UNRELATED) is False
    assert looks_alike(REAL, REAL) is False            # identical is not a look-alike
    assert looks_alike("", REAL) is False


def test_match_strength_reports_head_and_tail():
    pre, suf = match_strength(REAL, POISON)
    assert pre == 4 and suf == 4
    # a longer grind shows as a stronger match
    strong_a = "0x" + "dead" + "1" * 32 + "beef"
    strong_b = "0x" + "dead" + "2" * 32 + "beef"
    assert match_strength(strong_a, strong_b) == (4, 4)


def test_is_dust():
    assert is_dust(0, 0) and is_dust(1000, 1000) and not is_dust(1001, 1000)


# --------------------------------------------------------------------------- #
# poisoning detection — severity ladder
# --------------------------------------------------------------------------- #
def _cp(addr, from_v=0, to_v=0, zero=0):
    return Counterparty(addr, value_from_victim=from_v, value_to_victim=to_v, zero_value_transfers=zero)


def test_high_when_dust_primed_lookalike_of_genuine_counterparty():
    cps = [
        _cp(REAL, from_v=1_000_000),          # victim really paid this one
        _cp(POISON, zero=1),                  # poison primed with a zero-value transfer
        _cp(UNRELATED, from_v=500_000),
    ]
    findings = detect_address_poisoning("0xVICTIM", cps, dust_threshold=1000)
    assert len(findings) == 1
    f = findings[0]
    assert f.real == REAL and f.lookalike == POISON
    assert f.primed_with_dust is True and f.victim_paid_lookalike == 0
    assert f.severity == "high"


def test_critical_when_victim_paid_the_lookalike():
    cps = [
        _cp(REAL, from_v=1_000_000),
        _cp(POISON, from_v=5_000_000, zero=1),   # victim sent real value to the poison
    ]
    findings = detect_address_poisoning("0xVICTIM", cps, dust_threshold=1000)
    assert findings[0].severity == "critical"
    assert findings[0].victim_paid_lookalike == 5_000_000
    # orientation: the genuinely-established address is 'real', the impersonator 'lookalike'
    assert findings[0].real == REAL and findings[0].lookalike == POISON


def test_medium_for_bare_lookalike_without_dust_or_payment():
    cps = [_cp(REAL), _cp(POISON)]   # neither paid, no dust evidence
    findings = detect_address_poisoning("0xVICTIM", cps, dust_threshold=1000)
    assert findings and findings[0].severity == "medium"


def test_no_findings_without_lookalikes():
    cps = [_cp(REAL, from_v=1_000_000), _cp(UNRELATED, from_v=500_000)]
    assert detect_address_poisoning("0xVICTIM", cps, dust_threshold=1000) == []


def test_findings_sorted_critical_first():
    other_real = "0x" + "beef" + "1" * 32 + "cafe"
    other_poison = "0x" + "beef" + "7" * 32 + "cafe"
    cps = [
        _cp(REAL, from_v=1_000_000), _cp(POISON, zero=1),                       # -> high
        _cp(other_real, from_v=1_000_000), _cp(other_poison, from_v=9_000_000), # -> critical
    ]
    findings = detect_address_poisoning("0xVICTIM", cps, dust_threshold=1000)
    assert [f.severity for f in findings] == ["critical", "high"]


# --------------------------------------------------------------------------- #
# dusting detection
# --------------------------------------------------------------------------- #
def test_dusting_flagged_when_many_sources():
    incoming = [(f"0xsrc{i}", 1) for i in range(5)] + [("0xbig", 10_000_000)]
    f = detect_dusting("0xTARGET", incoming, dust_threshold=100, min_sources=3)
    assert f is not None and f.dust_sources == 5 and f.dust_transfers == 5


def test_dusting_not_flagged_below_threshold():
    incoming = [("0xa", 1), ("0xb", 1)]
    assert detect_dusting("0xTARGET", incoming, dust_threshold=100, min_sources=3) is None


# --------------------------------------------------------------------------- #
# integration: counterparties from transactions + report surfacing
# --------------------------------------------------------------------------- #
def test_counterparties_from_txs_captures_direction_and_zero_value():
    from ariadne.core.poisoning import counterparties_from_txs
    from ariadne.models import Transaction, TxInput, TxOutput

    victim = "0xVICTIM"
    txs = [
        # victim pays A 100
        Transaction("t1", [TxInput(victim, 100)], [TxOutput("0xA", 100, 0)]),
        # B primes the victim with a zero-value transfer
        Transaction("t2", [TxInput("0xB", 0)], [TxOutput(victim, 0, 0)]),
    ]
    cps = {c.address: c for c in counterparties_from_txs(victim, txs)}
    assert cps["0xA"].value_from_victim == 100
    assert cps["0xB"].value_to_victim == 0 and cps["0xB"].zero_value_transfers == 1


def test_build_report_surfaces_lookalike_warnings():
    from ariadne.models import BTC, NodeType, TraceNode, TraceResult
    from ariadne.report.report import build_report

    r = TraceResult(seed="0xSEED" + "0" * 36, direction="forward", asset=BTC)
    r.add_node(TraceNode(r.seed, NodeType.SEED, 0))
    r.add_node(TraceNode(REAL, NodeType.ADDRESS, 1))
    r.add_node(TraceNode(POISON, NodeType.ADDRESS, 1))
    report = build_report(r)
    warns = report["lookalike_warnings"]
    assert len(warns) == 1
    pair = {warns[0]["a"], warns[0]["b"]}
    assert pair == {REAL, POISON}
    assert warns[0]["matched_prefix"] == 4 and warns[0]["matched_suffix"] == 4
