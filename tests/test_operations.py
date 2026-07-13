"""Deterministic offline tests for the batch-operation and validation harnesses.

These two modules ship live CLI commands (`ariadne operation`, `ariadne validate`)
yet had zero test coverage. This suite drives every function offline: file
parsing, chain inference, per-wallet result extraction, ring correlation, campaign
rendering, and the full trace -> taint -> report -> known-answer check path.
"""

import pathlib
import tempfile

from ariadne import operation, validation
from ariadne.enrich.labels import Label, LabelCategory, LabelStore
from ariadne.models import BTC, Transaction, TxInput, TxOutput


def _tx(txid, ins, outs):
    return Transaction(
        txid,
        [TxInput(a, v) for a, v in ins],
        [TxOutput(a, v, i) for i, (a, v) in enumerate(outs)],
    )


# --------------------------------------------------------------------------- #
# operation.infer_chain
# --------------------------------------------------------------------------- #
def test_infer_chain_btc_evm_trx_and_unknown():
    assert operation.infer_chain("12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw") == "btc"
    assert operation.infer_chain("0x28C6c06298d514Db089934071355E5743bf21d60") == "usdt"
    assert operation.infer_chain("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t") == "trx"
    assert operation.infer_chain("not-an-address") is None
    # Injection-shaped garbage must never be inferred as a chain.
    assert operation.infer_chain("<script>alert(1)</script>") is None


def test_infer_chain_does_not_raise_on_gated_chains():
    # A DOGE-shaped string still resolves to a gated chain code without crashing;
    # the point is that inference never throws on any input.
    for probe in ("", "   ", "0xnothex", "D" + "A" * 30):
        operation.infer_chain(probe)  # must not raise


# --------------------------------------------------------------------------- #
# operation.read_wallets
# --------------------------------------------------------------------------- #
def test_read_wallets_parsing_comments_hints_and_inference():
    body = "\n".join(
        [
            "# operation input — one wallet per line",
            "",
            "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw   # inferred btc",
            "0x28C6c06298d514Db089934071355E5743bf21d60,usdt",
            "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t trx",
            "   ",  # whitespace-only, skipped
        ]
    )
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "wallets.txt"
        p.write_text(body, encoding="utf-8")
        rows = operation.read_wallets(p)
    assert len(rows) == 3
    assert rows[0] == ("12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw", "btc")
    assert rows[1] == ("0x28C6c06298d514Db089934071355E5743bf21d60", "usdt")
    assert rows[2] == ("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "trx")


def test_read_wallets_empty_file_returns_empty():
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "empty.txt"
        p.write_text("# only a comment\n\n", encoding="utf-8")
        assert operation.read_wallets(p) == []


# --------------------------------------------------------------------------- #
# operation.wallet_result_from_report
# --------------------------------------------------------------------------- #
def _report(seed="S", findings=None, n_findings=None):
    findings = findings if findings is not None else []
    return {
        "trace": {"seed": seed},
        "brief": {"risk_level": "high", "risk_score": 74},
        "summary": {"findings": n_findings if n_findings is not None else len(findings)},
        "findings": findings,
        "nodes": [],
    }


def test_wallet_result_extracts_endpoints_and_sanctioned():
    report = _report(
        findings=[
            {"type": "service", "address": "EX", "label": "Binance", "category": "exchange"},
            {"type": "address", "address": "M", "label": None, "category": "mixer"},
            {"type": "address", "address": "S", "label": None, "category": None},
            {"type": "service", "address": "OFAC", "label": "Lazarus", "category": "sanctioned"},
        ],
        n_findings=4,
    )
    wr = operation.wallet_result_from_report("S", "btc", report, "reports/s.json")
    assert wr.ok and wr.risk_level == "high" and wr.risk_score == 74
    assert wr.findings == 4
    # service OR any categorised finding becomes an endpoint; the plain address does not.
    endpoints = {e[0] for e in wr.endpoints}
    assert endpoints == {"EX", "M", "OFAC"}
    assert wr.sanctioned == ["OFAC"]
    # category falls back to type when the label lacks a category.
    by_addr = {e[0]: e for e in wr.endpoints}
    assert by_addr["M"][2] == "mixer"


# --------------------------------------------------------------------------- #
# operation.correlate  (ring linkage by shared infrastructure)
# --------------------------------------------------------------------------- #
def test_correlate_finds_shared_infrastructure_and_ignores_singletons():
    r1 = operation.WalletResult("W1", "btc", endpoints=[("EX", "Binance", "exchange"), ("solo", None, "address")])
    r2 = operation.WalletResult("W2", "btc", endpoints=[("EX", "Binance", "exchange")])
    r3 = operation.WalletResult("W3", "btc", endpoints=[("EX", "Binance", "exchange")])
    bad = operation.WalletResult("W4", "btc", ok=False, error="boom", endpoints=[("EX", "Binance", "exchange")])

    out = operation.correlate([r1, r2, r3, bad])
    shared = out["shared_infrastructure"]
    assert len(shared) == 1  # only EX is shared; "solo" reached by one wallet
    link = shared[0]
    assert link["endpoint"] == "EX" and link["label"] == "Binance"
    # errored wallets are excluded from linkage, so EX links exactly W1..W3.
    assert link["wallets"] == ["W1", "W2", "W3"]


def test_correlate_empty_when_no_overlap():
    r1 = operation.WalletResult("W1", "btc", endpoints=[("A", None, "exchange")])
    r2 = operation.WalletResult("W2", "btc", endpoints=[("B", None, "exchange")])
    assert operation.correlate([r1, r2])["shared_infrastructure"] == []


# --------------------------------------------------------------------------- #
# operation.write_campaign  (markdown rendering)
# --------------------------------------------------------------------------- #
def test_write_campaign_renders_ring_and_errors():
    results = [
        operation.WalletResult("W1", "btc", risk_level="critical", risk_score=90, findings=3, report_path="a.json"),
        operation.WalletResult("W2", "btc", risk_level="high", risk_score=70, findings=2, report_path="b.json"),
        operation.WalletResult("Wbad", "trx", ok=False, error="provider 500"),
    ]
    campaign = {
        "shared_infrastructure": [
            {"endpoint": "EX", "label": "Binance", "category": "exchange", "wallets": ["W1", "W2"]}
        ]
    }
    with tempfile.TemporaryDirectory() as d:
        path = operation.write_campaign("theseus", results, campaign, pathlib.Path(d))
        text = path.read_text(encoding="utf-8")
    assert path.name == "OPERATION_theseus.md"
    assert "2 flagged critical/high risk" in text
    assert "Binance" in text and "EX" in text
    assert "provider 500" in text  # errored wallet surfaced
    assert "`W1`" in text and "CRITICAL" in text


def test_write_campaign_no_links_message():
    results = [operation.WalletResult("W1", "btc", risk_level="info", risk_score=0)]
    campaign = {"shared_infrastructure": []}
    with tempfile.TemporaryDirectory() as d:
        text = operation.write_campaign("solo", results, campaign, pathlib.Path(d)).read_text(encoding="utf-8")
    assert "No shared infrastructure detected" in text


# --------------------------------------------------------------------------- #
# validation predicates
# --------------------------------------------------------------------------- #
def _val_report(seed_level="high", node_types=("seed", "service"), named_service=True):
    nodes = [{"type": t, "label": ("Binance" if (t == "service" and named_service) else None)} for t in node_types]
    findings = [{"address": "S", "confidence": {"level": seed_level, "score": 90}}]
    return {"trace": {"seed": "S"}, "findings": findings, "nodes": nodes}


def test_validation_predicates():
    rep = _val_report(seed_level="confirmed")
    assert validation.seed_grade_in({"high", "confirmed"})(rep)
    assert not validation.seed_grade_in({"low"})(rep)
    assert validation.reaches_cashout(rep)
    assert validation.cashout_named(rep)

    unnamed = _val_report(seed_level="low", named_service=True, node_types=("seed",))
    assert not validation.reaches_cashout(unnamed)   # no service node
    assert validation.no_high_findings(unnamed)      # seed only graded low

    clean = _val_report(seed_level="low", node_types=("seed", "service"), named_service=False)
    assert validation.reaches_cashout(clean)
    assert not validation.cashout_named(clean)        # service present but unlabelled


def test_seed_finding_absent_returns_false():
    rep = {"trace": {"seed": "S"}, "findings": [{"address": "OTHER", "confidence": {"level": "high", "score": 1}}], "nodes": []}
    assert not validation.seed_grade_in({"high"})(rep)


# --------------------------------------------------------------------------- #
# validation.run_case  (end-to-end, offline fake provider)
# --------------------------------------------------------------------------- #
class _FakeProv:
    name = "fake"
    asset_info = BTC

    def __init__(self, db, service):
        self.db = db
        self.service = set(service)

    def normalize(self, a):
        return a

    def address_tx_count(self, a):
        return 9_000_000 if a in self.service else 3

    def get_transactions(self, a, n):
        return self.db.get(a, [])


def test_run_case_reaches_and_names_cashout():
    # SEED -> MID -> EXCH (a labelled exchange service). 0.005 BTC each hop, above
    # the 0.001-BTC min_value floor run_case applies.
    v = 500_000
    db = {
        "SEED": [_tx("t1", [("SEED", v)], [("MID", v)])],
        "MID": [_tx("t2", [("MID", v)], [("EXCH", v)])],
        "EXCH": [],
    }
    labels = LabelStore()
    labels.add(Label("EXCH", LabelCategory.EXCHANGE, "Binance", "test"))

    case = validation.Case(
        "synthetic reach", "SEED", "btc", "constructed",
        [
            ("reaches a cash-out point", validation.reaches_cashout, "attribution"),
            ("cash-out is NAMED", validation.cashout_named, "attribution"),
        ],
        depth=2,
    )

    def build_provider(chain, cache):
        return _FakeProv(db, service={"EXCH"})

    results = validation.run_case(case, build_provider, labels, cache=None)
    by_desc = {desc: ok for desc, ok, _cat in results}
    assert by_desc["reaches a cash-out point"] is True
    assert by_desc["cash-out is NAMED"] is True
    # category tags are preserved on every returned tuple.
    assert all(cat == "attribution" for _d, _ok, cat in results)


def test_run_case_clean_seed_has_no_named_cashout():
    v = 500_000
    db = {"SEED": [_tx("t1", [("SEED", v)], [("PLAIN", v)])], "PLAIN": []}
    case = validation.Case(
        "no cashout", "SEED", "btc", "constructed",
        [("reaches a cash-out point", validation.reaches_cashout, "attribution")],
        depth=2,
    )

    def build_provider(chain, cache):
        return _FakeProv(db, service=set())

    results = validation.run_case(case, build_provider, LabelStore(), cache=None)
    assert results[0][1] is False  # PLAIN is an ordinary address, not a service
