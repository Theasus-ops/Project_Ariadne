"""Deterministic unit tests for the Ariadne engine (no network)."""

import json
import pathlib
import tempfile
from argparse import Namespace

from rich.console import Console

from ariadne.cases import CaseStore, InvestigationCase
from ariadne.cli import cmd_case, main
from ariadne.core.cluster import Clusterer
from ariadne.core.coinjoin import classify as classify_coinjoin
from ariadne.core.confidence import assess
from ariadne.core.taint import compute_taint
from ariadne.core.trace import Tracer
from ariadne.enrich.labels import LabelStore, default_labels_path, ofac_labels_path
from ariadne.models import (
    BTC,
    NodeType,
    TraceNode,
    TraceResult,
    Transaction,
    TxInput,
    TxOutput,
    is_valid_address,
)
from ariadne.monitor.scoring import TxScorer
from ariadne.providers.blockchair import BlockchairProvider
from ariadne.providers.ethereum import EthereumProvider
from ariadne.providers.monero import MoneroProvider
from ariadne.report.report import build_report, write_html
from ariadne.security import AuditLogger
from ariadne.web.app import create_app


def _tx(txid, ins, outs):
    return Transaction(
        txid,
        [TxInput(a, v) for a, v in ins],
        [TxOutput(a, v, i) for i, (a, v) in enumerate(outs)],
    )


# ---------- address validation ----------
def test_address_validation():
    assert is_valid_address("12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw", "btc")
    assert is_valid_address("0x28C6c06298d514Db089934071355E5743bf21d60", "usdt")
    assert not is_valid_address("<script>", "btc")
    assert not is_valid_address("javascript:alert(1)", "btc")
    assert not is_valid_address("0xnothex", "eth")


# ---------- coinjoin ----------
def test_coinjoin_whirlpool():
    tx = _tx("t", [(f"i{i}", 1_000_000) for i in range(5)], [(f"o{i}", 1_000_000) for i in range(5)])
    info = classify_coinjoin(tx)
    assert info and info.kind.value == "whirlpool"


def test_coinjoin_normal_negative():
    assert classify_coinjoin(_tx("t", [("a", 100)], [("b", 90), ("a", 9)])) is None


# ---------- taint conservation ----------
def test_taint_conserves_value():
    r = TraceResult(seed="S", direction="forward", asset=BTC)
    r.add_node(TraceNode("S", NodeType.SEED, 0))
    a = TraceNode("A", NodeType.ADDRESS, 1)
    a.total_received = 20 * 10**8
    r.add_node(a)
    x = TraceNode("X", NodeType.SERVICE, 2)
    x.total_received = 100 * 10**8
    x.tx_count = 5000
    r.add_node(x)
    r.edge("S", "A").value = 10 * 10**8
    r.edge("A", "X").value = 20 * 10**8
    compute_taint(r)
    assert abs(r.nodes["A"].taint_fraction - 0.5) < 1e-6
    # dirty reaching the cash-out must not exceed what the seed disbursed
    assert r.nodes["X"].dirty_received <= r.nodes["S"].dirty_received + 1


# ---------- clustering ----------
class _FakeProv:
    name = "fake"
    asset_info = BTC

    def __init__(self, db, service=()):
        self.db = db
        self.service = set(service)

    def normalize(self, a):
        return a

    def address_tx_count(self, a):
        return 9_000_000 if a in self.service else 3

    def get_transactions(self, a, n):
        return self.db.get(a, [])


def test_clustering_transitive():
    t1 = _tx("t1", [("A", 1), ("B", 1)], [("X", 1)])
    t2 = _tx("t2", [("B", 1), ("C", 1)], [("Y", 1)])
    prov = _FakeProv({"A": [t1], "B": [t1, t2], "C": [t2]})
    assert Clusterer(prov).cluster("A").members == {"A", "B", "C"}


def test_clustering_stops_at_service():
    t = _tx("t1", [("A", 1), ("EX", 1)], [("Z", 1)])
    ex = [_tx(f"e{i}", [("EX", 1), (f"s{i}", 1)], [("q", 1)]) for i in range(20)]
    prov = _FakeProv({"A": [t], "EX": ex}, service=["EX"])
    cl = Clusterer(prov, service_tx_threshold=3000).cluster("A")
    assert cl.members == {"A", "EX"} and "EX" in cl.services_touched


def test_clustering_captures_temporal_rotation_patterns():
    txs = {
        "seed": [
            Transaction("tx1", [TxInput("seed", 100)], [TxOutput("rot-a", 30, 0), TxOutput("rot-b", 30, 1), TxOutput("rot-c", 40, 2)]),
            Transaction("tx2", [TxInput("seed", 100)], [TxOutput("rot-d", 30, 0), TxOutput("rot-e", 30, 1), TxOutput("rot-f", 40, 2)]),
        ]
    }

    class _RotationProv:
        name = "fake"
        asset_info = BTC

        def normalize(self, a):
            return a

        def address_tx_count(self, a):
            return 1

        def get_transactions(self, a, n):
            return txs.get(a, [])

    cluster = Clusterer(_RotationProv()).cluster("seed")
    assert {"rot-a", "rot-b", "rot-c", "rot-d", "rot-e", "rot-f"}.issubset(cluster.members)
    assert any(item.get("pattern") == "temporal_rotation" for item in cluster.links)


# ---------- scoring ----------
def test_scoring_flags_labeled_and_coinjoin():
    labels = LabelStore.load(default_labels_path(), ofac_labels_path())
    scorer = TxScorer(BTC, labels, large_value_units=10)
    to_wc = _tx("t", [("x", 5 * 10**8)], [("12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw", 5 * 10**8)])
    assert scorer.score(to_wc).total >= 45  # ransomware counterparty
    cj = _tx("t", [(f"i{i}", 1_000_000) for i in range(5)], [(f"o{i}", 1_000_000) for i in range(5)])
    assert scorer.score(cj).total >= 30


def test_scoring_flags_wallet_rotation_patterns():
    labels = LabelStore.load(default_labels_path(), ofac_labels_path())
    scorer = TxScorer(BTC, labels, large_value_units=10, fanout_threshold=3)
    tx = Transaction(
        "rotation",
        [TxInput("source", 500_000_000)],
        [TxOutput(f"new-{i}", 20_000, i) for i in range(6)],
    )
    scored = scorer.score(tx)
    assert scored.total >= 15
    assert any("rotation" in reason.lower() for reason in scored.reasons)


# ---------- confidence ----------
def test_confidence_levels():
    n = TraceNode("a", NodeType.ADDRESS, 1)
    n.label_category = "sanctioned"
    assert assess(n, "").level == "confirmed"
    n2 = TraceNode("b", NodeType.ADDRESS, 1)
    n2.label_category = "ransomware"
    assert assess(n2, "").level == "high"
    svc = TraceNode("c", NodeType.SERVICE, 2)
    svc.tx_count = 9000
    assert assess(svc, "").level == "low"  # unlabeled service, no illicit origin


# ---------- html escaping (XSS) ----------
def test_html_escaping():
    r = TraceResult(seed="<img src=x onerror=alert(1)>", direction="forward", asset=BTC)
    r.add_node(TraceNode("<img src=x onerror=alert(1)>", NodeType.SEED, 0))
    p = pathlib.Path(tempfile.gettempdir()) / "ariadne_xss.html"
    write_html(r, p)
    assert "<img src=x onerror" not in p.read_text(encoding="utf-8")


# ---------- ethereum live monitoring ----------
def test_eth_provider_live_monitor_methods(monkeypatch):
    provider = EthereumProvider(asset="ETH")

    def fake_get(url, cache_key):
        if "module=proxy&action=eth_blockNumber" in url:
            return {"result": "0x10"}
        if "module=proxy&action=eth_getBlockByNumber" in url:
            return {
                "result": {
                    "number": "0x10",
                    "transactions": [
                        {
                            "hash": "0xabc",
                            "from": "0x1111111111111111111111111111111111111111",
                            "to": "0x2222222222222222222222222222222222222222",
                            "value": "0x1",
                            "blockNumber": "0x10",
                        }
                    ],
                }
            }
        if "module=proxy&action=txpool_content" in url:
            return {"result": {"pending": {}}}
        raise AssertionError(url)

    monkeypatch.setattr(provider, "_get", fake_get)

    assert provider.latest_block_height() == 16
    txs = provider.get_block_transactions(16, max_txs=1)
    assert len(txs) == 1
    assert txs[0].txid == "0xabc"
    assert provider.get_mempool_transactions(max_txs=1) == []


# ---------- web input validation (no network) ----------
def test_web_rejects_bad_input():
    c = create_app().test_client()
    assert c.post("/api/trace", json={"address": "<x>", "chain": "btc"}).status_code == 400
    assert c.post("/api/trace", json={"address": "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw", "chain": "doge"}).status_code == 400
    assert c.post("/api/trace", data="notjson", content_type="text/plain").status_code == 400


def test_health_endpoint_reports_status():
    c = create_app().test_client()
    response = c.get("/api/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["service"] == "ariadne"
    assert "btc" in payload["chains"]


def test_web_enforces_auth_and_audit(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    app = create_app(auth_token="secret-token", audit_log_path=audit_path)
    client = app.test_client()

    missing = client.post("/api/trace", json={"address": "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw", "chain": "btc"})
    assert missing.status_code == 401

    authorized = client.post(
        "/api/trace",
        json={"address": "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw", "chain": "btc"},
        headers={"Authorization": "Bearer secret-token"},
    )
    assert authorized.status_code in {200, 400}

    assert audit_path.exists()
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 1
    payload = lines[-1]
    assert '"action": "trace"' in payload
    assert '"event": "request"' in payload


def test_web_enforces_role_based_access(tmp_path):
    # Roles are bound to tokens on the SERVER, not to a client-supplied X-Role
    # header (which would be trivially spoofable). Two tokens, two roles.
    app = create_app(
        auth_tokens={"analyst-tok": "analyst", "admin-tok": "admin"},
        case_store_path=tmp_path / "cases.json",
    )
    client = app.test_client()

    created = client.post(
        "/api/cases",
        json={"case_id": "rbac-case", "title": "RBAC case", "note": "opened"},
        headers={"Authorization": "Bearer analyst-tok"},
    )
    assert created.status_code == 200

    # An analyst cannot export — and cannot escalate by asserting a role in a header.
    denied = client.post(
        "/api/cases/rbac-case/export",
        headers={"Authorization": "Bearer analyst-tok", "X-Role": "admin"},
    )
    assert denied.status_code == 403

    allowed = client.post(
        "/api/cases/rbac-case/export",
        headers={"Authorization": "Bearer admin-tok"},
    )
    assert allowed.status_code == 200


def test_audit_logger_emits_jsonl(tmp_path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.log("trace", "operator", "started", {"chain": "btc"})
    logger.log("trace", "operator", "completed", {"chain": "btc", "result": "ok"})
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert '"event": "trace"' in lines[0]


def test_new_providers_support_extended_chains(monkeypatch):
    provider = BlockchairProvider(chain="ltc")
    assert provider.asset_info.symbol == "LTC"

    monero = MoneroProvider()
    monkeypatch.setattr(monero, "get_transactions", lambda address, max_txs=200: [])
    assert monero.heuristic_risk("4test") == {"privacy_coin": True, "observed_txs": 0, "suspicious": False}


def test_backward_trace_follows_inbound_flows():
    class _BackwardProv:
        name = "fake"
        asset_info = BTC

        def normalize(self, a):
            return a

        def address_tx_count(self, a):
            return 1

        def address_received(self, a):
            return None

        def get_transactions(self, a, n):
            if a == "seed":
                return [Transaction("t1", [TxInput("prev", 100_000_000)], [TxOutput("seed", 100_000_000, 0)])]
            return []

    result = Tracer(_BackwardProv(), max_txs_per_address=10).trace_backward("seed", depth=1, min_value=1, max_branch=5)
    assert "prev" in result.nodes
    assert result.edge("prev", "seed").value == 100_000_000


def test_trace_report_links_wallets_to_related_illicit_activity():
    result = TraceResult(seed="seed", direction="forward", asset=BTC)
    result.add_node(TraceNode("seed", NodeType.SEED, 0))
    suspicious = TraceNode("wallet-1", NodeType.ADDRESS, 1)
    suspicious.label_name = "Tornado Cash"
    suspicious.label_category = "mixer"
    suspicious.dirty_received = 10 * 10**8
    suspicious.taint_fraction = 0.9
    result.add_node(suspicious)
    result.edge("seed", "wallet-1").value = 10 * 10**8

    report = build_report(result)
    finding = report["findings"][0]
    assert "mixer" in finding["linked_activity"][0].lower() or any("service" in item.lower() for item in finding["linked_activity"])
    assert any("tornado" in item.lower() for item in finding["linked_activity"])


def test_case_store_persists_and_exports(tmp_path):
    store = CaseStore(tmp_path / "cases.json")
    case = InvestigationCase("case-1", "Test case")
    case.add_note("First note")
    case.add_tag("crypto")
    case.add_evidence({"type": "trace", "address": "abc"})
    store.save_case(case)
    stored = store.load_case("case-1")
    assert stored["title"] == "Test case"
    assert len(stored["timeline"]) == 2
    exported = store.export_bundle("case-1", tmp_path / "evidence")
    payload = json.loads(exported.read_text(encoding="utf-8"))
    assert payload["signature"]


def test_cli_case_actions_update_existing_case(tmp_path):
    store = CaseStore(tmp_path / "cases.json")
    store.save_case(InvestigationCase("case-2", "Existing case"))

    cmd_case(Namespace(action="add-note", case_id="case-2", title=None, note="Second note", tag=None, store=str(tmp_path / "cases.json"), outdir=str(tmp_path / "evidence")), Console())
    cmd_case(Namespace(action="add-evidence", case_id="case-2", title=None, note=None, tag=None, store=str(tmp_path / "cases.json"), outdir=str(tmp_path / "evidence")), Console())

    stored = store.load_case("case-2")
    assert stored["notes"][-1] == "Second note"
    assert stored["evidence"][-1]["type"] == "manual"


def test_cli_parser_supports_note_and_evidence_updates(tmp_path):
    store_path = tmp_path / "cases.json"
    main(["case", "create", "--case-id", "cli-case", "--title", "CLI case", "--store", str(store_path)])
    main(["case", "add-note", "--case-id", "cli-case", "--note", "CLI note", "--store", str(store_path)])
    main(["case", "add-evidence", "--case-id", "cli-case", "--detail", "CLI evidence", "--store", str(store_path)])

    stored = CaseStore(store_path).load_case("cli-case")
    assert stored["notes"][-1] == "CLI note"
    assert stored["evidence"][-1]["detail"] == "CLI evidence"


def test_web_case_updates_existing_case(tmp_path):
    app = create_app(case_store_path=tmp_path / "cases.json")
    client = app.test_client()

    created = client.post(
        "/api/cases",
        json={"case_id": "case-web", "title": "Web case", "note": "Opened from UI"},
    )
    assert created.status_code == 200

    updated = client.post(
        "/api/cases/case-web/update",
        json={"note": "Updated from UI", "evidence": {"type": "manual", "detail": "UI evidence"}},
    )
    assert updated.status_code == 200
    payload = updated.get_json()
    assert payload["notes"][-1] == "Updated from UI"
    assert payload["evidence"][-1]["type"] == "manual"
