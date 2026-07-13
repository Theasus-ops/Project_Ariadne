"""Regression tests for load-bearing but under-tested logic.

Each function here guards a headline claim: tag classification (attribution at
scale), OFAC SDN parsing (the highest-signal label), alert fan-out (never miss
movement), and Tron TRC-20 parsing (the pig-butchering settlement rail). None hit
the network — feeds/providers are driven through injected data or a monkeypatched
fetcher.
"""

import io
import json
import pathlib
import tempfile

from ariadne.enrich import feeds, ofac
from ariadne.enrich.labels import LabelCategory
from ariadne.monitor.notify import (
    CompositeNotifier,
    ConsoleNotifier,
    FileNotifier,
    Notifier,
)
from ariadne.providers.tron import TronProvider


# --------------------------------------------------------------------------- #
# feeds.classify_tags — the attribution-at-scale classifier
# --------------------------------------------------------------------------- #
def test_classify_tags_maps_each_category():
    assert feeds.classify_tags({"binance"}) is LabelCategory.EXCHANGE
    assert feeds.classify_tags({"uniswap"}) is LabelCategory.DEX
    assert feeds.classify_tags({"tornado-cash"}) is LabelCategory.MIXER
    assert feeds.classify_tags({"wormhole"}) is LabelCategory.BRIDGE
    assert feeds.classify_tags({"casino"}) is LabelCategory.GAMBLING
    assert feeds.classify_tags({"bitcoin-atm"}) is LabelCategory.ATM
    assert feeds.classify_tags({"aave"}) is LabelCategory.SERVICE
    assert feeds.classify_tags({"phishing"}) is LabelCategory.SCAM
    assert feeds.classify_tags({"ransomware"}) is LabelCategory.RANSOMWARE
    assert feeds.classify_tags({"darknet-market"}) is LabelCategory.DARKNET
    assert feeds.classify_tags({"ofac-sanctions-lists"}) is LabelCategory.SANCTIONED
    assert feeds.classify_tags({"tether-banned"}) is LabelCategory.FROZEN


def test_classify_tags_illicit_wins_over_service():
    # An address tagged BOTH sanctioned and exchange must resolve to sanctioned —
    # never let a benign tag mask the highest-signal finding.
    assert feeds.classify_tags({"binance", "ofac"}) is LabelCategory.SANCTIONED
    assert feeds.classify_tags({"uniswap", "phishing"}) is LabelCategory.SCAM
    assert feeds.classify_tags({"exchange", "tornado"}) is LabelCategory.MIXER


def test_classify_tags_unknown_and_empty_are_none():
    assert feeds.classify_tags(set()) is None
    assert feeds.classify_tags({"some-random-project", "nft"}) is None


def test_classify_tags_is_case_insensitive():
    assert feeds.classify_tags({"BINANCE"}) is LabelCategory.EXCHANGE
    assert feeds.classify_tags({"OFAC"}) is LabelCategory.SANCTIONED


def test_fetch_exchanges_offline_via_injected_json(monkeypatch):
    payload = {
        "0xaaa": {"name": "Binance 14", "labels": ["binance", "exchange"]},
        "0xbbb": {"name": "", "labels": ["tornado-cash"]},
        "0xccc": {"name": "Random dApp", "labels": ["nft-marketplace"]},  # unclassifiable -> dropped
        "0xddd": "not-a-dict",  # malformed row -> skipped, no crash
    }

    class _Resp:
        def json(self):
            return payload

    monkeypatch.setattr(feeds, "_get", lambda url: _Resp())
    labels = {label.address: label for label in feeds.fetch_exchanges()}
    assert set(labels) == {"0xaaa", "0xbbb"}
    assert labels["0xaaa"].category is LabelCategory.EXCHANGE
    assert labels["0xaaa"].name == "Binance 14"
    # empty name falls back to the first tag, never an IndexError on empty tags.
    assert labels["0xbbb"].category is LabelCategory.MIXER
    assert labels["0xbbb"].name == "tornado-cash"


# --------------------------------------------------------------------------- #
# ofac.parse_sdn — extract SANCTIONED crypto addresses from SDN XML
# --------------------------------------------------------------------------- #
_SDN_XML = """<?xml version="1.0" encoding="utf-8"?>
<sdnList xmlns="http://tempuri.org/sdnList.xsd">
  <sdnEntry>
    <uid>1</uid>
    <firstName>Alex</firstName>
    <lastName>Ivanov</lastName>
    <idList>
      <id>
        <uid>10</uid>
        <idType>Digital Currency Address - XBT</idType>
        <idNumber>1BitcoinSanctionedAddrxxxxxxxxxxxxx</idNumber>
      </id>
      <id>
        <uid>11</uid>
        <idType>Passport</idType>
        <idNumber>P1234567</idNumber>
      </id>
    </idList>
  </sdnEntry>
  <sdnEntry>
    <uid>2</uid>
    <lastName>NoCryptoEntity</lastName>
    <idList>
      <id>
        <uid>20</uid>
        <idType>Email Address</idType>
        <idNumber>x@example.com</idNumber>
      </id>
    </idList>
  </sdnEntry>
</sdnList>
"""


def test_parse_sdn_extracts_only_crypto_addresses():
    labels = ofac.parse_sdn(io.BytesIO(_SDN_XML.encode("utf-8")))
    assert len(labels) == 1
    lbl = labels[0]
    assert lbl.address == "1BitcoinSanctionedAddrxxxxxxxxxxxxx"
    assert lbl.category is LabelCategory.SANCTIONED
    assert lbl.name == "Alex Ivanov"  # first + last combined
    assert lbl.description.startswith("Digital Currency Address")


def test_parse_sdn_name_fallbacks():
    # last-name-only entity with a crypto id still parses and names cleanly.
    xml = _SDN_XML.replace("<firstName>Alex</firstName>\n    ", "")
    labels = ofac.parse_sdn(io.BytesIO(xml.encode("utf-8")))
    assert labels[0].name == "Ivanov"


# --------------------------------------------------------------------------- #
# notify — alert fan-out is best-effort and durable
# --------------------------------------------------------------------------- #
def test_file_notifier_writes_jsonl():
    with tempfile.TemporaryDirectory() as d:
        path = pathlib.Path(d) / "nested" / "alerts.jsonl"
        n = FileNotifier(path)
        n.alert({"level": "critical", "txid": "abc", "score": 99})
        n.alert({"level": "high", "txid": "def", "score": 70})
        lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["txid"] == "abc"
    assert json.loads(lines[1])["score"] == 70


def test_composite_notifier_isolates_failures():
    seen = []

    class _Boom(Notifier):
        def alert(self, event):
            raise RuntimeError("sink down")

    class _Record(Notifier):
        def alert(self, event):
            seen.append(event["txid"])

    CompositeNotifier([_Boom(), _Record()]).alert({"txid": "t1"})
    # a broken sink must not stop the healthy one.
    assert seen == ["t1"]


def test_console_notifier_no_console_prints(capsys):
    ConsoleNotifier(console=None).alert(
        {"level": "critical", "chain": "btc", "txid": "deadbeef", "score": 88,
         "reasons": ["sanctioned hop"], "recommended_action": "freeze"}
    )
    out = capsys.readouterr().out
    assert "CRITICAL" in out and "freeze" in out


# --------------------------------------------------------------------------- #
# TronProvider — TRC-20 parsing / pagination / success-filtering
# --------------------------------------------------------------------------- #
def _tron_offline():
    # offline=True guarantees _get never touches the network on a cache miss.
    return TronProvider(offline=True)


def test_tron_row_to_tx_parsing():
    row = {
        "transaction_id": "tx1",
        "from_address": "TFrom",
        "to_address": "TTo",
        "quant": "1500000",  # 1.5 USDT (6 decimals)
        "block": 123,
        "block_ts": 1_700_000_000_000,  # ms
    }
    tx = TronProvider._row_to_tx(row)
    assert tx.txid == "tx1"
    assert tx.inputs[0].address == "TFrom" and tx.inputs[0].value == 1_500_000
    assert tx.outputs[0].address == "TTo" and tx.outputs[0].value == 1_500_000
    assert tx.block_time == 1_700_000_000  # ms -> s


def test_tron_row_to_tx_handles_bad_quant_and_ts():
    tx = TronProvider._row_to_tx({"quant": "not-a-number", "block_ts": None})
    assert tx.inputs[0].value == 0 and tx.block_time is None


def test_tron_get_transactions_filters_and_paginates(monkeypatch):
    prov = _tron_offline()
    contract = prov.contract
    page1 = {
        "token_transfers": [
            {"transaction_id": "a", "from_address": "F", "to_address": "T", "quant": "1000000",
             "contract_address": contract, "finalResult": "SUCCESS", "contractRet": "SUCCESS", "block_ts": 1},
            {"transaction_id": "reverted", "from_address": "F", "to_address": "T", "quant": "1000000",
             "contract_address": contract, "finalResult": "REVERT", "block_ts": 1},  # dropped
            {"transaction_id": "wrong-token", "from_address": "F", "to_address": "T", "quant": "1000000",
             "contract_address": "TOtherToken", "block_ts": 1},  # dropped
        ]
    }
    page2 = {
        "token_transfers": [
            {"transaction_id": "b", "from_address": "F", "to_address": "T", "quant": "2000000",
             "contract_address": contract, "block_ts": 2},
        ]
    }
    pages = {0: page1, 3: page2}  # keyed by pagination offset (start += len(rows))

    def fake_get(path, cache_key):
        start = int(path.split("start=")[1].split("&")[0])
        return pages.get(start, {"token_transfers": []})

    monkeypatch.setattr(prov, "_get", fake_get)
    # max_txs=3 makes page1 a "full" page (len(rows)==n), forcing a second fetch;
    # this exercises both the success/contract filtering and the pagination walk.
    txs = prov.get_transactions("Taddr", max_txs=3)
    ids = [t.txid for t in txs]
    assert ids == ["a", "b"]  # reverted + wrong-token filtered out, both pages walked
