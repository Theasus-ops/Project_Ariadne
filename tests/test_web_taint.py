"""The web trace endpoint's taint-model resolution.

Locks the gap fix: output-level (utxo-*) models must be usable from the web
console on UTXO chains (with transaction collection enabled) and must gracefully
downgrade — never silently mis-apply — on account chains or backward traces.
"""

from ariadne.web.app import resolve_taint_model


def test_utxo_model_enabled_on_btc_forward():
    model, collect = resolve_taint_model("utxo-fifo", "btc", "forward")
    assert model == "utxo-fifo" and collect is True


def test_utxo_model_downgrades_on_account_chain():
    # account chains have no UTXOs -> fall back to the address-level equivalent.
    model, collect = resolve_taint_model("utxo-fifo", "usdt", "forward")
    assert model == "fifo" and collect is False
    assert resolve_taint_model("utxo-haircut", "trx", "forward") == ("haircut", False)


def test_utxo_model_downgrades_on_backward_trace():
    model, collect = resolve_taint_model("utxo-poison", "btc", "backward")
    assert model == "poison" and collect is False


def test_address_level_models_pass_through():
    assert resolve_taint_model("haircut", "btc", "forward") == ("haircut", False)
    assert resolve_taint_model("fifo", "usdt", "forward") == ("fifo", False)


def test_unknown_or_missing_model_defaults_to_haircut():
    assert resolve_taint_model(None, "btc", "forward") == ("haircut", False)
    assert resolve_taint_model("bogus", "btc", "forward") == ("haircut", False)
    assert resolve_taint_model("UTXO-FIFO", "btc", "forward")[0] == "utxo-fifo"  # case-insensitive
