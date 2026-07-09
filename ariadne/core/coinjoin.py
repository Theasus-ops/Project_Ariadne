"""CoinJoin detection (counter-laundering).

CoinJoins (Wasabi, Samourai/Whirlpool) merge many users' coins into one
transaction with equal-value outputs, hiding the input->output mapping. Naively
following every output of a CoinJoin both explodes the trace and mis-attributes
funds. Instead we DETECT the CoinJoin, treat it as a mixing break-point, and
record the anonymity-set size (how many equal outputs share the denomination) so
an analyst knows exactly how much uncertainty the mix introduced.

Detection is structural and highly reliable in the literature (>99% for Wasabi,
~100% for Samourai):
  * Whirlpool: exactly 5 inputs and 5 outputs, all outputs equal to a fixed pool
    denomination (0.001 / 0.01 / 0.05 / 0.5 BTC).
  * Wasabi / generic CoinJoin: a large group of equal-valued outputs (the
    anonymity set) backed by many distinct inputs (many participants).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..models import Transaction

# Whirlpool fixed pool denominations, in satoshis.
_WHIRLPOOL_DENOMS = {100_000, 1_000_000, 5_000_000, 50_000_000}

# Minimum size of the equal-output group to call something a CoinJoin.
_MIN_EQUAL_OUTPUTS = 5


class CoinJoinType(str, Enum):
    WHIRLPOOL = "whirlpool"
    WASABI = "wasabi"
    COINJOIN = "coinjoin"


@dataclass
class CoinJoinInfo:
    kind: CoinJoinType
    anonymity_set: int  # number of equal-value outputs sharing the denomination
    denomination: int   # the shared output value (sats)


def _largest_equal_output_group(tx: Transaction) -> tuple[int, int]:
    """Return (value, count) of the most common positive output value."""
    counts = Counter(o.value for o in tx.outputs if o.value > 0)
    if not counts:
        return (0, 0)
    value, count = counts.most_common(1)[0]
    return value, count


def classify(tx: Transaction) -> Optional[CoinJoinInfo]:
    n_in = len(tx.inputs)
    n_out = len(tx.outputs)
    if n_in < 2 or n_out < 3:
        return None

    denom, group = _largest_equal_output_group(tx)

    # Whirlpool: 5x5 at a fixed pool denomination.
    if n_in == 5 and n_out == 5 and group == 5 and denom in _WHIRLPOOL_DENOMS:
        return CoinJoinInfo(CoinJoinType.WHIRLPOOL, anonymity_set=5, denomination=denom)

    # Wasabi 2.0 (WabiSabi): many inputs plus a sizeable equal-output group.
    if n_in >= 20 and group >= _MIN_EQUAL_OUTPUTS:
        return CoinJoinInfo(CoinJoinType.WASABI, anonymity_set=group, denomination=denom)

    # Generic CoinJoin: a substantial equal-output anonymity set backed by at
    # least as many independent inputs (multiple participants).
    if group >= _MIN_EQUAL_OUTPUTS and n_in >= group:
        return CoinJoinInfo(CoinJoinType.COINJOIN, anonymity_set=group, denomination=denom)

    return None


def is_coinjoin(tx: Transaction) -> bool:
    return classify(tx) is not None
