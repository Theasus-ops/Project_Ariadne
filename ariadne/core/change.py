"""Change-address identification — the second pillar of entity clustering.

Common-input-ownership finds wallets an actor *co-spends*. But a careful operator
who never co-spends still leaks ownership through **change**: when a wallet makes a
payment, the leftover returns to a fresh address it controls. Identifying that
change output links it to the spender's cluster without any co-spend.

Two classic, self-contained heuristics (no extra network calls), applied only when
they agree well enough to be safe:

  * **Round-payment.** Humans and merchants request round amounts (0.5, 100 USDT);
    the change is the unrounded remainder. The output with far fewer trailing
    zeros in its smallest-unit value is the change.
  * **Unnecessary-input / bound.** A change output cannot exceed the total inputs,
    and in a standard two-output spend exactly one output is the payment and one is
    change.

Guardrails mirror the clusterer's: never treat a CoinJoin as having identifiable
change, and never absorb a labelled service/exchange output as change.
"""

from __future__ import annotations

from ..models import Transaction, TxOutput


def trailing_zeros(value: int) -> int:
    """Number of trailing zero digits of a positive integer (roundness proxy)."""
    if value <= 0:
        return 0
    z = 0
    while value % 10 == 0:
        z += 1
        value //= 10
    return z


def identify_change(
    tx: Transaction,
    spender_addrs: set[str],
    is_service=None,
    min_zero_gap: int = 3,
) -> TxOutput | None:
    """Return the output most likely to be the spender's change, or None.

    ``is_service(addr) -> bool`` (optional) vetoes a candidate that is a known
    service. ``min_zero_gap`` is how much rounder the payment must be than the
    change for the call to be considered safe.
    """
    # Standard change detection only makes sense for a two-output spend.
    outs = [o for o in tx.outputs if o.address]
    if len(outs) != 2:
        return None
    if not any(a in spender_addrs for a in tx.input_addresses()):
        return None

    a, b = outs
    # Neither candidate may be a labelled service (change is self-owned).
    if is_service is not None and (is_service(a.address) or is_service(b.address)):
        return None
    # A change output cannot exceed the funds the spender put in.
    total_in = sum(i.value for i in tx.inputs) or 0

    za, zb = trailing_zeros(a.value), trailing_zeros(b.value)
    if abs(za - zb) < min_zero_gap:
        return None  # neither is clearly the round payment — too ambiguous to call
    change = a if za < zb else b  # fewer trailing zeros = the unrounded change
    payment = b if change is a else a

    # Sanity: the "payment" should be the rounder one and both within input bounds.
    if total_in and (change.value > total_in or payment.value > total_in):
        return None
    # Change addresses are typically fresh, not one of the spender's inputs.
    if change.address in spender_addrs:
        return None
    return change
