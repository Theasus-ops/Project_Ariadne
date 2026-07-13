"""Address-poisoning and dusting-attack detection.

Address poisoning is one of the highest-loss attacks of the current era (a single
2024 incident drained ~$68M). The mechanics exploit how wallets *display*
addresses — truncated as ``0x1234…5678``:

1. The attacker grinds a **vanity look-alike** address whose first and last few
   characters match an address the victim really transacts with.
2. They **prime** the victim's history with a tiny "dust" or **zero-value** token
   transfer to/from the victim, so the look-alike appears in the transaction list
   next to the genuine counterparty.
3. The victim later copies the address from history — or is fooled by the truncated
   display — and sends real funds to the attacker's look-alike instead.

This module detects that pattern from data Ariadne already holds — counterparties,
transfer values, and directions — so it works on **every** supported chain with no
new data source.

Everything here is pure and deterministic: the detectors take plain records and
return findings, so they are trivially testable offline and carry no chain
dependence.
"""

from __future__ import annotations

from dataclasses import dataclass, field


def compare_form(address: str) -> str:
    """Normalise an address for look-alike comparison.

    EVM ``0x`` addresses are case-insensitive and all share the ``0x`` prefix, so
    we drop it and lowercase — the attacker grinds the *hex*, and the shared ``0x``
    would otherwise inflate every prefix match. Other formats (Bitcoin base58, etc.)
    are case-sensitive and compared as-is.
    """
    a = (address or "").strip()
    if a[:2].lower() == "0x":
        return a[2:].lower()
    return a


def _common_prefix_len(a: str, b: str) -> int:
    n = 0
    for x, y in zip(a, b):  # noqa: B905 - stops at the shorter; that is intended
        if x != y:
            break
        n += 1
    return n


def match_strength(a: str, b: str) -> tuple[int, int]:
    """Return (common-prefix, common-suffix) length of two addresses' compare-forms.

    Longer shared head+tail = a stronger poisoning signal: an attacker must grind
    roughly 16 ** (prefix+suffix) candidate keys to hit an EVM look-alike, so a long
    match is deliberate, not coincidence.
    """
    fa, fb = compare_form(a), compare_form(b)
    pre = _common_prefix_len(fa, fb)
    suf = _common_prefix_len(fa[::-1], fb[::-1])
    return pre, suf


def looks_alike(a: str, b: str, prefix: int = 4, suffix: int = 4) -> bool:
    """True if ``a`` and ``b`` are different addresses that share the first
    ``prefix`` and last ``suffix`` characters of their compare-form — the exact
    confusion a truncated ``0x1234…5678`` display exploits."""
    if not a or not b:
        return False
    fa, fb = compare_form(a), compare_form(b)
    if fa == fb:
        return False  # same address
    if len(fa) < prefix + suffix or len(fb) < prefix + suffix:
        return False
    return fa[:prefix] == fb[:prefix] and fa[-suffix:] == fb[-suffix:]


def is_dust(value: int, threshold: int) -> bool:
    """A transfer is dust if it is zero-value or at/below the dust threshold."""
    return value <= threshold


def _primed(c: "Counterparty", dust_threshold: int) -> bool:
    """Whether a counterparty was primed as a poison: a zero-value transfer, or a
    dust-sized send to the victim to plant itself in the victim's history."""
    return c.zero_value_transfers > 0 or (0 < c.value_to_victim <= dust_threshold)


def lookalike_pairs(addresses, prefix: int = 4, suffix: int = 4) -> list[tuple[str, str, int, int]]:
    """All confusable look-alike pairs in a set of addresses (e.g. a trace graph).

    Returns ``(a, b, matched_prefix, matched_suffix)`` for each pair sharing the
    truncated display, strongest match first. Cheap to run over a trace's nodes to
    warn "two of these addresses look nearly identical — possible poisoning".
    """
    uniq = [a for a in dict.fromkeys(addresses) if a]
    pairs: list[tuple[str, str, int, int]] = []
    for i, a in enumerate(uniq):
        for b in uniq[i + 1:]:
            if looks_alike(a, b, prefix, suffix):
                pre, suf = match_strength(a, b)
                pairs.append((a, b, pre, suf))
    pairs.sort(key=lambda p: p[2] + p[3], reverse=True)
    return pairs


@dataclass
class Counterparty:
    """A victim's counterparty and the value that flowed each way (smallest unit)."""

    address: str
    value_from_victim: int = 0     # real value the victim SENT to this address
    value_to_victim: int = 0       # value this address sent to the victim
    zero_value_transfers: int = 0  # count of zero-value transfers involving the victim


def counterparties_from_txs(victim: str, txs) -> list["Counterparty"]:
    """Build per-counterparty value/priming stats from a victim's transactions.

    Works for both models: for each transaction, value the victim *sent* to an
    address counts as ``value_from_victim``; value the victim *received* counts as
    ``value_to_victim``; a zero-value transfer either way (the classic poisoning
    primer) increments ``zero_value_transfers``.
    """
    cps: dict[str, Counterparty] = {}

    def slot(addr: str) -> Counterparty:
        return cps.setdefault(addr, Counterparty(addr))

    for tx in txs:
        in_addrs = tx.input_addresses()
        victim_sends = victim in in_addrs
        victim_receives = any(o.address == victim for o in tx.outputs)
        if victim_sends:
            for o in tx.outputs:
                if o.address and o.address != victim:
                    c = slot(o.address)
                    c.value_from_victim += o.value
                    if o.value == 0:
                        c.zero_value_transfers += 1
        if victim_receives:
            for i in tx.inputs:
                if i.address and i.address != victim:
                    c = slot(i.address)
                    c.value_to_victim += i.value
                    if i.value == 0:
                        c.zero_value_transfers += 1
    return list(cps.values())


@dataclass
class PoisoningFinding:
    victim: str
    real: str            # the genuine counterparty being impersonated
    lookalike: str       # the poison address impersonating it
    matched_prefix: int
    matched_suffix: int
    primed_with_dust: bool          # the poison appeared via a dust / zero-value transfer
    victim_paid_lookalike: int      # real value the victim sent to the poison (a successful poison)
    severity: str                   # critical | high | medium
    note: str = ""


def detect_address_poisoning(
    victim: str,
    counterparties: list[Counterparty],
    *,
    prefix: int = 4,
    suffix: int = 4,
    dust_threshold: int = 0,
) -> list[PoisoningFinding]:
    """Find look-alike impersonations among a victim's counterparties.

    A finding pairs a *genuine* counterparty (the victim sent it real value) with a
    *look-alike* that shares its truncated display. Severity escalates when the
    look-alike was primed with dust, and to **critical** when the victim actually
    sent real value to the look-alike — i.e. the poisoning worked.
    """
    findings: list[PoisoningFinding] = []
    by_addr = {c.address: c for c in counterparties}
    addrs = [c.address for c in counterparties if c.address and c.address != victim]

    seen: set[frozenset] = set()
    for i, a in enumerate(addrs):
        for b in addrs[i + 1:]:
            if not looks_alike(a, b, prefix, suffix):
                continue
            key = frozenset((a, b))
            if key in seen:
                continue
            seen.add(key)

            ca, cb = by_addr[a], by_addr[b]

            # Orient the pair. The impersonator is the address *primed* with a dust or
            # zero-value transfer — that priming is the attacker's move, and it is the
            # reliable signal (amounts are not: a *successful* poison is paid MORE than
            # the genuine counterparty). If priming doesn't disambiguate, fall back to
            # the more-established real relationship, then to a deterministic tie-break.
            a_primed, b_primed = _primed(ca, dust_threshold), _primed(cb, dust_threshold)
            if a_primed and not b_primed:
                real, poison = cb, ca
            elif b_primed and not a_primed:
                real, poison = ca, cb
            elif ca.value_from_victim != cb.value_from_victim:
                real, poison = (ca, cb) if ca.value_from_victim > cb.value_from_victim else (cb, ca)
            else:
                real, poison = (ca, cb) if ca.address <= cb.address else (cb, ca)

            pre, suf = match_strength(real.address, poison.address)
            primed = _primed(poison, dust_threshold)
            paid = poison.value_from_victim if poison.value_from_victim > dust_threshold else 0

            if paid > 0:
                severity = "critical"
                note = "victim sent real value to the look-alike — poisoning appears to have succeeded"
            elif primed and real.value_from_victim > dust_threshold:
                severity = "high"
                note = "dust-primed look-alike of a genuine counterparty — a poisoning setup"
            else:
                severity = "medium"
                note = "confusable look-alike address pair — verify before sending"

            findings.append(PoisoningFinding(
                victim=victim,
                real=real.address,
                lookalike=poison.address,
                matched_prefix=pre,
                matched_suffix=suf,
                primed_with_dust=primed,
                victim_paid_lookalike=paid,
                severity=severity,
                note=note,
            ))

    order = {"critical": 0, "high": 1, "medium": 2}
    findings.sort(key=lambda f: (order[f.severity], -(f.matched_prefix + f.matched_suffix)))
    return findings


@dataclass
class DustingFinding:
    address: str
    dust_sources: int          # how many distinct addresses sent dust
    dust_transfers: int        # total dust transfers received
    note: str = ""
    sources: list = field(default_factory=list)


def detect_dusting(
    address: str,
    incoming: list[tuple[str, int]],
    *,
    dust_threshold: int,
    min_sources: int = 3,
) -> DustingFinding | None:
    """Flag a dusting attack: many distinct sources sending dust to one address.

    ``incoming`` is a list of ``(source_address, value)`` receipts. A dusting
    campaign sprays tiny amounts from many addresses to de-anonymise a wallet when
    the dust is later consolidated. We flag it when at least ``min_sources`` distinct
    addresses each sent a dust-sized (or zero) amount.
    """
    dust_sources = {src for src, val in incoming if src and is_dust(val, dust_threshold)}
    dust_count = sum(1 for _src, val in incoming if is_dust(val, dust_threshold))
    if len(dust_sources) < min_sources:
        return None
    return DustingFinding(
        address=address,
        dust_sources=len(dust_sources),
        dust_transfers=dust_count,
        sources=sorted(dust_sources),
        note=f"{len(dust_sources)} distinct sources sent dust — possible dusting / de-anonymisation campaign",
    )
