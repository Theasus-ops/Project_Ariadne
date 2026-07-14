"""The ground-truth validation corpus — with provenance.

A measured error rate is only as credible as the ground truth it is measured
against. This module records **where that ground truth comes from**, so the numbers
in a validation report are auditable rather than asserted:

* **Landmark cases** — a small set of individually-cited, human-verifiable
  addresses whose classification is a matter of public record (hardcoded ransomware
  wallets, an OFAC-listed address, a darklisted scam address, a well-known clean
  control). These are the anchor an outside reviewer can check by hand.

* **Feed-sourced ground truth** — the *statistical* corpus (see
  :mod:`ariadne.measurement`) samples from authoritative public feeds where
  *membership is the ground truth by definition*: an address on the OFAC SDN list
  **is** sanctioned; an address on the ethereum-lists darklist **is** flagged
  phishing. This module documents those sources and that rationale.

Nothing here is fabricated. Every landmark case is a public, documented address,
and every feed is named with its authority and the basis on which membership
constitutes ground truth.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .models import is_valid_address

_TRUTHS = ("illicit", "legitimate")


@dataclass(frozen=True)
class CorpusCase:
    address: str
    chain: str
    category: str      # sanctioned / ransomware / scam / ... or "legitimate"
    truth: str         # "illicit" | "legitimate"
    source: str        # citation for the classification
    note: str = ""


# Individually-cited, hand-verifiable landmark cases. Conservative on purpose:
# only addresses whose classification is public record and already vetted here.
LANDMARK_CASES: tuple[CorpusCase, ...] = (
    CorpusCase(
        "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw", "btc", "ransomware", "illicit",
        "WannaCry ransomware — one of three hardcoded ransom wallets (May 2017).",
        "Documented by Symantec, US-CERT TA17-132A, and widely reproduced.",
    ),
    CorpusCase(
        "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94", "btc", "ransomware", "illicit",
        "WannaCry ransomware — hardcoded ransom wallet #2 (May 2017).",
        "Hardcoded in the WannaCry binary; public record.",
    ),
    CorpusCase(
        "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn", "btc", "ransomware", "illicit",
        "WannaCry ransomware — hardcoded ransom wallet #3 (May 2017).",
        "Hardcoded in the WannaCry binary; public record.",
    ),
    CorpusCase(
        "123WBUDmSJv4GctdVEz6Qq6z8nXSKrJ4KX", "btc", "sanctioned", "illicit",
        "On the US Treasury OFAC SDN list (Digital Currency Address).",
        "Imported by `ariadne update-intel` from the OFAC SDN feed.",
    ),
    CorpusCase(
        "0x09750ad360fdb7a2ee23669c4503c974d86d8694", "eth", "scam", "illicit",
        "Listed on the ethereum-lists scam / phishing darklist.",
        "Community darklist (MyEtherWallet/ethereum-lists), MIT-licensed.",
    ),
    CorpusCase(
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "eth", "legitimate", "legitimate",
        "Well-known public address (vitalik.eth) — a legitimate control.",
        "Publicly attributed; used as a false-positive control.",
    ),
)


@dataclass(frozen=True)
class FeedSource:
    name: str
    url: str
    provides: str
    ground_truth_basis: str


# Where the statistical corpus's ground truth comes from. Membership in each of
# these is definitional for its category.
FEED_SOURCES: tuple[FeedSource, ...] = (
    FeedSource(
        "US Treasury OFAC SDN", "https://sanctionslist.ofac.treas.gov/",
        "sanctioned digital-currency addresses",
        "An address on the SDN list is sanctioned as a matter of US law.",
    ),
    FeedSource(
        "ethereum-lists darklist", "https://github.com/MyEtherWallet/ethereum-lists",
        "scam / phishing addresses",
        "Community-curated darklist; membership = flagged scam/phishing.",
    ),
    FeedSource(
        "ScamSniffer blacklist", "https://github.com/scamsniffer/scam-database",
        "scam / phishing addresses",
        "Curated scam-address blacklist; membership = flagged scam.",
    ),
    FeedSource(
        "Ransomwhere", "https://ransomwhe.re/",
        "ransomware payment addresses",
        "Crowdsourced, reviewed ransomware payment addresses (CC0).",
    ),
    FeedSource(
        "etherscan-labels", "https://github.com/brianleect/etherscan-labels",
        "named exchange / DeFi / bridge / mixer services (legitimate controls + break-points)",
        "Public Etherscan labels; named services used as legitimate controls.",
    ),
)


def corpus_cases_path() -> Path:
    """The committed, extensible data file of additional cited cases."""
    return Path(__file__).resolve().parent / "data" / "corpus_cases.json"


def load_extra_cases(path: Path | None = None) -> list[CorpusCase]:
    """Cited cases added to the data file (empty if it is missing or malformed).

    Only well-formed entries carrying a source citation are returned — a case
    without provenance is not ground truth.
    """
    p = path or corpus_cases_path()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out: list[CorpusCase] = []
    for e in raw.get("cases", []):
        if not isinstance(e, dict) or not e.get("address") or not e.get("source"):
            continue
        if e.get("truth") not in _TRUTHS:
            continue
        out.append(CorpusCase(
            address=e["address"], chain=e.get("chain", ""), category=e.get("category", ""),
            truth=e["truth"], source=e["source"], note=e.get("note", ""),
        ))
    return out


def load_cases(path: Path | None = None) -> list[CorpusCase]:
    """All ground-truth cases: built-in landmarks + data-file additions, deduped by address."""
    seen: set[str] = set()
    out: list[CorpusCase] = []
    for c in (*LANDMARK_CASES, *load_extra_cases(path)):
        key = c.address.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def add_case(address: str, chain: str, category: str, truth: str, source: str,
             note: str = "", path: Path | None = None) -> CorpusCase:
    """Validate and append a cited case to the data file. Growing ground truth is a
    data change, not a code change — the point of extensibility.

    Rejects a missing source (no provenance = not ground truth), an unknown truth
    value, a malformed address, and a duplicate.
    """
    if not source or not source.strip():
        raise ValueError("a corpus case requires a source citation")
    if truth not in _TRUTHS:
        raise ValueError(f"truth must be one of {_TRUTHS}, got {truth!r}")
    if not is_valid_address(address, chain):
        raise ValueError(f"invalid address for chain {chain!r}: {address}")
    if any(c.address.lower() == address.lower() for c in load_cases(path)):
        raise ValueError(f"address already in the corpus: {address}")

    p = path or corpus_cases_path()
    case = CorpusCase(address=address, chain=chain, category=category, truth=truth,
                      source=source.strip(), note=note.strip())
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        doc = {"cases": []}
    doc.setdefault("cases", []).append({k: v for k, v in asdict(case).items()})
    p.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return case


def summary(path: Path | None = None) -> dict:
    """Counts and provenance for the corpus, for a report header."""
    cases = load_cases(path)
    illicit = [c for c in cases if c.truth == "illicit"]
    legit = [c for c in cases if c.truth == "legitimate"]
    by_cat: dict[str, int] = {}
    for c in cases:
        by_cat[c.category] = by_cat.get(c.category, 0) + 1
    return {
        "landmark_total": len(cases),
        "landmark_illicit": len(illicit),
        "landmark_legitimate": len(legit),
        "landmark_by_category": by_cat,
        "feed_sources": [
            {"name": f.name, "url": f.url, "provides": f.provides, "basis": f.ground_truth_basis}
            for f in FEED_SOURCES
        ],
    }
