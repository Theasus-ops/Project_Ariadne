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

from dataclasses import dataclass


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


def summary() -> dict:
    """Counts and provenance for the corpus, for a report header."""
    illicit = [c for c in LANDMARK_CASES if c.truth == "illicit"]
    legit = [c for c in LANDMARK_CASES if c.truth == "legitimate"]
    by_cat: dict[str, int] = {}
    for c in LANDMARK_CASES:
        by_cat[c.category] = by_cat.get(c.category, 0) + 1
    return {
        "landmark_total": len(LANDMARK_CASES),
        "landmark_illicit": len(illicit),
        "landmark_legitimate": len(legit),
        "landmark_by_category": by_cat,
        "feed_sources": [
            {"name": f.name, "url": f.url, "provides": f.provides, "basis": f.ground_truth_basis}
            for f in FEED_SOURCES
        ],
    }
