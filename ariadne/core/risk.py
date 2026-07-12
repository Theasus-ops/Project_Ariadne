"""Money-laundering typology classification + composite risk — explainable.

Investigators think in *typologies*, not raw scores: "ransomware cash-out",
"sanctions exposure", "mixing/layering", "peel-chain layering". This module maps a
completed trace onto the recognised crypto-laundering typologies (aligned with FATF
red-flag guidance) and folds them into a single graded risk — but never as a black
box. Every typology carries its on-chain evidence, and the composite score lists
exactly which factors drove it, so a reviewer can audit the reasoning.

The composite is deliberately bounded and conservative: attribution-backed findings
dominate, structural laundering signals add to the picture, and an exchange that
merely received traced funds is a *lead*, never an accusation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_LEVELS = [(85, "critical"), (65, "high"), (40, "elevated"), (20, "low"), (0, "minimal")]


@dataclass
class Typology:
    id: str
    name: str
    description: str
    severity: int
    evidence: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "description": self.description,
            "severity": self.severity, "evidence": self.evidence,
        }


def _categories(report: dict) -> set[str]:
    cats = {n.get("category") for n in report.get("nodes", []) if n.get("category")}
    cats |= {f.get("category") for f in report.get("findings", []) if f.get("category")}
    return cats


def _seed_category(report: dict) -> str:
    seed = report.get("trace", {}).get("seed", "")
    for f in report.get("findings", []):
        if f.get("address") == seed:
            return f.get("category") or ""
    return ""


def classify(report: dict) -> list[Typology]:
    """Return the money-laundering typologies matched by this trace."""
    typ: list[Typology] = []
    cats = _categories(report)
    seed_cat = _seed_category(report)
    patterns = report.get("patterns", {})
    services = [n for n in report.get("nodes", []) if n.get("type") == "service"]
    mixing = report.get("mixing_events", [])

    if "sanctioned" in cats:
        who = next((f["address"] for f in report.get("findings", []) if f.get("category") == "sanctioned"), "")
        typ.append(Typology(
            "sanctions_exposure", "Sanctions exposure",
            "The traced value touches an OFAC-sanctioned address — a strict-liability exposure.",
            100, [f"sanctioned address in the flow: {who}"]))

    if "frozen" in cats:
        typ.append(Typology(
            "issuer_freeze", "Stablecoin issuer freeze",
            "The flow touches an address frozen/blacklisted by the token issuer.",
            90, ["frozen/blacklisted address in the flow"]))

    if seed_cat == "ransomware" and services:
        typ.append(Typology(
            "ransomware_cashout", "Ransomware cash-out",
            "Ransom-payment wallet whose funds reach a cash-out point.",
            88, [f"seed is a ransomware wallet; {len(services)} cash-out point(s) reached"]))

    if seed_cat == "scam":
        typ.append(Typology(
            "scam_proceeds", "Fraud / scam proceeds movement",
            "Known scam/fraud wallet moving proceeds toward a cash-out.",
            82, ["seed is a known scam/phishing wallet"]))

    if mixing or "mixer" in cats:
        n = len(mixing)
        ev = [f"{n} CoinJoin/mixing break-point(s)"] if n else ["mixer counterparty in the flow"]
        typ.append(Typology(
            "mixing_layering", "Mixing / obfuscation layering",
            "Funds routed through a mixer or CoinJoin to break the trail.",
            70, ev))

    peels = patterns.get("peel_chains") or []
    if peels:
        typ.append(Typology(
            "peel_chain_layering", "Peel-chain layering",
            "A main artery repeatedly peels small amounts while forwarding the bulk — classic layering.",
            60, [f"{len(peels)} peel chain(s) detected"]))

    if {"bridge", "dex"} & cats:
        typ.append(Typology(
            "cross_chain_layering", "Cross-chain / swap layering",
            "Value routed through a bridge or DEX, a chain/asset hop that breaks single-chain tracing.",
            58, [f"{sorted({c for c in cats if c in {'bridge', 'dex'}})} in the flow"]))

    offramps = patterns.get("off_ramps") or []
    if offramps and not any(t.id in ("mixing_layering", "peel_chain_layering") for t in typ):
        typ.append(Typology(
            "direct_offramp", "Direct off-ramp",
            "Funds move to an exchange with little layering — a straightforward cash-out to subpoena.",
            45, [f"{len(offramps)} flow(s) into a service/exchange"]))

    typ.sort(key=lambda t: t.severity, reverse=True)
    return typ


def assess_risk(report: dict) -> dict:
    """Composite, explainable risk grade for the whole investigation."""
    factors: list[str] = []
    findings = report.get("findings", [])

    # Attribution-backed findings dominate the score.
    top_finding = max((f["confidence"]["score"] for f in findings), default=0)
    if top_finding:
        lead = max(findings, key=lambda f: f["confidence"]["score"])
        factors.append(f"top finding graded {lead['confidence']['level'].upper()} "
                       f"({lead['confidence']['score']}) on {lead['address']}")

    typologies = classify(report)
    typ_component = max((t.severity for t in typologies), default=0)
    for t in typologies[:3]:
        factors.append(f"typology: {t.name} (severity {t.severity})")

    # Structural add-ons (bounded), so a heavily-layered trace scores above a plain one.
    structural = 0
    if report.get("mixing_events"):
        structural += 8
    if (report.get("patterns", {}).get("peel_chains")):
        structural += 6
    if len([n for n in report.get("nodes", []) if n.get("type") == "service"]) >= 2:
        structural += 4
        factors.append("multiple distinct cash-out points")

    score = min(100, max(top_finding, typ_component) + structural)
    level = next(name for threshold, name in _LEVELS if score >= threshold)

    return {
        "score": score,
        "level": level,
        "typologies": [t.as_dict() for t in typologies],
        "primary_typology": typologies[0].name if typologies else None,
        "factors": factors,
    }
