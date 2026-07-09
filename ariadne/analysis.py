"""Recommended-action engine for an investigation.

Turns a completed trace's report into concrete, prioritised next steps with the
real addresses, entities, and amounts filled in — so an operator reads "records
request to Binance for the account behind 0x… that received 9,058 USDT", not a
generic "review the cash-outs".
"""

from __future__ import annotations


def recommended_actions(report: dict) -> list[str]:
    findings = report.get("findings", [])
    asset = report.get("asset", "")
    seed = report.get("trace", {}).get("seed", "")
    actions: list[str] = []

    sanctioned = [f for f in findings if f.get("category") == "sanctioned"]
    if sanctioned:
        actions.append(
            f"OFAC exposure — the trace touches sanctioned address {sanctioned[0]['address']}. "
            "Report the exposure and, where within jurisdiction, freeze the funds."
        )

    seed_finding = next((f for f in findings if f["address"] == seed), None)
    if seed_finding and seed_finding.get("category") == "ransomware":
        actions.append(
            "The seed is a ransomware payment wallet — coordinate with the national CERT / Europol "
            "and check the ransomware family (Ransomwhere) for related victims and addresses."
        )
    elif seed_finding and seed_finding.get("category") == "scam":
        actions.append(
            "The seed is a known scam/fraud wallet — collect victim reports and pursue the cash-out "
            "exchanges below for the beneficiary's identity."
        )

    services = sorted(
        (f for f in findings if f["type"] == "service"),
        key=lambda f: f["dirty_received"],
        reverse=True,
    )
    for s in services[:3]:
        name = s.get("label") or "an unidentified high-activity service (probable exchange)"
        actions.append(
            f"Records request (KYC) to {name} for the account behind {s['address']} — "
            f"{s['dirty_received']} {asset} of traced funds arrived there."
        )

    if report.get("mixing_events"):
        actions.append(
            "Funds were passed through a mixer / CoinJoin — correlate deposits and withdrawals by "
            "amount and timing; treat links past this point as probabilistic, not proven."
        )
    if report.get("patterns", {}).get("peel_chains"):
        actions.append("Peel-chain layering detected — follow the main artery to its endpoint address.")

    if not actions:
        actions.append(
            "No high-risk indicators — keep the endpoint addresses under monitoring for follow-on movement."
        )
    actions.append(
        "Preserve this report (it is tamper-evident) as evidence and record the original transaction identifiers."
    )
    return actions
