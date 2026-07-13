"""Court-ready expert report — the standardized document an investigator files.

JSON is for machines; a prosecutor needs a structured written report with a named
methodology, the findings and their confidence, the chain of custody, and — non-
negotiable for admissibility — an explicit statement of limitations. This module
renders a completed trace (and, if present, its signed evidence bundle) into a
Markdown expert report laid out the way a forensic examiner's statement is:
scope → methodology → findings → risk → custody → limitations → next steps.

It asserts nothing the engine did not compute, and its Limitations section is a
first-class part of the document, not a footnote — an expert report that hides its
own uncertainty is worse than none.
"""

from __future__ import annotations

from datetime import datetime, timezone


def build_expert_report(report: dict, bundle: dict | None = None, case_ref: str | None = None) -> str:
    trace = report.get("trace", {})
    asset = report.get("asset", "")
    seed = trace.get("seed", "")
    methodology = report.get("methodology", {})
    risk = report.get("risk", {})
    screening = report.get("screening", {})
    temporal = report.get("temporal", {})
    findings = report.get("findings", [])
    patterns = report.get("patterns", {})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    L: list[str] = []
    ap = L.append

    ap("# Blockchain Financial-Investigation Report")
    ap("")
    ap(f"**Tool:** Ariadne v{report.get('version', '?')} &nbsp;|&nbsp; "
       f"**Generated:** {now} &nbsp;|&nbsp; **Asset/Chain:** {asset}")
    if case_ref:
        ap(f"**Case reference:** {case_ref}")
    ap("")
    ap("> This report is generated from public blockchain data by an automated tracing tool. "
       "It is investigative intelligence to guide lawful inquiry, not a determination of guilt. "
       "Confidence grades and the Limitations section below are integral to its interpretation.")
    ap("")

    # 1. Executive summary
    ap("## 1. Executive summary")
    ap("")
    ap(report.get("summary_text", "No summary available."))
    ap("")
    if risk:
        ap(f"**Composite risk:** {risk.get('level', '?').upper()} ({risk.get('score', 0)}/100). "
           f"**Primary typology:** {risk.get('primary_typology') or 'none identified'}.")
        ap("")
    val = report.get("valuation") or {}
    if val.get("seed_disbursed_usd") or val.get("total_cashout_usd"):
        def _f(usd, eur):
            if usd is None:
                return "n/a"
            return f"${usd:,.0f}" + (f" (€{eur:,.0f})" if eur is not None else "")
        ap(f"**Fiat valuation.** Value disbursed by the seed: {_f(val.get('seed_disbursed_usd'), val.get('seed_disbursed_eur'))}; "
           f"value reaching cash-out points: {_f(val.get('total_cashout_usd'), val.get('total_cashout_eur'))}. "
           f"_{val.get('note', '')}_")
        ap("")

    # 2. Subject of examination
    ap("## 2. Subject of examination")
    ap("")
    ap(f"- **Seed address:** `{seed}`")
    ap(f"- **Direction of trace:** {trace.get('direction', 'forward')}")
    params = trace.get("parameters", {})
    ap(f"- **Depth:** {params.get('depth', '?')} hops &nbsp;|&nbsp; "
       f"**Branching cap:** {params.get('max_branch', '?')} &nbsp;|&nbsp; "
       f"**Min. flow:** {params.get('min_value_sats', '?')} (smallest unit)")
    ap(f"- **Addresses reached:** {report.get('summary', {}).get('addresses', 0)} &nbsp;|&nbsp; "
       f"**Value flows:** {report.get('summary', {}).get('flows', 0)}")
    ap("")

    # 3. Methodology
    ap("## 3. Methodology")
    ap("")
    ap(f"- **Taint model:** {methodology.get('taint_model', 'haircut')} — "
       f"{methodology.get('taint_statement', '')}")
    ap("- **Attribution:** addresses are matched against public intelligence feeds "
       "(OFAC sanctions, ransomware, scam/phishing, named exchanges, issuer freezes) and "
       "Ariadne's own derived attributions. An unlabelled high-activity address is treated as a "
       "*lead*, never an offender.")
    ap("- **Data source:** public ledger data retrieved via a blockchain indexer; every response is "
       "cached with its URL, retrieval time, and a SHA-256 digest (see §8, Chain of custody).")
    ap("")

    # 4. Findings
    ap("## 4. Findings")
    ap("")
    if findings:
        ap("| Address | Attribution | Confidence | Dirty " + asset + " | Disposition |")
        ap("|---|---|---|---|---|")
        for f in findings[:25]:
            conf = f.get("confidence", {})
            disp = conf.get("disposition", "")
            ap(f"| `{f['address']}` | {f.get('label') or f.get('type')} | "
               f"{conf.get('level', '').upper()} ({conf.get('score', 0)}) | "
               f"{f.get('dirty_received', 0)} | {disp} |")
    else:
        ap("No flagged findings within the traced window.")
    ap("")

    # 5. Risk & typology
    if risk.get("typologies"):
        ap("## 5. Money-laundering typologies identified")
        ap("")
        for t in risk["typologies"]:
            ap(f"- **{t['name']}** (severity {t['severity']}). {t['description']}")
            for e in t.get("evidence", []):
                ap(f"  - _evidence:_ {e}")
        ap("")

    # 6. Sanctions screening
    if screening:
        ap("## 6. Sanctions / illicit-exposure screening")
        ap("")
        ap(f"**Verdict:** {screening.get('verdict', 'clear').upper().replace('_', ' ')}")
        for r in screening.get("reasons", []):
            ap(f"- {r}")
        if screening.get("nearest_hops") is not None:
            ap(f"- Nearest illicit touchpoint: {screening['nearest_hops']} hop(s); "
               f"exposed traced value: {screening.get('exposed_value', 0)} {asset}.")
        ap("")

    # 6b. Crypto-ATM cash-out with physical locations
    atm_intel = report.get("atm_intel") or []
    if atm_intel:
        ap("## 6b. Crypto-ATM cash-out — physical locations")
        ap("")
        for hit in atm_intel:
            ap(f"Funds reached crypto-ATM operator **{hit['operator']}** "
               f"(`{hit.get('address', '')}`), which runs {hit['machine_count']} known machine(s):")
            for m in hit.get("candidate_locations", [])[:15]:
                where = ", ".join(x for x in (m.get("street"), m.get("city"), m.get("country")) if x) or "location on file"
                ap(f"  - {where} — `{m['lat']:.5f}, {m['lon']:.5f}` ({m['osm_url']})")
            ap(f"  - _{hit['note']}_")
        ap("")

    # 6c. Cross-case links
    xrefs = report.get("cross_references") or []
    if xrefs:
        ap("## 6c. Links to prior investigations")
        ap("")
        ap("Addresses in this trace that also appear in earlier, separately-seeded investigations — "
           "candidate links between cases through shared infrastructure:")
        for x in xrefs[:20]:
            others = "; ".join(f"investigation #{l['investigation_id']} (seed `{l['other_seed']}`)" for l in x["links"][:3])
            ap(f"  - `{x['address']}` — also in {others}")
        ap("")

    # 7. Techniques + behaviour
    techniques = []
    if report.get("mixing_events"):
        techniques.append(f"{len(report['mixing_events'])} CoinJoin/mixing break-point(s)")
    if patterns.get("peel_chains"):
        techniques.append(f"{len(patterns['peel_chains'])} peel chain(s)")
    if patterns.get("off_ramps"):
        techniques.append(f"{len(patterns['off_ramps'])} flow(s) into a service/exchange")
    if techniques or temporal.get("events"):
        ap("## 7. Observed techniques & behaviour")
        ap("")
        if techniques:
            ap("**Laundering techniques:** " + "; ".join(techniques) + ".")
            ap("")
        if temporal.get("events"):
            off = temporal.get("likely_utc_offset")
            tz = f"UTC{'+' if (off or 0) >= 0 else ''}{off} ({temporal.get('region_hint')})" if off is not None else "indeterminate"
            ap(f"**Behavioural profile:** {temporal.get('events')} timestamped movements; "
               f"likely operator timezone {tz} _(probabilistic lead, not proof)_; "
               f"{'bursty' if (temporal.get('burstiness') or 0) > 1 else 'regular'} movement cadence.")
            ap("")

    # 8. Chain of custody
    ap("## 8. Chain of custody & integrity")
    ap("")
    if bundle:
        sig = bundle.get("signature", {})
        ap(f"- **Source records preserved:** {bundle.get('custody_count', 0)} "
           "(each with URL, retrieval timestamp, and SHA-256).")
        ap(f"- **Custody root:** `{bundle.get('custody_root', '')}`")
        ap(f"- **Digital signature:** {sig.get('algorithm', 'ed25519')} — public key "
           f"`{sig.get('public_key', '')}`")
        ap("- **Verification:** run `ariadne verify-evidence <bundle>` to confirm the signature, the "
           "custody root, and that this report is unaltered — offline, with no private key.")
    else:
        ap("- Every underlying API response is stored in the provenance cache with its URL, retrieval "
           "time, and SHA-256. Produce a signed bundle with `ariadne trace … --report` for a sealed, "
           "verifiable evidence package.")
    ap("")

    # 9. Limitations (first-class, non-negotiable)
    ap("## 9. Limitations & scope")
    ap("")
    ap("- Taint is an **address-level** approximation under the stated model, not a UTXO-precise, "
       "courtroom-final figure. Different models yield different attributions **by design**; the model "
       "used here is named in §3.")
    ap("- Attribution coverage is bounded by public feeds; an unlabelled address may still be a "
       "regulated service. Absence of a label is **not** exculpatory.")
    ap("- Behavioural/timezone inference is **probabilistic** and must not be used to locate an "
       "individual.")
    ap("- A `clear` screening verdict means *no illicit touchpoint within the traced window* — it is "
       "**not** a clean-bill of the address.")
    ap("- Findings are investigative leads. Attribution to a real person requires lawful process "
       "(e.g. exchange KYC records) beyond on-chain analysis.")
    comp = report.get("completeness") or {}
    if comp:
        ap(f"- **Trace completeness:** this trace followed {comp.get('value_followed_pct', 0)}% of the "
           f"outflow it observed ({comp.get('grade', '?')} confidence); {comp.get('truncated_at_horizon', 0)} "
           f"node(s) were truncated at the depth horizon, where funds likely continued. Deeper tracing "
           f"may reveal further movement.")
    ap("")

    # 10. Recommended next steps
    steps = (report.get("brief", {}) or {}).get("recommended_next_steps", [])
    if steps:
        ap("## 10. Recommended next steps")
        ap("")
        for s in steps:
            ap(f"1. {s}")
        ap("")

    ap("---")
    ap("_Generated by Ariadne — lawful blockchain financial-crime investigation. "
       "Interpret with §9 (Limitations)._")
    return "\n".join(L)


def write_expert_report(report: dict, path, bundle: dict | None = None, case_ref: str | None = None):
    from pathlib import Path
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_expert_report(report, bundle, case_ref), encoding="utf-8")
    return path
