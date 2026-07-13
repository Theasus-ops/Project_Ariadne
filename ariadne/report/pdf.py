"""Court-ready PDF expert report.

A prosecutor files a paginated, headed PDF — not a Markdown file. This renders a
completed trace into that document: title, methodology, a findings table, risk and
sanctions sections, the chain of custody, and — first-class — the limitations.

PDF generation is an **optional** capability: it uses the pure-Python ``fpdf2``
library (no system dependencies). If it is not installed, the caller falls back to
the Markdown expert report and says so, rather than failing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

# ASCII fold for the PDF core fonts (latin-1), so unicode never corrupts a page.
_FOLD = {
    "—": "-", "–": "-", "≈": "~", "→": "->", "×": "x", "·": "-", "…": "...",
    "“": '"', "”": '"', "’": "'", "‘": "'", "•": "-", "σ": "sd", "€": "EUR ",
    "≥": ">=", "≤": "<=", "✓": "[ok]", "►": ">", "📍": "", "⚠": "!",
}


def _ascii(text) -> str:
    s = str(text)
    for k, v in _FOLD.items():
        s = s.replace(k, v)
    return s.encode("latin-1", "replace").decode("latin-1")


def available() -> bool:
    try:
        import fpdf  # noqa: F401
        return True
    except Exception:
        return False


def write_expert_pdf(report: dict, path, bundle: dict | None = None, case_ref: str | None = None) -> Path:
    from fpdf import FPDF

    trace = report.get("trace", {})
    asset = report.get("asset", "")
    risk = report.get("risk", {})
    screening = report.get("screening", {})
    val = report.get("valuation") or {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    class PDF(FPDF):
        def header(self):
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(120)
            half = self.epw / 2
            self.cell(half, 6, _ascii(f"Ariadne v{report.get('version', '?')} - Investigation Report"), align="L")
            self.cell(half, 6, _ascii(now), align="R", new_x="LMARGIN", new_y="NEXT")
            self.set_draw_color(210)
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.ln(3)
            self.set_text_color(0)

        def footer(self):
            self.set_y(-12)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(120)
            self.cell(0, 8, _ascii(f"Page {self.page_no()}/{{nb}}  -  interpret with Section: Limitations"),
                      align="C")

    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    def heading(txt):
        pdf.ln(2)
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(20, 40, 80)
        pdf.multi_cell(pdf.epw, 6, _ascii(txt))
        pdf.set_text_color(0)
        pdf.set_font("Helvetica", size=10)

    def body(txt):
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", size=10)
        pdf.multi_cell(pdf.epw, 5, _ascii(txt))

    def bullet(txt):
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", size=10)
        pdf.multi_cell(pdf.epw, 5, _ascii("  - " + txt))

    # Title
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 17)
    pdf.multi_cell(pdf.epw, 9, "Blockchain Financial-Investigation Report")
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", size=9)
    pdf.set_text_color(90)
    meta = f"Asset/Chain: {asset}    Seed: {trace.get('seed', '')}"
    if case_ref:
        meta += f"    Case: {case_ref}"
    pdf.multi_cell(pdf.epw, 5, _ascii(meta))
    pdf.set_text_color(0)
    pdf.ln(1)
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_fill_color(245, 245, 235)
    pdf.multi_cell(pdf.epw, 5, _ascii(
        "This report is generated from public blockchain data by an automated tracing tool. It is "
        "investigative intelligence to guide lawful inquiry, not a determination of guilt. Confidence "
        "grades and the Limitations section are integral to its interpretation."), fill=True)

    # 1. Executive summary
    heading("1. Executive summary")
    body(report.get("summary_text", "No summary available."))
    if risk:
        body(f"Composite risk: {risk.get('level', '?').upper()} ({risk.get('score', 0)}/100). "
             f"Primary typology: {risk.get('primary_typology') or 'none identified'}.")
    if val.get("seed_disbursed_usd") or val.get("total_cashout_usd"):
        def f(u, e):
            return "n/a" if u is None else (f"${u:,.0f}" + (f" (EUR {e:,.0f})" if e is not None else ""))
        body(f"Fiat valuation: value disbursed by the seed {f(val.get('seed_disbursed_usd'), val.get('seed_disbursed_eur'))}; "
             f"reaching cash-outs {f(val.get('total_cashout_usd'), val.get('total_cashout_eur'))}.")

    # 2. Subject
    heading("2. Subject of examination")
    p = trace.get("parameters", {})
    bullet(f"Seed address: {trace.get('seed', '')}")
    bullet(f"Direction: {trace.get('direction', 'forward')}    Taint model: {trace.get('taint_model', 'haircut')}")
    bullet(f"Depth: {p.get('depth', '?')} hops    Branch cap: {p.get('max_branch', '?')}")
    bullet(f"Addresses reached: {report.get('summary', {}).get('addresses', 0)}    "
           f"Value flows: {report.get('summary', {}).get('flows', 0)}")

    # 3. Methodology
    heading("3. Methodology")
    body(f"Taint model: {report.get('methodology', {}).get('taint_statement', '')}")
    body("Attribution matched against public feeds (OFAC sanctions, ransomware, scam/phishing, named "
         "exchanges, issuer freezes) and Ariadne's derived attributions. An unlabelled high-activity "
         "address is a lead, never an offender.")

    # 4. Findings
    heading("4. Findings")
    findings = report.get("findings", [])
    if findings:
        with pdf.table(col_widths=(34, 26, 18, 16, 46), text_align="LEFT", first_row_as_headings=True,
                       line_height=5) as table:
            table.row(["Address", "Attribution", "Confidence", f"Dirty {asset}", "Disposition"])
            for fnd in findings[:25]:
                conf = fnd.get("confidence", {})
                addr = fnd["address"]
                table.row([
                    _ascii(addr[:10] + ".." + addr[-6:] if len(addr) > 20 else addr),
                    _ascii((fnd.get("label") or fnd.get("type") or "")[:22]),
                    _ascii(f"{conf.get('level', '').upper()} ({conf.get('score', 0)})"),
                    _ascii(str(fnd.get("dirty_received", 0))),
                    _ascii((conf.get("disposition", "") or "")[:80]),
                ])
    else:
        body("No flagged findings within the traced window.")

    # 5. Typologies
    if risk.get("typologies"):
        heading("5. Money-laundering typologies identified")
        for tp in risk["typologies"]:
            body(f"- {tp['name']} (severity {tp['severity']}). {tp['description']}")

    # 6. Sanctions screening
    if screening:
        heading("6. Sanctions / illicit-exposure screening")
        body(f"Verdict: {screening.get('verdict', 'clear').upper().replace('_', ' ')}")
        for r in screening.get("reasons", []):
            bullet(r)

    # 7. Chain of custody
    heading("7. Chain of custody & integrity")
    if bundle:
        sig = bundle.get("signature", {})
        bullet(f"Source records preserved: {bundle.get('custody_count', 0)} (URL + timestamp + SHA-256 each).")
        bullet(f"Custody root: {bundle.get('custody_root', '')}")
        bullet(f"Signature: {sig.get('algorithm', 'ed25519')} - public key {sig.get('public_key', '')}")
        bullet("Verify with `ariadne verify-evidence`; re-derive offline with `ariadne replay`.")
    else:
        bullet("Every API response is preserved in the provenance cache with URL, time, and SHA-256. "
               "Produce a signed bundle with `trace --report`.")

    # 8. Limitations
    heading("8. Limitations & scope")
    for lim in (
        "Taint is an address-level approximation under the stated model, not a UTXO-precise figure; "
        "different models yield different attributions by design.",
        "Attribution coverage is bounded by public feeds; absence of a label is not exculpatory.",
        "Behavioural / timezone inference is probabilistic and must not be used to locate an individual.",
        "A 'clear' screening verdict means no illicit touchpoint within the traced window - not a clean bill.",
        "Findings are investigative leads; attribution to a person requires lawful process (e.g. exchange KYC).",
    ):
        bullet(lim)
    comp = report.get("completeness") or {}
    if comp:
        bullet(f"Trace completeness: followed {comp.get('value_followed_pct', 0)}% of observed outflow "
               f"({comp.get('grade', '?')} confidence); {comp.get('truncated_at_horizon', 0)} node(s) truncated.")

    # 9. Next steps
    steps = (report.get("brief", {}) or {}).get("recommended_next_steps", [])
    if steps:
        heading("9. Recommended next steps")
        for s in steps:
            bullet(s)

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(path))
    return path
