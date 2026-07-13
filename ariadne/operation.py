"""Batch investigation — run an "operation" over many suspect wallets.

Feed Ariadne a list of wallets (harvested by an agency's OSINT / collection
pipeline); it investigates each one, writes a per-wallet evidence report, records
everything to the knowledge base, and then CONNECTS the wallets to each other by
the criminal infrastructure they share -- the same exchange cash-out, the same
sanctioned address, the same mixer. Shared infrastructure across wallets is how a
ring gets linked.

Scope: Ariadne is the *analysis* half. Collecting the wallets is the agency's job,
and connections are bounded by attribution data -- it links a wallet to *known*
criminal infrastructure, not to everything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .models import is_valid_address


def infer_chain(address: str) -> str | None:
    a = address.strip()
    if a.startswith("0x") and is_valid_address(a, "usdt"):
        return "usdt"
    for chain in ("trx", "btc", "ltc", "doge", "xmr"):
        if is_valid_address(a, chain):
            return chain
    return None


def read_wallets(path: str | Path) -> list[tuple[str, str | None]]:
    """One address per line; optional ',chain' or ' chain'. '#' comments allowed.

    Comments may be a whole line or trail an entry (``addr  # note``); everything
    from the first ``#`` is stripped. Addresses never contain ``#``, so this is
    safe — and it stops a trailing comment from being mis-read as the chain code,
    which would silently drop an otherwise-valid wallet from the operation.
    """
    out: list[tuple[str, str | None]] = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [p for p in line.replace(",", " ").split() if p]
        addr = parts[0]
        chain = parts[1].lower() if len(parts) > 1 else infer_chain(addr)
        out.append((addr, chain))
    return out


@dataclass
class WalletResult:
    address: str
    chain: str
    ok: bool = True
    risk_level: str = "info"
    risk_score: int = 0
    findings: int = 0
    endpoints: list = field(default_factory=list)   # (address, label, category) reached
    sanctioned: list = field(default_factory=list)
    error: str = ""
    report_path: str = ""


def wallet_result_from_report(address: str, chain: str, report: dict, report_path: str) -> WalletResult:
    brief = report.get("brief", {})
    endpoints = []
    for f in report.get("findings", []):
        if f["type"] == "service" or f.get("category"):
            endpoints.append((f["address"], f.get("label"), f.get("category") or f["type"]))
    sanctioned = [f["address"] for f in report.get("findings", []) if f.get("category") == "sanctioned"]
    return WalletResult(
        address=address,
        chain=chain,
        ok=True,
        risk_level=brief.get("risk_level", "info"),
        risk_score=brief.get("risk_score", 0),
        findings=report.get("summary", {}).get("findings", 0),
        endpoints=endpoints,
        sanctioned=sanctioned,
        report_path=report_path,
    )


def correlate(results: list[WalletResult]) -> dict:
    """Find infrastructure reached by more than one wallet — the links in the ring."""
    reached: dict[str, dict] = {}
    for r in results:
        if not r.ok:
            continue
        for addr, label, cat in r.endpoints:
            slot = reached.setdefault(addr, {"label": label, "category": cat, "wallets": set()})
            slot["wallets"].add(r.address)
    shared = [
        {"endpoint": a, "label": v["label"], "category": v["category"], "wallets": sorted(v["wallets"])}
        for a, v in reached.items()
        if len(v["wallets"]) >= 2
    ]
    shared.sort(key=lambda s: len(s["wallets"]), reverse=True)
    return {"shared_infrastructure": shared}


def write_campaign(name: str, results: list[WalletResult], campaign: dict, outdir: Path) -> Path:
    ok = [r for r in results if r.ok]
    flagged = [r for r in ok if r.risk_level in ("critical", "high")]
    lines = [
        f"# Operation {name} — Ariadne batch investigation",
        "",
        f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}. "
        f"{len(results)} wallet(s) submitted, {len(ok)} investigated, "
        f"**{len(flagged)} flagged critical/high risk**.",
        "",
        "## Wallets by risk",
        "",
        "| Wallet | Chain | Risk | Score | Findings | Report |",
        "|---|---|---|---|---|---|",
    ]
    for r in sorted(ok, key=lambda r: r.risk_score, reverse=True):
        lines.append(
            f"| `{r.address}` | {r.chain} | {r.risk_level.upper()} | {r.risk_score} | "
            f"{r.findings} | {Path(r.report_path).name if r.report_path else '-'} |"
        )

    shared = campaign["shared_infrastructure"]
    lines += ["", "## Shared criminal infrastructure — links between wallets", ""]
    if shared:
        lines.append(
            "These addresses were reached by MORE THAN ONE investigated wallet. Shared cash-out "
            "or obfuscation infrastructure is how a ring is linked:\n"
        )
        for s in shared:
            label = s["label"] or f"unlabelled {s['category']}"
            wallets = ", ".join(f"`{w[:14]}…`" for w in s["wallets"])
            lines.append(f"- **{label}** (`{s['endpoint']}`) — received from {len(s['wallets'])} wallets: {wallets}")
    else:
        lines.append("No shared infrastructure detected across these wallets — they may be independent.")

    errs = [r for r in results if not r.ok]
    if errs:
        lines += ["", "## Skipped / errored", ""]
        for r in errs:
            lines.append(f"- `{r.address}` ({r.chain}): {r.error}")

    path = outdir / f"OPERATION_{name}.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
