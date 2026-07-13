"""Reporting (Phase 5).

Produces three artifacts from a completed, taint-scored trace:

  * JSON  - structured evidence file (exact amounts, provenance-friendly).
  * DOT   - Graphviz graph for portable rendering.
  * HTML  - self-contained interactive report (vis-network) for an analyst.

Amounts are formatted using the trace's Asset (BTC / ETH / USDT / ...), so the
same code serves every chain.
"""

from __future__ import annotations

import html as _html
import json
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__
from ..analysis import recommended_actions
from ..core.confidence import assess as assess_confidence
from ..core.patterns import detect_offramps, detect_peel_chains
from ..core.taint_models import METHODOLOGY
from ..core.temporal import from_trace as temporal_from_trace
from ..models import NodeType, TraceResult

_HIGH_RISK_CATEGORIES = {"sanctioned", "ransomware", "darknet", "scam", "mixer"}

_NODE_COLORS = {"seed": "#e63946", "service": "#f4a261", "address": "#a8dadc"}
_CATEGORY_COLORS = {
    "sanctioned": "#9d0208",
    "ransomware": "#d00000",
    "darknet": "#6a040f",
    "scam": "#dc2f02",
    "mixer": "#e85d04",
    "exchange": "#f48c06",
}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def is_flagged(node) -> bool:
    return (
        node.node_type == NodeType.SERVICE
        or node.label_category in _HIGH_RISK_CATEGORIES
        or node.entered_mixer
    )


def narrative(result: TraceResult) -> str:
    """A plain-English executive summary of the trace, for a human reviewer."""
    asset = result.asset
    sym = asset.symbol
    seed_node = result.nodes.get(result.seed)
    seed_label = ""
    if seed_node and seed_node.label_name:
        seed_label = f" (flagged as {seed_node.label_name} — {seed_node.label_category})"
    hops = max((n.depth for n in result.nodes.values()), default=0)
    disbursed = seed_node.dirty_received if seed_node else 0

    services = [n for n in result.nodes.values() if n.node_type == NodeType.SERVICE]
    dirty_to_services = sum(n.dirty_received for n in services)

    parts = [
        f"Ariadne followed {asset.format(disbursed)} {sym} leaving {result.seed}{seed_label} "
        f"across {hops} hop(s), through {len(result.nodes)} address(es) and {len(result.edges)} transfer(s)."
    ]

    if services:
        named = [n.label_name for n in services if n.label_name]
        named_str = f" (including {', '.join(named[:3])})" if named else ""
        biggest = max(services, key=lambda n: n.dirty_received)
        parts.append(
            f"About {asset.format(dirty_to_services)} {sym} reached {len(services)} likely "
            f"cash-out point(s){named_str} — high-activity addresses that are probable exchanges. "
            f"The largest, {biggest.address} ({biggest.tx_count:,} transactions), took in "
            f"{asset.format(biggest.dirty_received)} {sym}."
        )

    techniques = []
    if result.mixing_events:
        techniques.append(f"{len(result.mixing_events)} CoinJoin/mixing break-point(s)")
    peels = detect_peel_chains(result)
    if peels:
        techniques.append(f"{len(peels)} peel chain(s)")
    offramps = detect_offramps(result)
    if offramps:
        techniques.append(f"{len(offramps)} flow(s) straight into a service")
    if techniques:
        parts.append("Laundering behaviour seen: " + "; ".join(techniques) + ".")

    if any(n.label_category == "sanctioned" for n in result.nodes.values()):
        parts.append("ALERT: the money touched an OFAC-sanctioned address.")

    if services:
        parts.append(
            "Recommended next step: request KYC/account records for the cash-out address(es) above — "
            "that is where the trail becomes attributable to a real person."
        )
    else:
        parts.append(
            "The funds have not yet reached an identifiable cash-out point in this trace; "
            "trace deeper or keep the endpoint addresses under monitoring."
        )
    return " ".join(parts)


def _node_color(node) -> str:
    if node.label_category in _CATEGORY_COLORS:
        return _CATEGORY_COLORS[node.label_category]
    return _NODE_COLORS.get(node.node_type.value, "#cccccc")


def build_brief(report: dict) -> dict:
    findings = report.get("findings", [])
    top_findings = sorted(findings, key=lambda f: (f["confidence"]["score"], f["dirty_received"]), reverse=True)[:3]
    risk_level = "low"
    if any(f["category"] in {"sanctioned", "ransomware", "darknet", "scam", "mixer"} for f in findings):
        risk_level = "critical"
    elif any(f["confidence"]["level"] == "high" for f in findings):
        risk_level = "high"
    elif report.get("mixing_events") or report.get("patterns", {}).get("off_ramps") or report.get("patterns", {}).get("peel_chains"):
        risk_level = "medium"

    recommended_next_steps = recommended_actions(report)

    return {
        "risk_level": risk_level,
        "risk_score": max((f["confidence"]["score"] for f in findings), default=0),
        "summary": report.get("summary_text", "Investigation summary unavailable."),
        "priority_findings": [
            {
                "address": f["address"],
                "confidence": f["confidence"]["level"],
                "category": f["category"],
                "dirty_received": f["dirty_received"],
            }
            for f in top_findings
        ],
        "recommended_next_steps": recommended_next_steps,
    }


def _linked_activity(node, result: TraceResult) -> list[str]:
    linked: list[str] = []
    if node.label_name:
        linked.append(f"Attributed label: {node.label_name} ({node.label_category or 'unclassified'})")
    if node.label_category in {"mixer", "exchange", "dex", "bridge", "sanctioned", "ransomware", "darknet", "scam"}:
        linked.append(f"Likely illicit service context: {node.label_category}")
    if node.entered_mixer:
        linked.append("Observed mixer interaction")
    for edge in result.edges.values():
        if edge.src == node.address:
            dst = result.nodes.get(edge.dst)
            if dst is not None and dst.label_name:
                linked.append(f"Outflow to {dst.label_name} ({dst.label_category or 'service'})")
            elif dst is not None and dst.node_type == NodeType.SERVICE:
                linked.append("Connected to a service wallet")
        if edge.dst == node.address:
            src = result.nodes.get(edge.src)
            if src is not None and src.label_name:
                linked.append(f"Inbound from {src.label_name} ({src.label_category or 'source'})")
    return linked[:4]


def _completeness(result: TraceResult) -> dict:
    """How much of the money the trace actually followed vs. pruned/truncated — an
    honest confidence signal. `followed_fraction` is kept-outflow / seen-outflow;
    truncated nodes are non-service addresses stopped at max depth (money likely
    continued past the trace horizon)."""
    cov = result.coverage
    considered = cov.get("considered_out", 0)
    kept = cov.get("kept_out", 0)
    followed = (kept / considered) if considered > 0 else 1.0
    depth = result.params.get("depth", 0)
    truncated = [
        n for n in result.nodes.values()
        if n.node_type == NodeType.ADDRESS and n.depth >= depth and n.address != result.seed
    ]
    services = [n for n in result.nodes.values() if n.node_type == NodeType.SERVICE]
    if followed >= 0.9 and len(truncated) == 0:
        grade = "high"
    elif followed >= 0.6:
        grade = "medium"
    else:
        grade = "low"
    return {
        "followed_fraction": round(followed, 4),
        "value_followed_pct": round(followed * 100, 1),
        "truncated_at_horizon": len(truncated),
        "cash_out_points_reached": len(services),
        "grade": grade,
        "note": (
            "Fraction of the outflow the trace actually followed (the remainder fell below the "
            "min-value threshold or the per-address branch cap). Nodes truncated at the depth "
            "horizon are where funds likely continued past the trace — increase --depth to follow them."
        ),
    }


def build_report(result: TraceResult) -> dict:
    asset = result.asset

    def units(v):
        return round(asset.to_units(v), asset.decimals if asset.decimals <= 8 else 8)

    seed_node = result.nodes.get(result.seed)
    seed_category = seed_node.label_category if seed_node else ""

    findings = []
    for node in result.nodes.values():
        if not is_flagged(node):
            continue
        finding = {
            "address": node.address,
            "type": node.node_type.value,
            "depth": node.depth,
            "activity": node.tx_count,
            "label": node.label_name or None,
            "category": node.label_category or None,
            "source": node.label_source or None,
            "dirty_received": units(node.dirty_received),
            "taint_fraction": round(node.taint_fraction, 4),
            "entered_mixer": node.entered_mixer,
            "confidence": assess_confidence(node, seed_category).as_dict(),
            "linked_activity": _linked_activity(node, result),
        }
        findings.append(finding)
    findings.sort(key=lambda f: (f["confidence"]["score"], f["dirty_received"]), reverse=True)

    report = {
        "tool": "Ariadne",
        "version": __version__,
        "generated_at": _iso(datetime.now(tz=timezone.utc).timestamp()),
        "asset": asset.symbol,
        "trace": {
            "seed": result.seed,
            "direction": result.direction,
            "created_at": _iso(result.created_at),
            "parameters": result.params,
            "taint_model": result.taint_model,
        },
        "methodology": {
            "taint_model": result.taint_model,
            "taint_statement": METHODOLOGY.get(result.taint_model, ""),
        },
        "summary": {
            "addresses": len(result.nodes),
            "flows": len(result.edges),
            "findings": len(findings),
        },
        "summary_text": narrative(result),
        "findings": findings,
        "mixing_events": result.mixing_events,
        "patterns": {
            "off_ramps": detect_offramps(result),
            "peel_chains": detect_peel_chains(result),
        },
        "temporal": temporal_from_trace(result).as_dict(),
        "risk": {},  # populated below (needs the assembled findings/patterns)
        "evidence": {
            "source": "public-ledger-analysis",
            "preservation_note": "Preserve this report with the original transaction identifiers and analyst notes.",
            "chain": asset.symbol,
            "executive_summary": narrative(result),
        },
        "nodes": [
            {
                "address": n.address,
                "type": n.node_type.value,
                "depth": n.depth,
                "activity": n.tx_count,
                "label": n.label_name or None,
                "category": n.label_category or None,
                "taint_fraction": round(n.taint_fraction, 4),
                "dirty_received": units(n.dirty_received),
                "entered_mixer": n.entered_mixer,
            }
            for n in sorted(result.nodes.values(), key=lambda n: (n.depth, -n.dirty_received))
        ],
        "edges": [
            {
                "src": e.src, "dst": e.dst, "amount": units(e.value), "raw": e.value,
                "txids": e.txids, "first_time": e.first_time, "dirty_value": units(e.dirty_value),
            }
            for e in sorted(result.edges.values(), key=lambda e: e.value, reverse=True)
        ],
    }
    report["completeness"] = _completeness(result)
    from ..core.risk import assess_risk
    from ..core.screening import screen
    report["risk"] = assess_risk(report)
    report["screening"] = screen(report).as_dict()
    report["brief"] = build_brief(report)
    return report


def write_json(result: TraceResult, path: Path, report: dict | None = None) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report or build_report(result), indent=2), encoding="utf-8")
    return path


def to_dot(result: TraceResult) -> str:
    asset = result.asset
    lines = [
        "digraph Ariadne {",
        "  rankdir=LR;",
        '  node [style=filled, fontname="Helvetica", shape=box];',
    ]
    for n in result.nodes.values():
        label = n.address[:10]
        if n.label_name:
            label += f"\\n{n.label_name}"
        lines.append(f'  "{n.address}" [label="{label}", fillcolor="{_node_color(n)}"];')
    for e in result.edges.values():
        lines.append(f'  "{e.src}" -> "{e.dst}" [label="{asset.format(e.value)} {asset.symbol}"];')
    lines.append("}")
    return "\n".join(lines)


def write_dot(result: TraceResult, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_dot(result), encoding="utf-8")
    return path


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Ariadne report - %%SEED%%</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
  body { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; margin:0; background:#0f1115; color:#e6e6e6; }
  header { padding:16px 24px; background:#171a21; border-bottom:1px solid #2a2f3a; }
  h1 { margin:0 0 4px; font-size:18px; }
  h3 { margin:0 0 8px; }
  .muted { color:#8a92a6; font-size:13px; }
  .summary { padding:16px 24px; background:#12151c; border-bottom:1px solid #2a2f3a; font-size:15px; line-height:1.6; }
  .summary b { color:#f4a261; }
  .wrap { display:flex; height:68vh; }
  #graph { flex:2; height:100%; }
  .side { flex:1; overflow:auto; padding:16px 20px; border-left:1px solid #2a2f3a; max-width:560px; }
  table { width:100%; border-collapse:collapse; font-size:12px; margin-bottom:16px; }
  th, td { text-align:left; padding:6px 8px; border-bottom:1px solid #2a2f3a; }
  th { color:#8a92a6; font-weight:600; }
  code { color:#a8dadc; word-break:break-all; }
  .badge { padding:1px 8px; border-radius:20px; font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.5px; }
  .badge.confirmed { background:#3a0d12; color:#ff8a94; }
  .badge.high { background:#3a1810; color:#ffb08a; }
  .badge.medium { background:#38300f; color:#f0d488; }
  .badge.low { background:#12303a; color:#8ad4e0; }
  .badge.info { background:#1c2430; color:#8a92a6; }
</style>
</head>
<body>
<header>
  <h1>Ariadne &mdash; %%DIRECTION%% %%ASSET%% trace</h1>
  <div class="muted">Seed <code>%%SEED%%</code> &middot; %%ADDRESSES%% addresses &middot; %%FLOWS%% flows &middot; %%FINDINGS%% findings &middot; generated %%GENERATED%%</div>
</header>
<div class="summary"><b>Summary.</b> %%SUMMARY%%</div>
<div class="wrap">
  <div id="graph"></div>
  <div class="side">
    <h3>Findings</h3>
    <table>
      <thead><tr><th>Address</th><th>Label / type</th><th>Confidence</th><th>Dirty %%ASSET%%</th><th>Taint</th></tr></thead>
      <tbody>%%FINDINGS_ROWS%%</tbody>
    </table>
    <p class="muted">Provenance: every underlying API response is stored with a SHA-256 in the local cache database. Amounts are exact (smallest-unit integer). Taint is an approximation over the traced subgraph.</p>
  </div>
</div>
<script>
  const nodes = new vis.DataSet(%%NODES_JSON%%);
  const edges = new vis.DataSet(%%EDGES_JSON%%);
  new vis.Network(document.getElementById('graph'), {nodes, edges}, {
    physics: { stabilization: true, barnesHut: { gravitationalConstant: -12000, springLength: 150 } },
    nodes: { font: { color: '#e6e6e6', size: 12 } },
    edges: { arrows: 'to', font: { color: '#8a92a6', size: 10, strokeWidth: 0 }, color: { color: '#4a5266' } }
  });
</script>
</body>
</html>
"""


def _html_nodes(result: TraceResult) -> list[dict]:
    asset = result.asset
    out = []
    for n in result.nodes.values():
        title = f"{n.address} | {n.node_type.value} | activity={n.tx_count:,}"
        if n.label_name:
            title += f" | {n.label_name} ({n.label_category})"
        if n.dirty_received:
            title += f" | dirty={asset.format(n.dirty_received)} {asset.symbol}"
        shape = "star" if n.node_type == NodeType.SEED else (
            "square" if n.node_type == NodeType.SERVICE else "dot"
        )
        out.append(
            {
                "id": n.address,
                "label": n.label_name or (n.address[:8] + ".." + n.address[-4:]),
                "title": title,
                "color": _node_color(n),
                "shape": shape,
                "value": max(1, n.dirty_received),
            }
        )
    return out


def _html_edges(result: TraceResult) -> list[dict]:
    asset = result.asset
    return [
        {
            "from": e.src,
            "to": e.dst,
            "label": asset.format(e.value),
            "title": ", ".join(e.txids[:5]),
        }
        for e in result.edges.values()
    ]


def write_html(result: TraceResult, path: Path, report: dict | None = None) -> Path:
    report = report or build_report(result)
    asset = result.asset
    rows = []
    for f in report["findings"]:
        label = _html.escape(f["label"] or f["type"])
        addr = _html.escape(f["address"])
        conf = f["confidence"]["level"]
        rows.append(
            "<tr>"
            f"<td><code>{addr}</code></td>"
            f"<td>{label}</td>"
            f'<td><span class="badge {conf}">{conf}</span></td>'
            f"<td>{f['dirty_received']}</td>"
            f"<td>{int(f['taint_fraction'] * 100)}%</td>"
            "</tr>"
        )

    def safe_json(obj):
        # Escape <, >, & so embedded data can never break out of the <script> tag.
        return (
            json.dumps(obj)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
        )

    html_out = (
        _HTML_TEMPLATE.replace("%%SEED%%", _html.escape(result.seed))
        .replace("%%DIRECTION%%", _html.escape(result.direction))
        .replace("%%ASSET%%", _html.escape(asset.symbol))
        .replace("%%ADDRESSES%%", str(report["summary"]["addresses"]))
        .replace("%%FLOWS%%", str(report["summary"]["flows"]))
        .replace("%%FINDINGS%%", str(report["summary"]["findings"]))
        .replace("%%GENERATED%%", _html.escape(report["generated_at"]))
        .replace("%%SUMMARY%%", _html.escape(report["summary_text"]))
        .replace("%%FINDINGS_ROWS%%", "".join(rows) or '<tr><td colspan="5" class="muted">none</td></tr>')
        .replace("%%NODES_JSON%%", safe_json(_html_nodes(result)))
        .replace("%%EDGES_JSON%%", safe_json(_html_edges(result)))
    )
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_out, encoding="utf-8")
    return path


def write_all(result: TraceResult, outdir: Path, basename: str, report: dict | None = None) -> dict[str, Path]:
    outdir = Path(outdir)
    return {
        "json": write_json(result, outdir / f"{basename}.json", report=report),
        "dot": write_dot(result, outdir / f"{basename}.dot"),
        "html": write_html(result, outdir / f"{basename}.html", report=report),
    }
