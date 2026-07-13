"""Graph interoperability — export a trace to the formats real analysts use.

Investigators live in link-analysis tools (Maltego, i2 Analyst's Notebook, Gephi).
A JSON report doesn't drop into those; a **GraphML** or **CSV edge/node list** does.
This module serialises a completed trace (or any node/edge set) to both, preserving
the forensic attributes — node type, attribution, taint, dirty value; edge value and
the transaction IDs backing it — so the graph carries its evidence into the other tool.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

from ..models import TraceResult

_NODE_KEYS = [
    ("d_type", "type", "string"), ("d_label", "label", "string"),
    ("d_category", "category", "string"), ("d_depth", "depth", "int"),
    ("d_taint", "taint_fraction", "double"), ("d_dirty", "dirty_received", "double"),
    ("d_activity", "tx_count", "int"),
]
_EDGE_KEYS = [
    ("e_value", "value", "double"), ("e_txids", "txids", "string"),
]


def to_graphml(result: TraceResult) -> str:
    asset = result.asset
    out = io.StringIO()
    out.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    out.write('<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n')
    for kid, name, typ in _NODE_KEYS:
        out.write(f'  <key id="{kid}" for="node" attr.name="{name}" attr.type="{typ}"/>\n')
    for kid, name, typ in _EDGE_KEYS:
        out.write(f'  <key id="{kid}" for="edge" attr.name="{name}" attr.type="{typ}"/>\n')
    out.write('  <graph edgedefault="directed">\n')
    for n in result.nodes.values():
        out.write(f'    <node id={quoteattr(n.address)}>\n')
        vals = {
            "d_type": n.node_type.value, "d_label": n.label_name or "",
            "d_category": n.label_category or "", "d_depth": n.depth,
            "d_taint": round(n.taint_fraction, 6), "d_dirty": asset.to_units(n.dirty_received),
            "d_activity": n.tx_count,
        }
        for kid, _, _ in _NODE_KEYS:
            out.write(f'      <data key="{kid}">{escape(str(vals[kid]))}</data>\n')
        out.write("    </node>\n")
    for i, e in enumerate(result.edges.values()):
        out.write(f'    <edge id="e{i}" source={quoteattr(e.src)} target={quoteattr(e.dst)}>\n')
        out.write(f'      <data key="e_value">{asset.to_units(e.value)}</data>\n')
        out.write(f'      <data key="e_txids">{escape(",".join(e.txids[:20]))}</data>\n')
        out.write("    </edge>\n")
    out.write("  </graph>\n</graphml>\n")
    return out.getvalue()


def to_csv_nodes(result: TraceResult) -> str:
    asset = result.asset
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["address", "type", "label", "category", "depth", "taint_fraction", "dirty_received", "tx_count"])
    for n in result.nodes.values():
        w.writerow([n.address, n.node_type.value, n.label_name, n.label_category, n.depth,
                    round(n.taint_fraction, 6), asset.to_units(n.dirty_received), n.tx_count])
    return buf.getvalue()


def to_csv_edges(result: TraceResult) -> str:
    asset = result.asset
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["src", "dst", "value", "first_time", "txids"])
    for e in result.edges.values():
        w.writerow([e.src, e.dst, asset.to_units(e.value), e.first_time or "", " ".join(e.txids[:20])])
    return buf.getvalue()


def write_exports(result: TraceResult, outdir: Path, basename: str) -> dict[str, Path]:
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    paths = {
        "graphml": outdir / f"{basename}.graphml",
        "nodes_csv": outdir / f"{basename}.nodes.csv",
        "edges_csv": outdir / f"{basename}.edges.csv",
    }
    paths["graphml"].write_text(to_graphml(result), encoding="utf-8")
    paths["nodes_csv"].write_text(to_csv_nodes(result), encoding="utf-8")
    paths["edges_csv"].write_text(to_csv_edges(result), encoding="utf-8")
    return paths
