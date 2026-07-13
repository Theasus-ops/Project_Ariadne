"""Multi-seed investigation — reason over a whole operation, not one address.

A real case has *many* suspect addresses. Tracing them one at a time misses the
point: the intelligence is in what they **share** — the same cash-out exchange, the
same mixer, the same intermediary wallet. This module traces many seeds into one
combined money-flow graph and surfaces that structure:

  * **shared infrastructure** — addresses reached from two or more seeds (the links
    that bind separate suspects into one ring);
  * **hubs** — high-betweenness brokers every flow routes through;
  * **communities** — densely-connected clusters that are candidate sub-rings.

It reuses the single-address tracer and the pure-Python graph analytics unchanged;
the only new thing is the merge and the cross-seed reachability.
"""

from __future__ import annotations

from ..models import TraceResult
from .graph import MoneyGraph


def merge_results(results: list[TraceResult]) -> TraceResult:
    """Fold several traces into one combined graph (min-depth node, summed edges)."""
    if not results:
        return TraceResult(seed="", direction="forward")
    merged = TraceResult(seed=results[0].seed, direction="forward", asset=results[0].asset)
    for r in results:
        for n in r.nodes.values():
            merged.add_node(n)
        for e in r.edges.values():
            me = merged.edge(e.src, e.dst)
            me.value += e.value
            me.txids.extend(e.txids)
            me.observe_time(e.first_time)
        merged.mixing_events.extend(r.mixing_events)
    return merged


def shared_infrastructure(results: list[TraceResult], labels=None) -> list[dict]:
    """Addresses reached from two or more distinct seeds — the ring's links."""
    seeds = {r.seed for r in results}
    reached: dict[str, set] = {}
    for r in results:
        for addr in r.nodes:
            if addr == r.seed:
                continue
            reached.setdefault(addr, set()).add(r.seed)
    out = []
    for addr, srcs in reached.items():
        if addr in seeds or len(srcs) < 2:
            continue
        lab = labels.get(addr) if labels else None
        out.append({
            "address": addr,
            "reached_from": sorted(srcs),
            "seed_count": len(srcs),
            "label": lab.name if lab else None,
            "category": lab.category.value if lab else None,
        })
    out.sort(key=lambda s: s["seed_count"], reverse=True)
    return out


def analyse(results: list[TraceResult], labels=None, top: int = 10) -> dict:
    """Combined-graph analytics over a multi-seed investigation."""
    merged = merge_results(results)
    node_labels = {n.address: (n.label_name or n.label_category or "") for n in merged.nodes.values() if n.label_name or n.label_category}
    graph = MoneyGraph.from_edges(
        [(e.src, e.dst, e.value) for e in merged.edges.values()], labels=node_labels
    )
    return {
        "merged": merged,
        "graph": graph,
        "summary": graph.summary(),
        "shared_infrastructure": shared_infrastructure(results, labels),
        "hubs": graph.hubs(top),
        "communities": graph.communities(min_size=3)[:top],
    }


def build_dossier(name: str, seed_rows: list[dict], analysis: dict, asset: str = "") -> str:
    """A plain-text/Markdown investigation dossier over all seeds."""
    L: list[str] = []
    ap = L.append
    s = analysis["summary"]
    ap(f"# Operation {name} — multi-seed investigation dossier")
    ap("")
    ap(f"{len(seed_rows)} seed(s) traced into one combined graph of "
       f"{s['nodes']} address(es) and {s['edges']} flow(s), in {s['components']} component(s).")
    ap("")
    ap("## Seeds")
    ap("")
    ap("| Seed | Chain | Risk | Findings | Cash-outs |")
    ap("|---|---|---|---|---|")
    for r in seed_rows:
        ap(f"| `{r['seed']}` | {r['chain']} | {r.get('risk', '?')} | {r.get('findings', 0)} | {r.get('cash_outs', 0)} |")
    ap("")

    shared = analysis["shared_infrastructure"]
    ap("## Shared infrastructure — links between seeds")
    ap("")
    if shared:
        ap("Addresses reached from **more than one** seed. Shared cash-out / obfuscation "
           "infrastructure is how separate suspects are bound into one ring:")
        ap("")
        for x in shared[:25]:
            label = x["label"] or (x["category"] or "unlabelled")
            ap(f"- **{label}** (`{x['address']}`) — reached from {x['seed_count']} seeds")
    else:
        ap("No shared infrastructure across the seeds in this trace — they may be independent.")
    ap("")

    hubs = analysis["hubs"]
    if hubs and hubs[0]["betweenness"] > 0:
        ap("## Central hubs (brokers by betweenness)")
        ap("")
        for h in hubs:
            if h["betweenness"] <= 0:
                continue
            ap(f"- `{h['address']}`{(' — ' + h['label']) if h.get('label') else ''} "
               f"(betweenness {h['betweenness']}, in {h['degree_in']} / out {h['degree_out']})")
        ap("")

    comms = analysis["communities"]
    if comms:
        ap("## Candidate sub-rings (communities)")
        ap("")
        for c in comms:
            labs = f" [{', '.join(c['labels'])}]" if c.get("labels") else ""
            ap(f"- {c['size']} members, {c['internal_edges']} internal flows{labs}")
        ap("")

    ap("---")
    ap("_Generated by Ariadne. Interpret with each seed's own graded findings and limitations._")
    return "\n".join(L)
