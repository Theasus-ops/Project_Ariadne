"""Laundering-pattern detectors over a completed trace (counter-laundering).

These run on the traced graph after taint scoring and surface the two highest-
signal money-laundering shapes:

  * off-ramps  - value arriving at an exchange/service (the cash-out moment that
                 matters to an investigator).
  * peel chains - a "main artery" that repeatedly forwards most of its value to a
                 new address while peeling smaller amounts off to the side, a
                 classic layering technique.
"""

from __future__ import annotations

from ..models import NodeType, TraceResult


def detect_offramps(result: TraceResult) -> list[dict]:
    ramps: list[dict] = []
    for edge in result.edges.values():
        dst = result.nodes.get(edge.dst)
        if dst is None:
            continue
        if dst.node_type == NodeType.SERVICE or dst.label_category == "exchange":
            ramps.append(
                {
                    "from": edge.src,
                    "to": edge.dst,
                    "service": dst.label_name or "unlabeled service",
                    "amount": round(result.asset.to_units(edge.value), 8),
                    "txids": edge.txids,
                }
            )
    ramps.sort(key=lambda r: r["amount"], reverse=True)
    return ramps


def detect_peel_chains(
    result: TraceResult, dominant_ratio: float = 0.6, min_length: int = 3
) -> list[list[str]]:
    out_edges: dict[str, list] = {}
    for edge in result.edges.values():
        out_edges.setdefault(edge.src, []).append(edge)

    def dominant_next(addr: str) -> str | None:
        edges = out_edges.get(addr, [])
        if len(edges) < 2:  # a peel needs a main flow plus at least one peel-off
            return None
        total = sum(e.value for e in edges)
        top = max(edges, key=lambda e: e.value)
        if total > 0 and top.value < total and (top.value / total) >= dominant_ratio:
            return top.dst
        return None

    chains: list[list[str]] = []
    consumed: set[str] = set()
    for start in out_edges:
        if start in consumed:
            continue
        chain = [start]
        current = start
        nxt = dominant_next(current)
        while nxt is not None and nxt not in chain:
            chain.append(nxt)
            current = nxt
            nxt = dominant_next(current)
        if len(chain) >= min_length:
            chains.append(chain)
            consumed.update(chain)
    return chains


def detect_round_trips(result: TraceResult) -> list[dict]:
    """Money that flows **back** toward its origin — a wash / self-laundering signal.

    An edge whose destination is the seed, or an address the trace reached at a
    strictly-shallower depth (i.e. earlier, closer to the source), is value looping
    back rather than moving onward. Round-tripping funds through a chain of one's
    own wallets is a recognised obfuscation and mule-recycling technique.
    """
    trips: list[dict] = []
    seed = result.seed
    for edge in result.edges.values():
        src = result.nodes.get(edge.src)
        dst = result.nodes.get(edge.dst)
        if src is None or dst is None or edge.src == edge.dst:
            continue
        returns_to_seed = edge.dst == seed
        if returns_to_seed or dst.depth < src.depth:
            trips.append(
                {
                    "from": edge.src,
                    "to": edge.dst,
                    "from_depth": src.depth,
                    "to_depth": dst.depth,
                    "amount": round(result.asset.to_units(edge.value), 8),
                    "returns_to_seed": returns_to_seed,
                    "txids": edge.txids[:5],
                }
            )
    trips.sort(key=lambda t: (t["returns_to_seed"], t["amount"]), reverse=True)
    return trips
