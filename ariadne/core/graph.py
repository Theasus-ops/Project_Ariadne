"""Graph analytics over the accumulated money-flow network — the "intelligence".

A single trace answers one question. An intelligence program asks structural ones
across *everything it has seen*: which entity sits at the centre of the flows?
Which addresses form a tightly-connected ring? Is there a path of money between
this scam wallet and that suspect? Ariadne accumulates every observed flow in the
knowledge base; this module turns that into a queryable directed graph and runs
the classic link-analysis algorithms on it.

Everything is pure Python (no Neo4j / networkx dependency) so the tool stays
auditable and self-contained — these are standard, non-cryptographic algorithms
that are entirely appropriate to implement directly:

  * **shortest_path** — fewest-hop directed path between two entities (BFS), or the
    max-value path when weighted; answers "connect A to B".
  * **degree_centrality / betweenness_centrality** — who is the hub. Betweenness
    uses Brandes' algorithm; a high-betweenness node is a broker every flow routes
    through (a laundering nexus / shared cash-out).
  * **communities** — weakly-connected components plus label-propagation refinement;
    a dense community of addresses is a candidate ring.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class MoneyGraph:
    adj: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(dict))
    radj: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(dict))
    nodes: set[str] = field(default_factory=set)
    labels: dict[str, str] = field(default_factory=dict)

    # ---- construction ----
    def add_edge(self, src: str, dst: str, weight: int = 1) -> None:
        self.nodes.add(src)
        self.nodes.add(dst)
        self.adj[src][dst] = self.adj[src].get(dst, 0) + weight
        self.radj[dst][src] = self.radj[dst].get(src, 0) + weight

    @classmethod
    def from_edges(cls, edges, labels: dict | None = None) -> "MoneyGraph":
        g = cls()
        for e in edges:
            if isinstance(e, dict):
                g.add_edge(e["src"], e["dst"], int(e.get("total_value") or e.get("weight") or 1))
            else:
                src, dst, *rest = e
                g.add_edge(src, dst, int(rest[0]) if rest else 1)
        g.labels = labels or {}
        return g

    @classmethod
    def from_knowledge(cls, store) -> "MoneyGraph":
        return cls.from_edges(store.all_edges(), store.entity_labels())

    # ---- reachability / paths ----
    def shortest_path(self, src: str, dst: str, directed: bool = True) -> list[str]:
        """Fewest-hop path src -> dst (BFS). Empty list if unreachable."""
        if src not in self.nodes or dst not in self.nodes:
            return []
        if src == dst:
            return [src]
        prev: dict[str, str] = {src: src}
        q: deque[str] = deque([src])
        while q:
            u = q.popleft()
            neighbours = dict(self.adj.get(u, {}))
            if not directed:
                neighbours.update(self.radj.get(u, {}))
            for v in neighbours:
                if v not in prev:
                    prev[v] = u
                    if v == dst:
                        return self._reconstruct(prev, src, dst)
                    q.append(v)
        return []

    @staticmethod
    def _reconstruct(prev: dict, src: str, dst: str) -> list[str]:
        path = [dst]
        while path[-1] != src:
            path.append(prev[path[-1]])
        return list(reversed(path))

    # ---- centrality ----
    def degree_centrality(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for n in self.nodes:
            out[n] = {
                "in": len(self.radj.get(n, {})),
                "out": len(self.adj.get(n, {})),
                "total": len(self.radj.get(n, {})) + len(self.adj.get(n, {})),
            }
        return out

    def betweenness_centrality(self) -> dict[str, float]:
        """Brandes' algorithm (unweighted, directed). O(V*E)."""
        cb = dict.fromkeys(self.nodes, 0.0)
        for s in self.nodes:
            stack: list[str] = []
            preds: dict[str, list[str]] = {w: [] for w in self.nodes}
            sigma = dict.fromkeys(self.nodes, 0.0)
            sigma[s] = 1.0
            dist = dict.fromkeys(self.nodes, -1)
            dist[s] = 0
            q: deque[str] = deque([s])
            while q:
                v = q.popleft()
                stack.append(v)
                for w in self.adj.get(v, {}):
                    if dist[w] < 0:
                        dist[w] = dist[v] + 1
                        q.append(w)
                    if dist[w] == dist[v] + 1:
                        sigma[w] += sigma[v]
                        preds[w].append(v)
            delta = dict.fromkeys(self.nodes, 0.0)
            while stack:
                w = stack.pop()
                for v in preds[w]:
                    if sigma[w]:
                        delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
                if w != s:
                    cb[w] += delta[w]
        return cb

    def hubs(self, n: int = 10) -> list[dict]:
        deg = self.degree_centrality()
        btw = self.betweenness_centrality()
        ranked = sorted(
            self.nodes,
            key=lambda a: (btw.get(a, 0.0), deg[a]["total"]),
            reverse=True,
        )
        return [
            {
                "address": a,
                "label": self.labels.get(a),
                "betweenness": round(btw.get(a, 0.0), 3),
                "degree_in": deg[a]["in"],
                "degree_out": deg[a]["out"],
            }
            for a in ranked[:n]
        ]

    # ---- communities ----
    def _weakly_connected_components(self) -> list[set[str]]:
        seen: set[str] = set()
        comps: list[set[str]] = []
        for start in self.nodes:
            if start in seen:
                continue
            comp: set[str] = set()
            q = deque([start])
            seen.add(start)
            while q:
                u = q.popleft()
                comp.add(u)
                for v in list(self.adj.get(u, {})) + list(self.radj.get(u, {})):
                    if v not in seen:
                        seen.add(v)
                        q.append(v)
            comps.append(comp)
        return comps

    def label_propagation(self, max_iter: int = 20) -> dict[str, int]:
        """Community label per node via synchronous label propagation."""
        label = {n: i for i, n in enumerate(sorted(self.nodes))}
        for _ in range(max_iter):
            changed = False
            for n in sorted(self.nodes):
                neighbours = list(self.adj.get(n, {})) + list(self.radj.get(n, {}))
                if not neighbours:
                    continue
                counts: dict[int, int] = defaultdict(int)
                for m in neighbours:
                    counts[label[m]] += 1
                best = min(
                    (lbl for lbl, c in counts.items() if c == max(counts.values())),
                )
                if label[n] != best:
                    label[n] = best
                    changed = True
            if not changed:
                break
        return label

    def communities(self, min_size: int = 2) -> list[dict]:
        """Return candidate rings: connected components, each split by label
        propagation, filtered to those with at least ``min_size`` members."""
        prop = self.label_propagation()
        groups: dict[int, set[str]] = defaultdict(set)
        for node, lbl in prop.items():
            groups[lbl].add(node)
        out = []
        for members in groups.values():
            if len(members) < min_size:
                continue
            internal = sum(
                1 for u in members for v in self.adj.get(u, {}) if v in members
            )
            out.append(
                {
                    "size": len(members),
                    "members": sorted(members),
                    "internal_edges": internal,
                    "labels": sorted({self.labels[m] for m in members if m in self.labels}),
                }
            )
        out.sort(key=lambda c: c["size"], reverse=True)
        return out

    def summary(self) -> dict:
        comps = self._weakly_connected_components()
        return {
            "nodes": len(self.nodes),
            "edges": sum(len(v) for v in self.adj.values()),
            "components": len(comps),
            "largest_component": max((len(c) for c in comps), default=0),
        }
