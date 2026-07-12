"""Entity clustering (common-input-ownership heuristic).

The strongest, most established heuristic in Bitcoin forensics: every input
address spent together in one transaction is controlled by the same entity -- you
must hold each input's private key to sign. Applying this transitively reveals the
full set of wallets a single actor controls, so from one address tied to a crime
we can surface *every* wallet of that entity.

Two guardrails keep it honest:
  * Never expand through a high-activity service (exchange / mixer / DEX / bridge).
    Those co-spend with thousands of unrelated users; merging through them would
    absorb half the chain into one cluster -- the classic clustering blow-up.
  * Never treat CoinJoin inputs as co-owned. The whole point of a CoinJoin is that
    its inputs belong to different people, so those links are excluded.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from ..enrich.labels import LabelCategory, LabelStore
from ..providers.base import Provider
from .change import identify_change
from .coinjoin import classify as classify_coinjoin

_STOP_CATEGORIES = {
    LabelCategory.EXCHANGE,
    LabelCategory.MIXER,
    LabelCategory.SERVICE,
    LabelCategory.DEX,
    LabelCategory.BRIDGE,
}


@dataclass
class Cluster:
    seed: str
    members: set[str] = field(default_factory=set)
    links: list[dict] = field(default_factory=list)          # co-spend evidence
    services_touched: dict[str, str] = field(default_factory=dict)  # addr -> label/name

    def as_dict(self) -> dict:
        return {
            "seed": self.seed,
            "entity_wallets": sorted(self.members),
            "wallet_count": len(self.members),
            "cospend_links": self.links,
            "services_touched": self.services_touched,
        }


class Clusterer:
    def __init__(
        self,
        provider: Provider,
        label_store: LabelStore | None = None,
        service_tx_threshold: int = 3000,
        max_addresses: int = 300,
        max_txs_per_address: int = 100,
    ) -> None:
        self.provider = provider
        self.label_store = label_store
        self.service_tx_threshold = service_tx_threshold
        self.max_addresses = max_addresses
        self.max_txs_per_address = max_txs_per_address

    def _is_service(self, address: str) -> tuple[bool, str]:
        label = self.label_store.get(address) if self.label_store else None
        if label is not None and label.category in _STOP_CATEGORIES:
            return True, label.name or label.category.value
        if self.provider.address_tx_count(address) > self.service_tx_threshold:
            return True, "high-activity address (probable service)"
        return False, ""

    def cluster(self, seed: str) -> Cluster:
        seed = self.provider.normalize(seed)
        cluster = Cluster(seed=seed)
        visited: set[str] = set()
        queue: deque[str] = deque([seed])

        while queue and len(cluster.members) < self.max_addresses:
            address = queue.popleft()
            if address in visited:
                continue
            visited.add(address)
            cluster.members.add(address)

            # Do not expand the cluster through a service (would merge strangers).
            is_service, why = self._is_service(address)
            if is_service and address != seed:
                cluster.services_touched[address] = why
                continue

            for tx in self.provider.get_transactions(address, self.max_txs_per_address):
                # CoinJoin inputs are NOT co-owned -- skip.
                if classify_coinjoin(tx) is not None:
                    continue
                in_addrs = tx.input_addresses()
                if address in in_addrs and len(in_addrs) > 1:
                    cluster.links.append({"txid": tx.txid, "addresses": sorted(in_addrs)})
                    for other in in_addrs:
                        if other not in visited and len(cluster.members) < self.max_addresses:
                            queue.append(other)

                # Second pillar: change-address identification. The leftover of a
                # spend returns to a fresh address the same actor controls.
                if address in in_addrs:
                    change = identify_change(
                        tx, in_addrs, is_service=lambda a: self._is_service(a)[0]
                    )
                    if change is not None and change.address not in visited:
                        cluster.links.append(
                            {"txid": tx.txid, "addresses": [address, change.address], "pattern": "change"}
                        )
                        if len(cluster.members) < self.max_addresses:
                            queue.append(change.address)

            # Also inspect outgoing spraying behavior from this node, as a weak but useful
            # anti-evasion signal when the same address repeatedly creates fresh outputs.
            for tx in self.provider.get_transactions(address, self.max_txs_per_address):
                if classify_coinjoin(tx) is not None:
                    continue
                outputs = [o.address for o in tx.outputs if o.address]
                if len(outputs) >= 3 and len(set(outputs)) >= 3:
                    cluster.links.append({"txid": tx.txid, "addresses": sorted(outputs), "pattern": "rotation"})
                    for addr in outputs:
                        if addr not in cluster.members and len(cluster.members) < self.max_addresses:
                            cluster.members.add(addr)

        # Rotation-aware pass: if a seed repeatedly sends to many outputs in a single transaction,
        # those outputs are likely part of the same evasive wallet family. Connect them into a
        # single suspicious cluster and surface them in the report even when they are not co-spent.
        if len(cluster.members) < self.max_addresses:
            seen_rotation: set[tuple[str, str]] = set()
            for tx in self.provider.get_transactions(seed, self.max_txs_per_address):
                if classify_coinjoin(tx) is not None:
                    continue
                outputs = [o.address for o in tx.outputs if o.address]
                if len(outputs) >= 3 and len(set(outputs)) >= 3:
                    cluster.links.append({"txid": tx.txid, "addresses": sorted(outputs), "pattern": "rotation"})
                    for addr in outputs:
                        if addr not in cluster.members and len(cluster.members) < self.max_addresses:
                            cluster.members.add(addr)

            # Repeated rotation behavior across several transactions is a stronger signal than a
            # one-off spray. Link the addresses that appear in multiple rotation-like transactions.
            rotation_txs: list[list[str]] = []
            for tx in self.provider.get_transactions(seed, self.max_txs_per_address):
                if classify_coinjoin(tx) is not None:
                    continue
                outputs = [o.address for o in tx.outputs if o.address]
                if len(outputs) >= 3 and len(set(outputs)) >= 3:
                    rotation_txs.append(outputs)
            if len(rotation_txs) >= 2:
                all_rotation_addrs = sorted({addr for outputs in rotation_txs for addr in outputs})
                for idx, addr in enumerate(all_rotation_addrs):
                    for other in all_rotation_addrs[idx + 1 :]:
                        pair = tuple(sorted((addr, other)))
                        if pair not in seen_rotation:
                            seen_rotation.add(pair)
                            cluster.links.append({"pattern": "temporal_rotation", "addresses": [addr, other], "evidence": len(rotation_txs)})

        return cluster
